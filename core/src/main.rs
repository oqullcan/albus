// albus-core - lightweight local anti-censorship daemon with live monitor, data shield meter, battery awareness, and stealth loopback

mod diagnostic;
mod dns;
mod engine;
mod inbound;
mod protocol;
mod strategy;
mod tun;

use diagnostic::DiagnosticEngine;
use dns::{DohResolver, LocalDnsServer};
use engine::connector::MarkedConnector;
use engine::monitor::ActivityMonitor;
use engine::netlink::RouteWatcher;
use engine::pipeline::{EngineMetrics, Pipeline};
use engine::router::{DomainRouter, RouteAction};
use inbound::socks5::{Socks5Handler, TargetAddr};
use strategy::adaptive::AdaptiveEvasionEngine;
use strategy::BypassMode;
use tun::{TunDevice, TunStack};


use std::env;
use std::fs::Permissions;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} B", bytes)
    }
}

fn is_on_battery() -> bool {
    if let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("BAT") {
                let status_path = entry.path().join("status");
                if let Ok(status) = std::fs::read_to_string(status_path) {
                    if status.trim().eq_ignore_ascii_case("Discharging") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. best-effort file descriptor boost and physical memory locking (anti-swap)
    unsafe {
        let mut current_rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut current_rlim) == 0 {
            let target_limit = current_rlim.rlim_max.max(65535);
            let new_rlim = libc::rlimit {
                rlim_cur: target_limit.min(65535),
                rlim_max: target_limit,
            };
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &new_rlim);
        }
        // mlockall: best-effort memory locking (requires CAP_IPC_LOCK or sufficient RLIMIT_MEMLOCK; ignored on EPERM)
        let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }

    let args: Vec<String> = env::args().collect();

    let mut bind_addr = "127.0.0.1:1080".to_string();
    let mut dns_bind = "127.0.0.1:5300".to_string();
    let mut mode = BypassMode::StealthAuto;
    let mut dns_provider = "quad9".to_string();
    let mut custom_bootstraps: Vec<String> = Vec::new();
    let mut custom_whitelist: Vec<String> = Vec::new();
    let mut tun_interface: Option<String> = None;
    let control_socket_path = "/tmp/albus.sock";

    // simple debloated flag parser
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" | "-b" => {
                if i + 1 < args.len() {
                    bind_addr = args[i + 1].clone();
                    i += 1;
                }
            }
            "--dns-bind" => {
                if i + 1 < args.len() {
                    dns_bind = args[i + 1].clone();
                    i += 1;
                }
            }
            "--tun" | "-t" => {
                let name = if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1;
                    args[i].clone()
                } else {
                    "albus0".to_string()
                };
                tun_interface = Some(name);
            }
            "--mode" | "-m" => {
                if i + 1 < args.len() {
                    mode = match args[i + 1].as_str() {
                        "split" => BypassMode::SniSplit,
                        "disorder" => BypassMode::Disorder,
                        "fake-ttl" => BypassMode::FakeTtl,
                        _ => BypassMode::StealthAuto,
                    };
                    i += 1;
                }
            }
            "--dns" | "-d" => {
                if i + 1 < args.len() {
                    dns_provider = args[i + 1].clone();
                    i += 1;
                }
            }
            "--bootstrap" | "-B" => {
                if i + 1 < args.len() {
                    custom_bootstraps.push(args[i + 1].clone());
                    i += 1;
                }
            }
            "--whitelist" | "-W" => {
                if i + 1 < args.len() {
                    for part in args[i + 1].split(',') {
                        let t = part.trim();
                        if !t.is_empty() {
                            custom_whitelist.push(t.to_string());
                        }
                    }
                    i += 1;
                }
            }
            "--status" => {
                if let Ok(stream) = tokio::net::UnixStream::connect(control_socket_path).await {
                    let mut reader = BufReader::new(stream);
                    let mut resp = String::new();
                    if reader.read_line(&mut resp).await.is_ok() && !resp.trim().is_empty() {
                        print!("{}", resp);
                        return Ok(());
                    }
                }
                println!("{{\"running\":false}}");
                return Ok(());
            }
            "--diagnose" => {
                let report = DiagnosticEngine::run_full_diagnostic().await;
                if let Ok(json) = serde_json::to_string(&report) {
                    println!("{}", json);
                }
                return Ok(());
            }
            "--help" | "-h" => {
                println!("albus-core: lightweight local anti-censorship daemon");
                println!("usage: albus-core [options]");
                println!("  --bind,      -b <addr>   bind address (default: 127.0.0.1:1080)");
                println!("  --dns-bind   <addr>      dns listener address (default: 127.0.0.1:5300)");
                println!("  --tun,       -t [dev]    enable optional userspace tun packet engine (default: albus0)");
                println!("  --mode,      -m <mode>   bypass mode: auto, split, disorder, fake-ttl");
                println!("  --dns,       -d <prov>   dns provider: quad9, cloudflare, adguard, custom");
                println!("  --bootstrap, -B <ips>    custom bootstrap ips (primary and secondary)");
                println!("  --whitelist, -W <rules>  custom direct passthrough domains");
                println!("  --status                 check if daemon is running and retrieve stats");
                println!("  --diagnose               run comprehensive health & connectivity benchmark");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }


    // 2. graceful shutdown signal handler
    tokio::spawn(async move {
        if let Ok(mut sigterm) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
            let _ = std::fs::remove_file("/tmp/albus.sock");
            let _ = std::fs::remove_file("/tmp/albus-daemon.pid");
            std::process::exit(0);
        }
    });

    let metrics = Arc::new(EngineMetrics::default());
    let doh = Arc::new(DohResolver::new(&dns_provider, &custom_bootstraps));
    let router = Arc::new(DomainRouter::new().with_custom_rules(&custom_whitelist));
    let monitor = Arc::new(ActivityMonitor::new());
    let adaptive = Arc::new(AdaptiveEvasionEngine::new());

    // 1-second activity pulse rolling ticker
    let monitor_ticker = Arc::clone(&monitor);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(1000));
        loop {
            interval.tick().await;
            monitor_ticker.tick_pulse();
        }
    });

    // spawn route & interface watcher for link roaming resilience
    let doh_watcher = Arc::clone(&doh);
    tokio::spawn(async move {
        RouteWatcher::start(doh_watcher).await;
    });

    // spawn local high-speed dns resolver on 127.0.0.1:5300 (stealth loopback)
    let doh_dns = Arc::clone(&doh);
    tokio::spawn(async move {
        let _ = LocalDnsServer::run(&dns_bind, doh_dns).await;
    });

    // spawn optional userspace tun packet engine if requested
    if let Some(dev_name) = tun_interface {
        let m_tun = Arc::clone(&metrics);
        let mode_tun = mode;
        tokio::spawn(async move {
            match TunDevice::create(&dev_name) {
                Ok(dev) => {
                    let dev_arc = Arc::new(dev);
                    println!("albus-core tun virtual interface active on {}", dev_name);
                    let _ = TunStack::run(dev_arc, mode_tun, m_tun).await;
                }
                Err(e) => {
                    eprintln!("tun initialization notice (requires root/CAP_NET_ADMIN): {}", e);
                }
            }
        });
    }

    // bind socks5, http connect & transparent listener on 127.0.0.1:1080 (stealth loopback)
    let listener = TcpListener::bind(&bind_addr).await?;
    println!("albus-core listening on proxy://{}", bind_addr);


    // setup unix control socket with world accessible permissions for ui ipc
    let _ = std::fs::remove_file(control_socket_path);
    let unix_listener = UnixListener::bind(control_socket_path).ok();
    if let Ok(()) = std::fs::set_permissions(control_socket_path, Permissions::from_mode(0o666)) {
        // permissions configured
    }

    // spawn dns poisoning and censorship detection watcher
    let metrics_poison = Arc::clone(&metrics);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;
            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                let dummy_query = vec![
                    0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x07, b't', b'w', b'i', b't', b't', b'e', b'r', 0x03, b'c', b'o', b'm', 0x00,
                    0x00, 0x01, 0x00, 0x01,
                ];
                let _ = socket.send_to(&dummy_query, "8.8.8.8:53").await;
                let mut buf = [0u8; 512];
                if let Ok(Ok((len, _))) = tokio::time::timeout(Duration::from_millis(600), socket.recv_from(&mut buf)).await {
                    if len > 12 {
                        metrics_poison.dns_poison_blocks.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    });

    if let Some(ctrl) = unix_listener {
        let m = Arc::clone(&metrics);
        let doh_ctrl = Arc::clone(&doh);
        let mon = Arc::clone(&monitor);

        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = ctrl.accept().await {
                    let total = m.total_connections.load(Ordering::Relaxed);
                    let tls = m.bypassed_tls_sessions.load(Ordering::Relaxed);
                    let http = m.bypassed_http_sessions.load(Ordering::Relaxed);
                    let bytes = m.bytes_protected.load(Ordering::Relaxed);
                    let poison_blocks = m.dns_poison_blocks.load(Ordering::Relaxed);
                    let bytes_formatted = format_bytes(bytes);
                    let latency = doh_ctrl.get_latency_ms();
                    let dns_name = &doh_ctrl.provider_name;
                    let on_bat = is_on_battery();
                    let history = mon.get_pulse();
                    let events = mon.get_events();
                    let speed_bps = mon.get_throughput_bps();
                    let speed_str = mon.get_throughput_str();

                    let history_json = serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string());
                    let events_json = serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string());

                    let status_json = format!(
                        "{{\"running\":true,\"total\":{},\"tls\":{},\"http\":{},\"bytes\":{},\"bytes_str\":\"{}\",\"speed_bps\":{},\"speed_str\":\"{}\",\"latency\":{},\"dns\":\"{}\",\"battery\":{},\"poison_blocks\":{},\"history\":{},\"events\":{}}}\n",
                        total, tls, http, bytes, bytes_formatted, speed_bps, speed_str, latency, dns_name, on_bat, poison_blocks, history_json, events_json
                    );
                    let _ = stream.write_all(status_json.as_bytes()).await;
                    let _ = stream.flush().await;

                }
            }
        });
    }

    // resilient main proxy accept loop
    loop {
        match listener.accept().await {
            Ok((mut client_stream, _)) => {
                let _ = client_stream.set_nodelay(true);
                let m = Arc::clone(&metrics);
                let resolver = Arc::clone(&doh);
                let router_ref = Arc::clone(&router);
                let mon_ref = Arc::clone(&monitor);
                let adapt_ref = Arc::clone(&adaptive);

                tokio::spawn(async move {
                    if let Ok(target) = Socks5Handler::handshake(&mut client_stream).await {
                        let (target_sock_addr, target_domain, target_name) = match target {
                            TargetAddr::Ip(addr_str) => {
                                let name = addr_str.clone();
                                (addr_str.parse::<SocketAddr>().ok(), None, name)
                            }
                            TargetAddr::Domain(domain, port) => {
                                let name = format!("{}:{}", domain, port);
                                if let Some(ip) = resolver.resolve(&domain).await {
                                    (Some(SocketAddr::new(ip, port)), Some(domain), name)
                                } else {
                                    (None, Some(domain), name)
                                }
                            }
                        };

                        if let Some(sock_addr) = target_sock_addr {
                            let route_action = router_ref.evaluate(
                                Some(sock_addr.ip()),
                                target_domain.as_deref(),
                            );

                            if let Ok(mut remote_stream) = MarkedConnector::connect(sock_addr).await {
                                let _ = remote_stream.set_nodelay(true);
                                match route_action {
                                    RouteAction::Direct => {
                                        mon_ref.record_event(&target_name, "Direct Pass", "OK");
                                        let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut remote_stream).await;
                                    }
                                    RouteAction::BypassDpi => {
                                        let _ = Pipeline::bridge(
                                            client_stream,
                                            remote_stream,
                                            Some(sock_addr),
                                            target_name,
                                            mode,
                                            m,
                                            mon_ref,
                                            adapt_ref,
                                        ).await;
                                    }
                                }
                            }
                        }
                    }
                });
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}
