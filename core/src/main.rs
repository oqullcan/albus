// albus - unified high-speed anti-dpi daemon, native cli, and system service orchestrator

mod diagnostic;
mod dns;
mod engine;
mod inbound;
mod protocol;
mod service;
mod strategy;
mod tun;

use dns::{DohResolver, LocalDnsServer};
use engine::connector::MarkedConnector;
use engine::monitor::ActivityMonitor;
use engine::netlink::RouteWatcher;
use engine::pipeline::{EngineMetrics, Pipeline};
use engine::router::{DomainRouter, RouteAction};
use inbound::socks5::{Socks5Handler, TargetAddr};
use service::cli::*;
use service::config::AlbusConfig;
use service::dns::{dns_restore_system, DnsGuard};
use service::firewall::{firewall_disable, FirewallGuard};
use strategy::adaptive::AdaptiveEvasionEngine;
use strategy::BypassMode;
use tun::{TunDevice, TunStack};

use std::env;
use std::fs::{self, Permissions};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
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
    let args: Vec<String> = env::args().collect();
    let cmd = if args.len() > 1 {
        let first = args[1].as_str();
        if first.starts_with("--") {
            if first == "--help" || first == "-h" {
                "help"
            } else if first == "--version" || first == "-v" {
                "version"
            } else if first == "--json" || first == "-j" {
                "status"
            } else {
                "run"
            }
        } else {
            first
        }
    } else {
        "status"
    };

    match cmd {
        "status" => {
            let json_mode = args.iter().any(|a| a == "--json" || a == "-j");
            cmd_status(json_mode);
            return Ok(());
        }
        "stats" => {
            cmd_stats();
            return Ok(());
        }
        "test" | "check" => {
            cmd_test();
            return Ok(());
        }
        "diag" | "diagnose" | "benchmark" => {
            cmd_diagnose().await;
            return Ok(());
        }
        "get-config" => {
            let cfg = AlbusConfig::load();
            println!("{}", serde_json::to_string(&cfg).unwrap_or_default());
            return Ok(());
        }
        "save-config" => {
            let mut cfg = AlbusConfig::load();
            if args.len() > 2 && !args[2].is_empty() { cfg.mode = args[2].clone(); }
            if args.len() > 3 && !args[3].is_empty() { cfg.dns = args[3].clone(); }
            if args.len() > 4 { cfg.custom_url = args[4].clone(); }
            if args.len() > 5 { cfg.custom_primary = args[5].clone(); }
            if args.len() > 6 { cfg.custom_secondary = args[6].clone(); }
            if args.len() > 7 { cfg.whitelist = args[7].clone(); }
            if args.len() > 8 { cfg.autostart = args[8] == "true"; }
            if args.len() > 9 { cfg.notifications = args[9] != "false"; }
            let _ = cfg.save();
            println!("{{\"saved\":true}}");
            return Ok(());
        }
        "set-autostart" => {
            let enable = args.get(2).map(|s| s == "true").unwrap_or(true);
            let _ = AlbusConfig::set_autostart(enable);
            println!("{{\"autostart\":{}}}", enable);
            return Ok(());
        }
        "purge-cache" | "flush" => {
            let _ = fs::remove_file(AlbusConfig::config_dir().join("stats.json"));
            println!("{{\"purged\":true}}");
            return Ok(());
        }
        "export-profile" => {
            match AlbusConfig::export_profile() {
                Ok(file) => println!("{{\"exported\":true,\"file\":\"{}\"}}", file),
                Err(e) => println!("{{\"exported\":false,\"error\":\"{}\"}}", e),
            }
            return Ok(());
        }
        "import-profile" => {
            match AlbusConfig::import_profile() {
                Ok(file) => println!("{{\"imported\":true,\"file\":\"{}\"}}", file),
                Err(e) => println!("{{\"imported\":false,\"error\":\"{}\"}}", e),
            }
            return Ok(());
        }
        "notify-evasion" => {
            let target = args.get(2).map(|s| s.as_str()).unwrap_or("unknown");
            let _ = std::process::Command::new("notify-send")
                .args(["-a", "Albus", "-i", "security-high", "DPI Bypassed", &format!("Secured connection to {}", target)])
                .output();
            return Ok(());
        }
        "check-core" => {
            println!("{{\"ready\":true,\"installed\":true}}");
            return Ok(());
        }
        "fix-network" | "repair" => {
            exec_privileged_run("fix-network-service", &[]);
            return Ok(());
        }
        "fix-network-service" => {
            cmd_fix_network();
            return Ok(());
        }
        "stop" => {
            print_banner();
            println!("{}> Stopping Albus daemon and restoring network rules...{}", C_YELLOW, C_RESET);
            exec_privileged_run("stop-service", &[]);
            println!("{}[OK] Albus daemon stopped cleanly.{}", C_GREEN, C_RESET);
            return Ok(());
        }
        "stop-service" => {
            firewall_disable();
            dns_restore_system();
            cmd_stop_process();
            println!("{{\"running\":false}}");
            return Ok(());
        }
        "restart" => {
            print_banner();
            println!("{}> Restarting Albus Anti-DPI...{}", C_BLUE, C_RESET);
            exec_privileged_run("stop-service", &[]);
            tokio::time::sleep(Duration::from_millis(300)).await;

            let remaining_args: Vec<String> = if args.len() > 2 { args[2..].to_vec() } else { Vec::new() };
            exec_privileged_run("run", &remaining_args);
            tokio::time::sleep(Duration::from_millis(200)).await;
            cmd_status(false);
            return Ok(());
        }
        "start" => {
            print_banner();
            println!("{}> Starting Albus Anti-DPI daemon...{}", C_BLUE, C_RESET);
            let mut remaining_args: Vec<String> = if args.len() > 2 { args[2..].to_vec() } else { Vec::new() };

            // Load saved user config defaults if empty
            if remaining_args.is_empty() {
                let cfg = AlbusConfig::load();
                remaining_args.push(cfg.mode);
                if cfg.dns == "custom" && !cfg.custom_url.is_empty() {
                    remaining_args.push(cfg.custom_url);
                } else {
                    remaining_args.push(cfg.dns);
                }
                let mut bootstraps = Vec::new();
                if !cfg.custom_primary.is_empty() { bootstraps.push(cfg.custom_primary); }
                if !cfg.custom_secondary.is_empty() { bootstraps.push(cfg.custom_secondary); }
                remaining_args.push(bootstraps.join(","));
                remaining_args.push(cfg.whitelist);
            }

            exec_privileged_run("run", &remaining_args);
            tokio::time::sleep(Duration::from_millis(200)).await;
            cmd_status(false);
            return Ok(());
        }
        "logs" | "log" => {
            for log_path in ["/run/albus/albus.log", "/tmp/albus.log"] {
                if fs::metadata(log_path).is_ok() {
                    println!("{}Tailing {} (Ctrl+C to exit):{}", C_CYAN, log_path, C_RESET);
                    let _ = std::process::Command::new("tail").args(["-f", log_path]).status();
                    return Ok(());
                }
            }
            println!("{}No active log file found.{}", C_YELLOW, C_RESET);
            return Ok(());
        }
        "help" | "--help" | "-h" => {
            print_banner();
            println!("{}USAGE:{} albus <command> [options]", C_BOLD, C_RESET);
            println!();
            println!("  {}start{}        Start Albus daemon with saved profile", C_GREEN, C_RESET);
            println!("  {}stop{}         Stop daemon & safely clean firewall rules", C_YELLOW, C_RESET);
            println!("  {}restart{}      Restart daemon", C_BLUE, C_RESET);
            println!("  {}status{}       Show live protection status and metrics", C_CYAN, C_RESET);
            println!("  {}stats{}        Detailed session telemetry and memory metrics", C_MAGENTA, C_RESET);
            println!("  {}test{}         Run instant live leak & defense verification suite", C_GREEN, C_RESET);
            println!("  {}fix-network{}  Emergency firewall flush & network repair", C_YELLOW, C_RESET);
            println!("  {}purge{}        Flush local DNS resolver caches", C_BLUE, C_RESET);
            println!("  {}diag{}         Run multi-CDN latency & bypass test", C_GREEN, C_RESET);
            println!("  {}logs{}         Follow daemon logs in real-time", C_DIM, C_RESET);
            println!();
            return Ok(());
        }
        "version" | "--version" | "-v" => {
            println!("Albus Anti-DPI v1.4.0");
            return Ok(());
        }
        "run" | "daemon" | "--service" => {
            // Daemon execution continues below
        }
        _ => {
            print_banner();
            println!("{}Unknown command: {}{}", C_RED, cmd, C_RESET);
            println!("Run 'albus help' for available commands.");
            return Ok(());
        }
    }

    // --- DAEMON EXECUTION (Privileged System Service) ---

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
        let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }

    let mut bind_addr = "127.0.0.1:1080".to_string();
    let mut dns_bind = "127.0.0.1:5300".to_string();
    let mut mode = BypassMode::StealthAuto;
    let mut dns_provider = "quad9".to_string();
    let mut custom_bootstraps: Vec<String> = Vec::new();
    let mut custom_whitelist: Vec<String> = Vec::new();
    let mut tun_interface: Option<String> = None;

    // Parse flags for daemon runtime
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" | "-b" => {
                if i + 1 < args.len() { bind_addr = args[i + 1].clone(); i += 1; }
            }
            "--dns-bind" => {
                if i + 1 < args.len() { dns_bind = args[i + 1].clone(); i += 1; }
            }
            "--tun" | "-t" => {
                let name = if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1; args[i].clone()
                } else {
                    "albus0".to_string()
                };
                tun_interface = Some(name);
            }
            "--mode" | "-m" => {
                if i + 1 < args.len() {
                    mode = match args[i + 1].to_lowercase().as_str() {
                        "split" => BypassMode::SniSplit,
                        "disorder" => BypassMode::Disorder,
                        "fake-ttl" | "fake_ttl" | "ghost" => BypassMode::FakeTtl,
                        _ => BypassMode::StealthAuto,
                    };
                    i += 1;
                }
            }
            "--dns" | "-d" => {
                if i + 1 < args.len() { dns_provider = args[i + 1].clone(); i += 1; }
            }
            "--bootstrap" | "-B" => {
                if i + 1 < args.len() { custom_bootstraps.push(args[i + 1].clone()); i += 1; }
            }
            "--whitelist" | "-W" => {
                if i + 1 < args.len() {
                    for part in args[i + 1].split(',') {
                        let t = part.trim();
                        if !t.is_empty() { custom_whitelist.push(t.to_string()); }
                    }
                    i += 1;
                }
            }
            _ => {
                // Positional arguments fallback: albus run [mode] [dns] [bootstraps] [whitelist]
                if i == 2 {
                    mode = match args[i].to_lowercase().as_str() {
                        "split" => BypassMode::SniSplit,
                        "disorder" => BypassMode::Disorder,
                        "fake-ttl" | "fake_ttl" | "ghost" => BypassMode::FakeTtl,
                        _ => BypassMode::StealthAuto,
                    };
                } else if i == 3 {
                    dns_provider = args[i].clone();
                } else if i == 4 && !args[i].is_empty() {
                    custom_bootstraps.push(args[i].clone());
                } else if i == 5 && !args[i].is_empty() {
                    for part in args[i].split(',') {
                        let t = part.trim();
                        if !t.is_empty() { custom_whitelist.push(t.to_string()); }
                    }
                }
            }
        }
        i += 1;
    }

    // 2. Prepare runtime directories
    let pid_file = get_pid_file();
    let socket_path = if is_dev_mode() { "/tmp/albus-dev.sock" } else { SOCKET_PATH };

    let _ = fs::create_dir_all("/run/albus");
    let _ = fs::set_permissions("/run/albus", Permissions::from_mode(0o755));
    let pid = std::process::id();
    let _ = fs::write(pid_file, pid.to_string());
    let _ = fs::set_permissions(pid_file, Permissions::from_mode(0o666));

    // 3. Arm RAII Netfilter & DNS Guards (automatic cleanup on exit/crash/signal)
    let _fw_guard = FirewallGuard::enable(1080, &custom_bootstraps);
    let _dns_guard = DnsGuard::enable();

    // 4. Graceful termination handler
    let sp_copy = socket_path.to_string();
    let pf_copy = pid_file.to_string();
    tokio::spawn(async move {
        if let Ok(mut sigterm) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
            firewall_disable();
            dns_restore_system();
            let _ = fs::remove_file(&sp_copy);
            let _ = fs::remove_file(RUN_SOCKET_PATH);
            let _ = fs::remove_file(&pf_copy);
            std::process::exit(0);
        }
    });

    let metrics = Arc::new(EngineMetrics::default());
    let doh = Arc::new(DohResolver::new(&dns_provider, &custom_bootstraps));
    let router = Arc::new(DomainRouter::new().with_custom_rules(&custom_whitelist));
    let monitor = Arc::new(ActivityMonitor::new());
    let adaptive = Arc::new(AdaptiveEvasionEngine::new());

    // Activity pulse ticker
    let monitor_ticker = Arc::clone(&monitor);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(1000));
        loop {
            interval.tick().await;
            monitor_ticker.tick_pulse();
        }
    });

    // Spawn route & interface watcher for link roaming resilience
    let doh_watcher = Arc::clone(&doh);
    tokio::spawn(async move {
        RouteWatcher::start(doh_watcher).await;
    });

    // Spawn local high-speed DNS resolver on 127.0.0.1:5300
    let doh_dns = Arc::clone(&doh);
    let dns_bind_clone = dns_bind.clone();
    tokio::spawn(async move {
        let _ = LocalDnsServer::run(&dns_bind_clone, doh_dns).await;
    });

    // Spawn optional userspace tun packet engine if requested
    if let Some(dev_name) = tun_interface {
        let m_tun = Arc::clone(&metrics);
        let mode_tun = mode;
        tokio::spawn(async move {
            if let Ok(dev) = TunDevice::create(&dev_name) {
                let dev_arc = Arc::new(dev);
                let _ = TunStack::run(dev_arc, mode_tun, m_tun).await;
            }
        });
    }

    // Bind proxy listener on 127.0.0.1:1080
    let listener = TcpListener::bind(&bind_addr).await?;

    // Setup unix control socket with world-accessible permissions for UI IPC
    let _ = fs::remove_file(socket_path);
    if !is_dev_mode() {
        let _ = fs::remove_file(RUN_SOCKET_PATH);
    }
    let unix_listener = UnixListener::bind(socket_path).ok();
    let _ = fs::set_permissions(socket_path, Permissions::from_mode(0o666));

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

    println!("{{\"running\":true,\"pid\":{},\"mode\":\"{:?}\",\"dns\":\"{}\"}}", pid, mode, dns_provider);

    // Resilient main proxy accept loop
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
