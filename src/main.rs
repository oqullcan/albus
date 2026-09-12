//! binary entrypoint for daemon lifecycle, cli dispatch, and engine execution.

use albus::app::cli::{Cli, Commands, ConfigCommands, RunArgs};
use albus::app::config::Config;
use albus::app::{monitor, service};
use albus::core::ebpf::is_root;
use albus::core::engine::Engine;
use albus::core::firewall;
use albus::dns;
use clap::Parser;
use std::io::Write;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // parse command line arguments via clap derive parser
    let cli = Cli::parse();

    // top-level resolver listing (dnscrypt-proxy CLI compatibility: --list, --list-all, --include-relays, --json)
    if cli.list || cli.list_all {
        let cfg = Config::load_or_default();
        let filter = cli.list && !cli.list_all;
        return handle_resolvers_list_custom(&cfg, filter, cli.include_relays, cli.json_output).await;
    }

    match cli.command {
        // query kernel capabilities and service state
        Some(Commands::Status(status_args)) => {
            albus::app::status::handle_status_command(status_args.json);
            Ok(())
        }
        // persistent configuration inspection and modification
        Some(Commands::Config(config_args)) => {
            match config_args.command {
                Some(ConfigCommands::Get) => {
                    let cfg = Config::load_or_default();
                    let json = serde_json::to_string_pretty(&cfg)?;
                    println!("{}", json);
                    Ok(())
                }
                Some(ConfigCommands::Set(args)) => {
                    let mut cfg = Config::load_or_default();
                    // update runtime tuning parameters
                    cfg.mss = args.mss;
                    cfg.min_mss = args.min_mss;
                    cfg.restore_mss = args.restore_mss;
                    cfg.restore_after_bytes = args.restore_after_bytes;
                    cfg.ports = args.ports;
                    cfg.cgroup_path = args.cgroup;
                    cfg.fake_ttl = args.fake_ttl;
                    cfg.fake_sni = args.fake_sni;
                    cfg.fake_bad_checksum = args.fake_bad_checksum;
                    cfg.fake_seq_offset = args.fake_seq_offset;
                    cfg.fake_window_size = args.fake_window_size;
                    cfg.fake_tcp_flags = args.fake_tcp_flags.clone();
                    cfg.auto_ttl = args.auto_ttl;
                    cfg.min_ttl = args.min_ttl;
                    cfg.max_ttl = args.max_ttl;
                    cfg.doh_enabled = args.doh;
                    cfg.dns_racing = args.dns_racing;
                    cfg.doh_upstream = args.doh_upstream;
                    cfg.doh_bootstrap_ips = args.doh_bootstrap_ips;
                    cfg.block_quic = args.block_quic;
                    cfg.block_stun = args.block_stun;
                    cfg.kill_switch = args.kill_switch;
                    cfg.network_lockdown = args.network_lockdown;
                    cfg.block_ipv6 = args.block_ipv6;
                    cfg.dnssec = args.dnssec;
                    cfg.pqc = args.pqc;
                    cfg.ram_only = args.ram_only;
                    cfg.anti_dns_rebinding = args.anti_dns_rebinding;
                    cfg.block_undelegated = args.block_undelegated;
                    cfg.edns_padding = args.edns_padding;
                    cfg.blocklist = args.blocklist;
                    cfg.blocklist_path = args.blocklist_path;
                    if let Some(ref domains) = args.allow_domains {
                        cfg.allow_domains = domains.clone();
                    }
                    if args.allowlist_path.is_some() {
                        cfg.allowlist_path = args.allowlist_path;
                    }
                    cfg.dns64 = args.dns64;
                    cfg.block_bogons = args.block_bogons;
                    cfg.uncloak_cnames = args.uncloak_cnames;
                    cfg.netmon = args.netmon;
                    cfg.tcp_listener = args.tcp_listener;
                    cfg.local_doh = args.local_doh;
                    cfg.local_doh_addr = args.local_doh_addr;
                    cfg.query_log = args.query_log;
                    if let Some(ref path) = args.query_log_path {
                        cfg.query_log_path = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    if let Some(ref key) = args.ipcrypt_key {
                        cfg.ipcrypt_key = if key.trim().is_empty() {
                            None
                        } else {
                            Some(key.clone())
                        };
                    }
                    cfg.odoh_enabled = args.odoh;
                    if let Some(ref relay) = args.odoh_relay {
                        cfg.odoh_relay = if relay.trim().is_empty() {
                            None
                        } else {
                            Some(relay.clone())
                        };
                    }
                    if let Some(ref target) = args.odoh_target {
                        cfg.odoh_target = if target.trim().is_empty() {
                            None
                        } else {
                            Some(target.clone())
                        };
                    }
                    if let Some(ref proxy) = args.socks5_proxy {
                        cfg.socks5_proxy = if proxy.trim().is_empty() {
                            None
                        } else {
                            Some(proxy.clone())
                        };
                    }
                    cfg.tor = args.tor;
                    cfg.nx_log = args.nx_log;
                    if let Some(ref path) = args.nx_log_path {
                        cfg.nx_log_path = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    if let Some(ref ecs) = args.edns_client_subnet {
                        cfg.edns_client_subnet = if ecs.trim().is_empty() {
                            None
                        } else {
                            Some(ecs.clone())
                        };
                    }
                    cfg.metrics = args.metrics;
                    cfg.metrics_addr = args.metrics_addr;
                    if let Some(ref cert) = args.tls_client_cert {
                        cfg.tls_client_cert = if cert.trim().is_empty() {
                            None
                        } else {
                            Some(cert.clone())
                        };
                    }
                    if let Some(ref key) = args.tls_client_key {
                        cfg.tls_client_key = if key.trim().is_empty() {
                            None
                        } else {
                            Some(key.clone())
                        };
                    }
                    if let Some(ref path) = args.forwarding_rules_path {
                        cfg.forwarding_rules_path = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    cfg.cache_neg_min_ttl = args.cache_neg_min_ttl;
                    cfg.cache_neg_max_ttl = args.cache_neg_max_ttl;
                    if let Some(ref path) = args.tls_key_log_file {
                        cfg.tls_key_log_file = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    cfg.timeout_load_reduction = args.timeout_load_reduction;
                    if let Some(w) = args.web_ui {
                        cfg.web_ui = w;
                    }
                    if let Some(ref addr) = args.web_ui_addr {
                        cfg.web_ui_addr = addr.clone();
                    }
                    if let Some(ref user) = args.web_ui_user {
                        cfg.web_ui_user = if user.trim().is_empty() {
                            None
                        } else {
                            Some(user.clone())
                        };
                    }
                    if let Some(ref pass) = args.web_ui_pass {
                        cfg.web_ui_pass = if pass.trim().is_empty() {
                            None
                        } else {
                            Some(pass.clone())
                        };
                    }
                    if let Some(ref s) = args.dnscrypt_servers {
                        cfg.dnscrypt_servers = s.clone();
                    }
                    if let Some(ref r) = args.dnscrypt_relays {
                        cfg.dnscrypt_relays = r.clone();
                    }
                    if args.cache_min_ttl != 60 {
                        cfg.cache_min_ttl = args.cache_min_ttl;
                    }
                    if args.cache_max_ttl != 86400 {
                        cfg.cache_max_ttl = args.cache_max_ttl;
                    }
                    if let Some(ref path) = args.blocked_ips_file {
                        cfg.blocked_ips_file = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    if let Some(ref path) = args.allowed_ips_file {
                        cfg.allowed_ips_file = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    if let Some(ref ips) = args.allowed_ips {
                        cfg.allowed_ips = ips.clone();
                    }
                    if let Some(ref path) = args.blocked_names_log {
                        cfg.blocked_names_log_path = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    if let Some(ref path) = args.blocked_ips_log {
                        cfg.blocked_ips_log_path = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    if let Some(ref path) = args.allowed_names_log {
                        cfg.allowed_names_log_path = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    if let Some(ref path) = args.allowed_ips_log {
                        cfg.allowed_ips_log_path = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    cfg.force_tcp = args.force_tcp;
                    if let Some(ref path) = args.captive_map_file {
                        cfg.captive_portals_map_file = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    if let Some(ref dot) = args.dot_upstream {
                        cfg.dot_upstream = if dot.trim().is_empty() {
                            None
                        } else {
                            Some(dot.clone())
                        };
                    }
                    if let Some(ref path) = args.client_rules_file {
                        cfg.client_rules_file = if path.trim().is_empty() {
                            None
                        } else {
                            Some(path.clone())
                        };
                    }
                    if let Some(ref relays) = args.anonymized_doh_relays {
                        cfg.anonymized_doh_relays = relays.clone();
                    }
                    if let Some(v) = args.safe_search {
                        cfg.safe_search = v;
                    }
                    if let Some(ref mode) = args.youtube_restricted_mode {
                        cfg.youtube_restricted_mode = if mode.trim().is_empty() {
                            None
                        } else {
                            Some(mode.clone())
                        };
                    }
                    if let Some(v) = args.local_dot {
                        cfg.local_dot = v;
                    }
                    if let Some(ref addr) = args.local_dot_addr {
                        cfg.local_dot_addr = addr.clone();
                    }
                    if let Some(v) = args.randomize_ecs {
                        cfg.randomize_ecs = v;
                    }
                    if let Some(v) = args.load_system_hosts {
                        cfg.load_system_hosts = v;
                    }
                    if let Some(ref doq) = args.doq_upstream {
                        cfg.doq_upstream = if doq.trim().is_empty() {
                            None
                        } else {
                            Some(doq.clone())
                        };
                    }
                    cfg.verbose = args.verbose;

                    let path = Config::default_config_path();
                    cfg.save_to_file(&path)?;
                    if cfg.ram_only {
                        println!(
                            "albus configuration saved to volatile ram storage ({})",
                            Config::volatile_config_path().display()
                        );
                    } else {
                        println!("albus configuration saved to {}", path.display());
                    }

                    // if background daemon is actively running, notify it via SIGHUP to apply maps live
                    let is_active = std::process::Command::new("systemctl")
                        .args(["is-active", "--quiet", "albus.service"])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    if is_active {
                        let _ = std::process::Command::new("systemctl")
                            .args(["kill", "-s", "HUP", "albus.service"])
                            .status();
                        println!("live configuration reloaded into running albus daemon (SIGHUP)");
                    }

                    Ok(())
                }
                None => {
                    let cfg = Config::load_or_default();
                    let json = serde_json::to_string_pretty(&cfg)?;
                    println!("{}", json);
                    Ok(())
                }
            }
        }
        // background systemd service daemon control
        Some(Commands::Service(service_args)) => {
            service::handle_service_command(service_args.command)
        }
        // interactive curses-style terminal monitor
        Some(Commands::Monitor) => monitor::run_monitor(),
        // crash recovery: restore system resolv.conf and iptables state
        Some(Commands::Cleanup) => {
            if !is_root() {
                eprintln!("albus cleanup requires root privileges — please run with sudo");
                return Ok(());
            }
            println!("albus cleanup");
            firewall::unblock_quic();
            firewall::unblock_stun();
            firewall::disable_kill_switch();
            firewall::disable_network_lockdown();
            match dns::cleanup_system_dns() {
                Ok(true) => {
                    println!("cleanup complete — system DNS and firewall rules restored");
                }
                Ok(false) => {
                    println!("cleanup complete — firewall rules checked");
                }
                Err(e) => {
                    eprintln!("error during cleanup: {}", e);
                }
            }
            Ok(())
        }
        // remote resolver lists with cryptographic minisign verification
        Some(Commands::Resolvers(resolvers_args)) => {
            handle_resolvers_command(resolvers_args.command).await
        }
        // probe and rank upstream resolvers by latency
        Some(Commands::Benchmark(b_args)) => {
            let cfg = Config::load_or_default();
            let opts = dns::BenchmarkOptions {
                domain: b_args.domain,
                count: b_args.count,
                timeout_secs: b_args.timeout,
                concurrency: b_args.concurrency,
                top: b_args.top,
                protocol_filter: b_args.protocol,
            };
            let _ = dns::run_benchmark(&cfg, &opts).await?;
            Ok(())
        }
        // download, parse, and compile domain blocklists from public feeds
        Some(Commands::Blocklist(b_args)) => handle_blocklist_command(b_args).await,
        // start packet fragmentation and desync engine
        Some(Commands::Run(args)) => run_engine(args).await,
        None => run_engine(cli.run_args).await,
    }
}

async fn run_engine(args: RunArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    // initialize structured tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);

    // load persistent configuration from json path or default hierarchy
    let mut cfg = if let Some(ref path) = args.config {
        Config::load_from_file(path)?
    } else {
        Config::load_or_default()
    };

    if let Some(ref domains) = args.allow_domains {
        cfg.allow_domains = domains.clone();
    }
    if let Some(ref path) = args.allowlist_path {
        cfg.allowlist_path = Some(path.clone());
    }
    if args.dns64 {
        cfg.dns64 = true;
    }
    if !args.block_bogons {
        cfg.block_bogons = false;
    }
    if !args.uncloak_cnames {
        cfg.uncloak_cnames = false;
    }
    if !args.netmon {
        cfg.netmon = false;
    }
    if !args.tcp_listener {
        cfg.tcp_listener = false;
    }
    if !args.local_doh {
        cfg.local_doh = false;
    }
    if args.local_doh_addr != "127.0.0.1:8053" {
        cfg.local_doh_addr = args.local_doh_addr;
    }
    if args.query_log {
        cfg.query_log = true;
    }
    if let Some(ref path) = args.query_log_path {
        cfg.query_log_path = Some(path.clone());
    }
    if let Some(ref key) = args.ipcrypt_key {
        cfg.ipcrypt_key = Some(key.clone());
    }
    if args.odoh {
        cfg.odoh_enabled = true;
    }
    if let Some(ref relay) = args.odoh_relay {
        cfg.odoh_relay = Some(relay.clone());
    }
    if let Some(ref target) = args.odoh_target {
        cfg.odoh_target = Some(target.clone());
    }
    if let Some(ref proxy) = args.socks5_proxy {
        cfg.socks5_proxy = Some(proxy.clone());
    }
    if args.tor {
        cfg.tor = true;
    }
    if args.nx_log {
        cfg.nx_log = true;
    }
    if let Some(ref path) = args.nx_log_path {
        cfg.nx_log_path = Some(path.clone());
    }
    if let Some(ref ecs) = args.edns_client_subnet {
        cfg.edns_client_subnet = Some(ecs.clone());
    }
    if args.metrics {
        cfg.metrics = true;
    }
    if args.metrics_addr != "127.0.0.1:9153" {
        cfg.metrics_addr = args.metrics_addr;
    }
    if let Some(ref cert) = args.tls_client_cert {
        cfg.tls_client_cert = Some(cert.clone());
    }
    if let Some(ref key) = args.tls_client_key {
        cfg.tls_client_key = Some(key.clone());
    }
    if let Some(ref path) = args.forwarding_rules_path {
        cfg.forwarding_rules_path = Some(path.clone());
    }
    if args.cache_neg_min_ttl != 60 {
        cfg.cache_neg_min_ttl = args.cache_neg_min_ttl;
    }
    if args.cache_neg_max_ttl != 600 {
        cfg.cache_neg_max_ttl = args.cache_neg_max_ttl;
    }
    if let Some(ref path) = args.tls_key_log_file {
        cfg.tls_key_log_file = Some(path.clone());
    }
    cfg.timeout_load_reduction = args.timeout_load_reduction;
    if let Some(w) = args.web_ui {
        cfg.web_ui = w;
    }
    if let Some(ref addr) = args.web_ui_addr {
        cfg.web_ui_addr = addr.clone();
    }
    if let Some(ref user) = args.web_ui_user {
        cfg.web_ui_user = Some(user.clone());
    }
    if let Some(ref pass) = args.web_ui_pass {
        cfg.web_ui_pass = Some(pass.clone());
    }
    if let Some(ref s) = args.dnscrypt_servers {
        cfg.dnscrypt_servers = s.clone();
    }
    if let Some(ref r) = args.dnscrypt_relays {
        cfg.dnscrypt_relays = r.clone();
    }
    cfg.fake_seq_offset = args.fake_seq_offset;
    if args.fake_window_size.is_some() {
        cfg.fake_window_size = args.fake_window_size;
    }
    if args.fake_tcp_flags.is_some() {
        cfg.fake_tcp_flags = args.fake_tcp_flags.clone();
    }
    cfg.dns_racing = args.dns_racing;
    if args.cache_min_ttl != 60 {
        cfg.cache_min_ttl = args.cache_min_ttl;
    }
    if args.cache_max_ttl != 86400 {
        cfg.cache_max_ttl = args.cache_max_ttl;
    }
    if let Some(ref path) = args.blocked_ips_file {
        cfg.blocked_ips_file = Some(path.clone());
    }
    if let Some(ref path) = args.allowed_ips_file {
        cfg.allowed_ips_file = Some(path.clone());
    }
    if let Some(ref ips) = args.allowed_ips {
        cfg.allowed_ips = ips.clone();
    }
    if let Some(ref path) = args.blocked_names_log {
        cfg.blocked_names_log_path = Some(path.clone());
    }
    if let Some(ref path) = args.blocked_ips_log {
        cfg.blocked_ips_log_path = Some(path.clone());
    }
    if let Some(ref path) = args.allowed_names_log {
        cfg.allowed_names_log_path = Some(path.clone());
    }
    if let Some(ref path) = args.allowed_ips_log {
        cfg.allowed_ips_log_path = Some(path.clone());
    }
    if args.force_tcp {
        cfg.force_tcp = true;
    }
    if let Some(ref path) = args.captive_map_file {
        cfg.captive_portals_map_file = Some(path.clone());
    }
    if let Some(ref dot) = args.dot_upstream {
        cfg.dot_upstream = Some(dot.clone());
    }
    if let Some(ref path) = args.client_rules_file {
        cfg.client_rules_file = Some(path.clone());
    }
    if let Some(ref relays) = args.anonymized_doh_relays {
        cfg.anonymized_doh_relays = relays.clone();
    }
    if let Some(v) = args.safe_search {
        cfg.safe_search = v;
    }
    if let Some(ref mode) = args.youtube_restricted_mode {
        cfg.youtube_restricted_mode = Some(mode.clone());
    }
    if let Some(v) = args.local_dot {
        cfg.local_dot = v;
    }
    if let Some(ref addr) = args.local_dot_addr {
        cfg.local_dot_addr = addr.clone();
    }
    if let Some(v) = args.randomize_ecs {
        cfg.randomize_ecs = v;
    }
    if let Some(v) = args.load_system_hosts {
        cfg.load_system_hosts = v;
    }
    if let Some(ref doq) = args.doq_upstream {
        cfg.doq_upstream = Some(doq.clone());
    }
    if let Some(ref p) = args.pidfile {
        cfg.pid_file = Some(p.clone());
    }
    cfg.cloak_ttl = args.cloak_ttl;
    cfg.reject_ttl = args.reject_ttl;
    if let Some(ref fb) = args.fragments_blocked {
        cfg.fragments_blocked = fb.clone();
    }
    if let Some(ref path) = args.cloaking_rules_path {
        cfg.cloaking_rules_path = Some(path.clone());
    }
    if let Some(lvl) = args.web_ui_privacy_level {
        cfg.web_ui_privacy_level = lvl;
    }
    if let Some(ref prof) = args.defense_profile {
        cfg.defense_profile = Some(prof.clone());
    }
    if let Some(ref j4) = args.ja4_mimic {
        cfg.ja4_mimic = Some(j4.clone());
    }
    if let Some(ref sm) = args.stack_morph {
        cfg.stack_morph = Some(sm.clone());
    }
    if args.anti_injection {
        cfg.anti_injection = true;
    }
    if let Some(tol) = args.anti_injection_ttl_tolerance {
        cfg.anti_injection_ttl_tolerance = tol;
    }
    if args.simd_accel {
        cfg.simd_accel = true;
    }

    // one-shot latency benchmark check
    if args.check {
        let opts = dns::BenchmarkOptions::default();
        let _ = dns::run_benchmark(&cfg, &opts).await?;
        return Ok(());
    }

    // one-shot dns resolution command
    if let Some(ref domain) = args.resolve {
        return albus::dns::diagnostics::handle_resolve_command(domain, &cfg).await;
    }

    // upstream security and cryptographic certificate inspection command
    if args.show_certs {
        return albus::dns::diagnostics::handle_show_certs_command(&cfg).await;
    }

    // audit binary and config permissions for security (dnscrypt-proxy permcheck parity)
    if let Ok(exe_path) = std::env::current_exe() {
        albus::dns::system::warn_if_maybe_writable_by_other_users(&exe_path);
    }
    if let Some(ref cfg_path) = args.config {
        albus::dns::system::warn_if_maybe_writable_by_other_users(cfg_path);
    }

    if is_root() {
        let _ = cfg.save_to_file("/etc/albus/config.json");
    }

    // 0. verify outbound network connectivity (coldstart netprobe) before initializing resolvers
    if cfg.netprobe_timeout != 0 {
        dns::wait_for_network(&cfg.netprobe_address, cfg.netprobe_timeout).await;
    }

    // instantiate and run async event loop
    let mut engine = Engine::new(cfg)?;
    engine.run().await
}

async fn handle_resolvers_list_custom(
    cfg: &Config,
    filter: bool,
    include_relays: bool,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cache_dir = dns::SourceManager::default_cache_dir();
    let mgr = dns::SourceManager::new();

    let mut sources = cfg.sources.clone();
    if sources.is_empty() {
        sources.insert("public-resolvers".to_string(), dns::SourceConfig::default());
    }

    let filter_opts = albus::dns::sources::ServerFilterOptions {
        ipv4: cfg.ipv4_servers,
        ipv6: cfg.ipv6_servers,
        dnscrypt: !cfg.dnscrypt_servers.is_empty(),
        doh: cfg.doh_servers,
        odoh: cfg.odoh_servers,
        require_dnssec: cfg.require_dnssec,
        require_nolog: cfg.require_nolog,
        require_nofilter: cfg.require_nofilter,
        disabled_server_names: cfg.disabled_server_names.clone(),
    };

    let mut all_entries = Vec::new();

    for (src_name, src_cfg) in &sources {
        match mgr.fetch_or_load_cached(src_cfg, &cache_dir).await {
            Ok(entries) => {
                for entry in entries {
                    if filter && !filter_opts.matches(&entry) {
                        continue;
                    }
                    if !include_relays {
                        if let Some(ref stamp) = entry.primary_stamp {
                            if matches!(
                                stamp.protocol,
                                dns::StampProtocol::ODoHRelay | dns::StampProtocol::DNSCryptRelay
                            ) {
                                continue;
                            }
                        }
                    }
                    all_entries.push(entry);
                }
            }
            Err(e) => {
                eprintln!("failed to load resolver source {}: {}", src_name, e);
            }
        }
    }

    let mut stdout = std::io::stdout();
    if json_output {
        let json = serde_json::to_string_pretty(&all_entries)?;
        let _ = writeln!(stdout, "{}", json);
        return Ok(());
    }

    if writeln!(
        stdout,
        "{:<32} {:<12} {:<24} DESCRIPTION\n{}",
        "NAME", "PROTO", "ADDRESS", "-".repeat(95)
    ).is_err() {
        return Ok(());
    }

    for entry in &all_entries {
        let (proto, addr) = if let Some(ref stamp) = entry.primary_stamp {
            let p = match stamp.protocol {
                dns::StampProtocol::PlainDns => "DNS",
                dns::StampProtocol::CryptDns => "DNSCrypt",
                dns::StampProtocol::DoH => "DoH",
                dns::StampProtocol::DoT => "DoT",
                dns::StampProtocol::DoQ => "DoQ",
                dns::StampProtocol::ODoHRelay => "ODoH-Relay",
                dns::StampProtocol::ODoHTarget => "ODoH-Target",
                dns::StampProtocol::DNSCryptRelay => "DNSCrypt-Relay",
                dns::StampProtocol::Unknown(_) => "Unknown",
            };
            let a = stamp
                .server_addr
                .map(|s| s.to_string())
                .unwrap_or_else(|| stamp.provider_name.clone());
            (p, a)
        } else {
            ("Unknown", "-".to_string())
        };
        let clean_desc: String = entry
            .description
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        let desc = if clean_desc.chars().count() > 30 {
            let truncated: String = clean_desc.chars().take(27).collect();
            format!("{}...", truncated)
        } else {
            clean_desc
        };
        if writeln!(stdout, "{:<32} {:<12} {:<24} {}", entry.name, proto, addr, desc).is_err() {
            return Ok(());
        }
    }
    let _ = writeln!(stdout, "{}\nTotal verified resolvers: {}", "-".repeat(95), all_entries.len());
    Ok(())
}

async fn handle_resolvers_command(
    command: Option<albus::app::cli::ResolversCommands>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = Config::load_or_default();
    let cache_dir = dns::SourceManager::default_cache_dir();
    let mgr = dns::SourceManager::new();

    let mut sources = cfg.sources.clone();
    if sources.is_empty() {
        sources.insert("public-resolvers".to_string(), dns::SourceConfig::default());
    }

    match command.unwrap_or(albus::app::cli::ResolversCommands::List) {
        albus::app::cli::ResolversCommands::List => {
            handle_resolvers_list_custom(&cfg, false, true, false).await?
        }
        albus::app::cli::ResolversCommands::Update => {
            println!("updating remote resolver lists with cryptographic minisign verification...");
            for (src_name, src_cfg) in &sources {
                print!("fetching source '{}' ... ", src_name);
                match mgr.update(src_cfg, &cache_dir).await {
                    Ok(entries) => {
                        println!("success ({} resolvers verified)", entries.len());
                    }
                    Err(e) => {
                        println!("failed: {}", e);
                    }
                }
            }
        }
        albus::app::cli::ResolversCommands::Show { name } => {
            let mut found = None;
            for src_cfg in sources.values() {
                if let Ok(entries) = mgr.fetch_or_load_cached(src_cfg, &cache_dir).await {
                    if let Some(entry) = entries.into_iter().find(|e| e.name == name) {
                        found = Some(entry);
                        break;
                    }
                }
            }
            match found {
                Some(entry) => {
                    println!("Name:        {}", entry.name);
                    println!("Description: {}", entry.description);
                    if let Some(ref stamp) = entry.primary_stamp {
                        println!("Protocol:    {:?}", stamp.protocol);
                        if let Some(addr) = stamp.server_addr {
                            println!("Server Addr: {}", addr);
                        }
                        println!("Provider:    {}", stamp.provider_name);
                        if !stamp.path.is_empty() {
                            println!("Path:        {}", stamp.path);
                        }
                        if !stamp.doh_url.is_empty() {
                            println!("DoH URL:     {}", stamp.doh_url);
                        }
                        println!("DNSSEC:      {}", stamp.dnssec);
                        println!("No Log:      {}", stamp.no_log);
                        println!("No Filter:   {}", stamp.no_filter);
                    }
                    println!("Stamps:");
                    for s in &entry.stamps {
                        println!("  {}", s);
                    }
                }
                None => {
                    eprintln!("resolver '{}' not found in any source list", name);
                }
            }
        }
    }
    Ok(())
}

async fn handle_blocklist_command(
    args: albus::app::cli::BlocklistArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut sources = args.sources;
    if let Some(ref cfg_path) = args.config {
        if let Ok(content) = std::fs::read_to_string(cfg_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    sources.push(trimmed.to_string());
                }
            }
        }
    }
    if sources.is_empty() {
        sources.extend(
            albus::dns::blocklist_generator::DEFAULT_FEED_URLS
                .iter()
                .map(|s| s.to_string()),
        );
    }

    println!("Compiling domain blocklist from {} sources...", sources.len());
    let count = albus::dns::compile_blocklist(
        &sources,
        args.allowlist.as_deref(),
        args.time_restricted.as_deref(),
        args.local_additions.as_deref(),
        &args.output,
    )
    .await?;

    println!(
        "Successfully compiled {} blocked domains into {}",
        count, args.output
    );
    Ok(())
}
