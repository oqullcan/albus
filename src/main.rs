//! binary entrypoint for daemon lifecycle, cli dispatch, and engine execution.

use albus::app::cli::{Cli, Commands, ConfigCommands, RunArgs};
use albus::app::config::Config;
use albus::app::{monitor, service};
use albus::core::ebpf::is_root;
use albus::core::engine::Engine;
use albus::core::firewall;
use albus::dns;
use clap::Parser;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // parse command line arguments via clap derive parser
    let cli = Cli::parse();

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
                    cfg.auto_ttl = args.auto_ttl;
                    cfg.min_ttl = args.min_ttl;
                    cfg.max_ttl = args.max_ttl;
                    cfg.doh_enabled = args.doh;
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
                    if args.query_log_path.is_some() {
                        cfg.query_log_path = args.query_log_path;
                    }
                    if args.ipcrypt_key.is_some() {
                        cfg.ipcrypt_key = args.ipcrypt_key;
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
        Some(Commands::Monitor) => {
            monitor::run_monitor()
        }
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
        // start packet fragmentation and desync engine
        Some(Commands::Run(args)) => {
            run_engine(args).await
        }
        None => {
            run_engine(cli.run_args).await
        }
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

    if is_root() {
        let _ = cfg.save_to_file("/etc/albus/config.json");
    }

    // instantiate and run async event loop
    let mut engine = Engine::new(cfg)?;
    engine.run().await
}
