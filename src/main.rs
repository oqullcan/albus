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
                    let cfg = apply_run_args_to_config(Config::load_or_default(), &args)?;
                    cfg.validate()?;

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

                    // if background daemon is actively running, notify it via SIGHUP to apply maps live.
                    // NOTE: SIGHUP only hot-reloads eBPF maps; firewall/DNS changes need restart.
                    // Only attempt the privileged signal as root: as an unprivileged user,
                    // `systemctl kill` would pop a polkit prompt on every save, so skip it.
                    let root = is_root();
                    let is_active = if root {
                        std::process::Command::new("/usr/bin/systemctl")
                            .args(["is-active", "--quiet", "albus.service"])
                            .status()
                            .map(|s| s.success())
                            .unwrap_or(false)
                    } else {
                        false
                    };
                    if should_signal_daemon(root, is_active) {
                        let _ = std::process::Command::new("/usr/bin/systemctl")
                            .args(["kill", "-s", "HUP", "albus.service"])
                            .status();
                        println!("live configuration reloaded into running albus daemon (SIGHUP)");
                    } else if !root {
                        println!(
                            "saved (unprivileged): restart albus.service to apply to the running daemon"
                        );
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
        // start packet fragmentation and desync engine
        Some(Commands::Run(args)) => run_engine(args).await,
        None => run_engine(cli.run_args).await,
    }
}

async fn run_engine(args: RunArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let level = resolve_log_level(args.verbose);

    // initialize structured tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);

    // load persistent configuration from json path or default hierarchy
    let cfg = if let Some(ref path) = args.config {
        Config::load_from_file_root_checked(path)?
    } else {
        Config::load_or_default()
    };
    cfg.validate()?;

    // instantiate and run async event loop
    let mut engine = Engine::new(cfg)?;
    engine.run().await
}

// maps CLI run arguments onto a config (pure; validation stays with caller)
fn apply_run_args_to_config(
    mut cfg: Config,
    args: &RunArgs,
) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    // update runtime tuning parameters
    cfg.mss = args.mss;
    cfg.min_mss = args.min_mss;
    cfg.restore_mss = args.restore_mss;
    cfg.restore_after_bytes = args.restore_after_bytes;
    cfg.ports = args.ports.clone();
    cfg.cgroup_path = args.cgroup.clone();
    cfg.fake_ttl = args.fake_ttl;
    cfg.fake_sni = args.fake_sni.clone();
    cfg.fake_bad_checksum = args.fake_bad_checksum;
    cfg.auto_ttl = args.auto_ttl;
    cfg.min_ttl = args.min_ttl;
    cfg.max_ttl = args.max_ttl;
    cfg.doh_enabled = args.doh;
    cfg.doh_upstream = args.doh_upstream.clone();
    cfg.doh_bootstrap_ips = args.doh_bootstrap_ips.clone();
    cfg.block_quic = args.block_quic;
    cfg.block_stun = args.block_stun;
    cfg.kill_switch = args.kill_switch;
    cfg.network_lockdown = args.network_lockdown;
    cfg.block_ipv6 = args.block_ipv6;
    cfg.dnssec = args.dnssec;
    cfg.pqc = args.pqc;
    cfg.ram_only = args.ram_only;
    cfg.verbose = args.verbose;
    Ok(cfg)
}

fn resolve_log_level(verbose: bool) -> Level {
    if verbose {
        Level::DEBUG
    } else {
        Level::INFO
    }
}

/// Whether a post-save SIGHUP may be attempted: root only, so unprivileged
/// saves never trigger a polkit prompt via `systemctl kill`.
fn should_signal_daemon(is_root_flag: bool, service_active: bool) -> bool {
    is_root_flag && service_active
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn set_args() -> RunArgs {
        match Cli::try_parse_from([
            "albus",
            "run",
            "--mss",
            "100",
            "--doh-upstream",
            "cloudflare",
            "--kill-switch",
            "false",
        ])
        .unwrap()
        .command
        {
            Some(Commands::Run(args)) => args,
            _ => panic!("expected run command"),
        }
    }

    #[test]
    fn test_apply_run_args_maps_fields() {
        let args = set_args();
        let cfg = apply_run_args_to_config(Config::default(), &args).unwrap();
        assert_eq!(cfg.mss, 100);
        assert_eq!(cfg.doh_upstream, "cloudflare");
        assert!(!cfg.kill_switch);
        // untouched base survives
        assert_eq!(cfg.min_mss, 64);
    }

    #[test]
    fn test_resolve_log_level() {
        assert_eq!(resolve_log_level(true), Level::DEBUG);
        assert_eq!(resolve_log_level(false), Level::INFO);
    }

    #[test]
    fn test_should_signal_daemon_needs_root_and_active() {
        assert!(should_signal_daemon(true, true));
        assert!(!should_signal_daemon(false, true));
        assert!(!should_signal_daemon(true, false));
        assert!(!should_signal_daemon(false, false));
    }
}
