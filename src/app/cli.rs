//! command-line interface definition and argument parsing using clap derive macros.

use clap::{Args, Parser, Subcommand};

// FP-08: fail fast at the CLI boundary too (Config::validate remains the
// single source of truth; these mirror its restore_* bounds).
fn parse_restore_after_bytes(s: &str) -> Result<u32, String> {
    let v: u32 = s
        .parse()
        .map_err(|_| format!("invalid restore_after_bytes {}", s))?;
    if v < 64 {
        return Err(format!(
            "invalid restore_after_bytes {} (expected >= 64)",
            v
        ));
    }
    Ok(v)
}

fn parse_restore_mss(s: &str) -> Result<u16, String> {
    let v: u16 = s
        .parse()
        .map_err(|_| format!("invalid restore_mss {}", s))?;
    if v != 0 && !(64..=1460).contains(&v) {
        return Err(format!(
            "invalid restore_mss {} (expected 0 or 64..=1460)",
            v
        ));
    }
    Ok(v)
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "albus",
    author = "oqullcan",
    version,
    about = "ebpf sock_ops tcp mss fragmentation and doh proxy engine",
    long_about = "albus is a kernel-level network utility utilizing ebpf sock_ops and encrypted doh to bypass deep packet inspection."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[command(flatten)]
    pub run_args: RunArgs,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    // start packet desynchronization and dns engine in foreground
    Run(RunArgs),

    // background systemd service management commands
    Service(ServiceArgs),

    // interactive terminal monitor displaying flow telemetry
    Monitor,

    // inspect or update persistent json configuration
    Config(ConfigArgs),

    // inspect kernel ebpf capabilities and systemd state
    Status(StatusArgs),

    // cleanup firewall rules and restore original resolv.conf
    Cleanup,
}

#[derive(Args, Debug, Clone)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: Option<ConfigCommands>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigCommands {
    // print active configuration parameters in formatted json
    Get {
        /// read the system-wide daemon config (/etc/albus/config.json)
        /// instead of the user file: what the running daemon actually uses
        #[arg(long, default_value_t = false)]
        system: bool,
    },

    // update configuration values and persist to disk
    Set(RunArgs),
}

#[derive(Args, Debug, Clone)]
pub struct StatusArgs {
    // emit structured json payload formatted for status bars
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub command: ServiceCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServiceCommands {
    // install systemd unit and enable multi-user startup
    Install(RunArgs),

    // stop and remove systemd service unit
    Uninstall,

    // start background systemd service
    Start,

    // stop active background systemd service
    Stop,

    // restart systemd service to reload parameters
    Restart,

    // reload systemd service configuration live via SIGHUP
    Reload,

    // print systemd service operational status
    Status,

    // stream service journal logs to stdout
    Logs,
}

#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    // path to explicit configuration json file
    #[arg(short, long)]
    pub config: Option<String>,

    // fallback time-to-live for fake packet injection
    #[arg(long, default_value_t = 8)]
    pub fake_ttl: u8,

    // custom server name indication string for fake clienthello
    #[arg(long)]
    pub fake_sni: Option<String>,

    // inject invalid tcp checksums (0xdead) to deceive stateful middleboxes
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub fake_bad_checksum: bool,

    // static TTL selection (no probing — see autottl docs): true clamps
    // the default into [min_ttl, max_ttl], false honors --fake-ttl exactly
    // (hop-distance heuristic stays a conservative constant until true
    // path probing lands; see measure_hop_distance)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub auto_ttl: bool,

    // minimum ttl boundary clamp for the static default
    #[arg(long, default_value_t = 3)]
    pub min_ttl: u8,

    // maximum ttl boundary clamp for the static default
    #[arg(long, default_value_t = 12)]
    pub max_ttl: u8,

    // enable local dns-over-https proxy listener on 127.0.0.1:53
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub doh: bool,

    // upstream doh resolver preset or explicit https url
    #[arg(long, default_value = "quad9")]
    pub doh_upstream: String,

    // bootstrap ipv4 endpoints for custom doh domains
    #[arg(long = "doh-bootstrap-ips", alias = "doh-bootstrap", value_delimiter = ',', value_parser = parse_optional_ipv4)]
    pub doh_bootstrap_ips: Vec<std::net::Ipv4Addr>,

    // enforce dnssec do-bit and ad flag validation on doh queries
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub dnssec: bool,

    // drop outgoing udp 443 traffic to force browser tcp fallback
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub block_quic: bool,

    // drop outgoing webrtc stun traffic (udp 3478, 5349) to prevent ip leaks
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub block_stun: bool,

    // activate strict dns kill-switch blocking all non-loopback plaintext dns queries
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub kill_switch: bool,

    // activate fail-closed network lockdown blocking outbound http/https if ebpf fails
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub network_lockdown: bool,

    // filter aaaa queries to prevent unfragmented ipv6 bypass leaks
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub block_ipv6: bool,

    // shaping watchdog: periodically reconcile fresh connections against
    // perf events; on consecutive unexplained windows, engage fail-closed
    // network lockdown once until restart. On by default (soaked live with
    // real traffic, zero false trips after the overrun fix).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub shaping_watchdog: bool,

    // tcp max segment size clamp for tls clienthello fragmentation
    #[arg(long, default_value_t = 88)]
    pub mss: u16,

    // minimum tcp mss clamp for jitter randomization (must stay within 32..=mss)
    #[arg(long, default_value_t = 64)]
    pub min_mss: u16,

    // transmitted byte threshold before restoring native line-rate mss
    #[arg(long, default_value_t = 600, value_parser = parse_restore_after_bytes)]
    pub restore_after_bytes: u32,

    // target mss value upon restoration (0 = 1460 auto)
    #[arg(long, default_value_t = 0, value_parser = parse_restore_mss)]
    pub restore_mss: u16,

    // target destination ports for ebpf sock_ops attachment
    #[arg(long, value_delimiter = ',', default_value = "443")]
    pub ports: Vec<u16>,

    // cgroup v2 unified hierarchy mount path
    #[arg(long, default_value = "/sys/fs/cgroup")]
    pub cgroup: String,

    // offer post-quantum cryptography (ml-kem / kyber768 hybrid key exchange) where negotiated
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub pqc: bool,

    // enforce volatile only-ram execution and isolate state in tmpfs (/run)
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub ram_only: bool,

    // enable verbose debug logging in tracing subscriber
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
}

// parses comma-separated ipv4 addresses for custom doh bootstrapping
fn parse_optional_ipv4(s: &str) -> Result<std::net::Ipv4Addr, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty ip string".to_string());
    }
    trimmed.parse().map_err(|e| format!("{}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_parse_optional_ipv4_shapes() {
        assert!(parse_optional_ipv4("1.1.1.1").is_ok());
        assert!(parse_optional_ipv4("  9.9.9.9  ").is_ok());
        for bad in ["", "   ", "999.1.1.1", "1.1.1", "abc", "1::1", "1.1.1.1.1"] {
            assert!(parse_optional_ipv4(bad).is_err(), "must reject {:?}", bad);
        }
    }

    #[test]
    fn test_cli_defaults_and_parsing() {
        let cli = Cli::try_parse_from(["albus", "run"]).expect("run parses");
        match cli.command {
            Some(Commands::Run(args)) => {
                assert_eq!(args.fake_ttl, 8);
                assert!(args.auto_ttl);
            }
            other => panic!("unexpected command: {:?}", other),
        }
        let cli = Cli::try_parse_from([
            "albus",
            "run",
            "--ports",
            "443,80",
            "--fake-sni",
            "x.example",
        ])
        .expect("flags parse");
        match cli.command {
            Some(Commands::Run(args)) => {
                assert_eq!(args.ports, vec![443, 80]);
                assert_eq!(args.fake_sni.as_deref(), Some("x.example"));
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }
}
