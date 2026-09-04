//! command-line interface definition and argument parsing using clap derive macros.

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "albus",
    author = "oqullcan",
    version = "2.1.0",
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
    Get,

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

    // dynamic hop distance estimation and ttl optimization
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub auto_ttl: bool,

    // minimum ttl boundary clamp for auto-ttl estimation
    #[arg(long, default_value_t = 3)]
    pub min_ttl: u8,

    // maximum ttl boundary clamp for auto-ttl estimation
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

    // tcp max segment size clamp for tls clienthello fragmentation
    #[arg(long, default_value_t = 88)]
    pub mss: u16,

    // minimum tcp mss clamp for jitter randomization (0 = fixed mss)
    #[arg(long, default_value_t = 64)]
    pub min_mss: u16,

    // transmitted byte threshold before restoring native line-rate mss
    #[arg(long, default_value_t = 600)]
    pub restore_after_bytes: u32,

    // target mss value upon restoration (0 = 1460 auto)
    #[arg(long, default_value_t = 0)]
    pub restore_mss: u16,

    // target destination ports for ebpf sock_ops attachment
    #[arg(long, value_delimiter = ',', default_value = "443")]
    pub ports: Vec<u16>,

    // cgroup v2 unified hierarchy mount path
    #[arg(long, default_value = "/sys/fs/cgroup")]
    pub cgroup: String,

    // enable post-quantum cryptography (ml-kem / kyber768 hybrid key exchange)
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
