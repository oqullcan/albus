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

    // drop upstream responses resolving to private/loopback ips (anti-dns-rebinding)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub anti_dns_rebinding: bool,

    // block queries for dotless names, .local, .lan, and undelegated private zones
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub block_undelegated: bool,

    // pad encrypted doh queries to discrete boundaries (rfc 8467)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub edns_padding: bool,

    // enable compact in-memory hagezi multi pro + tif ad/malware blocklist
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub blocklist: bool,

    // path to custom domain blocklist file or compiled binary
    #[arg(long)]
    pub blocklist_path: Option<String>,

    // comma-separated domains to allowlist/bypass blocklist
    #[arg(long, value_delimiter = ',')]
    pub allow_domains: Option<Vec<String>>,

    // path to custom domain allowlist file
    #[arg(long)]
    pub allowlist_path: Option<String>,

    // synthesize rfc 6052 ipv6 aaaa records for ipv4-only domains (dns64)
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub dns64: bool,

    // drop upstream responses resolving to bogon ip subnets
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub block_bogons: bool,

    // inspect and uncloak cname / https alias targets against blocklist
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub uncloak_cnames: bool,

    // monitor network interface and routing transitions (netmon)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub netmon: bool,

    // enable local tcp port 53 listener (rfc 7766)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub tcp_listener: bool,

    // enable local doh server (rfc 8484)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub local_doh: bool,

    // bind address for local doh server
    #[arg(long, default_value = "127.0.0.1:8053")]
    pub local_doh_addr: String,

    // enable structured query and threat audit logger
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub query_log: bool,

    // output file path for query audit log
    #[arg(long)]
    pub query_log_path: Option<String>,

    // 128-bit hex key for client ip pseudonymization (ipcrypt)
    #[arg(long)]
    pub ipcrypt_key: Option<String>,

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
