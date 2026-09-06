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

    // list, fetch, and verify remote resolver lists with cryptographic minisign signatures
    Resolvers(ResolversArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ResolversArgs {
    #[command(subcommand)]
    pub command: Option<ResolversCommands>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ResolversCommands {
    // list available resolvers from local cache or remote source
    List,

    // update and cryptographically verify remote resolver lists
    Update,

    // show details and stamp for a specific resolver
    Show {
        name: String,
    },
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

    // sequence number shift offset for overlapping or out-of-order fake packet injection
    #[arg(long, default_value_t = 0)]
    pub fake_seq_offset: i32,

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

    // query multiple upstreams concurrently (happy eyeballs DNS racing) for lowest latency
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub dns_racing: bool,

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

    // enable dedicated audit log for nxdomain responses (dga malware detection)
    #[arg(long, default_value_t = false, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub nx_log: bool,

    // output file path for nxdomain audit log
    #[arg(long)]
    pub nx_log_path: Option<String>,

    // 128-bit hex key for client ip pseudonymization (ipcrypt)
    #[arg(long)]
    pub ipcrypt_key: Option<String>,

    // enable oblivious dns-over-https (odoh, rfc 9230) proxying
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub odoh: bool,

    // oblivious doh relay proxy url
    #[arg(long)]
    pub odoh_relay: Option<String>,

    // oblivious doh target resolver url
    #[arg(long)]
    pub odoh_target: Option<String>,

    // edns client subnet (rfc 7871) cidr prefix for geo-optimization (e.g. 1.2.3.0/24 or 0.0.0.0/0 for zero-scope)
    #[arg(long)]
    pub edns_client_subnet: Option<String>,

    // enable prometheus metrics http server endpoint (/metrics)
    #[arg(long, default_value_t = false, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub metrics: bool,

    // prometheus metrics listen address
    #[arg(long, default_value = "127.0.0.1:9153")]
    pub metrics_addr: String,

    // route upstream encrypted doh/odoh queries via socks5 proxy (e.g. socks5://127.0.0.1:9050)
    #[arg(long)]
    pub socks5_proxy: Option<String>,

    // route upstream encrypted queries through local tor socks5 proxy (socks5://127.0.0.1:9050)
    #[arg(long, default_value_t = false, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub tor: bool,

    // client x.509 certificate file in pem format for mtls upstream authentication
    #[arg(long)]
    pub tls_client_cert: Option<String>,

    // client private key file in pem format (pkcs#8, pkcs#1, or sec1) for mtls upstream authentication
    #[arg(long)]
    pub tls_client_key: Option<String>,

    // path to external split-dns forwarding rules file (e.g. forwarding-rules.txt)
    #[arg(long, visible_alias = "forward-rules-path")]
    pub forwarding_rules_path: Option<String>,

    // minimum ttl clamp in seconds for negative responses (rfc 2308 nxdomain/nodata)
    #[arg(long, default_value_t = 60, visible_alias = "neg-min-ttl")]
    pub cache_neg_min_ttl: u32,

    // maximum ttl clamp in seconds for negative responses (rfc 2308 nxdomain/nodata)
    #[arg(long, default_value_t = 600, visible_alias = "neg-max-ttl")]
    pub cache_neg_max_ttl: u32,

    // write tls secrets (nss key log format) to file for wireshark debugging
    #[arg(long)]
    pub tls_key_log_file: Option<String>,

    // dynamic query timeout reduction factor under high load (0.0 to 1.0, e.g. 0.75)
    #[arg(long, default_value_t = 0.75)]
    pub timeout_load_reduction: f64,

    // enable embedded web monitoring dashboard (http://127.0.0.1:205)
    #[arg(long, default_value_t = true, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub web_ui: bool,

    // embedded web monitoring dashboard listen address
    #[arg(long, default_value = "127.0.0.1:205")]
    pub web_ui_addr: String,

    // optional basic authentication username for web monitoring dashboard
    #[arg(long)]
    pub web_ui_user: Option<String>,

    // optional basic authentication password for web monitoring dashboard
    #[arg(long, visible_alias = "web-ui-password")]
    pub web_ui_pass: Option<String>,

    // comma-separated list of dnscrypt resolver names or sdns stamps
    #[arg(long, value_delimiter = ',')]
    pub dnscrypt_servers: Option<Vec<String>>,

    // comma-separated list of anonymized dnscrypt relay names or sdns stamps
    #[arg(long, value_delimiter = ',')]
    pub dnscrypt_relays: Option<Vec<String>>,

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
    use std::net::Ipv4Addr;

    #[test]
    fn test_cli_default_run_args() {
        let cli = Cli::try_parse_from(["albus"]).expect("default args should parse");
        assert!(cli.command.is_none());
        assert_eq!(cli.run_args.mss, 88);
        assert_eq!(cli.run_args.min_mss, 64);
        assert_eq!(cli.run_args.fake_ttl, 8);
        assert_eq!(cli.run_args.ports, vec![443]);
        assert!(cli.run_args.doh);
        assert!(cli.run_args.pqc);
        assert!(cli.run_args.block_quic);
        assert!(cli.run_args.block_stun);
        assert!(cli.run_args.kill_switch);
        assert!(!cli.run_args.network_lockdown);
        assert_eq!(cli.run_args.doh_upstream, "quad9");
        assert_eq!(cli.run_args.socks5_proxy, None);
        assert!(!cli.run_args.tor);
        assert!(!cli.run_args.nx_log);
        assert_eq!(cli.run_args.nx_log_path, None);
        assert_eq!(cli.run_args.edns_client_subnet, None);
        assert!(!cli.run_args.metrics);
        assert_eq!(cli.run_args.metrics_addr, "127.0.0.1:9153");
        assert_eq!(cli.run_args.tls_client_cert, None);
        assert_eq!(cli.run_args.tls_client_key, None);
    }

    #[test]
    fn test_cli_tls_client_auth_flags() {
        let cli = Cli::try_parse_from([
            "albus",
            "run",
            "--tls-client-cert",
            "/etc/ssl/client.crt",
            "--tls-client-key",
            "/etc/ssl/client.key",
        ])
        .expect("mtls flags should parse");
        match cli.command {
            Some(Commands::Run(args)) => {
                assert_eq!(args.tls_client_cert.as_deref(), Some("/etc/ssl/client.crt"));
                assert_eq!(args.tls_client_key.as_deref(), Some("/etc/ssl/client.key"));
            }
            _ => panic!("expected Commands::Run"),
        }
    }

    #[test]
    fn test_cli_metrics_flags() {
        let cli = Cli::try_parse_from([
            "albus",
            "run",
            "--metrics",
            "--metrics-addr",
            "0.0.0.0:9090",
        ])
        .expect("metrics flags should parse");
        match cli.command {
            Some(Commands::Run(args)) => {
                assert!(args.metrics);
                assert_eq!(args.metrics_addr, "0.0.0.0:9090");
            }
            _ => panic!("expected Commands::Run"),
        }
    }

    #[test]
    fn test_cli_proxy_flags() {
        let cli_tor =
            Cli::try_parse_from(["albus", "run", "--tor"]).expect("tor flag should parse");
        match cli_tor.command {
            Some(Commands::Run(args)) => {
                assert!(args.tor);
                assert_eq!(args.socks5_proxy, None);
            }
            _ => panic!("expected Commands::Run"),
        }

        let cli_socks = Cli::try_parse_from([
            "albus",
            "run",
            "--socks5-proxy",
            "socks5://127.0.0.1:1080",
        ])
        .expect("socks5 flag should parse");
        match cli_socks.command {
            Some(Commands::Run(args)) => {
                assert!(!args.tor);
                assert_eq!(
                    args.socks5_proxy.as_deref(),
                    Some("socks5://127.0.0.1:1080")
                );
            }
            _ => panic!("expected Commands::Run"),
        }
    }

    #[test]
    fn test_cli_nx_log_flags() {
        let cli_nx = Cli::try_parse_from([
            "albus",
            "run",
            "--nx-log",
            "--nx-log-path",
            "/tmp/test_nx.log",
        ])
        .expect("nx-log flags should parse");
        match cli_nx.command {
            Some(Commands::Run(args)) => {
                assert!(args.nx_log);
                assert_eq!(args.nx_log_path.as_deref(), Some("/tmp/test_nx.log"));
            }
            _ => panic!("expected Commands::Run"),
        }
    }

    #[test]
    fn test_cli_ecs_flag() {
        let cli_ecs = Cli::try_parse_from([
            "albus",
            "run",
            "--edns-client-subnet",
            "1.2.3.0/24",
        ])
        .expect("ecs flag should parse");
        match cli_ecs.command {
            Some(Commands::Run(args)) => {
                assert_eq!(args.edns_client_subnet.as_deref(), Some("1.2.3.0/24"));
            }
            _ => panic!("expected Commands::Run"),
        }
    }

    #[test]
    fn test_cli_run_subcommand_with_custom_flags() {
        let cli = Cli::try_parse_from([
            "albus",
            "run",
            "--mss",
            "120",
            "--min-mss",
            "70",
            "--fake-ttl",
            "5",
            "--ports",
            "80,443,8443",
            "--doh-upstream",
            "cloudflare",
            "--fake-sni",
            "example.com",
            "--verbose",
        ])
        .expect("custom run args should parse");

        match cli.command {
            Some(Commands::Run(args)) => {
                assert_eq!(args.mss, 120);
                assert_eq!(args.min_mss, 70);
                assert_eq!(args.fake_ttl, 5);
                assert_eq!(args.ports, vec![80, 443, 8443]);
                assert_eq!(args.doh_upstream, "cloudflare");
                assert_eq!(args.fake_sni.as_deref(), Some("example.com"));
                assert!(args.verbose);
            }
            _ => panic!("expected Commands::Run"),
        }
    }

    #[test]
    fn test_cli_status_subcommand() {
        let cli_default = Cli::try_parse_from(["albus", "status"]).unwrap();
        match cli_default.command {
            Some(Commands::Status(args)) => assert!(!args.json),
            _ => panic!("expected Commands::Status"),
        }

        let cli_json = Cli::try_parse_from(["albus", "status", "--json"]).unwrap();
        match cli_json.command {
            Some(Commands::Status(args)) => assert!(args.json),
            _ => panic!("expected Commands::Status with json"),
        }
    }

    #[test]
    fn test_cli_service_subcommands() {
        let commands = [
            (
                "start",
                matches!(ServiceCommands::Start, ServiceCommands::Start),
            ),
            (
                "stop",
                matches!(ServiceCommands::Stop, ServiceCommands::Stop),
            ),
            (
                "restart",
                matches!(ServiceCommands::Restart, ServiceCommands::Restart),
            ),
            (
                "reload",
                matches!(ServiceCommands::Reload, ServiceCommands::Reload),
            ),
            (
                "status",
                matches!(ServiceCommands::Status, ServiceCommands::Status),
            ),
            (
                "logs",
                matches!(ServiceCommands::Logs, ServiceCommands::Logs),
            ),
            (
                "uninstall",
                matches!(ServiceCommands::Uninstall, ServiceCommands::Uninstall),
            ),
        ];

        for (cmd_name, _) in commands {
            let cli = Cli::try_parse_from(["albus", "service", cmd_name])
                .unwrap_or_else(|e| panic!("failed to parse service {cmd_name}: {e}"));
            assert!(matches!(cli.command, Some(Commands::Service(_))));
        }

        let cli_install =
            Cli::try_parse_from(["albus", "service", "install", "--mss", "92"]).unwrap();
        match cli_install.command {
            Some(Commands::Service(ServiceArgs {
                command: ServiceCommands::Install(args),
            })) => {
                assert_eq!(args.mss, 92);
            }
            _ => panic!("expected ServiceCommands::Install"),
        }
    }

    #[test]
    fn test_cli_config_subcommands() {
        let cli_get = Cli::try_parse_from(["albus", "config", "get"]).unwrap();
        assert!(matches!(
            cli_get.command,
            Some(Commands::Config(ConfigArgs {
                command: Some(ConfigCommands::Get)
            }))
        ));

        let cli_set = Cli::try_parse_from(["albus", "config", "set", "--mss", "140"]).unwrap();
        match cli_set.command {
            Some(Commands::Config(ConfigArgs {
                command: Some(ConfigCommands::Set(args)),
            })) => {
                assert_eq!(args.mss, 140);
            }
            _ => panic!("expected ConfigCommands::Set"),
        }
    }

    #[test]
    fn test_cli_misc_subcommands() {
        let cli_mon = Cli::try_parse_from(["albus", "monitor"]).unwrap();
        assert!(matches!(cli_mon.command, Some(Commands::Monitor)));

        let cli_clean = Cli::try_parse_from(["albus", "cleanup"]).unwrap();
        assert!(matches!(cli_clean.command, Some(Commands::Cleanup)));

        let cli_res_list = Cli::try_parse_from(["albus", "resolvers", "list"]).unwrap();
        match cli_res_list.command {
            Some(Commands::Resolvers(ResolversArgs {
                command: Some(ResolversCommands::List),
            })) => {}
            _ => panic!("expected ResolversCommands::List"),
        }

        let cli_res_show = Cli::try_parse_from(["albus", "resolvers", "show", "quad9"]).unwrap();
        match cli_res_show.command {
            Some(Commands::Resolvers(ResolversArgs {
                command: Some(ResolversCommands::Show { name }),
            })) => {
                assert_eq!(name, "quad9");
            }
            _ => panic!("expected ResolversCommands::Show"),
        }
    }

    #[test]
    fn test_cli_parse_optional_ipv4() {
        assert_eq!(
            parse_optional_ipv4("1.1.1.1").unwrap(),
            Ipv4Addr::new(1, 1, 1, 1)
        );
        assert_eq!(
            parse_optional_ipv4(" 8.8.8.8 ").unwrap(),
            Ipv4Addr::new(8, 8, 8, 8)
        );
        assert!(parse_optional_ipv4("").is_err());
        assert!(parse_optional_ipv4("   ").is_err());
        assert!(parse_optional_ipv4("999.999.999.999").is_err());
        assert!(parse_optional_ipv4("invalid-ip").is_err());
    }

    #[test]
    fn test_cli_invalid_flag_rejected() {
        assert!(Cli::try_parse_from(["albus", "--non-existent-flag"]).is_err());
    }
}
