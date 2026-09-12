//! lifecycle orchestrator coordinating doh dns proxy, iptables filtering, and ebpf desync engine.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::app::config::Config;
use crate::core::autottl::{resolve_optimal_restore_mss, AutoTtlConfig, AutoTtlEstimator};
use crate::core::ebpf::{is_root, BpfManager, BpfManagerConfig};
use crate::core::firewall::{
    block_quic, block_stun, disable_kill_switch, disable_network_lockdown,
    disable_network_lockdown_with_exemptions, enable_kill_switch, enable_network_lockdown,
    enable_network_lockdown_with_exemptions, unblock_quic, unblock_stun,
};
use crate::dns::{
    build_seed_blocklist, extract_upstream_ips, extract_upstream_ips_v6, fetch_and_compile_hagezi,
    restore_system_dns, set_system_dns, CloakEngine, CompactBlocklist, DnsServer, DnsStats,
    DomainAllowlist, IpFilter,
};

pub struct Engine {
    cfg: Config,
    dns_server: Option<Arc<DnsServer>>,
    bpf_manager: BpfManager,
    upstream_ips: Vec<std::net::Ipv4Addr>,
    upstream_ips_v6: Vec<std::net::Ipv6Addr>,
}

impl Engine {
    // initializes engine subsystems and configures runtime parameters
    pub fn new(mut cfg: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        cfg.apply_defense_profile();

        // resolve upstream doh resolver ips to populate bpf exclusion map
        let mut exclude_ips = if cfg.doh_enabled {
            extract_upstream_ips(&cfg.doh_upstream, &cfg.doh_bootstrap_ips)
        } else {
            Vec::new()
        };
        let mut exclude_ips_v6 = if cfg.doh_enabled {
            extract_upstream_ips_v6(&cfg.doh_upstream, &[])
        } else {
            Vec::new()
        };

        if cfg.odoh_enabled {
            let relay = cfg
                .odoh_relay
                .as_deref()
                .unwrap_or(crate::dns::DEFAULT_ODOH_RELAY);
            exclude_ips.extend(extract_upstream_ips(relay, &[]));
            exclude_ips_v6.extend(extract_upstream_ips_v6(relay, &[]));
        }

        // configure dynamic auto-ttl estimator with boundary bounds
        let auto_ttl_config = AutoTtlConfig {
            enabled: cfg.auto_ttl,
            default_ttl: cfg.fake_ttl,
            min_ttl: cfg.min_ttl,
            max_ttl: cfg.max_ttl,
        };
        let auto_ttl_estimator = AutoTtlEstimator::new(auto_ttl_config);

        let ja4_profile = cfg
            .ja4_mimic
            .as_deref()
            .and_then(crate::core::ja4_mimic::BrowserProfile::from_str);
        let stack_morph_profile = cfg
            .stack_morph
            .as_deref()
            .and_then(crate::core::stack_morph::OsProfile::from_str);
        let anti_injection_filter = if cfg.anti_injection {
            Some(Arc::new(
                crate::core::anti_injection::AntiInjectionFilter::new(
                    cfg.anti_injection_ttl_tolerance,
                ),
            ))
        } else {
            None
        };

        // assemble bpf manager configuration parameters
        let bpf_cfg = BpfManagerConfig {
            mss: cfg.mss,
            min_mss: cfg.min_mss,
            restore_mss: if cfg.restore_mss == 0 {
                resolve_optimal_restore_mss()
            } else {
                cfg.restore_mss
            },
            restore_after_bytes: cfg.restore_after_bytes,
            ports: cfg.ports.clone(),
            exclude_ips: exclude_ips.clone(),
            exclude_ips_v6: exclude_ips_v6.clone(),
            cgroup_path: cfg.cgroup_path.clone(),
            fake_ttl: cfg.fake_ttl,
            fake_sni: cfg.fake_sni.clone(),
            fake_bad_checksum: cfg.fake_bad_checksum,
            fake_seq_offset: cfg.fake_seq_offset,
            fake_window_size: cfg.fake_window_size,
            fake_tcp_flags: cfg
                .fake_tcp_flags
                .as_deref()
                .and_then(crate::core::rawsock::packet::parse_tcp_flags),
            pqc: cfg.pqc,
            ja4_mimic: cfg.ja4_mimic.is_some(),
            ja4_profile,
            stack_morph: cfg.stack_morph.is_some(),
            stack_morph_profile,
            auto_ttl_estimator,
            anti_injection: anti_injection_filter.clone(),
        };

        // instantiate local doh proxy server on 127.0.0.1:53
        let dns_server = if cfg.doh_enabled {
            let mut cloak = CloakEngine::new().with_cloak_ttl(cfg.cloak_ttl);
            if cfg.load_system_hosts {
                match cloak.load_hosts_file("/etc/hosts") {
                    Ok(n) => info!(
                        count = n,
                        "Loaded system /etc/hosts into DNS cloaking & reverse PTR engine"
                    ),
                    Err(e) => debug!("Could not read /etc/hosts: {}", e),
                }
            }
            if let Some(ref path) = cfg.cloaking_rules_path {
                if std::path::Path::new(path).exists() {
                    match cloak.load_cloaking_rules_file(path) {
                        Ok(n) => info!(count = n, path = %path, "Loaded cloaking rules from file"),
                        Err(e) => warn!("Failed to load cloaking rules from {}: {}", path, e),
                    }
                }
            }
            for (domain, target_str) in &cfg.cloaking_rules {
                if let Ok(ip) = target_str.parse::<IpAddr>() {
                    cloak.add_cloak_rule(domain, ip);
                } else {
                    cloak.add_cname_rule(domain, target_str);
                }
            }
            for (domain, addr_str) in &cfg.forwarding_rules {
                let addr_res = if addr_str.contains(':') {
                    addr_str.parse::<SocketAddr>()
                } else {
                    format!("{}:53", addr_str).parse::<SocketAddr>()
                };
                match addr_res {
                    Ok(addr) => cloak.add_forward_rule(domain, addr),
                    Err(_) => {
                        warn!(domain = %domain, target = %addr_str, "Invalid SocketAddr in forwarding_rules")
                    }
                }
            }

            // initialize compact blocklist (seed or cached binary)
            let cache_path = if let Some(ref p) = cfg.blocklist_path {
                std::path::PathBuf::from(p)
            } else if cfg.ram_only {
                Config::volatile_runtime_dir().join("blocklist.bin")
            } else {
                std::path::PathBuf::from("/var/lib/albus/blocklist.bin")
            };

            let initial_blocklist = if !cfg.blocklist {
                CompactBlocklist::empty()
            } else if cache_path.exists() {
                match CompactBlocklist::load_from_file(&cache_path) {
                    Ok(bl) => {
                        info!(rules = bl.total_domains, path = %cache_path.display(), "loaded cached HaGeZi blocklist");
                        bl
                    }
                    Err(e) => {
                        debug!("failed to load cached blocklist: {}; using seed list", e);
                        build_seed_blocklist()
                    }
                }
            } else {
                build_seed_blocklist()
            };

            let blocklist_arc = Arc::new(RwLock::new(initial_blocklist));

            // if blocklist is enabled and no custom static path was supplied, fetch latest HaGeZi in background
            if cfg.blocklist && cfg.blocklist_path.is_none() {
                let bl_updater = blocklist_arc.clone();
                let cp = cache_path.clone();
                tokio::spawn(async move {
                    match fetch_and_compile_hagezi(&cp).await {
                        Ok(compiled) => {
                            let mut lock = bl_updater.write().await;
                            *lock = compiled;
                            info!("live DNS blocklist upgraded with latest HaGeZi Multi PRO + TIF feeds");
                        }
                        Err(e) => {
                            debug!("HaGeZi background feed update deferred: {}", e);
                        }
                    }
                });
            }

            // initialize domain allowlist
            let mut allowlist = DomainAllowlist::from_iter(&cfg.allow_domains);
            if let Some(path) = &cfg.allowlist_path {
                match DomainAllowlist::from_file(path) {
                    Ok(al) => {
                        info!(rules = al.len(), path = %path, "loaded domain allowlist from file");
                        for pat in &cfg.allow_domains {
                            allowlist.add(pat);
                        }
                        allowlist = al;
                    }
                    Err(e) => warn!("failed to load allowlist file {}: {}", path, e),
                }
            }
            let allowlist_arc = Arc::new(RwLock::new(allowlist));

            // initialize IP filter with CIDR, wildcard, allowlist, and file loading
            let mut ip_filter = IpFilter::new(cfg.block_bogons, vec![]);
            for raw in &cfg.blocked_ips {
                if let Some(rule) = crate::dns::ip_filter::IpRule::parse(raw) {
                    ip_filter.add_blocked_rule(rule);
                }
            }
            for raw in &cfg.allowed_ips {
                if let Some(rule) = crate::dns::ip_filter::IpRule::parse(raw) {
                    ip_filter.add_allowed_rule(rule);
                }
            }
            if let Some(ref path) = cfg.blocked_ips_file {
                if let Ok(count) = ip_filter.load_blocked_file(path) {
                    info!(count, path = %path, "Loaded blocked IP rules from file");
                }
            }
            if let Some(ref path) = cfg.allowed_ips_file {
                if let Ok(count) = ip_filter.load_allowed_file(path) {
                    info!(count, path = %path, "Loaded allowed IP rules from file");
                }
            }
            let ip_filter_arc = Arc::new(ip_filter);

            // initialize captive portal map
            let mut captive_map = crate::dns::captive::CaptiveMap::new();
            if let Some(ref path) = cfg.captive_portals_map_file {
                if let Ok(count) = captive_map.load_from_file(path) {
                    info!(count, path = %path, "Loaded captive portal map entries from file");
                }
            }
            let captive_map_arc = Arc::new(captive_map);

            // initialize atomic DNS statistics
            let dns_stats = DnsStats::new();

            // initialize local DoH address and query audit logger
            let local_doh_addr: SocketAddr = cfg
                .local_doh_addr
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:8053".parse().unwrap());

            let query_logger = if cfg.query_log
                || cfg.nx_log
                || cfg.blocked_names_log_path.is_some()
                || cfg.blocked_ips_log_path.is_some()
                || cfg.allowed_names_log_path.is_some()
                || cfg.allowed_ips_log_path.is_some()
            {
                let ip_crypt = if let Some(ref hex) = cfg.ipcrypt_key {
                    match crate::dns::ipcrypt::IpCrypt::from_hex(hex) {
                        Ok(c) => Some(Arc::new(c)),
                        Err(e) => {
                            warn!(
                                "invalid ipcrypt key: {}; logging client IPs in plaintext",
                                e
                            );
                            None
                        }
                    }
                } else {
                    None
                };
                let main_path = if cfg.query_log {
                    Some(std::path::PathBuf::from(
                        cfg.query_log_path.clone().unwrap_or_else(|| {
                            if cfg.ram_only {
                                Config::volatile_runtime_dir()
                                    .join("query.log")
                                    .to_string_lossy()
                                    .to_string()
                            } else {
                                "/var/log/albus/query.log".to_string()
                            }
                        }),
                    ))
                } else {
                    None
                };
                let nx_path = if cfg.nx_log {
                    Some(std::path::PathBuf::from(
                        cfg.nx_log_path.clone().unwrap_or_else(|| {
                            if cfg.ram_only {
                                Config::volatile_runtime_dir()
                                    .join("nx.log")
                                    .to_string_lossy()
                                    .to_string()
                            } else {
                                "/var/log/albus/nx.log".to_string()
                            }
                        }),
                    ))
                } else {
                    None
                };
                let opts = crate::dns::logger::LoggerOptions {
                    main_path,
                    nx_path,
                    blocked_names_path: cfg
                        .blocked_names_log_path
                        .as_ref()
                        .map(std::path::PathBuf::from),
                    blocked_ips_path: cfg
                        .blocked_ips_log_path
                        .as_ref()
                        .map(std::path::PathBuf::from),
                    allowed_names_path: cfg
                        .allowed_names_log_path
                        .as_ref()
                        .map(std::path::PathBuf::from),
                    allowed_ips_path: cfg
                        .allowed_ips_log_path
                        .as_ref()
                        .map(std::path::PathBuf::from),
                    main_format: crate::dns::logger::LogFormat::parse_lenient(
                        &cfg.query_log_format,
                    ),
                    nx_format: crate::dns::logger::LogFormat::parse_lenient(&cfg.nx_log_format),
                    blocked_names_format: crate::dns::logger::LogFormat::parse_lenient(
                        &cfg.blocked_names_log_format,
                    ),
                    blocked_ips_format: crate::dns::logger::LogFormat::parse_lenient(
                        &cfg.blocked_ips_log_format,
                    ),
                    allowed_names_format: crate::dns::logger::LogFormat::parse_lenient(
                        &cfg.allowed_names_log_format,
                    ),
                    allowed_ips_format: crate::dns::logger::LogFormat::parse_lenient(
                        &cfg.allowed_ips_log_format,
                    ),
                    ip_crypt,
                    max_bytes: 10 * 1024 * 1024,
                    max_backups: 5,
                    ignored_qtypes: cfg.ignored_qtypes.clone(),
                    simd_accel: cfg.simd_accel,
                };
                Some(crate::dns::logger::QueryLogger::start_full(opts))
            } else {
                None
            };

            let effective_proxy = cfg.effective_proxy();
            if let Some(ref p) = effective_proxy {
                info!(proxy = %p, "upstream dns queries routed through socks5 proxy");
            }

            let odoh_client = if cfg.odoh_enabled {
                let relay = cfg
                    .odoh_relay
                    .as_deref()
                    .unwrap_or(crate::dns::DEFAULT_ODOH_RELAY);
                let target = cfg
                    .odoh_target
                    .as_deref()
                    .unwrap_or(crate::dns::DEFAULT_ODOH_TARGET);

                let mut client_builder = reqwest::Client::builder();
                if let Some(ref proxy_url) = effective_proxy {
                    if let Ok(p) = reqwest::Proxy::all(proxy_url) {
                        client_builder = client_builder.proxy(p);
                    }
                }
                let http_client = client_builder
                    .build()
                    .unwrap_or_else(|_| reqwest::Client::new());

                match crate::dns::ODoHClient::new(relay, target, http_client) {
                    Ok(c) => {
                        info!(relay = %relay, target = %target, "Oblivious DoH (RFC 9230) client initialized");
                        Some(Arc::new(c))
                    }
                    Err(e) => {
                        warn!(
                            "failed to initialize odoh client (relay: {}, target: {}): {}",
                            relay, target, e
                        );
                        None
                    }
                }
            } else {
                None
            };

            let mut schedule_mgr = crate::dns::ScheduleManager::from_config(&cfg.schedules);
            if let Some(ref path) = cfg.blocklist_path {
                if let Ok(content) = std::fs::read_to_string(path) {
                    schedule_mgr.load_rules_from_text(&content);
                }
            }
            let schedule_manager_arc = Arc::new(RwLock::new(schedule_mgr));

            let edns_client_subnet = cfg.edns_client_subnet.as_deref().and_then(|s| {
                match crate::dns::ClientSubnet::parse_cidr(s) {
                    Ok(subnet) => Some(subnet),
                    Err(e) => {
                        warn!("invalid edns-client-subnet '{}': {}", s, e);
                        None
                    }
                }
            });

            let metrics_addr: SocketAddr = cfg
                .metrics_addr
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:9153".parse().unwrap());

            let tls_auth = match (&cfg.tls_client_cert, &cfg.tls_client_key) {
                (Some(cert_path), Some(key_path)) => {
                    match crate::dns::TlsClientAuth::from_files(cert_path, key_path) {
                        Ok(auth) => {
                            info!(
                                "loaded X.509 client certificate for DoH mTLS from {}",
                                cert_path
                            );
                            Some(Arc::new(auth))
                        }
                        Err(e) => {
                            warn!("failed to load mTLS client certificate/key: {}; proceeding without mTLS", e);
                            None
                        }
                    }
                }
                _ => None,
            };

            let mut fw_engine = crate::dns::ForwardingEngine::new();
            if let Some(ref path) = cfg.forwarding_rules_path {
                if std::path::Path::new(path).exists() {
                    match crate::dns::ForwardingEngine::from_file(path) {
                        Ok(loaded) => {
                            info!("loaded split-dns forwarding rules from {}", path);
                            fw_engine = loaded;
                        }
                        Err(e) => {
                            warn!(
                                "failed to load split-dns forwarding rules from {}: {}",
                                path, e
                            );
                        }
                    }
                } else {
                    debug!(
                        "split-dns forwarding rules file not found (skipped): {}",
                        path
                    );
                }
            }
            for (domain, target) in &cfg.forwarding_rules {
                let mut servers = Vec::new();
                for s in target.split(',') {
                    let s_trim = s.trim();
                    if let Ok(sa) = s_trim.parse::<SocketAddr>() {
                        servers.push(sa);
                    } else if let Ok(ip) = s_trim.parse::<std::net::IpAddr>() {
                        servers.push(SocketAddr::new(ip, 53));
                    }
                }
                if !servers.is_empty() {
                    fw_engine.add_rule(domain, servers);
                }
            }
            let bootstrap_addrs: Vec<SocketAddr> = cfg
                .bootstrap_resolvers
                .iter()
                .filter_map(|s| s.parse::<SocketAddr>().ok())
                .collect();
            fw_engine = fw_engine
                .with_bootstrap_resolvers(bootstrap_addrs)
                .with_socks5_proxy(cfg.socks5_proxy.clone());
            let forwarding_arc = Arc::new(RwLock::new(fw_engine));

            let parsed_listen_addrs: Vec<SocketAddr> = cfg
                .listen_addresses
                .iter()
                .filter_map(|s| s.parse::<SocketAddr>().ok())
                .collect();
            let listen_addrs = if parsed_listen_addrs.is_empty() {
                vec!["127.0.0.1:53".parse().unwrap()]
            } else {
                parsed_listen_addrs
            };

            let mut client_rules_engine =
                crate::dns::ClientRuleEngine::from_configs(&cfg.client_rules);
            if let Some(ref path) = cfg.client_rules_file {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Ok(cfgs) =
                        serde_json::from_str::<Vec<crate::dns::ClientProfileConfig>>(&content)
                    {
                        for p in cfgs {
                            client_rules_engine
                                .add_profile(crate::dns::ClientProfile::from_config(&p));
                        }
                    }
                }
            }
            let client_rules_arc = Arc::new(client_rules_engine);

            let youtube_mode = cfg
                .youtube_restricted_mode
                .as_deref()
                .map(crate::dns::YouTubeMode::parse)
                .unwrap_or(crate::dns::YouTubeMode::None);
            let safesearch_engine = Arc::new(crate::dns::SafeSearchEngine::new(
                cfg.safe_search,
                youtube_mode,
            ));

            let dot_client = if let Some(ref dot_target) = cfg.dot_upstream {
                match crate::dns::DotClient::from_preset_or_addr(dot_target, cfg.pqc) {
                    Ok(client) => {
                        info!(upstream = %dot_target, pqc = cfg.pqc, "Configured DNS-over-TLS (DoT) upstream client");
                        Some(Arc::new(client))
                    }
                    Err(e) => {
                        warn!("Failed to initialize DoT upstream ({}): {}", dot_target, e);
                        None
                    }
                }
            } else {
                None
            };

            let doq_client = if let Some(ref doq_target) = cfg.doq_upstream {
                match crate::dns::DoQClient::from_preset_or_addr(doq_target) {
                    Ok(client) => {
                        info!(upstream = %doq_target, "Configured DNS-over-QUIC (DoQ) upstream client");
                        Some(Arc::new(client))
                    }
                    Err(e) => {
                        warn!("Failed to initialize DoQ upstream ({}): {}", doq_target, e);
                        None
                    }
                }
            } else {
                None
            };

            let dnscrypt_client = if !cfg.dnscrypt_servers.is_empty() {
                let first_server = &cfg.dnscrypt_servers[0];
                let relay_addr = if !cfg.dnscrypt_relays.is_empty() {
                    let r = &cfg.dnscrypt_relays[0];
                    if r.starts_with("sdns://") {
                        crate::dns::stamp::DnsStamp::parse(r)
                            .ok()
                            .and_then(|s| s.server_addr)
                    } else {
                        r.parse::<SocketAddr>().ok()
                    }
                } else {
                    crate::dns::AnonymizedRelay::select_relay_for_server(
                        first_server,
                        &cfg.anonymized_dns_routes,
                        &std::collections::HashMap::new(),
                    )
                };

                if first_server.starts_with("sdns://") {
                    match crate::dns::dnscrypt_client::DnsCryptClient::from_stamp_str(
                        first_server,
                        relay_addr,
                    ) {
                        Ok(client) => {
                            let client = client
                                .with_force_tcp(cfg.force_tcp)
                                .with_cert_ignore_timestamp(cfg.cert_ignore_timestamp)
                                .with_ephemeral_keys(cfg.dnscrypt_ephemeral_keys);
                            info!(upstream = %first_server, relay = ?relay_addr, "Configured DNSCrypt v2 upstream client from stamp");
                            Some(Arc::new(tokio::sync::RwLock::new(client)))
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse DNSCrypt server stamp ({}): {}",
                                first_server, e
                            );
                            None
                        }
                    }
                } else {
                    // Raw address format (e.g. 9.9.9.9:8443)
                    let s_addr = first_server
                        .parse::<SocketAddr>()
                        .unwrap_or_else(|_| "9.9.9.9:8443".parse().unwrap());
                    let provider_name = "2.dnscrypt-cert.quad9.net".to_string();
                    let client = crate::dns::dnscrypt_client::DnsCryptClient::new(
                        s_addr,
                        provider_name,
                        [0u8; 32],
                        relay_addr,
                    )
                    .with_force_tcp(cfg.force_tcp)
                    .with_cert_ignore_timestamp(cfg.cert_ignore_timestamp)
                    .with_ephemeral_keys(cfg.dnscrypt_ephemeral_keys);
                    info!(upstream = %first_server, relay = ?relay_addr, "Configured DNSCrypt v2 upstream client");
                    Some(Arc::new(tokio::sync::RwLock::new(client)))
                }
            } else {
                None
            };

            let local_dot_addr: SocketAddr = cfg
                .local_dot_addr
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:853".parse().unwrap());

            Some(Arc::new(
                DnsServer::new(
                    &cfg.doh_upstream,
                    &cfg.doh_bootstrap_ips,
                    cfg.block_ipv6,
                    cfg.dnssec,
                    cfg.pqc,
                    cfg.http3,
                    cfg.dns_racing,
                    cfg.anti_dns_rebinding,
                    cfg.block_undelegated,
                    cfg.edns_padding,
                    Arc::new(cloak),
                    blocklist_arc,
                    allowlist_arc,
                    ip_filter_arc,
                    cfg.uncloak_cnames,
                    cfg.dns64,
                    cfg.netmon,
                    dns_stats,
                    cfg.tcp_listener,
                    cfg.local_doh,
                    local_doh_addr,
                    query_logger,
                    cfg.allowlist_path.clone(),
                    cfg.blocklist_path.clone(),
                    odoh_client,
                    effective_proxy.as_deref(),
                    schedule_manager_arc,
                    edns_client_subnet,
                    cfg.metrics,
                    metrics_addr,
                    tls_auth,
                    forwarding_arc,
                    cfg.forwarding_rules_path.clone(),
                    cfg.tls_key_log_file.clone(),
                    cfg.timeout_load_reduction,
                    cfg.cache_neg_min_ttl,
                    cfg.cache_neg_max_ttl,
                    cfg.cache_min_ttl,
                    cfg.cache_max_ttl,
                    cfg.force_tcp,
                    captive_map_arc,
                )?
                .with_client_rules(client_rules_arc)
                .with_query_meta(cfg.query_meta.clone())
                .with_listen_addresses(listen_addrs)
                .with_max_clients(cfg.max_clients)
                .with_lb_strategy(&cfg.lb_strategy)
                .with_fragments_blocked(cfg.fragments_blocked.clone())
                .with_anonymized_dns_routes(
                    cfg.anonymized_dns_routes.clone(),
                    cfg.skip_incompatible,
                    cfg.direct_cert_fallback,
                )
                .with_local_doh_tls(
                    cfg.local_doh_tls,
                    cfg.local_doh_cert_file.clone(),
                    cfg.local_doh_key_file.clone(),
                )
                .with_blocked_query_response(&cfg.blocked_query_response)
                .with_offline_mode(cfg.offline_mode)
                .with_ignore_system_dns(cfg.ignore_system_dns)
                .with_cloaked_ptr(cfg.cloaked_ptr)
                .with_tls_disable_session_tickets(cfg.tls_disable_session_tickets)
                .with_cert_refresh_delay(cfg.cert_refresh_delay)
                .with_cert_ignore_timestamp(cfg.cert_ignore_timestamp)
                .with_udp_pool(cfg.udp_pool)
                .with_safesearch(safesearch_engine)
                .with_dot_client(dot_client)
                .with_doq_client(doq_client)
                .with_dnscrypt_client(dnscrypt_client)
                .with_randomize_ecs(cfg.randomize_ecs)
                .with_reject_ttl(cfg.reject_ttl)
                .with_optional_anti_injection(anti_injection_filter.clone())
                .with_local_dot(
                    cfg.local_dot,
                    local_dot_addr,
                    cfg.local_dot_cert_file.clone(),
                    cfg.local_dot_key_file.clone(),
                ),
            ))
        } else {
            None
        };

        let bpf_manager = BpfManager::new(bpf_cfg);

        Ok(Self {
            cfg,
            dns_server,
            bpf_manager,
            upstream_ips: exclude_ips,
            upstream_ips_v6: exclude_ips_v6,
        })
    }

    // starts all subsystems and blocks awaiting sigint or sigterm termination signals
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !is_root() {
            return Err("albus requires root privileges — run with sudo".into());
        }

        if let Some(ref prof_str) = self.cfg.defense_profile {
            if let Some(profile) = crate::app::defense_profile::DefenseProfile::from_str(prof_str) {
                info!("activated defense operational profile: {:?}", profile);
            }
        }
        if self.cfg.ja4_mimic.is_some() {
            info!("JA4 TLS ClientHello fingerprint mimicry enabled");
        }
        if self.cfg.stack_morph.is_some() {
            info!("TCP/IP OS stack fingerprint morphing enabled");
        }
        if self.cfg.anti_injection {
            info!(
                ttl_tolerance = self.cfg.anti_injection_ttl_tolerance,
                "stateful middlebox injection defense enabled"
            );
        }
        if self.cfg.simd_accel {
            info!("SIMD / AVX2 cryptographic vectorization enabled");
        }

        // 1. insert iptables rules dropping udp 443 (quic fallback) and stun ports (webrtc leak protection)
        if self.cfg.block_quic {
            block_quic();
        }
        if self.cfg.block_stun {
            block_stun();
        }

        // 2. bind udp listener on 127.0.0.1:53, activate kill-switch, and update /etc/resolv.conf
        if let Some(ref dns) = self.dns_server {
            dns.start().await?;
            if self.cfg.kill_switch {
                enable_kill_switch();
            }
            if let Err(e) = set_system_dns() {
                dns.stop();
                if self.cfg.kill_switch {
                    disable_kill_switch();
                }
                if self.cfg.block_stun {
                    unblock_stun();
                }
                if self.cfg.block_quic {
                    unblock_quic();
                }
                if self.cfg.network_lockdown {
                    disable_network_lockdown_with_exemptions(
                        &self.upstream_ips,
                        &self.upstream_ips_v6,
                    );
                }
                return Err(format!("failed to configure /etc/resolv.conf: {}", e).into());
            }
            info!("encrypted DNS active");

            if self.cfg.web_ui {
                let web_addr: SocketAddr =
                    crate::dns::web_ui::parse_web_ui_addr(&self.cfg.web_ui_addr);
                let auth = match (&self.cfg.web_ui_user, &self.cfg.web_ui_pass) {
                    (Some(u), Some(p)) if !u.trim().is_empty() && !p.trim().is_empty() => {
                        Some((u.clone(), p.clone()))
                    }
                    _ => {
                        // Multi-user security hardening: Never expose unauthenticated dashboard.
                        // Ephemeral secure credentials auto-generated when none configured.
                        let mut token_bytes = [0u8; 16];
                        let _ = aws_lc_rs::rand::fill(&mut token_bytes);
                        let token: String =
                            token_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                        let user = "admin".to_string();
                        info!(
                            user = %user,
                            "Web Monitoring Dashboard enabled without credentials; generated ephemeral password: {}",
                            token
                        );
                        let token_path = crate::app::config::Config::volatile_token_path();
                        if let Some(parent) = token_path.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        let token_content = format!("{}:{}\n", user, token);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt;
                            let _ = std::fs::OpenOptions::new()
                                .write(true)
                                .create(true)
                                .truncate(true)
                                .mode(0o600)
                                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                                .open(&token_path)
                                .and_then(|mut f| {
                                    use std::io::Write;
                                    f.write_all(token_content.as_bytes())?;
                                    f.sync_all()
                                });
                        }
                        #[cfg(not(unix))]
                        {
                            let _ = std::fs::write(token_path, token_content);
                        }
                        Some((user, token))
                    }
                };
                crate::dns::WebUiServer::start(
                    web_addr,
                    dns.stats.clone(),
                    auth,
                    dns.subscribe_shutdown(),
                    Some(dns.clone()),
                );
            }
        }

        // 3. attach ebpf sock_ops bytecode to cgroup v2 hierarchy and spawn raw socket injector
        match self.bpf_manager.start(self.dns_server.clone()) {
            Ok(_) => {
                info!("eBPF sock_ops DPI bypass engine active");
            }
            Err(e) => {
                warn!(
                    "eBPF sock_ops engine unavailable ({}). Entering graceful fallback mode: encrypted DNS remains fully active, packet-level DPI bypass disabled",
                    e
                );
                if self.cfg.network_lockdown {
                    enable_network_lockdown_with_exemptions(
                        &self.upstream_ips,
                        &self.upstream_ips_v6,
                    );
                }
            }
        }

        // 3.1 create PID file if configured
        let _pid_guard =
            self.cfg.pid_file.as_ref().and_then(
                |p| match crate::dns::system::PidFileGuard::create(p) {
                    Ok(guard) => Some(guard),
                    Err(e) => {
                        warn!("failed to create PID file at '{}': {}", p, e);
                        None
                    }
                },
            );

        // 3.2 drop root privileges if user_name is specified in configuration
        if let Some(ref user) = self.cfg.user_name {
            if let Err(e) = crate::dns::system::drop_privileges(user) {
                warn!("failed to drop privileges to user '{}': {}", user, e);
            }
        }

        info!("albus is running — press Ctrl+C to stop");

        // 4. block awaiting asynchronous signal trap (ctrl-c, sigterm, sigusr1 cache flush, or sighup config reload)
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigusr1 = signal(SignalKind::user_defined1())?;
        let mut sighup = signal(SignalKind::hangup())?;

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C received, shutting down...");
                    break;
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received, shutting down...");
                    break;
                }
                _ = sigusr1.recv() => {
                    if let Some(ref dns) = self.dns_server {
                        dns.flush_cache();
                    }
                }
                _ = sighup.recv() => {
                    info!("SIGHUP received — reloading configuration and updating eBPF maps live...");
                    self.reload_config().await;
                }
            }
        }

        self.shutdown();
        Ok(())
    }

    // reloads persistent configuration and updates ebpf kernel maps live without process restart
    pub async fn reload_config(&mut self) {
        let mut new_cfg = Config::load_or_default();
        new_cfg.apply_defense_profile();
        info!(
            "Reloading configuration from {}",
            Config::default_config_path().display()
        );

        if let Some(ref dns) = self.dns_server {
            if let Err(e) = dns.reload_from_config(&new_cfg).await {
                warn!("failed to reload DNS server from config: {}", e);
            }
        }

        let mut exclude_ips = if new_cfg.doh_enabled {
            extract_upstream_ips(&new_cfg.doh_upstream, &new_cfg.doh_bootstrap_ips)
        } else {
            Vec::new()
        };
        let mut exclude_ips_v6 = if new_cfg.doh_enabled {
            extract_upstream_ips_v6(&new_cfg.doh_upstream, &[])
        } else {
            Vec::new()
        };

        if new_cfg.odoh_enabled {
            let relay = new_cfg
                .odoh_relay
                .as_deref()
                .unwrap_or(crate::dns::DEFAULT_ODOH_RELAY);
            exclude_ips.extend(extract_upstream_ips(relay, &[]));
            exclude_ips_v6.extend(extract_upstream_ips_v6(relay, &[]));
        }

        let auto_ttl_config = AutoTtlConfig {
            enabled: new_cfg.auto_ttl,
            default_ttl: new_cfg.fake_ttl,
            min_ttl: new_cfg.min_ttl,
            max_ttl: new_cfg.max_ttl,
        };
        let auto_ttl_estimator = AutoTtlEstimator::new(auto_ttl_config);

        let ja4_profile = new_cfg
            .ja4_mimic
            .as_deref()
            .and_then(crate::core::ja4_mimic::BrowserProfile::from_str);
        let stack_morph_profile = new_cfg
            .stack_morph
            .as_deref()
            .and_then(crate::core::stack_morph::OsProfile::from_str);

        let bpf_cfg = BpfManagerConfig {
            mss: new_cfg.mss,
            min_mss: new_cfg.min_mss,
            restore_mss: if new_cfg.restore_mss == 0 {
                resolve_optimal_restore_mss()
            } else {
                new_cfg.restore_mss
            },
            restore_after_bytes: new_cfg.restore_after_bytes,
            ports: new_cfg.ports.clone(),
            exclude_ips: exclude_ips.clone(),
            exclude_ips_v6: exclude_ips_v6.clone(),
            cgroup_path: new_cfg.cgroup_path.clone(),
            fake_ttl: new_cfg.fake_ttl,
            fake_sni: new_cfg.fake_sni.clone(),
            fake_bad_checksum: new_cfg.fake_bad_checksum,
            fake_seq_offset: new_cfg.fake_seq_offset,
            fake_window_size: new_cfg.fake_window_size,
            fake_tcp_flags: new_cfg
                .fake_tcp_flags
                .as_deref()
                .and_then(crate::core::rawsock::packet::parse_tcp_flags),
            pqc: new_cfg.pqc,
            ja4_mimic: new_cfg.ja4_mimic.is_some(),
            ja4_profile,
            stack_morph: new_cfg.stack_morph.is_some(),
            stack_morph_profile,
            auto_ttl_estimator,
            anti_injection: self
                .dns_server
                .as_ref()
                .and_then(|s| s.anti_injection.clone()),
        };

        if let Err(e) = self.bpf_manager.reload_maps(&bpf_cfg) {
            warn!("Failed to reload eBPF maps dynamically: {}", e);
        } else {
            info!("Live eBPF map reload successful (target ports & exclusion IPs updated)");
        }

        self.upstream_ips = exclude_ips;
        self.upstream_ips_v6 = exclude_ips_v6;
        self.cfg = new_cfg;
    }

    // restores kernel socket options, removes iptables rules, and restores system dns
    pub fn shutdown(&mut self) {
        if self.cfg.network_lockdown {
            disable_network_lockdown_with_exemptions(&self.upstream_ips, &self.upstream_ips_v6);
        }

        if self.cfg.kill_switch {
            disable_kill_switch();
        }

        if self.cfg.block_stun {
            unblock_stun();
        }

        if self.cfg.block_quic {
            unblock_quic();
        }

        if self.cfg.doh_enabled {
            if let Err(e) = restore_system_dns() {
                warn!("failed to restore system DNS: {}", e);
            } else {
                info!("system DNS restored");
            }
            if let Some(ref dns) = self.dns_server {
                dns.stop();
            }
        }

        self.bpf_manager.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_new_and_shutdown_no_doh() {
        let mut cfg = Config::default();
        cfg.doh_enabled = false;
        cfg.block_quic = false;
        cfg.block_stun = false;
        cfg.kill_switch = false;
        cfg.network_lockdown = false;
        cfg.mss = 96;

        let mut engine = Engine::new(cfg).expect("engine initialization should succeed");
        assert_eq!(engine.cfg.mss, 96);
        assert!(engine.dns_server.is_none());

        // Test shutdown
        engine.shutdown();
    }
}
