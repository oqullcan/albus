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
    block_quic, block_stun, disable_kill_switch, disable_network_lockdown, enable_kill_switch,
    enable_network_lockdown, unblock_quic, unblock_stun,
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
}

impl Engine {
    // initializes engine subsystems and configures runtime parameters
    pub fn new(cfg: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
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
            exclude_ips,
            exclude_ips_v6,
            cgroup_path: cfg.cgroup_path.clone(),
            fake_ttl: cfg.fake_ttl,
            fake_sni: cfg.fake_sni.clone(),
            fake_bad_checksum: cfg.fake_bad_checksum,
            fake_seq_offset: cfg.fake_seq_offset,
            pqc: cfg.pqc,
            auto_ttl_estimator,
        };

        // instantiate local doh proxy server on 127.0.0.1:53
        let dns_server = if cfg.doh_enabled {
            let mut cloak = CloakEngine::new();
            for (domain, ip_str) in &cfg.cloaking_rules {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    cloak.add_cloak_rule(domain, ip);
                } else {
                    warn!(domain = %domain, ip = %ip_str, "Invalid IP address in cloaking_rules");
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
                std::path::PathBuf::from("/run/albus/blocklist.bin")
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

            // initialize IP filter
            let blocked_ips: Vec<std::net::IpAddr> = cfg
                .blocked_ips
                .iter()
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            let ip_filter_arc = Arc::new(IpFilter::new(cfg.block_bogons, blocked_ips));

            // initialize atomic DNS statistics
            let dns_stats = DnsStats::new();

            // initialize local DoH address and query audit logger
            let local_doh_addr: SocketAddr = cfg
                .local_doh_addr
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:8053".parse().unwrap());

            let query_logger = if cfg.query_log {
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
                let path = cfg.query_log_path.as_deref().unwrap_or(if cfg.ram_only {
                    "/run/albus/query.log"
                } else {
                    "/var/log/albus/query.log"
                });
                Some(crate::dns::logger::QueryLogger::start(
                    path,
                    ip_crypt,
                    10 * 1024 * 1024,
                    5,
                ))
            } else {
                None
            };

            let odoh_client = if cfg.odoh_enabled {
                let relay = cfg
                    .odoh_relay
                    .as_deref()
                    .unwrap_or(crate::dns::DEFAULT_ODOH_RELAY);
                let target = cfg
                    .odoh_target
                    .as_deref()
                    .unwrap_or(crate::dns::DEFAULT_ODOH_TARGET);
                match crate::dns::ODoHClient::new(relay, target, reqwest::Client::new()) {
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

            Some(Arc::new(DnsServer::new(
                &cfg.doh_upstream,
                &cfg.doh_bootstrap_ips,
                cfg.block_ipv6,
                cfg.dnssec,
                cfg.pqc,
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
            )?))
        } else {
            None
        };

        let bpf_manager = BpfManager::new(bpf_cfg);

        Ok(Self {
            cfg,
            dns_server,
            bpf_manager,
        })
    }

    // starts all subsystems and blocks awaiting sigint or sigterm termination signals
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !is_root() {
            return Err("albus requires root privileges — run with sudo".into());
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
                    disable_network_lockdown();
                }
                return Err(format!("failed to configure /etc/resolv.conf: {}", e).into());
            }
            info!("encrypted DNS active");
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
                    enable_network_lockdown();
                }
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
                    self.reload_config();
                }
            }
        }

        self.shutdown();
        Ok(())
    }

    // reloads persistent configuration and updates ebpf kernel maps live without process restart
    pub fn reload_config(&mut self) {
        let new_cfg = Config::load_or_default();
        info!(
            "Reloading configuration from {}",
            Config::default_config_path().display()
        );

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
            exclude_ips,
            exclude_ips_v6,
            cgroup_path: new_cfg.cgroup_path.clone(),
            fake_ttl: new_cfg.fake_ttl,
            fake_sni: new_cfg.fake_sni.clone(),
            fake_bad_checksum: new_cfg.fake_bad_checksum,
            fake_seq_offset: new_cfg.fake_seq_offset,
            pqc: new_cfg.pqc,
            auto_ttl_estimator,
        };

        if let Err(e) = self.bpf_manager.reload_maps(&bpf_cfg) {
            warn!("Failed to reload eBPF maps dynamically: {}", e);
        } else {
            info!("Live eBPF map reload successful (target ports & exclusion IPs updated)");
        }

        self.cfg = new_cfg;
    }

    // restores kernel socket options, removes iptables rules, and restores system dns
    pub fn shutdown(&mut self) {
        if self.cfg.network_lockdown {
            disable_network_lockdown();
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
