//! lifecycle orchestrator coordinating doh dns proxy, iptables filtering, and ebpf desync engine.

use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, warn};

use crate::app::config::Config;
use crate::core::autottl::{AutoTtlConfig, AutoTtlEstimator};
use crate::core::ebpf::{is_root, BpfManager, BpfManagerConfig};
use crate::core::firewall::{
    block_quic, block_stun, disable_kill_switch, disable_network_lockdown, enable_kill_switch,
    enable_network_lockdown, unblock_quic, unblock_stun,
};
use crate::dns::{
    extract_upstream_ips, extract_upstream_ips_v6, restore_system_dns, set_system_dns, DnsServer,
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
        let exclude_ips = if cfg.doh_enabled {
            extract_upstream_ips(&cfg.doh_upstream, &cfg.doh_bootstrap_ips)
        } else {
            Vec::new()
        };
        let exclude_ips_v6 = if cfg.doh_enabled {
            extract_upstream_ips_v6(&cfg.doh_upstream, &[])
        } else {
            Vec::new()
        };

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
            restore_mss: cfg.restore_mss,
            restore_after_bytes: cfg.restore_after_bytes,
            ports: cfg.ports.clone(),
            exclude_ips,
            exclude_ips_v6,
            cgroup_path: cfg.cgroup_path.clone(),
            fake_ttl: cfg.fake_ttl,
            fake_sni: cfg.fake_sni.clone(),
            fake_bad_checksum: cfg.fake_bad_checksum,
            pqc: cfg.pqc,
            auto_ttl_estimator,
        };

        // instantiate local doh proxy server on 127.0.0.1:53
        let dns_server = if cfg.doh_enabled {
            Some(Arc::new(DnsServer::new(
                &cfg.doh_upstream,
                &cfg.doh_bootstrap_ips,
                cfg.block_ipv6,
                cfg.dnssec,
                cfg.pqc,
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
        info!("Reloading configuration from {}", Config::default_config_path().display());

        let exclude_ips = if new_cfg.doh_enabled {
            extract_upstream_ips(&new_cfg.doh_upstream, &new_cfg.doh_bootstrap_ips)
        } else {
            Vec::new()
        };
        let exclude_ips_v6 = if new_cfg.doh_enabled {
            extract_upstream_ips_v6(&new_cfg.doh_upstream, &[])
        } else {
            Vec::new()
        };

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
            restore_mss: new_cfg.restore_mss,
            restore_after_bytes: new_cfg.restore_after_bytes,
            ports: new_cfg.ports.clone(),
            exclude_ips,
            exclude_ips_v6,
            cgroup_path: new_cfg.cgroup_path.clone(),
            fake_ttl: new_cfg.fake_ttl,
            fake_sni: new_cfg.fake_sni.clone(),
            fake_bad_checksum: new_cfg.fake_bad_checksum,
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
