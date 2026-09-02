//! lifecycle orchestrator coordinating doh dns proxy, iptables filtering, and ebpf desync engine.

use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, warn};

use crate::app::config::Config;
use crate::core::autottl::{AutoTtlConfig, AutoTtlEstimator};
use crate::core::ebpf::{is_root, BpfManager, BpfManagerConfig};
use crate::core::firewall::{block_quic, unblock_quic};
use crate::dns::{extract_upstream_ips, restore_system_dns, set_system_dns, DnsServer};

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
            restore_mss: cfg.restore_mss,
            restore_after_bytes: cfg.restore_after_bytes,
            ports: cfg.ports.clone(),
            exclude_ips,
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

        // 1. insert iptables rule dropping udp 443 to force tcp fallback
        if self.cfg.block_quic {
            block_quic();
        }

        // 2. bind udp listener on 127.0.0.1:53 and update /etc/resolv.conf
        if let Some(ref dns) = self.dns_server {
            dns.start().await?;
            if let Err(e) = set_system_dns() {
                dns.stop();
                if self.cfg.block_quic {
                    unblock_quic();
                }
                return Err(format!("failed to configure /etc/resolv.conf: {}", e).into());
            }
            info!("encrypted DNS active");
        }

        // 3. attach ebpf sock_ops bytecode to cgroup v2 hierarchy and spawn raw socket injector
        if let Err(e) = self.bpf_manager.start(self.dns_server.clone()) {
            if self.cfg.doh_enabled {
                let _ = restore_system_dns();
                if let Some(ref dns) = self.dns_server {
                    dns.stop();
                }
            }
            if self.cfg.block_quic {
                unblock_quic();
            }
            return Err(e);
        }

        info!("albus is running — press Ctrl+C to stop");

        // 4. block awaiting asynchronous signal trap
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received, shutting down...");
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received, shutting down...");
            }
        }

        self.shutdown();
        Ok(())
    }

    // restores kernel socket options, removes iptables rules, and restores system dns
    pub fn shutdown(&mut self) {
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
