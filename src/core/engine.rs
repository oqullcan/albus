//! lifecycle orchestrator coordinating doh dns proxy, iptables filtering, and ebpf desync engine.

use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, warn};

use crate::app::config::Config;
use crate::core::autottl::{AutoTtlConfig, AutoTtlEstimator};
use crate::core::ebpf::{has_service_privileges, BpfManager, BpfManagerConfig};
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
    applied_quic: bool,
    applied_stun: bool,
    applied_kill: bool,
    applied_dns: bool,
}

impl Engine {
    // initializes engine subsystems and configures runtime parameters
    pub fn new(cfg: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        cfg.validate()?;
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
            applied_quic: false,
            applied_stun: false,
            applied_kill: false,
            applied_dns: false,
        })
    }

    // starts all subsystems and blocks awaiting sigint or sigterm termination signals
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // L1 rootless-ready gate: uid 0 OR the dedicated service user holding
        // the unit's capability set (see has_service_privileges). Plain
        // unprivileged users are still refused before anything is touched.
        if !has_service_privileges() {
            return Err(
                "albus requires root or the albus service user (see User= in albus.service) — run with sudo".into(),
            );
        }

        // EBPF-01: every firewall control below is now fallible, and the
        // `applied_*` flags and the "... ACTIVE" journal lines are bound to the
        // kernel-side outcome. Previously these calls returned `()`, so a
        // non-zero iptables exit (xtables lock contention, a legacy/nft
        // backend mismatch, a missing xt_comment or REJECT target, a rejected
        // transaction) was indistinguishable from success and the daemon
        // recorded a lie the operator would later read as the control being in
        // place.

        // 1. insert iptables rules dropping udp 443 (quic fallback) and stun ports (webrtc leak protection)
        //
        // QUIC forcing and STUN blocking are evasion *hygiene*, not a
        // confidentiality control: if the kernel refuses them the daemon is
        // still correct, just less opaque. Warn with the real reason, leave
        // applied_* false, and keep going.
        if self.cfg.block_quic {
            match block_quic() {
                Ok(()) => self.applied_quic = true,
                Err(e) => warn!(
                    "QUIC (UDP 443) block NOT installed ({}). DPI evasion is degraded, \
                     but DNS confidentiality is unaffected; continuing.",
                    e
                ),
            }
        }
        if self.cfg.block_stun {
            match block_stun() {
                Ok(()) => self.applied_stun = true,
                Err(e) => warn!(
                    "WebRTC STUN block NOT installed ({}). Browser IP leakage \
                     protection is unavailable; continuing.",
                    e
                ),
            }
        }

        // 2. kill-switch applies even without DoH (fail-closed for plaintext DNS)
        //
        // This one IS a confidentiality control, and it can be the only one --
        // that is the whole point of "applies even without DoH". Continuing
        // after a failed install would point /etc/resolv.conf at the daemon
        // while non-loopback plaintext DNS is wide open, and then log
        // "Kill-Switch ACTIVE". Abort instead: this runs BEFORE resolv.conf is
        // touched, so the machine is left exactly as we found it rather than
        // half-configured, and the operator gets the kernel-side reason.
        if self.cfg.kill_switch {
            match enable_kill_switch() {
                Ok(()) => self.applied_kill = true,
                Err(e) => {
                    // Undo whatever did install, so we do not leave a partial
                    // kill-switch behind on the way out.
                    disable_kill_switch();
                    return Err(format!(
                        "DNS kill-switch requested but the packet filter refused the rule \
                         ({}). Refusing to start and claim plaintext DNS is blocked when \
                         it is not. Your DNS configuration is unchanged.",
                        e
                    )
                    .into());
                }
            }
        }

        // 3. bind udp listener on 127.0.0.1:53 and update /etc/resolv.conf
        if let Some(ref dns) = self.dns_server {
            dns.start().await?;
            if let Err(e) = set_system_dns() {
                // full revert: resolvectl links may already be pointed at loopback
                crate::dns::system::revert_resolvectl_dns();
                let _ = restore_system_dns();
                dns.stop();
                self.cleanup_firewall_only();
                return Err(format!("failed to configure /etc/resolv.conf: {}", e).into());
            }
            self.applied_dns = true;
            info!("encrypted DNS active");
        }

        // 4. attach ebpf sock_ops bytecode to cgroup v2 hierarchy and spawn raw socket injector
        match self.bpf_manager.start(self.dns_server.clone()) {
            Ok(_) => {
                info!("eBPF sock_ops DPI bypass engine active");
            }
            Err(e) => {
                warn!(
                    "eBPF sock_ops engine unavailable ({}). Encrypted DNS remains active, packet-level DPI bypass disabled",
                    e
                );
                if self.cfg.network_lockdown {
                    // Lockdown is the last line of defence: with the eBPF engine
                    // down it is the only thing standing between the user and an
                    // unfragmented, undecoyed connection. If it cannot be
                    // installed then there is no packet-level control at all,
                    // and continuing would mean running with nothing while
                    // reporting otherwise. Stop and say so.
                    match enable_network_lockdown() {
                        Ok(()) => {}
                        Err(e) => {
                            self.cleanup_firewall_only();
                            return Err(format!(
                                "eBPF DPI bypass is unavailable AND network lockdown could not \
                                 be installed ({}). With no DPI bypass and no packet filter there \
                                 is no protection left to provide; refusing to run.",
                                e
                            )
                            .into());
                        }
                    }
                } else {
                    warn!("network_lockdown is OFF — web traffic will flow without DPI bypass. Enable with --network-lockdown for fail-closed mode");
                }
            }
        }

        info!("albus is running — press Ctrl+C to stop");

        // 5. block awaiting asynchronous signal trap (ctrl-c, sigterm, sigusr1 cache flush, or sighup config reload)
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
                    info!("SIGHUP received — reloading eBPF maps live (firewall/DNS changes require restart)...");
                    self.reload_config();
                }
            }
        }

        self.shutdown();
        Ok(())
    }

    // reloads eBPF-relevant configuration live without process restart.
    // NOTE: firewall/DNS-affecting flags (kill_switch, block_quic/stun, doh_enabled,
    // block_ipv6, dnssec, cgroup_path, network_lockdown) are NOT hot-reloaded —
    // they require a restart. We deliberately keep old values for those.
    pub fn reload_config(&mut self) {
        let new_cfg = Config::load_or_default();
        if let Err(e) = new_cfg.validate() {
            warn!("ignoring invalid reloaded config: {}", e);
            return;
        }
        info!(
            "Reloading eBPF maps from {}",
            Config::default_config_path().display()
        );

        if new_cfg.kill_switch != self.cfg.kill_switch
            || new_cfg.block_quic != self.cfg.block_quic
            || new_cfg.block_stun != self.cfg.block_stun
            || new_cfg.doh_enabled != self.cfg.doh_enabled
            || new_cfg.block_ipv6 != self.cfg.block_ipv6
            || new_cfg.cgroup_path != self.cfg.cgroup_path
            || new_cfg.network_lockdown != self.cfg.network_lockdown
        {
            warn!("firewall/DNS-affecting options changed — restart albus to apply (hot-reload skipped for those)");
        }

        let exclude_ips = if self.cfg.doh_enabled {
            extract_upstream_ips(&self.cfg.doh_upstream, &self.cfg.doh_bootstrap_ips)
        } else {
            Vec::new()
        };
        let exclude_ips_v6 = if self.cfg.doh_enabled {
            extract_upstream_ips_v6(&self.cfg.doh_upstream, &[])
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

        // only hot-reload eBPF-safe fields; keep firewall/DNS identity from running cfg
        let bpf_cfg = BpfManagerConfig {
            mss: new_cfg.mss,
            min_mss: new_cfg.min_mss,
            restore_mss: new_cfg.restore_mss,
            restore_after_bytes: new_cfg.restore_after_bytes,
            ports: new_cfg.ports.clone(),
            exclude_ips,
            exclude_ips_v6,
            cgroup_path: self.cfg.cgroup_path.clone(),
            fake_ttl: new_cfg.fake_ttl,
            fake_sni: new_cfg.fake_sni.clone(),
            fake_bad_checksum: new_cfg.fake_bad_checksum,
            pqc: new_cfg.pqc,
            auto_ttl_estimator,
        };

        if let Err(e) = self.bpf_manager.reload_maps(&bpf_cfg) {
            warn!("Failed to reload eBPF maps dynamically: {}", e);
        } else {
            // FP-16: honest log — exclusion IPs and cgroup are intentionally
            // NOT reloaded (restart-required); only ports/MSS-class fields are.
            info!(
                "Live eBPF map reload successful (target ports & MSS updated; exclusion IPs/cgroup unchanged — restart to apply those)"
            );
        }

        // merge only hot-reloadable fields into running cfg
        self.cfg.mss = new_cfg.mss;
        self.cfg.min_mss = new_cfg.min_mss;
        self.cfg.restore_mss = new_cfg.restore_mss;
        self.cfg.restore_after_bytes = new_cfg.restore_after_bytes;
        self.cfg.ports = new_cfg.ports;
        self.cfg.fake_ttl = new_cfg.fake_ttl;
        self.cfg.fake_sni = new_cfg.fake_sni;
        self.cfg.fake_bad_checksum = new_cfg.fake_bad_checksum;
        self.cfg.auto_ttl = new_cfg.auto_ttl;
        self.cfg.min_ttl = new_cfg.min_ttl;
        self.cfg.max_ttl = new_cfg.max_ttl;
        self.cfg.pqc = new_cfg.pqc;
        self.cfg.verbose = new_cfg.verbose;
    }

    fn cleanup_firewall_only(&mut self) {
        // EBPF-01: the delete helpers return the number of rules they actually
        // removed so a failed teardown is visible instead of silently leaving
        // rules behind.
        let mut removed = 0usize;
        if self.cfg.network_lockdown {
            removed += disable_network_lockdown();
        }
        if self.applied_kill {
            removed += disable_kill_switch();
            self.applied_kill = false;
        }
        if self.applied_stun {
            removed += unblock_stun();
            self.applied_stun = false;
        }
        if self.applied_quic {
            removed += unblock_quic();
            self.applied_quic = false;
        }
        if self.applied_quic || self.applied_stun || self.applied_kill || self.cfg.network_lockdown
        {
            info!(
                "firewall teardown removed {} albus rule(s) (bounded delete: residue, if \
                 any, is pre-hardening comment-less and is documented, not blindly removed)",
                removed
            );
        }
    }

    // restores kernel socket options, removes iptables rules, and restores system dns
    // order: stop injection first, then DNS restore, then firewall open (no leak window)
    pub fn shutdown(&mut self) {
        self.bpf_manager.stop();

        if self.applied_dns {
            if let Err(e) = restore_system_dns() {
                warn!("failed to restore system DNS: {}", e);
            } else {
                info!("system DNS restored");
            }
            self.applied_dns = false;
        }
        if let Some(ref dns) = self.dns_server {
            dns.stop();
        }

        self.cleanup_firewall_only();
        if self.cfg.network_lockdown {
            disable_network_lockdown();
        }
    }
}
