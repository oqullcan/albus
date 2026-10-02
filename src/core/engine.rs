//! lifecycle orchestrator coordinating doh dns proxy, iptables filtering, and ebpf desync engine.

use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

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
                    if let Err(ce) = disable_kill_switch() {
                        warn!(
                            "kill-switch rollback after a failed install also failed ({}): \
                             residual DROP rules may remain",
                            ce
                        );
                    }
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
                // EBPF-03: only claim "active" when the userspace half can
                // actually receive kernel events. A partial perf-reader set
                // still shrinks TCP_MAXSEG (kernel-side) but silently misses
                // decoy injection for the CPUs without a reader, so the
                // announcement has to say which of the two happened.
                let complete = self.bpf_manager.readers_complete();
                let readers = self.bpf_manager.reader_count();
                if complete {
                    info!(readers = readers, "eBPF sock_ops DPI bypass engine active");
                } else {
                    warn!(
                        readers = readers,
                        "eBPF sock_ops DPI bypass engine DEGRADED — attached and                          fragmenting, but perf readers are missing on some CPUs,                          so decoy ClientHello injection will miss connections                          handled by them"
                    );
                }
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
    //
    // EBPF-02: the commit used to be a block of unconditional field
    // assignments placed AFTER the reload_maps call, on both arms. Two defects
    // shared that block:
    //
    //   1. On failure the daemon's memory adopted a configuration the kernel
    //      had rejected. That directly breaks the invariant `BpfManager::
    //      reload_maps` works hard to hold ("on mid-sequence failure best-effort
    //      restore the old sets so the kernel never sits half-migrated while
    //      memory claims either version"), one level up. The durable consequence
    //      is on the NEXT reload: `reload_maps` uses `&self.cfg` as the delete-set
    //      for `sync_target_ports` / `sync_exclude_ips*`, so a diverged baseline
    //      means any kernel-resident port or excluded IP missing from the
    //      diverged cfg is never deleted and keeps being applied indefinitely,
    //      until a restart.
    //
    //   2. The merge also assigned seven fields the running injector can never
    //      read. fake_ttl, fake_sni, fake_bad_checksum, auto_ttl, min_ttl,
    //      max_ttl and pqc are captured BY VALUE into the worker closure at
    //      start, so no SIGHUP can change the decoy payload, decoy TTL,
    //      bad-checksum flag or PQC set. Recording the new values made the
    //      operator's file and the daemon's memory agree with each other while
    //      neither the kernel maps nor the injected packets did.
    //
    // Both are now structural rather than a matter of placement: the commit
    // lives in `apply_reload`, after the `?`.
    pub fn reload_config(&mut self) {
        let new_cfg = Config::load_or_default();
        if let Err(e) = new_cfg.validate() {
            warn!("ignoring invalid reloaded config: {}", e);
            return;
        }
        if let Err(e) = self.apply_reload(&new_cfg) {
            warn!(
                "Failed to reload eBPF maps dynamically: {} — keeping the previous \
                 configuration in memory (the kernel rejected the new one)",
                e
            );
        }
    }

    /// Applies `new_cfg` to the running engine, committing to memory only after
    /// the kernel has accepted every map push.
    fn apply_reload(
        &mut self,
        new_cfg: &Config,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

        // EBPF-02: these are restart-required for a different reason than the
        // flags above. They are not kernel maps at all — the worker closure
        // captured them BY VALUE at start, so no SIGHUP can change what the
        // running injector emits. Saying only "firewall/DNS options" would leave
        // an operator who changed fake_sni or pqc believing it took effect.
        let mut restart_only = Vec::new();
        if new_cfg.fake_ttl != self.cfg.fake_ttl {
            restart_only.push("fake_ttl");
        }
        if new_cfg.fake_sni != self.cfg.fake_sni {
            restart_only.push("fake_sni");
        }
        if new_cfg.fake_bad_checksum != self.cfg.fake_bad_checksum {
            restart_only.push("fake_bad_checksum");
        }
        if new_cfg.auto_ttl != self.cfg.auto_ttl {
            restart_only.push("auto_ttl");
        }
        if new_cfg.min_ttl != self.cfg.min_ttl {
            restart_only.push("min_ttl");
        }
        if new_cfg.max_ttl != self.cfg.max_ttl {
            restart_only.push("max_ttl");
        }
        if new_cfg.pqc != self.cfg.pqc {
            restart_only.push("pqc");
        }
        if !restart_only.is_empty() {
            warn!(
                "injector-payload options changed ({}): restart albus to apply — these \
                 are captured by value at start and no live reload can change them",
                restart_only.join(", ")
            );
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

        // The `?` is the transaction boundary: on failure nothing below runs and
        // self.cfg keeps describing what the kernel is actually doing.
        self.bpf_manager.reload_maps(&bpf_cfg)?;

        // FP-16: honest log — exclusion IPs and cgroup are intentionally
        // NOT reloaded (restart-required); only ports/MSS-class fields are.
        info!(
            "Live eBPF map reload successful (target ports & MSS updated; exclusion IPs/cgroup unchanged — restart to apply those)"
        );

        // Commit exactly the fields the kernel accepted and the worker closure
        // can observe. Nothing else: the seven injector-payload fields above
        // would make memory disagree with the running process.
        Self::apply_hot_reloadable(&mut self.cfg, new_cfg);
        Ok(())
    }

    /// Copies the SIGHUP-applicable fields from `new_cfg` into the running
    /// configuration.
    ///
    /// EBPF-02: the previous list also included `fake_ttl`, `fake_sni`,
    /// `fake_bad_checksum`, `auto_ttl`, `min_ttl`, `max_ttl` and `pqc`. Those
    /// are captured by value into the injector worker closure when the engine
    /// starts, so no live reload can change them; committing them made the
    /// daemon claim a decoy payload and TTL that were never applied.
    fn apply_hot_reloadable(target: &mut Config, new_cfg: &Config) {
        target.mss = new_cfg.mss;
        target.min_mss = new_cfg.min_mss;
        target.restore_mss = new_cfg.restore_mss;
        target.restore_after_bytes = new_cfg.restore_after_bytes;
        target.ports = new_cfg.ports.clone();
        // `verbose` is read at each log site, so unlike the injector fields it
        // genuinely takes effect without a restart.
        target.verbose = new_cfg.verbose;
    }

    fn cleanup_firewall_only(&mut self) {
        // EBPF-01 / SUPPLY-03: the delete helpers return how many rules they actually
        // removed, or Err when the removal state could not be established. Both
        // are reported: a residual rule is a stranded fail-closed DROP, which is
        // exactly the condition that leaves a host with no outbound network and
        // no explanation.
        let mut removed = 0usize;
        let mut teardown_ok = true;
        let mut steps: Vec<(&str, crate::core::firewall::FwCount)> = Vec::new();
        if self.cfg.network_lockdown {
            steps.push(("disable_network_lockdown", disable_network_lockdown()));
        }
        if self.applied_kill {
            steps.push(("disable_kill_switch", disable_kill_switch()));
            self.applied_kill = false;
        }
        if self.applied_stun {
            steps.push(("unblock_stun", unblock_stun()));
            self.applied_stun = false;
        }
        if self.applied_quic {
            steps.push(("unblock_quic", unblock_quic()));
            self.applied_quic = false;
        }
        for (name, r) in steps {
            match r {
                Ok(k) => removed += k,
                Err(e) => {
                    teardown_ok = false;
                    warn!("firewall teardown {} failed: {}", name, e);
                }
            }
        }
        if teardown_ok {
            info!(
                "firewall teardown removed {} albus rule(s) (bounded delete: residue, if \
                 any, is pre-hardening comment-less and is documented, not blindly removed)",
                removed
            );
        } else {
            warn!(
                "firewall teardown could not verify every rule ({} removed) — residual albus \
                 rules may still be installed; inspect `iptables -S OUTPUT | grep albus`",
                removed
            );
        }
    }

    // restores kernel socket options, removes iptables rules, and restores system dns
    // order: stop injection first, then DNS restore, then firewall open (no leak window)
    pub fn shutdown(&mut self) {
        self.bpf_manager.stop();

        // DNS-04: the listener is only stopped once the host's resolver
        // configuration has actually been put back. This used to warn on a failed
        // restore and then stop it anyway: /etc/resolv.conf still pointed at
        // 127.0.0.1:53, so every process on the machine lost resolution — and
        // with the kill-switch DROP rules possibly still installed it could not
        // fall back either. A refused restore (nothing to restore from) must not
        // be followed by tearing down the only working resolver.
        let mut safe_to_stop_listener = true;
        if self.applied_dns {
            match restore_system_dns() {
                Ok(()) => info!("system DNS restored"),
                Err(e) => {
                    safe_to_stop_listener = false;
                    error!(
                        "failed to restore system DNS: {}. Leaving the DNS listener RUNNING \
                         so the host keeps resolving through albus; /etc/resolv.conf must be \
                         fixed by hand (sudo albus cleanup) before this listener is stopped.",
                        e
                    );
                }
            }
            self.applied_dns = false;
        }
        if let Some(ref dns) = self.dns_server {
            if safe_to_stop_listener {
                dns.stop();
            }
        }

        self.cleanup_firewall_only();
    }
}

#[cfg(test)]
mod reload_commit_tests {
    use super::*;

    fn cfg() -> Config {
        Config::default()
    }

    /// EBPF-02, the observable half: a SIGHUP that changes ONLY the fields the
    /// running injector cannot observe must leave memory describing the running
    /// process. On unpatched source all of these were copied into self.cfg, so
    /// the operator's file and the daemon's memory agreed while neither the
    /// kernel maps nor the injected packets did.
    #[test]
    fn test_injector_payload_fields_are_not_committed() {
        let mut running = cfg();
        let mut reloaded = cfg();

        // Only the seven restart-required fields differ.
        reloaded.fake_ttl = 42;
        reloaded.fake_sni = Some("cdn.example".into());
        reloaded.fake_bad_checksum = true;
        reloaded.auto_ttl = !reloaded.auto_ttl;
        reloaded.min_ttl = reloaded.min_ttl.wrapping_add(3);
        reloaded.max_ttl = reloaded.max_ttl.wrapping_add(5);
        reloaded.pqc = !reloaded.pqc;

        let before = running.clone();
        Engine::apply_hot_reloadable(&mut running, &reloaded);

        assert_eq!(
            running.fake_ttl, before.fake_ttl,
            "fake_ttl must not change"
        );
        assert_eq!(
            running.fake_sni, before.fake_sni,
            "fake_sni must not change"
        );
        assert_eq!(
            running.fake_bad_checksum, before.fake_bad_checksum,
            "fake_bad_checksum must not change"
        );
        assert_eq!(
            running.auto_ttl, before.auto_ttl,
            "auto_ttl must not change"
        );
        assert_eq!(running.min_ttl, before.min_ttl, "min_ttl must not change");
        assert_eq!(running.max_ttl, before.max_ttl, "max_ttl must not change");
        assert_eq!(running.pqc, before.pqc, "pqc must not change");
    }

    /// The positive path: the fields the kernel maps actually carry must be
    /// committed, so the fix did not simply freeze the config.
    #[test]
    fn test_map_backed_fields_are_committed() {
        let mut running = cfg();
        let mut reloaded = cfg();
        reloaded.mss = 1300;
        reloaded.min_mss = 1100;
        reloaded.restore_mss = 1460;
        reloaded.restore_after_bytes = 9_000_000;
        reloaded.ports = vec![443, 8443];

        Engine::apply_hot_reloadable(&mut running, &reloaded);

        assert_eq!(running.mss, 1300);
        assert_eq!(running.min_mss, 1100);
        assert_eq!(running.restore_mss, 1460);
        assert_eq!(running.restore_after_bytes, 9_000_000);
        assert_eq!(running.ports, vec![443, 8443]);
    }

    /// `verbose` is read at every log site, so unlike the injector fields it is
    /// genuinely live. Committing it is correct, not an oversight.
    #[test]
    fn test_verbose_is_committed_because_it_is_read_live() {
        let mut running = cfg();
        let mut reloaded = cfg();
        reloaded.verbose = !running.verbose;
        Engine::apply_hot_reloadable(&mut running, &reloaded);
        assert_eq!(running.verbose, reloaded.verbose);
    }

    /// And the transactional half: the commit must sit AFTER the `?` that
    /// propagates a kernel rejection. This is the durable defect — a diverged
    /// baseline makes the next reload compute the wrong delete-set, so a removed
    /// target port is never deleted and keeps being applied until a restart.
    #[test]
    fn test_commit_occurs_after_the_kernel_accepts() {
        let src = include_str!("engine.rs");
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod reload_commit_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);

        let at = prod.find("fn apply_reload(").expect("apply_reload");
        // Bound at the NEXT method so the window cannot spill into unrelated code.
        let body = {
            let tail = &prod[at..];
            let end = tail.find("fn apply_hot_reloadable").unwrap_or(tail.len());
            &tail[..end]
        };
        let reject = body
            .find("self.bpf_manager.reload_maps(&bpf_cfg)?;")
            .expect("the propagating reload call");
        let commit = body
            .find("Self::apply_hot_reloadable(&mut self.cfg, new_cfg);")
            .expect("the commit");

        assert!(
            reject < commit,
            "EBPF-02: the commit must come after the fallible reload, otherwise a \\
             rejected config is adopted in memory anyway"
        );
        assert!(
            !body.contains("if let Err(e) = self.bpf_manager.reload_maps"),
            "the reload error must propagate with `?`, not be logged and ignored"
        );
    }

    /// The restart-required warning must actually name the injector fields, so
    /// an operator who changed fake_sni or pqc is told it needs a restart
    /// instead of being left to assume it took effect.
    #[test]
    fn test_restart_warning_names_the_injector_fields() {
        let src = include_str!("engine.rs");
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod reload_commit_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod
            .find("let mut restart_only = Vec::new();")
            .expect("restart_only list");
        let block = &prod[at..(at + 1600).min(prod.len())];
        for field in [
            "fake_ttl",
            "fake_sni",
            "fake_bad_checksum",
            "auto_ttl",
            "min_ttl",
            "max_ttl",
            "pqc",
        ] {
            assert!(
                block.contains(field),
                "the restart-required warning must name {}",
                field
            );
        }
        assert!(
            block.contains("captured by value at start"),
            "the warning must say WHY these are not hot-reloadable"
        );
    }
}
