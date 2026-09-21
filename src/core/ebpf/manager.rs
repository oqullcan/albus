//! high-level ebpf manager coordinating kernel hooks, raw packet injection, and ring buffer polling.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use super::loader::{BpfConfig, BpfEngine, RawConnEvent};
use crate::core::autottl::AutoTtlEstimator;
use crate::core::fake::clienthello::build_fake_client_hello_opts;
use crate::core::fake::sni::DEFAULT_DECOY_SNI_POOL;
use crate::core::firewall::enable_network_lockdown;
use crate::core::rawsock::{ConnInfo, RawSocket};
use crate::dns::server::DnsServer;

/// Watchdog re-check interval: displacement is rare and fail-closed is
/// drastic, so slow polling beats hot polling (no per-packet cost).
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct BpfManagerConfig {
    pub mss: u16,
    pub min_mss: u16,
    pub restore_mss: u16,
    pub restore_after_bytes: u32,
    pub ports: Vec<u16>,
    pub exclude_ips: Vec<Ipv4Addr>,
    pub exclude_ips_v6: Vec<Ipv6Addr>,
    pub cgroup_path: String,
    pub fake_ttl: u8,
    pub fake_sni: Option<String>,
    pub fake_bad_checksum: bool,
    pub pqc: bool,
    pub auto_ttl_estimator: AutoTtlEstimator,
    /// shaping watchdog (displacement detection + fail-closed lockdown).
    /// Default on; --shaping-watchdog=false disables the periodic check.
    pub shaping_watchdog: bool,
}

// manager coordinating the ebpf filter engine and raw-socket injector
pub struct BpfManager {
    cfg: BpfManagerConfig,
    engine: Option<BpfEngine>,
    map_handles: Option<super::loader::BpfMapHandles>,
    running: Arc<AtomicBool>,
    worker_handle: Option<JoinHandle<()>>,
    /// latched on confirmed shaping loss (consecutive Unhealthy probes);
    /// drives the one-shot fail-closed lockdown below. Never auto-cleared:
    /// only a restart re-arms shaping.
    pub shaping_lost: Arc<AtomicBool>,
}

impl BpfManager {
    pub fn new(cfg: BpfManagerConfig) -> Self {
        Self {
            cfg,
            engine: None,
            map_handles: None,
            running: Arc::new(AtomicBool::new(false)),
            worker_handle: None,
            shaping_lost: Arc::new(AtomicBool::new(false)),
        }
    }

    // reloads ebpf maps live at runtime without stopping or detaching the program
    pub fn reload_maps(
        &mut self,
        new_cfg: &BpfManagerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.cfg = new_cfg.clone();
        if let Some(handles) = self.map_handles {
            let bpf_cfg = BpfConfig::new(
                new_cfg.mss,
                new_cfg.restore_mss,
                new_cfg.restore_after_bytes,
                new_cfg.min_mss,
                true,
            );
            handles.push_config(bpf_cfg)?;
            handles.push_target_ports(&new_cfg.ports)?;
            handles.push_exclude_ips(&new_cfg.exclude_ips)?;
            handles.push_exclude_ips_v6(&new_cfg.exclude_ips_v6)?;
            info!(
                mss = new_cfg.mss,
                min_mss = new_cfg.min_mss,
                ports = ?new_cfg.ports,
                exclude_count = new_cfg.exclude_ips.len(),
                exclude_v6_count = new_cfg.exclude_ips_v6.len(),
                "eBPF runtime maps reloaded dynamically"
            );
        }
        Ok(())
    }

    // loads ebpf, attaches to cgroup, initializes maps, and starts event polling loop
    pub fn start(
        &mut self,
        dns_server: Option<Arc<DnsServer>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Loading eBPF sock_ops program");

        let engine = BpfEngine::load_and_attach(&self.cfg.cgroup_path)?;
        self.map_handles = Some(engine.map_handles());

        let bpf_cfg = BpfConfig::new(
            self.cfg.mss,
            self.cfg.restore_mss,
            self.cfg.restore_after_bytes,
            self.cfg.min_mss,
            true,
        );
        engine.push_config(bpf_cfg)?;
        engine.push_target_ports(&self.cfg.ports)?;
        engine.push_exclude_ips(&self.cfg.exclude_ips)?;
        engine.push_exclude_ips_v6(&self.cfg.exclude_ips_v6)?;

        let raw_socket = Arc::new(RawSocket::new()?);
        let estimator = self.cfg.auto_ttl_estimator.clone();
        let running = self.running.clone();
        let fake_sni = self.cfg.fake_sni.clone();
        let fake_bad_checksum = self.cfg.fake_bad_checksum;
        let fake_ttl_fallback = self.cfg.fake_ttl;
        running.store(true, Ordering::SeqCst);

        self.engine = Some(engine);

        info!(
            mss = self.cfg.mss,
            min_mss = self.cfg.min_mss,
            fallback_ttl = self.cfg.fake_ttl,
            fake_sni = ?self.cfg.fake_sni,
            bad_checksum = self.cfg.fake_bad_checksum,
            pqc = self.cfg.pqc,
            ports = ?self.cfg.ports,
            "albus active — MSS fragmentation + Auto-TTL fake injection"
        );

        let mut engine_poll = self.engine.take().unwrap();
        let running_clone = running.clone();

        // assemble decoy clienthello payloads: rotate across pool if no custom sni is forced
        let fake_payloads: Vec<Vec<u8>> = if let Some(ref sni) = fake_sni {
            if sni != "www.google.com" && !sni.is_empty() {
                vec![build_fake_client_hello_opts(sni, self.cfg.pqc)]
            } else {
                DEFAULT_DECOY_SNI_POOL
                    .iter()
                    .map(|&s| build_fake_client_hello_opts(s, self.cfg.pqc))
                    .collect()
            }
        } else {
            DEFAULT_DECOY_SNI_POOL
                .iter()
                .map(|&s| build_fake_client_hello_opts(s, self.cfg.pqc))
                .collect()
        };

        // watchdog inputs, snapshotted for the worker thread
        let watchdog_enabled = self.cfg.shaping_watchdog;
        let watch_ports = self.cfg.ports.clone();
        let watch_exclude_v4 = self.cfg.exclude_ips.clone();
        let watch_exclude_v6 = self.cfg.exclude_ips_v6.clone();
        let tripped_clone = self.shaping_lost.clone();
        let events_seen = Arc::new(AtomicU64::new(0));
        let events_probe = events_seen.clone();
        // fresh start re-arms (a restart means a fresh attach)
        self.shaping_lost.store(false, Ordering::SeqCst);

        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok();
            let mut decoy_idx: usize = 0;
            // watchdog snapshot: read once, the worker owns the rest
            let mut last_watchdog_check = Instant::now();
            let mut watch_state = super::watch::WatchState::default();
            // latched per watchdog window: any perf-ring overrun inside the
            // window makes its event count untrustworthy (see poll_events)
            let mut watch_overrun = false;

            while running_clone.load(Ordering::Relaxed) {
                let mut received = false;
                watch_overrun |=
                    engine_poll.poll_events(|raw_evt: RawConnEvent| {
                        received = true;
                        // every perf event is evidence the program is firing
                        events_probe.fetch_add(1, Ordering::Relaxed);
                        // NOTE: RawConnEvent is #[repr(packed)] — never take references to its
                        // fields (unaligned). Copy out via read_unaligned first.
                        let (
                            src_ip,
                            dst_ip,
                            src_port,
                            dst_port,
                            seq,
                            ack,
                            family,
                            src_ip6,
                            dst_ip6,
                        ) = unsafe {
                            let p = &raw_evt as *const RawConnEvent;
                            (
                                std::ptr::addr_of!((*p).src_ip).read_unaligned(),
                                std::ptr::addr_of!((*p).dst_ip).read_unaligned(),
                                std::ptr::addr_of!((*p).src_port).read_unaligned(),
                                std::ptr::addr_of!((*p).dst_port).read_unaligned(),
                                std::ptr::addr_of!((*p).seq).read_unaligned(),
                                std::ptr::addr_of!((*p).ack).read_unaligned(),
                                std::ptr::addr_of!((*p).family).read_unaligned(),
                                std::ptr::addr_of!((*p).src_ip6).read_unaligned(),
                                std::ptr::addr_of!((*p).dst_ip6).read_unaligned(),
                            )
                        };
                        let conn = if family == 10 {
                            let mut src_octets = [0u8; 16];
                            let mut dst_octets = [0u8; 16];
                            for i in 0..4 {
                                src_octets[i * 4..(i + 1) * 4]
                                    .copy_from_slice(&src_ip6[i].to_ne_bytes());
                                dst_octets[i * 4..(i + 1) * 4]
                                    .copy_from_slice(&dst_ip6[i].to_ne_bytes());
                            }
                            ConnInfo::new_v6(
                                Ipv6Addr::from(src_octets),
                                Ipv6Addr::from(dst_octets),
                                src_port,
                                dst_port,
                                seq,
                                ack,
                            )
                        } else {
                            ConnInfo::new_v4(
                                Ipv4Addr::from(src_ip.to_ne_bytes()),
                                Ipv4Addr::from(dst_ip.to_ne_bytes()),
                                src_port,
                                dst_port,
                                seq,
                                ack,
                            )
                        };

                        // static TTL lookup for this destination (no probing)
                        let optimal_ttl = match conn.dst_ip {
                            IpAddr::V4(v4) => estimator.get_ttl(v4),
                            IpAddr::V6(_) => fake_ttl_fallback,
                        };

                        let payload = &fake_payloads[decoy_idx % fake_payloads.len()];
                        decoy_idx = decoy_idx.wrapping_add(1);

                        if let Err(e) = raw_socket.send_fake_opts(
                            &conn,
                            payload,
                            optimal_ttl,
                            fake_bad_checksum,
                        ) {
                            warn!("Failed to inject fake ClientHello: {}", e);
                        } else {
                            let mut dst_desc = format!("{}:{}", conn.dst_ip, conn.dst_port);

                            if let (Some(server), Some(runtime)) = (&dns_server, &rt) {
                                if let IpAddr::V4(v4) = conn.dst_ip {
                                    if let Some(domain) = runtime.block_on(server.pop_domain(v4)) {
                                        // domain originates from upstream DNS answers:
                                        // sanitize before it reaches the journal (L7/L8)
                                        let clean = crate::dns::server::sanitize_log_token(&domain);
                                        dst_desc = format!("{}:{}", clean, conn.dst_port);
                                    }
                                }
                            }

                            debug!(
                                dst = %dst_desc,
                                seq = conn.seq,
                                ack = conn.ack,
                                ttl = optimal_ttl,
                                bad_cs = fake_bad_checksum,
                                "fake ClientHello injected"
                            );
                        }
                    });

                if !received {
                    thread::sleep(Duration::from_micros(200));
                }

                // shaping watchdog (v2 reconciliation): every interval,
                // compare fresh ESTABLISHED target-port connections against
                // fresh perf events. Unexplained newcomers across two
                // consecutive quiet windows trip the one-shot fail-closed
                // lockdown (see watch::WatchState for the exact rules).
                if watchdog_enabled && last_watchdog_check.elapsed() >= WATCHDOG_INTERVAL {
                    last_watchdog_check = Instant::now();
                    // overrun inside the window: event count untrustworthy,
                    // freeze this round (neither trip nor reset)
                    if watch_overrun {
                        debug!("shaping watchdog: perf ring overran, round frozen");
                        watch_overrun = false;
                    } else {
                        let tcp4 = std::fs::read_to_string("/proc/net/tcp").unwrap_or_default();
                        let tcp6 = std::fs::read_to_string("/proc/net/tcp6").unwrap_or_default();
                        if !(tcp4.is_empty() && tcp6.is_empty()) {
                            let trip = watch_state.observe(
                                &tcp4,
                                &tcp6,
                                &watch_ports,
                                &watch_exclude_v4,
                                &watch_exclude_v6,
                                events_seen.load(Ordering::Relaxed),
                            );
                            if trip && !tripped_clone.swap(true, Ordering::SeqCst) {
                                warn!(
                                    "SHAPING LOST: fresh target-port connections produced no perf events across consecutive windows — engaging fail-closed network lockdown (restart albus to re-arm)"
                                );
                                enable_network_lockdown();
                            }
                        }
                    }
                }
            }

            let _ = engine_poll.detach();
        });

        self.worker_handle = Some(handle);
        Ok(())
    }

    // stops polling and cleanly releases all resources
    pub fn stop(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            info!("Stopping albus eBPF manager");
            self.running.store(false, Ordering::SeqCst);
            if let Some(handle) = self.worker_handle.take() {
                let _ = handle.join();
            }
            self.map_handles = None;
            info!("albus eBPF manager stopped");
        }
    }
}

impl Drop for BpfManager {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::autottl::{AutoTtlConfig, AutoTtlEstimator};

    fn test_cfg() -> BpfManagerConfig {
        BpfManagerConfig {
            mss: 88,
            min_mss: 64,
            restore_mss: 0,
            restore_after_bytes: 600,
            ports: vec![443],
            exclude_ips: vec![],
            exclude_ips_v6: vec![],
            cgroup_path: "/sys/fs/cgroup".to_string(),
            fake_ttl: 8,
            fake_sni: None,
            fake_bad_checksum: false,
            pqc: true,
            auto_ttl_estimator: AutoTtlEstimator::new(AutoTtlConfig::default()),
            shaping_watchdog: true,
        }
    }

    #[test]
    fn test_manager_new_is_stopped() {
        let mgr = BpfManager::new(test_cfg());
        assert!(!mgr.running.load(Ordering::SeqCst));
        assert_eq!(mgr.cfg.mss, 88);
        assert_eq!(mgr.cfg.ports, vec![443]);
    }
}

#[cfg(test)]
mod reload_tests {
    use super::*;
    use crate::core::autottl::{AutoTtlConfig, AutoTtlEstimator};

    fn cfg_with_ports(ports: Vec<u16>) -> BpfManagerConfig {
        BpfManagerConfig {
            mss: 88,
            min_mss: 64,
            restore_mss: 0,
            restore_after_bytes: 600,
            ports,
            exclude_ips: vec![],
            exclude_ips_v6: vec![],
            cgroup_path: "/sys/fs/cgroup".to_string(),
            fake_ttl: 8,
            fake_sni: None,
            fake_bad_checksum: false,
            pqc: true,
            auto_ttl_estimator: AutoTtlEstimator::new(AutoTtlConfig::default()),
            shaping_watchdog: true,
        }
    }

    #[test]
    fn test_reload_maps_without_handles_updates_cfg_only() {
        // no kernel maps attached: pure config swap, must not error
        let mut mgr = BpfManager::new(cfg_with_ports(vec![443]));
        let next = cfg_with_ports(vec![80, 443]);
        mgr.reload_maps(&next)
            .expect("cfg-only reload must succeed");
        assert_eq!(mgr.cfg.ports, vec![80, 443]);
    }
}
