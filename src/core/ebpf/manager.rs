//! high-level ebpf manager coordinating kernel hooks, raw packet injection, and ring buffer polling.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tracing::{info, warn};

use super::loader::{BpfConfig, BpfEngine, BpfMapHandles, RawConnEvent};
use crate::core::autottl::AutoTtlEstimator;
use crate::core::fake::clienthello::{build_fake_client_hello, FAKE_TLS_CLIENT_HELLO};
use crate::core::rawsock::{ConnInfo, RawSocket};
use crate::dns::server::DnsServer;

/// The map parameters `start` pushes, captured so the closure passed to
/// `commit_start` does not have to borrow `self`.
struct PushParams {
    mss: u16,
    restore_mss: u16,
    restore_after_bytes: u32,
    min_mss: u16,
    ports: Vec<u16>,
    exclude_ips: Vec<Ipv4Addr>,
    exclude_ips_v6: Vec<Ipv6Addr>,
}

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
}

// manager coordinating the ebpf filter engine and raw-socket injector
pub struct BpfManager {
    cfg: BpfManagerConfig,
    engine: Option<BpfEngine>,
    map_handles: Option<BpfMapHandles>,
    running: Arc<AtomicBool>,
    worker_handle: Option<JoinHandle<()>>,
}

impl BpfManager {
    pub fn new(cfg: BpfManagerConfig) -> Self {
        Self {
            cfg,
            engine: None,
            map_handles: None,
            running: Arc::new(AtomicBool::new(false)),
            worker_handle: None,
        }
    }

    /// EBPF-03: whether every CPU has a perf reader. False means the engine is
    /// attached and fragmenting but its decoy-injection half will miss some
    /// connections — a state the caller must not describe as "active".
    pub fn readers_complete(&self) -> bool {
        match &self.engine {
            Some(e) => e.readers_complete(),
            None => false,
        }
    }

    /// Perf readers actually installed.
    pub fn reader_count(&self) -> usize {
        self.engine.as_ref().map(|e| e.reader_count()).unwrap_or(0)
    }

    /// Runs every fallible map push and publishes the descriptors only if all of
    /// them succeeded.
    ///
    /// EBPF-04: the invariant is "map_handles must only be observable once every
    /// operation that can invalidate them has succeeded". Publishing first and
    /// retracting later leaves a window that `stop()`'s `running` guard cannot
    /// reach, which is how a failed start ended up holding descriptors to
    /// closed maps and turned every later SIGHUP into an undiagnosable
    /// `bpf(BPF_MAP_UPDATE_ELEM) failed`.
    ///
    /// Extracted as its own step so the state machine is testable without a
    /// kernel: no BPF map, cgroup, raw socket or syscall is involved.
    fn commit_start(
        &mut self,
        handles: BpfMapHandles,
        push: impl FnOnce(&BpfMapHandles) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        push(&handles)?;
        self.map_handles = Some(handles);
        Ok(())
    }

    // reloads ebpf maps live at runtime without stopping or detaching the program
    // FP-17: push first, swap cfg only on success; absent handles (pre-start)
    // is an explicit error, never a silent Ok.
    // Follow-up: sync (not just push) set maps so shrunk configs purge stale
    // entries; on mid-sequence failure best-effort restore the old sets so the
    // kernel never sits half-migrated while memory claims either version.
    pub fn reload_maps(
        &mut self,
        new_cfg: &BpfManagerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(handles) = self.map_handles else {
            return Err("eBPF maps not loaded yet — start the engine before reload".into());
        };
        let bpf_cfg = BpfConfig::new(
            new_cfg.mss,
            new_cfg.restore_mss,
            new_cfg.restore_after_bytes,
            new_cfg.min_mss,
            true,
        );
        let old = &self.cfg;
        let applied = (|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            handles.push_config(bpf_cfg)?;
            handles.sync_target_ports(&old.ports, &new_cfg.ports)?;
            handles.sync_exclude_ips(&old.exclude_ips, &new_cfg.exclude_ips)?;
            handles.sync_exclude_ips_v6(&old.exclude_ips_v6, &new_cfg.exclude_ips_v6)?;
            Ok(())
        })();
        if let Err(e) = applied {
            // best-effort rollback toward the pre-reload kernel state,
            // including the scalar config map (not just the sets).
            let old_cfg = BpfConfig::new(
                old.mss,
                old.restore_mss,
                old.restore_after_bytes,
                old.min_mss,
                true,
            );
            let _ = handles.push_config(old_cfg);
            let _ = handles.sync_target_ports(&new_cfg.ports, &old.ports);
            let _ = handles.sync_exclude_ips(&new_cfg.exclude_ips, &old.exclude_ips);
            let _ = handles.sync_exclude_ips_v6(&new_cfg.exclude_ips_v6, &old.exclude_ips_v6);
            return Err(e);
        }
        // all pushes succeeded: now adopt the new config (no cfg/map divergence)
        self.cfg = new_cfg.clone();
        info!(
            mss = new_cfg.mss,
            min_mss = new_cfg.min_mss,
            ports = ?new_cfg.ports,
            exclude_count = new_cfg.exclude_ips.len(),
            exclude_v6_count = new_cfg.exclude_ips_v6.len(),
            "eBPF runtime maps reloaded dynamically"
        );
        Ok(())
    }

    // loads ebpf, attaches to cgroup, initializes maps, and starts event polling loop
    pub fn start(
        &mut self,
        dns_server: Option<Arc<DnsServer>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Loading eBPF sock_ops program");

        let engine = BpfEngine::load_and_attach(&self.cfg.cgroup_path)?;

        // EBPF-04: publication moves AFTER the transition that validates it.
        // This used to assign self.map_handles while `engine` was still a local
        // that the four pushes below could fail on. On such a failure the local
        // engine drops (closing all six maps), but self.map_handles kept four
        // RawFd values now referring to CLOSED descriptors — and stop(), the
        // only retraction site, is gated behind `running`, which is not set
        // until further below. Engine::run treats a start() Err as recoverable,
        // so the daemon stayed up holding a poisoned manager, and the next
        // SIGHUP drove bpf_map_update/bpf_map_delete against those stale fd
        // numbers: a reload failure the operator could not diagnose from the
        // message, forever.
        let handles = engine.map_handles();

        let params = PushParams {
            mss: self.cfg.mss,
            restore_mss: self.cfg.restore_mss,
            restore_after_bytes: self.cfg.restore_after_bytes,
            min_mss: self.cfg.min_mss,
            ports: self.cfg.ports.clone(),
            exclude_ips: self.cfg.exclude_ips.clone(),
            exclude_ips_v6: self.cfg.exclude_ips_v6.clone(),
        };
        self.commit_start(handles, move |target: &BpfMapHandles| {
            // Push through the handles being published, so the validated
            // descriptors and the published descriptors are provably the same
            // objects rather than two independent reads of engine state.
            target.push_config(BpfConfig::new(
                params.mss,
                params.restore_mss,
                params.restore_after_bytes,
                params.min_mss,
                true,
            ))?;
            target.push_target_ports(&params.ports)?;
            target.push_exclude_ips(&params.exclude_ips)?;
            target.push_exclude_ips_v6(&params.exclude_ips_v6)?;
            Ok(())
        })?;

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
                vec![
                    crate::core::fake::clienthello::build_fake_client_hello_opts(sni, self.cfg.pqc),
                ]
            } else {
                crate::core::fake::sni::DEFAULT_DECOY_SNI_POOL
                    .iter()
                    .map(|&s| {
                        crate::core::fake::clienthello::build_fake_client_hello_opts(
                            s,
                            self.cfg.pqc,
                        )
                    })
                    .collect()
            }
        } else {
            crate::core::fake::sni::DEFAULT_DECOY_SNI_POOL
                .iter()
                .map(|&s| {
                    crate::core::fake::clienthello::build_fake_client_hello_opts(s, self.cfg.pqc)
                })
                .collect()
        };

        let handle = thread::spawn(move || {
            // FP-13 follow-up: multi_thread with one worker so spawned
            // estimator tasks are driven independently — a current_thread
            // runtime only polls tasks during block_on, which starved
            // estimation whenever the DNS path was idle.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .ok();
            // Keep the enter guard as well: sync get_ttl must observe a
            // context via try_current on this thread too.
            let _enter_guard = rt.as_ref().map(|r| r.enter());
            let mut decoy_idx: usize = 0;

            while running_clone.load(Ordering::Relaxed) {
                let mut received = false;
                engine_poll.poll_events(|raw_evt: RawConnEvent| {
                    received = true;
                    // NOTE: RawConnEvent is #[repr(packed)] — never take references to its
                    // fields (unaligned). Copy out via read_unaligned first.
                    let (src_ip, dst_ip, src_port, dst_port, seq, ack, family, src_ip6, dst_ip6) = unsafe {
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
                            src_octets[i * 4..(i + 1) * 4].copy_from_slice(&src_ip6[i].to_ne_bytes());
                            dst_octets[i * 4..(i + 1) * 4].copy_from_slice(&dst_ip6[i].to_ne_bytes());
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

                    // dynamically resolve optimal ttl for destination
                    let optimal_ttl = match conn.dst_ip {
                        IpAddr::V4(v4) => estimator.get_ttl(v4),
                        IpAddr::V6(_) => fake_ttl_fallback,
                    };

                    let payload = &fake_payloads[decoy_idx % fake_payloads.len()];
                    decoy_idx = decoy_idx.wrapping_add(1);

                    if let Err(e) = raw_socket.send_fake_opts(&conn, payload, optimal_ttl, fake_bad_checksum) {
                        warn!("Failed to inject fake ClientHello: {}", e);
                    } else {
                        let mut dst_desc = format!("{}:{}", conn.dst_ip, conn.dst_port);

                        if let (Some(server), Some(runtime)) = (&dns_server, &rt) {
                            if let IpAddr::V4(v4) = conn.dst_ip {
                                if let Some(domain) = runtime.block_on(server.pop_domain(v4)) {
                                    dst_desc = format!("{}:{}", domain, conn.dst_port);
                                }
                            }
                        }

                        info!(
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
            }

            let _ = engine_poll.detach();
        });

        self.worker_handle = Some(handle);
        Ok(())
    }

    // stops polling and cleanly releases all resources
    //
    // EBPF-04: the `map_handles` retraction is deliberately OUTSIDE the
    // `running` guard. It used to sit inside, which meant the only code that
    // could clear a stale `Some(...)` was unreachable on every failure path that
    // could create one. Retracting unconditionally costs nothing on the normal
    // path (the value is already None or about to be dropped with the engine)
    // and removes the flag as a precondition for correctness.
    pub fn stop(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            info!("Stopping albus eBPF manager");
            self.running.store(false, Ordering::SeqCst);
            if let Some(handle) = self.worker_handle.take() {
                let _ = handle.join();
            }
            info!("albus eBPF manager stopped");
        }
        self.map_handles = None;
    }
}

impl Drop for BpfManager {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod map_handle_lifecycle_tests {
    use super::*;
    use std::io;

    /// Sentinel descriptors. Never opened, never passed to a syscall: the
    /// tests below drive only the manager's own state machine.
    fn handles() -> BpfMapHandles {
        BpfMapHandles {
            config_map_fd: 1001,
            target_ports_fd: 1002,
            exclude_ips_fd: 1003,
            exclude_ips_v6_fd: 1004,
        }
    }

    fn manager() -> BpfManager {
        BpfManager::new(BpfManagerConfig {
            mss: 1200,
            min_mss: 1000,
            restore_mss: 1440,
            restore_after_bytes: 4 << 20,
            ports: vec![443],
            exclude_ips: vec![],
            exclude_ips_v6: vec![],
            cgroup_path: "/sys/fs/cgroup".into(),
            fake_ttl: 8,
            fake_sni: None,
            fake_bad_checksum: false,
            pqc: false,
            auto_ttl_estimator: AutoTtlEstimator::new(
                crate::core::autottl::AutoTtlConfig::default(),
            ),
        })
    }

    /// EBPF-04: a push that fails must leave `map_handles` unpublished. On
    /// unpatched source the descriptors were published BEFORE the pushes, so a
    /// failure left four RawFd values pointing at maps the dropped engine had
    /// already closed.
    #[test]
    fn test_failed_push_does_not_publish_map_handles() {
        let mut m = manager();
        assert!(m.map_handles.is_none(), "precondition: nothing published");

        let r = m.commit_start(handles(), |_h| {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "synthetic push failure",
            ))
        });

        assert!(r.is_err(), "the failing push must surface");
        assert!(
            m.map_handles.is_none(),
            "EBPF-04: descriptors must not be published when a push fails"
        );
    }

    /// And the observable consequence: a later reload must reach the
    /// "maps not loaded" precondition rather than issuing a bpf() syscall
    /// against a stale descriptor. The message is the diagnosability claim.
    #[test]
    fn test_reload_after_failed_start_reports_not_loaded_not_a_syscall_error() {
        let mut m = manager();
        let _ = m.commit_start(handles(), |_h| {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "synthetic push failure",
            ))
        });

        let err = m
            .reload_maps(&m.cfg.clone())
            .expect_err("reload must not succeed against a failed start");
        let msg = err.to_string();
        assert!(
            msg.contains("not loaded"),
            "reload must fail at the precondition, not at a syscall: {}",
            msg
        );
        assert!(
            !msg.contains("BPF_MAP_UPDATE_ELEM") && !msg.contains("bpf("),
            "no kernel call may be attempted against a stale descriptor: {}",
            msg
        );
    }

    /// The positive path still publishes, so the fix did not simply disable it.
    #[test]
    fn test_successful_push_publishes_map_handles() {
        let mut m = manager();
        let mut pushed = false;
        m.commit_start(handles(), |_h| {
            pushed = true;
            Ok(())
        })
        .expect("push succeeds");

        assert!(pushed, "the push closure must have run");
        let published = m.map_handles.expect("handles must be published");
        assert_eq!(published.config_map_fd, 1001);
        assert_eq!(published.exclude_ips_v6_fd, 1004);
    }

    /// EBPF-04's belt-and-braces half: the retraction must not sit behind the
    /// `running` flag, because that flag is not set on any failure path that can
    /// create a stale Some — which is exactly why it used to leak.
    #[test]
    fn test_stop_clears_map_handles_even_when_not_running() {
        let mut m = manager();
        m.commit_start(handles(), |_h| Ok(())).expect("push");
        assert!(m.map_handles.is_some(), "precondition: published");
        assert!(
            !m.running.load(Ordering::SeqCst),
            "precondition: never marked running"
        );

        m.stop();

        assert!(
            m.map_handles.is_none(),
            "EBPF-04: stop() must retract unconditionally, not only when running"
        );
    }

    /// Dropping a manager that was never started must not leave anything behind
    /// either — Drop calls stop().
    #[test]
    fn test_drop_after_failed_start_leaves_nothing_published() {
        let mut m = manager();
        let _ = m.commit_start(handles(), |_h| {
            Err(io::Error::new(io::ErrorKind::Other, "synthetic"))
        });
        drop(m);
        // Nothing observable survives the drop; the assertion is that the drop
        // path itself does not panic while `running` is false.
    }

    /// Regression guard on the ordering itself. The invariant lives inside
    /// `commit_start`: the pushes run first and the assignment happens only
    /// afterwards. `start` must route through it rather than assigning
    /// directly.
    #[test]
    fn test_publication_happens_after_the_pushes() {
        let src = include_str!("manager.rs");
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod map_handle_lifecycle_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);

        let commit_at = prod.find("fn commit_start(").expect("commit_start helper");
        let commit_body = &prod[commit_at..(commit_at + 700).min(prod.len())];
        let push_at = commit_body.find("push(&handles)?;").expect("push call");
        let assign_at = commit_body
            .find("self.map_handles = Some(handles);")
            .expect("publication");
        assert!(
            push_at < assign_at,
            "EBPF-04: publication must come AFTER the fallible push"
        );

        let start_at = prod.find("pub fn start(").expect("start");
        let start_end = prod[start_at..]
            .find("\n    pub fn ")
            .map(|o| start_at + o)
            .unwrap_or(prod.len());
        let start_body = &prod[start_at..start_end];
        assert!(
            !start_body.contains("self.map_handles = Some("),
            "start() must not assign map_handles directly: {}",
            start_body
        );
        assert!(
            start_body.contains("self.commit_start("),
            "start() must route publication through commit_start"
        );
    }
}
