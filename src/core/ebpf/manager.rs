//! high-level ebpf manager coordinating kernel hooks, raw packet injection, and ring buffer polling.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tracing::{info, warn};

use super::loader::{BpfConfig, BpfEngine, RawConnEvent};
use crate::core::autottl::AutoTtlEstimator;
use crate::core::fake::clienthello::{build_fake_client_hello, FAKE_TLS_CLIENT_HELLO};
use crate::core::rawsock::{ConnInfo, RawSocket};
use crate::dns::server::DnsServer;

#[derive(Debug, Clone)]
pub struct BpfManagerConfig {
    pub mss: u16,
    pub restore_mss: u16,
    pub restore_after_bytes: u32,
    pub ports: Vec<u16>,
    pub exclude_ips: Vec<Ipv4Addr>,
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
    running: Arc<AtomicBool>,
    worker_handle: Option<JoinHandle<()>>,
}

impl BpfManager {
    pub fn new(cfg: BpfManagerConfig) -> Self {
        Self {
            cfg,
            engine: None,
            running: Arc::new(AtomicBool::new(false)),
            worker_handle: None,
        }
    }

    // loads ebpf, attaches to cgroup, initializes maps, and starts event polling loop
    pub fn start(&mut self, dns_server: Option<Arc<DnsServer>>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Loading eBPF sock_ops program");

        let engine = BpfEngine::load_and_attach(&self.cfg.cgroup_path)?;

        let bpf_cfg = BpfConfig::new(
            self.cfg.mss,
            self.cfg.restore_mss,
            self.cfg.restore_after_bytes,
            true,
        );
        engine.push_config(bpf_cfg)?;
        engine.push_target_ports(&self.cfg.ports)?;
        engine.push_exclude_ips(&self.cfg.exclude_ips)?;

        let raw_socket = Arc::new(RawSocket::new()?);
        let estimator = self.cfg.auto_ttl_estimator.clone();
        let running = self.running.clone();
        let fake_sni = self.cfg.fake_sni.clone();
        let fake_bad_checksum = self.cfg.fake_bad_checksum;
        running.store(true, Ordering::SeqCst);

        self.engine = Some(engine);

        info!(
            mss = self.cfg.mss,
            fallback_ttl = self.cfg.fake_ttl,
            fake_sni = ?self.cfg.fake_sni,
            bad_checksum = self.cfg.fake_bad_checksum,
            pqc = self.cfg.pqc,
            ports = ?self.cfg.ports,
            "albus active — MSS fragmentation + Auto-TTL fake injection"
        );

        let mut engine_poll = self.engine.take().unwrap();
        let running_clone = running.clone();

        let fake_payload = if let Some(ref sni) = fake_sni {
            crate::core::fake::clienthello::build_fake_client_hello_opts(sni, self.cfg.pqc)
        } else {
            crate::core::fake::clienthello::build_fake_client_hello_opts("www.google.com", self.cfg.pqc)
        };

        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok();

            while running_clone.load(Ordering::Relaxed) {
                let mut received = false;
                engine_poll.poll_events(|raw_evt: RawConnEvent| {
                    received = true;
                    let conn = ConnInfo::new(
                        Ipv4Addr::from(raw_evt.src_ip.to_ne_bytes()),
                        Ipv4Addr::from(raw_evt.dst_ip.to_ne_bytes()),
                        raw_evt.src_port,
                        raw_evt.dst_port,
                        raw_evt.seq,
                        raw_evt.ack,
                    );

                    // dynamically resolve optimal ttl for destination
                    let optimal_ttl = estimator.get_ttl(conn.dst_ip);

                    if let Err(e) = raw_socket.send_fake_opts(&conn, &fake_payload, optimal_ttl, fake_bad_checksum) {
                        warn!("Failed to inject fake ClientHello: {}", e);
                    } else {
                        let mut dst_desc = format!("{}:{}", conn.dst_ip, conn.dst_port);

                        if let (Some(server), Some(runtime)) = (&dns_server, &rt) {
                            if let Some(domain) = runtime.block_on(server.pop_domain(conn.dst_ip)) {
                                dst_desc = format!("{}:{}", domain, conn.dst_port);
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
    pub fn stop(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            info!("Stopping albus eBPF manager");
            self.running.store(false, Ordering::SeqCst);
            if let Some(handle) = self.worker_handle.take() {
                let _ = handle.join();
            }
            info!("albus eBPF manager stopped");
        }
    }
}

impl Drop for BpfManager {
    fn drop(&mut self) {
        self.stop();
    }
}
