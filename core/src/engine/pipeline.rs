// packet bridge with dpi evasion strategies, 0-rtt early data segmentation, rst injection resilience, and volatile zeroization

use crate::engine::connector::MarkedConnector;
use crate::engine::monitor::ActivityMonitor;
use crate::protocol::http::HttpParser;
use crate::protocol::tls::TlsParser;
use crate::strategy::adaptive::AdaptiveEvasionEngine;
use crate::strategy::disorder::DisorderStrategy;
use crate::strategy::fake_ttl::GhostSniStrategy;
use crate::strategy::split::SniSplitter;
use crate::strategy::BypassMode;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Result};
use tokio::net::TcpStream;
use zeroize::Zeroize;

#[derive(Default)]
pub struct EngineMetrics {
    pub total_connections: AtomicU64,
    pub bypassed_tls_sessions: AtomicU64,
    pub bypassed_http_sessions: AtomicU64,
    pub bytes_protected: AtomicU64,
    pub dns_poison_blocks: AtomicU64,
}

pub struct Pipeline;

impl Pipeline {
    // bridges client and remote connection with dynamic packet segmentation, 0-rtt early data handling, and rst retry resilience
    pub async fn bridge(
        mut client: TcpStream,
        mut remote: TcpStream,
        sock_addr: Option<SocketAddr>,
        target_name: String,
        mode: BypassMode,
        metrics: Arc<EngineMetrics>,
        monitor: Arc<ActivityMonitor>,
        adaptive: Arc<AdaptiveEvasionEngine>,
    ) -> Result<()> {
        metrics.total_connections.fetch_add(1, Ordering::Relaxed);

        let mut initial_buf = vec![0u8; 8192];
        let n = client.read(&mut initial_buf).await?;

        if n == 0 {
            initial_buf.zeroize();
            return Ok(());
        }

        metrics.bytes_protected.fetch_add(n as u64, Ordering::Relaxed);
        let payload = &initial_buf[..n];

        // 1. inspect for tls clienthello (transparent layer-4 evasion)
        if TlsParser::is_client_hello(payload) {
            metrics.bypassed_tls_sessions.fetch_add(1, Ordering::Relaxed);

            let real_target = TlsParser::extract_sni(payload).unwrap_or(target_name);
            let is_early_data = TlsParser::has_early_data_extension(payload);
            let is_ech = TlsParser::has_ech_extension(payload);
            let dispatch_payload = payload;
            let effective_mode = adaptive.get_strategy(&real_target, mode);


            let strat_label = if is_ech {
                "TLS ECH"
            } else if is_early_data {
                "TLS 0-RTT"
            } else {
                match effective_mode {
                    BypassMode::StealthAuto | BypassMode::SniSplit => "TLS Split",
                    BypassMode::FakeTtl => "Ghost SNI",
                    BypassMode::Disorder => "Disorder",
                }
            };


            monitor.record_event(&real_target, strat_label, "OK");

            let res = match effective_mode {
                BypassMode::StealthAuto | BypassMode::SniSplit => {
                    SniSplitter::send_split(&mut remote, dispatch_payload, 1).await
                }
                BypassMode::FakeTtl => {
                    GhostSniStrategy::send_with_ghost_decoy(&mut remote, dispatch_payload).await
                }
                BypassMode::Disorder => {
                    DisorderStrategy::send_disordered(&mut remote, dispatch_payload, 16).await
                }
            };

            // spoofed rst injection resilience: if initial write failed on reset, attempt fallback reconnection
            if let Err(ref err) = res {
                if err.kind() == std::io::ErrorKind::ConnectionReset || err.kind() == std::io::ErrorKind::BrokenPipe {
                    if let Some(addr) = sock_addr {

                        adaptive.record_failure(&real_target);
                        if let Ok(mut retry_remote) = MarkedConnector::connect(addr).await {
                            let _ = retry_remote.set_nodelay(true);
                            let _ = DisorderStrategy::send_disordered(&mut retry_remote, payload, 16).await;
                            monitor.record_event(&real_target, "RST Recover", "OK");

                            initial_buf.zeroize();
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut retry_remote).await;
                            return Ok(());
                        }
                    }
                }
                adaptive.record_failure(&real_target);
                return res;
            } else {
                adaptive.record_success(&real_target);
            }
        }

        // 2. inspect for http/2 connection magic preface (preface segmentation)
        else if HttpParser::is_http2_preface(payload) {
            metrics.bypassed_http_sessions.fetch_add(1, Ordering::Relaxed);
            monitor.record_event(&target_name, "H2 Split", "OK");

            SniSplitter::send_split(&mut remote, payload, 12).await?;
        }
        // 3. inspect for plain http request (mutate Host header & sanitize tracking headers)
        else if HttpParser::is_http_request(payload) {
            metrics.bypassed_http_sessions.fetch_add(1, Ordering::Relaxed);
            monitor.record_event(&target_name, "HTTP Mutate", "OK");

            let mutated_payload = HttpParser::mutate_and_sanitize_http_request(payload);

            if let Some((host_start, _)) = HttpParser::find_host_header(&mutated_payload) {
                SniSplitter::send_split(&mut remote, &mutated_payload, host_start).await?;
            } else {
                SniSplitter::send_split(&mut remote, &mutated_payload, 2).await?;
            }
        }

        // 4. passthrough non-inspected streams
        else {
            monitor.record_event(&target_name, "Direct Pass", "OK");
            remote.write_all(payload).await?;
            remote.flush().await?;
        }

        // volatile zeroize initial packet memory immediately after handshake dispatch
        initial_buf.zeroize();

        // bidirectional bridge with byte counting and throughput tracking
        if let Ok((copied_down, copied_up)) = tokio::io::copy_bidirectional(&mut client, &mut remote).await {
            let total_bytes = copied_down + copied_up;
            metrics.bytes_protected.fetch_add(total_bytes, Ordering::Relaxed);
            monitor.record_bytes(total_bytes);
        }

        Ok(())
    }
}

