//! prometheus metrics http server endpoint (/metrics) for albus.
//!
//! exposes atomic dns query statistics, cache performance, and filtering drops in
//! standard prometheus text exposition format (version 0.0.4) for grafana and prometheus collectors.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Semaphore};
use tracing::{debug, error, info, warn};

use super::stats::DnsStats;

pub struct MetricsServer;

const MAX_CONCURRENT_METRICS_CONNS: usize = 64;
const MAX_REQUEST_SIZE: usize = 4096;

impl MetricsServer {
    pub fn start(
        bind_addr: SocketAddr,
        stats: Arc<DnsStats>,
        shutdown_rx: broadcast::Receiver<()>,
    ) {
        tokio::spawn(async move {
            let listener = match TcpListener::bind(bind_addr).await {
                Ok(l) => {
                    info!(addr = %bind_addr, "Prometheus metrics server active on http://{}/metrics", bind_addr);
                    l
                }
                Err(e) => {
                    warn!("failed to bind Prometheus metrics server to {}: {}", bind_addr, e);
                    return;
                }
            };

            Self::run_listener(listener, stats, shutdown_rx).await;
        });
    }

    pub async fn run_listener(
        listener: TcpListener,
        stats: Arc<DnsStats>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_METRICS_CONNS));

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((mut stream, _peer_addr)) => {
                            let permit = match sem.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    debug!("metrics server max connection limit reached; dropping connection");
                                    continue;
                                }
                            };
                            let stats_clone = stats.clone();

                            tokio::spawn(async move {
                                let _permit = permit;
                                let mut buf = [0u8; MAX_REQUEST_SIZE];

                                let read_res = tokio::time::timeout(
                                    Duration::from_secs(3),
                                    stream.read(&mut buf),
                                )
                                .await;

                                let n = match read_res {
                                    Ok(Ok(n)) if n > 0 => n,
                                    _ => return,
                                };

                                let req_str = String::from_utf8_lossy(&buf[..n]);
                                let first_line = req_str.lines().next().unwrap_or("");
                                let parts: Vec<&str> = first_line.split_whitespace().collect();

                                if parts.len() < 2 {
                                    return;
                                }

                                let method = parts[0];
                                let path = parts[1];

                                let response = if method == "GET" && (path == "/metrics" || path == "/") {
                                    let body = stats_clone.to_prometheus_text();
                                    format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        body.len(),
                                        body
                                    )
                                } else if method == "GET" && (path == "/health" || path == "/live") {
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".to_string()
                                } else {
                                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found".to_string()
                                };

                                let _ = stream.write_all(response.as_bytes()).await;
                                let _ = stream.flush().await;
                            });
                        }
                        Err(e) => {
                            warn!("metrics listener accept error: {}; continuing", e);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    debug!("Prometheus metrics server received shutdown signal");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn test_metrics_server_get_metrics() {
        let stats = DnsStats::new();
        stats.total_queries.fetch_add(100, Ordering::Relaxed);
        stats.queries_udp.fetch_add(90, Ordering::Relaxed);
        stats.queries_doh.fetch_add(10, Ordering::Relaxed);
        stats.cache_hits.fetch_add(45, Ordering::Relaxed);

        let (shutdown_tx, _) = broadcast::channel(1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let s_stats = stats.clone();
        let rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            MetricsServer::run_listener(listener, s_stats, rx).await;
        });

        let mut client = tokio::net::TcpStream::connect(actual_addr).await.unwrap();
        let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
        client.write_all(request.as_bytes()).await.unwrap();

        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf);

        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("albus_dns_queries_total{protocol=\"udp\"} 90"));
        assert!(resp.contains("albus_dns_cache_hits_total 45"));
        assert!(resp.contains("albus_dns_cache_hit_ratio 45.00"));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_metrics_server_get_health_and_not_found() {
        let stats = DnsStats::new();
        let (shutdown_tx, _) = broadcast::channel(1);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let s_stats = stats.clone();
        let rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            MetricsServer::run_listener(listener, s_stats, rx).await;
        });

        // test /health
        {
            let mut client = tokio::net::TcpStream::connect(actual_addr).await.unwrap();
            client.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
            let mut buf = Vec::new();
            client.read_to_end(&mut buf).await.unwrap();
            let resp = String::from_utf8_lossy(&buf);
            assert!(resp.starts_with("HTTP/1.1 200 OK"));
            assert!(resp.ends_with("OK"));
        }

        // test /nonexistent
        {
            let mut client = tokio::net::TcpStream::connect(actual_addr).await.unwrap();
            client.write_all(b"GET /random HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
            let mut buf = Vec::new();
            client.read_to_end(&mut buf).await.unwrap();
            let resp = String::from_utf8_lossy(&buf);
            assert!(resp.starts_with("HTTP/1.1 404 Not Found"));
        }

        let _ = shutdown_tx.send(());
    }
}
