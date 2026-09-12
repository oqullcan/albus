//! High-performance UDP socket connection pool.
//!
//! Reuses connected UDP sockets to upstream resolvers to avoid ephemeral port exhaustion
//! and kernel socket allocation overhead under heavy concurrent query loads.
//! Implements per-address pooling with idle timeout expiration matching dnscrypt-proxy architecture.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::debug;

pub const UDP_POOL_MAX_CONNS_PER_ADDR: usize = 4;
pub const UDP_POOL_MAX_IDLE_TIME: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct UdpConnPool {
    conns: Arc<Mutex<HashMap<SocketAddr, Vec<(Arc<UdpSocket>, Instant)>>>>,
    max_conns_per_addr: usize,
    max_idle_time: Duration,
}

impl Default for UdpConnPool {
    fn default() -> Self {
        Self::new(UDP_POOL_MAX_CONNS_PER_ADDR, UDP_POOL_MAX_IDLE_TIME)
    }
}

impl UdpConnPool {
    pub fn new(max_conns_per_addr: usize, max_idle_time: Duration) -> Self {
        let pool = Self {
            conns: Arc::new(Mutex::new(HashMap::new())),
            max_conns_per_addr,
            max_idle_time,
        };

        // Spawn periodic background cleanup if a Tokio runtime handle is available
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let pool_clone = pool.clone();
            handle.spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(10));
                loop {
                    interval.tick().await;
                    pool_clone.cleanup_stale().await;
                }
            });
        }

        pool
    }

    /// Acquires an idle connected UDP socket for target or creates a new one
    pub async fn get_or_create(
        &self,
        target: SocketAddr,
    ) -> Result<Arc<UdpSocket>, std::io::Error> {
        let now = Instant::now();
        {
            let mut guard = self.conns.lock().await;
            if let Some(list) = guard.get_mut(&target) {
                while let Some((sock, last_used)) = list.pop() {
                    if now.duration_since(last_used) <= self.max_idle_time {
                        // Drain any stale/delayed datagrams received after previous query timeout
                        let mut drain_buf = [0u8; 4096];
                        while sock.try_recv(&mut drain_buf).is_ok() {}
                        return Ok(sock);
                    }
                }
            }
        }

        // Create new socket connected to target
        let bind_addr: SocketAddr = if target.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let sock = UdpSocket::bind(bind_addr).await?;
        sock.connect(target).await?;
        Ok(Arc::new(sock))
    }

    /// Returns a socket back into the pool for future reuse
    pub async fn return_conn(&self, target: SocketAddr, socket: Arc<UdpSocket>) {
        let mut guard = self.conns.lock().await;
        // Limit total distinct addresses to prevent unbounded memory growth
        if guard.len() >= 256 && !guard.contains_key(&target) {
            return;
        }
        let list = guard.entry(target).or_default();
        if list.len() < self.max_conns_per_addr {
            list.push((socket, Instant::now()));
        }
    }

    /// Cleans up idle connections exceeding max idle time
    pub async fn cleanup_stale(&self) {
        let now = Instant::now();
        let mut guard = self.conns.lock().await;
        let mut empty_addrs = Vec::new();

        for (addr, list) in guard.iter_mut() {
            let initial_len = list.len();
            list.retain(|(_, last_used)| now.duration_since(*last_used) <= self.max_idle_time);
            if list.len() < initial_len {
                debug!(addr = %addr, closed = initial_len - list.len(), "UDP pool: closed stale idle connections");
            }
            if list.is_empty() {
                empty_addrs.push(*addr);
            }
        }

        for addr in empty_addrs {
            guard.remove(&addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_pool_acquire_and_reuse() {
        let pool = UdpConnPool::new(2, Duration::from_secs(5));
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap(); // discard port

        let s1 = pool.get_or_create(target).await.expect("bind socket 1");
        pool.return_conn(target, s1.clone()).await;

        let s2 = pool.get_or_create(target).await.expect("bind socket 2");
        assert!(Arc::ptr_eq(&s1, &s2), "pool must reuse active idle socket");
    }

    #[tokio::test]
    async fn test_udp_pool_cleanup_expired() {
        let pool = UdpConnPool::new(2, Duration::from_millis(50));
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap();

        let s1 = pool.get_or_create(target).await.unwrap();
        pool.return_conn(target, s1).await;

        tokio::time::sleep(Duration::from_millis(70)).await;
        pool.cleanup_stale().await;

        let guard = pool.conns.lock().await;
        assert!(guard.get(&target).is_none() || guard.get(&target).unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_udp_pool_drains_stale_datagrams() {
        // Bind mock UDP server
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let pool = UdpConnPool::new(2, Duration::from_secs(5));

        // Acquire socket, send initial byte, and return to pool
        let client_sock = pool.get_or_create(server_addr).await.unwrap();
        client_sock.send(b"query1").await.unwrap();

        let mut srv_buf = [0u8; 64];
        let (n, client_addr) = server.recv_from(&mut srv_buf).await.unwrap();
        assert_eq!(&srv_buf[..n], b"query1");

        pool.return_conn(server_addr, client_sock.clone()).await;

        // Simulate a late arriving response while socket is idle in pool
        server
            .send_to(b"late_delayed_response", client_addr)
            .await
            .unwrap();
        // Give kernel network stack a moment to buffer the packet
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Next acquire must drain the stale packet automatically
        let reused = pool.get_or_create(server_addr).await.unwrap();
        assert!(Arc::ptr_eq(&client_sock, &reused));

        // Socket buffer should now be empty (non-blocking try_recv fails with WouldBlock)
        let mut check_buf = [0u8; 64];
        assert!(
            reused.try_recv(&mut check_buf).is_err(),
            "stale packet must have been drained"
        );
    }
}
