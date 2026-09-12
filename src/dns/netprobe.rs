//! Network connectivity probe (coldstart netprobe) before proxy startup.
//!
//! Verifies that outbound network routing and Internet connectivity are operational
//! before starting upstream DNS resolvers, avoiding early startup failures on boot.

use std::time::Duration;
use tracing::{info, warn};

pub async fn wait_for_network(addr: &str, timeout_secs: i32) -> bool {
    if timeout_secs == 0 {
        return true;
    }

    info!(
        "netprobe: probing network connectivity via {} (timeout: {}s)...",
        addr, timeout_secs
    );
    let start = std::time::Instant::now();
    let max_duration = if timeout_secs < 0 {
        Duration::from_secs(86400 * 365)
    } else {
        Duration::from_secs(timeout_secs as u64)
    };

    while start.elapsed() < max_duration {
        // Try TCP connect first (with a short 1s timeout per attempt)
        let tcp_attempt =
            tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr))
                .await;

        if let Ok(Ok(_)) = tcp_attempt {
            info!(
                "netprobe: network connectivity verified via TCP to {}",
                addr
            );
            return true;
        }

        // Also test UDP routing probe
        let bind_addr = if addr.starts_with('[')
            || addr
                .parse::<std::net::SocketAddr>()
                .map(|s| s.is_ipv6())
                .unwrap_or(false)
        {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        if let Ok(socket) = tokio::net::UdpSocket::bind(bind_addr).await {
            if socket.connect(addr).await.is_ok() {
                let dummy_ping = [0u8; 1];
                if socket.send(&dummy_ping).await.is_ok() {
                    info!("netprobe: network route to {} is reachable via UDP", addr);
                    return true;
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    warn!(
        "netprobe: connectivity check timed out after {}s; proceeding with startup",
        timeout_secs
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_netprobe_zero_timeout_immediate() {
        assert!(wait_for_network("9.9.9.9:53", 0).await);
    }
}
