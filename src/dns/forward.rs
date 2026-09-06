//! domain-based split-dns forwarding engine (forwarding-rules.txt).
//!
//! routes dedicated intranet, enterprise, or homelab zones (*.corp, *.lan)
//! directly to internal dns servers via standard udp/tcp transport,
//! while general traffic is resolved over encrypted upstream providers.

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct ForwardRule {
    pub pattern: String,
    pub is_wildcard: bool,
    pub servers: Vec<SocketAddr>,
    pub counter: Arc<AtomicUsize>,
}

#[derive(Debug, Clone, Default)]
pub struct ForwardingEngine {
    exact_rules: HashMap<String, ForwardRule>,
    wildcard_rules: Vec<ForwardRule>,
}

impl ForwardingEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let content = fs::read_to_string(path)?;
        Ok(Self::from_text(&content))
    }

    pub fn from_text(content: &str) -> Self {
        let mut engine = Self::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let pattern = parts[0];
            let mut servers = Vec::new();

            for s in parts[1].split(',') {
                let s_trim = s.trim();
                if let Ok(sa) = s_trim.parse::<SocketAddr>() {
                    servers.push(sa);
                } else if let Ok(ip) = s_trim.parse::<std::net::IpAddr>() {
                    servers.push(SocketAddr::new(ip, 53));
                }
            }

            if !servers.is_empty() {
                engine.add_rule(pattern, servers);
            }
        }
        engine
    }

    pub fn add_rule(&mut self, pattern: &str, servers: Vec<SocketAddr>) {
        let clean = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        let is_wildcard = clean.starts_with("*.") || clean.starts_with('.');
        let rule_pattern = if clean.starts_with("*.") {
            clean[2..].to_string()
        } else if clean.starts_with('.') {
            clean[1..].to_string()
        } else {
            clean
        };

        let rule = ForwardRule {
            pattern: rule_pattern.clone(),
            is_wildcard,
            servers,
            counter: Arc::new(AtomicUsize::new(0)),
        };

        if is_wildcard {
            self.wildcard_rules.push(rule);
        } else {
            self.exact_rules.insert(rule_pattern, rule);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.exact_rules.is_empty() && self.wildcard_rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.exact_rules.len() + self.wildcard_rules.len()
    }

    pub fn find_target(&self, domain: &str) -> Option<SocketAddr> {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();

        // 1. check exact rule
        if let Some(rule) = self.exact_rules.get(&clean) {
            if !rule.servers.is_empty() {
                let idx = rule.counter.fetch_add(1, Ordering::Relaxed) % rule.servers.len();
                return Some(rule.servers[idx]);
            }
        }

        // 2. check wildcard rules (e.g. corp.internal matches app.corp.internal)
        for rule in &self.wildcard_rules {
            if clean == rule.pattern || clean.ends_with(&format!(".{}", rule.pattern)) {
                if !rule.servers.is_empty() {
                    let idx = rule.counter.fetch_add(1, Ordering::Relaxed) % rule.servers.len();
                    return Some(rule.servers[idx]);
                }
            }
        }

        None
    }

    pub async fn forward_query(
        &self,
        query: &[u8],
        target: SocketAddr,
    ) -> Result<Vec<u8>, std::io::Error> {
        let bind_addr: SocketAddr = if target.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let sock = UdpSocket::bind(bind_addr).await?;
        sock.send_to(query, target).await?;

        let mut buf = vec![0u8; 4096];
        let (n, _) = timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "udp forward query timeout"))??;

        buf.truncate(n);

        // If truncated (TC bit = 1), fallback to TCP
        if n >= 4 && (buf[2] & 0x02) != 0 {
            debug!(target = %target, "UDP response truncated (TC=1); falling back to TCP forward");
            if let Ok(tcp_resp) = self.forward_query_tcp(query, target).await {
                return Ok(tcp_resp);
            }
        }

        Ok(buf)
    }

    pub async fn forward_query_tcp(
        &self,
        query: &[u8],
        target: SocketAddr,
    ) -> Result<Vec<u8>, std::io::Error> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = timeout(Duration::from_secs(2), TcpStream::connect(target))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp forward connect timeout"))??;

        let len_prefix = (query.len() as u16).to_be_bytes();
        stream.write_all(&len_prefix).await?;
        stream.write_all(query).await?;
        stream.flush().await?;

        let mut resp_len_buf = [0u8; 2];
        timeout(Duration::from_secs(2), stream.read_exact(&mut resp_len_buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp forward read len timeout"))??;

        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        timeout(Duration::from_secs(2), stream.read_exact(&mut resp))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp forward read body timeout"))??;

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_forwarding_rules_from_text() {
        let rules_txt = r#"
        # comment line
        example.corp 10.0.0.1:53
        *.internal 192.168.1.1:53, 192.168.1.2:53
        local.lan 127.0.0.1
        "#;

        let engine = ForwardingEngine::from_text(rules_txt);
        assert_eq!(engine.len(), 3);

        // Exact match
        let t1 = engine.find_target("example.corp").expect("should match exact");
        assert_eq!(t1, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53));

        // Wildcard match
        let t2a = engine.find_target("auth.internal").expect("should match wildcard");
        let t2b = engine.find_target("db.internal").expect("should match wildcard");
        let valid_targets = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 53),
        ];
        assert!(valid_targets.contains(&t2a));
        assert!(valid_targets.contains(&t2b));

        // IP without port (defaults to 53)
        let t3 = engine.find_target("local.lan").expect("should match local.lan");
        assert_eq!(t3, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53));

        // Unmatched domain
        assert!(engine.find_target("google.com").is_none());
    }

    #[tokio::test]
    async fn test_forward_query_timeout_on_unreachable() {
        let engine = ForwardingEngine::new();
        // Send to non-listening blackhole address
        let fake_target: SocketAddr = "127.0.0.1:59999".parse().unwrap();
        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let res = engine.forward_query(query, fake_target).await;
        assert!(res.is_err());
    }
}
