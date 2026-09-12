//! domain-based split-dns forwarding engine (forwarding-rules.txt).
//!
//! routes dedicated intranet, enterprise, or homelab zones (*.corp, *.lan)
//! directly to internal dns servers via standard udp/tcp transport,
//! while general traffic is resolved over encrypted upstream providers.
//! Supports dnscrypt-proxy syntax including $BOOTSTRAP, $DHCP, $RESOLVCONF:<file>, and $PROXY: prefixes.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::debug;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardTargetItem {
    Explicit(Vec<SocketAddr>),
    Bootstrap,
    Dhcp,
    ResolvConf(String),
}

#[derive(Debug, Clone)]
pub struct ForwardRule {
    pub pattern: String,
    pub is_wildcard: bool,
    pub servers: Vec<SocketAddr>,
    pub sequence: Vec<ForwardTargetItem>,
    pub via_proxy: bool,
    pub counter: Arc<AtomicUsize>,
}

#[derive(Debug, Clone, Default)]
pub struct ForwardingEngine {
    exact_rules: HashMap<String, ForwardRule>,
    wildcard_rules: Vec<ForwardRule>,
    pub bootstrap_resolvers: Vec<SocketAddr>,
    pub socks5_proxy: Option<String>,
}

impl ForwardingEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_bootstrap_resolvers(mut self, resolvers: Vec<SocketAddr>) -> Self {
        self.bootstrap_resolvers = resolvers;
        self
    }

    pub fn with_socks5_proxy(mut self, proxy: Option<String>) -> Self {
        self.socks5_proxy = proxy;
        self
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
            let mut via_proxy = false;
            let target_str = if parts[1].starts_with("$PROXY:") {
                via_proxy = true;
                &parts[1]["$PROXY:".len()..]
            } else {
                parts[1]
            };

            let mut explicit_servers = Vec::new();
            let mut sequence = Vec::new();

            for s in target_str.split(',') {
                let s_trim = s.trim();
                if s_trim.is_empty() {
                    continue;
                }

                if s_trim == "$BOOTSTRAP" {
                    sequence.push(ForwardTargetItem::Bootstrap);
                } else if s_trim == "$DHCP" {
                    sequence.push(ForwardTargetItem::Dhcp);
                } else if let Some(rc_path) = s_trim.strip_prefix("$RESOLVCONF:") {
                    let clean_path = rc_path.trim();
                    if !clean_path.is_empty() {
                        sequence.push(ForwardTargetItem::ResolvConf(clean_path.to_string()));
                    }
                } else if let Ok(sa) = s_trim.parse::<SocketAddr>() {
                    explicit_servers.push(sa);
                } else if let Ok(ip) = s_trim.parse::<IpAddr>() {
                    explicit_servers.push(SocketAddr::new(ip, 53));
                }
            }

            if !explicit_servers.is_empty() {
                sequence.insert(0, ForwardTargetItem::Explicit(explicit_servers.clone()));
            }

            if !sequence.is_empty() {
                engine.add_rule_with_sequence(pattern, explicit_servers, sequence, via_proxy);
            }
        }
        engine
    }

    pub fn add_rule(&mut self, pattern: &str, servers: Vec<SocketAddr>) {
        let sequence = vec![ForwardTargetItem::Explicit(servers.clone())];
        self.add_rule_with_sequence(pattern, servers, sequence, false);
    }

    pub fn add_rule_with_sequence(
        &mut self,
        pattern: &str,
        servers: Vec<SocketAddr>,
        sequence: Vec<ForwardTargetItem>,
        via_proxy: bool,
    ) {
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
            sequence,
            via_proxy,
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

    pub fn find_rule(&self, domain: &str) -> Option<&ForwardRule> {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();

        // 1. check exact rule
        if let Some(rule) = self.exact_rules.get(&clean) {
            return Some(rule);
        }

        // 2. check wildcard rules (e.g. corp.internal matches app.corp.internal)
        for rule in &self.wildcard_rules {
            if clean == rule.pattern || clean.ends_with(&format!(".{}", rule.pattern)) {
                return Some(rule);
            }
        }

        None
    }

    pub fn find_target(&self, domain: &str) -> Option<SocketAddr> {
        if let Some(rule) = self.find_rule(domain) {
            if !rule.servers.is_empty() {
                let idx = rule.counter.fetch_add(1, Ordering::Relaxed) % rule.servers.len();
                return Some(rule.servers[idx]);
            }
        }
        None
    }

    /// Resolves query across candidate targets defined by the matching domain rule in fallback sequence.
    pub async fn forward_query_for_domain(
        &self,
        query: &[u8],
        domain: &str,
    ) -> Option<Result<Vec<u8>, std::io::Error>> {
        let rule = self.find_rule(domain)?.clone();

        let mut last_err = None;

        for item in &rule.sequence {
            match item {
                ForwardTargetItem::Explicit(servers) => {
                    if servers.is_empty() {
                        continue;
                    }
                    let idx = rule.counter.fetch_add(1, Ordering::Relaxed) % servers.len();
                    let target = servers[idx];
                    match self
                        .forward_query_with_proxy(query, target, rule.via_proxy)
                        .await
                    {
                        Ok(resp) => return Some(Ok(resp)),
                        Err(e) => last_err = Some(e),
                    }
                }
                ForwardTargetItem::Bootstrap => {
                    for target in &self.bootstrap_resolvers {
                        match self
                            .forward_query_with_proxy(query, *target, rule.via_proxy)
                            .await
                        {
                            Ok(resp) => return Some(Ok(resp)),
                            Err(e) => last_err = Some(e),
                        }
                    }
                }
                ForwardTargetItem::Dhcp => {
                    let dhcp_resolvers = detect_dhcp_resolvers();
                    for target in dhcp_resolvers {
                        match self
                            .forward_query_with_proxy(query, target, rule.via_proxy)
                            .await
                        {
                            Ok(resp) => return Some(Ok(resp)),
                            Err(e) => last_err = Some(e),
                        }
                    }
                }
                ForwardTargetItem::ResolvConf(path) => {
                    let rc_resolvers = parse_resolv_conf_nameservers(path);
                    for target in rc_resolvers {
                        match self
                            .forward_query_with_proxy(query, target, rule.via_proxy)
                            .await
                        {
                            Ok(resp) => return Some(Ok(resp)),
                            Err(e) => last_err = Some(e),
                        }
                    }
                }
            }
        }

        Some(Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "all forwarding targets failed or unavailable",
            )
        })))
    }

    pub async fn forward_query(
        &self,
        query: &[u8],
        target: SocketAddr,
    ) -> Result<Vec<u8>, std::io::Error> {
        self.forward_query_with_proxy(query, target, false).await
    }

    pub async fn forward_query_with_proxy(
        &self,
        query: &[u8],
        target: SocketAddr,
        via_proxy: bool,
    ) -> Result<Vec<u8>, std::io::Error> {
        if via_proxy {
            if let Some(ref proxy_url) = self.socks5_proxy {
                return self.forward_query_socks5(query, target, proxy_url).await;
            }
            return self.forward_query_tcp(query, target).await;
        }

        let bind_addr: SocketAddr = if target.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let sock = UdpSocket::bind(bind_addr).await?;
        let _ = sock.connect(target).await;
        sock.send(query).await?;

        let mut buf = vec![0u8; 4096];
        let timeout_dur = Duration::from_secs(2);
        let start = std::time::Instant::now();

        let n = loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout_dur {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "udp forward query timeout",
                ));
            }
            let remaining = timeout_dur - elapsed;
            let recv_len = timeout(remaining, sock.recv(&mut buf))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "udp forward query timeout")
                })??;

            if recv_len >= 2 && query.len() >= 2 && (buf[0] != query[0] || buf[1] != query[1]) {
                // Ignore mismatched transaction ID
                continue;
            }
            break recv_len;
        };

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
        let mut stream = timeout(Duration::from_secs(2), TcpStream::connect(target))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp forward connect timeout")
            })??;

        let len_prefix = (query.len() as u16).to_be_bytes();
        stream.write_all(&len_prefix).await?;
        stream.write_all(query).await?;
        stream.flush().await?;

        let mut resp_len_buf = [0u8; 2];
        timeout(Duration::from_secs(2), stream.read_exact(&mut resp_len_buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp forward read len timeout")
            })??;

        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        timeout(Duration::from_secs(2), stream.read_exact(&mut resp))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "tcp forward read body timeout",
                )
            })??;

        Ok(resp)
    }

    async fn forward_query_socks5(
        &self,
        query: &[u8],
        target: SocketAddr,
        proxy_url: &str,
    ) -> Result<Vec<u8>, std::io::Error> {
        let parsed_url = url::Url::parse(proxy_url).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid socks5 proxy URL: {}", e),
            )
        })?;
        let host = parsed_url.host_str().unwrap_or("127.0.0.1");
        let port = parsed_url.port().unwrap_or(1080);
        let proxy_addr = format!("{}:{}", host, port);

        let mut stream = timeout(Duration::from_secs(2), TcpStream::connect(&proxy_addr))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "socks5 proxy connect timeout")
            })??;

        // SOCKS5 handshake (no authentication)
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut handshake_resp = [0u8; 2];
        stream.read_exact(&mut handshake_resp).await?;
        if handshake_resp[0] != 0x05 || handshake_resp[1] != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "socks5 handshake rejected",
            ));
        }

        // SOCKS5 CONNECT command
        let mut req = Vec::new();
        req.extend_from_slice(&[0x05, 0x01, 0x00]);
        match target.ip() {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
        req.extend_from_slice(&target.port().to_be_bytes());
        stream.write_all(&req).await?;

        let mut resp_header = [0u8; 4];
        stream.read_exact(&mut resp_header).await?;
        if resp_header[1] != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("socks5 connect failed with status 0x{:02x}", resp_header[1]),
            ));
        }

        // Read bind address based on ATYP
        match resp_header[3] {
            0x01 => {
                let mut discard = [0u8; 6];
                stream.read_exact(&mut discard).await?;
            }
            0x04 => {
                let mut discard = [0u8; 18];
                stream.read_exact(&mut discard).await?;
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let mut discard = vec![0u8; len_buf[0] as usize + 2];
                stream.read_exact(&mut discard).await?;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "socks5 invalid atyp in response",
                ));
            }
        }

        // Now connected through proxy - send standard DNS over TCP (RFC 7766)
        let len_prefix = (query.len() as u16).to_be_bytes();
        stream.write_all(&len_prefix).await?;
        stream.write_all(query).await?;
        stream.flush().await?;

        let mut resp_len_buf = [0u8; 2];
        stream.read_exact(&mut resp_len_buf).await?;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await?;

        Ok(resp)
    }
}

/// Parses nameserver IP addresses from a resolv.conf formatted file.
pub fn parse_resolv_conf_nameservers<P: AsRef<Path>>(path: P) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(ip) = parts[1].parse::<IpAddr>() {
                        addrs.push(SocketAddr::new(ip, 53));
                    }
                }
            }
        }
    }
    addrs
}

/// Discovers DHCP-assigned DNS resolvers on Linux via system lease files or resolv.conf.
pub fn detect_dhcp_resolvers() -> Vec<SocketAddr> {
    let mut addrs = Vec::new();

    // 1. systemd-networkd lease files
    if let Ok(entries) = fs::read_dir("/run/systemd/netif/leases") {
        for entry in entries.flatten() {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                for line in content.lines() {
                    if let Some(dns_val) = line.strip_prefix("DNS=") {
                        for ip_str in dns_val.split_whitespace() {
                            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                addrs.push(SocketAddr::new(ip, 53));
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. NetworkManager lease files
    if addrs.is_empty() {
        if let Ok(entries) = fs::read_dir("/var/lib/NetworkManager") {
            for entry in entries.flatten() {
                if entry.path().extension().map_or(false, |ext| ext == "lease") {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        for line in content.lines() {
                            if let Some(dns_val) = line.strip_prefix("domain_name_servers=") {
                                let clean = dns_val.trim_matches('\'').trim_matches('"');
                                for ip_str in clean.split_whitespace() {
                                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                        addrs.push(SocketAddr::new(ip, 53));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Fallback to /etc/resolv.conf
    if addrs.is_empty() {
        addrs.extend(parse_resolv_conf_nameservers("/etc/resolv.conf"));
    }

    addrs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
        let t1 = engine
            .find_target("example.corp")
            .expect("should match exact");
        assert_eq!(
            t1,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53)
        );

        // Wildcard match
        let t2a = engine
            .find_target("auth.internal")
            .expect("should match wildcard");
        let t2b = engine
            .find_target("db.internal")
            .expect("should match wildcard");
        let valid_targets = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 53),
        ];
        assert!(valid_targets.contains(&t2a));
        assert!(valid_targets.contains(&t2b));

        // IP without port (defaults to 53)
        let t3 = engine
            .find_target("local.lan")
            .expect("should match local.lan");
        assert_eq!(
            t3,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53)
        );

        // Unmatched domain
        assert!(engine.find_target("google.com").is_none());
    }

    #[test]
    fn test_forwarding_rules_keywords_and_proxy() {
        let rules_txt = r#"
        corp.lan 192.168.1.1,$DHCP,$BOOTSTRAP,$RESOLVCONF:/tmp/test_resolv.conf
        proxy.org $PROXY:10.0.0.1:53,10.0.0.2:53
        "#;

        let engine = ForwardingEngine::from_text(rules_txt);
        assert_eq!(engine.len(), 2);

        let corp_rule = engine.find_rule("corp.lan").expect("corp.lan rule found");
        assert_eq!(corp_rule.via_proxy, false);
        assert_eq!(corp_rule.sequence.len(), 4);
        assert!(matches!(
            corp_rule.sequence[0],
            ForwardTargetItem::Explicit(_)
        ));
        assert_eq!(corp_rule.sequence[1], ForwardTargetItem::Dhcp);
        assert_eq!(corp_rule.sequence[2], ForwardTargetItem::Bootstrap);
        assert_eq!(
            corp_rule.sequence[3],
            ForwardTargetItem::ResolvConf("/tmp/test_resolv.conf".to_string())
        );

        let proxy_rule = engine.find_rule("proxy.org").expect("proxy.org rule found");
        assert_eq!(proxy_rule.via_proxy, true);
        assert_eq!(proxy_rule.servers.len(), 2);
    }

    #[test]
    fn test_parse_resolv_conf_nameservers() {
        let tmp_path = "/tmp/albus_test_resolv_conf.tmp";
        let content = "nameserver 1.1.1.1\n# comment\nnameserver 8.8.4.4\n";
        let _ = fs::write(tmp_path, content);
        let addrs = parse_resolv_conf_nameservers(tmp_path);
        let _ = fs::remove_file(tmp_path);

        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], "1.1.1.1:53".parse().unwrap());
        assert_eq!(addrs[1], "8.8.4.4:53".parse().unwrap());
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
