//! local cloaking, synthetic hosts overrides, and domain-based split-dns forwarding.
//!
//! allows mapped private services (*.lan, custom dashboards) to resolve locally at 0ms latency
//! without polluting /etc/hosts, while dispatching dedicated enterprise/intranet zones (*.corp)
//! directly to internal dns servers via standard udp transport.
//! Supports synthetic A/AAAA/PTR records and domain-to-domain CNAME cloaking / flattening with loop detection.

use super::filter::extract_question_end;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Debug, Clone)]
pub struct CloakEngine {
    exact_rules: HashMap<String, IpAddr>,
    reverse_rules: HashMap<IpAddr, String>,
    wildcard_rules: Vec<(String, IpAddr)>,
    exact_cname_rules: HashMap<String, String>,
    wildcard_cname_rules: Vec<(String, String)>,
    forward_rules: Vec<(String, SocketAddr)>,
    pub cloak_ttl: u32,
}

impl CloakEngine {
    pub fn new() -> Self {
        Self {
            exact_rules: HashMap::new(),
            reverse_rules: HashMap::new(),
            wildcard_rules: Vec::new(),
            exact_cname_rules: HashMap::new(),
            wildcard_cname_rules: Vec::new(),
            forward_rules: Vec::new(),
            cloak_ttl: 300,
        }
    }

    pub fn with_cloak_ttl(mut self, ttl: u32) -> Self {
        self.cloak_ttl = ttl;
        self
    }

    pub fn add_cloak_rule(&mut self, domain: &str, ip: IpAddr) {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if clean.starts_with("*.") {
            let suffix = clean[1..].to_string(); // e.g. ".lab.internal"
            self.wildcard_rules.push((suffix, ip));
        } else {
            self.exact_rules.insert(clean.clone(), ip);
            self.reverse_rules.insert(ip, clean);
        }
    }

    pub fn add_cname_rule(&mut self, domain: &str, target_domain: &str) {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let target_clean = target_domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if clean.starts_with("*.") {
            let suffix = clean[1..].to_string();
            self.wildcard_cname_rules.push((suffix, target_clean));
        } else if clean.starts_with('=') {
            self.exact_cname_rules
                .insert(clean[1..].to_string(), target_clean);
        } else {
            self.exact_cname_rules.insert(clean, target_clean);
        }
    }

    pub fn detect_cloaking_loops(&self) -> Result<(), String> {
        for (domain, target) in &self.exact_cname_rules {
            let mut visited = HashSet::new();
            visited.insert(domain.clone());
            let mut current = target.clone();
            while let Some(next) = self.exact_cname_rules.get(&current) {
                if visited.contains(next) {
                    return Err(format!(
                        "recursive cloaking rule detected: target [{}] loops back to cloak pattern [{}]",
                        current, next
                    ));
                }
                visited.insert(current.clone());
                current = next.clone();
            }
        }
        Ok(())
    }

    pub fn add_forward_rule(&mut self, domain_suffix: &str, target: SocketAddr) {
        let mut clean = domain_suffix.trim().to_ascii_lowercase();
        if !clean.starts_with('.') {
            clean.insert(0, '.');
        }
        self.forward_rules.push((clean, target));
    }

    /// Parses hosts file content (e.g. /etc/hosts) and populates cloak and reverse PTR rules.
    /// Format per line: <IP> <hostname> [alias1] [alias2]...
    pub fn load_hosts_str(&mut self, content: &str) -> usize {
        let mut count = 0;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line_clean = match line.split_once('#') {
                Some((clean, _comment)) => clean.trim(),
                None => line,
            };
            let mut parts = line_clean.split_whitespace();
            if let Some(ip_str) = parts.next() {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    for host in parts {
                        if !host.is_empty() {
                            self.add_cloak_rule(host, ip);
                            count += 1;
                        }
                    }
                }
            }
        }
        count
    }

    /// Loads an /etc/hosts formatted file from the specified path.
    pub fn load_hosts_file(&mut self, path: &str) -> Result<usize, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        Ok(self.load_hosts_str(&content))
    }

    /// Loads cloaking rules (either domain->IP or domain->domain CNAME) from text format.
    pub fn load_cloaking_rules_str(&mut self, content: &str) -> Result<usize, String> {
        let mut count = 0;
        for (line_idx, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let line_clean = match line.split_once('#') {
                Some((clean, _)) => clean.trim(),
                None => line,
            };
            let parts: Vec<&str> = line_clean.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let domain = parts[0];
            let target = parts[1];

            if let Ok(ip) = target.parse::<IpAddr>() {
                self.add_cloak_rule(domain, ip);
                count += 1;
            } else {
                self.add_cname_rule(domain, target);
                count += 1;
            }
        }
        self.detect_cloaking_loops()?;
        Ok(count)
    }

    /// Loads cloaking rules from a file.
    pub fn load_cloaking_rules_file(&mut self, path: &str) -> Result<usize, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read cloaking rules from {}: {}", path, e))?;
        self.load_cloaking_rules_str(&content)
    }

    // attempts to resolve domain against local cloaking table returning synthetic wire response
    pub fn resolve_cloaked(&self, domain: &str, qtype: u16, query: &[u8]) -> Option<Vec<u8>> {
        let lower = domain.trim().trim_end_matches('.').to_ascii_lowercase();

        // Handle PTR (reverse DNS lookup)
        if qtype == 12 {
            if let Some(ip) = parse_arpa_to_ip(&lower) {
                if let Some(target_domain) = self.reverse_rules.get(&ip) {
                    return Some(build_synthetic_ptr_response(
                        query,
                        target_domain,
                        self.cloak_ttl,
                    ));
                }
            }
            return None;
        }

        // 1. Direct IP Cloaking match
        let matched_ip = if let Some(&ip) = self.exact_rules.get(&lower) {
            Some(ip)
        } else {
            self.wildcard_rules
                .iter()
                .find(|(suffix, _)| {
                    lower.ends_with(suffix) || lower == suffix.trim_start_matches('.')
                })
                .map(|(_, ip)| *ip)
        };

        if let Some(ip) = matched_ip {
            return match ip {
                IpAddr::V4(v4) => {
                    if qtype == 1 {
                        Some(build_synthetic_a_response(query, v4, self.cloak_ttl))
                    } else if qtype == 28 {
                        Some(build_synthetic_nodata_response(query))
                    } else {
                        None
                    }
                }
                IpAddr::V6(v6) => {
                    if qtype == 28 {
                        Some(build_synthetic_aaaa_response(query, v6, self.cloak_ttl))
                    } else if qtype == 1 {
                        Some(build_synthetic_nodata_response(query))
                    } else {
                        None
                    }
                }
            };
        }

        // 2. CNAME Cloaking match
        let matched_cname = if let Some(target) = self.exact_cname_rules.get(&lower) {
            Some(target.as_str())
        } else {
            self.wildcard_cname_rules
                .iter()
                .find(|(suffix, _)| {
                    lower.ends_with(suffix) || lower == suffix.trim_start_matches('.')
                })
                .map(|(_, target)| target.as_str())
        };

        if let Some(target_domain) = matched_cname {
            // Check if the target domain itself is mapped to an IP address
            let target_lower = target_domain.to_ascii_lowercase();
            let target_ip = if let Some(&ip) = self.exact_rules.get(&target_lower) {
                Some(ip)
            } else {
                self.wildcard_rules
                    .iter()
                    .find(|(suffix, _)| {
                        target_lower.ends_with(suffix)
                            || target_lower == suffix.trim_start_matches('.')
                    })
                    .map(|(_, ip)| *ip)
            };

            if let Some(ip) = target_ip {
                if qtype == 1 && ip.is_ipv4() {
                    return Some(build_synthetic_cname_with_ip_response(
                        query,
                        target_domain,
                        ip,
                        self.cloak_ttl,
                    ));
                } else if qtype == 28 && ip.is_ipv6() {
                    return Some(build_synthetic_cname_with_ip_response(
                        query,
                        target_domain,
                        ip,
                        self.cloak_ttl,
                    ));
                }
            }

            // Return CNAME record response
            return Some(build_synthetic_cname_response(
                query,
                target_domain,
                self.cloak_ttl,
            ));
        }

        None
    }

    // checks if domain matches split-dns forward target
    pub fn get_forward_target(&self, domain: &str) -> Option<SocketAddr> {
        let lower = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        self.forward_rules
            .iter()
            .find(|(suffix, _)| lower.ends_with(suffix) || lower == suffix.trim_start_matches('.'))
            .map(|(_, addr)| *addr)
    }

    // forwards query via one-shot udp socket to dedicated split-dns upstream
    pub async fn forward_query(
        &self,
        query: &[u8],
        target: SocketAddr,
    ) -> Result<Vec<u8>, std::io::Error> {
        if query.len() < 12 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "dns query too short",
            ));
        }

        let bind_addr = if target.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let sock = UdpSocket::bind(bind_addr).await?;
        sock.connect(target).await?;
        sock.send(query).await?;

        let mut buf = [0u8; 4096];
        let timeout = Duration::from_millis(2000);
        let start = std::time::Instant::now();

        loop {
            let remaining = timeout.checked_sub(start.elapsed()).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "split-dns forward timeout")
            })?;

            let len = tokio::time::timeout(remaining, sock.recv(&mut buf))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "split-dns forward timeout")
                })??;

            if len >= 12 && buf[0] == query[0] && buf[1] == query[1] {
                return Ok(buf[..len].to_vec());
            }
        }
    }
}

// synthesizes type A response record with configurable TTL pointing to cloaked IPv4
fn build_synthetic_a_response(query: &[u8], ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let q_end = match extract_question_end(query) {
        Some(end) => end,
        None => return query.to_vec(),
    };

    let mut resp = Vec::with_capacity(q_end + 16);
    resp.extend_from_slice(&query[..q_end]);

    resp[2] = 0x81; // qr=1, rd=1
    resp[3] = 0x80; // ra=1, rcode=0
    resp[6] = 0x00;
    resp[7] = 0x01; // ancount = 1
    resp[8] = 0x00;
    resp[9] = 0x00;
    resp[10] = 0x00;
    resp[11] = 0x00;

    // answer pointing to question section at offset 12 (0xc00c)
    resp.push(0xc0);
    resp.push(0x0c);
    resp.extend_from_slice(&[0x00, 0x01]); // type A
    resp.extend_from_slice(&[0x00, 0x01]); // class IN
    resp.extend_from_slice(&ttl.to_be_bytes()); // TTL
    resp.extend_from_slice(&[0x00, 0x04]); // rdlength = 4
    resp.extend_from_slice(&ip.octets());

    resp
}

// synthesizes type AAAA response record with configurable TTL pointing to cloaked IPv6
fn build_synthetic_aaaa_response(query: &[u8], ip: Ipv6Addr, ttl: u32) -> Vec<u8> {
    let q_end = match extract_question_end(query) {
        Some(end) => end,
        None => return query.to_vec(),
    };

    let mut resp = Vec::with_capacity(q_end + 28);
    resp.extend_from_slice(&query[..q_end]);

    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[6] = 0x00;
    resp[7] = 0x01;
    resp[8] = 0x00;
    resp[9] = 0x00;
    resp[10] = 0x00;
    resp[11] = 0x00;

    resp.push(0xc0);
    resp.push(0x0c);
    resp.extend_from_slice(&[0x00, 0x1c]); // type AAAA (28)
    resp.extend_from_slice(&[0x00, 0x01]); // class IN
    resp.extend_from_slice(&ttl.to_be_bytes()); // TTL
    resp.extend_from_slice(&[0x00, 0x10]); // rdlength = 16
    resp.extend_from_slice(&ip.octets());

    resp
}

fn build_synthetic_nodata_response(query: &[u8]) -> Vec<u8> {
    let q_end = extract_question_end(query).unwrap_or(query.len().min(12));
    let mut resp = query[..q_end].to_vec();
    if resp.len() >= 12 {
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[6] = 0x00;
        resp[7] = 0x00; // ancount = 0
        resp[8] = 0x00;
        resp[9] = 0x00;
        resp[10] = 0x00;
        resp[11] = 0x00;
    }
    resp
}

pub fn build_synthetic_ptr_response(query: &[u8], target_name: &str, ttl: u32) -> Vec<u8> {
    let q_end = match extract_question_end(query) {
        Some(end) => end,
        None => return query.to_vec(),
    };

    let mut resp = Vec::with_capacity(q_end + 64);
    resp.extend_from_slice(&query[..q_end]);

    resp[2] = 0x85;
    resp[3] = 0x80;
    resp[6] = 0x00;
    resp[7] = 0x01; // ancount = 1
    resp[8] = 0x00;
    resp[9] = 0x00;
    resp[10] = 0x00;
    resp[11] = 0x00;

    // pointer to question name at offset 12
    resp.push(0xc0);
    resp.push(0x0c);

    // PTR RR (type: 12, class: IN 1)
    resp.extend_from_slice(&[0x00, 0x0c]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&ttl.to_be_bytes()); // TTL

    let mut name_wire = Vec::new();
    for part in target_name.trim_end_matches('.').split('.') {
        if !part.is_empty() {
            name_wire.push(part.len() as u8);
            name_wire.extend_from_slice(part.as_bytes());
        }
    }
    name_wire.push(0x00); // root label

    resp.extend_from_slice(&(name_wire.len() as u16).to_be_bytes());
    resp.extend_from_slice(&name_wire);

    resp
}

pub fn build_synthetic_cname_response(query: &[u8], target_name: &str, ttl: u32) -> Vec<u8> {
    let q_end = match extract_question_end(query) {
        Some(end) => end,
        None => return query.to_vec(),
    };

    let mut resp = Vec::with_capacity(q_end + 64);
    resp.extend_from_slice(&query[..q_end]);

    resp[2] = 0x85;
    resp[3] = 0x80;
    resp[6] = 0x00;
    resp[7] = 0x01; // ancount = 1
    resp[8] = 0x00;
    resp[9] = 0x00;
    resp[10] = 0x00;
    resp[11] = 0x00;

    // pointer to question name at offset 12
    resp.push(0xc0);
    resp.push(0x0c);

    // CNAME RR (type: 5, class: IN 1)
    resp.extend_from_slice(&[0x00, 0x05]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&ttl.to_be_bytes());

    let mut name_wire = Vec::new();
    for part in target_name.trim_end_matches('.').split('.') {
        if !part.is_empty() {
            name_wire.push(part.len() as u8);
            name_wire.extend_from_slice(part.as_bytes());
        }
    }
    name_wire.push(0x00);

    resp.extend_from_slice(&(name_wire.len() as u16).to_be_bytes());
    resp.extend_from_slice(&name_wire);

    resp
}

pub fn build_synthetic_cname_with_ip_response(
    query: &[u8],
    target_name: &str,
    ip: IpAddr,
    ttl: u32,
) -> Vec<u8> {
    let mut resp = build_synthetic_cname_response(query, target_name, ttl);
    if resp.len() < 12 {
        return resp;
    }
    resp[7] = 0x02; // ancount = 2

    // Target name as owner of second record
    let mut name_wire = Vec::new();
    for part in target_name.trim_end_matches('.').split('.') {
        if !part.is_empty() {
            name_wire.push(part.len() as u8);
            name_wire.extend_from_slice(part.as_bytes());
        }
    }
    name_wire.push(0x00);
    resp.extend_from_slice(&name_wire);

    match ip {
        IpAddr::V4(v4) => {
            resp.extend_from_slice(&[0x00, 0x01]); // type A
            resp.extend_from_slice(&[0x00, 0x01]); // class IN
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&[0x00, 0x04]); // rdlength 4
            resp.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            resp.extend_from_slice(&[0x00, 0x1c]); // type AAAA
            resp.extend_from_slice(&[0x00, 0x01]); // class IN
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&[0x00, 0x10]); // rdlength 16
            resp.extend_from_slice(&v6.octets());
        }
    }

    resp
}

pub fn parse_arpa_to_ip(domain: &str) -> Option<IpAddr> {
    let lower = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = lower.strip_suffix(".in-addr.arpa") {
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() == 4 {
            let o4 = parts[0].parse::<u8>().ok()?;
            let o3 = parts[1].parse::<u8>().ok()?;
            let o2 = parts[2].parse::<u8>().ok()?;
            let o1 = parts[3].parse::<u8>().ok()?;
            return Some(IpAddr::V4(Ipv4Addr::new(o1, o2, o3, o4)));
        }
    } else if let Some(rest) = lower.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = rest.split('.').collect();
        if nibbles.len() == 32 {
            let mut hex_chars = Vec::with_capacity(32);
            for n in nibbles.iter().rev() {
                hex_chars.push(*n);
            }
            let mut bytes = [0u8; 16];
            for i in 0..16 {
                let high = u8::from_str_radix(hex_chars[i * 2], 16).ok()?;
                let low = u8::from_str_radix(hex_chars[i * 2 + 1], 16).ok()?;
                bytes[i] = (high << 4) | low;
            }
            return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloaking_exact_and_wildcard() {
        let mut engine = CloakEngine::new();
        engine.add_cloak_rule("nas.lan", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
        engine.add_cloak_rule("*.internal", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let query = vec![
            0x11, 0x22, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'n',
            b'a', b's', 0x03, b'l', b'a', b'n', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let resp = engine
            .resolve_cloaked("nas.lan", 1, &query)
            .expect("must resolve cloaked");
        assert!(resp.windows(4).any(|w| w == [192, 168, 1, 50]));

        let wild_resp = engine
            .resolve_cloaked("router.internal", 1, &query)
            .expect("must resolve wildcard");
        assert!(wild_resp.windows(4).any(|w| w == [10, 0, 0, 1]));

        let apex_resp = engine
            .resolve_cloaked("internal", 1, &query)
            .expect("must resolve apex wildcard");
        assert!(apex_resp.windows(4).any(|w| w == [10, 0, 0, 1]));

        assert!(engine.resolve_cloaked("google.com", 1, &query).is_none());

        // PTR reverse cloaking test
        let ptr_query = vec![
            0x33, 0x44, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, b'5',
            b'0', 0x01, b'1', 0x03, b'1', b'6', b'8', 0x03, b'1', b'9', b'2', 0x07, b'i', b'n',
            b'-', b'a', b'd', b'd', b'r', 0x04, b'a', b'r', b'p', b'a', 0x00, 0x00, 0x0c, 0x00,
            0x01,
        ];
        let ptr_resp = engine
            .resolve_cloaked("50.1.168.192.in-addr.arpa", 12, &ptr_query)
            .expect("must resolve PTR");
        assert!(ptr_resp.windows(3).any(|w| w == b"nas"));
    }

    #[test]
    fn test_cname_cloaking_and_flattening() {
        let mut engine = CloakEngine::new();
        engine.add_cname_rule("safegoogle.com", "forcesafesearch.google.com");
        engine.add_cloak_rule(
            "forcesafesearch.google.com",
            IpAddr::V4(Ipv4Addr::new(216, 239, 38, 120)),
        );

        let query = vec![
            0x77, 0x88, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, b's',
            b'a', b'f', b'e', b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];

        let resp = engine
            .resolve_cloaked("safegoogle.com", 1, &query)
            .expect("must resolve CNAME flattened");
        assert_eq!(resp[7], 0x02); // 2 answers
        assert!(resp.windows(4).any(|w| w == [216, 239, 38, 120]));
    }

    #[test]
    fn test_cloaking_loop_detection() {
        let mut engine = CloakEngine::new();
        engine.add_cname_rule("a.com", "b.com");
        engine.add_cname_rule("b.com", "a.com");
        assert!(engine.detect_cloaking_loops().is_err());
    }

    #[test]
    fn test_split_dns_routing() {
        let mut engine = CloakEngine::new();
        engine.add_forward_rule(".corp", "10.0.0.53:53".parse().unwrap());

        assert_eq!(
            engine.get_forward_target("intranet.corp"),
            Some("10.0.0.53:53".parse().unwrap())
        );
        assert!(engine.get_forward_target("wikipedia.org").is_none());
    }

    #[test]
    fn test_load_hosts_str_and_ptr() {
        let mut engine = CloakEngine::new();
        let hosts_data = r#"
        # standard localhost mappings
        127.0.0.1 localhost localhost.localdomain
        ::1       ip6-localhost ip6-loopback

        # custom internal device
        192.168.1.200 printer.lan office-printer
        "#;

        let loaded = engine.load_hosts_str(hosts_data);
        assert_eq!(loaded, 6);

        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'p',
            b'r', b'i', b'n', b't', b'e', b'r', 0x03, b'l', b'a', b'n', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let resp = engine
            .resolve_cloaked("printer.lan", 1, &query)
            .expect("must resolve printer.lan");
        assert!(resp.windows(4).any(|w| w == [192, 168, 1, 200]));

        let ptr_query = vec![
            0x55, 0x66, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'2',
            b'0', b'0', 0x01, b'1', 0x03, b'1', b'6', b'8', 0x03, b'1', b'9', b'2', 0x07, b'i',
            b'n', b'-', b'a', b'd', b'd', b'r', 0x04, b'a', b'r', b'p', b'a', 0x00, 0x00, 0x0c,
            0x00, 0x01,
        ];
        let ptr_resp = engine
            .resolve_cloaked("200.1.168.192.in-addr.arpa", 12, &ptr_query)
            .expect("must resolve PTR");
        assert!(ptr_resp.windows(7).any(|w| w == b"printer"));
    }

    #[test]
    fn test_cloak_custom_ttl() {
        let mut engine = CloakEngine::new().with_cloak_ttl(120);
        engine.add_cloak_rule("custom.lan", "10.0.0.5".parse().unwrap());
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'c',
            b'u', b's', b't', b'o', b'm', 0x03, b'l', b'a', b'n', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let resp = engine
            .resolve_cloaked("custom.lan", 1, &query)
            .expect("must resolve");
        // TTL 120u32 is [0x00, 0x00, 0x00, 0x78]
        assert!(resp.windows(4).any(|w| w == [0x00, 0x00, 0x00, 0x78]));
    }
}
