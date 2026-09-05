//! local cloaking, synthetic hosts overrides, and domain-based split-dns forwarding.
//!
//! allows mapped private services (*.lan, custom dashboards) to resolve locally at 0ms latency
//! without polluting /etc/hosts, while dispatching dedicated enterprise/intranet zones (*.corp)
//! directly to internal dns servers via standard udp transport.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Debug, Clone)]
pub struct CloakEngine {
    exact_rules: HashMap<String, IpAddr>,
    wildcard_rules: Vec<(String, IpAddr)>,
    forward_rules: Vec<(String, SocketAddr)>,
}

impl CloakEngine {
    pub fn new() -> Self {
        Self {
            exact_rules: HashMap::new(),
            wildcard_rules: Vec::new(),
            forward_rules: Vec::new(),
        }
    }

    pub fn add_cloak_rule(&mut self, domain: &str, ip: IpAddr) {
        let clean = domain.trim().to_ascii_lowercase();
        if clean.starts_with("*.") {
            let suffix = clean[1..].to_string(); // e.g. ".lab.internal"
            self.wildcard_rules.push((suffix, ip));
        } else {
            self.exact_rules.insert(clean, ip);
        }
    }

    pub fn add_forward_rule(&mut self, domain_suffix: &str, target: SocketAddr) {
        let mut clean = domain_suffix.trim().to_ascii_lowercase();
        if !clean.starts_with('.') {
            clean.insert(0, '.');
        }
        self.forward_rules.push((clean, target));
    }

    // attempts to resolve domain against local cloaking table returning synthetic wire response
    pub fn resolve_cloaked(&self, domain: &str, qtype: u16, query: &[u8]) -> Option<Vec<u8>> {
        let lower = domain.trim().trim_end_matches('.').to_ascii_lowercase();

        let matched_ip = if let Some(&ip) = self.exact_rules.get(&lower) {
            Some(ip)
        } else {
            self.wildcard_rules
                .iter()
                .find(|(suffix, _)| lower.ends_with(suffix))
                .map(|(_, ip)| *ip)
        }?;

        match matched_ip {
            IpAddr::V4(v4) => {
                if qtype == 1 {
                    // Type A
                    Some(build_synthetic_a_response(query, v4))
                } else if qtype == 28 {
                    // Type AAAA: return empty NODATA
                    Some(build_synthetic_nodata_response(query))
                } else {
                    None
                }
            }
            IpAddr::V6(v6) => {
                if qtype == 28 {
                    // Type AAAA
                    Some(build_synthetic_aaaa_response(query, v6))
                } else if qtype == 1 {
                    // Type A: return empty NODATA
                    Some(build_synthetic_nodata_response(query))
                } else {
                    None
                }
            }
        }
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
    pub async fn forward_query(&self, query: &[u8], target: SocketAddr) -> Result<Vec<u8>, std::io::Error> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(target).await?;
        sock.send(query).await?;

        let mut buf = [0u8; 4096];
        let timeout = Duration::from_millis(2000);
        let len = tokio::time::timeout(timeout, sock.recv(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "split-dns forward timeout"))??;

        Ok(buf[..len].to_vec())
    }
}

// synthesizes type A response record with 60s TTL pointing to cloaked IPv4
fn build_synthetic_a_response(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() < 12 {
        return resp;
    }

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
    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
    resp.extend_from_slice(&[0x00, 0x04]); // rdlength = 4
    resp.extend_from_slice(&ip.octets());

    resp
}

// synthesizes type AAAA response record with 60s TTL pointing to cloaked IPv6
fn build_synthetic_aaaa_response(query: &[u8], ip: Ipv6Addr) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() < 12 {
        return resp;
    }

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
    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
    resp.extend_from_slice(&[0x00, 0x10]); // rdlength = 16
    resp.extend_from_slice(&ip.octets());

    resp
}

fn build_synthetic_nodata_response(query: &[u8]) -> Vec<u8> {
    let mut resp = query.to_vec();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloaking_exact_and_wildcard() {
        let mut engine = CloakEngine::new();
        engine.add_cloak_rule("nas.lan", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
        engine.add_cloak_rule("*.internal", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let query = vec![
            0x11, 0x22, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, b'n', b'a', b's', 0x03, b'l', b'a', b'n', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];

        let resp = engine.resolve_cloaked("nas.lan", 1, &query).expect("must resolve cloaked");
        assert!(resp.windows(4).any(|w| w == [192, 168, 1, 50]));

        let wild_resp = engine.resolve_cloaked("router.internal", 1, &query).expect("must resolve wildcard");
        assert!(wild_resp.windows(4).any(|w| w == [10, 0, 0, 1]));

        assert!(engine.resolve_cloaked("google.com", 1, &query).is_none());
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
}
