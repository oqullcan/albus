//! response ip and malicious cidr blacklisting filter.
//!
//! detects and drops dns responses resolving to bogon subnets (rfc 5735 / rfc 6890) or
//! user-configured malicious ip addresses, thwarting domain generation algorithms (dga) and bulletproof hosters.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpRule {
    Exact(IpAddr),
    CidrV4(Ipv4Addr, u8),
    CidrV6(Ipv6Addr, u8),
    Wildcard(String),
}

impl IpRule {
    pub fn parse(raw: &str) -> Option<Self> {
        let clean = raw.trim();
        if clean.is_empty() || clean.starts_with('#') || clean.starts_with(';') {
            return None;
        }

        // 1. Wildcard pattern (e.g. 127.*, 10.0.*, fe80:abcd:*)
        if clean.contains('*') {
            return Some(IpRule::Wildcard(clean.to_ascii_lowercase()));
        }

        // 2. CIDR subnet (e.g. 192.168.1.0/24, 2001:db8::/32)
        if let Some((ip_part, mask_part)) = clean.split_once('/') {
            let ip_clean = ip_part.trim();
            let mask_val = mask_part.trim().parse::<u8>().ok()?;
            if let Ok(v4) = ip_clean.parse::<Ipv4Addr>() {
                if mask_val <= 32 {
                    return Some(IpRule::CidrV4(v4, mask_val));
                }
            } else if let Ok(v6) = ip_clean.parse::<Ipv6Addr>() {
                if mask_val <= 128 {
                    return Some(IpRule::CidrV6(v6, mask_val));
                }
            }
            return None;
        }

        // 3. Exact IP address
        if let Ok(ip) = clean.parse::<IpAddr>() {
            return Some(IpRule::Exact(ip));
        }

        None
    }

    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            IpRule::Exact(exact) => ip == *exact,
            IpRule::CidrV4(net, mask_len) => {
                if let IpAddr::V4(v4) = ip {
                    ipv4_in_cidr(v4, *net, *mask_len)
                } else {
                    false
                }
            }
            IpRule::CidrV6(net, mask_len) => {
                if let IpAddr::V6(v6) = ip {
                    ipv6_in_cidr(v6, *net, *mask_len)
                } else {
                    false
                }
            }
            IpRule::Wildcard(pat) => {
                let ip_str = ip.to_string().to_ascii_lowercase();
                if let Some(prefix) = pat.strip_suffix('*') {
                    ip_str.starts_with(prefix)
                } else {
                    ip_str == *pat
                }
            }
        }
    }
}

pub fn ipv4_in_cidr(ip: Ipv4Addr, net: Ipv4Addr, mask_len: u8) -> bool {
    if mask_len > 32 {
        return false;
    }
    if mask_len == 0 {
        return true;
    }
    let mask = !0u32 << (32 - mask_len);
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

pub fn ipv6_in_cidr(ip: Ipv6Addr, net: Ipv6Addr, mask_len: u8) -> bool {
    if mask_len > 128 {
        return false;
    }
    if mask_len == 0 {
        return true;
    }
    let mask = !0u128 << (128 - mask_len);
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

#[derive(Clone, Debug, Default)]
pub struct IpFilter {
    pub block_bogons: bool,
    pub blocked_rules: Vec<IpRule>,
    pub allowed_rules: Vec<IpRule>,
}

impl IpFilter {
    pub fn new(block_bogons: bool, blocked_exact: Vec<IpAddr>) -> Self {
        let blocked = blocked_exact.into_iter().map(IpRule::Exact).collect();
        Self {
            block_bogons,
            blocked_rules: blocked,
            allowed_rules: Vec::new(),
        }
    }

    pub fn new_with_rules(
        block_bogons: bool,
        blocked_rules: Vec<IpRule>,
        allowed_rules: Vec<IpRule>,
    ) -> Self {
        Self {
            block_bogons,
            blocked_rules,
            allowed_rules,
        }
    }

    pub fn with_allowed_rules(mut self, allowed: Vec<IpRule>) -> Self {
        self.allowed_rules = allowed;
        self
    }

    pub fn add_blocked_rule(&mut self, rule: IpRule) {
        self.blocked_rules.push(rule);
    }

    pub fn add_allowed_rule(&mut self, rule: IpRule) {
        self.allowed_rules.push(rule);
    }

    pub fn parse_rules_from_text(text: &str) -> Vec<IpRule> {
        text.lines().filter_map(IpRule::parse).collect()
    }

    pub fn load_blocked_file<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<usize> {
        let content = fs::read_to_string(path)?;
        let rules = Self::parse_rules_from_text(&content);
        let count = rules.len();
        self.blocked_rules.extend(rules);
        Ok(count)
    }

    pub fn load_allowed_file<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<usize> {
        let content = fs::read_to_string(path)?;
        let rules = Self::parse_rules_from_text(&content);
        let count = rules.len();
        self.allowed_rules.extend(rules);
        Ok(count)
    }

    // checks if an ip is blocked (allowed_rules bypass takes precedence)
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        // 1. Allowlist bypass: if IP matches allowed rules, it is never blocked
        if self.allowed_rules.iter().any(|r| r.matches(ip)) {
            return false;
        }

        // 2. Custom blocked rules
        if self.blocked_rules.iter().any(|r| r.matches(ip)) {
            return true;
        }

        // 3. Bogon ranges
        if self.block_bogons && is_bogon_ip(ip) {
            return true;
        }

        false
    }
}

// checks if an ip falls into unallocated or reserved bogon space (rfc 6890)
pub fn is_bogon_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            // 0.0.0.0/8 (this network)
            oct[0] == 0
                // 100.64.0.0/10 (shared address space / cgnat)
                || (oct[0] == 100 && (oct[1] & 0xc0) == 64)
                // 192.0.0.0/24 (ietf protocol assignments)
                || (oct[0] == 192 && oct[1] == 0 && oct[2] == 0)
                // 192.0.2.0/24 (test-net-1)
                || (oct[0] == 192 && oct[1] == 0 && oct[2] == 2)
                // 198.18.0.0/15 (benchmarking)
                || (oct[0] == 198 && (oct[1] & 0xfe) == 18)
                // 198.51.100.0/24 (test-net-2)
                || (oct[0] == 198 && oct[1] == 51 && oct[2] == 100)
                // 203.0.113.0/24 (test-net-3)
                || (oct[0] == 203 && oct[1] == 0 && oct[2] == 113)
                // 240.0.0.0/4 (reserved for future use)
                || (oct[0] >= 240 && v4 != Ipv4Addr::BROADCAST)
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // 2001:db8::/32 (documentation)
            seg[0] == 0x2001 && seg[1] == 0x0db8
                // 100::/64 (discard-only prefix)
                || (seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0)
        }
    }
}

// extracts all resolved a and aaaa ip addresses from answer section of a dns response wire
pub fn extract_resolved_ips(response_wire: &[u8]) -> Vec<IpAddr> {
    if response_wire.len() < 12 {
        return Vec::new();
    }

    let ancount = ((response_wire[6] as usize) << 8) | (response_wire[7] as usize);
    if ancount == 0 {
        return Vec::new();
    }

    let qdcount = ((response_wire[4] as usize) << 8) | (response_wire[5] as usize);
    let mut pos = 12;

    // skip question section
    for _ in 0..qdcount {
        pos = match skip_dns_name(response_wire, pos) {
            Some(p) => p,
            None => return Vec::new(),
        };
        pos += 4;
        if pos > response_wire.len() {
            return Vec::new();
        }
    }

    let mut ips = Vec::new();

    for _ in 0..ancount {
        pos = match skip_dns_name(response_wire, pos) {
            Some(p) => p,
            None => break,
        };

        if pos + 10 > response_wire.len() {
            break;
        }

        let rtype = ((response_wire[pos] as u16) << 8) | (response_wire[pos + 1] as u16);
        let rdlength = ((response_wire[pos + 8] as usize) << 8) | (response_wire[pos + 9] as usize);
        pos += 10;

        if pos + rdlength > response_wire.len() {
            break;
        }

        if rtype == 1 && rdlength == 4 {
            let ip = Ipv4Addr::new(
                response_wire[pos],
                response_wire[pos + 1],
                response_wire[pos + 2],
                response_wire[pos + 3],
            );
            ips.push(IpAddr::V4(ip));
        } else if rtype == 28 && rdlength == 16 {
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&response_wire[pos..pos + 16]);
            ips.push(IpAddr::V6(std::net::Ipv6Addr::from(oct)));
        }

        if ips.len() >= 64 {
            break;
        }

        pos += rdlength;
    }

    ips
}

fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + len;
        jumps += 1;
        if jumps > 128 {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bogon_detection() {
        assert!(is_bogon_ip("192.0.2.1".parse().unwrap())); // test-net-1
        assert!(is_bogon_ip("100.64.0.5".parse().unwrap())); // cgnat
        assert!(is_bogon_ip("240.1.2.3".parse().unwrap())); // reserved
        assert!(!is_bogon_ip("8.8.8.8".parse().unwrap())); // public google
        assert!(!is_bogon_ip("9.9.9.9".parse().unwrap())); // public quad9
    }

    #[test]
    fn test_ip_filter_rules() {
        let blocked = vec!["1.2.3.4".parse().unwrap()];
        let filter = IpFilter::new(true, blocked);

        assert!(filter.is_blocked("1.2.3.4".parse().unwrap()));
        assert!(filter.is_blocked("192.0.2.100".parse().unwrap())); // bogon
        assert!(!filter.is_blocked("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_and_wildcard_and_allowlist() {
        let text_blocked = "10.0.0.0/8\n192.168.1.*\n2606:4700:1::/48\n4.4.4.4\n";
        let text_allowed = "10.0.0.1\n192.168.1.50\n";

        let filter = IpFilter::new_with_rules(
            true,
            IpFilter::parse_rules_from_text(text_blocked),
            IpFilter::parse_rules_from_text(text_allowed),
        );

        // 10.0.0.2 is blocked by 10.0.0.0/8
        assert!(filter.is_blocked("10.0.0.2".parse().unwrap()));
        // 10.0.0.1 is whitelisted by allowed rule!
        assert!(!filter.is_blocked("10.0.0.1".parse().unwrap()));

        // 192.168.1.100 is blocked by wildcard 192.168.1.*
        assert!(filter.is_blocked("192.168.1.100".parse().unwrap()));
        // 192.168.1.50 is allowed by allowed rule!
        assert!(!filter.is_blocked("192.168.1.50".parse().unwrap()));

        // IPv6 CIDR match
        assert!(filter.is_blocked("2606:4700:1:ffff::1".parse().unwrap()));
        assert!(!filter.is_blocked("2606:4700:2::1".parse().unwrap()));
    }
}
