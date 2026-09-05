//! response ip and malicious cidr blacklisting filter.
//!
//! detects and drops dns responses resolving to bogon subnets (rfc 5735 / rfc 6890) or
//! user-configured malicious ip addresses, thwarting domain generation algorithms (dga) and bulletproof hosters.

use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, Default)]
pub struct IpFilter {
    block_bogons: bool,
    blocked_exact: Vec<IpAddr>,
}

impl IpFilter {
    pub fn new(block_bogons: bool, blocked_exact: Vec<IpAddr>) -> Self {
        Self {
            block_bogons,
            blocked_exact,
        }
    }

    // checks if an ip matches bogon ranges or custom blacklisted subnets
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        if self.blocked_exact.contains(&ip) {
            return true;
        }

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
}
