//! Server-Side Request Forgery (SSRF) validation for DNS stamps and custom DoH upstreams.
//!
//! Validates IP addresses, CIDR blocks, and hostnames to prevent outbound requests
//! to RFC 1918 private subnets, loopback, link-local / cloud IMDS metadata endpoints
//! (169.254.169.254), carrier-grade NAT, and internal domain zones.

use std::net::IpAddr;

/// Checks if an IP address belongs to a private, loopback, link-local, or reserved range.
pub fn is_ssrf_risk_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            ipv4.is_loopback() // 127.0.0.0/8
                || ipv4.is_private() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || ipv4.is_link_local() // 169.254.0.0/16 (includes 169.254.169.254 AWS/GCP IMDS)
                || ipv4.is_broadcast() // 255.255.255.255
                || ipv4.is_unspecified() // 0.0.0.0
                || ipv4.is_multicast() // 224.0.0.0/4
                || (octets[0] == 100 && (octets[1] & 0xc0) == 64) // 100.64.0.0/10 Carrier-grade NAT (RFC 6598)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // 192.0.0.0/24 IETF Protocol Assignments (RFC 6890)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) // 192.0.2.0/24 TEST-NET-1 (RFC 5737)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)) // 198.18.0.0/15 Benchmark testing (RFC 2544)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) // 198.51.100.0/24 TEST-NET-2 (RFC 5737)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113) // 203.0.113.0/24 TEST-NET-3 (RFC 5737)
                || octets[0] >= 240 // 240.0.0.0/4 Reserved (Class E)
        }
        IpAddr::V6(ipv6) => {
            let seg = ipv6.segments();
            ipv6.is_loopback() // ::1
                || ipv6.is_unspecified() // ::
                || ipv6.is_multicast() // ff00::/8
                || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 Unique local (RFC 4193)
                || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 Link-local (RFC 4291)
                || (seg[0] == 0x2001 && seg[1] == 0x0db8) // 2001:db8::/32 Documentation (RFC 3849)
                || ((seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0xffff) // IPv4-mapped IPv6 (::ffff:x.x.x.x)
                    && is_ssrf_risk_ip(&IpAddr::V4(std::net::Ipv4Addr::new(
                        (seg[6] >> 8) as u8,
                        (seg[6] & 0xff) as u8,
                        (seg[7] >> 8) as u8,
                        (seg[7] & 0xff) as u8,
                    ))))
        }
    }
}

/// Checks if a hostname or IP string represents an SSRF risk.
pub fn is_ssrf_risk(host_or_ip: &str) -> bool {
    let clean = host_or_ip.trim().trim_matches('[').trim_matches(']');
    if clean.is_empty() {
        return true;
    }

    // Direct IP address check
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return is_ssrf_risk_ip(&ip);
    }

    // Hostname checks
    let lower = clean.to_ascii_lowercase();

    // Standard loopback and local domains
    if lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower.ends_with(".lan")
        || lower.ends_with(".home.arpa")
    {
        return true;
    }

    // Cloud Instance Metadata Service (IMDS) well-known hostnames
    if lower == "metadata.google.internal"
        || lower == "metadata"
        || lower == "instance-data"
        || lower.ends_with(".compute.internal")
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_ssrf_risk_ipv4_private_and_loopback() {
        assert!(is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(
            172, 31, 255, 255
        ))));
        assert!(is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        )))); // IMDS
        assert!(is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)))); // CGNAT
    }

    #[test]
    fn test_is_ssrf_risk_ipv4_public() {
        assert!(!is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))));
        assert!(!is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_ssrf_risk_ip(&IpAddr::V4(Ipv4Addr::new(194, 242, 2, 2))));
    }

    #[test]
    fn test_is_ssrf_risk_ipv6() {
        assert!(is_ssrf_risk_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_ssrf_risk_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        // Unique local fc00::/7
        assert!(is_ssrf_risk_ip(&IpAddr::V6("fd00::1".parse().unwrap())));
        // Link-local fe80::/10
        assert!(is_ssrf_risk_ip(&IpAddr::V6("fe80::1".parse().unwrap())));
        // IPv4-mapped loopback ::ffff:127.0.0.1
        assert!(is_ssrf_risk_ip(&IpAddr::V6(
            "::ffff:127.0.0.1".parse().unwrap()
        )));
        // IPv4-mapped private ::ffff:10.0.0.1
        assert!(is_ssrf_risk_ip(&IpAddr::V6(
            "::ffff:10.0.0.1".parse().unwrap()
        )));
        // IPv4-mapped public ::ffff:1.1.1.1 should be allowed
        assert!(!is_ssrf_risk_ip(&IpAddr::V6(
            "::ffff:1.1.1.1".parse().unwrap()
        )));
    }

    #[test]
    fn test_is_ssrf_risk_hostnames() {
        assert!(is_ssrf_risk("localhost"));
        assert!(is_ssrf_risk("sub.localhost"));
        assert!(is_ssrf_risk("server.local"));
        assert!(is_ssrf_risk("service.internal"));
        assert!(is_ssrf_risk("router.lan"));
        assert!(is_ssrf_risk("metadata.google.internal"));
        assert!(is_ssrf_risk("instance-data"));
        assert!(is_ssrf_risk("127.0.0.1"));
        assert!(is_ssrf_risk("169.254.169.254"));
        assert!(is_ssrf_risk("[::1]"));

        assert!(!is_ssrf_risk("cloudflare-dns.com"));
        assert!(!is_ssrf_risk("dns.quad9.net"));
        assert!(!is_ssrf_risk("dns.mullvad.net"));
        assert!(!is_ssrf_risk("1.1.1.1"));
        assert!(!is_ssrf_risk("9.9.9.9"));
    }
}
