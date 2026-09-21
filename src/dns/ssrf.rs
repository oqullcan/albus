//! server-side request forgery (SSRF) guards for DoH upstreams and bootstrap peers.
//!
//! Central, reusable blocklist: any dial target that is not globally
//! reachable (loopback, private, link-local incl. cloud metadata,
//! CGNAT, multicast, unspecified) is refused or skipped. Fail-closed for
//! explicit literals, skip-and-continue for resolver-supplied addresses
//! (TLS certificate verification remains the backstop there).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// IPv4 SSRF blocklist: 127/8, 0/8, 224+/4, 169.254/16, 10/8, 172.16/12,
/// 192.168/16, 100.64/10 (CGNAT).
pub fn blocked_ipv4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    // loopback, unspecified, multicast+
    if o[0] == 127 || o[0] == 0 || o[0] >= 224 {
        return true;
    }
    if o[0] == 169 && o[1] == 254 {
        return true; // link-local + cloud metadata 169.254.169.254
    }
    if o[0] == 10 {
        return true;
    }
    if o[0] == 172 && (16..32).contains(&o[1]) {
        return true;
    }
    if o[0] == 192 && o[1] == 168 {
        return true;
    }
    if o[0] == 100 && (64..128).contains(&o[1]) {
        return true; // CGNAT
    }
    false
}

/// IPv6 SSRF blocklist: ::1, :: (unspecified), ff00::/8 (multicast),
/// fe80::/10 (link-local), fc00::/7 (unique-local).
/// IPv4-mapped addresses (::ffff:a.b.c.d) are normalized to IPv4 first —
/// otherwise mapped loopback/private ranges bypass the screen.
pub fn blocked_ipv6(ip: &std::net::Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return blocked_ipv4(&mapped);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_unicast_link_local(ip)
        || is_unique_local(ip)
}

fn is_unicast_link_local(ip: &std::net::Ipv6Addr) -> bool {
    let seg = ip.segments();
    (seg[0] & 0xffc0) == 0xfe80
}

fn is_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    let seg = ip.segments();
    (seg[0] & 0xfe00) == 0xfc00
}

/// Address-family-agnostic entry point for dial-target screening.
pub fn blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => blocked_ipv4(v4),
        IpAddr::V6(v6) => blocked_ipv6(v6),
    }
}

/// Socket-level screening (port is irrelevant to the verdict).
pub fn blocked_socket(addr: &SocketAddr) -> bool {
    blocked_ip(&addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ipv4_blocklist() {
        for s in [
            "127.0.0.1",
            "127.1.2.3",
            "0.0.0.0",
            "169.254.169.254",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(blocked_ipv4(&Ipv4Addr::from_str(s).unwrap()), "{}", s);
        }
        for s in ["1.1.1.1", "9.9.9.9", "45.90.28.188", "8.8.8.8"] {
            assert!(!blocked_ipv4(&Ipv4Addr::from_str(s).unwrap()), "{}", s);
        }
        // 172.32 is public, 100.128 is public
        assert!(!blocked_ipv4(&Ipv4Addr::from_str("172.32.0.1").unwrap()));
        assert!(!blocked_ipv4(&Ipv4Addr::from_str("100.128.0.1").unwrap()));
    }

    #[test]
    fn test_ipv6_blocklist() {
        for s in ["::1", "::", "ff02::1", "fe80::1", "fc00::1", "fd00::99"] {
            assert!(blocked_ip(&IpAddr::from_str(s).unwrap()), "{}", s);
        }
        for s in ["2606:4700:4700::1111", "2620:fe::fe", "2a07:e340::2"] {
            assert!(!blocked_ip(&IpAddr::from_str(s).unwrap()), "{}", s);
        }
    }

    #[test]
    fn test_ipv4_mapped_ipv6_normalized() {
        // regression (L6): mapped non-global ranges must be refused via the
        // IPv4 policy, not waved through the IPv6 screen
        for s in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.5",
            "::ffff:172.16.9.9",
            "::ffff:172.31.255.255",
            "::ffff:192.168.0.1",
            "::ffff:169.254.169.254",
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
        ] {
            let ip = IpAddr::from_str(s).unwrap();
            assert!(blocked_ip(&ip), "mapped {} must be refused", s);
            if let IpAddr::V6(v6) = ip {
                assert!(blocked_ipv6(&v6), "mapped {} must be refused", s);
            }
        }
        // mapped globals stay reachable (no over-blocking)
        for s in ["::ffff:1.1.1.1", "::ffff:9.9.9.9", "::ffff:8.8.8.8"] {
            let ip = IpAddr::from_str(s).unwrap();
            assert!(!blocked_ip(&ip), "mapped {} must pass", s);
        }
        // unmapped loopback/unspecified still refused as before
        assert!(blocked_ip(&IpAddr::from_str("::1").unwrap()));
        assert!(!blocked_ip(
            &IpAddr::from_str("2606:4700:4700::1111").unwrap()
        ));
    }

    #[test]
    fn test_socket_level() {
        let a: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let b: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
        assert!(blocked_socket(&a));
        assert!(!blocked_socket(&b));
    }
}
