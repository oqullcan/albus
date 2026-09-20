//! 4-tuple connection metadata and tcp sequence state tracking.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// 4-tuple connection metadata with sequence and acknowledgment numbers supporting IPv4 and IPv6
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
}

impl ConnInfo {
    // constructs connection metadata for ipv4 endpoints
    pub fn new_v4(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
    ) -> Self {
        Self {
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port,
            dst_port,
            seq,
            ack,
        }
    }

    // constructs connection metadata for ipv6 endpoints
    pub fn new_v6(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
    ) -> Self {
        Self {
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            src_port,
            dst_port,
            seq,
            ack,
        }
    }

    // backwards-compatible constructor defaulting to ipv4
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
    ) -> Self {
        Self::new_v4(src_ip, dst_ip, src_port, dst_port, seq, ack)
    }

    pub fn is_ipv6(&self) -> bool {
        self.src_ip.is_ipv6()
    }

    /// Both endpoints must share one address family; `is_ipv6` alone only
    /// inspects src, so mixed V4/V6 values must be rejected explicitly.
    pub fn validate_families(&self) -> Result<(), &'static str> {
        match (self.src_ip.is_ipv6(), self.dst_ip.is_ipv6()) {
            (true, true) | (false, false) => Ok(()),
            _ => Err("mismatched IP families in ConnInfo"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_conn_info_v4_fields() {
        let c = ConnInfo::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(93, 184, 216, 34),
            12345,
            443,
            1000,
            2000,
        );
        assert!(!c.is_ipv6());
        assert_eq!(c.src_port, 12345);
        assert_eq!(c.dst_port, 443);
        assert_eq!(c.seq, 1000);
        assert_eq!(c.ack, 2000);
    }

    #[test]
    fn test_conn_info_v6_flag() {
        let c = ConnInfo::new_v6(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
            5000,
            443,
            7,
            8,
        );
        assert!(c.is_ipv6());
        assert_eq!(c.dst_port, 443);
    }

    #[test]
    fn test_validate_families_rejects_mixed() {
        use std::net::IpAddr;
        let mut mixed = ConnInfo::new_v4(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            1,
            443,
            0,
            0,
        );
        assert!(mixed.validate_families().is_ok());
        // is_ipv6 alone would still say false here — the mismatch is the point
        mixed.dst_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(!mixed.is_ipv6());
        assert!(mixed.validate_families().is_err());
    }
}
