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

    // creates a copy of ConnInfo with shifted sequence number for overlapping or out-of-order injection
    pub fn with_seq_offset(&self, offset: i32) -> Self {
        let mut copy = *self;
        copy.seq = if offset >= 0 {
            copy.seq.wrapping_add(offset as u32)
        } else {
            copy.seq.wrapping_sub((-offset) as u32)
        };
        copy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conn_info_seq_offset() {
        let conn = ConnInfo::new_v4(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(1, 1, 1, 1),
            12345,
            443,
            1000,
            2000,
        );

        let forward = conn.with_seq_offset(50);
        assert_eq!(forward.seq, 1050);

        let backward = conn.with_seq_offset(-100);
        assert_eq!(backward.seq, 900);

        let wrapping = conn.with_seq_offset(-1500);
        assert_eq!(wrapping.seq, 1000u32.wrapping_sub(1500));
    }

    #[test]
    fn test_conn_info_ipv6_and_constructors() {
        let v6_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let v6_dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let conn6 = ConnInfo::new_v6(v6_src, v6_dst, 54321, 443, 5000, 6000);

        assert!(conn6.is_ipv6());
        assert_eq!(conn6.src_port, 54321);
        assert_eq!(conn6.dst_port, 443);
        assert_eq!(conn6.seq, 5000);
        assert_eq!(conn6.ack, 6000);

        let offset_v6 = conn6.with_seq_offset(250);
        assert_eq!(offset_v6.seq, 5250);

        let conn4_compat = ConnInfo::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            8080,
            80,
            1,
            2,
        );
        assert!(!conn4_compat.is_ipv6());
        assert_eq!(conn4_compat.src_port, 8080);
    }
}
