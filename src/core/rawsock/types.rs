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
    pub fn new_v4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Self {
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
    pub fn new_v6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Self {
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
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Self {
        Self::new_v4(src_ip, dst_ip, src_port, dst_port, seq, ack)
    }

    pub fn is_ipv6(&self) -> bool {
        self.src_ip.is_ipv6()
    }
}
