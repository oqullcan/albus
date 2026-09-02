//! 4-tuple connection metadata and tcp sequence state tracking.

use std::net::Ipv4Addr;

// 4-tuple connection metadata with sequence and acknowledgment numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnInfo {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
}

impl ConnInfo {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
        }
    }
}
