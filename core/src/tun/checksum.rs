// fast zero-copy ipv4 and tcp checksum calculator

use std::net::Ipv4Addr;

pub struct Checksum;

impl Checksum {
    // computes internet checksum over a byte slice (16-bit one's complement)
    pub fn compute(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        while i + 1 < data.len() {
            let word = u16::from_be_bytes([data[i], data[i + 1]]);
            sum += word as u32;
            i += 2;
        }

        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }

    // computes tcp checksum including ipv4 pseudo-header
    pub fn compute_tcp(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // ipv4 pseudo-header
        for octet in src_ip.octets().chunks_exact(2) {
            sum += u16::from_be_bytes([octet[0], octet[1]]) as u32;
        }
        for octet in dst_ip.octets().chunks_exact(2) {
            sum += u16::from_be_bytes([octet[0], octet[1]]) as u32;
        }
        sum += 6; // protocol tcp (0x0006)
        sum += tcp_segment.len() as u32; // tcp length

        // tcp header and payload
        let mut i = 0;
        while i + 1 < tcp_segment.len() {
            // skip existing checksum field at byte offset 16-17
            if i != 16 {
                let word = u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]);
                sum += word as u32;
            }
            i += 2;
        }

        if i < tcp_segment.len() {
            sum += (tcp_segment[i] as u32) << 8;
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_compute() {
        // Sample IPv4 header bytes
        let ip_hdr = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let csum = Checksum::compute(&ip_hdr);
        assert_ne!(csum, 0);
    }
}

