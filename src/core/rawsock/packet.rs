//! stack-allocated packet serialization and rfc 1071 internet checksum calculation.

use super::types::ConnInfo;

pub const MAX_PACKET_LEN: usize = 1500;

// fixed-size stack buffer eliminating heap allocation overhead during packet synthesis
#[derive(Clone, Copy)]
pub struct StackPacket {
    buf: [u8; MAX_PACKET_LEN],
    len: usize,
}

impl StackPacket {
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: [0u8; MAX_PACKET_LEN],
            len: 0,
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for StackPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for StackPacket {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

// accumulates 16-bit word summation over byte slice for rfc 1071 checksum
#[inline]
pub fn checksum_partial(data: &[u8], mut sum: u32) -> u32 {
    let (chunks, rem) = data.as_chunks::<2>();
    for chunk in chunks {
        let word = ((chunk[0] as u32) << 8) | (chunk[1] as u32);
        sum = sum.wrapping_add(word);
    }
    if !rem.is_empty() {
        let word = (rem[0] as u32) << 8;
        sum = sum.wrapping_add(word);
    }
    sum
}

// folds 32-bit accumulated carry bits into 16-bit one's complement
#[inline]
pub fn checksum_finalize(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// computes complete rfc 1071 internet checksum across contiguous byte slice
#[inline]
pub fn checksum(data: &[u8]) -> u16 {
    let sum = checksum_partial(data, 0);
    checksum_finalize(sum)
}

// parses symbolic or numeric tcp control flags representation into 8-bit wire flag byte
pub fn parse_tcp_flags(flags_str: &str) -> Option<u8> {
    let s = flags_str.trim().to_lowercase();
    match s.as_str() {
        "pshack" | "psh_ack" | "psh+ack" => Some(0x18),
        "synack" | "syn_ack" | "syn+ack" => Some(0x12),
        "rst" => Some(0x04),
        "rstack" | "rst_ack" | "rst+ack" => Some(0x14),
        "ack" => Some(0x10),
        "syn" => Some(0x02),
        "fin" => Some(0x01),
        "finack" | "fin_ack" | "fin+ack" => Some(0x11),
        "urg" => Some(0x20),
        _ => {
            if let Some(hex) = s.strip_prefix("0x") {
                u8::from_str_radix(hex, 16).ok()
            } else {
                s.parse::<u8>().ok()
            }
        }
    }
}

// serializes ipv4 or ipv6 header and tcp segment directly into pre-allocated stack buffer
pub fn build_packet_stack_opts(
    conn: &ConnInfo,
    payload: &[u8],
    ttl: u8,
    bad_checksum: bool,
) -> StackPacket {
    build_packet_stack_advanced(conn, payload, ttl, bad_checksum, None, None)
}

use crate::core::stack_morph::OsProfile;

// serializes ipv4 or ipv6 header and tcp segment with customizable window size and tcp flags
pub fn build_packet_stack_advanced(
    conn: &ConnInfo,
    payload: &[u8],
    ttl: u8,
    bad_checksum: bool,
    window_size: Option<u16>,
    tcp_flags: Option<u8>,
) -> StackPacket {
    build_packet_stack_morphed(conn, payload, ttl, bad_checksum, window_size, tcp_flags, None)
}

// serializes ipv4 or ipv6 header and tcp segment morphing os fingerprints (tcp options, window, ttl)
pub fn build_packet_stack_morphed(
    conn: &ConnInfo,
    payload: &[u8],
    ttl: u8,
    bad_checksum: bool,
    window_size: Option<u16>,
    tcp_flags: Option<u8>,
    os_profile: Option<OsProfile>,
) -> StackPacket {
    let mut pkt = StackPacket::new();
    let effective_flags = tcp_flags.unwrap_or(0x18);
    let (tcp_options, default_win, default_ttl) = if let Some(profile) = os_profile {
        (
            profile.build_tcp_options(1460, 7, 0x12345678, 0),
            profile.default_window_size(),
            profile.default_ttl(),
        )
    } else {
        (Vec::new(), 502, 64)
    };

    let effective_win = window_size.unwrap_or(default_win);
    let effective_ttl = if ttl == 0 { default_ttl } else { ttl };
    let tcp_opts_len = tcp_options.len();
    let tcp_hdr_len = 20 + tcp_opts_len;
    let data_offset_words = (tcp_hdr_len / 4) as u8;

    match (conn.src_ip, conn.dst_ip) {
        (std::net::IpAddr::V6(src6), std::net::IpAddr::V6(dst6)) => {
            let ip_hdr_len = 40;
            let total_len = ip_hdr_len + tcp_hdr_len + payload.len();

            if total_len > MAX_PACKET_LEN {
                return pkt;
            }

            // 1. construct ipv6 header (rfc 8200)
            let mut ip6_hdr = [0u8; 40];
            ip6_hdr[0] = 0x60; // version 6, traffic class 0
            let payload_len = (tcp_hdr_len + payload.len()) as u16;
            ip6_hdr[4..6].copy_from_slice(&payload_len.to_be_bytes());
            ip6_hdr[6] = 6; // next header: tcp (6)
            ip6_hdr[7] = effective_ttl; // hop limit
            ip6_hdr[8..24].copy_from_slice(&src6.octets());
            ip6_hdr[24..40].copy_from_slice(&dst6.octets());

            pkt.buf[0..40].copy_from_slice(&ip6_hdr);

            // 2. construct tcp header (rfc 793)
            let mut tcp_hdr = [0u8; 20];
            tcp_hdr[0..2].copy_from_slice(&conn.src_port.to_be_bytes());
            tcp_hdr[2..4].copy_from_slice(&conn.dst_port.to_be_bytes());
            tcp_hdr[4..8].copy_from_slice(&conn.seq.to_be_bytes());
            tcp_hdr[8..12].copy_from_slice(&conn.ack.to_be_bytes());
            tcp_hdr[12] = data_offset_words << 4;
            tcp_hdr[13] = effective_flags;
            tcp_hdr[14..16].copy_from_slice(&effective_win.to_be_bytes());

            // 3. compute tcp checksum over ipv6 pseudo-header (rfc 8200 section 8.1)
            let mut pseudo_sum: u32 = 0;
            pseudo_sum = checksum_partial(&src6.octets(), pseudo_sum);
            pseudo_sum = checksum_partial(&dst6.octets(), pseudo_sum);
            let tcp_len_u32 = payload_len as u32;
            pseudo_sum = checksum_partial(&tcp_len_u32.to_be_bytes(), pseudo_sum);
            let next_hdr = [0x00, 0x00, 0x00, 6];
            pseudo_sum = checksum_partial(&next_hdr, pseudo_sum);
            pseudo_sum = checksum_partial(&tcp_hdr, pseudo_sum);
            if !tcp_options.is_empty() {
                pseudo_sum = checksum_partial(&tcp_options, pseudo_sum);
            }
            pseudo_sum = checksum_partial(payload, pseudo_sum);

            let tcp_cs = if bad_checksum {
                0xDEAD
            } else {
                checksum_finalize(pseudo_sum)
            };

            tcp_hdr[16] = (tcp_cs >> 8) as u8;
            tcp_hdr[17] = tcp_cs as u8;

            pkt.buf[40..60].copy_from_slice(&tcp_hdr);
            if !tcp_options.is_empty() {
                pkt.buf[60..60 + tcp_opts_len].copy_from_slice(&tcp_options);
            }

            let payload_start = 60 + tcp_opts_len;
            let payload_end = payload_start + payload.len();
            pkt.buf[payload_start..payload_end].copy_from_slice(payload);
            pkt.len = payload_end;

            pkt
        }
        (std::net::IpAddr::V4(src4), std::net::IpAddr::V4(dst4)) => {
            let ip_hdr_len = 20;
            let total_len = ip_hdr_len + tcp_hdr_len + payload.len();

            if total_len > MAX_PACKET_LEN {
                return pkt;
            }

            // 1. construct ipv4 header (rfc 791)
            let mut ip_hdr = [0u8; 20];
            ip_hdr[0] = 0x45; // version 4, internet header length 5 (20 bytes)
            ip_hdr[1] = 0x00; // differentiated services code point / ecn
            ip_hdr[2] = (total_len >> 8) as u8;
            ip_hdr[3] = total_len as u8;
            ip_hdr[4] = 0x12; // packet identification
            ip_hdr[5] = 0x34;
            ip_hdr[6] = 0x40; // flags: don't fragment (df) bit set
            ip_hdr[7] = 0x00;
            ip_hdr[8] = effective_ttl;
            ip_hdr[9] = 6; // transport protocol: tcp (6)
            ip_hdr[12..16].copy_from_slice(&src4.octets());
            ip_hdr[16..20].copy_from_slice(&dst4.octets());

            let ip_cs = checksum(&ip_hdr);
            ip_hdr[10] = (ip_cs >> 8) as u8;
            ip_hdr[11] = ip_cs as u8;

            pkt.buf[0..20].copy_from_slice(&ip_hdr);

            // 2. construct tcp header (rfc 793)
            let mut tcp_hdr = [0u8; 20];
            tcp_hdr[0..2].copy_from_slice(&conn.src_port.to_be_bytes());
            tcp_hdr[2..4].copy_from_slice(&conn.dst_port.to_be_bytes());
            tcp_hdr[4..8].copy_from_slice(&conn.seq.to_be_bytes());
            tcp_hdr[8..12].copy_from_slice(&conn.ack.to_be_bytes());
            tcp_hdr[12] = data_offset_words << 4;
            tcp_hdr[13] = effective_flags;
            tcp_hdr[14..16].copy_from_slice(&effective_win.to_be_bytes());
            tcp_hdr[18] = 0; // urgent pointer
            tcp_hdr[19] = 0;

            // 3. compute tcp checksum over pseudo-header + tcp header + options + payload
            let tcp_seg_len = (tcp_hdr_len + payload.len()) as u16;
            let mut pseudo_sum: u32 = 0;
            pseudo_sum = checksum_partial(&src4.octets(), pseudo_sum);
            pseudo_sum = checksum_partial(&dst4.octets(), pseudo_sum);
            let proto_and_len = [0x00, 6, (tcp_seg_len >> 8) as u8, tcp_seg_len as u8];
            pseudo_sum = checksum_partial(&proto_and_len, pseudo_sum);
            pseudo_sum = checksum_partial(&tcp_hdr, pseudo_sum);
            if !tcp_options.is_empty() {
                pseudo_sum = checksum_partial(&tcp_options, pseudo_sum);
            }
            pseudo_sum = checksum_partial(payload, pseudo_sum);

            let tcp_cs = if bad_checksum {
                0xDEAD // inject deliberate checksum mismatch to deceive stateful middleboxes
            } else {
                checksum_finalize(pseudo_sum)
            };

            tcp_hdr[16] = (tcp_cs >> 8) as u8;
            tcp_hdr[17] = tcp_cs as u8;

            pkt.buf[20..40].copy_from_slice(&tcp_hdr);
            if !tcp_options.is_empty() {
                pkt.buf[40..40 + tcp_opts_len].copy_from_slice(&tcp_options);
            }

            // 4. append transport layer payload
            let payload_start = 40 + tcp_opts_len;
            let payload_end = payload_start + payload.len();
            pkt.buf[payload_start..payload_end].copy_from_slice(payload);
            pkt.len = payload_end;

            pkt
        }
        _ => pkt,
    }
}

#[inline]
pub fn build_packet_stack(conn: &ConnInfo, payload: &[u8], ttl: u8) -> StackPacket {
    build_packet_stack_opts(conn, payload, ttl, false)
}

#[inline]
pub fn build_packet(conn: &ConnInfo, payload: &[u8], ttl: u8) -> Vec<u8> {
    build_packet_stack(conn, payload, ttl).as_slice().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_checksum_rfc1071_property() {
        let mut data = vec![0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let cs = checksum(&data);
        assert_ne!(cs, 0);

        data.push((cs >> 8) as u8);
        data.push(cs as u8);
        assert_eq!(checksum(&data), 0x0000);
    }

    #[test]
    fn test_build_packet_validity() {
        let conn = ConnInfo::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
            12345,
            443,
            1000,
            2000,
        );
        let payload = b"fake-payload";
        let ttl = 8;
        let pkt = build_packet(&conn, payload, ttl);

        assert_eq!(pkt.len(), 20 + 20 + payload.len());

        // ip header validation
        assert_eq!(pkt[0], 0x45);
        assert_eq!(pkt[8], 8);
        assert_eq!(pkt[9], 6);
        assert_eq!(&pkt[12..16], &[192, 168, 1, 100]);
        assert_eq!(&pkt[16..20], &[93, 184, 216, 34]);

        // tcp header validation
        let tcp = &pkt[20..];
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        assert_eq!(src_port, 12345);
        assert_eq!(dst_port, 443);
        assert_eq!(seq, 1000);
        assert_eq!(ack, 2000);
        assert_eq!(tcp[13], 0x18);

        // payload verification
        assert_eq!(&pkt[40..], payload);
    }

    #[test]
    fn test_bad_checksum_option() {
        let conn = ConnInfo::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            8080,
            443,
            100,
            200,
        );
        let pkt = build_packet_stack_opts(&conn, b"hello", 10, true);
        assert_eq!(pkt.buf[36], 0xDE);
        assert_eq!(pkt.buf[37], 0xAD);
    }

    #[test]
    fn test_packet_building_and_tcp_checksum() {
        let conn = ConnInfo::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(93, 184, 216, 34),
            12345,
            443,
            1000,
            2000,
        );
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let ttl = 12;

        let pkt = build_packet(&conn, payload, ttl);
        assert_eq!(pkt.len(), 20 + 20 + payload.len());

        // ip header checks
        assert_eq!(pkt[0], 0x45);
        assert_eq!(pkt[8], 12);
        assert_eq!(pkt[9], 6);

        // tcp segment verification
        let tcp_seg = &pkt[20..];
        let mut pseudo = Vec::new();
        match (conn.src_ip, conn.dst_ip) {
            (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) => {
                pseudo.extend_from_slice(&s.octets());
                pseudo.extend_from_slice(&d.octets());
            }
            _ => unreachable!(),
        }
        pseudo.push(0x00);
        pseudo.push(6); // tcp
        pseudo.push((tcp_seg.len() >> 8) as u8);
        pseudo.push(tcp_seg.len() as u8);
        pseudo.extend_from_slice(tcp_seg);

        // complement property: checksum over pseudo header + segment must be 0
        assert_eq!(checksum(&pseudo), 0x0000);
    }

    #[test]
    fn test_packet_building_and_tcp_checksum_ipv6() {
        use std::net::Ipv6Addr;
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let conn = ConnInfo::new_v6(src, dst, 54321, 443, 2000, 4000);
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let ttl = 64;

        let pkt = build_packet(&conn, payload, ttl);
        assert_eq!(pkt.len(), 40 + 20 + payload.len());

        // ipv6 header checks
        assert_eq!(pkt[0], 0x60); // version 6
        assert_eq!(pkt[6], 6); // next header: tcp
        assert_eq!(pkt[7], 64); // hop limit
        assert_eq!(&pkt[8..24], &src.octets());
        assert_eq!(&pkt[24..40], &dst.octets());

        // tcp segment verification over ipv6 pseudo header
        let tcp_seg = &pkt[40..];
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        let tcp_len_u32 = tcp_seg.len() as u32;
        pseudo.extend_from_slice(&tcp_len_u32.to_be_bytes());
        pseudo.extend_from_slice(&[0x00, 0x00, 0x00, 6]);
        pseudo.extend_from_slice(tcp_seg);

        assert_eq!(checksum(&pseudo), 0x0000);
    }

    #[test]
    fn test_checksum_deterministic() {
        let sample = b"Deterministic Checksum Test 12345";
        let cs1 = checksum(sample);
        let cs2 = checksum(sample);
        assert_eq!(cs1, cs2);
    }

    #[test]
    fn test_parse_tcp_flags() {
        assert_eq!(parse_tcp_flags("pshack"), Some(0x18));
        assert_eq!(parse_tcp_flags("PSH_ACK"), Some(0x18));
        assert_eq!(parse_tcp_flags("synack"), Some(0x12));
        assert_eq!(parse_tcp_flags("rst"), Some(0x04));
        assert_eq!(parse_tcp_flags("rstack"), Some(0x14));
        assert_eq!(parse_tcp_flags("ack"), Some(0x10));
        assert_eq!(parse_tcp_flags("syn"), Some(0x02));
        assert_eq!(parse_tcp_flags("fin"), Some(0x01));
        assert_eq!(parse_tcp_flags("finack"), Some(0x11));
        assert_eq!(parse_tcp_flags("0x18"), Some(0x18));
        assert_eq!(parse_tcp_flags("24"), Some(24));
        assert_eq!(parse_tcp_flags("invalid_flags"), None);
    }

    #[test]
    fn test_build_packet_stack_advanced_window_and_flags() {
        let conn = ConnInfo::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            80,
            100,
            200,
        );
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        // test zero-window probe with RST flag
        let pkt = build_packet_stack_advanced(&conn, payload, 10, false, Some(0), Some(0x04));
        assert!(!pkt.is_empty());
        let tcp_seg = &pkt[20..40];
        // flag at byte 13
        assert_eq!(tcp_seg[13], 0x04);
        // window size at bytes 14..16
        let win = u16::from_be_bytes([tcp_seg[14], tcp_seg[15]]);
        assert_eq!(win, 0);

        // test default fallback (None, None) -> 502 window, 0x18 (PSH+ACK)
        let pkt_default = build_packet_stack_advanced(&conn, payload, 10, false, None, None);
        let tcp_default = &pkt_default[20..40];
        assert_eq!(tcp_default[13], 0x18);
        let win_default = u16::from_be_bytes([tcp_default[14], tcp_default[15]]);
        assert_eq!(win_default, 502);
    }
}
