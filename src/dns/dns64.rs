//! rfc 6052 and rfc 6147 dns64 ipv6 address synthesis engine.
//!
//! maps standard ipv4-only domains to synthetic ipv6 aaaa records using the well-known prefix
//! 64:ff9b::/96, enabling seamless connectivity in nat64 / ipv6-only cellular and enterprise networks.

use std::net::{Ipv4Addr, Ipv6Addr};

// standard well-known prefix (wkp) defined in rfc 6052: 64:ff9b::/96
pub const DNS64_WKP_PREFIX: [u8; 12] = [
    0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// synthesizes an rfc 6052 ipv6 address from a native ipv4 address
pub fn synthesize_dns64_ipv6(v4: Ipv4Addr) -> Ipv6Addr {
    let oct = v4.octets();
    let mut oct6 = [0u8; 16];
    oct6[..12].copy_from_slice(&DNS64_WKP_PREFIX);
    oct6[12..16].copy_from_slice(&oct);
    Ipv6Addr::from(oct6)
}

// constructs a synthetic dns aaaa response containing dns64 synthesized ipv6 addresses
pub fn build_dns64_response(query_data: &[u8], ipv4_addrs: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
    if query_data.len() < 12 || ipv4_addrs.is_empty() {
        return query_data.to_vec();
    }

    // locate end of question section
    let mut pos = 12;
    while pos < query_data.len() {
        let len = query_data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    pos += 4; // qtype (2) + qclass (2)
    if pos > query_data.len() {
        pos = query_data.len();
    }

    let mut resp = Vec::with_capacity(pos + (ipv4_addrs.len() * 28));
    resp.extend_from_slice(&query_data[..pos]);

    // header flags: QR=1 (response), AA=1, RD=1, RA=1, RCODE=0
    resp[2] = 0x81;
    resp[3] = 0x80;
    // ancount = number of synthesized addresses
    let ancount = ipv4_addrs.len() as u16;
    resp[6] = (ancount >> 8) as u8;
    resp[7] = (ancount & 0xff) as u8;
    // nscount = 0, arcount = 0
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;

    for ip in ipv4_addrs {
        let v6 = synthesize_dns64_ipv6(*ip);
        // pointer to question name at offset 12 (0xc00c)
        resp.push(0xc0);
        resp.push(0x0c);
        resp.push(0x00);
        resp.push(0x1c); // type AAAA (28)
        resp.push(0x00);
        resp.push(0x01); // class IN (1)
        resp.extend_from_slice(&ttl.to_be_bytes()); // ttl
        resp.push(0x00);
        resp.push(0x10); // rdlength = 16 bytes for IPv6
        resp.extend_from_slice(&v6.octets());
    }

    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns64_synthesis() {
        let v4 = Ipv4Addr::new(192, 0, 2, 1);
        let v6 = synthesize_dns64_ipv6(v4);
        assert_eq!(v6, "64:ff9b::192.0.2.1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(v6.octets()[..12], DNS64_WKP_PREFIX);
        assert_eq!(&v6.octets()[12..16], &[192, 0, 2, 1]);
    }

    #[test]
    fn test_build_dns64_wire_response() {
        let mut query = vec![
            0xab, 0xcd, // ID
            0x01, 0x00, // Query
            0x00, 0x01, // 1 question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // example.com
        query.push(7);
        query.extend_from_slice(b"example");
        query.push(3);
        query.extend_from_slice(b"com");
        query.push(0);
        query.extend_from_slice(&[0x00, 0x1c, 0x00, 0x01]); // AAAA, IN

        let ipv4s = vec![Ipv4Addr::new(93, 184, 216, 34)];
        let resp = build_dns64_response(&query, &ipv4s, 300);

        assert_eq!(resp[0], 0xab);
        assert_eq!(resp[1], 0xcd);
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[7], 1); // 1 answer
        // Check synthesized IP at end
        let end_bytes = &resp[resp.len() - 16..];
        assert_eq!(&end_bytes[..12], &DNS64_WKP_PREFIX);
        assert_eq!(&end_bytes[12..], &[93, 184, 216, 34]);
    }
}
