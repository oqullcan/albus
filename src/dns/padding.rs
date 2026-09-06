//! rfc 8467 edns(0) padding option (code 12) implementation for dns-over-https queries.
//!
//! disguises original query length by padding encrypted requests to standardized discrete block
//! boundaries, preventing middlebox dpi systems from performing side-channel packet size fingerprinting.

const PADDING_OPTION_CODE: u16 = 12; // rfc 7830 / rfc 8467 edns0 padding option code
const ECS_OPTION_CODE: u16 = 8; // rfc 7871 edns0 client subnet
const DEFAULT_EDNS_PAYLOAD_SIZE: u16 = 4096;

// discrete padding boundaries (bytes) compliant with rfc 8467 recommendations
const DISCRETE_BOUNDARIES: &[usize] = &[
    64, 128, 192, 256, 320, 384, 512, 704, 768, 896, 960, 1024, 1088, 1152, 2688, 4080,
];

// calculates the nearest discrete boundary greater than or equal to unpadded_len
pub fn calculate_padded_len(unpadded_len: usize) -> usize {
    for &boundary in DISCRETE_BOUNDARIES {
        if unpadded_len <= boundary {
            return boundary;
        }
    }
    // for packets larger than highest predefined boundary, round up to next 128-byte block
    let rem = unpadded_len % 128;
    if rem == 0 {
        unpadded_len
    } else {
        unpadded_len + (128 - rem)
    }
}

use super::ecs::ClientSubnet;

// backward-compatible wrapper enabling both edns padding and ecs zero-scope anonymity
pub fn apply_edns_padding(query: &[u8], dnssec: bool) -> Vec<u8> {
    apply_edns_options(query, dnssec, true, true)
}

// applies rfc 8467 padding and rfc 7871 ecs zero-scope anonymity to outgoing queries
pub fn apply_edns_options(query: &[u8], dnssec: bool, padding: bool, ecs_zero: bool) -> Vec<u8> {
    let ecs = if ecs_zero {
        Some(ClientSubnet::zero_scope())
    } else {
        None
    };
    apply_edns_options_with_ecs(query, dnssec, padding, ecs.as_ref())
}

// applies rfc 8467 padding and optional custom / zero-scope rfc 7871 ecs subnet to outgoing queries
pub fn apply_edns_options_with_ecs(
    query: &[u8],
    dnssec: bool,
    padding: bool,
    ecs: Option<&ClientSubnet>,
) -> Vec<u8> {
    if query.len() < 12 || query.len() > 65500 {
        return query.to_vec();
    }

    let arcount = ((query[10] as u16) << 8) | (query[11] as u16);

    // fast-path: if no additional records exist, append an opt pseudo-rr with options
    if arcount == 0 {
        let mut rdata = Vec::new();

        // 1. rfc 7871 ecs option (custom subnet or zero-scope anonymity)
        if let Some(subnet) = ecs {
            let opt_rdata = subnet.to_option_rdata();
            rdata.extend_from_slice(&ECS_OPTION_CODE.to_be_bytes()); // option code 8
            rdata.extend_from_slice(&(opt_rdata.len() as u16).to_be_bytes());
            rdata.extend_from_slice(&opt_rdata);
        }

        // 2. rfc 8467 edns0 padding option 12
        if padding {
            // opt rr header without rdata = 11 bytes
            // option header = 4 bytes (code + len)
            let current_total_len = query.len() + 11 + rdata.len() + 4;
            let target_len = calculate_padded_len(current_total_len);
            let pad_len = target_len.saturating_sub(current_total_len);

            rdata.extend_from_slice(&PADDING_OPTION_CODE.to_be_bytes());
            rdata.extend_from_slice(&(pad_len as u16).to_be_bytes());
            rdata.resize(rdata.len() + pad_len, 0x00);
        }

        let mut out = Vec::with_capacity(query.len() + 11 + rdata.len());
        out.extend_from_slice(query);

        // update arcount = 1 in header
        out[10] = 0x00;
        out[11] = 0x01;

        // opt rr header
        out.push(0x00); // root label
        out.extend_from_slice(&41u16.to_be_bytes()); // type: opt (41)
        out.extend_from_slice(&DEFAULT_EDNS_PAYLOAD_SIZE.to_be_bytes()); // udp payload size (4096)

        // extended rcode & edns flags: set do bit (0x8000) if dnssec enabled
        if dnssec {
            out.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]);
        } else {
            out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        }

        // rdlength and rdata
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);

        return out;
    }

    // if arcount > 0, return query as-is
    query.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_padded_len() {
        assert_eq!(calculate_padded_len(50), 64);
        assert_eq!(calculate_padded_len(64), 64);
        assert_eq!(calculate_padded_len(65), 128);
        assert_eq!(calculate_padded_len(128), 128);
        assert_eq!(calculate_padded_len(129), 192);
        assert_eq!(calculate_padded_len(1050), 1088);
        assert_eq!(calculate_padded_len(1200), 2688);
    }

    #[test]
    fn test_apply_edns_padding_basic_query() {
        let mut query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: RD
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];
        query.extend_from_slice(b"\x07example\x03com\x00");
        query.extend_from_slice(&[0x00, 0x01]); // Type A
        query.extend_from_slice(&[0x00, 0x01]); // Class IN

        let unpadded_len = query.len();
        let padded = apply_edns_padding(&query, true);

        assert!(padded.len() > unpadded_len);
        assert_eq!(padded.len(), calculate_padded_len(unpadded_len + 23));
        assert_eq!(padded[10], 0x00);
        assert_eq!(padded[11], 0x01);

        let opt_start = unpadded_len;
        assert_eq!(padded[opt_start], 0x00);
        let rtype = u16::from_be_bytes([padded[opt_start + 1], padded[opt_start + 2]]);
        assert_eq!(rtype, 41);

        assert_eq!(padded[opt_start + 7] & 0x80, 0x80);

        // verify ecs option code 8 is present first
        let ecs_code = u16::from_be_bytes([padded[opt_start + 11], padded[opt_start + 12]]);
        assert_eq!(ecs_code, 8);

        // verify padding option code 12 is present
        let pad_code = u16::from_be_bytes([padded[opt_start + 19], padded[opt_start + 20]]);
        assert_eq!(pad_code, 12);
    }

    #[test]
    fn test_apply_edns_custom_ecs() {
        let mut query = vec![
            0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        query.extend_from_slice(b"\x06google\x03com\x00\x00\x01\x00\x01");

        let ecs = ClientSubnet::parse_cidr("1.2.3.0/24").unwrap();
        let formatted = apply_edns_options_with_ecs(&query, true, false, Some(&ecs));

        let opt_start = query.len();
        let ecs_code = u16::from_be_bytes([formatted[opt_start + 11], formatted[opt_start + 12]]);
        assert_eq!(ecs_code, 8);
        let ecs_len = u16::from_be_bytes([formatted[opt_start + 13], formatted[opt_start + 14]]);
        assert_eq!(ecs_len, 7);
        assert_eq!(&formatted[opt_start + 15..opt_start + 15 + 7], &[0x00, 0x01, 24, 0, 1, 2, 3]);
    }
}
