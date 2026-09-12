//! dns security filter providing anti-dns-rebinding protection and undelegated zone interception.
//!
//! protects local private networks (iot, router dashboards, localhost) from malicious browser-based
//! rebinding exploits and blocks internal reverse lookups/dotless names from leaking to public upstreams.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// undelegated top-level domains and private suffixes that must never leak to public upstream resolvers
const UNDELEGATED_SUFFIXES: &[&str] = &[
    ".local",
    ".lan",
    ".home",
    ".internal",
    ".corp",
    ".test",
    ".example",
    ".invalid",
    ".onion",
    ".10.in-addr.arpa",
    ".168.192.in-addr.arpa",
    ".127.in-addr.arpa",
    ".254.169.in-addr.arpa",
];

// checks if domain name lacks dots (dotless hostname like "localhost", "router", "printer")
pub fn is_unqualified(domain: &str) -> bool {
    let clean = domain.trim_end_matches('.');
    !clean.contains('.')
}

// checks if domain belongs to a private / internal / non-routable zone
pub fn is_undelegated_zone(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    let trimmed = lower.trim_end_matches('.');

    // check exact dotless matches or suffix matches
    if is_unqualified(trimmed) {
        return true;
    }

    for &suffix in UNDELEGATED_SUFFIXES {
        let clean_suffix = suffix.trim_start_matches('.');
        if trimmed == clean_suffix || trimmed.ends_with(suffix) {
            return true;
        }
    }

    // check rfc 1918 class b private reverse dns (172.16.0.0/12 -> 16.172..31.172.in-addr.arpa)
    if trimmed.ends_with(".172.in-addr.arpa") {
        if let Some(prefix) = trimmed.strip_suffix(".172.in-addr.arpa") {
            if let Some(oct) = prefix.split('.').last() {
                if let Ok(num) = oct.parse::<u8>() {
                    if (16..=31).contains(&num) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

// checks if an ip address resides in private, link-local, loopback, or non-routable space
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            // 0.0.0.0/8 (current network)
            oct[0] == 0
                // 127.0.0.0/8 (loopback)
                || oct[0] == 127
                // 10.0.0.0/8 (private class a)
                || oct[0] == 10
                // 172.16.0.0/12 (private class b)
                || (oct[0] == 172 && (16..=31).contains(&oct[1]))
                // 192.168.0.0/16 (private class c)
                || (oct[0] == 192 && oct[1] == 168)
                // 169.254.0.0/16 (link-local)
                || (oct[0] == 169 && oct[1] == 254)
                // 255.255.255.255/32 (broadcast)
                || v4 == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(v6) => {
            // ::1 (loopback)
            v6.is_loopback()
                // :: (unspecified)
                || v6.is_unspecified()
                // fc00::/7 (unique local address - ula)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 (link-local)
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

// inspects answer section of an upstream dns response and returns Err(private_ip) if a public
// domain resolves to private ip space (dns rebinding attempt)
pub fn detect_dns_rebinding(response_wire: &[u8]) -> Option<IpAddr> {
    if response_wire.len() < 12 {
        return None;
    }

    let ancount = ((response_wire[6] as usize) << 8) | (response_wire[7] as usize);
    if ancount == 0 {
        return None;
    }

    let qdcount = ((response_wire[4] as usize) << 8) | (response_wire[5] as usize);
    let mut pos = 12;

    // skip question section
    for _ in 0..qdcount {
        pos = skip_dns_name(response_wire, pos)?;
        pos += 4; // qtype (2) + qclass (2)
        if pos > response_wire.len() {
            return None;
        }
    }

    // inspect answer records
    for _ in 0..ancount {
        pos = skip_dns_name(response_wire, pos)?;
        if pos + 10 > response_wire.len() {
            return None;
        }

        let rtype = ((response_wire[pos] as u16) << 8) | (response_wire[pos + 1] as u16);
        let rdlength = ((response_wire[pos + 8] as usize) << 8) | (response_wire[pos + 9] as usize);
        pos += 10;

        if pos + rdlength > response_wire.len() {
            return None;
        }

        // type a (ipv4)
        if rtype == 1 && rdlength == 4 {
            let ip = Ipv4Addr::new(
                response_wire[pos],
                response_wire[pos + 1],
                response_wire[pos + 2],
                response_wire[pos + 3],
            );
            if is_private_ip(IpAddr::V4(ip)) {
                return Some(IpAddr::V4(ip));
            }
        } else if rtype == 28 && rdlength == 16 {
            // type aaaa (ipv6)
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&response_wire[pos..pos + 16]);
            let ip = Ipv6Addr::from(oct);
            if is_private_ip(IpAddr::V6(ip)) {
                return Some(IpAddr::V6(ip));
            }
        }

        pos += rdlength;
    }

    None
}

// helper to skip compressed or uncompressed rfc 1035 labels
fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            // pointer is 2 bytes
            return Some(pos + 2);
        }
        if (len & 0xC0) != 0 {
            return None; // invalid / reserved label format
        }
        pos += 1 + len;
        jumps += 1;
        if jumps > 128 {
            return None;
        }
    }
    None
}

// extracts the byte offset marking the end of the question section in a DNS query
pub fn extract_question_end(query: &[u8]) -> Option<usize> {
    if query.len() < 12 {
        return None;
    }
    let mut pos = 12;
    let mut jumps = 0;
    while pos < query.len() {
        let len = query[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) == 0xC0 {
            pos += 2;
            break;
        }
        if (len & 0xC0) != 0 {
            return None; // invalid / reserved label format
        }
        pos += 1 + len;
        jumps += 1;
        if jumps > 128 {
            return None;
        }
    }
    let end = pos.checked_add(4)?; // qtype (2) + qclass (2)
    if end <= query.len() {
        Some(end)
    } else {
        None
    }
}

// builds synthetic nxdomain response (rcode = 3)
pub fn build_nxdomain_response(query: &[u8]) -> Vec<u8> {
    let q_end = extract_question_end(query).unwrap_or(query.len().min(12));
    let mut resp = query[..q_end].to_vec();
    if resp.len() >= 12 {
        resp[2] = (resp[2] | 0x80) | 0x01; // qr=1 (response) + rd=1
        resp[3] = 0x83; // ra=1 + nxdomain (rcode=3)
        resp[6] = 0; // ancount = 0
        resp[7] = 0;
        resp[8] = 0; // nscount = 0
        resp[9] = 0;
        resp[10] = 0; // arcount = 0
        resp[11] = 0;
    }
    resp
}

// builds synthetic refused response (rcode = 5) for security policy violations
pub fn build_refused_response(query: &[u8]) -> Vec<u8> {
    let q_end = extract_question_end(query).unwrap_or(query.len().min(12));
    let mut resp = query[..q_end].to_vec();
    if resp.len() >= 12 {
        resp[2] = (resp[2] | 0x80) | 0x01; // qr=1 + rd=1
        resp[3] = 0x85; // ra=1 + refused (rcode=5)
        resp[6] = 0;
        resp[7] = 0;
        resp[8] = 0;
        resp[9] = 0;
        resp[10] = 0;
        resp[11] = 0;
    }
    resp
}

// checks if domain is the Mozilla Firefox DoH canary domain (use-application-dns.net)
pub fn is_firefox_canary(domain: &str) -> bool {
    let lower = domain.trim_end_matches('.').to_ascii_lowercase();
    lower == "use-application-dns.net" || lower.ends_with(".use-application-dns.net")
}

// appends an EDNS0 OPT record with RFC 8914 Extended DNS Error (EDE)
pub fn append_edns_ede(resp: &mut Vec<u8>, info_code: u16, extra_text: &str) {
    if resp.len() < 12 {
        return;
    }
    let arcount = ((resp[10] as u16) << 8) | (resp[11] as u16);
    let new_arcount = arcount.saturating_add(1);
    resp[10] = (new_arcount >> 8) as u8;
    resp[11] = (new_arcount & 0xff) as u8;

    // OPT RR
    resp.push(0x00); // root name
    resp.extend_from_slice(&[0x00, 0x29]); // type: OPT (41)
    resp.extend_from_slice(&[0x04, 0xd0]); // UDP payload size: 1232
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags

    let opt_len = (2 + extra_text.len()) as u16;
    let rdlength = 4 + opt_len;
    resp.extend_from_slice(&rdlength.to_be_bytes());

    // Option code 15: Extended DNS Error (RFC 8914)
    resp.extend_from_slice(&[0x00, 0x0f]);
    resp.extend_from_slice(&opt_len.to_be_bytes());
    resp.extend_from_slice(&info_code.to_be_bytes());
    resp.extend_from_slice(extra_text.as_bytes());
}

// builds synthetic HINFO response for blocked queries (Android 8+ compatibility)
pub fn build_hinfo_response(query: &[u8], ttl: u32) -> Vec<u8> {
    let q_end = match extract_question_end(query) {
        Some(end) => end,
        None => return build_nxdomain_response(query),
    };

    let mut resp = Vec::with_capacity(q_end + 64);
    resp.extend_from_slice(&query[..q_end]);

    // standard response, qr=1, aa=1, ra=1, rcode=0 (NoError)
    resp[2] = 0x85;
    resp[3] = 0x80;

    // ancount = 1
    resp[6] = 0x00;
    resp[7] = 0x01;

    // nscount = 0, arcount = 0
    resp[8] = 0x00;
    resp[9] = 0x00;
    resp[10] = 0x00;
    resp[11] = 0x00;

    // pointer to question name at offset 12
    resp.push(0xc0);
    resp.push(0x0c);

    // HINFO RR (type 13, class IN 1)
    resp.extend_from_slice(&[0x00, 0x0d]); // type: HINFO (13)
    resp.extend_from_slice(&[0x00, 0x01]); // class: IN (1)
    resp.extend_from_slice(&ttl.to_be_bytes()); // ttl

    let cpu = b"This query has been locally blocked";
    let os = b"by albus";
    let rdlen = 1 + cpu.len() + 1 + os.len();
    resp.extend_from_slice(&(rdlen as u16).to_be_bytes());

    resp.push(cpu.len() as u8);
    resp.extend_from_slice(cpu);
    resp.push(os.len() as u8);
    resp.extend_from_slice(os);

    append_edns_ede(
        &mut resp,
        15,
        "This query has been locally blocked by albus",
    );

    resp
}

// builds synthetic sinkhole response with custom IP
pub fn build_sinkhole_response_custom(query: &[u8], ip: IpAddr, ttl: u32) -> Vec<u8> {
    let q_end = match extract_question_end(query) {
        Some(end) => end,
        None => return build_nxdomain_response(query),
    };

    let mut resp = Vec::with_capacity(q_end + 32);
    resp.extend_from_slice(&query[..q_end]);

    // standard response, qr=1, aa=1, ra=1, rcode=0
    resp[2] = 0x85;
    resp[3] = 0x80;

    // ancount = 1
    resp[6] = 0x00;
    resp[7] = 0x01;

    // nscount = 0, arcount = 0
    resp[8] = 0x00;
    resp[9] = 0x00;
    resp[10] = 0x00;
    resp[11] = 0x00;

    // pointer to question name at offset 12
    resp.push(0xc0);
    resp.push(0x0c);

    match ip {
        IpAddr::V4(v4) => {
            resp.extend_from_slice(&[0x00, 0x01]); // type: a (1)
            resp.extend_from_slice(&[0x00, 0x01]); // class: in (1)
            resp.extend_from_slice(&ttl.to_be_bytes()); // ttl
            resp.extend_from_slice(&4u16.to_be_bytes()); // rdlen: 4
            resp.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            resp.extend_from_slice(&[0x00, 0x1c]); // type: aaaa (28)
            resp.extend_from_slice(&[0x00, 0x01]); // class: in (1)
            resp.extend_from_slice(&ttl.to_be_bytes()); // ttl
            resp.extend_from_slice(&16u16.to_be_bytes()); // rdlen: 16
            resp.extend_from_slice(&v6.octets());
        }
    }

    resp
}

// flexible dispatcher for blocked query responses matching dnscrypt-proxy
pub fn build_blocked_response(
    query: &[u8],
    qtype: u16,
    response_format: &str,
    ttl: u32,
) -> Vec<u8> {
    let fmt = response_format.trim().to_ascii_lowercase();
    if fmt == "refused" {
        let mut r = build_refused_response(query);
        append_edns_ede(&mut r, 15, "This query has been locally blocked by albus");
        r
    } else if fmt == "hinfo" {
        build_hinfo_response(query, ttl)
    } else if fmt.starts_with("a:") || fmt.contains('.') {
        let (v4_str, v6_str) = if let Some((part1, part2)) = fmt.split_once(',') {
            (
                part1.trim_start_matches("a:"),
                part2.trim_start_matches("aaaa:"),
            )
        } else {
            (fmt.trim_start_matches("a:"), "::")
        };
        let v4_ip = v4_str
            .parse::<Ipv4Addr>()
            .unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
        let v6_ip = v6_str.parse::<Ipv6Addr>().unwrap_or(Ipv6Addr::UNSPECIFIED);

        if qtype == 1 {
            let mut r = build_sinkhole_response_custom(query, IpAddr::V4(v4_ip), ttl);
            append_edns_ede(&mut r, 4, "Forged answer - filtered by albus");
            r
        } else if qtype == 28 {
            let mut r = build_sinkhole_response_custom(query, IpAddr::V6(v6_ip), ttl);
            append_edns_ede(&mut r, 4, "Forged answer - filtered by albus");
            r
        } else {
            build_hinfo_response(query, ttl)
        }
    } else {
        build_hinfo_response(query, ttl)
    }
}

// builds synthetic sinkhole response (0.0.0.0 for A, :: for AAAA) with 60s TTL for blocked domains
pub fn build_sinkhole_response(query: &[u8], qtype: u16) -> Vec<u8> {
    if qtype == 1 {
        build_sinkhole_response_custom(query, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 60)
    } else if qtype == 28 {
        build_sinkhole_response_custom(query, IpAddr::V6(Ipv6Addr::UNSPECIFIED), 60)
    } else {
        build_nxdomain_response(query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unqualified_and_undelegated() {
        assert!(is_unqualified("localhost"));
        assert!(is_unqualified("my-computer"));
        assert!(!is_unqualified("example.com"));

        assert!(is_undelegated_zone("mydevice.local"));
        assert!(is_undelegated_zone("printer.lan"));
        assert!(is_undelegated_zone("nas.home"));
        assert!(is_undelegated_zone("service.internal"));
        assert!(is_undelegated_zone("portal.corp"));
        assert!(is_undelegated_zone("1.1.168.192.in-addr.arpa"));
        assert!(is_undelegated_zone("5.10.in-addr.arpa"));
        assert!(is_undelegated_zone("20.172.in-addr.arpa"));
        assert!(!is_undelegated_zone("google.com"));
        assert!(!is_undelegated_zone("cloudflare-dns.com"));
    }

    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 20, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));

        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_private_ip(IpAddr::V6(
            "fd12:3456:789a::1".parse().unwrap()
        )));
        assert!(is_private_ip(IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(!is_private_ip(IpAddr::V6(
            "2606:4700:4700::1111".parse().unwrap()
        )));
    }

    #[test]
    fn test_firefox_canary() {
        assert!(is_firefox_canary("use-application-dns.net"));
        assert!(is_firefox_canary("foo.use-application-dns.net"));
        assert!(!is_firefox_canary("google.com"));
    }

    #[test]
    fn test_sinkhole_response() {
        let query = vec![
            0xAA, 0xBB, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'd', b's', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let resp = build_sinkhole_response(&query, 1);
        assert_eq!(resp[0], 0xAA);
        assert_eq!(resp[1], 0xBB);
        assert_eq!(resp[2] & 0x80, 0x80);
        assert_eq!(resp[7], 1); // ancount = 1
        assert!(resp.windows(4).any(|w| w == [0, 0, 0, 0]));
    }

    #[test]
    fn test_sinkhole_response_truncates_edns_and_places_answer() {
        // Query with 1 Question AND 1 Additional RR (arcount = 1, e.g. EDNS0 OPT)
        let mut query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // Question: test.org IN A
            0x04, b't', b'e', b's', b't', 0x03, b'o', b'r', b'g', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let q_end = query.len();
        // Add fake EDNS0 OPT record (11 bytes: root label 0x00, type 41 (0x0029), udp payload size 4096 (0x1000), ttl 0, rdlen 0)
        query.extend_from_slice(&[
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let resp = build_sinkhole_response(&query, 1);
        // Answer RR pointer 0xc00c should be located right at q_end, NOT after the EDNS record
        assert_eq!(resp[q_end], 0xc0);
        assert_eq!(resp[q_end + 1], 0x0c);
        // arcount must be 0
        assert_eq!(resp[10], 0);
        assert_eq!(resp[11], 0);
        // ancount must be 1
        assert_eq!(resp[6], 0);
        assert_eq!(resp[7], 1);
        // Total length should be q_end + 16 (pointer(2) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata(4))
        assert_eq!(resp.len(), q_end + 16);
    }

    #[test]
    fn test_build_hinfo_and_blocked_response() {
        let query = vec![
            0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'b',
            b'l', b'o', b'c', b'k', b'e', b'd', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        // 1. HINFO mode
        let hinfo_resp = build_blocked_response(&query, 1, "hinfo", 60);
        // rcode should be 0 (NoError)
        assert_eq!(hinfo_resp[3] & 0x0f, 0);
        // ancount = 1
        assert_eq!(hinfo_resp[7], 1);
        // arcount = 1 (EDNS0 EDE option)
        assert_eq!(hinfo_resp[11], 1);

        // 2. Refused mode
        let refused_resp = build_blocked_response(&query, 1, "refused", 60);
        // rcode should be 5 (Refused)
        assert_eq!(refused_resp[3] & 0x0f, 5);

        // 3. Custom IP mode
        let ip_resp = build_blocked_response(&query, 1, "a:127.0.0.2,aaaa:::1", 10);
        assert_eq!(ip_resp[3] & 0x0f, 0);
        assert_eq!(ip_resp[7], 1);
        assert!(ip_resp.windows(4).any(|w| w == [127, 0, 0, 2]));
    }
}
