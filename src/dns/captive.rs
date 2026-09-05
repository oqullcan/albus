//! wi-fi captive portal detection handler for airport, hotel, and public network logins.
//!
//! when connecting to restricted wi-fi networks before authentication, encrypted doh (tcp 443)
//! is typically blocked by the local gateway. operating systems probe standard captive portal
//! domains to detect this condition and trigger the browser login screen. this module synthesizes
//! instant ip responses so the os http probe proceeds and hits the gateway redirect.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use super::filter::extract_question_end;

struct CaptiveEntry {
    domain: &'static str,
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
}

const CAPTIVE_PROBES: &[CaptiveEntry] = &[
    CaptiveEntry {
        domain: "connectivitycheck.gstatic.com",
        ipv4: Ipv4Addr::new(64, 233, 162, 94),
        ipv6: None,
    },
    CaptiveEntry {
        domain: "connectivitycheck.android.com",
        ipv4: Ipv4Addr::new(64, 233, 162, 100),
        ipv6: None,
    },
    CaptiveEntry {
        domain: "captive.apple.com",
        ipv4: Ipv4Addr::new(17, 253, 109, 201),
        ipv6: None,
    },
    CaptiveEntry {
        domain: "www.msftconnecttest.com",
        ipv4: Ipv4Addr::new(13, 107, 4, 52),
        ipv6: None,
    },
    CaptiveEntry {
        domain: "www.msftncsi.com",
        ipv4: Ipv4Addr::new(23, 0, 175, 137),
        ipv6: None,
    },
    CaptiveEntry {
        domain: "ipv6.msftconnecttest.com",
        ipv4: Ipv4Addr::new(13, 107, 4, 52),
        ipv6: Some(Ipv6Addr::new(0x2a01, 0x111, 0x2003, 0, 0, 0, 0, 0x52)),
    },
    CaptiveEntry {
        domain: "nmcheck.gnome.org",
        ipv4: Ipv4Addr::new(8, 43, 85, 29),
        ipv6: None,
    },
    CaptiveEntry {
        domain: "network-test.debian.org",
        ipv4: Ipv4Addr::new(194, 177, 211, 200),
        ipv6: None,
    },
    CaptiveEntry {
        domain: "detectportal.firefox.com",
        ipv4: Ipv4Addr::new(104, 16, 249, 249),
        ipv6: None,
    },
];

// checks if domain is a known os captive portal probe and returns synthetic ip for qtype
pub fn check_captive_portal(domain: &str, qtype: u16) -> Option<IpAddr> {
    let lower = domain.trim_end_matches('.').to_ascii_lowercase();
    for entry in CAPTIVE_PROBES {
        if lower == entry.domain || lower.ends_with(&format!(".{}", entry.domain)) {
            return match qtype {
                1 => Some(IpAddr::V4(entry.ipv4)), // Type A
                28 => {
                    // Type AAAA
                    if let Some(v6) = entry.ipv6 {
                        Some(IpAddr::V6(v6))
                    } else {
                        None
                    }
                }
                _ => None,
            };
        }
    }
    None
}

// builds synthetic dns response with 60s ttl for captive portal resolution
pub fn build_captive_response(query: &[u8], ip: IpAddr) -> Vec<u8> {
    if query.len() < 12 {
        return query.to_vec();
    }

    let q_end = match extract_question_end(query) {
        Some(end) => end,
        None => return query.to_vec(),
    };

    let mut resp = Vec::with_capacity(q_end + 32);
    resp.extend_from_slice(&query[..q_end]);

    // standard response, qr=1, aa=1, ra=1, rcode=0 (noerror)
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
            resp.extend_from_slice(&60u32.to_be_bytes()); // ttl: 60s
            resp.extend_from_slice(&4u16.to_be_bytes()); // rdlength: 4
            resp.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            resp.extend_from_slice(&[0x00, 0x1c]); // type: aaaa (28)
            resp.extend_from_slice(&[0x00, 0x01]); // class: in (1)
            resp.extend_from_slice(&60u32.to_be_bytes()); // ttl: 60s
            resp.extend_from_slice(&16u16.to_be_bytes()); // rdlength: 16
            resp.extend_from_slice(&v6.octets());
        }
    }

    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_captive_portal_detection() {
        assert!(check_captive_portal("captive.apple.com", 1).is_some());
        assert!(check_captive_portal("connectivitycheck.gstatic.com", 1).is_some());
        assert!(check_captive_portal("nmcheck.gnome.org", 1).is_some());
        assert!(check_captive_portal("google.com", 1).is_none());
    }

    #[test]
    fn test_captive_response_wire() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'c', b'a', b'p', b't', b'i', b'v', b'e', 0x05, b'a', b'p', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        let ip = check_captive_portal("captive.apple.com", 1).unwrap();
        let resp = build_captive_response(&query, ip);
        assert_eq!(resp[0], 0x12);
        assert_eq!(resp[1], 0x34);
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[7], 1); // ancount=1
        assert!(resp.windows(4).any(|w| w == [17, 253, 109, 201]));
    }
}
