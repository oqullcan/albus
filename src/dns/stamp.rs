//! dns stamp (sdns://) parser and decoder.
//!
//! implements the dns stamp specification for encrypted upstream providers (doh / odoh).
//! decodes base64url-encoded stamp strings into upstream provider urls, ports, bootstrap ips,
//! and protocol attributes (dnssec, nolog, nofilter).

use std::net::{Ipv4Addr, SocketAddr};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StampProtocol {
    PlainDns,
    CryptDns,
    DoH,
    DoT,
    DoQ,
    ODoHTarget,
    ODoHRelay,
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsStamp {
    pub protocol: StampProtocol,
    pub dnssec: bool,
    pub no_log: bool,
    pub no_filter: bool,
    pub server_addr: Option<SocketAddr>,
    pub provider_name: String,
    pub path: String,
    pub doh_url: String,
    pub bootstrap_ips: Vec<Ipv4Addr>,
}

impl DnsStamp {
    // parses an "sdns://..." stamp string into structured encrypted endpoint configuration
    pub fn parse(stamp_str: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if stamp_str.len() > 8192 {
            return Err("dns stamp exceeds maximum allowed length (8192 bytes)".into());
        }

        let clean = stamp_str.trim();
        let encoded = clean.strip_prefix("sdns://").unwrap_or(clean);

        let decoded = decode_base64_url_lenient(encoded)?;
        if decoded.is_empty() {
            return Err("empty dns stamp payload".into());
        }

        let proto_byte = decoded[0];
        let protocol = match proto_byte {
            0x00 => StampProtocol::PlainDns,
            0x01 => StampProtocol::CryptDns,
            0x02 => StampProtocol::DoH,
            0x03 => StampProtocol::DoT,
            0x04 => StampProtocol::DoQ,
            0x05 => StampProtocol::ODoHTarget,
            0x85 => StampProtocol::ODoHRelay,
            other => StampProtocol::Unknown(other),
        };

        let mut pos = 1;

        // read props (8 bytes, little-endian u64)
        if pos + 8 > decoded.len() {
            return Err("stamp payload truncated while reading props".into());
        }
        let mut props_bytes = [0u8; 8];
        props_bytes.copy_from_slice(&decoded[pos..pos + 8]);
        let props = u64::from_le_bytes(props_bytes);
        pos += 8;

        let dnssec = (props & 0x01) != 0;
        let no_log = (props & 0x02) != 0;
        let no_filter = (props & 0x04) != 0;

        // read server address (length-prefixed)
        let (server_addr_str, next_pos) = read_lp_string(&decoded, pos)?;
        pos = next_pos;

        let (server_addr, bootstrap_ip) = if let Ok(sa) = server_addr_str.parse::<SocketAddr>() {
            let v4 = if let std::net::IpAddr::V4(ip) = sa.ip() {
                Some(ip)
            } else {
                None
            };
            (Some(sa), v4)
        } else if let Ok(ip) = server_addr_str.parse::<Ipv4Addr>() {
            let default_port = match protocol {
                StampProtocol::DoH | StampProtocol::ODoHTarget | StampProtocol::ODoHRelay => 443,
                _ => 53,
            };
            (Some(SocketAddr::from((ip, default_port))), Some(ip))
        } else if let Ok(ip) = server_addr_str.parse::<std::net::Ipv6Addr>() {
            let default_port = match protocol {
                StampProtocol::DoH | StampProtocol::ODoHTarget | StampProtocol::ODoHRelay => 443,
                _ => 53,
            };
            (Some(SocketAddr::from((ip, default_port))), None)
        } else {
            (None, None)
        };

        let mut bootstrap_ips = Vec::new();
        if let Some(v4) = bootstrap_ip {
            bootstrap_ips.push(v4);
        }

        let mut provider_name = String::new();
        let mut path = "/dns-query".to_string();

        if protocol == StampProtocol::DoH || protocol == StampProtocol::ODoHTarget {
            // skip hashes array (length-prefixed items)
            if pos < decoded.len() {
                pos = skip_vlen_array(&decoded, pos)?;
            }

            // read hostname (provider_name)
            if pos < decoded.len() {
                let (host, next_pos) = read_lp_string(&decoded, pos)?;
                provider_name = host;
                pos = next_pos;
            }

            // read path
            if pos < decoded.len() {
                let (p, _) = read_lp_string(&decoded, pos)?;
                if !p.is_empty() {
                    path = p;
                }
            }
        } else {
            // for cryptographic / plain dns: read provider public key / name
            if pos < decoded.len() {
                let (name, _) = read_lp_string(&decoded, pos)?;
                provider_name = name;
            }
        }

        let doh_url = if !provider_name.is_empty() {
            let clean_path = if path.starts_with('/') {
                path.clone()
            } else {
                format!("/{}", path)
            };
            format!("https://{}{}", provider_name, clean_path)
        } else if let Some(sa) = server_addr {
            format!("https://{}{}", sa, path)
        } else {
            "https://cloudflare-dns.com/dns-query".to_string()
        };

        Ok(Self {
            protocol,
            dnssec,
            no_log,
            no_filter,
            server_addr,
            provider_name,
            path,
            doh_url,
            bootstrap_ips,
        })
    }
}

// reads a 1-byte length-prefixed string
fn read_lp_string(
    data: &[u8],
    pos: usize,
) -> Result<(String, usize), Box<dyn std::error::Error + Send + Sync>> {
    if pos >= data.len() {
        return Ok((String::new(), pos));
    }
    let len = data[pos] as usize;
    let start = pos + 1;
    let end = start + len;
    if end > data.len() {
        return Err("length-prefixed string exceeds payload boundary".into());
    }
    let s = String::from_utf8_lossy(&data[start..end]).to_string();
    Ok((s, end))
}

// skips length-prefixed array of variable-length items
fn skip_vlen_array(
    data: &[u8],
    mut pos: usize,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    while pos < data.len() {
        let item_len = data[pos] as usize;
        pos += 1;
        if (item_len & 0x80) != 0 {
            // last item flag or high bit
            let actual_len = item_len & 0x7f;
            let next_pos = pos
                .checked_add(actual_len)
                .ok_or("vlen item length overflow")?;
            if next_pos > data.len() {
                return Err("vlen item exceeds payload boundary".into());
            }
            return Ok(next_pos);
        } else if item_len == 0 {
            return Ok(pos);
        } else {
            let next_pos = pos
                .checked_add(item_len)
                .ok_or("vlen item length overflow")?;
            if next_pos > data.len() {
                return Err("vlen item exceeds payload boundary".into());
            }
            pos = next_pos;
        }
    }
    Ok(pos)
}

// decodes standard, url-safe, padded or unpadded base64
fn decode_base64_url_lenient(
    input: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();

    clean = clean.replace('-', "+").replace('_', "/");
    while clean.len() % 4 != 0 {
        clean.push('=');
    }

    const B64_TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut map = [255u8; 256];
    for (i, &b) in B64_TABLE.iter().enumerate() {
        map[b as usize] = i as u8;
    }

    let bytes = clean.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);

    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let b0 = map[chunk[0] as usize];
        let b1 = map[chunk[1] as usize];
        let b2 = if chunk[2] == b'=' {
            0
        } else {
            map[chunk[2] as usize]
        };
        let b3 = if chunk[3] == b'=' {
            0
        } else {
            map[chunk[3] as usize]
        };

        if b0 == 255 || b1 == 255 || b2 == 255 || b3 == 255 {
            return Err("invalid base64 character in dns stamp".into());
        }
        if chunk[2] == b'=' && chunk[3] != b'=' {
            return Err("invalid base64 padding in dns stamp".into());
        }

        let triple = ((b0 as u32) << 18) | ((b1 as u32) << 12) | ((b2 as u32) << 6) | (b3 as u32);
        out.push(((triple >> 16) & 0xff) as u8);
        if chunk[2] != b'=' {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if chunk[3] != b'=' {
            out.push((triple & 0xff) as u8);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_quad9_doh_stamp() {
        // Quad9 DoH stamp: sdns://AgMAAAAAAAAABzkuOS45LjkADWRucy5xdWFkOS5uZXQKL2Rucy1xdWVyeQ
        // props: DNSSEC=1, NoLog=1 -> 0x03
        // addr: 9.9.9.9
        // host: dns.quad9.net
        // path: /dns-query
        let stamp_str = "sdns://AgMAAAAAAAAABzkuOS45LjkADWRucy5xdWFkOS5uZXQKL2Rucy1xdWVyeQ";
        let stamp = DnsStamp::parse(stamp_str).expect("failed to parse valid Quad9 stamp");

        assert_eq!(stamp.protocol, StampProtocol::DoH);
        assert!(stamp.dnssec);
        assert!(stamp.no_log);
        assert_eq!(stamp.provider_name, "dns.quad9.net");
        assert_eq!(stamp.path, "/dns-query");
        assert_eq!(stamp.doh_url, "https://dns.quad9.net/dns-query");
        assert!(stamp.bootstrap_ips.contains(&Ipv4Addr::new(9, 9, 9, 9)));
    }

    #[test]
    fn test_parse_cloudflare_stamp() {
        // Cloudflare stamp: sdns://AgcAAAAAAAAABzEuMS4xLjEAEmNsb3VkZmxhcmUtZG5zLmNvbQovZG5zLXF1ZXJ5
        let stamp_str = "sdns://AgcAAAAAAAAABzEuMS4xLjEAEmNsb3VkZmxhcmUtZG5zLmNvbQovZG5zLXF1ZXJ5";
        let stamp = DnsStamp::parse(stamp_str).expect("failed to parse Cloudflare stamp");

        assert_eq!(stamp.protocol, StampProtocol::DoH);
        assert!(stamp.dnssec);
        assert!(stamp.no_log);
        assert_eq!(stamp.provider_name, "cloudflare-dns.com");
        assert_eq!(stamp.doh_url, "https://cloudflare-dns.com/dns-query");
    }

    #[test]
    fn test_decode_base64_url_lenient_rejects_invalid_chars() {
        // Invalid char at chunk position 2
        assert!(decode_base64_url_lenient("AA!A").is_err());
        assert!(decode_base64_url_lenient("AA@A").is_err());

        // Invalid char at chunk position 3
        assert!(decode_base64_url_lenient("AAA!").is_err());
        assert!(decode_base64_url_lenient("AAA#").is_err());

        // Invalid padding (= followed by non-=)
        assert!(decode_base64_url_lenient("AA=A").is_err());
    }

    #[test]
    fn test_skip_vlen_array_bounds_check() {
        // Declared item length 50 exceeds remaining payload length (2)
        let malformed_data = [50u8, 1, 2];
        assert!(skip_vlen_array(&malformed_data, 0).is_err());

        // Declared high-bit item length 0x80 | 10 exceeds remaining payload (1)
        let malformed_last = [0x8au8, 1];
        assert!(skip_vlen_array(&malformed_last, 0).is_err());

        // Valid vlen array: item of length 2, then zero terminator
        let valid_data = [2u8, 0xAA, 0xBB, 0u8];
        let res = skip_vlen_array(&valid_data, 0);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 4);
    }
}
