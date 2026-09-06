//! rfc 7871 edns0 client subnet (ecs, option code 8) packer and parser.
//!
//! allows specifying client subnet information or zero-scope anonymity in edns0 opt records
//! so authoritative servers and cdns can provide geo-optimized responses without leaking full user ip.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ECS_OPTION_CODE: u16 = 8; // rfc 7871 edns0 client subnet option code

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSubnet {
    pub ip: IpAddr,
    pub prefix_len: u8,
}

impl ClientSubnet {
    pub fn new(ip: IpAddr, prefix_len: u8) -> Self {
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        let clamped = prefix_len.min(max_prefix);
        Self {
            ip,
            prefix_len: clamped,
        }
    }

    // zero-scope anonymity requesting upstream resolvers not to leak client address
    pub fn zero_scope() -> Self {
        Self::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
    }

    // parses cidr notation string like "1.2.3.0/24" or "2001:db8::/32"
    pub fn parse_cidr(s: &str) -> Result<Self, String> {
        let clean = s.trim();
        let parts: Vec<&str> = clean.split('/').collect();
        if parts.len() != 2 {
            return Err(format!(
                "invalid CIDR notation, expected IP/prefix: '{}'",
                s
            ));
        }
        let ip: IpAddr = parts[0]
            .trim()
            .parse()
            .map_err(|e| format!("invalid IP in CIDR '{}': {}", parts[0], e))?;
        let prefix_len: u8 = parts[1]
            .trim()
            .parse()
            .map_err(|e| format!("invalid prefix length in CIDR '{}': {}", parts[1], e))?;

        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            return Err(format!(
                "prefix length {} exceeds max {} for {}",
                prefix_len,
                max_prefix,
                if ip.is_ipv4() { "IPv4" } else { "IPv6" }
            ));
        }

        Ok(Self::new(ip, prefix_len))
    }

    // serializes into RFC 7871 Option 8 RDATA (Family, Source-Prefix-Len, Scope-Prefix-Len, Address)
    pub fn to_option_rdata(&self) -> Vec<u8> {
        let mut rdata = Vec::new();
        match self.ip {
            IpAddr::V4(v4) => {
                let family: u16 = 1;
                rdata.extend_from_slice(&family.to_be_bytes());
                rdata.push(self.prefix_len);
                rdata.push(0); // scope prefix-len in queries must be 0

                let bytes = v4.octets();
                let byte_len = ((self.prefix_len as usize) + 7) / 8;
                if byte_len > 0 {
                    rdata.extend_from_slice(&bytes[..byte_len]);
                }
            }
            IpAddr::V6(v6) => {
                let family: u16 = 2;
                rdata.extend_from_slice(&family.to_be_bytes());
                rdata.push(self.prefix_len);
                rdata.push(0); // scope prefix-len in queries must be 0

                let bytes = v6.octets();
                let byte_len = ((self.prefix_len as usize) + 7) / 8;
                if byte_len > 0 {
                    rdata.extend_from_slice(&bytes[..byte_len]);
                }
            }
        }
        rdata
    }

    // parses RFC 7871 Option 8 RDATA into ClientSubnet
    pub fn from_option_rdata(rdata: &[u8]) -> Result<Self, String> {
        if rdata.len() < 4 {
            return Err("ECS rdata too short".to_string());
        }
        let family = u16::from_be_bytes([rdata[0], rdata[1]]);
        let source_prefix = rdata[2];
        let _scope_prefix = rdata[3];
        let addr_bytes = &rdata[4..];

        match family {
            1 => {
                if source_prefix > 32 {
                    return Err("IPv4 ECS source prefix > 32".to_string());
                }
                let needed_bytes = ((source_prefix as usize) + 7) / 8;
                if addr_bytes.len() < needed_bytes {
                    return Err("IPv4 ECS address bytes truncated".to_string());
                }
                let mut octets = [0u8; 4];
                for i in 0..needed_bytes.min(4) {
                    octets[i] = addr_bytes[i];
                }
                Ok(Self::new(IpAddr::V4(Ipv4Addr::from(octets)), source_prefix))
            }
            2 => {
                if source_prefix > 128 {
                    return Err("IPv6 ECS source prefix > 128".to_string());
                }
                let needed_bytes = ((source_prefix as usize) + 7) / 8;
                if addr_bytes.len() < needed_bytes {
                    return Err("IPv6 ECS address bytes truncated".to_string());
                }
                let mut octets = [0u8; 16];
                for i in 0..needed_bytes.min(16) {
                    octets[i] = addr_bytes[i];
                }
                Ok(Self::new(IpAddr::V6(Ipv6Addr::from(octets)), source_prefix))
            }
            _ => Err(format!("unsupported ECS family: {}", family)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_scope_ecs() {
        let zero = ClientSubnet::zero_scope();
        let rdata = zero.to_option_rdata();
        assert_eq!(rdata.len(), 4);
        assert_eq!(rdata, vec![0x00, 0x01, 0x00, 0x00]);

        let parsed = ClientSubnet::from_option_rdata(&rdata).expect("zero-scope should parse");
        assert_eq!(parsed.prefix_len, 0);
        assert_eq!(parsed.ip, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn test_ipv4_cidr_parse_and_serialize() {
        let ecs = ClientSubnet::parse_cidr("198.51.100.0/24").expect("valid cidr");
        assert_eq!(ecs.prefix_len, 24);
        assert_eq!(ecs.ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)));

        let rdata = ecs.to_option_rdata();
        assert_eq!(rdata.len(), 4 + 3); // family (2) + src (1) + scope (1) + 3 bytes addr
        assert_eq!(rdata[0..4], [0x00, 0x01, 24, 0]);
        assert_eq!(rdata[4..7], [198, 51, 100]);

        let parsed = ClientSubnet::from_option_rdata(&rdata).expect("rdata should parse");
        assert_eq!(parsed.prefix_len, 24);
        assert_eq!(parsed.ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)));
    }

    #[test]
    fn test_ipv6_cidr_parse_and_serialize() {
        let ecs = ClientSubnet::parse_cidr("2001:db8::/32").expect("valid ipv6 cidr");
        assert_eq!(ecs.prefix_len, 32);

        let rdata = ecs.to_option_rdata();
        assert_eq!(rdata.len(), 4 + 4); // family (2) + src (1) + scope (1) + 4 bytes
        assert_eq!(rdata[0..4], [0x00, 0x02, 32, 0]);
        assert_eq!(rdata[4..8], [0x20, 0x01, 0x0d, 0xb8]);

        let parsed = ClientSubnet::from_option_rdata(&rdata).expect("ipv6 rdata should parse");
        assert_eq!(parsed.prefix_len, 32);
        assert_eq!(
            parsed.ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0))
        );
    }

    #[test]
    fn test_invalid_cidr() {
        assert!(ClientSubnet::parse_cidr("invalid").is_err());
        assert!(ClientSubnet::parse_cidr("1.2.3.4/33").is_err());
        assert!(ClientSubnet::parse_cidr("2001:db8::/129").is_err());
    }
}
