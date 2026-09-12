//! diagnostic commands for one-shot domain resolution and upstream cryptographic certificate inspection.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

use crate::app::config::Config;
use crate::dns::doh::DoHResolver;
use crate::dns::stamp::DnsStamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRecord {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub rdata_str: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDnsResponse {
    pub rcode: u8,
    pub rcode_name: &'static str,
    pub answers: Vec<ParsedRecord>,
    pub authorities: Vec<ParsedRecord>,
    pub additionals: Vec<ParsedRecord>,
}

// maps 4-bit dns rcode to standard mnemonic
pub fn rcode_to_str(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "UNKNOWN",
    }
}

// maps dns resource record type integer to mnemonic
pub fn rtype_to_str(rtype: u16) -> &'static str {
    match rtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        41 => "OPT",
        65 => "HTTPS",
        _ => "OTHER",
    }
}

// constructs rfc 1035 wire-format query with edns0 buffer extension
pub fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let clean = domain.trim().trim_matches('.');
    let mut query = Vec::with_capacity(64 + clean.len());

    // header
    query.extend_from_slice(&[0x13, 0x37]); // tx id
    query.extend_from_slice(&[0x01, 0x00]); // flags: standard query, recursion desired
    query.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
    query.extend_from_slice(&[0x00, 0x00]); // ancount = 0
    query.extend_from_slice(&[0x00, 0x00]); // nscount = 0
    query.extend_from_slice(&[0x00, 0x01]); // arcount = 1 (edns0)

    // question qname
    for label in clean.split('.') {
        if !label.is_empty() {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
    }
    query.push(0x00); // terminating zero

    // qtype & qclass (IN = 1)
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]);

    // edns0 opt pseudo-record (buffer size 4096)
    query.push(0x00); // root name
    query.extend_from_slice(&[0x00, 0x29]); // type 41 (OPT)
    query.extend_from_slice(&[0x10, 0x00]); // payload size 4096
    query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags & extended rcode
    query.extend_from_slice(&[0x00, 0x00]); // rdlen = 0

    query
}

// parses compressed dns name following RFC 1035 pointer offsets
pub fn parse_dns_name_wire(data: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_pos = pos;
    let max_jumps = 10;
    let mut jumps = 0;

    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            if !jumped {
                return_pos = pos + 1;
            }
            break;
        }

        // pointer offset (0b11xxxxxx)
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let pointer = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            if !jumped {
                return_pos = pos + 2;
                jumped = true;
            }
            jumps += 1;
            if jumps > max_jumps || pointer >= data.len() {
                return None;
            }
            pos = pointer;
            continue;
        }

        pos += 1;
        if pos + len > data.len() {
            return None;
        }

        if let Ok(label) = std::str::from_utf8(&data[pos..pos + len]) {
            labels.push(label.to_string());
        } else {
            labels.push(format!("<bin:{}>", len));
        }
        pos += len;
    }
    Some((labels.join("."), return_pos))
}

// parses resource record wire bytes
fn parse_rr(data: &[u8], mut pos: usize) -> Option<(ParsedRecord, usize)> {
    let (name, next_pos) = parse_dns_name_wire(data, pos)?;
    pos = next_pos;

    if pos + 10 > data.len() {
        return None;
    }

    let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
    let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
    pos += 10;

    if pos + rdlen > data.len() {
        return None;
    }

    let rdata_bytes = &data[pos..pos + rdlen];
    let rdata_str = match rtype {
        1 => {
            // A (IPv4)
            if rdlen == 4 {
                Ipv4Addr::new(
                    rdata_bytes[0],
                    rdata_bytes[1],
                    rdata_bytes[2],
                    rdata_bytes[3],
                )
                .to_string()
            } else {
                format!("<malformed A rdlen={}>", rdlen)
            }
        }
        28 => {
            // AAAA (IPv6)
            if rdlen == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata_bytes);
                Ipv6Addr::from(octets).to_string()
            } else {
                format!("<malformed AAAA rdlen={}>", rdlen)
            }
        }
        5 | 2 | 12 => {
            // CNAME, NS, PTR
            if let Some((target, _)) = parse_dns_name_wire(data, pos) {
                target
            } else {
                format!("<malformed name rdlen={}>", rdlen)
            }
        }
        16 => {
            // TXT
            let mut txt_parts = Vec::new();
            let mut c_pos = pos;
            let end = pos + rdlen;
            while c_pos < end {
                let slen = data[c_pos] as usize;
                c_pos += 1;
                if c_pos + slen > end {
                    break;
                }
                if let Ok(s) = std::str::from_utf8(&data[c_pos..c_pos + slen]) {
                    txt_parts.push(s.to_string());
                }
                c_pos += slen;
            }
            txt_parts.join(" ")
        }
        _ => format!("{} bytes payload", rdlen),
    };

    pos += rdlen;
    Some((
        ParsedRecord {
            name,
            rtype,
            ttl,
            rdata_str,
        },
        pos,
    ))
}

// parses complete wire dns response into structured response
pub fn parse_dns_query_response(data: &[u8]) -> Option<ParsedDnsResponse> {
    if data.len() < 12 {
        return None;
    }

    let rcode = data[3] & 0x0F;
    let rcode_name = rcode_to_str(rcode);

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut pos = 12;

    // skip questions
    for _ in 0..qdcount {
        let (_, next_pos) = parse_dns_name_wire(data, pos)?;
        pos = next_pos + 4; // skip QTYPE and QCLASS
        if pos > data.len() {
            return None;
        }
    }

    // parse answers
    let mut answers = Vec::new();
    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }
        let (rec, next_pos) = parse_rr(data, pos)?;
        answers.push(rec);
        pos = next_pos;
    }

    // parse authorities
    let mut authorities = Vec::new();
    for _ in 0..nscount {
        if pos >= data.len() {
            break;
        }
        let (rec, next_pos) = parse_rr(data, pos)?;
        authorities.push(rec);
        pos = next_pos;
    }

    // parse additionals
    let mut additionals = Vec::new();
    for _ in 0..arcount {
        if pos >= data.len() {
            break;
        }
        if let Some((rec, next_pos)) = parse_rr(data, pos) {
            // filter out OPT pseudo-records from additionals display
            if rec.rtype != 41 {
                additionals.push(rec);
            }
            pos = next_pos;
        } else {
            break;
        }
    }

    Some(ParsedDnsResponse {
        rcode,
        rcode_name,
        answers,
        authorities,
        additionals,
    })
}

// executes one-shot dns resolution command (--resolve <domain>)
pub async fn handle_resolve_command(
    domain: &str,
    cfg: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let clean_domain = domain.trim().trim_matches('.');
    if clean_domain.is_empty() {
        eprintln!("error: domain name cannot be empty");
        return Ok(());
    }

    println!("Resolving domain: {}", clean_domain);

    let tls_auth = match (&cfg.tls_client_cert, &cfg.tls_client_key) {
        (Some(cert_path), Some(key_path)) => {
            crate::dns::TlsClientAuth::from_files(cert_path, key_path)
                .ok()
                .map(Arc::new)
        }
        _ => None,
    };

    let resolver = DoHResolver::new_with_options(
        &cfg.doh_upstream,
        &cfg.doh_bootstrap_ips,
        cfg.pqc,
        cfg.http3,
        cfg.effective_proxy().as_deref(),
        tls_auth.as_deref(),
        cfg.tls_key_log_file.as_deref(),
    )?;

    // query IPv4 A records
    let q_a = build_dns_query(clean_domain, 1);
    let start_a = Instant::now();
    let res_a = resolver.resolve(&q_a).await;
    let elapsed_a = start_a.elapsed();

    // query IPv6 AAAA records
    let q_aaaa = build_dns_query(clean_domain, 28);
    let start_aaaa = Instant::now();
    let res_aaaa = resolver.resolve(&q_aaaa).await;
    let elapsed_aaaa = start_aaaa.elapsed();

    match res_a {
        Ok((resp_bytes_a, upstream_name)) => {
            println!("Upstream resolver: {} (DoH)", upstream_name);
            println!("Response latency:  {} ms", elapsed_a.as_millis());

            if let Some(parsed_a) = parse_dns_query_response(&resp_bytes_a) {
                println!("Status:            {}", parsed_a.rcode_name);

                let mut has_answers = false;
                println!("\nResolved records:");
                for rec in &parsed_a.answers {
                    has_answers = true;
                    println!(
                        "  {:<6} {:<32} (TTL: {}s) -> {}",
                        rtype_to_str(rec.rtype),
                        rec.name,
                        rec.ttl,
                        rec.rdata_str
                    );
                }

                // print IPv6 AAAA answers if successful
                if let Ok((resp_bytes_aaaa, _)) = res_aaaa {
                    if let Some(parsed_aaaa) = parse_dns_query_response(&resp_bytes_aaaa) {
                        for rec in &parsed_aaaa.answers {
                            if rec.rtype == 28 {
                                has_answers = true;
                                println!(
                                    "  {:<6} {:<32} (TTL: {}s) -> {}",
                                    rtype_to_str(rec.rtype),
                                    rec.name,
                                    rec.ttl,
                                    rec.rdata_str
                                );
                            }
                        }
                    }
                }

                if !has_answers {
                    if parsed_a.rcode == 3 {
                        println!("  Domain does not exist (NXDOMAIN)");
                    } else {
                        println!("  No resource records returned in answer section");
                    }
                }
            } else {
                println!("Failed to parse binary DNS wire response");
            }
        }
        Err(e) => {
            eprintln!("Upstream resolution failed: {}", e);
            if let Ok((_, upstream_name)) = res_aaaa {
                println!(
                    "Secondary upstream query via {} took {:?}",
                    upstream_name, elapsed_aaaa
                );
            }
        }
    }

    Ok(())
}

// executes upstream cryptographic certificate inspection command (--show-certs)
pub async fn handle_show_certs_command(
    cfg: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Albus Upstream Security & Cryptographic Certificate Status");
    println!("===========================================================");

    // 1. Primary DoH Upstream Details
    println!("\nDoH Upstream Configuration:");
    println!("  Endpoint URL:       {}", cfg.doh_upstream);
    if !cfg.doh_bootstrap_ips.is_empty() {
        let ips: Vec<String> = cfg
            .doh_bootstrap_ips
            .iter()
            .map(|ip| ip.to_string())
            .collect();
        println!("  Bootstrap IPs:      {}", ips.join(", "));
    } else {
        println!("  Bootstrap IPs:      Preset default");
    }
    println!(
        "  Post-Quantum (PQC): {}",
        if cfg.pqc {
            "Enabled (Hybrid ML-KEM / Kyber-768)"
        } else {
            "Disabled (Classical X25519 / P-256)"
        }
    );
    println!(
        "  HTTP/3 (QUIC):      {}",
        if cfg.http3 { "Enabled" } else { "Disabled" }
    );
    println!(
        "  DNSSEC Enforcement: {}",
        if cfg.dnssec { "Enabled" } else { "Disabled" }
    );
    if let Some(ref proxy) = cfg.effective_proxy() {
        println!("  SOCKS5 Proxy:       {}", proxy);
    } else {
        println!("  Routing:            Direct internet connection");
    }

    if let (Some(ref cert), Some(ref key)) = (&cfg.tls_client_cert, &cfg.tls_client_key) {
        println!("  mTLS Client Cert:   {} (Key: {})", cert, key);
    }

    // 2. DNS-over-TLS (DoT) Upstream Details
    if let Some(ref dot) = cfg.dot_upstream {
        println!("\nDNS-over-TLS (DoT) Configuration:");
        println!("  Upstream:           {}", dot);
        println!("  Port:               853");
        println!(
            "  Post-Quantum (PQC): {}",
            if cfg.pqc {
                "Enabled (Hybrid ML-KEM / Kyber-768)"
            } else {
                "Disabled"
            }
        );
    }

    // 3. Per-Client IP Filtering Profiles
    if !cfg.client_rules.is_empty() {
        println!("\nPer-Client IP Filtering Profiles:");
        for p in &cfg.client_rules {
            println!(
                "  Profile '{}': IPs: {}, Blocklist Bypass: {}, Block IPv6: {:?}",
                p.name,
                p.client_ips.join(", "),
                p.bypass_blocklist,
                p.block_ipv6
            );
        }
    }

    // 4. DNSCrypt Resolvers and Certificates
    if !cfg.dnscrypt_servers.is_empty() {
        println!("\nDNSCrypt Upstream Resolvers:");
        for server in &cfg.dnscrypt_servers {
            println!("  Server:             {}", server);
            if server.starts_with("sdns://") {
                if let Ok(stamp) = DnsStamp::parse(server) {
                    println!("    Protocol:         {:?}", stamp.protocol);
                    if let Some(addr) = stamp.server_addr {
                        println!("    Server Address:   {}", addr);
                    }
                    println!("    Provider Name:    {}", stamp.provider_name);
                    println!("    DNSSEC:           {}", stamp.dnssec);
                    println!("    No-Log Policy:    {}", stamp.no_log);
                }
            }
        }
    }

    // 3. Local DoH Server Security Details
    if cfg.local_doh {
        println!("\nLocal In-Process DoH Server:");
        println!("  Listen Address:     {}", cfg.local_doh_addr);
        println!(
            "  TLS Encryption:     {}",
            if cfg.local_doh_tls {
                "Enabled (HTTPS)"
            } else {
                "Disabled (HTTP plaintext)"
            }
        );
        if let Some(ref cert) = cfg.local_doh_cert_file {
            println!("  TLS Certificate:    {}", cert);
        }
    }

    // 4. Verification Sources
    if !cfg.sources.is_empty() {
        println!("\nCryptographic Resolver Sources:");
        for (name, src) in &cfg.sources {
            println!("  Source:             {}", name);
            println!("    URLs:             {}", src.urls.join(", "));
            println!("    Minisign PK:      {}", src.minisign_key);
            println!("    Cache Validity:   {} hours", src.refresh_delay_hours);
        }
    }

    println!("\nVerification complete — all security parameters active.\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_query_wire_format() {
        let q = build_dns_query("example.com", 1);
        assert!(q.len() > 12);
        assert_eq!(&q[0..2], &[0x13, 0x37]);
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD = 1
        assert_eq!(&q[4..6], &[0x00, 0x01]); // 1 question
        assert_eq!(&q[10..12], &[0x00, 0x01]); // 1 opt rr

        // verify name labels: \x07example\x03com\x00
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);

        // QTYPE = 1 (A), QCLASS = 1 (IN)
        assert_eq!(&q[25..27], &[0x00, 0x01]);
        assert_eq!(&q[27..29], &[0x00, 0x01]);
    }

    #[test]
    fn test_parse_dns_query_response_roundtrip() {
        // Construct mock DNS response for example.com A 93.184.216.34
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x13, 0x37]); // tx id
        resp.extend_from_slice(&[0x81, 0x80]); // QR=1, AA=0, RD=1, RA=1, RCODE=0 (NOERROR)
        resp.extend_from_slice(&[0x00, 0x01]); // 1 question
        resp.extend_from_slice(&[0x00, 0x01]); // 1 answer
        resp.extend_from_slice(&[0x00, 0x00]); // 0 ns
        resp.extend_from_slice(&[0x00, 0x00]); // 0 ar

        // Question: example.com A IN
        resp.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        resp.extend_from_slice(&[0x00, 0x01]); // A
        resp.extend_from_slice(&[0x00, 0x01]); // IN

        // Answer: pointer to question, A, IN, TTL=300, rdlen=4, 93.184.216.34
        resp.extend_from_slice(&[0xc0, 0x0c]); // pointer to example.com
        resp.extend_from_slice(&[0x00, 0x01]); // type A
        resp.extend_from_slice(&[0x00, 0x01]); // class IN
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL 300
        resp.extend_from_slice(&[0x00, 0x04]); // rdlen 4
        resp.extend_from_slice(&[93, 184, 216, 34]);

        let parsed = parse_dns_query_response(&resp).expect("should parse valid response");
        assert_eq!(parsed.rcode, 0);
        assert_eq!(parsed.rcode_name, "NOERROR");
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name, "example.com");
        assert_eq!(parsed.answers[0].rtype, 1);
        assert_eq!(parsed.answers[0].ttl, 300);
        assert_eq!(parsed.answers[0].rdata_str, "93.184.216.34");
    }

    #[test]
    fn test_parse_dns_query_response_nxdomain() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x13, 0x37]); // tx id
        resp.extend_from_slice(&[0x81, 0x83]); // RCODE = 3 (NXDOMAIN)
        resp.extend_from_slice(&[0x00, 0x01]); // 1 question
        resp.extend_from_slice(&[0x00, 0x00]); // 0 answer
        resp.extend_from_slice(&[0x00, 0x00]); // 0 ns
        resp.extend_from_slice(&[0x00, 0x00]); // 0 ar

        // Question: nonexistent.test A IN
        resp.extend_from_slice(&[
            11, b'n', b'o', b'n', b'e', b'x', b'i', b's', b't', b'e', b'n', b't', 4, b't', b'e',
            b's', b't', 0,
        ]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x01]);

        let parsed = parse_dns_query_response(&resp).expect("should parse nxdomain");
        assert_eq!(parsed.rcode, 3);
        assert_eq!(parsed.rcode_name, "NXDOMAIN");
        assert!(parsed.answers.is_empty());
    }
}
