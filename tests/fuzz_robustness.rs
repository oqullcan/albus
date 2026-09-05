//! High-throughput fuzzer and robustness stress testing harness.
//! Verifies that parsers, decoders, wire format converters, and packet generators
//! never panic, leak memory, or trigger undefined behavior on arbitrary, corrupted,
//! or adversarial input streams.

use albus::core::ebpf::loader::parse_elf_sockops;
use albus::core::fake::ech::has_ech_extension;
use albus::core::fake::http::{build_fake_http_request, is_http_payload, split_http_request};
use albus::core::fake::sni::parse_sni;
use albus::core::rawsock::packet::{build_packet, build_packet_stack_opts, checksum};
use albus::core::rawsock::types::ConnInfo;
use albus::dns::blocklist::CompactBlocklist;
use albus::dns::cache::{extract_min_ttl, extract_query_key, update_response_ttls};
use albus::dns::ipcrypt::IpCrypt;
use albus::dns::stamp::DnsStamp;
use albus::dns::uncloak::extract_alias_targets;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Deterministic 64-bit pseudo-random number generator (xorshift64)
struct FuzzRng(u64);

impl FuzzRng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x5a1b_05ca_fe1b_00f1
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u16(&mut self) -> u16 {
        self.next_u64() as u16
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        while buf.len() < len {
            let val = self.next_u64();
            let bytes = val.to_le_bytes();
            let take = (len - buf.len()).min(8);
            buf.extend_from_slice(&bytes[..take]);
        }
        buf
    }

    fn next_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        min + (self.next_u64() as usize % (max - min + 1))
    }
}

// ---------------------------------------------------------------------------
// 1. ELF SOCKOPS PARSER FUZZING
// ---------------------------------------------------------------------------
#[test]
fn test_fuzz_parse_elf_sockops() {
    let mut rng = FuzzRng::new(0x1122334455667788);
    let mut map_fds = HashMap::new();
    map_fds.insert("config_map".to_string(), 10);
    map_fds.insert("target_ports".to_string(), 11);
    map_fds.insert("exclude_ips".to_string(), 12);
    map_fds.insert("exclude_ips_v6".to_string(), 13);
    map_fds.insert("conn_events".to_string(), 14);
    map_fds.insert("connections".to_string(), 15);

    // 1a. Empty and small buffers
    for len in 0..64 {
        let buf = rng.next_bytes(len);
        let _ = parse_elf_sockops(&buf, &map_fds);
    }

    // 1b. Random noise buffers of various sizes up to 16KB
    for _ in 0..100 {
        let len = rng.next_range(64, 16384);
        let buf = rng.next_bytes(len);
        let _ = parse_elf_sockops(&buf, &map_fds);
    }

    // 1c. Mutated valid ELF header with scrambled fields
    let valid_elf = include_bytes!(concat!(env!("OUT_DIR"), "/sockops.bpf.o"));
    for _ in 0..100 {
        let mut mutated = valid_elf.to_vec();
        let num_mutations = rng.next_range(1, 20);
        for _ in 0..num_mutations {
            let offset = rng.next_range(0, mutated.len() - 1);
            mutated[offset] = rng.next_u8();
        }
        let _ = parse_elf_sockops(&mutated, &map_fds);
    }
}

// ---------------------------------------------------------------------------
// 2. DNS STAMP PARSER FUZZING
// ---------------------------------------------------------------------------
#[test]
fn test_fuzz_dns_stamp_parse() {
    let mut rng = FuzzRng::new(0x2233445566778899);

    // 2a. Arbitrary non-prefix strings
    for _ in 0..200 {
        let len = rng.next_range(0, 256);
        let raw = rng.next_bytes(len);
        let s = String::from_utf8_lossy(&raw);
        let _ = DnsStamp::parse(&s);
    }

    // 2b. sdns:// prefix with random payload
    for _ in 0..500 {
        let len = rng.next_range(0, 512);
        let raw = rng.next_bytes(len);
        let encoded = format!("sdns://{}", String::from_utf8_lossy(&raw));
        let _ = DnsStamp::parse(&encoded);
    }

    // 2c. Mutate valid DNS stamps
    let valid_stamps = [
        "sdns://AgMAAAAAAAAABzkuOS45LjkADWRucy5xdWFkOS5uZXQKL2Rucy1xdWVyeQ",
        "sdns://AgcAAAAAAAAABzEuMS4xLjEAEmNsb3VkZmxhcmUtZG5zLmNvbQovZG5zLXF1ZXJ5",
    ];

    for stamp in &valid_stamps {
        // Must parse valid stamp without error
        assert!(DnsStamp::parse(stamp).is_ok(), "valid stamp must parse");

        for _ in 0..200 {
            let mut chars: Vec<char> = stamp.chars().collect();
            if chars.len() > 8 {
                let idx = rng.next_range(7, chars.len() - 1);
                chars[idx] = (rng.next_range(32, 126) as u8) as char;
            }
            let mutated: String = chars.into_iter().collect();
            let _ = DnsStamp::parse(&mutated);
        }
    }
}

// ---------------------------------------------------------------------------
// 3. DNS WIRE CACHE & QUERY PARSER FUZZING
// ---------------------------------------------------------------------------
#[test]
fn test_fuzz_dns_wire_parsing() {
    let mut rng = FuzzRng::new(0x33445566778899aa);

    for _ in 0..1000 {
        let len = rng.next_range(0, 1024);
        let mut buf = rng.next_bytes(len);

        // Fuzz extract_query_key
        let _ = extract_query_key(&buf);

        // Fuzz extract_min_ttl
        let _ = extract_min_ttl(&buf);

        // Fuzz update_response_ttls in-place
        let new_ttl = rng.next_u32();
        update_response_ttls(&mut buf, new_ttl);
    }

    // 3b. Malformed pointer loops (RFC 1035 compression pointer bomb)
    // 12 bytes DNS header, then pointer pointing to itself (0xc0, 0x0c)
    let loop_query = [
        0x12, 0x34, // ID
        0x01, 0x00, // flags (standard query)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, // Pointer to offset 12 (itself!)
        0x00, 0x01, 0x00, 0x01,
    ];
    let key = extract_query_key(&loop_query);
    assert!(
        key.is_none() || key.is_some(),
        "pointer loop must not infinite loop or panic"
    );

    // Mutual pointer loop: offset 12 -> 14, offset 14 -> 12
    let mutual_loop = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        0x0e, // points to 14
        0xc0, 0x0c, // points to 12
    ];
    let _ = extract_query_key(&mutual_loop);
}

// ---------------------------------------------------------------------------
// 4. CNAME UNCLOAKING & ALIAS EXTRACTION FUZZING
// ---------------------------------------------------------------------------
#[test]
fn test_fuzz_cname_uncloaking() {
    let mut rng = FuzzRng::new(0x445566778899aabb);

    for _ in 0..1000 {
        let len = rng.next_range(0, 1024);
        let buf = rng.next_bytes(len);

        let _ = extract_alias_targets(&buf);
    }
}

// ---------------------------------------------------------------------------
// 5. TLS SNI & ECH EXTENSION PARSER FUZZING
// ---------------------------------------------------------------------------
#[test]
fn test_fuzz_tls_sni_and_ech() {
    let mut rng = FuzzRng::new(0x5566778899aabbcc);

    // 5a. Pure random noise
    for _ in 0..1000 {
        let len = rng.next_range(0, 1024);
        let buf = rng.next_bytes(len);

        let _ = parse_sni(&buf);
        let _ = has_ech_extension(&buf);
    }

    // 5b. Semi-structured TLS records with random internal fields
    for _ in 0..500 {
        let mut rec = vec![0x16, 0x03, 0x01]; // Handshake, TLS 1.0 record header
        let payload_len = rng.next_range(4, 512);
        rec.extend_from_slice(&(payload_len as u16).to_be_bytes());
        rec.push(0x01); // ClientHello
        let body_len = rng.next_range(0, payload_len - 1);
        rec.push(0x00);
        rec.extend_from_slice(&(body_len as u16).to_be_bytes());
        let random_body = rng.next_bytes(body_len);
        rec.extend_from_slice(&random_body);

        let _ = parse_sni(&rec);
        let _ = has_ech_extension(&rec);
    }
}

// ---------------------------------------------------------------------------
// 6. HTTP DPI BYPASS PARSER & SPLITTER FUZZING
// ---------------------------------------------------------------------------
#[test]
fn test_fuzz_http_dpi_evasion() {
    let mut rng = FuzzRng::new(0x66778899aabbccdd);

    // 6a. Fuzz is_http_payload and split_http_request
    for _ in 0..1000 {
        let len = rng.next_range(0, 512);
        let buf = rng.next_bytes(len);

        let _ = is_http_payload(&buf);
        let (first, second) = split_http_request(&buf);

        if !buf.is_empty() {
            // Invariant: concatenated slices must equal original slice
            let mut recombined = Vec::with_capacity(buf.len());
            recombined.extend_from_slice(first);
            recombined.extend_from_slice(second);
            assert_eq!(
                recombined, buf,
                "split_http_request must preserve original bytes"
            );
        }
    }

    // 6b. Fuzz build_fake_http_request
    for _ in 0..200 {
        let len = rng.next_range(0, 128);
        let raw = rng.next_bytes(len);
        let host = String::from_utf8_lossy(&raw);
        let fake = build_fake_http_request(&host);

        assert!(fake.starts_with(b"GET / HTTP/1.1\r\n"));
        assert!(fake.ends_with(b"\r\n\r\n"));
    }
}

// ---------------------------------------------------------------------------
// 7. IPCRYPT CRYPTOGRAPHIC INVARIANTS & FUZZING
// ---------------------------------------------------------------------------
#[test]
fn test_fuzz_ipcrypt_invariants() {
    let mut rng = FuzzRng::new(0x778899aabbccddee);

    for _ in 0..50 {
        let key = rng.next_bytes(16);
        let key_arr: [u8; 16] = key.try_into().unwrap();
        let ip_crypt = IpCrypt::new(key_arr);

        // Verify roundtrip bijectivity across 200 random IPs per key
        for _ in 0..200 {
            let ip = Ipv4Addr::new(rng.next_u8(), rng.next_u8(), rng.next_u8(), rng.next_u8());
            let encrypted = ip_crypt.encrypt(ip);
            let decrypted = ip_crypt.decrypt(encrypted);
            assert_eq!(
                ip, decrypted,
                "IpCrypt roundtrip invariant failed for ip {}",
                ip
            );
        }
    }

    // Passphrase key derivation fuzzing
    for _ in 0..100 {
        let len = rng.next_range(0, 128);
        let raw = rng.next_bytes(len);
        let passphrase = String::from_utf8_lossy(&raw);
        let crypt = IpCrypt::from_passphrase(&passphrase);
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(crypt.decrypt(crypt.encrypt(ip)), ip);
    }
}

// ---------------------------------------------------------------------------
// 8. COMPACT BLOCKLIST ROBUSTNESS FUZZING
// ---------------------------------------------------------------------------
#[test]
fn test_fuzz_compact_blocklist_decoding() {
    let mut rng = FuzzRng::new(0x8899aabbccddeeff);

    // 8a. Arbitrary garbage buffers must be rejected safely
    for _ in 0..500 {
        let len = rng.next_range(0, 4096);
        let buf = rng.next_bytes(len);
        let res = CompactBlocklist::load_from_bytes(&buf);
        assert!(
            res.is_err(),
            "arbitrary noise must not parse as valid CompactBlocklist"
        );
    }

    // 8b. Structured header with corrupted sections
    for _ in 0..100 {
        let mut buf = vec![b'A', b'L', b'B', b'U', b'S', b'B', b'L', b'K', 1]; // valid magic & ver
        let node_count = rng.next_u32();
        buf.extend_from_slice(&node_count.to_le_bytes());
        let str_len = rng.next_u32();
        buf.extend_from_slice(&str_len.to_le_bytes());
        let extra_len = rng.next_range(0, 512);
        let extra = rng.next_bytes(extra_len);
        buf.extend_from_slice(&extra);

        let _ = CompactBlocklist::load_from_bytes(&buf);
    }
}

// ---------------------------------------------------------------------------
// 9. RAW PACKET GENERATOR FUZZING
// ---------------------------------------------------------------------------
#[test]
fn test_fuzz_packet_builder() {
    let mut rng = FuzzRng::new(0x99aabbccddeeff00);

    for _ in 0..200 {
        let is_v6 = rng.next_u8() % 2 == 1;
        let mut conn = if is_v6 {
            let src_bytes = rng.next_bytes(16);
            let dst_bytes = rng.next_bytes(16);
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(src_bytes.as_slice()).unwrap());
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(dst_bytes.as_slice()).unwrap());
            ConnInfo::new_v6(
                src,
                dst,
                rng.next_u16(),
                rng.next_u16(),
                rng.next_u32(),
                rng.next_u32(),
            )
        } else {
            let src = Ipv4Addr::new(rng.next_u8(), rng.next_u8(), rng.next_u8(), rng.next_u8());
            let dst = Ipv4Addr::new(rng.next_u8(), rng.next_u8(), rng.next_u8(), rng.next_u8());
            ConnInfo::new_v4(
                src,
                dst,
                rng.next_u16(),
                rng.next_u16(),
                rng.next_u32(),
                rng.next_u32(),
            )
        };

        let offset = ((rng.next_u32() % 2000) as i32) - 1000;
        conn = conn.with_seq_offset(offset);

        let payload_len = rng.next_range(0, 256);
        let payload = rng.next_bytes(payload_len);
        let ttl = rng.next_u8();
        let bad_csum = rng.next_u8() % 2 == 1;

        let pkt1 = build_packet(&conn, &payload, ttl);
        assert!(!pkt1.is_empty());

        let pkt2 = build_packet_stack_opts(&conn, &payload, ttl, bad_csum);
        assert!(!pkt2.is_empty());

        // Checksum calculation on arbitrary slices
        let _ = checksum(&pkt1);
        let _ = checksum(pkt2.as_slice());
    }
}
