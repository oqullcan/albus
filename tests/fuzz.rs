//! Robustness fuzz suite: deterministic xorshift64 mutation of parser inputs.
//! Invariant everywhere: parsers return Ok/Err/None — they never panic,
//! hang, or exhibit UB. No network, no root, stable seed for CI.

use albus::core::ebpf::loader::parse_elf_sockops;
use albus::core::fake::clienthello::build_fake_client_hello;
use albus::core::fake::sni::parse_sni;
use albus::core::rawsock::packet::build_packet;
use albus::core::rawsock::types::ConnInfo;
use albus::dns::cache::extract_query_key;
use albus::dns::server::{is_aaaa_query, parse_dns_response};
use albus::dns::ssrf::{blocked_ipv4, blocked_ipv6};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Deterministic xorshift64: stable across CI runs (fixed seed, no entropy).
struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0 | 1;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

/// Minimal 64-byte ELF64 header template (invalid section table on purpose).
fn elf_template() -> Vec<u8> {
    let mut hdr = vec![0u8; 64];
    hdr[0..4].copy_from_slice(b"\x7FELF");
    hdr[4] = 2; // 64-bit
    hdr[5] = 1; // little-endian
    hdr[6] = 1; // version
    hdr
}

#[test]
fn fuzz_elf_loader_never_panics() {
    let mut rng = XorShift64(0x9E3779B97F4A7C15);
    let maps: HashMap<String, i32> = HashMap::new();
    for _ in 0..512 {
        let mut buf = elf_template();
        // mutate header fields + append random tail bytes
        for _ in 0..rng.below(24) {
            let i = rng.below(buf.len());
            buf[i] = rng.byte();
        }
        buf[0..4].copy_from_slice(b"\x7FELF"); // keep magic: exercise header math
        let tail_len = rng.below(256);
        buf.extend((0..tail_len).map(|_| rng.byte()));
        let _ = parse_elf_sockops(&buf, &maps);
    }
}

#[test]
fn fuzz_elf_truncated_inputs() {
    let maps: HashMap<String, i32> = HashMap::new();
    for len in 0..70 {
        let mut buf = vec![0x41u8; len];
        if len >= 4 {
            buf[0..4].copy_from_slice(b"\x7FELF");
        }
        let _ = parse_elf_sockops(&buf, &maps);
    }
}

fn cyclic_pointer_query(self_ref: bool) -> Vec<u8> {
    // header: standard query, qdcount=1
    let mut q = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    if self_ref {
        // QNAME = pointer to offset 12 (itself): infinite self-loop
        q.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
    } else {
        // two labels pointing at each other: 12 -> 16 -> 12 mutual loop
        q.extend_from_slice(&[0xC0, 0x10]); // at 12: jump to 16
        q.extend_from_slice(&[0xC0, 0x0C]); // at 16: jump to 12
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    }
    q
}

#[test]
fn fuzz_dns_compression_pointer_loops_terminate() {
    // self-referential and mutually-referential compression pointers
    for msg in [cyclic_pointer_query(true), cyclic_pointer_query(false)] {
        let _ = extract_query_key(&msg);
        let _ = is_aaaa_query(&msg);
        let _ = parse_dns_response(&msg);
    }
    // random mutation of a well-formed query incl. pointer bytes
    let mut rng = XorShift64(0x2545F4914F6CDD1D);
    let base = cyclic_pointer_query(false);
    for _ in 0..512 {
        let mut m = base.clone();
        for _ in 0..rng.below(8) {
            let i = rng.below(m.len());
            m[i] = rng.byte();
        }
        // sprinkle compression markers
        for _ in 0..rng.below(4) {
            let i = rng.below(m.len());
            m[i] = 0xC0;
        }
        let _ = extract_query_key(&m);
        let _ = is_aaaa_query(&m);
        let _ = parse_dns_response(&m);
    }
}

#[test]
fn fuzz_packet_split_reassembly_invariant() {
    // splitting a payload at arbitrary boundaries and rejoining must
    // reproduce the original bytes exactly (covers PQ-sized payloads).
    let mut rng = XorShift64(0x165667B19E3779F9);
    let conn = ConnInfo::new(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(93, 184, 216, 34),
        12345,
        443,
        1000,
        2000,
    );
    for _ in 0..64 {
        let len = 1 + rng.below(1400);
        let payload: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // random 1-4 way split
        let mut cuts = vec![0, len];
        for _ in 0..rng.below(3) {
            cuts.push(rng.below(len + 1));
        }
        cuts.sort_unstable();
        cuts.dedup();
        let mut rejoined = Vec::with_capacity(len);
        for w in cuts.windows(2) {
            let piece = &payload[w[0]..w[1]];
            // each piece must survive a packet build (headers + payload)
            let pkt = build_packet(&conn, piece, 8);
            assert_eq!(&pkt[40..], piece);
            rejoined.extend_from_slice(piece);
        }
        assert_eq!(rejoined, payload);
    }
}

#[test]
fn fuzz_sni_roundtrip() {
    // built hellos must parse back to the injected SNI (or cleanly reject)
    let mut rng = XorShift64(0x85EBCA77C2B2AE63);
    let labels = ["a", "example", "test-host", "x123", "verylonglabelnamehere"];
    for _ in 0..64 {
        let n = 1 + rng.below(3);
        let mut host = String::new();
        for i in 0..n {
            if i > 0 {
                host.push('.');
            }
            host.push_str(labels[rng.below(labels.len())]);
        }
        host.push_str(".com");
        let hello = build_fake_client_hello(&host);
        assert_eq!(parse_sni(&hello).as_deref(), Some(host.as_str()));
    }
    // mutated hellos must not panic the parser
    let hello = build_fake_client_hello("example.com");
    let mut rng = XorShift64(0x27D4EB2F165667C5);
    for _ in 0..512 {
        let mut m = hello.clone();
        for _ in 0..rng.below(12) {
            let i = rng.below(m.len());
            m[i] = rng.byte();
        }
        let _ = parse_sni(&m);
    }
}

#[test]
fn fuzz_ssrf_consistency() {
    // same input must always give the same verdict (no hidden state/time)
    let mut rng = XorShift64(0x1745F51422D7AEEF);
    for _ in 0..2048 {
        let v4 = Ipv4Addr::new(rng.byte(), rng.byte(), rng.byte(), rng.byte());
        assert_eq!(blocked_ipv4(&v4), blocked_ipv4(&v4));
        let segs = [
            rng.next() as u16,
            rng.next() as u16,
            rng.next() as u16,
            rng.next() as u16,
            rng.next() as u16,
            rng.next() as u16,
            rng.next() as u16,
            rng.next() as u16,
        ];
        let v6 = Ipv6Addr::from(segs);
        assert_eq!(blocked_ipv6(&v6), blocked_ipv6(&v6));
    }
    // spot checks anchor the policy
    assert!(blocked_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
    assert!(blocked_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
    assert!(blocked_ipv4(&Ipv4Addr::new(169, 254, 169, 254)));
    assert!(!blocked_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
    assert!(blocked_ipv6(&Ipv6Addr::LOCALHOST));
    assert!(!blocked_ipv6(&Ipv6Addr::new(
        0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
    )));
}
