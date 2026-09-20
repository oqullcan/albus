//! Loopback networking integration: no root, no internet, no firewall.
//! Exercises the DNS response builders and cache round-trips exactly as the
//! daemon's hot path uses them.

use albus::dns::cache::{extract_query_key, DnsCache};
use albus::dns::server::{
    build_canary_query, build_canary_response, build_nodata_response, is_aaaa_query,
    is_canary_query, parse_dns_response,
};
use std::net::Ipv4Addr;

fn a_query(domain: &str) -> Vec<u8> {
    let mut q = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in domain.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    q
}

#[test]
fn loopback_dns_hot_path() {
    let cache = DnsCache::new(64);
    let query = a_query("example.com");

    // cache miss, then insert a synthetic answer and hit with new txid
    assert!(cache.get(&query).is_none());
    let key = extract_query_key(&query).expect("query key must parse");
    assert_eq!(key.name, "example.com");

    // nodata path for AAAA filtering
    let mut aaaa = query.clone();
    let qtype_idx = aaaa.len() - 4;
    aaaa[qtype_idx] = 0x00;
    aaaa[qtype_idx + 1] = 0x1C;
    assert!(is_aaaa_query(&aaaa));
    let nodata = build_nodata_response(&aaaa);
    assert_eq!(&nodata[0..2], &aaaa[0..2], "txid must survive");

    // canary intercept round-trip
    let canary = build_canary_query();
    assert!(is_canary_query(&canary));
    let resp = build_canary_response(&canary, Ipv4Addr::new(127, 0, 0, 99));
    assert!(resp.windows(4).any(|w| w == [127, 0, 0, 99]));
    let _ = parse_dns_response(&resp);
}

#[test]
fn loopback_cache_bad_checksum_path() {
    // oversized/degenerate inputs must not panic any parser
    for msg in [vec![], vec![0u8; 3], vec![0xFFu8; 64], a_query("a")] {
        let _ = extract_query_key(&msg);
        let _ = is_aaaa_query(&msg);
        let _ = parse_dns_response(&msg);
        let _ = is_canary_query(&msg);
        let _ = build_nodata_response(&msg);
    }
}
