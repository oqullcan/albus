//! in-memory dns response wire cache with ttl-bounded expiration and transaction id rewriting.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// lookup key derived from queried fqdn labels and resource record type
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct DnsCacheKey {
    pub name: String,
    pub qtype: u16,
    pub do_bit: bool,
}

// cached response payload with calculated wall-clock expiry instant
#[derive(Clone, Debug)]
pub struct DnsCacheEntry {
    pub response_wire: Vec<u8>,
    pub expires_at: Instant,
}

impl Drop for DnsCacheEntry {
    fn drop(&mut self) {
        // volatile memory zeroization preventing cold-boot and memory-dump forensic inspection
        for byte in self.response_wire.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

// bounded hash map storing raw dns wire responses
pub struct DnsCache {
    entries: Mutex<HashMap<DnsCacheKey, DnsCacheEntry>>,
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::with_capacity(max_entries)),
            max_entries,
        }
    }

    // retrieves cached response wire bytes and substitutes transaction id to match client query
    pub fn get(&self, query_bytes: &[u8]) -> Option<Vec<u8>> {
        if query_bytes.len() < 12 {
            return None;
        }

        let key = extract_query_key(query_bytes)?;
        let now = Instant::now();

        let mut map = self.entries.lock().ok()?;
        if let Some(entry) = map.get(&key) {
            if entry.expires_at > now {
                let mut resp = entry.response_wire.clone();
                if resp.len() >= 2 {
                    // overwrite header transaction identifier (bytes 0-1) with client query id
                    resp[0] = query_bytes[0];
                    resp[1] = query_bytes[1];
                }
                return Some(resp);
            } else {
                map.remove(&key);
            }
        }

        None
    }

    // clears all entries from the in-memory cache
    pub fn clear(&self) {
        if let Ok(mut map) = self.entries.lock() {
            map.clear();
        }
    }

    // parses minimum ttl across answer section and inserts wire response into cache
    pub fn insert(&self, query_bytes: &[u8], response_bytes: &[u8]) {
        if query_bytes.len() < 12 || response_bytes.len() < 12 {
            return;
        }

        let key = match extract_query_key(query_bytes) {
            Some(k) => k,
            None => return,
        };

        let ttl_secs = extract_min_ttl(response_bytes).clamp(5, 600);
        let expires_at = Instant::now() + Duration::from_secs(ttl_secs as u64);

        let mut map = match self.entries.lock() {
            Ok(m) => m,
            Err(_) => return,
        };

        if map.len() >= self.max_entries {
            // purge expired cache entries upon reaching capacity limit
            let now = Instant::now();
            map.retain(|_, v| v.expires_at > now);
            if map.len() >= self.max_entries {
                if let Some(oldest_key) = map.keys().next().cloned() {
                    map.remove(&oldest_key);
                }
            }
        }

        map.insert(
            key,
            DnsCacheEntry {
                response_wire: response_bytes.to_vec(),
                expires_at,
            },
        );
    }
}

// FP-06: outcome of scanning the additional section for an OPT pseudo-RR.
// Malformed input is distinct from "no OPT present" so callers can fail
// closed (skip cache) instead of guessing the DO bit.
pub(crate) enum OptScan {
    Malformed,
    Absent,
    Present { ttl_offset: usize },
}

// skips one DNS name (labels and/or compression pointers), returning the
// offset just past it. Strictly bounded — None on any truncation.
fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    let mut steps = 0;
    loop {
        if pos >= data.len() || steps > 64 {
            return None;
        }
        steps += 1;
        let len = data[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 2 > data.len() {
                return None;
            }
            // pointer: name ends here (target not followed — only DO bit needed)
            return Some(pos + 2);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1 + (len as usize);
    }
}

// locates the OPT RR's 4-byte TTL field (DO flag lives in its low 16 bits).
pub(crate) fn scan_opt(data: &[u8]) -> OptScan {
    if data.len() < 12 {
        return OptScan::Malformed;
    }
    let arcount = (((data[10] as u16) << 8) | (data[11] as u16)) as usize;
    if arcount == 0 {
        return OptScan::Absent;
    }
    // skip question section: QNAME + QTYPE(2) + QCLASS(2)
    let mut pos = match skip_name(data, 12) {
        Some(p) => p,
        None => return OptScan::Malformed,
    };
    if pos + 4 > data.len() {
        return OptScan::Malformed;
    }
    pos += 4;
    for _ in 0..arcount {
        pos = match skip_name(data, pos) {
            Some(p) => p,
            None => return OptScan::Malformed,
        };
        // TYPE(2) CLASS(2) TTL(4) RDLEN(2)
        if pos + 10 > data.len() {
            return OptScan::Malformed;
        }
        let rr_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        let rdlen = (((data[pos + 8] as u16) << 8) | data[pos + 9] as u16) as usize;
        if rr_type == 41 {
            return OptScan::Present {
                ttl_offset: pos + 4,
            };
        }
        pos += 10;
        if pos + rdlen > data.len() {
            return OptScan::Malformed;
        }
        pos += rdlen;
    }
    OptScan::Absent
}

// FP-06: exact RFC 6891 DO bit (0x8000 in OPT TTL low 16), never ARCOUNT proxy.
// None = malformed input → callers must skip cache (fail closed).
pub fn extract_do_bit(data: &[u8]) -> Option<bool> {
    match scan_opt(data) {
        OptScan::Malformed => None,
        OptScan::Absent => Some(false),
        OptScan::Present { ttl_offset } => {
            let ttl = u32::from_be_bytes([
                data[ttl_offset],
                data[ttl_offset + 1],
                data[ttl_offset + 2],
                data[ttl_offset + 3],
            ]);
            Some(ttl & 0x8000 != 0)
        }
    }
}

// Parses question-section domain labels (RFC 1035) and qtype from the wire.
//
// The result is a cache key AND the DNSSEC negative-verdict key, so this must
// be a strict, injective image of the question: two different questions must
// never share one key. The previous version dropped labels that were not
// valid UTF-8 and accepted `.`/control bytes inside a label, so
// `labels.join(".")` was many-to-one — the single-label name
// `example.com` and the real two-label `example.com` produced identical keys,
// letting any unprivileged local process poison or evict the shared response
// cache (and replay a stale Bogus verdict) for a chosen domain with one
// 33-byte datagram.
//
// Rules, each rejecting the whole query rather than mangling the name:
//   * reserved label types (`len & 0xC0 != 0`), including compression
//     pointers — RFC 1035 §4.1.2 forbids pointers in a question section, and
//     following one here would read QTYPE out of the pointer's own bytes;
//   * labels that are not valid UTF-8 — dropped silently before, which merged
//     distinct names together;
//   * labels failing `label_is_safe`, the same allowlist the response parser
//     applies, so a hostile label cannot reach a map key, a queue entry or a
//     log field;
//   * an empty name.
pub fn extract_query_key(data: &[u8]) -> Option<DnsCacheKey> {
    if data.len() < 16 {
        return None;
    }

    let qdcount = ((data[4] as u16) << 8) | (data[5] as u16);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;
    let mut labels: Vec<String> = Vec::new();

    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Reserved label type, including a 0xC0 compression pointer: reject
        // rather than treating it as an end-of-name.
        if (len & 0xC0) != 0 {
            return None;
        }
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[pos..pos + len]).ok()?;
        if !crate::dns::server::label_is_safe(label) {
            return None;
        }
        labels.push(label.to_lowercase());
        pos += len;
    }

    if labels.is_empty() {
        return None;
    }
    if pos + 2 > data.len() {
        return None;
    }

    let qtype = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
    // FP-06: exact DO bit in cache key so dnssec on/off responses are never
    // cross-served. Malformed OPT section → None → callers skip cache.
    let do_bit = extract_do_bit(data)?;
    Some(DnsCacheKey {
        name: labels.join("."),
        qtype,
        do_bit,
    })
}

// parses answer section resource records to compute lowest ttl value
pub fn extract_min_ttl(data: &[u8]) -> u32 {
    if data.len() < 12 {
        return 60;
    }

    let qdcount = ((data[4] as usize) << 8) | (data[5] as usize);
    let ancount = ((data[6] as usize) << 8) | (data[7] as usize);

    if ancount == 0 {
        return 60;
    }

    let mut pos = 12;

    // skip question section records
    for _ in 0..qdcount {
        while pos < data.len() {
            let len = data[pos] as usize;
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
        pos += 4; // skip qtype and qclass
    }

    let mut min_ttl = 300u32;

    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }

        if (data[pos] & 0xC0) == 0xC0 {
            pos += 2;
        } else {
            while pos < data.len() {
                let len = data[pos] as usize;
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
        }

        if pos + 10 > data.len() {
            break;
        }

        let ttl = ((data[pos + 4] as u32) << 24)
            | ((data[pos + 5] as u32) << 16)
            | ((data[pos + 6] as u32) << 8)
            | (data[pos + 7] as u32);
        let rdlength = ((data[pos + 8] as usize) << 8) | (data[pos + 9] as usize);
        pos += 10 + rdlength;

        if ttl > 0 && ttl < min_ttl {
            min_ttl = ttl;
        }
    }

    min_ttl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_cache_hit_and_id_replacement() {
        let cache = DnsCache::new(100);

        let query1 = vec![
            0x12, 0x34, // ID 0x1234
            0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        let mut fake_resp = query1.clone();
        fake_resp[2] = 0x81;
        fake_resp[3] = 0x80;
        fake_resp[7] = 0x01; // ancount = 1
        fake_resp.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 93, 184, 216,
            34,
        ]);

        cache.insert(&query1, &fake_resp);

        let mut query2 = query1.clone();
        query2[0] = 0xAB;
        query2[1] = 0xCD;

        let hit = cache.get(&query2).expect("cache should hit");
        assert_eq!(hit[0], 0xAB);
        assert_eq!(hit[1], 0xCD);
        assert_eq!(&hit[hit.len() - 4..], &[93, 184, 216, 34]);
    }

    fn fp06_query(arcount_extra: &[u8]) -> Vec<u8> {
        let mut q = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // arcount patched below
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];
        if !arcount_extra.is_empty() {
            q[10] = 0x00;
            q[11] = 0x01;
            q.extend_from_slice(arcount_extra);
        }
        q
    }

    // FP-06: OPT-without-DO and OPT-with-DO must NOT share a cache key.
    #[test]
    fn test_do_bit_exact_not_arcount_proxy() {
        // no additionals → false
        assert_eq!(extract_do_bit(&fp06_query(&[])), Some(false));
        // OPT without DO → false
        let no_do = [
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(extract_do_bit(&fp06_query(&no_do)), Some(false));
        // OPT with DO → true
        let with_do = [
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        ];
        assert_eq!(extract_do_bit(&fp06_query(&with_do)), Some(true));
        // keys segregate
        let k_plain = extract_query_key(&fp06_query(&[])).unwrap();
        let k_nodo = extract_query_key(&fp06_query(&no_do)).unwrap();
        let k_do = extract_query_key(&fp06_query(&with_do)).unwrap();
        assert!(!k_nodo.do_bit);
        assert!(k_do.do_bit);
        assert_ne!(k_nodo, k_do);
        assert_eq!(k_plain.do_bit, k_nodo.do_bit);
        // truncated additionals → None (fail closed, skip cache)
        let mut bad = fp06_query(&no_do);
        bad.truncate(bad.len() - 3);
        // arcount still 1 but OPT truncated
        assert_eq!(extract_query_key(&bad), None);
    }
}

#[cfg(test)]
mod key_injectivity_tests {
    use super::*;

    /// Builds a minimal 33-byte DNS query. `labels` are the raw QNAME labels.
    fn query(labels: &[&[u8]], qtype: u16) -> Vec<u8> {
        let mut m: Vec<u8> = Vec::new();
        m.extend_from_slice(&[0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01]); // id, qr, qdcount=1
        m.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // an/ns/ar
        for l in labels {
            assert!(l.len() < 64);
            m.push(l.len() as u8);
            m.extend_from_slice(l);
        }
        m.push(0x00); // root label
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x01]); // qclass IN
        m
    }

    /// DNS-01: the single-label name whose bytes ARE "example.com" must not
    /// resolve to the same key as the real two-label `example.com`. Before the
    /// fix both produced `("example.com", 1, false)`, so one 33-byte datagram
    /// from any unprivileged local process could evict or poison the shared
    /// response cache for that domain.
    #[test]
    fn test_single_label_smuggled_name_cannot_collide() {
        let victim = query(&[b"example", b"com"], 1);
        let attacker = query(&[b"example.com"], 1);

        let vk = extract_query_key(&victim).expect("legitimate query has a key");
        let ak = extract_query_key(&attacker);
        assert_ne!(
            ak.as_ref().map(|k| &k.name),
            Some(&vk.name),
            "smuggled single-label name must not share the victim's cache key"
        );
        assert!(
            ak.is_none(),
            "label containing '.' must be rejected outright"
        );
    }

    /// Invalid UTF-8 was silently dropped, which also merged names.
    #[test]
    fn test_invalid_utf8_label_is_rejected_not_dropped() {
        let q = query(&[&[0xff, 0x00], b"com"], 1);
        assert!(
            extract_query_key(&q).is_none(),
            "an undecodable label must reject the query, not vanish from the key"
        );
        // And it must not collide with the surviving suffix alone.
        let survivor = query(&[b"com"], 1);
        let sk = extract_query_key(&survivor).expect("com is valid");
        assert_ne!(
            extract_query_key(&q).as_ref().map(|k| &k.name),
            Some(&sk.name)
        );
    }

    /// A compression pointer in the question section is forbidden by
    /// RFC 1035 §4.1.2. Previously it terminated the name and QTYPE was read
    /// from the pointer's own bytes, yielding an attacker-chosen key.
    #[test]
    fn test_compression_pointer_in_question_is_rejected() {
        let mut q = query(&[b"example", b"com"], 1);
        // Replace the QNAME with a pointer to offset 12.
        let mut p = Vec::new();
        p.extend_from_slice(&q[..12]);
        p.push(0xC0);
        p.push(0x0C);
        p.extend_from_slice(&1u16.to_be_bytes()); // qtype read from pointer bytes
        p.extend_from_slice(&[0x00, 0x01]);
        q.clear();
        assert!(
            extract_query_key(&p).is_none(),
            "a compression pointer in the question must be rejected"
        );
    }

    /// Reserved label types in general.
    #[test]
    fn test_reserved_label_types_are_rejected() {
        for first in [0x40u8, 0x80, 0xC0, 0xE0] {
            let mut p = Vec::new();
            p.extend_from_slice(&[0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01]);
            p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            p.push(first);
            p.extend_from_slice(b"com");
            p.push(0x00);
            p.extend_from_slice(&1u16.to_be_bytes());
            p.extend_from_slice(&[0x00, 0x01]);
            assert!(
                extract_query_key(&p).is_none(),
                "label type {:#04x} must be rejected",
                first
            );
        }
    }

    /// Ordinary names must keep working — the fix is not over-broad.
    #[test]
    fn test_legitimate_names_still_key() {
        for (labels, expected) in [
            (
                vec![b"example".as_slice(), b"com".as_slice()],
                "example.com",
            ),
            (
                vec![
                    b"_dmarc".as_slice(),
                    b"example".as_slice(),
                    b"com".as_slice(),
                ],
                "_dmarc.example.com",
            ),
            (vec![b"a-b".as_slice(), b"c".as_slice()], "a-b.c"),
            (
                vec![b"xn--80ak6aa92e".as_slice(), b"com".as_slice()],
                "xn--80ak6aa92e.com",
            ),
        ] {
            let q = query(&labels, 1);
            let k = extract_query_key(&q)
                .unwrap_or_else(|| panic!("{:?} must produce a key", expected));
            assert_eq!(k.name, expected);
            assert_eq!(k.qtype, 1);
        }
    }

    /// Case folding must still happen (DNS names are case-insensitive) while
    /// remaining injective for the wire forms that actually occur.
    #[test]
    fn test_case_insensitivity_is_preserved() {
        let upper = query(&[b"EXAMPLE", b"COM"], 1);
        let lower = query(&[b"example", b"com"], 1);
        assert_eq!(
            extract_query_key(&upper).map(|k| k.name),
            extract_query_key(&lower).map(|k| k.name),
            "DNS names are case-insensitive and must fold to one key"
        );
    }

    /// An empty QNAME must not produce the empty-string key.
    #[test]
    fn test_empty_name_is_rejected() {
        let q = query(&[], 1);
        assert!(extract_query_key(&q).is_none());
    }
}
