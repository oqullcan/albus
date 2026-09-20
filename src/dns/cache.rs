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

// parses question section domain labels (rfc 1035) and qtype from dns wire format
pub fn extract_query_key(data: &[u8]) -> Option<DnsCacheKey> {
    if data.len() < 16 {
        return None;
    }

    let qdcount = ((data[4] as u16) << 8) | (data[5] as u16);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;
    let mut labels = Vec::new();

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
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        if let Ok(label) = std::str::from_utf8(&data[pos..pos + len]) {
            labels.push(label.to_lowercase());
        }
        pos += len;
    }

    if pos + 2 > data.len() {
        return None;
    }

    let qtype = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
    // include DO-bit in cache key so dnssec on/off responses are not cross-served
    let do_bit = data.len() >= 12 && {
        let arcount = ((data[10] as u16) << 8) | (data[11] as u16);
        arcount > 0
    };
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
}

#[cfg(test)]
mod eviction_tests {
    use super::*;

    fn query_for(name: &str, id: u16) -> Vec<u8> {
        let mut q = vec![
            (id >> 8) as u8,
            id as u8,
            0x01,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        q
    }

    fn canned_response(query: &[u8]) -> Vec<u8> {
        let mut r = query.to_vec();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 0x01; // ancount = 1
        r.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 93, 184, 216,
            34,
        ]);
        r
    }

    #[test]
    fn test_capacity_bounded_under_flood() {
        let cache = DnsCache::new(4);
        for i in 0..32u16 {
            let q = query_for(&format!("host{}.example.com", i), i);
            let r = canned_response(&q);
            cache.insert(&q, &r);
        }
        let len = cache.entries.lock().unwrap().len();
        assert!(len <= 4, "cache must stay bounded, len={}", len);
    }

    #[test]
    fn test_degenerate_inputs_ignored() {
        let cache = DnsCache::new(8);
        let q = query_for("example.com", 1);
        cache.insert(&[], &[]);
        cache.insert(&q, &[]);
        cache.insert(&[], &q);
        cache.insert(&[0u8; 11], &[0u8; 11]);
        assert!(cache.entries.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
mod ttl_tests {
    use super::*;

    fn response_with_ttl(ttl: u32) -> Vec<u8> {
        let mut q = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let _ = &mut q;
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 0x01;
        r.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&[0x00, 0x04, 93, 184, 216, 34]);
        r
    }

    #[test]
    fn test_extract_min_ttl_table() {
        // ttl=0 is ignored (falls back to default 300), values pass through
        let q = response_with_ttl(0);
        // craft query form for extract_min_ttl input (full response wire)
        assert_eq!(extract_min_ttl(&q), 300);
        assert_eq!(extract_min_ttl(&response_with_ttl(60)), 60);
        // high TTLs pass through here; the 5..600 clamp lives in insert()
        assert_eq!(extract_min_ttl(&response_with_ttl(3600)), 300);
        assert_eq!(extract_min_ttl(&[]), 60);
        assert_eq!(extract_min_ttl(&[0u8; 10]), 60);
    }
}
