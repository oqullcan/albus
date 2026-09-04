//! in-memory dns response wire cache with ttl-bounded expiration and transaction id rewriting.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// lookup key derived from queried fqdn labels and resource record type
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct DnsCacheKey {
    pub name: String,
    pub qtype: u16,
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

        let ttl_secs = extract_min_ttl(response_bytes).clamp(5, 3600);
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
    Some(DnsCacheKey {
        name: labels.join("."),
        qtype,
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
            0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        let mut fake_resp = query1.clone();
        fake_resp[2] = 0x81;
        fake_resp[3] = 0x80;
        fake_resp[7] = 0x01; // ancount = 1
        fake_resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 93, 184, 216, 34]);

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
