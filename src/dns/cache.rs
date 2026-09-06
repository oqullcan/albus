//! in-memory dns response wire cache with dynamic ttl decay, serve-stale (rfc 8767), and negative caching (rfc 2308).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// lookup key derived from queried fqdn labels and resource record type
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct DnsCacheKey {
    pub name: String,
    pub qtype: u16,
}

// cached response payload with dynamic ttl decay and serve-stale boundaries
#[derive(Clone, Debug)]
pub struct DnsCacheEntry {
    pub response_wire: Vec<u8>,
    pub original_ttl: u32,
    pub inserted_at: Instant,
    pub expires_at: Instant,
    pub stale_until: Instant,
    pub is_negative: bool,
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
    min_ttl: u32,
    max_ttl: u32,
    negative_ttl: u32,
    neg_min_ttl: u32,
    neg_max_ttl: u32,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::with_capacity(max_entries)),
            max_entries,
            min_ttl: 60,      // clamp minimum ttl to 60s
            max_ttl: 86400,   // clamp maximum ttl to 24h
            negative_ttl: 60, // rfc 2308 negative cache duration: 60s
            neg_min_ttl: 60,  // clamp minimum negative ttl
            neg_max_ttl: 600, // clamp maximum negative ttl
        }
    }

    pub fn with_neg_ttl(mut self, min: u32, max: u32) -> Self {
        self.neg_min_ttl = min;
        self.neg_max_ttl = max.max(min);
        self
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|m| m.len()).unwrap_or(0)
    }

    // retrieves active cached response wire bytes with dynamic ttl decay and transaction id rewriting
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
                if resp.len() >= 12 {
                    resp[0] = query_bytes[0];
                    resp[1] = query_bytes[1];

                    // dynamic ttl decay: calculate remaining seconds and update wire records
                    let elapsed = now.saturating_duration_since(entry.inserted_at).as_secs() as u32;
                    let remaining_ttl = entry.original_ttl.saturating_sub(elapsed).max(1);
                    update_response_ttls(&mut resp, remaining_ttl);
                }
                return Some(resp);
            } else if entry.stale_until <= now {
                // purge entry only if even serve-stale grace period has fully expired
                map.remove(&key);
            }
        }

        None
    }

    // retrieves expired response under rfc 8767 serve-stale policy during upstream downtime or timeouts
    pub fn get_stale(&self, query_bytes: &[u8]) -> Option<Vec<u8>> {
        if query_bytes.len() < 12 {
            return None;
        }

        let key = extract_query_key(query_bytes)?;
        let now = Instant::now();

        let map = self.entries.lock().ok()?;
        if let Some(entry) = map.get(&key) {
            // serve stale only if expired but still within stale grace window (30s past expiry)
            if now >= entry.expires_at && now <= entry.stale_until {
                let mut resp = entry.response_wire.clone();
                if resp.len() >= 12 {
                    resp[0] = query_bytes[0];
                    resp[1] = query_bytes[1];
                    // rfc 8767: advertise low 30s ttl for stale synthetic responses
                    update_response_ttls(&mut resp, 30);
                }
                return Some(resp);
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

    // parses ttl and inserts wire response into cache (supports negative caching and serve-stale)
    pub fn insert(&self, query_bytes: &[u8], response_bytes: &[u8]) {
        if query_bytes.len() < 12 || response_bytes.len() < 12 {
            return;
        }

        let key = match extract_query_key(query_bytes) {
            Some(k) => k,
            None => return,
        };

        let now = Instant::now();
        let rcode = response_bytes[3] & 0x0F;
        let ancount = ((response_bytes[6] as usize) << 8) | (response_bytes[7] as usize);

        // rfc 2308: cache nxdomain (rcode 3) and nodata (ancount 0) responses
        let is_negative = rcode == 3 || (rcode == 0 && ancount == 0);
        let ttl_secs = if is_negative {
            extract_min_ttl(response_bytes).clamp(self.neg_min_ttl, self.neg_max_ttl)
        } else {
            extract_min_ttl(response_bytes).clamp(self.min_ttl, self.max_ttl)
        };

        let expires_at = now + Duration::from_secs(ttl_secs as u64);
        // rfc 8767: retain stale responses for an extra 30 seconds after expiry
        let stale_until = expires_at + Duration::from_secs(30);

        let mut map = match self.entries.lock() {
            Ok(m) => m,
            Err(_) => return,
        };

        if map.len() >= self.max_entries {
            map.retain(|_, v| v.stale_until > now);
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
                original_ttl: ttl_secs,
                inserted_at: now,
                expires_at,
                stale_until,
                is_negative,
            },
        );
    }
}

// skips a dns name (rfc 1035 labels and compression pointers) and returns offset after the name
fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            return Some(pos + 2);
        }
        if (len & 0xC0) != 0 {
            return None;
        }
        pos += 1 + len;
    }
    None
}

// traverses answer and authority sections of wire response and overwrites all ttl fields with new_ttl
pub fn update_response_ttls(data: &mut [u8], new_ttl: u32) {
    if data.len() < 12 {
        return;
    }

    let qdcount = ((data[4] as usize) << 8) | (data[5] as usize);
    let ancount = ((data[6] as usize) << 8) | (data[7] as usize);
    let nscount = ((data[8] as usize) << 8) | (data[9] as usize);

    let records_to_update = if ancount > 0 { ancount } else { nscount };
    if records_to_update == 0 {
        return;
    }

    let mut pos = 12;

    // skip questions
    for _ in 0..qdcount {
        pos = match skip_dns_name(data, pos) {
            Some(p) => p,
            None => return,
        };
        if pos + 4 > data.len() {
            return;
        }
        pos += 4; // qtype + qclass
    }

    let ttl_bytes = new_ttl.to_be_bytes();

    for _ in 0..records_to_update {
        if pos >= data.len() {
            break;
        }

        pos = match skip_dns_name(data, pos) {
            Some(p) => p,
            None => break,
        };

        if pos + 10 > data.len() {
            break;
        }

        // overwrite ttl field (bytes 4..8 after record name)
        data[pos + 4] = ttl_bytes[0];
        data[pos + 5] = ttl_bytes[1];
        data[pos + 6] = ttl_bytes[2];
        data[pos + 7] = ttl_bytes[3];

        let rdlength = ((data[pos + 8] as usize) << 8) | (data[pos + 9] as usize);
        pos += 10 + rdlength;
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
        if (len & 0xC0) != 0 {
            return None;
        }
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        if let Ok(label) = std::str::from_utf8(&data[pos..pos + len]) {
            labels.push(label.to_lowercase());
        }
        if labels.len() >= 128 {
            return None;
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

// parses answer or authority section resource records to compute lowest ttl value
pub fn extract_min_ttl(data: &[u8]) -> u32 {
    if data.len() < 12 {
        return 60;
    }

    let qdcount = ((data[4] as usize) << 8) | (data[5] as usize);
    let ancount = ((data[6] as usize) << 8) | (data[7] as usize);
    let nscount = ((data[8] as usize) << 8) | (data[9] as usize);

    let count = if ancount > 0 { ancount } else { nscount };
    if count == 0 {
        return 60;
    }

    let mut min_ttl = 300u32;
    let mut pos = 12;

    for _ in 0..qdcount {
        pos = match skip_dns_name(data, pos) {
            Some(p) => p,
            None => return min_ttl,
        };
        if pos + 4 > data.len() {
            return min_ttl;
        }
        pos += 4; // qtype + qclass
    }

    for _ in 0..count {
        if pos >= data.len() {
            break;
        }

        pos = match skip_dns_name(data, pos) {
            Some(p) => p,
            None => break,
        };

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
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        let mut fake_resp = query1.clone();
        fake_resp[2] = 0x81;
        fake_resp[3] = 0x80;
        fake_resp[7] = 0x01;
        fake_resp.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 93, 184, 216,
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

    #[test]
    fn test_ttl_decay_and_update() {
        let mut resp = vec![
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, // Answer
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 1, 1, 1, 1,
        ];

        update_response_ttls(&mut resp, 42);
        // TTL is at offset 12 (header) + 17 (question) + 6 (name, type, class) = 35..39
        assert_eq!(&resp[35..39], &42u32.to_be_bytes());
    }

    #[test]
    fn test_negative_cache_clamping() {
        let cache = DnsCache::new(100).with_neg_ttl(30, 300);

        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'n',
            b'o', b't', b'f', b'n', b'd', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        // NXDOMAIN response (rcode = 3) with an authority record having TTL 10 (< neg_min_ttl 30)
        let mut nx_resp = query.clone();
        nx_resp[2] = 0x81;
        nx_resp[3] = 0x83; // NXDOMAIN
        nx_resp[8] = 0x00;
        nx_resp[9] = 0x01; // NSCOUNT = 1
        nx_resp.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x04, 0, 0, 0,
            0, // TTL = 10
        ]);

        cache.insert(&query, &nx_resp);

        let key = extract_query_key(&query).unwrap();
        let map = cache.entries.lock().unwrap();
        let entry = map.get(&key).expect("should be cached");
        assert!(entry.is_negative);
        assert_eq!(entry.original_ttl, 30); // clamped to neg_min_ttl: 30
    }
}
