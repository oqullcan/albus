// high-speed bounded in-memory dns response cache with ttl expiration

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const MAX_CACHE_ENTRIES: usize = 2048; // hard cap: ~250kb max memory footprint

#[derive(Clone)]
struct CacheEntry {
    response_payload: Vec<u8>,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct DnsCache {
    entries: Arc<RwLock<HashMap<Vec<u8>, CacheEntry>>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::with_capacity(256))),
        }
    }

    // extracts lookup key from raw dns query (skipping the 2-byte transaction id)
    fn extract_query_key(packet: &[u8]) -> Option<&[u8]> {
        if packet.len() >= 12 {
            Some(&packet[2..]) // question section without tx id
        } else {
            None
        }
    }

    // parses minimum ttl from dns answer records
    fn parse_ttl(response: &[u8]) -> Duration {
        if response.len() < 12 {
            return Duration::from_secs(60);
        }

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        if ancount == 0 {
            return Duration::from_secs(30);
        }

        let mut pos = 12;
        while pos < response.len() && response[pos] != 0 {
            if (response[pos] & 0xc0) == 0xc0 {
                pos += 2;
                break;
            }
            pos += 1 + (response[pos] as usize);
        }
        if pos < response.len() && response[pos] == 0 {
            pos += 1;
        }
        pos += 4; // qtype + qclass

        let mut min_ttl = 300u32;
        for _ in 0..ancount {
            if pos >= response.len() {
                break;
            }
            if (response[pos] & 0xc0) == 0xc0 {
                pos += 2;
            } else {
                while pos < response.len() && response[pos] != 0 {
                    pos += 1 + (response[pos] as usize);
                }
                pos += 1;
            }
            if pos + 10 > response.len() {
                break;
            }
            let ttl = u32::from_be_bytes([
                response[pos + 4],
                response[pos + 5],
                response[pos + 6],
                response[pos + 7],
            ]);
            if ttl > 0 && ttl < min_ttl {
                min_ttl = ttl;
            }
            let rdlen = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }

        // clamp ttl between 5 seconds and 10 minutes
        let clamped = min_ttl.clamp(5, 600) as u64;
        Duration::from_secs(clamped)
    }

    // gets cached response and rewrites transaction id to match client request
    pub async fn get(&self, query_packet: &[u8]) -> Option<Vec<u8>> {
        let key = Self::extract_query_key(query_packet)?;
        let tx_id = [query_packet[0], query_packet[1]];

        let cache = self.entries.read().await;
        if let Some(entry) = cache.get(key) {
            if Instant::now() < entry.expires_at && entry.response_payload.len() >= 2 {
                let mut resp = entry.response_payload.clone();
                resp[0] = tx_id[0];
                resp[1] = tx_id[1];
                return Some(resp);
            }
        }
        None
    }

    // inserts validated dns response into bounded cache
    pub async fn insert(&self, query_packet: &[u8], response_packet: &[u8]) {
        if let Some(key) = Self::extract_query_key(query_packet) {
            let ttl = Self::parse_ttl(response_packet);
            let mut cache = self.entries.write().await;

            // enforce strict capacity limit to prevent memory growth
            if cache.len() >= MAX_CACHE_ENTRIES {
                let now = Instant::now();
                cache.retain(|_, v| v.expires_at > now);
                if cache.len() >= MAX_CACHE_ENTRIES {
                    if let Some(first_key) = cache.keys().next().cloned() {
                        cache.remove(&first_key);
                    }
                }
            }

            cache.insert(
                key.to_vec(),
                CacheEntry {
                    response_payload: response_packet.to_vec(),
                    expires_at: Instant::now() + ttl,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_cache_insert_and_get() {
        let cache = DnsCache::new();

        // Sample query: tx_id=0x1234, rest=question
        let query1 = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x00];
        // Sample response with same question + answer
        let resp1 = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x00];

        cache.insert(&query1, &resp1).await;

        // Query with different tx_id=0xabcd for same domain
        let query2 = vec![0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x00];
        let cached = cache.get(&query2).await;

        assert!(cached.is_some());
        let cached_resp = cached.unwrap();
        // TX ID must be rewritten to match client query (0xabcd)
        assert_eq!(cached_resp[0], 0xab);
        assert_eq!(cached_resp[1], 0xcd);
    }
}

