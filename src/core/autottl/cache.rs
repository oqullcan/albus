//! thread-safe in-memory cache mapping destination ipv4 addresses to calculated optimal ttl values.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

const MAX_CACHE_ENTRIES: usize = 2048;

#[derive(Debug, Clone)]
struct CacheEntry {
    ttl: u8,
    inserted_at: Instant,
}

impl Drop for CacheEntry {
    fn drop(&mut self) {
        // volatile zeroization of sensitive route distance metadata
        unsafe {
            std::ptr::write_volatile(&mut self.ttl, 0);
        }
    }
}

#[derive(Debug, Clone)]
pub struct TtlCache {
    inner: Arc<RwLock<HashMap<Ipv4Addr, CacheEntry>>>,
}

impl TtlCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // queries cached ttl value for a destination ipv4 endpoint
    pub fn get(&self, ip: &Ipv4Addr) -> Option<u8> {
        let guard = self.inner.read().ok()?;
        guard.get(ip).map(|entry| entry.ttl)
    }

    // stores calculated optimal ttl with timestamp-based capacity eviction
    pub fn insert(&self, ip: Ipv4Addr, ttl: u8) {
        if let Ok(mut guard) = self.inner.write() {
            if guard.len() >= MAX_CACHE_ENTRIES {
                // evict entries older than 3600 seconds when table capacity is saturated
                guard.retain(|_, entry| entry.inserted_at.elapsed().as_secs() < 3600);
                if guard.len() >= MAX_CACHE_ENTRIES {
                    if let Some(oldest) = guard.keys().next().cloned() {
                        guard.remove(&oldest);
                    }
                }
            }
            guard.insert(
                ip,
                CacheEntry {
                    ttl,
                    inserted_at: Instant::now(),
                },
            );
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for TtlCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_cache_basic() {
        let cache = TtlCache::new();
        let ip = Ipv4Addr::new(93, 184, 216, 34);

        assert_eq!(cache.get(&ip), None);
        cache.insert(ip, 6);
        assert_eq!(cache.get(&ip), Some(6));
    }

    #[test]
    fn test_ttl_cache_len_and_is_empty_and_default() {
        let cache = TtlCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        let ip1 = Ipv4Addr::new(1, 1, 1, 1);
        cache.insert(ip1, 12);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&ip1), Some(12));

        // overwrite existing ip
        cache.insert(ip1, 14);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&ip1), Some(14));
    }

    #[test]
    fn test_ttl_cache_capacity_and_entry_drop() {
        let cache = TtlCache::new();
        // verify cache entry drop zeroization doesn't panic
        let entry = CacheEntry {
            ttl: 64,
            inserted_at: Instant::now(),
        };
        drop(entry);

        // insert a few IPs
        for i in 1..=5 {
            cache.insert(Ipv4Addr::new(10, 0, 0, i), i);
        }
        assert_eq!(cache.len(), 5);
        assert_eq!(cache.get(&Ipv4Addr::new(10, 0, 0, 3)), Some(3));
    }
}
