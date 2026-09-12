//! Active probing and replay attack defense engine.
//!
//! State-level firewalls (such as GFW and TSPU) perform active probing by replaying
//! recorded TLS ClientHello packets or sending malformed probes to suspect IPs.
//! This module utilizes a high-efficiency Rolling Bloom Filter to detect replay
//! attempts and returns deceptive honeytoken responses (e.g., standard Nginx/Apache 404s)
//! to convince censors that the endpoint is merely an ordinary web server.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

/// Sliding window Rolling Bloom Filter for zero-allocation replay packet detection.
pub struct RollingBloomFilter {
    primary: Vec<u64>,
    secondary: Vec<u64>,
    num_bits: usize,
    num_hashes: usize,
    last_rotation: Instant,
    window_duration: Duration,
}

impl RollingBloomFilter {
    pub fn new(num_bits: usize, num_hashes: usize, window_duration: Duration) -> Self {
        let num_u64s = (num_bits + 63) / 64;
        Self {
            primary: vec![0u64; num_u64s],
            secondary: vec![0u64; num_u64s],
            num_bits,
            num_hashes,
            last_rotation: Instant::now(),
            window_duration,
        }
    }

    fn hashes<T: Hash + ?Sized>(&self, item: &T) -> Vec<usize> {
        let mut results = Vec::with_capacity(self.num_hashes);
        let mut hasher1 = DefaultHasher::new();
        item.hash(&mut hasher1);
        let h1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        h1.hash(&mut hasher2);
        let h2 = hasher2.finish();

        for i in 0..self.num_hashes {
            let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
            results.push((combined as usize) % self.num_bits);
        }
        results
    }

    /// Checks if a rotation is due and shifts generations.
    pub fn maybe_rotate(&mut self, now: Instant) {
        if now.duration_since(self.last_rotation) >= self.window_duration {
            self.secondary = std::mem::take(&mut self.primary);
            self.primary = vec![0u64; (self.num_bits + 63) / 64];
            self.last_rotation = now;
        }
    }

    /// Checks whether the item has been seen recently.
    pub fn contains<T: Hash + ?Sized>(&self, item: &T) -> bool {
        let indices = self.hashes(item);

        let in_primary = indices.iter().all(|&idx| {
            let word = idx / 64;
            let bit = idx % 64;
            (self.primary[word] & (1u64 << bit)) != 0
        });

        if in_primary {
            return true;
        }

        indices.iter().all(|&idx| {
            let word = idx / 64;
            let bit = idx % 64;
            (self.secondary[word] & (1u64 << bit)) != 0
        })
    }

    /// Inserts an item into the primary bloom filter.
    pub fn insert<T: Hash + ?Sized>(&mut self, item: &T) {
        let indices = self.hashes(item);
        for idx in indices {
            let word = idx / 64;
            let bit = idx % 64;
            self.primary[word] |= 1u64 << bit;
        }
    }
}

/// Active probe verdict and action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeAction {
    Legitimate,
    ReplayDetected,
    MalformedProbe,
}

/// Honeytoken response generator.
pub struct HoneytokenGenerator;

impl HoneytokenGenerator {
    /// Generates an authentic HTTP 404 Not Found response mimicking standard Nginx.
    pub fn generate_nginx_404() -> &'static [u8] {
        b"HTTP/1.1 404 Not Found\r\n\
Server: nginx/1.24.0\r\n\
Date: Sat, 12 Sep 2026 12:00:00 GMT\r\n\
Content-Type: text/html\r\n\
Content-Length: 162\r\n\
Connection: close\r\n\
\r\n\
<html>\r\n\
<head><title>404 Not Found</title></head>\r\n\
<body>\r\n\
<center><h1>404 Not Found</h1></center>\r\n\
<hr><center>nginx/1.24.0</center>\r\n\
</body>\r\n\
</html>\r\n"
    }

    /// Generates a benign DNS Refused response for probing DNS scanners.
    pub fn generate_dns_refused(query_packet: &[u8]) -> Vec<u8> {
        if query_packet.len() < 12 {
            return vec![0x00, 0x00, 0x81, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        }

        let mut resp = query_packet.to_vec();
        // Set QR = 1 (response), RCODE = 5 (Refused: 0x8185)
        resp[2] = 0x81;
        resp[3] = 0x85;
        // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        resp[6] = 0;
        resp[7] = 0;
        resp[8] = 0;
        resp[9] = 0;
        resp[10] = 0;
        resp[11] = 0;
        resp
    }
}

/// Active probe defense controller.
pub struct ActiveProbeDetector {
    bloom: RollingBloomFilter,
}

impl ActiveProbeDetector {
    pub fn new() -> Self {
        Self {
            bloom: RollingBloomFilter::new(16384, 4, Duration::from_secs(300)),
        }
    }

    /// Evaluates an incoming packet payload for active probing or replay.
    pub fn inspect_payload(&mut self, payload: &[u8]) -> ProbeAction {
        self.bloom.maybe_rotate(Instant::now());

        if payload.is_empty() {
            return ProbeAction::MalformedProbe;
        }

        if self.bloom.contains(payload) {
            ProbeAction::ReplayDetected
        } else {
            self.bloom.insert(payload);
            ProbeAction::Legitimate
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_insert_and_contains() {
        let mut bloom = RollingBloomFilter::new(1024, 3, Duration::from_secs(60));
        let item1 = b"handshake_nonce_alpha";
        let item2 = b"handshake_nonce_beta";

        assert!(!bloom.contains(item1));
        bloom.insert(item1);
        assert!(bloom.contains(item1));
        assert!(!bloom.contains(item2));
    }

    #[test]
    fn test_active_probe_detector_replay() {
        let mut detector = ActiveProbeDetector::new();
        let probe = b"\x16\x03\x01\x00\x45\x01ClientHelloReplay";

        assert_eq!(detector.inspect_payload(probe), ProbeAction::Legitimate);
        // Second identical packet is flagged as a replay probe!
        assert_eq!(detector.inspect_payload(probe), ProbeAction::ReplayDetected);
    }

    #[test]
    fn test_honeytoken_generation() {
        let nginx_404 = HoneytokenGenerator::generate_nginx_404();
        assert!(nginx_404.starts_with(b"HTTP/1.1 404 Not Found"));

        let fake_query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let refused = HoneytokenGenerator::generate_dns_refused(&fake_query);
        assert_eq!(refused[0], 0x12);
        assert_eq!(refused[1], 0x34);
        assert_eq!(refused[2], 0x81);
        assert_eq!(refused[3], 0x85); // REFUSED
    }
}
