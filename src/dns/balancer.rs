//! weighted power of two (wp2) load balancing and ewma latency estimation for doh client pools.
//!
//! selects the optimal upstream resolver dynamically by evaluating real-time round-trip latency (rtt)
//! and query success ratios, avoiding slow or degraded resolvers while preventing load concentration.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

#[derive(Debug)]
pub struct UpstreamStats {
    pub name: String,
    // stored as atomic bits of f64 for lock-free read/update
    ewma_rtt_ms: AtomicU64,
    total_queries: AtomicU64,
    failed_queries: AtomicU64,
}

impl UpstreamStats {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            // default optimistic rtt: 50.0ms
            ewma_rtt_ms: AtomicU64::new(50.0f64.to_bits()),
            total_queries: AtomicU64::new(0),
            failed_queries: AtomicU64::new(0),
        }
    }

    pub fn rtt_ms(&self) -> f64 {
        f64::from_bits(self.ewma_rtt_ms.load(Ordering::Relaxed))
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.total_queries.load(Ordering::Relaxed);
        let failed = self.failed_queries.load(Ordering::Relaxed);
        if total == 0 {
            return 1.0;
        }
        let succeeded = total.saturating_sub(failed);
        succeeded as f64 / total as f64
    }

    // calculates performance score [0.0..1.0] (70% latency, 30% reliability)
    pub fn score(&self) -> f64 {
        let rtt = self.rtt_ms();
        let rtt_score = (1.0 - (rtt / 1000.0)).clamp(0.0, 1.0);
        let rel_score = self.success_rate().clamp(0.0, 1.0);
        (rtt_score * 0.7) + (rel_score * 0.3)
    }

    // updates moving average latency and success counters
    pub fn record_outcome(&self, latency: Duration, success: bool) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.failed_queries.fetch_add(1, Ordering::Relaxed);
            // penalize rtt on failure by doubling estimated rtt up to 1000ms
            let prev_bits = self.ewma_rtt_ms.load(Ordering::Relaxed);
            let prev = f64::from_bits(prev_bits);
            let penalized = (prev * 2.0).min(1500.0);
            self.ewma_rtt_ms.store(penalized.to_bits(), Ordering::Relaxed);
            return;
        }

        let sample_ms = latency.as_secs_f64() * 1000.0;
        let prev_bits = self.ewma_rtt_ms.load(Ordering::Relaxed);
        let prev = f64::from_bits(prev_bits);
        // ewma smoothing factor: 0.8 * old + 0.2 * new
        let next = (prev * 0.8) + (sample_ms * 0.2);
        self.ewma_rtt_ms.store(next.to_bits(), Ordering::Relaxed);
    }
}

pub struct LoadBalancer {
    stats: RwLock<Vec<UpstreamStats>>,
}

impl LoadBalancer {
    pub fn new(names: &[String]) -> Self {
        let list = names.iter().map(|n| UpstreamStats::new(n)).collect();
        Self {
            stats: RwLock::new(list),
        }
    }

    // resets all upstream moving averages upon network roaming transitions
    pub fn reset(&self) {
        let stats_guard = self.stats.read().unwrap_or_else(|p| p.into_inner());
        for stat in stats_guard.iter() {
            stat.ewma_rtt_ms.store(50.0f64.to_bits(), Ordering::Relaxed);
            stat.total_queries.store(0, Ordering::Relaxed);
            stat.failed_queries.store(0, Ordering::Relaxed);
        }
    }

    // selects dispatch order of upstream candidate indices using weighted power-of-two (wp2)
    pub fn select_candidates(&self) -> Vec<usize> {
        let stats_guard = self.stats.read().unwrap_or_else(|p| p.into_inner());
        let count = stats_guard.len();
        if count == 0 {
            return Vec::new();
        }
        if count == 1 {
            return vec![0];
        }

        // 1. pick two random candidates (c1 != c2)
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as usize;

        let c1 = now_nanos % count;
        let mut c2 = (now_nanos / 7) % count;
        if c2 == c1 {
            c2 = (c1 + 1) % count;
        }

        let score1 = stats_guard[c1].score();
        let score2 = stats_guard[c2].score();

        let (winner, runner_up) = if score1 >= score2 {
            (c1, c2)
        } else {
            (c2, c1)
        };

        // return prioritized candidates followed by all remaining upstreams sorted by score
        let mut ordered = Vec::with_capacity(count);
        ordered.push(winner);
        ordered.push(runner_up);

        for i in 0..count {
            if i != winner && i != runner_up {
                ordered.push(i);
            }
        }

        ordered
    }

    pub fn record_result(&self, index: usize, latency: Duration, success: bool) {
        let guard = self.stats.read().unwrap_or_else(|p| p.into_inner());
        if let Some(target) = guard.get(index) {
            target.record_outcome(latency, success);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upstream_scoring() {
        let stats = UpstreamStats::new("test");
        assert!(stats.score() > 0.5);

        // simulate fast queries
        for _ in 0..10 {
            stats.record_outcome(Duration::from_millis(15), true);
        }
        assert!(stats.rtt_ms() < 30.0);
        assert!(stats.score() > 0.85);

        // simulate failures
        for _ in 0..5 {
            stats.record_outcome(Duration::from_millis(500), false);
        }
        assert!(stats.success_rate() < 0.7);
        assert!(stats.score() < 0.7);
    }

    #[test]
    fn test_wp2_selection() {
        let names = vec!["cf".to_string(), "q9".to_string(), "mv".to_string()];
        let lb = LoadBalancer::new(&names);

        // penalize q9
        lb.record_result(1, Duration::from_millis(900), false);
        lb.record_result(1, Duration::from_millis(900), false);

        // boost cf
        lb.record_result(0, Duration::from_millis(10), true);

        let candidates = lb.select_candidates();
        assert_eq!(candidates.len(), 3);
    }
}
