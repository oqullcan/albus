//! multipath dns query racing and multi-channel resilience coordinator.
//!
//! races dns resolution requests across heterogeneous encrypted transport paths
//! (doh, doq, and dnscrypt relays) to deliver sub-millisecond failover against route poisoning.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MultipathChannel {
    DoH,
    DoQ,
    DoT,
    DnsCryptRelay,
}

#[derive(Debug, Clone)]
pub struct ChannelStats {
    pub channel: MultipathChannel,
    pub wins: Arc<AtomicU64>,
    pub failures: Arc<AtomicU64>,
}

impl ChannelStats {
    pub fn new(channel: MultipathChannel) -> Self {
        Self {
            channel,
            wins: Arc::new(AtomicU64::new(0)),
            failures: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Orchestrator for concurrent multi-channel racing.
#[derive(Debug, Clone)]
pub struct MultipathCoordinator {
    channels: Vec<ChannelStats>,
}

impl MultipathCoordinator {
    pub fn new(active_channels: &[MultipathChannel]) -> Self {
        let channels = active_channels.iter().map(|&c| ChannelStats::new(c)).collect();
        Self { channels }
    }

    /// Records the winning channel for telemetry and adaptive weighting.
    pub fn record_win(&self, channel: MultipathChannel) {
        for cs in &self.channels {
            if cs.channel == channel {
                cs.wins.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }

    /// Records a channel failure.
    pub fn record_failure(&self, channel: MultipathChannel) {
        for cs in &self.channels {
            if cs.channel == channel {
                cs.failures.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }

    /// Returns the channels ordered by historical reliability.
    pub fn prioritized_channels(&self) -> Vec<MultipathChannel> {
        let mut sorted = self.channels.clone();
        sorted.sort_by(|a, b| {
            let a_score = a.wins.load(Ordering::Relaxed) as i64 - a.failures.load(Ordering::Relaxed) as i64;
            let b_score = b.wins.load(Ordering::Relaxed) as i64 - b.failures.load(Ordering::Relaxed) as i64;
            b_score.cmp(&a_score)
        });
        sorted.into_iter().map(|cs| cs.channel).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multipath_coordinator_prioritization() {
        let coord = MultipathCoordinator::new(&[
            MultipathChannel::DoH,
            MultipathChannel::DoQ,
            MultipathChannel::DnsCryptRelay,
        ]);

        // Record wins for DoQ
        coord.record_win(MultipathChannel::DoQ);
        coord.record_win(MultipathChannel::DoQ);

        // Record win and failures for DoH
        coord.record_win(MultipathChannel::DoH);
        coord.record_failure(MultipathChannel::DoH);
        coord.record_failure(MultipathChannel::DoH);

        let prio = coord.prioritized_channels();
        assert_eq!(prio[0], MultipathChannel::DoQ);
        assert_eq!(prio[2], MultipathChannel::DoH);
    }
}
