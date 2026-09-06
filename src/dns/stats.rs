//! thread-safe atomic telemetry and query performance metrics for the dns subsystem.
//!
//! tracks real-time counts of total queries, cache hits, blocked domains, uncloaked cnames,
//! anti-rebinding drops, network changes, and publishes periodic runtime snapshots.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DnsStatsSnapshot {
    pub total_queries: u64,
    pub cache_hits: u64,
    pub blocked_domains: u64,
    pub uncloaked_cnames: u64,
    pub rebinding_drops: u64,
    pub cloaked_responses: u64,
    pub captive_probes: u64,
    pub upstream_queries: u64,
    pub network_changes: u64,
    pub dns64_synthesized: u64,
    pub cache_hit_ratio: f64,
    #[serde(default)]
    pub queries_udp: u64,
    #[serde(default)]
    pub queries_tcp: u64,
    #[serde(default)]
    pub queries_doh: u64,
    #[serde(default)]
    pub blocked_blocklist: u64,
    #[serde(default)]
    pub blocked_schedule: u64,
    #[serde(default)]
    pub blocked_rebinding: u64,
    #[serde(default)]
    pub blocked_bogon: u64,
    #[serde(default)]
    pub blocked_undelegated: u64,
    #[serde(default)]
    pub active_queries: u64,
}

#[derive(Debug, Default)]
pub struct DnsStats {
    pub total_queries: AtomicU64,
    pub cache_hits: AtomicU64,
    pub blocked_domains: AtomicU64,
    pub uncloaked_cnames: AtomicU64,
    pub rebinding_drops: AtomicU64,
    pub cloaked_responses: AtomicU64,
    pub captive_probes: AtomicU64,
    pub upstream_queries: AtomicU64,
    pub network_changes: AtomicU64,
    pub dns64_synthesized: AtomicU64,
    pub queries_udp: AtomicU64,
    pub queries_tcp: AtomicU64,
    pub queries_doh: AtomicU64,
    pub blocked_blocklist: AtomicU64,
    pub blocked_schedule: AtomicU64,
    pub blocked_rebinding: AtomicU64,
    pub blocked_bogon: AtomicU64,
    pub blocked_undelegated: AtomicU64,
    pub active_queries: AtomicU64,
}

impl DnsStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn snapshot(&self) -> DnsStatsSnapshot {
        let total = self.total_queries.load(Ordering::Relaxed);
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let ratio = if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        DnsStatsSnapshot {
            total_queries: total,
            cache_hits: hits,
            blocked_domains: self.blocked_domains.load(Ordering::Relaxed),
            uncloaked_cnames: self.uncloaked_cnames.load(Ordering::Relaxed),
            rebinding_drops: self.rebinding_drops.load(Ordering::Relaxed),
            cloaked_responses: self.cloaked_responses.load(Ordering::Relaxed),
            captive_probes: self.captive_probes.load(Ordering::Relaxed),
            upstream_queries: self.upstream_queries.load(Ordering::Relaxed),
            network_changes: self.network_changes.load(Ordering::Relaxed),
            dns64_synthesized: self.dns64_synthesized.load(Ordering::Relaxed),
            cache_hit_ratio: ratio,
            queries_udp: self.queries_udp.load(Ordering::Relaxed),
            queries_tcp: self.queries_tcp.load(Ordering::Relaxed),
            queries_doh: self.queries_doh.load(Ordering::Relaxed),
            blocked_blocklist: self.blocked_blocklist.load(Ordering::Relaxed),
            blocked_schedule: self.blocked_schedule.load(Ordering::Relaxed),
            blocked_rebinding: self.blocked_rebinding.load(Ordering::Relaxed),
            blocked_bogon: self.blocked_bogon.load(Ordering::Relaxed),
            blocked_undelegated: self.blocked_undelegated.load(Ordering::Relaxed),
            active_queries: self.active_queries.load(Ordering::Relaxed),
        }
    }

    pub fn to_prometheus_text(&self) -> String {
        let total = self.total_queries.load(Ordering::Relaxed);
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let ratio = if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let mut out = String::with_capacity(1024);
        out.push_str("# HELP albus_dns_queries_total Total number of DNS queries received.\n");
        out.push_str("# TYPE albus_dns_queries_total counter\n");
        out.push_str(&format!(
            "albus_dns_queries_total{{protocol=\"udp\"}} {}\n",
            self.queries_udp.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "albus_dns_queries_total{{protocol=\"tcp\"}} {}\n",
            self.queries_tcp.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "albus_dns_queries_total{{protocol=\"doh\"}} {}\n",
            self.queries_doh.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP albus_dns_cache_hits_total Total number of DNS cache hits.\n");
        out.push_str("# TYPE albus_dns_cache_hits_total counter\n");
        out.push_str(&format!("albus_dns_cache_hits_total {}\n", hits));

        out.push_str("# HELP albus_dns_blocked_queries_total Total number of blocked DNS queries by category.\n");
        out.push_str("# TYPE albus_dns_blocked_queries_total counter\n");
        out.push_str(&format!(
            "albus_dns_blocked_queries_total{{reason=\"blocklist\"}} {}\n",
            self.blocked_blocklist.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "albus_dns_blocked_queries_total{{reason=\"schedule\"}} {}\n",
            self.blocked_schedule.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "albus_dns_blocked_queries_total{{reason=\"rebinding\"}} {}\n",
            self.blocked_rebinding.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "albus_dns_blocked_queries_total{{reason=\"bogon\"}} {}\n",
            self.blocked_bogon.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "albus_dns_blocked_queries_total{{reason=\"undelegated\"}} {}\n",
            self.blocked_undelegated.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP albus_dns_uncloaked_cnames_total Total uncloaked CNAME aliases detected.\n",
        );
        out.push_str("# TYPE albus_dns_uncloaked_cnames_total counter\n");
        out.push_str(&format!(
            "albus_dns_uncloaked_cnames_total {}\n",
            self.uncloaked_cnames.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP albus_dns_rebinding_drops_total Total anti-rebinding drops.\n");
        out.push_str("# TYPE albus_dns_rebinding_drops_total counter\n");
        out.push_str(&format!(
            "albus_dns_rebinding_drops_total {}\n",
            self.rebinding_drops.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP albus_dns_cloaked_responses_total Total cloaked DNS responses returned.\n",
        );
        out.push_str("# TYPE albus_dns_cloaked_responses_total counter\n");
        out.push_str(&format!(
            "albus_dns_cloaked_responses_total {}\n",
            self.cloaked_responses.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP albus_dns_captive_probes_total Total captive portal detection probes handled.\n");
        out.push_str("# TYPE albus_dns_captive_probes_total counter\n");
        out.push_str(&format!(
            "albus_dns_captive_probes_total {}\n",
            self.captive_probes.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP albus_dns_upstream_queries_total Total live DoH queries sent to upstreams.\n",
        );
        out.push_str("# TYPE albus_dns_upstream_queries_total counter\n");
        out.push_str(&format!(
            "albus_dns_upstream_queries_total {}\n",
            self.upstream_queries.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP albus_dns_network_changes_total Total network interface changes detected.\n",
        );
        out.push_str("# TYPE albus_dns_network_changes_total counter\n");
        out.push_str(&format!(
            "albus_dns_network_changes_total {}\n",
            self.network_changes.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP albus_dns_dns64_synthesized_total Total DNS64 synthetic IPv6 responses created.\n");
        out.push_str("# TYPE albus_dns_dns64_synthesized_total counter\n");
        out.push_str(&format!(
            "albus_dns_dns64_synthesized_total {}\n",
            self.dns64_synthesized.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP albus_dns_cache_hit_ratio Percentage of DNS queries served from cache.\n",
        );
        out.push_str("# TYPE albus_dns_cache_hit_ratio gauge\n");
        out.push_str(&format!("albus_dns_cache_hit_ratio {:.2}\n", ratio));

        out.push_str("# HELP albus_dns_active_queries Currently active concurrent DNS queries.\n");
        out.push_str("# TYPE albus_dns_active_queries gauge\n");
        out.push_str(&format!(
            "albus_dns_active_queries {}\n",
            self.active_queries.load(Ordering::Relaxed)
        ));

        out
    }

    // writes current stats to volatile /run runtime path for albus monitor inspection
    pub fn dump_to_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let snap = self.snapshot();
        let json = serde_json::to_string_pretty(&snap)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if let Some(parent) = path.as_ref().parent() {
            let _ = fs::create_dir_all(parent);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o755));
            }
        }

        // atomic write via temporary file
        let tmp_path = format!("{}.tmp.{}", path.as_ref().display(), std::process::id());
        fs::write(&tmp_path, json.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o644));
        }
        let res = fs::rename(&tmp_path, path);
        if res.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        res?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_stats_increment_and_snapshot() {
        let stats = DnsStats::new();
        stats.total_queries.fetch_add(10, Ordering::Relaxed);
        stats.cache_hits.fetch_add(4, Ordering::Relaxed);
        stats.blocked_domains.fetch_add(2, Ordering::Relaxed);
        stats.uncloaked_cnames.fetch_add(1, Ordering::Relaxed);

        let snap = stats.snapshot();
        assert_eq!(snap.total_queries, 10);
        assert_eq!(snap.cache_hits, 4);
        assert_eq!(snap.blocked_domains, 2);
        assert_eq!(snap.uncloaked_cnames, 1);
        assert!((snap.cache_hit_ratio - 40.0).abs() < 0.001);
    }

    #[test]
    fn test_dns_stats_zero_queries_ratio() {
        let stats = DnsStats::new();
        let snap = stats.snapshot();
        assert_eq!(snap.total_queries, 0);
        assert_eq!(snap.cache_hit_ratio, 0.0);
    }

    #[test]
    fn test_dns_stats_dump_to_file_roundtrip() {
        let stats = DnsStats::new();
        stats.total_queries.fetch_add(50, Ordering::Relaxed);
        stats.cache_hits.fetch_add(25, Ordering::Relaxed);
        stats.dns64_synthesized.fetch_add(7, Ordering::Relaxed);

        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join(format!("albus_test_stats_{}.json", std::process::id()));

        let res = stats.dump_to_file(&test_file);
        assert!(res.is_ok(), "dump_to_file should succeed");

        let read_json =
            fs::read_to_string(&test_file).expect("should read back written stats file");
        let snap: DnsStatsSnapshot = serde_json::from_str(&read_json).expect("should parse json");

        assert_eq!(snap.total_queries, 50);
        assert_eq!(snap.cache_hits, 25);
        assert_eq!(snap.dns64_synthesized, 7);
        assert!((snap.cache_hit_ratio - 50.0).abs() < 0.001);

        let _ = fs::remove_file(&test_file);
    }

    #[test]
    fn test_dns_stats_prometheus_format() {
        let stats = DnsStats::new();
        stats.total_queries.fetch_add(10, Ordering::Relaxed);
        stats.queries_udp.fetch_add(8, Ordering::Relaxed);
        stats.queries_doh.fetch_add(2, Ordering::Relaxed);
        stats.cache_hits.fetch_add(5, Ordering::Relaxed);
        stats.blocked_blocklist.fetch_add(1, Ordering::Relaxed);
        stats.blocked_schedule.fetch_add(1, Ordering::Relaxed);

        let prom = stats.to_prometheus_text();
        assert!(prom.contains("albus_dns_queries_total{protocol=\"udp\"} 8"));
        assert!(prom.contains("albus_dns_queries_total{protocol=\"doh\"} 2"));
        assert!(prom.contains("albus_dns_cache_hits_total 5"));
        assert!(prom.contains("albus_dns_blocked_queries_total{reason=\"blocklist\"} 1"));
        assert!(prom.contains("albus_dns_blocked_queries_total{reason=\"schedule\"} 1"));
        assert!(prom.contains("albus_dns_cache_hit_ratio 50.00"));
    }
}
