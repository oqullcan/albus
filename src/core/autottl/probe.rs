//! Hop-distance TTL selection for middlebox desynchronization.
//!
//! CONTRACT (honest by design — see M1 remediation + FP-13):
//! There is deliberately no traceroute/ICMP machinery here: every new
//! destination would otherwise receive unsolicited probe traffic
//! (fingerprintable noise), and a raw ICMP listener would widen the
//! daemon's attack surface for a heuristic gain.
//! Instead the effective TTL is derived from operator configuration:
//! auto mode clamps `default_ttl` into `[min_ttl, max_ttl]`; manual mode
//! (`enabled = false`) honors `default_ttl` exactly.
//! A bounded background task (one in-flight estimation per destination,
//! capped at 512, Drop-guarded, poison-tolerant locks) may refine the
//! value through `calculate_optimal_ttl`, but `measure_hop_distance`
//! performs no real measurement today — it sends a single fire-and-forget
//! UDP packet to the traceroute port and returns a conservative constant
//! (no listener exists to read any reply). The synchronous `get_ttl` path
//! therefore stays deterministic per configuration: cache hit, else the
//! clamped default. A true TTL-sweep measurement would need raw ICMP
//! sockets and is explicitly out of scope here.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tracing::debug;

use super::cache::TtlCache;

#[derive(Debug, Clone)]
pub struct AutoTtlConfig {
    pub enabled: bool,
    pub default_ttl: u8,
    pub min_ttl: u8,
    pub max_ttl: u8,
}

impl Default for AutoTtlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_ttl: 8,
            min_ttl: 3,
            max_ttl: 12,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AutoTtlEstimator {
    config: AutoTtlConfig,
    cache: TtlCache,
    // FP-13: in-flight destinations so one miss spawns exactly one task.
    inflight: Arc<Mutex<HashSet<Ipv4Addr>>>,
}

impl AutoTtlEstimator {
    pub fn new(config: AutoTtlConfig) -> Self {
        Self {
            config,
            cache: TtlCache::new(),
            inflight: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    // TTL contract: deterministic per configuration on the sync path.
    // Auto mode clamps the default into the safe bounds; manual mode honors
    // the operator's exact value. A cache hit (background estimation) wins;
    // otherwise a bounded estimation task is spawned when a tokio runtime
    // is present (never in unit tests) and the clamped default is returned.
    pub fn get_ttl(&self, dst_ip: Ipv4Addr) -> u8 {
        if !self.config.enabled {
            return self.config.default_ttl;
        }

        if let Some(ttl) = self.cache.get(&dst_ip) {
            return ttl;
        }

        // spawn non-blocking hop measurement task within runtime context.
        // FP-13 follow-ups: dedup via the in-flight set (capped — no task
        // storms on fan-out), poison-tolerant locks (fail open to default,
        // never silently stuck).
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            // cap the in-flight set: fan-out beyond this falls back to
            // default instead of queueing unbounded tasks.
            const MAX_INFLIGHT: usize = 512;
            let mut set = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            let fresh = set.len() < MAX_INFLIGHT && set.insert(dst_ip);
            drop(set);
            if fresh {
                let this = self.clone();
                handle.spawn(async move {
                    // scope guard: the entry is always released, even on
                    // panic/cancellation, so one bad task cannot suppress
                    // an IP's estimation for daemon lifetime.
                    struct Release {
                        owner: AutoTtlEstimator,
                        ip: Ipv4Addr,
                    }
                    impl Drop for Release {
                        fn drop(&mut self) {
                            self.owner
                                .inflight
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&self.ip);
                        }
                    }
                    let _release = Release {
                        owner: this.clone(),
                        ip: dst_ip,
                    };
                    this.estimate_and_cache(dst_ip).await;
                });
            }
        }

        // Synchronous fallback stays clamped (T7 contract): the estimator
        // is destination-independent until a background task refines it.
        self.config
            .default_ttl
            .clamp(self.config.min_ttl, self.config.max_ttl)
    }

    // Branch-table mapping consulted by the background estimator (see module
    // docs): honest heuristic, pinned by branch-table tests.
    pub fn calculate_optimal_ttl(&self, total_hops: u8) -> u8 {
        if total_hops <= 3 {
            self.config.min_ttl
        } else if total_hops <= 6 {
            (total_hops.saturating_sub(2)).clamp(self.config.min_ttl, self.config.max_ttl)
        } else if total_hops <= 12 {
            ((total_hops / 2) + 1).clamp(self.config.min_ttl, self.config.max_ttl)
        } else {
            self.config
                .default_ttl
                .clamp(self.config.min_ttl, self.config.max_ttl)
        }
    }

    async fn estimate_and_cache(&self, dst_ip: Ipv4Addr) {
        let estimated_hops = measure_hop_distance(dst_ip).await;
        let optimal_ttl = self.calculate_optimal_ttl(estimated_hops);
        debug!(ip = %dst_ip, total_hops = estimated_hops, optimal_ttl = optimal_ttl, "Auto-TTL estimated");
        self.cache.insert(dst_ip, optimal_ttl);
        self.inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&dst_ip);
    }
}

// parses /proc/net/route to determine the primary outbound interface and gateway
pub fn resolve_default_network_interface() -> Option<(String, Ipv4Addr)> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_route_table(&content)
}

// pure route-table parser: first 00000000-destination row wins; hex gateway
// is little-endian on the wire (/proc/net/route), hence to_be for the octet
// order so Ipv4Addr::from (network-order u32) yields the right octets
// on little-endian hosts (all supported targets).
pub fn parse_route_table(content: &str) -> Option<(String, Ipv4Addr)> {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 {
            let iface = fields[0];
            let dest_hex = fields[1];
            let gw_hex = fields[2];

            // destination 00000000 signifies default gateway route (0.0.0.0/0)
            if dest_hex == "00000000" {
                if let Ok(gw_val) = u32::from_str_radix(gw_hex, 16) {
                    let gw_ip = Ipv4Addr::from(gw_val.to_be());
                    return Some((iface.to_string(), gw_ip));
                }
            }
        }
    }
    None
}

// sends synthetic traceroute probe to estimate network layer router hop count.
// FP-13 honesty note: no ICMP listener exists, so the reply cannot be read and
// this returns a conservative constant. The estimator pipeline (runtime spawn,
// dedup, expiring cache) around it is real; a true TTL-sweep measurement would
// need raw ICMP sockets and is explicitly out of scope here.
pub async fn measure_hop_distance(dst_ip: Ipv4Addr) -> u8 {
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return 12,
    };

    let target = format!("{}:33434", dst_ip);
    let probe_payload = [0u8; 24];

    let _ = socket.send_to(&probe_payload, &target).await;
    12
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimal_ttl_calculation() {
        let estimator = AutoTtlEstimator::new(AutoTtlConfig::default());

        assert_eq!(estimator.calculate_optimal_ttl(4), 3);
        assert_eq!(estimator.calculate_optimal_ttl(10), 6);
        assert_eq!(estimator.calculate_optimal_ttl(18), 8);
    }

    #[test]
    fn test_autottl_cached_retrieval() {
        // sync contract: first call already returns the default — with no
        // tokio runtime in unit tests nothing spawns, nothing to "warm up"
        let config = AutoTtlConfig {
            enabled: true,
            default_ttl: 8,
            min_ttl: 3,
            max_ttl: 12,
        };
        let estimator = AutoTtlEstimator::new(config);
        let ip = Ipv4Addr::new(1, 1, 1, 1);

        let ttl1 = estimator.get_ttl(ip);
        assert_eq!(ttl1, 8);
    }

    #[test]
    fn test_static_contract_pins_no_dynamics() {
        // T7/M1 regression: the sync estimator path must be
        // destination-independent (background refinement, if any, only ever
        // narrows through the clamped branch table).
        let estimator = AutoTtlEstimator::new(AutoTtlConfig::default());
        let a = Ipv4Addr::new(1, 1, 1, 1);
        let b = Ipv4Addr::new(203, 0, 113, 7);
        let c = Ipv4Addr::new(192, 0, 2, 99);
        assert_eq!(estimator.get_ttl(a), 8);
        assert_eq!(estimator.get_ttl(b), 8);
        assert_eq!(estimator.get_ttl(c), 8);
        // repeated calls are stable (no background mutation)
        assert_eq!(estimator.get_ttl(a), estimator.get_ttl(a));
    }

    #[test]
    fn test_static_contract_clamp_and_manual() {
        // auto mode clamps an out-of-range default into [min, max] ...
        let clamped = AutoTtlEstimator::new(AutoTtlConfig {
            enabled: true,
            default_ttl: 200,
            min_ttl: 4,
            max_ttl: 10,
        });
        assert_eq!(clamped.get_ttl(Ipv4Addr::new(9, 9, 9, 9)), 10);
        let clamped_lo = AutoTtlEstimator::new(AutoTtlConfig {
            enabled: true,
            default_ttl: 1,
            min_ttl: 4,
            max_ttl: 10,
        });
        assert_eq!(clamped_lo.get_ttl(Ipv4Addr::new(9, 9, 9, 9)), 4);
        // ... while manual mode honors the operator's exact value
        let manual = AutoTtlEstimator::new(AutoTtlConfig {
            enabled: false,
            default_ttl: 200,
            min_ttl: 4,
            max_ttl: 10,
        });
        assert_eq!(manual.get_ttl(Ipv4Addr::new(9, 9, 9, 9)), 200);
    }

    #[test]
    fn test_autottl_disabled_fallback() {
        let config = AutoTtlConfig {
            enabled: false,
            default_ttl: 10,
            min_ttl: 3,
            max_ttl: 12,
        };
        let estimator = AutoTtlEstimator::new(config);
        let ip = Ipv4Addr::new(8, 8, 8, 8);

        assert_eq!(estimator.get_ttl(ip), 10);
    }

    #[test]
    fn test_autottl_boundaries() {
        let config = AutoTtlConfig {
            enabled: true,
            default_ttl: 8,
            min_ttl: 4,
            max_ttl: 10,
        };
        let estimator = AutoTtlEstimator::new(config);

        assert_eq!(estimator.calculate_optimal_ttl(2), 4);
        assert_eq!(estimator.calculate_optimal_ttl(25), 8);
    }

    #[test]
    fn test_resolve_default_network_interface_execution() {
        let route = resolve_default_network_interface();
        let _ = route;
    }
}

#[cfg(test)]
mod branch_tests {
    use super::*;

    fn estimator() -> AutoTtlEstimator {
        AutoTtlEstimator::new(AutoTtlConfig {
            enabled: true,
            default_ttl: 8,
            min_ttl: 4,
            max_ttl: 10,
        })
    }

    #[test]
    fn test_calculate_optimal_ttl_full_branch_table() {
        let e = estimator();
        // <=3 -> min
        assert_eq!(e.calculate_optimal_ttl(0), 4);
        assert_eq!(e.calculate_optimal_ttl(3), 4);
        // 4..=6 -> hops-2 clamped
        assert_eq!(e.calculate_optimal_ttl(4), 4);
        assert_eq!(e.calculate_optimal_ttl(6), 4);
        // 7..=12 -> hops/2+1 clamped
        assert_eq!(e.calculate_optimal_ttl(7), 4);
        assert_eq!(e.calculate_optimal_ttl(12), 7);
        // >12 -> default clamped
        assert_eq!(e.calculate_optimal_ttl(13), 8);
        assert_eq!(e.calculate_optimal_ttl(255), 8);
    }

    #[test]
    fn test_parse_route_table_shapes() {
        let table = "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\neth0\t000101A8\t00000000\t0001\n";
        let (iface, gw) = parse_route_table(table).expect("default route parses");
        assert_eq!(iface, "eth0");
        assert_eq!(gw, Ipv4Addr::new(192, 168, 1, 1));
        // no default route
        assert!(
            parse_route_table("Iface\tDestination\tGateway\neth0\t000101A8\t00000000\n").is_none()
        );
        // bad hex skipped, short lines skipped, empty missing
        assert!(parse_route_table("Iface\neth0\t00000000\tZZZZ\n").is_none());
        assert!(parse_route_table("").is_none());
        // first default wins
        let two = "Iface\tD\tG\neth0\t00000000\t0101010A\neth1\t00000000\t0202020A\n";
        assert_eq!(parse_route_table(two).unwrap().0, "eth0");
    }
}
