//! Hop-distance TTL selection for middlebox desynchronization.
//!
//! CONTRACT (static model, honest by design — see M1 remediation):
//! albus does NOT perform active hop-distance probing. There is deliberately
//! no traceroute/ICMP machinery here: every new destination would otherwise
//! receive unsolicited probe traffic (fingerprintable noise), and a raw ICMP
//! listener would widen the daemon's attack surface for a heuristic gain.
//! Instead the effective TTL is derived from operator configuration:
//! auto mode clamps `default_ttl` into `[min_ttl, max_ttl]`; manual mode
//! (`enabled = false`) honors `default_ttl` exactly.
//! `calculate_optimal_ttl` below is the RESERVED mapping for a future active
//! prober (kept with its branch-table tests as specification); nothing in
//! production consults it today. If probing is ever reintroduced, the T7
//! contract tests in this file must be updated deliberately — they pin the
//! static behavior so fake "dynamics" cannot slip back in silently.

use std::net::Ipv4Addr;

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
}

impl AutoTtlEstimator {
    pub fn new(config: AutoTtlConfig) -> Self {
        Self { config }
    }

    // Static TTL contract: no measurement, no spawned tasks, no network I/O.
    // Auto mode clamps the default into the safe bounds; manual mode honors
    // the operator's exact value. Deterministic per configuration.
    pub fn get_ttl(&self, _dst_ip: Ipv4Addr) -> u8 {
        if !self.config.enabled {
            return self.config.default_ttl;
        }
        self.config
            .default_ttl
            .clamp(self.config.min_ttl, self.config.max_ttl)
    }

    // RESERVED mapping for a future active prober (see module docs): kept
    // with its branch-table tests as specification, not consulted today.
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
}

// parses /proc/net/route to determine the primary outbound interface and gateway
pub fn resolve_default_network_interface() -> Option<(String, Ipv4Addr)> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_route_table(&content)
}

// pure route-table parser: first 00000000-destination row wins; hex gateway
// is little-endian on the wire, hence to_be for the octet order.
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
        // static contract: first call already returns the default — no
        // spawned task, no network I/O, nothing to "warm up"
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
        // T7/M1 regression: the estimator must be destination-independent.
        // If genuine probing is ever reintroduced, this test must be
        // updated deliberately — it pins the static contract.
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
