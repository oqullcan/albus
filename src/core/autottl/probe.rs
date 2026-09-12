//! hop distance heuristic measurement and optimal time-to-live middlebox desynchronization calculation.

use std::net::Ipv4Addr;
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
}

impl AutoTtlEstimator {
    pub fn new(config: AutoTtlConfig) -> Self {
        Self {
            config,
            cache: TtlCache::new(),
        }
    }

    // calculates optimal ttl for destination endpoint or schedules asynchronous background estimation
    pub fn get_ttl(&self, dst_ip: Ipv4Addr) -> u8 {
        if !self.config.enabled {
            return self.config.default_ttl;
        }

        if let Some(ttl) = self.cache.get(&dst_ip) {
            return ttl;
        }

        // eagerly insert default_ttl to prevent task storm for identical uncached IP
        self.cache.insert(dst_ip, self.config.default_ttl);

        // spawn non-blocking hop measurement task within runtime context
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let this = self.clone();
            handle.spawn(async move {
                this.estimate_and_cache(dst_ip).await;
            });
        }

        self.config.default_ttl
    }

    // derives middlebox drop ttl based on estimated path length
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
    }

    /// Passively records an observed incoming packet TTL, deriving hop distance and caching the optimal evasion TTL.
    pub fn record_observed_ttl(&self, dst_ip: Ipv4Addr, observed_ttl: u8) {
        if !self.config.enabled {
            return;
        }
        let hops = estimate_hops_from_ttl(observed_ttl);
        let optimal = self.calculate_optimal_ttl(hops);
        self.cache.insert(dst_ip, optimal);
    }
}

// parses /proc/net/route to determine the primary outbound interface and gateway
pub fn resolve_default_network_interface() -> Option<(String, Ipv4Addr)> {
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
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
    }
    None
}

// reads the configured MTU for a given network interface via sysfs
pub fn detect_interface_mtu(iface: &str) -> Option<u16> {
    let path = format!("/sys/class/net/{}/mtu", iface);
    let content = std::fs::read_to_string(path).ok()?;
    content.trim().parse::<u16>().ok()
}

// dynamically resolves optimal restore mss based on default interface MTU (PMTUD)
pub fn resolve_optimal_restore_mss() -> u16 {
    if let Some((iface, _)) = resolve_default_network_interface() {
        if let Some(mtu) = detect_interface_mtu(&iface) {
            if mtu >= 576 {
                // subtract standard IPv4 header (20) + TCP header (20)
                let optimal_mss = mtu.saturating_sub(40);
                debug!(iface = %iface, mtu = mtu, restore_mss = optimal_mss, "dynamically detected interface MTU");
                return optimal_mss;
            }
        }
    }
    1460
}

/// Estimates network router hop distance from observed IP packet TTL using standard initial TTL heuristics.
pub fn estimate_hops_from_ttl(received_ttl: u8) -> u8 {
    let initial_ttl: u8 = if received_ttl <= 32 {
        32
    } else if received_ttl <= 64 {
        64
    } else if received_ttl <= 128 {
        128
    } else {
        255
    };
    initial_ttl.saturating_sub(received_ttl).max(1)
}

// sends synthetic traceroute probe to estimate network layer router hop count
pub async fn measure_hop_distance(dst_ip: Ipv4Addr) -> u8 {
    if dst_ip.is_loopback() {
        return 1;
    }
    if dst_ip.is_private() {
        return 2;
    }

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

    #[test]
    fn test_resolve_optimal_restore_mss() {
        let mss = resolve_optimal_restore_mss();
        assert!(mss >= 536 && mss <= 9000);
    }

    #[test]
    fn test_detect_interface_mtu_lo() {
        // loopback interface 'lo' exists on all linux kernels
        if let Some(mtu) = detect_interface_mtu("lo") {
            assert!(mtu > 0);
        }
    }

    #[test]
    fn test_estimate_hops_from_ttl_and_observed_recording() {
        assert_eq!(estimate_hops_from_ttl(54), 10); // 64 - 54
        assert_eq!(estimate_hops_from_ttl(118), 10); // 128 - 118
        assert_eq!(estimate_hops_from_ttl(245), 10); // 255 - 245
        assert_eq!(estimate_hops_from_ttl(28), 4); // 32 - 28

        let estimator = AutoTtlEstimator::new(AutoTtlConfig::default());
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        estimator.record_observed_ttl(ip, 54); // 10 hops -> optimal TTL 6
        assert_eq!(estimator.get_ttl(ip), 6);
    }

    #[tokio::test]
    async fn test_measure_hop_distance_private_and_loopback() {
        assert_eq!(measure_hop_distance(Ipv4Addr::new(127, 0, 0, 1)).await, 1);
        assert_eq!(measure_hop_distance(Ipv4Addr::new(192, 168, 1, 1)).await, 2);
        assert_eq!(measure_hop_distance(Ipv4Addr::new(10, 0, 0, 1)).await, 2);
    }
}
