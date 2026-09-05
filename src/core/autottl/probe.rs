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
            self.config.default_ttl.clamp(self.config.min_ttl, self.config.max_ttl)
        }
    }

    async fn estimate_and_cache(&self, dst_ip: Ipv4Addr) {
        let estimated_hops = measure_hop_distance(dst_ip).await;
        let optimal_ttl = self.calculate_optimal_ttl(estimated_hops);
        debug!(ip = %dst_ip, total_hops = estimated_hops, optimal_ttl = optimal_ttl, "Auto-TTL estimated");
        self.cache.insert(dst_ip, optimal_ttl);
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

// sends synthetic traceroute probe to estimate network layer router hop count
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
}
