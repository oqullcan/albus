// adaptive ttl hop distance estimator and decoy ttl calculator

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[allow(dead_code)]
pub struct TtlHopEstimator {
    // target ip -> last received ttl
    hop_cache: Arc<RwLock<HashMap<IpAddr, u8>>>,
}

#[allow(dead_code)]
impl TtlHopEstimator {
    pub fn new() -> Self {
        Self {
            hop_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // estimates total hop count from received ttl (assuming initial ttl 64, 128, or 255)
    pub fn estimate_total_hops(received_ttl: u8) -> u8 {
        if received_ttl <= 64 {
            64 - received_ttl
        } else if received_ttl <= 128 {
            128 - received_ttl
        } else {
            255 - received_ttl
        }
    }

    // calculates safe decoy ttl (falls short of true server but reaches isp middlebox)
    pub fn calculate_dpi_decoy_ttl(total_hops: u8) -> u8 {
        if total_hops <= 2 {
            1
        } else if total_hops <= 6 {
            total_hops - 1
        } else {
            // standard isp dpi sits 3 to 6 hops away from residential subscriber
            (total_hops / 2).max(2)
        }
    }

    pub async fn get_decoy_ttl(&self, target_ip: IpAddr) -> u8 {
        let cache = self.hop_cache.read().await;
        if let Some(&received_ttl) = cache.get(&target_ip) {
            let total_hops = Self::estimate_total_hops(received_ttl);
            Self::calculate_dpi_decoy_ttl(total_hops)
        } else {
            // safe default for residential isp middlebox interception
            4
        }
    }

    pub async fn record_hop(&self, target_ip: IpAddr, received_ttl: u8) {
        let mut cache = self.hop_cache.write().await;
        cache.insert(target_ip, received_ttl);
    }
}
