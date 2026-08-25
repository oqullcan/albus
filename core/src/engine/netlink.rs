// async network interface and route auto-sync monitor

use crate::dns::DohResolver;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

pub struct RouteWatcher;

impl RouteWatcher {
    // reads the current primary default gateway interface from /proc/net/route
    fn get_default_interface() -> Option<String> {
        let content = fs::read_to_string("/proc/net/route").ok()?;
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 && fields[1] == "00000000" {
                return Some(fields[0].to_string());
            }
        }
        None
    }

    // continuously monitors default gateway interface and refreshes doh connection pools on link changes
    pub async fn start(doh: Arc<DohResolver>) {
        let mut current_iface = Self::get_default_interface();

        loop {
            tokio::time::sleep(Duration::from_millis(2500)).await;

            let new_iface = Self::get_default_interface();
            if new_iface.is_some() && new_iface != current_iface {
                current_iface = new_iface.clone();
                // link interface switched: trigger resolver warmup
                let doh_clone = Arc::clone(&doh);
                tokio::spawn(async move {
                    doh_clone.warmup().await;
                });
            }
        }
    }
}
