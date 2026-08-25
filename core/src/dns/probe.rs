// asynchronous latency probe for upstream doh resolvers

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct DnsProbe {
    provider_url: String,
    client: reqwest::Client,
    pub last_latency_ms: Arc<AtomicU64>,
}

impl DnsProbe {
    pub fn new(provider_url: &str, client: reqwest::Client) -> Self {
        Self {
            provider_url: provider_url.to_string(),
            client,
            last_latency_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    // measures round-trip time of a minimal doh query
    pub async fn measure_latency(&self) -> u64 {
        // minimal query packet for checking latency (querying root zone '.')
        let probe_query = vec![
            0xaa, 0xbb, // tx id
            0x01, 0x00, // standard query
            0x00, 0x01, // 1 question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,       // root domain
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
        ];

        let start = Instant::now();
        if let Ok(resp) = self
            .client
            .post(&self.provider_url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(probe_query)
            .send()
            .await
        {
            if resp.status().is_success() {
                let ms = start.elapsed().as_millis() as u64;
                self.last_latency_ms.store(ms, Ordering::Relaxed);
                return ms;
            }
        }

        0
    }

    // starts periodic latency background probe loop
    pub fn start_periodic_probe(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                self.measure_latency().await;
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        });
    }
}
