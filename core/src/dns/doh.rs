// zero-log rfc 8484 binary wireformat doh client with connection pre-warming, cname flattening, and micro-cache

use super::cache::DnsCache;
use super::probe::DnsProbe;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct DohResolver {
    pub provider_url: String,
    pub provider_name: String,
    fallback_url: Option<String>,
    client: reqwest::Client,
    cache: DnsCache,
    probe: Arc<DnsProbe>,
}

impl DohResolver {
    pub fn new(provider: &str, custom_bootstraps: &[String]) -> Self {
        let prov_lower = provider.to_lowercase();
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_millis(2500))
            .tcp_nodelay(true)
            .use_rustls_tls();

        // map default doh hostnames directly to bootstrap ips (zero dns leak)
        builder = builder
            .resolve("dns.quad9.net", SocketAddr::from(([9, 9, 9, 9], 443)))
            .resolve("dns.quad9.net", SocketAddr::from(([149, 112, 112, 112], 443)))
            .resolve("cloudflare-dns.com", SocketAddr::from(([1, 1, 1, 1], 443)))
            .resolve("cloudflare-dns.com", SocketAddr::from(([1, 0, 0, 1], 443)))
            .resolve("dns.adguard-dns.com", SocketAddr::from(([94, 140, 14, 14], 443)))
            .resolve("dns.adguard-dns.com", SocketAddr::from(([94, 140, 15, 15], 443)));

        // extract custom doh hostname if custom url provided
        let mut custom_host = String::new();
        if provider.starts_with("http://") || provider.starts_with("https://") {
            if let Ok(parsed_url) = reqwest::Url::parse(provider) {
                if let Some(host) = parsed_url.host_str() {
                    custom_host = host.to_string();
                }
            }
        }

        // map custom bootstrap ips to custom host
        for cb in custom_bootstraps {
            for part in cb.split([',', ' ', ';']) {
                let trimmed = part.trim();

                if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
                    if !custom_host.is_empty() {
                        builder = builder.resolve(&custom_host, SocketAddr::from((ip, 443)));
                    }
                    builder = builder.resolve("dns.nextdns.io", SocketAddr::from((ip, 443)));
                    builder = builder.resolve("custom.doh", SocketAddr::from((ip, 443)));
                }
            }
        }

        let (url, fallback, name) = match prov_lower.as_str() {
            "quad9" => (
                "https://dns.quad9.net/dns-query".to_string(),
                Some("https://149.112.112.112/dns-query".to_string()),
                "Quad9".to_string(),
            ),
            "cloudflare" => (
                "https://1.1.1.1/dns-query".to_string(),
                Some("https://1.0.0.1/dns-query".to_string()),
                "Cloudflare".to_string(),
            ),
            "adguard" => (
                "https://dns.adguard-dns.com/dns-query".to_string(),
                Some("https://94.140.15.15/dns-query".to_string()),
                "AdGuard".to_string(),
            ),
            custom => {
                if custom.starts_with("http://") || custom.starts_with("https://") {
                    (custom.to_string(), None, "Custom".to_string())
                } else {
                    (
                        "https://dns.quad9.net/dns-query".to_string(),
                        Some("https://149.112.112.112/dns-query".to_string()),
                        "Quad9".to_string(),
                    )
                }
            }
        };

        let client = builder.build().unwrap_or_default();
        let probe = Arc::new(DnsProbe::new(&url, client.clone()));
        probe.clone().start_periodic_probe();

        // pre-warm connection pool immediately in background for zero first-load latency
        let warm_client = client.clone();
        let warm_url = url.clone();
        tokio::spawn(async move {
            let dummy_query = vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, b'a', 0x00, 0x00, 0x01, 0x00, 0x01,
            ];
            let _ = warm_client
                .post(&warm_url)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(dummy_query)
                .send()
                .await;
        });

        Self {
            provider_url: url,
            provider_name: name,
            fallback_url: fallback,
            client,
            cache: DnsCache::new(),
            probe,
        }
    }

    // pre-warms connection pool and refreshes tcp sessions on link change
    pub async fn warmup(&self) {
        let dummy_query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, b'a', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let _ = self.client
            .post(&self.provider_url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(dummy_query)
            .send()
            .await;
    }

    // gets current measured latency in milliseconds
    pub fn get_latency_ms(&self) -> u64 {
        self.probe.last_latency_ms.load(Ordering::Relaxed)
    }

    // proxies raw rfc 8484 binary dns query with micro-cache and failover
    pub async fn query_wireformat(&self, query_packet: &[u8]) -> Option<Vec<u8>> {
        // 1. check bounded in-memory micro-cache (0.02ms instant lookup)
        if let Some(cached) = self.cache.get(query_packet).await {
            return Some(cached);
        }

        // 2. primary upstream doh query
        if let Ok(resp) = self
            .client
            .post(&self.provider_url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(query_packet.to_vec())
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(bytes) = resp.bytes().await {
                    let resp_vec = bytes.to_vec();
                    self.cache.insert(query_packet, &resp_vec).await;
                    return Some(resp_vec);
                }
            }
        }

        // 3. same-provider fallback query if primary timed out
        if let Some(ref fb_url) = self.fallback_url {
            if let Ok(resp) = self
                .client
                .post(fb_url)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(query_packet.to_vec())
                .send()
                .await
            {
                if resp.status().is_success() {
                    if let Ok(bytes) = resp.bytes().await {
                        let resp_vec = bytes.to_vec();
                        self.cache.insert(query_packet, &resp_vec).await;
                        return Some(resp_vec);
                    }
                }
            }
        }

        None
    }

    // resolves domain name to ip address with cname flattening
    pub async fn resolve(&self, domain: &str) -> Option<IpAddr> {
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Some(ip);
        }

        let mut query = vec![
            0x12, 0x34,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        for label in domain.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        if let Some(resp) = self.query_wireformat(&query).await {
            if let Some(ip) = Self::extract_ip_from_response(&resp) {
                return Some(ip);
            }
        }

        None
    }

    // flattens cname chains and extracts direct A or AAAA ip address
    fn extract_ip_from_response(resp: &[u8]) -> Option<IpAddr> {
        if resp.len() < 12 {
            return None;
        }

        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        if ancount == 0 {
            return None;
        }

        let mut pos = 12;
        while pos < resp.len() && resp[pos] != 0 {
            if (resp[pos] & 0xc0) == 0xc0 {
                pos += 2;
                break;
            }
            pos += 1 + (resp[pos] as usize);
        }
        if pos < resp.len() && resp[pos] == 0 {
            pos += 1;
        }
        pos += 4; // qtype + qclass

        let mut fallback_v6 = None;

        for _ in 0..ancount {
            if pos >= resp.len() {
                break;
            }

            if (resp[pos] & 0xc0) == 0xc0 {
                pos += 2;
            } else {
                while pos < resp.len() && resp[pos] != 0 {
                    pos += 1 + (resp[pos] as usize);
                }
                pos += 1;
            }

            if pos + 10 > resp.len() {
                break;
            }

            let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
            let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
            pos += 10;

            // 1. type A (IPv4) - prioritize direct A record
            if rtype == 1 && rdlen == 4 && pos + 4 <= resp.len() {
                return Some(IpAddr::V4(Ipv4Addr::new(
                    resp[pos],
                    resp[pos + 1],
                    resp[pos + 2],
                    resp[pos + 3],
                )));
            }
            // 2. type AAAA (IPv6)
            else if rtype == 28 && rdlen == 16 && pos + 16 <= resp.len() {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&resp[pos..pos + 16]);
                fallback_v6 = Some(IpAddr::V6(Ipv6Addr::from(octets)));
            }

            // cname (rtype == 5) is naturally skipped to evaluate next flattened answer record
            pos += rdlen;
        }

        fallback_v6
    }
}
