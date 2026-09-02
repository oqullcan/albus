//! rfc 8484 dns-over-https (doh) client implementation supporting preset and custom upstreams, ip bootstrapping, and post-quantum cryptography.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, warn};
use url::Url;

const CLOUDFLARE_IPS: &[Ipv4Addr] = &[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)];
const QUAD9_IPS: &[Ipv4Addr] = &[Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)];

const MULLVAD_STANDARD_IPS: &[Ipv4Addr] = &[Ipv4Addr::new(194, 242, 2, 2)];
const MULLVAD_ADBLOCK_IPS: &[Ipv4Addr] = &[Ipv4Addr::new(194, 242, 2, 3)];
const MULLVAD_BASE_IPS: &[Ipv4Addr] = &[Ipv4Addr::new(194, 242, 2, 4)];
const MULLVAD_EXTENDED_IPS: &[Ipv4Addr] = &[Ipv4Addr::new(194, 242, 2, 5)];
const MULLVAD_FAMILY_IPS: &[Ipv4Addr] = &[Ipv4Addr::new(194, 242, 2, 6)];
const MULLVAD_ALL_IPS: &[Ipv4Addr] = &[Ipv4Addr::new(194, 242, 2, 9)];

// static lookup table of pre-configured public doh endpoints and bootstrap ipv4 addresses
pub static DOH_PRESETS: LazyLock<HashMap<&'static str, (&'static str, &'static [Ipv4Addr])>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("cloudflare", ("https://cloudflare-dns.com/dns-query", CLOUDFLARE_IPS));
    m.insert("quad9", ("https://dns.quad9.net/dns-query", QUAD9_IPS));
    m.insert("mullvad", ("https://dns.mullvad.net/dns-query", MULLVAD_STANDARD_IPS));
    m.insert("mullvad-standard", ("https://dns.mullvad.net/dns-query", MULLVAD_STANDARD_IPS));
    m.insert("mullvad-adblock", ("https://adblock.dns.mullvad.net/dns-query", MULLVAD_ADBLOCK_IPS));
    m.insert("mullvad-base", ("https://base.dns.mullvad.net/dns-query", MULLVAD_BASE_IPS));
    m.insert("mullvad-extended", ("https://extended.dns.mullvad.net/dns-query", MULLVAD_EXTENDED_IPS));
    m.insert("mullvad-family", ("https://family.dns.mullvad.net/dns-query", MULLVAD_FAMILY_IPS));
    m.insert("mullvad-all", ("https://all.dns.mullvad.net/dns-query", MULLVAD_ALL_IPS));
    m
});

// individual http/2 client targeting an encrypted dns endpoint
#[derive(Clone)]
pub struct SingleDoHClient {
    pub name: String,
    pub url: String,
    pub pqc: bool,
    client: reqwest::Client,
}

impl SingleDoHClient {
    pub fn new(
        upstream: &str,
        name: &str,
        custom_bootstrap_ips: &[Ipv4Addr],
        pqc: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if pqc {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }

        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(5));

        if let Ok(parsed) = Url::parse(upstream) {
            if let Some(host_str) = parsed.host_str() {
                let port = parsed.port().unwrap_or(443);
                let mut bootstrap_addrs = Vec::new();

                // 1. resolve bootstrap ips from pre-configured lookup table
                if let Some((_, ips)) = DOH_PRESETS.get(name) {
                    for ip in *ips {
                        bootstrap_addrs.push(SocketAddr::from((*ip, port)));
                    }
                }

                // 2. append user-specified custom bootstrap endpoints
                for ip in custom_bootstrap_ips {
                    bootstrap_addrs.push(SocketAddr::from((*ip, port)));
                }

                // 3. handle raw ipv4 host literal
                if bootstrap_addrs.is_empty() {
                    if let Ok(ip) = host_str.parse::<Ipv4Addr>() {
                        bootstrap_addrs.push(SocketAddr::from((ip, port)));
                    } else {
                        // 4. resolve fqdn via system resolver prior to resolv.conf modification
                        let host_with_port = format!("{}:{}", host_str, port);
                        if let Ok(resolved) = host_with_port.to_socket_addrs() {
                            for addr in resolved {
                                bootstrap_addrs.push(addr);
                            }
                        }
                    }
                }

                if !bootstrap_addrs.is_empty() {
                    builder = builder.resolve_to_addrs(host_str, &bootstrap_addrs);
                }
            }
        }

        let client = builder.build()?;
        Ok(Self {
            name: name.to_string(),
            url: upstream.to_string(),
            pqc,
            client,
        })
    }

    // transmits binary dns query via http post with application/dns-message content type
    pub async fn resolve(
        &self,
        query_wire_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let resp = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query_wire_bytes.to_vec())
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(format!("DoH server {} returned HTTP {}", self.name, resp.status()).into());
        }

        let body = resp.bytes().await?;
        Ok(body.to_vec())
    }
}

// multi-upstream client pool providing ordered query dispatch and fallback
#[derive(Clone)]
pub struct DoHResolver {
    clients: Vec<SingleDoHClient>,
}

impl DoHResolver {
    pub fn new(
        upstreams_csv: &str,
        custom_bootstrap_ips: &[Ipv4Addr],
        pqc: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut clients = Vec::new();

        for raw in upstreams_csv.split(',') {
            let u = raw.trim();
            if u.is_empty() {
                continue;
            }

            if let Some((url, _)) = DOH_PRESETS.get(u) {
                match SingleDoHClient::new(url, u, custom_bootstrap_ips, pqc) {
                    Ok(client) => clients.push(client),
                    Err(e) => warn!("failed to initialize doh preset {}: {}", u, e),
                }
            } else if u.starts_with("http://") || u.starts_with("https://") {
                let name = Url::parse(u)
                    .ok()
                    .and_then(|p| p.host_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| "custom".to_string());
                match SingleDoHClient::new(u, &name, custom_bootstrap_ips, pqc) {
                    Ok(client) => clients.push(client),
                    Err(e) => warn!("failed to initialize custom doh {}: {}", u, e),
                }
            } else {
                warn!("unknown doh preset or invalid url: {}", u);
            }
        }

        if clients.is_empty() {
            let cf = SingleDoHClient::new(
                "https://cloudflare-dns.com/dns-query",
                "cloudflare",
                custom_bootstrap_ips,
                pqc,
            )?;
            clients.push(cf);
        }

        Ok(Self { clients })
    }

    // attempts query resolution sequentially across configured upstream clients
    pub async fn resolve(
        &self,
        query_wire_bytes: &[u8],
    ) -> Result<(Vec<u8>, String), Box<dyn std::error::Error + Send + Sync>> {
        let mut last_err = None;

        for client in &self.clients {
            match client.resolve(query_wire_bytes).await {
                Ok(data) => {
                    return Ok((data, client.name.clone()));
                }
                Err(e) => {
                    debug!("DoH upstream {} failed: {}", client.name, e);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "no doh upstreams available".into()))
    }
}

// extracts ipv4 addresses of upstream doh endpoints to populate ebpf exclusion maps
pub fn extract_upstream_ips(
    upstreams_csv: &str,
    custom_bootstrap_ips: &[Ipv4Addr],
) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();

    // append all user-specified bootstrap endpoints
    ips.extend_from_slice(custom_bootstrap_ips);

    for raw in upstreams_csv.split(',') {
        let u = raw.trim();
        if u.is_empty() {
            continue;
        }

        if let Some((_, preset_ips)) = DOH_PRESETS.get(u) {
            ips.extend_from_slice(preset_ips);
            continue;
        }

        if let Ok(parsed) = Url::parse(u) {
            if let Some(host_str) = parsed.host_str() {
                if let Ok(ip) = host_str.parse::<Ipv4Addr>() {
                    ips.push(ip);
                } else {
                    let host_with_port = format!("{}:{}", host_str, parsed.port().unwrap_or(443));
                    if let Ok(resolved) = host_with_port.to_socket_addrs() {
                        for addr in resolved {
                            if let std::net::SocketAddr::V4(v4) = addr {
                                ips.push(*v4.ip());
                            }
                        }
                    }
                }
            }
        }
    }

    ips.sort();
    ips.dedup();
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_preset_ips() {
        let ips = extract_upstream_ips("cloudflare,quad9,mullvad,mullvad-all", &[]);
        assert!(ips.contains(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(ips.contains(&Ipv4Addr::new(9, 9, 9, 9)));
        assert!(ips.contains(&Ipv4Addr::new(194, 242, 2, 2)));
        assert!(ips.contains(&Ipv4Addr::new(194, 242, 2, 9)));
    }

    #[tokio::test]
    async fn test_doh_quad9_live_query() {
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let query_wire = [
            0x12, 0x34, // id
            0x01, 0x00, // standard query
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, // ancount = 0
            0x00, 0x00, // nscount = 0
            0x00, 0x00, // arcount = 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, // type a
            0x00, 0x01, // class in
        ];

        let (response_wire, upstream_used) = resolver.resolve(&query_wire).await.expect("quad9 doh should resolve");
        assert_eq!(upstream_used, "quad9");
        assert!(response_wire.len() > 12);
    }
}
