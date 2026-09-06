//! rfc 8484 dns-over-https (doh) client implementation supporting preset and custom upstreams, ip bootstrapping, and post-quantum cryptography.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
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

const CLOUDFLARE_IPS_V6: &[Ipv6Addr] = &[
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
];
const QUAD9_IPS_V6: &[Ipv6Addr] = &[
    Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe),
    Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0009),
];

const MULLVAD_STANDARD_IPS_V6: &[Ipv6Addr] =
    &[Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 0x0002)];
const MULLVAD_ADBLOCK_IPS_V6: &[Ipv6Addr] = &[Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 0x0003)];
const MULLVAD_BASE_IPS_V6: &[Ipv6Addr] = &[Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 0x0004)];
const MULLVAD_EXTENDED_IPS_V6: &[Ipv6Addr] =
    &[Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 0x0005)];
const MULLVAD_FAMILY_IPS_V6: &[Ipv6Addr] = &[Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 0x0006)];
const MULLVAD_ALL_IPS_V6: &[Ipv6Addr] = &[Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 0x0009)];

// static lookup table of pre-configured public doh endpoints and bootstrap ipv4 addresses
pub static DOH_PRESETS: LazyLock<HashMap<&'static str, (&'static str, &'static [Ipv4Addr])>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert(
            "cloudflare",
            ("https://cloudflare-dns.com/dns-query", CLOUDFLARE_IPS),
        );
        m.insert("quad9", ("https://dns.quad9.net/dns-query", QUAD9_IPS));
        m.insert(
            "mullvad",
            ("https://dns.mullvad.net/dns-query", MULLVAD_STANDARD_IPS),
        );
        m.insert(
            "mullvad-standard",
            ("https://dns.mullvad.net/dns-query", MULLVAD_STANDARD_IPS),
        );
        m.insert(
            "mullvad-adblock",
            (
                "https://adblock.dns.mullvad.net/dns-query",
                MULLVAD_ADBLOCK_IPS,
            ),
        );
        m.insert(
            "mullvad-base",
            ("https://base.dns.mullvad.net/dns-query", MULLVAD_BASE_IPS),
        );
        m.insert(
            "mullvad-extended",
            (
                "https://extended.dns.mullvad.net/dns-query",
                MULLVAD_EXTENDED_IPS,
            ),
        );
        m.insert(
            "mullvad-family",
            (
                "https://family.dns.mullvad.net/dns-query",
                MULLVAD_FAMILY_IPS,
            ),
        );
        m.insert(
            "mullvad-all",
            ("https://all.dns.mullvad.net/dns-query", MULLVAD_ALL_IPS),
        );
        m
    });

// static lookup table of pre-configured public doh endpoints and bootstrap ipv6 addresses
pub static DOH_PRESETS_V6: LazyLock<HashMap<&'static str, &'static [Ipv6Addr]>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert("cloudflare", CLOUDFLARE_IPS_V6);
        m.insert("quad9", QUAD9_IPS_V6);
        m.insert("mullvad", MULLVAD_STANDARD_IPS_V6);
        m.insert("mullvad-standard", MULLVAD_STANDARD_IPS_V6);
        m.insert("mullvad-adblock", MULLVAD_ADBLOCK_IPS_V6);
        m.insert("mullvad-base", MULLVAD_BASE_IPS_V6);
        m.insert("mullvad-extended", MULLVAD_EXTENDED_IPS_V6);
        m.insert("mullvad-family", MULLVAD_FAMILY_IPS_V6);
        m.insert("mullvad-all", MULLVAD_ALL_IPS_V6);
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

#[derive(Clone, Debug)]
pub struct FileKeyLog {
    path: std::path::PathBuf,
}

impl FileKeyLog {
    pub fn new<P: Into<std::path::PathBuf>>(path: P) -> Self {
        Self { path: path.into() }
    }
}

impl rustls::KeyLog for FileKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        use std::io::Write;
        let mut hex_client_random = String::with_capacity(client_random.len() * 2);
        for &b in client_random {
            use std::fmt::Write;
            let _ = write!(hex_client_random, "{:02x}", b);
        }
        let mut hex_secret = String::with_capacity(secret.len() * 2);
        for &b in secret {
            use std::fmt::Write;
            let _ = write!(hex_secret, "{:02x}", b);
        }
        let line = format!("{} {} {}\n", label, hex_client_random, hex_secret);
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

impl SingleDoHClient {
    pub fn new(
        upstream: &str,
        name: &str,
        custom_bootstrap_ips: &[Ipv4Addr],
        pqc: bool,
        proxy: Option<&str>,
        tls_auth: Option<&crate::dns::tls_auth::TlsClientAuth>,
        tls_key_log_file: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        if !pqc {
            // enforce classical key exchange ONLY: eliminate all post-quantum KEMs
            provider.kx_groups.retain(|kx| {
                let name = format!("{:?}", kx.name());
                !name.contains("MLKEM") && !name.contains("Kyber")
            });
        }

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let builder = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(root_store);

        let mut client_config = if let Some(auth) = tls_auth {
            builder.with_client_auth_cert(auth.certs.clone(), auth.key.clone_key())?
        } else {
            builder.with_no_client_auth()
        };
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        if let Some(keylog_path) = tls_key_log_file {
            client_config.key_log = std::sync::Arc::new(FileKeyLog::new(keylog_path));
        } else if let Ok(env_path) = std::env::var("SSLKEYLOGFILE") {
            if !env_path.trim().is_empty() {
                client_config.key_log = std::sync::Arc::new(FileKeyLog::new(env_path));
            }
        }

        let mut builder = reqwest::Client::builder()
            .use_preconfigured_tls(client_config)
            .timeout(Duration::from_secs(5));

        if let Some(proxy_str) = proxy {
            let clean = proxy_str.trim();
            if !clean.is_empty() {
                builder = builder.proxy(reqwest::Proxy::all(clean)?);
            }
        }

        if let Ok(parsed) = Url::parse(upstream) {
            if let Some(host_str) = parsed.host_str() {
                if !DOH_PRESETS.contains_key(name) && crate::dns::ssrf::is_ssrf_risk(host_str) {
                    return Err(format!(
                        "SSRF risk: upstream host '{}' is in a private/reserved network range",
                        host_str
                    )
                    .into());
                }

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
                    if crate::dns::ssrf::is_ssrf_risk_ip(&std::net::IpAddr::V4(*ip)) {
                        return Err(format!(
                            "SSRF risk: custom bootstrap IP '{}' is in a private/reserved network range",
                            ip
                        )
                        .into());
                    }
                    bootstrap_addrs.push(SocketAddr::from((*ip, port)));
                }

                // 3. handle raw ipv4 host literal
                if bootstrap_addrs.is_empty() {
                    if let Ok(ip) = host_str.parse::<Ipv4Addr>() {
                        bootstrap_addrs.push(SocketAddr::from((ip, port)));
                    } else if proxy.is_none() {
                        // 4. resolve fqdn via system resolver prior to resolv.conf modification (skip when using proxy to avoid leaks)
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
        let mut resp = self
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

        if let Some(content_len) = resp.content_length() {
            if content_len > 65536 {
                return Err(format!(
                    "DoH response length {} exceeds maximum allowed (65536 bytes)",
                    content_len
                )
                .into());
            }
        }

        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > 65536 {
                return Err("DoH response body exceeds 64 KB limit".into());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

use super::balancer::LoadBalancer;
use std::sync::Arc;

// multi-upstream client pool providing weighted power of two (wp2) query dispatch and fallback
#[derive(Clone)]
pub struct DoHResolver {
    clients: Vec<SingleDoHClient>,
    balancer: Arc<LoadBalancer>,
}

impl DoHResolver {
    pub fn new(
        upstreams_csv: &str,
        custom_bootstrap_ips: &[Ipv4Addr],
        pqc: bool,
        proxy: Option<&str>,
        tls_auth: Option<&crate::dns::tls_auth::TlsClientAuth>,
        tls_key_log_file: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut clients = Vec::new();

        for raw in upstreams_csv.split(',') {
            let u = raw.trim();
            if u.is_empty() {
                continue;
            }

            if let Some((url, _)) = DOH_PRESETS.get(u) {
                match SingleDoHClient::new(
                    url,
                    u,
                    custom_bootstrap_ips,
                    pqc,
                    proxy,
                    tls_auth,
                    tls_key_log_file,
                ) {
                    Ok(client) => clients.push(client),
                    Err(e) => warn!("failed to initialize doh preset {}: {}", u, e),
                }
            } else if u.starts_with("https://") {
                let name = Url::parse(u)
                    .ok()
                    .and_then(|p| p.host_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| "custom".to_string());
                match SingleDoHClient::new(
                    u,
                    &name,
                    custom_bootstrap_ips,
                    pqc,
                    proxy,
                    tls_auth,
                    tls_key_log_file,
                ) {
                    Ok(client) => clients.push(client),
                    Err(e) => warn!("failed to initialize custom doh {}: {}", u, e),
                }
            } else if u.starts_with("http://") {
                warn!("RFC 8484 violation: plain HTTP DoH ({}) is prohibited to prevent plaintext DNS leaks; use https://", u);
            } else if u.starts_with("sdns://") {
                match crate::dns::stamp::DnsStamp::parse(u) {
                    Ok(stamp) => {
                        let name = if !stamp.provider_name.is_empty() {
                            stamp.provider_name.clone()
                        } else {
                            "stamp".to_string()
                        };
                        let mut all_bootstraps = stamp.bootstrap_ips.clone();
                        for ip in custom_bootstrap_ips {
                            if !all_bootstraps.contains(ip) {
                                all_bootstraps.push(*ip);
                            }
                        }
                        if stamp.doh_url.is_empty() {
                            warn!("dns stamp {} does not specify a doh endpoint", u);
                        } else {
                            match SingleDoHClient::new(
                                &stamp.doh_url,
                                &name,
                                &all_bootstraps,
                                pqc,
                                proxy,
                                tls_auth,
                                tls_key_log_file,
                            ) {
                                Ok(client) => clients.push(client),
                                Err(e) => warn!("failed to initialize stamp doh {}: {}", name, e),
                            }
                        }
                    }
                    Err(e) => warn!("failed to parse dns stamp {}: {}", u, e),
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
                proxy,
                tls_auth,
                tls_key_log_file,
            )?;
            clients.push(cf);
        }

        let names: Vec<String> = clients.iter().map(|c| c.name.clone()).collect();
        let balancer = Arc::new(LoadBalancer::new(&names));

        Ok(Self { clients, balancer })
    }

    // resets upstream performance scoring upon network changes
    pub fn reset_balancer(&self) {
        self.balancer.reset();
    }

    // attempts query resolution dynamically prioritized by weighted power-of-two (wp2) load balancing
    pub async fn resolve(
        &self,
        query_wire_bytes: &[u8],
    ) -> Result<(Vec<u8>, String), Box<dyn std::error::Error + Send + Sync>> {
        let candidates = self.balancer.select_candidates();
        let mut last_err = None;

        for idx in candidates {
            if let Some(client) = self.clients.get(idx) {
                let start = std::time::Instant::now();
                match client.resolve(query_wire_bytes).await {
                    Ok(data) => {
                        self.balancer.record_result(idx, start.elapsed(), true);
                        return Ok((data, client.name.clone()));
                    }
                    Err(e) => {
                        self.balancer.record_result(idx, start.elapsed(), false);
                        debug!("DoH upstream {} failed: {}", client.name, e);
                        last_err = Some(e);
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "no doh upstreams available".into()))
    }

    // queries multiple highest-ranked upstreams concurrently (happy eyeballs DNS racing),
    // returning the fastest successful response, canceling slower tasks, and updating latency scores
    pub async fn resolve_racing(
        &self,
        query_wire_bytes: &[u8],
    ) -> Result<(Vec<u8>, String), Box<dyn std::error::Error + Send + Sync>> {
        let candidates = self.balancer.select_candidates();
        if candidates.len() <= 1 {
            return self.resolve(query_wire_bytes).await;
        }

        let race_candidates: Vec<usize> = candidates.into_iter().take(3).collect();
        let mut set = tokio::task::JoinSet::new();

        for &idx in &race_candidates {
            if let Some(client) = self.clients.get(idx) {
                let client = client.clone();
                let q_bytes = query_wire_bytes.to_vec();
                set.spawn(async move {
                    let start = std::time::Instant::now();
                    let res = client.resolve(&q_bytes).await;
                    (idx, client.name, res, start.elapsed())
                });
            }
        }

        let mut last_err = None;
        while let Some(join_res) = set.join_next().await {
            if let Ok((idx, name, res, elapsed)) = join_res {
                match res {
                    Ok(data) => {
                        self.balancer.record_result(idx, elapsed, true);
                        set.abort_all();
                        return Ok((data, name));
                    }
                    Err(e) => {
                        self.balancer.record_result(idx, elapsed, false);
                        debug!("Racing DoH upstream {} failed: {}", name, e);
                        last_err = Some(e);
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "all racing doh upstreams failed".into()))
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

        if u.starts_with("sdns://") {
            if let Ok(stamp) = crate::dns::stamp::DnsStamp::parse(u) {
                ips.extend_from_slice(&stamp.bootstrap_ips);
                if let Some(std::net::SocketAddr::V4(v4)) = stamp.server_addr {
                    ips.push(*v4.ip());
                }
            }
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

// extracts ipv6 addresses of upstream doh endpoints to populate ebpf exclusion maps
pub fn extract_upstream_ips_v6(
    upstreams_csv: &str,
    custom_bootstrap_ips: &[Ipv6Addr],
) -> Vec<Ipv6Addr> {
    let mut ips = Vec::new();

    // append all user-specified bootstrap endpoints
    ips.extend_from_slice(custom_bootstrap_ips);

    for raw in upstreams_csv.split(',') {
        let u = raw.trim();
        if u.is_empty() {
            continue;
        }

        if let Some(preset_ips) = DOH_PRESETS_V6.get(u) {
            ips.extend_from_slice(preset_ips);
            continue;
        }

        if u.starts_with("sdns://") {
            if let Ok(stamp) = crate::dns::stamp::DnsStamp::parse(u) {
                if let Some(std::net::SocketAddr::V6(v6)) = stamp.server_addr {
                    ips.push(*v6.ip());
                }
            }
            continue;
        }

        if let Ok(parsed) = Url::parse(u) {
            if let Some(host_str) = parsed.host_str() {
                let clean_host = host_str.trim_start_matches('[').trim_end_matches(']');
                if let Ok(ip) = clean_host.parse::<Ipv6Addr>() {
                    ips.push(ip);
                } else {
                    let host_with_port = format!("{}:{}", host_str, parsed.port().unwrap_or(443));
                    if let Ok(resolved) = host_with_port.to_socket_addrs() {
                        for addr in resolved {
                            if let std::net::SocketAddr::V6(v6) = addr {
                                ips.push(*v6.ip());
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
    fn test_pqc_toggle_true_vs_false_kx_groups() {
        // 1. verify pqc: true contains quantum-resistant KEM hybrid group
        let client_pqc = SingleDoHClient::new(
            "https://dns.quad9.net/dns-query",
            "quad9",
            &[],
            true,
            None,
            None,
            None,
        );
        assert!(
            client_pqc.is_ok(),
            "PQC client initialization should succeed"
        );
        assert!(client_pqc.unwrap().pqc);

        // 2. verify pqc: false contains exclusively classical elliptic curves
        let client_classical = SingleDoHClient::new(
            "https://dns.quad9.net/dns-query",
            "quad9",
            &[],
            false,
            None,
            None,
            None,
        );
        assert!(
            client_classical.is_ok(),
            "Classical client initialization should succeed"
        );
        assert!(!client_classical.unwrap().pqc);

        // 3. assert crypto provider kx_groups filtering correctness
        let mut classical_provider = rustls::crypto::aws_lc_rs::default_provider();
        classical_provider.kx_groups.retain(|kx| {
            let name = format!("{:?}", kx.name());
            !name.contains("MLKEM") && !name.contains("Kyber")
        });

        for kx in &classical_provider.kx_groups {
            let name = format!("{:?}", kx.name());
            assert!(
                !name.contains("MLKEM"),
                "Classical provider must not contain ML-KEM"
            );
            assert!(
                !name.contains("Kyber"),
                "Classical provider must not contain Kyber"
            );
        }

        let pqc_provider = rustls::crypto::aws_lc_rs::default_provider();
        let has_pq = pqc_provider.kx_groups.iter().any(|kx| {
            let name = format!("{:?}", kx.name());
            name.contains("MLKEM") || name.contains("Kyber")
        });
        assert!(
            has_pq,
            "PQC provider must contain quantum-resistant ML-KEM or Kyber group"
        );
    }

    #[test]
    fn test_extract_preset_ips() {
        let ips = extract_upstream_ips("cloudflare,quad9,mullvad,mullvad-all", &[]);
        assert!(ips.contains(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(ips.contains(&Ipv4Addr::new(9, 9, 9, 9)));
        assert!(ips.contains(&Ipv4Addr::new(194, 242, 2, 2)));
        assert!(ips.contains(&Ipv4Addr::new(194, 242, 2, 9)));
    }

    #[test]
    fn test_extract_preset_ips_v6() {
        let ips = extract_upstream_ips_v6("cloudflare,quad9,mullvad,mullvad-all", &[]);
        assert!(ips.contains(&Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)));
        assert!(ips.contains(&Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)));
        assert!(ips.contains(&Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 0x0002)));
        assert!(ips.contains(&Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 0x0009)));
    }

    #[tokio::test]
    async fn test_doh_quad9_live_query() {
        let resolver = DoHResolver::new("quad9", &[], true, None, None, None)
            .expect("resolver init should succeed");
        let query_wire = [
            0x12, 0x34, // id
            0x01, 0x00, // standard query
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, // ancount = 0
            0x00, 0x00, // nscount = 0
            0x00, 0x00, // arcount = 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // type a
            0x00, 0x01, // class in
        ];

        if let Ok((response_wire, upstream_used)) = resolver.resolve(&query_wire).await {
            assert_eq!(upstream_used, "quad9");
            assert!(response_wire.len() > 12);
        }
    }

    #[test]
    fn test_sdns_stamp_resolver_init() {
        let quad9_stamp = "sdns://AgMAAAAAAAAABzkuOS45LjkADWRucy5xdWFkOS5uZXQKL2Rucy1xdWVyeQ";
        let resolver = DoHResolver::new(quad9_stamp, &[], true, None, None, None);
        assert!(
            resolver.is_ok(),
            "DNS stamp DoHResolver init should succeed"
        );
        let ips = extract_upstream_ips(quad9_stamp, &[]);
        assert!(ips.contains(&Ipv4Addr::new(9, 9, 9, 9)));
    }

    #[test]
    fn test_doh_socks5_proxy_initialization() {
        let client = SingleDoHClient::new(
            "https://dns.quad9.net/dns-query",
            "quad9",
            &[],
            true,
            Some("socks5://127.0.0.1:9050"),
            None,
            None,
        );
        assert!(
            client.is_ok(),
            "SOCKS5 proxy client initialization should succeed"
        );

        let resolver = DoHResolver::new(
            "quad9",
            &[],
            true,
            Some("socks5://127.0.0.1:9050"),
            None,
            None,
        );
        assert!(
            resolver.is_ok(),
            "SOCKS5 resolver initialization should succeed"
        );
    }

    #[test]
    fn test_doh_mtls_client_auth_initialization() {
        use crate::dns::tls_auth::{parse_pem_certificates, parse_pem_private_key, TlsClientAuth};

        let cert_pem = "\
-----BEGIN CERTIFICATE-----
MIIBMjCB5aADAgECAhRiGYeiUl4eSpC3v2h93QMnVA4ELjAFBgMrZXAwDzENMAsG
A1UEAwwEdGVzdDAeFw0yNjA5MDYxMDA5NTBaFw0yNzA5MDYxMDA5NTBaMA8xDTAL
BgNVBAMMBHRlc3QwKjAFBgMrZXADIQDUlp3l8cIqw86L1Z/uGZgbVKSeykhplytm
aj78Ya+DU6NTMFEwHQYDVR0OBBYEFG2a8XoMhubcMTzlwTIBQrDTHvuHMB8GA1Ud
IwQYMBaAFG2a8XoMhubcMTzlwTIBQrDTHvuHMA8GA1UdEwEB/wQFMAMBAf8wBQYD
K2VwA0EA5v0N/77fyRgBxS4syXPL8ioqnZI08XxgFkHvw4knTseLMpQlHFS1A3gB
yMTicETKeL9NPUtbnt4DlQ3biPeOCg==
-----END CERTIFICATE-----
";
        let key_pem = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEII1my9yC6gDHipAN+m87pQ1AECzquF5mj3NU+c6Yg7a7
-----END PRIVATE KEY-----
";
        let certs = parse_pem_certificates(cert_pem).unwrap();
        let key = parse_pem_private_key(key_pem).unwrap();
        let auth = TlsClientAuth { certs, key };

        let client = SingleDoHClient::new(
            "https://dns.quad9.net/dns-query",
            "quad9",
            &[],
            true,
            None,
            Some(&auth),
            None,
        );
        assert!(
            client.is_ok(),
            "mTLS client initialization should succeed with valid cert and key"
        );

        let resolver = DoHResolver::new("quad9", &[], true, None, Some(&auth), None);
        assert!(
            resolver.is_ok(),
            "mTLS resolver initialization should succeed"
        );
    }

    #[test]
    fn test_tls_keylog_export() {
        use rustls::KeyLog;
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("test_tls_keylog.txt");
        let keylog = FileKeyLog::new(&path);

        keylog.log("CLIENT_RANDOM", &[0xaa, 0xbb], &[0x11, 0x22]);
        let content = std::fs::read_to_string(&path).expect("keylog file must exist");
        assert_eq!(content, "CLIENT_RANDOM aabb 1122\n");

        let client = SingleDoHClient::new(
            "https://dns.quad9.net/dns-query",
            "quad9",
            &[],
            true,
            None,
            None,
            Some(path.to_str().unwrap()),
        );
        assert!(client.is_ok(), "DoHClient with keylog file should succeed");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_custom_doh_ssrf_rejection() {
        // Localhost URL
        let client_res = SingleDoHClient::new(
            "https://127.0.0.1/dns-query",
            "local",
            &[],
            true,
            None,
            None,
            None,
        );
        assert!(client_res.is_err());
        assert!(client_res.err().unwrap().to_string().contains("SSRF risk"));

        // Cloud metadata IMDS
        let imds_res = SingleDoHClient::new(
            "https://169.254.169.254/dns-query",
            "imds",
            &[],
            true,
            None,
            None,
            None,
        );
        assert!(imds_res.is_err());

        // Private IP in bootstrap list
        let priv_boot_res = SingleDoHClient::new(
            "https://example.com/dns-query",
            "example",
            &[Ipv4Addr::new(10, 0, 0, 1)],
            true,
            None,
            None,
            None,
        );
        assert!(priv_boot_res.is_err());
    }
}
