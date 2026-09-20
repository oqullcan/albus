//! rfc 8484 dns-over-https (doh) client implementation supporting preset and custom upstreams, ip bootstrapping, and post-quantum cryptography.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, info, warn};
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

fn is_pq_kx_group(name: &str) -> bool {
    let u = name.to_uppercase().replace(['-', '_', ' '], "");
    u.contains("MLKEM")
        || u.contains("KYBER")
        || u.contains("XWING")
        || u.contains("X25519MLKEM")
        || u.contains("SNTRUP")
        || u.contains("FRODO")
        || u.contains("BIKE")
        || u.contains("HQC")
}

fn is_blocked_bootstrap_ip(ip: &Ipv4Addr) -> bool {
    super::ssrf::blocked_ipv4(ip)
}

// individual http/2 client targeting an encrypted dns endpoint
#[derive(Clone)]
pub struct SingleDoHClient {
    pub name: String,
    pub url: String,
    pub pqc: bool,
    client: reqwest::Client,
    server_name: String,
    bootstrap_addrs: Vec<SocketAddr>,
}

impl SingleDoHClient {
    /// Shared TLS client-config builder: classical-only when `pqc` is off,
    /// PQ-offering otherwise; optional ECH mode (forces TLS 1.3-only per RFC).
    fn tls_client_config(
        pqc: bool,
        ech: Option<rustls::client::EchMode>,
    ) -> Result<rustls::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        if !pqc {
            // enforce classical key exchange ONLY: eliminate all post-quantum KEMs
            // (case-insensitive, covers ML-KEM / MLKEM / Kyber / X-Wing variants)
            provider
                .kx_groups
                .retain(|kx| !is_pq_kx_group(&format!("{:?}", kx.name())));
        }
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = std::sync::Arc::new(provider);
        let builder = rustls::ClientConfig::builder_with_provider(provider);
        let builder = match ech {
            Some(mode) => builder.with_ech(mode)?,
            None => builder.with_safe_default_protocol_versions()?,
        };
        let mut client_config = builder
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(client_config)
    }

    pub fn new(
        upstream: &str,
        name: &str,
        custom_bootstrap_ips: &[Ipv4Addr],
        pqc: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // https-only: refuse plaintext downgrade
        if !upstream.starts_with("https://") {
            return Err(format!("DoH upstream must use https:// (got {:?})", upstream).into());
        }
        for ip in custom_bootstrap_ips {
            if is_blocked_bootstrap_ip(ip) {
                return Err(
                    format!("blocked bootstrap IP {} (private/link-local/metadata)", ip).into(),
                );
            }
        }
        let client_config = Self::tls_client_config(pqc, None)?;

        let mut builder = reqwest::Client::builder()
            .use_preconfigured_tls(client_config)
            .timeout(Duration::from_secs(3));

        // SNI + dial addresses, remembered for the post-quantum verification probe
        let mut server_name = String::new();
        let mut dial_addrs: Vec<SocketAddr> = Vec::new();

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

                // 3. handle raw ip host literals — fail closed on SSRF targets
                if bootstrap_addrs.is_empty() {
                    if let Ok(ip) = host_str.parse::<Ipv4Addr>() {
                        if super::ssrf::blocked_ipv4(&ip) {
                            return Err(format!(
                                "blocked DoH host literal {} (non-global address)",
                                ip
                            )
                            .into());
                        }
                        bootstrap_addrs.push(SocketAddr::from((ip, port)));
                    } else if let Ok(ip6) = host_str
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .parse::<Ipv6Addr>()
                    {
                        if super::ssrf::blocked_ipv6(&ip6) {
                            return Err(format!(
                                "blocked DoH host literal {} (non-global address)",
                                ip6
                            )
                            .into());
                        }
                        bootstrap_addrs.push(SocketAddr::from((ip6, port)));
                    } else {
                        // 4. resolve fqdn via system resolver prior to resolv.conf modification.
                        // Screen results: a poisoned/malicious resolver must not pin us
                        // to loopback- or metadata-range dial targets (TLS cert check
                        // remains the backstop for anything that passes the screen).
                        let host_with_port = format!("{}:{}", host_str, port);
                        if let Ok(resolved) = host_with_port.to_socket_addrs() {
                            for addr in resolved {
                                if super::ssrf::blocked_socket(&addr) {
                                    continue;
                                }
                                bootstrap_addrs.push(addr);
                            }
                        }
                    }
                }

                if !bootstrap_addrs.is_empty() {
                    builder = builder.resolve_to_addrs(host_str, &bootstrap_addrs);
                }
                server_name = host_str.to_string();
                dial_addrs = bootstrap_addrs;
            }
        }

        let client = builder.build()?;
        Ok(Self {
            name: name.to_string(),
            url: upstream.to_string(),
            pqc,
            client,
            server_name,
            bootstrap_addrs: dial_addrs,
        })
    }

    /// Applies an ECHConfigList (fetched from the upstream's HTTPS record) by
    /// rebuilding the TLS stack with ECH enabled. Returns a short mode label
    /// for logs. No GREASE theater: without a published config we stay plain
    /// (GREASE hides nothing — it only fights ossification).
    pub(crate) fn apply_ech(&mut self, ech_list: Option<Vec<u8>>) -> &'static str {
        let bytes = match ech_list {
            Some(b) if !b.is_empty() && b.len() <= 4096 => b,
            _ => return "plain-no-ech-config",
        };
        let ech_config = match rustls::client::EchConfig::new(
            bytes.into(),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        ) {
            Ok(c) => c,
            Err(_) => return "plain-invalid-ech-config",
        };
        let client_config = match Self::tls_client_config(
            self.pqc,
            Some(rustls::client::EchMode::from(ech_config)),
        ) {
            Ok(c) => c,
            Err(_) => return "plain-ech-build-failed",
        };
        let mut builder = reqwest::Client::builder()
            .use_preconfigured_tls(client_config)
            .timeout(Duration::from_secs(3));
        if !self.bootstrap_addrs.is_empty() {
            builder = builder.resolve_to_addrs(self.server_name.as_str(), &self.bootstrap_addrs);
        }
        match builder.build() {
            Ok(c) => {
                self.client = c;
                "ech-active"
            }
            Err(_) => "plain-rebuild-failed",
        }
    }

    /// Verifies the upstream really negotiates post-quantum key exchange by
    /// completing a TLS handshake that offers ONLY PQ KEM groups. Blocking
    /// call with bounded dials — run off the async runtime (background thread).
    /// Returns false when `pqc` is off, the endpoint is unknown, or no PQ-only
    /// handshake completes.
    pub fn probe_pq_support(&self, per_addr_timeout: Duration) -> bool {
        if !self.pqc || self.server_name.is_empty() || self.bootstrap_addrs.is_empty() {
            return false;
        }
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider
            .kx_groups
            .retain(|kx| is_pq_kx_group(&format!("{:?}", kx.name())));
        if provider.kx_groups.is_empty() {
            return false;
        }
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let builder =
            match rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
                .with_safe_default_protocol_versions()
            {
                Ok(b) => b,
                Err(_) => return false,
            };
        let config = std::sync::Arc::new(
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );
        let server_name = if let Ok(ip) = self.server_name.parse::<std::net::IpAddr>() {
            rustls::pki_types::ServerName::from(ip)
        } else {
            match rustls::pki_types::ServerName::try_from(self.server_name.clone()) {
                Ok(n) => n,
                Err(_) => return false,
            }
        };
        // bounded dials; first completed PQ-only handshake wins
        for addr in self.bootstrap_addrs.iter().take(2) {
            let sock = match std::net::TcpStream::connect_timeout(addr, per_addr_timeout) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = sock.set_read_timeout(Some(per_addr_timeout));
            let _ = sock.set_write_timeout(Some(per_addr_timeout));
            let mut conn = match rustls::ClientConnection::new(config.clone(), server_name.clone())
            {
                Ok(c) => c,
                Err(_) => return false,
            };
            let mut sock = sock;
            loop {
                if !conn.is_handshaking() {
                    let _ = sock.shutdown(std::net::Shutdown::Both);
                    return true;
                }
                match conn.complete_io(&mut sock) {
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
        }
        false
    }

    // transmits binary dns query via http post with application/dns-message content type
    pub async fn resolve(
        &self,
        query_wire_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // hard cap: a DNS message cannot exceed 64 KiB; anything larger from
        // a (possibly malicious custom) upstream is a flood, not DNS
        const MAX_BODY: usize = 65537;
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

        if let Some(len) = resp.content_length() {
            if len > MAX_BODY as u64 {
                return Err(format!("DoH server {} response too large", self.name).into());
            }
        }
        let mut body = Vec::new();
        let mut resp = resp;
        loop {
            match resp.chunk().await? {
                None => break,
                Some(chunk) => {
                    body.extend_from_slice(&chunk);
                    if body.len() > MAX_BODY {
                        return Err(format!("DoH server {} response too large", self.name).into());
                    }
                }
            }
        }
        Ok(body)
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
            } else if u.starts_with("https://") {
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
            return Err(
                "no valid DoH upstreams configured (refusing silent Cloudflare fallback)".into(),
            );
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

    /// Returns an upgraded copy of this pool with ECH enabled wherever the
    /// upstream publishes an ECHConfig (fetched over the plain-DoH channel
    /// first). Per-upstream outcome is logged; upstreams without configs
    /// stay plain. Consumes nothing; call before cloning into tasks.
    pub async fn with_ech_upgraded(&self, cache: &crate::dns::ech::EchConfigCache) -> Self {
        let mut upgraded = self.clone();
        for c in &mut upgraded.clients {
            if c.server_name.is_empty() {
                continue;
            }
            let fetched = match cache.get(&c.server_name) {
                Some(b) => Some(b),
                None => {
                    let f = crate::dns::ech::fetch_echconfig_list(&c.server_name, self).await;
                    if let Some(ref b) = f {
                        cache.insert(c.server_name.clone(), b.clone());
                    }
                    f
                }
            };
            match c.apply_ech(fetched) {
                "ech-active" => info!(
                    "DoH upstream {}: ECH active (SNI encrypted to cover name)",
                    c.name
                ),
                other => info!("DoH upstream {}: ECH off ({})", c.name, other),
            }
        }
        upgraded
    }

    /// Spawns a background one-shot probe that verifies each PQC-enabled
    /// upstream completes a TLS handshake offering ONLY post-quantum KEMs.
    /// Makes the "post-quantum DoH" claim measurable at runtime: one INFO
    /// line per upstream. Non-blocking; failures only warn (traffic still
    /// flows, classically if needed).
    pub fn spawn_pq_probe(&self) {
        if !self.clients.iter().any(|c| c.pqc) {
            return;
        }
        let clients = self.clients.clone();
        std::thread::spawn(move || {
            for c in &clients {
                if !c.pqc {
                    continue;
                }
                if c.probe_pq_support(Duration::from_secs(4)) {
                    info!(
                        "DoH upstream {}: post-quantum KEM handshake OK (PQ-only offer accepted)",
                        c.name
                    );
                } else {
                    warn!(
                        "DoH upstream {}: PQ-only handshake failed — TLS falls back to classical KEX despite pqc=true",
                        c.name
                    );
                }
            }
        });
    }
}

// extracts ipv4 addresses of upstream doh endpoints to populate ebpf exclusion maps
pub fn extract_upstream_ips(
    upstreams_csv: &str,
    custom_bootstrap_ips: &[Ipv4Addr],
) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();

    // append all user-specified bootstrap endpoints (minus blocked ranges)
    for ip in custom_bootstrap_ips {
        if !is_blocked_bootstrap_ip(ip) {
            ips.push(*ip);
        }
    }

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
                    if !super::ssrf::blocked_ipv4(&ip) {
                        ips.push(ip);
                    }
                } else {
                    let host_with_port = format!("{}:{}", host_str, parsed.port().unwrap_or(443));
                    if let Ok(resolved) = host_with_port.to_socket_addrs() {
                        for addr in resolved {
                            if let std::net::SocketAddr::V4(v4) = addr {
                                if !super::ssrf::blocked_ipv4(v4.ip()) {
                                    ips.push(*v4.ip());
                                }
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

    // append user-specified bootstrap endpoints (minus blocked ranges)
    for ip in custom_bootstrap_ips {
        if !super::ssrf::blocked_ipv6(ip) {
            ips.push(*ip);
        }
    }

    for raw in upstreams_csv.split(',') {
        let u = raw.trim();
        if u.is_empty() {
            continue;
        }

        if let Some(preset_ips) = DOH_PRESETS_V6.get(u) {
            ips.extend_from_slice(preset_ips);
            continue;
        }

        if let Ok(parsed) = Url::parse(u) {
            if let Some(host_str) = parsed.host_str() {
                let clean_host = host_str.trim_start_matches('[').trim_end_matches(']');
                if let Ok(ip) = clean_host.parse::<Ipv6Addr>() {
                    if !super::ssrf::blocked_ipv6(&ip) {
                        ips.push(ip);
                    }
                } else {
                    let host_with_port = format!("{}:{}", host_str, parsed.port().unwrap_or(443));
                    if let Ok(resolved) = host_with_port.to_socket_addrs() {
                        for addr in resolved {
                            if let std::net::SocketAddr::V6(v6) = addr {
                                if !super::ssrf::blocked_ipv6(v6.ip()) {
                                    ips.push(*v6.ip());
                                }
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
        let client_pqc =
            SingleDoHClient::new("https://dns.quad9.net/dns-query", "quad9", &[], true);
        assert!(
            client_pqc.is_ok(),
            "PQC client initialization should succeed"
        );
        assert!(client_pqc.unwrap().pqc);

        // 2. verify pqc: false contains exclusively classical elliptic curves
        let client_classical =
            SingleDoHClient::new("https://dns.quad9.net/dns-query", "quad9", &[], false);
        assert!(
            client_classical.is_ok(),
            "Classical client initialization should succeed"
        );
        assert!(!client_classical.unwrap().pqc);

        // 3. assert crypto provider kx_groups filtering correctness
        let mut classical_provider = rustls::crypto::aws_lc_rs::default_provider();
        classical_provider
            .kx_groups
            .retain(|kx| !is_pq_kx_group(&format!("{:?}", kx.name())));

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
    fn test_pq_probe_skipped_without_pqc_flag() {
        // probe must short-circuit (no network) when pqc is off
        let client =
            SingleDoHClient::new("https://dns.quad9.net/dns-query", "quad9", &[], false).unwrap();
        assert!(!client.probe_pq_support(Duration::from_millis(100)));
    }

    #[test]
    fn test_ssrf_custom_urls_rejected() {
        // plaintext is refused outright
        assert!(
            SingleDoHClient::new("http://127.0.0.1:1234/dns-query", "custom", &[], true).is_err()
        );
        assert!(SingleDoHClient::new(
            "http://169.254.169.254/latest/meta-data/",
            "custom",
            &[],
            true
        )
        .is_err());
        // https does not save non-global literals (new host-literal screen)
        assert!(SingleDoHClient::new("https://127.0.0.1/dns-query", "custom", &[], true).is_err());
        assert!(SingleDoHClient::new("https://[::1]/dns-query", "custom", &[], true).is_err());
        assert!(
            SingleDoHClient::new("https://169.254.169.254/dns-query", "custom", &[], true).is_err()
        );
        // sane inputs still pass
        assert!(
            SingleDoHClient::new("https://dns.quad9.net/dns-query", "quad9", &[], true).is_ok()
        );
    }

    /// Live measurement: which upstreams truly negotiate PQ KEM.
    /// Ignored by default (needs network); run with:
    /// `cargo test -- --ignored --nocapture live_probe_upstreams`
    #[test]
    #[ignore]
    fn live_probe_upstreams_print_support() {
        for (url, name) in [
            ("https://dns.quad9.net/dns-query", "quad9"),
            ("https://cloudflare-dns.com/dns-query", "cloudflare"),
            ("https://dns.mullvad.net/dns-query", "mullvad"),
        ] {
            let c = SingleDoHClient::new(url, name, &[], true).unwrap();
            println!(
                "PQ-PROBE {}: pq_only_handshake={}",
                name,
                c.probe_pq_support(Duration::from_secs(6))
            );
        }
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
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
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

        let (response_wire, upstream_used) = resolver
            .resolve(&query_wire)
            .await
            .expect("quad9 doh should resolve");
        assert_eq!(upstream_used, "quad9");
        assert!(response_wire.len() > 12);
    }
}

#[cfg(test)]
mod ssrf_matrix_tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_bootstrap_ips_blocked_matrix() {
        // every non-global family member must be refused as bootstrap
        for s in [
            "10.0.0.5",
            "172.16.9.9",
            "172.31.0.1",
            "192.168.0.1",
            "0.0.0.0",
            "169.254.10.20",
            "224.0.0.251",
        ] {
            let ip = Ipv4Addr::from_str(s).unwrap();
            assert!(
                SingleDoHClient::new("https://dns.quad9.net/dns-query", "quad9", &[ip], true)
                    .is_err(),
                "bootstrap {} must be refused",
                s
            );
        }
        // global addresses pass (construction succeeds)
        let ok = [Ipv4Addr::new(45, 90, 28, 188), Ipv4Addr::new(1, 1, 1, 1)];
        assert!(
            SingleDoHClient::new("https://dns.quad9.net/dns-query", "quad9", &ok, true).is_ok()
        );
    }

    #[test]
    fn test_extract_filters_and_dedups() {
        // blocked + duplicate + invalid entries collapse to clean globals
        let custom = [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::new(9, 9, 9, 9),
        ];
        let ips = extract_upstream_ips("quad9, quad9, not-a-url@@@, ,", &custom);
        assert!(!ips.contains(&Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            ips.iter()
                .filter(|ip| **ip == Ipv4Addr::new(9, 9, 9, 9))
                .count(),
            1
        );
        assert!(extract_upstream_ips("", &[]).is_empty());
        // v6: loopback/link-local stripped, globals kept
        let v6: Vec<Ipv6Addr> = vec!["::1", "fe80::1"]
            .iter()
            .map(|s| Ipv6Addr::from_str(s).unwrap())
            .collect();
        let out = extract_upstream_ips_v6("cloudflare", &v6);
        assert!(!out.iter().any(|ip| ip.is_loopback()));
        assert!(out.contains(&Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)));
        let _ = IpAddr::from([127, 0, 0, 1]);
    }
}
