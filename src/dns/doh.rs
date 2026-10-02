//! rfc 8484 dns-over-https (doh) client implementation supporting preset and custom upstreams, ip bootstrapping, and post-quantum cryptography.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
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
    let o = ip.octets();
    // loopback, unspecified, multicast, link-local, metadata, private
    if o[0] == 127 || o[0] == 0 || o[0] >= 224 {
        return true;
    }
    if o[0] == 169 && o[1] == 254 {
        return true; // link-local + cloud metadata 169.254.169.254
    }
    if o[0] == 10 {
        return true;
    }
    if o[0] == 172 && (16..32).contains(&o[1]) {
        return true;
    }
    if o[0] == 192 && o[1] == 168 {
        return true;
    }
    if o[0] == 100 && (64..128).contains(&o[1]) {
        return true; // CGNAT
    }
    false
}

/// IPv6 counterpart of `is_blocked_bootstrap_ip`.
///
/// W3-01/W3-03: the crate had no IPv6 predicate at all, so every v6 ingress
/// — a `[::1]` literal host, an `AAAA` answer, and the whole
/// `extract_upstream_ips_v6` path that feeds the eBPF exclusion maps — was
/// structurally unscreenable. Mirrors the v4 coverage: loopback, unspecified,
/// multicast, link-local, unique-local, documentation, NAT64-mapped v4 and
/// IPv4-mapped addresses (a mapped `::ffff:127.0.0.1` is loopback in v4 terms).
fn is_blocked_bootstrap_ip_v6(ip: &Ipv6Addr) -> bool {
    let s = ip.segments();

    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }

    // IPv4-mapped (::ffff:0:0/96) and NAT64-compatible (64:ff9b::/96) carry a
    // v4 address that must be judged by the v4 rules, not waved through
    // because it arrived wrapped in v6 syntax.
    if let Some(v4) = ipv4_embedded_in(ip) {
        return is_blocked_bootstrap_ip(&v4);
    }

    let (a, b) = (s[0], s[1]);
    // fe80::/10 link-local
    if (a & 0xffc0) == 0xfe80 {
        return true;
    }
    // fc00::/7 unique-local
    if (a & 0xfe00) == 0xfc00 {
        return true;
    }
    // 2001:db8::/32 documentation
    if a == 0x2001 && b == 0x0db8 {
        return true;
    }
    // 2002::/16 6to4 wraps a v4 address in the next 32 bits (segments 1..2)
    if a == 0x2002 {
        let v4 = Ipv4Addr::new(
            (s[1] >> 8) as u8,
            (s[1] & 0xff) as u8,
            (s[2] >> 8) as u8,
            (s[2] & 0xff) as u8,
        );
        return is_blocked_bootstrap_ip(&v4);
    }
    false
}

/// Extracts the v4 address a v6 address stands for, when it stands for one at
/// all. A wrapped loopback or metadata address must not be laundered into a
/// public destination just by arriving in v6 syntax.
fn ipv4_embedded_in(ip: &Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    // ::ffff:a.b.c.d  (IPv4-mapped, ::ffff:0:0/96). The prefix is the first
    // 96 bits, i.e. s[0..=5] with s[5] == 0xffff; the v4 is s[6],s[7].
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0xffff {
        return Some(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        ));
    }
    // 64:ff9b::/96 well-known NAT64 prefix
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        ));
    }
    None
}

/// The single value-level screen for a resolved DoH destination.
///
/// W3-01: `is_blocked_bootstrap_ip` was IPv4-only and was called on exactly
/// two sites, both of which only walked the operator's `custom_bootstrap_ips`
/// list. The address that actually receives every query comes from two other
/// ingresses that were never screened — an IPv4 literal host and the
/// `to_socket_addrs()` FQDN answers. So `--doh-upstream
/// https://169.254.169.254/dns-query` was accepted, and the bootstrap pin that
/// the module documents as its anti-hijack guarantee was free to point at the
/// cloud metadata service. Applying the check to one ingress of a value and
/// treating it as coverage of the value is the defect; this dispatches on the
/// address that is about to become a network destination.
fn is_blocked_bootstrap_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_bootstrap_ip(v4),
        IpAddr::V6(v6) => is_blocked_bootstrap_ip_v6(v6),
    }
}

fn socket_addr_is_blocked(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(_) | SocketAddr::V6(_) => is_blocked_bootstrap_addr(&addr.ip()),
    }
}

/// Fail-closed redirect policy for DoH upstreams.
///
/// reqwest defaults to `Policy::limit(10)`: it happily follows a chain of up
/// to ten 3xx hops and, with `https_only` unset, an `https://` upstream can
/// hand us an `http://` `Location`. For a privileged DNS client every one of
/// those hops is an attack primitive:
///   * scheme downgrade — the DNS query leaves in plaintext, defeating the
///     whole point of DoH and exposing it to an on-path observer;
///   * host change — our bootstrap address pinning is keyed on the original
///     host, so the new name is resolved by the system resolver, which by
///     then points at albus's own loopback resolver (self-loop / amplification)
///     and re-enters the untrusted resolution path the bootstrap pin exists to
///     avoid;
///   * arbitrary hop — the redirect target is never re-checked against the
///     blocked private/link-local/metadata ranges enforced on bootstrap IPs,
///     turning a compromised or hostile upstream into an SSRF gadget with
///     root-adjacent reach (169.254.169.254, loopback admin ports, ...).
///
/// RFC 8484 defines DoH at a fixed URL: a conforming endpoint answers the
/// request directly and never redirects. So we refuse every hop. `error` (not
/// reqwest's `Policy::none()`, which merely hands the 30x back as `Ok`) makes
/// the refusal fail the request at the send site with a diagnosable message;
/// `resolve`'s non-2xx check stays as defense in depth.
fn doh_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let status = attempt.status();
        let next = attempt.url().clone();
        attempt.error(format!(
            "DoH upstream redirected (HTTP {} -> {}); refusing to follow \
             redirects to avoid plaintext downgrade, bootstrap-pin bypass and \
             SSRF into private/metadata ranges",
            status, next
        ))
    })
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

/// Shared TLS client-config builder: classical-only when `pqc` is off,
/// PQ-offering otherwise; optional ECH mode (forces TLS 1.3-only per RFC).
/// Which key-exchange groups a `ClientConfig` may offer.
///
/// W3-02: `probe_pq_support` used to build its own provider inline, which made
/// this module contain two independent `ClientConfig` construction sites and
/// left the module's structural guard (a substring count of the reqwest
/// client-builder call) blind to the rustls-shaped one. Encoding the policy
/// instead of the mutation keeps one construction path.
#[derive(Clone, Copy)]
enum KxPolicy {
    /// Everything the provider offers.
    All,
    /// Classical only — every post-quantum KEM removed.
    ClassicalOnly,
    /// PQ only — every classical group removed. Used by the capability probe,
    /// which must prove the negotiated group actually was post-quantum.
    PqOnly,
}

/// The single `ClientConfig` construction site in this module.
///
/// Both the query path and the PQ capability probe go through here, so the
/// root store, the protocol-version policy and the kx-group policy cannot
/// drift apart between the client that sends DNS queries and the client whose
/// handshake result is the only runtime evidence of the tool's
/// post-quantum claim.
fn build_client_config(
    policy: KxPolicy,
    ech: Option<rustls::client::EchMode>,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    match policy {
        KxPolicy::All => {}
        KxPolicy::ClassicalOnly => {
            // enforce classical key exchange ONLY: eliminate all post-quantum KEMs
            // (case-insensitive, covers ML-KEM / MLKEM / Kyber / X-Wing variants)
            provider
                .kx_groups
                .retain(|kx| !is_pq_kx_group(&format!("{:?}", kx.name())));
        }
        KxPolicy::PqOnly => {
            provider
                .kx_groups
                .retain(|kx| is_pq_kx_group(&format!("{:?}", kx.name())));
        }
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

fn tls_client_config(
    pqc: bool,
    ech: Option<rustls::client::EchMode>,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    build_client_config(
        if pqc {
            KxPolicy::All
        } else {
            KxPolicy::ClassicalOnly
        },
        ech,
    )
}

impl SingleDoHClient {
    /// The one and only place a DoH `reqwest::Client` is constructed.
    ///
    /// Every hardening knob lives here — pinned TLS config, 3s timeout,
    /// https-only, no-redirect — so the plain and ECH rebuild paths cannot
    /// drift apart and a new client cannot accidentally ship reqwest's
    /// permissive defaults.
    fn hardened_builder(tls: rustls::ClientConfig) -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .timeout(Duration::from_secs(3))
            .https_only(true)
            // reqwest honours `HTTPS_PROXY`/`ALL_PROXY` from the environment by
            // default (auto_sys_proxy). A proxy is CONNECT-tunnelled, so
            // `resolve_to_addrs` is never consulted and the bootstrap pin
            // becomes dead config -- while the DNS query itself is handed to a
            // third party. An inherited proxy env var would silently undo the
            // anti-hijack and anti-SSRF guarantees this client exists to
            // provide, so we refuse proxies outright rather than let the
            // ambient environment decide where DNS traffic goes.
            .no_proxy()
            .redirect(doh_redirect_policy())
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
        let client_config = tls_client_config(pqc, None)?;

        let mut builder = Self::hardened_builder(client_config);

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

                // W3-01: screen the ASSEMBLED PIN, not the operator's list.
                // Every DoH query is sent to these addresses, and two of the
                // three ingresses above (a literal host, a resolver answer)
                // were never range-checked, so `--doh-upstream
                // https://127.0.0.1/dns-query` or a hostile/spoofed A record
                // aimed the resolver at loopback or cloud metadata while the
                // module logged the pin as an anti-hijack guarantee. Reject
                // rather than filter: silently dropping a blocked pin would
                // leave `bootstrap_addrs` empty or partially populated and let
                // reqwest fall back to its own resolution, re-opening the hole
                // this closes.
                if let Some(bad) = bootstrap_addrs.iter().find(|a| socket_addr_is_blocked(a)) {
                    return Err(format!(
                        "DoH bootstrap pin for {} resolves to blocked address {} \
                         (loopback/private/link-local/metadata/multicast)",
                        host_str,
                        bad.ip()
                    )
                    .into());
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
        let client_config =
            match tls_client_config(self.pqc, Some(rustls::client::EchMode::from(ech_config))) {
                Ok(c) => c,
                Err(_) => return "plain-ech-build-failed",
            };
        let mut builder = Self::hardened_builder(client_config);
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
        // W3-02: reuse the module's single ClientConfig construction site
        // instead of hand-building a third policy here. The probe performs the
        // same network egress as the query path -- it sends the upstream SNI --
        // so it must not be the one client in the module with its own idea of
        // which root store and protocol versions are acceptable.
        let config = match build_client_config(KxPolicy::PqOnly, None) {
            Ok(c) => std::sync::Arc::new(c),
            Err(_) => return false,
        };
        let server_name = if let Ok(ip) = self.server_name.parse::<std::net::IpAddr>() {
            rustls::pki_types::ServerName::from(ip)
        } else {
            match rustls::pki_types::ServerName::try_from(self.server_name.clone()) {
                Ok(n) => n,
                Err(_) => return false,
            }
        };
        // W3-02: refuse to dial any destination the query path would refuse.
        // A probe that completes a TLS handshake against an address the query
        // path rejects is still a real egress event -- a ClientHello carrying
        // the upstream SNI, to loopback or the metadata service.
        let candidates: Vec<&SocketAddr> = self
            .bootstrap_addrs
            .iter()
            .take(2)
            .filter(|a| !socket_addr_is_blocked(a))
            .collect();
        if candidates.is_empty() {
            return false;
        }
        // bounded dials; first completed PQ-only handshake wins
        for addr in candidates {
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

        if resp.status().is_redirection() {
            // Load-bearing, not a redundant belt-and-braces check. reqwest's
            // redirect layer only invokes the policy for
            // {301,302,303,307,308}; every other 3xx (300/304/305/306, and
            // any redirect status sent without a `Location`) is returned to us
            // verbatim as `Ok` without the policy ever running. This check is
            // the only thing standing between those bodies and the resolver.
            return Err(format!(
                "DoH server {} returned redirect {} (refusing to follow)",
                self.name,
                resp.status()
            )
            .into());
        }
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
                    // FP-15: validate before caching — a transient bad blob
                    // must never stick and pin the upstream to plain fallback.
                    if let Some(ref b) = f {
                        if rustls::client::EchConfig::new(
                            b.clone().into(),
                            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
                        )
                        .is_ok()
                        {
                            cache.insert(c.server_name.clone(), b.clone());
                        } else {
                            warn!(
                                "DoH upstream {}: fetched ECH blob failed parse; not cached",
                                c.name
                            );
                        }
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
                // W3-03: this vector becomes the eBPF exclude_ips map, where a
                // membership hit means "do not fragment, decoy or desync" --
                // sockops.bpf.c returns BPF_OK for that destination. An
                // unchecked address here therefore does not misroute a query,
                // it silently switches OFF DPI evasion for that destination
                // while the daemon reports the bypass active. Screen the value.
                if let Ok(ip) = host_str.parse::<Ipv4Addr>() {
                    if !is_blocked_bootstrap_ip(&ip) {
                        ips.push(ip);
                    }
                } else {
                    let host_with_port = format!("{}:{}", host_str, parsed.port().unwrap_or(443));
                    if let Ok(resolved) = host_with_port.to_socket_addrs() {
                        for addr in resolved {
                            if let std::net::SocketAddr::V4(v4) = addr {
                                if !is_blocked_bootstrap_ip(v4.ip()) {
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

    // W3-03: this path screened nothing -- not even the operator's explicit
    // list. These addresses become eBPF exclude_ips_v6 map entries, where a
    // hit means "leave this destination unfragmented and undecoyed".
    ips.extend(
        custom_bootstrap_ips
            .iter()
            .filter(|ip| !is_blocked_bootstrap_ip_v6(ip))
            .copied(),
    );

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
                // W3-03: same exclusion-map hazard as the v4 path.
                if let Ok(ip) = clean_host.parse::<Ipv6Addr>() {
                    if !is_blocked_bootstrap_ip_v6(&ip) {
                        ips.push(ip);
                    }
                } else {
                    let host_with_port = format!("{}:{}", host_str, parsed.port().unwrap_or(443));
                    if let Ok(resolved) = host_with_port.to_socket_addrs() {
                        for addr in resolved {
                            if let std::net::SocketAddr::V6(v6) = addr {
                                if !is_blocked_bootstrap_ip_v6(v6.ip()) {
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
    use std::io::{Read as _, Write as _};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

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

    /// Minimal single-shot HTTP/1.1 responder bound to loopback.
    ///
    /// Serves `response` to the first connection, records whether it was ever
    /// contacted in `hit`, and lets the caller observe the client's decision
    /// without any TLS/DNS dependency. Loopback only: no egress, hermetic.
    fn spawn_one_shot(response: &[u8], hit: Arc<AtomicBool>) -> u16 {
        let response = response.to_vec();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local_addr").port();
        std::thread::spawn(move || {
            // Bounded: never let a hung assertion wedge the test binary.
            let _ = listener.set_nonblocking(true);
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                if std::time::Instant::now() > deadline {
                    return;
                }
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        hit.store(true, Ordering::SeqCst);
                        let _ = sock.set_nonblocking(false);
                        let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                        // Drain the request head so the client can write its
                        // body without RST-ing the connection.
                        let mut buf = [0u8; 2048];
                        let _ = sock.read(&mut buf);
                        let _ = sock.write_all(&response);
                        let _ = sock.flush();
                        return;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });
        port
    }

    /// Flattens a `reqwest::Error` and its whole `source` chain into one
    /// string. reqwest surfaces a refused redirect as a generic "error
    /// following redirect" wrapper and puts our reason in the cause, so
    /// asserting on `to_string()` alone would pass on the wrong evidence.
    fn err_chain(e: &dyn std::error::Error) -> String {
        let mut out = e.to_string();
        let mut cur = e.source();
        while let Some(c) = cur {
            out.push_str(" | ");
            out.push_str(&c.to_string());
            cur = c.source();
        }
        out
    }

    /// Regression (HANCORE): reqwest's stock policy follows up to 10 redirect
    /// hops, and the DoH client inherited that default. A malicious or
    /// compromised upstream could therefore bounce a DNS query to an
    /// `http://` URL (plaintext downgrade of the whole point of DoH), to a
    /// host outside the bootstrap-pinned set (resolved by the system resolver,
    /// which albus has pointed at its own loopback listener), or to a private
    /// /link-local/metadata address that the blocked-IP checks never see.
    ///
    /// The client must refuse the hop and error, never dereference `Location`.
    ///
    /// Each `Location` points at a *live* second loopback sink that would
    /// answer if it were ever dialed, so a policy regression fails on observed
    /// behaviour (target contacted) and not merely on an error string. The
    /// non-loopback targets are covered by name only -- they exist to prove
    /// the URL is reported, and are never dialed because the policy refuses
    /// first.
    #[tokio::test]
    async fn test_doh_client_refuses_redirects() {
        for (label, template) in [
            // Live loopback target: dereferencing it is observable.
            ("live-target", "http://127.0.0.1:{port}/dns-query"),
            // Off-host targets: refused by name, never dialed.
            ("scheme-downgrade", "http://127.0.0.1:1/dns-query"),
            (
                "private-metadata",
                "https://169.254.169.254/latest/meta-data/",
            ),
            ("loopback-admin", "https://127.0.0.1:8080/"),
            ("cross-host", "https://attacker.invalid/dns-query"),
        ] {
            // Live sink the redirect points at; must never be contacted.
            let target_hit = Arc::new(AtomicBool::new(false));
            let target_port = spawn_one_shot(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nPWNED",
                Arc::clone(&target_hit),
            );
            let location = template.replace("{port}", &target_port.to_string());

            let hit = Arc::new(AtomicBool::new(false));
            let redirect = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n",
                location
            );
            let port = spawn_one_shot(redirect.as_bytes(), Arc::clone(&hit));

            let client = reqwest::Client::builder()
                .redirect(doh_redirect_policy())
                .timeout(Duration::from_secs(3))
                .build()
                .expect("client build");

            let out = client
                .post(format!("http://127.0.0.1:{}/dns-query", port))
                .body(vec![0x00; 4])
                .send()
                .await;

            let err = out
                .err()
                .unwrap_or_else(|| panic!("{}: redirect was followed instead of refused", label));
            let msg = err_chain(&err);
            assert!(
                msg.contains("refusing to follow redirects"),
                "{}: refusal reason missing, Location may have been dereferenced: {}",
                label,
                msg
            );
            assert!(
                msg.contains(&location),
                "{}: error should name the refused target {}: {}",
                label,
                location,
                msg
            );
            assert!(
                !target_hit.load(Ordering::SeqCst),
                "{}: the redirect target was actually contacted -- the policy \
                 was not applied",
                label
            );
            assert!(
                hit.load(Ordering::SeqCst),
                "control failed: the redirecting sink never answered for {}",
                label
            );
        }
    }

    /// Control for the test above: proves the harness would actually observe a
    /// followed redirect, i.e. that `test_doh_client_refuses_redirects` is not
    /// passing merely because the sink was unreachable or the policy never
    /// fired at all.
    #[tokio::test]
    async fn test_default_reqwest_policy_would_follow_redirect() {
        let hit = Arc::new(AtomicBool::new(false));
        let resp: &'static [u8] =
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n";
        let port = spawn_one_shot(resp, Arc::clone(&hit));

        // No `.redirect(...)` => reqwest's permissive Policy::limit(10).
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .expect("client build");

        // /next is unresolvable, so a followed hop surfaces as an error -- but
        // the first hop already proved the server answered at all.
        let out = client
            .post(format!("http://127.0.0.1:{}/dns-query", port))
            .body(vec![0x00; 4])
            .send()
            .await;

        assert!(
            hit.load(Ordering::SeqCst),
            "control failed: sink never answered, so the redirect test proves nothing"
        );
        let chain = out.err().map(|e| err_chain(&e)).unwrap_or_default();
        assert!(
            !chain.contains("refusing to follow redirects"),
            "control failed: stock policy must not emit our refusal, got: {}",
            chain
        );
    }

    /// `https_only(true)` is the second half of the fix: it rejects any
    /// `http://` request at dispatch time, closing the downgrade leg even if
    /// the redirect policy were ever relaxed. Asserted against the *production*
    /// builder so a future refactor cannot drop the flag unnoticed.
    #[tokio::test]
    async fn test_doh_client_refuses_plaintext_scheme() {
        let client =
            SingleDoHClient::hardened_builder(tls_client_config(false, None).expect("tls config"))
                .build()
                .expect("client build");

        let err = client
            .post("http://127.0.0.1:1/dns-query")
            .body(vec![0x00; 4])
            .send()
            .await
            .expect_err("http:// must be rejected under https_only");
        assert!(
            err.is_builder(),
            "expected a builder-level bad-scheme error, got: {}",
            err
        );
    }

    /// Structural guard: the hardened builder must carry the refusing redirect
    /// policy and the 3s bound.
    #[test]
    fn test_hardened_builder_carries_policy_and_timeout() {
        let tls = tls_client_config(false, None).expect("tls config");
        let debug = format!("{:?}", SingleDoHClient::hardened_builder(tls));
        assert!(
            debug.contains("redirect_policy: Policy(Custom)"),
            "hardened builder must install our refusing policy: {}",
            debug
        );
        assert!(
            debug.contains("timeout: 3s"),
            "hardened builder must keep the 3s bound: {}",
            debug
        );
    }

    /// Source-level guard: the only production `reqwest::Client::builder()` in
    /// this module is the hardened one, so *both* call sites — `new` and the
    /// ECH rebuild in `apply_ech` — are pinned to it.
    ///
    /// Deliberately a source assertion rather than a behavioural one: no test
    /// can observe which builder a given call site uses. Verified by reverting
    /// `apply_ech` alone to an inline permissive builder — nothing else in the
    /// suite fails, because `apply_ech` is otherwise never exercised. Without
    /// this guard the ECH path could silently restore `Policy::limit(10)` plus
    /// plaintext-scheme acceptance.
    #[test]
    fn test_no_production_client_builder_outside_hardened_builder() {
        let src = include_str!("doh.rs");
        // Production section only: the test harness legitimately builds
        // throwaway clients against loopback sinks.
        let prod = src
            .split_once("#[cfg(test)]")
            .expect("test module marker")
            .0;

        let mut sites = prod.match_indices("reqwest::Client::builder()");
        let (first, _) = sites.next().expect("hardened_builder call site");
        assert!(
            sites.next().is_none(),
            "found more than one production reqwest::Client::builder(); every \
             construction site must go through SingleDoHClient::hardened_builder"
        );

        // The one allowed site must carry both hardening flags.
        let rest = &prod[first..];
        let call = &rest[..rest.find(';').expect("builder statement terminator")];
        assert!(
            call.contains("https_only(true)"),
            "the sole production builder must set https_only: {}",
            call
        );
        assert!(
            call.contains("doh_redirect_policy()"),
            "the sole production builder must set the refusing redirect policy: {}",
            call
        );
        assert!(
            call.contains(".no_proxy()"),
            "the sole production builder must refuse ambient proxy env vars, \
             which would bypass resolve_to_addrs entirely: {}",
            call
        );

        // W3-02: the guard above counts a reqwest-shaped literal, so it is
        // structurally blind to a rustls-shaped construction site -- which is
        // exactly how `probe_pq_support` shipped its own provider, root store
        // and protocol-version policy while this test still passed. Count the
        // rustls literal too, and require the same "exactly once" guarantee.
        let needle = "rustls::ClientConfig::builder_with_provider";
        let mut tls_sites = prod.match_indices(needle);
        let (tls_first, _) = tls_sites.next().expect("build_client_config call site");
        assert!(
            tls_sites.next().is_none(),
            "found more than one production {}; there must be exactly one \
             ClientConfig construction site so the query path and the PQ probe \
             cannot drift apart",
            needle
        );
        let tls_rest = &prod[tls_first..];
        let tls_call = &tls_rest[..tls_rest.find('\n').expect("statement line")];
        assert!(
            !tls_call.contains("webpki_roots"),
            "the root store must be installed in the shared construction site, \
             not at a call site: {}",
            tls_call
        );

        // And the probe must not dial a bare socket to an unscreened address.
        assert!(
            prod.contains("filter(|a| !socket_addr_is_blocked(a))"),
            "probe_pq_support must apply the same destination screen the query \
             path applies; it performs the same egress"
        );
    }

    /// `no_proxy()` is load-bearing: reqwest enables `auto_sys_proxy` by default,
    /// so an inherited `HTTPS_PROXY`/`ALL_PROXY` CONNECT-tunnels every DoH
    /// query through a third party and `resolve_to_addrs` is never consulted —
    /// the bootstrap pin becomes dead config and the DNS query leaves the
    /// machine.
    ///
    /// Sets a hostile proxy in the ambient environment and asserts the
    /// production client still carries no proxy matcher.
    ///
    /// **Mutates process-global state**, so it must not run alongside tests
    /// that build reqwest clients — a concurrent test would inherit the bogus
    /// proxy and fail spuriously. `#[ignore]` keeps it out of the default
    /// suite; run it explicitly with:
    /// `cargo test -- --ignored test_doh_client_ignores_ambient_proxy_env`
    #[test]
    #[ignore]
    fn test_doh_client_ignores_ambient_proxy_env() {
        let tls = tls_client_config(false, None).expect("tls config");

        let prev: Vec<(&str, Option<std::ffi::OsString>)> =
            ["HTTPS_PROXY", "ALL_PROXY", "https_proxy", "all_proxy"]
                .into_iter()
                .map(|k| (k, std::env::var_os(k)))
                .collect();
        std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:1");
        std::env::set_var("ALL_PROXY", "http://127.0.0.1:1");

        let debug = format!(
            "{:?}",
            SingleDoHClient::hardened_builder(tls)
                .build()
                .expect("client build")
        );

        for (k, v) in prev {
            restore_env(k, v);
        }

        assert!(
            !debug.contains("System"),
            "production client must not install the ambient system proxy \
             matcher (HTTPS_PROXY/ALL_PROXY): {}",
            debug
        );
        // reqwest omits the `proxies` field entirely when the list is empty
        // (the same presence-based encoding it uses for the default redirect
        // policy), so an absent field is the positive signal here.
        assert!(
            !debug.contains("proxies:"),
            "production client must carry no proxy matchers at all: {}",
            debug
        );
    }

    fn restore_env(key: &str, prev: Option<std::ffi::OsString>) {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    /// Defense in depth: even if a 3xx ever reaches `resolve` (e.g. a future
    /// `Policy::stop()` that hands the redirect back as `Ok`), it must be
    /// rejected on the status check and never parsed as a DNS answer -- the
    /// body is attacker-chosen bytes headed straight for the resolver.
    ///
    /// `Policy::none()` hands the 3xx back as `Ok`, which is how a redirect
    /// status reaches `resolve` at all; `https_only` is left off here so the
    /// loopback sink is reachable.
    #[tokio::test]
    async fn test_resolve_rejects_redirect_response() {
        // Poison body: qdcount=0 header bytes the resolver must never see.
        let poison: &'static [u8] = b"HTTP/1.1 302 Found\r\nLocation: https://evil.invalid/\r\nContent-Length: 12\r\n\r\n\x00\x00\x00\x00junkjunk";
        let hit = Arc::new(AtomicBool::new(false));
        let port = spawn_one_shot(poison, Arc::clone(&hit));

        // `Policy::none()` hands the 3xx back as `Ok`, which is the only way a
        // redirect status can reach `resolve`; `https_only` is left off here so
        // the loopback sink is reachable at all.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client build");

        let c = SingleDoHClient {
            name: "test-redirect".into(),
            url: format!("http://127.0.0.1:{}/dns-query", port),
            pqc: false,
            client,
            server_name: String::new(),
            bootstrap_addrs: Vec::new(),
        };

        let err = c
            .resolve(&[0x00; 4])
            .await
            .expect_err("3xx must not be accepted as a DNS answer");
        let msg = err_chain(err.as_ref());
        assert!(
            msg.contains("302") && msg.contains("refusing to follow"),
            "redirect status should be reported explicitly, got: {}",
            msg
        );
        assert!(
            hit.load(Ordering::SeqCst),
            "control failed: sink never answered, so this test proves nothing"
        );
    }

    /// The `is_redirection()` check in `resolve` is load-bearing, because
    /// reqwest's redirect layer only consults the policy for
    /// {301,302,303,307,308}. Every other 3xx -- 300/304/305/306, plus any
    /// redirect status sent *without* a `Location` header -- is handed back to
    /// us as `Ok` with the policy never invoked.
    ///
    /// This test drives exactly those escape statuses through the real
    /// `resolve` path and pins that none of their bodies is ever accepted as a
    /// DNS answer. Deleting the `is_redirection()` check fails this test.
    #[tokio::test]
    async fn test_resolve_rejects_statuses_that_bypass_the_policy() {
        // 300/304/305/306: not matched by reqwest's redirect arm at all.
        // 301-without-Location: matched, but bails before the policy runs.
        for (label, status_line) in [
            ("300-multiple-choices", "HTTP/1.1 300 Multiple Choices\r\nContent-Length: 12\r\n\r\n\x00\x00\x00\x00junkjunk"),
            ("304-not-modified", "HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n\x00\x00\x00\x00junkjunk"),
            ("305-use-proxy", "HTTP/1.1 305 Use Proxy\r\nContent-Length: 12\r\n\r\n\x00\x00\x00\x00junkjunk"),
            ("306-unused", "HTTP/1.1 306 Unused\r\nContent-Length: 12\r\n\r\n\x00\x00\x00\x00junkjunk"),
            (
                "301-without-location",
                "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 12\r\n\r\n\x00\x00\x00\x00junkjunk",
            ),
        ] {
            let hit = Arc::new(AtomicBool::new(false));
            let port = spawn_one_shot(status_line.as_bytes(), Arc::clone(&hit));

            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .expect("client build");

            let c = SingleDoHClient {
                name: format!("test-{}", label),
                url: format!("http://127.0.0.1:{}/dns-query", port),
                pqc: false,
                client,
                server_name: String::new(),
                bootstrap_addrs: Vec::new(),
            };

            let err = c
                .resolve(&[0x00; 4])
                .await
                .err()
                .unwrap_or_else(|| {
                    panic!(
                        "{}: 3xx body was accepted as a DNS answer (is_redirection check removed?)",
                        label
                    )
                });
            let msg = err_chain(err.as_ref() as &dyn std::error::Error);
            assert!(
                msg.contains("refusing to follow"),
                "{}: expected the explicit redirect rejection, got: {}",
                label,
                msg
            );
            assert!(
                hit.load(Ordering::SeqCst),
                "control failed: sink never answered for {}, so this proves nothing",
                label
            );
        }
    }

    // Run-4: live-network test — excluded from hermetic gates
    // (`cargo test -- --ignored`), matching the live_* convention.
    #[tokio::test]
    #[ignore]
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
mod blocked_destination_tests {
    use super::*;

    /// W3-01: a bootstrap pin may never be loopback, private, link-local,
    /// CGNAT, multicast or metadata. Each of these constructs successfully on
    /// unpatched source, including the literal-host ingress that needs no DNS
    /// at all: `albus config set --doh-upstream https://127.0.0.1/dns-query`.
    #[test]
    fn test_literal_blocked_pins_are_rejected() {
        let blocked = [
            "127.0.0.1",       // loopback
            "127.0.0.15",      // loopback /8
            "0.0.0.0",         // unspecified
            "10.0.0.1",        // RFC1918
            "172.16.0.1",      // RFC1918
            "192.168.1.1",     // RFC1918
            "100.64.0.1",      // CGNAT
            "169.254.169.254", // link-local + cloud metadata
            "224.0.0.1",       // multicast
        ];
        for ip in blocked {
            let url = format!("https://{}/dns-query", ip);
            assert!(
                SingleDoHClient::new(&url, "custom", &[], false).is_err(),
                "blocked pin {} must be rejected",
                ip
            );
        }
    }

    /// Positive control: public upstreams must still construct. An over-broad
    /// fix that rejected everything would satisfy the test above.
    #[test]
    fn test_public_literal_pins_still_accepted() {
        for ip in ["1.1.1.1", "9.9.9.9", "8.8.8.8"] {
            let url = format!("https://{}/dns-query", ip);
            assert!(
                SingleDoHClient::new(&url, "custom", &[], false).is_ok(),
                "public pin {} must still be accepted",
                ip
            );
        }
        // Preset names keep working too: a preset supplies its own public pins,
        // so the scheme is still https and no name resolution is needed.
        let preset = SingleDoHClient::new(
            "https://cloudflare-dns.com/dns-query",
            "cloudflare",
            &[],
            false,
        );
        assert!(
            preset.is_ok(),
            "a preset upstream with no literal host must still construct"
        );
    }

    /// W3-01: the v6 predicate did not exist, so these were all accepted.
    #[test]
    fn test_blocked_v6_predicate_covers_v6_ranges() {
        let blocked = [
            "::1",                    // loopback
            "::",                     // unspecified
            "fc00::1",                // unique-local fc00::/7
            "fd12:3456::1",           // unique-local
            "fe80::1",                // link-local
            "2001:db8::1",            // documentation
            "ff02::1",                // multicast
            "::ffff:127.0.0.1",       // v4-mapped loopback
            "::ffff:169.254.169.254", // v4-mapped metadata
            "::ffff:10.0.0.1",        // v4-mapped RFC1918
            "64:ff9b::127.0.0.1",     // NAT64-wrapped loopback
            "2002:7f00:1::",          // 6to4-wrapped loopback
        ];
        for s in blocked {
            let ip: Ipv6Addr = s.parse().unwrap_or_else(|_| panic!("bad fixture {}", s));
            assert!(
                is_blocked_bootstrap_addr(&IpAddr::V6(ip)),
                "v6 address {} must be blocked",
                s
            );
        }
        for s in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            let ip: Ipv6Addr = s.parse().expect("fixture");
            assert!(
                !is_blocked_bootstrap_addr(&IpAddr::V6(ip)),
                "public v6 {} must be allowed",
                s
            );
        }
    }

    /// W3-03: these vectors feed the eBPF exclude maps, where membership means
    /// "no fragmentation, no decoy, no desync". Before the fix
    /// `extract_upstream_ips("https://127.0.0.1/dns-query", &[])` returned
    /// `[127.0.0.1]`, silently disabling DPI evasion for that destination.
    #[test]
    fn test_extracted_exclusion_ips_exclude_blocked_ranges() {
        let v4 = extract_upstream_ips("https://127.0.0.1/dns-query", &[]);
        assert!(
            v4.is_empty(),
            "loopback must not enter exclude_ips, got {:?}",
            v4
        );
        assert!(
            extract_upstream_ips("https://169.254.169.254/dns-query", &[]).is_empty(),
            "metadata must not enter exclude_ips"
        );
        assert!(
            extract_upstream_ips("https://192.168.1.1/dns-query", &[]).is_empty(),
            "RFC1918 must not enter exclude_ips"
        );
        // The explicit custom list was already screened; keep it that way.
        assert!(extract_upstream_ips("", &[Ipv4Addr::new(10, 0, 0, 1)]).is_empty());

        // Positive controls.
        let pub4 = extract_upstream_ips("https://1.1.1.1/dns-query", &[]);
        assert_eq!(pub4, vec![Ipv4Addr::new(1, 1, 1, 1)]);
        assert!(!extract_upstream_ips("cloudflare", &[]).is_empty());
    }

    /// W3-03: the v6 extractor screened nothing at all -- not the custom list,
    /// not the literal, not the resolver answers.
    #[test]
    fn test_extracted_exclusion_ips_v6_exclude_blocked_ranges() {
        assert!(
            extract_upstream_ips_v6("https://[::1]/dns-query", &[]).is_empty(),
            "v6 loopback must not enter exclude_ips_v6"
        );
        assert!(
            extract_upstream_ips_v6("https://[fd00::1]/dns-query", &[]).is_empty(),
            "v6 unique-local must not enter exclude_ips_v6"
        );
        assert!(
            extract_upstream_ips_v6("https://[fe80::1]/dns-query", &[]).is_empty(),
            "v6 link-local must not enter exclude_ips_v6"
        );
        assert!(
            extract_upstream_ips_v6("", &["::ffff:0.0.0.0".parse().unwrap()]).is_empty(),
            "blocked custom v6 must not enter exclude_ips_v6"
        );

        // Positive control.
        let pub6 = extract_upstream_ips_v6("https://[2606:4700:4700::1111]/dns-query", &[]);
        assert_eq!(pub6.len(), 1);
        assert_eq!(pub6[0].to_string(), "2606:4700:4700::1111");
    }

    /// A preset lookup must not be subvertible by naming a preset with a
    /// blocked suffix; presets are the trusted source and stay unfiltered.
    #[test]
    fn test_presets_are_presets() {
        let v4 = extract_upstream_ips("cloudflare,google", &[]);
        for ip in &v4 {
            assert!(
                !is_blocked_bootstrap_ip(ip),
                "preset table must contain only public addresses, found {}",
                ip
            );
        }
    }
}
