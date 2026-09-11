//! rfc 7858 dns-over-tls (dot) client implementation supporting post-quantum cryptography.
//!
//! provides secure encrypted dns transport directly over tls port 853 with
//! alpn "dot" protocol negotiation and rfc 1035 2-octet length-prefixed framing.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

// static lookup table of pre-configured public dot endpoints and hostnames
pub static DOT_PRESETS: LazyLock<HashMap<&'static str, (SocketAddr, &'static str)>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert(
            "cloudflare",
            (
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 853),
                "cloudflare-dns.com",
            ),
        );
        m.insert(
            "cloudflare-secondary",
            (
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 853),
                "cloudflare-dns.com",
            ),
        );
        m.insert(
            "quad9",
            (
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 853),
                "dns.quad9.net",
            ),
        );
        m.insert(
            "quad9-secondary",
            (
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)), 853),
                "dns.quad9.net",
            ),
        );
        m.insert(
            "google",
            (
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 853),
                "dns.google",
            ),
        );
        m.insert(
            "google-secondary",
            (
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 853),
                "dns.google",
            ),
        );
        m.insert(
            "mullvad",
            (
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(194, 242, 2, 2)), 853),
                "dns.mullvad.net",
            ),
        );
        m
    });

#[derive(Clone)]
pub struct DotClient {
    pub name: String,
    pub server_addr: SocketAddr,
    pub hostname: String,
    pub pqc: bool,
    connector: TlsConnector,
}

impl std::fmt::Debug for DotClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotClient")
            .field("name", &self.name)
            .field("server_addr", &self.server_addr)
            .field("hostname", &self.hostname)
            .field("pqc", &self.pqc)
            .finish()
    }
}

impl DotClient {
    // initializes dot client targeting a specific socket address and tls sni hostname
    pub fn new(
        server_addr: SocketAddr,
        hostname: &str,
        pqc: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        if !pqc {
            // enforce classical key exchange only: eliminate all post-quantum KEMs
            provider.kx_groups.retain(|kx| {
                let name = format!("{:?}", kx.name());
                !name.contains("MLKEM") && !name.contains("Kyber")
            });
        }

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(root_store);

        let mut client_config = builder.with_no_client_auth();
        // RFC 7858 section 3.2 specifies ALPN protocol "dot"
        client_config.alpn_protocols = vec![b"dot".to_vec()];

        Ok(Self {
            name: format!("dot:{}", hostname),
            server_addr,
            hostname: hostname.to_string(),
            pqc,
            connector: TlsConnector::from(Arc::new(client_config)),
        })
    }

    // instantiates dot client using built-in preset provider name
    pub fn from_preset(name: &str, pqc: bool) -> Option<Self> {
        let (addr, hostname) = DOT_PRESETS.get(name)?;
        Self::new(*addr, hostname, pqc).ok()
    }

    /// Instantiates DotClient from either a preset name (quad9, cloudflare, google, mullvad)
    /// or an explicit IP/SocketAddr format (e.g. "9.9.9.9:853").
    pub fn from_preset_or_addr(input: &str, pqc: bool) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let trimmed = input.trim();
        if let Some(client) = Self::from_preset(trimmed, pqc) {
            return Ok(client);
        }
        if let Ok(addr) = trimmed.parse::<SocketAddr>() {
            let host = addr.ip().to_string();
            return Self::new(addr, &host, pqc);
        }
        if let Some((host, port_str)) = trimmed.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    return Self::new(SocketAddr::new(ip, port), host, pqc);
                }
            }
        }
        Err(format!("unknown DoT preset or invalid socket address: '{}'", input).into())
    }

    /// Transmits raw DNS query over TLS with default 4-second timeout.
    pub async fn query(
        &self,
        query_wire_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        self.resolve(query_wire_bytes, Duration::from_secs(4)).await
    }

    // transmits raw dns query over tls session with 2-byte rfc 1035/7858 length prefix
    pub async fn resolve(
        &self,
        query_wire_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if query_wire_bytes.len() > 65535 {
            return Err("query exceeds maximum 65535 octets".into());
        }

        let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect(self.server_addr)).await??;
        let _ = tcp_stream.set_nodelay(true);

        let server_name = rustls::pki_types::ServerName::try_from(self.hostname.clone())
            .map_err(|e| format!("invalid dot server hostname '{}': {:?}", self.hostname, e))?;

        let mut tls_stream = tokio::time::timeout(timeout, self.connector.connect(server_name, tcp_stream)).await??;

        let len_prefix = (query_wire_bytes.len() as u16).to_be_bytes();
        tokio::time::timeout(timeout, async {
            tls_stream.write_all(&len_prefix).await?;
            tls_stream.write_all(query_wire_bytes).await?;
            tls_stream.flush().await?;

            let mut len_buf = [0u8; 2];
            tls_stream.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;

            if resp_len < 12 || resp_len > 65535 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid dot response length: {}", resp_len),
                ));
            }

            let mut resp_buf = vec![0u8; resp_len];
            tls_stream.read_exact(&mut resp_buf).await?;
            Ok::<Vec<u8>, std::io::Error>(resp_buf)
        })
        .await?
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dot_presets_and_lookup() {
        assert!(DOT_PRESETS.contains_key("cloudflare"));
        assert!(DOT_PRESETS.contains_key("quad9"));
        assert!(DOT_PRESETS.contains_key("google"));
        assert!(DOT_PRESETS.contains_key("mullvad"));

        let (cf_addr, cf_host) = DOT_PRESETS.get("cloudflare").unwrap();
        assert_eq!(cf_addr.port(), 853);
        assert_eq!(*cf_host, "cloudflare-dns.com");

        let client = DotClient::from_preset("quad9", false).expect("preset should initialize");
        assert_eq!(client.hostname, "dns.quad9.net");
        assert!(!client.pqc);
    }

    #[test]
    fn test_dot_client_pqc_creation() {
        let addr: SocketAddr = "1.1.1.1:853".parse().unwrap();
        let client_pqc = DotClient::new(addr, "cloudflare-dns.com", true).expect("pqc client should initialize");
        assert!(client_pqc.pqc);

        let client_classical = DotClient::new(addr, "cloudflare-dns.com", false).expect("classical client should initialize");
        assert!(!client_classical.pqc);
    }
}
