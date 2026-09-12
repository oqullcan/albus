//! rfc 9250 dns-over-quic (doq) client implementation.
//!
//! executes encrypted dns queries over dedicated quic streams on port 853,
//! providing zero round-trip connection resumption (0-rtt), multiplexing without
//! head-of-line blocking, and connection migration resilience.

use quinn::{ClientConfig, Endpoint};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::debug;

pub static DOQ_PRESETS: LazyLock<HashMap<&'static str, (SocketAddr, &'static str)>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert(
            "adguard",
            ("94.140.14.14:853".parse().unwrap(), "dns.adguard-dns.com"),
        );
        m.insert(
            "adguard-unfiltered",
            (
                "94.140.14.140:853".parse().unwrap(),
                "unfiltered.adguard-dns.com",
            ),
        );
        m.insert(
            "nextdns",
            ("45.90.28.0:853".parse().unwrap(), "dns.nextdns.io"),
        );
        m
    });

#[derive(Clone)]
pub struct DoQClient {
    name: String,
    server_addr: SocketAddr,
    hostname: String,
    client_config: ClientConfig,
    endpoint: Arc<Mutex<Option<Endpoint>>>,
}

impl DoQClient {
    /// Initializes DoQ client targeting a specific socket address and TLS SNI hostname.
    pub fn new(
        server_addr: SocketAddr,
        hostname: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(root_store);

        let mut client_crypto = builder.with_no_client_auth();
        // RFC 9250 Section 4 specifies ALPN "doq"
        client_crypto.alpn_protocols = vec![b"doq".to_vec()];

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?;
        let client_config = ClientConfig::new(Arc::new(quic_client_config));

        Ok(Self {
            name: format!("doq:{}", hostname),
            server_addr,
            hostname: hostname.to_string(),
            client_config,
            endpoint: Arc::new(Mutex::new(None)),
        })
    }

    /// Instantiates DoQ client using a preset resolver name (adguard, adguard-unfiltered, nextdns).
    pub fn from_preset(name: &str) -> Option<Self> {
        let (addr, hostname) = DOQ_PRESETS.get(name)?;
        Self::new(*addr, hostname).ok()
    }

    /// Instantiates DoQ client from preset name or explicit socket address / url.
    pub fn from_preset_or_addr(
        input: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let trimmed = input.trim().trim_start_matches("quic://");
        if let Some(client) = Self::from_preset(trimmed) {
            return Ok(client);
        }
        if let Ok(addr) = trimmed.parse::<SocketAddr>() {
            let host = addr.ip().to_string();
            return Self::new(addr, &host);
        }
        if let Some((host, port_str)) = trimmed.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    return Self::new(SocketAddr::new(ip, port), host);
                }
            }
        }
        Err(format!("unknown DoQ preset or invalid address: '{}'", input).into())
    }

    async fn get_or_create_endpoint(
        &self,
    ) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
        let mut ep_lock = self.endpoint.lock().await;
        if let Some(ref ep) = *ep_lock {
            return Ok(ep.clone());
        }

        let bind_addr: SocketAddr = if self.server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(self.client_config.clone());
        *ep_lock = Some(endpoint.clone());
        Ok(endpoint)
    }

    /// Transmits raw DNS query over dedicated QUIC stream (RFC 9250).
    pub async fn resolve(
        &self,
        query_wire_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = self.get_or_create_endpoint().await?;
        tokio::time::timeout(timeout, async {
            let connecting = endpoint.connect(self.server_addr, &self.hostname)?;
            let connection = connecting.await?;

            let (mut send, mut recv) = connection.open_bi().await?;

            // RFC 9250 section 4.2: In DoQ, messages are not length-prefixed.
            // A stream carries exactly one DNS query and its response.
            send.write_all(query_wire_bytes).await?;
            send.finish()?;

            let resp = recv.read_to_end(65535).await?;
            debug!(
                server = %self.name,
                bytes = resp.len(),
                "Resolved DNS query over DoQ"
            );
            Ok(resp)
        })
        .await
        .map_err(|_| format!("DoQ query to {} timed out", self.name))?
    }

    /// Query helper with 4-second default timeout.
    pub async fn query(
        &self,
        query_wire_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        self.resolve(query_wire_bytes, Duration::from_secs(4)).await
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doq_presets_and_creation() {
        assert!(DOQ_PRESETS.contains_key("adguard"));
        assert!(DOQ_PRESETS.contains_key("nextdns"));

        let client = DoQClient::from_preset("adguard");
        assert!(client.is_some());
        let c = client.unwrap();
        assert_eq!(c.name(), "doq:dns.adguard-dns.com");

        let custom = DoQClient::from_preset_or_addr("94.140.14.14:853");
        assert!(custom.is_ok());
    }
}
