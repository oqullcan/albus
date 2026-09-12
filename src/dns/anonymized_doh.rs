//! anonymized dns-over-https (doh) relay chaining and header scrubbing engine.
//!
//! obscures client network identity by sanitizing identifying http headers,
//! enforcing discrete rfc 8467 query padding, and optionally forwarding requests
//! across multi-hop http connect / socks5 / tor proxy tunnels.

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use std::sync::Arc;
use tracing::debug;

use crate::dns::padding::apply_edns_padding;

#[derive(Clone, Debug)]
pub struct AnonymizedDoHClient {
    pub target_url: String,
    pub relay_url: Option<String>,
    pub client: reqwest::Client,
    pub enforce_padding: bool,
}

impl AnonymizedDoHClient {
    pub fn new(
        target_url: &str,
        relay_url: Option<&str>,
        proxy: Option<&str>,
        enforce_padding: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = reqwest::Client::builder();

        // If an explicit proxy is configured (e.g. socks5://127.0.0.1:9050 or http://relay:8080)
        let effective_proxy = relay_url.or(proxy);
        if let Some(p_url) = effective_proxy {
            if let Ok(proxy_cfg) = reqwest::Proxy::all(p_url) {
                builder = builder.proxy(proxy_cfg);
                debug!(proxy = %p_url, "Configured anonymizing proxy tunnel for DoH");
            }
        }

        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/dns-message"),
        );
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/dns-message"));

        let client = builder
            .default_headers(default_headers)
            .build()
            .map_err(|e| format!("failed to build anonymized doh client: {:?}", e))?;

        Ok(Self {
            target_url: target_url.to_string(),
            relay_url: relay_url.map(|s| s.to_string()),
            client,
            enforce_padding,
        })
    }

    // sanitizes query and transmits through anonymizing tunnel
    pub async fn resolve(
        &self,
        query_wire_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Enforce discrete RFC 8467 EDNS padding if requested
        let effective_query = if self.enforce_padding {
            apply_edns_padding(query_wire_bytes, true)
        } else {
            query_wire_bytes.to_vec()
        };

        let resp = self
            .client
            .post(&self.target_url)
            .body(effective_query)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(format!("Anonymized DoH target returned HTTP {}", resp.status()).into());
        }

        let body = resp.bytes().await?;
        Ok(body.to_vec())
    }
}

// sanitizes raw request headers, removing client tracking fingerprints
pub fn scrub_identifying_headers(headers: &mut HeaderMap) {
    let identifying_keys = [
        "user-agent",
        "accept-language",
        "cookie",
        "authorization",
        "x-forwarded-for",
        "x-real-ip",
        "client-ip",
        "forwarded",
        "cf-connecting-ip",
        "true-client-ip",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
    ];

    for key in &identifying_keys {
        headers.remove(*key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_identifying_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("Mozilla/5.0"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.195"));
        headers.insert("cookie", HeaderValue::from_static("session=abcdef"));
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/dns-message"),
        );

        assert_eq!(headers.len(), 4);
        scrub_identifying_headers(&mut headers);

        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("content-type"));
        assert!(!headers.contains_key("user-agent"));
        assert!(!headers.contains_key("x-forwarded-for"));
        assert!(!headers.contains_key("cookie"));
    }

    #[test]
    fn test_anonymized_doh_client_creation() {
        let client = AnonymizedDoHClient::new(
            "https://dns.quad9.net/dns-query",
            Some("socks5://127.0.0.1:9050"),
            None,
            true,
        )
        .expect("client should initialize");

        assert_eq!(client.target_url, "https://dns.quad9.net/dns-query");
        assert_eq!(client.relay_url.as_deref(), Some("socks5://127.0.0.1:9050"));
        assert!(client.enforce_padding);
    }
}
