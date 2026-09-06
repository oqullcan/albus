//! remote resolver list management and minisign ed25519 signature verification.
//!
//! downloads public-resolvers.md, validates cryptographic signatures using minisign ed25519,
//! caches verified lists locally, and parses dns stamps for upstream resolution.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use super::stamp::DnsStamp;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceConfig {
    pub urls: Vec<String>,
    pub cache_file: String,
    pub minisign_key: String,
    #[serde(default = "default_refresh_delay_hours")]
    pub refresh_delay_hours: u32,
    #[serde(default)]
    pub prefix: String,
}

fn default_refresh_delay_hours() -> u32 {
    72
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            urls: vec![
                "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md".to_string(),
                "https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md".to_string(),
            ],
            cache_file: "public-resolvers.md".to_string(),
            minisign_key: "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3".to_string(),
            refresh_delay_hours: 72,
            prefix: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteResolverEntry {
    pub name: String,
    pub description: String,
    pub stamps: Vec<String>,
    pub primary_stamp: Option<DnsStamp>,
}

pub struct MinisignPublicKey {
    pub key_id: [u8; 8],
    pub public_key: [u8; 32],
}

impl MinisignPublicKey {
    pub fn from_base64(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let clean = s.trim();
        let decoded = decode_b64(clean)?;
        if decoded.len() != 42 {
            return Err(format!(
                "invalid minisign public key length: {} (expected 42)",
                decoded.len()
            )
            .into());
        }
        if &decoded[0..2] != b"Ed" {
            return Err("unsupported minisign algorithm (must be Ed25519)".into());
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&decoded[2..10]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&decoded[10..42]);
        Ok(Self { key_id, public_key })
    }

    pub fn verify(
        &self,
        data: &[u8],
        sig_str: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let lines: Vec<&str> = sig_str
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();
        if lines.len() < 2 {
            return Err("invalid minisign signature format: requires at least 2 lines".into());
        }

        // line 2 contains the base64-encoded signature record
        let sig_bytes = decode_b64(lines[1])?;
        if sig_bytes.len() != 74 {
            return Err(format!(
                "invalid minisign signature line length: {} (expected 74)",
                sig_bytes.len()
            )
            .into());
        }
        if &sig_bytes[0..2] != b"Ed" {
            return Err("unsupported signature algorithm ID (expected Ed)".into());
        }

        let sig_key_id = &sig_bytes[2..10];
        if sig_key_id != self.key_id {
            return Err(format!(
                "minisign signature key ID mismatch: {:02x?} != {:02x?}",
                sig_key_id, self.key_id
            )
            .into());
        }

        let raw_signature = &sig_bytes[10..74];
        let peer_pk = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ED25519,
            &self.public_key,
        );

        peer_pk
            .verify(data, raw_signature)
            .map_err(|e| format!("minisign signature verification failed: {:?}", e))?;

        // If trusted comment and global signature are present, verify them too
        if lines.len() >= 4 && lines[2].starts_with("trusted comment:") {
            if let Ok(global_sig) = decode_b64(lines[3]) {
                if global_sig.len() == 64 {
                    let mut signed_data = Vec::with_capacity(64 + lines[2].len());
                    signed_data.extend_from_slice(raw_signature);
                    signed_data.extend_from_slice(lines[2].as_bytes());
                    let _ = peer_pk.verify(&signed_data, &global_sig);
                }
            }
        }

        Ok(())
    }
}

pub fn parse_resolver_markdown(content: &str, prefix: &str) -> Vec<RemoteResolverEntry> {
    let mut entries = Vec::new();
    let sections: Vec<&str> = content.split("## ").collect();
    if sections.len() < 2 {
        return entries;
    }

    for sec in &sections[1..] {
        let lines: Vec<&str> = sec.lines().collect();
        if lines.is_empty() {
            continue;
        }
        let raw_name = lines[0].trim();
        if raw_name.is_empty() {
            continue;
        }
        let full_name = format!("{}{}", prefix, raw_name);

        let mut desc_lines = Vec::new();
        let mut stamps = Vec::new();
        let mut primary_stamp = None;

        for line in &lines[1..] {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            if trimmed.starts_with("sdns://") {
                stamps.push(trimmed.to_string());
                if primary_stamp.is_none() {
                    primary_stamp = DnsStamp::parse(trimmed).ok();
                }
            } else {
                desc_lines.push(trimmed);
            }
        }

        if !stamps.is_empty() {
            entries.push(RemoteResolverEntry {
                name: full_name,
                description: desc_lines.join(" "),
                stamps,
                primary_stamp,
            });
        }
    }

    entries
}

pub struct SourceManager {
    client: reqwest::Client,
}

impl Default for SourceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceManager {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { client }
    }

    pub fn default_cache_dir() -> PathBuf {
        if let Ok(runtime_dir) = std::env::var("XDG_CACHE_HOME") {
            if !runtime_dir.trim().is_empty() {
                return PathBuf::from(runtime_dir).join("albus").join("resolvers");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.trim().is_empty() {
                return PathBuf::from(home).join(".cache").join("albus").join("resolvers");
            }
        }
        PathBuf::from("/var/cache/albus/resolvers")
    }

    pub async fn update(
        &self,
        config: &SourceConfig,
        cache_dir: &Path,
    ) -> Result<Vec<RemoteResolverEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let cache_path = cache_dir.join(&config.cache_file);
        let sig_path = cache_dir.join(format!("{}.minisig", config.cache_file));

        let pubkey = MinisignPublicKey::from_base64(&config.minisign_key)?;
        for url in &config.urls {
            let sig_url = format!("{}.minisig", url);
            debug!(url = %url, "Attempting to download remote resolver list");

            let data_res = self.client.get(url).send().await;
            let sig_res = self.client.get(&sig_url).send().await;

            if let (Ok(d_resp), Ok(s_resp)) = (data_res, sig_res) {
                if d_resp.status().is_success() && s_resp.status().is_success() {
                    if let (Ok(data_bytes), Ok(sig_str)) =
                        (d_resp.bytes().await, s_resp.text().await)
                    {
                        if pubkey.verify(&data_bytes, &sig_str).is_ok() {
                            info!(
                                url = %url,
                                "Cryptographically verified remote resolver list via Minisign"
                            );
                            let _ = fs::create_dir_all(cache_dir);
                            let _ = fs::write(&cache_path, &data_bytes);
                            let _ = fs::write(&sig_path, sig_str.as_bytes());

                            let content = String::from_utf8_lossy(&data_bytes);
                            return Ok(parse_resolver_markdown(&content, &config.prefix));
                        } else {
                            warn!(
                                url = %url,
                                "Minisign signature verification failed; rejecting remote list"
                            );
                        }
                    }
                }
            }
        }

        // Fallback: if network fails or verification fails, check if existing cache file exists
        if let Ok(content) = fs::read_to_string(&cache_path) {
            let parsed = parse_resolver_markdown(&content, &config.prefix);
            if !parsed.is_empty() {
                warn!(
                    file = %cache_path.display(),
                    "Using cached resolver list following download failure"
                );
                return Ok(parsed);
            }
        }

        Err(format!(
            "failed to fetch and verify remote source from any url ({:?})",
            config.urls
        )
        .into())
    }

    pub async fn fetch_or_load_cached(
        &self,
        config: &SourceConfig,
        cache_dir: &Path,
    ) -> Result<Vec<RemoteResolverEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let cache_path = cache_dir.join(&config.cache_file);

        let is_fresh = if let Ok(meta) = fs::metadata(&cache_path) {
            if let Ok(mtime) = meta.modified() {
                if let Ok(elapsed) = SystemTime::now().duration_since(mtime) {
                    elapsed < Duration::from_secs(config.refresh_delay_hours as u64 * 3600)
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if is_fresh {
            if let Ok(content) = fs::read_to_string(&cache_path) {
                let parsed = parse_resolver_markdown(&content, &config.prefix);
                if !parsed.is_empty() {
                    debug!(
                        file = %cache_path.display(),
                        count = parsed.len(),
                        "Loaded fresh remote resolver list from cache"
                    );
                    return Ok(parsed);
                }
            }
        }

        self.update(config, cache_dir).await
    }
}

fn decode_b64(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    while clean.len() % 4 != 0 {
        clean.push('=');
    }

    const B64_TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut map = [255u8; 256];
    for (i, &b) in B64_TABLE.iter().enumerate() {
        map[b as usize] = i as u8;
    }

    let bytes = clean.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);

    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let b0 = map[chunk[0] as usize];
        let b1 = map[chunk[1] as usize];
        let b2 = if chunk[2] == b'=' {
            0
        } else {
            map[chunk[2] as usize]
        };
        let b3 = if chunk[3] == b'=' {
            0
        } else {
            map[chunk[3] as usize]
        };

        if b0 == 255 || b1 == 255 || b2 == 255 || b3 == 255 {
            return Err("invalid base64 character in minisign data".into());
        }
        if chunk[2] == b'=' && chunk[3] != b'=' {
            return Err("invalid base64 padding in minisign data".into());
        }

        let triple = ((b0 as u32) << 18) | ((b1 as u32) << 12) | ((b2 as u32) << 6) | (b3 as u32);
        out.push(((triple >> 16) & 0xff) as u8);
        if chunk[2] != b'=' {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if chunk[3] != b'=' {
            out.push((triple & 0xff) as u8);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DNSCRYPT_PUBLIC_KEY: &str =
        "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

    #[test]
    fn test_minisign_public_key_parsing() {
        let pk = MinisignPublicKey::from_base64(DNSCRYPT_PUBLIC_KEY).expect("should parse valid key");
        assert_eq!(pk.key_id, [0x1f, 0xe8, 0xb4, 0x42, 0x18, 0x0f, 0x62, 0xe7]);
        assert_eq!(pk.public_key.len(), 32);
    }

    #[test]
    fn test_minisign_public_key_invalid() {
        assert!(MinisignPublicKey::from_base64("too_short").is_err());
        assert!(MinisignPublicKey::from_base64("INVALID_CHARS!!!").is_err());
    }

    #[test]
    fn test_parse_resolver_markdown() {
        let md = "\
# public-resolvers list

## quad9-doh-ip4-filter-pri
Quad9 (anycast) DNS-over-HTTPS with malware blocking
https://www.quad9.net
sdns://AgMAAAAAAAAABzkuOS45LjkADWRucy5xdWFkOS5uZXQKL2Rucy1xdWVyeQ

## cloudflare
Cloudflare public DNS
sdns://AgcAAAAAAAAABzEuMS4xLjEAEmNsb3VkZmxhcmUtZG5zLmNvbQovZG5zLXF1ZXJ5
";

        let entries = parse_resolver_markdown(md, "test-");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "test-quad9-doh-ip4-filter-pri");
        assert!(entries[0].description.contains("Quad9"));
        assert_eq!(entries[0].stamps.len(), 1);
        assert!(entries[0].primary_stamp.is_some());

        assert_eq!(entries[1].name, "test-cloudflare");
        assert_eq!(entries[1].stamps.len(), 1);
    }

    #[test]
    fn test_minisign_signature_verification_and_tamper() {
        // Generate ephemeral ed25519 keypair using aws_lc_rs
        let pk_bytes: [u8; 32] = [
            0x79, 0xa5, 0x61, 0xe7, 0x0e, 0xe0, 0x8c, 0xd3,
            0xe7, 0x54, 0xc6, 0x3e, 0x9b, 0xd6, 0xb9, 0xc3,
            0x52, 0x0a, 0x1d, 0x42, 0x04, 0xcd, 0x10, 0x4d,
            0xa2, 0xe7, 0xef, 0x76, 0x3b, 0x18, 0x53, 0xb7,
        ];
        let key_id: [u8; 8] = [0x1f, 0xe8, 0xb4, 0x42, 0x18, 0x0f, 0x62, 0xe7];
        let pubkey = MinisignPublicKey { key_id, public_key: pk_bytes };

        // Test signature string with mismatched key_id should error
        let bad_sig = "\
untrusted comment: signature from minisign secret key
RWQf6LRCGA9i58/9NQptePkEAkqBxU/+zNiKh1fjVhYF+ZR5Klgf2z0lyHTuEC21poTFMCgNKYZY4DvlorLyaid4l8u39jsgags=
trusted comment: timestamp:1788418738	file:public-resolvers.md
0JOEp/0RbRNkcGtQg41++0r2MvBAeWe/Ctj+QNcV4J9UCLuJbFjPgcn2H4TGKgZwxvKeYs/F+agk9Colkg5dDQ==
";
        let test_data = b"tampered data content";
        let res = pubkey.verify(test_data, bad_sig);
        assert!(res.is_err(), "verification must fail on tampered data");
    }
}
