//! rfc 9230 oblivious dns over https (odoh) client and hpke encryption implementation.
//!
//! decouples client ip address from dns queries using an intermediary oblivious proxy relay
//! and end-to-end hpke (hybrid public key encryption, rfc 9180) encryption to the target resolver.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hpke::{
    aead::ChaCha20Poly1305 as HpkeAead, kdf::HkdfSha256 as HpkeKdf,
    kem::X25519HkdfSha256 as HpkeKem, Deserializable, Kem, OpModeS, Serializable,
};
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use url::Url;

pub const ODOH_HTTP_HEADER: &str = "application/oblivious-dns-message";

// hpke cipher suite constants per rfc 9230 section 5
pub const KEM_DHKEM_X25519_HKDF_SHA256: u16 = 0x0020;
pub const KDF_HKDF_SHA256: u16 = 0x0001;
pub const AEAD_CHACHA20_POLY1305: u16 = 0x0003;
pub const ODOH_VERSION_1: u16 = 0x0001;

pub const DEFAULT_ODOH_RELAY: &str = "https://odoh.cloudflare-dns.com/dns-query";
pub const DEFAULT_ODOH_TARGET: &str = "https://odoh.cloudflare-dns.com/dns-query";

/// parsed representation of a target's rfc 9230 public key configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ODoHConfigContents {
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    pub public_key: Vec<u8>,
}

impl ODoHConfigContents {
    /// serializes the config contents into tls presentation wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(6 + 2 + self.public_key.len());
        buf.extend_from_slice(&self.kem_id.to_be_bytes());
        buf.extend_from_slice(&self.kdf_id.to_be_bytes());
        buf.extend_from_slice(&self.aead_id.to_be_bytes());
        buf.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.public_key);
        buf
    }

    /// computes the 32-byte key_id per rfc 9230 section 6.1:
    /// key_id = Expand(Extract("", config), "odoh key id", Nh)
    pub fn compute_key_id(&self) -> [u8; 32] {
        let raw_config = self.encode();
        let hk = Hkdf::<Sha256>::new(None, &raw_config);
        let mut key_id = [0u8; 32];
        hk.expand(b"odoh key id", &mut key_id)
            .expect("32 bytes is valid length for sha256 hkdf");
        key_id
    }
}

/// rfc 9230 versioned odoh config container
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ODoHConfig {
    pub version: u16,
    pub contents: ODoHConfigContents,
}

impl ODoHConfig {
    /// parses an obliviousdohconfigs structure (rfc 9230 section 5) from raw bytes
    pub fn parse_configs(
        bytes: &[u8],
    ) -> Result<Vec<Self>, Box<dyn std::error::Error + Send + Sync>> {
        if bytes.len() < 2 {
            return Err("odohconfigs payload too short".into());
        }

        let total_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        let mut pos = 2;
        let limit = (pos + total_len).min(bytes.len());
        let mut configs = Vec::new();

        while pos + 4 <= limit {
            let version = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
            let length = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
            pos += 4;

            if pos + length > limit {
                break;
            }

            let contents_bytes = &bytes[pos..pos + length];
            pos += length;

            if version == ODOH_VERSION_1 && contents_bytes.len() >= 8 {
                let kem_id = u16::from_be_bytes([contents_bytes[0], contents_bytes[1]]);
                let kdf_id = u16::from_be_bytes([contents_bytes[2], contents_bytes[3]]);
                let aead_id = u16::from_be_bytes([contents_bytes[4], contents_bytes[5]]);
                let pk_len = u16::from_be_bytes([contents_bytes[6], contents_bytes[7]]) as usize;

                if contents_bytes.len() >= 8 + pk_len {
                    let public_key = contents_bytes[8..8 + pk_len].to_vec();
                    configs.push(ODoHConfig {
                        version,
                        contents: ODoHConfigContents {
                            kem_id,
                            kdf_id,
                            aead_id,
                            public_key,
                        },
                    });
                }
            }
        }

        if configs.is_empty() {
            Err("no compatible odoh configurations found in payload".into())
        } else {
            Ok(configs)
        }
    }
}

/// state retained across request to decrypt the corresponding oblivious response
pub struct ODoHContext {
    sender_ctx: hpke::aead::AeadCtxS<HpkeAead, HpkeKdf, HpkeKem>,
    q_plain: Vec<u8>,
}

/// client orchestrator handling oblivious query encapsulation and relay dispatch
pub struct ODoHClient {
    pub relay_url: Url,
    pub target_url: Url,
    client: reqwest::Client,
    cached_config: Arc<RwLock<Option<ODoHConfigContents>>>,
}

impl ODoHClient {
    pub fn new(
        relay_url_str: &str,
        target_url_str: &str,
        client: reqwest::Client,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let relay_url = Url::parse(relay_url_str)?;
        let target_url = Url::parse(target_url_str)?;

        if relay_url.scheme() != "https" || target_url.scheme() != "https" {
            return Err("both oblivious relay and target URLs must use HTTPS".into());
        }

        Ok(Self {
            relay_url,
            target_url,
            client,
            cached_config: Arc::new(RwLock::new(None)),
        })
    }

    /// fetches target resolver's public key configuration from `/.well-known/odohconfigs`
    pub async fn fetch_target_config(
        &self,
    ) -> Result<ODoHConfigContents, Box<dyn std::error::Error + Send + Sync>> {
        // return cached config if already resolved
        {
            let lock = self.cached_config.read().await;
            if let Some(ref c) = *lock {
                return Ok(c.clone());
            }
        }

        let mut config_url = self.target_url.clone();
        config_url.set_path("/.well-known/odohconfigs");
        config_url.set_query(None);

        debug!(url = %config_url, "fetching odoh target configuration");
        let mut resp = self
            .client
            .get(config_url.as_str())
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(format!("failed to fetch odohconfigs: HTTP {}", resp.status()).into());
        }

        if let Some(content_len) = resp.content_length() {
            if content_len > 65536 {
                return Err(format!(
                    "odohconfigs length {} exceeds maximum allowed (65536 bytes)",
                    content_len
                )
                .into());
            }
        }

        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > 65536 {
                return Err("odohconfigs body exceeds 64 KB limit".into());
            }
            body.extend_from_slice(&chunk);
        }
        let configs = ODoHConfig::parse_configs(&body)?;

        // select best matching configuration (prefer x25519 + chacha20poly1305)
        let selected = configs
            .into_iter()
            .find(|c| {
                c.contents.kem_id == KEM_DHKEM_X25519_HKDF_SHA256
                    && c.contents.aead_id == AEAD_CHACHA20_POLY1305
            })
            .or_else(|| None)
            .ok_or_else(|| {
                "no compatible X25519+ChaCha20Poly1305 cipher suite found in target odohconfigs"
            })?;

        let contents = selected.contents;
        {
            let mut lock = self.cached_config.write().await;
            *lock = Some(contents.clone());
        }

        info!(target = %self.target_url, "odoh target public key configuration cached");
        Ok(contents)
    }

    /// manually injects a known target config (e.g. from a dns stamp sdns://)
    pub async fn set_target_config(&self, config: ODoHConfigContents) {
        let mut lock = self.cached_config.write().await;
        *lock = Some(config);
    }

    /// clears cached target configuration, forcing re-fetch on next query (e.g. after key rotation)
    pub async fn invalidate_target_config(&self) {
        let mut lock = self.cached_config.write().await;
        *lock = None;
    }

    /// encrypts a raw dns wire query into an oblivious doh query message (rfc 9230 section 6-7)
    pub fn encrypt_query(
        &self,
        dns_query: &[u8],
        target_cfg: &ODoHConfigContents,
    ) -> Result<(Vec<u8>, ODoHContext), Box<dyn std::error::Error + Send + Sync>> {
        if dns_query.is_empty() || dns_query.len() > 65535 {
            return Err("invalid dns query length for odoh encapsulation".into());
        }

        // 1. format ObliviousDoHMessagePlaintext (query + padding)
        let pad_len = match dns_query.len() {
            0..=128 => 128 - dns_query.len(),
            129..=256 => 256 - dns_query.len(),
            257..=512 => 512 - dns_query.len(),
            _ => 0,
        };

        let mut q_plain = Vec::with_capacity(2 + dns_query.len() + 2 + pad_len);
        q_plain.extend_from_slice(&(dns_query.len() as u16).to_be_bytes());
        q_plain.extend_from_slice(dns_query);
        q_plain.extend_from_slice(&(pad_len as u16).to_be_bytes());
        q_plain.extend(std::iter::repeat(0u8).take(pad_len));

        // 2. deserialize target public key
        let server_pk = <HpkeKem as Kem>::PublicKey::from_bytes(&target_cfg.public_key)
            .map_err(|e| format!("invalid target x25519 public key: {:?}", e))?;

        // 3. setup hpke sender context with info "odoh query"
        let (encapped_key, mut sender_ctx) = hpke::setup_sender::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeS::Base,
            &server_pk,
            b"odoh query",
        )
        .map_err(|e| format!("hpke setup_sender failed: {:?}", e))?;

        let key_id = target_cfg.compute_key_id();

        // 4. aad = 0x01 || len(key_id) || key_id
        let mut aad = Vec::with_capacity(1 + 2 + key_id.len());
        aad.push(0x01);
        aad.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
        aad.extend_from_slice(&key_id);

        // 5. encrypt query plaintext
        let mut ct = q_plain.clone();
        let tag = sender_ctx
            .seal_inout_detached(hpke::inout::InOutBuf::from(ct.as_mut_slice()), &aad)
            .map_err(|e| format!("hpke seal failed: {:?}", e))?;

        let mut q_encrypted = encapped_key.to_bytes().to_vec();
        q_encrypted.extend_from_slice(&ct);
        q_encrypted.extend_from_slice(&tag.to_bytes());

        // 6. format outer ObliviousDoHMessage (type 0x01 = query)
        let mut msg = Vec::with_capacity(1 + 2 + key_id.len() + 2 + q_encrypted.len());
        msg.push(0x01); // message_type = query
        msg.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
        msg.extend_from_slice(&key_id);
        msg.extend_from_slice(&(q_encrypted.len() as u16).to_be_bytes());
        msg.extend_from_slice(&q_encrypted);

        Ok((
            msg,
            ODoHContext {
                sender_ctx,
                q_plain,
            },
        ))
    }

    /// decrypts an oblivious doh response message (rfc 9230 section 6.2)
    pub fn decrypt_response(
        &self,
        ctx: ODoHContext,
        response_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if response_bytes.len() < 5 {
            return Err("odoh response payload too short".into());
        }

        let msg_type = response_bytes[0];
        if msg_type != 0x02 {
            return Err(format!(
                "unexpected odoh message type: expected 0x02, got 0x{:02x}",
                msg_type
            )
            .into());
        }

        let key_id_len = u16::from_be_bytes([response_bytes[1], response_bytes[2]]) as usize;
        let mut pos = 3;
        if pos + key_id_len + 2 > response_bytes.len() {
            return Err("truncated key_id / resp_nonce in odoh response".into());
        }

        let resp_nonce = &response_bytes[pos..pos + key_id_len];
        pos += key_id_len;

        let r_enc_len = u16::from_be_bytes([response_bytes[pos], response_bytes[pos + 1]]) as usize;
        pos += 2;

        if pos + r_enc_len > response_bytes.len() {
            return Err("truncated encrypted_message in odoh response".into());
        }
        let r_encrypted = &response_bytes[pos..pos + r_enc_len];

        // derive response decryption secrets per rfc 9230 section 5.2
        let mut secret = [0u8; 32];
        ctx.sender_ctx
            .export(b"odoh response", &mut secret)
            .map_err(|e| format!("hpke export secret failed: {:?}", e))?;

        // salt = Q_plain || len(resp_nonce) || resp_nonce
        let mut salt = Vec::with_capacity(ctx.q_plain.len() + 2 + resp_nonce.len());
        salt.extend_from_slice(&ctx.q_plain);
        salt.extend_from_slice(&(resp_nonce.len() as u16).to_be_bytes());
        salt.extend_from_slice(resp_nonce);

        let hk = Hkdf::<Sha256>::new(Some(&salt), &secret);
        let mut aead_key_bytes = [0u8; 32];
        let mut aead_nonce_bytes = [0u8; 12];

        hk.expand(b"odoh key", &mut aead_key_bytes)
            .map_err(|e| format!("hkdf expand odoh key failed: {:?}", e))?;
        hk.expand(b"odoh nonce", &mut aead_nonce_bytes)
            .map_err(|e| format!("hkdf expand odoh nonce failed: {:?}", e))?;

        // aad = 0x02 || len(resp_nonce) || resp_nonce
        let mut aad = Vec::with_capacity(1 + 2 + resp_nonce.len());
        aad.push(0x02);
        aad.extend_from_slice(&(resp_nonce.len() as u16).to_be_bytes());
        aad.extend_from_slice(resp_nonce);

        // decrypt via chacha20poly1305
        let cipher = ChaCha20Poly1305::new(&Key::from(aead_key_bytes));
        let nonce = Nonce::from(aead_nonce_bytes);

        let payload = Payload {
            msg: r_encrypted,
            aad: &aad,
        };

        let r_plain = cipher
            .decrypt(&nonce, payload)
            .map_err(|_| "aead authentication failure during odoh response decryption")?;

        if r_plain.len() < 4 {
            return Err("decrypted odoh plaintext response too short".into());
        }

        let dns_len = u16::from_be_bytes([r_plain[0], r_plain[1]]) as usize;
        let padding_offset = 2 + dns_len;
        if padding_offset + 2 > r_plain.len() {
            return Err("dns response length exceeds plaintext bounds".into());
        }

        let pad_len =
            u16::from_be_bytes([r_plain[padding_offset], r_plain[padding_offset + 1]]) as usize;
        if padding_offset + 2 + pad_len != r_plain.len() {
            return Err("invalid padding length in odoh response plaintext".into());
        }

        // constant-time verification that all padding bytes are 0x00 per RFC 9230 Section 6.2
        let padding_bytes = &r_plain[padding_offset + 2..];
        let mut non_zero: u8 = 0;
        for &b in padding_bytes {
            non_zero |= b;
        }
        if non_zero != 0 {
            return Err("non-zero padding bytes detected in odoh response plaintext".into());
        }

        let mut dns_response = r_plain[2..2 + dns_len].to_vec();

        // restore original query transaction id so client receives matching transaction identifier
        if dns_response.len() >= 2 && ctx.q_plain.len() >= 4 {
            dns_response[0] = ctx.q_plain[2];
            dns_response[1] = ctx.q_plain[3];
        }

        Ok(dns_response)
    }

    /// performs complete oblivious dns query dispatch through relay proxy to target resolver.
    /// includes automatic target key refresh retry if relay/target reports 401 key rollover.
    pub async fn resolve(
        &self,
        dns_query: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        for attempt in 0..2 {
            let config = self.fetch_target_config().await?;
            let (encrypted_body, context) = self.encrypt_query(dns_query, &config)?;

            // build proxy request url per rfc 9230 section 4.1:
            // https://proxy.example/dns-query?targethost=target.example&targetpath=/dns-query
            let mut req_url = self.relay_url.clone();
            let target_host = self
                .target_url
                .host_str()
                .unwrap_or("odoh.cloudflare-dns.com");
            let target_path = self.target_url.path();

            req_url
                .query_pairs_mut()
                .append_pair("targethost", target_host)
                .append_pair("targetpath", target_path);

            debug!(relay = %self.relay_url, target = %target_host, "dispatching encrypted oblivious doh query");

            let mut response = self
                .client
                .post(req_url.as_str())
                .header("Content-Type", ODOH_HTTP_HEADER)
                .header("Accept", ODOH_HTTP_HEADER)
                .body(encrypted_body)
                .timeout(Duration::from_secs(6))
                .send()
                .await?;

            // HTTP 401 Unauthorized or 200 with empty body indicates target key rotation
            if response.status() == reqwest::StatusCode::UNAUTHORIZED
                || (response.status().is_success() && response.content_length() == Some(0))
            {
                if attempt == 0 {
                    warn!("odoh target returned 401 / empty body; invalidating cached key and retrying");
                    self.invalidate_target_config().await;
                    continue;
                }
            }

            if !response.status().is_success() {
                return Err(format!(
                    "odoh relay returned error status: HTTP {}",
                    response.status()
                )
                .into());
            }

            if let Some(content_len) = response.content_length() {
                if content_len > 65536 {
                    return Err(format!(
                        "odoh response length {} exceeds maximum allowed (65536 bytes)",
                        content_len
                    )
                    .into());
                }
            }

            let mut resp_bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if resp_bytes.len() + chunk.len() > 65536 {
                    return Err("odoh response body exceeds 64 KB limit".into());
                }
                resp_bytes.extend_from_slice(&chunk);
            }
            if resp_bytes.is_empty() {
                if attempt == 0 {
                    warn!("odoh relay returned empty response body; invalidating cached key and retrying");
                    self.invalidate_target_config().await;
                    continue;
                }
                return Err("odoh relay returned empty response body".into());
            }

            let decrypted_dns = self.decrypt_response(context, &resp_bytes)?;
            return Ok(decrypted_dns);
        }

        Err("odoh query resolution failed after key refresh retry".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_odoh_config_encoding_and_key_id() {
        let dummy_pk = vec![0x42u8; 32];
        let contents = ODoHConfigContents {
            kem_id: KEM_DHKEM_X25519_HKDF_SHA256,
            kdf_id: KDF_HKDF_SHA256,
            aead_id: AEAD_CHACHA20_POLY1305,
            public_key: dummy_pk.clone(),
        };

        let encoded = contents.encode();
        assert_eq!(encoded.len(), 6 + 2 + 32);

        let key_id = contents.compute_key_id();
        assert_eq!(key_id.len(), 32);
    }

    #[test]
    fn test_odoh_config_parser() {
        let dummy_pk = vec![0xAAu8; 32];
        let mut raw = Vec::new();

        let inner_len = 6 + 2 + 32;
        let entry_len = 4 + inner_len;
        raw.extend_from_slice(&(entry_len as u16).to_be_bytes()); // total configs len

        raw.extend_from_slice(&1u16.to_be_bytes()); // version
        raw.extend_from_slice(&(inner_len as u16).to_be_bytes()); // length

        raw.extend_from_slice(&KEM_DHKEM_X25519_HKDF_SHA256.to_be_bytes());
        raw.extend_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
        raw.extend_from_slice(&AEAD_CHACHA20_POLY1305.to_be_bytes());
        raw.extend_from_slice(&(32u16).to_be_bytes());
        raw.extend_from_slice(&dummy_pk);

        let parsed = ODoHConfig::parse_configs(&raw).expect("should parse valid odohconfigs");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].contents.kem_id, KEM_DHKEM_X25519_HKDF_SHA256);
        assert_eq!(parsed[0].contents.public_key, dummy_pk);
    }

    #[test]
    fn test_odoh_query_encrypt_structure() {
        let (_server_sk, server_pk) = <HpkeKem as Kem>::gen_keypair();
        let contents = ODoHConfigContents {
            kem_id: KEM_DHKEM_X25519_HKDF_SHA256,
            kdf_id: KDF_HKDF_SHA256,
            aead_id: AEAD_CHACHA20_POLY1305,
            public_key: server_pk.to_bytes().to_vec(),
        };

        let client = ODoHClient::new(
            DEFAULT_ODOH_RELAY,
            DEFAULT_ODOH_TARGET,
            reqwest::Client::new(),
        )
        .unwrap();
        let query_payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

        let (encrypted_wire, _ctx) = client
            .encrypt_query(query_payload, &contents)
            .expect("encryption should succeed");
        assert_eq!(encrypted_wire[0], 0x01, "message_type must be query (0x01)");
    }

    #[test]
    fn test_odoh_full_encryption_roundtrip() {
        use hpke::OpModeR;

        // 1. Generate target server keypair
        let (server_sk, server_pk) = <HpkeKem as Kem>::gen_keypair();
        let contents = ODoHConfigContents {
            kem_id: KEM_DHKEM_X25519_HKDF_SHA256,
            kdf_id: KDF_HKDF_SHA256,
            aead_id: AEAD_CHACHA20_POLY1305,
            public_key: server_pk.to_bytes().to_vec(),
        };

        let client = ODoHClient::new(
            DEFAULT_ODOH_RELAY,
            DEFAULT_ODOH_TARGET,
            reqwest::Client::new(),
        )
        .unwrap();
        let dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

        // 2. Client encrypts query
        let (query_msg, client_ctx) = client
            .encrypt_query(dns_query, &contents)
            .expect("encrypt query");
        assert_eq!(query_msg[0], 0x01);

        let key_id_len = u16::from_be_bytes([query_msg[1], query_msg[2]]) as usize;
        let key_id = &query_msg[3..3 + key_id_len];
        assert_eq!(key_id, &contents.compute_key_id());

        let q_enc_pos = 3 + key_id_len;
        let q_enc_len =
            u16::from_be_bytes([query_msg[q_enc_pos], query_msg[q_enc_pos + 1]]) as usize;
        let q_enc = &query_msg[q_enc_pos + 2..q_enc_pos + 2 + q_enc_len];

        // 3. Server receives and decrypts query
        let encapped_key = <HpkeKem as Kem>::EncappedKey::from_bytes(&q_enc[..32])
            .expect("deserialize encapped pk");
        let mut receiver_ctx = hpke::setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &server_sk,
            &encapped_key,
            b"odoh query",
        )
        .expect("hpke setup_receiver");

        let mut aad = Vec::with_capacity(1 + 2 + key_id.len());
        aad.push(0x01);
        aad.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
        aad.extend_from_slice(key_id);

        let tag_bytes = &q_enc[q_enc.len() - 16..];
        let tag = hpke::aead::AeadTag::<HpkeAead>::from_bytes(tag_bytes).expect("tag bytes");
        let mut ct = q_enc[32..q_enc.len() - 16].to_vec();

        receiver_ctx
            .open_inout_detached(hpke::inout::InOutBuf::from(ct.as_mut_slice()), &aad, &tag)
            .expect("receiver open ciphertext");

        let q_plain = ct;
        let query_len = u16::from_be_bytes([q_plain[0], q_plain[1]]) as usize;
        let decrypted_query = &q_plain[2..2 + query_len];
        assert_eq!(decrypted_query, dns_query);

        // 4. Server formulates DNS response & encrypts it
        let mock_dns_response = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22";
        let pad_len = 16usize;
        let mut r_plain = Vec::new();
        r_plain.extend_from_slice(&(mock_dns_response.len() as u16).to_be_bytes());
        r_plain.extend_from_slice(mock_dns_response);
        r_plain.extend_from_slice(&(pad_len as u16).to_be_bytes());
        r_plain.extend(std::iter::repeat(0u8).take(pad_len));

        let resp_nonce = [0x55u8; 32];
        let mut resp_secret = [0u8; 32];
        receiver_ctx
            .export(b"odoh response", &mut resp_secret)
            .expect("export secret");

        let mut salt = Vec::with_capacity(q_plain.len() + 2 + resp_nonce.len());
        salt.extend_from_slice(&q_plain);
        salt.extend_from_slice(&(resp_nonce.len() as u16).to_be_bytes());
        salt.extend_from_slice(&resp_nonce);

        let hk = Hkdf::<Sha256>::new(Some(&salt), &resp_secret);
        let mut aead_key = [0u8; 32];
        let mut aead_nonce = [0u8; 12];
        hk.expand(b"odoh key", &mut aead_key).unwrap();
        hk.expand(b"odoh nonce", &mut aead_nonce).unwrap();

        let mut resp_aad = Vec::with_capacity(1 + 2 + resp_nonce.len());
        resp_aad.push(0x02);
        resp_aad.extend_from_slice(&(resp_nonce.len() as u16).to_be_bytes());
        resp_aad.extend_from_slice(&resp_nonce);

        let cipher = ChaCha20Poly1305::new(&Key::from(aead_key));
        let nonce = Nonce::from(aead_nonce);
        let r_encrypted = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &r_plain,
                    aad: &resp_aad,
                },
            )
            .unwrap();

        let mut resp_msg = Vec::new();
        resp_msg.push(0x02); // type response
        resp_msg.extend_from_slice(&(resp_nonce.len() as u16).to_be_bytes());
        resp_msg.extend_from_slice(&resp_nonce);
        resp_msg.extend_from_slice(&(r_encrypted.len() as u16).to_be_bytes());
        resp_msg.extend_from_slice(&r_encrypted);

        // 5. Client receives and decrypts response
        let client_decrypted = client
            .decrypt_response(client_ctx, &resp_msg)
            .expect("client decrypt response");
        assert_eq!(client_decrypted, mock_dns_response);
    }
}
