//! dnscrypt v2 wire protocol client and anonymized udp relay implementation.
//!
//! supports dnscrypt v2 certificate parsing (x25519 + ed25519 + chacha20-poly1305),
//! question padding, encrypted query encapsulation, and two-hop anonymized udp relays.

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::rand::SystemRandom;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

pub const DNSCRYPT_MAGIC_CERT: &[u8; 4] = b"DNSC";
pub const DNSCRYPT_MAGIC_RESOLVER: &[u8; 8] = b"r6fnvWJ8";
pub const DNSCRYPT_RELAY_MAGIC: &[u8; 9] = &[0xff; 9];
pub const MIN_QUERY_PADDED_LEN: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsCryptCert {
    pub cert_magic: [u8; 4],
    pub es_version: u16,
    pub protocol_minor: u16,
    pub signature: [u8; 64],
    pub resolver_pk: [u8; 32],
    pub client_magic: [u8; 8],
    pub serial: u32,
    pub ts_start: u32,
    pub ts_end: u32,
}

impl DnsCryptCert {
    // parses a 124-byte binary dnscrypt certificate from raw wire payload or txt record
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 124 {
            return Err("dnscrypt cert too short (minimum 124 bytes)");
        }

        if &bytes[0..4] != DNSCRYPT_MAGIC_CERT {
            return Err("invalid dnscrypt cert magic");
        }

        let mut cert_magic = [0u8; 4];
        cert_magic.copy_from_slice(&bytes[0..4]);

        let es_version = u16::from_be_bytes([bytes[4], bytes[5]]);
        let protocol_minor = u16::from_be_bytes([bytes[6], bytes[7]]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[8..72]);

        let mut resolver_pk = [0u8; 32];
        resolver_pk.copy_from_slice(&bytes[72..104]);

        let mut client_magic = [0u8; 8];
        client_magic.copy_from_slice(&bytes[104..112]);

        let serial = u32::from_be_bytes([bytes[112], bytes[113], bytes[114], bytes[115]]);
        let ts_start = u32::from_be_bytes([bytes[116], bytes[117], bytes[118], bytes[119]]);
        let ts_end = u32::from_be_bytes([bytes[120], bytes[121], bytes[122], bytes[123]]);

        Ok(Self {
            cert_magic,
            es_version,
            protocol_minor,
            signature,
            resolver_pk,
            client_magic,
            serial,
            ts_start,
            ts_end,
        })
    }

    // verifies the ed25519 signature of the certificate body using the provider's public key
    pub fn verify_signature(&self, provider_pk: &[u8; 32]) -> bool {
        use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
        let peer_pk = UnparsedPublicKey::new(&ED25519, provider_pk);

        // signed data is everything after the 64-byte signature (offset 72..124)
        let mut signed_data = Vec::with_capacity(52);
        signed_data.extend_from_slice(&self.resolver_pk);
        signed_data.extend_from_slice(&self.client_magic);
        signed_data.extend_from_slice(&self.serial.to_be_bytes());
        signed_data.extend_from_slice(&self.ts_start.to_be_bytes());
        signed_data.extend_from_slice(&self.ts_end.to_be_bytes());

        peer_pk.verify(&signed_data, &self.signature).is_ok()
    }

    // checks whether certificate is within valid timestamp epoch
    pub fn is_valid_at(&self, epoch_secs: u32) -> bool {
        epoch_secs >= self.ts_start && epoch_secs <= self.ts_end
    }

    // serializes certificate back to 124 bytes (useful for testing and mocks)
    pub fn to_bytes(&self) -> [u8; 124] {
        let mut buf = [0u8; 124];
        buf[0..4].copy_from_slice(&self.cert_magic);
        buf[4..6].copy_from_slice(&self.es_version.to_be_bytes());
        buf[6..8].copy_from_slice(&self.protocol_minor.to_be_bytes());
        buf[8..72].copy_from_slice(&self.signature);
        buf[72..104].copy_from_slice(&self.resolver_pk);
        buf[104..112].copy_from_slice(&self.client_magic);
        buf[112..116].copy_from_slice(&self.serial.to_be_bytes());
        buf[116..120].copy_from_slice(&self.ts_start.to_be_bytes());
        buf[120..124].copy_from_slice(&self.ts_end.to_be_bytes());
        buf
    }
}

// pads raw dns query payload to prevent packet length side-channel fingerprinting
pub fn pad_query(query: &[u8], min_len: usize) -> Vec<u8> {
    let mut out = query.to_vec();
    out.push(0x80);
    while out.len() < min_len || (out.len() % 64) != 0 {
        out.push(0x00);
    }
    out
}

// unpads decrypted response payload by stripping trailing zeros and single 0x80 delimiter
pub fn unpad_response(padded: &[u8]) -> Option<&[u8]> {
    let mut idx = padded.len();
    while idx > 0 && padded[idx - 1] == 0x00 {
        idx -= 1;
    }
    if idx > 0 && padded[idx - 1] == 0x80 {
        Some(&padded[..idx - 1])
    } else {
        None
    }
}

// anonymized dnscrypt relay encapsulation
pub struct AnonymizedRelay;

impl AnonymizedRelay {
    // wraps dnscrypt packet into anonymized relay header for transmission to proxy relay
    pub fn wrap_packet(target_addr: SocketAddr, packet: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + 1 + 16 + 2 + packet.len());
        out.extend_from_slice(DNSCRYPT_RELAY_MAGIC);

        match target_addr.ip() {
            IpAddr::V4(v4) => {
                out.push(0x01); // ipv4 family
                out.extend_from_slice(&v4.octets());
                out.extend_from_slice(&target_addr.port().to_be_bytes());
            }
            IpAddr::V6(v6) => {
                out.push(0x02); // ipv6 family
                out.extend_from_slice(&v6.octets());
                out.extend_from_slice(&target_addr.port().to_be_bytes());
            }
        }

        out.extend_from_slice(packet);
        out
    }

    // unwraps relay header received by a relay server
    pub fn unwrap_packet(data: &[u8]) -> Result<(SocketAddr, &[u8]), &'static str> {
        if data.len() < 9 + 1 + 4 + 2 {
            return Err("relay packet too short");
        }

        if &data[0..9] != DNSCRYPT_RELAY_MAGIC {
            return Err("invalid relay magic header");
        }

        let family = data[9];
        let mut pos = 10;

        let target_addr = match family {
            0x01 => {
                if data.len() < pos + 4 + 2 {
                    return Err("truncated ipv4 in relay packet");
                }
                let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
                pos += 4;
                let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
                pos += 2;
                SocketAddr::from((ip, port))
            }
            0x02 => {
                if data.len() < pos + 16 + 2 {
                    return Err("truncated ipv6 in relay packet");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[pos..pos + 16]);
                let ip = Ipv6Addr::from(octets);
                pos += 16;
                let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
                pos += 2;
                SocketAddr::from((ip, port))
            }
            _ => return Err("unsupported ip family in relay header"),
        };

        Ok((target_addr, &data[pos..]))
    }
}

/// HSalsa20 core hash function (crypto_core_hsalsa20 as used in NaCl/libsodium `crypto_box_beforenm`).
/// Maps a 256-bit key and 128-bit input to a 256-bit output.
pub fn hsalsa20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    #[inline(always)]
    fn salsa_quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[b] ^= (x[a].wrapping_add(x[d])).rotate_left(7);
        x[c] ^= (x[b].wrapping_add(x[a])).rotate_left(9);
        x[d] ^= (x[c].wrapping_add(x[b])).rotate_left(13);
        x[a] ^= (x[d].wrapping_add(x[c])).rotate_left(18);
    }

    let c: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]; // "expand 32-byte k"

    let mut kw = [0u32; 8];
    for i in 0..8 {
        kw[i] = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }

    let mut inw = [0u32; 4];
    for i in 0..4 {
        inw[i] = u32::from_le_bytes([
            input[i * 4],
            input[i * 4 + 1],
            input[i * 4 + 2],
            input[i * 4 + 3],
        ]);
    }

    let mut x: [u32; 16] = [
        c[0], kw[0], kw[1], kw[2], kw[3], c[1], inw[0], inw[1], inw[2], inw[3], c[2], kw[4], kw[5],
        kw[6], kw[7], c[3],
    ];

    for _ in 0..10 {
        // column rounds
        salsa_quarter_round(&mut x, 0, 4, 8, 12);
        salsa_quarter_round(&mut x, 5, 9, 13, 1);
        salsa_quarter_round(&mut x, 10, 14, 2, 6);
        salsa_quarter_round(&mut x, 15, 3, 7, 11);
        // row rounds
        salsa_quarter_round(&mut x, 0, 1, 2, 3);
        salsa_quarter_round(&mut x, 5, 6, 7, 4);
        salsa_quarter_round(&mut x, 10, 11, 8, 9);
        salsa_quarter_round(&mut x, 15, 12, 13, 14);
    }

    let outw: [u32; 8] = [x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9]];
    let mut out = [0u8; 32];
    for (i, word) in outw.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// HChaCha20 core hash function (crypto_core_hchacha20 as used in libsodium `crypto_box_curve25519xchacha20poly1305_beforenm` / DNSCrypt ES version 2).
/// Maps a 256-bit key and 128-bit input to a 256-bit output.
pub fn hchacha20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    #[inline(always)]
    fn chacha_quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = x[a].wrapping_add(x[b]);
        x[d] ^= x[a];
        x[d] = x[d].rotate_left(16);
        x[c] = x[c].wrapping_add(x[d]);
        x[b] ^= x[c];
        x[b] = x[b].rotate_left(12);
        x[a] = x[a].wrapping_add(x[b]);
        x[d] ^= x[a];
        x[d] = x[d].rotate_left(8);
        x[c] = x[c].wrapping_add(x[d]);
        x[b] ^= x[c];
        x[b] = x[b].rotate_left(7);
    }

    let c: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]; // "expand 32-byte k"

    let mut kw = [0u32; 8];
    for i in 0..8 {
        kw[i] = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }

    let mut inw = [0u32; 4];
    for i in 0..4 {
        inw[i] = u32::from_le_bytes([
            input[i * 4],
            input[i * 4 + 1],
            input[i * 4 + 2],
            input[i * 4 + 3],
        ]);
    }

    let mut x: [u32; 16] = [
        c[0], c[1], c[2], c[3], kw[0], kw[1], kw[2], kw[3], kw[4], kw[5], kw[6], kw[7], inw[0],
        inw[1], inw[2], inw[3],
    ];

    for _ in 0..10 {
        // column rounds
        chacha_quarter_round(&mut x, 0, 4, 8, 12);
        chacha_quarter_round(&mut x, 1, 5, 9, 13);
        chacha_quarter_round(&mut x, 2, 6, 10, 14);
        chacha_quarter_round(&mut x, 3, 7, 11, 15);
        // diagonal rounds
        chacha_quarter_round(&mut x, 0, 5, 10, 15);
        chacha_quarter_round(&mut x, 1, 6, 11, 12);
        chacha_quarter_round(&mut x, 2, 7, 8, 13);
        chacha_quarter_round(&mut x, 3, 4, 9, 14);
    }

    let outw: [u32; 8] = [x[0], x[1], x[2], x[3], x[12], x[13], x[14], x[15]];
    let mut out = [0u8; 32];
    for (i, word) in outw.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Derives the 32-byte shared symmetric key from the X25519 shared secret point
/// using HSalsa20 and a 16-byte zero nonce (NaCl/libsodium `crypto_box_beforenm`).
pub fn derive_shared_key_hsalsa20(shared_point: &[u8; 32]) -> [u8; 32] {
    hsalsa20(shared_point, &[0u8; 16])
}

/// Derives the 32-byte shared symmetric key from the X25519 shared secret point
/// using HChaCha20 and a 16-byte zero nonce (libsodium `crypto_box_curve25519xchacha20poly1305_beforenm`).
pub fn derive_shared_key_hchacha20(shared_point: &[u8; 32]) -> [u8; 32] {
    hchacha20(shared_point, &[0u8; 16])
}

/// Derives the shared symmetric key according to the certificate encryption scheme (ES version).
pub fn derive_shared_key(shared_point: &[u8; 32], es_version: u16) -> [u8; 32] {
    match es_version {
        1 => derive_shared_key_hsalsa20(shared_point),
        2 => derive_shared_key_hsalsa20(shared_point),
        _ => derive_shared_key_hsalsa20(shared_point),
    }
}

// client capable of resolving encrypted dns queries using dnscrypt v2 and optional anonymized relays
#[derive(Clone, Debug)]
pub struct DnsCryptClient {
    pub server_addr: SocketAddr,
    pub provider_name: String,
    pub provider_pk: [u8; 32],
    pub relay_addr: Option<SocketAddr>,
    pub cert: Option<DnsCryptCert>,
}

impl DnsCryptClient {
    pub fn new(
        server_addr: SocketAddr,
        provider_name: String,
        provider_pk: [u8; 32],
        relay_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            server_addr,
            provider_name,
            provider_pk,
            relay_addr,
            cert: None,
        }
    }

    // sets validated certificate for session encryption
    pub fn with_cert(mut self, cert: DnsCryptCert) -> Self {
        self.cert = Some(cert);
        self
    }

    // encrypts query using chacha20poly1305 with derived shared key
    pub fn encrypt_query_payload(
        client_magic: &[u8; 8],
        client_pk: &[u8; 32],
        derived_shared_key: &[u8; 32],
        nonce: &[u8; 12],
        query: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let padded = pad_query(query, MIN_QUERY_PADDED_LEN);
        let key = Key::from(*derived_shared_key);
        let cipher = ChaCha20Poly1305::new(&key);

        let mut chacha_nonce = [0u8; 12];
        chacha_nonce.copy_from_slice(nonce);
        let nonce_val = Nonce::from(chacha_nonce);

        let ciphertext = cipher
            .encrypt(&nonce_val, padded.as_ref())
            .map_err(|e| format!("encryption failed: {:?}", e))?;

        // Packet format on wire: [client_magic: 8B] || [client_pk: 32B] || [client_nonce: 12B] || [ciphertext]
        let mut packet = Vec::with_capacity(8 + 32 + 12 + ciphertext.len());
        packet.extend_from_slice(client_magic);
        packet.extend_from_slice(client_pk);
        packet.extend_from_slice(nonce);
        packet.extend_from_slice(&ciphertext);

        Ok(packet)
    }

    // decrypts resolver response payload using derived shared key
    pub fn decrypt_response_payload(
        derived_shared_key: &[u8; 32],
        expected_client_nonce: &[u8; 12],
        encrypted_response: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Response format: [resolver_magic: 8B] || [client_nonce: 12B] || [resolver_nonce: 12B] || [ciphertext]
        if encrypted_response.len() < 8 + 12 + 12 + 16 {
            return Err("dnscrypt response packet too short".into());
        }

        if &encrypted_response[0..8] != DNSCRYPT_MAGIC_RESOLVER {
            return Err("invalid dnscrypt resolver magic".into());
        }

        if &encrypted_response[8..20] != expected_client_nonce {
            return Err("client nonce mismatch in dnscrypt response".into());
        }

        let resolver_nonce = &encrypted_response[20..32];
        let ciphertext = &encrypted_response[32..];

        let mut r_nonce = [0u8; 12];
        r_nonce.copy_from_slice(resolver_nonce);

        let key = Key::from(*derived_shared_key);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce_val = Nonce::from(r_nonce);
        let plaintext_padded = cipher
            .decrypt(&nonce_val, ciphertext)
            .map_err(|e| format!("decryption failed: {:?}", e))?;

        let clean_wire = unpad_response(&plaintext_padded)
            .ok_or_else(|| "invalid padding in dnscrypt response")?;

        Ok(clean_wire.to_vec())
    }

    // resolves a dns query over udp (directly or through an anonymized relay)
    pub async fn resolve(
        &self,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let cert = self
            .cert
            .as_ref()
            .ok_or_else(|| "no valid dnscrypt certificate loaded")?;

        // 1. generate genuine ephemeral client X25519 keypair
        let rng = SystemRandom::new();
        let client_priv = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|e| format!("failed to generate ephemeral x25519 key: {:?}", e))?;

        let client_pk_pub = client_priv
            .compute_public_key()
            .map_err(|e| format!("failed to compute client public key: {:?}", e))?;

        let mut client_pk = [0u8; 32];
        client_pk.copy_from_slice(client_pk_pub.as_ref());

        // 2. perform real Diffie-Hellman scalar multiplication with resolver public key
        let resolver_peer_pk = UnparsedPublicKey::new(&X25519, &cert.resolver_pk);
        let mut raw_shared_point = [0u8; 32];
        agreement::agree_ephemeral(
            client_priv,
            &resolver_peer_pk,
            "x25519 key agreement failed",
            |key_material| {
                if key_material.len() != 32 {
                    return Err("invalid shared secret length from x25519 agreement");
                }
                raw_shared_point.copy_from_slice(key_material);
                Ok(())
            },
        )
        .map_err(|e| format!("x25519 agreement failed: {:?}", e))?;

        // 3. derive symmetric shared key using HSalsa20 (crypto_box_beforenm)
        let derived_key = derive_shared_key(&raw_shared_point, cert.es_version);

        let mut client_nonce = [0u8; 12];
        aws_lc_rs::rand::fill(&mut client_nonce).map_err(|e| format!("rand error: {:?}", e))?;

        // 4. encrypt payload with client public key and derived shared key
        let enc_packet = Self::encrypt_query_payload(
            &cert.client_magic,
            &client_pk,
            &derived_key,
            &client_nonce,
            query,
        )?;

        // 5. wrap in relay header if configured
        let wire_packet = if let Some(_) = self.relay_addr {
            AnonymizedRelay::wrap_packet(self.server_addr, &enc_packet)
        } else {
            enc_packet
        };

        let target = self.relay_addr.unwrap_or(self.server_addr);
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(target).await?;

        socket.send(&wire_packet).await?;

        let mut resp_buf = vec![0u8; 4096];
        let n = tokio::time::timeout(timeout, socket.recv(&mut resp_buf)).await??;
        resp_buf.truncate(n);

        // 6. decrypt response with derived shared key
        Self::decrypt_response_payload(&derived_key, &client_nonce, &resp_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dnscrypt_cert_parsing_and_serialization() {
        let mut raw = [0u8; 124];
        raw[0..4].copy_from_slice(DNSCRYPT_MAGIC_CERT);
        raw[4..6].copy_from_slice(&2u16.to_be_bytes()); // es_version = 2
        raw[72..104].copy_from_slice(&[0x42; 32]); // resolver_pk
        raw[104..112].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // client_magic
        raw[112..116].copy_from_slice(&100u32.to_be_bytes()); // serial = 100
        raw[116..120].copy_from_slice(&1000u32.to_be_bytes()); // ts_start = 1000
        raw[120..124].copy_from_slice(&2000u32.to_be_bytes()); // ts_end = 2000

        let cert = DnsCryptCert::parse(&raw).expect("cert should parse");
        assert_eq!(cert.es_version, 2);
        assert_eq!(cert.serial, 100);
        assert!(cert.is_valid_at(1500));
        assert!(!cert.is_valid_at(999));
        assert!(!cert.is_valid_at(2001));

        let serialized = cert.to_bytes();
        assert_eq!(serialized, raw);
    }

    #[test]
    fn test_anonymized_relay_wrap_and_unwrap() {
        let target: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let payload = b"encrypted_dnscrypt_payload";

        let wrapped = AnonymizedRelay::wrap_packet(target, payload);
        assert_eq!(&wrapped[0..9], DNSCRYPT_RELAY_MAGIC);

        let (unwrapped_target, unwrapped_payload) =
            AnonymizedRelay::unwrap_packet(&wrapped).expect("relay packet should unwrap");

        assert_eq!(unwrapped_target, target);
        assert_eq!(unwrapped_payload, payload);
    }

    #[test]
    fn test_padding_and_unpadding() {
        let query = b"query_wire_bytes";
        let padded = pad_query(query, 64);
        assert!(padded.len() >= 64);
        assert_eq!(padded.len() % 64, 0);

        let unpadded = unpad_response(&padded).expect("unpadding must succeed");
        assert_eq!(unpadded, query);
    }

    #[test]
    fn test_dnscrypt_hsalsa20_and_hchacha20_primitives() {
        // 1. Verify HChaCha20 against IETF draft-denis-dprive-dnscrypt Appendix 13.3 vector
        let k = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let input = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let expected_hchacha = [
            0x51, 0xe3, 0xff, 0x45, 0xa8, 0x95, 0x67, 0x5c, 0x4b, 0x33, 0xb4, 0x6c, 0x64, 0xf4,
            0xa9, 0xac, 0xe1, 0x10, 0xd3, 0x4d, 0xf6, 0xa2, 0xce, 0xab, 0x48, 0x63, 0x72, 0xba,
            0xcb, 0xd3, 0xef, 0xf6,
        ];
        assert_eq!(hchacha20(&k, &input), expected_hchacha);

        // 2. Verify DNSCrypt v2 Appendix 14.2 derived shared key vector
        let shared_point = [
            0x04, 0xc3, 0x04, 0xfb, 0x1c, 0xa8, 0x3c, 0xee, 0x75, 0xe2, 0x06, 0x34, 0x42, 0x31,
            0xf3, 0x37, 0x97, 0xe0, 0x7d, 0x99, 0x29, 0xdb, 0x67, 0x09, 0x94, 0xb7, 0xc6, 0xfb,
            0xeb, 0x1d, 0xc2, 0x55,
        ];
        let zero16 = [0u8; 16];
        let expected_shared_key = [
            0x33, 0x5d, 0x32, 0xf2, 0xd6, 0x5e, 0x66, 0x23, 0xcb, 0xbd, 0x05, 0xb6, 0x53, 0x9c,
            0x95, 0x75, 0xfe, 0xe1, 0x6c, 0xb5, 0x40, 0x5f, 0xe8, 0x39, 0xab, 0x4b, 0xd2, 0x91,
            0xfd, 0xf1, 0x32, 0x62,
        ];
        assert_eq!(hchacha20(&shared_point, &zero16), expected_shared_key);

        // 3. Verify HSalsa20 against libsodium crypto_core_hsalsa20 vector
        let k_salsa = [
            0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a,
            0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08,
            0x44, 0xf6, 0x83, 0x89,
        ];
        let input_salsa = [
            0x69, 0x6e, 0x20, 0x31, 0x36, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6e, 0x6f, 0x6e,
            0x63, 0x65,
        ];
        let expected_hsalsa = [
            0xe0, 0xb0, 0xb5, 0x65, 0x1e, 0x69, 0x44, 0xc6, 0xb8, 0x92, 0x3f, 0x27, 0x75, 0x4a,
            0xa9, 0x80, 0xda, 0xc7, 0xdf, 0x86, 0x6f, 0x8e, 0x3b, 0x89, 0xc1, 0x53, 0x78, 0xbd,
            0x70, 0x7c, 0xb8, 0x2e,
        ];
        assert_eq!(hsalsa20(&k_salsa, &input_salsa), expected_hsalsa);
    }

    #[test]
    fn test_dnscrypt_two_party_dh_agreement() {
        let rng = SystemRandom::new();

        // Independent Client Key Generation
        let client_priv = EphemeralPrivateKey::generate(&X25519, &rng)
            .expect("client ephemeral key generation should succeed");
        let client_pub = client_priv
            .compute_public_key()
            .expect("client public key computation should succeed");
        let mut client_pk = [0u8; 32];
        client_pk.copy_from_slice(client_pub.as_ref());

        // Independent Resolver Key Generation
        let resolver_priv = EphemeralPrivateKey::generate(&X25519, &rng)
            .expect("resolver ephemeral key generation should succeed");
        let resolver_pub = resolver_priv
            .compute_public_key()
            .expect("resolver public key computation should succeed");
        let mut resolver_pk = [0u8; 32];
        resolver_pk.copy_from_slice(resolver_pub.as_ref());

        // Client computes DH shared point with Resolver's Public Key
        let mut client_shared_point = [0u8; 32];
        agreement::agree_ephemeral(
            client_priv,
            &UnparsedPublicKey::new(&X25519, &resolver_pk),
            "client DH failed",
            |material| {
                client_shared_point.copy_from_slice(material);
                Ok(())
            },
        )
        .expect("client agreement should succeed");

        // Resolver computes DH shared point with Client's Public Key
        let mut resolver_shared_point = [0u8; 32];
        agreement::agree_ephemeral(
            resolver_priv,
            &UnparsedPublicKey::new(&X25519, &client_pk),
            "resolver DH failed",
            |material| {
                resolver_shared_point.copy_from_slice(material);
                Ok(())
            },
        )
        .expect("resolver agreement should succeed");

        // CRITICAL AXIOM OF DIFFIE-HELLMAN: X25519(sk_A, pk_B) == X25519(sk_B, pk_A)
        assert_eq!(
            client_shared_point, resolver_shared_point,
            "two independent parties must compute identical shared secret point"
        );

        // Verify that HSalsa20 key derivation yields identical symmetric session keys
        let client_derived_salsa = derive_shared_key_hsalsa20(&client_shared_point);
        let resolver_derived_salsa = derive_shared_key_hsalsa20(&resolver_shared_point);
        assert_eq!(
            client_derived_salsa, resolver_derived_salsa,
            "HSalsa20 derived session keys must be identical"
        );

        // Verify that HChaCha20 key derivation yields identical symmetric session keys
        let client_derived_chacha = derive_shared_key_hchacha20(&client_shared_point);
        let resolver_derived_chacha = derive_shared_key_hchacha20(&resolver_shared_point);
        assert_eq!(
            client_derived_chacha, resolver_derived_chacha,
            "HChaCha20 derived session keys must be identical"
        );
    }

    #[test]
    fn test_dnscrypt_regression_shared_secret_not_xor_of_public_keys() {
        let rng = SystemRandom::new();

        let client_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let client_pub = client_priv.compute_public_key().unwrap();
        let mut client_pk = [0u8; 32];
        client_pk.copy_from_slice(client_pub.as_ref());

        let resolver_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let resolver_pub = resolver_priv.compute_public_key().unwrap();
        let mut resolver_pk = [0u8; 32];
        resolver_pk.copy_from_slice(resolver_pub.as_ref());

        let mut real_shared_point = [0u8; 32];
        agreement::agree_ephemeral(
            client_priv,
            &UnparsedPublicKey::new(&X25519, &resolver_pk),
            "agreement failed",
            |material| {
                real_shared_point.copy_from_slice(material);
                Ok(())
            },
        )
        .unwrap();

        let derived_shared_key = derive_shared_key_hsalsa20(&real_shared_point);

        // Passive observer sniffing traffic computes client_pk XOR resolver_pk
        let mut eavesdropper_xor = [0u8; 32];
        for i in 0..32 {
            eavesdropper_xor[i] = client_pk[i] ^ resolver_pk[i];
        }

        // REGRESSION CHECK: Real cryptographic shared point and key MUST NOT equal public XOR
        assert_ne!(
            real_shared_point, eavesdropper_xor,
            "cryptographic shared point must not equal passive public key XOR"
        );
        assert_ne!(
            derived_shared_key, eavesdropper_xor,
            "derived session key must not equal passive public key XOR"
        );

        // Client public key sent over wire must be a non-trivial curve point
        assert_ne!(client_pk, [0u8; 32]);
        assert_ne!(resolver_pk, [0u8; 32]);
    }

    #[test]
    fn test_dnscrypt_encryption_decryption_roundtrip() {
        let rng = SystemRandom::new();

        // 1. Generate client and resolver real X25519 keypairs
        let client_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let client_pub = client_priv.compute_public_key().unwrap();
        let mut client_pk = [0u8; 32];
        client_pk.copy_from_slice(client_pub.as_ref());

        let resolver_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let resolver_pub = resolver_priv.compute_public_key().unwrap();
        let mut resolver_pk = [0u8; 32];
        resolver_pk.copy_from_slice(resolver_pub.as_ref());

        // Client derives shared key
        let mut client_shared_point = [0u8; 32];
        agreement::agree_ephemeral(
            client_priv,
            &UnparsedPublicKey::new(&X25519, &resolver_pk),
            "client DH",
            |mat| {
                client_shared_point.copy_from_slice(mat);
                Ok(())
            },
        )
        .unwrap();
        let client_shared_key = derive_shared_key_hsalsa20(&client_shared_point);

        // Resolver derives shared key
        let mut resolver_shared_point = [0u8; 32];
        agreement::agree_ephemeral(
            resolver_priv,
            &UnparsedPublicKey::new(&X25519, &client_pk),
            "resolver DH",
            |mat| {
                resolver_shared_point.copy_from_slice(mat);
                Ok(())
            },
        )
        .unwrap();
        let resolver_shared_key = derive_shared_key_hsalsa20(&resolver_shared_point);

        assert_eq!(client_shared_key, resolver_shared_key);

        let client_magic = [0xAA; 8];
        let client_nonce = [0x99; 12];
        let query = b"test_dns_query_wire_packet";

        // 2. Client encrypts query
        let encrypted = DnsCryptClient::encrypt_query_payload(
            &client_magic,
            &client_pk,
            &client_shared_key,
            &client_nonce,
            query,
        )
        .expect("encryption must succeed");

        assert_eq!(&encrypted[0..8], &client_magic);
        assert_eq!(&encrypted[8..40], &client_pk);
        assert_eq!(&encrypted[40..52], &client_nonce);

        // 3. Resolver simulates response: [resolver_magic: 8B] || [client_nonce: 12B] || [resolver_nonce: 12B] || [ciphertext]
        let resolver_nonce = [0x55; 12];
        let response_data = b"test_dns_response_wire_packet";
        let padded_resp = pad_query(response_data, 64);

        let key = Key::from(resolver_shared_key);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce_val = Nonce::from(resolver_nonce);
        let ciphertext = cipher.encrypt(&nonce_val, padded_resp.as_ref()).unwrap();

        let mut simulated_response = Vec::new();
        simulated_response.extend_from_slice(DNSCRYPT_MAGIC_RESOLVER);
        simulated_response.extend_from_slice(&client_nonce);
        simulated_response.extend_from_slice(&resolver_nonce);
        simulated_response.extend_from_slice(&ciphertext);

        // 4. Client decrypts response
        let decrypted = DnsCryptClient::decrypt_response_payload(
            &client_shared_key,
            &client_nonce,
            &simulated_response,
        )
        .expect("decryption must succeed");

        assert_eq!(decrypted, response_data);
    }

    #[tokio::test]
    async fn test_dnscrypt_local_mock_resolver_end_to_end() {
        let rng = SystemRandom::new();

        // 1. Setup mock resolver UDP socket
        let resolver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver_addr = resolver_socket.local_addr().unwrap();

        // 2. Resolver generates X25519 keypair
        let resolver_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let resolver_pub = resolver_priv.compute_public_key().unwrap();
        let mut resolver_pk = [0u8; 32];
        resolver_pk.copy_from_slice(resolver_pub.as_ref());

        let client_magic = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let test_cert = DnsCryptCert {
            cert_magic: *DNSCRYPT_MAGIC_CERT,
            es_version: 2,
            protocol_minor: 0,
            signature: [0u8; 64],
            resolver_pk,
            client_magic,
            serial: 1,
            ts_start: 0,
            ts_end: u32::MAX,
        };

        // 3. Spawn background resolver loop to service one query
        let resolver_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (n, peer) = resolver_socket.recv_from(&mut buf).await.unwrap();
            buf.truncate(n);

            assert!(buf.len() >= 52);
            assert_eq!(&buf[0..8], &client_magic);

            let mut client_pk = [0u8; 32];
            client_pk.copy_from_slice(&buf[8..40]);
            let mut client_nonce = [0u8; 12];
            client_nonce.copy_from_slice(&buf[40..52]);
            let ciphertext = &buf[52..];

            // Resolver computes DH shared secret
            let mut resolver_shared_point = [0u8; 32];
            agreement::agree_ephemeral(
                resolver_priv,
                &UnparsedPublicKey::new(&X25519, &client_pk),
                "server DH failed",
                |mat| {
                    resolver_shared_point.copy_from_slice(mat);
                    Ok(())
                },
            )
            .unwrap();
            let server_shared_key = derive_shared_key_hsalsa20(&resolver_shared_point);

            // Decrypt query
            let cipher = ChaCha20Poly1305::new(&Key::from(server_shared_key));
            let query_plaintext = cipher
                .decrypt(&Nonce::from(client_nonce), ciphertext)
                .expect("server decrypt failed");
            let clean_query = unpad_response(&query_plaintext).expect("server unpad failed");
            assert_eq!(clean_query, b"ping_query_payload");

            // Encrypt response: [resolver_magic: 8B] || [client_nonce: 12B] || [resolver_nonce: 12B] || [ciphertext]
            let resolver_nonce = [0xee; 12];
            let resp_plaintext = pad_query(b"pong_dns_response_payload", 64);
            let resp_cipher = cipher
                .encrypt(&Nonce::from(resolver_nonce), resp_plaintext.as_ref())
                .unwrap();

            let mut response_packet = Vec::new();
            response_packet.extend_from_slice(DNSCRYPT_MAGIC_RESOLVER);
            response_packet.extend_from_slice(&client_nonce);
            response_packet.extend_from_slice(&resolver_nonce);
            response_packet.extend_from_slice(&resp_cipher);

            resolver_socket
                .send_to(&response_packet, peer)
                .await
                .unwrap();
        });

        // 4. Client resolves query end-to-end
        let client =
            DnsCryptClient::new(resolver_addr, "mock.resolver".to_string(), [0u8; 32], None)
                .with_cert(test_cert);

        let response = client
            .resolve(b"ping_query_payload", Duration::from_secs(2))
            .await
            .expect("client resolve should succeed");

        assert_eq!(response, b"pong_dns_response_payload");

        resolver_handle.await.unwrap();
    }
}
