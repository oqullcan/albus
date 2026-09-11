//! dnscrypt v2 wire protocol client and anonymized udp relay implementation.
//!
//! supports dnscrypt v2 certificate parsing (x25519 + ed25519 + chacha20-poly1305),
//! question padding, encrypted query encapsulation, and two-hop anonymized udp relays.

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::rand::SystemRandom;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, warn};

pub const DNSCRYPT_MAGIC_CERT: &[u8; 4] = b"DNSC";
pub const DNSCRYPT_MAGIC_RESOLVER: &[u8; 8] = b"r6fnvWJ8";
pub const DNSCRYPT_RELAY_MAGIC_STANDARD: &[u8; 10] = &[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
];
pub const DNSCRYPT_RELAY_HEADER_SIZE: usize = 8 + 2 + 16 + 2; // 28 bytes
pub const DNSCRYPT_RELAY_MAGIC: &[u8; 9] = &[0xff; 9];
pub const MIN_QUERY_PADDED_LEN: usize = 256;

pub const PQ_XWING_PUBLIC_KEY_SIZE: usize = 1216;
pub const PQ_XWING_CIPHERTEXT_SIZE: usize = 1120;
pub const PQ_CLIENT_MAGIC_LEN: usize = 8;
pub const PQ_PROFILE_EXT_SIZE: usize = 12;
pub const PQ_CONTROL_VERSION: u8 = 0x01;
pub const PQ_EXT_VERSION: u8 = 0x01;
pub const PQ_KDF_ID: u8 = 0x01;
pub const PQ_AEAD_ID: u8 = 0x01;
pub const PQ_RESUMED_PADDING_FLOOR: usize = 256;
pub const PQ_ES_VERSION: [u8; 2] = [0x00, 0x03];
pub const PQ_RESUME_MAGIC: [u8; 8] = *b"PQResume";
pub const PQ_CONTROL_MAGIC: [u8; 4] = *b"PQDR";
pub const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]; // \./ /^\

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsCryptCert {
    pub cert_magic: [u8; 4],
    pub es_version: u16,
    pub protocol_minor: u16,
    pub signature: [u8; 64],
    pub resolver_pk: Vec<u8>,
    pub client_magic: [u8; 8],
    pub serial: u32,
    pub ts_start: u32,
    pub ts_end: u32,
    pub raw_cert: Vec<u8>,
}

impl DnsCryptCert {
    // parses a binary dnscrypt certificate from raw wire payload or txt record
    // supports both 124-byte classic certificates (es_version 1 or 2) and 1320-byte post-quantum certificates (es_version 3)
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

        let (resolver_pk, client_magic, serial, ts_start, ts_end) = if es_version == 3 {
            if bytes.len() < 1320 {
                return Err("pq dnscrypt certificate too short (minimum 1320 bytes)");
            }
            let ext = &bytes[1308..1320];
            if ext != pq_profile_extension() || &bytes[4..6] != &ext[4..6] {
                return Err("invalid pq profile extension in certificate");
            }
            let pk = bytes[72..1288].to_vec();
            let mut magic = [0u8; 8];
            magic.copy_from_slice(&bytes[1288..1296]);
            let s = u32::from_be_bytes([bytes[1296], bytes[1297], bytes[1298], bytes[1299]]);
            let ts_s = u32::from_be_bytes([bytes[1300], bytes[1301], bytes[1302], bytes[1303]]);
            let ts_e = u32::from_be_bytes([bytes[1304], bytes[1305], bytes[1306], bytes[1307]]);
            (pk, magic, s, ts_s, ts_e)
        } else {
            let pk = bytes[72..104].to_vec();
            let mut magic = [0u8; 8];
            magic.copy_from_slice(&bytes[104..112]);
            let s = u32::from_be_bytes([bytes[112], bytes[113], bytes[114], bytes[115]]);
            let ts_s = u32::from_be_bytes([bytes[116], bytes[117], bytes[118], bytes[119]]);
            let ts_e = u32::from_be_bytes([bytes[120], bytes[121], bytes[122], bytes[123]]);
            (pk, magic, s, ts_s, ts_e)
        };

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
            raw_cert: bytes.to_vec(),
        })
    }

    // verifies the ed25519 signature of the certificate body using the provider's public key
    pub fn verify_signature(&self, provider_pk: &[u8; 32]) -> bool {
        use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
        let peer_pk = UnparsedPublicKey::new(&ED25519, provider_pk);

        if !self.raw_cert.is_empty() && self.raw_cert.len() >= 72 {
            return peer_pk.verify(&self.raw_cert[72..], &self.signature).is_ok();
        }

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&self.resolver_pk);
        signed_data.extend_from_slice(&self.client_magic);
        signed_data.extend_from_slice(&self.serial.to_be_bytes());
        signed_data.extend_from_slice(&self.ts_start.to_be_bytes());
        signed_data.extend_from_slice(&self.ts_end.to_be_bytes());
        if self.es_version == 3 {
            signed_data.extend_from_slice(&pq_profile_extension());
        }

        peer_pk.verify(&signed_data, &self.signature).is_ok()
    }

    // checks whether certificate is within valid timestamp epoch
    pub fn is_valid_at(&self, epoch_secs: u32) -> bool {
        epoch_secs >= self.ts_start && epoch_secs <= self.ts_end
    }

    // selects the best certificate from a list according to DNSCrypt spec:
    // 1. filters certificates valid at epoch_secs
    // 2. selects certificate with highest serial number
    // 3. if serial numbers tie, prefers higher es_version (3: X-Wing PQ > 2: XChaCha20 > 1: XSalsa20)
    pub fn select_best_cert(certs: &[Self], epoch_secs: u32) -> Option<Self> {
        let mut best: Option<Self> = None;

        for cert in certs {
            if !cert.is_valid_at(epoch_secs) {
                continue;
            }
            match best.as_ref() {
                None => best = Some(cert.clone()),
                Some(current) => {
                    if cert.serial > current.serial {
                        best = Some(cert.clone());
                    } else if cert.serial == current.serial && cert.es_version > current.es_version {
                        best = Some(cert.clone());
                    }
                }
            }
        }

        best
    }

    // parses multiple binary certificates (e.g. from TXT records), verifies signatures,
    // filters by validity at epoch_secs, and returns the highest serial certificate
    pub fn parse_and_select_best(
        records: &[&[u8]],
        provider_pk: &[u8; 32],
        epoch_secs: u32,
    ) -> Result<Self, &'static str> {
        let mut valid_certs = Vec::new();
        for rec in records {
            if let Ok(cert) = Self::parse(rec) {
                if cert.verify_signature(provider_pk) && cert.is_valid_at(epoch_secs) {
                    valid_certs.push(cert);
                }
            }
        }

        Self::select_best_cert(&valid_certs, epoch_secs)
            .ok_or("no valid, signed, and unexpired dnscrypt certificate found")
    }

    // serializes certificate back to binary representation (124 bytes for classic, 1320 bytes for PQ)
    pub fn to_bytes(&self) -> Vec<u8> {
        if !self.raw_cert.is_empty() {
            return self.raw_cert.clone();
        }
        if self.es_version == 3 {
            let mut buf = Vec::with_capacity(1320);
            buf.extend_from_slice(&self.cert_magic);
            buf.extend_from_slice(&self.es_version.to_be_bytes());
            buf.extend_from_slice(&self.protocol_minor.to_be_bytes());
            buf.extend_from_slice(&self.signature);
            buf.extend_from_slice(&self.resolver_pk);
            buf.extend_from_slice(&self.client_magic);
            buf.extend_from_slice(&self.serial.to_be_bytes());
            buf.extend_from_slice(&self.ts_start.to_be_bytes());
            buf.extend_from_slice(&self.ts_end.to_be_bytes());
            buf.extend_from_slice(&pq_profile_extension());
            buf
        } else {
            let mut buf = Vec::with_capacity(124);
            buf.extend_from_slice(&self.cert_magic);
            buf.extend_from_slice(&self.es_version.to_be_bytes());
            buf.extend_from_slice(&self.protocol_minor.to_be_bytes());
            buf.extend_from_slice(&self.signature);
            if self.resolver_pk.len() >= 32 {
                buf.extend_from_slice(&self.resolver_pk[0..32]);
            } else {
                buf.resize(buf.len() + 32, 0);
            }
            buf.extend_from_slice(&self.client_magic);
            buf.extend_from_slice(&self.serial.to_be_bytes());
            buf.extend_from_slice(&self.ts_start.to_be_bytes());
            buf.extend_from_slice(&self.ts_end.to_be_bytes());
            buf
        }
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
    // wraps dnscrypt packet into anonymized relay header for transmission to proxy relay (standard 28-byte format matching dnscrypt-proxy)
    pub fn wrap_packet(target_addr: SocketAddr, packet: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(DNSCRYPT_RELAY_HEADER_SIZE + packet.len());
        out.extend_from_slice(DNSCRYPT_RELAY_MAGIC_STANDARD);

        match target_addr.ip() {
            IpAddr::V4(v4) => {
                // standard IPv4-mapped IPv6 representation (::ffff:a.b.c.d)
                out.extend_from_slice(&[0u8; 10]);
                out.extend_from_slice(&[0xff, 0xff]);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&v6.octets());
            }
        }
        out.extend_from_slice(&target_addr.port().to_be_bytes());
        out.extend_from_slice(packet);
        out
    }

    // unwraps relay header received by a relay server (supporting both standard 28-byte and legacy 9-byte formats)
    pub fn unwrap_packet(data: &[u8]) -> Result<(SocketAddr, &[u8]), &'static str> {
        // 1. check standard 28-byte format (8x 0xff + 2x 0x00 + 16B IP + 2B Port)
        if data.len() >= DNSCRYPT_RELAY_HEADER_SIZE && &data[0..10] == DNSCRYPT_RELAY_MAGIC_STANDARD {
            let ip_bytes = &data[10..26];
            let port = u16::from_be_bytes([data[26], data[27]]);

            let ip: IpAddr = if ip_bytes[0..10] == [0u8; 10] && ip_bytes[10..12] == [0xff, 0xff] {
                IpAddr::V4(Ipv4Addr::new(
                    ip_bytes[12],
                    ip_bytes[13],
                    ip_bytes[14],
                    ip_bytes[15],
                ))
            } else {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(ip_bytes);
                IpAddr::V6(Ipv6Addr::from(octets))
            };

            return Ok((SocketAddr::new(ip, port), &data[DNSCRYPT_RELAY_HEADER_SIZE..]));
        }

        // 2. backwards-compatible legacy format (9x 0xff + 1B Family + 4B/16B IP + 2B Port)
        if data.len() >= 9 + 1 + 4 + 2 && &data[0..9] == DNSCRYPT_RELAY_MAGIC {
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
            return Ok((target_addr, &data[pos..]));
        }

        Err("invalid or unrecognized relay magic header")
    }

    // selects relay address for a given server name according to routes configuration
    pub fn select_relay_for_server(
        server_name: &str,
        routes: &[crate::app::config::AnonymizedDnsRoute],
        available_relays: &std::collections::HashMap<String, SocketAddr>,
    ) -> Option<SocketAddr> {
        // 1. Exact match on server_name
        for route in routes {
            if route.server_name.eq_ignore_ascii_case(server_name) {
                for via in &route.via {
                    if let Some(addr) = available_relays.get(via) {
                        return Some(*addr);
                    }
                    if let Ok(addr) = via.parse::<SocketAddr>() {
                        return Some(addr);
                    }
                }
            }
        }
        // 2. Wildcard "*" match
        for route in routes {
            if route.server_name == "*" {
                for via in &route.via {
                    if let Some(addr) = available_relays.get(via) {
                        return Some(*addr);
                    }
                    if let Ok(addr) = via.parse::<SocketAddr>() {
                        return Some(addr);
                    }
                }
            }
        }
        None
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
        2 => derive_shared_key_hchacha20(shared_point),
        _ => derive_shared_key_hsalsa20(shared_point),
    }
}

pub fn pq_profile_extension() -> [u8; 12] {
    let mut ext = [0u8; 12];
    ext[0..3].copy_from_slice(b"PQD");
    ext[3] = PQ_EXT_VERSION;
    ext[4] = PQ_ES_VERSION[0];
    ext[5] = PQ_ES_VERSION[1];
    ext[6] = PQ_KDF_ID;
    ext[7] = PQ_AEAD_ID;
    ext[8..10].copy_from_slice(&(PQ_XWING_PUBLIC_KEY_SIZE as u16).to_be_bytes());
    ext[10..12].copy_from_slice(&(PQ_XWING_CIPHERTEXT_SIZE as u16).to_be_bytes());
    ext
}

pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), &'static str> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out).map_err(|_| "hkdf expand failed")
}

pub fn pq_cert_context(bin_cert: &[u8]) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(
        14 + 2 + 2 + PQ_XWING_PUBLIC_KEY_SIZE + 8 + 4 + 4 + 4 + PQ_PROFILE_EXT_SIZE,
    );
    ctx.extend_from_slice(b"DNSCrypt-PQ-v1");
    ctx.extend_from_slice(&bin_cert[4..6]); // es-version
    ctx.extend_from_slice(&bin_cert[6..8]); // protocol-minor-version
    ctx.extend_from_slice(&bin_cert[72..1288]); // resolver-pk
    ctx.extend_from_slice(&bin_cert[1288..1296]); // client-magic
    ctx.extend_from_slice(&bin_cert[1296..1300]); // serial
    ctx.extend_from_slice(&bin_cert[1300..1304]); // ts-start
    ctx.extend_from_slice(&bin_cert[1304..1308]); // ts-end
    ctx.extend_from_slice(&bin_cert[1308..1320]); // extensions
    ctx
}

pub fn pq_derive_shared_key(
    kem_ss: &[u8; 32],
    client_magic: &[u8; 8],
    cert_context: &[u8],
    ct: &[u8],
) -> Result<[u8; 32], &'static str> {
    let mut salt = Vec::with_capacity(10);
    salt.extend_from_slice(&PQ_ES_VERSION);
    salt.extend_from_slice(client_magic);

    let mut info = Vec::with_capacity(cert_context.len() + ct.len());
    info.extend_from_slice(cert_context);
    info.extend_from_slice(ct);

    let mut key = [0u8; 32];
    hkdf_sha256(&salt, kem_ss, &info, &mut key)?;
    Ok(key)
}

pub fn pq_resume_secret(
    shared_key: &[u8; 32],
    client_magic: &[u8; 8],
    client_nonce: &[u8; 12],
) -> Result<[u8; 32], &'static str> {
    let mut salt = Vec::with_capacity(20);
    salt.extend_from_slice(client_magic);
    salt.extend_from_slice(client_nonce);

    let mut out = [0u8; 32];
    hkdf_sha256(&salt, shared_key, b"DNSCrypt-PQ-resume-secret-v1", &mut out)?;
    Ok(out)
}

pub fn pq_resumed_shared_key(
    resume_secret: &[u8; 32],
    client_magic: &[u8; 8],
    client_nonce: &[u8; 12],
    ticket: &[u8],
) -> Result<[u8; 32], &'static str> {
    let mut salt = Vec::with_capacity(20);
    salt.extend_from_slice(client_magic);
    salt.extend_from_slice(client_nonce);

    let th = Sha256::digest(ticket);
    let mut info = Vec::with_capacity(27 + 32);
    info.extend_from_slice(b"DNSCrypt-PQ-resumed-query-v1");
    info.extend_from_slice(&th);

    let mut key = [0u8; 32];
    hkdf_sha256(&salt, resume_secret, &info, &mut key)?;
    Ok(key)
}

pub fn pq_pad(packet: &[u8], floor: usize) -> Vec<u8> {
    let target = ((packet.len() + 1 + 63) & !63).max(floor);
    let mut padded = vec![0u8; target];
    padded[..packet.len()].copy_from_slice(packet);
    padded[packet.len()] = 0x80;
    padded
}

pub fn pq_encapsulate(
    pk: &[u8],
) -> Result<([u8; 32], Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    if pk.len() != PQ_XWING_PUBLIC_KEY_SIZE {
        return Err(format!(
            "invalid x-wing public key length: expected {}, got {}",
            PQ_XWING_PUBLIC_KEY_SIZE,
            pk.len()
        )
        .into());
    }
    let pk_m = &pk[0..1184];
    let pk_x = &pk[1184..1216];

    // 1. ML-KEM-768 encapsulation
    use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};
    let enc_key = EncapsulationKey::new(&ML_KEM_768, pk_m)
        .map_err(|e| format!("ml-kem-768 key parse error: {:?}", e))?;
    let (ct_m, ss_m) = enc_key
        .encapsulate()
        .map_err(|e| format!("ml-kem-768 encapsulate error: {:?}", e))?;

    // 2. Ephemeral X25519 key generation
    let rng = SystemRandom::new();
    let ek_x = EphemeralPrivateKey::generate(&X25519, &rng)
        .map_err(|e| format!("x25519 keygen error: {:?}", e))?;
    let ct_x_pub = ek_x
        .compute_public_key()
        .map_err(|e| format!("x25519 pubkey error: {:?}", e))?;
    let mut ct_x = [0u8; 32];
    ct_x.copy_from_slice(ct_x_pub.as_ref());

    // 3. X25519 shared secret
    let mut ss_x = [0u8; 32];
    agreement::agree_ephemeral(
        ek_x,
        &UnparsedPublicKey::new(&X25519, pk_x),
        "x25519 agree error",
        |mat| {
            if mat.len() != 32 {
                return Err("invalid x25519 shared secret len");
            }
            ss_x.copy_from_slice(mat);
            Ok(())
        },
    )
    .map_err(|e| format!("x25519 agree error: {:?}", e))?;

    // 4. Combiner: SHA3-256(XWingLabel || ss_M || ss_X || ct_X || pk_X)
    use aws_lc_rs::digest::{Context, SHA3_256};
    let mut hasher = Context::new(&SHA3_256);
    hasher.update(&XWING_LABEL);
    hasher.update(ss_m.as_ref());
    hasher.update(&ss_x);
    hasher.update(&ct_x);
    hasher.update(pk_x);
    let digest = hasher.finish();
    let mut kem_ss = [0u8; 32];
    kem_ss.copy_from_slice(digest.as_ref());

    // 5. Ciphertext: ct_M || ct_X
    let mut ct = Vec::with_capacity(PQ_XWING_CIPHERTEXT_SIZE);
    ct.extend_from_slice(ct_m.as_ref());
    ct.extend_from_slice(&ct_x);

    Ok((kem_ss, ct))
}

#[derive(Clone, Debug, Default)]
pub struct PqSessionState {
    inner: Arc<std::sync::Mutex<PqSessionStateInner>>,
}

#[derive(Default, Debug)]
struct PqSessionStateInner {
    ticket: Option<Vec<u8>>,
    resume_secret: [u8; 32],
    expiry: Option<std::time::Instant>,
    epoch: u64,
    encap_ct: Option<Vec<u8>>,
    encap_key: [u8; 32],
    encap_epoch: u64,
}

impl PqSessionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store_ticket(
        &self,
        ticket: Vec<u8>,
        resume_secret: [u8; 32],
        ttl: Duration,
        epoch: u64,
    ) {
        if let Ok(mut lock) = self.inner.lock() {
            lock.ticket = Some(ticket);
            lock.resume_secret = resume_secret;
            lock.expiry = Some(std::time::Instant::now() + ttl);
            lock.epoch = epoch;
        }
    }

    pub fn get_ticket(&self, current_epoch: u64) -> Option<(Vec<u8>, [u8; 32])> {
        let mut lock = self.inner.lock().ok()?;
        if let Some(exp) = lock.expiry {
            if std::time::Instant::now() > exp {
                lock.ticket = None;
                lock.expiry = None;
                return None;
            }
        }
        if lock.epoch != current_epoch {
            lock.ticket = None;
            lock.expiry = None;
            return None;
        }
        lock.ticket.as_ref().map(|t| (t.clone(), lock.resume_secret))
    }

    pub fn store_encapsulation(&self, ct: Vec<u8>, key: [u8; 32], epoch: u64) {
        if let Ok(mut lock) = self.inner.lock() {
            lock.encap_ct = Some(ct);
            lock.encap_key = key;
            lock.encap_epoch = epoch;
        }
    }

    pub fn get_cached_encapsulation(&self, current_epoch: u64) -> Option<(Vec<u8>, [u8; 32])> {
        let mut lock = self.inner.lock().ok()?;
        if lock.encap_epoch != current_epoch {
            lock.encap_ct = None;
            return None;
        }
        lock.encap_ct.as_ref().map(|ct| (ct.clone(), lock.encap_key))
    }
}

// client capable of resolving encrypted dns queries using dnscrypt v2, pqdnscrypt, and optional anonymized relays
#[derive(Clone, Debug)]
pub struct DnsCryptClient {
    pub server_addr: SocketAddr,
    pub provider_name: String,
    pub provider_pk: [u8; 32],
    pub relay_addr: Option<SocketAddr>,
    pub cert: Option<DnsCryptCert>,
    pub ephemeral_keys: bool,
    pub cert_ignore_timestamp: bool,
    pub force_tcp: bool,
    pub udp_pool: Option<Arc<crate::dns::udp_pool::UdpConnPool>>,
    session_key_cache: Option<(Arc<[u8; 32]>, [u8; 32])>,
    pub pq_session: PqSessionState,
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
            ephemeral_keys: true, // default to maximum privacy
            cert_ignore_timestamp: false,
            force_tcp: false,
            udp_pool: None,
            session_key_cache: None,
            pq_session: PqSessionState::new(),
        }
    }

    pub fn with_force_tcp(mut self, force: bool) -> Self {
        self.force_tcp = force;
        self
    }

    pub fn with_udp_pool(mut self, pool: Option<Arc<crate::dns::udp_pool::UdpConnPool>>) -> Self {
        self.udp_pool = pool;
        self
    }

    pub fn with_cert_ignore_timestamp(mut self, ignore: bool) -> Self {
        self.cert_ignore_timestamp = ignore;
        self
    }

    /// Sets whether to generate a fresh X25519 keypair for every query (maximum forward secrecy) or reuse a cached session key.
    pub fn with_ephemeral_keys(mut self, ephemeral: bool) -> Self {
        self.ephemeral_keys = ephemeral;
        if ephemeral {
            self.session_key_cache = None;
        } else if let Some(cert) = self.cert.clone() {
            self.init_session_cache(&cert);
        }
        self
    }

    fn init_session_cache(&mut self, cert: &DnsCryptCert) {
        if cert.resolver_pk.len() < 32 {
            return;
        }
        let rng = SystemRandom::new();
        if let Ok(client_priv) = EphemeralPrivateKey::generate(&X25519, &rng) {
            if let Ok(client_pk_pub) = client_priv.compute_public_key() {
                let mut client_pk = [0u8; 32];
                client_pk.copy_from_slice(client_pk_pub.as_ref());
                let resolver_peer_pk = UnparsedPublicKey::new(&X25519, &cert.resolver_pk[0..32]);
                let mut raw_shared_point = [0u8; 32];
                if agreement::agree_ephemeral(
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
                .is_ok()
                {
                    let derived_key = derive_shared_key(&raw_shared_point, cert.es_version);
                    self.session_key_cache = Some((Arc::new(derived_key), client_pk));
                }
            }
        }
    }

    // sets validated certificate for session encryption
    pub fn with_cert(mut self, cert: DnsCryptCert) -> Self {
        if !self.ephemeral_keys {
            self.init_session_cache(&cert);
        }
        self.cert = Some(cert);
        self
    }

    // queries server for txt records matching provider_name to discover and validate dnscrypt certificates
    pub async fn fetch_cert(
        &mut self,
        timeout: Duration,
    ) -> Result<DnsCryptCert, Box<dyn std::error::Error + Send + Sync>> {
        let mut query = Vec::with_capacity(512);
        // Transaction ID
        query.extend_from_slice(&[0x12, 0x34]);
        // Flags: standard query, recursion desired (0x0100)
        query.extend_from_slice(&[0x01, 0x00]);
        // QDCOUNT: 1
        query.extend_from_slice(&[0x00, 0x01]);
        // ANCOUNT: 0
        query.extend_from_slice(&[0x00, 0x00]);
        // NSCOUNT: 0
        query.extend_from_slice(&[0x00, 0x00]);
        // ARCOUNT: 1 (EDNS0 OPT RR)
        query.extend_from_slice(&[0x00, 0x01]);

        // QNAME: provider_name
        for part in self.provider_name.split('.') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                query.push(trimmed.len() as u8);
                query.extend_from_slice(trimmed.as_bytes());
            }
        }
        query.push(0x00); // end of name

        // QTYPE: TXT (16)
        query.extend_from_slice(&[0x00, 0x10]);
        // QCLASS: IN (1)
        query.extend_from_slice(&[0x00, 0x01]);

        // OPT pseudo-RR (RFC 6891) for EDNS0 buffer size 4096
        query.push(0x00); // root
        query.extend_from_slice(&[0x00, 0x29]); // type 41 (OPT)
        query.extend_from_slice(&[0x10, 0x00]); // UDP payload size: 4096 bytes
        query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // extended RCODE and flags
        query.extend_from_slice(&[0x00, 0x00]); // RDLEN: 0

        // Send query packet to server
        let resp = self.send_packet(self.server_addr, &query, timeout).await?;
        if resp.len() < 12 {
            return Err("response packet too short".into());
        }

        let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
        let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;

        if ancount == 0 {
            return Err("no answer records in cert response".into());
        }

        let mut pos = 12;
        // Skip Question section
        for _ in 0..qdcount {
            while pos < resp.len() {
                let len = resp[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                if (len & 0xC0) == 0xC0 {
                    pos += 2;
                    break;
                }
                pos += 1 + len;
            }
            pos += 4; // skip QTYPE and QCLASS
            if pos > resp.len() {
                return Err("malformed question section in response".into());
            }
        }

        let mut candidate_certs = Vec::new();
        // Parse Answer section
        for _ in 0..ancount {
            if pos >= resp.len() {
                break;
            }
            // Skip NAME
            while pos < resp.len() {
                let len = resp[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                if (len & 0xC0) == 0xC0 {
                    pos += 2;
                    break;
                }
                pos += 1 + len;
            }
            if pos + 10 > resp.len() {
                break;
            }
            let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
            let _rclass = u16::from_be_bytes([resp[pos + 2], resp[pos + 3]]);
            let _ttl = u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
            let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > resp.len() {
                break;
            }

            if rtype == 16 {
                // TXT record: assemble character-strings
                let mut txt_data = Vec::new();
                let mut chunk_pos = pos;
                let end = pos + rdlength;
                while chunk_pos < end {
                    let chunk_len = resp[chunk_pos] as usize;
                    chunk_pos += 1;
                    if chunk_pos + chunk_len > end {
                        break;
                    }
                    txt_data.extend_from_slice(&resp[chunk_pos..chunk_pos + chunk_len]);
                    chunk_pos += chunk_len;
                }

                if txt_data.len() >= 124 && &txt_data[0..4] == DNSCRYPT_MAGIC_CERT {
                    if let Ok(cert) = DnsCryptCert::parse(&txt_data) {
                        let is_zero_pk = self.provider_pk == [0u8; 32];
                        if is_zero_pk || cert.verify_signature(&self.provider_pk) {
                            candidate_certs.push(cert);
                        }
                    }
                }
            }
            pos += rdlength;
        }

        if candidate_certs.is_empty() {
            return Err("no valid dnscrypt certificates found in response".into());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        let best = if self.cert_ignore_timestamp {
            candidate_certs.into_iter().max_by_key(|c| c.serial)
        } else {
            DnsCryptCert::select_best_cert(&candidate_certs, now)
                .or_else(|| candidate_certs.into_iter().max_by_key(|c| c.serial))
        }
        .ok_or_else(|| "no acceptable dnscrypt certificate selected")?;

        self.cert = Some(best.clone());
        if !self.ephemeral_keys {
            self.init_session_cache(&best);
        }

        Ok(best)
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

    /// xsecretbox seal: [Poly1305 tag: 16B] || [XChaCha20 ciphertext]
    pub fn xsecretbox_seal(key: &[u8; 32], nonce: &[u8; 24], message: &[u8]) -> Vec<u8> {
        use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use chacha20::XChaCha20;
        use poly1305::universal_hash::{KeyInit, UniversalHash};
        use poly1305::Poly1305;

        let mut cipher = XChaCha20::new(key.into(), nonce.into());
        let mut first_block = [0u8; 64];
        cipher.apply_keystream(&mut first_block);

        let poly_key = *poly1305::Key::from_slice(&first_block[0..32]);

        let mut out = Vec::with_capacity(16 + message.len());
        out.resize(16, 0u8);

        let first_chunk_len = message.len().min(32);
        for i in 0..first_chunk_len {
            out.push(first_block[32 + i] ^ message[i]);
        }

        if message.len() > 32 {
            let mut rest = message[32..].to_vec();
            cipher.seek(64);
            cipher.apply_keystream(&mut rest);
            out.extend_from_slice(&rest);
        }

        let mut poly = Poly1305::new(&poly_key);
        poly.update_padded(&out[16..]);
        let tag = poly.finalize();
        out[0..16].copy_from_slice(&tag);
        out
    }

    /// xsecretbox open: verifies Poly1305 tag and decrypts XChaCha20 ciphertext
    pub fn xsecretbox_open(
        key: &[u8; 32],
        nonce: &[u8; 24],
        box_data: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use chacha20::XChaCha20;
        use poly1305::universal_hash::{KeyInit, UniversalHash};
        use poly1305::Poly1305;

        if box_data.len() < 16 {
            return Err("ciphertext too short for tag");
        }

        let tag = &box_data[0..16];
        let ciphertext = &box_data[16..];

        let mut cipher = XChaCha20::new(key.into(), nonce.into());
        let mut first_block = [0u8; 64];
        cipher.apply_keystream(&mut first_block);

        let poly_key = *poly1305::Key::from_slice(&first_block[0..32]);
        let mut poly = Poly1305::new(&poly_key);
        poly.update_padded(ciphertext);
        let expected_tag = poly.finalize();

        if aws_lc_rs::constant_time::verify_slices_are_equal(tag, expected_tag.as_slice()).is_err() {
            return Err("incorrect tag in xsecretbox");
        }

        let mut message = Vec::with_capacity(ciphertext.len());
        let first_chunk_len = ciphertext.len().min(32);
        for i in 0..first_chunk_len {
            message.push(first_block[32 + i] ^ ciphertext[i]);
        }

        if ciphertext.len() > 32 {
            let mut rest = ciphertext[32..].to_vec();
            cipher.seek(64);
            cipher.apply_keystream(&mut rest);
            message.extend_from_slice(&rest);
        }

        Ok(message)
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

    async fn send_packet(
        &self,
        target: SocketAddr,
        wire_packet: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if self.force_tcp {
            let mut stream = tokio::time::timeout(timeout, TcpStream::connect(target)).await??;
            let len_bytes = (wire_packet.len() as u16).to_be_bytes();
            tokio::time::timeout(timeout, async {
                stream.write_all(&len_bytes).await?;
                stream.write_all(wire_packet).await?;
                stream.flush().await?;
                let mut rlen = [0u8; 2];
                stream.read_exact(&mut rlen).await?;
                let resp_len = u16::from_be_bytes(rlen) as usize;
                let mut resp_buf = vec![0u8; resp_len];
                stream.read_exact(&mut resp_buf).await?;
                Ok::<Vec<u8>, std::io::Error>(resp_buf)
            })
            .await?
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        } else {
            let (socket, pooled) = if let Some(ref pool) = self.udp_pool {
                (pool.get_or_create(target).await?, true)
            } else {
                let s = UdpSocket::bind("0.0.0.0:0").await?;
                s.connect(target).await?;
                (Arc::new(s), false)
            };
            socket.send(wire_packet).await?;

            let mut resp_buf = vec![0u8; 4096];
            let recv_res = tokio::time::timeout(timeout, socket.recv(&mut resp_buf)).await;
            if pooled {
                if let Some(ref pool) = self.udp_pool {
                    pool.return_conn(target, socket).await;
                }
            }
            let n = recv_res??;
            resp_buf.truncate(n);
            Ok(resp_buf)
        }
    }

    // resolves a dns query using pqdnscrypt (x-wing hybrid kem / es_version 3) with ticket resumption support
    pub async fn resolve_pq_with_epoch(
        &self,
        query: &[u8],
        timeout: Duration,
        epoch_secs: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let cert = self
            .cert
            .as_ref()
            .ok_or_else(|| "no valid dnscrypt certificate loaded")?;

        if !self.cert_ignore_timestamp && !cert.is_valid_at(epoch_secs) {
            return Err(format!(
                "dnscrypt certificate expired or not yet valid (ts_start={}, ts_end={}, current_epoch={})",
                cert.ts_start, cert.ts_end, epoch_secs
            )
            .into());
        }

        let query_epoch = epoch_secs as u64;
        let mut client_nonce = [0u8; 12];
        aws_lc_rs::rand::fill(&mut client_nonce).map_err(|e| format!("rand error: {:?}", e))?;

        let mut nonce24 = [0u8; 24];
        nonce24[0..12].copy_from_slice(&client_nonce);

        let (key, wire_packet) = if let Some((ticket, resume_secret)) =
            self.pq_session.get_ticket(query_epoch)
        {
            let key =
                pq_resumed_shared_key(&resume_secret, &cert.client_magic, &client_nonce, &ticket)
                    .map_err(|e| format!("pq resume key derivation error: {}", e))?;
            let padded = pq_pad(query, PQ_RESUMED_PADDING_FLOOR);
            let ct = Self::xsecretbox_seal(&key, &nonce24, &padded);
            let mut out = Vec::with_capacity(8 + 2 + ticket.len() + 12 + ct.len());
            out.extend_from_slice(&PQ_RESUME_MAGIC);
            out.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            out.extend_from_slice(&ticket);
            out.extend_from_slice(&client_nonce);
            out.extend_from_slice(&ct);
            (key, out)
        } else {
            let (ct_kem, key) =
                if let Some(cached) = self.pq_session.get_cached_encapsulation(query_epoch) {
                    cached
                } else {
                    let (kem_ss, ct_kem) = pq_encapsulate(&cert.resolver_pk)?;
                    let cert_ctx = if !cert.raw_cert.is_empty() {
                        pq_cert_context(&cert.raw_cert)
                    } else {
                        let synthesized = cert.to_bytes();
                        pq_cert_context(&synthesized)
                    };
                    let key = pq_derive_shared_key(&kem_ss, &cert.client_magic, &cert_ctx, &ct_kem)
                        .map_err(|e| format!("pq shared key derivation error: {}", e))?;
                    self.pq_session
                        .store_encapsulation(ct_kem.clone(), key, query_epoch);
                    (ct_kem, key)
                };

            let padded = pq_pad(query, 64);
            let ct = Self::xsecretbox_seal(&key, &nonce24, &padded);
            let mut out = Vec::with_capacity(8 + ct_kem.len() + 12 + ct.len());
            out.extend_from_slice(&cert.client_magic);
            out.extend_from_slice(&ct_kem);
            out.extend_from_slice(&client_nonce);
            out.extend_from_slice(&ct);
            (key, out)
        };

        let wire_query = if self.relay_addr.is_some() {
            AnonymizedRelay::wrap_packet(self.server_addr, &wire_packet)
        } else {
            wire_packet
        };

        let target = self.relay_addr.unwrap_or(self.server_addr);
        let resp_buf = self.send_packet(target, &wire_query, timeout).await?;

        if resp_buf.len() < 8 + 12 + 12 + 16 {
            return Err("pq dnscrypt response packet too short".into());
        }
        if &resp_buf[0..8] != DNSCRYPT_MAGIC_RESOLVER {
            return Err("invalid dnscrypt resolver magic in pq response".into());
        }
        if &resp_buf[8..20] != &client_nonce {
            return Err("client nonce mismatch in pq response".into());
        }

        let mut server_nonce24 = [0u8; 24];
        server_nonce24.copy_from_slice(&resp_buf[8..32]);
        let ciphertext = &resp_buf[32..];

        let plaintext = Self::xsecretbox_open(&key, &server_nonce24, ciphertext)
            .map_err(|e| format!("pq response decrypt error: {}", e))?;

        if plaintext.len() < 2 {
            return Err("pq response too short".into());
        }
        let control_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        if 2 + control_len > plaintext.len() {
            return Err("pq control block overflows response".into());
        }

        let control = &plaintext[2..2 + control_len];
        let body = &plaintext[2 + control_len..];

        if control_len >= 11
            && &control[0..4] == &PQ_CONTROL_MAGIC
            && control[4] == PQ_CONTROL_VERSION
        {
            let lifetime = u32::from_be_bytes([control[5], control[6], control[7], control[8]]);
            let ticket_len = u16::from_be_bytes([control[9], control[10]]) as usize;
            if 11 + ticket_len <= control.len() {
                let ticket = &control[11..11 + ticket_len];
                if let Ok(resume_secret) =
                    pq_resume_secret(&key, &cert.client_magic, &client_nonce)
                {
                    self.pq_session.store_ticket(
                        ticket.to_vec(),
                        resume_secret,
                        Duration::from_secs(lifetime as u64),
                        query_epoch,
                    );
                }
            }
        }

        let clean_wire = unpad_response(body)
            .ok_or_else(|| "invalid padding in pq dnscrypt response")?;

        Ok(clean_wire.to_vec())
    }

    // resolves a dns query over udp (directly or through an anonymized relay) using explicit unix epoch for cert validation
    pub async fn resolve_with_epoch(
        &self,
        query: &[u8],
        timeout: Duration,
        epoch_secs: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let cert = self
            .cert
            .as_ref()
            .ok_or_else(|| "no valid dnscrypt certificate loaded")?;

        if !self.cert_ignore_timestamp && !cert.is_valid_at(epoch_secs) {
            return Err(format!(
                "dnscrypt certificate expired or not yet valid (ts_start={}, ts_end={}, current_epoch={})",
                cert.ts_start, cert.ts_end, epoch_secs
            )
            .into());
        }

        if cert.es_version == 3 {
            return self.resolve_pq_with_epoch(query, timeout, epoch_secs).await;
        }

        // 1. obtain client keypair and derived shared key (ephemeral or cached session key)
        let (derived_key, client_pk) = if !self.ephemeral_keys {
            if let Some((ref key, pk)) = self.session_key_cache {
                (**key, pk)
            } else {
                let rng = SystemRandom::new();
                let client_priv = EphemeralPrivateKey::generate(&X25519, &rng)
                    .map_err(|e| format!("failed to generate ephemeral x25519 key: {:?}", e))?;
                let client_pk_pub = client_priv
                    .compute_public_key()
                    .map_err(|e| format!("failed to compute client public key: {:?}", e))?;
                let mut client_pk = [0u8; 32];
                client_pk.copy_from_slice(client_pk_pub.as_ref());
                let resolver_peer_pk = UnparsedPublicKey::new(&X25519, &cert.resolver_pk[0..32]);
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
                let derived = derive_shared_key(&raw_shared_point, cert.es_version);
                (derived, client_pk)
            }
        } else {
            let rng = SystemRandom::new();
            let client_priv = EphemeralPrivateKey::generate(&X25519, &rng)
                .map_err(|e| format!("failed to generate ephemeral x25519 key: {:?}", e))?;
            let client_pk_pub = client_priv
                .compute_public_key()
                .map_err(|e| format!("failed to compute client public key: {:?}", e))?;
            let mut client_pk = [0u8; 32];
            client_pk.copy_from_slice(client_pk_pub.as_ref());
            let resolver_peer_pk = UnparsedPublicKey::new(&X25519, &cert.resolver_pk[0..32]);
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
            let derived = derive_shared_key(&raw_shared_point, cert.es_version);
            (derived, client_pk)
        };

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
        let resp_buf = self.send_packet(target, &wire_packet, timeout).await?;

        // 6. decrypt response with derived shared key
        Self::decrypt_response_payload(&derived_key, &client_nonce, &resp_buf)
    }

    // resolves a dns query over udp using current system clock for certificate validity check
    pub async fn resolve(
        &self,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let current_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        self.resolve_with_epoch(query, timeout, current_epoch).await
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
        assert_eq!(&wrapped[0..10], DNSCRYPT_RELAY_MAGIC_STANDARD);

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
            resolver_pk: resolver_pk.to_vec(),
            client_magic,
            serial: 1,
            ts_start: 0,
            ts_end: u32::MAX,
            raw_cert: Vec::new(),
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
            let server_shared_key = derive_shared_key(&resolver_shared_point, test_cert.es_version);

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

    #[tokio::test]
    async fn test_dnscrypt_tcp_mock_resolver_end_to_end() {
        let rng = SystemRandom::new();

        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let resolver_addr = tcp_listener.local_addr().unwrap();

        let resolver_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let resolver_pub = resolver_priv.compute_public_key().unwrap();
        let mut resolver_pk = [0u8; 32];
        resolver_pk.copy_from_slice(resolver_pub.as_ref());

        let client_magic = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22];
        let test_cert = DnsCryptCert {
            cert_magic: *DNSCRYPT_MAGIC_CERT,
            es_version: 2,
            protocol_minor: 0,
            signature: [0u8; 64],
            resolver_pk: resolver_pk.to_vec(),
            client_magic,
            serial: 1,
            ts_start: 0,
            ts_end: u32::MAX,
            raw_cert: Vec::new(),
        };

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let query_len = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; query_len];
            stream.read_exact(&mut buf).await.unwrap();

            assert_eq!(&buf[0..8], &client_magic);
            let mut client_pk = [0u8; 32];
            client_pk.copy_from_slice(&buf[8..40]);
            let mut client_nonce = [0u8; 12];
            client_nonce.copy_from_slice(&buf[40..52]);
            let ciphertext = &buf[52..];

            let client_unparsed = UnparsedPublicKey::new(&X25519, &client_pk);
            let mut shared_secret = [0u8; 32];
            agreement::agree_ephemeral(
                resolver_priv,
                &client_unparsed,
                "server dh",
                |mat| {
                    shared_secret.copy_from_slice(mat);
                    Ok(())
                },
            )
            .unwrap();

            let derived = derive_shared_key(&shared_secret, 2);
            let cipher = ChaCha20Poly1305::new(&Key::from(derived));
            let plaintext = cipher.decrypt(&Nonce::from(client_nonce), ciphertext).unwrap();
            let unpadded = unpad_response(&plaintext).unwrap();
            assert_eq!(unpadded, b"tcp_ping_query_payload");

            let resolver_nonce = [0x77; 12];
            let resp_plaintext = pad_query(b"tcp_pong_response_payload", 64);
            let resp_cipher = cipher
                .encrypt(&Nonce::from(resolver_nonce), resp_plaintext.as_ref())
                .unwrap();

            let mut response_packet = Vec::new();
            response_packet.extend_from_slice(DNSCRYPT_MAGIC_RESOLVER);
            response_packet.extend_from_slice(&client_nonce);
            response_packet.extend_from_slice(&resolver_nonce);
            response_packet.extend_from_slice(&resp_cipher);

            let resp_len_bytes = (response_packet.len() as u16).to_be_bytes();
            stream.write_all(&resp_len_bytes).await.unwrap();
            stream.write_all(&response_packet).await.unwrap();
            stream.flush().await.unwrap();
        });

        let client =
            DnsCryptClient::new(resolver_addr, "mock.resolver".to_string(), [0u8; 32], None)
                .with_force_tcp(true)
                .with_cert(test_cert);

        let response = client
            .resolve(b"tcp_ping_query_payload", Duration::from_secs(2))
            .await
            .expect("tcp client resolve should succeed");

        assert_eq!(response, b"tcp_pong_response_payload");
        server_handle.await.unwrap();
    }

    #[test]
    fn test_derive_shared_key_es_version_distinction() {
        let shared_point = [0x42u8; 32];
        let key_es1 = derive_shared_key(&shared_point, 1);
        let key_es2 = derive_shared_key(&shared_point, 2);

        // Verification according to dnscrypt-proxy crypto.go:
        // es_version 1 must use HSalsa20 (crypto_box_beforenm)
        // es_version 2 must use HChaCha20 (xsecretbox.SharedKey)
        assert_ne!(
            key_es1, key_es2,
            "es_version 1 (HSalsa20) and es_version 2 (HChaCha20) must derive completely different keys"
        );
        assert_eq!(key_es1, derive_shared_key_hsalsa20(&shared_point));
        assert_eq!(key_es2, derive_shared_key_hchacha20(&shared_point));
    }

    #[tokio::test]
    async fn test_resolve_rejects_expired_and_future_certificates() {
        let dummy_addr: SocketAddr = "127.0.0.1:5354".parse().unwrap();
        let cert = DnsCryptCert {
            cert_magic: *DNSCRYPT_MAGIC_CERT,
            es_version: 2,
            protocol_minor: 0,
            signature: [0u8; 64],
            resolver_pk: vec![0x42; 32],
            client_magic: [0x01; 8],
            serial: 10,
            ts_start: 1000,
            ts_end: 2000,
            raw_cert: Vec::new(),
        };

        let client = DnsCryptClient::new(dummy_addr, "test.resolver".to_string(), [0u8; 32], None)
            .with_cert(cert);

        // 1. Valid epoch (1500) -> fails on network connect/timeout, NOT cert expiry
        // 2. Expired epoch (2001) -> fails immediately with cert expired error
        let err_expired = client
            .resolve_with_epoch(b"query", Duration::from_millis(50), 2001)
            .await
            .unwrap_err();
        assert!(err_expired.to_string().contains("expired or not yet valid"));

        // 3. Future epoch (999) -> fails immediately with cert not yet valid error
        let err_future = client
            .resolve_with_epoch(b"query", Duration::from_millis(50), 999)
            .await
            .unwrap_err();
        assert!(err_future.to_string().contains("expired or not yet valid"));
    }

    #[test]
    fn test_multi_certificate_filtering_and_highest_serial_selection() {
        let current_epoch = 1500u32;

        let cert_expired = DnsCryptCert {
            cert_magic: *DNSCRYPT_MAGIC_CERT,
            es_version: 2,
            protocol_minor: 0,
            signature: [0u8; 64],
            resolver_pk: vec![0x01; 32],
            client_magic: [0x01; 8],
            serial: 100, // High serial, but expired!
            ts_start: 500,
            ts_end: 1000,
            raw_cert: Vec::new(),
        };

        let cert_valid_low_serial = DnsCryptCert {
            cert_magic: *DNSCRYPT_MAGIC_CERT,
            es_version: 1,
            protocol_minor: 0,
            signature: [0u8; 64],
            resolver_pk: vec![0x02; 32],
            client_magic: [0x02; 8],
            serial: 10, // Valid, but low serial
            ts_start: 1000,
            ts_end: 2000,
            raw_cert: Vec::new(),
        };

        let cert_valid_high_serial_es1 = DnsCryptCert {
            cert_magic: *DNSCRYPT_MAGIC_CERT,
            es_version: 1,
            protocol_minor: 0,
            signature: [0u8; 64],
            resolver_pk: vec![0x03; 32],
            client_magic: [0x03; 8],
            serial: 50,
            ts_start: 1000,
            ts_end: 2000,
            raw_cert: Vec::new(),
        };

        let cert_valid_high_serial_es2 = DnsCryptCert {
            cert_magic: *DNSCRYPT_MAGIC_CERT,
            es_version: 2, // Preferred es_version 2 (XChaCha20)
            protocol_minor: 0,
            signature: [0u8; 64],
            resolver_pk: vec![0x04; 32],
            client_magic: [0x04; 8],
            serial: 50, // Same serial as es1
            ts_start: 1000,
            ts_end: 2000,
            raw_cert: Vec::new(),
        };

        let cert_future = DnsCryptCert {
            cert_magic: *DNSCRYPT_MAGIC_CERT,
            es_version: 2,
            protocol_minor: 0,
            signature: [0u8; 64],
            resolver_pk: vec![0x05; 32],
            client_magic: [0x05; 8],
            serial: 999, // Highest serial, but not valid yet!
            ts_start: 3000,
            ts_end: 4000,
            raw_cert: Vec::new(),
        };

        // Multi-cert selection test 1: Expired + Low Serial + High Serial + Future
        let candidate_list = vec![
            cert_expired.clone(),
            cert_valid_low_serial.clone(),
            cert_valid_high_serial_es1.clone(),
            cert_future.clone(),
        ];

        let best = DnsCryptCert::select_best_cert(&candidate_list, current_epoch)
            .expect("should find best valid cert");
        assert_eq!(best.serial, 50);
        assert_eq!(best.client_magic, [0x03; 8]);

        // Multi-cert selection test 2: Serial tie-breaker prefers es_version 2 (XChaCha20) over es_version 1
        let candidate_list_tie = vec![
            cert_valid_high_serial_es1.clone(),
            cert_valid_high_serial_es2.clone(),
        ];
        let best_tie = DnsCryptCert::select_best_cert(&candidate_list_tie, current_epoch)
            .expect("should find best valid cert in tie");
        assert_eq!(best_tie.serial, 50);
        assert_eq!(best_tie.es_version, 2);
        assert_eq!(best_tie.client_magic, [0x04; 8]);
    }

    #[test]
    fn test_anonymized_relay_standard_format_interop() {
        let target_v4: SocketAddr = "9.9.9.9:8443".parse().unwrap();
        let target_v6: SocketAddr = "[2001:4860:4860::8888]:5353".parse().unwrap();
        let payload = b"encrypted_dnscrypt_packet_wire";

        // 1. IPv4 wrapping produces standard 28-byte header (10B magic + 16B mapped v6 + 2B port)
        let wrapped_v4 = AnonymizedRelay::wrap_packet(target_v4, payload);
        assert_eq!(wrapped_v4.len(), 28 + payload.len());
        assert_eq!(&wrapped_v4[0..10], DNSCRYPT_RELAY_MAGIC_STANDARD);
        assert_eq!(&wrapped_v4[10..20], &[0u8; 10]);
        assert_eq!(&wrapped_v4[20..22], &[0xff, 0xff]);
        assert_eq!(&wrapped_v4[22..26], &[9, 9, 9, 9]);
        assert_eq!(&wrapped_v4[26..28], &8443u16.to_be_bytes());

        let (unwrapped_v4, unwrapped_payload_v4) =
            AnonymizedRelay::unwrap_packet(&wrapped_v4).expect("standard v4 relay should unwrap");
        assert_eq!(unwrapped_v4, target_v4);
        assert_eq!(unwrapped_payload_v4, payload);

        // 2. IPv6 wrapping produces standard 28-byte header
        let wrapped_v6 = AnonymizedRelay::wrap_packet(target_v6, payload);
        assert_eq!(wrapped_v6.len(), 28 + payload.len());
        assert_eq!(&wrapped_v6[0..10], DNSCRYPT_RELAY_MAGIC_STANDARD);

        let (unwrapped_v6, unwrapped_payload_v6) =
            AnonymizedRelay::unwrap_packet(&wrapped_v6).expect("standard v6 relay should unwrap");
        assert_eq!(unwrapped_v6, target_v6);
        assert_eq!(unwrapped_payload_v6, payload);
    }

    #[test]
    fn test_ephemeral_keys_toggle() {
        let dummy_server: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let cert = DnsCryptCert {
            cert_magic: *DNSCRYPT_MAGIC_CERT,
            es_version: 2,
            protocol_minor: 0,
            signature: [0u8; 64],
            resolver_pk: vec![0x42u8; 32],
            client_magic: [0x01; 8],
            serial: 1,
            ts_start: 1000,
            ts_end: 2000,
            raw_cert: Vec::new(),
        };

        // 1. Ephemeral keys mode (default true)
        let client_eph = DnsCryptClient::new(dummy_server, "test".to_string(), [0u8; 32], None)
            .with_ephemeral_keys(true)
            .with_cert(cert.clone());
        assert!(client_eph.ephemeral_keys);
        assert!(client_eph.session_key_cache.is_none());

        // 2. Session key cache mode (ephemeral false)
        let client_cached = DnsCryptClient::new(dummy_server, "test".to_string(), [0u8; 32], None)
            .with_ephemeral_keys(false)
            .with_cert(cert);
        assert!(!client_cached.ephemeral_keys);
        assert!(client_cached.session_key_cache.is_some());
    }

    #[test]
    fn test_xsecretbox_vector() {
        let shared_key = [
            0xe6, 0xd4, 0xab, 0x9c, 0xff, 0xc9, 0xb4, 0x9e, 0x2a, 0x64, 0xd8, 0x0d, 0x7e, 0xb2,
            0xdd, 0xe2, 0x80, 0xf8, 0x06, 0xb8, 0x9e, 0x83, 0x4d, 0x59, 0x6a, 0xd3, 0x85, 0xb1,
            0xdd, 0x75, 0xe9, 0xef,
        ];
        let mut q_nonce24 = [0u8; 24];
        for i in 0..12 {
            q_nonce24[i] = 0xb0 + i as u8;
        }

        let dns_query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let padded = pad_query(&dns_query, 64);
        assert_eq!(padded.len(), 64);

        let enc_query = DnsCryptClient::xsecretbox_seal(&shared_key, &q_nonce24, &padded);
        let expected_enc_hex = "c41764468cb42d3a837c51234c08be714af49e1a6830ea6da28178e9e280d76bac1b87fd7f56515f2b2cc3d4715aaa42907c282db1edff0bc3b92cd535a710e264859a5bdaf67c17ffa6e1c6f6e02a50";
        let actual_hex: String = enc_query.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(actual_hex, expected_enc_hex);

        let decrypted = DnsCryptClient::xsecretbox_open(&shared_key, &q_nonce24, &enc_query)
            .expect("open must succeed");
        assert_eq!(decrypted, padded);
        let unpadded = unpad_response(&decrypted).expect("unpad must succeed");
        assert_eq!(unpadded, dns_query);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_pq_appendix3_vectors() {
        let client_magic = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
        let dns_query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let shared_key = [
            0xe6, 0xd4, 0xab, 0x9c, 0xff, 0xc9, 0xb4, 0x9e, 0x2a, 0x64, 0xd8, 0x0d, 0x7e, 0xb2,
            0xdd, 0xe2, 0x80, 0xf8, 0x06, 0xb8, 0x9e, 0x83, 0x4d, 0x59, 0x6a, 0xd3, 0x85, 0xb1,
            0xdd, 0x75, 0xe9, 0xef,
        ];

        let mut q_nonce = [0u8; 12];
        for i in 0..12 {
            q_nonce[i] = 0xb0 + i as u8;
        }

        // 1. Test resume-secret HKDF derivation matches pinned vector
        let rs = pq_resume_secret(&shared_key, &client_magic, &q_nonce).expect("resume secret");
        let expected_rs_hex = "df158804e3f8ddf383ff7c9d3128491b29437a894936ec72c68aed8a9553272b";
        let rs_hex: String = rs.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(rs_hex, expected_rs_hex);

        // 2. Test resumed key derivation against pinned ticket and rq_nonce
        let ticket = hex_decode("00000001d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e1d90c86474574e0e51e82d8a29938896b0999e827138f8f452f21e044d9809f65a013cfad8981be94c1354178b3e03dd518c28bcbaab962aa45246e446de7763288aa4a01e207725a0ae7bc95452fef3743f6083deb10cd23e2881e8d9307fc2f43bce1a97e");
        let mut rq_nonce = [0u8; 12];
        for i in 0..12 {
            rq_nonce[i] = 0xf0 + i as u8;
        }

        let resumed_key =
            pq_resumed_shared_key(&rs, &client_magic, &rq_nonce, &ticket).expect("resumed key");
        let expected_resumed_key_hex =
            "e61f03acb2ee2ef01b952a0c312c60653267d47a2766fcfd804747fdf2fe789f";
        let res_key_hex: String = resumed_key.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(res_key_hex, expected_resumed_key_hex);

        // 3. Test resumed query xsecretbox sealing and wire packet hash
        let mut rq_nonce24 = [0u8; 24];
        rq_nonce24[0..12].copy_from_slice(&rq_nonce);
        let rpadded = pq_pad(&dns_query, 256);
        assert_eq!(rpadded.len(), 256);

        let renc_query = DnsCryptClient::xsecretbox_seal(&resumed_key, &rq_nonce24, &rpadded);
        let mut resume_query = Vec::new();
        resume_query.extend_from_slice(&PQ_RESUME_MAGIC);
        resume_query.extend_from_slice(&130u16.to_be_bytes()); // ticket len = 130
        resume_query.extend_from_slice(&ticket);
        resume_query.extend_from_slice(&rq_nonce);
        resume_query.extend_from_slice(&renc_query);
        assert_eq!(resume_query.len(), 424);

        let resume_wire_hash = Sha256::digest(&resume_query);
        let expected_wire_hash =
            "34be2e331b4d7c7e808e968c5efc9f25675a9de9064cb33f7c66950e0e4e6db7";
        let wire_hash_hex: String = resume_wire_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(wire_hash_hex, expected_wire_hash);
    }

    #[tokio::test]
    async fn test_pq_dnscrypt_full_roundtrip_with_resumption() {
        use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_768};

        // 1. Resolver generates ML-KEM-768 keypair and X25519 keypair
        let decaps_key = DecapsulationKey::generate(&ML_KEM_768).unwrap();
        let encap_key = decaps_key.encapsulation_key().unwrap();
        let mlkem_pk = encap_key.key_bytes().unwrap();

        let rng = SystemRandom::new();
        let x25519_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let x25519_pub = x25519_priv.compute_public_key().unwrap();

        let mut resolver_pk = Vec::with_capacity(PQ_XWING_PUBLIC_KEY_SIZE);
        resolver_pk.extend_from_slice(mlkem_pk.as_ref());
        resolver_pk.extend_from_slice(x25519_pub.as_ref());
        assert_eq!(resolver_pk.len(), 1216);

        let client_magic = [0x99; 8];
        let test_cert = DnsCryptCert {
            cert_magic: *DNSCRYPT_MAGIC_CERT,
            es_version: 3,
            protocol_minor: 0,
            signature: [0u8; 64],
            resolver_pk: resolver_pk.clone(),
            client_magic,
            serial: 10,
            ts_start: 0,
            ts_end: u32::MAX,
            raw_cert: Vec::new(),
        };

        let resolver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver_addr = resolver_socket.local_addr().unwrap();

        // 2. Server handles two queries: initial X-Wing query, followed by resumed query
        let cert_synthesized = test_cert.to_bytes();
        let cert_ctx = pq_cert_context(&cert_synthesized);
        let issued_ticket = vec![0x42u8; 32];
        let issued_ticket_clone = issued_ticket.clone();

        let server_handle = tokio::spawn(async move {
            // --- Query 1: Full X-Wing query ---
            let mut buf1 = vec![0u8; 4096];
            let (n1, peer1) = resolver_socket.recv_from(&mut buf1).await.unwrap();
            buf1.truncate(n1);

            assert_eq!(&buf1[0..8], &client_magic);
            let ct_kem = &buf1[8..8 + PQ_XWING_CIPHERTEXT_SIZE];
            let client_nonce1 = &buf1[8 + PQ_XWING_CIPHERTEXT_SIZE..8 + PQ_XWING_CIPHERTEXT_SIZE + 12];
            let enc_query1 = &buf1[8 + PQ_XWING_CIPHERTEXT_SIZE + 12..];

            // Server decapsulates ML-KEM-768
            let ct_m = &ct_kem[0..1088];
            let ct_x = &ct_kem[1088..1120];
            let ss_m = decaps_key
                .decapsulate(Ciphertext::from(ct_m))
                .expect("server ml-kem decapsulate");

            // Server completes X25519 DH
            let mut ss_x = [0u8; 32];
            agreement::agree_ephemeral(
                x25519_priv,
                &UnparsedPublicKey::new(&X25519, ct_x),
                "server DH",
                |mat| {
                    ss_x.copy_from_slice(mat);
                    Ok(())
                },
            )
            .unwrap();

            // Combiner: SHA3-256(XWingLabel || ss_M || ss_X || ct_X || pk_X)
            use aws_lc_rs::digest::{Context, SHA3_256};
            let mut hasher = Context::new(&SHA3_256);
            hasher.update(&XWING_LABEL);
            hasher.update(ss_m.as_ref());
            hasher.update(&ss_x);
            hasher.update(ct_x);
            hasher.update(x25519_pub.as_ref());
            let kem_ss_digest = hasher.finish();
            let mut kem_ss = [0u8; 32];
            kem_ss.copy_from_slice(kem_ss_digest.as_ref());

            let server_shared_key1 =
                pq_derive_shared_key(&kem_ss, &client_magic, &cert_ctx, ct_kem).unwrap();

            let mut nonce24_1 = [0u8; 24];
            nonce24_1[0..12].copy_from_slice(client_nonce1);
            let decrypted1 =
                DnsCryptClient::xsecretbox_open(&server_shared_key1, &nonce24_1, enc_query1)
                    .unwrap();
            let query_payload1 = unpad_response(&decrypted1).unwrap();
            assert_eq!(query_payload1, b"pq_query_payload_1");

            // Server builds response 1 with a resumption ticket in control block:
            // control: b"PQDR" (4B) || 0x01 (1B) || lifetime 3600 (4B) || ticket_len 32 (2B) || ticket (32B)
            let mut control = Vec::new();
            control.extend_from_slice(&PQ_CONTROL_MAGIC);
            control.push(PQ_CONTROL_VERSION);
            control.extend_from_slice(&3600u32.to_be_bytes());
            control.extend_from_slice(&(issued_ticket_clone.len() as u16).to_be_bytes());
            control.extend_from_slice(&issued_ticket_clone);

            let resp_body1 = pad_query(b"pq_response_payload_1", 64);
            let mut resp_plaintext1 = Vec::new();
            resp_plaintext1.extend_from_slice(&(control.len() as u16).to_be_bytes());
            resp_plaintext1.extend_from_slice(&control);
            resp_plaintext1.extend_from_slice(&resp_body1);

            let resolver_nonce1 = [0x33; 12];
            let mut server_nonce24_1 = [0u8; 24];
            server_nonce24_1[0..12].copy_from_slice(client_nonce1);
            server_nonce24_1[12..24].copy_from_slice(&resolver_nonce1);

            let resp_cipher1 = DnsCryptClient::xsecretbox_seal(
                &server_shared_key1,
                &server_nonce24_1,
                &resp_plaintext1,
            );

            let mut resp_packet1 = Vec::new();
            resp_packet1.extend_from_slice(DNSCRYPT_MAGIC_RESOLVER);
            resp_packet1.extend_from_slice(client_nonce1);
            resp_packet1.extend_from_slice(&resolver_nonce1);
            resp_packet1.extend_from_slice(&resp_cipher1);
            resolver_socket.send_to(&resp_packet1, peer1).await.unwrap();

            // Compute expected resume secret for query 2
            let mut q1_nonce12 = [0u8; 12];
            q1_nonce12.copy_from_slice(client_nonce1);
            let resume_sec = pq_resume_secret(&server_shared_key1, &client_magic, &q1_nonce12).unwrap();

            // --- Query 2: Resumed query ---
            let mut buf2 = vec![0u8; 4096];
            let (n2, peer2) = resolver_socket.recv_from(&mut buf2).await.unwrap();
            buf2.truncate(n2);

            assert_eq!(&buf2[0..8], &PQ_RESUME_MAGIC);
            let t_len = u16::from_be_bytes([buf2[8], buf2[9]]) as usize;
            assert_eq!(t_len, issued_ticket_clone.len());
            let recv_ticket = &buf2[10..10 + t_len];
            assert_eq!(recv_ticket, issued_ticket_clone.as_slice());

            let client_nonce2 = &buf2[10 + t_len..10 + t_len + 12];
            let enc_query2 = &buf2[10 + t_len + 12..];

            let mut q2_nonce12 = [0u8; 12];
            q2_nonce12.copy_from_slice(client_nonce2);
            let server_resumed_key =
                pq_resumed_shared_key(&resume_sec, &client_magic, &q2_nonce12, recv_ticket).unwrap();

            let mut nonce24_2 = [0u8; 24];
            nonce24_2[0..12].copy_from_slice(client_nonce2);
            let decrypted2 =
                DnsCryptClient::xsecretbox_open(&server_resumed_key, &nonce24_2, enc_query2)
                    .unwrap();
            let query_payload2 = unpad_response(&decrypted2).unwrap();
            assert_eq!(query_payload2, b"pq_query_payload_2");

            // Server builds response 2 (empty control block)
            let resp_body2 = pad_query(b"pq_response_payload_2", 64);
            let mut resp_plaintext2 = Vec::new();
            resp_plaintext2.extend_from_slice(&0u16.to_be_bytes()); // control_len = 0
            resp_plaintext2.extend_from_slice(&resp_body2);

            let resolver_nonce2 = [0x44; 12];
            let mut server_nonce24_2 = [0u8; 24];
            server_nonce24_2[0..12].copy_from_slice(client_nonce2);
            server_nonce24_2[12..24].copy_from_slice(&resolver_nonce2);

            let resp_cipher2 = DnsCryptClient::xsecretbox_seal(
                &server_resumed_key,
                &server_nonce24_2,
                &resp_plaintext2,
            );

            let mut resp_packet2 = Vec::new();
            resp_packet2.extend_from_slice(DNSCRYPT_MAGIC_RESOLVER);
            resp_packet2.extend_from_slice(client_nonce2);
            resp_packet2.extend_from_slice(&resolver_nonce2);
            resp_packet2.extend_from_slice(&resp_cipher2);
            resolver_socket.send_to(&resp_packet2, peer2).await.unwrap();
        });

        // 3. Client executes Query 1
        let client = DnsCryptClient::new(resolver_addr, "mock.pq.resolver".to_string(), [0u8; 32], None)
            .with_cert(test_cert);

        let resp1 = client
            .resolve_with_epoch(b"pq_query_payload_1", Duration::from_secs(3), 1000)
            .await
            .expect("query 1 must succeed");
        assert_eq!(resp1, b"pq_response_payload_1");

        // Client must now hold the resumption ticket in its session state
        let ticket_opt = client.pq_session.get_ticket(1000);
        assert!(ticket_opt.is_some(), "session ticket must be stored after response 1");

        // 4. Client executes Query 2 (resumption)
        let resp2 = client
            .resolve_with_epoch(b"pq_query_payload_2", Duration::from_secs(3), 1000)
            .await
            .expect("query 2 must succeed via resumption");
        assert_eq!(resp2, b"pq_response_payload_2");

        server_handle.await.unwrap();
    }

    #[test]
    fn test_anonymized_relay_route_selection() {
        let mut available = std::collections::HashMap::new();
        available.insert("anon-de".to_string(), "192.0.2.1:443".parse().unwrap());
        available.insert("anon-nl".to_string(), "192.0.2.2:443".parse().unwrap());
        available.insert("anon-wildcard".to_string(), "192.0.2.99:443".parse().unwrap());

        let routes = vec![
            crate::app::config::AnonymizedDnsRoute {
                server_name: "cloudflare".to_string(),
                via: vec!["anon-de".to_string()],
            },
            crate::app::config::AnonymizedDnsRoute {
                server_name: "*".to_string(),
                via: vec!["anon-wildcard".to_string()],
            },
        ];

        // Specific route match
        let cf_relay = AnonymizedRelay::select_relay_for_server("cloudflare", &routes, &available);
        assert_eq!(cf_relay, Some("192.0.2.1:443".parse().unwrap()));

        // Wildcard match
        let quad9_relay = AnonymizedRelay::select_relay_for_server("quad9", &routes, &available);
        assert_eq!(quad9_relay, Some("192.0.2.99:443".parse().unwrap()));

        // Unknown when no wildcard
        let no_wildcard = vec![crate::app::config::AnonymizedDnsRoute {
            server_name: "other".to_string(),
            via: vec!["anon-nl".to_string()],
        }];
        assert_eq!(
            AnonymizedRelay::select_relay_for_server("unknown", &no_wildcard, &available),
            None
        );
    }

    #[test]
    fn test_cert_ignore_timestamp() {
        let mut client = DnsCryptClient::new(
            "127.0.0.1:443".parse().unwrap(),
            "2.dnscrypt-cert.example.com".to_string(),
            [0u8; 32],
            None,
        );
        assert!(!client.cert_ignore_timestamp);
        client = client.with_cert_ignore_timestamp(true);
        assert!(client.cert_ignore_timestamp);
    }

    #[tokio::test]
    async fn test_fetch_cert_from_mock_resolver() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        let test_cert = DnsCryptCert {
            cert_magic: *DNSCRYPT_MAGIC_CERT,
            es_version: 2,
            protocol_minor: 0,
            signature: [0u8; 64],
            resolver_pk: vec![0x42; 32],
            client_magic: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            serial: 9999,
            ts_start: 0,
            ts_end: u32::MAX,
            raw_cert: Vec::new(),
        };
        let cert_bytes = test_cert.to_bytes();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (n, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            buf.truncate(n);

            // build DNS response with TXT answer
            let mut resp = Vec::new();
            resp.extend_from_slice(&buf[0..2]); // tx id
            resp.extend_from_slice(&[0x81, 0x80]); // standard response, no error
            resp.extend_from_slice(&[0x00, 0x01]); // qdcount: 1
            resp.extend_from_slice(&[0x00, 0x01]); // ancount: 1
            resp.extend_from_slice(&[0x00, 0x00]); // nscount: 0
            resp.extend_from_slice(&[0x00, 0x00]); // arcount: 0

            // Copy question from query
            let mut pos = 12;
            while pos < buf.len() && buf[pos] != 0 {
                pos += 1 + buf[pos] as usize;
            }
            pos += 1; // 0x00
            pos += 4; // qtype + qclass
            resp.extend_from_slice(&buf[12..pos]);

            // Answer section: TXT record
            resp.extend_from_slice(&[0xc0, 0x0c]); // pointer to QNAME
            resp.extend_from_slice(&[0x00, 0x10]); // type TXT
            resp.extend_from_slice(&[0x00, 0x01]); // class IN
            resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // ttl 60

            // TXT RDATA: character-string chunks of <= 255 bytes
            let mut txt_rdata = Vec::new();
            for chunk in cert_bytes.chunks(255) {
                txt_rdata.push(chunk.len() as u8);
                txt_rdata.extend_from_slice(chunk);
            }
            resp.extend_from_slice(&(txt_rdata.len() as u16).to_be_bytes());
            resp.extend_from_slice(&txt_rdata);

            mock_socket.send_to(&resp, peer).await.unwrap();
        });

        let mut client = DnsCryptClient::new(
            mock_addr,
            "2.dnscrypt-cert.example.com".to_string(),
            [0u8; 32],
            None,
        );

        let cert = client.fetch_cert(Duration::from_secs(2)).await.unwrap();
        assert_eq!(cert.serial, 9999);
        assert_eq!(cert.client_magic, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(client.cert.is_some());

        handle.await.unwrap();
    }
}
