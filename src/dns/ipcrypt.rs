//! ipcrypt format-preserving 32-bit ip address permutation and pseudonymization.
//!
//! transforms 32-bit ipv4 addresses into deterministic pseudo-ipv4 addresses using a 16-byte key,
//! preventing client ip disclosure in dns audit logs while preserving analytical grouping.

use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IpCrypt {
    key: [u8; 16],
}

impl std::fmt::Debug for IpCrypt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IpCrypt { key: [REDACTED] }")
    }
}

impl IpCrypt {
    pub fn new(key: [u8; 16]) -> Self {
        Self { key }
    }

    /// Derives a deterministic 128-bit key from an arbitrary human-readable passphrase using SHA-256.
    ///
    /// This method is intended for configuration convenience, human-readable passphrases, and
    /// deterministic testing. For production audit log pseudonymization where maximum security
    /// and entropy are required, a random 16-byte hex key should be provided via [`IpCrypt::from_hex`].
    pub fn from_passphrase(passphrase: &str) -> Self {
        let mut hash = Sha256::digest(passphrase.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash[..16]);
        hash.zeroize();
        Self { key }
    }

    // parses 16-byte (32-character) hex string into key
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        let clean = hex_str.trim().trim_start_matches("0x");
        if clean.len() != 32 {
            return Err("hex key must be exactly 32 hex characters (16 bytes)".to_string());
        }
        let mut key = [0u8; 16];
        for i in 0..16 {
            let byte_str = &clean[i * 2..i * 2 + 2];
            key[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|e| format!("invalid hex at byte {}: {}", i, e))?;
        }
        Ok(Self { key })
    }

    // encrypts / pseudonymizes an ipv4 address
    pub fn encrypt(&self, ip: Ipv4Addr) -> Ipv4Addr {
        let mut b = ip.octets();
        let k = &self.key;

        // 4-round feistel network
        b[0] = b[0].wrapping_add(k[0]);
        b[1] = b[1].wrapping_add(k[1]);
        b[2] = b[2].wrapping_add(k[2]);
        b[3] = b[3].wrapping_add(k[3]);

        b[1] ^= rotl8(b[0].wrapping_add(b[3]), 2);
        b[2] = b[2].wrapping_add(b[1] ^ k[4]);
        b[3] ^= rotl8(b[2].wrapping_add(b[0]), 5);
        b[0] = b[0].wrapping_add(b[3] ^ k[5]);

        b[1] = b[1].wrapping_add(k[6]);
        b[2] = b[2].wrapping_add(k[7]);
        b[3] = b[3].wrapping_add(k[8]);
        b[0] = b[0].wrapping_add(k[9]);

        b[2] ^= rotl8(b[1].wrapping_add(b[0]), 3);
        b[3] = b[3].wrapping_add(b[2] ^ k[10]);
        b[0] ^= rotl8(b[3].wrapping_add(b[1]), 4);
        b[1] = b[1].wrapping_add(b[0] ^ k[11]);

        b[0] ^= k[12];
        b[1] ^= k[13];
        b[2] ^= k[14];
        b[3] ^= k[15];

        Ipv4Addr::from(b)
    }

    // decrypts / restores the original ipv4 address from the pseudonym
    pub fn decrypt(&self, ip: Ipv4Addr) -> Ipv4Addr {
        let mut b = ip.octets();
        let k = &self.key;

        b[0] ^= k[12];
        b[1] ^= k[13];
        b[2] ^= k[14];
        b[3] ^= k[15];

        b[1] = b[1].wrapping_sub(b[0] ^ k[11]);
        b[0] ^= rotl8(b[3].wrapping_add(b[1]), 4);
        b[3] = b[3].wrapping_sub(b[2] ^ k[10]);
        b[2] ^= rotl8(b[1].wrapping_add(b[0]), 3);

        b[1] = b[1].wrapping_sub(k[6]);
        b[2] = b[2].wrapping_sub(k[7]);
        b[3] = b[3].wrapping_sub(k[8]);
        b[0] = b[0].wrapping_sub(k[9]);

        b[0] = b[0].wrapping_sub(b[3] ^ k[5]);
        b[3] ^= rotl8(b[2].wrapping_add(b[0]), 5);
        b[2] = b[2].wrapping_sub(b[1] ^ k[4]);
        b[1] ^= rotl8(b[0].wrapping_add(b[3]), 2);

        b[0] = b[0].wrapping_sub(k[0]);
        b[1] = b[1].wrapping_sub(k[1]);
        b[2] = b[2].wrapping_sub(k[2]);
        b[3] = b[3].wrapping_sub(k[3]);

        Ipv4Addr::from(b)
    }

    /// Format-preserving 128-bit IPv6 address permutation and pseudonymization.
    /// Uses an 8-round constant-time Feistel network operating over four 32-bit words.
    pub fn encrypt_v6(&self, ip: Ipv6Addr) -> Ipv6Addr {
        let octets = ip.octets();
        let mut w = [
            u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
            u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
            u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
            u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]),
        ];

        let rk = self.derive_v6_round_keys();

        // 8-round generalized balanced Feistel network
        for round in 0..8 {
            let k = rk[round % 4];
            let f = feistel_round_f(w[0], k, round as u32);
            let next_w1 = w[1] ^ f;
            w[1] = w[2];
            w[2] = w[3];
            w[3] = w[0];
            w[0] = next_w1;
        }

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&w[0].to_be_bytes());
        out[4..8].copy_from_slice(&w[1].to_be_bytes());
        out[8..12].copy_from_slice(&w[2].to_be_bytes());
        out[12..16].copy_from_slice(&w[3].to_be_bytes());
        Ipv6Addr::from(out)
    }

    /// Decrypts / restores the original 128-bit IPv6 address from its pseudonym.
    pub fn decrypt_v6(&self, ip: Ipv6Addr) -> Ipv6Addr {
        let octets = ip.octets();
        let mut w = [
            u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
            u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
            u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
            u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]),
        ];

        let rk = self.derive_v6_round_keys();

        // Reverse 8 rounds
        for round in (0..8).rev() {
            let k = rk[round % 4];
            let prev_w0 = w[3];
            let f = feistel_round_f(prev_w0, k, round as u32);
            let prev_w1 = w[0] ^ f;
            w[0] = prev_w0;
            w[3] = w[2];
            w[2] = w[1];
            w[1] = prev_w1;
        }

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&w[0].to_be_bytes());
        out[4..8].copy_from_slice(&w[1].to_be_bytes());
        out[8..12].copy_from_slice(&w[2].to_be_bytes());
        out[12..16].copy_from_slice(&w[3].to_be_bytes());
        Ipv6Addr::from(out)
    }

    #[inline(always)]
    fn derive_v6_round_keys(&self) -> [u32; 4] {
        [
            u32::from_be_bytes([self.key[0], self.key[1], self.key[2], self.key[3]]),
            u32::from_be_bytes([self.key[4], self.key[5], self.key[6], self.key[7]]),
            u32::from_be_bytes([self.key[8], self.key[9], self.key[10], self.key[11]]),
            u32::from_be_bytes([self.key[12], self.key[13], self.key[14], self.key[15]]),
        ]
    }
}

#[inline(always)]
fn feistel_round_f(x: u32, k: u32, round: u32) -> u32 {
    let mixed = x.wrapping_add(k).rotate_left(7);
    let round_const = 0x9e3779b9u32.wrapping_mul(round.wrapping_add(1));
    (mixed ^ round_const).rotate_left(13)
}

#[inline(always)]
fn rotl8(x: u8, n: u32) -> u8 {
    (x << n) | (x >> (8 - n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipcrypt_encrypt_decrypt_roundtrip() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let ip_crypt = IpCrypt::new(key);

        let original = Ipv4Addr::new(192, 168, 1, 100);
        let encrypted = ip_crypt.encrypt(original);
        assert_ne!(original, encrypted);

        let decrypted = ip_crypt.decrypt(encrypted);
        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_ipcrypt_from_hex_and_passphrase() {
        let hex = "0123456789abcdef0123456789abcdef";
        let crypt = IpCrypt::from_hex(hex).expect("valid hex key");
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let enc = crypt.encrypt(ip);
        assert_eq!(crypt.decrypt(enc), ip);

        // invalid hex length
        assert!(IpCrypt::from_hex("012345").is_err());

        // passphrase test
        let pass_crypt = IpCrypt::from_passphrase("albus-secret-audit-key");
        let pass_enc = pass_crypt.encrypt(ip);
        assert_eq!(pass_crypt.decrypt(pass_enc), ip);
    }

    #[test]
    fn test_passphrase_derivation_deterministic() {
        let crypt1 = IpCrypt::from_passphrase("albus-secret-audit-key");
        let crypt2 = IpCrypt::from_passphrase("albus-secret-audit-key");
        let crypt3 = IpCrypt::from_passphrase("different-passphrase");

        // deterministic: same passphrase produces identical key and ciphertext
        assert_eq!(crypt1.key, crypt2.key);
        // different passphrase produces different key
        assert_ne!(crypt1.key, crypt3.key);

        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let enc1 = crypt1.encrypt(ip);
        let enc2 = crypt2.encrypt(ip);
        let enc3 = crypt3.encrypt(ip);

        assert_eq!(enc1, enc2);
        assert_ne!(enc1, enc3);

        assert_eq!(crypt1.decrypt(enc1), ip);
        assert_eq!(crypt3.decrypt(enc3), ip);
    }

    #[test]
    fn test_ipcrypt_v6_roundtrip() {
        let key = [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45,
            0x23, 0x01,
        ];
        let ip_crypt = IpCrypt::new(key);

        let original: Ipv6Addr = "2001:db8:85a3::8a2e:370:7334".parse().unwrap();
        let encrypted = ip_crypt.encrypt_v6(original);
        assert_ne!(original, encrypted);

        let decrypted = ip_crypt.decrypt_v6(encrypted);
        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_ipcrypt_debug_redacted() {
        let crypt = IpCrypt::from_passphrase("super-confidential");
        let debug_str = format!("{:?}", crypt);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("super-confidential"));
    }
}
