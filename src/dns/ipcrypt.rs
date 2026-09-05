//! ipcrypt format-preserving 32-bit ip address permutation and pseudonymization.
//!
//! transforms 32-bit ipv4 addresses into deterministic pseudo-ipv4 addresses using a 16-byte key,
//! preventing client ip disclosure in dns audit logs while preserving analytical grouping.

use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

pub struct IpCrypt {
    key: [u8; 16],
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
        let hash = Sha256::digest(passphrase.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash[..16]);
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
}

impl Drop for IpCrypt {
    fn drop(&mut self) {
        for b in self.key.iter_mut() {
            unsafe {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
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
}
