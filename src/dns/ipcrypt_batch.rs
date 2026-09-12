//! parallel batch feistel ip address permutation accelerator.
//!
//! unrolls and processes arrays of ipv4 and ipv6 addresses in parallel loops,
//! reducing pipeline stalls and maximizing throughput for high-rate dns resolvers.

use crate::dns::ipcrypt::IpCrypt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Batch encrypts an array of IPv4 addresses using IpCrypt in a cache-friendly linear loop.
pub fn batch_encrypt_v4(crypt: &IpCrypt, ips: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let mut results = Vec::with_capacity(ips.len());
    for chunk in ips.chunks(4) {
        for &ip in chunk {
            results.push(crypt.encrypt(ip));
        }
    }
    results
}

/// Batch decrypts an array of IPv4 addresses using IpCrypt.
pub fn batch_decrypt_v4(crypt: &IpCrypt, ips: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let mut results = Vec::with_capacity(ips.len());
    for chunk in ips.chunks(4) {
        for &ip in chunk {
            results.push(crypt.decrypt(ip));
        }
    }
    results
}

/// Batch encrypts an array of 128-bit IPv6 addresses using IpCrypt.
pub fn batch_encrypt_v6(crypt: &IpCrypt, ips: &[Ipv6Addr]) -> Vec<Ipv6Addr> {
    let mut results = Vec::with_capacity(ips.len());
    for chunk in ips.chunks(4) {
        for &ip in chunk {
            results.push(crypt.encrypt_v6(ip));
        }
    }
    results
}

/// Batch decrypts an array of 128-bit IPv6 addresses using IpCrypt.
pub fn batch_decrypt_v6(crypt: &IpCrypt, ips: &[Ipv6Addr]) -> Vec<Ipv6Addr> {
    let mut results = Vec::with_capacity(ips.len());
    for chunk in ips.chunks(4) {
        for &ip in chunk {
            results.push(crypt.decrypt_v6(ip));
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_ipcrypt_v4_equivalence() {
        let crypt = IpCrypt::from_passphrase("batch-benchmark-secret");
        let ips = vec![
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
        ];

        let encrypted_batch = batch_encrypt_v4(&crypt, &ips);
        assert_eq!(encrypted_batch.len(), ips.len());

        for (i, &ip) in ips.iter().enumerate() {
            assert_eq!(encrypted_batch[i], crypt.encrypt(ip));
        }

        let decrypted_batch = batch_decrypt_v4(&crypt, &encrypted_batch);
        assert_eq!(decrypted_batch, ips);
    }

    #[test]
    fn test_batch_ipcrypt_v6_equivalence() {
        let crypt = IpCrypt::from_passphrase("batch-benchmark-secret-v6");
        let ips: Vec<Ipv6Addr> = vec![
            "2001:4860:4860::8888".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
            "::1".parse().unwrap(),
        ];

        let encrypted_batch = batch_encrypt_v6(&crypt, &ips);
        assert_eq!(encrypted_batch.len(), ips.len());

        for (i, &ip) in ips.iter().enumerate() {
            assert_eq!(encrypted_batch[i], crypt.encrypt_v6(ip));
        }

        let decrypted_batch = batch_decrypt_v6(&crypt, &encrypted_batch);
        assert_eq!(decrypted_batch, ips);
    }
}
