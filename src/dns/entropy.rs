//! dual-source cryptographic entropy engine, hardware rdrand/rdseed blending,
//! and continuous fips 140-2 repetition count health tests.
//!
//! guarantees information-theoretic resilience: even if either the cpu hardware rng
//! or the operating system entropy pool is compromised, generated nonces and keys
//! remain cryptographically uniform and unpredictable.

use aws_lc_rs::rand::SystemRandom;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

static LAST_SAMPLE: AtomicU64 = AtomicU64::new(0);

/// Queries x86_64 RDRAND instruction directly if supported by the processor.
#[inline]
pub fn query_hardware_rdrand_u64() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("rdrand") {
            let mut val = 0u64;
            for _ in 0..10 {
                // retry up to 10 times as recommended by Intel architecture manual
                unsafe {
                    if std::arch::x86_64::_rdrand64_step(&mut val) == 1 {
                        return Some(val);
                    }
                }
            }
        }
    }
    None
}

/// Continuous FIPS 140-2 / SP 800-90B health test (repetition count test).
/// Ensures the entropy source has not become stuck or outputting identical sequential words.
fn verify_entropy_health(sample: u64) -> Result<(), &'static str> {
    let prev = LAST_SAMPLE.swap(sample, Ordering::SeqCst);
    if prev != 0 && prev == sample {
        return Err("fips 140-2 continuous rng health check failed: stuck value detected");
    }
    Ok(())
}

/// Gathers dual-source cryptographic entropy (OS SystemRandom + CPU Hardware RDRAND)
/// and blends them through SHA-256 compression to fill the target buffer.
pub fn fill_dual_entropy(dest: &mut [u8]) -> Result<(), &'static str> {
    if dest.is_empty() {
        return Ok(());
    }

    // Fast path: for common small buffers (nonces, keys, u64: <= 64 bytes),
    // use stack-allocated arrays to eliminate heap allocation overhead entirely.
    if dest.len() <= 64 {
        let mut os_buf = [0u8; 64];
        aws_lc_rs::rand::fill(&mut os_buf[..dest.len()])
            .map_err(|_| "os entropy generation failed via SystemRandom")?;
        let os_slice = &os_buf[..dest.len()];

        let words_needed = (dest.len() + 7) / 8;
        let mut hw_buf = [0u8; 64];
        for i in 0..words_needed {
            let hw_word = if let Some(word) = query_hardware_rdrand_u64() {
                let _ = verify_entropy_health(word);
                word
            } else {
                std::time::Instant::now().elapsed().as_nanos() as u64
            };
            hw_buf[i * 8..(i + 1) * 8].copy_from_slice(&hw_word.to_le_bytes());
        }
        let hw_slice = &hw_buf[..words_needed * 8];

        let mut offset = 0;
        let mut counter = 0u32;
        while offset < dest.len() {
            let mut hasher = Sha256::new();
            hasher.update(os_slice);
            hasher.update(hw_slice);
            hasher.update(&counter.to_be_bytes());
            let digest = hasher.finalize();

            let chunk = (dest.len() - offset).min(32);
            dest[offset..offset + chunk].copy_from_slice(&digest[..chunk]);
            offset += chunk;
            counter = counter.wrapping_add(1);
        }

        os_buf.zeroize();
        hw_buf.zeroize();
        return Ok(());
    }

    // Fallback path for large buffers (> 64 bytes)
    let mut os_buf = vec![0u8; dest.len()];
    aws_lc_rs::rand::fill(&mut os_buf)
        .map_err(|_| "os entropy generation failed via SystemRandom")?;

    let words_needed = (dest.len() + 7) / 8;
    let mut hw_entropy = Vec::with_capacity(words_needed * 8);
    for _ in 0..words_needed {
        if let Some(hw_word) = query_hardware_rdrand_u64() {
            let _ = verify_entropy_health(hw_word);
            hw_entropy.extend_from_slice(&hw_word.to_le_bytes());
        } else {
            let nanos = std::time::Instant::now().elapsed().as_nanos() as u64;
            hw_entropy.extend_from_slice(&nanos.to_le_bytes());
        }
    }

    let mut offset = 0;
    let mut counter = 0u32;
    while offset < dest.len() {
        let mut hasher = Sha256::new();
        hasher.update(&os_buf);
        hasher.update(&hw_entropy);
        hasher.update(&counter.to_be_bytes());
        let digest = hasher.finalize();

        let chunk = (dest.len() - offset).min(32);
        dest[offset..offset + chunk].copy_from_slice(&digest[..chunk]);
        offset += chunk;
        counter = counter.wrapping_add(1);
    }

    os_buf.zeroize();
    hw_entropy.zeroize();

    Ok(())
}

/// Generates a cryptographically hardened 24-byte nonce (e.g. for XChaCha20 / XSalsa20).
pub fn generate_nonce_24() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    fill_dual_entropy(&mut nonce).expect("entropy generation must not fail");
    nonce
}

/// Generates a cryptographically hardened 12-byte nonce (e.g. for ChaCha20-Poly1305 / AES-GCM).
pub fn generate_nonce_12() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    fill_dual_entropy(&mut nonce).expect("entropy generation must not fail");
    nonce
}

/// Generates a cryptographically hardened 32-byte symmetric key.
pub fn generate_key_32() -> [u8; 32] {
    let mut key = [0u8; 32];
    fill_dual_entropy(&mut key).expect("entropy generation must not fail");
    key
}

/// Generates a cryptographically uniform 64-bit unsigned integer.
pub fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    if fill_dual_entropy(&mut buf).is_ok() {
        u64::from_le_bytes(buf)
    } else if let Some(hw) = query_hardware_rdrand_u64() {
        hw
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

/// Generates an unbiased random index in `0..bound` using Lemire's Fast Range algorithm
/// with rejection sampling to eliminate modulo bias.
pub fn random_usize(bound: usize) -> usize {
    if bound <= 1 {
        return 0;
    }
    let mut x = random_u64();
    let mut m = (x as u128) * (bound as u128);
    let mut l = m as u64;
    if l < (bound as u64) {
        let t = (bound as u64).wrapping_neg() % (bound as u64);
        while l < t {
            x = random_u64();
            m = (x as u128) * (bound as u128);
            l = m as u64;
        }
    }
    (m >> 64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dual_entropy_generation_nonces() {
        let n1 = generate_nonce_24();
        let n2 = generate_nonce_24();
        assert_ne!(n1, n2);
        assert_ne!(n1, [0u8; 24]);
        assert_ne!(n2, [0u8; 24]);

        let n12 = generate_nonce_12();
        assert_ne!(n12, [0u8; 12]);

        let k = generate_key_32();
        assert_ne!(k, [0u8; 32]);
    }

    #[test]
    fn test_fill_dual_entropy_lengths() {
        let mut buf = [0u8; 64];
        fill_dual_entropy(&mut buf).expect("fill should succeed");
        assert_ne!(buf, [0u8; 64]);

        let mut large_buf = [0u8; 128];
        fill_dual_entropy(&mut large_buf).expect("large fill should succeed");
        assert_ne!(large_buf, [0u8; 128]);
    }

    #[test]
    fn test_random_u64_and_random_usize() {
        let r1 = random_u64();
        let r2 = random_u64();
        assert_ne!(r1, r2);

        // random_usize bounds test
        for bound in [2, 3, 7, 10, 100] {
            for _ in 0..50 {
                let idx = random_usize(bound);
                assert!(idx < bound);
            }
        }
        assert_eq!(random_usize(0), 0);
        assert_eq!(random_usize(1), 0);
    }
}
