use std::{env, sync::OnceLock, time::Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

const DEFAULT_ARGON2_MEMORY_KIB: u32 = 98_304;
const DEFAULT_ARGON2_ITERATIONS: u32 = 4;
const DEFAULT_ARGON2_PARALLELISM: u32 = 1;
const DEFAULT_ARGON2_SALT_LEN: usize = 16;
const DEFAULT_NONCE_LEN: usize = 24;
const DEFAULT_KEY_LEN: usize = 32;
const MAX_SUPPORTED_ARGON2_MEMORY_KIB: u32 = 262_144;
const MAX_SUPPORTED_ARGON2_ITERATIONS: u32 = 6;
const MAX_SUPPORTED_ARGON2_PARALLELISM: u32 = 4;
const CALIBRATION_TARGET_MILLIS: u128 = 250;
const CALIBRATION_MEMORY_CANDIDATES_KIB: &[u32] = &[98_304, 131_072, 196_608, 262_144];

/// Supported password-based key derivation algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KdfAlgorithm {
    /// Argon2id as specified in RFC 9106.
    Argon2id,
}

impl KdfAlgorithm {
    /// Returns the persisted algorithm identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Argon2id => "argon2id",
        }
    }
}

/// Supported authenticated encryption algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AeadAlgorithm {
    /// `XChaCha20Poly1305` using an extended 192-bit nonce.
    XChaCha20Poly1305,
}

impl AeadAlgorithm {
    /// Returns the persisted algorithm identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XChaCha20Poly1305 => "xchacha20poly1305",
        }
    }
}

/// Post-Argon2 file-key derivation schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeySchedule {
    /// Legacy v1 behavior: Argon2 output is used directly as the file key.
    LegacyDirect,
    /// Current behavior: Argon2 output is expanded through HKDF-SHA256.
    HkdfSha256V1,
}

impl KeySchedule {
    /// Returns the persisted identifier for schedules that are explicitly stored.
    #[must_use]
    pub const fn persisted_name(self) -> Option<&'static str> {
        match self {
            Self::LegacyDirect => None,
            Self::HkdfSha256V1 => Some("hkdf-sha256-v1"),
        }
    }
}

/// File-specific KDF parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KdfParams {
    /// Argon2 version identifier stored in the file.
    pub version: u32,
    /// Random salt length in bytes.
    pub salt_len: usize,
    /// Memory cost in kibibytes.
    pub memory_kib: u32,
    /// Iteration count.
    pub iterations: u32,
    /// Parallelism lanes.
    pub parallelism: u32,
}

/// Upper bounds accepted when opening an existing file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KdfLimits {
    /// Maximum accepted Argon2 memory cost in kibibytes.
    pub memory_kib: u32,
    /// Maximum accepted Argon2 iteration count.
    pub iterations: u32,
    /// Maximum accepted Argon2 parallelism lanes.
    pub parallelism: u32,
}

/// Centralized crypto policy for v1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoPolicy {
    /// Selected KDF algorithm.
    pub kdf_algorithm: KdfAlgorithm,
    /// Selected AEAD algorithm.
    pub aead_algorithm: AeadAlgorithm,
    /// KDF parameters.
    pub kdf_params: KdfParams,
    /// Maximum KDF settings accepted when reading an existing file.
    pub kdf_limits: KdfLimits,
    /// Nonce length for the chosen AEAD.
    pub nonce_len: usize,
    /// Derived key length.
    pub key_len: usize,
    /// Key schedule used for newly written files.
    pub key_schedule: KeySchedule,
}

impl CryptoPolicy {
    /// Returns the fixed v1 crypto policy.
    #[must_use]
    pub fn v1() -> Self {
        Self::default()
    }

    /// Returns a cached interactive policy that auto-tunes Argon2 upward for
    /// this host while preserving broad read compatibility.
    #[must_use]
    pub fn calibrated_interactive() -> Self {
        static CACHED: OnceLock<CryptoPolicy> = OnceLock::new();
        CACHED.get_or_init(Self::calibrate_interactive).clone()
    }

    fn calibrate_interactive() -> Self {
        let mut policy = Self::default();
        if let Some(overridden) = overridden_kdf_params(&policy.kdf_params, &policy.kdf_limits) {
            policy.kdf_params = overridden;
            return policy;
        }

        let mut measured_candidates = Vec::with_capacity(CALIBRATION_MEMORY_CANDIDATES_KIB.len());
        for &candidate_memory_kib in CALIBRATION_MEMORY_CANDIDATES_KIB {
            if candidate_memory_kib < policy.kdf_params.memory_kib
                || candidate_memory_kib > policy.kdf_limits.memory_kib
            {
                continue;
            }

            let Some(duration_millis) = benchmark_argon2_millis(
                candidate_memory_kib,
                policy.kdf_params.iterations,
                policy.kdf_params.parallelism,
                policy.key_len,
            ) else {
                break;
            };
            measured_candidates.push((candidate_memory_kib, duration_millis));
            if duration_millis > calibration_target_millis() {
                break;
            }
        }

        policy.kdf_params.memory_kib = select_calibrated_memory(
            &measured_candidates,
            policy.kdf_params.memory_kib,
            calibration_target_millis(),
        );
        policy
    }
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self {
            kdf_algorithm: KdfAlgorithm::Argon2id,
            aead_algorithm: AeadAlgorithm::XChaCha20Poly1305,
            kdf_params: KdfParams {
                version: 19,
                salt_len: DEFAULT_ARGON2_SALT_LEN,
                memory_kib: DEFAULT_ARGON2_MEMORY_KIB,
                iterations: DEFAULT_ARGON2_ITERATIONS,
                parallelism: DEFAULT_ARGON2_PARALLELISM,
            },
            kdf_limits: KdfLimits {
                memory_kib: MAX_SUPPORTED_ARGON2_MEMORY_KIB,
                iterations: MAX_SUPPORTED_ARGON2_ITERATIONS,
                parallelism: MAX_SUPPORTED_ARGON2_PARALLELISM,
            },
            nonce_len: DEFAULT_NONCE_LEN,
            key_len: DEFAULT_KEY_LEN,
            key_schedule: KeySchedule::HkdfSha256V1,
        }
    }
}

fn overridden_kdf_params(base: &KdfParams, limits: &KdfLimits) -> Option<KdfParams> {
    let memory_override = env::var("ALBUS_ARGON2_MEMORY_KIB")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    let iterations_override = env::var("ALBUS_ARGON2_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());

    if memory_override.is_none() && iterations_override.is_none() {
        return None;
    }

    Some(KdfParams {
        version: base.version,
        salt_len: base.salt_len,
        memory_kib: memory_override
            .unwrap_or(base.memory_kib)
            .clamp(base.memory_kib, limits.memory_kib),
        iterations: iterations_override
            .unwrap_or(base.iterations)
            .clamp(base.iterations, limits.iterations),
        parallelism: base.parallelism,
    })
}

fn calibration_target_millis() -> u128 {
    env::var("ALBUS_ARGON2_TARGET_MILLIS")
        .ok()
        .and_then(|value| value.parse::<u128>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(CALIBRATION_TARGET_MILLIS)
}

fn benchmark_argon2_millis(
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    key_len: usize,
) -> Option<u128> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(key_len)).ok()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; DEFAULT_KEY_LEN];
    let start = Instant::now();
    argon2
        .hash_password_into(
            b"albus-calibration-passphrase",
            &[0x5A; DEFAULT_ARGON2_SALT_LEN],
            &mut output,
        )
        .ok()?;
    output.zeroize();
    Some(start.elapsed().as_millis())
}

fn select_calibrated_memory(
    measured_candidates: &[(u32, u128)],
    base_memory_kib: u32,
    target_millis: u128,
) -> u32 {
    let mut selected = base_memory_kib;
    for &(memory_kib, duration_millis) in measured_candidates {
        if duration_millis <= target_millis {
            selected = memory_kib;
        } else {
            break;
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::select_calibrated_memory;

    #[test]
    fn calibration_prefers_the_highest_memory_within_target() {
        let selected = select_calibrated_memory(
            &[(98_304, 120), (131_072, 180), (196_608, 310)],
            98_304,
            250,
        );
        assert_eq!(selected, 131_072);
    }

    #[test]
    fn calibration_falls_back_to_the_base_memory_when_the_first_probe_is_too_slow() {
        let selected = select_calibrated_memory(&[(98_304, 320), (131_072, 410)], 98_304, 250);
        assert_eq!(selected, 98_304);
    }
}
