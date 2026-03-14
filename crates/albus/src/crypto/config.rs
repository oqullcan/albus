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

/// Centralized crypto policy for v1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoPolicy {
    /// Selected KDF algorithm.
    pub kdf_algorithm: KdfAlgorithm,
    /// Selected AEAD algorithm.
    pub aead_algorithm: AeadAlgorithm,
    /// KDF parameters.
    pub kdf_params: KdfParams,
    /// Nonce length for the chosen AEAD.
    pub nonce_len: usize,
    /// Derived key length.
    pub key_len: usize,
}

impl CryptoPolicy {
    /// Returns the fixed v1 crypto policy.
    #[must_use]
    pub fn v1() -> Self {
        Self::default()
    }
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self {
            kdf_algorithm: KdfAlgorithm::Argon2id,
            aead_algorithm: AeadAlgorithm::XChaCha20Poly1305,
            kdf_params: KdfParams {
                version: 19,
                salt_len: 16,
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 1,
            },
            nonce_len: 24,
            key_len: 32,
        }
    }
}
