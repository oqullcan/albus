use thiserror::Error;

/// Errors raised by cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The provided passphrase was empty after trimming.
    #[error("passphrase must not be empty")]
    EmptyPassphrase,
    /// Newly set passphrases must clear the minimum length policy.
    #[error("new passphrase must contain at least {0} non-whitespace characters")]
    PassphraseTooShort(usize),
    /// The KDF algorithm in the file header is unsupported.
    #[error("unsupported KDF algorithm: {0}")]
    UnsupportedKdfAlgorithm(String),
    /// The Argon2 version in the file header is unsupported.
    #[error("unsupported Argon2 version: {0}")]
    UnsupportedKdfVersion(u32),
    /// The AEAD algorithm in the file header is unsupported.
    #[error("unsupported AEAD algorithm: {0}")]
    UnsupportedAeadAlgorithm(String),
    /// The post-Argon2 key schedule in the file header is unsupported.
    #[error("unsupported key schedule: {0}")]
    UnsupportedKeySchedule(String),
    /// The local binding provider in the file header is unsupported.
    #[error("unsupported local binding provider: {0}")]
    UnsupportedLocalBindingProvider(String),
    /// The local binding scope in the file header is unsupported.
    #[error("unsupported local binding scope for provider {provider}: {scope}")]
    UnsupportedLocalBindingScope {
        /// Persisted local binding provider.
        provider: String,
        /// Persisted local binding scope.
        scope: String,
    },
    /// Local device binding metadata is not valid for this container.
    #[error("local host binding metadata is only supported for vault containers")]
    UnexpectedLocalBinding,
    /// The provided salt length is invalid.
    #[error("invalid salt length: expected {expected}, got {actual}")]
    InvalidSaltLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// The provided nonce length is invalid.
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// The provided key length is invalid.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// Base64 decoding failed.
    #[error("{field} is not valid base64")]
    InvalidBase64 {
        /// Field label for diagnostics.
        field: &'static str,
    },
    /// Random byte generation failed.
    #[error("failed to obtain random bytes")]
    RandomFailure,
    /// Key derivation failed.
    #[error("failed to derive encryption key")]
    KeyDerivationFailure,
    /// Encryption failed.
    #[error("failed to encrypt plaintext")]
    EncryptionFailure,
    /// Authentication failed during decryption.
    #[error("vault authentication failed")]
    AuthenticationFailed,
    /// Argon2 parameters in the header are invalid.
    #[error("invalid Argon2 parameters")]
    InvalidKdfParameters,
    /// A persisted Argon2 parameter is outside the supported v1 range.
    #[error("Argon2 parameter {field} is out of range: expected {min}..={max}, got {value}")]
    KdfParameterOutOfRange {
        /// Field label for diagnostics.
        field: &'static str,
        /// Inclusive minimum allowed value.
        min: u32,
        /// Inclusive maximum allowed value.
        max: u32,
        /// Actual persisted value.
        value: u32,
    },
}
