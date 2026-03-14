#![forbid(unsafe_code)]
#![doc = "Cryptographic policy and envelope boundary types for Albus."]

/// Algorithm and policy definitions.
mod config;
/// Authenticated envelope metadata types.
mod envelope;
/// Typed errors for cryptographic operations.
mod error;
/// Shared passphrase validation policy.
mod passphrase;
/// Password-based key derivation, AEAD operations, and randomness.
mod primitives;
/// Secret-bearing wrapper types.
mod secret;

pub use config::{AeadAlgorithm, CryptoPolicy, KdfAlgorithm, KdfParams};
pub use envelope::{
    CipherHeader, ContainerKind, EnvelopeHeader, EnvelopeMetadata, KdfHeader,
    LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE, LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN,
    LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI, LOCAL_BINDING_SCOPE_CURRENT_USER, LocalBindingHeader,
    assemble_envelope_container, build_envelope_aad,
};
pub use error::CryptoError;
pub use passphrase::{
    MIN_NEW_PASSPHRASE_NON_WHITESPACE_CHARS, validate_existing_passphrase, validate_new_passphrase,
};
pub use primitives::{decrypt, derive_key, encrypt, random_bytes};
pub use secret::SecretBytes;
