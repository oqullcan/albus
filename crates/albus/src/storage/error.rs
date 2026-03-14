use std::path::PathBuf;

use albus_core::CoreError;
use albus_crypto::CryptoError;
use thiserror::Error;

/// Errors raised by the storage boundary.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The vault path was not provided or was malformed.
    #[error("invalid vault path")]
    InvalidPath,
    /// The target vault does not exist.
    #[error("vault file does not exist: {0}")]
    VaultNotFound(PathBuf),
    /// A new vault cannot be created because the target already exists.
    #[error("vault file already exists: {0}")]
    VaultAlreadyExists(PathBuf),
    /// Replace-only restore requires a pre-existing target file.
    #[error("restore target does not exist: {0}")]
    RestoreTargetMissing(PathBuf),
    /// The container magic bytes are invalid.
    #[error("invalid vault magic")]
    InvalidMagic,
    /// The persisted header length prefix is invalid.
    #[error("invalid header length")]
    InvalidHeaderLength,
    /// The header is larger than the configured maximum.
    #[error("header length exceeds configured maximum: {0}")]
    HeaderTooLarge(u32),
    /// The full container is larger than the configured maximum.
    #[error("container length exceeds configured maximum: {0}")]
    ContainerTooLarge(u64),
    /// The outer container kind is not a vault.
    #[error("unexpected container kind")]
    UnexpectedContainerKind,
    /// The outer envelope version is unsupported.
    #[error("unsupported format version: {0}")]
    UnsupportedFormatVersion(u32),
    /// The inner plaintext schema version is unsupported.
    #[error("unsupported schema version: {0}")]
    UnsupportedSchemaVersion(u32),
    /// The header JSON could not be parsed.
    #[error("invalid header JSON")]
    InvalidHeaderJson(#[source] serde_json::Error),
    /// The decrypted plaintext JSON could not be parsed.
    #[error("invalid vault plaintext JSON")]
    InvalidPlaintextJson(#[source] serde_json::Error),
    /// The decrypted or serialized plaintext is larger than the configured maximum.
    #[error("vault plaintext length exceeds configured maximum: {0}")]
    PlaintextTooLarge(usize),
    /// The ciphertext section is empty.
    #[error("ciphertext must not be empty")]
    EmptyCiphertext,
    /// Header metadata and plaintext metadata did not match.
    #[error("header metadata mismatch: {0}")]
    MetadataMismatch(&'static str),
    /// Filesystem I/O failed.
    #[error("filesystem I/O failed")]
    Io(#[from] std::io::Error),
    /// Cryptographic validation or authentication failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The decrypted domain model failed validation.
    #[error(transparent)]
    Core(#[from] CoreError),
}
