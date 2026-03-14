use std::path::PathBuf;

use albus_core::CoreError;
use albus_crypto::CryptoError;
use albus_storage::StorageError;
use thiserror::Error;

/// Errors raised by backup export and restore operations.
#[derive(Debug, Error)]
pub enum BackupError {
    /// The backup path was not provided or was malformed.
    #[error("invalid backup path")]
    InvalidPath,
    /// The backup file does not exist.
    #[error("backup file does not exist: {0}")]
    BackupNotFound(PathBuf),
    /// The container magic bytes are invalid.
    #[error("invalid backup magic")]
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
    /// The outer container kind is not a backup.
    #[error("unexpected container kind")]
    UnexpectedContainerKind,
    /// The outer envelope version is unsupported.
    #[error("unsupported format version: {0}")]
    UnsupportedFormatVersion(u32),
    /// The inner plaintext schema version is unsupported.
    #[error("unsupported schema version: {0}")]
    UnsupportedSchemaVersion(u32),
    /// The header JSON could not be parsed.
    #[error("invalid backup header JSON")]
    InvalidHeaderJson(#[source] serde_json::Error),
    /// The decrypted plaintext JSON could not be parsed.
    #[error("invalid backup plaintext JSON")]
    InvalidPlaintextJson(#[source] serde_json::Error),
    /// The decrypted or serialized plaintext is larger than the configured maximum.
    #[error("backup plaintext length exceeds configured maximum: {0}")]
    PlaintextTooLarge(usize),
    /// The ciphertext section is empty.
    #[error("ciphertext must not be empty")]
    EmptyCiphertext,
    /// Export will not overwrite an existing backup file.
    #[error("backup file already exists: {0}")]
    BackupAlreadyExists(PathBuf),
    /// A required backup metadata field was empty or invalid.
    #[error("invalid backup metadata: {0}")]
    InvalidBackupMetadata(&'static str),
    /// Header metadata and plaintext metadata did not match.
    #[error("header metadata mismatch: {0}")]
    MetadataMismatch(&'static str),
    /// The requested restore mode is not compatible with the target path.
    #[error("restore mode violation: {0}")]
    RestoreModeViolation(&'static str),
    /// Formatting a backup timestamp failed.
    #[error("timestamp formatting failed")]
    TimeFormat(#[from] time::error::Format),
    /// Filesystem I/O failed.
    #[error("filesystem I/O failed")]
    Io(#[from] std::io::Error),
    /// Cryptographic validation or authentication failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The decrypted domain model failed validation.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// Restoring into a vault file failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
}
