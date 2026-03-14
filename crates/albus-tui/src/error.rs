use thiserror::Error;

use albus::{BackupError, CoreError, CryptoError, StorageError};

/// Errors raised by the terminal shell.
#[derive(Debug, Error)]
pub enum AppError {
    /// The local configuration directory could not be determined.
    #[error("unable to determine the local Albus configuration directory")]
    ProjectDirsUnavailable,
    /// A vault operation was requested in the wrong state.
    #[error("invalid operation for the current app state: {0}")]
    InvalidOperation(&'static str),
    /// A new vault requires two matching passphrase entries.
    #[error("passphrase confirmation does not match")]
    PassphraseMismatch,
    /// Passphrases must contain at least one non-whitespace character.
    #[error("passphrase must not be empty")]
    EmptyPassphrase,
    /// Newly created passphrases must clear the minimum length policy.
    #[error("new passphrase must contain at least {0} non-whitespace characters")]
    PassphraseTooShort(usize),
    /// The requested local device-binding provider is unavailable on this host.
    #[error(
        "vault requires local device-bound key protection provider {provider}, but it is unavailable on this host"
    )]
    DeviceBindingUnavailable {
        /// Provider identifier carried in the vault header or local policy.
        provider: String,
    },
    /// The local secret for a device-bound vault could not be found.
    #[error(
        "missing local device-bound key material for vault {vault_id}; use the original host profile or restore from backup"
    )]
    MissingDeviceBindingKey {
        /// Stable vault identifier.
        vault_id: String,
    },
    /// The local device-binding state file was malformed.
    #[error("invalid local device-binding state")]
    InvalidDeviceBindingState(#[source] serde_json::Error),
    /// The platform device-binding service failed unexpectedly.
    #[error("local device-binding service failed: {0}")]
    DeviceBindingService(String),
    /// The local trust anchor detected an older vault revision than previously trusted.
    #[error(
        "possible vault rollback detected for {vault_id}: file revision {current_revision} is older than locally trusted revision {trusted_revision}"
    )]
    RollbackDetected {
        /// Stable vault identifier read from the encrypted header.
        vault_id: String,
        /// Revision observed in the current file.
        current_revision: u64,
        /// Highest locally trusted revision on this host.
        trusted_revision: u64,
    },
    /// Deleting an entry requires explicit confirmation.
    #[error("type DELETE to remove the selected entry")]
    DeleteConfirmationRequired,
    /// Replacing an existing restore target requires explicit confirmation.
    #[error("type REPLACE to overwrite an existing target vault")]
    ReplaceConfirmationRequired,
    /// Saving dirty state requires a passphrase.
    #[error("passphrase is required to save a dirty vault")]
    PassphraseRequired,
    /// The vault path must not be empty.
    #[error("vault path must not be empty")]
    EmptyVaultPath,
    /// The backup path must not be empty.
    #[error("backup path must not be empty")]
    EmptyBackupPath,
    /// Backup export must not target the active vault file.
    #[error("backup path must differ from the active vault path")]
    BackupPathMatchesVaultPath,
    /// The import URI must not be empty.
    #[error("otpauth URI must not be empty")]
    EmptyImportUri,
    /// Delete requires a selected entry in the unlocked list.
    #[error("no entry is selected")]
    NoEntrySelected,
    /// A numeric field in the TUI form was malformed.
    #[error("{0} must be a positive integer")]
    InvalidNumber(&'static str),
    /// Filesystem operations failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The local rollback trust anchor file was malformed.
    #[error("invalid local trust anchor state")]
    InvalidTrustAnchorState(#[from] serde_json::Error),
    /// Timestamp formatting failed.
    #[error(transparent)]
    TimeFormat(#[from] time::error::Format),
    /// The domain layer rejected the input.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// Cryptographic random-material generation failed unexpectedly.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Vault storage failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Backup export or restore failed.
    #[error(transparent)]
    Backup(#[from] BackupError),
}
