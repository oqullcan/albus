#![forbid(unsafe_code)]
#![doc = "Encrypted backup boundary for Albus."]

/// Backup-specific error types.
mod error;
/// Backup header and snapshot types.
mod format;
/// Backup repository types and restore policy.
mod repository;

pub use error::BackupError;
pub use format::{BackupHeader, BackupSnapshot};
pub use repository::{
    BackupPolicy, BackupRepository, FileBackupRepository, RestoreMode, RestoreRequest,
};
