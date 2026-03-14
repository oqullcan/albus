#![forbid(unsafe_code)]
#![doc = "Encrypted vault persistence boundary for Albus."]

/// Storage-specific error types.
mod error;
mod format;
mod privacy;
/// Repository traits and storage policy.
mod repository;

pub use error::StorageError;
pub use privacy::{harden_private_directory, harden_private_file};
pub use repository::{FileVaultRepository, PersistenceMode, StoragePolicy, VaultRepository};
