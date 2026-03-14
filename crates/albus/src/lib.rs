#![forbid(unsafe_code)]
#![doc = "Core library for Albus."]

extern crate self as albus_backup;
extern crate self as albus_core;
extern crate self as albus_crypto;
extern crate self as albus_storage;

pub mod backup;
pub mod core;
pub mod crypto;
pub mod storage;

pub use backup::{
    BackupError, BackupHeader, BackupPolicy, BackupRepository, BackupSnapshot,
    FileBackupRepository, RestoreMode, RestoreRequest,
};
pub use core::{
    AccountLabel, CoreError, Digits, EntryId, HashAlgorithm, Issuer, OtpEntry, OtpSecret, Period,
    TotpCode, TotpGenerator, TotpParameters, Vault, VaultId, parse_totp_uri,
};
pub use crypto::{
    AeadAlgorithm, CipherHeader, ContainerKind, CryptoError, CryptoPolicy, EnvelopeHeader,
    EnvelopeMetadata, KdfAlgorithm, KdfHeader, KdfParams, KeySchedule,
    LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE, LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN,
    LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI, LOCAL_BINDING_SCOPE_CURRENT_USER, LocalBindingHeader,
    MIN_NEW_PASSPHRASE_NON_WHITESPACE_CHARS, SecretBytes, assemble_envelope_container,
    build_envelope_aad, decrypt, derive_envelope_key, derive_key, derive_key_with_secret, encrypt,
    random_bytes, validate_existing_passphrase, validate_new_passphrase,
};
pub use storage::{
    FileVaultRepository, PersistenceMode, StorageError, StoragePolicy, VaultRepository,
    ensure_non_symlink_path, harden_private_directory, harden_private_file,
};
