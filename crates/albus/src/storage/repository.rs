use std::{
    fs::{self},
    io::{Read, Write},
    path::Path,
};

use albus_core::Vault;
use albus_crypto::{
    ContainerKind, CryptoPolicy, EnvelopeHeader, EnvelopeMetadata, LocalBindingHeader,
    assemble_envelope_container, build_envelope_aad, decrypt, derive_envelope_key, encrypt,
    random_bytes, validate_existing_passphrase, validate_new_passphrase,
};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

use super::{
    format::PlaintextVault,
    privacy::{ensure_non_symlink_path, harden_private_directory, harden_private_file},
};
use crate::StorageError;

#[cfg(windows)]
use std::fs::OpenOptions;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

#[cfg(not(windows))]
use std::fs::File;

/// Persisted storage policy for the primary vault file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoragePolicy {
    /// Envelope version used for the primary vault.
    pub format_version: u32,
    /// Maximum permitted header size in bytes.
    pub max_header_len: u32,
    /// Maximum permitted total container size in bytes.
    pub max_container_len: u64,
    /// Maximum permitted decrypted plaintext size in bytes.
    pub max_plaintext_len: usize,
    /// Primary file extension.
    pub vault_extension: &'static str,
    /// Magic bytes written at the start of every vault file.
    pub magic: [u8; 8],
}

impl Default for StoragePolicy {
    fn default() -> Self {
        Self {
            format_version: 1,
            max_header_len: 64 * 1024,
            max_container_len: 16 * 1024 * 1024,
            max_plaintext_len: 8 * 1024 * 1024,
            vault_extension: "albus",
            magic: *b"ALBUSV1\0",
        }
    }
}

/// Persistence mode for writing vault files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceMode {
    /// Create a new vault and fail if the target exists.
    CreateNew,
    /// Replace an existing vault file.
    ReplaceExisting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PassphraseValidation {
    Existing,
    New,
}

/// Trait representing the storage boundary.
pub trait VaultRepository {
    /// Loads and validates the encrypted vault header without decrypting it.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the file path is invalid, unreadable, or
    /// the container header is malformed.
    fn load_header(&self, path: &Path) -> Result<EnvelopeHeader, StorageError>;

    /// Creates a new encrypted vault file.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the target already exists or the vault
    /// cannot be serialized and persisted safely.
    fn create_new(&self, path: &Path, passphrase: &str, vault: &Vault) -> Result<(), StorageError>;

    /// Unlocks and fully decrypts the vault.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the file cannot be read, the passphrase is
    /// wrong, or the decrypted payload is invalid.
    fn unlock(&self, path: &Path, passphrase: &str) -> Result<Vault, StorageError>;

    /// Saves an updated vault by replacing the existing encrypted file.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the target does not exist or the new
    /// snapshot cannot be persisted safely.
    fn save(&self, path: &Path, passphrase: &str, vault: &Vault) -> Result<(), StorageError>;

    /// Replaces an existing vault path with a restored vault snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the target does not already exist or the
    /// new encrypted snapshot cannot be persisted safely.
    fn restore_replace(
        &self,
        path: &Path,
        passphrase: &str,
        vault: &Vault,
    ) -> Result<(), StorageError>;
}

/// Filesystem-backed vault repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileVaultRepository {
    storage_policy: StoragePolicy,
    crypto_policy: CryptoPolicy,
    vault_binding: Option<LocalBindingHeader>,
}

impl FileVaultRepository {
    /// Creates a repository with the supplied storage and crypto policies.
    #[must_use]
    pub fn new(storage_policy: StoragePolicy, crypto_policy: CryptoPolicy) -> Self {
        Self {
            storage_policy,
            crypto_policy,
            vault_binding: None,
        }
    }

    /// Returns a repository clone that writes the supplied local host binding
    /// metadata into new vault headers.
    #[must_use]
    pub fn with_vault_binding(mut self, vault_binding: Option<LocalBindingHeader>) -> Self {
        self.vault_binding = vault_binding;
        self
    }

    fn read_container(&self, path: &Path) -> Result<LockedContainer, StorageError> {
        validate_path(path)?;
        if !path.exists() {
            return Err(StorageError::VaultNotFound(path.to_path_buf()));
        }

        let bytes = Zeroizing::new(read_limited_file(
            path,
            self.storage_policy.max_container_len,
        )?);

        let prefix_len = self.storage_policy.magic.len() + 4;
        if bytes.len() < prefix_len {
            return Err(StorageError::InvalidHeaderLength);
        }

        if bytes[..self.storage_policy.magic.len()] != self.storage_policy.magic {
            return Err(StorageError::InvalidMagic);
        }

        let header_len_offset = self.storage_policy.magic.len();
        let header_len = u32::from_le_bytes(
            bytes[header_len_offset..header_len_offset + 4]
                .try_into()
                .map_err(|_| StorageError::InvalidHeaderLength)?,
        );

        if header_len == 0 {
            return Err(StorageError::InvalidHeaderLength);
        }

        if header_len > self.storage_policy.max_header_len {
            return Err(StorageError::HeaderTooLarge(header_len));
        }

        let header_start = prefix_len;
        let header_end = header_start
            + usize::try_from(header_len).map_err(|_| StorageError::InvalidHeaderLength)?;
        if bytes.len() < header_end {
            return Err(StorageError::InvalidHeaderLength);
        }

        let header_json = bytes[header_start..header_end].to_vec();
        let ciphertext = bytes[header_end..].to_vec();
        if ciphertext.is_empty() {
            return Err(StorageError::EmptyCiphertext);
        }

        let header: EnvelopeHeader =
            serde_json::from_slice(&header_json).map_err(StorageError::InvalidHeaderJson)?;
        self.validate_header(&header)?;

        Ok(LockedContainer {
            header,
            header_json,
            ciphertext,
        })
    }

    fn validate_header(&self, header: &EnvelopeHeader) -> Result<(), StorageError> {
        if header.kind != ContainerKind::Vault {
            return Err(StorageError::UnexpectedContainerKind);
        }

        if header.format_version != self.storage_policy.format_version {
            return Err(StorageError::UnsupportedFormatVersion(
                header.format_version,
            ));
        }

        if header.schema_version != 1 {
            return Err(StorageError::UnsupportedSchemaVersion(
                header.schema_version,
            ));
        }

        header.validate_crypto(&self.crypto_policy)?;
        Ok(())
    }

    fn persist_vault(
        &self,
        path: &Path,
        passphrase: &str,
        supplemental_secret: Option<&[u8]>,
        vault: &Vault,
        mode: PersistenceMode,
        passphrase_validation: PassphraseValidation,
    ) -> Result<(), StorageError> {
        validate_path(path)?;
        match passphrase_validation {
            PassphraseValidation::Existing => validate_existing_passphrase(passphrase)?,
            PassphraseValidation::New => validate_new_passphrase(passphrase)?,
        }
        if vault.schema_version() != 1 {
            return Err(StorageError::UnsupportedSchemaVersion(
                vault.schema_version(),
            ));
        }
        vault.validate()?;

        let path_buf = path.to_path_buf();
        match mode {
            PersistenceMode::CreateNew if path.exists() => {
                return Err(StorageError::VaultAlreadyExists(path_buf));
            }
            PersistenceMode::ReplaceExisting if !path.exists() => {
                return Err(StorageError::RestoreTargetMissing(path_buf));
            }
            PersistenceMode::CreateNew | PersistenceMode::ReplaceExisting => {}
        }

        let plaintext = PlaintextVault::from_vault(vault);
        let plaintext_bytes = Zeroizing::new(
            serde_json::to_vec(&plaintext).map_err(StorageError::InvalidPlaintextJson)?,
        );
        if plaintext_bytes.len() > self.storage_policy.max_plaintext_len {
            return Err(StorageError::PlaintextTooLarge(plaintext_bytes.len()));
        }

        let salt = random_bytes(self.crypto_policy.kdf_params.salt_len)?;
        let nonce = random_bytes(self.crypto_policy.nonce_len)?;
        let mut header = EnvelopeHeader::new_vault(
            self.storage_policy.format_version,
            vault.schema_version(),
            EnvelopeMetadata {
                vault_id: vault.vault_id().as_str().to_owned(),
                revision: vault.revision(),
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &self.crypto_policy,
        )?;
        if let Some(binding) = self.vault_binding.clone() {
            header = header.with_local_binding(binding);
        }
        let header_json = serde_json::to_vec(&header).map_err(StorageError::InvalidHeaderJson)?;
        let aad = build_envelope_aad(&self.storage_policy.magic, &header_json)
            .map_err(|_| StorageError::InvalidHeaderLength)?;
        let key = derive_envelope_key(
            passphrase,
            &header,
            &self.crypto_policy,
            supplemental_secret,
        )?;
        let ciphertext = encrypt(
            &key,
            &nonce,
            &aad,
            plaintext_bytes.as_slice(),
            &self.crypto_policy,
        )?;
        let container_bytes = Zeroizing::new(
            assemble_envelope_container(&self.storage_policy.magic, &header_json, &ciphertext)
                .map_err(|_| StorageError::InvalidHeaderLength)?,
        );
        if u64::try_from(container_bytes.len()).unwrap_or(u64::MAX)
            > self.storage_policy.max_container_len
        {
            return Err(StorageError::ContainerTooLarge(
                u64::try_from(container_bytes.len()).unwrap_or(u64::MAX),
            ));
        }

        persist_bytes(path, container_bytes.as_slice(), mode)
    }

    fn decrypt_container(
        &self,
        locked: &LockedContainer,
        passphrase: &str,
        supplemental_secret: Option<&[u8]>,
    ) -> Result<Vault, StorageError> {
        let nonce = locked.header.decode_nonce(&self.crypto_policy)?;
        let aad = build_envelope_aad(&self.storage_policy.magic, &locked.header_json)
            .map_err(|_| StorageError::InvalidHeaderLength)?;
        let key = derive_envelope_key(
            passphrase,
            &locked.header,
            &self.crypto_policy,
            supplemental_secret,
        )?;
        let plaintext = Zeroizing::new(decrypt(
            &key,
            &nonce,
            &aad,
            &locked.ciphertext,
            &self.crypto_policy,
        )?);
        if plaintext.len() > self.storage_policy.max_plaintext_len {
            return Err(StorageError::PlaintextTooLarge(plaintext.len()));
        }
        let persisted: PlaintextVault = serde_json::from_slice(plaintext.as_slice())
            .map_err(StorageError::InvalidPlaintextJson)?;

        if persisted.schema_version != locked.header.schema_version {
            return Err(StorageError::MetadataMismatch("schema_version"));
        }

        let vault = persisted.into_vault()?;
        validate_metadata_match(&locked.header, &vault)?;
        Ok(vault)
    }
}

impl Default for FileVaultRepository {
    fn default() -> Self {
        Self::new(StoragePolicy::default(), CryptoPolicy::default())
    }
}

impl VaultRepository for FileVaultRepository {
    fn load_header(&self, path: &Path) -> Result<EnvelopeHeader, StorageError> {
        Ok(self.read_container(path)?.header.clone())
    }

    fn create_new(&self, path: &Path, passphrase: &str, vault: &Vault) -> Result<(), StorageError> {
        self.persist_vault(
            path,
            passphrase,
            None,
            vault,
            PersistenceMode::CreateNew,
            PassphraseValidation::New,
        )
    }

    fn unlock(&self, path: &Path, passphrase: &str) -> Result<Vault, StorageError> {
        let locked = self.read_container(path)?;
        self.decrypt_container(&locked, passphrase, None)
    }

    fn save(&self, path: &Path, passphrase: &str, vault: &Vault) -> Result<(), StorageError> {
        if !path.exists() {
            return Err(StorageError::VaultNotFound(path.to_path_buf()));
        }

        self.persist_vault(
            path,
            passphrase,
            None,
            vault,
            PersistenceMode::ReplaceExisting,
            PassphraseValidation::Existing,
        )
    }

    fn restore_replace(
        &self,
        path: &Path,
        passphrase: &str,
        vault: &Vault,
    ) -> Result<(), StorageError> {
        self.persist_vault(
            path,
            passphrase,
            None,
            vault,
            PersistenceMode::ReplaceExisting,
            PassphraseValidation::New,
        )
    }
}

impl FileVaultRepository {
    /// Creates a new encrypted vault file using optional supplemental key material.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the target already exists or the vault
    /// cannot be serialized and persisted safely.
    pub fn create_new_with_secret(
        &self,
        path: &Path,
        passphrase: &str,
        supplemental_secret: Option<&[u8]>,
        vault: &Vault,
    ) -> Result<(), StorageError> {
        self.persist_vault(
            path,
            passphrase,
            supplemental_secret,
            vault,
            PersistenceMode::CreateNew,
            PassphraseValidation::New,
        )
    }

    /// Unlocks and fully decrypts the vault using optional supplemental key material.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the file cannot be read, the passphrase is
    /// wrong, or the decrypted payload is invalid.
    pub fn unlock_with_secret(
        &self,
        path: &Path,
        passphrase: &str,
        supplemental_secret: Option<&[u8]>,
    ) -> Result<Vault, StorageError> {
        let locked = self.read_container(path)?;
        self.decrypt_container(&locked, passphrase, supplemental_secret)
    }

    /// Saves an updated vault using optional supplemental key material.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the target does not exist or the new
    /// snapshot cannot be persisted safely.
    pub fn save_with_secret(
        &self,
        path: &Path,
        passphrase: &str,
        supplemental_secret: Option<&[u8]>,
        vault: &Vault,
    ) -> Result<(), StorageError> {
        if !path.exists() {
            return Err(StorageError::VaultNotFound(path.to_path_buf()));
        }

        self.persist_vault(
            path,
            passphrase,
            supplemental_secret,
            vault,
            PersistenceMode::ReplaceExisting,
            PassphraseValidation::Existing,
        )
    }

    /// Replaces an existing vault path with a restored snapshot using optional supplemental key material.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the target does not already exist or the
    /// new encrypted snapshot cannot be persisted safely.
    pub fn restore_replace_with_secret(
        &self,
        path: &Path,
        passphrase: &str,
        supplemental_secret: Option<&[u8]>,
        vault: &Vault,
    ) -> Result<(), StorageError> {
        self.persist_vault(
            path,
            passphrase,
            supplemental_secret,
            vault,
            PersistenceMode::ReplaceExisting,
            PassphraseValidation::New,
        )
    }
}

struct LockedContainer {
    header: EnvelopeHeader,
    header_json: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Drop for LockedContainer {
    fn drop(&mut self) {
        self.header_json.zeroize();
        self.ciphertext.zeroize();
    }
}

fn read_limited_file(path: &Path, max_len: u64) -> Result<Vec<u8>, StorageError> {
    let file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > max_len {
        return Err(StorageError::ContainerTooLarge(len));
    }

    let limit = max_len.saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_len {
        return Err(StorageError::ContainerTooLarge(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        ));
    }

    Ok(bytes)
}

fn validate_path(path: &Path) -> Result<(), StorageError> {
    if path.as_os_str().is_empty() {
        return Err(StorageError::InvalidPath);
    }

    ensure_non_symlink_path(path)?;
    Ok(())
}

fn persist_bytes(
    destination: &Path,
    bytes: &[u8],
    mode: PersistenceMode,
) -> Result<(), StorageError> {
    let parent = ensure_destination_parent_directory(destination)?;
    let mut temp = NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.flush()?;
    temp.as_file().sync_all()?;

    match mode {
        PersistenceMode::CreateNew => {
            temp.persist_noclobber(destination).map_err(|error| {
                if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                    StorageError::VaultAlreadyExists(destination.to_path_buf())
                } else {
                    StorageError::Io(error.error)
                }
            })?;
        }
        PersistenceMode::ReplaceExisting => {
            temp.persist(destination)
                .map_err(|error| StorageError::Io(error.error))?;
        }
    }
    harden_private_file(destination)?;
    sync_directory(parent)?;

    Ok(())
}

fn ensure_destination_parent_directory(destination: &Path) -> Result<&Path, StorageError> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    create_dir_all_durable(parent)?;
    Ok(parent)
}

fn create_dir_all_durable(path: &Path) -> Result<(), StorageError> {
    if path.exists() {
        return Ok(());
    }

    let mut missing = Vec::new();
    let mut current = path;
    while !current.exists() {
        missing.push(current.to_path_buf());
        current = current.parent().unwrap_or_else(|| Path::new("."));
    }

    missing.reverse();
    for directory in missing {
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists && directory.is_dir() => {}
            Err(error) => return Err(StorageError::Io(error)),
        }
        harden_private_directory(&directory)?;

        let parent = directory.parent().unwrap_or_else(|| Path::new("."));
        sync_directory(parent)?;
    }

    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), StorageError> {
    #[cfg(windows)]
    {
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

        let directory = OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        directory.sync_all()?;
    }

    #[cfg(not(windows))]
    {
        let directory = File::open(path)?;
        directory.sync_all()?;
    }

    Ok(())
}

fn validate_metadata_match(header: &EnvelopeHeader, vault: &Vault) -> Result<(), StorageError> {
    if header.metadata.vault_id != vault.vault_id().as_str() {
        return Err(StorageError::MetadataMismatch("vault_id"));
    }

    if header.metadata.revision != vault.revision() {
        return Err(StorageError::MetadataMismatch("revision"));
    }

    Ok(())
}
