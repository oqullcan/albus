use std::{
    fs::{self},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use albus_core::Vault;
use albus_crypto::{
    ContainerKind, CryptoPolicy, EnvelopeHeader, EnvelopeMetadata, LocalBindingHeader,
    assemble_envelope_container, build_envelope_aad, decrypt, derive_key, encrypt, random_bytes,
    validate_new_passphrase,
};
use albus_storage::{
    FileVaultRepository, StoragePolicy, VaultRepository, harden_private_directory,
    harden_private_file,
};
use tempfile::NamedTempFile;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use super::format::{BackupHeader, BackupSnapshot, PlaintextBackupSnapshot};
use crate::BackupError;

#[cfg(windows)]
use std::fs::OpenOptions;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

#[cfg(not(windows))]
use std::fs::File;

/// Persisted storage policy for encrypted backup files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupPolicy {
    /// Envelope version used for backup files.
    pub format_version: u32,
    /// Maximum permitted header size in bytes.
    pub max_header_len: u32,
    /// Maximum permitted total container size in bytes.
    pub max_container_len: u64,
    /// Maximum permitted decrypted plaintext size in bytes.
    pub max_plaintext_len: usize,
    /// Primary backup file extension.
    pub backup_extension: &'static str,
    /// Magic bytes written at the start of every backup file.
    pub magic: [u8; 8],
}

impl Default for BackupPolicy {
    fn default() -> Self {
        Self {
            format_version: 1,
            max_header_len: 64 * 1024,
            max_container_len: 16 * 1024 * 1024,
            max_plaintext_len: 8 * 1024 * 1024,
            backup_extension: "albusbak",
            magic: *b"ALBUSV1\0",
        }
    }
}

/// Restore behavior for the target vault path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreMode {
    /// Restore into a path that must not already exist.
    CreateNew,
    /// Replace an existing vault path.
    ReplaceExisting,
}

/// Parameters required to restore a backup into a vault file.
#[derive(Clone, Debug)]
pub struct RestoreRequest<'a> {
    /// Source encrypted backup file path.
    pub backup_path: &'a Path,
    /// Passphrase used to decrypt the backup file.
    pub backup_passphrase: &'a str,
    /// Target vault path to write.
    pub target_vault_path: &'a Path,
    /// Master passphrase for the restored vault.
    pub target_vault_passphrase: &'a str,
    /// Optional local host binding metadata for the restored vault file.
    pub target_local_binding: Option<LocalBindingHeader>,
    /// Restore mode for the target path.
    pub mode: RestoreMode,
}

/// Backup repository boundary.
pub trait BackupRepository {
    /// Loads and validates the encrypted backup header without decrypting it.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError`] when the file cannot be read, the outer
    /// container is malformed, or the header does not satisfy the v1 backup
    /// policy.
    fn load_header(&self, path: &Path) -> Result<BackupHeader, BackupError>;

    /// Exports a full encrypted backup snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError`] when the destination path is invalid, the vault
    /// fails validation, random material generation fails, or the encrypted
    /// container cannot be persisted.
    fn export(
        &self,
        path: &Path,
        backup_passphrase: &str,
        vault: &Vault,
    ) -> Result<(), BackupError>;

    /// Decrypts and validates a full backup snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError`] when the container cannot be read, the backup
    /// passphrase is wrong, authentication fails, or the decrypted snapshot
    /// does not validate against the header metadata.
    fn decrypt_snapshot(
        &self,
        path: &Path,
        backup_passphrase: &str,
    ) -> Result<BackupSnapshot, BackupError>;

    /// Restores an encrypted backup into a normal vault file.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError`] when the backup cannot be decrypted, the
    /// requested restore mode is incompatible with the target path, or writing
    /// the restored vault file fails.
    fn restore(&self, request: &RestoreRequest<'_>) -> Result<Vault, BackupError>;
}

/// Filesystem-backed backup repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileBackupRepository {
    backup_policy: BackupPolicy,
    crypto_policy: CryptoPolicy,
    vault_repository: FileVaultRepository,
}

impl FileBackupRepository {
    /// Creates a repository with the supplied backup and crypto policies.
    #[must_use]
    pub fn new(backup_policy: BackupPolicy, crypto_policy: CryptoPolicy) -> Self {
        let vault_repository =
            FileVaultRepository::new(StoragePolicy::default(), crypto_policy.clone());

        Self {
            backup_policy,
            crypto_policy,
            vault_repository,
        }
    }

    fn read_container(&self, path: &Path) -> Result<LockedBackupContainer, BackupError> {
        validate_path(path)?;
        if !path.exists() {
            return Err(BackupError::BackupNotFound(path.to_path_buf()));
        }

        let bytes = read_limited_file(path, self.backup_policy.max_container_len)?;

        let prefix_len = self.backup_policy.magic.len() + 4;
        if bytes.len() < prefix_len {
            return Err(BackupError::InvalidHeaderLength);
        }

        if bytes[..self.backup_policy.magic.len()] != self.backup_policy.magic {
            return Err(BackupError::InvalidMagic);
        }

        let header_len_offset = self.backup_policy.magic.len();
        let header_len = u32::from_le_bytes(
            bytes[header_len_offset..header_len_offset + 4]
                .try_into()
                .map_err(|_| BackupError::InvalidHeaderLength)?,
        );

        if header_len == 0 {
            return Err(BackupError::InvalidHeaderLength);
        }

        if header_len > self.backup_policy.max_header_len {
            return Err(BackupError::HeaderTooLarge(header_len));
        }

        let header_start = prefix_len;
        let header_end = header_start
            + usize::try_from(header_len).map_err(|_| BackupError::InvalidHeaderLength)?;
        if bytes.len() < header_end {
            return Err(BackupError::InvalidHeaderLength);
        }

        let header_json = bytes[header_start..header_end].to_vec();
        let ciphertext = bytes[header_end..].to_vec();
        if ciphertext.is_empty() {
            return Err(BackupError::EmptyCiphertext);
        }

        let header: EnvelopeHeader =
            serde_json::from_slice(&header_json).map_err(BackupError::InvalidHeaderJson)?;
        self.validate_header(&header)?;
        let _ = BackupHeader::from_envelope(&header)?;

        Ok(LockedBackupContainer {
            header,
            header_json,
            ciphertext,
        })
    }

    fn validate_header(&self, header: &EnvelopeHeader) -> Result<(), BackupError> {
        if header.kind != ContainerKind::Backup {
            return Err(BackupError::UnexpectedContainerKind);
        }

        if header.format_version != self.backup_policy.format_version {
            return Err(BackupError::UnsupportedFormatVersion(header.format_version));
        }

        if header.schema_version != 1 {
            return Err(BackupError::UnsupportedSchemaVersion(header.schema_version));
        }

        header.validate_crypto(&self.crypto_policy)?;
        Ok(())
    }

    fn decrypt_locked_snapshot(
        &self,
        locked: &LockedBackupContainer,
        backup_passphrase: &str,
    ) -> Result<BackupSnapshot, BackupError> {
        let salt = locked.header.decode_salt(&self.crypto_policy)?;
        let nonce = locked.header.decode_nonce(&self.crypto_policy)?;
        let aad = build_envelope_aad(&self.backup_policy.magic, &locked.header_json)
            .map_err(|_| BackupError::InvalidHeaderLength)?;
        let key = derive_key(
            backup_passphrase,
            &salt,
            &locked.header.kdf_params()?,
            &self.crypto_policy,
        )?;
        let plaintext = Zeroizing::new(decrypt(
            &key,
            &nonce,
            &aad,
            &locked.ciphertext,
            &self.crypto_policy,
        )?);
        if plaintext.len() > self.backup_policy.max_plaintext_len {
            return Err(BackupError::PlaintextTooLarge(plaintext.len()));
        }
        let snapshot: PlaintextBackupSnapshot = serde_json::from_slice(plaintext.as_slice())
            .map_err(BackupError::InvalidPlaintextJson)?;
        let snapshot = snapshot.into_snapshot()?;
        validate_metadata_match(&locked.header, &snapshot)?;
        Ok(snapshot)
    }
}

impl Default for FileBackupRepository {
    fn default() -> Self {
        Self::new(BackupPolicy::default(), CryptoPolicy::default())
    }
}

impl BackupRepository for FileBackupRepository {
    fn load_header(&self, path: &Path) -> Result<BackupHeader, BackupError> {
        let header = self.read_container(path)?.header;
        BackupHeader::from_envelope(&header)
    }

    fn export(
        &self,
        path: &Path,
        backup_passphrase: &str,
        vault: &Vault,
    ) -> Result<(), BackupError> {
        validate_path(path)?;
        validate_new_passphrase(backup_passphrase)?;
        vault.validate()?;

        ensure_destination_parent_directory(path)?;

        let snapshot = BackupSnapshot {
            exported_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
            source_app_version: env!("CARGO_PKG_VERSION").to_owned(),
            vault: vault.clone(),
        };
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&PlaintextBackupSnapshot::from_snapshot(&snapshot))
                .map_err(BackupError::InvalidPlaintextJson)?,
        );
        if plaintext.len() > self.backup_policy.max_plaintext_len {
            return Err(BackupError::PlaintextTooLarge(plaintext.len()));
        }

        let salt = random_bytes(self.crypto_policy.kdf_params.salt_len)?;
        let nonce = random_bytes(self.crypto_policy.nonce_len)?;
        let header = EnvelopeHeader::new_backup(
            self.backup_policy.format_version,
            snapshot.vault.schema_version(),
            EnvelopeMetadata {
                vault_id: snapshot.vault.vault_id().as_str().to_owned(),
                revision: snapshot.vault.revision(),
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &self.crypto_policy,
        )?;
        let header_json = serde_json::to_vec(&header).map_err(BackupError::InvalidHeaderJson)?;
        let aad = build_envelope_aad(&self.backup_policy.magic, &header_json)
            .map_err(|_| BackupError::InvalidHeaderLength)?;
        let key = derive_key(
            backup_passphrase,
            &salt,
            &header.kdf_params()?,
            &self.crypto_policy,
        )?;
        let ciphertext = encrypt(
            &key,
            &nonce,
            &aad,
            plaintext.as_slice(),
            &self.crypto_policy,
        )?;
        let container =
            assemble_envelope_container(&self.backup_policy.magic, &header_json, &ciphertext)
                .map_err(|_| BackupError::InvalidHeaderLength)?;
        if u64::try_from(container.len()).unwrap_or(u64::MAX) > self.backup_policy.max_container_len
        {
            return Err(BackupError::ContainerTooLarge(
                u64::try_from(container.len()).unwrap_or(u64::MAX),
            ));
        }

        persist_bytes(path, &container)
    }

    fn decrypt_snapshot(
        &self,
        path: &Path,
        backup_passphrase: &str,
    ) -> Result<BackupSnapshot, BackupError> {
        let locked = self.read_container(path)?;
        self.decrypt_locked_snapshot(&locked, backup_passphrase)
    }

    fn restore(&self, request: &RestoreRequest<'_>) -> Result<Vault, BackupError> {
        validate_path(request.backup_path)?;
        validate_path(request.target_vault_path)?;
        if paths_conflict(request.backup_path, request.target_vault_path) {
            return Err(BackupError::RestoreModeViolation(
                "backup path and target vault path must differ",
            ));
        }

        let snapshot = self.decrypt_snapshot(request.backup_path, request.backup_passphrase)?;

        let vault_repository = self
            .vault_repository
            .clone()
            .with_vault_binding(request.target_local_binding.clone());

        match request.mode {
            RestoreMode::CreateNew => {
                if request.target_vault_path.exists() {
                    return Err(BackupError::RestoreModeViolation(
                        "target path already exists",
                    ));
                }

                vault_repository.create_new(
                    request.target_vault_path,
                    request.target_vault_passphrase,
                    &snapshot.vault,
                )?;
            }
            RestoreMode::ReplaceExisting => {
                if !request.target_vault_path.exists() {
                    return Err(BackupError::RestoreModeViolation(
                        "target path must already exist",
                    ));
                }

                vault_repository.restore_replace(
                    request.target_vault_path,
                    request.target_vault_passphrase,
                    &snapshot.vault,
                )?;
            }
        }

        Ok(snapshot.vault)
    }
}

struct LockedBackupContainer {
    header: EnvelopeHeader,
    header_json: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn validate_path(path: &Path) -> Result<(), BackupError> {
    if path.as_os_str().is_empty() {
        return Err(BackupError::InvalidPath);
    }

    Ok(())
}

fn persist_bytes(destination: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    let parent = ensure_destination_parent_directory(destination)?;
    let mut temp = NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(destination).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            BackupError::BackupAlreadyExists(destination.to_path_buf())
        } else {
            BackupError::Io(error.error)
        }
    })?;
    harden_private_file(destination)?;
    sync_directory(parent)?;

    Ok(())
}

fn read_limited_file(path: &Path, max_len: u64) -> Result<Vec<u8>, BackupError> {
    let file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > max_len {
        return Err(BackupError::ContainerTooLarge(len));
    }

    let limit = max_len.saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_len {
        return Err(BackupError::ContainerTooLarge(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        ));
    }

    Ok(bytes)
}

fn paths_conflict(left: &Path, right: &Path) -> bool {
    match (
        resolve_path_for_conflict(left),
        resolve_path_for_conflict(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        (Err(_), _) | (_, Err(_)) => true,
    }
}

fn resolve_path_for_conflict(path: &Path) -> Result<PathBuf, std::io::Error> {
    let absolute = normalize_absolute_path(path)?;
    let mut pending = Vec::new();
    let mut current = absolute.as_path();

    loop {
        match fs::canonicalize(current) {
            Ok(mut resolved) => {
                for component in pending.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if current.exists() => return Err(error),
            Err(error) => {
                let Some(component) = current.file_name() else {
                    return Err(error);
                };
                pending.push(component.to_os_string());
                let Some(parent) = current.parent() else {
                    return Err(error);
                };
                current = parent;
            }
        }
    }
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(part) => normalized.push(part),
        }
    }

    Ok(normalized)
}

fn ensure_destination_parent_directory(destination: &Path) -> Result<&Path, BackupError> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    create_dir_all_durable(parent)?;
    Ok(parent)
}

fn create_dir_all_durable(path: &Path) -> Result<(), BackupError> {
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
            Err(error) => return Err(BackupError::Io(error)),
        }
        harden_private_directory(&directory)?;

        let parent = directory.parent().unwrap_or_else(|| Path::new("."));
        sync_directory(parent)?;
    }

    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), BackupError> {
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

fn validate_metadata_match(
    header: &EnvelopeHeader,
    snapshot: &BackupSnapshot,
) -> Result<(), BackupError> {
    if header.metadata.vault_id != snapshot.vault.vault_id().as_str() {
        return Err(BackupError::MetadataMismatch("vault_id"));
    }

    if header.metadata.revision != snapshot.vault.revision() {
        return Err(BackupError::MetadataMismatch("revision"));
    }

    Ok(())
}
