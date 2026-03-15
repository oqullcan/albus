#![doc = "Encrypted backup integration tests for albus."]

use std::{fs, path::Path};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use albus::{
    AccountLabel, Digits, EntryId, HashAlgorithm, Issuer, OtpEntry, OtpSecret, Period,
    TotpParameters, Vault, VaultId,
};
use albus::{BackupError, BackupRepository, FileBackupRepository, RestoreMode, RestoreRequest};
use albus::{
    CryptoError, CryptoPolicy, EnvelopeHeader, FileVaultRepository, VaultRepository, decrypt,
    derive_envelope_key, encrypt,
};
use serde_json::Value;
use tempfile::tempdir;

const LONG_BACKUP_PASSPHRASE: &str = "backup passphrase long";

#[test]
fn export_round_trip_decrypts_the_same_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("vault-backup.albusbak");
    let repository = FileBackupRepository::default();
    let vault = sample_vault(2)?;

    repository.export(&path, "backup-passphrase", &vault)?;
    let header = repository.load_header(&path)?;
    let snapshot = repository.decrypt_snapshot(&path, "backup-passphrase")?;

    assert_eq!(header.vault_id, vault.vault_id().as_str());
    assert_eq!(header.revision, vault.revision());
    assert_eq!(snapshot.vault, vault);
    assert_eq!(snapshot.source_app_version, env!("CARGO_PKG_VERSION"));
    Ok(())
}

#[test]
fn export_creates_missing_parent_directories() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp
        .path()
        .join("nested")
        .join("exports")
        .join("vault.albusbak");
    let repository = FileBackupRepository::default();

    repository.export(&path, "backup-passphrase", &sample_vault(1)?)?;

    assert!(path.exists());
    let snapshot = repository.decrypt_snapshot(&path, "backup-passphrase")?;
    assert_eq!(snapshot.vault.entries().len(), 1);
    Ok(())
}

#[test]
fn wrong_backup_passphrase_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("wrong-passphrase.albusbak");
    let repository = FileBackupRepository::default();

    repository.export(&path, "backup-passphrase", &sample_vault(1)?)?;
    assert!(matches!(
        repository.decrypt_snapshot(&path, "wrong-passphrase"),
        Err(BackupError::Crypto(CryptoError::AuthenticationFailed))
    ));
    Ok(())
}

#[test]
fn corrupted_backup_header_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("corrupted-header.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, LONG_BACKUP_PASSPHRASE, &sample_vault(1)?)?;

    let mut bytes = fs::read(&path)?;
    bytes[12] = b'!';
    fs::write(&path, bytes)?;

    assert!(matches!(
        repository.load_header(&path),
        Err(BackupError::InvalidHeaderJson(_))
    ));
    Ok(())
}

#[test]
fn corrupted_backup_kind_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("wrong-kind.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, LONG_BACKUP_PASSPHRASE, &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["kind"] = Value::from("vault");
    })?;

    assert!(matches!(
        repository.load_header(&path),
        Err(BackupError::UnexpectedContainerKind)
    ));
    Ok(())
}

#[test]
fn load_header_rejects_blank_metadata_fields() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("blank-metadata.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, LONG_BACKUP_PASSPHRASE, &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["metadata"]["vault_id"] = Value::from("   ");
    })?;

    assert!(matches!(
        repository.load_header(&path),
        Err(BackupError::InvalidBackupMetadata("vault_id"))
    ));
    Ok(())
}

#[test]
fn backup_headers_reject_local_binding_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("backup-local-binding.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, "backup-passphrase", &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["local_binding"] = serde_json::json!({
            "provider": "windows-dpapi",
            "scope": "current-user"
        });
    })?;

    assert!(matches!(
        repository.load_header(&path),
        Err(BackupError::Crypto(CryptoError::UnexpectedLocalBinding))
    ));
    Ok(())
}

#[test]
fn corrupted_ciphertext_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("corrupted-ciphertext.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, LONG_BACKUP_PASSPHRASE, &sample_vault(1)?)?;

    let mut bytes = fs::read(&path)?;
    let last_index = bytes.len() - 1;
    bytes[last_index] ^= 0x01;
    fs::write(&path, bytes)?;

    assert!(matches!(
        repository.decrypt_snapshot(&path, LONG_BACKUP_PASSPHRASE),
        Err(BackupError::Crypto(CryptoError::AuthenticationFailed))
    ));
    Ok(())
}

#[test]
fn corrupted_nonce_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("corrupted-nonce.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, LONG_BACKUP_PASSPHRASE, &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["cipher"]["nonce_b64"] = Value::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    })?;

    assert!(matches!(
        repository.decrypt_snapshot(&path, LONG_BACKUP_PASSPHRASE),
        Err(BackupError::Crypto(CryptoError::AuthenticationFailed))
    ));
    Ok(())
}

#[test]
fn corrupted_salt_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("corrupted-salt.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, LONG_BACKUP_PASSPHRASE, &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["kdf"]["salt_b64"] = Value::from("AAAAAAAAAAAAAAAAAAAAAA==");
    })?;

    assert!(matches!(
        repository.decrypt_snapshot(&path, LONG_BACKUP_PASSPHRASE),
        Err(BackupError::Crypto(CryptoError::AuthenticationFailed))
    ));
    Ok(())
}

#[test]
fn metadata_mismatch_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("metadata-mismatch.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, LONG_BACKUP_PASSPHRASE, &sample_vault(1)?)?;

    mutate_plaintext_json(&path, LONG_BACKUP_PASSPHRASE, |plaintext| {
        plaintext["vault"]["revision"] = Value::from(999_u64);
    })?;

    assert!(matches!(
        repository.decrypt_snapshot(&path, LONG_BACKUP_PASSPHRASE),
        Err(BackupError::MetadataMismatch("revision"))
    ));
    Ok(())
}

#[test]
fn restore_to_a_new_target_path_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let backup_path = temp.path().join("restore-new.albusbak");
    let target_path = temp.path().join("restored").join("vault.albus");
    let backup_repository = FileBackupRepository::default();
    let storage_repository = FileVaultRepository::default();
    let vault = sample_vault(2)?;

    backup_repository.export(&backup_path, "backup-passphrase", &vault)?;
    let restored_vault = backup_repository.restore(&RestoreRequest {
        backup_path: &backup_path,
        backup_passphrase: "backup-passphrase",
        target_vault_path: &target_path,
        target_vault_passphrase: "vault-passphrase",
        target_vault_supplemental_secret: None,
        target_local_binding: None,
        mode: RestoreMode::CreateNew,
    })?;

    assert_eq!(restored_vault, vault);
    let unlocked = storage_repository.unlock(&target_path, "vault-passphrase")?;
    assert_eq!(unlocked, vault);
    Ok(())
}

#[test]
fn restore_with_create_new_fails_if_target_exists() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let backup_path = temp.path().join("create-new-fails.albusbak");
    let target_path = temp.path().join("existing.albus");
    let backup_repository = FileBackupRepository::default();
    let storage_repository = FileVaultRepository::default();

    backup_repository.export(&backup_path, "backup-passphrase", &sample_vault(1)?)?;
    storage_repository.create_new(&target_path, "current-vault-passphrase", &empty_vault()?)?;

    assert!(matches!(
        backup_repository.restore(&RestoreRequest {
            backup_path: &backup_path,
            backup_passphrase: "backup-passphrase",
            target_vault_path: &target_path,
            target_vault_passphrase: "new-vault-passphrase",
            target_vault_supplemental_secret: None,
            target_local_binding: None,
            mode: RestoreMode::CreateNew,
        }),
        Err(BackupError::RestoreModeViolation(
            "target path already exists"
        ))
    ));
    Ok(())
}

#[test]
fn restore_with_replace_existing_fails_if_target_is_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let backup_path = temp.path().join("replace-missing.albusbak");
    let target_path = temp.path().join("missing.albus");
    let backup_repository = FileBackupRepository::default();

    backup_repository.export(&backup_path, "backup-passphrase", &sample_vault(1)?)?;

    assert!(matches!(
        backup_repository.restore(&RestoreRequest {
            backup_path: &backup_path,
            backup_passphrase: "backup-passphrase",
            target_vault_path: &target_path,
            target_vault_passphrase: "new-vault-passphrase",
            target_vault_supplemental_secret: None,
            target_local_binding: None,
            mode: RestoreMode::ReplaceExisting,
        }),
        Err(BackupError::RestoreModeViolation(
            "target path must already exist"
        ))
    ));
    Ok(())
}

#[test]
fn restore_with_replace_existing_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let backup_path = temp.path().join("replace-existing.albusbak");
    let target_path = temp.path().join("target.albus");
    let backup_repository = FileBackupRepository::default();
    let storage_repository = FileVaultRepository::default();
    let vault = sample_vault(3)?;

    storage_repository.create_new(&target_path, "old-vault-passphrase", &empty_vault()?)?;
    backup_repository.export(&backup_path, "backup-passphrase", &vault)?;
    backup_repository.restore(&RestoreRequest {
        backup_path: &backup_path,
        backup_passphrase: "backup-passphrase",
        target_vault_path: &target_path,
        target_vault_passphrase: "new-vault-passphrase",
        target_vault_supplemental_secret: None,
        target_local_binding: None,
        mode: RestoreMode::ReplaceExisting,
    })?;

    let unlocked = storage_repository.unlock(&target_path, "new-vault-passphrase")?;
    assert_eq!(unlocked, vault);
    Ok(())
}

#[test]
fn serialization_deserialization_is_consistent_after_export()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("stable.albusbak");
    let repository = FileBackupRepository::default();
    let vault = sample_vault(2)?;

    repository.export(&path, "backup-passphrase", &vault)?;
    let snapshot = repository.decrypt_snapshot(&path, "backup-passphrase")?;

    assert_eq!(snapshot.vault, vault);
    assert!(!snapshot.exported_at.is_empty());
    assert_eq!(snapshot.source_app_version, env!("CARGO_PKG_VERSION"));
    Ok(())
}

#[test]
fn empty_backup_passphrase_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("empty-passphrase.albusbak");
    let repository = FileBackupRepository::default();

    assert!(matches!(
        repository.export(&path, "   ", &sample_vault(1)?),
        Err(BackupError::Crypto(CryptoError::EmptyPassphrase))
    ));
    Ok(())
}

#[test]
fn short_new_backup_passphrase_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("short-passphrase.albusbak");
    let repository = FileBackupRepository::default();

    assert!(matches!(
        repository.export(&path, "too-short", &sample_vault(1)?),
        Err(BackupError::Crypto(CryptoError::PassphraseTooShort(16)))
    ));
    Ok(())
}

#[test]
fn export_refuses_to_overwrite_existing_backup() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("existing.albusbak");
    let repository = FileBackupRepository::default();
    let vault = sample_vault(1)?;

    repository.export(&path, "backup-passphrase", &vault)?;
    assert!(matches!(
        repository.export(&path, "backup-passphrase", &vault),
        Err(BackupError::BackupAlreadyExists(_))
    ));
    Ok(())
}

#[test]
fn restore_rejects_using_the_backup_path_as_the_target_vault()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let backup_path = temp.path().join("same-path.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&backup_path, "backup-passphrase", &sample_vault(1)?)?;

    assert!(matches!(
        repository.restore(&RestoreRequest {
            backup_path: &backup_path,
            backup_passphrase: "backup-passphrase",
            target_vault_path: &backup_path,
            target_vault_passphrase: "vault-passphrase",
            target_vault_supplemental_secret: None,
            target_local_binding: None,
            mode: RestoreMode::ReplaceExisting,
        }),
        Err(BackupError::RestoreModeViolation(
            "backup path and target vault path must differ"
        ))
    ));
    Ok(())
}

#[test]
fn restore_rejects_backup_path_aliases_even_when_intermediate_components_are_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let backup_path = temp.path().join("alias-path.albusbak");
    let alias_target = temp
        .path()
        .join("missing")
        .join("..")
        .join("alias-path.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&backup_path, "backup-passphrase", &sample_vault(1)?)?;

    assert!(matches!(
        repository.restore(&RestoreRequest {
            backup_path: &backup_path,
            backup_passphrase: "backup-passphrase",
            target_vault_path: &alias_target,
            target_vault_passphrase: "vault-passphrase",
            target_vault_supplemental_secret: None,
            target_local_binding: None,
            mode: RestoreMode::CreateNew,
        }),
        Err(BackupError::RestoreModeViolation(
            "backup path and target vault path must differ"
        ))
    ));
    Ok(())
}

#[test]
fn oversized_container_is_rejected_before_parsing() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("oversized.albusbak");
    fs::write(&path, vec![0_u8; 65])?;

    let policy = albus::BackupPolicy {
        max_container_len: 64,
        ..albus::BackupPolicy::default()
    };
    let repository = FileBackupRepository::new(policy, CryptoPolicy::default());

    assert!(matches!(
        repository.load_header(&path),
        Err(BackupError::ContainerTooLarge(65))
    ));
    Ok(())
}

#[test]
fn oversized_plaintext_is_rejected_on_export_and_decrypt() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempdir()?;
    let path = temp.path().join("oversized-plaintext.albusbak");
    let vault = sample_vault(2)?;

    let write_policy = albus::BackupPolicy {
        max_plaintext_len: 64,
        ..albus::BackupPolicy::default()
    };
    let write_repository = FileBackupRepository::new(write_policy, CryptoPolicy::default());
    assert!(matches!(
        write_repository.export(&path, "backup-passphrase", &vault),
        Err(BackupError::PlaintextTooLarge(_))
    ));

    let default_repository = FileBackupRepository::default();
    default_repository.export(&path, "backup-passphrase", &vault)?;

    let read_policy = albus::BackupPolicy {
        max_plaintext_len: 64,
        ..albus::BackupPolicy::default()
    };
    let read_repository = FileBackupRepository::new(read_policy, CryptoPolicy::default());
    assert!(matches!(
        read_repository.decrypt_snapshot(&path, "backup-passphrase"),
        Err(BackupError::PlaintextTooLarge(_))
    ));
    Ok(())
}

#[test]
fn unknown_header_fields_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("unknown-header.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, "backup-passphrase", &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["unexpected"] = Value::from(true);
    })?;

    assert!(matches!(
        repository.load_header(&path),
        Err(BackupError::InvalidHeaderJson(_))
    ));
    Ok(())
}

#[test]
fn unknown_plaintext_fields_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("unknown-plaintext.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, "backup-passphrase", &sample_vault(1)?)?;

    mutate_plaintext_json(&path, "backup-passphrase", |plaintext| {
        plaintext["unexpected"] = Value::from(true);
    })?;

    assert!(matches!(
        repository.decrypt_snapshot(&path, "backup-passphrase"),
        Err(BackupError::InvalidPlaintextJson(_))
    ));
    Ok(())
}

#[test]
fn written_backup_headers_omit_optional_timestamp_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("minimal-header.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, "backup-passphrase", &sample_vault(1)?)?;

    let bytes = fs::read(&path)?;
    let magic_len = 8;
    let header_len = u32::from_le_bytes(bytes[magic_len..magic_len + 4].try_into()?);
    let header_start = magic_len + 4;
    let header_end = header_start + usize::try_from(header_len)?;
    let header: Value = serde_json::from_slice(&bytes[header_start..header_end])?;

    assert!(header["metadata"].get("created_at").is_none());
    assert!(header["metadata"].get("updated_at").is_none());
    Ok(())
}

#[cfg(unix)]
#[test]
fn created_backup_and_parent_directories_use_private_unix_modes()
-> Result<(), Box<dyn std::error::Error>> {
    if matches!(
        std::env::var("GITHUB_ACTIONS")
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    ) {
        eprintln!(
            "skipping unix backup permission test in GitHub Actions: runner filesystem modes can be host-dependent"
        );
        return Ok(());
    }

    let temp = tempdir()?;
    let path = temp
        .path()
        .join("private")
        .join("exports")
        .join("vault.albusbak");
    let repository = FileBackupRepository::default();
    repository.export(&path, "backup-passphrase", &sample_vault(1)?)?;

    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(path.parent().ok_or("missing backup parent")?)?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    Ok(())
}

fn sample_vault(entries: usize) -> Result<Vault, Box<dyn std::error::Error>> {
    let mut items = Vec::with_capacity(entries);
    for index in 0..entries {
        let parameters = TotpParameters::new(
            Issuer::new(format!("Example {index}"))?,
            AccountLabel::new(format!("alice{index}@example.com"))?,
            OtpSecret::from_base32("JBSWY3DPEHPK3PXP")?,
            if index % 2 == 0 {
                Digits::Six
            } else {
                Digits::Eight
            },
            Period::new(if index % 2 == 0 { 30 } else { 45 })?,
            if index % 3 == 0 {
                HashAlgorithm::Sha1
            } else if index % 3 == 1 {
                HashAlgorithm::Sha256
            } else {
                HashAlgorithm::Sha512
            },
        );
        items.push(OtpEntry::new(
            EntryId::new(format!("entry-{index}"))?,
            parameters,
        ));
    }

    Ok(Vault::new(
        VaultId::new("vault-1")?,
        1,
        7,
        "2026-03-11T00:00:00Z",
        "2026-03-11T00:05:00Z",
        items,
    )?)
}

fn empty_vault() -> Result<Vault, Box<dyn std::error::Error>> {
    Ok(Vault::new(
        VaultId::new("vault-empty")?,
        1,
        1,
        "2026-03-11T00:00:00Z",
        "2026-03-11T00:00:00Z",
        Vec::new(),
    )?)
}

fn mutate_header_json(
    path: &Path,
    mutate: impl FnOnce(&mut Value),
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let magic_len = 8;
    let header_len = u32::from_le_bytes(bytes[magic_len..magic_len + 4].try_into()?);
    let header_start = magic_len + 4;
    let header_end = header_start + usize::try_from(header_len)?;

    let mut header: Value = serde_json::from_slice(&bytes[header_start..header_end])?;
    mutate(&mut header);
    let new_header = serde_json::to_vec(&header)?;
    let new_header_len = u32::try_from(new_header.len())?;

    let mut mutated = Vec::with_capacity(bytes.len() + new_header.len());
    mutated.extend_from_slice(&bytes[..magic_len]);
    mutated.extend_from_slice(&new_header_len.to_le_bytes());
    mutated.extend_from_slice(&new_header);
    mutated.extend_from_slice(&bytes[header_end..]);
    fs::write(path, mutated)?;
    Ok(())
}

fn mutate_plaintext_json(
    path: &Path,
    passphrase: &str,
    mutate: impl FnOnce(&mut Value),
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let magic = *b"ALBUSV1\0";
    let magic_len = magic.len();
    let header_len = u32::from_le_bytes(bytes[magic_len..magic_len + 4].try_into()?);
    let header_start = magic_len + 4;
    let header_end = header_start + usize::try_from(header_len)?;

    let header_json = bytes[header_start..header_end].to_vec();
    let header: EnvelopeHeader = serde_json::from_slice(&header_json)?;
    let ciphertext = bytes[header_end..].to_vec();
    let policy = CryptoPolicy::default();
    let nonce = header.decode_nonce(&policy)?;
    let aad = build_aad(magic, &header_json)?;
    let key = derive_envelope_key(passphrase, &header, &policy, None)?;
    let plaintext = decrypt(&key, &nonce, &aad, &ciphertext, &policy)?;

    let mut json: Value = serde_json::from_slice(&plaintext)?;
    mutate(&mut json);

    let new_plaintext = serde_json::to_vec(&json)?;
    let new_ciphertext = encrypt(&key, &nonce, &aad, &new_plaintext, &policy)?;
    let mut mutated = Vec::with_capacity(header_end + new_ciphertext.len());
    mutated.extend_from_slice(&bytes[..header_end]);
    mutated.extend_from_slice(&new_ciphertext);
    fs::write(path, mutated)?;
    Ok(())
}

fn build_aad(magic: [u8; 8], header_json: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let header_len = u32::try_from(header_json.len())?;
    let mut aad = Vec::with_capacity(magic.len() + 4 + header_json.len());
    aad.extend_from_slice(&magic);
    aad.extend_from_slice(&header_len.to_le_bytes());
    aad.extend_from_slice(header_json);
    Ok(aad)
}
