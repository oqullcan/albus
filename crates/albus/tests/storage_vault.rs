#![doc = "Encrypted vault storage integration tests for albus."]

use std::{fs, path::Path};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use albus::{
    AccountLabel, Digits, EntryId, HashAlgorithm, Issuer, OtpEntry, OtpSecret, Period,
    TotpParameters, Vault, VaultId,
};
use albus::{
    ContainerKind, CryptoError, CryptoPolicy, EnvelopeHeader, assemble_envelope_container, decrypt,
    derive_envelope_key, encrypt,
};
use albus::{FileVaultRepository, StorageError, StoragePolicy, VaultRepository};
use serde_json::Value;
use tempfile::tempdir;

const LONG_VAULT_PASSPHRASE: &str = "correct horse battery staple";

#[test]
fn successful_round_trip_unlocks_the_same_vault() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("vault.albus");
    let repository = FileVaultRepository::default();
    let vault = sample_vault(1)?;

    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &vault)?;
    let header = repository.load_header(&path)?;
    assert_eq!(header.kind, ContainerKind::Vault);

    let unlocked = repository.unlock(&path, LONG_VAULT_PASSPHRASE)?;
    assert_eq!(unlocked, vault);
    Ok(())
}

#[test]
fn wrong_passphrase_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("vault.albus");
    let repository = FileVaultRepository::default();
    let vault = sample_vault(1)?;

    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &vault)?;
    assert!(matches!(
        repository.unlock(&path, "wrong passphrase"),
        Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
    ));
    Ok(())
}

#[test]
fn corrupted_header_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("vault.albus");
    let repository = FileVaultRepository::default();
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

    let mut bytes = fs::read(&path)?;
    bytes[12] = b'!';
    fs::write(&path, bytes)?;

    assert!(matches!(
        repository.load_header(&path),
        Err(StorageError::InvalidHeaderJson(_))
    ));
    Ok(())
}

#[test]
fn corrupted_version_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("vault.albus");
    let repository = FileVaultRepository::default();
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["format_version"] = Value::from(2);
    })?;

    assert!(matches!(
        repository.load_header(&path),
        Err(StorageError::UnsupportedFormatVersion(2))
    ));
    Ok(())
}

#[test]
fn unknown_local_binding_provider_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("unknown-local-binding-provider.albus");
    let repository = FileVaultRepository::default();
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["local_binding"] = serde_json::json!({
            "provider": "unknown-provider",
            "scope": "current-user"
        });
    })?;

    assert!(matches!(
        repository.load_header(&path),
        Err(StorageError::Crypto(CryptoError::UnsupportedLocalBindingProvider(
            provider
        ))) if provider == "unknown-provider"
    ));
    Ok(())
}

#[test]
fn invalid_local_binding_scope_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("invalid-local-binding-scope.albus");
    let repository = FileVaultRepository::default();
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["local_binding"] = serde_json::json!({
            "provider": "windows-dpapi",
            "scope": "machine"
        });
    })?;

    assert!(matches!(
        repository.load_header(&path),
        Err(StorageError::Crypto(CryptoError::UnsupportedLocalBindingScope {
            provider,
            scope,
        })) if provider == "windows-dpapi" && scope == "machine"
    ));
    Ok(())
}

#[test]
fn corrupted_nonce_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("vault.albus");
    let repository = FileVaultRepository::default();
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["cipher"]["nonce_b64"] = Value::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    })?;

    assert!(matches!(
        repository.unlock(&path, LONG_VAULT_PASSPHRASE),
        Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
    ));
    Ok(())
}

#[test]
fn corrupted_salt_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("vault.albus");
    let repository = FileVaultRepository::default();
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["kdf"]["salt_b64"] = Value::from("AAAAAAAAAAAAAAAAAAAAAA==");
    })?;

    assert!(matches!(
        repository.unlock(&path, LONG_VAULT_PASSPHRASE),
        Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
    ));
    Ok(())
}

#[test]
fn corrupted_ciphertext_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("vault.albus");
    let repository = FileVaultRepository::default();
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

    let mut bytes = fs::read(&path)?;
    let last_index = bytes.len() - 1;
    bytes[last_index] ^= 0x01;
    fs::write(&path, bytes)?;

    assert!(matches!(
        repository.unlock(&path, LONG_VAULT_PASSPHRASE),
        Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
    ));
    Ok(())
}

#[test]
fn empty_vault_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("empty.albus");
    let repository = FileVaultRepository::default();
    let vault = empty_vault()?;

    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &vault)?;
    let unlocked = repository.unlock(&path, LONG_VAULT_PASSPHRASE)?;
    assert_eq!(unlocked, vault);
    Ok(())
}

#[test]
fn create_new_creates_missing_parent_directories() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp
        .path()
        .join("nested")
        .join("vaults")
        .join("vault.albus");
    let repository = FileVaultRepository::default();

    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

    assert!(path.exists());
    let unlocked = repository.unlock(&path, LONG_VAULT_PASSPHRASE)?;
    assert_eq!(unlocked.entries().len(), 1);
    Ok(())
}

#[test]
fn multiple_entries_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("multi.albus");
    let repository = FileVaultRepository::default();
    let vault = sample_vault(3)?;

    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &vault)?;
    let unlocked = repository.unlock(&path, LONG_VAULT_PASSPHRASE)?;
    assert_eq!(unlocked, vault);
    Ok(())
}

#[test]
fn serialization_deserialization_is_consistent_after_save() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempdir()?;
    let path = temp.path().join("stable.albus");
    let repository = FileVaultRepository::default();
    let original = sample_vault(2)?;

    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &original)?;
    let unlocked = repository.unlock(&path, LONG_VAULT_PASSPHRASE)?;
    repository.save(&path, LONG_VAULT_PASSPHRASE, &unlocked)?;
    let unlocked_again = repository.unlock(&path, LONG_VAULT_PASSPHRASE)?;

    assert_eq!(unlocked_again, original);
    Ok(())
}

#[test]
fn save_does_not_leave_backup_artifacts_in_the_vault_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("vault.albus");
    let repository = FileVaultRepository::default();
    let vault = sample_vault(1)?;

    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &vault)?;
    let unlocked = repository.unlock(&path, LONG_VAULT_PASSPHRASE)?;
    repository.save(&path, LONG_VAULT_PASSPHRASE, &unlocked)?;

    let mut names = fs::read_dir(temp.path())?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    assert_eq!(names, vec!["vault.albus".to_owned()]);
    Ok(())
}

#[test]
fn restore_replace_requires_existing_target() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("restore.albus");
    let repository = FileVaultRepository::default();
    let vault = sample_vault(1)?;

    assert!(matches!(
        repository.restore_replace(&path, LONG_VAULT_PASSPHRASE, &vault),
        Err(StorageError::RestoreTargetMissing(_))
    ));
    Ok(())
}

#[test]
fn empty_passphrase_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("empty-passphrase.albus");
    let repository = FileVaultRepository::default();

    assert!(matches!(
        repository.create_new(&path, "   ", &sample_vault(1)?),
        Err(StorageError::Crypto(CryptoError::EmptyPassphrase))
    ));
    Ok(())
}

#[test]
fn short_new_passphrase_is_rejected_for_create_and_restore_replace()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let create_path = temp.path().join("short-create.albus");
    let replace_path = temp.path().join("short-replace.albus");
    let repository = FileVaultRepository::default();
    let vault = sample_vault(1)?;

    assert!(matches!(
        repository.create_new(&create_path, "too-short", &vault),
        Err(StorageError::Crypto(CryptoError::PassphraseTooShort(16)))
    ));

    repository.create_new(&replace_path, LONG_VAULT_PASSPHRASE, &empty_vault()?)?;
    assert!(matches!(
        repository.restore_replace(&replace_path, "too-short", &vault),
        Err(StorageError::Crypto(CryptoError::PassphraseTooShort(16)))
    ));
    Ok(())
}

#[test]
fn oversized_container_is_rejected_before_parsing() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("oversized.albus");
    fs::write(&path, vec![0_u8; 33])?;

    let policy = StoragePolicy {
        max_container_len: 32,
        ..StoragePolicy::default()
    };
    let repository = FileVaultRepository::new(policy, CryptoPolicy::default());

    assert!(matches!(
        repository.load_header(&path),
        Err(StorageError::ContainerTooLarge(33))
    ));
    Ok(())
}

#[test]
fn oversized_plaintext_is_rejected_on_write_and_unlock() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("oversized-plaintext.albus");
    let vault = sample_vault(2)?;

    let write_policy = StoragePolicy {
        max_plaintext_len: 64,
        ..StoragePolicy::default()
    };
    let write_repository = FileVaultRepository::new(write_policy, CryptoPolicy::default());
    assert!(matches!(
        write_repository.create_new(&path, LONG_VAULT_PASSPHRASE, &vault),
        Err(StorageError::PlaintextTooLarge(_))
    ));

    let default_repository = FileVaultRepository::default();
    default_repository.create_new(&path, LONG_VAULT_PASSPHRASE, &vault)?;

    let read_policy = StoragePolicy {
        max_plaintext_len: 64,
        ..StoragePolicy::default()
    };
    let read_repository = FileVaultRepository::new(read_policy, CryptoPolicy::default());
    assert!(matches!(
        read_repository.unlock(&path, LONG_VAULT_PASSPHRASE),
        Err(StorageError::PlaintextTooLarge(_))
    ));
    Ok(())
}

#[test]
fn unknown_header_fields_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("unknown-header-field.albus");
    let repository = FileVaultRepository::default();
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

    mutate_header_json(&path, |header| {
        header["unexpected"] = Value::from(true);
    })?;

    assert!(matches!(
        repository.load_header(&path),
        Err(StorageError::InvalidHeaderJson(_))
    ));
    Ok(())
}

#[test]
fn unknown_plaintext_fields_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("unknown-plaintext-field.albus");
    let repository = FileVaultRepository::default();
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

    mutate_plaintext_json(&path, LONG_VAULT_PASSPHRASE, |plaintext| {
        plaintext["unexpected"] = Value::from(true);
    })?;

    assert!(matches!(
        repository.unlock(&path, LONG_VAULT_PASSPHRASE),
        Err(StorageError::InvalidPlaintextJson(_))
    ));
    Ok(())
}

#[test]
fn written_headers_omit_optional_timestamp_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("minimal-header.albus");
    let repository = FileVaultRepository::default();
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

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

#[test]
fn legacy_header_timestamp_metadata_remains_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let path = temp.path().join("legacy-header.albus");
    let repository = FileVaultRepository::default();
    let vault = sample_vault(1)?;
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &vault)?;

    mutate_header_json_and_reencrypt(&path, LONG_VAULT_PASSPHRASE, |header| {
        header["metadata"]["created_at"] = Value::from("2026-03-11T00:00:00Z");
        header["metadata"]["updated_at"] = Value::from("2026-03-11T00:05:00Z");
    })?;

    let unlocked = repository.unlock(&path, LONG_VAULT_PASSPHRASE)?;
    assert_eq!(unlocked, vault);
    Ok(())
}

#[cfg(unix)]
#[test]
fn created_vault_and_parent_directories_use_private_unix_modes()
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
            "skipping unix vault permission test in GitHub Actions: runner filesystem modes can be host-dependent"
        );
        return Ok(());
    }

    let temp = tempdir()?;
    let path = temp
        .path()
        .join("private")
        .join("vaults")
        .join("vault.albus");
    let repository = FileVaultRepository::default();
    repository.create_new(&path, LONG_VAULT_PASSPHRASE, &sample_vault(1)?)?;

    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(path.parent().ok_or("missing vault parent")?)?
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

fn mutate_header_json_and_reencrypt(
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

    let mut json: Value = serde_json::from_slice(&header_json)?;
    mutate(&mut json);
    let new_header_json = serde_json::to_vec(&json)?;
    let new_aad = build_aad(magic, &new_header_json)?;
    let new_ciphertext = encrypt(&key, &nonce, &new_aad, &plaintext, &policy)?;
    let container = assemble_envelope_container(&magic, &new_header_json, &new_ciphertext)?;
    fs::write(path, container)?;
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
