use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use albus_core::{
    AccountLabel, Digits, EntryId, HashAlgorithm, Issuer, OtpEntry, OtpSecret, Period,
    TotpParameters, Vault, VaultId,
};
use albus_crypto::EnvelopeHeader;

use crate::BackupError;

/// Non-secret header fields for a backup container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupHeader {
    /// Outer file format version.
    pub format_version: u32,
    /// Inner snapshot schema version.
    pub schema_version: u32,
    /// Stable source vault identifier.
    pub vault_id: String,
    /// Source vault revision.
    pub revision: u64,
}

impl BackupHeader {
    pub(crate) fn from_envelope(header: &EnvelopeHeader) -> Result<Self, BackupError> {
        Ok(Self {
            format_version: header.format_version,
            schema_version: header.schema_version,
            vault_id: normalize_required_field("vault_id", &header.metadata.vault_id)?,
            revision: header.metadata.revision,
        })
    }
}

/// Full decrypted backup snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSnapshot {
    /// Timestamp at which the snapshot was exported.
    pub exported_at: String,
    /// Source application version.
    pub source_app_version: String,
    /// Full vault payload.
    pub vault: Vault,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlaintextBackupSnapshot {
    pub(crate) schema_version: u32,
    pub(crate) exported_at: String,
    pub(crate) source_app_version: String,
    pub(crate) vault: PlaintextVault,
}

impl PlaintextBackupSnapshot {
    pub(crate) fn from_snapshot(snapshot: &BackupSnapshot) -> Self {
        Self {
            schema_version: snapshot.vault.schema_version(),
            exported_at: snapshot.exported_at.clone(),
            source_app_version: snapshot.source_app_version.clone(),
            vault: PlaintextVault::from_vault(&snapshot.vault),
        }
    }

    pub(crate) fn into_snapshot(self) -> Result<BackupSnapshot, BackupError> {
        let mut snapshot = self;
        let exported_at = normalize_required_field("exported_at", &snapshot.exported_at)?;
        let source_app_version =
            normalize_required_field("source_app_version", &snapshot.source_app_version)?;
        let vault = std::mem::take(&mut snapshot.vault).into_vault()?;

        if snapshot.schema_version != vault.schema_version() {
            return Err(BackupError::MetadataMismatch("schema_version"));
        }

        Ok(BackupSnapshot {
            exported_at,
            source_app_version,
            vault,
        })
    }
}

impl Drop for PlaintextBackupSnapshot {
    fn drop(&mut self) {
        self.exported_at.zeroize();
        self.source_app_version.zeroize();
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlaintextVault {
    pub(crate) schema_version: u32,
    pub(crate) vault_id: String,
    pub(crate) revision: u64,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) entries: Vec<PlaintextOtpEntry>,
}

impl PlaintextVault {
    pub(crate) fn from_vault(vault: &Vault) -> Self {
        Self {
            schema_version: vault.schema_version(),
            vault_id: vault.vault_id().as_str().to_owned(),
            revision: vault.revision(),
            created_at: vault.created_at().to_owned(),
            updated_at: vault.updated_at().to_owned(),
            entries: vault
                .entries()
                .iter()
                .map(PlaintextOtpEntry::from_entry)
                .collect(),
        }
    }

    pub(crate) fn into_vault(self) -> Result<Vault, BackupError> {
        let mut plaintext = self;
        let entries = std::mem::take(&mut plaintext.entries)
            .into_iter()
            .map(PlaintextOtpEntry::into_entry)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Vault::new(
            VaultId::new(std::mem::take(&mut plaintext.vault_id))?,
            plaintext.schema_version,
            plaintext.revision,
            std::mem::take(&mut plaintext.created_at),
            std::mem::take(&mut plaintext.updated_at),
            entries,
        )?)
    }
}

impl Drop for PlaintextVault {
    fn drop(&mut self) {
        self.vault_id.zeroize();
        self.created_at.zeroize();
        self.updated_at.zeroize();
        for entry in &mut self.entries {
            entry.zeroize();
        }
        self.entries.clear();
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlaintextOtpEntry {
    pub(crate) entry_id: String,
    pub(crate) issuer: String,
    pub(crate) account_label: String,
    pub(crate) secret_b64: String,
    pub(crate) digits: u32,
    pub(crate) period_secs: u32,
    pub(crate) algorithm: String,
}

impl PlaintextOtpEntry {
    fn from_entry(entry: &OtpEntry) -> Self {
        let parameters = entry.parameters();
        Self {
            entry_id: entry.entry_id().as_str().to_owned(),
            issuer: parameters.issuer().as_str().to_owned(),
            account_label: parameters.account_label().as_str().to_owned(),
            secret_b64: parameters.secret().to_base64(),
            digits: parameters.digits().get(),
            period_secs: parameters.period().get(),
            algorithm: parameters.algorithm().as_storage_str().to_owned(),
        }
    }

    fn into_entry(self) -> Result<OtpEntry, BackupError> {
        let mut entry = self;
        let parameters = TotpParameters::new(
            Issuer::new(std::mem::take(&mut entry.issuer))?,
            AccountLabel::new(std::mem::take(&mut entry.account_label))?,
            OtpSecret::from_base64(&entry.secret_b64)?,
            Digits::try_from(entry.digits)?,
            Period::new(entry.period_secs)?,
            entry.algorithm.parse::<HashAlgorithm>()?,
        );

        Ok(OtpEntry::new(
            EntryId::new(std::mem::take(&mut entry.entry_id))?,
            parameters,
        ))
    }

    fn zeroize(&mut self) {
        self.entry_id.zeroize();
        self.issuer.zeroize();
        self.account_label.zeroize();
        self.secret_b64.zeroize();
        self.algorithm.zeroize();
    }
}

impl Drop for PlaintextOtpEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn normalize_required_field(field_name: &'static str, value: &str) -> Result<String, BackupError> {
    let normalized = value.trim().to_owned();
    if normalized.is_empty() {
        return Err(BackupError::InvalidBackupMetadata(field_name));
    }

    Ok(normalized)
}
