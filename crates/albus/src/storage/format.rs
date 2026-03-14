use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use albus_core::{
    AccountLabel, Digits, EntryId, HashAlgorithm, Issuer, OtpEntry, OtpSecret, Period,
    TotpParameters, Vault, VaultId,
};

use crate::StorageError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

    pub(crate) fn into_vault(self) -> Result<Vault, StorageError> {
        let mut plaintext = self;
        let entries = std::mem::take(&mut plaintext.entries)
            .into_iter()
            .map(PlaintextOtpEntry::into_entry)
            .collect::<Result<Vec<_>, _>>()?;

        Vault::new(
            VaultId::new(std::mem::take(&mut plaintext.vault_id))?,
            plaintext.schema_version,
            plaintext.revision,
            std::mem::take(&mut plaintext.created_at),
            std::mem::take(&mut plaintext.updated_at),
            entries,
        )
        .map_err(StorageError::from)
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

    fn into_entry(self) -> Result<OtpEntry, StorageError> {
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
