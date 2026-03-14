use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    AppError,
    private_fs::{read_limited_file, write_private_file_atomic},
};

const TRUST_ANCHOR_FILE_NAME: &str = "trusted-vault-revisions-v1.json";
const MAX_TRUST_ANCHOR_STATE_LEN: u64 = 512 * 1024;

/// Local best-effort rollback detection anchor for known vault revisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VaultTrustAnchor {
    state_file: PathBuf,
}

impl VaultTrustAnchor {
    /// Creates a trust anchor next to the local remembered-path config file.
    #[must_use]
    pub(crate) fn from_config_file(config_file: &Path) -> Self {
        let parent = config_file.parent().unwrap_or_else(|| Path::new("."));
        Self {
            state_file: parent.join(TRUST_ANCHOR_FILE_NAME),
        }
    }

    /// Returns an error when the observed revision is older than the locally
    /// trusted revision for the same vault identifier.
    pub(crate) fn ensure_not_rolled_back(
        &self,
        vault_id: &str,
        observed_revision: u64,
    ) -> Result<(), AppError> {
        let state = self.load_state()?;
        let Some(trusted) = state.vaults.iter().find(|entry| entry.vault_id == vault_id) else {
            return Ok(());
        };

        if observed_revision < trusted.revision {
            return Err(AppError::RollbackDetected {
                vault_id: vault_id.to_owned(),
                current_revision: observed_revision,
                trusted_revision: trusted.revision,
            });
        }

        Ok(())
    }

    /// Records the newest trusted revision observed for a vault.
    pub(crate) fn record_max(&self, vault_id: &str, revision: u64) -> Result<(), AppError> {
        self.record(vault_id, revision, RecordMode::OnlyIncrease)
    }

    /// Records a trusted revision exactly, even if it intentionally lowers the
    /// previous ceiling, such as after an explicit restore.
    pub(crate) fn record_exact(&self, vault_id: &str, revision: u64) -> Result<(), AppError> {
        self.record(vault_id, revision, RecordMode::AllowDowngrade)
    }

    fn record(&self, vault_id: &str, revision: u64, mode: RecordMode) -> Result<(), AppError> {
        let mut state = self.load_state()?;
        match state
            .vaults
            .iter_mut()
            .find(|entry| entry.vault_id == vault_id)
        {
            Some(entry) => match mode {
                RecordMode::OnlyIncrease => {
                    entry.revision = entry.revision.max(revision);
                }
                RecordMode::AllowDowngrade => {
                    entry.revision = revision;
                }
            },
            None => state.vaults.push(TrustedVaultRevision {
                vault_id: vault_id.to_owned(),
                revision,
            }),
        }

        state
            .vaults
            .sort_by(|left, right| left.vault_id.cmp(&right.vault_id));
        self.write_state(&state)
    }

    fn load_state(&self) -> Result<TrustAnchorState, AppError> {
        match read_limited_file(&self.state_file, MAX_TRUST_ANCHOR_STATE_LEN) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(AppError::InvalidTrustAnchorState),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(TrustAnchorState::default())
            }
            Err(error) => Err(AppError::Io(error)),
        }
    }

    fn write_state(&self, state: &TrustAnchorState) -> Result<(), AppError> {
        let encoded = serde_json::to_vec(state)?;
        write_private_file_atomic(&self.state_file, &encoded)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordMode {
    OnlyIncrease,
    AllowDowngrade,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustAnchorState {
    #[serde(default)]
    vaults: Vec<TrustedVaultRevision>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedVaultRevision {
    vault_id: String,
    revision: u64,
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::VaultTrustAnchor;
    use crate::AppError;

    #[test]
    fn trust_anchor_rejects_older_observed_revisions() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let anchor = VaultTrustAnchor::from_config_file(&tempdir.path().join("remembered.txt"));
        anchor.record_max("vault-1", 7)?;

        let result = anchor.ensure_not_rolled_back("vault-1", 6);

        assert!(matches!(
            result,
            Err(AppError::RollbackDetected {
                current_revision: 6,
                trusted_revision: 7,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn trust_anchor_can_intentionally_accept_lower_restored_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let anchor = VaultTrustAnchor::from_config_file(&tempdir.path().join("remembered.txt"));
        anchor.record_max("vault-1", 7)?;
        anchor.record_exact("vault-1", 3)?;

        assert!(anchor.ensure_not_rolled_back("vault-1", 3).is_ok());
        Ok(())
    }
}
