use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use albus::{
    AccountLabel, BackupRepository, CryptoError, Digits, EntryId, FileBackupRepository,
    FileVaultRepository, HashAlgorithm, Issuer, LocalBindingHeader, OtpEntry, OtpSecret, Period,
    RestoreMode, RestoreRequest, TotpGenerator, TotpParameters, Vault, VaultId, VaultRepository,
    parse_totp_uri, validate_existing_passphrase as validate_existing_crypto_passphrase,
    validate_new_passphrase as validate_new_crypto_passphrase,
};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    AppError, Clock, RememberedVaultPath, device_binding::DeviceBindingStore,
    trust_anchor::VaultTrustAnchor,
};

/// The exact high-level application states used by the TUI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppState {
    /// No remembered or valid vault exists yet.
    NoVault,
    /// A vault path is known, but plaintext is not loaded.
    Locked,
    /// The plaintext vault is resident in memory.
    Unlocked,
}

/// Manual add-entry input captured by the TUI.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AddEntryInput {
    /// Human-readable issuer.
    pub issuer: String,
    /// Human-readable account label.
    pub account_label: String,
    /// Base32-encoded OTP secret.
    pub secret_base32: String,
    /// Optional algorithm override. Defaults to `SHA1`.
    pub algorithm: Option<String>,
    /// Optional digit override. Defaults to `6`.
    pub digits: Option<String>,
    /// Optional period override. Defaults to `30`.
    pub period: Option<String>,
}

/// Manual edit-entry input captured by the TUI.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EditEntryInput {
    /// Human-readable issuer.
    pub issuer: String,
    /// Human-readable account label.
    pub account_label: String,
    /// Base32-encoded OTP secret.
    pub secret_base32: String,
    /// Optional algorithm override. Defaults to `SHA1`.
    pub algorithm: Option<String>,
    /// Optional digit override. Defaults to `6`.
    pub digits: Option<String>,
    /// Optional period override. Defaults to `30`.
    pub period: Option<String>,
}

/// Manual URI-import input captured by the TUI.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImportUriInput {
    /// Raw `otpauth://totp` URI text.
    pub uri: String,
}

/// Manual delete-entry confirmation captured by the TUI.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeleteEntryInput {
    /// Explicit confirmation text. Must be `DELETE`.
    pub confirmation: String,
}

/// Manual change-passphrase input captured by the TUI.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChangePassphraseInput {
    /// Current master passphrase used to verify the existing vault file.
    pub current_passphrase: String,
    /// New master passphrase for the re-encrypted vault file.
    pub new_passphrase: String,
    /// New master passphrase confirmation.
    pub confirmation: String,
}

/// Manual export-backup input captured by the TUI.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BackupExportInput {
    /// Destination encrypted backup path.
    pub backup_path: PathBuf,
    /// Backup passphrase.
    pub backup_passphrase: String,
    /// Backup passphrase confirmation.
    pub confirmation: String,
}

/// Manual restore-backup input captured by the TUI.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BackupRestoreInput {
    /// Source encrypted backup path.
    pub backup_path: PathBuf,
    /// Backup passphrase used to decrypt the source file.
    pub backup_passphrase: String,
    /// Destination vault path.
    pub target_vault_path: PathBuf,
    /// Master passphrase for the restored vault file.
    pub target_vault_passphrase: String,
    /// Target vault passphrase confirmation.
    pub confirmation: String,
    /// Whether replacing an existing target path was explicitly confirmed.
    pub replace_existing: bool,
}

impl AddEntryInput {
    fn zeroize_secret_fields(&mut self) {
        self.secret_base32.zeroize();
    }
}

impl EditEntryInput {
    fn zeroize_secret_fields(&mut self) {
        self.secret_base32.zeroize();
    }
}

impl ImportUriInput {
    fn zeroize_secret_fields(&mut self) {
        self.uri.zeroize();
    }
}

impl ChangePassphraseInput {
    fn zeroize_secret_fields(&mut self) {
        self.current_passphrase.zeroize();
        self.new_passphrase.zeroize();
        self.confirmation.zeroize();
    }
}

impl BackupExportInput {
    fn zeroize_secret_fields(&mut self) {
        self.backup_passphrase.zeroize();
        self.confirmation.zeroize();
    }
}

impl BackupRestoreInput {
    fn zeroize_secret_fields(&mut self) {
        self.backup_passphrase.zeroize();
        self.target_vault_passphrase.zeroize();
        self.confirmation.zeroize();
    }
}

/// View model for the `NoVault` screen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoVaultView {
    /// Suggested default vault path for the create flow.
    pub suggested_vault_path: PathBuf,
    /// Optional inline status or error text.
    pub status_message: Option<String>,
}

/// View model for the `Locked` screen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedView {
    /// The known vault path.
    pub vault_path: PathBuf,
    /// Known entry count from a prior unlock or create flow.
    pub known_entry_count: Option<usize>,
    /// Optional inline status or error text.
    pub status_message: Option<String>,
}

/// List item shown in the unlocked entry list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryListItem {
    /// Issuer name.
    pub issuer: String,
    /// Account label.
    pub account_label: String,
}

/// Detail pane data for the selected entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryDetail {
    /// Issuer name.
    pub issuer: String,
    /// Account label.
    pub account_label: String,
    /// Current TOTP code.
    pub code: String,
    /// Seconds remaining in the current TOTP window.
    pub valid_for_secs: u32,
    /// Selected TOTP algorithm.
    pub algorithm: HashAlgorithm,
    /// Digit count.
    pub digits: u32,
    /// Period in seconds.
    pub period_secs: u32,
}

/// View model for the `Unlocked` screen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnlockedView {
    /// The vault path.
    pub vault_path: PathBuf,
    /// Whether the in-memory session differs from the last persisted snapshot.
    pub dirty: bool,
    /// Active entry filter query, if any.
    pub filter_query: Option<String>,
    /// Number of entries visible after filtering.
    pub visible_entry_count: usize,
    /// Total number of entries in the unlocked vault.
    pub total_entry_count: usize,
    /// Renderable entry list items.
    pub entries: Vec<EntryListItem>,
    /// Current selection index, if any.
    pub selected_index: Option<usize>,
    /// Current selected entry detail.
    pub selected_detail: Option<EntryDetail>,
    /// Optional inline status or error text.
    pub status_message: Option<String>,
}

/// Read-only data snapshot for rendering and tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppSnapshot {
    /// No vault exists yet.
    NoVault(NoVaultView),
    /// Vault exists but is locked.
    Locked(LockedView),
    /// Plaintext vault is available.
    Unlocked(UnlockedView),
}

/// Testable application controller for the TUI shell.
#[derive(Debug)]
pub struct AppController<C: Clock> {
    clock: C,
    remembered_path: RememberedVaultPath,
    trust_anchor: VaultTrustAnchor,
    device_binding_store: DeviceBindingStore,
    repository: FileVaultRepository,
    backup_repository: FileBackupRepository,
    state: ControllerState,
}

#[derive(Debug)]
enum ControllerState {
    NoVault(NoVaultState),
    Locked(LockedState),
    Unlocked(UnlockedSession),
}

#[derive(Debug, Default)]
struct NoVaultState {
    status_message: Option<String>,
}

#[derive(Debug)]
struct LockedState {
    vault_path: PathBuf,
    known_entry_count: Option<usize>,
    status_message: Option<String>,
}

#[derive(Debug)]
struct UnlockedSession {
    vault_path: PathBuf,
    vault_id: VaultId,
    local_binding: Option<LocalBindingHeader>,
    schema_version: u32,
    persisted_revision: u64,
    created_at: String,
    updated_at: String,
    persisted_entry_count: usize,
    entries: Vec<OtpEntry>,
    entry_filter: String,
    selected_index: Option<usize>,
    dirty: bool,
    status_message: Option<String>,
}

struct SavePlan {
    vault_path: PathBuf,
    entry_count: usize,
    vault: Vault,
}

impl<C: Clock> AppController<C> {
    /// Initializes the controller from the remembered local vault path.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when the remembered-path config cannot be read.
    pub fn initialize(clock: C, remembered_path: RememberedVaultPath) -> Result<Self, AppError> {
        let device_binding_store =
            DeviceBindingStore::from_config_file(remembered_path.config_file());
        Self::initialize_with_device_binding(clock, remembered_path, device_binding_store)
    }

    fn initialize_with_device_binding(
        clock: C,
        remembered_path: RememberedVaultPath,
        device_binding_store: DeviceBindingStore,
    ) -> Result<Self, AppError> {
        let trust_anchor = VaultTrustAnchor::from_config_file(remembered_path.config_file());
        let repository = FileVaultRepository::default();
        let backup_repository = FileBackupRepository::default();
        let state = match remembered_path.load()? {
            Some(vault_path) => match repository.load_header(&vault_path) {
                Ok(header) => {
                    let status_message = trust_anchor
                        .ensure_not_rolled_back(
                            header.metadata.vault_id.as_str(),
                            header.metadata.revision,
                        )
                        .err()
                        .map(|error| error.to_string());
                    ControllerState::Locked(LockedState {
                        vault_path,
                        known_entry_count: None,
                        status_message,
                    })
                }
                Err(error) => ControllerState::NoVault(NoVaultState {
                    status_message: Some(format!("remembered vault is unavailable: {error}")),
                }),
            },
            None => ControllerState::NoVault(NoVaultState::default()),
        };

        Ok(Self {
            clock,
            remembered_path,
            trust_anchor,
            device_binding_store,
            repository,
            backup_repository,
            state,
        })
    }

    /// Returns the current high-level app state.
    #[must_use]
    pub fn state(&self) -> AppState {
        match self.state {
            ControllerState::NoVault(_) => AppState::NoVault,
            ControllerState::Locked(_) => AppState::Locked,
            ControllerState::Unlocked(_) => AppState::Unlocked,
        }
    }

    /// Returns a read-only render snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] if TOTP generation fails unexpectedly.
    pub fn snapshot(&self) -> Result<AppSnapshot, AppError> {
        match &self.state {
            ControllerState::NoVault(state) => Ok(AppSnapshot::NoVault(NoVaultView {
                suggested_vault_path: self.remembered_path.suggested_vault_path().to_path_buf(),
                status_message: state.status_message.clone(),
            })),
            ControllerState::Locked(state) => Ok(AppSnapshot::Locked(LockedView {
                vault_path: state.vault_path.clone(),
                known_entry_count: state.known_entry_count,
                status_message: state.status_message.clone(),
            })),
            ControllerState::Unlocked(session) => {
                let filtered_indices = session.filtered_entry_indices();
                let entries = filtered_indices
                    .iter()
                    .filter_map(|index| session.entries.get(*index))
                    .map(|entry| EntryListItem {
                        issuer: entry.parameters().issuer().as_str().to_owned(),
                        account_label: entry.parameters().account_label().as_str().to_owned(),
                    })
                    .collect();
                let selected_index = session.selected_index.and_then(|selected_index| {
                    filtered_indices
                        .iter()
                        .position(|index| *index == selected_index)
                });

                let selected_detail = selected_index
                    .and_then(|index| filtered_indices.get(index).copied())
                    .and_then(|index| session.entries.get(index))
                    .map(|entry| -> Result<EntryDetail, AppError> {
                        let code = TotpGenerator::generate(
                            entry.parameters(),
                            self.clock.now_unix_timestamp(),
                        )?;

                        Ok(EntryDetail {
                            issuer: entry.parameters().issuer().as_str().to_owned(),
                            account_label: entry.parameters().account_label().as_str().to_owned(),
                            code: code.code().to_owned(),
                            valid_for_secs: code.valid_for_secs(),
                            algorithm: entry.parameters().algorithm(),
                            digits: entry.parameters().digits().get(),
                            period_secs: entry.parameters().period().get(),
                        })
                    })
                    .transpose()?;

                Ok(AppSnapshot::Unlocked(UnlockedView {
                    vault_path: session.vault_path.clone(),
                    dirty: session.dirty,
                    filter_query: session.active_entry_filter().map(str::to_owned),
                    visible_entry_count: filtered_indices.len(),
                    total_entry_count: session.entries.len(),
                    entries,
                    selected_index,
                    selected_detail,
                    status_message: session.status_message.clone(),
                }))
            }
        }
    }

    /// Creates a new empty vault and transitions to `Locked`.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `NoVault`, the input is
    /// invalid, or persistence fails.
    pub fn create_vault(
        &mut self,
        path: PathBuf,
        passphrase: String,
        confirmation: String,
    ) -> Result<(), AppError> {
        let mut passphrase = passphrase;
        let mut confirmation = confirmation;
        let result = self.create_vault_with_refs(path, passphrase.as_str(), confirmation.as_str());
        passphrase.zeroize();
        confirmation.zeroize();
        result
    }

    pub(crate) fn create_vault_with_refs(
        &mut self,
        path: PathBuf,
        passphrase: &str,
        confirmation: &str,
    ) -> Result<(), AppError> {
        if !matches!(self.state, ControllerState::NoVault(_)) {
            return self.fail(AppError::InvalidOperation("create_vault"));
        }

        if path.to_string_lossy().trim().is_empty() {
            return self.fail(AppError::EmptyVaultPath);
        }

        if passphrase != confirmation {
            return self.fail(AppError::PassphraseMismatch);
        }
        if let Err(error) = validate_new_passphrase(passphrase) {
            return self.fail(error);
        }

        let timestamp = self.format_now()?;
        let vault = Vault::new(
            VaultId::new(Uuid::new_v4().to_string())?,
            1,
            1,
            timestamp.clone(),
            timestamp,
            Vec::new(),
        )?;
        let local_binding = self.device_binding_store.requested_binding()?;
        let prepared_passphrase = self.device_binding_store.prepare_for_new_vault(
            vault.vault_id().as_str(),
            passphrase,
            local_binding.as_ref(),
        )?;

        let create_result = self
            .repository
            .clone()
            .with_vault_binding(local_binding.clone())
            .create_new(&path, prepared_passphrase.as_str(), &vault);

        if let Err(error) = create_result {
            if prepared_passphrase.created_secret() {
                let _ = self.device_binding_store.clear(vault.vault_id().as_str());
            }
            return self.fail(error.into());
        }

        let mut status_message = None;
        if local_binding.is_some() {
            append_status_message(
                &mut status_message,
                "vault created with local device-bound key protection".to_owned(),
            );
        }
        if let Err(error) = self
            .trust_anchor
            .record_exact(vault.vault_id().as_str(), vault.revision())
        {
            append_status_message(
                &mut status_message,
                format!(
                    "vault created, but the local rollback anchor could not be updated: {error}"
                ),
            );
        }
        if let Err(error) = self.remembered_path.store(&path) {
            append_status_message(
                &mut status_message,
                format!(
                    "vault created, but the local remembered path could not be stored: {error}"
                ),
            );
        }

        self.state = ControllerState::Locked(LockedState {
            vault_path: path,
            known_entry_count: Some(0),
            status_message,
        });
        Ok(())
    }

    /// Unlocks the current vault and transitions to `Unlocked`.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `Locked` or storage rejects the
    /// passphrase or vault.
    pub fn unlock(&mut self, mut passphrase: String) -> Result<(), AppError> {
        let result = self.unlock_with_ref(passphrase.as_str());
        passphrase.zeroize();
        result
    }

    pub(crate) fn unlock_with_ref(&mut self, passphrase: &str) -> Result<(), AppError> {
        let vault_path = match &self.state {
            ControllerState::Locked(locked) => locked.vault_path.clone(),
            ControllerState::NoVault(_) | ControllerState::Unlocked(_) => {
                return self.fail(AppError::InvalidOperation("unlock"));
            }
        };

        if let Err(error) = validate_existing_passphrase(passphrase) {
            return self.fail(error);
        }
        let header = match self.repository.load_header(&vault_path) {
            Ok(header) => header,
            Err(error) => {
                return self.fail(error.into());
            }
        };
        if let Err(error) = self
            .trust_anchor
            .ensure_not_rolled_back(header.metadata.vault_id.as_str(), header.metadata.revision)
        {
            return self.fail(error);
        }
        let prepared_passphrase = self.device_binding_store.prepare_for_existing_vault(
            header.metadata.vault_id.as_str(),
            passphrase,
            header.local_binding.as_ref(),
        );
        let prepared_passphrase = match prepared_passphrase {
            Ok(prepared_passphrase) => prepared_passphrase,
            Err(error) => {
                return self.fail(error);
            }
        };
        let unlock_result = self
            .repository
            .unlock(&vault_path, prepared_passphrase.as_str());

        match unlock_result {
            Ok(vault) => {
                self.state = ControllerState::Unlocked(UnlockedSession::from_vault(
                    vault_path,
                    &vault,
                    header.local_binding.clone(),
                ));
                if let Err(error) = self
                    .trust_anchor
                    .record_max(vault.vault_id().as_str(), vault.revision())
                {
                    self.set_status(Some(format!(
                        "vault unlocked, but the local rollback anchor could not be updated: {error}"
                    )));
                }
                Ok(())
            }
            Err(error) => self.fail(error.into()),
        }
    }

    /// Adds a new manual TOTP entry to the in-memory unlocked vault.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `Unlocked` or the user input is
    /// invalid.
    pub fn add_entry(&mut self, mut input: AddEntryInput) -> Result<(), AppError> {
        let result = self.add_entry_with_refs(
            input.issuer.as_str(),
            input.account_label.as_str(),
            input.secret_base32.as_str(),
            input.algorithm.as_deref(),
            input.digits.as_deref(),
            input.period.as_deref(),
        );
        input.zeroize_secret_fields();
        result
    }

    pub(crate) fn add_entry_with_refs(
        &mut self,
        issuer: &str,
        account_label: &str,
        secret_base32: &str,
        algorithm: Option<&str>,
        digits: Option<&str>,
        period: Option<&str>,
    ) -> Result<(), AppError> {
        if !matches!(self.state, ControllerState::Unlocked(_)) {
            return self.fail(AppError::InvalidOperation("add_entry"));
        }

        let parameters = build_parameters_with_refs(
            issuer,
            account_label,
            secret_base32,
            algorithm,
            digits,
            period,
        )?;
        let updated_at = self.format_now()?;

        let ControllerState::Unlocked(session) = &mut self.state else {
            return self.fail(AppError::InvalidOperation("add_entry"));
        };

        let entry = OtpEntry::new(EntryId::new(Uuid::new_v4().to_string())?, parameters);
        session.entries.push(entry);
        session.selected_index = Some(session.entries.len() - 1);
        session.ensure_selection_visible();
        session.updated_at = updated_at;
        session.dirty = true;
        session.status_message = None;
        Ok(())
    }

    /// Imports a TOTP entry from a pasted `otpauth://totp` URI.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `Unlocked` or the URI is
    /// malformed.
    pub fn import_entry_uri(&mut self, mut input: ImportUriInput) -> Result<(), AppError> {
        let result = self.import_entry_uri_with_ref(input.uri.as_str());
        input.zeroize_secret_fields();
        result
    }

    pub(crate) fn import_entry_uri_with_ref(&mut self, uri: &str) -> Result<(), AppError> {
        if !matches!(self.state, ControllerState::Unlocked(_)) {
            return self.fail(AppError::InvalidOperation("import_entry_uri"));
        }

        let parameters = {
            let trimmed = uri.trim();
            if trimmed.is_empty() {
                return self.fail(AppError::EmptyImportUri);
            }

            parse_totp_uri(trimmed)
        };
        let parameters = match parameters {
            Ok(parameters) => parameters,
            Err(error) => return self.fail(error.into()),
        };
        let updated_at = self.format_now()?;

        let ControllerState::Unlocked(session) = &mut self.state else {
            return self.fail(AppError::InvalidOperation("import_entry_uri"));
        };

        let entry = OtpEntry::new(EntryId::new(Uuid::new_v4().to_string())?, parameters);
        session.entries.push(entry);
        session.selected_index = Some(session.entries.len() - 1);
        session.ensure_selection_visible();
        session.updated_at = updated_at;
        session.dirty = true;
        session.status_message = Some("imported entry from otpauth URI".to_owned());
        Ok(())
    }

    /// Returns the currently selected entry as an edit draft.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `Unlocked` or no entry is
    /// selected.
    pub(crate) fn selected_entry_edit_input(&self) -> Result<EditEntryInput, AppError> {
        let ControllerState::Unlocked(session) = &self.state else {
            return Err(AppError::InvalidOperation("selected_entry_edit_input"));
        };

        let Some(index) = session.selected_index else {
            return Err(AppError::NoEntrySelected);
        };
        let Some(entry) = session.entries.get(index) else {
            return Err(AppError::NoEntrySelected);
        };

        Ok(EditEntryInput {
            issuer: entry.parameters().issuer().as_str().to_owned(),
            account_label: entry.parameters().account_label().as_str().to_owned(),
            secret_base32: String::new(),
            algorithm: Some(entry.parameters().algorithm().as_otpauth_str().to_owned()),
            digits: Some(entry.parameters().digits().get().to_string()),
            period: Some(entry.parameters().period().get().to_string()),
        })
    }

    /// Replaces the currently selected entry in the unlocked in-memory vault.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `Unlocked`, no entry is
    /// selected, or the updated parameters are invalid.
    pub fn edit_selected_entry(&mut self, mut input: EditEntryInput) -> Result<(), AppError> {
        let result = self.edit_selected_entry_with_refs(
            input.issuer.as_str(),
            input.account_label.as_str(),
            input.secret_base32.as_str(),
            input.algorithm.as_deref(),
            input.digits.as_deref(),
            input.period.as_deref(),
        );
        input.zeroize_secret_fields();
        result
    }

    pub(crate) fn edit_selected_entry_with_refs(
        &mut self,
        issuer: &str,
        account_label: &str,
        secret_base32: &str,
        algorithm: Option<&str>,
        digits: Option<&str>,
        period: Option<&str>,
    ) -> Result<(), AppError> {
        if !matches!(self.state, ControllerState::Unlocked(_)) {
            return self.fail(AppError::InvalidOperation("edit_selected_entry"));
        }

        let parameters = match &self.state {
            ControllerState::Unlocked(session) => {
                let Some(index) = session.selected_index else {
                    return self.fail(AppError::NoEntrySelected);
                };
                let Some(existing) = session.entries.get(index) else {
                    return self.fail(AppError::NoEntrySelected);
                };

                build_edit_parameters_with_refs(
                    existing,
                    issuer,
                    account_label,
                    secret_base32,
                    algorithm,
                    digits,
                    period,
                )?
            }
            ControllerState::NoVault(_) | ControllerState::Locked(_) => {
                return self.fail(AppError::InvalidOperation("edit_selected_entry"));
            }
        };
        let updated_at = self.format_now()?;

        let ControllerState::Unlocked(session) = &mut self.state else {
            return self.fail(AppError::InvalidOperation("edit_selected_entry"));
        };

        let Some(index) = session.selected_index else {
            return self.fail(AppError::NoEntrySelected);
        };
        let Some(existing) = session.entries.get(index) else {
            return self.fail(AppError::NoEntrySelected);
        };
        let entry_id = existing.entry_id().clone();
        session.entries[index] = OtpEntry::new(entry_id, parameters);
        session.ensure_selection_visible();
        session.updated_at = updated_at;
        session.dirty = true;
        session.status_message = Some("updated selected entry".to_owned());
        Ok(())
    }

    /// Deletes the currently selected entry from the unlocked in-memory vault.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `Unlocked`, no entry is
    /// selected, or the confirmation text is not `DELETE`.
    pub fn delete_selected_entry(&mut self, input: DeleteEntryInput) -> Result<(), AppError> {
        if !matches!(self.state, ControllerState::Unlocked(_)) {
            return self.fail(AppError::InvalidOperation("delete_selected_entry"));
        }

        let updated_at = self.format_now()?;
        let confirmation = input.confirmation;
        let normalized_confirmation = confirmation.trim();
        let selected_index = match &self.state {
            ControllerState::Unlocked(session) => session.selected_index,
            ControllerState::NoVault(_) | ControllerState::Locked(_) => {
                return self.fail(AppError::InvalidOperation("delete_selected_entry"));
            }
        };

        let Some(index) = selected_index else {
            return self.fail(AppError::NoEntrySelected);
        };

        if normalized_confirmation != "DELETE" {
            return self.fail(AppError::DeleteConfirmationRequired);
        }

        let ControllerState::Unlocked(session) = &mut self.state else {
            return self.fail(AppError::InvalidOperation("delete_selected_entry"));
        };

        let removed = session.entries.remove(index);
        session.selected_index = if session.entries.is_empty() {
            None
        } else if index >= session.entries.len() {
            Some(session.entries.len() - 1)
        } else {
            Some(index)
        };
        session.ensure_selection_visible();
        session.updated_at = updated_at;
        session.dirty = true;
        session.status_message = Some(format!(
            "deleted entry {} | {}",
            removed.parameters().issuer().as_str(),
            removed.parameters().account_label().as_str()
        ));
        Ok(())
    }

    /// Exports the current unlocked vault snapshot into an encrypted backup
    /// file.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `Unlocked`, the input is
    /// invalid, or backup export fails.
    pub fn export_backup(&mut self, mut input: BackupExportInput) -> Result<(), AppError> {
        let result = self.export_backup_with_refs(
            input.backup_path.as_path(),
            input.backup_passphrase.as_str(),
            input.confirmation.as_str(),
        );
        input.zeroize_secret_fields();
        result
    }

    pub(crate) fn export_backup_with_refs(
        &mut self,
        backup_path: &Path,
        backup_passphrase: &str,
        confirmation: &str,
    ) -> Result<(), AppError> {
        if !matches!(self.state, ControllerState::Unlocked(_)) {
            return self.fail(AppError::InvalidOperation("export_backup"));
        }

        if backup_path.to_string_lossy().trim().is_empty() {
            return self.fail(AppError::EmptyBackupPath);
        }

        let export_vault = {
            let ControllerState::Unlocked(session) = &self.state else {
                return self.fail(AppError::InvalidOperation("export_backup"));
            };
            if paths_conflict(session.vault_path.as_path(), backup_path) {
                return self.fail(AppError::BackupPathMatchesVaultPath);
            }
            session.build_export_vault()?
        };

        if backup_passphrase != confirmation {
            return self.fail(AppError::PassphraseMismatch);
        }
        if let Err(error) = validate_new_passphrase(backup_passphrase) {
            return self.fail(error);
        }

        let export_result =
            self.backup_repository
                .export(backup_path, backup_passphrase, &export_vault);

        match export_result {
            Ok(()) => {
                self.set_status(Some(format!(
                    "backup exported to {}",
                    backup_path.display()
                )));
                Ok(())
            }
            Err(error) => self.fail(error.into()),
        }
    }

    /// Restores an encrypted backup into a vault file and transitions to
    /// `Locked`.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called from `Unlocked`, the input is invalid,
    /// or restore fails.
    pub fn restore_backup(&mut self, mut input: BackupRestoreInput) -> Result<(), AppError> {
        let result = self.restore_backup_with_refs(
            input.backup_path.as_path(),
            input.backup_passphrase.as_str(),
            input.target_vault_path.as_path(),
            input.target_vault_passphrase.as_str(),
            input.confirmation.as_str(),
            input.replace_existing,
        );
        input.zeroize_secret_fields();
        result
    }

    pub(crate) fn restore_backup_with_refs(
        &mut self,
        backup_path: &Path,
        backup_passphrase: &str,
        target_vault_path: &Path,
        target_vault_passphrase: &str,
        confirmation: &str,
        replace_existing: bool,
    ) -> Result<(), AppError> {
        if matches!(self.state, ControllerState::Unlocked(_)) {
            return self.fail(AppError::InvalidOperation("restore_backup"));
        }

        if backup_path.to_string_lossy().trim().is_empty() {
            return self.fail(AppError::EmptyBackupPath);
        }

        if target_vault_path.to_string_lossy().trim().is_empty() {
            return self.fail(AppError::EmptyVaultPath);
        }

        if target_vault_passphrase != confirmation {
            return self.fail(AppError::PassphraseMismatch);
        }
        if let Err(error) = validate_existing_passphrase(backup_passphrase) {
            return self.fail(error);
        }
        if let Err(error) = validate_new_passphrase(target_vault_passphrase) {
            return self.fail(error);
        }
        let backup_header = match self.backup_repository.load_header(backup_path) {
            Ok(header) => header,
            Err(error) => return self.fail(error.into()),
        };
        let target_local_binding = self.device_binding_store.requested_binding()?;
        let prepared_passphrase = self.device_binding_store.prepare_for_new_vault(
            backup_header.vault_id.as_str(),
            target_vault_passphrase,
            target_local_binding.as_ref(),
        )?;

        let target_exists = target_vault_path.exists();
        let mode = if target_exists {
            if !replace_existing {
                return self.fail(AppError::ReplaceConfirmationRequired);
            }
            RestoreMode::ReplaceExisting
        } else {
            RestoreMode::CreateNew
        };

        let request = RestoreRequest {
            backup_path,
            backup_passphrase,
            target_vault_path,
            target_vault_passphrase: prepared_passphrase.as_str(),
            target_local_binding: target_local_binding.clone(),
            mode,
        };
        let restore_result = self.backup_repository.restore(&request);

        let restored_vault = match restore_result {
            Ok(vault) => vault,
            Err(error) => {
                if prepared_passphrase.created_secret() {
                    let _ = self
                        .device_binding_store
                        .clear(backup_header.vault_id.as_str());
                }
                return self.fail(error.into());
            }
        };

        let known_entry_count = restored_vault.entries().len();
        let mut status_message = None;
        if target_local_binding.is_some() {
            append_status_message(
                &mut status_message,
                "backup restored with local device-bound key protection".to_owned(),
            );
        }
        if let Err(error) = self.trust_anchor.record_exact(
            restored_vault.vault_id().as_str(),
            restored_vault.revision(),
        ) {
            append_status_message(
                &mut status_message,
                format!(
                    "backup restored, but the local rollback anchor could not be updated: {error}"
                ),
            );
        }
        if let Err(error) = self.remembered_path.store(target_vault_path) {
            append_status_message(
                &mut status_message,
                format!(
                    "backup restored, but the local remembered path could not be stored: {error}"
                ),
            );
        }

        self.state = ControllerState::Locked(LockedState {
            vault_path: target_vault_path.to_path_buf(),
            known_entry_count: Some(known_entry_count),
            status_message,
        });
        Ok(())
    }

    /// Re-encrypts the current unlocked vault with a new master passphrase and
    /// transitions back to `Locked`.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `Unlocked`, the new passphrase
    /// confirmation does not match, the current passphrase is wrong, or
    /// persistence fails.
    pub fn change_passphrase(&mut self, mut input: ChangePassphraseInput) -> Result<(), AppError> {
        let result = self.change_passphrase_with_refs(
            input.current_passphrase.as_str(),
            input.new_passphrase.as_str(),
            input.confirmation.as_str(),
        );
        input.zeroize_secret_fields();
        result
    }

    pub(crate) fn change_passphrase_with_refs(
        &mut self,
        current_passphrase: &str,
        new_passphrase: &str,
        confirmation: &str,
    ) -> Result<(), AppError> {
        if !matches!(self.state, ControllerState::Unlocked(_)) {
            return self.fail(AppError::InvalidOperation("change_passphrase"));
        }

        if new_passphrase != confirmation {
            return self.fail(AppError::PassphraseMismatch);
        }
        if let Err(error) = validate_existing_passphrase(current_passphrase) {
            return self.fail(error);
        }
        if let Err(error) = validate_new_passphrase(new_passphrase) {
            return self.fail(error);
        }

        let persist_plan = match &self.state {
            ControllerState::Unlocked(session) if session.dirty => {
                let updated_at = self.format_now()?;
                session.build_save_plan(updated_at)?
            }
            ControllerState::Unlocked(session) => SavePlan {
                vault_path: session.vault_path.clone(),
                entry_count: session.entries.len(),
                vault: session.build_export_vault()?,
            },
            ControllerState::NoVault(_) | ControllerState::Locked(_) => {
                return self.fail(AppError::InvalidOperation("change_passphrase"));
            }
        };
        let local_binding = match &self.state {
            ControllerState::Unlocked(session) => session.local_binding.clone(),
            ControllerState::NoVault(_) | ControllerState::Locked(_) => {
                return self.fail(AppError::InvalidOperation("change_passphrase"));
            }
        };
        let current_passphrase = self.device_binding_store.prepare_for_existing_vault(
            persist_plan.vault.vault_id().as_str(),
            current_passphrase,
            local_binding.as_ref(),
        )?;
        let new_passphrase = self.device_binding_store.prepare_for_existing_vault(
            persist_plan.vault.vault_id().as_str(),
            new_passphrase,
            local_binding.as_ref(),
        )?;

        let verification_result = self
            .repository
            .unlock(&persist_plan.vault_path, current_passphrase.as_str());
        if let Err(error) = verification_result {
            return self.fail(error.into());
        }

        let save_result = self
            .repository
            .clone()
            .with_vault_binding(local_binding.clone())
            .save(
                &persist_plan.vault_path,
                new_passphrase.as_str(),
                &persist_plan.vault,
            );

        match save_result {
            Ok(()) => {
                let mut status_message = Some("master passphrase changed; vault locked".to_owned());
                if local_binding.is_some() {
                    append_status_message(
                        &mut status_message,
                        "local device-bound key protection preserved".to_owned(),
                    );
                }
                if let Err(error) = self.trust_anchor.record_max(
                    persist_plan.vault.vault_id().as_str(),
                    persist_plan.vault.revision(),
                ) {
                    append_status_message(
                        &mut status_message,
                        format!("local rollback anchor could not be updated: {error}"),
                    );
                }
                self.state = ControllerState::Locked(LockedState {
                    vault_path: persist_plan.vault_path,
                    known_entry_count: Some(persist_plan.entry_count),
                    status_message,
                });
                Ok(())
            }
            Err(error) => self.fail(error.into()),
        }
    }

    /// Moves the unlocked entry selection forward by one item.
    pub fn select_next(&mut self) {
        let ControllerState::Unlocked(session) = &mut self.state else {
            return;
        };

        let filtered_indices = session.filtered_entry_indices();
        if filtered_indices.is_empty() {
            session.selected_index = None;
            return;
        }

        let current_position = session.selected_index.and_then(|selected_index| {
            filtered_indices
                .iter()
                .position(|index| *index == selected_index)
        });
        let next_position = match current_position {
            Some(index) if index + 1 < filtered_indices.len() => index + 1,
            _ => 0,
        };
        session.selected_index = filtered_indices.get(next_position).copied();
    }

    /// Moves the unlocked entry selection backward by one item.
    pub fn select_previous(&mut self) {
        let ControllerState::Unlocked(session) = &mut self.state else {
            return;
        };

        let filtered_indices = session.filtered_entry_indices();
        if filtered_indices.is_empty() {
            session.selected_index = None;
            return;
        }

        let current_position = session.selected_index.and_then(|selected_index| {
            filtered_indices
                .iter()
                .position(|index| *index == selected_index)
        });
        let previous_position = match current_position {
            Some(index) if index > 0 => index - 1,
            _ => filtered_indices.len() - 1,
        };
        session.selected_index = filtered_indices.get(previous_position).copied();
    }

    /// Applies or clears the unlocked entry filter.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `Unlocked`.
    pub fn set_entry_filter(&mut self, filter: &str) -> Result<(), AppError> {
        let ControllerState::Unlocked(session) = &mut self.state else {
            return self.fail(AppError::InvalidOperation("set_entry_filter"));
        };

        filter.trim().clone_into(&mut session.entry_filter);
        session.ensure_selection_visible();
        session.status_message = Some(match session.active_entry_filter() {
            Some(filter) => format!(
                "filtered entries by \"{filter}\" ({}/{})",
                session.filtered_entry_indices().len(),
                session.entries.len()
            ),
            None => "entry filter cleared".to_owned(),
        });
        Ok(())
    }

    /// Saves the unlocked vault if dirty and always transitions back to
    /// `Locked`.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `Unlocked`, when a dirty save
    /// is attempted without a passphrase, or when storage rejects the save.
    pub fn save_and_lock(&mut self, passphrase: Option<String>) -> Result<(), AppError> {
        let mut passphrase = passphrase;
        let result = self.save_and_lock_with_ref(passphrase.as_deref());
        if let Some(passphrase) = &mut passphrase {
            passphrase.zeroize();
        }
        result
    }

    pub(crate) fn save_and_lock_with_ref(
        &mut self,
        passphrase: Option<&str>,
    ) -> Result<(), AppError> {
        let save_plan = match &self.state {
            ControllerState::Unlocked(session) if !session.dirty => {
                return self.lock_without_saving();
            }
            ControllerState::Unlocked(session) => {
                let Some(passphrase) = passphrase else {
                    return self.fail(AppError::PassphraseRequired);
                };
                let updated_at = self.format_now()?;
                (passphrase, session.build_save_plan(updated_at)?)
            }
            ControllerState::NoVault(_) | ControllerState::Locked(_) => {
                return self.fail(AppError::InvalidOperation("save_and_lock"));
            }
        };

        let (passphrase, save_plan) = save_plan;
        if let Err(error) = validate_existing_passphrase(passphrase) {
            return self.fail(error);
        }
        let local_binding = match &self.state {
            ControllerState::Unlocked(session) => session.local_binding.clone(),
            ControllerState::NoVault(_) | ControllerState::Locked(_) => {
                return self.fail(AppError::InvalidOperation("save_and_lock"));
            }
        };
        let prepared_passphrase = match self.device_binding_store.prepare_for_existing_vault(
            save_plan.vault.vault_id().as_str(),
            passphrase,
            local_binding.as_ref(),
        ) {
            Ok(prepared_passphrase) => prepared_passphrase,
            Err(error) => {
                return self.fail(error);
            }
        };
        let verification_result = self
            .repository
            .unlock(&save_plan.vault_path, prepared_passphrase.as_str());
        if let Err(error) = verification_result {
            return self.fail(error.into());
        }

        let save_result = self
            .repository
            .clone()
            .with_vault_binding(local_binding)
            .save(
                &save_plan.vault_path,
                prepared_passphrase.as_str(),
                &save_plan.vault,
            );

        match save_result {
            Ok(()) => {
                let mut status_message = None;
                if let Err(error) = self.trust_anchor.record_max(
                    save_plan.vault.vault_id().as_str(),
                    save_plan.vault.revision(),
                ) {
                    append_status_message(
                        &mut status_message,
                        format!("local rollback anchor could not be updated: {error}"),
                    );
                }
                self.state = ControllerState::Locked(LockedState {
                    vault_path: save_plan.vault_path,
                    known_entry_count: Some(save_plan.entry_count),
                    status_message,
                });
                Ok(())
            }
            Err(error) => self.fail(error.into()),
        }
    }

    /// Discards the unlocked plaintext state and transitions back to `Locked`.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when called outside `Unlocked`.
    pub fn lock_without_saving(&mut self) -> Result<(), AppError> {
        self.lock_with_status(None)
    }

    pub(crate) fn auto_lock_due_to_idle(&mut self, idle_secs: u64) -> Result<(), AppError> {
        self.lock_with_status(Some(format!(
            "vault auto-locked after {idle_secs} seconds of inactivity"
        )))
    }

    fn format_now(&self) -> Result<String, AppError> {
        Ok(self.clock.now_utc().format(&Rfc3339)?)
    }

    fn fail<T>(&mut self, error: AppError) -> Result<T, AppError> {
        self.set_status(Some(error.to_string()));
        Err(error)
    }

    pub(crate) fn set_error_status(&mut self, error: &AppError) {
        self.set_status(Some(error.to_string()));
    }

    pub(crate) fn append_status(&mut self, addition: String) {
        if addition.trim().is_empty() {
            return;
        }

        let mut status_message = match &self.state {
            ControllerState::NoVault(state) => state.status_message.clone(),
            ControllerState::Locked(state) => state.status_message.clone(),
            ControllerState::Unlocked(state) => state.status_message.clone(),
        };
        append_status_message(&mut status_message, addition);
        self.set_status(status_message);
    }

    fn set_status(&mut self, status_message: Option<String>) {
        match &mut self.state {
            ControllerState::NoVault(state) => state.status_message = status_message,
            ControllerState::Locked(state) => state.status_message = status_message,
            ControllerState::Unlocked(state) => state.status_message = status_message,
        }
    }

    fn lock_with_status(&mut self, status_message: Option<String>) -> Result<(), AppError> {
        let (vault_path, known_entry_count) = match &self.state {
            ControllerState::Unlocked(session) => (
                session.vault_path.clone(),
                Some(session.persisted_entry_count),
            ),
            ControllerState::NoVault(_) | ControllerState::Locked(_) => {
                return self.fail(AppError::InvalidOperation("lock_without_saving"));
            }
        };

        self.state = ControllerState::Locked(LockedState {
            vault_path,
            known_entry_count,
            status_message,
        });
        Ok(())
    }
}

impl UnlockedSession {
    fn from_vault(
        vault_path: PathBuf,
        vault: &Vault,
        local_binding: Option<LocalBindingHeader>,
    ) -> Self {
        let entries = vault.entries().to_vec();
        let selected_index = if entries.is_empty() { None } else { Some(0) };

        Self {
            vault_path,
            vault_id: vault.vault_id().clone(),
            local_binding,
            schema_version: vault.schema_version(),
            persisted_revision: vault.revision(),
            created_at: vault.created_at().to_owned(),
            updated_at: vault.updated_at().to_owned(),
            persisted_entry_count: entries.len(),
            entries,
            entry_filter: String::new(),
            selected_index,
            dirty: false,
            status_message: None,
        }
    }

    fn build_save_plan(&self, updated_at: String) -> Result<SavePlan, AppError> {
        let revision = self.persisted_revision.saturating_add(1);
        let vault = Vault::new(
            self.vault_id.clone(),
            self.schema_version,
            revision,
            self.created_at.clone(),
            updated_at,
            self.entries.clone(),
        )?;

        Ok(SavePlan {
            vault_path: self.vault_path.clone(),
            entry_count: self.entries.len(),
            vault,
        })
    }

    fn build_export_vault(&self) -> Result<Vault, AppError> {
        let revision = if self.dirty {
            self.persisted_revision.saturating_add(1)
        } else {
            self.persisted_revision
        };

        Ok(Vault::new(
            self.vault_id.clone(),
            self.schema_version,
            revision,
            self.created_at.clone(),
            self.updated_at.clone(),
            self.entries.clone(),
        )?)
    }

    fn active_entry_filter(&self) -> Option<&str> {
        let filter = self.entry_filter.trim();
        if filter.is_empty() {
            None
        } else {
            Some(filter)
        }
    }

    fn filtered_entry_indices(&self) -> Vec<usize> {
        let Some(filter) = self.active_entry_filter() else {
            return (0..self.entries.len()).collect();
        };

        let needle = filter.to_lowercase();
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let issuer = entry.parameters().issuer().as_str().to_lowercase();
                let account_label = entry.parameters().account_label().as_str().to_lowercase();
                if issuer.contains(&needle) || account_label.contains(&needle) {
                    Some(index)
                } else {
                    None
                }
            })
            .collect()
    }

    fn ensure_selection_visible(&mut self) {
        let filtered_indices = self.filtered_entry_indices();
        if filtered_indices.is_empty() {
            self.selected_index = None;
            return;
        }

        if self
            .selected_index
            .is_some_and(|selected_index| filtered_indices.contains(&selected_index))
        {
            return;
        }

        self.selected_index = filtered_indices.first().copied();
    }
}

fn build_parameters_with_refs(
    issuer: &str,
    account_label: &str,
    secret_base32: &str,
    algorithm: Option<&str>,
    digits: Option<&str>,
    period: Option<&str>,
) -> Result<TotpParameters, AppError> {
    let issuer = Issuer::new(issuer.to_owned())?;
    let account_label = AccountLabel::new(account_label.to_owned())?;
    let secret = OtpSecret::from_base32(secret_base32)?;
    let algorithm = parse_algorithm(algorithm)?;
    let digits = Digits::try_from(parse_u32_field(digits, "digits", 6)?)?;
    let period = Period::new(parse_u32_field(period, "period", 30)?)?;

    Ok(TotpParameters::new(
        issuer,
        account_label,
        secret,
        digits,
        period,
        algorithm,
    ))
}

fn build_edit_parameters_with_refs(
    existing: &OtpEntry,
    issuer: &str,
    account_label: &str,
    secret_base32: &str,
    algorithm: Option<&str>,
    digits: Option<&str>,
    period: Option<&str>,
) -> Result<TotpParameters, AppError> {
    let issuer = Issuer::new(issuer.to_owned())?;
    let account_label = AccountLabel::new(account_label.to_owned())?;
    let secret = if secret_base32.trim().is_empty() {
        existing.parameters().secret().clone()
    } else {
        OtpSecret::from_base32(secret_base32)?
    };
    let algorithm = parse_algorithm(algorithm)?;
    let digits = Digits::try_from(parse_u32_field(digits, "digits", 6)?)?;
    let period = Period::new(parse_u32_field(period, "period", 30)?)?;

    Ok(TotpParameters::new(
        issuer,
        account_label,
        secret,
        digits,
        period,
        algorithm,
    ))
}

fn validate_existing_passphrase(passphrase: &str) -> Result<(), AppError> {
    match validate_existing_crypto_passphrase(passphrase) {
        Ok(()) => Ok(()),
        Err(CryptoError::EmptyPassphrase) => Err(AppError::EmptyPassphrase),
        Err(CryptoError::PassphraseTooShort(min)) => Err(AppError::PassphraseTooShort(min)),
        Err(error) => Err(AppError::Crypto(error)),
    }
}

fn validate_new_passphrase(passphrase: &str) -> Result<(), AppError> {
    match validate_new_crypto_passphrase(passphrase) {
        Ok(()) => Ok(()),
        Err(CryptoError::EmptyPassphrase) => Err(AppError::EmptyPassphrase),
        Err(CryptoError::PassphraseTooShort(min)) => Err(AppError::PassphraseTooShort(min)),
        Err(error) => Err(AppError::Crypto(error)),
    }
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
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }

    Ok(normalized)
}

fn parse_algorithm(value: Option<&str>) -> Result<HashAlgorithm, AppError> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => Ok(HashAlgorithm::from_str(value)?),
        None => Ok(HashAlgorithm::Sha1),
    }
}

fn parse_u32_field(
    value: Option<&str>,
    field_name: &'static str,
    default: u32,
) -> Result<u32, AppError> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => value
            .parse::<u32>()
            .map_err(|_| AppError::InvalidNumber(field_name)),
        None => Ok(default),
    }
}

fn append_status_message(status_message: &mut Option<String>, addition: String) {
    match status_message {
        Some(existing) => {
            existing.push(' ');
            existing.push_str(&addition);
        }
        None => *status_message = Some(addition),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use albus::{
        BackupRepository, FileBackupRepository, FileVaultRepository, HashAlgorithm, Vault, VaultId,
        VaultRepository,
    };
    use tempfile::TempDir;
    use time::OffsetDateTime;

    use super::{
        AddEntryInput, AppController, AppSnapshot, AppState, BackupExportInput, BackupRestoreInput,
        ChangePassphraseInput, DeleteEntryInput, EditEntryInput, ImportUriInput,
    };
    #[cfg(windows)]
    use crate::device_binding::{DeviceBindingPreference, DeviceBindingStore};
    use crate::{AppError, Clock, RememberedVaultPath};

    #[derive(Clone, Copy, Debug)]
    struct FixedClock {
        now: OffsetDateTime,
    }

    impl Clock for FixedClock {
        fn now_utc(&self) -> OffsetDateTime {
            self.now
        }
    }

    fn remembered_path(tempdir: &TempDir) -> RememberedVaultPath {
        RememberedVaultPath::new(
            tempdir
                .path()
                .join("config")
                .join("remembered-vault-path.txt"),
            tempdir.path().join("vault.albus"),
        )
    }

    fn fixed_clock() -> Result<FixedClock, Box<dyn std::error::Error>> {
        Ok(FixedClock {
            now: OffsetDateTime::from_unix_timestamp(1_717_171_717)?,
        })
    }

    #[test]
    fn state_machine_flows_between_the_three_supported_states()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("state-machine.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        assert_eq!(controller.state(), AppState::NoVault);

        controller.create_vault(
            vault_path,
            "correct horse battery staple".to_owned(),
            "correct horse battery staple".to_owned(),
        )?;
        assert_eq!(controller.state(), AppState::Locked);

        controller.unlock("correct horse battery staple".to_owned())?;
        assert_eq!(controller.state(), AppState::Unlocked);

        controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        controller.save_and_lock(Some("correct horse battery staple".to_owned()))?;
        assert_eq!(controller.state(), AppState::Locked);

        controller.unlock("correct horse battery staple".to_owned())?;
        assert_eq!(controller.state(), AppState::Unlocked);
        controller.lock_without_saving()?;
        assert_eq!(controller.state(), AppState::Locked);

        let snapshot = controller.snapshot()?;
        assert!(matches!(snapshot, AppSnapshot::Locked(_)));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn create_and_unlock_with_windows_device_binding_requires_the_local_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("device-bound.albus");
        let binding_store = DeviceBindingStore::new(
            tempdir.path().join("config").join("device-bindings-v1"),
            DeviceBindingPreference::WindowsDpapiCurrentUser,
        );
        let mut controller = AppController::initialize_with_device_binding(
            fixed_clock()?,
            remembered.clone(),
            binding_store,
        )?;

        controller.create_vault(
            vault_path.clone(),
            "correct horse battery staple".to_owned(),
            "correct horse battery staple".to_owned(),
        )?;

        let header = FileVaultRepository::default().load_header(&vault_path)?;
        assert_eq!(
            header
                .local_binding
                .as_ref()
                .map(|binding| binding.provider.as_str()),
            Some("windows-dpapi")
        );
        assert!(
            FileVaultRepository::default()
                .unlock(&vault_path, "correct horse battery staple")
                .is_err()
        );

        controller.unlock("correct horse battery staple".to_owned())?;
        assert_eq!(controller.state(), AppState::Unlocked);
        assert!(
            remembered
                .config_file()
                .parent()
                .unwrap_or(tempdir.path())
                .join("device-bindings-v1")
                .exists()
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn missing_windows_device_binding_secret_refuses_unlock_until_restored()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("device-bound-missing-key.albus");
        let binding_dir = tempdir.path().join("config").join("device-bindings-v1");
        let binding_store = DeviceBindingStore::new(
            binding_dir.clone(),
            DeviceBindingPreference::WindowsDpapiCurrentUser,
        );
        let mut controller = AppController::initialize_with_device_binding(
            fixed_clock()?,
            remembered,
            binding_store,
        )?;

        controller.create_vault(
            vault_path.clone(),
            "correct horse battery staple".to_owned(),
            "correct horse battery staple".to_owned(),
        )?;

        let header = FileVaultRepository::default().load_header(&vault_path)?;
        let state_path = std::fs::read_dir(binding_dir)?
            .next()
            .ok_or("expected a device-binding state file")??
            .path();
        let state_bytes = std::fs::read(&state_path)?;
        std::fs::remove_file(&state_path)?;

        let result = controller.unlock("correct horse battery staple".to_owned());
        assert!(matches!(
            result,
            Err(AppError::MissingDeviceBindingKey { ref vault_id })
                if vault_id == header.metadata.vault_id.as_str()
        ));
        assert_eq!(controller.state(), AppState::Locked);

        std::fs::write(&state_path, state_bytes)?;
        controller.unlock("correct horse battery staple".to_owned())?;
        assert_eq!(controller.state(), AppState::Unlocked);
        Ok(())
    }

    #[test]
    fn export_from_unlocked_succeeds_without_clearing_dirty_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("export-source.albus");
        let backup_path = tempdir.path().join("exports").join("vault.albusbak");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        controller.export_backup(BackupExportInput {
            backup_path: backup_path.clone(),
            backup_passphrase: "backup-passphrase".to_owned(),
            confirmation: "backup-passphrase".to_owned(),
        })?;

        assert!(backup_path.exists());
        let backup_repository = FileBackupRepository::default();
        let header = backup_repository.load_header(&backup_path)?;
        let snapshot = backup_repository.decrypt_snapshot(&backup_path, "backup-passphrase")?;
        assert_eq!(header.revision, 2);
        assert_eq!(snapshot.vault.revision(), 2);
        assert_eq!(snapshot.vault.entries().len(), 1);
        match controller.snapshot()? {
            AppSnapshot::Unlocked(view) => assert!(view.dirty),
            AppSnapshot::NoVault(_) | AppSnapshot::Locked(_) => {
                return Err("controller left the unlocked state unexpectedly".into());
            }
        }

        Ok(())
    }

    #[test]
    fn import_uri_from_unlocked_adds_entry_and_marks_dirty()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("import-uri.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;

        controller.import_entry_uri(ImportUriInput {
            uri: "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
                .to_owned(),
        })?;

        match controller.snapshot()? {
            AppSnapshot::Unlocked(view) => {
                assert!(view.dirty);
                assert_eq!(view.entries.len(), 1);
                assert_eq!(view.entries[0].issuer, "Example");
                assert_eq!(view.entries[0].account_label, "alice@example.com");
            }
            AppSnapshot::NoVault(_) | AppSnapshot::Locked(_) => {
                return Err("controller left the unlocked state unexpectedly".into());
            }
        }
        Ok(())
    }

    #[test]
    fn edit_selected_entry_updates_the_current_entry() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("edit-entry.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        let original = controller.selected_entry_edit_input()?;
        assert_eq!(original.issuer, "Example");

        controller.edit_selected_entry(EditEntryInput {
            issuer: "Updated".to_owned(),
            account_label: "bob@example.com".to_owned(),
            secret_base32: "KRUGS4ZANFZSAYJA".to_owned(),
            algorithm: Some("SHA256".to_owned()),
            digits: Some("8".to_owned()),
            period: Some("45".to_owned()),
        })?;

        let edited = controller.selected_entry_edit_input()?;
        assert_eq!(edited.issuer, "Updated");
        assert_eq!(edited.account_label, "bob@example.com");
        assert_eq!(edited.algorithm.as_deref(), Some("SHA256"));
        assert_eq!(edited.digits.as_deref(), Some("8"));
        assert_eq!(edited.period.as_deref(), Some("45"));
        match controller.snapshot()? {
            AppSnapshot::Unlocked(view) => {
                assert!(view.dirty);
                assert_eq!(view.entries.len(), 1);
                let detail = view
                    .selected_detail
                    .ok_or("expected selected detail after edit")?;
                assert_eq!(detail.issuer, "Updated");
                assert_eq!(detail.account_label, "bob@example.com");
                assert_eq!(detail.algorithm, HashAlgorithm::Sha256);
                assert_eq!(detail.digits, 8);
                assert_eq!(detail.period_secs, 45);
            }
            AppSnapshot::NoVault(_) | AppSnapshot::Locked(_) => {
                return Err("controller left the unlocked state unexpectedly".into());
            }
        }
        Ok(())
    }

    #[test]
    fn create_vault_creates_missing_parent_directories() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir
            .path()
            .join("nested")
            .join("folder")
            .join("vault.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path.clone(),
            "correct horse battery staple".to_owned(),
            "correct horse battery staple".to_owned(),
        )?;

        assert!(vault_path.exists());
        assert_eq!(controller.state(), AppState::Locked);
        Ok(())
    }

    #[test]
    fn create_vault_rejects_empty_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("empty-passphrase.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        let result = controller.create_vault(vault_path, "   ".to_owned(), "   ".to_owned());

        assert!(matches!(result, Err(AppError::EmptyPassphrase)));
        assert_eq!(controller.state(), AppState::NoVault);
        Ok(())
    }

    #[test]
    fn create_vault_rejects_short_new_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("short-passphrase.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        let result =
            controller.create_vault(vault_path, "short-pass".to_owned(), "short-pass".to_owned());

        assert!(matches!(result, Err(AppError::PassphraseTooShort(12))));
        assert_eq!(controller.state(), AppState::NoVault);
        Ok(())
    }

    #[test]
    fn unlock_allows_existing_short_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("legacy-short-passphrase.albus");
        let repository = FileVaultRepository::default();
        let vault = empty_vault("legacy")?;
        repository.create_new(&vault_path, "correct horse battery staple", &vault)?;
        repository.save(&vault_path, "passphrase", &vault)?;
        remembered.store(&vault_path)?;

        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;
        controller.unlock("passphrase".to_owned())?;

        assert_eq!(controller.state(), AppState::Unlocked);
        Ok(())
    }

    #[test]
    fn unlock_rejects_possible_rollback_older_than_the_local_trust_anchor()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("rollback-detected.albus");
        let passphrase = "correct horse battery staple";
        let mut controller = AppController::initialize(fixed_clock()?, remembered.clone())?;

        controller.create_vault(
            vault_path.clone(),
            passphrase.to_owned(),
            passphrase.to_owned(),
        )?;
        let original_bytes = std::fs::read(&vault_path)?;

        controller.unlock(passphrase.to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        controller.save_and_lock(Some(passphrase.to_owned()))?;

        std::fs::write(&vault_path, original_bytes)?;

        let mut reopened = AppController::initialize(fixed_clock()?, remembered)?;
        let AppSnapshot::Locked(view) = reopened.snapshot()? else {
            return Err("expected locked state after reopening remembered vault".into());
        };
        assert!(
            view.status_message
                .as_deref()
                .is_some_and(|message| message.contains("rollback"))
        );

        let result = reopened.unlock(passphrase.to_owned());
        assert!(matches!(
            result,
            Err(AppError::RollbackDetected {
                current_revision: 1,
                trusted_revision: 2,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn explicit_restore_can_intentionally_replace_the_local_trust_anchor_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("restore-anchor.albus");
        let backup_path = tempdir.path().join("restore-anchor.albusbak");
        let passphrase = "correct horse battery staple";
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path.clone(),
            passphrase.to_owned(),
            passphrase.to_owned(),
        )?;
        controller.unlock(passphrase.to_owned())?;
        controller.export_backup(BackupExportInput {
            backup_path: backup_path.clone(),
            backup_passphrase: "backup-passphrase-long".to_owned(),
            confirmation: "backup-passphrase-long".to_owned(),
        })?;
        controller.add_entry(AddEntryInput {
            issuer: "Later".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        controller.save_and_lock(Some(passphrase.to_owned()))?;

        controller.restore_backup(BackupRestoreInput {
            backup_path,
            backup_passphrase: "backup-passphrase-long".to_owned(),
            target_vault_path: vault_path.clone(),
            target_vault_passphrase: passphrase.to_owned(),
            confirmation: passphrase.to_owned(),
            replace_existing: true,
        })?;
        controller.unlock(passphrase.to_owned())?;

        let AppSnapshot::Unlocked(view) = controller.snapshot()? else {
            return Err("expected unlocked state after intentional restore".into());
        };
        assert!(view.entries.is_empty());
        Ok(())
    }

    #[test]
    fn restore_is_rejected_from_unlocked() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let source_vault_path = tempdir.path().join("source.albus");
        let backup_path = tempdir.path().join("source.albusbak");
        let restored_vault_path = tempdir.path().join("restored.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            source_vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;
        controller.export_backup(BackupExportInput {
            backup_path,
            backup_passphrase: "backup-passphrase".to_owned(),
            confirmation: "backup-passphrase".to_owned(),
        })?;

        let result = controller.restore_backup(BackupRestoreInput {
            backup_path: tempdir.path().join("source.albusbak"),
            backup_passphrase: "backup-passphrase".to_owned(),
            target_vault_path: restored_vault_path,
            target_vault_passphrase: "restored-passphrase".to_owned(),
            confirmation: "restored-passphrase".to_owned(),
            replace_existing: false,
        });

        assert!(result.is_err());
        assert_eq!(controller.state(), AppState::Unlocked);
        Ok(())
    }

    #[test]
    fn invalid_entry_input_keeps_the_controller_in_unlocked_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path: PathBuf = tempdir.path().join("invalid-entry.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "valid-passphrase".to_owned(),
            "valid-passphrase".to_owned(),
        )?;
        controller.unlock("valid-passphrase".to_owned())?;

        let result = controller.add_entry(AddEntryInput {
            issuer: String::new(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "not-base32".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        });

        assert!(result.is_err());
        assert_eq!(controller.state(), AppState::Unlocked);
        Ok(())
    }

    #[test]
    fn selected_entry_edit_input_redacts_and_preserves_the_existing_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("edit-secret-redacted.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        let original_code = match controller.snapshot()? {
            AppSnapshot::Unlocked(view) => {
                view.selected_detail
                    .ok_or("expected selected detail before edit")?
                    .code
            }
            AppSnapshot::NoVault(_) | AppSnapshot::Locked(_) => {
                return Err("controller left the unlocked state unexpectedly".into());
            }
        };

        let original = controller.selected_entry_edit_input()?;
        assert!(original.secret_base32.is_empty());

        controller.edit_selected_entry(EditEntryInput {
            issuer: "Updated".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: String::new(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        match controller.snapshot()? {
            AppSnapshot::Unlocked(view) => {
                let detail = view
                    .selected_detail
                    .ok_or("expected selected detail after edit")?;
                assert_eq!(detail.issuer, "Updated");
                assert_eq!(detail.code, original_code);
            }
            AppSnapshot::NoVault(_) | AppSnapshot::Locked(_) => {
                return Err("controller left the unlocked state unexpectedly".into());
            }
        }
        Ok(())
    }

    #[test]
    fn wrong_save_passphrase_does_not_discard_dirty_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("wrong-save-passphrase.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "good-passphrase".to_owned(),
            "good-passphrase".to_owned(),
        )?;
        controller.unlock("good-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        let save_result = controller.save_and_lock(Some("bad-passphrase".to_owned()));

        assert!(save_result.is_err());
        assert_eq!(controller.state(), AppState::Unlocked);
        match controller.snapshot()? {
            AppSnapshot::Unlocked(view) => {
                assert!(view.dirty);
                assert_eq!(view.entries.len(), 1);
            }
            AppSnapshot::NoVault(_) | AppSnapshot::Locked(_) => {
                return Err("controller left the unlocked state unexpectedly".into());
            }
        }

        Ok(())
    }

    #[test]
    fn save_and_lock_rejects_empty_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("empty-save-passphrase.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        let result = controller.save_and_lock(Some("   ".to_owned()));

        assert!(matches!(result, Err(AppError::EmptyPassphrase)));
        assert_eq!(controller.state(), AppState::Unlocked);
        Ok(())
    }

    #[test]
    fn restore_from_no_vault_transitions_to_locked() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let source_remembered = remembered_path(&tempdir);
        let source_vault_path = tempdir.path().join("source.albus");
        let backup_path = tempdir.path().join("source.albusbak");
        let restored_vault_path = tempdir.path().join("restored.albus");
        let mut source_controller = AppController::initialize(fixed_clock()?, source_remembered)?;

        source_controller.create_vault(
            source_vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        source_controller.unlock("vault-passphrase".to_owned())?;
        source_controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        source_controller.export_backup(BackupExportInput {
            backup_path: backup_path.clone(),
            backup_passphrase: "backup-passphrase".to_owned(),
            confirmation: "backup-passphrase".to_owned(),
        })?;

        let fresh_temp = TempDir::new()?;
        let remembered = remembered_path(&fresh_temp);
        let mut controller = AppController::initialize(fixed_clock()?, remembered.clone())?;
        controller.restore_backup(BackupRestoreInput {
            backup_path,
            backup_passphrase: "backup-passphrase".to_owned(),
            target_vault_path: restored_vault_path.clone(),
            target_vault_passphrase: "restored-passphrase".to_owned(),
            confirmation: "restored-passphrase".to_owned(),
            replace_existing: false,
        })?;

        assert_eq!(controller.state(), AppState::Locked);
        match controller.snapshot()? {
            AppSnapshot::Locked(view) => {
                assert_eq!(view.vault_path, restored_vault_path);
                assert_eq!(view.known_entry_count, Some(1));
            }
            AppSnapshot::NoVault(_) | AppSnapshot::Unlocked(_) => {
                return Err("controller did not stay locked after restore".into());
            }
        }
        assert_eq!(remembered.load()?, Some(restored_vault_path));
        Ok(())
    }

    #[test]
    fn restore_from_locked_to_new_target_updates_remembered_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let source_vault_path = tempdir.path().join("source.albus");
        let backup_path = tempdir.path().join("source.albusbak");
        let current_vault_path = tempdir.path().join("current.albus");
        let restored_vault_path = tempdir.path().join("restored.albus");
        let mut source_controller = AppController::initialize(fixed_clock()?, remembered.clone())?;

        source_controller.create_vault(
            source_vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        source_controller.unlock("vault-passphrase".to_owned())?;
        source_controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        source_controller.export_backup(BackupExportInput {
            backup_path: backup_path.clone(),
            backup_passphrase: "backup-passphrase".to_owned(),
            confirmation: "backup-passphrase".to_owned(),
        })?;
        source_controller.lock_without_saving()?;

        FileVaultRepository::default().create_new(
            &current_vault_path,
            "current-passphrase",
            &empty_vault("current-vault")?,
        )?;
        remembered.store(&current_vault_path)?;

        let mut controller = AppController::initialize(fixed_clock()?, remembered.clone())?;
        assert_eq!(controller.state(), AppState::Locked);

        controller.restore_backup(BackupRestoreInput {
            backup_path,
            backup_passphrase: "backup-passphrase".to_owned(),
            target_vault_path: restored_vault_path.clone(),
            target_vault_passphrase: "restored-passphrase".to_owned(),
            confirmation: "restored-passphrase".to_owned(),
            replace_existing: false,
        })?;

        assert_eq!(controller.state(), AppState::Locked);
        match controller.snapshot()? {
            AppSnapshot::Locked(view) => {
                assert_eq!(view.vault_path, restored_vault_path);
                assert_eq!(view.known_entry_count, Some(1));
            }
            AppSnapshot::NoVault(_) | AppSnapshot::Unlocked(_) => {
                return Err("controller did not stay locked after restore".into());
            }
        }
        assert_eq!(remembered.load()?, Some(restored_vault_path));
        Ok(())
    }

    #[test]
    fn restore_replace_requires_explicit_confirmation() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let source_vault_path = tempdir.path().join("source.albus");
        let backup_path = tempdir.path().join("source.albusbak");
        let target_vault_path = tempdir.path().join("target.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered.clone())?;

        controller.create_vault(
            source_vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;
        controller.export_backup(BackupExportInput {
            backup_path: backup_path.clone(),
            backup_passphrase: "backup-passphrase".to_owned(),
            confirmation: "backup-passphrase".to_owned(),
        })?;
        controller.lock_without_saving()?;
        FileVaultRepository::default().create_new(
            &target_vault_path,
            "current-passphrase",
            &empty_vault("existing-vault")?,
        )?;

        let result = controller.restore_backup(BackupRestoreInput {
            backup_path,
            backup_passphrase: "backup-passphrase".to_owned(),
            target_vault_path: target_vault_path.clone(),
            target_vault_passphrase: "restored-passphrase".to_owned(),
            confirmation: "restored-passphrase".to_owned(),
            replace_existing: false,
        });

        assert!(result.is_err());
        assert_eq!(controller.state(), AppState::Locked);
        Ok(())
    }

    #[test]
    fn export_backup_rejects_the_active_vault_path() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("active-vault.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path.clone(),
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;

        let result = controller.export_backup(BackupExportInput {
            backup_path: vault_path,
            backup_passphrase: "backup-passphrase".to_owned(),
            confirmation: "backup-passphrase".to_owned(),
        });

        assert!(matches!(result, Err(AppError::BackupPathMatchesVaultPath)));
        assert_eq!(controller.state(), AppState::Unlocked);
        Ok(())
    }

    #[test]
    fn paths_conflict_rejects_aliases_even_when_canonicalize_would_hit_a_missing_ancestor()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let canonical = tempdir.path().join("vault.albus");
        let alias = tempdir
            .path()
            .join("missing")
            .join("..")
            .join("vault.albus");

        std::fs::write(&canonical, b"vault")?;

        assert!(super::paths_conflict(&canonical, &alias));
        Ok(())
    }

    #[test]
    fn delete_selected_entry_requires_explicit_confirmation()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("delete-confirmation.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        let result = controller.delete_selected_entry(DeleteEntryInput {
            confirmation: "WRONG".to_owned(),
        });

        assert!(result.is_err());
        match controller.snapshot()? {
            AppSnapshot::Unlocked(view) => assert_eq!(view.entries.len(), 1),
            AppSnapshot::NoVault(_) | AppSnapshot::Locked(_) => {
                return Err("controller left the unlocked state unexpectedly".into());
            }
        }
        Ok(())
    }

    #[test]
    fn delete_selected_entry_removes_the_current_entry() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("delete-entry.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Example A".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        controller.add_entry(AddEntryInput {
            issuer: "Example B".to_owned(),
            account_label: "bob@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        controller.select_previous();

        controller.delete_selected_entry(DeleteEntryInput {
            confirmation: "DELETE".to_owned(),
        })?;

        match controller.snapshot()? {
            AppSnapshot::Unlocked(view) => {
                assert!(view.dirty);
                assert_eq!(view.entries.len(), 1);
                assert_eq!(view.selected_index, Some(0));
                assert_eq!(view.entries[0].issuer, "Example B");
            }
            AppSnapshot::NoVault(_) | AppSnapshot::Locked(_) => {
                return Err("controller left the unlocked state unexpectedly".into());
            }
        }
        Ok(())
    }

    #[test]
    fn change_passphrase_reencrypts_the_vault_and_locks() -> Result<(), Box<dyn std::error::Error>>
    {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("change-passphrase.albus");
        let storage = FileVaultRepository::default();
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path.clone(),
            "old-passphrase".to_owned(),
            "old-passphrase".to_owned(),
        )?;
        controller.unlock("old-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        controller.change_passphrase(ChangePassphraseInput {
            current_passphrase: "old-passphrase".to_owned(),
            new_passphrase: "new-passphrase".to_owned(),
            confirmation: "new-passphrase".to_owned(),
        })?;

        assert_eq!(controller.state(), AppState::Locked);
        assert!(storage.unlock(&vault_path, "old-passphrase").is_err());
        let unlocked = storage.unlock(&vault_path, "new-passphrase")?;
        assert_eq!(unlocked.entries().len(), 1);
        Ok(())
    }

    #[test]
    fn change_passphrase_rejects_short_new_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("short-change-passphrase.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "old-passphrase".to_owned(),
            "old-passphrase".to_owned(),
        )?;
        controller.unlock("old-passphrase".to_owned())?;

        let result = controller.change_passphrase(ChangePassphraseInput {
            current_passphrase: "old-passphrase".to_owned(),
            new_passphrase: "too-short".to_owned(),
            confirmation: "too-short".to_owned(),
        });

        assert!(matches!(result, Err(AppError::PassphraseTooShort(12))));
        assert_eq!(controller.state(), AppState::Unlocked);
        Ok(())
    }

    #[test]
    fn wrong_current_passphrase_does_not_leave_unlocked_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("wrong-current-passphrase.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "old-passphrase".to_owned(),
            "old-passphrase".to_owned(),
        )?;
        controller.unlock("old-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        let result = controller.change_passphrase(ChangePassphraseInput {
            current_passphrase: "wrong-passphrase".to_owned(),
            new_passphrase: "new-passphrase".to_owned(),
            confirmation: "new-passphrase".to_owned(),
        });

        assert!(result.is_err());
        match controller.snapshot()? {
            AppSnapshot::Unlocked(view) => {
                assert!(view.dirty);
                assert_eq!(view.entries.len(), 1);
            }
            AppSnapshot::NoVault(_) | AppSnapshot::Locked(_) => {
                return Err("controller left the unlocked state unexpectedly".into());
            }
        }
        Ok(())
    }

    #[test]
    fn auto_lock_due_to_idle_locks_a_clean_unlocked_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("idle-auto-lock.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path.clone(),
            "correct horse battery staple".to_owned(),
            "correct horse battery staple".to_owned(),
        )?;
        controller.unlock("correct horse battery staple".to_owned())?;
        controller.auto_lock_due_to_idle(5)?;

        assert_eq!(controller.state(), AppState::Locked);
        let AppSnapshot::Locked(view) = controller.snapshot()? else {
            return Err("expected locked view after idle auto-lock".into());
        };
        assert_eq!(view.vault_path, vault_path);
        assert_eq!(view.known_entry_count, Some(0));
        assert_eq!(
            view.status_message.as_deref(),
            Some("vault auto-locked after 5 seconds of inactivity")
        );
        Ok(())
    }

    #[test]
    fn entry_filter_limits_visible_entries_and_selected_detail()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("entry-filter.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Example A".to_owned(),
            account_label: "alice@alpha.test".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        controller.add_entry(AddEntryInput {
            issuer: "Example B".to_owned(),
            account_label: "bob@beta.test".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        controller.add_entry(AddEntryInput {
            issuer: "Other".to_owned(),
            account_label: "carol@other.test".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        controller.set_entry_filter("example ")?;

        match controller.snapshot()? {
            AppSnapshot::Unlocked(view) => {
                assert_eq!(view.filter_query.as_deref(), Some("example"));
                assert_eq!(view.visible_entry_count, 2);
                assert_eq!(view.total_entry_count, 3);
                assert_eq!(view.entries.len(), 2);
                assert_eq!(view.entries[0].issuer, "Example A");
                assert_eq!(view.entries[1].issuer, "Example B");
                let detail = view
                    .selected_detail
                    .ok_or("expected selected detail while filtered")?;
                assert_eq!(detail.issuer, "Example A");
                assert_eq!(view.selected_index, Some(0));
            }
            AppSnapshot::NoVault(_) | AppSnapshot::Locked(_) => {
                return Err("controller left the unlocked state unexpectedly".into());
            }
        }

        Ok(())
    }

    #[test]
    fn selection_moves_within_filtered_entries() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("filtered-selection.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "North".to_owned(),
            account_label: "alice@north.test".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        controller.add_entry(AddEntryInput {
            issuer: "Beta".to_owned(),
            account_label: "bob@green.test".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        controller.add_entry(AddEntryInput {
            issuer: "Beryl".to_owned(),
            account_label: "carol@stone.test".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        controller.set_entry_filter("be")?;
        let AppSnapshot::Unlocked(view) = controller.snapshot()? else {
            return Err("expected unlocked snapshot".into());
        };
        let detail = view
            .selected_detail
            .ok_or("expected selected detail after applying filter")?;
        assert_eq!(detail.issuer, "Beryl");

        controller.select_next();

        let AppSnapshot::Unlocked(view) = controller.snapshot()? else {
            return Err("expected unlocked snapshot".into());
        };
        let detail = view
            .selected_detail
            .ok_or("expected selected detail after filtered next")?;
        assert_eq!(detail.issuer, "Beta");

        controller.select_previous();
        let AppSnapshot::Unlocked(view) = controller.snapshot()? else {
            return Err("expected unlocked snapshot".into());
        };
        let detail = view
            .selected_detail
            .ok_or("expected selected detail after filtered previous")?;
        assert_eq!(detail.issuer, "Beryl");

        Ok(())
    }

    #[test]
    fn clearing_filter_restores_the_full_entry_list() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = remembered_path(&tempdir);
        let vault_path = tempdir.path().join("clear-filter.albus");
        let mut controller = AppController::initialize(fixed_clock()?, remembered)?;

        controller.create_vault(
            vault_path,
            "vault-passphrase".to_owned(),
            "vault-passphrase".to_owned(),
        )?;
        controller.unlock("vault-passphrase".to_owned())?;
        controller.add_entry(AddEntryInput {
            issuer: "Alpha".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;
        controller.add_entry(AddEntryInput {
            issuer: "Beta".to_owned(),
            account_label: "bob@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        controller.set_entry_filter("beta")?;
        controller.set_entry_filter("")?;

        match controller.snapshot()? {
            AppSnapshot::Unlocked(view) => {
                assert_eq!(view.filter_query, None);
                assert_eq!(view.visible_entry_count, 2);
                assert_eq!(view.total_entry_count, 2);
                assert_eq!(view.entries.len(), 2);
            }
            AppSnapshot::NoVault(_) | AppSnapshot::Locked(_) => {
                return Err("controller left the unlocked state unexpectedly".into());
            }
        }

        Ok(())
    }

    fn empty_vault(vault_id: &str) -> Result<Vault, Box<dyn std::error::Error>> {
        Ok(Vault::new(
            VaultId::new(vault_id)?,
            1,
            1,
            "2026-03-11T00:00:00Z",
            "2026-03-11T00:00:00Z",
            Vec::new(),
        )?)
    }
}
