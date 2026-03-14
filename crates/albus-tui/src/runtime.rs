use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use zeroize::Zeroize;

use crate::{
    AppController, AppError, AppSnapshot, AppState, DeleteEntryInput, EditEntryInput,
    RememberedVaultPath, SystemClock, process_hardening, sensitive_text::SensitiveText, ui,
};

const DEFAULT_IDLE_LOCK_SECS: u64 = 300;

/// Starts the interactive terminal shell.
///
/// # Errors
///
/// Returns [`AppError`] when terminal initialization or app startup fails.
pub fn run() -> Result<(), AppError> {
    let remembered_path = RememberedVaultPath::for_project_dirs()?;
    let mut controller = AppController::initialize(SystemClock, remembered_path)?;
    if let Some(status_message) = process_hardening::startup_warning_from_env() {
        controller.append_status(status_message);
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let run_result = run_loop(&mut terminal, &mut controller);
    if controller.state() == AppState::Unlocked {
        let _ = controller.lock_without_saving();
    }

    let cleanup_result = cleanup_terminal(&mut terminal);
    match (run_result, cleanup_result) {
        (Err(error), Ok(()) | Err(_)) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    controller: &mut AppController<SystemClock>,
) -> Result<(), AppError> {
    let mut ui_state = UiState::default();
    let mut last_tick = Instant::now();
    let idle_lock_policy =
        idle_lock_policy_from_env(std::env::var("ALBUS_IDLE_LOCK_SECS").ok().as_deref());
    let mut last_user_activity = Instant::now();

    loop {
        let snapshot = controller.snapshot()?;
        let modal_view = ui_state.modal.as_ref().map(Modal::view);
        terminal.draw(|frame| ui::render(frame, &snapshot, modal_view.as_ref()))?;

        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            last_user_activity = Instant::now();
            match ui_state.handle_key(key, controller, &snapshot)? {
                LoopControl::Continue => {}
                LoopControl::Quit => return Ok(()),
            }
        }

        if let Some(idle_secs) =
            idle_lock_timeout_to_apply(&snapshot, idle_lock_policy, last_user_activity.elapsed())
        {
            ui_state.modal = None;
            controller.auto_lock_due_to_idle(idle_secs)?;
            last_user_activity = Instant::now();
            continue;
        }

        if last_tick.elapsed() >= Duration::from_secs(1) {
            last_tick = Instant::now();
        }
    }
}

fn cleanup_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), AppError> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

#[derive(Default)]
struct UiState {
    modal: Option<Modal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdleLockPolicy {
    timeout_secs: u64,
}

impl IdleLockPolicy {
    fn timeout(self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

impl UiState {
    fn handle_key(
        &mut self,
        key: KeyEvent,
        controller: &mut AppController<SystemClock>,
        snapshot: &AppSnapshot,
    ) -> Result<LoopControl, AppError> {
        if let Some(modal) = &mut self.modal {
            let close_modal = modal.handle_key(key, controller);
            if close_modal {
                self.modal = None;
            }
            return Ok(LoopControl::Continue);
        }

        match controller.state() {
            AppState::NoVault => Ok(self.handle_no_vault_key(key, snapshot)),
            AppState::Locked => Ok(self.handle_locked_key(key, snapshot)),
            AppState::Unlocked => self.handle_unlocked_key(key, controller),
        }
    }

    fn handle_no_vault_key(&mut self, key: KeyEvent, snapshot: &AppSnapshot) -> LoopControl {
        match key.code {
            KeyCode::Char('c') => {
                let AppSnapshot::NoVault(view) = snapshot else {
                    return LoopControl::Continue;
                };
                self.modal = Some(Modal::Create(CreateForm::new(
                    view.suggested_vault_path.display().to_string(),
                )));
                LoopControl::Continue
            }
            KeyCode::Char('r') => {
                let AppSnapshot::NoVault(view) = snapshot else {
                    return LoopControl::Continue;
                };
                self.modal = Some(Modal::Restore(RestoreBackupForm::new(
                    suggested_backup_path(view.suggested_vault_path.as_path()),
                    view.suggested_vault_path.display().to_string(),
                )));
                LoopControl::Continue
            }
            KeyCode::Char('q') => LoopControl::Quit,
            _ => LoopControl::Continue,
        }
    }

    fn handle_locked_key(&mut self, key: KeyEvent, snapshot: &AppSnapshot) -> LoopControl {
        match key.code {
            KeyCode::Char('u') => {
                self.modal = Some(Modal::Unlock(PassphraseForm::default()));
                LoopControl::Continue
            }
            KeyCode::Char('r') => {
                let AppSnapshot::Locked(view) = snapshot else {
                    return LoopControl::Continue;
                };
                self.modal = Some(Modal::Restore(RestoreBackupForm::new(
                    suggested_backup_path(view.vault_path.as_path()),
                    view.vault_path.display().to_string(),
                )));
                LoopControl::Continue
            }
            KeyCode::Char('q') => LoopControl::Quit,
            _ => LoopControl::Continue,
        }
    }

    fn handle_unlocked_key(
        &mut self,
        key: KeyEvent,
        controller: &mut AppController<SystemClock>,
    ) -> Result<LoopControl, AppError> {
        match key.code {
            KeyCode::Up => {
                controller.select_previous();
                Ok(LoopControl::Continue)
            }
            KeyCode::Down => {
                controller.select_next();
                Ok(LoopControl::Continue)
            }
            KeyCode::Char('a') => {
                self.modal = Some(Modal::AddEntry(AddEntryForm::default()));
                Ok(LoopControl::Continue)
            }
            KeyCode::Char('i') => {
                self.modal = Some(Modal::ImportUri(ImportUriForm::default()));
                Ok(LoopControl::Continue)
            }
            KeyCode::Char('e') => {
                match controller.selected_entry_edit_input() {
                    Ok(input) => {
                        self.modal = Some(Modal::Edit(EditEntryForm::new(input)));
                    }
                    Err(error) => controller.set_error_status(&error),
                }
                Ok(LoopControl::Continue)
            }
            KeyCode::Char('d') => {
                let AppSnapshot::Unlocked(view) = controller.snapshot()? else {
                    return Ok(LoopControl::Continue);
                };

                if let Some(index) = view.selected_index {
                    let entry_label = view.entries.get(index).map_or_else(
                        || "selected entry".to_owned(),
                        |entry| format!("{} | {}", entry.issuer, entry.account_label),
                    );
                    self.modal = Some(Modal::Delete(DeleteEntryForm::new(entry_label)));
                } else {
                    let _ = controller.delete_selected_entry(DeleteEntryInput::default());
                }
                Ok(LoopControl::Continue)
            }
            KeyCode::Char('b') => {
                let AppSnapshot::Unlocked(view) = controller.snapshot()? else {
                    return Ok(LoopControl::Continue);
                };
                self.modal = Some(Modal::Export(ExportBackupForm::new(suggested_backup_path(
                    view.vault_path.as_path(),
                ))));
                Ok(LoopControl::Continue)
            }
            KeyCode::Char('/') => {
                let AppSnapshot::Unlocked(view) = controller.snapshot()? else {
                    return Ok(LoopControl::Continue);
                };
                self.modal = Some(Modal::Filter(FilterForm::new(
                    view.filter_query.unwrap_or_default(),
                )));
                Ok(LoopControl::Continue)
            }
            KeyCode::Char('p') => {
                self.modal = Some(Modal::ChangePassphrase(ChangePassphraseForm::default()));
                Ok(LoopControl::Continue)
            }
            KeyCode::Char('s') => {
                let AppSnapshot::Unlocked(view) = controller.snapshot()? else {
                    return Ok(LoopControl::Continue);
                };

                if view.dirty {
                    self.modal = Some(Modal::Save(PassphraseForm::default()));
                } else {
                    controller.save_and_lock(None)?;
                }
                Ok(LoopControl::Continue)
            }
            KeyCode::Char('l') => {
                controller.lock_without_saving()?;
                Ok(LoopControl::Continue)
            }
            KeyCode::Char('q') => {
                controller.lock_without_saving()?;
                Ok(LoopControl::Quit)
            }
            _ => Ok(LoopControl::Continue),
        }
    }
}

enum LoopControl {
    Continue,
    Quit,
}

enum Modal {
    Create(CreateForm),
    Unlock(PassphraseForm),
    AddEntry(AddEntryForm),
    ImportUri(ImportUriForm),
    Edit(EditEntryForm),
    Delete(DeleteEntryForm),
    Export(ExportBackupForm),
    Restore(RestoreBackupForm),
    Filter(FilterForm),
    ChangePassphrase(ChangePassphraseForm),
    Save(PassphraseForm),
}

impl Modal {
    fn handle_key(&mut self, key: KeyEvent, controller: &mut AppController<SystemClock>) -> bool {
        match self {
            Self::Create(form) => form.handle_key(key, controller),
            Self::Unlock(form) => form.handle_unlock_key(key, controller),
            Self::AddEntry(form) => form.handle_key(key, controller),
            Self::ImportUri(form) => form.handle_key(key, controller),
            Self::Edit(form) => form.handle_key(key, controller),
            Self::Delete(form) => form.handle_key(key, controller),
            Self::Export(form) => form.handle_key(key, controller),
            Self::Restore(form) => form.handle_key(key, controller),
            Self::Filter(form) => form.handle_key(key, controller),
            Self::ChangePassphrase(form) => form.handle_key(key, controller),
            Self::Save(form) => form.handle_save_key(key, controller),
        }
    }

    fn view(&self) -> ModalView {
        match self {
            Self::Create(form) => form.view(),
            Self::Unlock(form) => form.unlock_view(),
            Self::AddEntry(form) => form.view(),
            Self::ImportUri(form) => form.view(),
            Self::Edit(form) => form.view(),
            Self::Delete(form) => form.view(),
            Self::Export(form) => form.view(),
            Self::Restore(form) => form.view(),
            Self::Filter(form) => form.view(),
            Self::ChangePassphrase(form) => form.view(),
            Self::Save(form) => form.save_view(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ModalFieldView {
    pub(crate) label: String,
    pub(crate) value: String,
    pub(crate) secret_len: Option<usize>,
    pub(crate) is_active: bool,
}

impl ModalFieldView {
    fn plain(label: &str, value: String, is_active: bool) -> Self {
        Self {
            label: label.to_owned(),
            value,
            secret_len: None,
            is_active,
        }
    }

    fn secret(label: &str, secret_len: usize, is_active: bool) -> Self {
        Self {
            label: label.to_owned(),
            value: String::new(),
            secret_len: Some(secret_len),
            is_active,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ModalView {
    pub(crate) title: String,
    pub(crate) fields: Vec<ModalFieldView>,
    pub(crate) hint: String,
}

#[derive(Default)]
struct PassphraseForm {
    passphrase: SensitiveText,
}

impl PassphraseForm {
    fn handle_unlock_key(
        &mut self,
        key: KeyEvent,
        controller: &mut AppController<SystemClock>,
    ) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Enter => match controller.unlock_with_ref(self.passphrase.as_str()) {
                Ok(()) => true,
                Err(_) => false,
            },
            _ => {
                edit_sensitive_field(&mut self.passphrase, key);
                false
            }
        }
    }

    fn handle_save_key(
        &mut self,
        key: KeyEvent,
        controller: &mut AppController<SystemClock>,
    ) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Enter => {
                match controller.save_and_lock_with_ref(Some(self.passphrase.as_str())) {
                    Ok(()) => true,
                    Err(_) => false,
                }
            }
            _ => {
                edit_sensitive_field(&mut self.passphrase, key);
                false
            }
        }
    }

    fn unlock_view(&self) -> ModalView {
        ModalView {
            title: "Unlock Vault".to_owned(),
            fields: vec![ModalFieldView::secret(
                "Passphrase",
                self.passphrase.chars_count(),
                true,
            )],
            hint: "Enter submits. Esc closes.".to_owned(),
        }
    }

    fn save_view(&self) -> ModalView {
        ModalView {
            title: "Save And Lock".to_owned(),
            fields: vec![ModalFieldView::secret(
                "Passphrase",
                self.passphrase.chars_count(),
                true,
            )],
            hint: "Enter submits. Esc closes.".to_owned(),
        }
    }
}

struct CreateForm {
    path: String,
    passphrase: SensitiveText,
    confirmation: SensitiveText,
    active_field: CreateField,
}

struct FilterForm {
    query: String,
}

impl FilterForm {
    fn new(default_query: String) -> Self {
        Self {
            query: default_query,
        }
    }

    fn handle_key(&mut self, key: KeyEvent, controller: &mut AppController<SystemClock>) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Enter => {
                let query = std::mem::take(&mut self.query);
                match controller.set_entry_filter(query.as_str()) {
                    Ok(()) => true,
                    Err(_) => false,
                }
            }
            _ => {
                edit_text_field(&mut self.query, key);
                false
            }
        }
    }

    fn view(&self) -> ModalView {
        ModalView {
            title: "Filter Entries".to_owned(),
            fields: vec![ModalFieldView::plain("Query", self.query.clone(), true)],
            hint: "Enter applies. Empty query clears the current filter. Esc closes.".to_owned(),
        }
    }
}

impl CreateForm {
    fn new(default_path: String) -> Self {
        Self {
            path: default_path,
            passphrase: SensitiveText::default(),
            confirmation: SensitiveText::default(),
            active_field: CreateField::Path,
        }
    }

    fn handle_key(&mut self, key: KeyEvent, controller: &mut AppController<SystemClock>) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Enter if self.active_field == CreateField::Confirmation => {
                let path = PathBuf::from(self.path.trim());
                match controller.create_vault_with_refs(
                    path,
                    self.passphrase.as_str(),
                    self.confirmation.as_str(),
                ) {
                    Ok(()) => {
                        self.passphrase.clear();
                        self.confirmation.clear();
                        true
                    }
                    Err(_) => false,
                }
            }
            KeyCode::Enter | KeyCode::Tab | KeyCode::Down => {
                self.active_field = self.active_field.next();
                false
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.active_field = self.active_field.previous();
                false
            }
            _ => {
                self.edit_active_field(key);
                false
            }
        }
    }

    fn edit_active_field(&mut self, key: KeyEvent) {
        match self.active_field {
            CreateField::Path => edit_text_field(&mut self.path, key),
            CreateField::Passphrase => edit_sensitive_field(&mut self.passphrase, key),
            CreateField::Confirmation => edit_sensitive_field(&mut self.confirmation, key),
        }
    }

    fn view(&self) -> ModalView {
        ModalView {
            title: "Create Vault".to_owned(),
            fields: vec![
                ModalFieldView::plain(
                    "Path",
                    self.path.clone(),
                    self.active_field == CreateField::Path,
                ),
                ModalFieldView::secret(
                    "Passphrase",
                    self.passphrase.chars_count(),
                    self.active_field == CreateField::Passphrase,
                ),
                ModalFieldView::secret(
                    "Confirm",
                    self.confirmation.chars_count(),
                    self.active_field == CreateField::Confirmation,
                ),
            ],
            hint:
                "Tab moves fields. Enter submits on Confirm. New passphrases need at least 12 non-whitespace characters."
                    .to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreateField {
    Path,
    Passphrase,
    Confirmation,
}

impl CreateField {
    fn next(self) -> Self {
        match self {
            Self::Path => Self::Passphrase,
            Self::Passphrase => Self::Confirmation,
            Self::Confirmation => Self::Path,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Path => Self::Confirmation,
            Self::Passphrase => Self::Path,
            Self::Confirmation => Self::Passphrase,
        }
    }
}

#[derive(Default)]
struct AddEntryForm {
    issuer: String,
    account_label: String,
    secret_base32: SensitiveText,
    algorithm: String,
    digits: String,
    period: String,
    active_field: AddEntryField,
}

impl AddEntryForm {
    fn handle_key(&mut self, key: KeyEvent, controller: &mut AppController<SystemClock>) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Enter if self.active_field == AddEntryField::Period => {
                match controller.add_entry_with_refs(
                    self.issuer.as_str(),
                    self.account_label.as_str(),
                    self.secret_base32.as_str(),
                    empty_to_none_ref(self.algorithm.as_str()),
                    empty_to_none_ref(self.digits.as_str()),
                    empty_to_none_ref(self.period.as_str()),
                ) {
                    Ok(()) => {
                        self.issuer.clear();
                        self.account_label.clear();
                        self.secret_base32.clear();
                        self.algorithm.clear();
                        self.digits.clear();
                        self.period.clear();
                        true
                    }
                    Err(_) => false,
                }
            }
            KeyCode::Enter | KeyCode::Tab | KeyCode::Down => {
                self.active_field = self.active_field.next();
                false
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.active_field = self.active_field.previous();
                false
            }
            _ => {
                self.edit_active_field(key);
                false
            }
        }
    }

    fn edit_active_field(&mut self, key: KeyEvent) {
        match self.active_field {
            AddEntryField::Issuer => edit_text_field(&mut self.issuer, key),
            AddEntryField::AccountLabel => edit_text_field(&mut self.account_label, key),
            AddEntryField::SecretBase32 => edit_sensitive_field(&mut self.secret_base32, key),
            AddEntryField::Algorithm => edit_text_field(&mut self.algorithm, key),
            AddEntryField::Digits => edit_text_field(&mut self.digits, key),
            AddEntryField::Period => edit_text_field(&mut self.period, key),
        }
    }

    fn view(&self) -> ModalView {
        ModalView {
            title: "Add Entry".to_owned(),
            fields: vec![
                ModalFieldView::plain(
                    "Issuer",
                    self.issuer.clone(),
                    self.active_field == AddEntryField::Issuer,
                ),
                ModalFieldView::plain(
                    "Account",
                    self.account_label.clone(),
                    self.active_field == AddEntryField::AccountLabel,
                ),
                ModalFieldView::secret(
                    "Secret",
                    self.secret_base32.chars_count(),
                    self.active_field == AddEntryField::SecretBase32,
                ),
                ModalFieldView::plain(
                    "Algorithm",
                    self.algorithm.clone(),
                    self.active_field == AddEntryField::Algorithm,
                ),
                ModalFieldView::plain(
                    "Digits",
                    self.digits.clone(),
                    self.active_field == AddEntryField::Digits,
                ),
                ModalFieldView::plain(
                    "Period",
                    self.period.clone(),
                    self.active_field == AddEntryField::Period,
                ),
            ],
            hint: "Algorithm defaults to SHA1, digits to 6, period to 30. Enter submits on Period."
                .to_owned(),
        }
    }
}

#[derive(Default)]
struct ImportUriForm {
    uri: SensitiveText,
}

impl ImportUriForm {
    fn handle_key(&mut self, key: KeyEvent, controller: &mut AppController<SystemClock>) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Enter => match controller.import_entry_uri_with_ref(self.uri.as_str()) {
                Ok(()) => {
                    self.uri.clear();
                    true
                }
                Err(_) => false,
            },
            _ => {
                edit_sensitive_field(&mut self.uri, key);
                false
            }
        }
    }

    fn view(&self) -> ModalView {
        ModalView {
            title: "Import URI".to_owned(),
            fields: vec![ModalFieldView::secret(
                "otpauth://",
                self.uri.chars_count(),
                true,
            )],
            hint: "Paste an otpauth://totp URI. Enter submits. Esc closes.".to_owned(),
        }
    }
}

struct EditEntryForm {
    issuer: String,
    account_label: String,
    secret_base32: SensitiveText,
    algorithm: String,
    digits: String,
    period: String,
    active_field: AddEntryField,
}

impl EditEntryForm {
    fn new(input: EditEntryInput) -> Self {
        Self {
            issuer: input.issuer,
            account_label: input.account_label,
            secret_base32: SensitiveText::from(input.secret_base32.as_str()),
            algorithm: input.algorithm.unwrap_or_default(),
            digits: input.digits.unwrap_or_default(),
            period: input.period.unwrap_or_default(),
            active_field: AddEntryField::Issuer,
        }
    }

    fn handle_key(&mut self, key: KeyEvent, controller: &mut AppController<SystemClock>) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Enter if self.active_field == AddEntryField::Period => {
                match controller.edit_selected_entry_with_refs(
                    self.issuer.as_str(),
                    self.account_label.as_str(),
                    self.secret_base32.as_str(),
                    empty_to_none_ref(self.algorithm.as_str()),
                    empty_to_none_ref(self.digits.as_str()),
                    empty_to_none_ref(self.period.as_str()),
                ) {
                    Ok(()) => {
                        self.secret_base32.clear();
                        true
                    }
                    Err(_) => false,
                }
            }
            KeyCode::Enter | KeyCode::Tab | KeyCode::Down => {
                self.active_field = self.active_field.next();
                false
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.active_field = self.active_field.previous();
                false
            }
            _ => {
                self.edit_active_field(key);
                false
            }
        }
    }

    fn edit_active_field(&mut self, key: KeyEvent) {
        match self.active_field {
            AddEntryField::Issuer => edit_text_field(&mut self.issuer, key),
            AddEntryField::AccountLabel => edit_text_field(&mut self.account_label, key),
            AddEntryField::SecretBase32 => edit_sensitive_field(&mut self.secret_base32, key),
            AddEntryField::Algorithm => edit_text_field(&mut self.algorithm, key),
            AddEntryField::Digits => edit_text_field(&mut self.digits, key),
            AddEntryField::Period => edit_text_field(&mut self.period, key),
        }
    }

    fn view(&self) -> ModalView {
        ModalView {
            title: "Edit Entry".to_owned(),
            fields: vec![
                ModalFieldView::plain(
                    "Issuer",
                    self.issuer.clone(),
                    self.active_field == AddEntryField::Issuer,
                ),
                ModalFieldView::plain(
                    "Account",
                    self.account_label.clone(),
                    self.active_field == AddEntryField::AccountLabel,
                ),
                ModalFieldView::secret(
                    "Secret",
                    self.secret_base32.chars_count(),
                    self.active_field == AddEntryField::SecretBase32,
                ),
                ModalFieldView::plain(
                    "Algorithm",
                    self.algorithm.clone(),
                    self.active_field == AddEntryField::Algorithm,
                ),
                ModalFieldView::plain(
                    "Digits",
                    self.digits.clone(),
                    self.active_field == AddEntryField::Digits,
                ),
                ModalFieldView::plain(
                    "Period",
                    self.period.clone(),
                    self.active_field == AddEntryField::Period,
                ),
            ],
            hint: "Leave Secret blank to keep the current secret. Enter submits on Period."
                .to_owned(),
        }
    }
}

struct DeleteEntryForm {
    entry_label: String,
    confirmation: String,
}

impl DeleteEntryForm {
    fn new(entry_label: String) -> Self {
        Self {
            entry_label,
            confirmation: String::new(),
        }
    }

    fn handle_key(&mut self, key: KeyEvent, controller: &mut AppController<SystemClock>) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Enter => {
                let input = DeleteEntryInput {
                    confirmation: self.confirmation.clone(),
                };
                match controller.delete_selected_entry(input) {
                    Ok(()) => {
                        self.confirmation.zeroize();
                        true
                    }
                    Err(_) => false,
                }
            }
            _ => {
                edit_text_field(&mut self.confirmation, key);
                false
            }
        }
    }

    fn view(&self) -> ModalView {
        ModalView {
            title: "Delete Entry".to_owned(),
            fields: vec![
                ModalFieldView::plain("Entry", self.entry_label.clone(), false),
                ModalFieldView::plain("Type DELETE", self.confirmation.clone(), true),
            ],
            hint: "Enter submits. Esc closes.".to_owned(),
        }
    }
}

impl Drop for DeleteEntryForm {
    fn drop(&mut self) {
        self.confirmation.zeroize();
    }
}

#[derive(Default)]
struct ChangePassphraseForm {
    current_passphrase: SensitiveText,
    new_passphrase: SensitiveText,
    confirmation: SensitiveText,
    active_field: ChangePassphraseField,
}

impl ChangePassphraseForm {
    fn handle_key(&mut self, key: KeyEvent, controller: &mut AppController<SystemClock>) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Enter if self.active_field == ChangePassphraseField::Confirmation => {
                match controller.change_passphrase_with_refs(
                    self.current_passphrase.as_str(),
                    self.new_passphrase.as_str(),
                    self.confirmation.as_str(),
                ) {
                    Ok(()) => {
                        self.current_passphrase.clear();
                        self.new_passphrase.clear();
                        self.confirmation.clear();
                        true
                    }
                    Err(_) => false,
                }
            }
            KeyCode::Enter | KeyCode::Tab | KeyCode::Down => {
                self.active_field = self.active_field.next();
                false
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.active_field = self.active_field.previous();
                false
            }
            _ => {
                self.edit_active_field(key);
                false
            }
        }
    }

    fn edit_active_field(&mut self, key: KeyEvent) {
        match self.active_field {
            ChangePassphraseField::CurrentPassphrase => {
                edit_sensitive_field(&mut self.current_passphrase, key);
            }
            ChangePassphraseField::NewPassphrase => {
                edit_sensitive_field(&mut self.new_passphrase, key);
            }
            ChangePassphraseField::Confirmation => {
                edit_sensitive_field(&mut self.confirmation, key);
            }
        }
    }

    fn view(&self) -> ModalView {
        ModalView {
            title: "Change Passphrase".to_owned(),
            fields: vec![
                ModalFieldView::secret(
                    "Current",
                    self.current_passphrase.chars_count(),
                    self.active_field == ChangePassphraseField::CurrentPassphrase,
                ),
                ModalFieldView::secret(
                    "New",
                    self.new_passphrase.chars_count(),
                    self.active_field == ChangePassphraseField::NewPassphrase,
                ),
                ModalFieldView::secret(
                    "Confirm",
                    self.confirmation.chars_count(),
                    self.active_field == ChangePassphraseField::Confirmation,
                ),
            ],
            hint:
                "Tab moves fields. Enter submits on Confirm. New passphrases need at least 12 non-whitespace characters."
                    .to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ChangePassphraseField {
    #[default]
    CurrentPassphrase,
    NewPassphrase,
    Confirmation,
}

impl ChangePassphraseField {
    fn next(self) -> Self {
        match self {
            Self::CurrentPassphrase => Self::NewPassphrase,
            Self::NewPassphrase => Self::Confirmation,
            Self::Confirmation => Self::CurrentPassphrase,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::CurrentPassphrase => Self::Confirmation,
            Self::NewPassphrase => Self::CurrentPassphrase,
            Self::Confirmation => Self::NewPassphrase,
        }
    }
}

struct ExportBackupForm {
    backup_path: String,
    backup_passphrase: SensitiveText,
    confirmation: SensitiveText,
    active_field: ExportBackupField,
}

impl ExportBackupForm {
    fn new(default_path: String) -> Self {
        Self {
            backup_path: default_path,
            backup_passphrase: SensitiveText::default(),
            confirmation: SensitiveText::default(),
            active_field: ExportBackupField::BackupPath,
        }
    }

    fn handle_key(&mut self, key: KeyEvent, controller: &mut AppController<SystemClock>) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Enter if self.active_field == ExportBackupField::Confirmation => {
                match controller.export_backup_with_refs(
                    PathBuf::from(self.backup_path.trim()).as_path(),
                    self.backup_passphrase.as_str(),
                    self.confirmation.as_str(),
                ) {
                    Ok(()) => {
                        self.backup_passphrase.clear();
                        self.confirmation.clear();
                        true
                    }
                    Err(_) => false,
                }
            }
            KeyCode::Enter | KeyCode::Tab | KeyCode::Down => {
                self.active_field = self.active_field.next();
                false
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.active_field = self.active_field.previous();
                false
            }
            _ => {
                self.edit_active_field(key);
                false
            }
        }
    }

    fn edit_active_field(&mut self, key: KeyEvent) {
        match self.active_field {
            ExportBackupField::BackupPath => edit_text_field(&mut self.backup_path, key),
            ExportBackupField::BackupPassphrase => {
                edit_sensitive_field(&mut self.backup_passphrase, key);
            }
            ExportBackupField::Confirmation => edit_sensitive_field(&mut self.confirmation, key),
        }
    }

    fn view(&self) -> ModalView {
        ModalView {
            title: "Export Backup".to_owned(),
            fields: vec![
                ModalFieldView::plain(
                    "Backup Path",
                    self.backup_path.clone(),
                    self.active_field == ExportBackupField::BackupPath,
                ),
                ModalFieldView::secret(
                    "Backup Passphrase",
                    self.backup_passphrase.chars_count(),
                    self.active_field == ExportBackupField::BackupPassphrase,
                ),
                ModalFieldView::secret(
                    "Confirm",
                    self.confirmation.chars_count(),
                    self.active_field == ExportBackupField::Confirmation,
                ),
            ],
            hint:
                "Backup passphrase may differ from the vault passphrase and must be at least 12 non-whitespace characters. Enter submits on Confirm."
                    .to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExportBackupField {
    BackupPath,
    BackupPassphrase,
    Confirmation,
}

impl ExportBackupField {
    fn next(self) -> Self {
        match self {
            Self::BackupPath => Self::BackupPassphrase,
            Self::BackupPassphrase => Self::Confirmation,
            Self::Confirmation => Self::BackupPath,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::BackupPath => Self::Confirmation,
            Self::BackupPassphrase => Self::BackupPath,
            Self::Confirmation => Self::BackupPassphrase,
        }
    }
}

#[derive(Default)]
struct RestoreBackupForm {
    backup_path: String,
    backup_passphrase: SensitiveText,
    target_vault_path: String,
    target_vault_passphrase: SensitiveText,
    confirmation: SensitiveText,
    overwrite_confirmation: String,
    active_field: RestoreBackupField,
}

impl RestoreBackupForm {
    fn new(default_backup_path: String, default_target_vault_path: String) -> Self {
        Self {
            backup_path: default_backup_path,
            backup_passphrase: SensitiveText::default(),
            target_vault_path: default_target_vault_path,
            target_vault_passphrase: SensitiveText::default(),
            confirmation: SensitiveText::default(),
            overwrite_confirmation: String::new(),
            active_field: RestoreBackupField::BackupPath,
        }
    }

    fn handle_key(&mut self, key: KeyEvent, controller: &mut AppController<SystemClock>) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Enter if self.active_field == RestoreBackupField::OverwriteConfirmation => {
                let backup_path = PathBuf::from(self.backup_path.trim());
                let target_vault_path = PathBuf::from(self.target_vault_path.trim());
                match controller.restore_backup_with_refs(
                    backup_path.as_path(),
                    self.backup_passphrase.as_str(),
                    target_vault_path.as_path(),
                    self.target_vault_passphrase.as_str(),
                    self.confirmation.as_str(),
                    self.overwrite_confirmation.trim() == "REPLACE",
                ) {
                    Ok(()) => {
                        self.backup_passphrase.clear();
                        self.target_vault_passphrase.clear();
                        self.confirmation.clear();
                        self.overwrite_confirmation.zeroize();
                        true
                    }
                    Err(_) => false,
                }
            }
            KeyCode::Enter | KeyCode::Tab | KeyCode::Down => {
                self.active_field = self.active_field.next();
                false
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.active_field = self.active_field.previous();
                false
            }
            _ => {
                self.edit_active_field(key);
                false
            }
        }
    }

    fn edit_active_field(&mut self, key: KeyEvent) {
        match self.active_field {
            RestoreBackupField::BackupPath => edit_text_field(&mut self.backup_path, key),
            RestoreBackupField::BackupPassphrase => {
                edit_sensitive_field(&mut self.backup_passphrase, key);
            }
            RestoreBackupField::TargetVaultPath => {
                edit_text_field(&mut self.target_vault_path, key);
            }
            RestoreBackupField::TargetVaultPassphrase => {
                edit_sensitive_field(&mut self.target_vault_passphrase, key);
            }
            RestoreBackupField::Confirmation => edit_sensitive_field(&mut self.confirmation, key),
            RestoreBackupField::OverwriteConfirmation => {
                edit_text_field(&mut self.overwrite_confirmation, key);
            }
        }
    }

    fn view(&self) -> ModalView {
        let target_exists = !self.target_vault_path.trim().is_empty()
            && PathBuf::from(self.target_vault_path.trim()).exists();
        let hint = if target_exists {
            "Target exists. Type REPLACE to overwrite it. The new vault passphrase must be at least 12 non-whitespace characters. Enter submits on Replace."
        } else {
            "Target will be created if it does not exist. The new vault passphrase must be at least 12 non-whitespace characters. Leave Replace blank. Enter submits on Replace."
        };

        ModalView {
            title: "Restore Backup".to_owned(),
            fields: vec![
                ModalFieldView::plain(
                    "Backup Path",
                    self.backup_path.clone(),
                    self.active_field == RestoreBackupField::BackupPath,
                ),
                ModalFieldView::secret(
                    "Backup Passphrase",
                    self.backup_passphrase.chars_count(),
                    self.active_field == RestoreBackupField::BackupPassphrase,
                ),
                ModalFieldView::plain(
                    "Target Vault Path",
                    self.target_vault_path.clone(),
                    self.active_field == RestoreBackupField::TargetVaultPath,
                ),
                ModalFieldView::secret(
                    "Vault Passphrase",
                    self.target_vault_passphrase.chars_count(),
                    self.active_field == RestoreBackupField::TargetVaultPassphrase,
                ),
                ModalFieldView::secret(
                    "Confirm",
                    self.confirmation.chars_count(),
                    self.active_field == RestoreBackupField::Confirmation,
                ),
                ModalFieldView::plain(
                    "Replace",
                    self.overwrite_confirmation.clone(),
                    self.active_field == RestoreBackupField::OverwriteConfirmation,
                ),
            ],
            hint: hint.to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum RestoreBackupField {
    #[default]
    BackupPath,
    BackupPassphrase,
    TargetVaultPath,
    TargetVaultPassphrase,
    Confirmation,
    OverwriteConfirmation,
}

impl RestoreBackupField {
    fn next(self) -> Self {
        match self {
            Self::BackupPath => Self::BackupPassphrase,
            Self::BackupPassphrase => Self::TargetVaultPath,
            Self::TargetVaultPath => Self::TargetVaultPassphrase,
            Self::TargetVaultPassphrase => Self::Confirmation,
            Self::Confirmation => Self::OverwriteConfirmation,
            Self::OverwriteConfirmation => Self::BackupPath,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::BackupPath => Self::OverwriteConfirmation,
            Self::BackupPassphrase => Self::BackupPath,
            Self::TargetVaultPath => Self::BackupPassphrase,
            Self::TargetVaultPassphrase => Self::TargetVaultPath,
            Self::Confirmation => Self::TargetVaultPassphrase,
            Self::OverwriteConfirmation => Self::Confirmation,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum AddEntryField {
    #[default]
    Issuer,
    AccountLabel,
    SecretBase32,
    Algorithm,
    Digits,
    Period,
}

impl AddEntryField {
    fn next(self) -> Self {
        match self {
            Self::Issuer => Self::AccountLabel,
            Self::AccountLabel => Self::SecretBase32,
            Self::SecretBase32 => Self::Algorithm,
            Self::Algorithm => Self::Digits,
            Self::Digits => Self::Period,
            Self::Period => Self::Issuer,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Issuer => Self::Period,
            Self::AccountLabel => Self::Issuer,
            Self::SecretBase32 => Self::AccountLabel,
            Self::Algorithm => Self::SecretBase32,
            Self::Digits => Self::Algorithm,
            Self::Period => Self::Digits,
        }
    }
}

fn edit_text_field(field: &mut String, key: KeyEvent) {
    match key.code {
        KeyCode::Backspace => {
            field.pop();
        }
        KeyCode::Char(character) if key.modifiers == KeyModifiers::NONE => {
            field.push(character);
        }
        KeyCode::Char(character) if key.modifiers == KeyModifiers::SHIFT => {
            field.push(character);
        }
        _ => {}
    }
}

fn edit_sensitive_field(field: &mut SensitiveText, key: KeyEvent) {
    match key.code {
        KeyCode::Backspace => field.pop(),
        KeyCode::Char(character) if key.modifiers == KeyModifiers::NONE => {
            let _ = field.push_char(character);
        }
        KeyCode::Char(character) if key.modifiers == KeyModifiers::SHIFT => {
            let _ = field.push_char(character);
        }
        _ => {}
    }
}

fn empty_to_none_ref(value: &str) -> Option<&str> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn suggested_backup_path(vault_path: &std::path::Path) -> String {
    let policy = albus::BackupPolicy::default();
    let parent = vault_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = vault_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("vault");
    parent
        .join(format!("{stem}-backup.{}", policy.backup_extension))
        .display()
        .to_string()
}

fn idle_lock_timeout_to_apply(
    snapshot: &AppSnapshot,
    idle_lock_policy: Option<IdleLockPolicy>,
    idle_elapsed: Duration,
) -> Option<u64> {
    let idle_lock_policy = idle_lock_policy?;
    if matches!(snapshot, AppSnapshot::Unlocked(view) if !view.dirty)
        && idle_elapsed >= idle_lock_policy.timeout()
    {
        Some(idle_lock_policy.timeout_secs)
    } else {
        None
    }
}

fn idle_lock_policy_from_env(value: Option<&str>) -> Option<IdleLockPolicy> {
    let normalized = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default();
    if normalized.is_empty() {
        return Some(IdleLockPolicy {
            timeout_secs: DEFAULT_IDLE_LOCK_SECS,
        });
    }

    match normalized.parse::<u64>() {
        Ok(0) => None,
        Ok(timeout_secs) => Some(IdleLockPolicy { timeout_secs }),
        Err(_) => Some(IdleLockPolicy {
            timeout_secs: DEFAULT_IDLE_LOCK_SECS,
        }),
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::{
        AddEntryField, AddEntryForm, AppSnapshot, ChangePassphraseField, ChangePassphraseForm,
        DEFAULT_IDLE_LOCK_SECS, EditEntryForm, ExportBackupForm, IdleLockPolicy, ImportUriForm,
        ModalFieldView, PassphraseForm, RestoreBackupForm, edit_sensitive_field,
        idle_lock_policy_from_env, idle_lock_timeout_to_apply,
    };
    use crate::sensitive_text::SensitiveText;
    use crate::{AppController, AppState, Clock, EditEntryInput, LockedView, RememberedVaultPath};
    use std::time::Duration;
    use tempfile::TempDir;
    use time::OffsetDateTime;

    #[derive(Clone, Copy, Debug)]
    struct FixedClock {
        now: OffsetDateTime,
    }

    impl Clock for FixedClock {
        fn now_utc(&self) -> OffsetDateTime {
            self.now
        }
    }

    #[test]
    fn secret_modal_fields_store_only_mask_lengths() {
        let form = PassphraseForm {
            passphrase: SensitiveText::from("secret-passphrase"),
        };

        let view = form.unlock_view();

        assert_eq!(
            view.fields,
            vec![ModalFieldView::secret(
                "Passphrase",
                "secret-passphrase".len(),
                true
            )]
        );
    }

    #[test]
    fn add_edit_import_and_backup_forms_redact_secret_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let add_form = AddEntryForm {
            secret_base32: SensitiveText::from("JBSWY3DPEHPK3PXP"),
            ..AddEntryForm::default()
        };

        let import_form = ImportUriForm {
            uri: SensitiveText::from(
                "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
            ),
        };

        let mut edit_form = EditEntryForm::new(EditEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: String::new(),
            algorithm: None,
            digits: None,
            period: None,
        });
        edit_form.secret_base32 = SensitiveText::from("KRUGS4ZANFZSAYJA");

        let change_form = ChangePassphraseForm {
            current_passphrase: SensitiveText::from("current-passphrase"),
            new_passphrase: SensitiveText::from("new-passphrase"),
            confirmation: SensitiveText::from("new-passphrase"),
            ..ChangePassphraseForm::default()
        };

        let mut export_form = ExportBackupForm::new("backup.albusbak".to_owned());
        export_form.backup_passphrase = SensitiveText::from("backup-passphrase");
        export_form.confirmation = SensitiveText::from("backup-passphrase");

        let mut restore_form =
            RestoreBackupForm::new("backup.albusbak".to_owned(), "vault.albus".to_owned());
        restore_form.backup_passphrase = SensitiveText::from("backup-passphrase");
        restore_form.target_vault_passphrase = SensitiveText::from("vault-passphrase");
        restore_form.confirmation = SensitiveText::from("vault-passphrase");

        for (view, label, expected_len) in [
            (
                add_form.view(),
                "Secret",
                add_form.secret_base32.chars_count(),
            ),
            (
                import_form.view(),
                "otpauth://",
                import_form.uri.chars_count(),
            ),
            (
                edit_form.view(),
                "Secret",
                edit_form.secret_base32.chars_count(),
            ),
            (
                change_form.view(),
                "Current",
                change_form.current_passphrase.chars_count(),
            ),
            (
                export_form.view(),
                "Backup Passphrase",
                export_form.backup_passphrase.chars_count(),
            ),
            (
                restore_form.view(),
                "Backup Passphrase",
                restore_form.backup_passphrase.chars_count(),
            ),
        ] {
            let field = view
                .fields
                .iter()
                .find(|field| field.label == label)
                .ok_or("expected secret field in modal view")?;
            assert_eq!(field.value, "");
            assert_eq!(field.secret_len, Some(expected_len));
        }
        Ok(())
    }

    #[test]
    fn sensitive_modal_fields_accept_repeated_edits_without_visible_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut add_form = AddEntryForm {
            active_field: AddEntryField::SecretBase32,
            ..AddEntryForm::default()
        };
        for character in "JBSWY3DPEHPK3PXP".chars() {
            edit_sensitive_field(&mut add_form.secret_base32, key(character));
        }
        for _ in 0..4 {
            edit_sensitive_field(&mut add_form.secret_base32, backspace_key());
        }
        for character in "TEST".chars() {
            edit_sensitive_field(&mut add_form.secret_base32, key(character));
        }

        let mut change_form = ChangePassphraseForm {
            active_field: ChangePassphraseField::NewPassphrase,
            ..ChangePassphraseForm::default()
        };
        for character in "correct horse battery staple".chars() {
            edit_sensitive_field(&mut change_form.new_passphrase, key(character));
        }
        edit_sensitive_field(&mut change_form.new_passphrase, backspace_key());
        edit_sensitive_field(&mut change_form.new_passphrase, key('!'));

        let add_secret = add_form
            .view()
            .fields
            .into_iter()
            .find(|field| field.label == "Secret")
            .ok_or("expected secret field")?;
        assert_eq!(add_form.secret_base32.as_str(), "JBSWY3DPEHPKTEST");
        assert_eq!(
            add_secret.secret_len,
            Some("JBSWY3DPEHPKTEST".chars().count())
        );
        assert_eq!(add_secret.value, "");

        let new_passphrase = change_form
            .view()
            .fields
            .into_iter()
            .find(|field| field.label == "New")
            .ok_or("expected new passphrase field")?;
        assert_eq!(
            change_form.new_passphrase.as_str(),
            "correct horse battery stapl!"
        );
        assert_eq!(
            new_passphrase.secret_len,
            Some("correct horse battery stapl!".chars().count())
        );
        assert_eq!(new_passphrase.value, "");
        Ok(())
    }

    #[test]
    fn idle_lock_defaults_to_five_minutes() {
        assert_eq!(
            idle_lock_policy_from_env(None),
            Some(super::IdleLockPolicy {
                timeout_secs: DEFAULT_IDLE_LOCK_SECS,
            })
        );
    }

    #[test]
    fn idle_lock_can_be_disabled_with_zero() {
        assert_eq!(idle_lock_policy_from_env(Some("0")), None);
    }

    #[test]
    fn idle_lock_uses_custom_env_values() {
        assert_eq!(
            idle_lock_policy_from_env(Some("900")),
            Some(super::IdleLockPolicy { timeout_secs: 900 })
        );
    }

    #[test]
    fn idle_lock_only_applies_to_clean_unlocked_sessions_after_timeout()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let remembered = RememberedVaultPath::new(
            tempdir
                .path()
                .join("config")
                .join("remembered-vault-path.txt"),
            tempdir.path().join("vault.albus"),
        );
        let mut controller = AppController::initialize(
            FixedClock {
                now: OffsetDateTime::from_unix_timestamp(1_717_171_717)?,
            },
            remembered,
        )?;

        controller.create_vault(
            tempdir.path().join("idle-lock.albus"),
            "correct horse battery staple".to_owned(),
            "correct horse battery staple".to_owned(),
        )?;
        controller.unlock("correct horse battery staple".to_owned())?;

        let snapshot = controller.snapshot()?;
        assert_eq!(
            idle_lock_timeout_to_apply(
                &snapshot,
                Some(IdleLockPolicy { timeout_secs: 5 }),
                Duration::from_secs(5),
            ),
            Some(5)
        );

        controller.add_entry(crate::AddEntryInput {
            issuer: "Example".to_owned(),
            account_label: "alice@example.com".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: None,
            digits: None,
            period: None,
        })?;

        let dirty_snapshot = controller.snapshot()?;
        assert_eq!(
            idle_lock_timeout_to_apply(
                &dirty_snapshot,
                Some(IdleLockPolicy { timeout_secs: 5 }),
                Duration::from_secs(30),
            ),
            None
        );
        assert_eq!(controller.state(), AppState::Unlocked);
        assert_eq!(
            idle_lock_timeout_to_apply(
                &AppSnapshot::Locked(LockedView {
                    vault_path: tempdir.path().join("idle-lock.albus"),
                    known_entry_count: Some(1),
                    status_message: None,
                }),
                Some(IdleLockPolicy { timeout_secs: 5 }),
                Duration::from_secs(30),
            ),
            None
        );
        Ok(())
    }

    fn key(character: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE)
    }

    fn backspace_key() -> KeyEvent {
        KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE)
    }
}
