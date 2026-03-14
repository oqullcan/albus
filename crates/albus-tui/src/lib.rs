#![deny(unsafe_code)]
#![doc = "Minimal terminal authenticator shell for Albus."]

mod app;
mod clock;
mod device_binding;
mod error;
#[allow(unsafe_code)]
mod process_hardening;
mod remembered_path;
mod runtime;
#[allow(unsafe_code)]
mod sensitive_text;
mod trust_anchor;
mod ui;

pub use app::{
    AddEntryInput, AppController, AppSnapshot, AppState, BackupExportInput, BackupRestoreInput,
    ChangePassphraseInput, DeleteEntryInput, EditEntryInput, EntryDetail, EntryListItem,
    ImportUriInput, LockedView, NoVaultView, UnlockedView,
};
pub use clock::{Clock, SystemClock};
pub use error::AppError;
pub use remembered_path::RememberedVaultPath;
pub use runtime::run;
