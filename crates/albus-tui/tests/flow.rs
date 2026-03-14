#![allow(missing_docs)]

use albus::{TotpGenerator, parse_totp_uri};
use albus_tui::{
    AddEntryInput, AppController, AppSnapshot, BackupExportInput, BackupRestoreInput,
    ChangePassphraseInput, Clock, DeleteEntryInput, EditEntryInput, ImportUriInput,
    RememberedVaultPath,
};
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

fn fixed_clock() -> Result<FixedClock, Box<dyn std::error::Error>> {
    Ok(FixedClock {
        now: OffsetDateTime::from_unix_timestamp(2_000_000_000)?,
    })
}

#[test]
fn create_unlock_add_export_restore_unlock_round_trip_is_usable()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = TempDir::new()?;
    let remembered = RememberedVaultPath::new(
        tempdir
            .path()
            .join("config")
            .join("remembered-vault-path.txt"),
        tempdir.path().join("vault.albus"),
    );
    let vault_path = tempdir.path().join("primary.albus");
    let backup_path = tempdir.path().join("primary-backup.albusbak");
    let restored_vault_path = tempdir.path().join("restored.albus");
    let clock = fixed_clock()?;
    let mut controller = AppController::initialize(clock, remembered)?;

    controller.create_vault(
        vault_path,
        "correct horse battery staple".to_owned(),
        "correct horse battery staple".to_owned(),
    )?;
    controller.unlock("correct horse battery staple".to_owned())?;
    controller.add_entry(AddEntryInput {
        issuer: "Example".to_owned(),
        account_label: "alice@example.com".to_owned(),
        secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
        algorithm: None,
        digits: None,
        period: None,
    })?;
    controller.export_backup(BackupExportInput {
        backup_path,
        backup_passphrase: "backup-passphrase".to_owned(),
        confirmation: "backup-passphrase".to_owned(),
    })?;
    controller.lock_without_saving()?;
    controller.restore_backup(BackupRestoreInput {
        backup_path: tempdir.path().join("primary-backup.albusbak"),
        backup_passphrase: "backup-passphrase".to_owned(),
        target_vault_path: restored_vault_path.clone(),
        target_vault_passphrase: "restored-vault-passphrase".to_owned(),
        confirmation: "restored-vault-passphrase".to_owned(),
        replace_existing: false,
    })?;
    controller.unlock("restored-vault-passphrase".to_owned())?;

    let AppSnapshot::Unlocked(view) = controller.snapshot()? else {
        return Err("controller is not unlocked after the second unlock".into());
    };
    assert_eq!(view.entries.len(), 1);

    let Some(detail) = view.selected_detail else {
        return Err("expected a selected entry detail".into());
    };
    let parameters = parse_totp_uri(
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    )?;
    let expected = TotpGenerator::generate(&parameters, clock.now_unix_timestamp())?;

    assert_eq!(detail.code, expected.code());
    assert_eq!(detail.valid_for_secs, expected.valid_for_secs());
    assert_eq!(detail.issuer, "Example");
    assert_eq!(detail.account_label, "alice@example.com");
    Ok(())
}

#[test]
fn change_passphrase_and_delete_entry_round_trip_stays_usable()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = TempDir::new()?;
    let remembered = RememberedVaultPath::new(
        tempdir
            .path()
            .join("config")
            .join("remembered-vault-path.txt"),
        tempdir.path().join("vault.albus"),
    );
    let vault_path = tempdir.path().join("primary.albus");
    let clock = fixed_clock()?;
    let mut controller = AppController::initialize(clock, remembered)?;

    controller.create_vault(
        vault_path,
        "correct horse battery staple".to_owned(),
        "correct horse battery staple".to_owned(),
    )?;
    controller.unlock("correct horse battery staple".to_owned())?;
    controller.add_entry(AddEntryInput {
        issuer: "Example".to_owned(),
        account_label: "alice@example.com".to_owned(),
        secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
        algorithm: None,
        digits: None,
        period: None,
    })?;
    controller.change_passphrase(ChangePassphraseInput {
        current_passphrase: "correct horse battery staple".to_owned(),
        new_passphrase: "new vault passphrase".to_owned(),
        confirmation: "new vault passphrase".to_owned(),
    })?;
    controller.unlock("new vault passphrase".to_owned())?;
    controller.delete_selected_entry(DeleteEntryInput {
        confirmation: "DELETE".to_owned(),
    })?;
    controller.save_and_lock(Some("new vault passphrase".to_owned()))?;
    controller.unlock("new vault passphrase".to_owned())?;

    let AppSnapshot::Unlocked(view) = controller.snapshot()? else {
        return Err("controller is not unlocked after passphrase change and delete".into());
    };
    assert!(view.entries.is_empty());
    assert!(view.selected_detail.is_none());
    Ok(())
}

#[test]
fn import_and_edit_round_trip_stays_usable() -> Result<(), Box<dyn std::error::Error>> {
    let tempdir = TempDir::new()?;
    let remembered = RememberedVaultPath::new(
        tempdir
            .path()
            .join("config")
            .join("remembered-vault-path.txt"),
        tempdir.path().join("vault.albus"),
    );
    let vault_path = tempdir.path().join("primary.albus");
    let clock = fixed_clock()?;
    let mut controller = AppController::initialize(clock, remembered)?;

    controller.create_vault(
        vault_path,
        "correct horse battery staple".to_owned(),
        "correct horse battery staple".to_owned(),
    )?;
    controller.unlock("correct horse battery staple".to_owned())?;
    controller.import_entry_uri(ImportUriInput {
        uri: "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
            .to_owned(),
    })?;
    controller.edit_selected_entry(EditEntryInput {
        issuer: "Updated".to_owned(),
        account_label: "bob@example.com".to_owned(),
        secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
        algorithm: Some("SHA512".to_owned()),
        digits: Some("8".to_owned()),
        period: Some("45".to_owned()),
    })?;

    let AppSnapshot::Unlocked(view) = controller.snapshot()? else {
        return Err("controller is not unlocked after import and edit".into());
    };
    assert_eq!(view.entries.len(), 1);
    let Some(detail) = view.selected_detail else {
        return Err("expected a selected entry detail".into());
    };
    let parameters = parse_totp_uri(
        "otpauth://totp/Updated:bob@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Updated&algorithm=SHA512&digits=8&period=45",
    )?;
    let expected = TotpGenerator::generate(&parameters, clock.now_unix_timestamp())?;

    assert_eq!(detail.code, expected.code());
    assert_eq!(detail.valid_for_secs, expected.valid_for_secs());
    assert_eq!(detail.issuer, "Updated");
    assert_eq!(detail.account_label, "bob@example.com");
    Ok(())
}
