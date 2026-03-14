use std::{
    fs,
    path::{Path, PathBuf},
};

use albus::{harden_private_directory, harden_private_file};
use directories::ProjectDirs;

use crate::AppError;

const PROJECT_DIR_OVERRIDE_ENV: &str = "ALBUS_PROJECT_DIR";
const CONFIG_DIR_NAME: &str = "config";
const DATA_DIR_NAME: &str = "data";

/// Secret-free local helper that remembers the selected vault path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RememberedVaultPath {
    config_file: PathBuf,
    suggested_vault_path: PathBuf,
    store_enabled: bool,
}

impl RememberedVaultPath {
    /// Creates a helper with explicit filesystem paths.
    #[must_use]
    pub fn new(config_file: PathBuf, suggested_vault_path: PathBuf) -> Self {
        Self::with_store_enabled(config_file, suggested_vault_path, true)
    }

    /// Creates a helper with explicit filesystem paths and an explicit local
    /// persistence policy.
    #[must_use]
    pub fn with_store_enabled(
        config_file: PathBuf,
        suggested_vault_path: PathBuf,
        store_enabled: bool,
    ) -> Self {
        Self {
            config_file,
            suggested_vault_path,
            store_enabled,
        }
    }

    /// Creates a helper using the local Albus project directories.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when the platform-specific project directories are
    /// unavailable.
    pub fn for_project_dirs() -> Result<Self, AppError> {
        let store_enabled =
            store_enabled_from_env(std::env::var_os("ALBUS_REMEMBER_VAULT_PATH").as_deref());
        if let Some(root) =
            project_dir_override_from_env(std::env::var_os(PROJECT_DIR_OVERRIDE_ENV).as_deref())
        {
            return Ok(Self::from_local_state_root(root.as_path(), store_enabled));
        }

        let Some(project_dirs) = ProjectDirs::from("io", "albus-auth", "albus") else {
            return Err(AppError::ProjectDirsUnavailable);
        };

        Ok(Self::with_store_enabled(
            project_dirs.config_dir().join("remembered-vault-path.txt"),
            project_dirs.data_local_dir().join("vault.albus"),
            store_enabled,
        ))
    }

    /// Returns the path of the local remembered-vault config file.
    #[must_use]
    pub fn config_file(&self) -> &Path {
        &self.config_file
    }

    /// Returns the default vault path suggested in the create flow.
    #[must_use]
    pub fn suggested_vault_path(&self) -> &Path {
        &self.suggested_vault_path
    }

    /// Returns whether plaintext remembered-path persistence is enabled.
    #[must_use]
    pub const fn store_enabled(&self) -> bool {
        self.store_enabled
    }

    /// Loads the remembered vault path, if any.
    ///
    /// Empty files are treated as missing configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when the file cannot be read.
    pub fn load(&self) -> Result<Option<PathBuf>, AppError> {
        if !self.store_enabled {
            return Ok(None);
        }

        match fs::read_to_string(&self.config_file) {
            Ok(contents) => {
                let normalized = contents.trim();
                if normalized.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(PathBuf::from(normalized)))
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(AppError::Io(error)),
        }
    }

    /// Stores the remembered vault path.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when the parent directory cannot be created or the
    /// file cannot be written.
    pub fn store(&self, path: &Path) -> Result<(), AppError> {
        if !self.store_enabled {
            return self.clear();
        }

        if let Some(parent) = self.config_file.parent() {
            let existed = parent.exists();
            fs::create_dir_all(parent)?;
            if !existed {
                harden_private_directory(parent)?;
            }
        }

        fs::write(&self.config_file, path.to_string_lossy().as_ref())?;
        harden_private_file(&self.config_file)?;
        Ok(())
    }

    /// Removes the remembered local vault path, if present.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when an existing config file cannot be removed.
    pub fn clear(&self) -> Result<(), AppError> {
        match fs::remove_file(&self.config_file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AppError::Io(error)),
        }
    }

    fn from_local_state_root(root: &Path, store_enabled: bool) -> Self {
        Self::with_store_enabled(
            root.join(CONFIG_DIR_NAME).join("remembered-vault-path.txt"),
            root.join(DATA_DIR_NAME).join("vault.albus"),
            store_enabled,
        )
    }
}

fn store_enabled_from_env(value: Option<&std::ffi::OsStr>) -> bool {
    let Some(value) = value else {
        return false;
    };

    matches!(
        value.to_string_lossy().trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn project_dir_override_from_env(value: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let value = value?;
    let normalized = value.to_string_lossy().trim().to_owned();
    if normalized.is_empty() {
        None
    } else {
        Some(PathBuf::from(normalized))
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{project_dir_override_from_env, store_enabled_from_env};
    use crate::RememberedVaultPath;
    use tempfile::TempDir;

    #[test]
    fn remembered_path_defaults_to_disabled_without_opt_in() {
        assert!(!store_enabled_from_env(None));
    }

    #[test]
    fn remembered_path_env_opt_in_accepts_common_truthy_values() {
        for candidate in ["1", "true", "TRUE", "yes", "on"] {
            assert!(store_enabled_from_env(Some(candidate.as_ref())));
        }
    }

    #[test]
    fn remembered_path_env_opt_in_rejects_other_values() {
        for candidate in ["0", "false", "no", "off", "random"] {
            assert!(!store_enabled_from_env(Some(candidate.as_ref())));
        }
    }

    #[test]
    fn project_dir_override_uses_trimmed_non_empty_path() {
        let path = project_dir_override_from_env(Some("  C:\\isolated-albus  ".as_ref()));
        assert_eq!(path, Some(PathBuf::from("C:\\isolated-albus")));
    }

    #[test]
    fn project_dir_override_rejects_empty_values() {
        assert_eq!(project_dir_override_from_env(Some("   ".as_ref())), None);
        assert_eq!(project_dir_override_from_env(None), None);
    }

    #[test]
    fn local_state_root_override_derives_config_and_data_paths() {
        let helper =
            RememberedVaultPath::from_local_state_root(Path::new("C:\\isolated-albus"), false);

        assert_eq!(
            helper.config_file(),
            Path::new("C:\\isolated-albus")
                .join("config")
                .join("remembered-vault-path.txt")
                .as_path()
        );
        assert_eq!(
            helper.suggested_vault_path(),
            Path::new("C:\\isolated-albus")
                .join("data")
                .join("vault.albus")
                .as_path()
        );
        assert!(!helper.store_enabled());
    }

    #[test]
    fn disabled_store_removes_any_existing_plaintext_path_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let config_file = tempdir.path().join("remembered-vault-path.txt");
        let helper = RememberedVaultPath::with_store_enabled(
            config_file.clone(),
            tempdir.path().join("vault.albus"),
            false,
        );
        std::fs::write(&config_file, "C:\\sensitive\\vault.albus")?;

        helper.store(tempdir.path().join("ignored.albus").as_path())?;

        assert!(!config_file.exists());
        assert_eq!(helper.load()?, None);
        Ok(())
    }
}
