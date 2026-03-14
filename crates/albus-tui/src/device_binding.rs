use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(windows)]
use std::process::Command;

use albus::{
    LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI, LOCAL_BINDING_SCOPE_CURRENT_USER, LocalBindingHeader,
    harden_private_directory, harden_private_file, random_bytes,
};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::AppError;

const STATE_DIR_NAME: &str = "device-bindings-v1";
const DEVICE_SECRET_LEN: usize = 32;

/// Local device-binding policy for newly written vaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeviceBindingPreference {
    /// Do not enable local device binding for newly written vaults.
    Disabled,
    /// Require Windows DPAPI-backed local device binding for newly written vaults.
    WindowsDpapiCurrentUser,
}

/// Derived passphrase material plus whether a fresh local secret was created.
#[derive(Debug)]
pub(crate) struct PreparedPassphrase {
    value: Zeroizing<String>,
    created_secret: bool,
}

impl PreparedPassphrase {
    /// Returns the derived passphrase bytes as a string slice.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        self.value.as_str()
    }

    /// Returns whether this operation created a new local secret file.
    #[must_use]
    pub(crate) const fn created_secret(&self) -> bool {
        self.created_secret
    }
}

/// Local store for host-bound vault augmentation secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceBindingStore {
    state_dir: PathBuf,
    preference: DeviceBindingPreference,
}

impl DeviceBindingStore {
    /// Creates a binding store next to the local config file using env-based policy.
    #[must_use]
    pub(crate) fn from_config_file(config_file: &Path) -> Self {
        let parent = config_file.parent().unwrap_or_else(|| Path::new("."));
        Self::new(
            parent.join(STATE_DIR_NAME),
            preference_from_env(std::env::var_os("ALBUS_ENABLE_DEVICE_BINDING").as_deref()),
        )
    }

    /// Creates a binding store with explicit paths and policy.
    #[must_use]
    pub(crate) fn new(state_dir: PathBuf, preference: DeviceBindingPreference) -> Self {
        Self {
            state_dir,
            preference,
        }
    }

    /// Returns the local binding header for newly written vaults, if requested.
    pub(crate) fn requested_binding(&self) -> Result<Option<LocalBindingHeader>, AppError> {
        match self.preference {
            DeviceBindingPreference::Disabled => Ok(None),
            DeviceBindingPreference::WindowsDpapiCurrentUser => {
                let binding = windows_dpapi_binding_header();
                ensure_provider_available(Some(&binding))?;
                Ok(Some(binding))
            }
        }
    }

    /// Returns a derived passphrase for a newly created or restored bound vault.
    pub(crate) fn prepare_for_new_vault(
        &self,
        vault_id: &str,
        passphrase: &str,
        binding: Option<&LocalBindingHeader>,
    ) -> Result<PreparedPassphrase, AppError> {
        let Some(binding) = binding else {
            return Ok(PreparedPassphrase {
                value: Zeroizing::new(passphrase.to_owned()),
                created_secret: false,
            });
        };

        ensure_provider_available(Some(binding))?;
        let (secret, created_secret) = self.load_or_create_secret(vault_id, binding)?;
        Ok(PreparedPassphrase {
            value: compose_effective_passphrase(passphrase, secret.as_slice()),
            created_secret,
        })
    }

    /// Returns a derived passphrase for an existing bound vault on this host.
    pub(crate) fn prepare_for_existing_vault(
        &self,
        vault_id: &str,
        passphrase: &str,
        binding: Option<&LocalBindingHeader>,
    ) -> Result<PreparedPassphrase, AppError> {
        let Some(binding) = binding else {
            return Ok(PreparedPassphrase {
                value: Zeroizing::new(passphrase.to_owned()),
                created_secret: false,
            });
        };

        ensure_provider_available(Some(binding))?;
        let secret = self.load_secret(vault_id, binding)?;
        Ok(PreparedPassphrase {
            value: compose_effective_passphrase(passphrase, secret.as_slice()),
            created_secret: false,
        })
    }

    /// Removes a locally persisted binding secret if present.
    pub(crate) fn clear(&self, vault_id: &str) -> Result<(), AppError> {
        match fs::remove_file(self.state_file(vault_id)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AppError::Io(error)),
        }
    }

    fn load_or_create_secret(
        &self,
        vault_id: &str,
        binding: &LocalBindingHeader,
    ) -> Result<(Zeroizing<Vec<u8>>, bool), AppError> {
        let state_file = self.state_file(vault_id);
        match fs::read(&state_file) {
            Ok(bytes) => Ok((Self::decode_state(vault_id, binding, &bytes)?, false)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let secret = Zeroizing::new(random_bytes(DEVICE_SECRET_LEN)?);
                let protected = protect_bytes(secret.as_slice(), binding)?;
                let state = StoredBindingState {
                    provider: binding.provider.clone(),
                    scope: binding.scope.clone(),
                    protected_key_b64: BASE64.encode(protected.as_slice()),
                };
                Self::write_state(&state_file, &state)?;
                Ok((secret, true))
            }
            Err(error) => Err(AppError::Io(error)),
        }
    }

    fn load_secret(
        &self,
        vault_id: &str,
        binding: &LocalBindingHeader,
    ) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let state_file = self.state_file(vault_id);
        let bytes = match fs::read(&state_file) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(AppError::MissingDeviceBindingKey {
                    vault_id: vault_id.to_owned(),
                });
            }
            Err(error) => return Err(AppError::Io(error)),
        };

        Self::decode_state(vault_id, binding, &bytes)
    }

    fn decode_state(
        vault_id: &str,
        binding: &LocalBindingHeader,
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let state: StoredBindingState =
            serde_json::from_slice(bytes).map_err(AppError::InvalidDeviceBindingState)?;
        if state.provider != binding.provider || state.scope != binding.scope {
            return Err(AppError::DeviceBindingUnavailable {
                provider: binding.provider.clone(),
            });
        }

        let protected = BASE64
            .decode(state.protected_key_b64.as_bytes())
            .map_err(|_| AppError::MissingDeviceBindingKey {
                vault_id: vault_id.to_owned(),
            })?;
        let protected = Zeroizing::new(protected);
        let secret = unprotect_bytes(protected.as_slice(), binding)?;
        if secret.len() != DEVICE_SECRET_LEN {
            return Err(AppError::MissingDeviceBindingKey {
                vault_id: vault_id.to_owned(),
            });
        }

        Ok(secret)
    }

    fn write_state(state_file: &Path, state: &StoredBindingState) -> Result<(), AppError> {
        if let Some(parent) = state_file.parent() {
            let existed = parent.exists();
            fs::create_dir_all(parent)?;
            if !existed {
                harden_private_directory(parent)?;
            }
        }

        let encoded = serde_json::to_vec(state).map_err(AppError::InvalidDeviceBindingState)?;
        fs::write(state_file, encoded)?;
        harden_private_file(state_file)?;
        Ok(())
    }

    fn state_file(&self, vault_id: &str) -> PathBuf {
        self.state_dir
            .join(format!("{}.json", sanitize_vault_id(vault_id)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBindingState {
    provider: String,
    scope: String,
    protected_key_b64: String,
}

fn windows_dpapi_binding_header() -> LocalBindingHeader {
    LocalBindingHeader {
        provider: LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI.to_owned(),
        scope: LOCAL_BINDING_SCOPE_CURRENT_USER.to_owned(),
    }
}

fn preference_from_env(value: Option<&std::ffi::OsStr>) -> DeviceBindingPreference {
    let Some(value) = value else {
        return DeviceBindingPreference::Disabled;
    };

    let normalized = value.to_string_lossy().trim().to_ascii_lowercase();
    if matches!(normalized.as_str(), "1" | "true" | "yes" | "on") {
        DeviceBindingPreference::WindowsDpapiCurrentUser
    } else {
        DeviceBindingPreference::Disabled
    }
}

fn sanitize_vault_id(vault_id: &str) -> String {
    let mut normalized = String::with_capacity(vault_id.len());
    for character in vault_id.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
            normalized.push(character);
        } else {
            normalized.push('_');
        }
    }

    if normalized.is_empty() {
        "vault".to_owned()
    } else {
        normalized
    }
}

fn compose_effective_passphrase(passphrase: &str, secret: &[u8]) -> Zeroizing<String> {
    let encoded_secret = BASE64.encode(secret);
    Zeroizing::new(format!("{passphrase}\0albus-device:{encoded_secret}"))
}

fn ensure_provider_available(binding: Option<&LocalBindingHeader>) -> Result<(), AppError> {
    let Some(binding) = binding else {
        return Ok(());
    };

    if binding.provider != LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI
        || binding.scope != LOCAL_BINDING_SCOPE_CURRENT_USER
    {
        return Err(AppError::DeviceBindingUnavailable {
            provider: binding.provider.clone(),
        });
    }

    #[cfg(windows)]
    {
        Ok(())
    }

    #[cfg(not(windows))]
    {
        Err(AppError::DeviceBindingUnavailable {
            provider: binding.provider.clone(),
        })
    }
}

fn protect_bytes(
    bytes: &[u8],
    binding: &LocalBindingHeader,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    ensure_provider_available(Some(binding))?;
    let encoded = BASE64.encode(bytes);
    run_windows_protected_data(encoded.as_str(), DpapiOperation::Protect)
}

fn unprotect_bytes(
    bytes: &[u8],
    binding: &LocalBindingHeader,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    ensure_provider_available(Some(binding))?;
    let encoded = BASE64.encode(bytes);
    run_windows_protected_data(encoded.as_str(), DpapiOperation::Unprotect)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DpapiOperation {
    Protect,
    Unprotect,
}

fn run_windows_protected_data(
    input_b64: &str,
    operation: DpapiOperation,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    #[cfg(windows)]
    {
        let script = match operation {
            DpapiOperation::Protect => {
                "Add-Type -AssemblyName System.Security; [Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Protect([Convert]::FromBase64String($env:ALBUS_DPAPI_INPUT_B64), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))"
            }
            DpapiOperation::Unprotect => {
                "Add-Type -AssemblyName System.Security; [Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($env:ALBUS_DPAPI_INPUT_B64), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))"
            }
        };

        let output = Command::new("powershell.exe")
            .env("ALBUS_DPAPI_INPUT_B64", input_b64)
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let detail = if stderr.is_empty() { stdout } else { stderr };
            return Err(AppError::DeviceBindingService(detail));
        }

        let normalized = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let decoded = BASE64
            .decode(normalized.as_bytes())
            .map_err(|_| AppError::DeviceBindingService("unexpected DPAPI response".to_owned()))?;
        Ok(Zeroizing::new(decoded))
    }

    #[cfg(not(windows))]
    {
        let _ = input_b64;
        let _ = operation;
        Err(AppError::DeviceBindingUnavailable {
            provider: LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DeviceBindingPreference, compose_effective_passphrase, preference_from_env,
        sanitize_vault_id,
    };
    #[cfg(windows)]
    use super::{DeviceBindingStore, windows_dpapi_binding_header};
    #[cfg(windows)]
    use tempfile::TempDir;

    #[test]
    fn device_binding_defaults_to_disabled_without_opt_in() {
        assert_eq!(preference_from_env(None), DeviceBindingPreference::Disabled);
    }

    #[test]
    fn device_binding_env_opt_in_accepts_common_truthy_values() {
        for candidate in ["1", "true", "TRUE", "yes", "on"] {
            assert_eq!(
                preference_from_env(Some(candidate.as_ref())),
                DeviceBindingPreference::WindowsDpapiCurrentUser
            );
        }
    }

    #[test]
    fn sanitize_vault_id_normalizes_non_filename_characters() {
        assert_eq!(sanitize_vault_id("vault:/id"), "vault__id");
    }

    #[test]
    fn composed_passphrase_changes_when_secret_is_present() {
        let composed = compose_effective_passphrase("passphrase", &[0x11; 4]);
        assert_ne!(composed.as_str(), "passphrase");
        assert!(composed.as_str().starts_with("passphrase"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_dpapi_store_round_trips_the_same_secret() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let store = DeviceBindingStore::new(
            tempdir.path().join("bindings"),
            DeviceBindingPreference::WindowsDpapiCurrentUser,
        );
        let binding = windows_dpapi_binding_header();

        let prepared = store.prepare_for_new_vault("vault-1", "passphrase", Some(&binding))?;
        let loaded = store.prepare_for_existing_vault("vault-1", "passphrase", Some(&binding))?;

        assert_eq!(prepared.as_str(), loaded.as_str());
        Ok(())
    }
}
