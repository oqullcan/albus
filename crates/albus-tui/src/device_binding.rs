use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::HashMap;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::OnceLock;

#[cfg(windows)]
use windows_dpapi::{Scope, decrypt_data, encrypt_data};

use albus::{
    LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE, LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN,
    LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI, LOCAL_BINDING_SCOPE_CURRENT_USER, LocalBindingHeader,
    random_bytes,
};
use data_encoding::BASE64;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use keyring_core::{Entry as KeyringEntry, Error as KeyringError, set_default_store};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    AppError,
    private_fs::{read_limited_file, write_private_file_atomic},
};

const STATE_DIR_NAME: &str = "device-bindings-v1";
const DEVICE_SECRET_LEN: usize = 32;
const MAX_BINDING_STATE_LEN: u64 = 16 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const KEYRING_SERVICE_NAME: &str = "io.albus.device-binding.v1";

/// Local device-binding policy for newly written vaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeviceBindingPreference {
    /// Do not enable local device binding for newly written vaults.
    Disabled,
    /// Require Windows DPAPI-backed local device binding for newly written vaults.
    WindowsDpapiCurrentUser,
    /// Require macOS Keychain-backed local device binding for newly written vaults.
    MacosKeychainCurrentUser,
    /// Require Linux Secret Service-backed local device binding for newly written vaults.
    LinuxSecretServiceCurrentUser,
}

/// Derived passphrase material plus whether a fresh local secret was created.
#[derive(Debug)]
pub(crate) struct PreparedPassphrase {
    value: Zeroizing<String>,
    supplemental_secret: Option<Zeroizing<Vec<u8>>>,
    created_secret: bool,
}

impl PreparedPassphrase {
    /// Returns the derived passphrase bytes as a string slice.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        self.value.as_str()
    }

    /// Returns optional supplemental secret material for Argon2 peppering.
    #[must_use]
    pub(crate) fn supplemental_secret(&self) -> Option<&[u8]> {
        self.supplemental_secret.as_deref().map(Vec::as_slice)
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
            DeviceBindingPreference::MacosKeychainCurrentUser => {
                let binding = macos_keychain_binding_header();
                ensure_provider_available(Some(&binding))?;
                Ok(Some(binding))
            }
            DeviceBindingPreference::LinuxSecretServiceCurrentUser => {
                let binding = linux_secret_service_binding_header();
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
                supplemental_secret: None,
                created_secret: false,
            });
        };

        ensure_provider_available(Some(binding))?;
        let (secret, composition, created_secret) =
            self.load_or_create_secret(vault_id, binding)?;
        Ok(compose_prepared_passphrase(
            passphrase,
            secret,
            composition,
            created_secret,
        ))
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
                supplemental_secret: None,
                created_secret: false,
            });
        };

        ensure_provider_available(Some(binding))?;
        let (secret, composition) = self.load_secret(vault_id, binding)?;
        Ok(compose_prepared_passphrase(
            passphrase,
            secret,
            composition,
            false,
        ))
    }

    /// Removes a locally persisted binding secret if present.
    pub(crate) fn clear(&self, vault_id: &str) -> Result<(), AppError> {
        let state_path = self.state_file(vault_id);
        if let Ok(bytes) = read_limited_file(&state_path, MAX_BINDING_STATE_LEN)
            && let Ok(state) = serde_json::from_slice::<StoredBindingState>(&bytes)
        {
            let binding = LocalBindingHeader {
                provider: state.provider,
                scope: state.scope,
            };
            let _ = clear_provider_secret(vault_id, &binding);
        }

        match fs::remove_file(state_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AppError::Io(error)),
        }
    }

    fn load_or_create_secret(
        &self,
        vault_id: &str,
        binding: &LocalBindingHeader,
    ) -> Result<(Zeroizing<Vec<u8>>, DeviceBindingComposition, bool), AppError> {
        let state_file = self.state_file(vault_id);
        match read_limited_file(&state_file, MAX_BINDING_STATE_LEN) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let (secret, composition) =
                    Self::decode_state(vault_id, binding, bytes.as_slice())?;
                Ok((secret, composition, false))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let secret = Zeroizing::new(random_bytes(DEVICE_SECRET_LEN)?);
                let state = StoredBindingState {
                    provider: binding.provider.clone(),
                    scope: binding.scope.clone(),
                    composition: Some(DeviceBindingComposition::Argon2SecretV1),
                    protected_key_b64: create_protected_state(
                        vault_id,
                        secret.as_slice(),
                        binding,
                    )?,
                };
                Self::write_state(&state_file, &state)?;
                Ok((secret, DeviceBindingComposition::Argon2SecretV1, true))
            }
            Err(error) => Err(AppError::Io(error)),
        }
    }

    fn load_secret(
        &self,
        vault_id: &str,
        binding: &LocalBindingHeader,
    ) -> Result<(Zeroizing<Vec<u8>>, DeviceBindingComposition), AppError> {
        let state_file = self.state_file(vault_id);
        let bytes = match read_limited_file(&state_file, MAX_BINDING_STATE_LEN) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(AppError::MissingDeviceBindingKey {
                    vault_id: vault_id.to_owned(),
                });
            }
            Err(error) => return Err(AppError::Io(error)),
        };

        Self::decode_state(vault_id, binding, bytes.as_slice())
    }

    fn decode_state(
        vault_id: &str,
        binding: &LocalBindingHeader,
        bytes: &[u8],
    ) -> Result<(Zeroizing<Vec<u8>>, DeviceBindingComposition), AppError> {
        let state: StoredBindingState =
            serde_json::from_slice(bytes).map_err(AppError::InvalidDeviceBindingState)?;
        if state.provider != binding.provider || state.scope != binding.scope {
            return Err(AppError::DeviceBindingUnavailable {
                provider: binding.provider.clone(),
            });
        }

        let protected = BASE64
            .decode(state.protected_key_b64.as_bytes())
            .map(Zeroizing::new);
        let secret = load_provider_secret(vault_id, binding, protected)?;
        if secret.len() != DEVICE_SECRET_LEN {
            return Err(AppError::MissingDeviceBindingKey {
                vault_id: vault_id.to_owned(),
            });
        }

        Ok((
            secret,
            state
                .composition
                .unwrap_or(DeviceBindingComposition::LegacyPassphraseConcat),
        ))
    }

    fn write_state(state_file: &Path, state: &StoredBindingState) -> Result<(), AppError> {
        let encoded =
            Zeroizing::new(serde_json::to_vec(state).map_err(AppError::InvalidDeviceBindingState)?);
        write_private_file_atomic(state_file, encoded.as_slice())?;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    composition: Option<DeviceBindingComposition>,
    protected_key_b64: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DeviceBindingComposition {
    LegacyPassphraseConcat,
    Argon2SecretV1,
}

fn windows_dpapi_binding_header() -> LocalBindingHeader {
    LocalBindingHeader {
        provider: LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI.to_owned(),
        scope: LOCAL_BINDING_SCOPE_CURRENT_USER.to_owned(),
    }
}

fn macos_keychain_binding_header() -> LocalBindingHeader {
    LocalBindingHeader {
        provider: LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN.to_owned(),
        scope: LOCAL_BINDING_SCOPE_CURRENT_USER.to_owned(),
    }
}

fn linux_secret_service_binding_header() -> LocalBindingHeader {
    LocalBindingHeader {
        provider: LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE.to_owned(),
        scope: LOCAL_BINDING_SCOPE_CURRENT_USER.to_owned(),
    }
}

fn preference_from_env(value: Option<&std::ffi::OsStr>) -> DeviceBindingPreference {
    let Some(value) = value else {
        return DeviceBindingPreference::Disabled;
    };

    let normalized = value.to_string_lossy().trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" | "native" | "platform" => platform_default_preference(),
        "windows" | "windows-dpapi" => DeviceBindingPreference::WindowsDpapiCurrentUser,
        "macos" | "macos-keychain" | "keychain" => {
            DeviceBindingPreference::MacosKeychainCurrentUser
        }
        "linux" | "linux-secret-service" | "secret-service" => {
            DeviceBindingPreference::LinuxSecretServiceCurrentUser
        }
        _ => DeviceBindingPreference::Disabled,
    }
}

fn platform_default_preference() -> DeviceBindingPreference {
    #[cfg(windows)]
    {
        DeviceBindingPreference::WindowsDpapiCurrentUser
    }

    #[cfg(target_os = "macos")]
    {
        DeviceBindingPreference::MacosKeychainCurrentUser
    }

    #[cfg(target_os = "linux")]
    {
        DeviceBindingPreference::LinuxSecretServiceCurrentUser
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
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

fn compose_legacy_effective_passphrase(passphrase: &str, secret: &[u8]) -> Zeroizing<String> {
    let encoded_secret = BASE64.encode(secret);
    Zeroizing::new(format!("{passphrase}\0albus-device:{encoded_secret}"))
}

fn compose_prepared_passphrase(
    passphrase: &str,
    secret: Zeroizing<Vec<u8>>,
    composition: DeviceBindingComposition,
    created_secret: bool,
) -> PreparedPassphrase {
    match composition {
        DeviceBindingComposition::LegacyPassphraseConcat => PreparedPassphrase {
            value: compose_legacy_effective_passphrase(passphrase, secret.as_slice()),
            supplemental_secret: None,
            created_secret,
        },
        DeviceBindingComposition::Argon2SecretV1 => PreparedPassphrase {
            value: Zeroizing::new(passphrase.to_owned()),
            supplemental_secret: Some(secret),
            created_secret,
        },
    }
}

fn ensure_provider_available(binding: Option<&LocalBindingHeader>) -> Result<(), AppError> {
    let Some(binding) = binding else {
        return Ok(());
    };

    if binding.scope != LOCAL_BINDING_SCOPE_CURRENT_USER {
        return Err(AppError::DeviceBindingUnavailable {
            provider: binding.provider.clone(),
        });
    }

    match binding.provider.as_str() {
        LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI => {
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
        LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN | LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE => {
            initialize_native_keyring_store(binding)
        }
        _ => Err(AppError::DeviceBindingUnavailable {
            provider: binding.provider.clone(),
        }),
    }
}

fn create_protected_state(
    vault_id: &str,
    secret: &[u8],
    binding: &LocalBindingHeader,
) -> Result<String, AppError> {
    match binding.provider.as_str() {
        LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI => {
            let protected = protect_bytes(secret, binding)?;
            Ok(BASE64.encode(protected.as_slice()))
        }
        LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN | LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE => {
            store_native_keyring_secret(vault_id, secret, binding)?;
            Ok(String::new())
        }
        _ => Err(AppError::DeviceBindingUnavailable {
            provider: binding.provider.clone(),
        }),
    }
}

fn load_provider_secret(
    vault_id: &str,
    binding: &LocalBindingHeader,
    protected: Result<Zeroizing<Vec<u8>>, data_encoding::DecodeError>,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    match binding.provider.as_str() {
        LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI => {
            let protected = protected.map_err(|_| AppError::MissingDeviceBindingKey {
                vault_id: vault_id.to_owned(),
            })?;
            unprotect_bytes(protected.as_slice(), binding)
        }
        LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN | LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE => {
            load_native_keyring_secret(vault_id, binding)
        }
        _ => Err(AppError::DeviceBindingUnavailable {
            provider: binding.provider.clone(),
        }),
    }
}

fn clear_provider_secret(vault_id: &str, binding: &LocalBindingHeader) -> Result<(), AppError> {
    match binding.provider.as_str() {
        LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI => Ok(()),
        LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN | LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE => {
            delete_native_keyring_secret(vault_id, binding)
        }
        _ => Err(AppError::DeviceBindingUnavailable {
            provider: binding.provider.clone(),
        }),
    }
}

fn protect_bytes(
    bytes: &[u8],
    binding: &LocalBindingHeader,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    ensure_provider_available(Some(binding))?;
    #[cfg(windows)]
    {
        encrypt_data(bytes, Scope::User, None)
            .map(Zeroizing::new)
            .map_err(|error| AppError::DeviceBindingService(error.to_string()))
    }

    #[cfg(not(windows))]
    {
        let _ = bytes;
        Err(AppError::DeviceBindingUnavailable {
            provider: binding.provider.clone(),
        })
    }
}

fn unprotect_bytes(
    bytes: &[u8],
    binding: &LocalBindingHeader,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    ensure_provider_available(Some(binding))?;
    #[cfg(windows)]
    {
        decrypt_data(bytes, Scope::User, None)
            .map(Zeroizing::new)
            .map_err(|error| AppError::DeviceBindingService(error.to_string()))
    }

    #[cfg(not(windows))]
    {
        let _ = bytes;
        Err(AppError::DeviceBindingUnavailable {
            provider: binding.provider.clone(),
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn initialize_native_keyring_store(binding: &LocalBindingHeader) -> Result<(), AppError> {
    static KEYRING_STORE_INIT: OnceLock<Result<(), String>> = OnceLock::new();

    let initialized = KEYRING_STORE_INIT.get_or_init(|| {
        let config = HashMap::new();

        #[cfg(target_os = "macos")]
        {
            use apple_native_keyring_store::keychain::Store;

            let store =
                Store::new_with_configuration(&config).map_err(|error| error.to_string())?;
            set_default_store(store);
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            use dbus_secret_service_keyring_store::Store;

            let store =
                Store::new_with_configuration(&config).map_err(|error| error.to_string())?;
            set_default_store(store);
            Ok(())
        }
    });

    match initialized {
        Ok(()) => Ok(()),
        Err(_) => Err(AppError::DeviceBindingUnavailable {
            provider: binding.provider.clone(),
        }),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn initialize_native_keyring_store(binding: &LocalBindingHeader) -> Result<(), AppError> {
    Err(AppError::DeviceBindingUnavailable {
        provider: binding.provider.clone(),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn keyring_entry(vault_id: &str, binding: &LocalBindingHeader) -> Result<KeyringEntry, AppError> {
    initialize_native_keyring_store(binding)?;
    KeyringEntry::new(
        KEYRING_SERVICE_NAME,
        format!("{}:{vault_id}", binding.provider).as_str(),
    )
    .map_err(|error| map_keyring_error(&error, binding, Some(vault_id)))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn store_native_keyring_secret(
    vault_id: &str,
    secret: &[u8],
    binding: &LocalBindingHeader,
) -> Result<(), AppError> {
    keyring_entry(vault_id, binding)?
        .set_secret(secret)
        .map_err(|error| map_keyring_error(&error, binding, Some(vault_id)))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_native_keyring_secret(
    vault_id: &str,
    binding: &LocalBindingHeader,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    keyring_entry(vault_id, binding)?
        .get_secret()
        .map(Zeroizing::new)
        .map_err(|error| map_keyring_error(&error, binding, Some(vault_id)))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn delete_native_keyring_secret(
    vault_id: &str,
    binding: &LocalBindingHeader,
) -> Result<(), AppError> {
    match keyring_entry(vault_id, binding)?
        .delete_credential()
        .map_err(|error| map_keyring_error(&error, binding, Some(vault_id)))
    {
        Ok(()) | Err(AppError::MissingDeviceBindingKey { .. }) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn store_native_keyring_secret(
    _vault_id: &str,
    _secret: &[u8],
    binding: &LocalBindingHeader,
) -> Result<(), AppError> {
    Err(AppError::DeviceBindingUnavailable {
        provider: binding.provider.clone(),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn load_native_keyring_secret(
    _vault_id: &str,
    binding: &LocalBindingHeader,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    Err(AppError::DeviceBindingUnavailable {
        provider: binding.provider.clone(),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn delete_native_keyring_secret(
    _vault_id: &str,
    binding: &LocalBindingHeader,
) -> Result<(), AppError> {
    Err(AppError::DeviceBindingUnavailable {
        provider: binding.provider.clone(),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn map_keyring_error(
    error: &KeyringError,
    binding: &LocalBindingHeader,
    vault_id: Option<&str>,
) -> AppError {
    match error {
        KeyringError::NoEntry => AppError::MissingDeviceBindingKey {
            vault_id: vault_id.unwrap_or("vault").to_owned(),
        },
        KeyringError::NoStorageAccess(_)
        | KeyringError::PlatformFailure(_)
        | KeyringError::NoDefaultStore
        | KeyringError::NotSupportedByStore(_) => AppError::DeviceBindingUnavailable {
            provider: binding.provider.clone(),
        },
        _ => AppError::DeviceBindingService(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::linux_secret_service_binding_header;
    #[cfg(target_os = "macos")]
    use super::macos_keychain_binding_header;
    #[cfg(windows)]
    use super::windows_dpapi_binding_header;
    use super::{
        DeviceBindingComposition, DeviceBindingPreference, DeviceBindingStore,
        compose_legacy_effective_passphrase, platform_default_preference, preference_from_env,
        sanitize_vault_id,
    };
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    use tempfile::TempDir;
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    use uuid::Uuid;

    #[test]
    fn device_binding_defaults_to_disabled_without_opt_in() {
        assert_eq!(preference_from_env(None), DeviceBindingPreference::Disabled);
    }

    #[test]
    fn device_binding_env_opt_in_accepts_common_truthy_values() {
        for candidate in ["1", "true", "TRUE", "yes", "on"] {
            assert_eq!(
                preference_from_env(Some(candidate.as_ref())),
                platform_default_preference()
            );
        }
    }

    #[test]
    fn device_binding_env_accepts_explicit_provider_values() {
        assert_eq!(
            preference_from_env(Some("windows-dpapi".as_ref())),
            DeviceBindingPreference::WindowsDpapiCurrentUser
        );
        assert_eq!(
            preference_from_env(Some("macos-keychain".as_ref())),
            DeviceBindingPreference::MacosKeychainCurrentUser
        );
        assert_eq!(
            preference_from_env(Some("linux-secret-service".as_ref())),
            DeviceBindingPreference::LinuxSecretServiceCurrentUser
        );
    }

    #[test]
    fn sanitize_vault_id_normalizes_non_filename_characters() {
        assert_eq!(sanitize_vault_id("vault:/id"), "vault__id");
    }

    #[test]
    fn composed_passphrase_changes_when_secret_is_present() {
        let composed = compose_legacy_effective_passphrase("passphrase", &[0x11; 4]);
        assert_ne!(composed.as_str(), "passphrase");
        assert!(composed.as_str().starts_with("passphrase"));
    }

    #[test]
    fn missing_composition_defaults_to_legacy_concat() -> Result<(), Box<dyn std::error::Error>> {
        let state = super::StoredBindingState {
            provider: "windows-dpapi".to_owned(),
            scope: "current-user".to_owned(),
            composition: None,
            protected_key_b64: String::new(),
        };

        let encoded = serde_json::to_vec(&state)?;
        let decoded: super::StoredBindingState = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded.composition, None);
        assert_eq!(
            decoded
                .composition
                .unwrap_or(DeviceBindingComposition::LegacyPassphraseConcat),
            DeviceBindingComposition::LegacyPassphraseConcat
        );
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn native_binding_smoke_enabled() -> bool {
        matches!(
            std::env::var("ALBUS_RUN_NATIVE_BINDING_SMOKE")
                .ok()
                .as_deref()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("1" | "true" | "yes" | "on")
        )
    }

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    #[derive(Clone, Debug)]
    struct BindingSmokeGuard {
        store: DeviceBindingStore,
        vault_id: String,
    }

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    impl Drop for BindingSmokeGuard {
        fn drop(&mut self) {
            let _ = self.store.clear(&self.vault_id);
        }
    }

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    fn exercise_native_binding_round_trip(
        store: &DeviceBindingStore,
        binding: &albus::LocalBindingHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let vault_id = format!("smoke-{}", Uuid::new_v4());
        let _cleanup = BindingSmokeGuard {
            store: store.clone(),
            vault_id: vault_id.clone(),
        };

        let prepared = store.prepare_for_new_vault(&vault_id, "passphrase", Some(binding))?;
        let loaded = store.prepare_for_existing_vault(&vault_id, "passphrase", Some(binding))?;

        assert!(prepared.created_secret());
        assert_eq!(prepared.as_str(), loaded.as_str());
        assert_eq!(prepared.supplemental_secret(), loaded.supplemental_secret());
        Ok(())
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

        exercise_native_binding_round_trip(&store, &binding)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_keychain_store_round_trips_when_smoke_enabled()
    -> Result<(), Box<dyn std::error::Error>> {
        if !native_binding_smoke_enabled() {
            return Ok(());
        }

        let tempdir = TempDir::new()?;
        let store = DeviceBindingStore::new(
            tempdir.path().join("bindings"),
            DeviceBindingPreference::MacosKeychainCurrentUser,
        );
        let binding = macos_keychain_binding_header();

        exercise_native_binding_round_trip(&store, &binding)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_secret_service_store_round_trips_when_smoke_enabled()
    -> Result<(), Box<dyn std::error::Error>> {
        if !native_binding_smoke_enabled() {
            return Ok(());
        }

        let tempdir = TempDir::new()?;
        let store = DeviceBindingStore::new(
            tempdir.path().join("bindings"),
            DeviceBindingPreference::LinuxSecretServiceCurrentUser,
        );
        let binding = linux_secret_service_binding_header();

        exercise_native_binding_round_trip(&store, &binding)?;
        Ok(())
    }
}
