use std::num::TryFromIntError;

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};

use super::{
    config::{CryptoPolicy, KdfParams, KeySchedule},
    error::CryptoError,
};

/// The only supported persisted local binding provider in v1.
pub const LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI: &str = "windows-dpapi";
/// Supported persisted local binding provider for macOS Keychain.
pub const LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN: &str = "macos-keychain";
/// Supported persisted local binding provider for Linux Secret Service.
pub const LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE: &str = "linux-secret-service";
/// The only supported persisted local binding scope in v1.
pub const LOCAL_BINDING_SCOPE_CURRENT_USER: &str = "current-user";
/// Persisted identifier for the current HKDF-based file key schedule.
pub const KEY_SCHEDULE_HKDF_SHA256_V1: &str = "hkdf-sha256-v1";

/// Outer container kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerKind {
    /// Primary encrypted vault file.
    Vault,
    /// Encrypted backup file.
    Backup,
}

/// Non-secret metadata authenticated alongside the ciphertext.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeMetadata {
    /// Stable vault identifier.
    pub vault_id: String,
    /// Monotonic mutation counter or snapshot revision.
    pub revision: u64,
    /// Legacy optional creation timestamp kept for backwards-compatible reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Legacy optional update timestamp kept for backwards-compatible reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Optional local host binding metadata for a vault.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBindingHeader {
    /// Binding provider identifier.
    pub provider: String,
    /// Provider-specific protection scope.
    pub scope: String,
}

/// Persisted KDF settings embedded in the header.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfHeader {
    /// Persisted KDF identifier.
    pub algorithm: String,
    /// Argon2 version number.
    pub version: u32,
    /// Memory cost in kibibytes.
    pub memory_kib: u32,
    /// Iteration count.
    pub iterations: u32,
    /// Parallelism lanes.
    pub parallelism: u32,
    /// Base64-encoded salt bytes.
    pub salt_b64: String,
    /// Optional post-Argon2 key schedule marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_schedule: Option<String>,
}

/// Persisted AEAD settings embedded in the header.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherHeader {
    /// Persisted AEAD identifier.
    pub algorithm: String,
    /// Base64-encoded nonce bytes.
    pub nonce_b64: String,
}

/// Persisted header fields required to derive the file key and verify the file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeHeader {
    /// Vault or backup.
    pub kind: ContainerKind,
    /// Outer envelope version.
    pub format_version: u32,
    /// Inner decrypted schema version.
    pub schema_version: u32,
    /// KDF settings.
    pub kdf: KdfHeader,
    /// AEAD settings.
    pub cipher: CipherHeader,
    /// Non-secret file metadata.
    pub metadata: EnvelopeMetadata,
    /// Optional local host binding requirement for primary vaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_binding: Option<LocalBindingHeader>,
}

impl EnvelopeHeader {
    /// Constructs a new vault header from the v1 crypto policy.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the salt or nonce lengths do not match the
    /// selected crypto policy.
    pub fn new_vault(
        format_version: u32,
        schema_version: u32,
        metadata: EnvelopeMetadata,
        salt: &[u8],
        nonce: &[u8],
        policy: &CryptoPolicy,
    ) -> Result<Self, CryptoError> {
        Self::new(
            ContainerKind::Vault,
            format_version,
            schema_version,
            metadata,
            salt,
            nonce,
            policy,
        )
    }

    /// Constructs a new backup header from the v1 crypto policy.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the salt or nonce lengths do not match the
    /// selected crypto policy.
    pub fn new_backup(
        format_version: u32,
        schema_version: u32,
        metadata: EnvelopeMetadata,
        salt: &[u8],
        nonce: &[u8],
        policy: &CryptoPolicy,
    ) -> Result<Self, CryptoError> {
        Self::new(
            ContainerKind::Backup,
            format_version,
            schema_version,
            metadata,
            salt,
            nonce,
            policy,
        )
    }

    fn new(
        kind: ContainerKind,
        format_version: u32,
        schema_version: u32,
        metadata: EnvelopeMetadata,
        salt: &[u8],
        nonce: &[u8],
        policy: &CryptoPolicy,
    ) -> Result<Self, CryptoError> {
        validate_material_lengths(salt, nonce, policy)?;

        Ok(Self {
            kind,
            format_version,
            schema_version,
            kdf: KdfHeader {
                algorithm: policy.kdf_algorithm.as_str().to_owned(),
                version: policy.kdf_params.version,
                memory_kib: policy.kdf_params.memory_kib,
                iterations: policy.kdf_params.iterations,
                parallelism: policy.kdf_params.parallelism,
                salt_b64: BASE64.encode(salt),
                key_schedule: policy.key_schedule.persisted_name().map(str::to_owned),
            },
            cipher: CipherHeader {
                algorithm: policy.aead_algorithm.as_str().to_owned(),
                nonce_b64: BASE64.encode(nonce),
            },
            metadata,
            local_binding: None,
        })
    }

    /// Returns a copy of this header with local host binding metadata set.
    #[must_use]
    pub fn with_local_binding(mut self, local_binding: LocalBindingHeader) -> Self {
        self.local_binding = Some(local_binding);
        self
    }

    /// Decodes and validates the stored salt bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the stored salt is malformed or the wrong
    /// length for the active policy.
    pub fn decode_salt(&self, policy: &CryptoPolicy) -> Result<Vec<u8>, CryptoError> {
        let salt = BASE64
            .decode(self.kdf.salt_b64.as_bytes())
            .map_err(|_| CryptoError::InvalidBase64 { field: "salt_b64" })?;

        if salt.len() != policy.kdf_params.salt_len {
            return Err(CryptoError::InvalidSaltLength {
                expected: policy.kdf_params.salt_len,
                actual: salt.len(),
            });
        }

        Ok(salt)
    }

    /// Decodes and validates the stored nonce bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the stored nonce is malformed or the wrong
    /// length for the active policy.
    pub fn decode_nonce(&self, policy: &CryptoPolicy) -> Result<Vec<u8>, CryptoError> {
        let nonce = BASE64
            .decode(self.cipher.nonce_b64.as_bytes())
            .map_err(|_| CryptoError::InvalidBase64 { field: "nonce_b64" })?;

        if nonce.len() != policy.nonce_len {
            return Err(CryptoError::InvalidNonceLength {
                expected: policy.nonce_len,
                actual: nonce.len(),
            });
        }

        Ok(nonce)
    }

    /// Converts the persisted KDF settings into derivation parameters.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the stored KDF identifier or version is
    /// unsupported.
    pub fn kdf_params(&self) -> Result<KdfParams, CryptoError> {
        if self.kdf.algorithm != "argon2id" {
            return Err(CryptoError::UnsupportedKdfAlgorithm(
                self.kdf.algorithm.clone(),
            ));
        }

        if self.kdf.version != 19 {
            return Err(CryptoError::UnsupportedKdfVersion(self.kdf.version));
        }

        Ok(KdfParams {
            version: self.kdf.version,
            salt_len: 16,
            memory_kib: self.kdf.memory_kib,
            iterations: self.kdf.iterations,
            parallelism: self.kdf.parallelism,
        })
    }

    /// Validates the stored cryptographic identifiers against the active policy.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the stored identifiers or lengths are
    /// unsupported.
    pub fn validate_crypto(&self, policy: &CryptoPolicy) -> Result<(), CryptoError> {
        if self.kdf.algorithm != policy.kdf_algorithm.as_str() {
            return Err(CryptoError::UnsupportedKdfAlgorithm(
                self.kdf.algorithm.clone(),
            ));
        }

        if self.cipher.algorithm != policy.aead_algorithm.as_str() {
            return Err(CryptoError::UnsupportedAeadAlgorithm(
                self.cipher.algorithm.clone(),
            ));
        }

        self.kdf_params()?;
        validate_kdf_parameter(
            "memory_kib",
            self.kdf.memory_kib,
            policy.kdf_limits.memory_kib,
        )?;
        validate_kdf_parameter(
            "iterations",
            self.kdf.iterations,
            policy.kdf_limits.iterations,
        )?;
        validate_kdf_parameter(
            "parallelism",
            self.kdf.parallelism,
            policy.kdf_limits.parallelism,
        )?;
        let _ = self.decode_salt(policy)?;
        let _ = self.decode_nonce(policy)?;
        self.validate_local_binding()?;
        let _ = self.key_schedule()?;
        Ok(())
    }

    /// Returns the file-key schedule implied by this header.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the persisted schedule marker is unknown.
    pub fn key_schedule(&self) -> Result<KeySchedule, CryptoError> {
        match self.kdf.key_schedule.as_deref() {
            None => Ok(KeySchedule::LegacyDirect),
            Some(KEY_SCHEDULE_HKDF_SHA256_V1) => Ok(KeySchedule::HkdfSha256V1),
            Some(other) => Err(CryptoError::UnsupportedKeySchedule(other.to_owned())),
        }
    }

    fn validate_local_binding(&self) -> Result<(), CryptoError> {
        let Some(local_binding) = &self.local_binding else {
            return Ok(());
        };

        if self.kind != ContainerKind::Vault {
            return Err(CryptoError::UnexpectedLocalBinding);
        }

        if !matches!(
            local_binding.provider.as_str(),
            LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI
                | LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN
                | LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE
        ) {
            return Err(CryptoError::UnsupportedLocalBindingProvider(
                local_binding.provider.clone(),
            ));
        }

        if local_binding.scope != LOCAL_BINDING_SCOPE_CURRENT_USER {
            return Err(CryptoError::UnsupportedLocalBindingScope {
                provider: local_binding.provider.clone(),
                scope: local_binding.scope.clone(),
            });
        }

        Ok(())
    }
}

/// Builds the exact envelope AAD bytes from the persisted magic and header.
///
/// # Errors
///
/// Returns [`TryFromIntError`] when `header_json` is too large to fit into the
/// 32-bit persisted header length field.
pub fn build_envelope_aad(magic: &[u8], header_json: &[u8]) -> Result<Vec<u8>, TryFromIntError> {
    let header_len = u32::try_from(header_json.len())?;
    let mut aad = Vec::with_capacity(magic.len() + 4 + header_json.len());
    aad.extend_from_slice(magic);
    aad.extend_from_slice(&header_len.to_le_bytes());
    aad.extend_from_slice(header_json);
    Ok(aad)
}

/// Assembles the persisted envelope bytes from the magic, header, and ciphertext.
///
/// # Errors
///
/// Returns [`TryFromIntError`] when `header_json` is too large to fit into the
/// 32-bit persisted header length field.
pub fn assemble_envelope_container(
    magic: &[u8],
    header_json: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, TryFromIntError> {
    let header_len = u32::try_from(header_json.len())?;
    let mut container = Vec::with_capacity(magic.len() + 4 + header_json.len() + ciphertext.len());
    container.extend_from_slice(magic);
    container.extend_from_slice(&header_len.to_le_bytes());
    container.extend_from_slice(header_json);
    container.extend_from_slice(ciphertext);
    Ok(container)
}

fn validate_kdf_parameter(field: &'static str, value: u32, max: u32) -> Result<(), CryptoError> {
    if value == 0 || value > max {
        return Err(CryptoError::KdfParameterOutOfRange {
            field,
            min: 1,
            max,
            value,
        });
    }

    Ok(())
}

fn validate_material_lengths(
    salt: &[u8],
    nonce: &[u8],
    policy: &CryptoPolicy,
) -> Result<(), CryptoError> {
    if salt.len() != policy.kdf_params.salt_len {
        return Err(CryptoError::InvalidSaltLength {
            expected: policy.kdf_params.salt_len,
            actual: salt.len(),
        });
    }

    if nonce.len() != policy.nonce_len {
        return Err(CryptoError::InvalidNonceLength {
            expected: policy.nonce_len,
            actual: nonce.len(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ContainerKind, EnvelopeHeader, EnvelopeMetadata, KEY_SCHEDULE_HKDF_SHA256_V1,
        LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE, LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN,
        LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI, LOCAL_BINDING_SCOPE_CURRENT_USER, LocalBindingHeader,
        assemble_envelope_container, build_envelope_aad,
    };
    use crate::{CryptoError, CryptoPolicy, KeySchedule};

    #[test]
    fn new_vault_header_uses_xchacha20poly1305_and_24_byte_nonce() -> Result<(), CryptoError> {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; policy.nonce_len];
        let header = EnvelopeHeader::new_vault(
            1,
            1,
            EnvelopeMetadata {
                vault_id: "vault-1".to_owned(),
                revision: 7,
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &policy,
        )?;

        assert_eq!(header.kind, ContainerKind::Vault);
        assert_eq!(header.cipher.algorithm, "xchacha20poly1305");
        assert_eq!(
            header.kdf.key_schedule.as_deref(),
            Some(KEY_SCHEDULE_HKDF_SHA256_V1)
        );
        assert_eq!(header.decode_nonce(&policy)?, nonce);
        Ok(())
    }

    #[test]
    fn new_backup_header_uses_backup_kind() -> Result<(), CryptoError> {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; policy.nonce_len];
        let header = EnvelopeHeader::new_backup(
            1,
            1,
            EnvelopeMetadata {
                vault_id: "vault-1".to_owned(),
                revision: 7,
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &policy,
        )?;

        assert_eq!(header.kind, ContainerKind::Backup);
        assert_eq!(header.cipher.algorithm, "xchacha20poly1305");
        Ok(())
    }

    #[test]
    fn new_vault_header_rejects_legacy_12_byte_nonce() {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; 12];
        let error = EnvelopeHeader::new_vault(
            1,
            1,
            EnvelopeMetadata {
                vault_id: "vault-1".to_owned(),
                revision: 7,
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &policy,
        );

        assert!(matches!(
            error,
            Err(CryptoError::InvalidNonceLength {
                expected: 24,
                actual: 12,
            })
        ));
    }

    #[test]
    fn validate_crypto_rejects_excessive_argon2_memory_cost() -> Result<(), CryptoError> {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; policy.nonce_len];
        let mut header = EnvelopeHeader::new_vault(
            1,
            1,
            EnvelopeMetadata {
                vault_id: "vault-1".to_owned(),
                revision: 7,
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &policy,
        )?;
        header.kdf.memory_kib = policy.kdf_limits.memory_kib + 1;

        assert!(matches!(
            header.validate_crypto(&policy),
            Err(CryptoError::KdfParameterOutOfRange {
                field: "memory_kib",
                min: 1,
                max,
                value,
            }) if max == policy.kdf_limits.memory_kib
                && value == policy.kdf_limits.memory_kib + 1
        ));
        Ok(())
    }

    #[test]
    fn aad_uses_magic_header_length_and_header_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let aad = build_envelope_aad(b"ALBUSV1\0", br#"{"kind":"vault"}"#)?;

        assert_eq!(&aad[..8], b"ALBUSV1\0");
        assert_eq!(u32::from_le_bytes(aad[8..12].try_into()?), 16);
        assert_eq!(&aad[12..], br#"{"kind":"vault"}"#);
        Ok(())
    }

    #[test]
    fn assembled_container_persists_header_length_prefix() -> Result<(), Box<dyn std::error::Error>>
    {
        let container =
            assemble_envelope_container(b"ALBUSV1\0", br#"{"kind":"backup"}"#, b"ciphertext")?;

        assert_eq!(&container[..8], b"ALBUSV1\0");
        assert_eq!(u32::from_le_bytes(container[8..12].try_into()?), 17);
        assert_eq!(&container[12..29], br#"{"kind":"backup"}"#);
        assert_eq!(&container[29..], b"ciphertext");
        Ok(())
    }

    #[test]
    fn local_binding_header_round_trips_through_json() -> Result<(), Box<dyn std::error::Error>> {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; policy.nonce_len];
        let header = EnvelopeHeader::new_vault(
            1,
            1,
            EnvelopeMetadata {
                vault_id: "vault-1".to_owned(),
                revision: 7,
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &policy,
        )?
        .with_local_binding(LocalBindingHeader {
            provider: LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI.to_owned(),
            scope: LOCAL_BINDING_SCOPE_CURRENT_USER.to_owned(),
        });

        let encoded = serde_json::to_vec(&header)?;
        let decoded: EnvelopeHeader = serde_json::from_slice(&encoded)?;

        assert_eq!(decoded.local_binding, header.local_binding);
        Ok(())
    }

    #[test]
    fn validate_crypto_rejects_unknown_local_binding_provider() -> Result<(), CryptoError> {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; policy.nonce_len];
        let header = EnvelopeHeader::new_vault(
            1,
            1,
            EnvelopeMetadata {
                vault_id: "vault-1".to_owned(),
                revision: 7,
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &policy,
        )?
        .with_local_binding(LocalBindingHeader {
            provider: "unknown-provider".to_owned(),
            scope: LOCAL_BINDING_SCOPE_CURRENT_USER.to_owned(),
        });

        assert!(matches!(
            header.validate_crypto(&policy),
            Err(CryptoError::UnsupportedLocalBindingProvider(provider))
                if provider == "unknown-provider"
        ));
        Ok(())
    }

    #[test]
    fn validate_crypto_accepts_macos_keychain_local_binding() -> Result<(), CryptoError> {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; policy.nonce_len];
        let header = EnvelopeHeader::new_vault(
            1,
            1,
            EnvelopeMetadata {
                vault_id: "vault-1".to_owned(),
                revision: 7,
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &policy,
        )?
        .with_local_binding(LocalBindingHeader {
            provider: LOCAL_BINDING_PROVIDER_MACOS_KEYCHAIN.to_owned(),
            scope: LOCAL_BINDING_SCOPE_CURRENT_USER.to_owned(),
        });

        header.validate_crypto(&policy)?;
        Ok(())
    }

    #[test]
    fn missing_key_schedule_marker_is_treated_as_legacy() -> Result<(), CryptoError> {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; policy.nonce_len];
        let mut header = EnvelopeHeader::new_vault(
            1,
            1,
            EnvelopeMetadata {
                vault_id: "vault-1".to_owned(),
                revision: 7,
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &policy,
        )?;
        header.kdf.key_schedule = None;

        assert_eq!(header.key_schedule()?, KeySchedule::LegacyDirect);
        header.validate_crypto(&policy)?;
        Ok(())
    }

    #[test]
    fn validate_crypto_accepts_linux_secret_service_local_binding() -> Result<(), CryptoError> {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; policy.nonce_len];
        let header = EnvelopeHeader::new_vault(
            1,
            1,
            EnvelopeMetadata {
                vault_id: "vault-1".to_owned(),
                revision: 7,
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &policy,
        )?
        .with_local_binding(LocalBindingHeader {
            provider: LOCAL_BINDING_PROVIDER_LINUX_SECRET_SERVICE.to_owned(),
            scope: LOCAL_BINDING_SCOPE_CURRENT_USER.to_owned(),
        });

        header.validate_crypto(&policy)?;
        Ok(())
    }

    #[test]
    fn validate_crypto_rejects_local_binding_on_backup_headers() -> Result<(), CryptoError> {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; policy.nonce_len];
        let header = EnvelopeHeader::new_backup(
            1,
            1,
            EnvelopeMetadata {
                vault_id: "vault-1".to_owned(),
                revision: 7,
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &policy,
        )?
        .with_local_binding(LocalBindingHeader {
            provider: LOCAL_BINDING_PROVIDER_WINDOWS_DPAPI.to_owned(),
            scope: LOCAL_BINDING_SCOPE_CURRENT_USER.to_owned(),
        });

        assert!(matches!(
            header.validate_crypto(&policy),
            Err(CryptoError::UnexpectedLocalBinding)
        ));
        Ok(())
    }
}
