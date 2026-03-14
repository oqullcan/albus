use super::{
    config::{CryptoPolicy, KdfParams, KeySchedule},
    envelope::EnvelopeHeader,
    error::CryptoError,
    passphrase::validate_existing_passphrase,
    secret::SecretBytes,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use getrandom::getrandom;
use hkdf::Hkdf;
use sha2::Sha256;

const KEY_PURPOSE_VAULT_FILE_V1: &[u8] = b"albus:vault:file-key:v1";
const KEY_PURPOSE_BACKUP_FILE_V1: &[u8] = b"albus:backup:file-key:v1";

/// Generates cryptographically secure random bytes.
///
/// # Errors
///
/// Returns [`CryptoError`] when the operating system RNG fails.
pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0_u8; len];
    getrandom(&mut bytes).map_err(|_| CryptoError::RandomFailure)?;
    Ok(bytes)
}

/// Derives a file encryption key from a passphrase and salt.
///
/// # Errors
///
/// Returns [`CryptoError`] when the salt length or Argon2 parameters are
/// invalid, or key derivation fails.
pub fn derive_key(
    passphrase: &str,
    salt: &[u8],
    params: &KdfParams,
    policy: &CryptoPolicy,
) -> Result<SecretBytes, CryptoError> {
    derive_key_with_secret(passphrase, salt, params, policy, None)
}

/// Derives a file encryption key from a passphrase, salt, and optional secret.
///
/// # Errors
///
/// Returns [`CryptoError`] when the salt length or Argon2 parameters are
/// invalid, or key derivation fails.
pub fn derive_key_with_secret(
    passphrase: &str,
    salt: &[u8],
    params: &KdfParams,
    policy: &CryptoPolicy,
    supplemental_secret: Option<&[u8]>,
) -> Result<SecretBytes, CryptoError> {
    validate_existing_passphrase(passphrase)?;

    if salt.len() != params.salt_len {
        return Err(CryptoError::InvalidSaltLength {
            expected: params.salt_len,
            actual: salt.len(),
        });
    }

    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(policy.key_len),
    )
    .map_err(|_| CryptoError::InvalidKdfParameters)?;
    let argon2 = match supplemental_secret {
        Some(secret) => {
            Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, argon2_params)
                .map_err(|_| CryptoError::InvalidKdfParameters)?
        }
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params),
    };

    let mut derived = SecretBytes::new(vec![0_u8; policy.key_len]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, derived.expose_mut())
        .map_err(|_| CryptoError::KeyDerivationFailure)?;

    Ok(derived)
}

/// Derives the authenticated file key for a specific envelope header.
///
/// Legacy envelopes use raw Argon2 output. Current envelopes derive a master
/// key with Argon2 and then expand a purpose-specific subkey with HKDF-SHA256.
///
/// # Errors
///
/// Returns [`CryptoError`] when key derivation fails or the header carries an
/// unsupported key schedule.
pub fn derive_envelope_key(
    passphrase: &str,
    header: &EnvelopeHeader,
    policy: &CryptoPolicy,
    supplemental_secret: Option<&[u8]>,
) -> Result<SecretBytes, CryptoError> {
    let params = header.kdf_params()?;
    let salt = header.decode_salt(policy)?;

    match header.key_schedule()? {
        KeySchedule::LegacyDirect => {
            derive_key_with_secret(passphrase, &salt, &params, policy, supplemental_secret)
        }
        KeySchedule::HkdfSha256V1 => derive_hkdf_separated_key(
            passphrase,
            &salt,
            &params,
            policy,
            header.kind,
            supplemental_secret,
        ),
    }
}

fn derive_hkdf_separated_key(
    passphrase: &str,
    salt: &[u8],
    params: &KdfParams,
    policy: &CryptoPolicy,
    kind: super::envelope::ContainerKind,
    supplemental_secret: Option<&[u8]>,
) -> Result<SecretBytes, CryptoError> {
    let master = derive_key_with_secret(passphrase, salt, params, policy, supplemental_secret)?;
    let hkdf = Hkdf::<Sha256>::new(None, master.expose());
    let mut separated = SecretBytes::new(vec![0_u8; policy.key_len]);
    hkdf.expand(key_purpose_info(kind), separated.expose_mut())
        .map_err(|_| CryptoError::KeyDerivationFailure)?;
    Ok(separated)
}

fn key_purpose_info(kind: super::envelope::ContainerKind) -> &'static [u8] {
    match kind {
        super::envelope::ContainerKind::Vault => KEY_PURPOSE_VAULT_FILE_V1,
        super::envelope::ContainerKind::Backup => KEY_PURPOSE_BACKUP_FILE_V1,
    }
}

/// Encrypts plaintext using `XChaCha20Poly1305`.
///
/// # Errors
///
/// Returns [`CryptoError`] when the key or nonce length is invalid, or the
/// encryption operation fails.
pub fn encrypt(
    key: &SecretBytes,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    policy: &CryptoPolicy,
) -> Result<Vec<u8>, CryptoError> {
    validate_key_and_nonce(key, nonce, policy)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose()));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailure)
}

/// Decrypts ciphertext using `XChaCha20Poly1305`.
///
/// # Errors
///
/// Returns [`CryptoError`] when the key or nonce length is invalid, or
/// authentication fails.
pub fn decrypt(
    key: &SecretBytes,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    policy: &CryptoPolicy,
) -> Result<Vec<u8>, CryptoError> {
    validate_key_and_nonce(key, nonce, policy)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose()));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn validate_key_and_nonce(
    key: &SecretBytes,
    nonce: &[u8],
    policy: &CryptoPolicy,
) -> Result<(), CryptoError> {
    if key.len() != policy.key_len {
        return Err(CryptoError::InvalidKeyLength {
            expected: policy.key_len,
            actual: key.len(),
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
    use super::{derive_envelope_key, derive_key};
    use crate::{CryptoError, CryptoPolicy, EnvelopeHeader, EnvelopeMetadata};

    #[test]
    fn derive_key_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let policy = CryptoPolicy::default();
        let params = policy.kdf_params.clone();
        let salt = vec![7_u8; params.salt_len];

        let left = derive_key("correct horse battery staple", &salt, &params, &policy)?;
        let right = derive_key("correct horse battery staple", &salt, &params, &policy)?;

        assert_eq!(left, right);
        assert_eq!(left.len(), policy.key_len);
        Ok(())
    }

    #[test]
    fn derive_key_rejects_empty_passphrase() {
        let policy = CryptoPolicy::default();
        let params = policy.kdf_params.clone();
        let salt = vec![7_u8; params.salt_len];

        assert!(matches!(
            derive_key("   ", &salt, &params, &policy),
            Err(CryptoError::EmptyPassphrase)
        ));
    }

    #[test]
    fn envelope_key_separation_differs_between_vault_and_backup() -> Result<(), CryptoError> {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; policy.nonce_len];
        let metadata = EnvelopeMetadata {
            vault_id: "vault-1".to_owned(),
            revision: 1,
            created_at: None,
            updated_at: None,
        };
        let vault_header =
            EnvelopeHeader::new_vault(1, 1, metadata.clone(), &salt, &nonce, &policy)?;
        let backup_header = EnvelopeHeader::new_backup(1, 1, metadata, &salt, &nonce, &policy)?;

        let vault_key =
            derive_envelope_key("correct horse battery staple", &vault_header, &policy, None)?;
        let backup_key = derive_envelope_key(
            "correct horse battery staple",
            &backup_header,
            &policy,
            None,
        )?;

        assert_ne!(vault_key.expose(), backup_key.expose());
        Ok(())
    }

    #[test]
    fn envelope_key_derivation_uses_supplemental_secret() -> Result<(), CryptoError> {
        let policy = CryptoPolicy::default();
        let salt = vec![0x11; policy.kdf_params.salt_len];
        let nonce = vec![0x22; policy.nonce_len];
        let header = EnvelopeHeader::new_vault(
            1,
            1,
            EnvelopeMetadata {
                vault_id: "vault-1".to_owned(),
                revision: 1,
                created_at: None,
                updated_at: None,
            },
            &salt,
            &nonce,
            &policy,
        )?;

        let without_secret =
            derive_envelope_key("correct horse battery staple", &header, &policy, None)?;
        let with_secret = derive_envelope_key(
            "correct horse battery staple",
            &header,
            &policy,
            Some(b"device-binding-secret"),
        )?;

        assert_ne!(without_secret.expose(), with_secret.expose());
        Ok(())
    }
}
