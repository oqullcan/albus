use super::{
    config::{CryptoPolicy, KdfParams},
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
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut derived = SecretBytes::new(vec![0_u8; policy.key_len]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, derived.expose_mut())
        .map_err(|_| CryptoError::KeyDerivationFailure)?;

    Ok(derived)
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
    use super::derive_key;
    use crate::{CryptoError, CryptoPolicy};

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
}
