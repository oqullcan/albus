use crate::CryptoError;

/// Minimum number of non-whitespace characters required for newly set
/// passphrases.
pub const MIN_NEW_PASSPHRASE_NON_WHITESPACE_CHARS: usize = 16;

/// Validates a passphrase used to access an existing encrypted artifact.
///
/// # Errors
///
/// Returns [`CryptoError`] when the passphrase is empty after trimming.
pub fn validate_existing_passphrase(passphrase: &str) -> Result<(), CryptoError> {
    if passphrase.trim().is_empty() {
        return Err(CryptoError::EmptyPassphrase);
    }

    Ok(())
}

/// Validates a passphrase that will protect a newly written encrypted artifact.
///
/// # Errors
///
/// Returns [`CryptoError`] when the passphrase is empty after trimming or does
/// not satisfy the minimum non-whitespace character policy.
pub fn validate_new_passphrase(passphrase: &str) -> Result<(), CryptoError> {
    validate_existing_passphrase(passphrase)?;
    if passphrase
        .chars()
        .filter(|character| !character.is_whitespace())
        .count()
        < MIN_NEW_PASSPHRASE_NON_WHITESPACE_CHARS
    {
        return Err(CryptoError::PassphraseTooShort(
            MIN_NEW_PASSPHRASE_NON_WHITESPACE_CHARS,
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        MIN_NEW_PASSPHRASE_NON_WHITESPACE_CHARS, validate_existing_passphrase,
        validate_new_passphrase,
    };
    use crate::CryptoError;

    #[test]
    fn existing_passphrase_rejects_blank_values() {
        assert!(matches!(
            validate_existing_passphrase("   "),
            Err(CryptoError::EmptyPassphrase)
        ));
    }

    #[test]
    fn new_passphrase_rejects_short_values() {
        assert!(matches!(
            validate_new_passphrase("too-short"),
            Err(CryptoError::PassphraseTooShort(min))
                if min == MIN_NEW_PASSPHRASE_NON_WHITESPACE_CHARS
        ));
    }

    #[test]
    fn new_passphrase_accepts_sixteen_non_whitespace_characters() -> Result<(), CryptoError> {
        validate_new_passphrase("four words passphrase")?;
        Ok(())
    }
}
