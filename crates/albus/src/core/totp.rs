use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use super::model::{Digits, HashAlgorithm, OtpSecret, Period, TotpParameters};
use crate::CoreError;

/// HOTP primitive namespace.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Hotp;

impl Hotp {
    /// Generates an HOTP value for a validated secret and counter.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if HMAC initialization fails unexpectedly.
    pub fn generate(
        secret: &OtpSecret,
        algorithm: HashAlgorithm,
        digits: Digits,
        counter: u64,
    ) -> Result<String, CoreError> {
        let counter_bytes = counter.to_be_bytes();
        let digest = Zeroizing::new(match algorithm {
            HashAlgorithm::Sha1 => compute_hmac_sha1(secret.expose(), &counter_bytes)?,
            HashAlgorithm::Sha256 => compute_hmac_sha256(secret.expose(), &counter_bytes)?,
            HashAlgorithm::Sha512 => compute_hmac_sha512(secret.expose(), &counter_bytes)?,
        });

        let truncated = dynamic_truncate(&digest);
        Ok(format_code(truncated, digits))
    }
}

/// TOTP generation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpCode {
    code: String,
    valid_for_secs: u32,
}

impl TotpCode {
    /// Creates a new generated TOTP code.
    #[must_use]
    pub fn new(code: String, valid_for_secs: u32) -> Self {
        Self {
            code,
            valid_for_secs,
        }
    }

    /// Returns the zero-padded TOTP code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the number of seconds left in the current window.
    #[must_use]
    pub const fn valid_for_secs(&self) -> u32 {
        self.valid_for_secs
    }
}

/// TOTP engine namespace.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TotpGenerator;

impl TotpGenerator {
    /// Returns the moving TOTP counter for a timestamp.
    #[must_use]
    pub fn counter_for(period: Period, unix_time_secs: u64) -> u64 {
        unix_time_secs / u64::from(period.get())
    }

    /// Returns the number of seconds left in the current TOTP window.
    #[must_use]
    pub fn remaining_secs(period: Period, unix_time_secs: u64) -> u32 {
        let elapsed_u64 = unix_time_secs % u64::from(period.get());
        let elapsed = match u32::try_from(elapsed_u64) {
            Ok(value) => value,
            Err(_) => period.get(),
        };
        let remaining = period.get() - elapsed;
        if remaining == 0 {
            period.get()
        } else {
            remaining
        }
    }

    /// Generates a TOTP code from validated parameters and a Unix timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if HMAC initialization fails unexpectedly.
    pub fn generate(
        parameters: &TotpParameters,
        unix_time_secs: u64,
    ) -> Result<TotpCode, CoreError> {
        let counter = Self::counter_for(parameters.period(), unix_time_secs);
        let code = Hotp::generate(
            parameters.secret(),
            parameters.algorithm(),
            parameters.digits(),
            counter,
        )?;

        Ok(TotpCode::new(
            code,
            Self::remaining_secs(parameters.period(), unix_time_secs),
        ))
    }
}

fn compute_hmac_sha1(secret: &[u8], message: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret).map_err(|_| CoreError::HmacInitialization)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn compute_hmac_sha256(secret: &[u8], message: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| CoreError::HmacInitialization)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn compute_hmac_sha512(secret: &[u8], message: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut mac =
        Hmac::<Sha512>::new_from_slice(secret).map_err(|_| CoreError::HmacInitialization)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn dynamic_truncate(digest: &[u8]) -> u32 {
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    ((u32::from(digest[offset] & 0x7f)) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3])
}

fn format_code(value: u32, digits: Digits) -> String {
    let reduced = value % digits.modulus();
    format!("{reduced:0width$}", width = digits.get() as usize)
}

#[cfg(test)]
mod tests {
    use super::Hotp;
    use crate::{CoreError, Digits, HashAlgorithm, OtpSecret};

    #[test]
    fn hotp_matches_rfc_4226_vectors() -> Result<(), CoreError> {
        let secret = OtpSecret::from_bytes(b"12345678901234567890".to_vec())?;
        let expected = [
            (0_u64, "755224"),
            (1, "287082"),
            (2, "359152"),
            (3, "969429"),
            (4, "338314"),
            (5, "254676"),
            (6, "287922"),
            (7, "162583"),
            (8, "399871"),
            (9, "520489"),
        ];

        for (counter, expected_code) in expected {
            let code = Hotp::generate(&secret, HashAlgorithm::Sha1, Digits::Six, counter)?;
            assert_eq!(code, expected_code);
        }

        Ok(())
    }
}
