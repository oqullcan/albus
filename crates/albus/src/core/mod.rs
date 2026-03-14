#![forbid(unsafe_code)]
#![doc = "Core domain model and pure logic for Albus."]

/// Errors raised by the domain layer.
mod error;
/// Persisted and in-memory domain types.
mod model;
/// Strict `otpauth://totp` URI parsing.
mod otpauth;
/// Pure time-window calculations for TOTP.
mod totp;

pub use error::CoreError;
pub use model::{
    AccountLabel, Digits, EntryId, HashAlgorithm, Issuer, OtpEntry, OtpSecret, Period,
    TotpParameters, Vault, VaultId,
};
pub use otpauth::parse_totp_uri;
pub use totp::{TotpCode, TotpGenerator};
