use core::{fmt, num::NonZeroU32, str::FromStr};
use std::collections::HashSet;

use data_encoding::{BASE32_NOPAD, BASE64};
use zeroize::Zeroize;

use crate::CoreError;

/// Stable vault identifier.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct VaultId(String);

impl VaultId {
    /// Creates a validated vault identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the identifier is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        normalize_required_field("vault_id", value).map(Self)
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable entry identifier.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EntryId(String);

impl EntryId {
    /// Creates a validated entry identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the identifier is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        normalize_required_field("entry_id", value).map(Self)
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Human-readable issuer name.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Issuer(String);

impl Issuer {
    /// Creates a validated issuer name.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the issuer is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        normalize_required_field("issuer", value).map(Self)
    }

    /// Returns the issuer as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Human-readable account label.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AccountLabel(String);

impl AccountLabel {
    /// Creates a validated account label.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the label is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        normalize_required_field("account_label", value).map(Self)
    }

    /// Returns the label as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Supported TOTP hash algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HashAlgorithm {
    /// HMAC-SHA1.
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl HashAlgorithm {
    /// Returns the canonical otpauth query value.
    #[must_use]
    pub const fn as_otpauth_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// Returns the lowercase persisted representation used in vault JSON.
    #[must_use]
    pub const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

impl FromStr for HashAlgorithm {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            other => Err(CoreError::UnsupportedAlgorithm(other.to_owned())),
        }
    }
}

/// Supported TOTP code lengths for v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Digits {
    /// Six-digit TOTP code.
    Six,
    /// Eight-digit TOTP code.
    Eight,
}

impl Digits {
    /// Returns the numeric digit count.
    #[must_use]
    pub const fn get(self) -> u32 {
        match self {
            Self::Six => 6,
            Self::Eight => 8,
        }
    }

    /// Returns the decimal modulus for code truncation.
    #[must_use]
    pub const fn modulus(self) -> u32 {
        match self {
            Self::Six => 1_000_000,
            Self::Eight => 100_000_000,
        }
    }
}

impl TryFrom<u32> for Digits {
    type Error = CoreError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            6 => Ok(Self::Six),
            8 => Ok(Self::Eight),
            other => Err(CoreError::InvalidDigits(other)),
        }
    }
}

/// Positive TOTP time period.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Period(NonZeroU32);

impl Period {
    /// Creates a positive TOTP time period.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the period is zero.
    pub fn new(value: u32) -> Result<Self, CoreError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(CoreError::InvalidPeriod(value))
    }

    /// Returns the period in seconds.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Decoded OTP secret bytes.
#[derive(Eq, PartialEq)]
pub struct OtpSecret(Vec<u8>);

impl OtpSecret {
    /// Creates a secret from raw decoded bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the secret byte vector is empty.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CoreError> {
        if bytes.is_empty() {
            return Err(CoreError::EmptySecret);
        }

        Ok(Self(bytes))
    }

    /// Decodes a base32-encoded secret using the v1 normalization rules.
    ///
    /// Normalization is intentionally limited to:
    /// - trimming ASCII whitespace
    /// - removing ASCII spaces and `-` separators
    /// - accepting lowercase input
    /// - removing trailing `=` padding
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the normalized secret is empty or not valid
    /// base32.
    pub fn from_base32(input: &str) -> Result<Self, CoreError> {
        let mut normalized = normalize_base32(input)?;
        let decoded = BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|_| CoreError::InvalidBase32);
        normalized.zeroize();
        let decoded = decoded?;

        Self::from_bytes(decoded)
    }

    /// Decodes a base64-encoded persisted secret.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the input is not valid base64 or decodes to
    /// an empty byte string.
    pub fn from_base64(input: &str) -> Result<Self, CoreError> {
        let normalized = input.trim();
        if normalized.is_empty() {
            return Err(CoreError::EmptySecret);
        }

        let decoded = BASE64
            .decode(normalized.as_bytes())
            .map_err(|_| CoreError::InvalidBase64("secret_b64"))?;

        Self::from_bytes(decoded)
    }

    /// Returns the persisted base64 representation of the secret.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.0)
    }

    /// Returns the canonical base32 representation of the secret without padding.
    #[must_use]
    pub fn to_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0)
    }

    /// Returns the decoded secret bytes within the crate.
    #[must_use]
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Clone for OtpSecret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for OtpSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for OtpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtpSecret(REDACTED)")
    }
}

/// Validated TOTP parameters shared by URI parsing and entry storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpParameters {
    issuer: Issuer,
    account_label: AccountLabel,
    secret: OtpSecret,
    digits: Digits,
    period: Period,
    algorithm: HashAlgorithm,
}

impl TotpParameters {
    /// Creates validated TOTP parameters.
    #[must_use]
    pub fn new(
        issuer: Issuer,
        account_label: AccountLabel,
        secret: OtpSecret,
        digits: Digits,
        period: Period,
        algorithm: HashAlgorithm,
    ) -> Self {
        Self {
            issuer,
            account_label,
            secret,
            digits,
            period,
            algorithm,
        }
    }

    /// Returns the issuer.
    #[must_use]
    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// Returns the account label.
    #[must_use]
    pub fn account_label(&self) -> &AccountLabel {
        &self.account_label
    }

    /// Returns the decoded secret.
    #[must_use]
    pub fn secret(&self) -> &OtpSecret {
        &self.secret
    }

    /// Returns the TOTP digit count.
    #[must_use]
    pub fn digits(&self) -> Digits {
        self.digits
    }

    /// Returns the TOTP period.
    #[must_use]
    pub fn period(&self) -> Period {
        self.period
    }

    /// Returns the hash algorithm.
    #[must_use]
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
}

/// One TOTP entry stored in the decrypted vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtpEntry {
    entry_id: EntryId,
    parameters: TotpParameters,
}

impl OtpEntry {
    /// Creates a new validated vault entry.
    #[must_use]
    pub fn new(entry_id: EntryId, parameters: TotpParameters) -> Self {
        Self {
            entry_id,
            parameters,
        }
    }

    /// Returns the stable entry identifier.
    #[must_use]
    pub fn entry_id(&self) -> &EntryId {
        &self.entry_id
    }

    /// Returns the validated TOTP parameters.
    #[must_use]
    pub fn parameters(&self) -> &TotpParameters {
        &self.parameters
    }
}

/// In-memory decrypted vault.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vault {
    vault_id: VaultId,
    schema_version: u32,
    revision: u64,
    created_at: String,
    updated_at: String,
    entries: Vec<OtpEntry>,
}

impl Vault {
    /// Creates a validated decrypted vault.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when timestamps are empty or entry identifiers are
    /// duplicated.
    pub fn new(
        vault_id: VaultId,
        schema_version: u32,
        revision: u64,
        created_at: impl Into<String>,
        updated_at: impl Into<String>,
        entries: Vec<OtpEntry>,
    ) -> Result<Self, CoreError> {
        let created_at = normalize_required_field("created_at", created_at)?;
        let updated_at = normalize_required_field("updated_at", updated_at)?;
        let vault = Self {
            vault_id,
            schema_version,
            revision,
            created_at,
            updated_at,
            entries,
        };
        vault.validate()?;
        Ok(vault)
    }

    /// Returns the vault identifier.
    #[must_use]
    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// Returns the schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the vault revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    /// Returns the update timestamp.
    #[must_use]
    pub fn updated_at(&self) -> &str {
        &self.updated_at
    }

    /// Returns the entries.
    #[must_use]
    pub fn entries(&self) -> &[OtpEntry] {
        &self.entries
    }

    /// Validates vault-level invariants.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when timestamps are empty or entry identifiers are
    /// duplicated.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.created_at.is_empty() {
            return Err(CoreError::EmptyField("created_at"));
        }

        if self.updated_at.is_empty() {
            return Err(CoreError::EmptyField("updated_at"));
        }

        let mut entry_ids = HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            if !entry_ids.insert(entry.entry_id().as_str()) {
                return Err(CoreError::DuplicateEntryId);
            }
        }

        Ok(())
    }
}

fn normalize_required_field(
    field_name: &'static str,
    value: impl Into<String>,
) -> Result<String, CoreError> {
    let normalized = value.into().trim().to_owned();
    if normalized.is_empty() {
        return Err(CoreError::EmptyField(field_name));
    }

    Ok(normalized)
}

fn normalize_base32(input: &str) -> Result<String, CoreError> {
    let mut compact = String::with_capacity(input.len());
    for character in input.chars() {
        if character.is_ascii_whitespace() || character == '-' {
            continue;
        }

        if !character.is_ascii() {
            return Err(CoreError::InvalidBase32);
        }

        compact.push(character.to_ascii_uppercase());
    }

    while compact.ends_with('=') {
        compact.pop();
    }

    if compact.is_empty() {
        return Err(CoreError::EmptySecret);
    }

    if compact.contains('=') {
        return Err(CoreError::InvalidBase32);
    }

    Ok(compact)
}

#[cfg(test)]
mod tests {
    use super::{
        AccountLabel, Digits, EntryId, HashAlgorithm, Issuer, OtpSecret, Period, TotpParameters,
        Vault, VaultId,
    };
    use crate::CoreError;

    #[test]
    fn base32_decoder_accepts_common_normalization() -> Result<(), CoreError> {
        let secret = OtpSecret::from_base32("mzxw6ytb-oi======")?;
        assert_eq!(secret.to_base64(), "Zm9vYmFy");
        Ok(())
    }

    #[test]
    fn base32_decoder_rejects_embedded_padding() {
        assert_eq!(
            OtpSecret::from_base32("MZXW=6YTBOI"),
            Err(CoreError::InvalidBase32)
        );
    }

    #[test]
    fn base64_round_trip_preserves_secret_bytes() -> Result<(), CoreError> {
        let secret = OtpSecret::from_base64("Zm9vYmFy")?;
        assert_eq!(secret.to_base64(), "Zm9vYmFy");
        Ok(())
    }

    #[test]
    fn base32_round_trip_preserves_secret_bytes() -> Result<(), CoreError> {
        let secret = OtpSecret::from_base32("JBSWY3DPEHPK3PXP")?;
        assert_eq!(secret.to_base32(), "JBSWY3DPEHPK3PXP");
        Ok(())
    }

    #[test]
    fn vault_validation_rejects_duplicate_entry_ids() -> Result<(), CoreError> {
        let parameters = TotpParameters::new(
            Issuer::new("Example")?,
            AccountLabel::new("alice@example.com")?,
            OtpSecret::from_base32("JBSWY3DPEHPK3PXP")?,
            Digits::Six,
            Period::new(30)?,
            HashAlgorithm::Sha1,
        );

        let duplicate_entry_a = crate::OtpEntry::new(EntryId::new("entry-1")?, parameters.clone());
        let duplicate_entry_b = crate::OtpEntry::new(EntryId::new("entry-1")?, parameters);

        let result = Vault::new(
            VaultId::new("vault-1")?,
            1,
            1,
            "2026-03-11T00:00:00Z",
            "2026-03-11T00:00:00Z",
            vec![duplicate_entry_a, duplicate_entry_b],
        );

        assert_eq!(result, Err(CoreError::DuplicateEntryId));
        Ok(())
    }
}
