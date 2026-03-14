use core::fmt;

/// Errors raised by the pure domain layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreError {
    /// A required field was empty.
    EmptyField(&'static str),
    /// The requested digit length is not supported.
    InvalidDigits(u32),
    /// The requested time period is not supported.
    InvalidPeriod(u32),
    /// The secret is empty after normalization or decoding.
    EmptySecret,
    /// The base32 secret is malformed.
    InvalidBase32,
    /// The base64 secret is malformed.
    InvalidBase64(&'static str),
    /// The otpauth URI type is unsupported.
    UnsupportedOtpType(String),
    /// The hash algorithm is unsupported.
    UnsupportedAlgorithm(String),
    /// A required query parameter is missing.
    MissingParameter(&'static str),
    /// A query parameter was provided more than once.
    DuplicateParameter(&'static str),
    /// A query parameter is not supported by the strict v1 parser.
    UnexpectedParameter(String),
    /// The otpauth URI is malformed.
    InvalidUri(&'static str),
    /// The issuer in the label prefix and query parameter did not match.
    IssuerMismatch,
    /// HMAC initialization unexpectedly failed.
    HmacInitialization,
    /// The vault contains duplicate entry identifiers.
    DuplicateEntryId,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "required field is empty: {field}"),
            Self::InvalidDigits(value) => write!(f, "invalid TOTP digit count: {value}"),
            Self::InvalidPeriod(value) => write!(f, "invalid TOTP period: {value}"),
            Self::EmptySecret => f.write_str("OTP secret must not be empty"),
            Self::InvalidBase32 => f.write_str("OTP secret is not valid base32"),
            Self::InvalidBase64(field) => write!(f, "{field} is not valid base64"),
            Self::UnsupportedOtpType(value) => write!(f, "unsupported otpauth type: {value}"),
            Self::UnsupportedAlgorithm(value) => {
                write!(f, "unsupported TOTP algorithm: {value}")
            }
            Self::MissingParameter(name) => write!(f, "missing query parameter: {name}"),
            Self::DuplicateParameter(name) => write!(f, "duplicate query parameter: {name}"),
            Self::UnexpectedParameter(name) => write!(f, "unexpected query parameter: {name}"),
            Self::InvalidUri(reason) => write!(f, "invalid otpauth URI: {reason}"),
            Self::IssuerMismatch => {
                f.write_str("issuer label prefix and issuer query parameter do not match")
            }
            Self::HmacInitialization => f.write_str("failed to initialize HMAC"),
            Self::DuplicateEntryId => f.write_str("vault contains duplicate entry identifiers"),
        }
    }
}

impl std::error::Error for CoreError {}
