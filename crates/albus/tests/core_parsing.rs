#![doc = "Strict base32 and otpauth URI parsing integration tests for albus."]

use albus::{CoreError, Digits, HashAlgorithm, OtpSecret, parse_totp_uri};

#[test]
fn base32_decoder_accepts_lowercase_separators_and_padding() -> Result<(), CoreError> {
    let secret = OtpSecret::from_base32("mzxw6ytb oi======")?;
    assert_eq!(secret.to_base64(), "Zm9vYmFy");
    Ok(())
}

#[test]
fn base32_decoder_rejects_invalid_characters() {
    assert_eq!(
        OtpSecret::from_base32("MZXW6YTB0I"),
        Err(CoreError::InvalidBase32)
    );
}

#[test]
fn base32_decoder_rejects_empty_input_after_normalization() {
    assert_eq!(OtpSecret::from_base32("  -  "), Err(CoreError::EmptySecret));
}

#[test]
fn otpauth_parser_accepts_matching_label_and_query_issuer() -> Result<(), CoreError> {
    let parameters = parse_totp_uri(
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=8&period=45",
    )?;

    assert_eq!(parameters.issuer().as_str(), "Example");
    assert_eq!(parameters.account_label().as_str(), "alice@example.com");
    assert_eq!(parameters.algorithm(), HashAlgorithm::Sha256);
    assert_eq!(parameters.digits(), Digits::Eight);
    assert_eq!(parameters.period().get(), 45);
    Ok(())
}

#[test]
fn otpauth_parser_applies_standard_defaults() -> Result<(), CoreError> {
    let parameters =
        parse_totp_uri("otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP")?;

    assert_eq!(parameters.issuer().as_str(), "Example");
    assert_eq!(parameters.account_label().as_str(), "alice@example.com");
    assert_eq!(parameters.algorithm(), HashAlgorithm::Sha1);
    assert_eq!(parameters.digits(), Digits::Six);
    assert_eq!(parameters.period().get(), 30);
    Ok(())
}

#[test]
fn otpauth_parser_accepts_query_only_issuer() -> Result<(), CoreError> {
    let parameters =
        parse_totp_uri("otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")?;

    assert_eq!(parameters.issuer().as_str(), "Example");
    assert_eq!(parameters.account_label().as_str(), "alice@example.com");
    Ok(())
}

#[test]
fn otpauth_parser_rejects_non_otpauth_scheme() {
    assert_eq!(
        parse_totp_uri(
            "https://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        ),
        Err(CoreError::InvalidUri("scheme must be otpauth"))
    );
}

#[test]
fn otpauth_parser_rejects_non_totp_type() {
    assert_eq!(
        parse_totp_uri(
            "otpauth://hotp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        ),
        Err(CoreError::UnsupportedOtpType("hotp".to_owned()))
    );
}

#[test]
fn otpauth_parser_rejects_missing_secret() {
    assert_eq!(
        parse_totp_uri("otpauth://totp/Example:alice@example.com?issuer=Example"),
        Err(CoreError::MissingParameter("secret"))
    );
}

#[test]
fn otpauth_parser_rejects_missing_issuer() {
    assert_eq!(
        parse_totp_uri("otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP"),
        Err(CoreError::MissingParameter("issuer"))
    );
}

#[test]
fn otpauth_parser_rejects_unknown_parameter() {
    assert_eq!(
        parse_totp_uri(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&image=https://example.invalid/logo.png",
        ),
        Err(CoreError::UnexpectedParameter("image".to_owned()))
    );
}

#[test]
fn otpauth_parser_rejects_duplicate_parameter() {
    assert_eq!(
        parse_totp_uri(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP&issuer=Example",
        ),
        Err(CoreError::DuplicateParameter("secret"))
    );
}

#[test]
fn otpauth_parser_rejects_issuer_mismatch() {
    assert_eq!(
        parse_totp_uri(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Other",
        ),
        Err(CoreError::IssuerMismatch)
    );
}

#[test]
fn otpauth_parser_rejects_invalid_secret() {
    assert_eq!(
        parse_totp_uri("otpauth://totp/Example:alice@example.com?secret=NOT*BASE32&issuer=Example",),
        Err(CoreError::InvalidBase32)
    );
}

#[test]
fn otpauth_parser_rejects_unsupported_algorithm() {
    assert_eq!(
        parse_totp_uri(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=MD5",
        ),
        Err(CoreError::UnsupportedAlgorithm("MD5".to_owned()))
    );
}

#[test]
fn otpauth_parser_rejects_invalid_digits() {
    assert_eq!(
        parse_totp_uri(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=7",
        ),
        Err(CoreError::InvalidDigits(7))
    );
}

#[test]
fn otpauth_parser_rejects_invalid_period() {
    assert_eq!(
        parse_totp_uri(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=0",
        ),
        Err(CoreError::InvalidPeriod(0))
    );
}

#[test]
fn otpauth_parser_rejects_fragments() {
    assert_eq!(
        parse_totp_uri(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example#fragment",
        ),
        Err(CoreError::InvalidUri("fragment is not allowed"))
    );
}
