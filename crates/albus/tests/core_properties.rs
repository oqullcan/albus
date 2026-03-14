#![doc = "Property tests for secret encoding and strict otpauth URI parsing."]

use albus::{Digits, HashAlgorithm, OtpSecret, parse_totp_uri};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

fn safe_label_component() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@"
                .chars()
                .collect::<Vec<_>>(),
        ),
        1..32,
    )
    .prop_map(|characters| characters.into_iter().collect())
}

fn hash_algorithm_name(index: u8) -> &'static str {
    match index % 3 {
        0 => "SHA1",
        1 => "SHA256",
        _ => "SHA512",
    }
}

fn expected_hash_algorithm(index: u8) -> HashAlgorithm {
    match index % 3 {
        0 => HashAlgorithm::Sha1,
        1 => HashAlgorithm::Sha256,
        _ => HashAlgorithm::Sha512,
    }
}

fn digit_count(index: u8) -> u32 {
    if index.is_multiple_of(2) { 6 } else { 8 }
}

fn expected_digits(index: u8) -> Digits {
    if index.is_multiple_of(2) {
        Digits::Six
    } else {
        Digits::Eight
    }
}

proptest! {
    #[test]
    fn otp_secret_base32_round_trips(bytes in prop::collection::vec(any::<u8>(), 1..128)) {
        let secret = OtpSecret::from_bytes(bytes).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let reparsed = OtpSecret::from_base32(&secret.to_base32())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        prop_assert_eq!(secret.to_base64(), reparsed.to_base64());
    }

    #[test]
    fn otp_secret_base64_round_trips(bytes in prop::collection::vec(any::<u8>(), 1..128)) {
        let secret = OtpSecret::from_bytes(bytes).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let reparsed = OtpSecret::from_base64(&secret.to_base64())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        prop_assert_eq!(secret.to_base64(), reparsed.to_base64());
    }

    #[test]
    fn otpauth_parser_round_trips_canonical_uris(
        issuer in safe_label_component(),
        account in safe_label_component(),
        secret_bytes in prop::collection::vec(any::<u8>(), 1..64),
        algorithm_index in any::<u8>(),
        digits_index in any::<u8>(),
        period in 1_u32..600,
    ) {
        let secret =
            OtpSecret::from_bytes(secret_bytes).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let algorithm = hash_algorithm_name(algorithm_index);
        let digits = digit_count(digits_index);
        let uri = format!(
            "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period={period}",
            secret = secret.to_base32(),
        );

        let parsed = parse_totp_uri(&uri).map_err(|error| TestCaseError::fail(error.to_string()))?;

        prop_assert_eq!(parsed.issuer().as_str(), issuer);
        prop_assert_eq!(parsed.account_label().as_str(), account);
        prop_assert_eq!(parsed.secret().to_base64(), secret.to_base64());
        prop_assert_eq!(parsed.algorithm(), expected_hash_algorithm(algorithm_index));
        prop_assert_eq!(parsed.digits(), expected_digits(digits_index));
        prop_assert_eq!(parsed.period().get(), period);
    }
}
