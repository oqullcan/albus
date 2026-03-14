#![doc = "RFC-backed HOTP and TOTP integration tests for albus."]

use albus::{
    AccountLabel, CoreError, Digits, HashAlgorithm, Issuer, OtpSecret, Period, TotpGenerator,
    TotpParameters, parse_totp_uri,
};

#[test]
fn totp_matches_rfc_6238_vectors_for_sha1_sha256_and_sha512() -> Result<(), CoreError> {
    let timestamps = [
        59_u64,
        1_111_111_109,
        1_111_111_111,
        1_234_567_890,
        2_000_000_000,
        20_000_000_000,
    ];

    let test_cases = [
        (
            HashAlgorithm::Sha1,
            OtpSecret::from_bytes(b"12345678901234567890".to_vec())?,
            [
                "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
            ],
        ),
        (
            HashAlgorithm::Sha256,
            OtpSecret::from_bytes(b"12345678901234567890123456789012".to_vec())?,
            [
                "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
            ],
        ),
        (
            HashAlgorithm::Sha512,
            OtpSecret::from_bytes(
                b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
            )?,
            [
                "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
            ],
        ),
    ];

    let period = Period::new(30)?;

    for (algorithm, secret, expected_codes) in test_cases {
        let parameters = TotpParameters::new(
            Issuer::new("Example")?,
            AccountLabel::new("alice@example.com")?,
            secret,
            Digits::Eight,
            period,
            algorithm,
        );

        for (index, timestamp) in timestamps.into_iter().enumerate() {
            let code = TotpGenerator::generate(&parameters, timestamp)?;
            assert_eq!(code.code(), expected_codes[index]);
        }
    }

    Ok(())
}

#[test]
fn totp_counter_and_remaining_seconds_follow_the_period() -> Result<(), CoreError> {
    let period = Period::new(30)?;
    assert_eq!(TotpGenerator::counter_for(period, 60), 2);
    assert_eq!(TotpGenerator::remaining_secs(period, 61), 29);
    assert_eq!(TotpGenerator::remaining_secs(period, 90), 30);
    Ok(())
}

#[test]
fn parsed_uri_can_drive_totp_generation() -> Result<(), CoreError> {
    let parameters = parse_totp_uri(
        "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&digits=8&period=30&algorithm=SHA1",
    )?;

    let code = TotpGenerator::generate(&parameters, 59)?;
    assert_eq!(code.code(), "94287082");
    assert_eq!(code.valid_for_secs(), 1);
    Ok(())
}
