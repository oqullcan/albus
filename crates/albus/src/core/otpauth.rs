use percent_encoding::percent_decode_str;
use url::Url;

use super::model::{
    AccountLabel, Digits, HashAlgorithm, Issuer, OtpSecret, Period, TotpParameters,
};
use crate::CoreError;

/// Parses a strict `otpauth://totp` URI into validated TOTP parameters.
///
/// Supported query parameters:
/// - `secret` (required)
/// - `issuer` (required unless present in the label prefix)
/// - `algorithm` (optional, defaults to `SHA1`)
/// - `digits` (optional, defaults to `6`)
/// - `period` (optional, defaults to `30`)
///
/// Unknown parameters, duplicate parameters, fragments, non-`totp` types, and
/// malformed values are rejected.
///
/// # Errors
///
/// Returns [`CoreError`] when the URI is malformed, unsupported, or contains
/// invalid TOTP parameters.
pub fn parse_totp_uri(input: &str) -> Result<TotpParameters, CoreError> {
    let url = Url::parse(input).map_err(|_| CoreError::InvalidUri("failed to parse URI"))?;

    if url.scheme() != "otpauth" {
        return Err(CoreError::InvalidUri("scheme must be otpauth"));
    }

    if url.cannot_be_a_base() {
        return Err(CoreError::InvalidUri("URI must include a totp path"));
    }

    if url.username() != "" || url.password().is_some() {
        return Err(CoreError::InvalidUri("user info is not allowed"));
    }

    if url.port().is_some() {
        return Err(CoreError::InvalidUri("port is not allowed"));
    }

    if url.fragment().is_some() {
        return Err(CoreError::InvalidUri("fragment is not allowed"));
    }

    let otp_type = url
        .host_str()
        .ok_or(CoreError::InvalidUri("missing otpauth type"))?;
    if otp_type != "totp" {
        return Err(CoreError::UnsupportedOtpType(otp_type.to_owned()));
    }

    if url.path_segments().map_or(0, Iterator::count) != 1 {
        return Err(CoreError::InvalidUri("label must be a single path segment"));
    }

    let raw_label = url
        .path()
        .strip_prefix('/')
        .ok_or(CoreError::InvalidUri("label path is missing"))?;
    let decoded_label = percent_decode_str(raw_label)
        .decode_utf8()
        .map_err(|_| CoreError::InvalidUri("label is not valid UTF-8"))?
        .into_owned();

    let (issuer_from_label, account_label) = split_label(&decoded_label)?;

    let mut secret = None;
    let mut issuer_from_query = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => assign_once(&mut secret, "secret", value.into_owned())?,
            "issuer" => assign_once(&mut issuer_from_query, "issuer", value.into_owned())?,
            "algorithm" => assign_once(&mut algorithm, "algorithm", value.into_owned())?,
            "digits" => assign_once(&mut digits, "digits", value.into_owned())?,
            "period" => assign_once(&mut period, "period", value.into_owned())?,
            other => return Err(CoreError::UnexpectedParameter(other.to_owned())),
        }
    }

    let secret = OtpSecret::from_base32(
        secret
            .as_deref()
            .ok_or(CoreError::MissingParameter("secret"))?,
    )?;

    let final_issuer = match (issuer_from_label, issuer_from_query) {
        (Some(label_issuer), Some(query_issuer)) => {
            let query_issuer = Issuer::new(query_issuer)?;
            if label_issuer != query_issuer {
                return Err(CoreError::IssuerMismatch);
            }

            label_issuer
        }
        (Some(label_issuer), None) => label_issuer,
        (None, Some(query_issuer)) => Issuer::new(query_issuer)?,
        (None, None) => return Err(CoreError::MissingParameter("issuer")),
    };

    let algorithm = match algorithm {
        Some(value) => value.parse()?,
        None => HashAlgorithm::Sha1,
    };

    let digits = match digits {
        Some(value) => value
            .parse::<u32>()
            .map_err(|_| CoreError::InvalidUri("digits must be a base-10 integer"))
            .and_then(Digits::try_from)?,
        None => Digits::Six,
    };

    let period = match period {
        Some(value) => value
            .parse::<u32>()
            .map_err(|_| CoreError::InvalidUri("period must be a base-10 integer"))
            .and_then(Period::new)?,
        None => Period::new(30)?,
    };

    Ok(TotpParameters::new(
        final_issuer,
        account_label,
        secret,
        digits,
        period,
        algorithm,
    ))
}

fn split_label(value: &str) -> Result<(Option<Issuer>, AccountLabel), CoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CoreError::EmptyField("account_label"));
    }

    if let Some((issuer, label)) = trimmed.split_once(':') {
        let label = AccountLabel::new(label)?;
        let issuer = Issuer::new(issuer)?;
        return Ok((Some(issuer), label));
    }

    Ok((None, AccountLabel::new(trimmed)?))
}

fn assign_once(
    slot: &mut Option<String>,
    field_name: &'static str,
    value: String,
) -> Result<(), CoreError> {
    if slot.replace(value).is_some() {
        return Err(CoreError::DuplicateParameter(field_name));
    }

    Ok(())
}
