//! draft-ietf-tls-esni / encrypted client hello (ech) extension parser and detector.

pub const TLS_EXT_ECH_STANDARD: u16 = 0xfe0d;
pub const TLS_EXT_ECH_DRAFT: u16 = 0xfe08;
pub const TLS_EXT_ECH_GREASE: u16 = 0x550d;

// inspects raw tls record byte slice to detect presence of ech extension blocks
pub fn has_ech_extension(data: &[u8]) -> bool {
    // 1. verify record layer encapsulation
    if data.len() < 5 || data[0] != 0x16 {
        return false;
    }

    let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
    if data.len() < 5 + record_len {
        return false;
    }
    let hs = &data[5..5 + record_len];

    // 2. verify handshake message type (0x01 client_hello)
    if hs.len() < 4 || hs[0] != 0x01 {
        return false;
    }

    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs.len() < 4 + hs_len {
        return false;
    }
    let body = &hs[4..4 + hs_len];

    if body.len() < 34 {
        return false;
    }
    let mut pos = 34; // skip client version (2) + random (32)

    // skip legacy session id vector
    if pos >= body.len() {
        return false;
    }
    let session_id_len = body[pos] as usize;
    pos += 1 + session_id_len;

    // skip cipher suites vector
    if pos + 2 > body.len() {
        return false;
    }
    let cipher_suites_len = ((body[pos] as usize) << 8) | (body[pos + 1] as usize);
    pos += 2 + cipher_suites_len;

    // skip compression methods vector
    if pos >= body.len() {
        return false;
    }
    let compression_len = body[pos] as usize;
    pos += 1 + compression_len;

    // parse extensions block length
    if pos + 2 > body.len() {
        return false;
    }
    let extensions_len = ((body[pos] as usize) << 8) | (body[pos + 1] as usize);
    pos += 2;

    if pos + extensions_len > body.len() {
        return false;
    }
    let mut exts = &body[pos..pos + extensions_len];

    // iterate through extension type-length-value records
    while exts.len() >= 4 {
        let ext_type = ((exts[0] as u16) << 8) | (exts[1] as u16);
        let ext_len = ((exts[2] as usize) << 8) | (exts[3] as usize);
        if 4 + ext_len > exts.len() {
            break;
        }

        if ext_type == TLS_EXT_ECH_STANDARD || ext_type == TLS_EXT_ECH_DRAFT || ext_type == TLS_EXT_ECH_GREASE {
            return true;
        }

        exts = &exts[4 + ext_len..];
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_ech_extension_false_on_standard_hello() {
        use crate::core::fake::clienthello::FAKE_TLS_CLIENT_HELLO;
        assert!(!has_ech_extension(&FAKE_TLS_CLIENT_HELLO));
    }
}
