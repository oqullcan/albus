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

        if ext_type == TLS_EXT_ECH_STANDARD
            || ext_type == TLS_EXT_ECH_DRAFT
            || ext_type == TLS_EXT_ECH_GREASE
        {
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

    #[test]
    fn test_has_ech_extension_invalid_inputs() {
        assert!(!has_ech_extension(&[]));
        assert!(!has_ech_extension(&[0x16, 0x03, 0x01])); // too short (< 5)
        assert!(!has_ech_extension(&[0x17, 0x03, 0x03, 0x00, 0x10])); // application data (0x17)
        assert!(!has_ech_extension(&[0x16, 0x03, 0x01, 0x00, 0x10, 0x02])); // handshake type 0x02 (ServerHello)
    }

    fn build_synthetic_client_hello_with_ext(ext_type: u16) -> Vec<u8> {
        let mut body = Vec::new();
        // client version (2) + random (32)
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        // session id
        body.push(0);
        // cipher suites (2 bytes len + 2 bytes suite)
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        // compression
        body.extend_from_slice(&[0x01, 0x00]);

        // extension: ext_type, len 4, data [1, 2, 3, 4]
        let mut exts = Vec::new();
        exts.extend_from_slice(&ext_type.to_be_bytes());
        exts.extend_from_slice(&[0x00, 0x04, 0x01, 0x02, 0x03, 0x04]);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hs_len = body.len();
        hs.push((hs_len >> 16) as u8);
        hs.push((hs_len >> 8) as u8);
        hs.push(hs_len as u8);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn test_has_ech_extension_synthetic_types() {
        let std_ech = build_synthetic_client_hello_with_ext(TLS_EXT_ECH_STANDARD);
        assert!(has_ech_extension(&std_ech));

        let draft_ech = build_synthetic_client_hello_with_ext(TLS_EXT_ECH_DRAFT);
        assert!(has_ech_extension(&draft_ech));

        let grease_ech = build_synthetic_client_hello_with_ext(TLS_EXT_ECH_GREASE);
        assert!(has_ech_extension(&grease_ech));

        let other_ext = build_synthetic_client_hello_with_ext(0x0000); // ServerName
        assert!(!has_ech_extension(&other_ext));
    }
}
