//! rfc 6066 server name indication (sni) extension parser for clienthello records.

// parses the server name indication hostname string from an incoming tls clienthello record
pub fn parse_sni(data: &[u8]) -> Option<String> {
    // 1. verify tls record layer encapsulation (content_type 0x16)
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }

    let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
    if data.len() < 5 + record_len {
        return None;
    }
    let hs = &data[5..5 + record_len];

    // 2. verify handshake message type (0x01 client_hello)
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }

    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs.len() < 4 + hs_len {
        return None;
    }
    let body = &hs[4..4 + hs_len];

    // 3. parse clienthello parameters
    if body.len() < 34 {
        return None;
    }
    let mut pos = 34; // skip client version (2) + random (32)

    // skip legacy session id vector
    if pos >= body.len() {
        return None;
    }
    let session_id_len = body[pos] as usize;
    pos += 1 + session_id_len;

    // skip cipher suites vector
    if pos + 2 > body.len() {
        return None;
    }
    let cipher_suites_len = ((body[pos] as usize) << 8) | (body[pos + 1] as usize);
    pos += 2 + cipher_suites_len;

    // skip compression methods vector
    if pos >= body.len() {
        return None;
    }
    let compression_len = body[pos] as usize;
    pos += 1 + compression_len;

    // 4. parse extensions block length
    if pos + 2 > body.len() {
        return None;
    }
    let extensions_len = ((body[pos] as usize) << 8) | (body[pos + 1] as usize);
    pos += 2;

    if pos + extensions_len > body.len() {
        return None;
    }
    let mut exts = &body[pos..pos + extensions_len];

    // 5. iterate through extension blocks to locate server name (0x0000)
    while exts.len() >= 4 {
        let ext_type = ((exts[0] as u16) << 8) | (exts[1] as u16);
        let ext_len = ((exts[2] as usize) << 8) | (exts[3] as usize);
        if 4 + ext_len > exts.len() {
            break;
        }

        if ext_type == 0x0000 {
            return parse_sni_extension(&exts[4..4 + ext_len]);
        }

        exts = &exts[4 + ext_len..];
    }

    None
}

// parses host_name entries within the server name list extension data
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let list_len = ((data[0] as usize) << 8) | (data[1] as usize);
    if 2 + list_len > data.len() {
        return None;
    }
    let mut entries = &data[2..2 + list_len];

    while entries.len() >= 3 {
        let name_type = entries[0];
        let name_len = ((entries[1] as usize) << 8) | (entries[2] as usize);
        if 3 + name_len > entries.len() {
            break;
        }

        // name_type 0x00 corresponds to host_name
        if name_type == 0x00 {
            let host_bytes = &entries[3..3 + name_len];
            if let Ok(host) = std::str::from_utf8(host_bytes) {
                return Some(host.to_string());
            }
        }

        entries = &entries[3 + name_len..];
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::fake::clienthello::FAKE_TLS_CLIENT_HELLO;

    #[test]
    fn test_parse_sni_from_generated_client_hello() {
        let sni = parse_sni(&FAKE_TLS_CLIENT_HELLO);
        assert_eq!(sni, Some("www.google.com".to_string()));
    }

    #[test]
    fn test_custom_sni_client_hello() {
        use crate::core::fake::clienthello::build_fake_client_hello;
        let custom_ch = build_fake_client_hello("example.org");
        let sni = parse_sni(&custom_ch);
        assert_eq!(sni, Some("example.org".to_string()));
    }

    #[test]
    fn test_parse_sni_empty_or_invalid() {
        assert_eq!(parse_sni(&[]), None);
        assert_eq!(parse_sni(&[0x16, 0x03]), None);
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), None);
    }
}
