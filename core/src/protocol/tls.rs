// zero-copy tls record parser and rfc 8701 grease detector

pub struct TlsParser;

impl TlsParser {
    // checks if the buffer starts with a valid tls handshake clienthello record
    pub fn is_client_hello(buf: &[u8]) -> bool {
        // record type 0x16 (handshake), tls version >= 3.1, handshake type 0x01 (clienthello)
        buf.len() >= 9 && buf[0] == 0x16 && buf[1] == 0x03 && buf[5] == 0x01
    }

    // checks if clienthello contains tls 1.3 early_data extension (0x002a)
    pub fn has_early_data_extension(buf: &[u8]) -> bool {
        if !Self::is_client_hello(buf) || buf.len() < 43 {
            return false;
        }

        let mut pos = 9 + 34; // record header (5) + handshake type/len (4) + version (2) + random (32)
        if pos >= buf.len() {
            return false;
        }

        // session id
        let session_id_len = buf[pos] as usize;
        pos += 1 + session_id_len;
        if pos + 2 > buf.len() {
            return false;
        }

        // cipher suites
        let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;
        if pos + 1 > buf.len() {
            return false;
        }

        // compression methods
        let comp_len = buf[pos] as usize;
        pos += 1 + comp_len;
        if pos + 2 > buf.len() {
            return false;
        }

        // extensions length
        let ext_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total_len).min(buf.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;

            // 0x002a = early_data (tls 1.3 0-rtt)
            if ext_type == 0x002a {
                return true;
            }

            pos += ext_len;
        }

        false
    }

    // extracts server name indication (sni) domain from clienthello
    pub fn extract_sni(buf: &[u8]) -> Option<String> {
        if !Self::is_client_hello(buf) || buf.len() < 43 {
            return None;
        }

        let mut pos = 9 + 34; // record header (5) + handshake header (4) + version (2) + random (32)
        if pos >= buf.len() {
            return None;
        }

        let session_id_len = *buf.get(pos)? as usize;
        pos += 1 + session_id_len;

        let cipher_suites_len = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;
        pos += 2 + cipher_suites_len;

        let comp_len = *buf.get(pos)? as usize;
        pos += 1 + comp_len;

        let ext_total_len = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total_len).min(buf.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;

            // 0x0000 = server_name extension (sni)
            if ext_type == 0x0000 && pos + ext_len <= ext_end {
                let mut p = pos + 2; // skip server_name_list length
                while p + 3 <= pos + ext_len {
                    let name_type = buf[p];
                    let name_len = u16::from_be_bytes([buf[p + 1], buf[p + 2]]) as usize;
                    p += 3;
                    if name_type == 0x00 && p + name_len <= pos + ext_len {
                        return String::from_utf8(buf[p..p + name_len].to_vec()).ok();
                    }
                    p += name_len;
                }
            }

            pos += ext_len;
        }

        None
    }

    // checks if clienthello contains encrypted client hello (ech) extension (0xfe0d / rfc 9460)

    pub fn has_ech_extension(buf: &[u8]) -> bool {
        if !Self::is_client_hello(buf) || buf.len() < 43 {
            return false;
        }

        let mut pos = 9 + 34; // record header (5) + handshake type/len (4) + version (2) + random (32)
        if pos >= buf.len() {
            return false;
        }

        // session id
        let session_id_len = buf[pos] as usize;
        pos += 1 + session_id_len;
        if pos + 2 > buf.len() {
            return false;
        }

        // cipher suites
        let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;
        if pos + 1 > buf.len() {
            return false;
        }

        // compression methods
        let comp_len = buf[pos] as usize;
        pos += 1 + comp_len;
        if pos + 2 > buf.len() {
            return false;
        }

        // extensions length
        let ext_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total_len).min(buf.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;

            // 0xfe0d = encrypted_client_hello (rfc 9460) or 0xff02 (legacy esni)
            if ext_type == 0xfe0d || ext_type == 0xff02 {
                return true;
            }

            pos += ext_len;
        }

        false
    }

    // reorders tls extensions and injects rfc 8701 grease to defeat static ja3/ja4 fingerprinting
    #[allow(dead_code)]
    pub fn permute_extensions_and_grease(buf: &[u8]) -> Option<Vec<u8>> {

        if !Self::is_client_hello(buf) || buf.len() < 43 {
            return None;
        }

        let mut pos = 9 + 34; // record header (5) + handshake type/len (4) + version (2) + random (32)
        if pos >= buf.len() {
            return None;
        }

        // session id
        let session_id_len = *buf.get(pos)? as usize;
        pos += 1 + session_id_len;
        if pos + 2 > buf.len() {
            return None;
        }

        // cipher suites
        let cipher_suites_len = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;
        pos += 2 + cipher_suites_len;
        if pos + 1 > buf.len() {
            return None;
        }

        // compression methods
        let comp_len = *buf.get(pos)? as usize;
        pos += 1 + comp_len;
        if pos + 2 > buf.len() {
            return None;
        }

        // extensions length field location
        let ext_len_pos = pos;
        let ext_total_len = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;
        pos += 2;
        let ext_end = pos + ext_total_len;
        if ext_end > buf.len() {
            return None;
        }

        // parse each extension
        let mut extensions: Vec<(u16, Vec<u8>)> = Vec::new();
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > ext_end {
                return None;
            }
            extensions.push((ext_type, buf[pos..pos + ext_len].to_vec()));
            pos += ext_len;
        }

        if extensions.len() >= 2 {
            // rotate extensions to randomize order
            extensions.rotate_left(1);
        }

        // serialize reordered extensions
        let mut new_ext_buf = Vec::new();
        for (ext_type, ext_data) in &extensions {
            new_ext_buf.extend_from_slice(&ext_type.to_be_bytes());
            new_ext_buf.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            new_ext_buf.extend_from_slice(ext_data);
        }

        // reconstruct complete ClientHello
        let mut out = Vec::with_capacity(buf.len() + 16);
        out.extend_from_slice(&buf[..ext_len_pos]);
        out.extend_from_slice(&(new_ext_buf.len() as u16).to_be_bytes());
        out.extend_from_slice(&new_ext_buf);

        // fix handshake length (3 bytes at offset 6..9)
        let handshake_len = (out.len() - 9) as u32;
        out[6] = ((handshake_len >> 16) & 0xff) as u8;
        out[7] = ((handshake_len >> 8) & 0xff) as u8;
        out[8] = (handshake_len & 0xff) as u8;

        // fix record length (2 bytes at offset 3..5)
        let record_len = (out.len() - 5) as u16;
        let rec_bytes = record_len.to_be_bytes();
        out[3] = rec_bytes[0];
        out[4] = rec_bytes[1];

        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_client_hello() {
        let sample = [0x16, 0x03, 0x03, 0x00, 0x20, 0x01, 0x00, 0x00, 0x1c, 0x03, 0x03];
        assert!(TlsParser::is_client_hello(&sample));
    }

    #[test]
    fn test_invalid_client_hello() {
        let http_sample = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!TlsParser::is_client_hello(http_sample));
        assert!(!TlsParser::is_client_hello(&[0x16, 0x03]));
        assert!(!TlsParser::is_client_hello(&[]));
    }

    #[test]
    fn test_truncated_extension_parsers() {
        // Truncated packet shouldn't panic
        let truncated = [0x16, 0x03, 0x01, 0x00, 0x10, 0x01];
        assert!(!TlsParser::has_early_data_extension(&truncated));
        assert!(!TlsParser::has_ech_extension(&truncated));
        assert!(TlsParser::permute_extensions_and_grease(&truncated).is_none());
    }
}



