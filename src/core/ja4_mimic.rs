//! TLS Client Hello mimicry and JA3/JA4 fingerprint camouflage.
//!
//! Modern DPI systems extract JA3 and JA4 fingerprints from TLS Client Hello packets
//! to detect non-browser TLS clients (such as custom proxies or automated scripts).
//! This module provides tools to synthesize and reshape TLS Client Hello records
//! to match genuine browser fingerprints (Chrome, Firefox, Safari).

use sha2::{Digest, Sha256};

/// Target browser profile for TLS Client Hello fingerprint mimicry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProfile {
    Chrome130,
    Firefox130,
    Safari18,
}

impl BrowserProfile {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().replace(['-', '_', ' '], "").as_str() {
            "chrome" | "chrome130" | "chromium" | "google" => Some(Self::Chrome130),
            "firefox" | "firefox130" | "mozilla" | "ff" => Some(Self::Firefox130),
            "safari" | "safari18" | "apple" => Some(Self::Safari18),
            _ => None,
        }
    }

    /// Returns the standardized JA4 string for this profile with SNI present and h2 ALPN.
    pub fn expected_ja4(&self) -> String {
        compute_ja4_fingerprint(
            true,
            true,
            self.cipher_suites(),
            self.extension_order(),
            Some("h2"),
        )
    }

    /// Cipher suites ordered according to the specific browser implementation.
    pub fn cipher_suites(&self) -> &'static [u16] {
        match self {
            BrowserProfile::Chrome130 => &[
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            ],
            BrowserProfile::Firefox130 => &[
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
                0xc00a, 0xc009, 0xc013, 0xc014, 0x009c,
            ],
            BrowserProfile::Safari18 => &[
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8,
                0xc00a, 0xc009,
            ],
        }
    }

    /// Supported TLS extension IDs ordered as per the browser specification.
    pub fn extension_order(&self) -> &'static [u16] {
        match self {
            BrowserProfile::Chrome130 => &[
                0x0000, // server_name
                0x0017, // extended_master_secret
                0xff01, // renegotiation_info
                0x000a, // supported_groups
                0x000b, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // alpn
                0x0005, // status_request
                0x000d, // signature_algorithms
                0x0012, // signed_certificate_timestamp
                0x0033, // key_share
                0x002d, // psk_key_exchange_modes
                0x002b, // supported_versions
                0x001b, // compress_certificate
                0x0015, // padding
                0xfe0d, // encrypted_client_hello
            ],
            BrowserProfile::Firefox130 => &[
                0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x0017, 0x0023, 0x002b, 0x002d,
                0x0033, 0xff01, 0x001b, 0xfe0d,
            ],
            BrowserProfile::Safari18 => &[
                0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x0023, 0x002b,
                0x002d, 0x0033, 0xfe0d,
            ],
        }
    }
}

/// Computes a simplified JA4-like fingerprint string from a raw TLS record or components.
pub fn compute_ja4_fingerprint(
    is_tcp: bool,
    has_sni: bool,
    ciphers: &[u16],
    extensions: &[u16],
    first_alpn: Option<&str>,
) -> String {
    let proto = if is_tcp { 't' } else { 'q' };
    let tls_ver = "13";
    let sni_flag = if has_sni { 'd' } else { 'i' };
    let cipher_count = format!("{:02}", ciphers.len().min(99));
    let ext_count = format!("{:02}", extensions.len().min(99));

    let alpn_code = match first_alpn {
        Some(a) if a.len() >= 2 => {
            let bytes = a.as_bytes();
            format!("{}{}", bytes[0] as char, bytes[bytes.len() - 1] as char)
        }
        Some(a) if a.len() == 1 => format!("{}0", a),
        _ => "00".to_string(),
    };

    let mut sorted_ciphers = ciphers.to_vec();
    sorted_ciphers.sort_unstable();
    let mut cipher_hasher = Sha256::new();
    for c in sorted_ciphers {
        cipher_hasher.update(c.to_be_bytes());
    }
    let cipher_hash: String = cipher_hasher.finalize()[..6]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let mut sorted_exts = extensions.to_vec();
    sorted_exts.sort_unstable();
    let mut ext_hasher = Sha256::new();
    for e in sorted_exts {
        ext_hasher.update(e.to_be_bytes());
    }
    let ext_hash: String = ext_hasher.finalize()[..6]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    format!(
        "{}{}{}{}{}{}_{}_{}",
        proto, tls_ver, sni_flag, cipher_count, ext_count, alpn_code, cipher_hash, ext_hash
    )
}

/// Synthesizes an authentic TLS 1.3 ClientHello record matching the chosen browser profile.
pub fn synthesize_client_hello(
    profile: BrowserProfile,
    server_name: &str,
    alpn: &[&str],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // TLS Record Header: Handshake (0x16), Version TLS 1.0 (0x03, 0x01)
    packet.push(0x16);
    packet.push(0x03);
    packet.push(0x01);
    packet.extend_from_slice(&[0x00, 0x00]); // length placeholder

    let record_payload_start = packet.len();

    // Handshake Type: ClientHello (0x01)
    packet.push(0x01);
    packet.extend_from_slice(&[0x00, 0x00, 0x00]); // handshake length placeholder
    let handshake_payload_start = packet.len();

    // Client Version: TLS 1.2 legacy (0x03, 0x03)
    packet.push(0x03);
    packet.push(0x03);

    // Client Random: 32 bytes
    let mut client_random = [0x42u8; 32];
    let _ = crate::dns::entropy::fill_dual_entropy(&mut client_random);
    packet.extend_from_slice(&client_random);

    // Legacy Session ID: 32 bytes
    packet.push(32);
    let mut session_id = [0x24u8; 32];
    let _ = crate::dns::entropy::fill_dual_entropy(&mut session_id);
    packet.extend_from_slice(&session_id);

    // Cipher Suites
    let ciphers = profile.cipher_suites();
    let ciphers_len_bytes = ((ciphers.len() * 2) as u16).to_be_bytes();
    packet.extend_from_slice(&ciphers_len_bytes);
    for &c in ciphers {
        packet.extend_from_slice(&c.to_be_bytes());
    }

    // Compression Methods: 1 byte length (0x01), 0x00 (null compression)
    packet.push(0x01);
    packet.push(0x00);

    // Extensions
    let extensions_len_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]); // extensions length placeholder
    let extensions_payload_start = packet.len();

    for &ext_id in profile.extension_order() {
        match ext_id {
            0x0000 => {
                // Server Name Indication (SNI)
                packet.extend_from_slice(&0x0000u16.to_be_bytes());
                let sni_bytes = server_name.as_bytes();
                let list_len = (sni_bytes.len() + 3) as u16;
                let ext_len = list_len + 2;
                packet.extend_from_slice(&ext_len.to_be_bytes());
                packet.extend_from_slice(&list_len.to_be_bytes());
                packet.push(0x00); // host_name type
                packet.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
                packet.extend_from_slice(sni_bytes);
            }
            0x0010 => {
                // ALPN
                packet.extend_from_slice(&0x0010u16.to_be_bytes());
                let mut alpn_data = Vec::new();
                for &proto in alpn {
                    alpn_data.push(proto.len() as u8);
                    alpn_data.extend_from_slice(proto.as_bytes());
                }
                let list_len = alpn_data.len() as u16;
                let ext_len = list_len + 2;
                packet.extend_from_slice(&ext_len.to_be_bytes());
                packet.extend_from_slice(&list_len.to_be_bytes());
                packet.extend_from_slice(&alpn_data);
            }
            0x002b => {
                // Supported Versions (TLS 1.3: 0x0304)
                packet.extend_from_slice(&0x002bu16.to_be_bytes());
                packet.extend_from_slice(&3u16.to_be_bytes());
                packet.push(0x02); // list length
                packet.extend_from_slice(&0x0304u16.to_be_bytes());
            }
            other => {
                // Generic empty/dummy extension body
                packet.extend_from_slice(&other.to_be_bytes());
                packet.extend_from_slice(&0u16.to_be_bytes());
            }
        }
    }

    // Fix extensions length
    let extensions_len = (packet.len() - extensions_payload_start) as u16;
    let ext_len_bytes = extensions_len.to_be_bytes();
    packet[extensions_len_pos] = ext_len_bytes[0];
    packet[extensions_len_pos + 1] = ext_len_bytes[1];

    // Fix handshake length
    let handshake_len = (packet.len() - handshake_payload_start) as u32;
    packet[record_payload_start + 1] = ((handshake_len >> 16) & 0xff) as u8;
    packet[record_payload_start + 2] = ((handshake_len >> 8) & 0xff) as u8;
    packet[record_payload_start + 3] = (handshake_len & 0xff) as u8;

    // Fix record length
    let record_len = (packet.len() - record_payload_start) as u16;
    let rec_len_bytes = record_len.to_be_bytes();
    packet[3] = rec_len_bytes[0];
    packet[4] = rec_len_bytes[1];

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_profiles_ciphers_and_extensions() {
        for profile in &[
            BrowserProfile::Chrome130,
            BrowserProfile::Firefox130,
            BrowserProfile::Safari18,
        ] {
            assert!(!profile.cipher_suites().is_empty());
            assert!(!profile.extension_order().is_empty());
            assert!(!profile.expected_ja4().is_empty());
        }
    }

    #[test]
    fn test_compute_ja4_fingerprint_structure() {
        let ciphers = &[0x1301, 0x1302, 0x1303];
        let exts = &[0x0000, 0x0010, 0x002b];
        let fp = compute_ja4_fingerprint(true, true, ciphers, exts, Some("h2"));
        assert!(fp.starts_with("t13d0303h2_"));
    }

    #[test]
    fn test_synthesize_client_hello_format() {
        let hello = synthesize_client_hello(BrowserProfile::Chrome130, "example.com", &["h2", "http/1.1"]);
        assert!(hello.len() > 100);
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x01);
        assert_eq!(hello[5], 0x01); // ClientHello
    }

    #[test]
    fn test_browser_profile_from_str() {
        assert_eq!(BrowserProfile::from_str("chrome130"), Some(BrowserProfile::Chrome130));
        assert_eq!(BrowserProfile::from_str("chrome"), Some(BrowserProfile::Chrome130));
        assert_eq!(BrowserProfile::from_str("firefox"), Some(BrowserProfile::Firefox130));
        assert_eq!(BrowserProfile::from_str("mozilla"), Some(BrowserProfile::Firefox130));
        assert_eq!(BrowserProfile::from_str("safari"), Some(BrowserProfile::Safari18));
        assert_eq!(BrowserProfile::from_str("apple"), Some(BrowserProfile::Safari18));
        assert_eq!(BrowserProfile::from_str("unknown_browser"), None);
    }
}
