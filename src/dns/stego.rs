//! cryptographic steganography and covert channel transport engine.
//!
//! disguises encrypted dns packets inside innocent carrier protocols (http cookies,
//! ntp extension packets, and icmp echo payloads) to bypass total protocol blocking.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroize;

/// Carrier protocol format for covert channel encapsulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StegoCarrier {
    HttpCookie,
    NtpExtension,
    IcmpEcho,
}

/// Encapsulates a DNS payload into an HTTP Cookie carrier.
pub fn encode_http_cookie(key: &[u8; 32], nonce: &[u8; 12], dns_payload: &[u8]) -> Result<String, &'static str> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce_val = Nonce::from(*nonce);

    let ciphertext = cipher
        .encrypt(&nonce_val, dns_payload)
        .map_err(|_| "encryption failed")?;

    // Combine nonce (12B) + ciphertext and format as hex cookie
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&ciphertext);

    let hex_data: String = combined.iter().map(|b| format!("{:02x}", b)).collect();
    Ok(format!("__cf_bm={}; path=/; secure; HttpOnly", hex_data))
}

/// Decodes and decrypts a DNS payload from an HTTP Cookie carrier.
pub fn decode_http_cookie(key: &[u8; 32], cookie_header: &str) -> Result<Vec<u8>, &'static str> {
    let prefix = "__cf_bm=";
    let start = cookie_header.find(prefix).ok_or("missing cookie carrier prefix")? + prefix.len();
    let end = cookie_header[start..].find(';').map(|p| start + p).unwrap_or(cookie_header.len());

    let hex_str = &cookie_header[start..end].trim();
    if hex_str.len() < 24 + 32 || (hex_str.len() % 2) != 0 {
        return Err("invalid carrier payload length");
    }

    let mut raw = Vec::with_capacity(hex_str.len() / 2);
    for i in 0..(hex_str.len() / 2) {
        let b = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|_| "invalid hex character in carrier")?;
        raw.push(b);
    }

    let nonce_bytes = &raw[..12];
    let ciphertext = &raw[12..];

    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let mut n = [0u8; 12];
    n.copy_from_slice(nonce_bytes);
    let nonce_val = Nonce::from(n);

    let decrypted = cipher
        .decrypt(&nonce_val, ciphertext)
        .map_err(|_| "covert channel authentication tag mismatch")?;

    Ok(decrypted)
}

/// Encapsulates a DNS payload into an NTP extension field carrier.
pub fn encode_ntp_carrier(key: &[u8; 32], nonce: &[u8; 12], dns_payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce_val = Nonce::from(*nonce);

    let ciphertext = cipher
        .encrypt(&nonce_val, dns_payload)
        .map_err(|_| "encryption failed")?;

    // Standard NTP header (48 bytes) + Extension Field
    let mut ntp_packet = vec![0u8; 48];
    ntp_packet[0] = 0x24; // NTP v4 client

    // Extension Field Type: 0x0104, Length: 4 + 12 + ciphertext
    let field_len = (4 + 12 + ciphertext.len()) as u16;
    ntp_packet.extend_from_slice(&0x0104u16.to_be_bytes());
    ntp_packet.extend_from_slice(&field_len.to_be_bytes());
    ntp_packet.extend_from_slice(nonce);
    ntp_packet.extend_from_slice(&ciphertext);

    Ok(ntp_packet)
}

/// Decodes a DNS payload from an NTP extension field carrier.
pub fn decode_ntp_carrier(key: &[u8; 32], ntp_packet: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ntp_packet.len() < 48 + 4 + 12 + 16 {
        return Err("ntp packet too short for covert carrier");
    }

    let ext_data = &ntp_packet[48..];
    let field_type = u16::from_be_bytes([ext_data[0], ext_data[1]]);
    if field_type != 0x0104 {
        return Err("unrecognized ntp extension field type");
    }

    let field_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
    if ext_data.len() < field_len || field_len < 16 + 16 {
        return Err("truncated ntp extension field");
    }

    let nonce_bytes = &ext_data[4..16];
    let ciphertext = &ext_data[16..field_len];

    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let mut n = [0u8; 12];
    n.copy_from_slice(nonce_bytes);
    let nonce_val = Nonce::from(n);

    cipher
        .decrypt(&nonce_val, ciphertext)
        .map_err(|_| "ntp covert channel auth failure")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_cookie_covert_channel_roundtrip() {
        let key = [0x55u8; 32];
        let nonce = [0x77u8; 12];
        let dns_query = b"encrypted-wire-query-payload";

        let cookie_header = encode_http_cookie(&key, &nonce, dns_query).expect("cookie encoding should succeed");
        assert!(cookie_header.starts_with("__cf_bm="));
        assert!(cookie_header.contains("secure"));

        let recovered = decode_http_cookie(&key, &cookie_header).expect("cookie decoding should succeed");
        assert_eq!(&recovered, dns_query);
    }

    #[test]
    fn test_ntp_covert_channel_roundtrip() {
        let key = [0x99u8; 32];
        let nonce = [0x33u8; 12];
        let dns_query = b"stealthy-ntp-dns-wire";

        let ntp_packet = encode_ntp_carrier(&key, &nonce, dns_query).expect("ntp encoding should succeed");
        assert_eq!(ntp_packet[0], 0x24);
        assert!(ntp_packet.len() >= 48 + 16);

        let recovered = decode_ntp_carrier(&key, &ntp_packet).expect("ntp decoding should succeed");
        assert_eq!(&recovered, dns_query);
    }
}
