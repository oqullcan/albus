//! rfc 5246 / rfc 8446 compliant tls clienthello record generator with custom server name indication and post-quantum kyber768 key shares.

use std::sync::LazyLock;

// static pre-compiled clienthello payload embedding www.google.com sni
pub static FAKE_TLS_CLIENT_HELLO: LazyLock<Vec<u8>> = LazyLock::new(|| build_fake_client_hello("www.google.com"));

// constructs valid binary tls record containing handshake protocol and sni extension
pub fn build_fake_client_hello(sni_host: &str) -> Vec<u8> {
    build_fake_client_hello_opts(sni_host, true)
}

// constructs valid tls clienthello with optional post-quantum cryptography (ml-kem / kyber768) extensions
pub fn build_fake_client_hello_opts(sni_host: &str, pqc: bool) -> Vec<u8> {
    let sni_bytes = sni_host.as_bytes();
    let sni_len = sni_bytes.len();

    // 1. server name indication extension payload (rfc 6066):
    // name_type (0x00 host_name) + host_name_length (2 bytes) + host_name_bytes
    let mut sni_payload = Vec::with_capacity(1 + 2 + sni_len);
    sni_payload.push(0x00);
    sni_payload.push((sni_len >> 8) as u8);
    sni_payload.push(sni_len as u8);
    sni_payload.extend_from_slice(sni_bytes);

    // 2. sni server name list container
    let sni_list_len = sni_payload.len();
    let mut sni_ext_data = Vec::with_capacity(2 + sni_list_len);
    sni_ext_data.push((sni_list_len >> 8) as u8);
    sni_ext_data.push(sni_list_len as u8);
    sni_ext_data.extend_from_slice(&sni_payload);

    // 3. extension header: extension_type (0x0000) + extension_data_length (2 bytes)
    let mut sni_ext = Vec::with_capacity(4 + sni_ext_data.len());
    sni_ext.push(0x00);
    sni_ext.push(0x00);
    sni_ext.push((sni_ext_data.len() >> 8) as u8);
    sni_ext.push(sni_ext_data.len() as u8);
    sni_ext.extend_from_slice(&sni_ext_data);

    // 4. assemble extensions container
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);

    if pqc {
        // supported_groups extension (0x000a) with x25519kyber768draft00 (0x6399) and secp256r1mlkem768 (0x11ec)
        let groups_ext: [u8; 10] = [
            0x00, 0x0a, // extension type: supported_groups
            0x00, 0x06, // extension data length: 6
            0x00, 0x04, // supported group list length: 4
            0x63, 0x99, // x25519kyber768draft00
            0x11, 0xec, // secp256r1mlkem768
        ];
        extensions.extend_from_slice(&groups_ext);

        // key_share extension (0x0033) with synthetic hybrid kyber768 client share
        let mut key_share_entry = Vec::with_capacity(4 + 32 + 32);
        key_share_entry.push(0x63); // group 0x6399 (x25519kyber768draft00)
        key_share_entry.push(0x99);
        key_share_entry.push(0x00); // key exchange length (32 bytes)
        key_share_entry.push(0x20);
        key_share_entry.extend_from_slice(&[0x42; 32]); // synthetic x25519 + kyber public share

        let ks_list_len = key_share_entry.len();
        let mut key_share_data = Vec::with_capacity(2 + ks_list_len);
        key_share_data.push((ks_list_len >> 8) as u8);
        key_share_data.push(ks_list_len as u8);
        key_share_data.extend_from_slice(&key_share_entry);

        let mut key_share_ext = Vec::with_capacity(4 + key_share_data.len());
        key_share_ext.push(0x00); // extension type: key_share (0x0033)
        key_share_ext.push(0x33);
        key_share_ext.push((key_share_data.len() >> 8) as u8);
        key_share_ext.push(key_share_data.len() as u8);
        key_share_ext.extend_from_slice(&key_share_data);

        extensions.extend_from_slice(&key_share_ext);
    }

    // 5. clienthello structure
    let mut body = Vec::new();
    body.push(0x03); // client_version major (tls 1.2 legacy)
    body.push(0x03); // client_version minor
    body.extend_from_slice(&[0u8; 32]); // 32-byte client random
    body.push(0x00); // legacy_session_id vector length
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites (tls_aes_128_gcm_sha256)
    body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods (null compression)

    // 6. append extensions vector length and contents
    body.push((extensions.len() >> 8) as u8);
    body.push(extensions.len() as u8);
    body.extend_from_slice(&extensions);

    // 7. handshake header: msg_type (0x01 client_hello) + length (uint24)
    let mut handshake = Vec::with_capacity(4 + body.len());
    handshake.push(0x01);
    let body_len = body.len();
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&body);

    // 8. tls plaintext record layer header: content_type (0x16 handshake) + legacy_version (0x0301) + length
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(0x16);
    record.push(0x03);
    record.push(0x01);
    let hs_len = handshake.len();
    record.push((hs_len >> 8) as u8);
    record.push(hs_len as u8);
    record.extend_from_slice(&handshake);

    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_structure() {
        let ch = &FAKE_TLS_CLIENT_HELLO;
        assert!(ch.len() >= 5, "clienthello record too short");

        // record layer validation
        assert_eq!(ch[0], 0x16, "content type must be handshake (0x16)");
        assert_eq!(ch[1], 0x03, "major version 3");
        assert_eq!(ch[2], 0x01, "minor version 1");

        let record_len = ((ch[3] as usize) << 8) | (ch[4] as usize);
        assert_eq!(record_len, ch.len() - 5, "record length mismatch");

        // handshake layer validation
        assert_eq!(ch[5], 0x01, "handshake type must be clienthello (0x01)");
        let hs_len = ((ch[6] as usize) << 16) | ((ch[7] as usize) << 8) | (ch[8] as usize);
        assert_eq!(hs_len, ch.len() - 9, "handshake length mismatch");

        // client version validation
        assert_eq!(ch[9], 0x03, "client version major");
        assert_eq!(ch[10], 0x03, "client version minor");

        // verify embedded hostname
        let sni_bytes = b"www.google.com";
        assert!(
            ch.windows(sni_bytes.len()).any(|w| w == sni_bytes),
            "clienthello must contain sni www.google.com"
        );
    }

    #[test]
    fn test_pqc_kyber768_extension_present() {
        let pqc_ch = build_fake_client_hello_opts("pqc.test.org", true);
        // verify x25519kyber768draft00 group identifier (0x6399) is present
        assert!(
            pqc_ch.windows(2).any(|w| w == [0x63, 0x99]),
            "post-quantum clienthello must contain kyber768 group 0x6399"
        );
    }
}
