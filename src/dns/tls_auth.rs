//! x.509 client certificate and private key pem parser for mtls authentication.
//!
//! loads rfc 5280 client certificate chains and pkcs#8 / pkcs#1 / sec1 private keys
//! to authenticate albus to private/enterprise doh resolvers.

use std::fs;
use std::path::Path;

fn decode_b64(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    while clean.len() % 4 != 0 {
        clean.push('=');
    }

    const B64_TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut map = [255u8; 256];
    for (i, &b) in B64_TABLE.iter().enumerate() {
        map[b as usize] = i as u8;
    }

    let bytes = clean.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);

    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let b0 = map[chunk[0] as usize];
        let b1 = map[chunk[1] as usize];
        let b2 = if chunk[2] == b'=' {
            0
        } else {
            map[chunk[2] as usize]
        };
        let b3 = if chunk[3] == b'=' {
            0
        } else {
            map[chunk[3] as usize]
        };

        if b0 == 255 || b1 == 255 || b2 == 255 || b3 == 255 {
            return Err("invalid base64 character in PEM".into());
        }
        if chunk[2] == b'=' && chunk[3] != b'=' {
            return Err("invalid base64 padding in PEM".into());
        }

        let triple = ((b0 as u32) << 18) | ((b1 as u32) << 12) | ((b2 as u32) << 6) | (b3 as u32);
        out.push(((triple >> 16) & 0xff) as u8);
        if chunk[2] != b'=' {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if chunk[3] != b'=' {
            out.push((triple & 0xff) as u8);
        }
    }

    Ok(out)
}

pub fn parse_pem_certificates(
    pem_str: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>>
{
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut b64_buf = String::new();

    for line in pem_str.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            b64_buf.clear();
        } else if trimmed == "-----END CERTIFICATE-----" {
            if in_cert {
                let der = decode_b64(&b64_buf)?;
                certs.push(rustls::pki_types::CertificateDer::from(der));
                in_cert = false;
            }
        } else if in_cert {
            b64_buf.push_str(trimmed);
        }
    }

    if certs.is_empty() {
        return Err("no valid X.509 certificates found in PEM data".into());
    }
    Ok(certs)
}

pub fn parse_pem_private_key(
    pem_str: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let mut in_key = false;
    let mut key_type = "";
    let mut b64_buf = String::new();

    for line in pem_str.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN PRIVATE KEY-----" {
            in_key = true;
            key_type = "pkcs8";
            b64_buf.clear();
        } else if trimmed == "-----BEGIN RSA PRIVATE KEY-----" {
            in_key = true;
            key_type = "pkcs1";
            b64_buf.clear();
        } else if trimmed == "-----BEGIN EC PRIVATE KEY-----" {
            in_key = true;
            key_type = "sec1";
            b64_buf.clear();
        } else if trimmed.starts_with("-----END ") && trimmed.ends_with("-----") {
            if in_key {
                let der = decode_b64(&b64_buf)?;
                return match key_type {
                    "pkcs8" => Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(der.into())),
                    "pkcs1" => Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(der.into())),
                    "sec1" => Ok(rustls::pki_types::PrivateKeyDer::Sec1(der.into())),
                    _ => Err("unsupported private key format".into()),
                };
            }
        } else if in_key {
            b64_buf.push_str(trimmed);
        }
    }

    Err("no supported private key (PKCS#8, PKCS#1, or SEC1) found in PEM data".into())
}

pub struct TlsClientAuth {
    pub certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl Clone for TlsClientAuth {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl TlsClientAuth {
    pub fn from_files<P: AsRef<Path>>(
        cert_path: P,
        key_path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (certs, key) = load_client_auth_from_files(cert_path, key_path)?;
        Ok(Self { certs, key })
    }
}

pub fn load_client_auth_from_files<P: AsRef<Path>>(
    cert_path: P,
    key_path: P,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let cert_pem = fs::read_to_string(cert_path)?;
    let key_pem = fs::read_to_string(key_path)?;

    let certs = parse_pem_certificates(&cert_pem)?;
    let key = parse_pem_private_key(&key_pem)?;
    Ok((certs, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBqDCCAVCgAwIBAgIUeN7h93Q7Q1YwDQYJKoZIhvcNAQELBQAwEDEOMAwGA1UE
AwwFdGVzdDAeFw0yNjA5MDYwMDAwMDBaFw0yNzA5MDYwMDAwMDBaMBEDEOMAwGA1
UEAwwFdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ/3O5Z21o3Y2m0y
-----END CERTIFICATE-----
";

    const SAMPLE_PKCS8_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOGe5/89qU5sY0m1n2p3q4r5s6t7u8v9w0x1y2z3a4b5
-----END PRIVATE KEY-----
";

    const SAMPLE_RSA_KEY_PEM: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAL7K4AAA
-----END RSA PRIVATE KEY-----
";

    const SAMPLE_EC_KEY_PEM: &str = "\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPf9876543210000
-----END EC PRIVATE KEY-----
";

    #[test]
    fn test_parse_pem_certificates_valid() {
        let certs = parse_pem_certificates(SAMPLE_CERT_PEM).expect("should parse valid cert");
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_empty());
    }

    #[test]
    fn test_parse_pem_certificates_empty_err() {
        let res = parse_pem_certificates("no certificates here");
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_pem_private_key_variants() {
        let k1 = parse_pem_private_key(SAMPLE_PKCS8_KEY_PEM).expect("pkcs8 should parse");
        match k1 {
            rustls::pki_types::PrivateKeyDer::Pkcs8(_) => {}
            _ => panic!("expected Pkcs8 variant"),
        }

        let k2 = parse_pem_private_key(SAMPLE_RSA_KEY_PEM).expect("pkcs1 should parse");
        match k2 {
            rustls::pki_types::PrivateKeyDer::Pkcs1(_) => {}
            _ => panic!("expected Pkcs1 variant"),
        }

        let k3 = parse_pem_private_key(SAMPLE_EC_KEY_PEM).expect("sec1 should parse");
        match k3 {
            rustls::pki_types::PrivateKeyDer::Sec1(_) => {}
            _ => panic!("expected Sec1 variant"),
        }
    }

    #[test]
    fn test_parse_pem_private_key_missing() {
        let res = parse_pem_private_key("just some random text");
        assert!(res.is_err());
    }
}
