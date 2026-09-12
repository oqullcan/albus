//! rfc 9576 & rfc 9577 privacy pass architecture and blind token authorization.
//!
//! provides mathematical unlinkability between dns query submission and authorization,
//! preventing relay-target collusion from attributing queries to specific client sessions.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// RFC 9576 Token Types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TokenType {
    BlindRsa = 0x0001,
    PrivateTokenVoprf = 0x0002,
    Unknown(u16),
}

impl TokenType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x0001 => Self::BlindRsa,
            0x0002 => Self::PrivateTokenVoprf,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            Self::BlindRsa => 0x0001,
            Self::PrivateTokenVoprf => 0x0002,
            Self::Unknown(v) => *v,
        }
    }
}

/// A Token Challenge presented by the server or relay (RFC 9576 Section 5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenChallenge {
    pub token_type: TokenType,
    pub issuer_name: String,
    pub redemption_context: Option<[u8; 32]>,
    pub origin_info: Option<String>,
}

impl TokenChallenge {
    pub fn parse_header(header_value: &str) -> Option<Self> {
        let trimmed = header_value.trim();
        if !trimmed.starts_with("PrivateToken") {
            return None;
        }

        let params = trimmed.trim_start_matches("PrivateToken").trim();
        let mut token_type = TokenType::PrivateTokenVoprf;
        let mut issuer_name = String::new();
        let mut redemption_context = None;
        let mut origin_info = None;

        for part in params.split(',') {
            let kv: Vec<&str> = part.splitn(2, '=').collect();
            if kv.len() == 2 {
                let key = kv[0].trim();
                let val = kv[1].trim().trim_matches('"');
                match key {
                    "token-type" => {
                        if let Ok(tt) = val.parse::<u16>() {
                            token_type = TokenType::from_u16(tt);
                        }
                    }
                    "challenge" | "issuer" => {
                        issuer_name = val.to_string();
                    }
                    "redemption-context" => {
                        if val.len() == 64 {
                            let mut ctx = [0u8; 32];
                            for i in 0..32 {
                                if let Ok(b) = u8::from_str_radix(&val[i * 2..i * 2 + 2], 16) {
                                    ctx[i] = b;
                                }
                            }
                            redemption_context = Some(ctx);
                        }
                    }
                    "origin-info" => {
                        origin_info = Some(val.to_string());
                    }
                    _ => {}
                }
            }
        }

        Some(Self {
            token_type,
            issuer_name,
            redemption_context,
            origin_info,
        })
    }
}

/// An Unblinded Redemption Token (RFC 9576 Section 5.3) presented with a DNS query.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct RedemptionToken {
    pub token_type: u16,
    pub key_id: [u8; 32],
    pub token_authenticator: Vec<u8>,
    pub nonce: [u8; 32],
}

impl std::fmt::Debug for RedemptionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedemptionToken { key_id: [REDACTED], token_authenticator: [REDACTED] }")
    }
}

impl RedemptionToken {
    /// Serializes redemption token into binary wire representation.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 32 + 32 + 2 + self.token_authenticator.len());
        buf.extend_from_slice(&self.token_type.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.key_id);
        buf.extend_from_slice(&(self.token_authenticator.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.token_authenticator);
        buf
    }

    /// Parses redemption token from binary wire bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 2 + 32 + 32 + 2 {
            return Err("token wire bytes too short");
        }

        let token_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&bytes[2..34]);

        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(&bytes[34..66]);

        let auth_len = u16::from_be_bytes([bytes[66], bytes[67]]) as usize;
        if bytes.len() < 68 + auth_len {
            return Err("token authenticator payload truncated");
        }

        let token_authenticator = bytes[68..68 + auth_len].to_vec();

        Ok(Self {
            token_type,
            key_id,
            token_authenticator,
            nonce,
        })
    }

    /// Verifies token integrity in constant time against an expected authenticator.
    pub fn verify_constant_time(&self, expected_authenticator: &[u8]) -> bool {
        if self.token_authenticator.len() != expected_authenticator.len() {
            return false;
        }
        self.token_authenticator
            .ct_eq(expected_authenticator)
            .unwrap_u8()
            == 1
    }

    /// Derives deterministic token identifier for replay cache indexing without revealing token secret.
    pub fn compute_tag(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.token_type.to_be_bytes());
        hasher.update(&self.nonce);
        hasher.update(&self.key_id);
        let hash = hasher.finalize();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&hash);
        tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_challenge_parsing() {
        let header = "PrivateToken challenge=\"example-issuer\", token-type=2, origin-info=\"target.albus.internal\"";
        let challenge = TokenChallenge::parse_header(header).expect("must parse header");
        assert_eq!(challenge.token_type, TokenType::PrivateTokenVoprf);
        assert_eq!(challenge.issuer_name, "example-issuer");
        assert_eq!(challenge.origin_info.as_deref(), Some("target.albus.internal"));
    }

    #[test]
    fn test_redemption_token_roundtrip() {
        let token = RedemptionToken {
            token_type: 2,
            key_id: [0x55; 32],
            token_authenticator: vec![0xaa; 64],
            nonce: [0x77; 32],
        };

        let encoded = token.encode();
        let parsed = RedemptionToken::parse(&encoded).expect("token must parse");
        assert_eq!(parsed.token_type, 2);
        assert_eq!(parsed.key_id, [0x55; 32]);
        assert_eq!(parsed.nonce, [0x77; 32]);
        assert!(parsed.verify_constant_time(&[0xaa; 64]));
        assert!(!parsed.verify_constant_time(&[0xbb; 64]));

        // verify debug string is redacted
        let dbg = format!("{:?}", token);
        assert!(dbg.contains("REDACTED"));
    }
}
