//! Post-quantum DNSSEC algorithm presence inspection (ML-DSA, SLH-DSA),
//! IANA root trust anchor pinning (KSK-2017, KSK-2024), and RFC 4035 anti-downgrade policy engine.
//!
//! Note: Detects post-quantum algorithms and defends against downgrade attacks while relying on
//! upstream resolver authenticated data (AD bit) validation without local ML-DSA signature computation.

use std::fmt;

/// IANA DNSSEC signature algorithms (RFC 4034, RFC 8624, draft-ietf-dnsop-postquantum-dnssec).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DnssecAlgorithm {
    RsaMd5,
    DsaSha1,
    RsaSha1,
    RsaSha1Nsec3,
    RsaSha256,
    RsaSha512,
    GostR3410,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
    Ed448,
    Falcon512,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    Unknown(u8),
}

impl DnssecAlgorithm {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::RsaMd5,
            3 => Self::DsaSha1,
            5 => Self::RsaSha1,
            7 => Self::RsaSha1Nsec3,
            8 => Self::RsaSha256,
            10 => Self::RsaSha512,
            12 => Self::GostR3410,
            13 => Self::EcdsaP256Sha256,
            14 => Self::EcdsaP384Sha384,
            15 => Self::Ed25519,
            16 => Self::Ed448,
            17 => Self::Falcon512,
            18 => Self::MlDsa44,
            19 => Self::MlDsa65,
            20 => Self::MlDsa87,
            21 => Self::SlhDsaSha2_128s,
            22 => Self::SlhDsaSha2_128f,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            Self::RsaMd5 => 1,
            Self::DsaSha1 => 3,
            Self::RsaSha1 => 5,
            Self::RsaSha1Nsec3 => 7,
            Self::RsaSha256 => 8,
            Self::RsaSha512 => 10,
            Self::GostR3410 => 12,
            Self::EcdsaP256Sha256 => 13,
            Self::EcdsaP384Sha384 => 14,
            Self::Ed25519 => 15,
            Self::Ed448 => 16,
            Self::Falcon512 => 17,
            Self::MlDsa44 => 18,
            Self::MlDsa65 => 19,
            Self::MlDsa87 => 20,
            Self::SlhDsaSha2_128s => 21,
            Self::SlhDsaSha2_128f => 22,
            Self::Unknown(n) => *n,
        }
    }

    /// Returns true if this algorithm is a post-quantum lattice-based or hash-based signature scheme.
    #[inline]
    pub fn is_post_quantum(&self) -> bool {
        matches!(
            self,
            Self::MlDsa44
                | Self::MlDsa65
                | Self::MlDsa87
                | Self::Falcon512
                | Self::SlhDsaSha2_128s
                | Self::SlhDsaSha2_128f
        )
    }

    /// Returns true if the algorithm is cryptographically deprecated or broken.
    #[inline]
    pub fn is_deprecated(&self) -> bool {
        matches!(
            self,
            Self::RsaMd5 | Self::DsaSha1 | Self::RsaSha1 | Self::RsaSha1Nsec3
        )
    }

    /// Returns expected signature length in bytes if fixed for this algorithm.
    pub fn expected_signature_len(&self) -> Option<usize> {
        match self {
            Self::EcdsaP256Sha256 => Some(64),
            Self::EcdsaP384Sha384 => Some(96),
            Self::Ed25519 => Some(64),
            Self::Ed448 => Some(114),
            Self::MlDsa44 => Some(2420), // 2,420 bytes for NIST FIPS 204 ML-DSA-44
            Self::MlDsa65 => Some(3309), // 3,309 bytes for NIST FIPS 204 ML-DSA-65
            Self::MlDsa87 => Some(4627), // 4,627 bytes for NIST FIPS 204 ML-DSA-87
            Self::SlhDsaSha2_128s => Some(7856), // NIST FIPS 205 SLH-DSA-SHA2-128s
            Self::SlhDsaSha2_128f => Some(17088), // NIST FIPS 205 SLH-DSA-SHA2-128f
            Self::Falcon512 => Some(666),
            _ => None,
        }
    }

    /// Returns expected public key length in bytes if known.
    pub fn expected_public_key_len(&self) -> Option<usize> {
        match self {
            Self::EcdsaP256Sha256 => Some(64),
            Self::EcdsaP384Sha384 => Some(96),
            Self::Ed25519 => Some(32),
            Self::Ed448 => Some(57),
            Self::MlDsa44 => Some(1312), // 1,312 bytes for ML-DSA-44 public key
            Self::MlDsa65 => Some(1952), // 1,952 bytes for ML-DSA-65 public key
            Self::MlDsa87 => Some(2592), // 2,592 bytes for ML-DSA-87 public key
            Self::SlhDsaSha2_128s => Some(32), // 32 bytes for SLH-DSA public key
            Self::SlhDsaSha2_128f => Some(32),
            Self::Falcon512 => Some(897),
            _ => None,
        }
    }
}

impl fmt::Display for DnssecAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MlDsa44 => write!(f, "ML-DSA-44 (18) [Post-Quantum]"),
            Self::MlDsa65 => write!(f, "ML-DSA-65 (19) [Post-Quantum]"),
            Self::MlDsa87 => write!(f, "ML-DSA-87 (20) [Post-Quantum]"),
            Self::SlhDsaSha2_128s => write!(f, "SLH-DSA-SHA2-128s (21) [Post-Quantum]"),
            Self::SlhDsaSha2_128f => write!(f, "SLH-DSA-SHA2-128f (22) [Post-Quantum]"),
            Self::Falcon512 => write!(f, "Falcon-512 (17) [Post-Quantum]"),
            Self::Ed25519 => write!(f, "Ed25519 (15)"),
            Self::Ed448 => write!(f, "Ed448 (16)"),
            Self::EcdsaP256Sha256 => write!(f, "ECDSA-P256-SHA256 (13)"),
            Self::EcdsaP384Sha384 => write!(f, "ECDSA-P384-SHA384 (14)"),
            Self::RsaSha256 => write!(f, "RSA-SHA256 (8)"),
            Self::RsaSha512 => write!(f, "RSA-SHA512 (10)"),
            Self::Unknown(n) => write!(f, "Algorithm-{}", n),
            other => write!(f, "{:?}", other),
        }
    }
}

/// Parsed RRSIG Resource Record (RFC 4034 Section 3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RrsigRecord {
    pub type_covered: u16,
    pub algorithm: DnssecAlgorithm,
    pub labels: u8,
    pub original_ttl: u32,
    pub sig_expiration: u32,
    pub sig_inception: u32,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature_len: usize,
}

/// Parsed DS (Delegation Signer) Resource Record (RFC 4034 Section 5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsRecord {
    pub key_tag: u16,
    pub algorithm: DnssecAlgorithm,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

/// Parsed DNSKEY Resource Record (RFC 4034 Section 2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnskeyRecord {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: DnssecAlgorithm,
    pub public_key_len: usize,
}

/// Official IANA Root Zone Trust Anchors (RFC 7958).
#[derive(Clone, Debug)]
pub struct RootTrustAnchor {
    pub anchors: Vec<DsRecord>,
}

impl Default for RootTrustAnchor {
    fn default() -> Self {
        Self::iana_root_anchors()
    }
}

impl RootTrustAnchor {
    /// Returns default official IANA root zone trust anchors (KSK-2017 Key Tag 20326 and KSK-2024 Key Tag 38696).
    pub fn iana_root_anchors() -> Self {
        let ksk_2017_digest = [
            0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65,
            0xD0, 0x84, 0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37,
            0xC7, 0xF8, 0xEC, 0x8D,
        ];
        let ksk_2024_digest = [
            0x5B, 0x5A, 0x33, 0xD6, 0x2D, 0x15, 0x40, 0xCE, 0xFF, 0x39, 0xA7, 0xF8, 0x5D, 0x3B,
            0x89, 0x59, 0xDF, 0x0A, 0x07, 0xB3, 0x76, 0x22, 0x83, 0x08, 0x7D, 0x81, 0x3F, 0xEA,
            0x58, 0x68, 0xB4, 0x5B,
        ];

        Self {
            anchors: vec![
                DsRecord {
                    key_tag: 20326,
                    algorithm: DnssecAlgorithm::RsaSha256,
                    digest_type: 2,
                    digest: ksk_2017_digest.to_vec(),
                },
                DsRecord {
                    key_tag: 38696,
                    algorithm: DnssecAlgorithm::RsaSha256,
                    digest_type: 2,
                    digest: ksk_2024_digest.to_vec(),
                },
            ],
        }
    }

    /// Verifies whether a DNSKEY matches one of the trusted root trust anchors.
    pub fn verify_root_dnskey(
        &self,
        flags: u16,
        protocol: u8,
        algorithm: DnssecAlgorithm,
        public_key: &[u8],
    ) -> bool {
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;

        let mut wire_dnskey = Vec::with_capacity(1 + 2 + 1 + 1 + public_key.len());
        wire_dnskey.push(0x00);
        wire_dnskey.extend_from_slice(&flags.to_be_bytes());
        wire_dnskey.push(protocol);
        wire_dnskey.push(algorithm.as_u8());
        wire_dnskey.extend_from_slice(public_key);

        let mut ac: u32 = 0;
        let bytes_for_tag = &wire_dnskey[1..];
        for (i, &b) in bytes_for_tag.iter().enumerate() {
            ac += if (i & 1) != 0 {
                b as u32
            } else {
                (b as u32) << 8
            };
        }
        ac += (ac >> 16) & 0xFFFF;
        let computed_tag = (ac & 0xFFFF) as u16;

        let digest: [u8; 32] = Sha256::digest(&wire_dnskey).into();

        for anchor in &self.anchors {
            if anchor.key_tag == computed_tag
                && anchor.algorithm == algorithm
                && anchor.digest_type == 2
            {
                if anchor.digest.as_slice().ct_eq(&digest).unwrap_u8() == 1 {
                    return true;
                }
            }
        }

        false
    }
}

/// Summary report of DNSSEC properties in a DNS wire response.
#[derive(Clone, Debug, Default)]
pub struct DnssecReport {
    pub authenticated: bool, // AD bit set in DNS header
    pub rrsigs: Vec<RrsigRecord>,
    pub ds_records: Vec<DsRecord>,
    pub dnskeys: Vec<DnskeyRecord>,
    pub has_pqc_rrsig: bool,
    pub has_pqc_ds_signal: bool,
    pub has_classical_rrsig: bool,
}

/// Downgrade violation types when anti-downgrade local validation policy is enforced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DowngradeViolation {
    /// Parent DS record signaled Algorithm 18 (ML-DSA-44) support, but no ML-DSA-44 RRSIG was present in response.
    PqcSignatureStripped,
    /// Post-quantum signature was present, but upstream response was not authenticated (AD bit false).
    PqcNotAuthenticated,
}

impl fmt::Display for DowngradeViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PqcSignatureStripped => write!(
                f,
                "DNSSEC downgrade attack detected: parent DS signaled ML-DSA-44 (18), but post-quantum RRSIG is missing"
            ),
            Self::PqcNotAuthenticated => write!(
                f,
                "Post-quantum DNSSEC validation failed: ML-DSA-44 signature present without AD bit"
            ),
        }
    }
}

impl std::error::Error for DowngradeViolation {}

/// Inspects a DNS response wire packet and extracts DNSSEC telemetry and post-quantum indicators.
pub fn inspect_response_dnssec(wire: &[u8]) -> DnssecReport {
    let mut report = DnssecReport::default();
    if wire.len() < 12 {
        return report;
    }

    // Check AD (Authenticated Data) bit: Byte 3, bit 5 (0x20)
    report.authenticated = (wire[3] & 0x20) != 0;

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;
    let nscount = u16::from_be_bytes([wire[8], wire[9]]) as usize;
    let arcount = u16::from_be_bytes([wire[10], wire[11]]) as usize;

    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        if let Some((_, next_pos)) = skip_dns_name(wire, pos) {
            pos = next_pos + 4; // QTYPE (2) + QCLASS (2)
            if pos > wire.len() {
                return report;
            }
        } else {
            return report;
        }
    }

    let total_rrs = ancount + nscount + arcount;
    for _ in 0..total_rrs {
        if pos >= wire.len() {
            break;
        }

        let next_pos = match skip_dns_name(wire, pos) {
            Some((_, p)) => p,
            None => break,
        };

        if next_pos + 10 > wire.len() {
            break;
        }

        let rr_type = u16::from_be_bytes([wire[next_pos], wire[next_pos + 1]]);
        let _rr_class = u16::from_be_bytes([wire[next_pos + 2], wire[next_pos + 3]]);
        let _rr_ttl = u32::from_be_bytes([
            wire[next_pos + 4],
            wire[next_pos + 5],
            wire[next_pos + 6],
            wire[next_pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([wire[next_pos + 8], wire[next_pos + 9]]) as usize;
        let rdata_start = next_pos + 10;
        let rdata_end = rdata_start + rdlength;

        if rdata_end > wire.len() {
            break;
        }

        let rdata = &wire[rdata_start..rdata_end];

        match rr_type {
            46 => {
                // RRSIG
                if let Some(rrsig) = parse_rrsig(rdata, wire) {
                    if rrsig.algorithm.is_post_quantum() {
                        report.has_pqc_rrsig = true;
                    } else {
                        report.has_classical_rrsig = true;
                    }
                    report.rrsigs.push(rrsig);
                }
            }
            43 => {
                // DS
                if let Some(ds) = parse_ds(rdata) {
                    if ds.algorithm.is_post_quantum() {
                        report.has_pqc_ds_signal = true;
                    }
                    report.ds_records.push(ds);
                }
            }
            48 => {
                // DNSKEY
                if let Some(dnskey) = parse_dnskey(rdata) {
                    report.dnskeys.push(dnskey);
                }
            }
            _ => {}
        }

        pos = rdata_end;
    }

    report
}

/// Evaluates RFC 4035 / Cloudflare local validation anti-downgrade policy.
///
/// When the parent DS record announces an Algorithm 18 (ML-DSA-44) key, this policy
/// refuses fallback to classical algorithms (ECDSA/RSA), ensuring quantum adversaries
/// cannot strip post-quantum signatures and force validation over weakened algorithms.
pub fn check_anti_downgrade(report: &DnssecReport) -> Result<(), DowngradeViolation> {
    if report.has_pqc_ds_signal && !report.has_pqc_rrsig {
        return Err(DowngradeViolation::PqcSignatureStripped);
    }

    if report.has_pqc_rrsig && !report.authenticated {
        return Err(DowngradeViolation::PqcNotAuthenticated);
    }

    Ok(())
}

/// Parses an RRSIG record from its RDATA payload (RFC 4034 Section 3.1).
fn parse_rrsig(rdata: &[u8], wire: &[u8]) -> Option<RrsigRecord> {
    if rdata.len() < 18 {
        return None;
    }

    let type_covered = u16::from_be_bytes([rdata[0], rdata[1]]);
    let algorithm = DnssecAlgorithm::from_u8(rdata[2]);
    let labels = rdata[3];
    let original_ttl = u32::from_be_bytes([rdata[4], rdata[5], rdata[6], rdata[7]]);
    let sig_expiration = u32::from_be_bytes([rdata[8], rdata[9], rdata[10], rdata[11]]);
    let sig_inception = u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]);
    let key_tag = u16::from_be_bytes([rdata[16], rdata[17]]);

    // RFC 4034: Signer's name starts at offset 18
    let (signer_name, name_end_offset) = parse_uncompressed_name(&rdata[18..])?;
    let signature_start = 18 + name_end_offset;
    if signature_start > rdata.len() {
        return None;
    }

    let signature_len = rdata.len() - signature_start;

    Some(RrsigRecord {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        sig_expiration,
        sig_inception,
        key_tag,
        signer_name,
        signature_len,
    })
}

/// Parses a DS record from its RDATA payload (RFC 4034 Section 5.1).
fn parse_ds(rdata: &[u8]) -> Option<DsRecord> {
    if rdata.len() < 4 {
        return None;
    }

    let key_tag = u16::from_be_bytes([rdata[0], rdata[1]]);
    let algorithm = DnssecAlgorithm::from_u8(rdata[2]);
    let digest_type = rdata[3];
    let digest = rdata[4..].to_vec();

    Some(DsRecord {
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

/// Parses a DNSKEY record from its RDATA payload (RFC 4034 Section 2.1).
fn parse_dnskey(rdata: &[u8]) -> Option<DnskeyRecord> {
    if rdata.len() < 4 {
        return None;
    }

    let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
    let protocol = rdata[2];
    let algorithm = DnssecAlgorithm::from_u8(rdata[3]);
    let public_key_len = rdata.len() - 4;

    Some(DnskeyRecord {
        flags,
        protocol,
        algorithm,
        public_key_len,
    })
}

/// Skips over a DNS domain name in wire format (supporting uncompressed labels and compression pointers).
fn skip_dns_name(wire: &[u8], mut pos: usize) -> Option<((), usize)> {
    let mut jumped = false;
    let mut return_pos = pos;
    let mut jumps = 0;
    const MAX_JUMPS: usize = 5;

    while pos < wire.len() {
        let len = wire[pos] as usize;
        if len == 0 {
            if !jumped {
                return_pos = pos + 1;
            }
            return Some(((), return_pos));
        }

        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= wire.len() {
                return None;
            }
            let pointer = ((len & 0x3F) << 8) | (wire[pos + 1] as usize);
            if !jumped {
                return_pos = pos + 2;
                jumped = true;
            }
            jumps += 1;
            if jumps > MAX_JUMPS || pointer >= wire.len() {
                return None;
            }
            pos = pointer;
            continue;
        }

        pos += 1 + len;
        if !jumped {
            return_pos = pos;
        }
    }

    None
}

/// Parses an uncompressed wire name (RFC 4034 requires RRSIG Signer's Name to be uncompressed).
fn parse_uncompressed_name(slice: &[u8]) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = 0;

    while pos < slice.len() {
        let len = slice[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) != 0 {
            // Compressed pointer not permitted in RRSIG signer's name
            return None;
        }
        pos += 1;
        if pos + len > slice.len() {
            return None;
        }
        if let Ok(label) = std::str::from_utf8(&slice[pos..pos + len]) {
            labels.push(label);
        } else {
            return None;
        }
        pos += len;
    }

    Some((labels.join("."), pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dnssec_algorithm_properties() {
        assert_eq!(DnssecAlgorithm::from_u8(18), DnssecAlgorithm::MlDsa44);
        assert!(DnssecAlgorithm::MlDsa44.is_post_quantum());
        assert!(!DnssecAlgorithm::MlDsa44.is_deprecated());
        assert_eq!(
            DnssecAlgorithm::MlDsa44.expected_signature_len(),
            Some(2420)
        );
        assert_eq!(
            DnssecAlgorithm::MlDsa44.expected_public_key_len(),
            Some(1312)
        );

        assert_eq!(
            DnssecAlgorithm::from_u8(13),
            DnssecAlgorithm::EcdsaP256Sha256
        );
        assert!(!DnssecAlgorithm::EcdsaP256Sha256.is_post_quantum());
        assert_eq!(
            DnssecAlgorithm::EcdsaP256Sha256.expected_signature_len(),
            Some(64)
        );

        assert_eq!(DnssecAlgorithm::from_u8(1), DnssecAlgorithm::RsaMd5);
        assert!(DnssecAlgorithm::RsaMd5.is_deprecated());
    }

    #[test]
    fn test_rrsig_mldsa44_wire_parsing() {
        // Construct a synthetic RRSIG with ML-DSA-44 (algorithm 18) and 2420-byte signature
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // Type Covered = A (1)
        rdata.push(18); // Algorithm = 18 (ML-DSA-44)
        rdata.push(4); // Labels = 4
        rdata.extend_from_slice(&300u32.to_be_bytes()); // Original TTL = 300
        rdata.extend_from_slice(&1789166009u32.to_be_bytes()); // Expiration
        rdata.extend_from_slice(&1789076009u32.to_be_bytes()); // Inception
        rdata.extend_from_slice(&23176u16.to_be_bytes()); // Key Tag = 23176

        // Signer's Name: valid.mldsa44.dnstest.dev. (uncompressed labels)
        for label in ["valid", "mldsa44", "dnstest", "dev"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0x00); // Root label

        // 2,420 bytes dummy ML-DSA-44 signature payload
        let fake_sig = vec![0x42u8; 2420];
        rdata.extend_from_slice(&fake_sig);

        let parsed = parse_rrsig(&rdata, &rdata).expect("RRSIG parsing must succeed");
        assert_eq!(parsed.type_covered, 1);
        assert_eq!(parsed.algorithm, DnssecAlgorithm::MlDsa44);
        assert_eq!(parsed.labels, 4);
        assert_eq!(parsed.key_tag, 23176);
        assert_eq!(parsed.signer_name, "valid.mldsa44.dnstest.dev");
        assert_eq!(parsed.signature_len, 2420);
    }

    #[test]
    fn test_ds_record_parsing() {
        let mut ds_rdata = Vec::new();
        ds_rdata.extend_from_slice(&23176u16.to_be_bytes()); // Key Tag
        ds_rdata.push(18); // Algorithm = 18 (ML-DSA-44)
        ds_rdata.push(2); // Digest Type = SHA-256
        ds_rdata.extend_from_slice(&[0xaa; 32]); // 32-byte SHA-256 digest

        let ds = parse_ds(&ds_rdata).expect("DS parsing must succeed");
        assert_eq!(ds.key_tag, 23176);
        assert_eq!(ds.algorithm, DnssecAlgorithm::MlDsa44);
        assert_eq!(ds.digest_type, 2);
        assert_eq!(ds.digest.len(), 32);
    }

    #[test]
    fn test_anti_downgrade_policy_detects_stripping() {
        let mut report = DnssecReport::default();
        report.authenticated = true;
        // Parent DS advertised ML-DSA-44 (18)
        report.has_pqc_ds_signal = true;
        // But adversary stripped ML-DSA-44 signature, leaving only classical
        report.has_pqc_rrsig = false;
        report.has_classical_rrsig = true;

        let result = check_anti_downgrade(&report);
        assert_eq!(result, Err(DowngradeViolation::PqcSignatureStripped));
    }

    #[test]
    fn test_anti_downgrade_policy_allows_valid_pqc_path() {
        let mut report = DnssecReport::default();
        report.authenticated = true;
        report.has_pqc_ds_signal = true;
        report.has_pqc_rrsig = true;

        let result = check_anti_downgrade(&report);
        assert!(result.is_ok());
    }

    #[test]
    fn test_anti_downgrade_policy_rejects_unauthenticated_pqc() {
        let mut report = DnssecReport::default();
        report.authenticated = false; // Missing AD bit
        report.has_pqc_rrsig = true;

        let result = check_anti_downgrade(&report);
        assert_eq!(result, Err(DowngradeViolation::PqcNotAuthenticated));
    }

    #[test]
    fn test_root_trust_anchor_initialization() {
        let anchor = RootTrustAnchor::default();
        assert_eq!(anchor.anchors.len(), 2);
        assert_eq!(anchor.anchors[0].key_tag, 20326);
        assert_eq!(anchor.anchors[1].key_tag, 38696);
    }
}
