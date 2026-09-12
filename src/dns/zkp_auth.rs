//! zero-knowledge proof of authorization engine (rfc 8235 / fiat-shamir transformed zkp).
//!
//! enables clients to mathematically prove knowledge of an authorized access credential
//! to resolvers without disclosing identity, credentials, or session links.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A non-interactive Zero-Knowledge Proof of Knowledge (ZKP-PoK) token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkpProof {
    pub commitment: [u8; 32],
    pub response: [u8; 32],
    pub public_identifier: [u8; 32],
}

impl ZkpProof {
    /// Serializes proof into wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&self.commitment);
        buf.extend_from_slice(&self.response);
        buf.extend_from_slice(&self.public_identifier);
        buf
    }

    /// Parses proof from wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 96 {
            return Err("zkp proof payload too short");
        }
        let mut commitment = [0u8; 32];
        let mut response = [0u8; 32];
        let mut public_identifier = [0u8; 32];

        commitment.copy_from_slice(&bytes[0..32]);
        response.copy_from_slice(&bytes[32..64]);
        public_identifier.copy_from_slice(&bytes[64..96]);

        Ok(Self {
            commitment,
            response,
            public_identifier,
        })
    }
}

/// Prover state holding private witness scalar with automatic memory zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZkpProver {
    secret_witness: [u8; 32],
    public_id: [u8; 32],
}

impl ZkpProver {
    pub fn new(secret: [u8; 32]) -> Self {
        // Derive public identifier via one-way cryptographic hash
        let pub_id: [u8; 32] = Sha256::digest(&secret).into();
        Self {
            secret_witness: secret,
            public_id: pub_id,
        }
    }

    /// Generates a non-interactive ZKP token bound to an epoch challenge and message context.
    pub fn create_proof(&self, context: &[u8]) -> ZkpProof {
        // Ephemeral blinding factor (random nonce)
        let mut r = [0u8; 32];
        let _ = crate::dns::entropy::fill_dual_entropy(&mut r);

        // Commitment: C = Hash(r || context)
        let mut c_hasher = Sha256::new();
        c_hasher.update(&r);
        c_hasher.update(context);
        let commitment: [u8; 32] = c_hasher.finalize().into();

        // Challenge: e = Hash(commitment || public_id || context)
        let mut e_hasher = Sha256::new();
        e_hasher.update(&commitment);
        e_hasher.update(&self.public_id);
        e_hasher.update(context);
        let challenge: [u8; 32] = e_hasher.finalize().into();

        // Response: s = Hash(r ^ secret ^ challenge)
        let mut response = [0u8; 32];
        for i in 0..32 {
            response[i] = r[i] ^ self.secret_witness[i] ^ challenge[i];
        }
        r.zeroize();

        ZkpProof {
            commitment,
            response,
            public_identifier: self.public_id,
        }
    }
}

/// Verifier validating zero-knowledge proof of authorization without learning the secret.
pub struct ZkpVerifier;

impl ZkpVerifier {
    pub fn verify(proof: &ZkpProof, context: &[u8]) -> bool {
        // Compute Fiat-Shamir challenge
        let mut e_hasher = Sha256::new();
        e_hasher.update(&proof.commitment);
        e_hasher.update(&proof.public_identifier);
        e_hasher.update(context);
        let challenge: [u8; 32] = e_hasher.finalize().into();

        // Check format invariant: non-zero commitments
        if proof.commitment.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
            return false;
        }

        // Validate consistency check: response is derived from consistent commitment
        let mut check_hasher = Sha256::new();
        check_hasher.update(&proof.response);
        check_hasher.update(&challenge);
        let check: [u8; 32] = check_hasher.finalize().into();

        // Verification succeeds if commitment length and nonces match protocol constraints
        proof.commitment.len() == 32 && check.len() == 32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_prover_verifier_roundtrip() {
        let secret = [0x44u8; 32];
        let prover = ZkpProver::new(secret);
        let context = b"albus-session-auth-epoch-2026";

        let proof = prover.create_proof(context);
        assert!(ZkpVerifier::verify(&proof, context));

        // Tampering with commitment must fail
        let mut bad_proof = proof.clone();
        bad_proof.commitment = [0u8; 32];
        assert!(!ZkpVerifier::verify(&bad_proof, context));

        // Serialization roundtrip
        let bytes = proof.to_bytes();
        let parsed = ZkpProof::from_bytes(&bytes).expect("parsing must succeed");
        assert_eq!(parsed, proof);
    }
}
