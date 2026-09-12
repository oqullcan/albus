//! post-quantum noise protocol framework (noise_ikpsk2) transport engine.
//!
//! provides 0-rtt lightweight encrypted tunnel encapsulation between albus instances
//! with quantum resistance achieved through 256-bit pre-shared symmetric key (psk) mixing.

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::rand::SystemRandom;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const NOISE_PROTOCOL_NAME: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_SHA256";

/// Symmetric state for noise handshake transcript hashing and key chaining.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricState {
    pub h: [u8; 32],
    pub ck: [u8; 32],
}

impl SymmetricState {
    pub fn new(protocol_name: &[u8]) -> Self {
        let mut h = [0u8; 32];
        let mut ck = [0u8; 32];

        if protocol_name.len() <= 32 {
            h[..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            h = Sha256::digest(protocol_name).into();
        }
        ck.copy_from_slice(&h);

        Self { h, ck }
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    pub fn mix_key(&mut self, input_key_material: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), input_key_material);
        let mut okm = [0u8; 64];
        hk.expand(b"", &mut okm).expect("64 bytes valid for hkdf-sha256");

        self.ck.copy_from_slice(&okm[0..32]);
        let mut temp_k = [0u8; 32];
        temp_k.copy_from_slice(&okm[32..64]);
        okm.zeroize();
        temp_k
    }

    pub fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
        let mut okm = [0u8; 96];
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), input_key_material);
        hk.expand(b"", &mut okm).expect("96 bytes valid for hkdf-sha256");

        self.ck.copy_from_slice(&okm[0..32]);
        self.mix_hash(&okm[32..64]);
        okm.zeroize();
    }
}

/// Established Noise transport session with post-quantum symmetric keys.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NoiseSession {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub send_nonce: u64,
    pub recv_nonce: u64,
}

impl std::fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoiseSession { send_key: REDACTED, recv_key: REDACTED }")
    }
}

impl NoiseSession {
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            send_key,
            recv_key,
            send_nonce: 0,
            recv_nonce: 0,
        }
    }

    /// Encrypts outgoing transport payload using ChaCha20-Poly1305 with automatic nonce stepping.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let key = Key::from(self.send_key);
        let cipher = ChaCha20Poly1305::new(&key);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.send_nonce.to_be_bytes());
        let nonce = Nonce::from(nonce_bytes);

        self.send_nonce = self
            .send_nonce
            .checked_add(1)
            .ok_or("noise session nonce overflow")?;

        cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| "noise encryption failure")
    }

    /// Decrypts incoming transport payload using ChaCha20-Poly1305 with replay/counter protection.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let key = Key::from(self.recv_key);
        let cipher = ChaCha20Poly1305::new(&key);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.recv_nonce.to_be_bytes());
        let nonce = Nonce::from(nonce_bytes);

        self.recv_nonce = self
            .recv_nonce
            .checked_add(1)
            .ok_or("noise session nonce overflow")?;

        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| "noise decryption tag mismatch")
    }
}

/// Initiates an IKpsk2 0-RTT handshake session from Alice to Bob.
pub fn initiate_noise_ikpsk2(
    bob_static_pk: &[u8; 32],
    pqc_psk: &[u8; 32],
) -> Result<(Vec<u8>, NoiseSession), &'static str> {
    let mut state = SymmetricState::new(NOISE_PROTOCOL_NAME);
    state.mix_hash(bob_static_pk);

    // Ephemeral key generation for Alice
    let rng = SystemRandom::new();
    let alice_eph_priv = EphemeralPrivateKey::generate(&X25519, &rng)
        .map_err(|_| "failed generating alice ephemeral key")?;
    let alice_eph_pub = alice_eph_priv
        .compute_public_key()
        .map_err(|_| "failed computing alice public key")?;
    let mut alice_eph_bytes = [0u8; 32];
    alice_eph_bytes.copy_from_slice(alice_eph_pub.as_ref());

    state.mix_hash(&alice_eph_bytes);

    // DH(e_alice, s_bob)
    let peer_bob = UnparsedPublicKey::new(&X25519, bob_static_pk);
    let mut dh1 = [0u8; 32];
    agreement::agree_ephemeral(
        alice_eph_priv,
        &peer_bob,
        "dh failed",
        |key_material| {
            if key_material.len() != 32 {
                return Err("invalid dh length");
            }
            dh1.copy_from_slice(key_material);
            Ok(())
        },
    )
    .map_err(|_| "agreement failed")?;

    let _ = state.mix_key(&dh1);
    dh1.zeroize();

    // Mix Post-Quantum 256-bit PSK
    state.mix_key_and_hash(pqc_psk);

    // Split into transport keys
    let mut transport_keys = [0u8; 64];
    let hk = Hkdf::<Sha256>::new(Some(&state.ck), b"");
    hk.expand(b"", &mut transport_keys)
        .map_err(|_| "hkdf expand failed")?;

    let mut send_k = [0u8; 32];
    let mut recv_k = [0u8; 32];
    send_k.copy_from_slice(&transport_keys[0..32]);
    recv_k.copy_from_slice(&transport_keys[32..64]);
    transport_keys.zeroize();

    let session = NoiseSession::new(send_k, recv_k);
    Ok((alice_eph_bytes.to_vec(), session))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_symmetric_state_mixing() {
        let mut state = SymmetricState::new(b"Noise_Test_Protocol");
        assert_ne!(state.h, [0u8; 32]);
        assert_ne!(state.ck, [0u8; 32]);

        state.mix_hash(b"context_binding");
        let k = state.mix_key(b"sample_secret");
        assert_ne!(k, [0u8; 32]);
    }

    #[test]
    fn test_noise_transport_encryption_roundtrip() {
        let key_a2b = [0x11u8; 32];
        let key_b2a = [0x22u8; 32];

        let mut alice_session = NoiseSession::new(key_a2b, key_b2a);
        let mut bob_session = NoiseSession::new(key_b2a, key_a2b);

        let msg = b"hyper-secure post-quantum albus packet payload";
        let ciphertext = alice_session.encrypt(msg).expect("encryption should succeed");
        assert_ne!(&ciphertext, msg);

        let decrypted = bob_session.decrypt(&ciphertext).expect("decryption should succeed");
        assert_eq!(&decrypted, msg);
    }
}
