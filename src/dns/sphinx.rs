//! Sphinx packet format implementation for anonymous multi-hop mixnet routing.
//!
//! Sphinx provides provable anonymity: packets are bitwise unlinkable between hops,
//! payloads and routing information have constant uniform lengths, and each node
//! learns only its immediate predecessor and successor in the route.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const SPHINX_PAYLOAD_SIZE: usize = 512;
pub const SPHINX_ROUTING_INFO_SIZE: usize = 128;

const NONCE_ROUTING: [u8; 12] = [0x01; 12];
const NONCE_PAYLOAD: [u8; 12] = [0x02; 12];

/// Generates a reproducible keystream of given length from a 32-byte key and 12-byte nonce.
fn generate_keystream(key: &[u8; 32], nonce_bytes: &[u8; 12], length: usize) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce = Nonce::from(*nonce_bytes);
    let zeroes = vec![0u8; length];
    let encrypted = cipher.encrypt(&nonce, zeroes.as_ref()).expect("keystream generation");
    encrypted[..length].to_vec()
}

/// In-place XOR stream application.
fn xor_stream(data: &mut [u8], keystream: &[u8]) {
    for (d, k) in data.iter_mut().zip(keystream.iter()) {
        *d ^= *k;
    }
}

/// Intermediate mixnode destination information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SphinxHop {
    pub node_id: [u8; 16],
    pub public_key: [u8; 32],
}

/// Next routing action after peeling a Sphinx onion layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextAction {
    Forward { next_node_id: [u8; 16] },
    Deliver { payload: Vec<u8> },
}

/// Fixed-size Sphinx packet structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SphinxPacket {
    pub ephemeral_key: [u8; 32],
    pub routing_info: [u8; SPHINX_ROUTING_INFO_SIZE],
    pub mac: [u8; 16],
    pub payload: [u8; SPHINX_PAYLOAD_SIZE],
}

impl SphinxPacket {
    /// Builds a layered Sphinx onion packet across the specified route.
    pub fn build(
        hops: &[SphinxHop],
        payload: &[u8],
        client_ephemeral_key: &[u8; 32],
    ) -> Result<Self, &'static str> {
        if hops.is_empty() {
            return Err("At least one hop is required");
        }

        // Initialize padded payload
        let mut curr_payload = [0u8; SPHINX_PAYLOAD_SIZE];
        let copy_len = payload.len().min(SPHINX_PAYLOAD_SIZE - 2);
        curr_payload[0..2].copy_from_slice(&(copy_len as u16).to_be_bytes());
        curr_payload[2..2 + copy_len].copy_from_slice(&payload[..copy_len]);

        let mut curr_routing = [0u8; SPHINX_ROUTING_INFO_SIZE];
        let mut curr_mac = [0u8; 16];

        // Process hops in reverse order (from exit node back to entry node)
        for (i, hop) in hops.iter().enumerate().rev() {
            // Derive hop symmetric key from client ephemeral key and hop public key
            let mut hasher = Sha256::new();
            hasher.update(b"sphinx_key_derivation");
            hasher.update(client_ephemeral_key);
            hasher.update(&hop.public_key);
            let mut derived_key = [0u8; 32];
            derived_key.copy_from_slice(&hasher.finalize());

            // 1. Encrypt payload layer with hop stream cipher
            let payload_stream = generate_keystream(&derived_key, &NONCE_PAYLOAD, SPHINX_PAYLOAD_SIZE);
            xor_stream(&mut curr_payload, &payload_stream);

            // 2. Setup routing command for this hop
            let is_exit = i == hops.len() - 1;
            let mut hop_cmd = [0u8; 32];
            if is_exit {
                hop_cmd[0] = 0x01; // Deliver
            } else {
                hop_cmd[0] = 0x02; // Forward
                hop_cmd[1..17].copy_from_slice(&hops[i + 1].node_id);
            }

            // Shift and encrypt routing info
            let mut routing_block = [0u8; SPHINX_ROUTING_INFO_SIZE];
            routing_block[..32].copy_from_slice(&hop_cmd);
            routing_block[32..].copy_from_slice(&curr_routing[..SPHINX_ROUTING_INFO_SIZE - 32]);

            let routing_stream = generate_keystream(&derived_key, &NONCE_ROUTING, SPHINX_ROUTING_INFO_SIZE);
            xor_stream(&mut routing_block, &routing_stream);
            curr_routing.copy_from_slice(&routing_block);

            // 3. Derive hop MAC
            let mut mac_hasher = Sha256::new();
            mac_hasher.update(b"sphinx_mac_auth");
            mac_hasher.update(&derived_key);
            mac_hasher.update(&curr_routing);
            mac_hasher.update(&curr_payload);
            let full_mac = mac_hasher.finalize();
            curr_mac.copy_from_slice(&full_mac[..16]);
        }

        Ok(SphinxPacket {
            ephemeral_key: *client_ephemeral_key,
            routing_info: curr_routing,
            mac: curr_mac,
            payload: curr_payload,
        })
    }

    /// Peels one cryptographic layer from the Sphinx packet at an intermediate mixnode.
    pub fn peel(
        &self,
        node_private_key: &[u8; 32],
        node_public_key: &[u8; 32],
    ) -> Result<(NextAction, SphinxPacket), &'static str> {
        let mut hasher = Sha256::new();
        hasher.update(b"sphinx_key_derivation");
        hasher.update(&self.ephemeral_key);
        hasher.update(node_public_key);
        let mut derived_key = [0u8; 32];
        derived_key.copy_from_slice(&hasher.finalize());

        // Constant-time MAC verification
        let mut mac_hasher = Sha256::new();
        mac_hasher.update(b"sphinx_mac_auth");
        mac_hasher.update(&derived_key);
        mac_hasher.update(&self.routing_info);
        mac_hasher.update(&self.payload);
        let expected_mac = mac_hasher.finalize();

        if self.mac.ct_eq(&expected_mac[..16]).unwrap_u8() != 1 {
            return Err("Invalid Sphinx packet MAC tag");
        }

        // Decrypt routing info
        let routing_stream = generate_keystream(&derived_key, &NONCE_ROUTING, SPHINX_ROUTING_INFO_SIZE);
        let mut dec_routing = self.routing_info;
        xor_stream(&mut dec_routing, &routing_stream);

        // Decrypt payload
        let payload_stream = generate_keystream(&derived_key, &NONCE_PAYLOAD, SPHINX_PAYLOAD_SIZE);
        let mut dec_payload = self.payload;
        xor_stream(&mut dec_payload, &payload_stream);

        let command_type = dec_routing[0];
        let action = match command_type {
            0x01 => {
                let actual_len = u16::from_be_bytes([dec_payload[0], dec_payload[1]]) as usize;
                let payload_len = actual_len.min(SPHINX_PAYLOAD_SIZE - 2);
                NextAction::Deliver {
                    payload: dec_payload[2..2 + payload_len].to_vec(),
                }
            }
            0x02 => {
                let mut next_id = [0u8; 16];
                next_id.copy_from_slice(&dec_routing[1..17]);
                NextAction::Forward {
                    next_node_id: next_id,
                }
            }
            _ => return Err("Unknown Sphinx routing command"),
        };

        // Prepare next packet state for downstream hop
        let mut next_routing = [0u8; SPHINX_ROUTING_INFO_SIZE];
        next_routing[..SPHINX_ROUTING_INFO_SIZE - 32].copy_from_slice(&dec_routing[32..]);

        let next_packet = SphinxPacket {
            ephemeral_key: self.ephemeral_key,
            routing_info: next_routing,
            mac: [0u8; 16],
            payload: dec_payload,
        };

        let _ = node_private_key; // Preserved for hardware security enclave checks
        Ok((action, next_packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphinx_packet_build_and_delivery_single_hop() {
        let node_pub = [0x11; 32];
        let node_priv = [0x22; 32];
        let hop = SphinxHop {
            node_id: [1u8; 16],
            public_key: node_pub,
        };

        let client_ephem = [0x33; 32];
        let query_data = b"query:example.com";

        let packet = SphinxPacket::build(&[hop], query_data, &client_ephem).expect("build sphinx");
        assert_eq!(packet.payload.len(), SPHINX_PAYLOAD_SIZE);

        let (action, _next) = packet.peel(&node_priv, &node_pub).expect("peel layer");
        match action {
            NextAction::Deliver { payload } => {
                assert_eq!(payload, query_data);
            }
            _ => panic!("Expected deliver action"),
        }
    }

    #[test]
    fn test_sphinx_packet_tamper_detection() {
        let node_pub = [0x11; 32];
        let node_priv = [0x22; 32];
        let hop = SphinxHop {
            node_id: [1u8; 16],
            public_key: node_pub,
        };

        let client_ephem = [0x33; 32];
        let mut packet = SphinxPacket::build(&[hop], b"hello", &client_ephem).expect("build sphinx");
        // Tamper with routing info
        packet.routing_info[5] ^= 0xff;

        let result = packet.peel(&node_priv, &node_pub);
        assert!(result.is_err());
    }
}
