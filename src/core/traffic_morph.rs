//! traffic morphing, cryptographic chaffing, and poisson inter-arrival jitter engine.
//!
//! disguises traffic flows against statistical and machine-learning dpi classifiers
//! by flattening packet length distributions and randomizing inter-arrival times.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficProtocol {
    Tls,
    Dns,
    Http,
}

/// Standard packet size quantization bins to flatten packet length histograms.
pub const DEFAULT_SIZE_BINS: [usize; 4] = [256, 512, 1024, 1440];

/// Generates a delay in milliseconds modeled after a Poisson process (exponential distribution).
/// Lambda is the average arrival rate per unit time.
pub fn calculate_poisson_delay(lambda: f64) -> Duration {
    if lambda <= 0.0 {
        return Duration::from_millis(0);
    }

    let mut raw = [0u8; 8];
    if crate::dns::entropy::fill_dual_entropy(&mut raw).is_err() {
        return Duration::from_millis(1);
    }

    let u_int = u64::from_le_bytes(raw);
    let u = ((u_int as f64) + 1.0) / ((u64::MAX as f64) + 2.0);

    // Inverse CDF of exponential distribution: -ln(1 - u) / lambda
    let delay_secs = -(1.0 - u).ln() / lambda;
    let delay_ms = (delay_secs * 1000.0).clamp(0.0, 50.0);
    Duration::from_millis(delay_ms as u64)
}

/// Pads a packet payload to the nearest quantization bin to destroy length fingerprints.
pub fn pad_packet_to_bin(payload: &[u8], bins: &[usize]) -> Vec<u8> {
    let mut target_size = payload.len();
    for &bin in bins {
        if bin >= payload.len() {
            target_size = bin;
            break;
        }
    }

    let mut out = Vec::with_capacity(target_size);
    out.extend_from_slice(payload);

    if out.len() < target_size {
        let pad_len = target_size - out.len();
        let mut noise = vec![0u8; pad_len];
        let _ = crate::dns::entropy::fill_dual_entropy(&mut noise);
        out.extend_from_slice(&noise);
    }

    out
}

/// Generates a decoy chaff packet to poison stateful middlebox tracking heuristics.
pub fn generate_chaff_packet(protocol: TrafficProtocol, length: usize) -> Vec<u8> {
    let mut packet = vec![0u8; length.max(64)];
    let _ = crate::dns::entropy::fill_dual_entropy(&mut packet);

    match protocol {
        TrafficProtocol::Tls => {
            // Synthesize TLS Record Header: [ContentType: 0x16 (Handshake)] [Version: 0x03, 0x01] [Length: 2B]
            if packet.len() >= 5 {
                packet[0] = 0x16;
                packet[1] = 0x03;
                packet[2] = 0x01;
                let payload_len = (packet.len() - 5) as u16;
                packet[3..5].copy_from_slice(&payload_len.to_be_bytes());
            }
        }
        TrafficProtocol::Dns => {
            // Synthesize DNS query header
            if packet.len() >= 12 {
                packet[2] = 0x01; // RD flag
                packet[3] = 0x00;
                packet[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
                packet[6..12].fill(0);
            }
        }
        TrafficProtocol::Http => {
            // Synthesize dummy HTTP GET
            let prefix = b"GET /cdn-check HTTP/1.1\r\nHost: cdn.cloudflare.com\r\n\r\n";
            if packet.len() >= prefix.len() {
                packet[0..prefix.len()].copy_from_slice(prefix);
            }
        }
    }

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poisson_delay_generation() {
        let delay = calculate_poisson_delay(100.0);
        assert!(delay.as_millis() <= 50);
    }

    #[test]
    fn test_pad_packet_to_bin() {
        let data = b"small_payload";
        let padded = pad_packet_to_bin(data, &DEFAULT_SIZE_BINS);
        assert_eq!(padded.len(), 256);
        assert_eq!(&padded[..data.len()], data);

        let data_large = vec![0x42; 600];
        let padded_large = pad_packet_to_bin(&data_large, &DEFAULT_SIZE_BINS);
        assert_eq!(padded_large.len(), 1024);
    }

    #[test]
    fn test_generate_chaff_packet_formats() {
        let tls_chaff = generate_chaff_packet(TrafficProtocol::Tls, 128);
        assert_eq!(tls_chaff[0], 0x16);
        assert_eq!(tls_chaff[1], 0x03);
        assert_eq!(tls_chaff[2], 0x01);

        let dns_chaff = generate_chaff_packet(TrafficProtocol::Dns, 64);
        assert_eq!(dns_chaff[2], 0x01);

        let http_chaff = generate_chaff_packet(TrafficProtocol::Http, 80);
        assert!(&http_chaff[..4] == b"GET ");
    }
}
