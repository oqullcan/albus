// in-kernel raw packet mangle engine and nfqueue packet splitting helper

#[allow(dead_code)]
pub struct NfqPacketEngine;

impl NfqPacketEngine {
    // splits a raw tcp clienthello packet payload into two distinct segments
    #[allow(dead_code)]
    pub fn split_raw_tcp_payload(payload: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {

        if payload.len() < 2 {
            return None;
        }

        let (part1, part2) = payload.split_at(1);
        Some((part1.to_vec(), part2.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_raw_tcp_payload() {
        let sample = b"\x16\x03\x01\x00\x10test";
        let (p1, p2) = NfqPacketEngine::split_raw_tcp_payload(sample).unwrap();
        assert_eq!(p1, vec![0x16]);
        assert_eq!(p2, sample[1..].to_vec());
    }
}
