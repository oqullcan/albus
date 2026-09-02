//! rfc 9460 service binding and https resource record (type 65) parser for echconfiglist extraction.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub const DNS_TYPE_SVCB: u16 = 64;
pub const DNS_TYPE_HTTPS: u16 = 65;
pub const SVC_PARAM_ECH: u16 = 0x0005;

// extracts raw echconfiglist byte payload from rfc 9460 svcb / https rdata records
pub fn parse_https_ech_config(rdata: &[u8]) -> Option<Vec<u8>> {
    if rdata.len() < 2 {
        return None;
    }

    let _priority = ((rdata[0] as u16) << 8) | (rdata[1] as u16);
    let mut pos = 2;

    // parse targetname uncompressed domain labels
    while pos < rdata.len() {
        let label_len = rdata[pos] as usize;
        pos += 1;
        if label_len == 0 {
            break;
        }
        pos += label_len;
    }

    if pos > rdata.len() {
        return None;
    }

    // parse svcparam key-value pairs
    let params_data = &rdata[pos..];
    let mut param_pos = 0;

    while param_pos + 4 <= params_data.len() {
        let param_key = ((params_data[param_pos] as u16) << 8) | (params_data[param_pos + 1] as u16);
        let param_len = ((params_data[param_pos + 2] as usize) << 8) | (params_data[param_pos + 3] as usize);
        param_pos += 4;

        if param_pos + param_len > params_data.len() {
            break;
        }

        // key 0x0005 corresponds to echconfiglist parameter
        if param_key == SVC_PARAM_ECH {
            return Some(params_data[param_pos..param_pos + param_len].to_vec());
        }

        param_pos += param_len;
    }

    None
}

// synchronized lookup table caching extracted ech configurations
#[derive(Debug, Clone, Default)]
pub struct EchConfigCache {
    inner: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl EchConfigCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert(&self, domain: String, ech_config: Vec<u8>) {
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(domain, ech_config);
        }
    }

    pub fn get(&self, domain: &str) -> Option<Vec<u8>> {
        let guard = self.inner.read().ok()?;
        guard.get(domain).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_https_ech_config() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // priority: 1
        rdata.push(0x00); // targetname: root (.)

        // svcparam: key = 0x0005 (ech), length = 4, data = [0xaa, 0xbb, 0xcc, 0xdd]
        rdata.extend_from_slice(&SVC_PARAM_ECH.to_be_bytes());
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let ech = parse_https_ech_config(&rdata);
        assert_eq!(ech, Some(vec![0xAA, 0xBB, 0xCC, 0xDD]));
    }

    #[test]
    fn test_ech_dns_parsing_and_caching() {
        let cache = EchConfigCache::new();
        let domain = "cloudflare.com";

        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // SvcPriority
        rdata.push(0x00); // TargetName

        let dummy_ech = vec![0xFE, 0x0D, 0x00, 0x20, 0x01, 0x02, 0x03, 0x04];
        rdata.extend_from_slice(&SVC_PARAM_ECH.to_be_bytes());
        rdata.extend_from_slice(&(dummy_ech.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&dummy_ech);

        let parsed = parse_https_ech_config(&rdata);
        assert_eq!(parsed, Some(dummy_ech.clone()));

        cache.insert(domain.to_string(), dummy_ech.clone());
        assert_eq!(cache.get(domain), Some(dummy_ech));
        assert_eq!(cache.get("unknown.com"), None);
    }
}
