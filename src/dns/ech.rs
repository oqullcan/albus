//! rfc 9460 service binding and https resource record (type 65) parser for echconfiglist extraction.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use hickory_proto::rr::{Name, Record};
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

    // parse targetname uncompressed domain labels (bounds-checked each step)
    while pos < rdata.len() {
        let label_len = rdata[pos] as usize;
        pos += 1;
        if label_len == 0 {
            break;
        }
        if label_len > 63 {
            return None;
        }
        pos = pos.checked_add(label_len)?;
        if pos > rdata.len() {
            return None;
        }
    }

    if pos > rdata.len() {
        return None;
    }

    // parse svcparam key-value pairs
    let params_data = &rdata[pos..];
    let mut param_pos = 0;

    while param_pos + 4 <= params_data.len() {
        let param_key =
            ((params_data[param_pos] as u16) << 8) | (params_data[param_pos + 1] as u16);
        let param_len =
            ((params_data[param_pos + 2] as usize) << 8) | (params_data[param_pos + 3] as usize);
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
        if domain.len() > 253 || ech_config.len() > 4096 {
            return;
        }
        // Hardening: validate-inside — only parseable configs enter the cache,
        // so no future caller can poison it with unchecked bytes (doh.rs also
        // pre-validates; defense in depth).
        if rustls::client::EchConfig::new(
            ech_config.clone().into(),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        )
        .is_err()
        {
            return;
        }
        if let Ok(mut guard) = self.inner.write() {
            // bound memory: simple eviction when too many domains
            if guard.len() >= 1024 {
                guard.clear();
            }
            guard.insert(domain, ech_config);
        }
    }

    pub fn get(&self, domain: &str) -> Option<Vec<u8>> {
        let guard = self.inner.read().ok()?;
        guard.get(domain).cloned()
    }
}

/// Fetches the ECHConfigList for `host` through our own DoH path (Type 65
/// HTTPS query) and returns the raw config-list bytes ready for
/// `rustls::client::EchConfig::new`. Follows one alias-mode hop; never
/// panics; None when unpublished, unparseable, or unreachable.
pub async fn fetch_echconfig_list(
    host: &str,
    resolver: &crate::dns::doh::DoHResolver,
) -> Option<Vec<u8>> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    use hickory_proto::rr::{RData, RecordType};

    let clean = host.trim().trim_end_matches('.');
    if clean.is_empty() || clean.len() > 253 {
        return None;
    }
    let fqdn = format!("{}.", clean);
    let mut name = Name::from_ascii(&fqdn).ok()?;
    if name.is_root() {
        return None;
    }
    // at most one alias-mode hop, then stop
    for _ in 0..2 {
        let mut msg = Message::new(query_id(), MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name.clone(), RecordType::HTTPS));
        let wire = msg.to_vec().ok()?;
        if wire.is_empty() {
            return None;
        }
        let (resp_wire, _) = resolver.resolve(&wire).await.ok()?;
        let resp = Message::from_vec(&resp_wire).ok()?;
        let records: Vec<_> = resp.answers.iter().chain(resp.authorities.iter()).collect();
        if let Some(hit) = echconfig_from_records(&records, &name) {
            return Some(hit);
        }
        // alias mode (priority 0): continue at the target name once
        let mut alias: Option<Name> = None;
        for rec in &records {
            let (priority, target) = match &rec.data {
                RData::HTTPS(h) => (h.svc_priority, &h.target_name),
                RData::SVCB(s) => (s.svc_priority, &s.target_name),
                _ => continue,
            };
            if priority == 0 && !target.is_root() {
                alias = Some(target.clone());
                break;
            }
        }
        match alias {
            Some(t) => name = t,
            None => return None,
        }
    }
    None
}

/// Pure extraction: ECHConfigList from owner-matching HTTPS/SVCB records
/// only (never a stranger zone's config). Offline-testable.
fn echconfig_from_records(records: &[&Record], owner: &Name) -> Option<Vec<u8>> {
    use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    use hickory_proto::rr::RData;
    for rec in records {
        if rec.name.to_ascii().to_lowercase() != owner.to_ascii().to_lowercase() {
            continue;
        }
        let params: &[(SvcParamKey, SvcParamValue)] = match &rec.data {
            RData::HTTPS(h) => &h.svc_params,
            RData::SVCB(s) => &s.svc_params,
            _ => continue,
        };
        for (k, v) in params {
            if *k == SvcParamKey::EchConfigList {
                if let SvcParamValue::EchConfigList(list) = v {
                    if !list.0.is_empty() && list.0.len() <= 4096 {
                        return Some(list.0.clone());
                    }
                }
            }
        }
    }
    None
}
/// Hardening note (ex-ECH-TXID): query IDs come from the shared OS-CSPRNG
/// helper so upstream observers cannot predict them.
fn query_id() -> u16 {
    super::secure_query_id()
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

        // insert validates: parseable configs stick, garbage does not.
        // valid vector is a real-world ECHConfigList (crypto.cloudflare.com).
        let blob = valid_ech_blob();
        cache.insert(domain.to_string(), blob.clone());
        assert_eq!(cache.get(domain), Some(blob));
        cache.insert("junk.example".to_string(), vec![0x00, 0x01, 0x02, 0x03]);
        assert_eq!(cache.get("junk.example"), None);
        assert_eq!(cache.get("unknown.com"), None);
    }

    // real-world ECHConfigList (crypto.cloudflare.com, X25519/AES-128-GCM).
    // Hand-decoded base64 (no new dependency); any byte drift fails loudly
    // via the length assert, so silent vector corruption cannot weaken this.
    fn valid_ech_blob() -> Vec<u8> {
        const B64: &str = "AEX+DQBBoAAgACDXqb8UltVlB1gDiwNadmQbL4AApc/6BKXFF3w0MsBNbQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";
        fn b64val(c: u8) -> Option<u8> {
            match c {
                b'A'..=b'Z' => Some(c - b'A'),
                b'a'..=b'z' => Some(c - b'a' + 26),
                b'0'..=b'9' => Some(c - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                _ => None,
            }
        }
        let bytes: Vec<u8> = B64.bytes().filter(|b| *b != b'=').collect();
        let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
        for chunk in bytes.chunks(4) {
            let mut n = 0u32;
            for (i, b) in chunk.iter().enumerate() {
                n |= (b64val(*b).expect("test vector must be valid base64") as u32) << (18 - 6 * i);
            }
            let emit = if chunk.len() == 4 { 3 } else { chunk.len() - 1 };
            for i in 0..emit {
                out.push((n >> (16 - 8 * i)) as u8);
            }
        }
        assert_eq!(out.len(), 71, "test vector must decode to 71 bytes");
        out
    }

    #[test]
    fn test_ech_config_rejects_garbage_offline() {
        // junk bytes must never become an ECH config (deterministic, no network)
        let junk = vec![0x00u8, 0x01, 0x02, 0x03];
        let res = rustls::client::EchConfig::new(
            junk.into(),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        );
        assert!(res.is_err(), "garbage must not parse as ECHConfig");
    }

    #[test]
    fn test_fetch_rejects_bad_host_offline() {
        // empty/root hosts short-circuit without network; run inside a
        // throwaway runtime since fetch is async
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resolver = crate::dns::doh::DoHResolver::new("quad9", &[], true).unwrap();
        assert!(rt.block_on(fetch_echconfig_list("", &resolver)).is_none());
    }

    #[test]
    fn test_echconfig_extraction_from_synthetic_https_offline() {
        use hickory_proto::rr::rdata::svcb::{EchConfigList, SvcParamKey, SvcParamValue};
        use hickory_proto::rr::rdata::{HTTPS, SVCB};
        use hickory_proto::rr::{RData, Record};
        // positive control: synthetic HTTPS record carrying an echconfig
        let owner = Name::from_ascii("example.com.").unwrap();
        let blob = vec![0xFE, 0x0D, 0x00, 0x20, 0x01, 0x02, 0x03, 0x04];
        let svcb = SVCB::new(
            1,
            owner.clone(),
            vec![(
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(blob.clone())),
            )],
        );
        let rec = Record::from_rdata(owner.clone(), 300, RData::HTTPS(HTTPS(svcb)));
        let refs = vec![&rec];
        assert_eq!(echconfig_from_records(&refs, &owner), Some(blob));
        // another zone's config must never match (no cross-zone fallback)
        let other = Name::from_ascii("other.example.").unwrap();
        assert_eq!(echconfig_from_records(&refs, &other), None);
        // record without ech param yields nothing
        let bare = SVCB::new(1, owner.clone(), vec![]);
        let rec2 = Record::from_rdata(owner.clone(), 300, RData::HTTPS(HTTPS(bare)));
        let refs2 = vec![&rec2];
        assert_eq!(echconfig_from_records(&refs2, &owner), None);
    }

    /// Live measurement: which DoH hosts publish ECHConfigs.
    /// Ignored by default (needs network); run with:
    /// `cargo test -- --ignored --nocapture live_ech_publishers`
    #[test]
    #[ignore]
    fn live_ech_publishers_print_configs() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resolver = crate::dns::doh::DoHResolver::new("quad9", &[], true).unwrap();
        for host in [
            "cloudflare-dns.com",
            "dns.google",
            "dns.quad9.net",
            "dns.mullvad.net",
        ] {
            let fetched = rt.block_on(fetch_echconfig_list(host, &resolver));
            match fetched {
                Some(b) => {
                    let ok = rustls::client::EchConfig::new(
                        b.clone().into(),
                        rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
                    )
                    .is_ok();
                    println!(
                        "ECH-PROBE {}: published len={} rustls_accept={}",
                        host,
                        b.len(),
                        ok
                    );
                }
                None => println!("ECH-PROBE {}: no echconfig published", host),
            }
        }
    }
}
