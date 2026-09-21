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
fn query_id() -> u16 {
    crate::dns::secure_rand_u16()
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

#[cfg(test)]
mod extraction_tests {
    use super::*;
    use hickory_proto::rr::rdata::svcb::{EchConfigList, SvcParamKey, SvcParamValue};
    use hickory_proto::rr::rdata::{HTTPS, SVCB};
    use hickory_proto::rr::{Name, RData, Record};

    fn https_rec(owner: &str, priority: u16, target: &str, ech: Option<Vec<u8>>) -> Record {
        let mut params = Vec::new();
        if let Some(b) = ech {
            params.push((
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(b)),
            ));
        }
        let svcb = SVCB::new(priority, Name::from_ascii(target).unwrap(), params);
        Record::from_rdata(
            Name::from_ascii(owner).unwrap(),
            300,
            RData::HTTPS(HTTPS(svcb)),
        )
    }

    #[test]
    fn test_alias_mode_ignored_without_chase() {
        // alias (priority 0) record alone yields nothing from pure extraction
        let rec = https_rec("a.example.", 0, "b.example.", None);
        let refs = vec![&rec];
        let owner = Name::from_ascii("a.example.").unwrap();
        assert_eq!(echconfig_from_records(&refs, &owner), None);
    }

    #[test]
    fn test_oversize_ech_dropped() {
        let rec = https_rec("a.example.", 1, ".", Some(vec![0xAA; 5000]));
        let refs = vec![&rec];
        let owner = Name::from_ascii("a.example.").unwrap();
        assert_eq!(echconfig_from_records(&refs, &owner), None);
    }

    #[test]
    fn test_empty_ech_dropped() {
        let rec = https_rec("a.example.", 1, ".", Some(vec![]));
        let refs = vec![&rec];
        let owner = Name::from_ascii("a.example.").unwrap();
        assert_eq!(echconfig_from_records(&refs, &owner), None);
    }
}
