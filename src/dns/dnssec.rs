//! local DNSSEC chain validation (RRSIG + DNSKEY + DS up to the embedded root trust anchor).
//!
//! Scope (honest limits, also documented in README §5):
//! - Positive answers (A/AAAA covered here) are fully chain-validated.
//! - NODATA/NXDOMAIN denial is validated only when NSEC/NSEC3 RRsets with
//!   RRSIGs are present; NSEC3 closest-encloser completeness is NOT checked.
//! - DNAME redirections are never Secure: hickory-proto rejects DNAME
//!   records at parse time, so such responses fall through to Insecure
//!   (served) rather than validating — fail-open by library limit.
//! - No RFC 5011 trust-anchor rollover: the compiled-in root KSKs are used.
//!   Roadmap if ever needed: persist observed root DNSKEY sets in a
//!   root-owned dir, track add/remove hold-down timers (30 days), honor the
//!   REVOKE bit, and only then swap the anchor — weeks of careful,
//!   time-dependent work for a threat (silent root KSK rollover) that
//!   announces itself months ahead via IANA.
//! - DNSSEC signatures themselves are classical (ECDSA/RSA); "post-quantum"
//!   in albus refers to DoH transport key exchange, not signatures.
//!
//! States: Secure (chain verifies), Insecure (unsigned, served as before),
//! Bogus (cryptographic failure → SERVFAIL, never cached), Indeterminate
//! (infrastructure error → served with warning, never cached as secure).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::dnssec::rdata::{DNSKEY, NSEC3, RRSIG};
use hickory_proto::dnssec::{Algorithm, PublicKey, SupportedAlgorithms, TrustAnchors, Verifier};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tracing::debug;

use crate::dns::doh::DoHResolver;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecState {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

// algorithms we accept signatures from. RSASHA1-family is weak but still
// deployed by legacy signed zones; standard validators accept it, so we
// verify it too (and log the algorithm) instead of breaking those zones.
// allow(deprecated): deliberate compat decision, see above.
#[allow(deprecated)]
fn secure_algorithms() -> SupportedAlgorithms {
    SupportedAlgorithms::from_vec(&[
        Algorithm::RSASHA1,
        Algorithm::RSASHA1NSEC3SHA1,
        Algorithm::RSASHA256,
        Algorithm::RSASHA512,
        Algorithm::ECDSAP256SHA256,
        Algorithm::ECDSAP384SHA384,
        Algorithm::ED25519,
    ])
}

// maximum chain depth (name → TLD → root is normally 2-3 DS steps)
const MAX_CHAIN_DEPTH: usize = 8;
// cached DNSKEY/DS RRsets live at most this long
const KEY_CACHE_CAP: Duration = Duration::from_secs(3600);
// negative verdicts (Bogus/Indeterminate) are remembered briefly so a LAN
// attacker hammering random names cannot turn every miss into a full
// upstream chain walk (amplification bound)
const NEG_CACHE_TTL: Duration = Duration::from_secs(60);
// CNAME hops followed during validation
const MAX_CNAME_HOPS: usize = 4;

pub struct DnssecValidator {
    anchors: TrustAnchors,
    supported: SupportedAlgorithms,
    // (zone-name, type) -> (records, fetched-at)
    key_cache: Mutex<KeyCacheMap>,
    // (qname, qtype) -> (verdict, decided-at); Secure/Insecure live in DnsCache
    neg_cache: Mutex<NegCacheMap>,
}

// factored so clippy::type_complexity stays quiet and the shapes are named
type KeyCacheMap = HashMap<(String, u16), (Vec<Record>, Instant)>;
type NegCacheMap = HashMap<(String, u16), (DnssecState, Instant)>;

impl DnssecValidator {
    pub fn new() -> Self {
        Self {
            anchors: TrustAnchors::default(),
            supported: secure_algorithms(),
            key_cache: Mutex::new(HashMap::new()),
            neg_cache: Mutex::new(HashMap::new()),
        }
    }

    fn neg_lookup(&self, qname: &str, qtype: u16) -> Option<DnssecState> {
        let key = (qname.to_lowercase(), qtype);
        let mut guard = self.neg_cache.lock().ok()?;
        if let Some((state, at)) = guard.get(&key) {
            if at.elapsed() < NEG_CACHE_TTL {
                return Some(*state);
            }
            guard.remove(&key);
        }
        None
    }

    fn neg_store(&self, qname: &str, qtype: u16, state: DnssecState) {
        if state != DnssecState::Bogus && state != DnssecState::Indeterminate {
            return;
        }
        if let Ok(mut guard) = self.neg_cache.lock() {
            if guard.len() > 1024 {
                guard.clear();
            }
            guard.insert((qname.to_lowercase(), qtype), (state, Instant::now()));
        }
    }

    fn now_epoch() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }

    fn owner_name(dotted: &str) -> Option<Name> {
        let fqdn = if dotted.is_empty() {
            ".".to_string()
        } else if dotted.ends_with('.') {
            dotted.to_string()
        } else {
            format!("{}.", dotted)
        };
        Name::from_ascii(&fqdn).ok()
    }

    fn build_query(name: &Name, rtype: RecordType) -> Vec<u8> {
        use hickory_proto::op::Edns;
        let mut msg = Message::new(rand_id(), MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name.clone(), rtype));
        // chain queries need DNSSEC records too: set the DO bit
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.set_max_payload(1232);
        msg.set_edns(edns);
        msg.to_vec().unwrap_or_default()
    }

    fn cache_lookup(&self, name: &Name, rtype: RecordType) -> Option<Vec<Record>> {
        let key = (name.to_ascii().to_lowercase(), u16::from(rtype));
        let mut guard = self.key_cache.lock().ok()?;
        if let Some((records, at)) = guard.get(&key) {
            if at.elapsed() < KEY_CACHE_CAP {
                return Some(records.clone());
            }
            guard.remove(&key);
        }
        None
    }

    fn cache_store(&self, name: &Name, rtype: RecordType, records: Vec<Record>) {
        if let Ok(mut guard) = self.key_cache.lock() {
            if guard.len() > 512 {
                guard.clear();
            }
            guard.insert(
                (name.to_ascii().to_lowercase(), u16::from(rtype)),
                (records, Instant::now()),
            );
        }
    }

    // fetches raw records of (name, type) through our own DoH path
    async fn fetch_rrset(
        &self,
        name: &Name,
        rtype: RecordType,
        resolver: &DoHResolver,
    ) -> Option<Vec<Record>> {
        if let Some(cached) = self.cache_lookup(name, rtype) {
            return Some(cached);
        }
        let wire = Self::build_query(name, rtype);
        if wire.is_empty() {
            return None;
        }
        let (resp_wire, _) = resolver.resolve(&wire).await.ok()?;
        let msg = Message::from_vec(&resp_wire).ok()?;
        if msg.response_code != ResponseCode::NoError {
            return None;
        }
        let mut out = Vec::new();
        for rec in msg
            .answers
            .iter()
            .chain(msg.authorities.iter())
            .chain(msg.additionals.iter())
        {
            // keep the requested RRset plus any accompanying RRSIGs (needed to
            // authenticate it); dropping RRSIGs here silently breaks the chain
            if rec.record_type() == RecordType::RRSIG
                || (name_eq(&rec.name, name) && rec.record_type() == rtype)
            {
                out.push(rec.clone());
            }
        }
        if out.is_empty() {
            return None;
        }
        self.cache_store(name, rtype, out.clone());
        Some(out)
    }

    fn rrsig_records(records: &[Record], covered: RecordType) -> Vec<RRSIG> {
        let mut sigs = Vec::new();
        for rec in records {
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = &rec.data {
                if sig.input().type_covered == covered {
                    sigs.push(sig.clone());
                }
            }
        }
        sigs
    }

    fn dnskey_records(records: &[Record]) -> Vec<DNSKEY> {
        let mut keys = Vec::new();
        for rec in records {
            if let RData::DNSSEC(DNSSECRData::DNSKEY(key)) = &rec.data {
                keys.push(key.clone());
            }
        }
        keys
    }

    // verifies one RRset against one DNSKEY set; returns the signer zone on success
    fn verify_rrset(
        &self,
        owner: &Name,
        records: &[Record],
        rrsig: &RRSIG,
        dnskeys: &[DNSKEY],
        now: u32,
    ) -> Option<Name> {
        let input = rrsig.input();
        if !self.supported.has(input.algorithm) {
            return None;
        }
        if now < input.sig_inception.get() || now > input.sig_expiration.get() {
            return None;
        }
        for key in dnskeys {
            if key.public_key().algorithm() != input.algorithm {
                continue;
            }
            let tag = key.calculate_key_tag().ok();
            if tag != Some(input.key_tag) {
                continue;
            }
            if key
                .verify_rrsig(owner, DNSClass::IN, rrsig, records.iter())
                .is_ok()
            {
                return Some(input.signer_name.clone());
            }
        }
        None
    }

    // authenticates a DNSKEY RRset for `zone` up to the root trust anchor
    async fn chain_to_root(
        &self,
        zone: &Name,
        dnskey_records: &[Record],
        resolver: &DoHResolver,
        depth: usize,
    ) -> bool {
        if depth > MAX_CHAIN_DEPTH {
            return false;
        }
        let keys = Self::dnskey_records(dnskey_records);
        if keys.is_empty() {
            return false;
        }
        if zone.is_root() {
            return self.matches_anchor(&keys);
        }
        // DS RRset lives in the parent; fetch DS + parent DNSKEY concurrently
        let parent = zone.base_name();
        let (ds_records, parent_keys) = tokio::join!(
            self.fetch_rrset(zone, RecordType::DS, resolver),
            self.fetch_rrset(&parent, RecordType::DNSKEY, resolver)
        );
        let ds_records = match ds_records {
            Some(r) => r,
            None => {
                return false;
            }
        };
        let parent_keys = match parent_keys {
            Some(r) => r,
            None => {
                return false;
            }
        };
        let parent_dnskeys = Self::dnskey_records(&parent_keys);
        let now = Self::now_epoch();
        // DS must digest a SEP (flag 257) key; the DS RRset itself must be
        // signed by the parent keys, whose chain we then recurse into.
        for rec in &ds_records {
            let RData::DNSSEC(DNSSECRData::DS(ds)) = &rec.data else {
                continue;
            };
            if ds.digest_type() != hickory_proto::dnssec::DigestType::SHA256
                && ds.digest_type() != hickory_proto::dnssec::DigestType::SHA384
            {
                continue;
            }
            for key in &keys {
                if !is_sep(key) || key.calculate_key_tag().ok() != Some(ds.key_tag()) {
                    continue;
                }
                if key.public_key().algorithm() != ds.algorithm() {
                    continue;
                }
                if !ds.covers(zone, key).unwrap_or(false) {
                    continue;
                }
                let ds_sigs = Self::rrsig_records(&ds_records, RecordType::DS);
                for ds_sig in &ds_sigs {
                    let v = self.verify_rrset(zone, &ds_records, ds_sig, &parent_dnskeys, now);
                    if v.is_some_and(|signer| name_eq(&signer, &parent))
                        && Box::pin(self.chain_to_root(&parent, &parent_keys, resolver, depth + 1))
                            .await
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn matches_anchor(&self, keys: &[DNSKEY]) -> bool {
        for key in keys {
            for i in 0..self.anchors.len() {
                if let Some(anchor) = self.anchors.get(i) {
                    if anchor.algorithm() == key.public_key().algorithm()
                        && anchor.public_bytes() == key.public_key().public_bytes()
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Early warning for a root KSK rollover (poor man's RFC 5011): fetches
    /// the live root DNSKEY set and compares its SEP keys against the
    /// compiled-in anchors. Returns true when they match. A mismatch does
    /// NOT change validation behavior — it logs a warning so the operator
    /// updates albus before the old anchor stops verifying. Best-effort:
    /// any fetch/parse failure yields true (no false alarms offline).
    pub async fn anchor_health(&self, resolver: &DoHResolver) -> bool {
        let root = match Self::owner_name("") {
            Some(n) => n,
            None => return true,
        };
        let live = match self.fetch_rrset(&root, RecordType::DNSKEY, resolver).await {
            Some(r) => r,
            None => return true,
        };
        let mut live_sep = 0u32;
        let mut matched = 0u32;
        for key in Self::dnskey_records(&live) {
            if !is_sep(&key) {
                continue;
            }
            live_sep += 1;
            if self.matches_anchor(std::slice::from_ref(&key)) {
                matched += 1;
            }
        }
        if live_sep == 0 {
            return true;
        }
        matched == live_sep
    }

    /// Validates a full DoH response for (qname, qtype). Never panics; all
    /// error paths are Indeterminate (infrastructure) except cryptographic
    /// mismatches, which are Bogus.
    pub async fn validate(
        &self,
        qname: &str,
        qtype: u16,
        resp_wire: &[u8],
        resolver: &DoHResolver,
    ) -> DnssecState {
        if let Some(cached) = self.neg_lookup(qname, qtype) {
            return cached;
        }
        let state = self.validate_inner(qname, qtype, resp_wire, resolver).await;
        self.neg_store(qname, qtype, state);
        state
    }

    async fn validate_inner(
        &self,
        qname: &str,
        qtype: u16,
        resp_wire: &[u8],
        resolver: &DoHResolver,
    ) -> DnssecState {
        let msg = match Message::from_vec(resp_wire) {
            Ok(m) => m,
            Err(_) => return DnssecState::Indeterminate,
        };
        if msg.response_code != ResponseCode::NoError && msg.response_code != ResponseCode::NXDomain
        {
            return DnssecState::Indeterminate;
        }
        let owner = match Self::owner_name(qname) {
            Some(n) => n,
            None => return DnssecState::Indeterminate,
        };
        let rtype = RecordType::from(qtype);
        let now = Self::now_epoch();

        // gather candidate RRsets: positive answers, else authority denial records
        let mut candidates: Vec<(Name, Vec<Record>, RecordType)> = Vec::new();
        let mut answer_recs: Vec<Record> = Vec::new();
        for rec in &msg.answers {
            let t = rec.record_type();
            if t == rtype || t == RecordType::RRSIG || t == RecordType::CNAME {
                answer_recs.push(rec.clone());
            }
        }
        if answer_recs
            .iter()
            .any(|r| r.record_type() == rtype && name_eq(&r.name, &owner))
        {
            candidates.push((owner.clone(), answer_recs, rtype));
        } else if let Some(chain) = cname_chain(&msg.answers, &owner, rtype) {
            // CNAME chain: every link plus the terminal RRset must verify;
            // a missing link degrades to insecure (served, never Secure).
            candidates.extend(chain);
        } else {
            // denial: validate NSEC/NSEC3 RRsets carrying RRSIGs when present
            let mut denial: HashMap<String, (Name, Vec<Record>, RecordType)> = HashMap::new();
            for rec in &msg.authorities {
                let t = rec.record_type();
                if t == RecordType::NSEC || t == RecordType::NSEC3 || t == RecordType::RRSIG {
                    let entry = denial
                        .entry(rec.name.to_ascii().to_lowercase())
                        .or_insert_with(|| (rec.name.clone(), Vec::new(), t));
                    entry.1.push(rec.clone());
                    if t != RecordType::RRSIG {
                        entry.2 = t;
                    }
                }
            }
            for (_, (name, recs, t)) in denial {
                if t == RecordType::NSEC || t == RecordType::NSEC3 {
                    candidates.push((name, recs, t));
                }
            }
            if candidates.is_empty() {
                // unsigned denial — insecure, not bogus
                return DnssecState::Insecure;
            }
        }

        // Per-RRset semantics (RFC 4035 style):
        // - signed but unverifiable -> Bogus immediately (fail closed);
        // - unsigned -> insecure link (served, never Secure);
        // - Secure requires every link verified: a signed CNAME to unsigned
        //   data is Insecure, not Bogus (no stripping proven).
        let mut secure_links = 0u32;
        let mut insecure_links = 0u32;
        let mut nsec3_seen = false;
        let mut nsec3_covers = false;
        let mut nsec3_encloser = false;
        let mut nsec_seen = false;
        let mut nsec_covered = false;
        let nxdomain = msg.response_code == ResponseCode::NXDomain;
        for (name, recs, t) in &candidates {
            let is_nsec3 = *t == RecordType::NSEC3;
            let is_nsec = *t == RecordType::NSEC;
            if is_nsec3 {
                nsec3_seen = true;
            }
            if is_nsec {
                nsec_seen = true;
            }
            let sigs = Self::rrsig_records(recs, *t);
            if sigs.is_empty() {
                insecure_links += 1;
                continue;
            }
            let mut rrset_secure = false;
            for sig in &sigs {
                let signer = sig.input().signer_name.clone();
                // fetch the signer's DNSKEY set and try it
                let dnskey_recs = match self
                    .fetch_rrset(&signer, RecordType::DNSKEY, resolver)
                    .await
                {
                    Some(r) => r,
                    None => continue,
                };
                if self
                    .verify_rrset(name, recs, sig, &Self::dnskey_records(&dnskey_recs), now)
                    .is_none()
                {
                    continue;
                }
                if Box::pin(self.chain_to_root(&signer, &dnskey_recs, resolver, 0)).await {
                    rrset_secure = true;
                    break;
                }
            }
            if rrset_secure {
                // NSEC3 denial additionally requires a covering record for the
                // queried name itself, issued within qname's own lineage
                // (parent zone == qname or an ancestor). A signed-but-foreign
                // NSEC3 proves someone else's denial, not ours.
                if is_nsec3 {
                    if any_nsec3_covers_in_scope(recs, &owner) {
                        nsec3_covers = true;
                    }
                    if nxdomain && any_nsec3_matches_encloser(recs, &owner) {
                        nsec3_encloser = true;
                    }
                    continue;
                }
                // L11: same rule for NSEC — a verified NSEC counts toward
                // Secure only when its span actually denies qname. Verified
                // but non-covering groups are ignored (never Bogus: only
                // cryptographic failure is Bogus; the answer is still
                // served, as Indeterminate, and revalidated next query).
                if is_nsec {
                    if any_nsec_covers(recs, name, &owner) {
                        nsec_covered = true;
                    }
                    continue;
                }
                secure_links += 1;
                continue;
            }
            // RRSIGs present but none chain-verify: cryptographic failure
            debug!(
                "dnssec: RRSIGs present but chain failed for {}",
                name.to_ascii()
            );
            return DnssecState::Bogus;
        }
        // an NSEC3 denial with no covering record is an incomplete proof
        if nsec3_seen {
            if !nsec3_covers {
                debug!("dnssec: NSEC3 denial lacks covering record");
                return DnssecState::Bogus;
            }
            // NXDOMAIN additionally needs a closest-encloser proof: a verified
            // NSEC3 whose owner hashes to qname itself or one of its ancestors.
            // (NODATA keeps covering-only; wildcard-cover completeness for the
            // wildcard step remains documented future work.)
            if nxdomain && !nsec3_encloser {
                debug!("dnssec: NXDOMAIN lacks closest-encloser proof");
                return DnssecState::Bogus;
            }
            return DnssecState::Secure;
        }
        // L11: verified NSEC coverage promotes the denial to a secure link
        if nsec_seen && nsec_covered {
            secure_links += 1;
        }
        if secure_links > 0 && insecure_links == 0 {
            return DnssecState::Secure;
        }
        if insecure_links > 0 {
            DnssecState::Insecure
        } else {
            DnssecState::Indeterminate
        }
    }
}

fn name_eq(a: &Name, b: &Name) -> bool {
    a.to_ascii().to_lowercase() == b.to_ascii().to_lowercase()
}

/// Lineage-scoped variant: the covering record must additionally live under
/// qname's own zone cut (parent zone == qname or an ancestor). Stops an
/// attacker replaying a genuine signed NSEC3 from an unrelated zone.
fn any_nsec3_covers_in_scope(recs: &[Record], qname: &Name) -> bool {
    for rec in recs {
        let RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) = &rec.data else {
            continue;
        };
        if !zone_in_scope(&rec.name, qname) {
            continue;
        }
        if nsec3_covers(nsec3, &rec.name, qname) {
            return true;
        }
    }
    false
}

/// Closest-encloser existence: an NSEC3 owner whose hash equals qname or one
/// of its ancestors (walked up to root, hashed with the record's own params).
/// A covering span alone does not prove the encloser exists.
fn any_nsec3_matches_encloser(recs: &[Record], qname: &Name) -> bool {
    for rec in recs {
        let RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) = &rec.data else {
            continue;
        };
        let owner_hash = match owner_hash_bytes(&rec.name) {
            Some(h) => h,
            None => continue,
        };
        let mut cur = qname.clone();
        loop {
            if let Ok(digest) = nsec3
                .hash_algorithm()
                .hash(nsec3.salt(), &cur, nsec3.iterations())
            {
                let h: &[u8] = digest.as_ref();
                if h.len() == owner_hash.len() && h == owner_hash.as_slice() {
                    return true;
                }
            }
            if cur.is_root() {
                break;
            }
            cur = cur.base_name();
        }
    }
    false
}

/// Parent zone of an NSEC3 owner must equal qname or strictly contain it
/// (label-boundary suffix match, case-insensitive).
fn zone_in_scope(rec_name: &Name, qname: &Name) -> bool {
    let parent = rec_name.base_name();
    if name_eq(&parent, qname) {
        return true;
    }
    let q = qname
        .to_ascii()
        .to_lowercase()
        .trim_end_matches('.')
        .to_string();
    let p = parent
        .to_ascii()
        .to_lowercase()
        .trim_end_matches('.')
        .to_string();
    !p.is_empty() && q.len() > p.len() && q.ends_with(&format!(".{}", p))
}

/// Canonical DNS name ordering (RFC 4034 s6.1): labels compared right to
/// left, case-insensitive octet-wise; an ancestor sorts before its
/// descendants. Used for NSEC denial coverage.
fn cmp_dns_name(a: &Name, b: &Name) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut al: Vec<Vec<u8>> = a.iter().map(|l| l.to_ascii_lowercase()).collect();
    let mut bl: Vec<Vec<u8>> = b.iter().map(|l| l.to_ascii_lowercase()).collect();
    // drop the root empty label when present so "x." and "x" compare equal
    if al.last().is_some_and(|l| l.is_empty()) {
        al.pop();
    }
    if bl.last().is_some_and(|l| l.is_empty()) {
        bl.pop();
    }
    al.reverse();
    bl.reverse();
    for (x, y) in al.iter().zip(bl.iter()) {
        match x.cmp(y) {
            Ordering::Equal => continue,
            ord => return ord,
        }
    }
    al.len().cmp(&bl.len())
}

/// NSEC denial coverage (L11): qname is denied iff owner < qname <= next in
/// canonical order, wrap-aware. A verified-but-not-covering NSEC proves
/// someone else's denial, not ours.
fn nsec_covers(owner: &Name, next: &Name, qname: &Name) -> bool {
    use std::cmp::Ordering;
    let owner_next = cmp_dns_name(owner, next);
    if owner_next == Ordering::Equal {
        return true; // degenerate single-name span
    }
    let owner_q = cmp_dns_name(owner, qname);
    let q_next = cmp_dns_name(qname, next);
    if owner_next == Ordering::Less {
        // normal interval: owner < qname <= next
        owner_q == Ordering::Less && q_next != Ordering::Greater
    } else {
        // wrap-around: qname past owner, or at/before next
        owner_q == Ordering::Less || q_next != Ordering::Greater
    }
}

/// True when any NSEC record in `recs` (owned by `owner`) covers `qname`.
fn any_nsec_covers(recs: &[Record], owner: &Name, qname: &Name) -> bool {
    for rec in recs {
        let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = &rec.data else {
            continue;
        };
        if !name_eq(&rec.name, owner) {
            continue;
        }
        if nsec_covers(owner, nsec.next_domain_name(), qname) {
            return true;
        }
    }
    false
}

fn nsec3_covers(nsec3: &NSEC3, owner: &Name, qname: &Name) -> bool {
    let owner_hash = match owner_hash_bytes(owner) {
        Some(h) => h,
        None => return false,
    };
    let Ok(digest) = nsec3
        .hash_algorithm()
        .hash(nsec3.salt(), qname, nsec3.iterations())
    else {
        return false;
    };
    let h: &[u8] = digest.as_ref();
    let next: &[u8] = nsec3.next_hashed_owner_name();
    if owner_hash.len() != h.len() || next.len() != h.len() {
        return false;
    }
    if owner_hash.as_slice() == next {
        // single-record span covers the whole zone
        return true;
    }
    if owner_hash.as_slice() < next {
        owner_hash.as_slice() < h && h <= next
    } else {
        // wrap-around interval
        h > owner_hash.as_slice() || h <= next
    }
}

/// First-label base32hex decode of an NSEC3 owner name.
fn owner_hash_bytes(owner: &Name) -> Option<Vec<u8>> {
    let first: &[u8] = owner.iter().next()?;
    if first.is_empty() {
        return None;
    }
    base32hex_decode(first)
}

fn base32hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut bits: u32 = 0;
    let mut filled = 0u8;
    let mut out = Vec::with_capacity((input.len() * 5) / 8 + 1);
    for raw in input {
        let c = raw.to_ascii_lowercase();
        let val = ALPHABET.iter().position(|&a| a == c)? as u32;
        bits = (bits << 5) | val;
        filled += 5;
        if filled >= 8 {
            filled -= 8;
            out.push((bits >> filled) as u8);
            bits &= (1 << filled) - 1;
        }
    }
    if filled >= 5 || out.is_empty() || bits != 0 {
        // trailing non-zero bits, overlong input, or empty hash
        return None;
    }
    Some(out)
}

// follows CNAME links present in this response (no extra fetches):
// returns per-link (owner, records, CNAME) plus the terminal (owner, records,
// qtype) candidate. Empty when the chain is broken (caller treats as insecure).
fn cname_chain(
    answers: &[Record],
    owner: &Name,
    rtype: RecordType,
) -> Option<Vec<(Name, Vec<Record>, RecordType)>> {
    use std::ops::Deref;
    let mut out = Vec::new();
    let mut current = owner.clone();
    // RRSIGs ride alongside; verification filters by covered type/owner,
    // so attaching the whole set is safe and simple.
    let all_sigs: Vec<Record> = answers
        .iter()
        .filter(|r| r.record_type() == RecordType::RRSIG)
        .cloned()
        .collect();
    for _ in 0..MAX_CNAME_HOPS {
        // terminal RRset present?
        if answers
            .iter()
            .any(|r| r.record_type() == rtype && name_eq(&r.name, &current))
        {
            let mut recs: Vec<Record> = answers
                .iter()
                .filter(|r| r.record_type() == rtype && name_eq(&r.name, &current))
                .cloned()
                .collect();
            recs.extend(all_sigs.iter().cloned());
            out.push((current, recs, rtype));
            return Some(out);
        }
        // next CNAME link for current owner?
        let mut next: Option<(Name, Vec<Record>)> = None;
        for r in answers {
            if r.record_type() == RecordType::CNAME && name_eq(&r.name, &current) {
                if let RData::CNAME(t) = &r.data {
                    let target: &Name = t.deref();
                    let mut recs: Vec<Record> = answers
                        .iter()
                        .filter(|x| {
                            x.record_type() == RecordType::CNAME && name_eq(&x.name, &current)
                        })
                        .cloned()
                        .collect();
                    recs.extend(all_sigs.iter().cloned());
                    next = Some((target.clone(), recs));
                    break;
                }
            }
        }
        match next {
            Some((t, recs)) => {
                out.push((current, recs, RecordType::CNAME));
                current = t;
            }
            None => return None,
        }
    }
    None
}

fn rand_id() -> u16 {
    crate::dns::secure_rand_u16()
}

fn is_sep(key: &DNSKEY) -> bool {
    key.flags() & 0x0001 != 0
}

impl Default for DnssecValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::rdata::NSEC;
    use hickory_proto::rr::rdata::A;

    // tiny local base32hex encoder for building deterministic fixtures
    fn b32hex_enc(bytes: &[u8]) -> String {
        const ALPHA: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
        let mut bits: u32 = 0;
        let mut filled = 0u8;
        let mut out = String::new();
        for b in bytes {
            bits = (bits << 8) | (*b as u32);
            filled += 8;
            while filled >= 5 {
                filled -= 5;
                out.push(ALPHA[((bits >> filled) & 31) as usize] as char);
                bits &= (1 << filled) - 1;
            }
        }
        if filled > 0 {
            out.push(ALPHA[((bits << (5 - filled)) & 31) as usize] as char);
        }
        out
    }

    // builds a minimal unsigned A-response wire message (no RRSIGs)
    fn unsigned_a_response() -> (String, u16, Vec<u8>) {
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        let name = Name::from_ascii("example.com.").unwrap();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        let rec = Record::from_rdata(name, 300, RData::A(A::new(93, 184, 216, 34)));
        msg.answers.push(rec);
        ("example.com".to_string(), 1, msg.to_vec().unwrap())
    }

    #[tokio::test]
    async fn test_unsigned_response_is_insecure_offline() {
        let v = DnssecValidator::new();
        // resolver unused on the insecure path (no RRSIGs → no fetches)
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let (name, qtype, wire) = unsigned_a_response();
        let state = v.validate(&name, qtype, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Insecure);
    }

    #[tokio::test]
    async fn test_garbage_wire_is_indeterminate() {
        let v = DnssecValidator::new();
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let state = v.validate("example.com", 1, &[0u8; 4], &resolver).await;
        assert_eq!(state, DnssecState::Indeterminate);
    }

    // Offline self-signed root zone: generates a fresh P-256 key, anchors it,
    // signs a root A RRset, and pre-seeds the DNSKEY cache. Fully
    // deterministic apart from key material (which never affects verdicts).
    // No network, no clock beyond validity windows.
    struct SignedRootFixture {
        validator: DnssecValidator,
        wire: Vec<u8>,
    }

    fn signed_root_fixture() -> SignedRootFixture {
        use hickory_proto::dnssec::crypto::EcdsaSigningKey;
        use hickory_proto::dnssec::rdata::SigInput;
        use hickory_proto::dnssec::{DnssecSigner, SigningKey, TBS};
        use hickory_proto::rr::SerialNumber;

        let root = Name::from_ascii(".").unwrap();
        let der =
            EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).expect("keygen works");
        let signing_key = EcdsaSigningKey::from_key_der(&der.into(), Algorithm::ECDSAP256SHA256)
            .expect("key parses");
        let pubkey = signing_key.to_public_key().expect("pubkey derives");
        let dnskey = DNSKEY::new(true, true, false, pubkey.clone());
        let key_tag = dnskey.calculate_key_tag().expect("tag computes");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock works")
            .as_secs() as u32;
        let mut validator = DnssecValidator::new();
        validator.anchors.insert(&pubkey);

        // signed root A RRset
        let a_rec = Record::from_rdata(root.clone(), 300, RData::A(A::new(93, 184, 216, 34)));
        let input = SigInput {
            type_covered: RecordType::A,
            algorithm: Algorithm::ECDSAP256SHA256,
            num_labels: 0,
            original_ttl: 300,
            sig_expiration: SerialNumber::new(now + 3600),
            sig_inception: SerialNumber::new(now - 100),
            key_tag,
            signer_name: root.clone(),
        };
        let tbs = TBS::from_input(&root, DNSClass::IN, &input, std::iter::once(&a_rec))
            .expect("tbs builds");
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(signing_key),
            root.clone(),
            Duration::from_secs(3600),
        );
        let sig_bytes = signer.sign(&tbs).expect("signing works");
        let sig_rec = Record::from_rdata(
            root.clone(),
            300,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig_bytes))),
        );

        // seed the DNSKEY cache so no network is touched
        let dnskey_rec = Record::from_rdata(
            root.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        );
        validator.cache_store(&root, RecordType::DNSKEY, vec![dnskey_rec]);

        let mut msg = Message::new(0x4242, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.add_query(Query::query(root, RecordType::A));
        msg.answers.push(a_rec);
        msg.answers.push(sig_rec);
        SignedRootFixture {
            validator,
            wire: msg.to_vec().unwrap(),
        }
    }

    fn dummy_resolver() -> DoHResolver {
        DoHResolver::new("quad9", &[], true).expect("resolver init should succeed")
    }

    #[tokio::test]
    async fn test_self_signed_root_validates_secure_offline() {
        let fx = signed_root_fixture();
        let resolver = dummy_resolver();
        let state = fx.validator.validate(".", 1, &fx.wire, &resolver).await;
        assert_eq!(state, DnssecState::Secure);
    }

    #[tokio::test]
    async fn test_tampered_signed_response_is_bogus_offline() {
        let fx = signed_root_fixture();
        let resolver = dummy_resolver();
        // flip a byte inside the A rdata: signature must fail closed
        let mut msg = Message::from_vec(&fx.wire).expect("fixture parses");
        for rec in msg.answers.iter_mut() {
            if rec.record_type() == RecordType::A {
                if let RData::A(addr) = &mut rec.data {
                    let mut octets = addr.octets();
                    octets[3] ^= 0x01;
                    *addr = A::new(octets[0], octets[1], octets[2], octets[3]);
                    break;
                }
            }
        }
        let wire = msg.to_vec().unwrap();
        let state = fx.validator.validate(".", 1, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Bogus);
    }

    #[tokio::test]
    async fn test_unsigned_cname_chain_is_insecure_offline() {
        use hickory_proto::rr::rdata::CNAME;
        // www -> cdn (unsigned) -> A (unsigned): chain present but unsigned
        let mut msg = Message::new(0x2222, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        let alias = Name::from_ascii("www.example.com.").unwrap();
        let canon = Name::from_ascii("cdn.example.net.").unwrap();
        msg.add_query(Query::query(alias.clone(), RecordType::A));
        msg.answers.push(Record::from_rdata(
            alias.clone(),
            300,
            RData::CNAME(CNAME(canon.clone())),
        ));
        msg.answers.push(Record::from_rdata(
            canon,
            300,
            RData::A(A::new(93, 184, 216, 34)),
        ));
        let wire = msg.to_vec().unwrap();
        let v = DnssecValidator::new();
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let state = v.validate("www.example.com", 1, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Insecure);
    }

    #[test]
    fn test_base32hex_vectors() {
        // RFC 4648 base32hex, unpadded form as it appears in owner names
        // (lowercase accepted too); non-zero pad bits are rejected.
        assert_eq!(base32hex_decode(b"CPNMUOG"), Some(b"foob".to_vec()));
        assert_eq!(base32hex_decode(b"cpnmuog"), Some(b"foob".to_vec()));
        assert_eq!(base32hex_decode(b"CO"), Some(b"f".to_vec()));
        // 8 chars = 40 bits = 5 full bytes, no padding involved
        assert_eq!(base32hex_decode(b"CPNMUOJ1"), Some(b"fooba".to_vec()));
        // leftover pad bits must be zero: "CP" leaves bits "01"
        assert_eq!(base32hex_decode(b"CP"), None);
        assert_eq!(base32hex_decode(b"CPNMUOJ1="), None);
        assert_eq!(base32hex_decode(b"!!!!"), None);
        assert_eq!(base32hex_decode(b""), None);
    }

    #[test]
    fn test_base32hex_roundtrip_and_adversarial() {
        // encode(decode) roundtrip over representative lengths incl. NSEC3
        // SHA1 (20 bytes -> 32 chars): decode must invert the encoder exactly.
        // (len 0 excluded: empty input is rejected by design — an empty
        // owner label never hashes, see owner_hash_bytes.)
        let mut lens = vec![1usize, 2, 3, 4, 5, 19, 20, 21, 32, 64];
        lens.extend([7, 13, 31]);
        for len in lens {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let enc = b32hex_enc(&bytes);
            assert_eq!(
                base32hex_decode(enc.as_bytes()),
                Some(bytes),
                "roundtrip failed for len {}",
                len
            );
        }
        // adversarial: uppercase/lowercase mix, padding chars, whitespace,
        // overlong runs, all-zero and all-max inputs never panic and reject
        // anything outside the strict unpadded alphabet
        for bad in [
            "CPNMUOJ1=".as_bytes(),
            "CP NMUOJ1".as_bytes(),
            "cpnmuoj1\n".as_bytes(),
            "=========".as_bytes(),
            "CC1".as_bytes(),
            "~~~~~~~~~~~~~~~~".as_bytes(),
            b"\xff\xfe\x00\x01".as_slice(),
        ] {
            assert_eq!(base32hex_decode(bad), None, "must reject {:?}", bad);
        }
        // all-max input is valid (decodes to 0xFF bytes, zero pad bits)
        assert_eq!(
            base32hex_decode(b"vvvvvvvv"),
            Some(vec![0xFF; 5]),
            "max-value input must decode"
        );
        // single chars: trailing zero pad bits accepted, nonzero rejected
        // ("C0" -> 01100 00000 -> byte 0x60, pad 00; "C1" -> pad 01)
        assert_eq!(base32hex_decode(b"C0"), Some(vec![0x60]));
        assert_eq!(base32hex_decode(b"C1"), None);
    }

    #[test]
    fn test_matches_anchor_positive_and_negative() {
        use hickory_proto::dnssec::crypto::EcdsaSigningKey;
        use hickory_proto::dnssec::{PublicKey, SigningKey};
        let v = DnssecValidator::new();
        assert!(v.anchors.len() >= 1, "embedded root anchors must exist");
        // a fresh random key must NOT match the compiled-in anchors...
        let der = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
        let key = EcdsaSigningKey::from_key_der(&der.into(), Algorithm::ECDSAP256SHA256).unwrap();
        let pubkey = key.to_public_key().unwrap();
        let stranger = DNSKEY::new(true, true, false, pubkey.clone());
        assert!(!v.matches_anchor(std::slice::from_ref(&stranger)));
        // ...but does once inserted (simulates a completed rollover)
        let mut v2 = DnssecValidator::new();
        assert!(v2.anchors.insert(&pubkey));
        assert!(v2.matches_anchor(std::slice::from_ref(&stranger)));
        let _ = (pubkey.algorithm(), pubkey.public_bytes().len());
    }

    #[test]
    fn test_neg_cache_stores_only_negative_verdicts() {
        let v = DnssecValidator::new();
        // Bogus + Indeterminate are remembered (anti-amplification bound)
        v.neg_store("Example.COM", 1, DnssecState::Bogus);
        assert_eq!(v.neg_lookup("example.com", 1), Some(DnssecState::Bogus));
        v.neg_store("other.example.", 28, DnssecState::Indeterminate);
        assert_eq!(
            v.neg_lookup("other.example.", 28),
            Some(DnssecState::Indeterminate)
        );
        // Secure/Insecure are never stored (live in DnsCache instead)
        v.neg_store("example.com", 1, DnssecState::Secure);
        v.neg_store("plain.example.", 1, DnssecState::Insecure);
        assert_eq!(v.neg_lookup("plain.example.", 1), None);
        // qtype is part of the key; unknown names miss
        assert_eq!(v.neg_lookup("example.com", 28), None);
        assert_eq!(v.neg_lookup("absent.example.", 1), None);
    }

    #[test]
    fn test_nsec_span_logic() {
        let n = |s: &str| Name::from_ascii(s).unwrap();
        // canonical order: ancestors first, case-insensitive, label-wise
        assert_eq!(
            cmp_dns_name(&n("example.com."), &n("example.com.")),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            cmp_dns_name(&n("example.com."), &n("a.example.com.")),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            cmp_dns_name(&n("b.example.com."), &n("a.example.com.")),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            cmp_dns_name(&n("A.EXAMPLE.com."), &n("a.example.com.")),
            std::cmp::Ordering::Equal
        );
        // owner < qname <= next denies; endpoints: owner itself does not
        let owner = n("a.example.");
        let next = n("c.example.");
        assert!(nsec_covers(&owner, &next, &n("b.example.")));
        assert!(nsec_covers(&owner, &next, &n("c.example.")));
        assert!(!nsec_covers(&owner, &next, &n("a.example.")));
        assert!(!nsec_covers(&owner, &next, &n("d.example.")));
        // wrap-around: (y.example., b.example.] covers z.* and a.*, not m.*
        let w_owner = n("y.example.");
        let w_next = n("b.example.");
        assert!(nsec_covers(&w_owner, &w_next, &n("z.example.")));
        assert!(nsec_covers(&w_owner, &w_next, &n("a.example.")));
        assert!(!nsec_covers(&w_owner, &w_next, &n("m.example.")));
        assert!(!nsec_covers(&w_owner, &w_next, &n("y.example.")));
        // degenerate single-name span covers
        assert!(nsec_covers(&owner, &owner, &n("b.example.")));

        // record-level: covering NSEC counts, foreign one does not
        let mk_rec = |owner: Name, next: Name| {
            Record::from_rdata(
                owner,
                300,
                RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, [RecordType::A]))),
            )
        };
        let qname = n("b.example.");
        let rec = mk_rec(n("a.example."), n("c.example."));
        assert!(any_nsec_covers(
            std::slice::from_ref(&rec),
            &n("a.example."),
            &qname
        ));
        let foreign = mk_rec(n("x.other."), n("z.other."));
        assert!(!any_nsec_covers(
            std::slice::from_ref(&foreign),
            &n("x.other."),
            &qname
        ));
        // wrong-owner record in the set is skipped, not trusted
        let impostor = mk_rec(n("a.example."), n("b.example."));
        assert!(!any_nsec_covers(
            std::slice::from_ref(&impostor),
            &n("zzz.example."),
            &qname
        ));
    }

    #[test]
    fn test_nsec3_span_logic() {
        use hickory_proto::dnssec::rdata::NSEC3;
        use hickory_proto::dnssec::Nsec3HashAlgorithm;
        let enc = b32hex_enc;
        let qname = Name::from_ascii("example.com.").unwrap();
        let h: Vec<u8> = Nsec3HashAlgorithm::SHA1
            .hash(&[], &qname, 0)
            .expect("hash works")
            .as_ref()
            .to_vec();
        assert_eq!(h.len(), 20);
        let mk = |next: &[u8]| {
            NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                0,
                vec![],
                next.to_vec(),
                [RecordType::A],
            )
        };
        // single-record span covers everything
        let same_owner = Name::from_ascii(&format!("{}.example.com.", enc(&h))).unwrap();
        let nsec3 = mk(&h);
        assert!(nsec3_covers(&nsec3, &same_owner, &qname));
        // interval (owner, next] containing h
        let mut below = h.clone();
        below[19] = below[19].wrapping_sub(1);
        let owner2 = Name::from_ascii(&format!("{}.example.com.", enc(&below))).unwrap();
        let nsec3 = mk(&h);
        assert!(nsec3_covers(&nsec3, &owner2, &qname));
        // disjoint interval does not cover
        let mut above = h.clone();
        above[19] = above[19].wrapping_add(2);
        let mut above2 = h.clone();
        above2[19] = above2[19].wrapping_add(10);
        let owner3 = Name::from_ascii(&format!("{}.example.com.", enc(&above))).unwrap();
        let nsec3 = mk(&above2);
        assert!(!nsec3_covers(&nsec3, &owner3, &qname));
        // any_nsec3_covers over a synthetic record
        let rec = Record::from_rdata(
            owner2.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(mk(&h))),
        );
        assert!(any_nsec3_covers_in_scope(
            std::slice::from_ref(&rec),
            &qname
        ));
        // same span math, but the record lives in a foreign zone:
        // the raw span still covers, the in-scope check must refuse it
        let foreign_owner =
            Name::from_ascii(&format!("{}.other-zone.example.", enc(&below))).unwrap();
        assert!(nsec3_covers(&mk(&h), &foreign_owner, &qname));
        let rec_foreign = Record::from_rdata(
            foreign_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(mk(&h))),
        );
        assert!(!any_nsec3_covers_in_scope(
            std::slice::from_ref(&rec_foreign),
            &qname
        ));
        assert!(any_nsec3_covers_in_scope(
            std::slice::from_ref(&rec),
            &qname
        ));
    }

    #[test]
    fn test_nsec3_encloser_match() {
        use hickory_proto::dnssec::rdata::NSEC3;
        use hickory_proto::dnssec::Nsec3HashAlgorithm;
        let qname = Name::from_ascii("deep.missing.example.com.").unwrap();
        let hash_of = |n: &Name| -> Vec<u8> {
            Nsec3HashAlgorithm::SHA1
                .hash(&[], n, 0)
                .expect("hash works")
                .as_ref()
                .to_vec()
        };
        let mk_rec = |owner_hash: &[u8]| {
            let owner =
                Name::from_ascii(&format!("{}.example.com.", b32hex_enc(owner_hash))).unwrap();
            Record::from_rdata(
                owner,
                300,
                RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                    Nsec3HashAlgorithm::SHA1,
                    false,
                    0,
                    vec![],
                    owner_hash.to_vec(),
                    [RecordType::A],
                ))),
            )
        };
        // owner == hash(parent suffix "missing.example.com.") -> encloser found
        let parent = Name::from_ascii("missing.example.com.").unwrap();
        let rec = mk_rec(&hash_of(&parent));
        assert!(any_nsec3_matches_encloser(
            std::slice::from_ref(&rec),
            &qname
        ));
        // owner == hash(grandparent "example.com.") also counts
        let gp = Name::from_ascii("example.com.").unwrap();
        let rec2 = mk_rec(&hash_of(&gp));
        assert!(any_nsec3_matches_encloser(
            std::slice::from_ref(&rec2),
            &qname
        ));
        // owner == hash(qname) itself counts (exact-match record)
        let rec3 = mk_rec(&hash_of(&qname));
        assert!(any_nsec3_matches_encloser(
            std::slice::from_ref(&rec3),
            &qname
        ));
        // unrelated hash matches nothing
        let other = Name::from_ascii("unrelated.other.").unwrap();
        let rec4 = mk_rec(&hash_of(&other));
        assert!(!any_nsec3_matches_encloser(
            std::slice::from_ref(&rec4),
            &qname
        ));
        // non-NSEC3 records are ignored
        let a_rec = Record::from_rdata(
            qname.clone(),
            300,
            RData::A(hickory_proto::rr::rdata::A::new(93, 184, 216, 34)),
        );
        assert!(!any_nsec3_matches_encloser(
            std::slice::from_ref(&a_rec),
            &qname
        ));
    }

    #[test]
    fn test_zone_in_scope_boundaries() {
        let n = |s: &str| Name::from_ascii(s).unwrap();
        // exact parent
        assert!(zone_in_scope(&n("abc.example.com."), &n("example.com.")));
        // deep nesting still in scope when lineage holds
        assert!(zone_in_scope(
            &n("h.a.b.example.com."),
            &n("a.b.example.com.")
        ));
        // sibling suffix without boundary must not match
        assert!(!zone_in_scope(
            &n("abc.notexample.com."),
            &n("example.com.")
        ));
        assert!(!zone_in_scope(
            &n("abc.example.com.evil."),
            &n("example.com.")
        ));
        // case-insensitive
        assert!(zone_in_scope(&n("ABC.EXAMPLE.COM."), &n("example.com.")));
    }

    #[tokio::test]
    async fn test_signed_cname_to_unsigned_target_is_insecure_offline() {
        use hickory_proto::dnssec::crypto::EcdsaSigningKey;
        use hickory_proto::dnssec::rdata::SigInput;
        use hickory_proto::dnssec::{DnssecSigner, SigningKey, TBS};
        use hickory_proto::rr::rdata::CNAME;
        use hickory_proto::rr::SerialNumber;

        // root-anchored key (same pattern as the fixture)
        let root = Name::from_ascii(".").unwrap();
        let der = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
        let signing_key =
            EcdsaSigningKey::from_key_der(&der.into(), Algorithm::ECDSAP256SHA256).unwrap();
        let pubkey = signing_key.to_public_key().unwrap();
        let dnskey = DNSKEY::new(true, true, false, pubkey.clone());
        let key_tag = dnskey.calculate_key_tag().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        // alias under root, target with UNSIGNED A
        let alias = Name::from_ascii("alias.").unwrap();
        let target = Name::from_ascii("target.").unwrap();
        let cname_rec = Record::from_rdata(alias.clone(), 300, RData::CNAME(CNAME(target.clone())));
        let input = SigInput {
            type_covered: RecordType::CNAME,
            algorithm: Algorithm::ECDSAP256SHA256,
            num_labels: 1,
            original_ttl: 300,
            sig_expiration: SerialNumber::new(now + 3600),
            sig_inception: SerialNumber::new(now - 100),
            key_tag,
            signer_name: root.clone(),
        };
        let tbs =
            TBS::from_input(&alias, DNSClass::IN, &input, std::iter::once(&cname_rec)).unwrap();
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(signing_key),
            root.clone(),
            Duration::from_secs(3600),
        );
        let sig_bytes = signer.sign(&tbs).unwrap();
        let sig_rec = Record::from_rdata(
            alias.clone(),
            300,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig_bytes))),
        );
        let a_rec = Record::from_rdata(target.clone(), 300, RData::A(A::new(10, 0, 0, 1)));

        let mut validator = DnssecValidator::new();
        validator.anchors.insert(&pubkey);
        let dnskey_rec = Record::from_rdata(
            root.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        );
        validator.cache_store(&root, RecordType::DNSKEY, vec![dnskey_rec]);

        let mut msg = Message::new(0x5151, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.add_query(Query::query(alias.clone(), RecordType::A));
        msg.answers.push(cname_rec);
        msg.answers.push(a_rec);
        msg.answers.push(sig_rec);
        let wire = msg.to_vec().unwrap();

        let resolver = DoHResolver::new("quad9", &[], true).unwrap();
        // signed CNAME, unsigned terminal: Insecure (served), NOT Bogus
        let state = validator.validate("alias", 1, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Insecure);
    }
}
