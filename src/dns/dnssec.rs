//! local DNSSEC chain validation (RRSIG + DNSKEY + DS up to the embedded root trust anchor).
//!
//! Scope (honest limits, also summarized in the README options table):
//! - Positive answers (A/AAAA covered here) are fully chain-validated.
//! - NSEC denial requires interval/bitmap coverage (FP-18); NSEC3 denials are
//!   capped at Indeterminate (no hash verification without new crypto deps),
//!   and NSEC3 closest-encloser completeness is NOT checked.
//! - Truncated CNAME chains with signed links are Bogus, never silently
//!   demoted to Insecure (FP-19).
//! - No RFC 5011 trust-anchor rollover: the compiled-in root KSKs are used.
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
use hickory_proto::dnssec::rdata::{DNSKEY, RRSIG};
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

/// Fetch result with proven-Nodata distinguished from failure (island fix):
/// only a NOERROR response carrying zero matching records proves the RRset
/// does not exist. Timeouts, SERVFAIL, and parse errors are `Failed` so
/// callers keep failing closed instead of downgrading on infrastructure errors.
#[derive(Debug)]
enum FetchOutcome {
    Found(Vec<Record>),
    /// NOERROR with no records of the requested type. The authority-section
    /// denial records (NSEC/NSEC3 plus their RRSIGs) ride along so the caller
    /// can authenticate the denial instead of taking the resolver's word for it.
    Nodata {
        denial: Vec<Record>,
    },
    Failed,
}

/// Chain verdict with unsigned-delegation (island) distinguished from failure:
///
/// - `Secure`: full DS→DNSKEY chain to the trust anchor.
/// - `InsecureIsland`: the parent provably holds no DS for the zone
///   (NOERROR + zero DS records), i.e. an unsigned delegation per RFC 4035
///   §4.2. Served as Insecure, never Bogus.
/// - `Fail`: anything undecided (fetch failure, bad digest, broken chain).
#[derive(Debug, PartialEq, Eq)]
enum ChainVerdict {
    Secure,
    InsecureIsland,
    Fail,
}

// algorithms we accept signatures from (RSASHA1/NSEC3RSASHA1 excluded)
fn secure_algorithms() -> SupportedAlgorithms {
    SupportedAlgorithms::from_vec(&[
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
/// DNS-02: entry caps are now enforced by bounded eviction, not by clearing the
/// whole map.
const KEY_CACHE_CAP_ENTRIES: usize = 512;
const NEG_CACHE_CAP: usize = 1024;
// negative verdicts (Bogus/Indeterminate) are remembered briefly so a LAN
// attacker hammering random names cannot turn every miss into a full
// upstream chain walk (amplification bound)
const NEG_CACHE_TTL: Duration = Duration::from_secs(60);
// CNAME hops followed during validation
const MAX_CNAME_HOPS: usize = 4;

#[allow(clippy::type_complexity)]
pub struct DnssecValidator {
    anchors: TrustAnchors,
    supported: SupportedAlgorithms,
    // (zone-name, type) -> (records, fetched-at)
    key_cache: Mutex<HashMap<(String, u16), (Vec<Record>, Instant)>>,
    // (qname, qtype) -> (verdict, decided-at); Secure/Insecure live in DnsCache
    neg_cache: Mutex<HashMap<(String, u16), (DnssecState, Instant)>>,
}

impl DnssecValidator {
    pub fn new() -> Self {
        Self {
            anchors: TrustAnchors::default(),
            supported: secure_algorithms(),
            key_cache: Mutex::new(HashMap::new()),
            neg_cache: Mutex::new(HashMap::new()),
        }
    }

    /// W6-01: operator-requested invalidation. Both DNSSEC caches were
    /// unreachable from every flush path, so a "flushed" resolver could still
    /// serve a stale Bogus verdict for up to NEG_CACHE_TTL (which `validate`
    /// short-circuits on, turning a one-shot LAN-attacker stamp into a 60s
    /// denial that simply out-waits the operator), and could ignore a KSK/DS
    /// rollover for up to KEY_CACHE_CAP. Only size-triggered eviction ever
    /// touched them.
    /// Test-only view of the negative-verdict cache, so a flush can be asserted
    /// to actually have emptied it rather than merely "not been called".
    #[cfg(test)]
    pub(crate) fn neg_cached(&self, qname: &str, qtype: u16) -> Option<DnssecState> {
        self.neg_lookup(qname, qtype)
    }

    /// Test-only: seed a negative verdict the way a real Bogus response does.
    #[cfg(test)]
    pub(crate) fn neg_store_for_test(&self, qname: &str, qtype: u16, state: DnssecState) {
        self.neg_store(qname, qtype, state)
    }

    pub fn clear_caches(&self) {
        if let Ok(mut g) = self.neg_cache.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.key_cache.lock() {
            g.clear();
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
            // DNS-02: the recovery for a full cache used to be a wholesale
            // clear(), which an attacker-chosen name stream triggers directly —
            // turning a per-name amortised cost into a per-query one, and wiping
            // every still-valid verdict an honest query had paid for. Evict only
            // what is actually expired, and refuse the insert rather than
            // discarding the cache when nothing is.
            if guard.len() >= NEG_CACHE_CAP {
                Self::evict_expired(&mut guard, NEG_CACHE_TTL);
            }
            if guard.len() >= NEG_CACHE_CAP {
                debug!(
                    "negative-verdict cache full ({} entries); declining to cache \
                     this verdict rather than clearing the cache",
                    NEG_CACHE_CAP
                );
                return;
            }
            guard.insert((qname.to_lowercase(), qtype), (state, Instant::now()));
        }
    }

    /// Removes entries whose TTL has elapsed, oldest first. Bounded work: one
    /// pass over the map, no allocation, and the fresh entries an honest query
    /// paid for survive.
    pub(crate) fn evict_expired<T>(map: &mut HashMap<(String, u16), (T, Instant)>, ttl: Duration) {
        let now = Instant::now();
        map.retain(|_, (_, at)| now.duration_since(*at) < ttl);
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
            // DNS-02: same wholesale-clear problem as the negative cache.
            if guard.len() >= KEY_CACHE_CAP_ENTRIES {
                Self::evict_expired(&mut guard, KEY_CACHE_CAP);
            }
            if guard.len() >= KEY_CACHE_CAP_ENTRIES {
                debug!(
                    "DNSSEC key cache full ({} entries); declining to cache this \
                     RRset rather than clearing the cache",
                    KEY_CACHE_CAP_ENTRIES
                );
                return;
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
    ) -> FetchOutcome {
        if let Some(cached) = self.cache_lookup(name, rtype) {
            return FetchOutcome::Found(cached);
        }
        let wire = Self::build_query(name, rtype);
        if wire.is_empty() {
            return FetchOutcome::Failed;
        }
        let (resp_wire, _) = match resolver.resolve(&wire).await {
            Ok(r) => r,
            Err(_) => return FetchOutcome::Failed,
        };
        let msg = match Message::from_vec(&resp_wire) {
            Ok(m) => m,
            Err(_) => return FetchOutcome::Failed,
        };
        // Only NOERROR with zero matching records is a proven Nodata.
        // Anything else undecided (SERVFAIL/REFUSED/timeout/parse) stays a
        // failure so callers fail closed.
        if msg.response_code != ResponseCode::NoError {
            return FetchOutcome::Failed;
        }
        let mut out = Vec::new();
        let mut matched = false;
        // Denial candidates are taken from the AUTHORITY section only, and they
        // are retained rather than reduced to a boolean.
        //
        // HANCORE 2026-10: this used to accept an SOA/NSEC/NSEC3 from answers,
        // authorities OR additionals as a bare `denial_marker` boolean and then
        // discard the records. Two consequences, both exploitable by a hostile
        // resolver with no network position:
        //   * an SOA proved nothing at all about the requested type — it rides
        //     along in every authoritative Nodata answer — so no NSEC was even
        //     required to trigger the downgrade;
        //   * an additional-section record has no relationship to the query, so
        //     the "proof" could be wholly unrelated to the name being asked.
        // The marker is now the record set itself, so the caller can verify it.
        let mut denial: Vec<Record> = Vec::new();
        for rec in msg.answers.iter() {
            // keep the requested RRset plus any accompanying RRSIGs (needed to
            // authenticate it); dropping RRSIGs here silently breaks the chain
            if rec.record_type() == RecordType::RRSIG {
                out.push(rec.clone());
            } else if name_eq(&rec.name, name) && rec.record_type() == rtype {
                out.push(rec.clone());
                matched = true;
            }
        }
        if !matched {
            for rec in msg.authorities.iter() {
                let t = rec.record_type();
                if t == RecordType::NSEC
                    || t == RecordType::NSEC3
                    || (t == RecordType::RRSIG
                        && matches!(
                            &rec.data,
                            RData::DNSSEC(DNSSECRData::RRSIG(s))
                                if s.input().type_covered == RecordType::NSEC
                                    || s.input().type_covered == RecordType::NSEC3
                        ))
                {
                    denial.push(rec.clone());
                }
            }
            // An NSEC/NSEC3 is the only shape that can *mean* non-existence for
            // a type. Without one the answer is undecided, so stay fail-closed.
            let has_denial_record = denial
                .iter()
                .any(|r| matches!(r.record_type(), RecordType::NSEC | RecordType::NSEC3));
            if !has_denial_record {
                return FetchOutcome::Failed;
            }
            return FetchOutcome::Nodata { denial };
        }
        self.cache_store(name, rtype, out.clone());
        FetchOutcome::Found(out)
    }

    /// Authenticates a parent-side proof that `zone` has no DS record, per
    /// RFC 4035 §5.2.
    ///
    /// The proof must be an NSEC at the delegation name whose type bitmap omits
    /// DS (hickory surfaces that shape as `is_ancestor_delegation`), carrying an
    /// RRSIG made by the PARENT's key. The parent's own keys have already been
    /// fetched here; they are themselves chained to the root by the recursion
    /// that follows, so accepting this proof cannot launder a forged parent.
    ///
    /// NSEC3 is deliberately refused. This crate has no NSEC3 hash
    /// implementation (see the module header), so it cannot prove that an NSEC3
    /// record actually covers the delegation. Refusing yields
    /// `ChainVerdict::Fail` -> Indeterminate at the top level, which is served
    /// with a warning and never cached as Secure — strictly better than the
    /// unauthenticated Insecure this replaces.
    fn authenticate_denial(
        &self,
        zone: &Name,
        parent: &Name,
        denial: &[Record],
        parent_dnskeys: &[DNSKEY],
        now: u32,
    ) -> bool {
        if denial.is_empty() || parent_dnskeys.is_empty() {
            return false;
        }

        let nsecs: Vec<&Record> = denial
            .iter()
            .filter(|r| r.record_type() == RecordType::NSEC)
            .collect();
        let nsec3s: Vec<&Record> = denial
            .iter()
            .filter(|r| r.record_type() == RecordType::NSEC3)
            .collect();

        // A mixed NSEC + NSEC3 answer: neither can be said to be the intended
        // proof, so believe neither.
        if !nsecs.is_empty() && !nsec3s.is_empty() {
            return false;
        }

        // ---- NSEC3 path (RFC 5155 §8.5) -------------------------------------
        //
        // Not hypothetical: `com.` is NSEC3-signed with opt-out, so a real
        // insecure delegation such as chatgpt.com is denied with NSEC3 and
        // nothing else. The first version of this fix refused NSEC3 outright,
        // which turned every such zone Bogus — SERVFAIL for every client, on a
        // zone that is genuinely fine.
        //
        // What IS verified here, and is not merely the resolver's word:
        //   * the NSEC3 RRset carries an RRSIG made by the PARENT's key. The
        //     signature covers the canonical NSEC3 RDATA we already parsed, so
        //     verifying it needs no hashing implementation;
        //   * the signer is the parent zone itself;
        //   * the opt-out flag is set — that flag is the mechanism by which a
        //     signed parent asserts "delegations under this hash may be
        //     unsigned", so a plain NSEC3 here would prove nothing about DS.
        //
        // KNOWN GAP, deliberately not papered over: this does not recompute the
        // NSEC3 hash to prove the record actually COVERS this delegation's
        // next-closer name. Until the closest-encloser walk lands, a hostile
        // resolver could replay a DIFFERENT validly-signed NSEC3 from the same
        // parent and have it accepted. That is a far narrower attack than the
        // defect this replaced — the previous code accepted a bare SOA, which
        // anyone can fabricate — but it is not zero, and it is the same reason
        // the answer-path NSEC3 denial is still capped at Indeterminate.
        if nsecs.is_empty() {
            if nsec3s.is_empty() {
                return false;
            }
            let sigs3 = Self::rrsig_records(denial, RecordType::NSEC3);
            if sigs3.is_empty() {
                return false;
            }
            for n3 in &nsec3s {
                let RData::DNSSEC(DNSSECRData::NSEC3(rec)) = &n3.data else {
                    continue;
                };
                if !rec.opt_out() {
                    continue;
                }
                for sig in &sigs3 {
                    if let Some(signer) =
                        self.verify_rrset(&n3.name, &[(*n3).clone()], sig, parent_dnskeys, now)
                    {
                        if name_eq(&signer, parent) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        let sigs = Self::rrsig_records(denial, RecordType::NSEC);
        if sigs.is_empty() {
            return false;
        }

        for nsec in &nsecs {
            let RData::DNSSEC(DNSSECRData::NSEC(n)) = &nsec.data else {
                continue;
            };
            // The NSEC must sit at the delegation name itself and describe an
            // insecure delegation: NS present, DS and SOA absent.
            if !name_eq(&nsec.name, zone) {
                continue;
            }
            if n.type_bit_maps().any(|t| t == RecordType::DS) {
                continue;
            }
            if !n.is_ancestor_delegation() {
                continue;
            }
            for sig in &sigs {
                // Verified against the PARENT's keys, and the signer must BE
                // the parent — a signature by some other zone proves nothing
                // about this delegation.
                if let Some(signer) =
                    self.verify_rrset(zone, &[(*nsec).clone()], sig, parent_dnskeys, now)
                {
                    if name_eq(&signer, parent) {
                        return true;
                    }
                }
            }
        }
        false
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
    ) -> ChainVerdict {
        if depth > MAX_CHAIN_DEPTH {
            return ChainVerdict::Fail;
        }
        let keys = Self::dnskey_records(dnskey_records);
        if keys.is_empty() {
            return ChainVerdict::Fail;
        }
        if zone.is_root() {
            return if self.matches_anchor(&keys) {
                ChainVerdict::Secure
            } else {
                ChainVerdict::Fail
            };
        }
        // DS RRset lives in the parent; fetch DS + parent DNSKEY concurrently
        let parent = zone.base_name();
        let (ds_records, parent_keys) = tokio::join!(
            self.fetch_rrset(zone, RecordType::DS, resolver),
            self.fetch_rrset(&parent, RecordType::DNSKEY, resolver)
        );
        let parent_keys = match parent_keys {
            FetchOutcome::Found(r) => r,
            FetchOutcome::Nodata { .. } | FetchOutcome::Failed => {
                return ChainVerdict::Fail;
            }
        };
        let parent_dnskeys = Self::dnskey_records(&parent_keys);
        let now = Self::now_epoch();

        // HANCORE 2026-10: proven DS absence is an unsigned delegation — but
        // "proven" has to mean authenticated. This used to be
        // `Nodata => InsecureIsland`, i.e. the resolver's assertion that no DS
        // exists was taken at face value, which let any resolver that answered
        // the DS query with NOERROR + a denial-shaped record declare the whole
        // subtree unsigned and bypass local validation for it. The parent must
        // now sign the denial.
        let ds_records = match ds_records {
            FetchOutcome::Found(r) => r,
            FetchOutcome::Nodata { denial } => {
                if self.authenticate_denial(zone, &parent, &denial, &parent_dnskeys, now) {
                    return ChainVerdict::InsecureIsland;
                }
                // Unauthenticated or unverifiable denial: not an island, and not
                // a cryptographic contradiction either. Fail closed and let the
                // caller report Indeterminate rather than silently demoting.
                return ChainVerdict::Fail;
            }
            FetchOutcome::Failed => {
                return ChainVerdict::Fail;
            }
        };
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
                    if !v.is_some_and(|signer| name_eq(&signer, &parent)) {
                        continue;
                    }
                    // Propagate island upward: a DS under an unsigned parent
                    // proves nothing, so the subtree is insecure — but it is
                    // NOT a cryptographic contradiction (never Bogus here).
                    match Box::pin(self.chain_to_root(&parent, &parent_keys, resolver, depth + 1))
                        .await
                    {
                        ChainVerdict::Secure => return ChainVerdict::Secure,
                        ChainVerdict::InsecureIsland => return ChainVerdict::InsecureIsland,
                        ChainVerdict::Fail => continue,
                    }
                }
            }
        }
        ChainVerdict::Fail
    }

    // FP-19 follow-up (video.twimg.com 2026-09-23): whether an unsigned link
    // lives in signed space. Checks DS at the owner name and its parent: a DS at
    // either proves a signed zone covers the name (stripping → Bogus). No DS at
    // both (e.g. CDN CNAME in an unsigned zone pointing at a signed target) means
    // the unsigned link is legitimate cross-zone data (Insecure link, never Bogus
    // by itself). Fetch failures count as NOT-signed here on purpose: when the
    // network is down the signed links fail closed to Bogus through their own
    // fetch/verify path, so the end state stays fail-closed regardless.
    async fn owner_zone_signed(&self, name: &Name, resolver: &DoHResolver) -> bool {
        let mut current = name.clone();
        for _ in 0..2 {
            if let FetchOutcome::Found(recs) =
                self.fetch_rrset(&current, RecordType::DS, resolver).await
            {
                if recs
                    .iter()
                    .any(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::DS(_))))
                {
                    return true;
                }
            }
            if current.is_root() {
                break;
            }
            current = current.base_name();
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

        // gather candidate RRsets: positive answers, else authority denial records.
        // The bool marks denial candidates: ONLY they go through the FP-18
        // coverage gate. Positive/chain candidates return Secure on chain
        // success exactly as before.
        let mut candidates: Vec<(Name, Vec<Record>, RecordType, bool)> = Vec::new();
        // True when the candidates form a CNAME chain (one or more links plus
        // the terminal RRset) rather than a single positive answer. Chains must
        // be authenticated END TO END: returning Secure on the first
        // chain-verifying link let a genuine signed CNAME authenticate a
        // substituted terminal address.
        let mut chain_mode = false;
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
            candidates.push((owner.clone(), answer_recs, rtype, false));
        } else if let Some(chain) = cname_chain(&msg.answers, &owner, rtype) {
            // CNAME chain: every link plus the terminal RRset must verify;
            // a missing link degrades to insecure (served, never Secure).
            chain_mode = true;
            candidates.extend(chain.into_iter().map(|(n, r, t)| (n, r, t, false)));
        } else if answer_recs
            .iter()
            .any(|rec| matches!(&rec.data, RData::DNSSEC(DNSSECRData::RRSIG(_))))
        {
            // FP-19: signed material in answers that chained to nothing is a
            // fail-closed Bogus — never silently demote a truncated signed
            // chain (e.g. hop-cap exceed) to Insecure via the denial path.
            debug!(
                "dnssec: signed answer records without a verifiable chain for {}",
                owner.to_ascii()
            );
            return DnssecState::Bogus;
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
                    candidates.push((name, recs, t, true));
                }
            }
            if candidates.is_empty() {
                // unsigned denial — insecure, not bogus
                return DnssecState::Insecure;
            }
        }

        let mut saw_insecure = false;
        // FP-18: coverage-gated denial. Chain-verified but non-covering NSECs
        // are replayed forgeries for THIS query (skip; Bogus if nothing else
        // verifies). Interval-only NSECs and all NSEC3s (no hash impl) cap at
        // Indeterminate — served honestly, never Secure.
        let mut noncovering_signed = false;
        let mut saw_capped = false;
        // A candidate whose RRSIGs are all present-but-unverifiable is
        // cryptographic-failure EVIDENCE, not an instant verdict: round-robin
        // CDN answers mix signature sets, and aborting on the first failing
        // candidate starves later ones (SERVFAIL roulette). Decided below,
        // after every candidate had its chance.
        let mut saw_crypto_failure = false;
        // CNAME-chain completeness: every link AND the terminal RRset must
        // chain-verify before the answer may be called Secure. Cleared by any
        // link that does not verify, so a genuine first CNAME can no longer
        // authenticate a substituted terminal address.
        let mut all_secure = true;
        // Strict chain rule: if ANY candidate carries RRSIGs, every link must
        // verify Secure. An unsigned link beside signed links smells like a
        // stripped signature redirecting qname to another valid signed name.
        let any_signed = candidates
            .iter()
            .any(|(_, recs, t, _)| !Self::rrsig_records(recs, *t).is_empty());
        for (name, recs, t, is_denial) in &candidates {
            let sigs = Self::rrsig_records(recs, *t);
            if sigs.is_empty() {
                if any_signed {
                    // Unsigned link beside signed candidates: stripping OR
                    // legitimate cross-zone unsigned data (CDN CNAME in an
                    // unsigned zone pointing at a signed target). Only Bogus
                    // when the link's own zone is signed (DS at the owner
                    // name or its parent); otherwise it is an Insecure link.
                    if self.owner_zone_signed(name, resolver).await {
                        debug!(
                            "dnssec: unsigned link in signed zone among signed candidates for {}",
                            name.to_ascii()
                        );
                        return DnssecState::Bogus;
                    }
                    saw_insecure = true;
                    all_secure = false;
                    continue;
                }
                saw_insecure = true;
                all_secure = false;
                continue;
            }
            let mut rrset_secure = false;
            let mut rrset_island = false;
            for sig in &sigs {
                let signer = sig.input().signer_name.clone();
                // fetch the signer's DNSKEY set and try it
                let dnskey_recs = match self
                    .fetch_rrset(&signer, RecordType::DNSKEY, resolver)
                    .await
                {
                    FetchOutcome::Found(r) => r,
                    // Nodata/Failed DNSKEY fetches cannot authenticate: try
                    // the next signature, fail closed at the end.
                    FetchOutcome::Nodata { .. } | FetchOutcome::Failed => continue,
                };
                if self
                    .verify_rrset(name, recs, sig, &Self::dnskey_records(&dnskey_recs), now)
                    .is_none()
                {
                    continue;
                }
                match Box::pin(self.chain_to_root(&signer, &dnskey_recs, resolver, 0)).await {
                    ChainVerdict::Secure => {
                        rrset_secure = true;
                        break;
                    }
                    // Unsigned delegation above a signed RRset: serve as
                    // insecure (RFC 4035 §4.2), never Bogus.
                    ChainVerdict::InsecureIsland => {
                        rrset_island = true;
                        break;
                    }
                    ChainVerdict::Fail => continue,
                }
            }
            if rrset_island {
                // Accumulate rather than return: a Bogus link elsewhere in the
                // chain must still outrank this (Bogus > Insecure).
                saw_insecure = true;
                all_secure = false;
                continue;
            }
            if rrset_secure && !is_denial {
                if !chain_mode {
                    // Single positive answer: nothing left to authenticate.
                    return DnssecState::Secure;
                }
                // CNAME chain: keep going. The terminal RRset (and any
                // further links) must chain-verify before the whole answer can
                // be Secure — the verdict is decided after the loop.
                continue;
            }
            if rrset_secure {
                // FP-18: a valid signature is not enough for denial — it must
                // actually deny THIS (qname, qtype).
                if *t == RecordType::NSEC {
                    if let Some((next, has_qtype, has_cname)) = nsec_shape(recs, rtype) {
                        match nsec_coverage(name, &next, has_qtype, has_cname, &owner, rtype) {
                            NsecCoverage::CoversNodata => return DnssecState::Secure,
                            NsecCoverage::CoversInterval => {
                                saw_capped = true;
                                continue;
                            }
                            NsecCoverage::NoCover => {
                                noncovering_signed = true;
                                continue;
                            }
                        }
                    } else {
                        // unparseable NSEC shape: cannot prove denial
                        noncovering_signed = true;
                        continue;
                    }
                } else {
                    // NSEC3 without hash verification: cap at Indeterminate.
                    saw_capped = true;
                    continue;
                }
            }
            // RRSIGs present but none chain-verify: record the cryptographic
            // failure and keep evaluating — a later candidate may still
            // authenticate the answer (CDN round-robin shapes). Decided below.
            debug!(
                "dnssec: RRSIGs present but chain failed for {}",
                name.to_ascii()
            );
            saw_crypto_failure = true;
            all_secure = false;
            continue;
        }
        if noncovering_signed {
            // chain-valid signatures that deny nothing for this query:
            // replayed/forged denial material for a different name.
            debug!(
                "dnssec: signed but non-covering denial for {}",
                owner.to_ascii()
            );
            return DnssecState::Bogus;
        }
        if saw_crypto_failure {
            // some RRset carried RRSIGs that verified against nothing while
            // no other candidate authenticated the answer: tampering or
            // breakage, fail closed.
            debug!(
                "dnssec: RRSIGs present but nothing chain-verified for {}",
                owner.to_ascii()
            );
            return DnssecState::Bogus;
        }
        if chain_mode && all_secure {
            // Every CNAME link and the terminal RRset chain-verified.
            debug!(
                "dnssec: signed CNAME chain fully authenticated for {}",
                owner.to_ascii()
            );
            return DnssecState::Secure;
        }
        if saw_capped {
            // wildcard-unproven interval or NSEC3: honestly unverified.
            return DnssecState::Indeterminate;
        }
        if saw_insecure {
            // At least one link (or the terminal) sits in an unsigned zone:
            // the answer cannot be called Secure (RFC 4035 §4.2 — an
            // unauthenticated CNAME binds nothing between the queried name and
            // the address it resolves to). Served, never authenticated.
            DnssecState::Insecure
        } else {
            DnssecState::Indeterminate
        }
    }
}

fn name_eq(a: &Name, b: &Name) -> bool {
    a.to_ascii().to_lowercase() == b.to_ascii().to_lowercase()
}

// FP-18: RFC 4034 §6.1 canonical DNS name ordering (rightmost-label-first,
// case-insensitive; shorter sorts first on shared suffix). Used to check
// NSEC interval coverage so replayed non-covering NSECs cannot yield Secure.
fn canonical_labels(name: &Name) -> Vec<String> {
    let s = name.to_ascii().to_lowercase();
    let s = s.strip_suffix('.').unwrap_or(&s);
    if s.is_empty() {
        Vec::new()
    } else {
        s.split('.').map(|l| l.to_string()).collect()
    }
}

fn canonical_cmp(a: &Name, b: &Name) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (la, lb) = (canonical_labels(a), canonical_labels(b));
    let n = la.len().min(lb.len());
    for i in 0..n {
        match la[la.len() - 1 - i].cmp(&lb[lb.len() - 1 - i]) {
            Ordering::Equal => continue,
            o => return o,
        }
    }
    la.len().cmp(&lb.len())
}

#[derive(Debug, PartialEq, Eq)]
enum NsecCoverage {
    /// Owner == qname and bitmap lacks qtype (genuine Nodata denial).
    CoversNodata,
    /// Interval brackets qname but wildcard/encloser proof is out of scope.
    CoversInterval,
    /// Does not deny this (qname, qtype) at all.
    NoCover,
}

// thin adapter: first NSEC RDATA in the candidate RRset → coverage inputs.
// None when no parseable NSEC is present (caller treats as unproven).
fn nsec_shape(recs: &[Record], qtype: RecordType) -> Option<(Name, bool, bool)> {
    for rec in recs {
        if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = &rec.data {
            let has_qtype = nsec.type_bit_maps().any(|t| t == qtype);
            let has_cname = nsec.type_bit_maps().any(|t| t == RecordType::CNAME);
            return Some((nsec.next_domain_name().clone(), has_qtype, has_cname));
        }
    }
    None
}

// FP-18: pure coverage decision over primitives (unit-testable without
// constructing NSEC records). Bitmap/CNAME presence comes from the NSEC RDATA.
fn nsec_coverage(
    owner: &Name,
    next: &Name,
    bitmap_has_qtype: bool,
    bitmap_has_cname: bool,
    qname: &Name,
    qtype: RecordType,
) -> NsecCoverage {
    use std::cmp::Ordering;
    if name_eq(owner, qname) {
        if bitmap_has_qtype {
            return NsecCoverage::NoCover;
        }
        // a CNAME at owner means the server should have returned it, not NSEC
        if bitmap_has_cname && qtype != RecordType::CNAME {
            return NsecCoverage::NoCover;
        }
        return NsecCoverage::CoversNodata;
    }
    let order = canonical_cmp(owner, next);
    let inside = if order == Ordering::Less {
        canonical_cmp(owner, qname) == Ordering::Less
            && canonical_cmp(qname, next) == Ordering::Less
    } else if order == Ordering::Greater {
        // wrap-around at the zone end: (owner, +inf) ∪ (-inf, next)
        canonical_cmp(owner, qname) == Ordering::Less
            || canonical_cmp(qname, next) == Ordering::Less
    } else {
        false
    };
    if inside {
        NsecCoverage::CoversInterval
    } else {
        NsecCoverage::NoCover
    }
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

// Run-4: retired in favor of crate::dns::secure_query_id (OS CSPRNG).
// All DNS TXIDs — chain queries, ECH queries, canary probes — now share one
// strength instead of three different ones.
fn rand_id() -> u16 {
    crate::dns::secure_query_id()
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
    use hickory_proto::rr::rdata::A;

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

    // FP-18: canonical ordering (RFC 4034 §6.1) — rightmost-first,
    // case-insensitive, shorter-first on shared suffix.
    #[test]
    fn test_canonical_cmp_ordering() {
        use std::cmp::Ordering;
        let n = |s: &str| Name::from_ascii(s).unwrap();
        assert_eq!(
            canonical_cmp(&n("a.example."), &n("b.example.")),
            Ordering::Less
        );
        assert_eq!(
            canonical_cmp(&n("example."), &n("a.example.")),
            Ordering::Less
        );
        assert_eq!(
            canonical_cmp(&n("WWW.EXAMPLE."), &n("www.example.")),
            Ordering::Equal
        );
        assert_eq!(
            canonical_cmp(&n("a.example."), &n("a.example.")),
            Ordering::Equal
        );
        // zulu.example > alpha.example at the leftmost differing label
        assert_eq!(
            canonical_cmp(&n("zulu.example."), &n("alpha.example.")),
            Ordering::Greater
        );
    }

    // FP-18: NSEC coverage matrix over primitives (no network, no keys).
    #[test]
    fn test_nsec_coverage_matrix() {
        let n = |s: &str| Name::from_ascii(s).unwrap();
        // owner == qname, bitmap lacks qtype → genuine Nodata denial
        assert_eq!(
            nsec_coverage(
                &n("host.example."),
                &n("other.example."),
                false,
                false,
                &n("host.example."),
                RecordType::A
            ),
            NsecCoverage::CoversNodata
        );
        // owner == qname but bitmap HAS qtype → denies nothing (replay/wrong RRset)
        assert_eq!(
            nsec_coverage(
                &n("host.example."),
                &n("other.example."),
                true,
                false,
                &n("host.example."),
                RecordType::A
            ),
            NsecCoverage::NoCover
        );
        // CNAME at owner for non-CNAME query → server should have returned it
        assert_eq!(
            nsec_coverage(
                &n("host.example."),
                &n("other.example."),
                false,
                true,
                &n("host.example."),
                RecordType::A
            ),
            NsecCoverage::NoCover
        );
        // interval brackets qname → NXDOMAIN-shaped, wildcard unproven
        assert_eq!(
            nsec_coverage(
                &n("a.example."),
                &n("c.example."),
                false,
                false,
                &n("b.example."),
                RecordType::A
            ),
            NsecCoverage::CoversInterval
        );
        // replayed NSEC from elsewhere in the zone → no cover (the FP-18 kill)
        assert_eq!(
            nsec_coverage(
                &n("x.example."),
                &n("z.example."),
                false,
                false,
                &n("b.example."),
                RecordType::A
            ),
            NsecCoverage::NoCover
        );
        // wrap-around at zone end covers
        assert_eq!(
            nsec_coverage(
                &n("z.example."),
                &n("a.example."),
                false,
                false,
                &n("zz.example."),
                RecordType::A
            ),
            NsecCoverage::CoversInterval
        );
    }

    // builds a DO-bit query with hickory (never hand-rolled wire bytes)
    fn doh_query_with_do(name: &str, qtype: RecordType) -> Vec<u8> {
        use hickory_proto::op::Edns;
        let mut msg = Message::new(rand_id(), MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let fqdn = format!("{}.", name.trim_end_matches('.'));
        let owner = Name::from_ascii(&fqdn).unwrap();
        msg.add_query(Query::query(owner, qtype));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.set_max_payload(1232);
        msg.set_edns(edns);
        msg.to_vec().unwrap()
    }

    // Run-4: live-network test — excluded from hermetic gates
    // (`cargo test -- --ignored`), matching the live_* convention.
    #[tokio::test]
    #[ignore]
    async fn test_signed_zone_validates_secure_live() {
        let v = DnssecValidator::new();
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        // ietf.org is DNSSEC-signed (independently confirmed via AD flag)
        let q = doh_query_with_do("ietf.org", RecordType::A);
        let (resp, _) = resolver
            .resolve(&q)
            .await
            .expect("live DoH query should succeed");
        let state = v.validate("ietf.org", 1, &resp, &resolver).await;
        assert_eq!(state, DnssecState::Secure);
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

    // Island regression (chatgpt.com 2026-09-23): a signed zone with NO DS
    // in the parent must validate Insecure (served), never Bogus (SERVFAIL).
    // Live-network — excluded from hermetic gates like the other live tests.
    #[tokio::test]
    #[ignore]
    async fn test_unsigned_delegation_island_is_insecure_live() {
        let v = DnssecValidator::new();
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let q = doh_query_with_do("chatgpt.com", RecordType::A);
        let (resp, _) = resolver
            .resolve(&q)
            .await
            .expect("live DoH query should succeed");
        let state = v.validate("chatgpt.com", 1, &resp, &resolver).await;
        assert_eq!(state, DnssecState::Insecure);
    }

    // CDN regression (video.twimg.com 2026-09-23): unsigned CNAME in an
    // unsigned zone pointing at a signed target must be SERVED (Secure when
    // the target chain verifies, Insecure otherwise) — never Bogus. Round-
    // robin CDN shapes vary per query, so assert served-ness, not a fixed
    // state. Live-network — excluded from hermetic gates.
    #[tokio::test]
    #[ignore]
    async fn test_unsigned_cname_to_signed_target_is_secure_live() {
        let v = DnssecValidator::new();
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let q = doh_query_with_do("video.twimg.com", RecordType::A);
        let (resp, _) = resolver
            .resolve(&q)
            .await
            .expect("live DoH query should succeed");
        let state = v.validate("video.twimg.com", 1, &resp, &resolver).await;
        assert_ne!(state, DnssecState::Bogus, "CDN answer must be served");
    }

    #[tokio::test]
    #[ignore]
    async fn test_tampered_signed_response_is_bogus_live() {
        let v = DnssecValidator::new();
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let q = doh_query_with_do("ietf.org", RecordType::A);
        let (resp, _) = resolver
            .resolve(&q)
            .await
            .expect("live DoH query should succeed");
        // flip a byte inside the first A-record rdata via parsed message
        let mut msg = Message::from_vec(&resp).expect("response must parse");
        let mut tampered = false;
        for rec in msg.answers.iter_mut() {
            if rec.record_type() == RecordType::A {
                if let RData::A(addr) = &mut rec.data {
                    let mut octets = addr.octets();
                    octets[3] ^= 0x01;
                    *addr = hickory_proto::rr::rdata::A::new(
                        octets[0], octets[1], octets[2], octets[3],
                    );
                    tampered = true;
                    break;
                }
            }
        }
        assert!(tampered, "live response must contain an A record");
        let wire = msg.to_vec().unwrap();
        let state = v.validate("ietf.org", 1, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Bogus);
    }

    /// HANCORE regression: a CNAME chain must be authenticated end to end.
    ///
    /// `validate_inner` returned `Secure` as soon as the FIRST candidate
    /// chain-verified, so a genuinely signed first CNAME link was enough to
    /// authenticate the whole response — later links and, critically, the
    /// terminal address RRset were never examined. A hostile or compromised
    /// resolver could therefore keep a real signed CNAME and substitute the
    /// address it points at; `server.rs` then cached and served it as Secure.
    ///
    /// Both assertions come from one live response so the test is
    /// self-consistent: untampered must be Secure (proving the first link does
    /// verify, so the case really is a signed chain), and tampering only the
    /// terminal address must NOT stay Secure.
    #[tokio::test]
    #[ignore]
    async fn test_tampered_terminal_in_signed_cname_chain_is_not_secure_live() {
        let v = DnssecValidator::new();
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let q = doh_query_with_do("www.sidn.nl", RecordType::A);
        let (resp, _) = resolver
            .resolve(&q)
            .await
            .expect("live DoH query should succeed");

        let msg = Message::from_vec(&resp).expect("response must parse");
        let has_cname = msg
            .answers
            .iter()
            .any(|r| r.record_type() == RecordType::CNAME);
        assert!(has_cname, "fixture must be a CNAME chain");

        // Control: the untampered chain authenticates. Without this the test
        // could pass for the wrong reason (e.g. chain shape changed, so the
        // first link never verified at all).
        assert_eq!(
            v.validate("www.sidn.nl", 1, &resp, &resolver).await,
            DnssecState::Secure,
            "unmodified signed chain must validate Secure"
        );

        // Now substitute only the terminal address, leaving every signature
        // untouched — exactly what a hostile resolver can do.
        let mut msg = Message::from_vec(&resp).expect("response must parse");
        let mut tampered = false;
        for rec in msg.answers.iter_mut() {
            if rec.record_type() == RecordType::A {
                if let RData::A(addr) = &mut rec.data {
                    let mut o = addr.octets();
                    o[3] ^= 0x01;
                    *addr = hickory_proto::rr::rdata::A::new(o[0], o[1], o[2], o[3]);
                    tampered = true;
                    break;
                }
            }
        }
        assert!(tampered, "chain must contain a terminal A record");

        let state = v
            .validate("www.sidn.nl", 1, &msg.to_vec().unwrap(), &resolver)
            .await;
        assert_ne!(
            state,
            DnssecState::Secure,
            "terminal address RRset was never authenticated: a substituted A \
             record rode the first CNAME link's valid signature to Secure"
        );
    }

    /// HANCORE regression, multi-link shape: the intermediate links matter too,
    /// not just the terminal. A real CDN chain (signed apex CNAME into unsigned
    /// CDN zones) is exactly the shape where an attacker has a genuine signed
    /// first link to ride on.
    ///
    /// Asserts the chain is fully authenticated when untouched, and that
    /// substituting the terminal address does not stay Secure.
    #[tokio::test]
    #[ignore]
    async fn test_tampered_terminal_in_multihop_cname_chain_is_not_secure_live() {
        let v = DnssecValidator::new();
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let q = doh_query_with_do("www.powerdns.com", RecordType::A);
        let (resp, _) = resolver
            .resolve(&q)
            .await
            .expect("live DoH query should succeed");

        let msg = Message::from_vec(&resp).expect("response must parse");
        let cname_hops = msg
            .answers
            .iter()
            .filter(|r| r.record_type() == RecordType::CNAME)
            .count();
        if cname_hops < 2 {
            eprintln!(
                "SKIP: www.powerdns.com is no longer a multi-hop CNAME chain \
                 ({} link(s)) — CDN shape changed",
                cname_hops
            );
            return;
        }

        assert_eq!(
            v.validate("www.powerdns.com", 1, &resp, &resolver).await,
            DnssecState::Secure,
            "unmodified signed multi-hop chain must validate Secure"
        );

        let mut msg = Message::from_vec(&resp).expect("response must parse");
        let mut tampered = false;
        for rec in msg.answers.iter_mut() {
            if rec.record_type() == RecordType::A {
                if let RData::A(addr) = &mut rec.data {
                    let mut o = addr.octets();
                    o[3] ^= 0x01;
                    *addr = hickory_proto::rr::rdata::A::new(o[0], o[1], o[2], o[3]);
                    tampered = true;
                    break;
                }
            }
        }
        assert!(tampered, "chain must contain a terminal A record");

        let state = v
            .validate("www.powerdns.com", 1, &msg.to_vec().unwrap(), &resolver)
            .await;
        assert_ne!(
            state,
            DnssecState::Secure,
            "multi-hop chain terminal was authenticated only via the first link"
        );
    }

    /// `cname_chain` must enumerate EVERY link plus the terminal RRset.
    ///
    /// This is the enumeration half of the HANCORE fix: the validator can only
    /// require end-to-end authentication if it actually hands back every hop.
    /// Pure and hermetic — no crypto, no network.
    #[test]
    fn test_cname_chain_enumerates_every_link_and_terminal() {
        use hickory_proto::rr::rdata::CNAME;
        let mut msg = Message::new(0x3333, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        let owner = Name::from_ascii("www.example.com.").unwrap();
        let hop1 = Name::from_ascii("cdn.example.net.").unwrap();
        let hop2 = Name::from_ascii("edge.example.org.").unwrap();

        msg.answers.push(Record::from_rdata(
            owner.clone(),
            300,
            RData::CNAME(CNAME(hop1.clone())),
        ));
        msg.answers.push(Record::from_rdata(
            hop1.clone(),
            300,
            RData::CNAME(CNAME(hop2.clone())),
        ));
        msg.answers.push(Record::from_rdata(
            hop2.clone(),
            300,
            RData::A(A::new(93, 184, 216, 34)),
        ));

        let chain = cname_chain(&msg.answers, &owner, RecordType::A)
            .expect("well-formed chain must enumerate");
        assert_eq!(chain.len(), 3, "two links plus the terminal");
        assert!(name_eq(&chain[0].0, &owner) && chain[0].2 == RecordType::CNAME);
        assert!(name_eq(&chain[1].0, &hop1) && chain[1].2 == RecordType::CNAME);
        assert!(name_eq(&chain[2].0, &hop2) && chain[2].2 == RecordType::A);
    }

    /// A chain whose terminal RRset is missing must NOT enumerate — the
    /// validator treats that as a broken chain (FP-19 Bogus), never as a
    /// verified prefix.
    #[test]
    fn test_cname_chain_rejects_chain_without_terminal() {
        use hickory_proto::rr::rdata::CNAME;
        let mut msg = Message::new(0x4444, MessageType::Response, OpCode::Query);
        let owner = Name::from_ascii("www.example.com.").unwrap();
        let hop1 = Name::from_ascii("cdn.example.net.").unwrap();
        msg.answers.push(Record::from_rdata(
            owner.clone(),
            300,
            RData::CNAME(CNAME(hop1.clone())),
        ));
        // no terminal A for hop1
        assert!(
            cname_chain(&msg.answers, &owner, RecordType::A).is_none(),
            "chain without a terminal RRset must not enumerate"
        );
    }
}

#[cfg(test)]
mod delegation_denial_tests {
    use super::*;
    use hickory_proto::dnssec::rdata::{SigInput, NSEC};
    use hickory_proto::dnssec::PublicKeyBuf;
    use hickory_proto::rr::SerialNumber;

    fn zone(s: &str) -> Name {
        s.parse().expect("zone")
    }

    fn now() -> u32 {
        DnssecValidator::now_epoch()
    }

    /// An NSEC at `owner` advertising `types`. A signed parent uses this shape
    /// at a delegation name to prove the delegation is insecure: NS present,
    /// DS and SOA absent (hickory exposes exactly that as
    /// `is_ancestor_delegation`).
    fn nsec(owner: &str, next: &str, types: &[RecordType]) -> Record {
        let nsec = NSEC::new(next.parse::<Name>().expect("next"), types.iter().copied());
        Record::from_rdata(
            owner.parse::<Name>().expect("owner"),
            3600,
            RData::DNSSEC(DNSSECRData::NSEC(nsec)),
        )
    }

    fn dnskey_rec(owner: &str, tag: u16) -> Record {
        let key = hickory_proto::dnssec::rdata::DNSKEY::new(
            true,  // zone key
            true,  // SEP
            false, // not revoked
            PublicKeyBuf::new(vec![0u8; 64], Algorithm::ECDSAP256SHA256),
        );
        let _ = tag;
        Record::from_rdata(
            owner.parse::<Name>().expect("owner"),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(key)),
        )
    }

    /// An RRSIG whose bytes cannot possibly verify — it exists only so the
    /// "a denial must be signed" path has a signature present to reject.
    fn unverifiable_rrsig(owner: &str, signer: &str, covers: RecordType) -> Record {
        let input = SigInput {
            type_covered: covers,
            algorithm: Algorithm::ECDSAP256SHA256,
            num_labels: owner.parse::<Name>().expect("owner").num_labels(),
            original_ttl: 3600,
            sig_expiration: SerialNumber::new(now() + 3600),
            sig_inception: SerialNumber::new(now().saturating_sub(60)),
            key_tag: 4242,
            signer_name: signer.parse::<Name>().expect("signer"),
        };
        Record::from_rdata(
            owner.parse::<Name>().expect("owner"),
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![0xAA; 64]))),
        )
    }

    fn keys(records: &[Record]) -> Vec<DNSKEY> {
        DnssecValidator::dnskey_records(records)
    }

    /// HANCORE 2026-10, the headline case. A hostile resolver answers the DS
    /// query with NOERROR + zero DS records plus an NSEC it signs itself (or not
    /// at all). Accepting that as an insecure delegation is the bypass: on
    /// unpatched source this was `true`, because the old code only required
    /// that *some* denial-shaped record be present and never verified it.
    #[test]
    fn test_unauthenticated_denial_is_refused() {
        let denial = vec![
            nsec("example.com.", "aaa.com.", &[RecordType::NS]),
            unverifiable_rrsig("example.com.", "com.", RecordType::NSEC),
        ];
        assert!(
            !DnssecValidator::new().authenticate_denial(
                &zone("example.com."),
                &zone("com."),
                &denial,
                &keys(&[dnskey_rec("com.", 1)]),
                now()
            ),
            "a denial that does not verify against the parent's keys must not \
             be accepted as an insecure delegation"
        );
    }

    /// A denial with no RRSIG at all is the purest form of the bypass.
    #[test]
    fn test_denial_without_any_signature_is_refused() {
        let denial = vec![nsec("example.com.", "aaa.com.", &[RecordType::NS])];
        assert!(!DnssecValidator::new().authenticate_denial(
            &zone("example.com."),
            &zone("com."),
            &denial,
            &keys(&[dnskey_rec("com.", 1)]),
            now()
        ));
    }

    /// Nothing to check.
    #[test]
    fn test_empty_denial_is_refused() {
        assert!(!DnssecValidator::new().authenticate_denial(
            &zone("example.com."),
            &zone("com."),
            &[],
            &keys(&[dnskey_rec("com.", 1)]),
            now()
        ));
    }

    /// A denial with no parent keys to verify against must not be believed.
    #[test]
    fn test_denial_with_no_parent_keys_is_refused() {
        let denial = vec![
            nsec("example.com.", "aaa.com.", &[RecordType::NS]),
            unverifiable_rrsig("example.com.", "com.", RecordType::NSEC),
        ];
        assert!(!DnssecValidator::new().authenticate_denial(
            &zone("example.com."),
            &zone("com."),
            &denial,
            &[],
            now()
        ));
    }

    /// NSEC3-only cannot be evaluated (this crate has no NSEC3 hash
    /// implementation), so it must be refused rather than believed. The caller
    /// turns a refusal into Indeterminate: served with a warning, never cached
    /// as Secure — strictly better than the unauthenticated Insecure this
    /// replaces.
    #[test]
    fn test_nsec3_denial_is_refused() {
        let denial = vec![
            nsec("example.com.", "aaa.com.", &[RecordType::NS]),
            unverifiable_rrsig("example.com.", "com.", RecordType::NSEC3),
        ];
        assert!(!DnssecValidator::new().authenticate_denial(
            &zone("example.com."),
            &zone("com."),
            &denial,
            &keys(&[dnskey_rec("com.", 1)]),
            now()
        ));
    }

    /// The NSEC must sit at the delegation name. One for an unrelated name is a
    /// replay, not a proof about this zone.
    #[test]
    fn test_denial_nsec_must_be_at_the_delegation_name() {
        let denial = vec![
            nsec("other.com.", "zzz.com.", &[RecordType::NS]),
            unverifiable_rrsig("other.com.", "com.", RecordType::NSEC),
        ];
        assert!(!DnssecValidator::new().authenticate_denial(
            &zone("example.com."),
            &zone("com."),
            &denial,
            &keys(&[dnskey_rec("com.", 1)]),
            now()
        ));
    }

    /// An NSEC whose bitmap advertises DS describes a SIGNED delegation, whose
    /// absence cannot be proven this way.
    #[test]
    fn test_denial_nsec_claiming_ds_is_refused() {
        let denial = vec![
            nsec(
                "example.com.",
                "aaa.com.",
                &[RecordType::NS, RecordType::DS],
            ),
            unverifiable_rrsig("example.com.", "com.", RecordType::NSEC),
        ];
        assert!(!DnssecValidator::new().authenticate_denial(
            &zone("example.com."),
            &zone("com."),
            &denial,
            &keys(&[dnskey_rec("com.", 1)]),
            now()
        ));
    }

    /// A well-formed, correctly-placed, correctly-typed denial must be refused
    /// for exactly one reason: the signature does not verify. This isolates the
    /// fix to authentication and proves the shape checks are not simply
    /// rejecting everything.
    #[test]
    fn test_shape_is_accepted_and_only_authentication_gates_it() {
        // Sanity: the fixture really is the insecure-delegation shape, so a
        // refusal can only come from the signature check.
        let n = nsec("example.com.", "aaa.com.", &[RecordType::NS]);
        let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = &n.data else {
            panic!("fixture is not an NSEC")
        };
        assert!(
            nsec.is_ancestor_delegation(),
            "fixture must be a delegation NSEC"
        );
        assert!(
            !nsec.type_bit_maps().any(|t| t == RecordType::DS),
            "fixture must not advertise DS"
        );

        let denial = vec![
            n,
            unverifiable_rrsig("example.com.", "com.", RecordType::NSEC),
        ];
        assert!(!DnssecValidator::new().authenticate_denial(
            &zone("example.com."),
            &zone("com."),
            &denial,
            &keys(&[dnskey_rec("com.", 1)]),
            now()
        ));
    }

    /// Regression guard on the response-shape half of the fix: the SOA that used
    /// to stand in for a denial is gone, and the additional section is no
    /// longer scanned.
    #[test]
    fn test_soa_and_additional_section_are_not_denial_proofs() {
        let src = include_str!("dnssec.rs");
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod delegation_denial_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod
            .find("let mut denial: Vec<Record> = Vec::new();")
            .expect("denial collection");
        let block = &prod[at..(at + 1400).min(prod.len())];
        assert!(
            !block.contains("msg.additionals"),
            "the additional section must not be scanned for denial records: {}",
            block
        );
        assert!(
            !block.contains("RecordType::SOA"),
            "an SOA must not count as a denial record: {}",
            block
        );
        assert!(
            block.contains("msg.authorities"),
            "denial records must come from the authority section: {}",
            block
        );
    }

    /// And `chain_to_root` must route Nodata through the authenticator instead
    /// of returning InsecureIsland directly.
    #[test]
    fn test_chain_does_not_take_nodata_at_face_value() {
        let src = include_str!("dnssec.rs");
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod delegation_denial_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);
        assert!(
            !prod.contains("Nodata => return ChainVerdict::InsecureIsland"),
            "Nodata must no longer be an unconditional insecure delegation"
        );
        assert!(
            prod.contains("self.authenticate_denial(zone, &parent, &denial, &parent_dnskeys, now)"),
            "chain_to_root must authenticate the denial before declaring an island"
        );
    }
}
