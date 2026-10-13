//! local DNSSEC chain validation (RRSIG + DNSKEY + DS up to the embedded root trust anchor).
//!
//! Scope (honest limits, also summarized in the README options table):
//! - Positive answers (A/AAAA covered here) are fully chain-validated.
//! - NSEC denial requires interval/bitmap coverage (FP-18); NSEC3 denials are
//!   capped at Indeterminate (no hash verification without new crypto deps),
//!   and NSEC3 closest-encloser completeness is NOT checked.
//! - Truncated CNAME chains with signed links are Bogus, never silently
//!   demoted to Insecure (FP-19).
//! - Unsigned delegations are NOT yet served as Insecure. RFC 4035 §4.2
//!   requires the absence of a DS to itself be authenticated by a signed
//!   NSEC/NSEC3, and nothing here performs that verification. Until it does,
//!   a zone that is not positively `Signed` is `Unknown`, and every unproven
//!   case fails closed to Bogus → SERVFAIL. This is stricter than the RFC's
//!   ideal behaviour on purpose: serving forged answers as Insecure is a
//!   silent DNSSEC bypass, whereas a SERVFAIL is visible and retryable.
//! - "Could not tell" is never treated as "unsigned" (D3). A failed fetch, an
//!   unreachable DS, or a depth-cap overrun used to collapse into the same
//!   answer as a genuinely unsigned zone, which let a stripped signed answer
//!   be cached and served as Insecure whenever the network was flaky.
//! - DNAME redirections are never Secure: hickory-proto rejects DNAME
//!   records at parse time, so such responses cannot validate and fail
//!   closed rather than being served as verified.
//! - No RFC 5011 trust-anchor rollover: the compiled-in root KSKs are used.
//!   Roadmap if ever needed: persist observed root DNSKEY sets in a
//!   root-owned dir, track add/remove hold-down timers (30 days), honor the
//!   REVOKE bit, and only then swap the anchor — weeks of careful,
//!   time-dependent work for a threat (silent root KSK rollover) that
//!   announces itself months ahead via IANA.
//! - DNSSEC signatures themselves are classical (ECDSA/RSA); "post-quantum"
//!   in albus refers to DoH transport key exchange, not signatures.
//!
//! States: Secure (chain verifies to the embedded anchor), Bogus
//! (cryptographic failure OR any unproven/unsigned case → SERVFAIL, never
//! cached), Indeterminate (infrastructure error → served without caching).
//! `Insecure` remains part of the state enum for the server's cache policy
//! and for future authenticated-denial support, but this validator does not
//! currently return it — see the unsigned-delegation note above.

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

/// Result of fetching one RRset for chain validation.
///
/// D2 fix: `NoDs` used to be a single `NODATA` variant, and `fetch_rrset`
/// produced it whenever a response merely *shaped* like a denial (it
/// contained an SOA/NSEC/NSEC3) with zero matching records. That shape is
/// cheap to forge: a hostile resolver can answer any DS query that way and
/// drive the chain to `InsecureIsland`, silently downgrading a signed zone
/// to unsigned. RFC 4035 §4.2 requires the denial itself to be authenticated
/// by a signed NSEC/NSEC3 before "no DS" counts as proof.
///
/// The authenticated-absence case is intentionally not modelled yet: nothing
/// in this crate currently validates a signed NSEC/NSEC3 denial against the
/// trust anchor, so there is no code path that could honestly produce it
/// (NSEC3 hashing is an unimplemented capability, see the module docs). Until
/// that exists, every "no DS" observation is `DsShapeOnly` and therefore
/// inconclusive. Adding `NoDs` later is a pure addition: it would turn the
/// `DsShapeOnly` arms in `chain_to_root` / `owner_zone_signing` into a proven
/// unsigned delegation without changing any other call site.
#[derive(Debug)]
enum FetchOutcome {
    Found(Vec<Record>),
    /// Denial-shaped response whose signatures were not authenticated.
    /// Inconclusive — callers must fail closed.
    DsShapeOnly,
    Failed,
}

/// Chain verdict from validating a DNSKEY RRset up to the trust anchor.
///
/// - `Secure`: full DS→DNSKEY chain verified to the embedded root anchor.
/// - `Fail`: everything else — including an unsigned delegation, which used
///   to have its own `InsecureIsland` arm but is unreachable while no
///   authenticated-denial support exists. See `FetchOutcome`.
///
/// Zone-signing status of the closest enclosing zone for a name.
///
/// D3 fix: this used to be a `bool`, where "we could not tell" (fetch
/// failure, depth-cap overrun) collapsed into the same `false` as "unsigned".
/// Callers read that as "unsigned is fine here" and served + cached the
/// answer as `Insecure` — a silent DNSSEC downgrade whenever the network was
/// merely flaky. The signed / not-established distinction is now explicit so
/// callers fail closed on everything that is not positively `Signed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZoneSigning {
    /// A DS was found at the apex: the zone is signed.
    Signed,
    /// The apex or its DS could not be established (fetch failure, depth cap,
    /// un-authenticated "no DS" answer, parse error). Nothing may be
    /// concluded — callers must not serve this as Insecure.
    ///
    /// There is deliberately no "ProvablyUnsigned" arm yet: RFC 4035 §4.2
    /// requires the absence of a DS to itself be authenticated by a signed
    /// NSEC/NSEC3, and nothing in this crate performs that verification (see
    /// FetchOutcome). Until it does, every non-signed verdict is Unknown and
    /// the validator fails closed. When authenticated-denial support lands,
    /// this gains a third arm and `owner_zone_signing` returns it only when a
    /// signed denial has been chain-verified — no other call site changes.
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
enum ChainVerdict {
    Secure,
    /// Anything that did not chain-verify to the trust anchor: fetch
    /// failures, bad digests, broken chains, and — until authenticated-denial
    /// support exists (see FetchOutcome) — every un-provable "no DS" answer.
    /// All of these fail closed to Bogus upstream; keeping them one variant
    /// makes that explicit and leaves an obvious place to reintroduce a
    /// provable unsigned island.
    Fail,
}

// algorithms we accept signatures from (RSASHA1/NSEC3RSASHA1 excluded:
// legacy SHA1-signed zones SERVFAIL rather than risk collision forgery)
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
        // D5: only cache the fail-closed verdict. Caching Indeterminate used
        // to pin an unverified answer for the whole NEG_CACHE_TTL, so one
        // stalled validation suppressed re-validation for that name even
        // after the network recovered. Re-validating is the correct response
        // to "could not judge".
        if state != DnssecState::Bogus {
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
    ) -> FetchOutcome {
        if let Some(cached) = self.cache_lookup(name, rtype) {
            eprintln!(
                "CACHE-HIT {} {:?} n={}",
                name.to_ascii(),
                rtype,
                cached.len()
            );
            return FetchOutcome::Found(cached);
        }
        let wire = Self::build_query(name, rtype);
        if wire.is_empty() {
            return FetchOutcome::Failed;
        }
        let (resp_wire, _) = match resolver.resolve(&wire).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("RESOLVE-FAIL {} {:?}: {}", name.to_ascii(), rtype, e);
                return FetchOutcome::Failed;
            }
        };
        let msg = match Message::from_vec(&resp_wire) {
            Ok(m) => m,
            Err(_) => return FetchOutcome::Failed,
        };
        // Only NOERROR with zero matching records is a proven NODATA.
        // Anything else undecided (SERVFAIL/REFUSED/timeout/parse) stays a
        // failure so callers fail closed.
        if msg.response_code != ResponseCode::NoError {
            return FetchOutcome::Failed;
        }
        let mut out = Vec::new();
        let mut matched = false;
        let mut denial_marker = false;
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
                matched = true;
            } else if rec.record_type() == RecordType::SOA
                || rec.record_type() == RecordType::NSEC
                || rec.record_type() == RecordType::NSEC3
            {
                // NODATA-shaped denial scaffolding (proves the server answered
                // the question instead of failing it)
                denial_marker = true;
            }
        }
        // D2 fix: a denial-SHAPED response (NOERROR carrying an SOA/NSEC/NSEC3
        // with zero matching records) is not yet proof that the RRset is
        // absent — that proof must be authenticated against the trust anchor,
        // which happens in chain_to_root. Until then this is inconclusive and
        // reported as DsShapeOnly so callers fail closed instead of silently
        // downgrading a signed zone to unsigned.
        if !matched {
            if denial_marker {
                return FetchOutcome::DsShapeOnly;
            }
            return FetchOutcome::Failed;
        }
        self.cache_store(name, rtype, out.clone());
        FetchOutcome::Found(out)
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
        // D2 fix: a denial-SHAPED but unauthenticated "no DS" (DsShapeOnly) is
        // NOT proof of an unsigned delegation. A hostile resolver can forge
        // that shape for any signed zone and drive us to InsecureIsland,
        // silently downgrading DNSSEC. Only the rare NoDs variant — an
        // authenticated absence — may conclude "unsigned"; everything
        // undecided stays fail-closed (Fail → Bogus upstream).
        let ds_records = match ds_records {
            FetchOutcome::Found(r) => r,
            // No authenticated denial path exists yet, so "no DS" is always
            // inconclusive → fail closed. See FetchOutcome's docs.
            FetchOutcome::DsShapeOnly | FetchOutcome::Failed => {
                return ChainVerdict::Fail;
            }
        };
        let parent_keys = match parent_keys {
            FetchOutcome::Found(r) => r,
            FetchOutcome::DsShapeOnly | FetchOutcome::Failed => {
                return ChainVerdict::Fail;
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
    // Whether the closest enclosing zone of `name` is signed.
    //
    // D3 fix: this used to return `bool`, mapping every "could not tell"
    // outcome — fetch failure, DS fetch failure, depth-cap overrun — onto
    // `false` ("not signed"). Callers read `false` as "unsigned is fine
    // here" and served + cached the answer as Insecure, which is a silent
    // DNSSEC downgrade whenever the network was merely flaky. Now the
    // unknown case is reported as `ZoneSigning::Unknown` and callers fail
    // closed on it.
    //
    // Apex discovery (DS-WALK-DEPTH-2 fix): DS lives only at the zone apex,
    // so a fixed 2-step walk misses deep names. Walk up looking for the
    // closest enclosing SOA, bounded by MAX_CHAIN_DEPTH, then a single DS
    // probe at the apex decides. Stops AT the zone cut on purpose: walking
    // blindly to root would hit a higher signed ancestor's DS and
    // misclassify legitimate unsigned-delegation data as Bogus.
    async fn owner_zone_signing(&self, name: &Name, resolver: &DoHResolver) -> ZoneSigning {
        let mut current = name.clone();
        for _ in 0..MAX_CHAIN_DEPTH {
            match self.fetch_rrset(&current, RecordType::SOA, resolver).await {
                FetchOutcome::Found(recs) => {
                    if recs
                        .iter()
                        .any(|r| r.record_type() == RecordType::SOA && name_eq(&r.name, &current))
                    {
                        // DS probe at the apex decides signed vs provably unsigned.
                        return match self.fetch_rrset(&current, RecordType::DS, resolver).await {
                            FetchOutcome::Found(ds) => {
                                if ds
                                    .iter()
                                    .any(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::DS(_))))
                                {
                                    ZoneSigning::Signed
                                } else {
                                    // D2: DS RRset answered but holds no DS.
                                    // RFC 4035 §4.2 requires that absence to be
                                    // PROVEN by a signed NSEC/NSEC3 in the
                                    // parent; an empty-but-unsigned answer is
                                    // exactly what a hostile resolver
                                    // fabricates to strip a signed zone. Without
                                    // authenticated denial we cannot conclude
                                    // "unsigned", so this is Unknown and the
                                    // caller fails closed.
                                    //
                                    // This is the correct behaviour even when a
                                    // DS-less answer reaches us via the key
                                    // cache: cached or live, it carries no proof.
                                    ZoneSigning::Unknown
                                }
                            }
                            // D2: without authenticated-denial support,
                            // neither a denial-shaped nor a failed DS probe
                            // proves absence. The zone may well be signed, so
                            // this is Unknown and callers fail closed rather
                            // than serving a stripped signed answer as
                            // Insecure. ProvablyUnsigned is reserved for the
                            // case an authenticated denial will produce.
                            FetchOutcome::DsShapeOnly | FetchOutcome::Failed => {
                                ZoneSigning::Unknown
                            }
                        };
                    }
                    // SOA answer that does not cover `current`: keep walking.
                }
                // SOA fetch failed for THIS label: we have not located the
                // apex yet. Keep walking up — a higher label may still be
                // cached/answerable. Only if the whole walk finds no apex do
                // we conclude Unknown (below).
                FetchOutcome::DsShapeOnly | FetchOutcome::Failed => {}
            }
            if current.is_root() {
                break;
            }
            current = current.base_name();
        }
        // Depth cap or root reached without ever seeing an SOA for this name.
        ZoneSigning::Unknown
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
            FetchOutcome::Found(r) => r,
            // best-effort: inconclusive/failed fetches yield true (no false
            // alarms offline)
            FetchOutcome::DsShapeOnly | FetchOutcome::Failed => return true,
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

        // gather candidate RRsets: positive answers, else authority denial records.
        // The bool marks denial candidates: ONLY they go through the FP-18
        // coverage gate. Positive/chain candidates return Secure on chain
        // success exactly as before.
        let mut candidates: Vec<(Name, Vec<Record>, RecordType, bool)> = Vec::new();
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
                // Fully stripped denial (no NSEC/NSEC3/RRSIG in authority).
                // Only a PROVABLY unsigned owner zone makes this a legitimate
                // unsigned denial; a signed zone means forged denial
                // material. D3: an unknown zone status fails closed rather
                // than silently serving.
                match self.owner_zone_signing(&owner, resolver).await {
                    ZoneSigning::Signed => {
                        debug!(
                            "dnssec: stripped denial in signed zone for {}",
                            owner.to_ascii()
                        );
                        return DnssecState::Bogus;
                    }
                    ZoneSigning::Unknown => {
                        debug!(
                            "dnssec: stripped denial, zone signing status unknown for {}",
                            owner.to_ascii()
                        );
                        return DnssecState::Bogus;
                    }
                }
            }
        }

        // FP-18: coverage-gated denial. Chain-verified but non-covering NSECs
        // are replayed forgeries for THIS query (skip; Bogus if nothing else
        // verifies). Interval-only NSECs and all NSEC3s (no hash impl) cap at
        // Indeterminate — served honestly, never Secure.
        let mut noncovering_signed = false;
        let mut saw_capped = false;
        // D1: count verified positive (non-denial) candidates and the total
        // positive candidates. Secure is returned only when every one of them
        // verified — a CNAME chain's terminal RRset is a candidate too.
        let mut verified_positive = 0usize;
        let mut total_positive = 0usize;
        // A candidate whose RRSIGs are all present-but-unverifiable is
        // cryptographic-failure EVIDENCE, not an instant verdict: round-robin
        // CDN answers mix signature sets, and aborting on the first failing
        // candidate starves later ones (SERVFAIL roulette). Decided below,
        // after every candidate had its chance.
        let mut saw_crypto_failure = false;
        // Unsigned links are EITHER genuine unsigned data OR stripped
        // signatures: the two are wire-indistinguishable, so every
        // unsigned link is checked against DS (at the owner name or its
        // parent). Signed owner zone with no signatures on the wire is
        // stripping → Bogus; a PROVABLY unsigned zone is an Insecure link.
        // (There is no any_signed fast path on purpose: strip-all must not
        // bypass the DS check.) D3: when the zone's signing status could
        // not be established at all (network error, depth cap), we do NOT
        // treat the link as legitimately unsigned — that would serve and
        // cache a stripped signed answer. Fail closed as Bogus.
        for (name, recs, t, is_denial) in &candidates {
            let sigs = Self::rrsig_records(recs, *t);
            if !is_denial {
                total_positive += 1;
            }
            if sigs.is_empty() {
                // Stripping OR legitimate cross-zone unsigned data (CDN
                // CNAME in an unsigned zone pointing at a signed target).
                // The zone's signing status decides:
                //   Signed          → Bogus (stripped signed data)
                //   ProvablyUnsigned→ Insecure link (legitimate, RFC 4035 §4.2)
                //   Unknown         → Bogus (fail closed; D3)
                match self.owner_zone_signing(name, resolver).await {
                    ZoneSigning::Signed => {
                        debug!(
                            "dnssec: unsigned link in signed zone for {}",
                            name.to_ascii()
                        );
                        return DnssecState::Bogus;
                    }
                    ZoneSigning::Unknown => {
                        debug!(
                            "dnssec: zone signing status unknown for {}, failing closed",
                            name.to_ascii()
                        );
                        return DnssecState::Bogus;
                    }
                }
            }
            let mut rrset_secure = false;
            for sig in &sigs {
                let signer = sig.input().signer_name.clone();
                // fetch the signer's DNSKEY set and try it
                let dnskey_recs = match self
                    .fetch_rrset(&signer, RecordType::DNSKEY, resolver)
                    .await
                {
                    FetchOutcome::Found(r) => r,
                    // Inconclusive/failed DNSKEY fetches cannot
                    // authenticate: try the next signature, fail closed at
                    // the end.
                    FetchOutcome::DsShapeOnly | FetchOutcome::Failed => continue,
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
                    // No authenticated unsigned-island verdict is reachable
                    // yet (see ChainVerdict::Fail), so every unverified chain
                    // keeps evaluating and ultimately fails closed.
                    ChainVerdict::Fail => continue,
                }
            }
            if rrset_secure && !is_denial {
                // D1: a CNAME chain is only as trustworthy as its WEAKEST
                // link. Returning Secure on the first verified candidate let
                // a signed CNAME vouch for a terminal RRset that was never
                // checked — the classic DNSSEC bypass where an attacker who
                // controls an unsigned delegation in the chain redirects a
                // signed name to an address of their choosing, and the answer
                // is then cached and served with AD=1.
                //
                // RFC 4035 §5.2 requires the whole chain to validate, so keep
                // counting and decide only after every candidate has had its
                // turn. `cname_chain` emits the terminal RRset last, which is
                // exactly what made the early return exploitable.
                verified_positive += 1;
                continue;
            }
            if rrset_secure {
                // FP-18: a valid signature is not enough for denial — it must
                // actually deny THIS (qname, qtype).
                if *t == RecordType::NSEC {
                    if let Some((next, has_qtype, has_cname)) = nsec_shape(recs, rtype) {
                        match nsec_coverage(name, &next, has_qtype, has_cname, &owner, rtype) {
                            NsecCoverage::CoversNODATA => return DnssecState::Secure,
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
                    // NSEC3 without hash verification: capped at Indeterminate.
                    // NSEC3 hash validity (low): an NSEC3 whose hash
                    // algorithm we cannot evaluate (anything but SHA-1,
                    // RFC 5155) or whose parameters are malformed cannot
                    // earn the unverified caps — treat it as forged
                    // denial material rather than an honest Indeterminate.
                    let nsec3 = recs.iter().find_map(|rec| {
                        if let RData::DNSSEC(DNSSECRData::NSEC3(n)) = &rec.data {
                            Some(n)
                        } else {
                            None
                        }
                    });
                    let params_valid = match nsec3 {
                        Some(n) => n.hash_algorithm()
                            == hickory_proto::dnssec::Nsec3HashAlgorithm::SHA1,
                        // No NSEC3 RDATA carrying the signed group: forged.
                        None => false,
                    };
                    if !params_valid {
                        noncovering_signed = true;
                        continue;
                    }
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
        if verified_positive > 0 {
            // D1: every positive candidate verified, so the whole chain —
            // CNAME links and terminal RRset alike — is authenticated. This
            // is the only path to Secure for an answer.
            if verified_positive == total_positive {
                return DnssecState::Secure;
            }
            // Some positive candidate neither verified nor failed loudly
            // (e.g. it fell into a capped/indeterminate branch). The chain
            // is not fully covered, so it is not Secure.
            debug!(
                "dnssec: partial chain coverage for {} ({} of {} candidates verified)",
                owner.to_ascii(),
                verified_positive,
                total_positive
            );
        }
        if saw_capped {
            // wildcard-unproven interval or NSEC3: honestly unverified.
            return DnssecState::Indeterminate;
        }
        // Nothing authenticated, nothing proven unsigned, nothing
        // conclusively wrong: the answer could not be judged. D3 fail-closed
        // — reported as Indeterminate, which the server serves WITHOUT
        // caching and WITHOUT a Secure claim.
        DnssecState::Indeterminate
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
    /// Owner == qname and bitmap lacks qtype (genuine NODATA denial).
    CoversNODATA,
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
        return NsecCoverage::CoversNODATA;
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
    use hickory_proto::dnssec::rdata::NSEC3;
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
        unsigned_a_response_for("probe.invalid")
    }

    // .invalid (RFC 2606) can never exist in DNS: DS lookups fail
    // deterministically (NXDOMAIN/SERVFAIL → Failed → not-signed) with
    // or without network, so unsigned-island tests stay hermetic even
    // though the resolver is live. Do NOT use example.com/net here —
    // real zones drift (edge-signing, new DS) as proven 2026-09-24.
    fn unsigned_a_response_for(domain: &str) -> (String, u16, Vec<u8>) {
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        let fqdn = format!("{domain}.");
        let name = Name::from_ascii(&fqdn).unwrap();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        let rec = Record::from_rdata(name, 300, RData::A(A::new(93, 184, 216, 34)));
        msg.answers.push(rec);
        (domain.to_string(), 1, msg.to_vec().unwrap())
    }

    #[tokio::test]
    async fn test_unsigned_response_is_insecure_offline() {
        let v = DnssecValidator::new();
        // D3: an offline/unreachable zone can no longer be treated as
        // "provably unsigned" — that was a silent DNSSEC downgrade. With no
        // cached apex and no reachable DS, the signing status is Unknown and
        // the validator fails closed (Bogus), rather than serving + caching
        // the answer as Insecure. Contrast with
        // test_unsigned_delegation_stays_insecure_offline, which seeds the
        // apex so the ProvablyUnsigned verdict is actually provable.
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let (name, qtype, wire) = unsigned_a_response();
        let state = v.validate(&name, qtype, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Bogus);
    }

    // Seeds a zone apex into the validator cache (no network): an SOA
    // owned by the apex (self-identifying, for apex discovery) plus an
    // optional DS (for the signed verdict). .invalid keeps it hermetic.
    //
    // D3: when there is no DS, an EMPTY DS RRset is still seeded so the DS
    // probe resolves from cache as a proven "no DS at this apex"
    // (ProvablyUnsigned, RFC 4035 §4.2) instead of falling through to a live
    // fetch that would fail as Unknown. This keeps the unsigned-zone tests
    // hermetic while still exercising the ProvablyUnsigned verdict rather
    // than the Unknown fail-closed path.
    fn seed_zone_apex(v: &DnssecValidator, apex: &str, with_ds: bool) {
        let zone = Name::from_ascii(apex).unwrap();
        let soa = Record::from_rdata(
            zone.clone(),
            300,
            RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::from_ascii("ns1.invalid.").unwrap(),
                Name::from_ascii("hostmaster.invalid.").unwrap(),
                1,
                3600,
                600,
                86400,
                300,
            )),
        );
        v.cache_store(&zone, RecordType::SOA, vec![soa]);
        if with_ds {
            let ds = Record::from_rdata(
                zone.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DS(hickory_proto::dnssec::rdata::DS::new(
                    1234,
                    Algorithm::ECDSAP256SHA256,
                    hickory_proto::dnssec::DigestType::SHA256,
                    vec![0u8; 32],
                ))),
            );
            v.cache_store(&zone, RecordType::DS, vec![ds]);
        } else {
            // Proven NODATA for DS at this apex: NOERROR + zero DS records is
            // exactly the unsigned-delegation proof RFC 4035 §4.2 requires.
            // Seeding an empty RRset lets the cache answer the DS probe
            // without network, keeping this test hermetic.
            v.cache_store(&zone, RecordType::DS, Vec::new());
        }
    }

    #[tokio::test]
    async fn test_stripped_signed_zone_answer_is_bogus_offline() {
        // Strip-all lock (DNSSEC-STRIP-ALL-UNSIGNED): the same unsigned
        // wire as above, but the owner zone is PROVEN signed via a
        // cache-seeded apex (no network) → must fail closed (Bogus).
        let v = DnssecValidator::new();
        seed_zone_apex(&v, "probe.invalid.", true);
        let resolver = dummy_resolver();
        let (name, qtype, wire) = unsigned_a_response();
        let state = v.validate(&name, qtype, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Bogus);
    }

    #[tokio::test]
    async fn test_stripped_deep_name_in_signed_zone_is_bogus_offline() {
        // DS-WALK-DEPTH-2 lock: 2 labels below the apex
        // (deep.sub.probe.invalid, DS only at probe.invalid). The old
        // fixed 2-step walk never reached the apex; apex discovery must.
        let v = DnssecValidator::new();
        seed_zone_apex(&v, "probe.invalid.", true);
        let resolver = dummy_resolver();
        let (name, qtype, wire) = unsigned_a_response_for("deep.sub.probe.invalid");
        let state = v.validate(&name, qtype, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Bogus);
    }

    #[tokio::test]
    async fn test_unproven_delegation_fails_closed_offline() {
        // D2/D3: an unsigned CHILD zone under a signed parent is a real,
        // common shape (RFC 4035 §4.2) — and albus must not serve it as
        // Insecure until "no DS at the apex" is authenticated by a signed
        // NSEC/NSEC3. Seeding an apex with a DS-less answer is exactly the
        // material a hostile resolver fabricates, so it cannot be trusted as
        // proof and the validator fails closed.
        //
        // When authenticated-denial support lands (see FetchOutcome's docs),
        // this same wire becomes Insecure again through ProvablyUnsigned.
        // Keeping the test on the fail-closed expectation makes that change
        // visible rather than silent.
        let v = DnssecValidator::new();
        seed_zone_apex(&v, "sub.probe.invalid.", false);
        let resolver = dummy_resolver();
        let (name, qtype, wire) = unsigned_a_response_for("host.sub.probe.invalid");
        let state = v.validate(&name, qtype, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Bogus);
    }

    #[tokio::test]
    async fn test_stripped_denial_in_signed_zone_is_bogus_offline() {
        // Empty-denial half of the same lock: NOERROR with an empty
        // authority section in a proven-signed zone → Bogus; without the
        // seeded DS the identical wire stays Insecure (offline fetch
        // fails closed to not-signed).
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        let name = Name::from_ascii("probe.invalid.").unwrap();
        msg.add_query(Query::query(name, RecordType::A));
        let wire = msg.to_vec().unwrap();

        let v = DnssecValidator::new();
        seed_zone_apex(&v, "probe.invalid.", true);
        let resolver = dummy_resolver();
        let state = v.validate("probe.invalid", 1, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Bogus);

        let plain = DnssecValidator::new();
        let state = plain.validate("probe.invalid", 1, &wire, &resolver).await;
        // D3: with no seeded apex the zone-signing status is Unknown, so the
        // identical wire now fails closed as Bogus too. Previously the
        // unreachable-DS path degraded to "not-signed" and served the
        // stripped denial as Insecure — a silent downgrade whenever the
        // network was flaky. Only a PROVEN unsigned zone (seeded apex, empty
        // DS) may yield Insecure.
        assert_eq!(state, DnssecState::Bogus);
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
        signed_root_fixture_anchored(true)
    }

    /// anchor=false builds an island of security: cryptographically valid
    /// signatures under a key the validator does NOT trust (no DS link
    /// possible). Must validate Insecure (served), never Bogus.
    fn signed_root_fixture_anchored(anchor: bool) -> SignedRootFixture {
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
        if anchor {
            validator.anchors.insert(&pubkey);
        }

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
        // owner == qname, bitmap lacks qtype → genuine NODATA denial
        assert_eq!(
            nsec_coverage(
                &n("host.example."),
                &n("other.example."),
                false,
                false,
                &n("host.example."),
                RecordType::A
            ),
            NsecCoverage::CoversNODATA
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
    async fn test_self_signed_root_validates_secure_offline() {
        let fx = signed_root_fixture();
        let resolver = dummy_resolver();
        let state = fx.validator.validate(".", 1, &fx.wire, &resolver).await;
        assert_eq!(state, DnssecState::Secure);
    }

    // D1 regression: a CNAME chain must not be declared Secure on the strength
    // of its signed links alone. The terminal RRset is itself a candidate and
    // must verify too (RFC 4035 §5.2).
    //
    // This is the historical bypass: the CNAME link below carries a genuine
    // signature from the anchored root key, while the terminal A record it
    // redirects to carries none at all. Returning Secure on the first
    // verified candidate handed the answer back with AD=1 set, and the server
    // cached it — so anyone able to steer an unsigned delegation in the chain
    // could hand a victim an address of their choosing, DNSSEC's own
    // guarantee intact on paper.
    //
    // Expected: Bogus. The unsigned terminal is either stripping (fail closed)
    // or an unproven delegation (also fail closed, see D2/D3) — either way it
    // must never be reported Secure.
    #[tokio::test]
    async fn test_signed_cname_with_unsigned_terminal_is_not_secure_offline() {
        use hickory_proto::dnssec::crypto::EcdsaSigningKey;
        use hickory_proto::dnssec::rdata::SigInput;
        use hickory_proto::dnssec::{DnssecSigner, SigningKey, TBS};
        use hickory_proto::rr::SerialNumber;

        let root = Name::from_ascii(".").unwrap();
        let alias = Name::from_ascii("www.example.test.").unwrap();
        let target = Name::from_ascii("evil.attacker.test.").unwrap();

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

        // A genuinely signed CNAME, signer = root (anchored, so it verifies).
        let cname_rec = Record::from_rdata(
            alias.clone(),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(target.clone())),
        );
        let input = SigInput {
            type_covered: RecordType::CNAME,
            algorithm: Algorithm::ECDSAP256SHA256,
            num_labels: 3,
            original_ttl: 300,
            sig_expiration: SerialNumber::new(now + 3600),
            sig_inception: SerialNumber::new(now.saturating_sub(100)),
            key_tag,
            signer_name: root.clone(),
        };
        let tbs = TBS::from_input(&alias, DNSClass::IN, &input, std::iter::once(&cname_rec))
            .expect("tbs builds");
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(signing_key),
            root.clone(),
            Duration::from_secs(3600),
        );
        let sig_rec = Record::from_rdata(
            alias.clone(),
            300,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(
                input,
                signer.sign(&tbs).expect("signing works"),
            ))),
        );

        // The attacker-controlled terminal: NO RRSIG, pointing at an address
        // of the attacker's choosing.
        let evil_a = Record::from_rdata(target.clone(), 300, RData::A(A::new(6, 6, 6, 6)));

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
        msg.answers.push(sig_rec);
        msg.answers.push(evil_a);

        let state = validator
            .validate(
                "www.example.test",
                1,
                &msg.to_vec().unwrap(),
                &dummy_resolver(),
            )
            .await;

        assert_ne!(
            state,
            DnssecState::Secure,
            "a CNAME chain whose terminal RRset is unsigned must never be Secure"
        );
        assert_eq!(
            state,
            DnssecState::Bogus,
            "unsigned terminal in an otherwise-signed chain fails closed"
        );
    }

    // Live-network variant (ignored in hermetic gates): ietf.org is
    // DNSSEC-signed (independently confirmed via AD flag).
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

    #[test]
    fn test_rsasha1_excluded_from_supported_algorithms() {
        // Decision A (2026-09-25, locked): the RSASHA1 family is rejected
        // even though hickory could verify it — SHA-1 collision forgery
        // risk beats legacy-zone compat. Zones using it SERVFAIL (Bogus),
        // proven by test_rsasha1_signed_answer_is_bogus_offline below.
        // (hickory itself refuses to SIGN with RSASHA1, so the behavioral
        // test relabels a real ECDSA signature instead.)
        assert!(!secure_algorithms().has(Algorithm::RSASHA1));
        assert!(!secure_algorithms().has(Algorithm::RSASHA1NSEC3SHA1));
        for alg in [
            Algorithm::RSASHA256,
            Algorithm::RSASHA512,
            Algorithm::ECDSAP256SHA256,
            Algorithm::ECDSAP384SHA384,
            Algorithm::ED25519,
        ] {
            assert!(secure_algorithms().has(alg), "{alg:?} must stay supported");
        }
    }

    #[tokio::test]
    async fn test_rsasha1_signed_answer_is_bogus_offline() {
        // Same fixture as the Secure control, but the RRSIG is relabeled
        // RSASHA1: the algorithm gate must reject before any crypto, so a
        // legacy-signed answer fails closed (Bogus), never served.
        let fx = signed_root_fixture();
        let resolver = dummy_resolver();
        let mut msg = Message::from_vec(&fx.wire).expect("fixture parses");
        let mut relabeled = false;
        for rec in msg.answers.iter_mut() {
            if rec.record_type() == RecordType::RRSIG {
                if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &rec.data {
                    let mut input = rrsig.input().clone();
                    input.algorithm = Algorithm::RSASHA1;
                    let relabeled_rrsig = RRSIG::from_sig(input, rrsig.sig().to_vec());
                    rec.data = RData::DNSSEC(DNSSECRData::RRSIG(relabeled_rrsig));
                    relabeled = true;
                }
            }
        }
        assert!(relabeled, "fixture must carry an RRSIG to relabel");
        let wire = msg.to_vec().unwrap();
        let state = fx.validator.validate(".", 1, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Bogus);
    }

    // NOTE (merge master→develop): the offline root-island fixture test was
    // retired here. Under the FetchOutcome/ChainVerdict architecture a
    // self-signed ROOT with an untrusted key is Fail (→ Bogus), not
    // InsecureIsland: root has no parent to prove DS absence from, so it is
    // indistinguishable from forgery. Genuine islands are non-root zones
    // with proven DS absence — covered by
    // test_unsigned_delegation_island_is_insecure_live below.

    #[tokio::test]
    async fn test_unsigned_cname_chain_is_insecure_offline() {
        use hickory_proto::rr::rdata::CNAME;
        // www -> cdn -> A, no RRSIG anywhere.
        //
        // D3: these names are NOT seeded, so the zone-signing status cannot
        // be established (no cached apex, no reachable DS). "Cannot tell" is
        // no longer treated as "unsigned" — the validator fails closed.
        // A genuinely unsigned zone must be PROVEN unsigned (DS probe returns
        // NOERROR + zero DS at a located apex) to yield Insecure; see
        // test_unsigned_delegation_stays_insecure_offline, which seeds the
        // apex and therefore exercises the ProvablyUnsigned verdict.
        let mut msg = Message::new(0x2222, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        let alias = Name::from_ascii("www.site.invalid.").unwrap();
        let canon = Name::from_ascii("cdn.site.invalid.").unwrap();
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
        let state = v.validate("www.site.invalid", 1, &wire, &resolver).await;
        assert_eq!(state, DnssecState::Bogus);
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

    // Unsigned delegation (neverssl.com 2026-09-24, verified live): a zone
    // with NO DS in the parent serving UNSIGNED answers must validate
    // Insecure (served), never Bogus (SERVFAIL). neverssl.com is
    // purpose-built for stability (plain-HTTP-forever mission, single
    // unsigned A, no DNSSEC ambitions). Live-network — excluded from
    // hermetic gates like the other live tests.
    #[tokio::test]
    #[ignore]
    async fn test_unsigned_delegation_is_insecure_live() {
        let v = DnssecValidator::new();
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let q = doh_query_with_do("neverssl.com", RecordType::A);
        let (resp, _) = resolver
            .resolve(&q)
            .await
            .expect("live DoH query should succeed");
        let state = v.validate("neverssl.com", 1, &resp, &resolver).await;
        assert_eq!(state, DnssecState::Insecure);
    }

    // FP-19 live lock (chatgpt.com 2026-09-24, verified live): the zone
    // publishes DNSKEY + RRSIGs but has NO DS in .com (signed-but-unchained).
    // Such answers are Bogus (SERVFAIL), never silently Insecure. DOMAIN
    // DRIFT NOTE: on 2026-09-23 this same name served unsigned answers and
    // the test above asserted Insecure for it; by 2026-09-24 it serves
    // unanchored RRSIGs, so the expectation moved here. If this test fails
    // with Insecure/Secure, the zone likely gained a DS (fully chained now)
    // — verify with a DS lookup before "fixing" the code.
    #[tokio::test]
    #[ignore]
    async fn test_signed_but_unchained_is_bogus_live() {
        let v = DnssecValidator::new();
        let resolver = DoHResolver::new("quad9", &[], true).expect("resolver init should succeed");
        let q = doh_query_with_do("chatgpt.com", RecordType::A);
        let (resp, _) = resolver
            .resolve(&q)
            .await
            .expect("live DoH query should succeed");
        let state = v.validate("chatgpt.com", 1, &resp, &resolver).await;
        assert_eq!(state, DnssecState::Bogus);
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

    #[test]
    fn test_neg_cache_stores_only_negative_verdicts() {
        let v = DnssecValidator::new();
        // Bogus is remembered (anti-amplification bound, and it is the
        // fail-closed verdict callers must see consistently).
        v.neg_store("Example.COM", 1, DnssecState::Bogus);
        assert_eq!(v.neg_lookup("example.com", 1), Some(DnssecState::Bogus));
        // D5: Indeterminate is NOT remembered. It means "could not judge",
        // and pinning it for NEG_CACHE_TTL would serve one stalled validation
        // as the verdict for every subsequent query of that name. It also
        // keeps the anti-amplification role with Bogus, which is what the
        // server turns into SERVFAIL anyway.
        v.neg_store("other.example.", 28, DnssecState::Indeterminate);
        assert_eq!(v.neg_lookup("other.example.", 28), None);
        // Secure/Insecure are never stored (live in DnsCache instead)
        v.neg_store("example.com", 1, DnssecState::Secure);
        v.neg_store("plain.example.", 1, DnssecState::Insecure);
        assert_eq!(v.neg_lookup("plain.example.", 1), None);
        // qtype is part of the key; unknown names miss
        assert_eq!(v.neg_lookup("example.com", 28), None);
        assert_eq!(v.neg_lookup("absent.example.", 1), None);
    }

    // NOTE (merge master→develop): the offline signed-CNAME-to-unsigned-target
    // test was retired here. Under the ChainVerdict flow a chain-verified
    // CNAME returns Secure before the unsigned terminal is evaluated
    // (cdb9ce6 deferred-Bogus design); the old Insecure expectation belongs
    // to the retired counter architecture. Served-ness for real CDN shapes
    // is locked by test_unsigned_cname_to_signed_target_is_secure_live
    // (asserts never-Bogus).

    /// Builds a self-signed root zone + validator with the key anchored and
    /// the DNSKEY set cache-seeded: fully offline validation harness for
    /// denial tests (root short-circuits the chain walk, no fetches).
    struct DenialFixture {
        validator: DnssecValidator,
        root: Name,
        key_tag: u16,
        signer: hickory_proto::dnssec::DnssecSigner,
        now: u32,
    }

    impl DenialFixture {
        fn new() -> Self {
            use hickory_proto::dnssec::crypto::EcdsaSigningKey;
            use hickory_proto::dnssec::SigningKey;
            let root = Name::from_ascii(".").unwrap();
            let der =
                EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).expect("keygen works");
            let signing_key =
                EcdsaSigningKey::from_key_der(&der.into(), Algorithm::ECDSAP256SHA256)
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
            let dnskey_rec = Record::from_rdata(
                root.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
            );
            validator.cache_store(&root, RecordType::DNSKEY, vec![dnskey_rec]);
            let signer = hickory_proto::dnssec::DnssecSigner::new(
                dnskey.clone(),
                Box::new(signing_key),
                root.clone(),
                Duration::from_secs(3600),
            );
            DenialFixture {
                validator,
                root,
                key_tag,
                signer,
                now,
            }
        }

        fn hash(&self, name: &Name) -> Vec<u8> {
            use hickory_proto::dnssec::Nsec3HashAlgorithm;
            Nsec3HashAlgorithm::SHA1
                .hash(&[], name, 0)
                .expect("hash works")
                .as_ref()
                .to_vec()
        }

        /// Signed NSEC3 group (owner label + next hash + RRSIG), ready for
        /// the authority section.
        fn group(&self, owner_hash: &[u8], next_hash: &[u8]) -> Vec<Record> {
            use hickory_proto::dnssec::rdata::SigInput;
            use hickory_proto::dnssec::TBS;
            use hickory_proto::rr::SerialNumber;
            let owner = Name::from_ascii(&format!("{}.", b32hex_enc(owner_hash))).unwrap();
            let nsec3 = NSEC3::new(
                hickory_proto::dnssec::Nsec3HashAlgorithm::SHA1,
                false,
                0,
                vec![],
                next_hash.to_vec(),
                [RecordType::A],
            );
            let rec =
                Record::from_rdata(owner.clone(), 300, RData::DNSSEC(DNSSECRData::NSEC3(nsec3)));
            let input = SigInput {
                type_covered: RecordType::NSEC3,
                algorithm: Algorithm::ECDSAP256SHA256,
                num_labels: 1,
                original_ttl: 300,
                sig_expiration: SerialNumber::new(self.now + 3600),
                sig_inception: SerialNumber::new(self.now - 100),
                key_tag: self.key_tag,
                signer_name: self.root.clone(),
            };
            let tbs = TBS::from_input(&owner, DNSClass::IN, &input, std::iter::once(&rec))
                .expect("tbs builds");
            let sig_bytes = self.signer.sign(&tbs).expect("signing works");
            let sig_rec = Record::from_rdata(
                owner,
                300,
                RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig_bytes))),
            );
            vec![rec, sig_rec]
        }

        fn nx_message(&self, qname: &str, groups: Vec<Vec<Record>>) -> Vec<u8> {
            let name = Name::from_ascii(qname).unwrap();
            let mut msg = Message::new(0x4242, MessageType::Response, OpCode::Query);
            msg.metadata.response_code = ResponseCode::NXDomain;
            msg.add_query(Query::query(name, RecordType::A));
            for g in groups {
                for rec in g {
                    msg.authorities.push(rec);
                }
            }
            msg.to_vec().unwrap()
        }
    }

    #[tokio::test]
    async fn test_nxdomain_denial_forged_group_is_bogus_offline() {
        // Forgery direction stays fail-closed: a tampered NSEC3 group kills
        // the whole denial even next to a fully valid covering group.
        let fx = DenialFixture::new();
        let qname = Name::from_ascii("missing.example.").unwrap();
        let h = fx.hash(&qname);
        // covering group: (h-1, h]
        let mut below = h.clone();
        below[19] = below[19].wrapping_sub(1);
        let cover = fx.group(&below, &h);
        // encloser group: owner == hash(example.)
        let enc = fx.hash(&Name::from_ascii("example.").unwrap());
        let encloser = fx.group(&enc, &enc);
        // forged group: valid shape, but the next-hash is flipped so the
        // signature over the RRset no longer verifies (same effect as a
        // corrupted RRSIG, without depending on signature codecs)
        let mut forged_group = fx.group(&h, &h);
        for rec in forged_group.iter_mut() {
            if let RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) = &mut rec.data {
                let mut next = nsec3.next_hashed_owner_name().to_vec();
                next[0] ^= 0x01;
                *nsec3 = NSEC3::new(
                    nsec3.hash_algorithm(),
                    nsec3.opt_out(),
                    nsec3.iterations(),
                    nsec3.salt().to_vec(),
                    next,
                    nsec3.type_bit_maps(),
                );
            }
        }
        let wire = fx.nx_message("missing.example.", vec![cover, encloser, forged_group]);
        let resolver = dummy_resolver();
        let state = fx
            .validator
            .validate("missing.example", 1, &wire, &resolver)
            .await;
        assert_eq!(state, DnssecState::Bogus);
    }
}
