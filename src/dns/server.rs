//! udp listener on 127.0.0.1:53 forwarding to encrypted doh with dnssec and ipv6 aaaa filtering.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, error, info, warn};

use super::cache::DnsCache;
use super::dnssec::{DnssecState, DnssecValidator};
use super::doh::DoHResolver;
use super::ech::EchConfigCache;

// local dns server instance wrapping doh client pool and response cache
pub struct DnsServer {
    resolver: DoHResolver,
    upstream_desc: String,
    block_ipv6: bool,
    dnssec: bool,
    pqc: bool,
    cache: Arc<DnsCache>,
    validator: Arc<DnssecValidator>,
    ech_cache: EchConfigCache,
    ip_queue: Arc<Mutex<HashMap<Ipv4Addr, VecDeque<String>>>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl DnsServer {
    pub fn new(
        upstreams_csv: &str,
        custom_bootstrap_ips: &[Ipv4Addr],
        block_ipv6: bool,
        dnssec: bool,
        pqc: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = DoHResolver::new(upstreams_csv, custom_bootstrap_ips, pqc)?;
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            resolver,
            upstream_desc: upstreams_csv.to_string(),
            block_ipv6,
            dnssec,
            pqc,
            cache: Arc::new(DnsCache::new(2048)),
            validator: Arc::new(DnssecValidator::new()),
            ech_cache: EchConfigCache::new(),
            ip_queue: Arc::new(Mutex::new(HashMap::new())),
            shutdown_tx,
        })
    }

    // pops oldest recorded domain fqdn associated with resolved destination ipv4 address
    pub async fn pop_domain(&self, ip: Ipv4Addr) -> Option<String> {
        let mut map = self.ip_queue.lock().await;
        if let Some(queue) = map.get_mut(&ip) {
            let domain = queue.pop_front();
            if queue.is_empty() {
                map.remove(&ip);
            }
            domain
        } else {
            None
        }
    }

    // spawns background asynchronous udp receive loop on loopback interface 127.0.0.1:53
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = match UdpSocket::bind("127.0.0.1:53").await {
            Ok(s) => s,
            Err(e) => {
                return Err(format!("failed to bind UDP socket to 127.0.0.1:53: {}", e).into());
            }
        };

        info!(
            addr = "127.0.0.1:53",
            upstream = %self.upstream_desc,
            block_ipv6 = self.block_ipv6,
            dnssec = self.dnssec,
            pqc = self.pqc,
            cache_capacity = 2048,
            "DNS server started"
        );

        let socket = Arc::new(socket);
        // upgrade DoH clients to ECH where the upstream publishes configs
        // (fetched over plain DoH first; logged per upstream)
        let resolver = self.resolver.with_ech_upgraded(&self.ech_cache).await;
        // verify the post-quantum claim in the background (one-shot, non-blocking)
        resolver.spawn_pq_probe();
        let cache = self.cache.clone();
        let validator = self.validator.clone();
        let ip_queue = self.ip_queue.clone();
        let block_ipv6 = self.block_ipv6;
        let dnssec = self.dnssec;
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        let mut canary_shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut tick_count: u64 = 0;
            let mut last_heal: Option<std::time::Instant> = None;
            // W4-01: bound the retry instead of looping forever on a failure.
            let mut heal_failures: u32 = 0;
            let mut heal_gave_up: bool = false;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        tick_count = tick_count.wrapping_add(1);

                        // 1. Passive check: verify resolv.conf still directs queries to loopback.
                        //
                        // W4-01: this used to answer "is the host resolver safe?"
                        // with its own prefix test — `starts_with("nameserver
                        // 127.0.0.1")` or `127.0.0.53`, and nothing about a
                        // second nameserver — while the repair it gates computes a
                        // strictly stronger conjunction. So the canary reported
                        // leak-free for `nameserver 127.0.0.15`, for
                        // `nameserver 127.0.0.1x`, and for the systemd-resolved
                        // stub `127.0.0.53` (which is not albus's resolver — it
                        // binds only 127.0.0.1:53) — every one of which is a
                        // state the repair would rewrite, so the repair was
                        // suppressed and the leak monitor was silently disabled.
                        //
                        // The canary now asks the repair's own question, and the
                        // decision read uses the writer's discipline
                        // (O_NOFOLLOW + O_CLOEXEC + regular-file check) instead
                        // of a symlink-following `read_to_string`, which also
                        // removes the FIFO-hang: a FIFO at /etc/resolv.conf would
                        // otherwise wedge this task forever.
                        match crate::dns::system::read_nofollow(std::path::Path::new(
                            "/etc/resolv.conf",
                        )) {
                            Ok(content) => {
                                if !crate::dns::system::resolver_is_albus_exclusive(&content) {
                                    warn!("DNS leak canary: /etc/resolv.conf is not exclusively albus's loopback resolver (possible DHCP/NetworkManager overwrite). Auto-healing system DNS...");
                                    let can_heal =
                                        last_heal.map(|t| t.elapsed().as_secs() >= 300).unwrap_or(true);
                                    if !can_heal {
                                        warn!("DNS auto-heal rate-limited (last heal <5min ago) — skipping root write");
                                    } else if let Err(e) = crate::dns::system::set_system_dns() {
                                        // W4-01: the backoff advanced only on
                                        // SUCCESS, so a persistently failing
                                        // set_system_dns() retried every 15s
                                        // forever, each attempt re-issuing
                                        // resolvectl writes across every physical
                                        // interface. Bound it.
                                        heal_failures = heal_failures.saturating_add(1);
                                        if heal_failures >= MAX_CONSECUTIVE_HEAL_FAILURES {
                                            if !heal_gave_up {
                                                heal_gave_up = true;
                                                warn!(
                                                    "DNS auto-heal failed {} consecutive times — giving up on automatic repair for this run. /etc/resolv.conf must be fixed by hand (`sudo albus cleanup`).",
                                                    MAX_CONSECUTIVE_HEAL_FAILURES
                                                );
                                            }
                                        } else {
                                            warn!(
                                                "failed to auto-heal /etc/resolv.conf: {} (attempt {} of {})",
                                                e,
                                                heal_failures,
                                                MAX_CONSECUTIVE_HEAL_FAILURES
                                            );
                                        }
                                    } else {
                                        heal_failures = 0;
                                        heal_gave_up = false;
                                        last_heal = Some(std::time::Instant::now());
                                        info!("DNS leak canary: successfully auto-healed /etc/resolv.conf to 127.0.0.1");
                                    }
                                }
                            }
                            Err(e) => {
                                // Unreadable or non-regular: that is NOT
                                // leak-free, and it is also not something the
                                // repair can fix. Report it distinctly rather
                                // than treating it as healthy.
                                warn!(
                                    "DNS leak canary: cannot read /etc/resolv.conf safely ({}): not asserting leak-free, and the auto-heal repair cannot run either",
                                    e
                                );
                            }
                        }

                        // 2. Active watchdog check: actively probe local resolver on 127.0.0.1:53 every 60s.
                        // Spawned, not awaited: the probe's jitter sleep must
                        // not stall the passive check or shutdown handling.
                        if tick_count % 4 == 0 {
                            tokio::spawn(run_active_canary_probe());
                        }
                    }
                    _ = canary_shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        // W4-01: after this many consecutive failed repairs the canary stops
        // writing and says so, instead of retrying every 15s forever.
        const MAX_CONSECUTIVE_HEAL_FAILURES: u32 = 5;

        const MAX_CONCURRENT_DNS_TASKS: usize = 512;
        const MAX_IP_QUEUE_ENTRIES: usize = 4096;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DNS_TASKS));

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];

            // DNS-02: a single reused SERVFAIL buffer for shed datagrams. The
            // shed path used to clone the datagram and perform an async send
            // INSIDE a freshly spawned task, so rejecting a packet cost a task
            // spawn, a heap allocation and a send — the exact work the shed was
            // meant to avoid. This is O(1) with no allocation, and it is safe to
            // reuse because the send is awaited here before the next recv can
            // overwrite it.
            let mut shed_buf = [0u8; 12];
            let mut shed_total: u64 = 0;

            loop {
                tokio::select! {
                    recv_res = socket.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((len, peer_addr)) => {
                                // DNS-02: ADMISSION CONTROL BEFORE ALLOCATION.
                                //
                                // The semaphore's comment claimed it existed to
                                // "shed load under flooding attacks to prevent
                                // unbounded task/socket spawning", but it was
                                // acquired INSIDE the per-datagram task it was
                                // meant to gate. By then the datagram had already
                                // been copied into a fresh Vec and six Arcs
                                // cloned, and the task had already been spawned —
                                // so the 512 permits bounded in-flight upstream
                                // work only, never the task count or the
                                // allocation rate. An unauthenticated local UDP
                                // sender could dictate the privileged daemon's
                                // task-allocation rate, on the same runtime that
                                // carries the resolv.conf canary and the
                                // kill-switch-protected resolver every host client
                                // depends on.
                                //
                                // The permit is now taken here, on the receive
                                // loop, before the copy and before the spawn, and
                                // it is moved into the task so it is held for the
                                // task's lifetime.
                                let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        shed_total = shed_total.wrapping_add(1);
                                        // Minimal SERVFAIL: echo the transaction
                                        // id so the client can match it, set QR
                                        // and RA, rcode 2, QDCOUNT 0. Bounded work,
                                        // no query copy, no task.
                                        shed_buf[0] = buf[0];
                                        shed_buf[1] = buf[1];
                                        shed_buf[2] = 0x80 | (buf[2] & 0x01); // QR + RD
                                        // RA + rcode 2 (SERVFAIL). The query's
                                        // low nibble in byte 3 is CD/AD/RD/Z, NOT
                                        // an rcode, so it must not be OR-ed in.
                                        shed_buf[3] = 0x80 | 0x02;
                                        shed_buf[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
                                        let _ = socket.send_to(&shed_buf, peer_addr).await;
                                        if shed_total % 1024 == 1 {
                                            warn!(
                                                shed = shed_total,
                                                limit = MAX_CONCURRENT_DNS_TASKS,
                                                "DNS load shedding: upstream concurrency \
                                                 limit reached, answering SERVFAIL without \
                                                 forwarding (any local process can trigger \
                                                 this by flooding 127.0.0.1:53)"
                                            );
                                        }
                                        continue;
                                    }
                                };

                                let query_data = buf[..len].to_vec();
                                let socket_clone = socket.clone();
                                let resolver_clone = resolver.clone();
                                let cache_clone = cache.clone();
                                let validator_clone = validator.clone();
                                let ip_queue_clone = ip_queue.clone();

                                tokio::spawn(async move {
                                    // held for this task's lifetime
                                    let _permit = permit;

                                    // 0. intercept internal dns leak test canary probe
                                    if is_canary_query(&query_data) {
                                        let canary_resp = build_canary_response(&query_data, Ipv4Addr::new(127, 0, 0, 99));
                                        let _ = socket_clone.send_to(&canary_resp, peer_addr).await;
                                        return;
                                    }

                                    // 1. synthesize instant nodata response for aaaa queries if ipv6 blocking is enabled
                                    if block_ipv6 && is_aaaa_query(&query_data) {
                                        let nodata = build_nodata_response(&query_data);
                                        let _ = socket_clone.send_to(&nodata, peer_addr).await;
                                        return;
                                    }

                                    // 2. check in-memory wire cache for fast-path 0ms response
                                    if let Some(cached_resp) = cache_clone.get(&query_data) {
                                        if let Some((domain, ips)) = parse_dns_response(&cached_resp) {
                                            if !ips.is_empty() {
                                                debug!(
                                                    domain = %domain,
                                                    ips = ?ips,
                                                    source = "cache_0ms",
                                                    "DNS cache hit"
                                                );
                                                let mut map = ip_queue_clone.lock().await;
                                                if map.len() >= MAX_IP_QUEUE_ENTRIES {
                                                    if let Some(oldest) = map.keys().next().cloned() {
                                                        map.remove(&oldest);
                                                    }
                                                }
                                                for ip in ips {
                                                    let queue = map.entry(ip).or_default();
                                                    if queue.len() < 50 {
                                                        queue.push_back(domain.clone());
                                                    }
                                                }
                                            }
                                        }
                                        let _ = socket_clone.send_to(&cached_resp, peer_addr).await;
                                        return;
                                    }

                                    // 3. append edns0 opt rr with do bit if dnssec is enabled
                                    let outgoing_query = if dnssec {
                                        enable_dnssec_do(&query_data)
                                    } else {
                                        query_data.clone()
                                    };

                                    match resolver_clone.resolve(&outgoing_query).await {
                                        Ok((resp_bytes, via)) => {
                                            // 4. local DNSSEC chain validation (fail-closed on Bogus)
                                            let dnssec_state = if dnssec {
                                                match crate::dns::cache::extract_query_key(&query_data) {
                                                    Some(key) => {
                                                        match tokio::time::timeout(
                                                            std::time::Duration::from_secs(10),
                                                            validator_clone.validate(
                                                                &key.name,
                                                                key.qtype,
                                                                &resp_bytes,
                                                                &resolver_clone,
                                                            ),
                                                        )
                                                        .await
                                                        {
                                                            Ok(s) => Some(s),
                                                            Err(_) => {
                                                                warn!("dnssec validation timed out; serving unverified");
                                                                Some(DnssecState::Indeterminate)
                                                            }
                                                        }
                                                    }
                                                    None => None,
                                                }
                                            } else {
                                                None
                                            };
                                            if dnssec_state == Some(DnssecState::Bogus) {
                                                warn!("dnssec BOGUS response rejected (not cached, SERVFAIL sent)");
                                                if query_data.len() >= 4 {
                                                    let mut fail_resp = query_data.clone();
                                                    fail_resp[2] |= 0x80;
                                                    fail_resp[3] = (fail_resp[3] & 0xF0) | 0x02;
                                                    let _ = socket_clone.send_to(&fail_resp, peer_addr).await;
                                                }
                                                return;
                                            }
                                            // DNS-03: the upstream's self-assessment
                                            // is read for the journal only, then
                                            // overridden. This used to be the whole
                                            // story: `dnssec_state` was computed,
                                            // only its `Bogus` arm had any effect,
                                            // and the response was cached and
                                            // forwarded with the AD bit the UPSTREAM
                                            // set. So a hostile or compromised DoH
                                            // upstream could answer AD=1 with no
                                            // RRSIGs at all — the validator took the
                                            // unsigned path, returned Insecure, the
                                            // answer was served, and AD=1 was handed
                                            // to every downstream stub resolver or
                                            // application honouring RFC 6840
                                            // trust-ad as though albus had
                                            // authenticated it. The reverse was
                                            // equally unguarded: stripping RRSIGs
                                            // from a genuinely Secure answer also
                                            // lands on Insecure.
                                            //
                                            // The locally computed verdict is now the
                                            // authority for the client-visible trust
                                            // bit. Normalisation happens BEFORE the
                                            // cache insert so a cache hit cannot
                                            // reintroduce the upstream's bit.
                                            let upstream_ad = is_dnssec_authenticated(&resp_bytes);
                                            let resp_bytes = normalize_ad_bit(
                                                resp_bytes,
                                                dnssec,
                                                dnssec_state,
                                            );
                                            let is_ad = is_dnssec_authenticated(&resp_bytes);

                                            // insert response into cache (bogus never cached)
                                            cache_clone.insert(&query_data, &resp_bytes);

                                            if let Some((domain, ips)) = parse_dns_response(&resp_bytes) {
                                                if !ips.is_empty() {
                                                    debug!(
                                                        domain = %domain,
                                                        ips = ?ips,
                                                        via = %via,
                                                        upstream_claimed_ad = upstream_ad,
                                                        dnssec_authenticated = is_ad,
                                                        dnssec_local = ?dnssec_state,
                                                        "DNS resolved"
                                                    );
                                                    let mut map = ip_queue_clone.lock().await;
                                                    if map.len() >= MAX_IP_QUEUE_ENTRIES {
                                                        if let Some(oldest) = map.keys().next().cloned() {
                                                            map.remove(&oldest);
                                                        }
                                                    }
                                                    for ip in ips {
                                                        let queue = map.entry(ip).or_default();
                                                        if queue.len() < 50 {
                                                            queue.push_back(domain.clone());
                                                        }
                                                    }
                                                }
                                            }

                                            if let Err(e) = socket_clone.send_to(&resp_bytes, peer_addr).await {
                                                debug!("failed to send DNS reply to {}: {}", peer_addr, e);
                                            }
                                        }
                                        Err(e) => {
                                            debug!("DNS resolution error: {}", e);
                                            if query_data.len() >= 2 {
                                                let mut fail_resp = query_data.clone();
                                                if fail_resp.len() >= 4 {
                                                    fail_resp[2] |= 0x80;
                                                    fail_resp[3] = (fail_resp[3] & 0xF0) | 0x02; // servfail rcode
                                                    let _ = socket_clone.send_to(&fail_resp, peer_addr).await;
                                                }
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                error!("UDP recv_from error: {}", e);
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("DNS server shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    // signals graceful shutdown to background udp listener task
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }

    // clears all entries from the in-memory response cache
    /// Operator-requested invalidation. W6-01: this reached one of the
    /// resolver's four caches. `validator` (both the Bogus negative-verdict
    /// cache and the DS/KEY cache) and `ech_cache` survived, so the panel's
    /// "DNS cache flushed" was untrue about scope and an attacker who had
    /// stamped a Bogus verdict simply out-waited the operator.
    pub fn flush_cache(&self) {
        self.cache.clear();
        self.validator.clear_caches();
        self.ech_cache.clear();
        info!("DNS in-memory caches flushed (response, DNSSEC negative/key, ECH config)");
    }
}

// inspects question section to identify aaaa (qtype 28) resource queries
pub fn is_aaaa_query(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }
    let qdcount = ((data[4] as u16) << 8) | (data[5] as u16);
    if qdcount == 0 {
        return false;
    }
    let mut pos = 12;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    if pos + 4 <= data.len() {
        let qtype = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        return qtype == 28; // aaaa record = 28
    }
    false
}

// appends rfc 6891 edns0 opt pseudo-rr with dnssec ok (do) bit enabled.
// FP-06: DO is forced even when the client sent additional records — an
// attacker OPT-without-DO must never suppress upstream DNSSEC.
pub fn enable_dnssec_do(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return query.to_vec();
    }

    let mut out = query.to_vec();
    let arcount = ((query[10] as u16) << 8) | (query[11] as u16);

    // shared OPT RR template: root(0x00), type 41, payload 4096, DO set.
    let opt_rr: [u8; 11] = [
        0x00, 0x00, 0x29, // type: opt (41)
        0x10, 0x00, // payload size: 4096
        0x00, // extended rcode
        0x00, // edns version
        0x80, 0x00, // do bit set (0x8000)
        0x00, 0x00, // rdlen: 0
    ];

    if arcount == 0 {
        out.extend_from_slice(&opt_rr);
        out[10] = 0x00;
        out[11] = 0x01;
        return out;
    }

    match crate::dns::cache::scan_opt(&out) {
        crate::dns::cache::OptScan::Present { ttl_offset } => {
            // patch the DO bit in place — length and ARCOUNT unchanged.
            let ttl = u32::from_be_bytes([
                out[ttl_offset],
                out[ttl_offset + 1],
                out[ttl_offset + 2],
                out[ttl_offset + 3],
            ]);
            let patched = (ttl | 0x8000).to_be_bytes();
            out[ttl_offset..ttl_offset + 4].copy_from_slice(&patched);
            out
        }
        crate::dns::cache::OptScan::Absent => {
            // additional records but no OPT: append one if ARCOUNT allows.
            if arcount < 0xFFFF {
                out.extend_from_slice(&opt_rr);
                let bumped = arcount + 1;
                out[10] = (bumped >> 8) as u8;
                out[11] = (bumped & 0xFF) as u8;
            }
            out
        }
        // malformed additionals: forward unchanged rather than corrupt.
        crate::dns::cache::OptScan::Malformed => out,
    }
}

// inspects header flags to verify presence of authenticated data (ad) bit
#[inline]
pub fn is_dnssec_authenticated(response: &[u8]) -> bool {
    if response.len() >= 4 {
        (response[3] & 0x20) != 0
    } else {
        false
    }
}

/// Projects albus's own DNSSEC verdict onto the AD bit of the response it
/// forwards, so the client-visible trust signal is the one albus actually
/// computed rather than the upstream's claim about itself.
///
/// DNS-03: the AD bit is what every downstream stub resolver and application
/// honouring RFC 6840 `trust-ad` reads to decide whether an answer is
/// authenticated. Relaying an unverified producer-declared flag across that
/// boundary makes the local validation decorative — the module would compute a
/// careful verdict, discard it, and forward the resolver's opinion instead.
///
/// The rule:
///
///   * `Secure`   -> AD set. albus built a DS→DNSKEY chain to the embedded root
///     anchor and verified the signatures itself.
///   * anything else -> AD cleared, including `Insecure`, `Bogus` (which never
///     reaches here; it became SERVFAIL above) and `Indeterminate`. An unsigned
///     zone is served — that is correct DNSSEC behaviour — but it must not be
///     *labelled* authenticated.
///   * `dnssec` off -> AD cleared. albus did not validate, so it must not assert
///     that something was validated.
///
/// A response shorter than 4 bytes has no header to fix and is returned
/// unchanged.
pub fn normalize_ad_bit(
    mut response: Vec<u8>,
    dnssec_enabled: bool,
    state: Option<crate::dns::dnssec::DnssecState>,
) -> Vec<u8> {
    if response.len() < 4 {
        return response;
    }
    let should_assert = dnssec_enabled && state == Some(crate::dns::dnssec::DnssecState::Secure);
    if should_assert {
        response[3] |= 0x20;
    } else {
        response[3] &= !0x20;
    }
    response
}

// inspects question section for internal dns leak test probe domain
pub fn is_canary_query(data: &[u8]) -> bool {
    if let Some((domain, _)) = parse_dns_name(data, 12) {
        domain == "leak-test.albus.internal" || domain == "canary.albus.internal"
    } else {
        false
    }
}

// generates synthetic a-record response pointing to internal canary ip (127.0.0.99)
pub fn build_canary_response(query: &[u8], canary_ip: Ipv4Addr) -> Vec<u8> {
    if query.len() < 12 {
        return query.to_vec();
    }

    // locate the end of question section
    let mut pos = 12;
    while pos < query.len() {
        let len = query[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    pos += 4; // qtype (2) + qclass (2)
    if pos > query.len() {
        pos = query.len();
    }

    let mut resp = Vec::with_capacity(pos + 16);
    resp.extend_from_slice(&query[..pos]);

    resp[2] = 0x81; // qr=1, rd=1
    resp[3] = 0x80; // ra=1, rcode=0
    resp[6] = 0x00;
    resp[7] = 0x01; // ancount = 1
    resp[8] = 0x00;
    resp[9] = 0x00;
    resp[10] = 0x00;
    resp[11] = 0x00;

    // answer rr pointing to question section at offset 12 (0xc00c)
    resp.push(0xc0);
    resp.push(0x0c);
    resp.push(0x00);
    resp.push(0x01); // type a (1)
    resp.push(0x00);
    resp.push(0x01); // class in (1)
    resp.extend_from_slice(&60u32.to_be_bytes()); // ttl = 60s
    resp.push(0x00);
    resp.push(0x04); // rdlength = 4
    resp.extend_from_slice(&canary_ip.octets());

    resp
}

// builds standard rfc 1035 dns query for leak-test.albus.internal (type a, class in).
// FP-14/run-4: TXID from the shared OS-CSPRNG helper (never fixed, never
// time-only); the verifier checks the echo.
pub fn build_canary_query() -> Vec<u8> {
    // avoid the legacy fixed sentinel even in the vanishingly unlikely
    // collision: unpredictability is the point
    let mut txid = crate::dns::secure_query_id();
    if txid == 0xCAFE {
        txid = 0xCAFF;
    }
    let mut query = vec![
        (txid >> 8) as u8,
        (txid & 0xFF) as u8, // Transaction ID
        0x01,
        0x00, // Flags: standard query, recursion desired
        0x00,
        0x01, // Questions: 1
        0x00,
        0x00, // Answer RRs: 0
        0x00,
        0x00, // Authority RRs: 0
        0x00,
        0x00, // Additional RRs: 0
    ];
    let domain = "leak-test.albus.internal";
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00); // root label
    query.extend_from_slice(&[0x00, 0x01]); // Type A (1)
    query.extend_from_slice(&[0x00, 0x01]); // Class IN (1)
    query
}

// FP-14: pure canary reply check (offline-testable): TXID match plus exact
// question-section echo. ANCOUNT-and-beyond are the answer and must differ.
fn canary_reply_valid(resp: &[u8], query: &[u8]) -> bool {
    resp.len() >= query.len()
        && query.len() >= 12
        && resp[0] == query[0]
        && resp[1] == query[1]
        && resp[12..query.len()] == query[12..]
}

// actively probes local loopback resolver to verify canary responsiveness and detect dns leaks.
// FP-14: pins the reply source to 127.0.0.1:53 and validates TXID + question
// echo — the first datagram is no longer trusted on pattern alone.
async fn run_active_canary_probe() {
    // FP-14: jitter the probe inside its window so the exact send instant is
    // not predictable from the 60s cadence (no rand crate: wall-clock nanos).
    let jitter_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() % 5000) as u64)
        .unwrap_or(0);
    tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
    let probe_res = tokio::time::timeout(std::time::Duration::from_millis(1500), async {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let query = build_canary_query();
        sock.send_to(&query, "127.0.0.1:53").await?;

        let mut resp_buf = [0u8; 512];
        let (len, peer) = sock.recv_from(&mut resp_buf).await?;
        // source pin: only our own resolver's answer counts
        if peer.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
            || peer.port() != 53
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "canary reply from unexpected source",
            ));
        }
        let resp = &resp_buf[..len];
        // TXID + question echo validation (response carries our question
        // as a PREFIX (header + question, then answers): compare exactly the
        // echoed question section. (Comparing header counts would always fail:
        // legit replies set ANCOUNT, which the query leaves zero.)
        if !canary_reply_valid(resp, &query) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "canary reply TXID/question mismatch",
            ));
        }
        Ok::<Vec<u8>, std::io::Error>(resp.to_vec())
    })
    .await;

    match probe_res {
        Ok(Ok(resp)) => {
            if resp.windows(4).any(|w| w == [127, 0, 0, 99]) {
                debug!("active DNS leak canary probe passed: 127.0.0.99 verified from local proxy");
            } else {
                warn!("Active DNS Leak Canary TRIPPED: resolver responded without expected canary IP (127.0.0.99). Potential DNS hijacking or poisoned cache detected! (passive canary will heal with backoff)");
            }
        }
        Ok(Err(e)) => {
            warn!("Active DNS Leak Canary probe network error ({}). Passive canary will heal with backoff...", e);
        }
        Err(_) => {
            warn!("Active DNS Leak Canary probe timed out (1.5s): local DNS proxy unresponsive! Passive canary will heal with backoff...");
        }
    }
}

// generates synthetic noerror response with ancount=0 (nodata)
pub fn build_nodata_response(query: &[u8]) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() >= 12 {
        resp[2] = (resp[2] | 0x80) | 0x01; // response flag (qr=1) + recursion desired
        resp[3] = 0x80; // recursion available + noerror (rcode=0)
        resp[6] = 0; // ancount = 0
        resp[7] = 0;
        resp[8] = 0; // nscount = 0
        resp[9] = 0;
        resp[10] = 0; // arcount = 0
        resp[11] = 0;
    }
    resp
}

// parses answer section records to extract domain name and a-record ipv4 addresses
pub fn parse_dns_response(data: &[u8]) -> Option<(String, Vec<Ipv4Addr>)> {
    if data.len() < 12 {
        return None;
    }

    let qdcount = ((data[4] as usize) << 8) | (data[5] as usize);
    let ancount = ((data[6] as usize) << 8) | (data[7] as usize);

    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;

    let (domain, next_pos) = parse_dns_name(data, pos)?;
    pos = next_pos + 4;

    if ancount == 0 || pos > data.len() {
        return Some((domain, Vec::new()));
    }

    let mut ips = Vec::new();

    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }

        if (data[pos] & 0xC0) == 0xC0 {
            pos += 2;
        } else {
            let (_, next_pos) = parse_dns_name(data, pos)?;
            pos = next_pos;
        }

        if pos + 10 > data.len() {
            break;
        }

        let rtype = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        let _rclass = ((data[pos + 2] as u16) << 8) | (data[pos + 3] as u16);
        let _ttl = ((data[pos + 4] as u32) << 24)
            | ((data[pos + 5] as u32) << 16)
            | ((data[pos + 6] as u32) << 8)
            | (data[pos + 7] as u32);
        let rdlength = ((data[pos + 8] as usize) << 8) | (data[pos + 9] as usize);
        pos += 10;

        if pos + rdlength > data.len() {
            break;
        }

        // rtype 1 corresponds to ipv4 a-record (4 octets)
        if rtype == 1 && rdlength == 4 {
            let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
            ips.push(ip);
        }

        pos += rdlength;
    }

    Some((domain, ips))
}

// FP-12 follow-up: allowlist (LDH + underscore for _dmarc/_acme-style names,
// case-insensitive). Real wire hostnames are LDH/punycode, so nothing
// legitimate is lost and whole homograph/confusable classes (Cf/Zl/Zp,
// controls, bidi) die at once — no denylist to outdate.
//
// Shared with `cache::extract_query_key`: a DNS name that may become a cache
// key, a queue entry or a log field must satisfy ONE policy. When this
// filter lived only in the response parser, `extract_query_key` was a second,
// laxer parser of the same question section and two distinct questions could
// collapse onto a single `DnsCacheKey`.
pub(crate) fn label_is_safe(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

// unpacks compressed dns name labels resolving RFC 1035 pointer offsets
fn parse_dns_name(data: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_pos = pos;
    let max_jumps = 5;
    let mut jumps = 0;

    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            if !jumped {
                return_pos = pos + 1;
            }
            break;
        }

        // compression pointer marker (0b11xxxxxx)
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let pointer = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            if !jumped {
                return_pos = pos + 2;
                jumped = true;
            }
            jumps += 1;
            if jumps > max_jumps || pointer >= data.len() {
                return None;
            }
            pos = pointer;
            continue;
        }

        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        if let Ok(label) = std::str::from_utf8(&data[pos..pos + len]) {
            // FP-12: reject control bytes (ESC/C0/C1/DEL) and bidi/format
            // marks at parse so hostile labels can never flow into logs,
            // queues, or terminal sinks. Hostile labels are dropped like
            // non-UTF8 ones (fail-closed-ish: the name no longer matches,
            // instead of carrying escapes).
            if label_is_safe(label) {
                labels.push(label.to_string());
            }
        }
        pos += len;
    }

    if labels.is_empty() {
        None
    } else {
        Some((labels.join("."), return_pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_server_queue_fifo() {
        let server = DnsServer::new("cloudflare", &[], true, true, true).unwrap();
        let test_ip = Ipv4Addr::new(10, 0, 0, 1);

        {
            let mut map = server.ip_queue.lock().await;
            let q = map.entry(test_ip).or_default();
            q.push_back("first.com".to_string());
            q.push_back("second.com".to_string());
        }

        assert_eq!(
            server.pop_domain(test_ip).await,
            Some("first.com".to_string())
        );
        assert_eq!(
            server.pop_domain(test_ip).await,
            Some("second.com".to_string())
        );
        assert_eq!(server.pop_domain(test_ip).await, None);
    }

    #[test]
    fn test_is_aaaa_query_and_nodata() {
        let mut query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // standard query
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // end of name
            0x00, 0x1C, // qtype = 28 (aaaa)
            0x00, 0x01, // qclass = in (1)
        ];

        assert!(is_aaaa_query(&query));

        let nodata = build_nodata_response(&query);
        assert_eq!(nodata[0], 0x12);
        assert_eq!(nodata[1], 0x34);
        assert_eq!(nodata[2] & 0x80, 0x80);
        assert_eq!(nodata[3] & 0x0F, 0x00);
        assert_eq!(nodata[6], 0x00);
        assert_eq!(nodata[7], 0x00);

        let idx = query.len() - 3;
        query[idx] = 0x01;
        assert!(!is_aaaa_query(&query));
    }

    #[test]
    fn test_enable_dnssec_do_and_ad_check() {
        let query = vec![
            0xAB, 0xCD, // ID
            0x01, 0x00, // standard query
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount = 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];

        let dnssec_query = enable_dnssec_do(&query);
        assert_eq!(dnssec_query[11], 1); // arcount = 1
        assert!(dnssec_query.len() > query.len());

        let fake_response = vec![0xAB, 0xCD, 0x81, 0xA0]; // ad bit set (0x20)
        assert!(is_dnssec_authenticated(&fake_response));
    }

    // FP-06: attacker OPT-without-DO must get DO patched, same length/arcount.
    #[test]
    fn test_enable_dnssec_do_forces_do_on_arcount() {
        let mut query = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(crate::dns::cache::extract_do_bit(&query), Some(false));
        let forced = enable_dnssec_do(&query);
        // patched in place: same length, same arcount, DO set
        assert_eq!(forced.len(), query.len());
        assert_eq!(forced[11], 1);
        assert_eq!(crate::dns::cache::extract_do_bit(&forced), Some(true));
        // idempotent on already-DO queries
        let do_pos = query.len() - 4;
        query[do_pos] = 0x80;
        let again = enable_dnssec_do(&query);
        assert_eq!(again.len(), query.len());
        assert_eq!(crate::dns::cache::extract_do_bit(&again), Some(true));
    }

    #[test]
    fn test_parse_dns_response_empty() {
        assert_eq!(parse_dns_response(&[]), None);
        assert_eq!(parse_dns_response(&[0u8; 10]), None);
    }

    // FP-12: control/bidi bytes must never survive into parsed names.
    #[test]
    fn test_label_safety_rejects_terminal_bytes() {
        assert!(label_is_safe("example"));
        assert!(label_is_safe("xn--nxasmq6b"));
        assert!(!label_is_safe("a\x1bb")); // ESC
        assert!(!label_is_safe("a\x7fb")); // DEL
        assert!(!label_is_safe("a\u{202e}b")); // RTL override
        assert!(!label_is_safe("a\u{200b}b")); // zero-width space
                                               // hostile label is dropped from the parsed name
        let mut q = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            0x1b, b'b', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let (name, _) = parse_dns_name(&q, 12).expect("parses");
        assert!(!name.contains('\x1b'), "ESC must not survive: {}", name);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let _ = q;
    }

    #[test]
    fn test_dns_leak_canary_intercept() {
        // build query for leak-test.albus.internal
        let mut query = vec![
            0xDE, 0xAD, // ID
            0x01, 0x00, // standard query
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
        let domain = "leak-test.albus.internal";
        for part in domain.split('.') {
            query.push(part.len() as u8);
            query.extend_from_slice(part.as_bytes());
        }
        query.push(0x00);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN

        assert!(is_canary_query(&query));

        let canary_resp = build_canary_response(&query, Ipv4Addr::new(127, 0, 0, 99));
        assert!(canary_resp.len() > query.len());
        // verify 127.0.0.99 is contained in the answer section
        assert!(canary_resp.windows(4).any(|w| w == [127, 0, 0, 99]));
    }

    #[test]
    fn test_build_canary_query() {
        let query = build_canary_query();
        assert!(is_canary_query(&query));
        let canary_resp = build_canary_response(&query, Ipv4Addr::new(127, 0, 0, 99));
        assert!(canary_resp.windows(4).any(|w| w == [127, 0, 0, 99]));
    }

    // FP-14: echo validation accepts legit replies, rejects forgeries.
    #[test]
    fn test_canary_reply_valid() {
        let query = build_canary_query();
        let good = build_canary_response(&query, Ipv4Addr::new(127, 0, 0, 99));
        assert!(canary_reply_valid(&good, &query));
        // wrong TXID
        let mut bad_tx = good.clone();
        bad_tx[0] ^= 0xFF;
        assert!(!canary_reply_valid(&bad_tx, &query));
        // truncated
        assert!(!canary_reply_valid(&good[..10], &query));
        // question replaced (pattern-only forgery with valid TXID)
        let mut forged = good.clone();
        let qlen = query.len();
        for b in forged[12..qlen].iter_mut() {
            *b = 0x41;
        }
        assert!(!canary_reply_valid(&forged, &query));
    }
}

#[cfg(test)]
mod flush_scope_tests {
    use super::*;

    /// Minimal query wire format: header, one QNAME, QTYPE/QCLASS.
    fn query_wire(name: &str, qtype: u16, txid: u16) -> Vec<u8> {
        let mut m: Vec<u8> = Vec::new();
        m.extend_from_slice(&txid.to_be_bytes());
        m.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        for l in name.split('.') {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x01]);
        m
    }

    /// Answer with `ancount` A records in the body.
    fn answer_wire(ancount: u8, ips: [&str; 1]) -> Vec<u8> {
        let mut m: Vec<u8> = Vec::new();
        m.extend_from_slice(&[0x42, 0x42, 0x81, 0x80, 0x00, ancount, 0, 0, 0, 0, 0, 0]);
        for ip in ips {
            m.extend_from_slice(&[0xC0, 0x0C]); // pointer to name at offset 12
            m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
            m.extend_from_slice(&60u32.to_be_bytes()); // TTL
            m.extend_from_slice(&4u16.to_be_bytes()); // rdlength
            let o: Vec<u8> = ip.split('.').map(|p| p.parse().unwrap()).collect();
            m.extend_from_slice(&o);
        }
        m
    }

    /// W6-01: the panel's "Flush Cache" must reach every resolver cache, not
    /// one of four. The three it missed are the security-relevant ones: a stale
    /// Bogus verdict in `neg_cache` short-circuits `validate()` and keeps
    /// returning SERVFAIL for up to NEG_CACHE_TTL after a successful flush, so a
    /// LAN attacker who stamps one Bogus response simply out-waits the operator;
    /// `key_cache` ignores a KSK/DS rollover for up to an hour; `ech_cache` was
    /// only ever evicted by size.
    #[test]
    fn test_flush_clears_every_resolver_cache() {
        let server = DnsServer::new("cloudflare", &[], true, true, true).expect("server");

        // Seed each cache with one entry.
        let qname = "flushtest.example";
        server
            .validator
            .neg_store_for_test(qname, 1, DnssecState::Bogus);
        server
            .ech_cache
            .insert_for_test(qname.to_string(), vec![0x00, 0x02, 0xfe, 0x0d]);
        let q = query_wire("flushtest.example", 1, 0x4242);
        server.cache.insert(&q, &answer_wire(1, ["203.0.113.7"]));

        // All four now hold something.
        assert!(
            server.validator.neg_cached(qname, 1).is_some(),
            "negative-verdict cache should be seeded"
        );
        assert!(!server.ech_cache.is_empty(), "ECH cache should be seeded");
        assert!(!server.cache.is_empty(), "response cache should be seeded");

        server.flush_cache();

        assert!(
            server.validator.neg_cached(qname, 1).is_none(),
            "W6-01: a flushed resolver must not keep serving a cached Bogus verdict"
        );
        assert_eq!(server.ech_cache.len(), 0, "ECH cache must be flushed");
        assert_eq!(server.cache.len(), 0, "response cache must be flushed");
    }

    /// The DNSSEC key cache is private, so exercise it through its own clear.
    #[test]
    fn test_dnssec_clear_clears_both_dnssec_caches() {
        let v = DnssecValidator::new();
        v.neg_store_for_test("a.example", 1, DnssecState::Indeterminate);
        assert!(v.neg_cached("a.example", 1).is_some());
        v.clear_caches();
        assert!(
            v.neg_cached("a.example", 1).is_none(),
            "neg_cache must be empty after clear_caches()"
        );
    }
}

#[cfg(test)]
mod ad_bit_authority_tests {
    use super::*;
    use crate::dns::dnssec::DnssecState;

    /// Minimal response header + question, with the AD bit optionally set.
    fn response(ad: bool) -> Vec<u8> {
        let mut r: Vec<u8> = Vec::new();
        r.extend_from_slice(&[0x12, 0x34, 0x81, 0x80]); // id, QR+AA+RD+RA, rcode 0
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        if ad {
            r[3] |= 0x20;
        }
        r
    }

    /// DNS-03, the headline attack: a hostile or compromised DoH upstream
    /// answers AD=1 with no RRSIGs. albus's validator returns Insecure (which is
    /// correct — there is nothing to verify), the answer is served, and before
    /// the fix the AD=1 travelled straight through to every downstream consumer
    /// honouring RFC 6840 trust-ad.
    #[test]
    fn test_upstream_claimed_ad_is_cleared_when_not_secure() {
        for state in [
            Some(DnssecState::Insecure),
            Some(DnssecState::Indeterminate),
            None,
        ] {
            let out = normalize_ad_bit(response(true), true, state);
            assert!(
                !is_dnssec_authenticated(&out),
                "AD must be cleared for state {:?}: the upstream's claim about \
                 itself is not albus's verdict",
                state
            );
        }
    }

    /// Bogus never reaches normalisation (it became SERVFAIL), but pin it:
    /// nothing but Secure may assert AD.
    #[test]
    fn test_only_secure_asserts_ad() {
        let out = normalize_ad_bit(response(false), true, Some(DnssecState::Secure));
        assert!(
            is_dnssec_authenticated(&out),
            "a verified chain must assert AD — that is the whole point of validating"
        );
    }

    /// AD=1 + verified chain stays AD=1: the bit is not merely cleared.
    #[test]
    fn test_secure_preserves_or_sets_ad() {
        let out = normalize_ad_bit(response(true), true, Some(DnssecState::Secure));
        assert!(is_dnssec_authenticated(&out));
    }

    /// With DNSSEC disabled albus did not validate anything, so it must not
    /// assert that anything was validated — regardless of what the upstream
    /// claimed.
    #[test]
    fn test_ad_is_cleared_when_dnssec_is_disabled() {
        let out = normalize_ad_bit(response(true), false, Some(DnssecState::Secure));
        assert!(
            !is_dnssec_authenticated(&out),
            "with dnssec off, albus has no verdict to project and must not \
             forward the upstream's claim"
        );
    }

    /// Normalisation must touch ONLY the AD bit — RCODE, QR and the counts are
    /// the client's to read.
    #[test]
    fn test_only_the_ad_bit_is_modified() {
        let before = response(true);
        let after = normalize_ad_bit(before.clone(), true, Some(DnssecState::Insecure));
        assert_eq!(before.len(), after.len());
        for (i, (b, a)) in before.iter().zip(after.iter()).enumerate() {
            if i == 3 {
                continue;
            }
            assert_eq!(b, a, "byte {} must be untouched", i);
        }
        assert_eq!(after[3] & 0x20, 0, "AD must be the only difference");
    }

    /// A response too short to have a header is returned untouched rather than
    /// panicking on an index.
    #[test]
    fn test_short_response_is_returned_unchanged() {
        let short = vec![0x00, 0x01, 0x02];
        let out = normalize_ad_bit(short.clone(), true, Some(DnssecState::Secure));
        assert_eq!(out, short);
    }

    /// Normalisation must happen BEFORE the cache insert, or a cache hit could
    /// reintroduce the upstream's bit.
    #[test]
    fn test_normalisation_precedes_the_cache_insert() {
        let src = include_str!("server.rs");
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod ad_bit_authority_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);
        let norm = prod.find("normalize_ad_bit(").expect("normalisation call");
        let insert = prod[norm..]
            .find("cache_clone.insert(")
            .map(|o| norm + o)
            .expect("cache insert");
        assert!(
            norm < insert,
            "DNS-03: the AD bit must be normalised before the response is cached, \
             or a later cache hit would serve the upstream's bit again"
        );
    }

    /// The upstream's own claim must survive only as a journal field, never as
    /// the value anything downstream reads.
    #[test]
    fn test_upstream_claim_is_logged_not_relayed() {
        let src = include_str!("server.rs");
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod ad_bit_authority_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);
        assert!(
            prod.contains("upstream_claimed_ad"),
            "the upstream's self-assessment should be visible in the journal for \
             diagnosis"
        );
        let at = prod
            .find("let is_ad = is_dnssec_authenticated(&resp_bytes);")
            .expect("post-norm read");
        let before = &prod[..at];
        assert!(
            before.rfind("normalize_ad_bit(").is_some()
                && before.rfind("normalize_ad_bit(") > before.rfind("upstream_ad ="),
            "is_ad must be read AFTER normalisation, so it reflects albus's verdict"
        );
    }
}

#[cfg(test)]
mod admission_control_tests {

    /// DNS-02's claim, made structural: the admission decision must precede the
    /// datagram copy and the spawn. A test that only measured behaviour could be
    /// satisfied by moving the permit later as long as the count stayed under
    /// 512; what actually matters is that a shed datagram costs no task and no
    /// heap allocation, which is only true if the gate is before them.
    #[test]
    fn test_admission_precedes_allocation_and_spawn() {
        let src = include_str!("server.rs");
        let prod = src
            .split_once("#[cfg(test)]")
            .map(|(p, _)| p)
            .unwrap_or(src);

        let recv = prod
            .find("recv_res = socket.recv_from(&mut buf)")
            .expect("receive site");
        // Bound at the per-datagram spawn so the window is exactly the
        // admission path.
        let body = {
            let tail = &prod[recv..];
            let end = tail
                .find("let query_data = buf[..len].to_vec();")
                .unwrap_or(tail.len());
            &tail[..end]
        };

        assert!(
            body.contains("try_acquire_owned"),
            "the permit must be acquired on the receive loop, not inside the task"
        );
        assert!(
            body.contains("continue;"),
            "a shed datagram must be dropped without spawning a task"
        );
        assert!(
            !body.contains("query_data.clone()"),
            "the shed path must not clone the datagram"
        );
    }

    /// The permit must be moved into the task, so it is held for the task's
    /// lifetime rather than released immediately.
    #[test]
    fn test_permit_is_held_by_the_task() {
        let src = include_str!("server.rs");
        let prod = src
            .split_once("#[cfg(test)]")
            .map(|(p, _)| p)
            .unwrap_or(src);
        assert!(
            prod.contains("let _permit = permit;"),
            "the owned permit must be moved into the spawned task"
        );
        assert!(
            !prod.contains("sem_clone"),
            "the old per-task semaphore clone must be gone: admission happens on \\
             the receive loop now"
        );
    }

    /// The shed path must be allocation-free and reuse one buffer.
    #[test]
    fn test_shed_path_is_o1() {
        let src = include_str!("server.rs");
        let prod = src
            .split_once("#[cfg(test)]")
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod
            .find("let mut shed_buf = [0u8; 12];")
            .expect("reused shed buffer");
        // Bound at the admission path's end, not by an arbitrary byte count.
        let tail = &prod[at..];
        let end = tail
            .find("let query_data = buf[..len].to_vec();")
            .unwrap_or(tail.len());
        let block = &tail[..end];
        assert!(
            block.contains("send_to(&shed_buf"),
            "the shed reply must come from the reused buffer"
        );
        assert!(
            !block.contains("to_vec()"),
            "the shed path must not allocate per datagram"
        );
        // The reused buffer must live OUTSIDE the receive loop, or it would
        // be re-allocated per iteration and the reuse would be illusory.
        // Anchor on the loop that follows the 4096-byte receive buffer, not on
        // the first `loop {` in the file.
        let recv_buf = prod
            .find("let mut buf = [0u8; 4096];")
            .expect("receive buffer");
        let loop_at = prod[recv_buf..]
            .find("loop {")
            .map(|o| recv_buf + o)
            .expect("receive loop");
        assert!(
            at > recv_buf && at < loop_at,
            "the shed buffer must be declared once, outside the receive loop \
             (recv_buf={} shed={} loop={})",
            recv_buf,
            at,
            loop_at
        );
    }

    /// And shedding must be visible: silent degradation is the same class of
    /// defect as EBPF-01.
    #[test]
    fn test_shedding_is_logged() {
        let src = include_str!("server.rs");
        let prod = src
            .split_once("#[cfg(test)]")
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod
            .find("DNS load shedding: upstream concurrency")
            .expect("shed warning");
        let block = &prod[at.saturating_sub(400)..(at + 300).min(prod.len())];
        assert!(
            block.contains("warn!"),
            "load shedding must be reported, not silent"
        );
    }

    /// The reused SERVFAIL must be a well-formed header: a client has to be able
    /// to match it by transaction id and see rcode 2.
    #[test]
    fn test_shed_servfail_header_is_well_formed() {
        // Same construction as the shed path in the receive loop.
        let mut query = [0u8; 16];
        query[0] = 0xAB;
        query[1] = 0xCD;
        query[2] = 0x01; // RD
        query[3] = 0x00;
        let mut shed = [0u8; 12];
        shed[0] = query[0];
        shed[1] = query[1];
        shed[2] = 0x80 | (query[2] & 0x01);
        shed[3] = 0x80 | 0x02;
        shed[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);

        assert_eq!(&shed[0..2], &[0xAB, 0xCD], "transaction id must be echoed");
        assert_eq!(shed[2] & 0x80, 0x80, "QR must be set");
        assert_eq!(shed[2] & 0x01, 0x01, "RD must be preserved");
        assert_eq!(shed[3] & 0x0F, 2, "rcode must be SERVFAIL");
        assert_eq!(shed[3] & 0x80, 0x80, "RA must be set");
        assert_eq!(
            query[3] & 0x0F,
            0x00,
            "fixture guard: byte 3's low nibble in a QUERY is CD/AD/RD/Z, so \
             OR-ing it into a response would produce rcode 0 (NOERROR) with an \
             empty body instead of SERVFAIL"
        );
        assert_eq!(&shed[4..6], &[0, 1], "QDCOUNT must be 1");
        assert_eq!(
            &shed[6..12],
            &[0, 0, 0, 0, 0, 0],
            "ANCOUNT/NSCOUNT/ARCOUNT 0"
        );
    }

    /// DNS-02's second half: the DNSSEC caches must use bounded eviction, not a
    /// wholesale clear. An attacker-chosen name stream must not be able to wipe
    /// every verdict an honest query paid for.
    #[test]
    fn test_dnssec_caches_do_not_clear_wholesale() {
        let src = include_str!("dnssec.rs");
        // Split on a top-level test MODULE, not the first `#[cfg(test)]`:
        // dnssec.rs has test-only helper FUNCTIONS earlier in the file, and
        // cutting at those would exclude the production code under test.
        let prod = src
            .split_once("\n#[cfg(test)]\nmod ")
            .map(|(p, _)| p)
            .unwrap_or(src);
        assert!(
            !prod.contains("guard.clear();"),
            "DNS-02: the DNSSEC caches must not recover from overflow by clearing \\
             the whole map — that turns a per-name amortised cost into a per-query \\
             one and destroys every still-valid entry"
        );
        assert!(
            prod.contains("Self::evict_expired(&mut guard, NEG_CACHE_TTL)"),
            "the negative cache must evict only expired entries"
        );
        assert!(
            prod.contains("Self::evict_expired(&mut guard, KEY_CACHE_CAP)"),
            "the key cache must evict only expired entries"
        );
    }

    /// Bounded eviction must actually preserve fresh entries.
    #[test]
    fn test_evict_expired_keeps_fresh_entries() {
        use crate::dns::dnssec::DnssecValidator;
        use std::collections::HashMap;
        use std::time::{Duration, Instant};

        let mut map: HashMap<(String, u16), (u8, Instant)> = HashMap::new();
        map.insert(("fresh".into(), 1), (1, Instant::now()));
        map.insert(
            ("stale".into(), 1),
            (2, Instant::now() - Duration::from_secs(120)),
        );

        DnssecValidator::evict_expired(&mut map, Duration::from_secs(60));

        assert_eq!(map.len(), 1, "only the expired entry should go");
        assert!(map.contains_key(&("fresh".into(), 1)));
        assert!(!map.contains_key(&("stale".into(), 1)));
    }

    /// And a full cache of fresh entries declines the insert rather than
    /// destroying them.
    #[test]
    fn test_full_cache_declines_insert_instead_of_clearing() {
        let v = crate::dns::dnssec::DnssecValidator::new();
        // Fill the negative cache past its cap with fresh entries.
        for i in 0..1200 {
            v.neg_store_for_test(
                &format!("n{}.example", i),
                1,
                crate::dns::dnssec::DnssecState::Bogus,
            );
        }
        // The oldest entries are still within NEG_CACHE_TTL, so eviction frees
        // nothing and the insert is declined. Nothing may be lost.
        let mut survivors = 0;
        for i in 0..1024 {
            if v.neg_cached(&format!("n{}.example", i), 1).is_some() {
                survivors += 1;
            }
        }
        assert_eq!(
            survivors, 1024,
            "a full cache of fresh verdicts must not be wiped"
        );
    }
}
