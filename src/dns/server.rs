//! udp listener on 127.0.0.1:53 forwarding to encrypted doh with dnssec and ipv6 aaaa filtering.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use super::allowlist::DomainAllowlist;
use super::blocklist::{build_seed_blocklist, CompactBlocklist};
use super::cache::{extract_query_key, DnsCache};
use super::captive::{build_captive_response, check_captive_portal};
use super::cloak::CloakEngine;
use super::dns64::build_dns64_response;
use super::doh::DoHResolver;
use super::filter::{
    build_nxdomain_response, build_refused_response, build_sinkhole_response, detect_dns_rebinding,
    extract_question_end, is_firefox_canary, is_undelegated_zone,
};
use super::ip_filter::{extract_resolved_ips, IpFilter};
use super::local_doh::LocalDoHServer;
use super::logger::{QueryLogEntry, QueryLogger, QueryStatus};
use super::netmon::NetworkMonitor;
use super::odoh::ODoHClient;
use super::padding::apply_edns_options;
use super::stats::DnsStats;
use super::tcp::DnsTcpServer;
use super::uncloak::extract_alias_targets;
use super::watcher::FileWatcher;

// local dns server instance wrapping doh client pool and response cache
#[derive(Clone)]
pub struct DnsServer {
    resolver: DoHResolver,
    pub odoh_client: Option<Arc<ODoHClient>>,
    upstream_desc: String,
    block_ipv6: bool,
    dnssec: bool,
    pqc: bool,
    pub racing: bool,
    anti_dns_rebinding: bool,
    block_undelegated: bool,
    edns_padding: bool,
    cloak: Arc<CloakEngine>,
    pub blocklist: Arc<RwLock<CompactBlocklist>>,
    pub allowlist: Arc<RwLock<DomainAllowlist>>,
    pub ip_filter: Arc<IpFilter>,
    pub uncloak_cnames: bool,
    pub dns64: bool,
    pub netmon: bool,
    pub stats: Arc<DnsStats>,
    cache: Arc<DnsCache>,
    ip_queue: Arc<Mutex<HashMap<Ipv4Addr, VecDeque<String>>>>,
    pub tcp_listener: bool,
    pub local_doh: bool,
    pub local_doh_addr: SocketAddr,
    pub query_logger: Option<Arc<QueryLogger>>,
    pub allowlist_path: Option<String>,
    pub blocklist_path: Option<String>,
    shutdown_tx: broadcast::Sender<()>,
}

impl DnsServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upstreams_csv: &str,
        custom_bootstrap_ips: &[Ipv4Addr],
        block_ipv6: bool,
        dnssec: bool,
        pqc: bool,
        racing: bool,
        anti_dns_rebinding: bool,
        block_undelegated: bool,
        edns_padding: bool,
        cloak: Arc<CloakEngine>,
        blocklist: Arc<RwLock<CompactBlocklist>>,
        allowlist: Arc<RwLock<DomainAllowlist>>,
        ip_filter: Arc<IpFilter>,
        uncloak_cnames: bool,
        dns64: bool,
        netmon: bool,
        stats: Arc<DnsStats>,
        tcp_listener: bool,
        local_doh: bool,
        local_doh_addr: SocketAddr,
        query_logger: Option<Arc<QueryLogger>>,
        allowlist_path: Option<String>,
        blocklist_path: Option<String>,
        odoh_client: Option<Arc<ODoHClient>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = DoHResolver::new(upstreams_csv, custom_bootstrap_ips, pqc)?;
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            resolver,
            odoh_client,
            upstream_desc: upstreams_csv.to_string(),
            block_ipv6,
            dnssec,
            pqc,
            racing,
            anti_dns_rebinding,
            block_undelegated,
            edns_padding,
            cloak,
            blocklist,
            allowlist,
            ip_filter,
            uncloak_cnames,
            dns64,
            netmon,
            stats,
            cache: Arc::new(DnsCache::new(2048)),
            ip_queue: Arc::new(Mutex::new(HashMap::new())),
            tcp_listener,
            local_doh,
            local_doh_addr,
            query_logger,
            allowlist_path,
            blocklist_path,
            shutdown_tx,
        })
    }

    pub fn with_defaults(
        upstreams_csv: &str,
        custom_bootstrap_ips: &[Ipv4Addr],
        block_ipv6: bool,
        dnssec: bool,
        pqc: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::new(
            upstreams_csv,
            custom_bootstrap_ips,
            block_ipv6,
            dnssec,
            pqc,
            true,
            true,
            true,
            true,
            Arc::new(CloakEngine::new()),
            Arc::new(RwLock::new(build_seed_blocklist())),
            Arc::new(RwLock::new(DomainAllowlist::new())),
            Arc::new(IpFilter::default()),
            true,
            false,
            true,
            DnsStats::new(),
            true,
            true,
            "127.0.0.1:8053".parse().unwrap(),
            None,
            None,
            None,
            None,
        )
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
}

// creates a Linux kernel socket tuned with IP_FREEBIND, IP_TOS (DSCP 0x70), and enlarged socket buffers
fn create_tuned_udp_socket(
    addr: &str,
) -> Result<tokio::net::UdpSocket, Box<dyn std::error::Error + Send + Sync>> {
    let std_sock = std::net::UdpSocket::bind(addr)
        .map_err(|e| format!("failed to bind UDP socket to {}: {}", addr, e))?;

    #[cfg(unix)]
    {
        let fd = std_sock.as_raw_fd();
        unsafe {
            let one: libc::c_int = 1;
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );

            #[cfg(target_os = "linux")]
            {
                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_FREEBIND,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&one) as libc::socklen_t,
                );
            }

            let tos: libc::c_int = 0x70; // DSCP Interactive / Low Latency
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &tos as *const _ as *const libc::c_void,
                std::mem::size_of_val(&tos) as libc::socklen_t,
            );

            let buf_size: libc::c_int = 256 * 1024;
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of_val(&buf_size) as libc::socklen_t,
            );
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of_val(&buf_size) as libc::socklen_t,
            );
        }
    }

    std_sock.set_nonblocking(true)?;
    let tokio_sock = tokio::net::UdpSocket::from_std(std_sock)?;
    Ok(tokio_sock)
}

// builds standard rfc 1035 type-a dns query for dns64 fallback queries
pub fn build_a_query(domain: &str) -> Vec<u8> {
    let mut query = vec![
        0x56, 0x78, // Transaction ID
        0x01, 0x00, // Standard query, RD=1
        0x00, 0x01, // Questions: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in domain.trim_matches('.').split('.') {
        if !label.is_empty() {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
    }
    query.push(0x00);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Type A (1), Class IN (1)
    query
}

impl DnsServer {
    // spawns background asynchronous udp receive loop on loopback interface 127.0.0.1:53
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = match create_tuned_udp_socket("127.0.0.1:53") {
            Ok(s) => s,
            Err(e) => {
                return Err(
                    format!("failed to bind tuned UDP socket to 127.0.0.1:53: {}", e).into(),
                );
            }
        };

        info!(
            addr = "127.0.0.1:53",
            upstream = %self.upstream_desc,
            block_ipv6 = self.block_ipv6,
            dnssec = self.dnssec,
            pqc = self.pqc,
            uncloak_cnames = self.uncloak_cnames,
            dns64 = self.dns64,
            netmon = self.netmon,
            tcp_listener = self.tcp_listener,
            local_doh = self.local_doh,
            local_doh_addr = %self.local_doh_addr,
            query_log = self.query_logger.is_some(),
            cache_capacity = 2048,
            "DNS server started"
        );

        let socket = Arc::new(socket);

        // 1. spawn network sentinel (netmon) for interface and routing transitions
        if self.netmon {
            let net_mon = NetworkMonitor::new();
            let cache_ref = self.cache.clone();
            let resolver_ref = self.resolver.clone();
            let stats_ref = self.stats.clone();
            net_mon.start(
                std::time::Duration::from_secs(5),
                move |_epoch| {
                    cache_ref.clear();
                    resolver_ref.reset_balancer();
                    stats_ref.network_changes.fetch_add(1, Ordering::Relaxed);
                },
                self.shutdown_tx.subscribe(),
            );
        }

        // 2. spawn periodic runtime telemetry dump to /run/albus/stats.json
        let stats_dump = self.stats.clone();
        let mut stats_shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let _ = stats_dump.dump_to_file("/run/albus/stats.json");
                    }
                    _ = stats_shutdown_rx.recv() => break,
                }
            }
        });

        let mut canary_shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut tick_count: u64 = 0;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        tick_count = tick_count.wrapping_add(1);

                        // Passive check: verify resolv.conf still directs queries to loopback
                        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
                            let has_loopback = content.lines().any(|line| {
                                let trimmed = line.trim();
                                (trimmed.starts_with("nameserver 127.0.0.1") || trimmed.starts_with("nameserver 127.0.0.53"))
                                    && !trimmed.starts_with('#')
                            });

                            if !has_loopback {
                                warn!("DNS leak canary: /etc/resolv.conf does not point to 127.0.0.1 (possible DHCP/NetworkManager overwrite). Auto-healing system DNS...");
                                if let Err(e) = crate::dns::system::set_system_dns() {
                                    warn!("failed to auto-heal /etc/resolv.conf: {}", e);
                                } else {
                                    info!("DNS leak canary: successfully auto-healed /etc/resolv.conf to 127.0.0.1");
                                }
                            }
                        }

                        // Active watchdog check: actively probe local resolver on 127.0.0.1:53 every 60s
                        if tick_count % 4 == 0 {
                            run_active_canary_probe().await;
                        }
                    }
                    _ = canary_shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        let server_arc = Arc::new(self.clone());

        // 3. spawn live file watcher for allowlist hot-reload
        if let Some(ref path_str) = self.allowlist_path {
            let p = PathBuf::from(path_str);
            if p.exists() {
                let al_ref = self.allowlist.clone();
                let path_clone = path_str.clone();
                let rx = self.shutdown_tx.subscribe();
                FileWatcher::watch_async(
                    p,
                    Duration::from_secs(3),
                    move || {
                        let al = al_ref.clone();
                        let path = path_clone.clone();
                        async move {
                            if let Ok(new_al) = DomainAllowlist::from_file(&path) {
                                let mut lock = al.write().await;
                                *lock = new_al;
                                info!("domain allowlist hot-reloaded successfully from {}", path);
                            }
                        }
                    },
                    rx,
                );
            }
        }

        // 4. spawn live file watcher for blocklist hot-reload
        if let Some(ref path_str) = self.blocklist_path {
            let p = PathBuf::from(path_str);
            if p.exists() {
                let bl_ref = self.blocklist.clone();
                let path_clone = path_str.clone();
                let rx = self.shutdown_tx.subscribe();
                FileWatcher::watch_async(
                    p,
                    Duration::from_secs(3),
                    move || {
                        let bl = bl_ref.clone();
                        let path = path_clone.clone();
                        async move {
                            if let Ok(new_bl) = CompactBlocklist::load_from_file(&path) {
                                let mut lock = bl.write().await;
                                *lock = new_bl;
                                info!("domain blocklist hot-reloaded successfully from {}", path);
                            }
                        }
                    },
                    rx,
                );
            }
        }

        // 5. spawn RFC 7766 TCP listener on 127.0.0.1:53
        if self.tcp_listener {
            let s_tcp = server_arc.clone();
            let rx = self.shutdown_tx.subscribe();
            let tcp_bind: SocketAddr = "127.0.0.1:53".parse().unwrap();
            DnsTcpServer::start(
                tcp_bind,
                move |query, peer| {
                    let s = s_tcp.clone();
                    async move { s.resolve_packet(&query, peer.ip()).await }
                },
                rx,
            );
        }

        // 6. spawn RFC 8484 Local DoH listener on local_doh_addr (e.g. 127.0.0.1:8053)
        if self.local_doh {
            let s_doh = server_arc.clone();
            let rx = self.shutdown_tx.subscribe();
            LocalDoHServer::start(
                self.local_doh_addr,
                move |query, peer| {
                    let s = s_doh.clone();
                    async move { s.resolve_packet(&query, peer.ip()).await }
                },
                rx,
            );
        }

        // 7. spawn UDP receive loop
        const MAX_CONCURRENT_DNS_TASKS: usize = 512;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DNS_TASKS));
        let server_udp = server_arc.clone();
        let mut udp_shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];

            loop {
                tokio::select! {
                    recv_res = socket.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((len, peer_addr)) => {
                                let query_data = buf[..len].to_vec();
                                let socket_clone = socket.clone();
                                let s = server_udp.clone();
                                let sem_clone = semaphore.clone();

                                tokio::spawn(async move {
                                    let _permit = match sem_clone.try_acquire() {
                                        Ok(permit) => permit,
                                        Err(_) => {
                                            if query_data.len() >= 12 {
                                                let fail_resp = build_servfail_response(&query_data);
                                                let _ = socket_clone.send_to(&fail_resp, peer_addr).await;
                                            }
                                            return;
                                        }
                                    };

                                    if let Some(resp) = s.resolve_packet(&query_data, peer_addr.ip()).await {
                                        let _ = socket_clone.send_to(&resp, peer_addr).await;
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("UDP recv_from error: {}; continuing", e);
                                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                            }
                        }
                    }
                    _ = udp_shutdown_rx.recv() => {
                        debug!("DNS UDP server shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    // helper to asynchronously forward queries to rotating audit logger with client ip pseudonymization
    fn maybe_log_query(
        &self,
        client_ip: IpAddr,
        domain: &str,
        qtype: u16,
        status: QueryStatus,
        start_time: std::time::Instant,
        details: Option<&str>,
    ) {
        if let Some(ref logger) = self.query_logger {
            logger.log(QueryLogEntry {
                timestamp_epoch_secs: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                client_ip,
                domain: domain.to_string(),
                qtype,
                status,
                duration_ms: start_time.elapsed().as_millis() as u32,
                details: details.map(|s| s.to_string()),
            });
        }
    }

    /// executes query resolution via oblivious doh relay (rfc 9230) if configured,
    /// with transparent automatic fallback to direct doh pool upon error
    async fn resolve_upstream(
        &self,
        outgoing_query: &[u8],
    ) -> Result<(Vec<u8>, String), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref odoh) = self.odoh_client {
            match odoh.resolve(outgoing_query).await {
                Ok(resp) => return Ok((resp, "odoh".to_string())),
                Err(e) => {
                    warn!(
                        "ODoH resolution failed ({}), falling back to direct DoH upstream",
                        e
                    );
                }
            }
        }
        if self.racing {
            self.resolver.resolve_racing(outgoing_query).await
        } else {
            self.resolver.resolve(outgoing_query).await
        }
    }

    // common unified query resolution pipeline shared across udp, tcp 53 (rfc 7766), and local doh (rfc 8484)
    pub async fn resolve_packet(&self, query_data: &[u8], client_ip: IpAddr) -> Option<Vec<u8>> {
        // validate minimal DNS header length and ensure packet is a query (QR == 0)
        if query_data.len() < 12 || (query_data[2] & 0x80) != 0 {
            return None;
        }

        const MAX_IP_QUEUE_ENTRIES: usize = 4096;
        let start_time = std::time::Instant::now();
        self.stats.total_queries.fetch_add(1, Ordering::Relaxed);

        // 0. intercept internal dns leak test canary probe
        if is_canary_query(query_data) {
            let canary_resp = build_canary_response(query_data, Ipv4Addr::new(127, 0, 0, 99));
            self.maybe_log_query(
                client_ip,
                "leak-test.albus.internal",
                1,
                QueryStatus::Canary,
                start_time,
                None,
            );
            return Some(canary_resp);
        }

        let query_key = extract_query_key(query_data);
        let domain = query_key
            .as_ref()
            .map(|k| k.name.clone())
            .unwrap_or_default();
        let qtype = query_key.as_ref().map(|k| k.qtype).unwrap_or(1);

        // 1. intercept mozilla firefox doh canary (use-application-dns.net) to force local proxy
        if let Some(key) = &query_key {
            if is_firefox_canary(&key.name) {
                debug!(domain = %key.name, "Intercepted Firefox DoH canary probe; returning NXDOMAIN to force local proxy");
                self.stats.cloaked_responses.fetch_add(1, Ordering::Relaxed);
                self.maybe_log_query(
                    client_ip,
                    &domain,
                    qtype,
                    QueryStatus::Cloak0ms,
                    start_time,
                    Some("firefox_canary"),
                );
                return Some(build_nxdomain_response(query_data));
            }
        }

        // 2. handle wi-fi captive portal detection probes (apple, android, windows, gnome)
        if let Some(key) = &query_key {
            if let Some(captive_ip) = check_captive_portal(&key.name, key.qtype) {
                debug!(domain = %key.name, ip = %captive_ip, "Synthesized captive portal detection response");
                self.stats.captive_probes.fetch_add(1, Ordering::Relaxed);
                self.maybe_log_query(
                    client_ip,
                    &domain,
                    qtype,
                    QueryStatus::Captive,
                    start_time,
                    Some("captive_probe"),
                );
                return build_captive_response(query_data, captive_ip);
            }
        }

        // 3. check local cloaking table (0ms local hosts / synthetic overrides)
        if let Some(key) = &query_key {
            if let Some(cloaked_resp) = self.cloak.resolve_cloaked(&key.name, key.qtype, query_data)
            {
                debug!(domain = %key.name, "Resolved via local cloaking table (0ms)");
                self.stats.cloaked_responses.fetch_add(1, Ordering::Relaxed);
                self.maybe_log_query(
                    client_ip,
                    &domain,
                    qtype,
                    QueryStatus::Cloak0ms,
                    start_time,
                    Some("cloak_override"),
                );
                return Some(cloaked_resp);
            }
        }

        // 4. check split-dns forwarding rules
        if let Some(key) = &query_key {
            if let Some(target_forwarder) = self.cloak.get_forward_target(&key.name) {
                match self.cloak.forward_query(query_data, target_forwarder).await {
                    Ok(resp) => {
                        debug!(domain = %key.name, target = %target_forwarder, "Resolved via split-DNS forwarder");
                        self.maybe_log_query(
                            client_ip,
                            &domain,
                            qtype,
                            QueryStatus::Pass,
                            start_time,
                            Some("split_dns"),
                        );
                        return Some(resp);
                    }
                    Err(e) => {
                        debug!("split-dns forward to {} failed: {}", target_forwarder, e);
                    }
                }
            }
        }

        // 5. block unqualified dotless hostnames and undelegated private zones (prevent leaks upstream)
        if self.block_undelegated {
            if let Some(key) = &query_key {
                if is_undelegated_zone(&key.name) {
                    debug!(domain = %key.name, "Blocked undelegated/unqualified domain from leaking upstream");
                    self.maybe_log_query(
                        client_ip,
                        &domain,
                        qtype,
                        QueryStatus::Undelegated,
                        start_time,
                        Some("undelegated_zone"),
                    );
                    return Some(build_nxdomain_response(query_data));
                }
            }
        }

        // 6. domain allowlist check (whitelisted domains bypass blocklist)
        let is_whitelisted = self.allowlist.read().await.is_allowed(&domain);

        // 7. check memory-optimized hagezi ad/tracker/malware blocklist
        if !is_whitelisted {
            if let Some(key) = &query_key {
                let is_blocked = {
                    let bl = self.blocklist.read().await;
                    bl.check(&key.name)
                };
                if is_blocked {
                    self.stats.blocked_domains.fetch_add(1, Ordering::Relaxed);
                    info!(
                        domain = %key.name,
                        qtype = key.qtype,
                        "DNS query blocked by HaGeZi filter"
                    );
                    self.maybe_log_query(
                        client_ip,
                        &domain,
                        qtype,
                        QueryStatus::BlockHagezi,
                        start_time,
                        Some("hagezi_block"),
                    );
                    return Some(build_sinkhole_response(query_data, key.qtype));
                }
            }
        }

        // 8. synthesize instant nodata response for aaaa queries if ipv6 blocking is enabled
        if self.block_ipv6 && !self.dns64 && is_aaaa_query(query_data) {
            self.maybe_log_query(
                client_ip,
                &domain,
                qtype,
                QueryStatus::Pass,
                start_time,
                Some("ipv6_nodata"),
            );
            return Some(build_nodata_response(query_data));
        }

        // 9. check in-memory wire cache for fast-path 0ms response (with dynamic TTL decay!)
        if let Some(cached_resp) = self.cache.get(query_data) {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            if let Some((domain_parsed, ips)) = parse_dns_response(&cached_resp) {
                if !ips.is_empty() {
                    debug!(
                        domain = %domain_parsed,
                        ips = ?ips,
                        source = "cache_0ms",
                        "DNS cache hit"
                    );
                    let mut map = self.ip_queue.lock().await;
                    if map.len() >= MAX_IP_QUEUE_ENTRIES {
                        if let Some(oldest) = map.keys().next().cloned() {
                            map.remove(&oldest);
                        }
                    }
                    for ip in ips {
                        let queue = map.entry(ip).or_default();
                        if queue.len() < 50 {
                            queue.push_back(domain_parsed.clone());
                        }
                    }
                }
            }
            self.maybe_log_query(
                client_ip,
                &domain,
                qtype,
                QueryStatus::CacheHit,
                start_time,
                Some("cache_0ms"),
            );
            return Some(cached_resp);
        }

        // 10. prepare outgoing query with RFC 8467 EDNS Padding, RFC 7871 ECS zero-scope, and DNSSEC DO-bit
        self.stats.upstream_queries.fetch_add(1, Ordering::Relaxed);
        let outgoing_query = if self.edns_padding {
            apply_edns_options(query_data, self.dnssec, true, true)
        } else if self.dnssec {
            enable_dnssec_do(query_data)
        } else {
            query_data.to_vec()
        };

        match self.resolve_upstream(&outgoing_query).await {
            Ok((resp_bytes, via)) => {
                // Anti-DNS-Rebinding validation
                if self.anti_dns_rebinding {
                    if let Some(private_ip) = detect_dns_rebinding(&resp_bytes) {
                        warn!(
                            domain = ?query_key.as_ref().map(|k| &k.name),
                            private_ip = %private_ip,
                            "Anti-DNS-Rebinding triggered: public response resolved to private IP! Blocking response."
                        );
                        self.stats.rebinding_drops.fetch_add(1, Ordering::Relaxed);
                        self.maybe_log_query(
                            client_ip,
                            &domain,
                            qtype,
                            QueryStatus::RebindRefused,
                            start_time,
                            Some("dns_rebind"),
                        );
                        return Some(build_refused_response(query_data));
                    }
                }

                // Response IP & Bogon blacklist filter
                if !is_whitelisted {
                    let ips = extract_resolved_ips(&resp_bytes);
                    if let Some(blocked_ip) =
                        ips.into_iter().find(|ip| self.ip_filter.is_blocked(*ip))
                    {
                        warn!(
                            domain = ?query_key.as_ref().map(|k| &k.name),
                            ip = %blocked_ip,
                            "Resolved IP dropped by Bogon/Malicious IP blacklist"
                        );
                        self.maybe_log_query(
                            client_ip,
                            &domain,
                            qtype,
                            QueryStatus::BogonDrop,
                            start_time,
                            Some("bogon_filter"),
                        );
                        return Some(build_refused_response(query_data));
                    }
                }

                // CNAME & HTTPS/SVCB AliasMode Uncloaking Defense
                if self.uncloak_cnames && !is_whitelisted {
                    let targets = extract_alias_targets(&resp_bytes);
                    for target in targets {
                        let is_target_whitelisted = self.allowlist.read().await.is_allowed(&target);
                        if !is_target_whitelisted {
                            let is_target_blocked = {
                                let bl = self.blocklist.read().await;
                                bl.check(&target)
                            };
                            if is_target_blocked {
                                info!(
                                    domain = ?query_key.as_ref().map(|k| &k.name),
                                    uncloaked_target = %target,
                                    "CNAME cloaking tracker detected and blocked"
                                );
                                self.stats.uncloaked_cnames.fetch_add(1, Ordering::Relaxed);
                                self.maybe_log_query(
                                    client_ip,
                                    &domain,
                                    qtype,
                                    QueryStatus::UncloakedCname,
                                    start_time,
                                    Some(&target),
                                );
                                let qtype_val = query_key.as_ref().map(|k| k.qtype).unwrap_or(1);
                                return Some(build_sinkhole_response(query_data, qtype_val));
                            }
                        }
                    }
                }

                // DNS64 IPv6 synthesis for IPv4-only domains (RFC 6052 / RFC 6147)
                if self.dns64 {
                    if let Some(key) = &query_key {
                        if key.qtype == 28 {
                            let ancount = if resp_bytes.len() >= 8 {
                                ((resp_bytes[6] as usize) << 8) | (resp_bytes[7] as usize)
                            } else {
                                0
                            };
                            if ancount == 0 {
                                let a_query = build_a_query(&key.name);
                                if let Ok((a_resp, _)) = self.resolve_upstream(&a_query).await {
                                    if let Some((_, v4_ips)) = parse_dns_response(&a_resp) {
                                        if !v4_ips.is_empty() {
                                            let dns64_resp =
                                                build_dns64_response(query_data, &v4_ips, 300);
                                            self.stats
                                                .dns64_synthesized
                                                .fetch_add(1, Ordering::Relaxed);
                                            self.maybe_log_query(
                                                client_ip,
                                                &domain,
                                                qtype,
                                                QueryStatus::Pass,
                                                start_time,
                                                Some("dns64_synth"),
                                            );
                                            return Some(dns64_resp);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // insert response into cache (supports negative caching and serve-stale)
                self.cache.insert(query_data, &resp_bytes);

                let is_ad = is_dnssec_authenticated(&resp_bytes);
                if let Some((domain_parsed, ips)) = parse_dns_response(&resp_bytes) {
                    if !ips.is_empty() {
                        debug!(
                            domain = %domain_parsed,
                            ips = ?ips,
                            via = %via,
                            dnssec_authenticated = is_ad,
                            "DNS resolved"
                        );
                        let mut map = self.ip_queue.lock().await;
                        if map.len() >= MAX_IP_QUEUE_ENTRIES {
                            if let Some(oldest) = map.keys().next().cloned() {
                                map.remove(&oldest);
                            }
                        }
                        for ip in ips {
                            let queue = map.entry(ip).or_default();
                            if queue.len() < 50 {
                                queue.push_back(domain_parsed.clone());
                            }
                        }
                    }
                }

                self.maybe_log_query(
                    client_ip,
                    &domain,
                    qtype,
                    QueryStatus::Pass,
                    start_time,
                    Some(&via),
                );
                Some(resp_bytes)
            }
            Err(e) => {
                debug!("DNS resolution error: {}", e);

                // Fallback to Serve-Stale (RFC 8767): if upstream fails, serve stale cached response!
                if let Some(stale_resp) = self.cache.get_stale(query_data) {
                    debug!(
                        domain = ?query_key.as_ref().map(|k| &k.name),
                        "Serving stale cached DNS response under RFC 8767 during upstream failure"
                    );
                    self.maybe_log_query(
                        client_ip,
                        &domain,
                        qtype,
                        QueryStatus::CacheHit,
                        start_time,
                        Some("serve_stale"),
                    );
                    return Some(stale_resp);
                }

                if query_data.len() >= 12 {
                    Some(build_servfail_response(query_data))
                } else {
                    None
                }
            }
        }
    }

    // signals graceful shutdown to background udp listener task
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }

    // clears all entries from the in-memory response cache
    pub fn flush_cache(&self) {
        self.cache.clear();
        info!("DNS in-memory response cache flushed");
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

// appends rfc 6891 edns0 opt pseudo-rr with dnssec ok (do) bit enabled
pub fn enable_dnssec_do(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return query.to_vec();
    }

    let mut out = query.to_vec();
    let arcount = ((query[10] as u16) << 8) | (query[11] as u16);

    if arcount == 0 {
        // opt rr specification: root domain (0x00), type 41 (opt), udp payload size 4096, do-bit (0x8000)
        let opt_rr: [u8; 11] = [
            0x00, 0x00, 0x29, // type: opt (41)
            0x10, 0x00, // payload size: 4096
            0x00, // extended rcode
            0x00, // edns version
            0x80, 0x00, // do bit set (0x8000)
            0x00, 0x00, // rdlen: 0
        ];
        out.extend_from_slice(&opt_rr);
        out[10] = 0x00;
        out[11] = 0x01;
    }

    out
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

    let q_end = match extract_question_end(query) {
        Some(end) => end,
        None => return query.to_vec(),
    };

    let mut resp = Vec::with_capacity(q_end + 16);
    resp.extend_from_slice(&query[..q_end]);

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

// builds standard rfc 1035 dns query for leak-test.albus.internal (type a, class in)
pub fn build_canary_query() -> Vec<u8> {
    let mut query = vec![
        0xca, 0xfe, // Transaction ID
        0x01, 0x00, // Flags: standard query, recursion desired
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
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

// actively probes local loopback resolver to verify canary responsiveness and detect dns leaks
async fn run_active_canary_probe() {
    let probe_res = tokio::time::timeout(std::time::Duration::from_millis(1500), async {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let query = build_canary_query();
        sock.send_to(&query, "127.0.0.1:53").await?;

        let mut resp_buf = [0u8; 512];
        let (len, _) = sock.recv_from(&mut resp_buf).await?;
        Ok::<Vec<u8>, std::io::Error>(resp_buf[..len].to_vec())
    })
    .await;

    match probe_res {
        Ok(Ok(resp)) => {
            if resp.windows(4).any(|w| w == [127, 0, 0, 99]) {
                debug!("active DNS leak canary probe passed: 127.0.0.99 verified from local proxy");
            } else {
                warn!("Active DNS Leak Canary TRIPPED: resolver responded without expected canary IP (127.0.0.99). Potential DNS hijacking or poisoned cache detected!");
                if let Err(e) = crate::dns::system::set_system_dns() {
                    warn!("failed to auto-heal /etc/resolv.conf: {}", e);
                }
            }
        }
        Ok(Err(e)) => {
            warn!(
                "Active DNS Leak Canary probe network error ({}). Auto-healing system DNS...",
                e
            );
            if let Err(err) = crate::dns::system::set_system_dns() {
                warn!("failed to auto-heal /etc/resolv.conf: {}", err);
            }
        }
        Err(_) => {
            warn!("Active DNS Leak Canary probe timed out (1.5s): local DNS proxy unresponsive! Auto-healing system DNS...");
            if let Err(e) = crate::dns::system::set_system_dns() {
                warn!("failed to auto-heal /etc/resolv.conf: {}", e);
            }
        }
    }
}

// generates synthetic noerror response with ancount=0 (nodata) truncated to question section
pub fn build_nodata_response(query: &[u8]) -> Vec<u8> {
    let q_end = extract_question_end(query).unwrap_or(query.len().min(12));
    let mut resp = query[..q_end].to_vec();
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

// generates synthetic servfail response (rcode=2) truncated to question section
pub fn build_servfail_response(query: &[u8]) -> Vec<u8> {
    let q_end = extract_question_end(query).unwrap_or(query.len().min(12));
    let mut resp = query[..q_end].to_vec();
    if resp.len() >= 12 {
        resp[2] = (resp[2] | 0x80) | 0x01; // response flag (qr=1) + recursion desired
        resp[3] = 0x82; // recursion available + servfail (rcode=2)
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
    let mut domain = String::new();

    for i in 0..qdcount {
        let (d, next_pos) = parse_dns_name(data, pos)?;
        if i == 0 {
            domain = d;
        }
        pos = next_pos + 4;
        if pos > data.len() {
            return None;
        }
    }

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
            labels.push(label.to_string());
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
        let server = DnsServer::with_defaults("cloudflare", &[], true, true, true).unwrap();
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

    #[test]
    fn test_parse_dns_response_empty() {
        assert_eq!(parse_dns_response(&[]), None);
        assert_eq!(parse_dns_response(&[0u8; 10]), None);
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

    #[test]
    fn test_build_servfail_response() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let resp = build_servfail_response(&query);
        assert_eq!(resp.len(), query.len());
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[3] & 0x0F, 0x02); // SERVFAIL (rcode=2)
        assert_eq!(resp[6], 0); // ANCOUNT = 0
        assert_eq!(resp[7], 0);
    }
}
