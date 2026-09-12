//! udp listener on 127.0.0.1:53 forwarding to encrypted doh with dnssec and ipv6 aaaa filtering.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use super::allowlist::DomainAllowlist;
use super::blocklist::{build_seed_blocklist, CompactBlocklist};
use super::cache::{extract_query_key, DnsCache};
use super::captive::{build_captive_response, check_captive_portal, CaptiveMap};
use super::cloak::CloakEngine;
use super::dns64::build_dns64_response;
use super::doh::DoHResolver;
use super::ecs::ClientSubnet;
use super::filter::{
    build_blocked_response, build_nxdomain_response, build_refused_response,
    build_sinkhole_response, detect_dns_rebinding, extract_question_end, is_firefox_canary,
    is_undelegated_zone,
};
use super::forward::ForwardingEngine;
use super::ip_filter::{extract_resolved_ips, IpFilter};
use super::local_doh::LocalDoHServer;
use super::logger::{QueryLogEntry, QueryLogger, QueryStatus};
use super::metrics_server::MetricsServer;
use super::netmon::NetworkMonitor;
use super::odoh::ODoHClient;
use super::padding::{apply_edns_options, apply_edns_options_with_ecs};
use super::schedule::ScheduleManager;
use super::stats::DnsStats;
use super::tcp::DnsTcpServer;
use super::tls_auth::TlsClientAuth;
use super::uncloak::extract_alias_targets;
use super::watcher::FileWatcher;

// local dns server instance wrapping doh client pool and response cache
#[derive(Clone)]
pub struct DnsServer {
    pub resolver: Arc<tokio::sync::RwLock<DoHResolver>>,
    pub odoh_client: Option<Arc<ODoHClient>>,
    upstream_desc: Arc<StdRwLock<String>>,
    block_ipv6: Arc<AtomicBool>,
    dnssec: Arc<AtomicBool>,
    pqc: Arc<AtomicBool>,
    pub http3: Arc<AtomicBool>,
    pub racing: Arc<AtomicBool>,
    anti_dns_rebinding: Arc<AtomicBool>,
    block_undelegated: Arc<AtomicBool>,
    edns_padding: Arc<AtomicBool>,
    cloak: Arc<CloakEngine>,
    pub blocklist: Arc<RwLock<CompactBlocklist>>,
    pub allowlist: Arc<RwLock<DomainAllowlist>>,
    pub ip_filter: Arc<IpFilter>,
    pub uncloak_cnames: Arc<AtomicBool>,
    pub dns64: Arc<AtomicBool>,
    pub netmon: Arc<AtomicBool>,
    pub stats: Arc<DnsStats>,
    cache: Arc<DnsCache>,
    ip_queue: Arc<Mutex<HashMap<Ipv4Addr, VecDeque<String>>>>,
    pub tcp_listener: bool,
    pub local_doh: bool,
    pub local_doh_addr: SocketAddr,
    pub local_doh_tls: bool,
    pub local_doh_cert_file: Option<String>,
    pub local_doh_key_file: Option<String>,
    pub local_dot: bool,
    pub local_dot_addr: SocketAddr,
    pub local_dot_cert_file: Option<String>,
    pub local_dot_key_file: Option<String>,
    pub query_logger: Option<Arc<QueryLogger>>,
    pub allowlist_path: Option<String>,
    pub blocklist_path: Option<String>,
    pub schedule_manager: Arc<RwLock<ScheduleManager>>,
    pub edns_client_subnet: Option<ClientSubnet>,
    pub metrics: bool,
    pub metrics_addr: SocketAddr,
    pub tls_auth: Option<Arc<TlsClientAuth>>,
    pub forwarding: Arc<RwLock<ForwardingEngine>>,
    pub forwarding_rules_path: Option<String>,
    pub timeout_load_reduction: f64,
    pub query_meta: Arc<StdRwLock<Vec<String>>>,
    pub listen_addresses: Vec<SocketAddr>,
    pub max_clients: Arc<AtomicUsize>,
    pub lb_strategy: Arc<StdRwLock<String>>,
    pub load_balancer: Arc<crate::dns::balancer::LoadBalancer>,
    pub fragments_blocked: Arc<StdRwLock<Vec<String>>>,
    pub anonymized_dns_routes: Arc<StdRwLock<Vec<crate::app::config::AnonymizedDnsRoute>>>,
    pub captive_map: Arc<CaptiveMap>,
    pub force_tcp: Arc<AtomicBool>,
    pub skip_incompatible: Arc<AtomicBool>,
    pub direct_cert_fallback: Arc<AtomicBool>,
    pub blocked_query_response: Arc<StdRwLock<String>>,
    pub offline_mode: Arc<AtomicBool>,
    pub ignore_system_dns: Arc<AtomicBool>,
    pub cloaked_ptr: Arc<AtomicBool>,
    pub tls_disable_session_tickets: Arc<AtomicBool>,
    pub cert_refresh_delay: Arc<AtomicU32>,
    pub cert_ignore_timestamp: Arc<AtomicBool>,
    pub udp_pool_enabled: Arc<AtomicBool>,
    pub udp_pool: Arc<crate::dns::udp_pool::UdpConnPool>,
    pub client_rules: Arc<crate::dns::client_rules::ClientRuleEngine>,
    pub safesearch: Arc<crate::dns::safesearch::SafeSearchEngine>,
    pub dot_client: Option<Arc<crate::dns::dot::DotClient>>,
    pub doq_client: Option<Arc<crate::dns::doq::DoQClient>>,
    pub dnscrypt_client: Option<Arc<tokio::sync::RwLock<crate::dns::dnscrypt_client::DnsCryptClient>>>,
    pub randomize_ecs: Arc<AtomicBool>,
    pub reject_ttl: Arc<AtomicU32>,
    pub anti_injection: Option<Arc<crate::core::anti_injection::AntiInjectionFilter>>,
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
        http3: bool,
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
        proxy: Option<&str>,
        schedule_manager: Arc<RwLock<ScheduleManager>>,
        edns_client_subnet: Option<ClientSubnet>,
        metrics: bool,
        metrics_addr: SocketAddr,
        tls_auth: Option<Arc<TlsClientAuth>>,
        forwarding: Arc<RwLock<ForwardingEngine>>,
        forwarding_rules_path: Option<String>,
        tls_key_log_file: Option<String>,
        timeout_load_reduction: f64,
        cache_neg_min_ttl: u32,
        cache_neg_max_ttl: u32,
        cache_min_ttl: u32,
        cache_max_ttl: u32,
        force_tcp: bool,
        captive_map: Arc<CaptiveMap>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = DoHResolver::new_with_options(
            upstreams_csv,
            custom_bootstrap_ips,
            pqc,
            http3,
            proxy,
            tls_auth.as_deref(),
            tls_key_log_file.as_deref(),
        )?;
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            resolver: Arc::new(tokio::sync::RwLock::new(resolver)),
            odoh_client,
            upstream_desc: Arc::new(StdRwLock::new(upstreams_csv.to_string())),
            block_ipv6: Arc::new(AtomicBool::new(block_ipv6)),
            dnssec: Arc::new(AtomicBool::new(dnssec)),
            pqc: Arc::new(AtomicBool::new(pqc)),
            http3: Arc::new(AtomicBool::new(http3)),
            racing: Arc::new(AtomicBool::new(racing)),
            anti_dns_rebinding: Arc::new(AtomicBool::new(anti_dns_rebinding)),
            block_undelegated: Arc::new(AtomicBool::new(block_undelegated)),
            edns_padding: Arc::new(AtomicBool::new(edns_padding)),
            cloak,
            blocklist,
            allowlist,
            ip_filter,
            uncloak_cnames: Arc::new(AtomicBool::new(uncloak_cnames)),
            dns64: Arc::new(AtomicBool::new(dns64)),
            netmon: Arc::new(AtomicBool::new(netmon)),
            stats,
            cache: Arc::new(
                DnsCache::new(2048)
                    .with_neg_ttl(cache_neg_min_ttl, cache_neg_max_ttl)
                    .with_ttl(cache_min_ttl, cache_max_ttl),
            ),
            ip_queue: Arc::new(Mutex::new(HashMap::new())),
            tcp_listener,
            local_doh,
            local_doh_addr,
            local_doh_tls: false,
            local_doh_cert_file: None,
            local_doh_key_file: None,
            local_dot: false,
            local_dot_addr: "127.0.0.1:853".parse().unwrap(),
            local_dot_cert_file: None,
            local_dot_key_file: None,
            query_logger,
            allowlist_path,
            blocklist_path,
            schedule_manager,
            edns_client_subnet,
            metrics,
            metrics_addr,
            tls_auth,
            forwarding,
            forwarding_rules_path,
            timeout_load_reduction,
            query_meta: Arc::new(StdRwLock::new(Vec::new())),
            listen_addresses: vec!["127.0.0.1:53".parse().unwrap()],
            max_clients: Arc::new(AtomicUsize::new(250)),
            lb_strategy: Arc::new(StdRwLock::new("wp2".to_string())),
            load_balancer: Arc::new(crate::dns::balancer::LoadBalancer::new(&[upstreams_csv.to_string()])),
            fragments_blocked: Arc::new(StdRwLock::new(vec![
                "cisco".to_string(),
                "cleanbrowsing-adult".to_string(),
            ])),
            anonymized_dns_routes: Arc::new(StdRwLock::new(Vec::new())),
            captive_map,
            force_tcp: Arc::new(AtomicBool::new(force_tcp)),
            skip_incompatible: Arc::new(AtomicBool::new(false)),
            direct_cert_fallback: Arc::new(AtomicBool::new(true)),
            blocked_query_response: Arc::new(StdRwLock::new("hinfo".to_string())),
            offline_mode: Arc::new(AtomicBool::new(false)),
            ignore_system_dns: Arc::new(AtomicBool::new(true)),
            cloaked_ptr: Arc::new(AtomicBool::new(true)),
            tls_disable_session_tickets: Arc::new(AtomicBool::new(false)),
            cert_refresh_delay: Arc::new(AtomicU32::new(240)),
            cert_ignore_timestamp: Arc::new(AtomicBool::new(false)),
            udp_pool_enabled: Arc::new(AtomicBool::new(true)),
            udp_pool: Arc::new(crate::dns::udp_pool::UdpConnPool::default()),
            client_rules: Arc::new(crate::dns::client_rules::ClientRuleEngine::new()),
            safesearch: Arc::new(crate::dns::safesearch::SafeSearchEngine::new(
                false,
                crate::dns::safesearch::YouTubeMode::None,
            )),
            dot_client: None,
            doq_client: None,
            dnscrypt_client: None,
            randomize_ecs: Arc::new(AtomicBool::new(false)),
            reject_ttl: Arc::new(AtomicU32::new(10)),
            anti_injection: None,
            shutdown_tx,
        })
    }

    /// Sets stateful anti-injection filter for detecting middlebox tampering.
    pub fn with_anti_injection(mut self, filter: Arc<crate::core::anti_injection::AntiInjectionFilter>) -> Self {
        self.anti_injection = Some(filter);
        self
    }

    /// Sets optional stateful anti-injection filter for detecting middlebox tampering.
    pub fn with_optional_anti_injection(mut self, filter: Option<Arc<crate::core::anti_injection::AntiInjectionFilter>>) -> Self {
        self.anti_injection = filter;
        self
    }

    /// Sets the TTL returned in synthetic responses for blocked/rejected queries.
    pub fn with_reject_ttl(self, ttl: u32) -> Self {
        self.reject_ttl.store(ttl, Ordering::Relaxed);
        self
    }

    /// Sets per-client IP filtering rules engine.
    pub fn with_client_rules(mut self, rules: Arc<crate::dns::client_rules::ClientRuleEngine>) -> Self {
        self.client_rules = rules;
        self
    }

    /// Sets SafeSearch enforcement engine.
    pub fn with_safesearch(mut self, safesearch: Arc<crate::dns::safesearch::SafeSearchEngine>) -> Self {
        self.safesearch = safesearch;
        self
    }

    /// Sets DNS-over-TLS (DoT) client for upstream failover.
    pub fn with_dot_client(mut self, client: Option<Arc<crate::dns::dot::DotClient>>) -> Self {
        self.dot_client = client;
        self
    }

    /// Sets DNS-over-QUIC (DoQ) client for upstream failover.
    pub fn with_doq_client(mut self, client: Option<Arc<crate::dns::doq::DoQClient>>) -> Self {
        self.doq_client = client;
        self
    }

    /// Sets DNSCrypt v2 client for upstream resolution and failover.
    pub fn with_dnscrypt_client(
        mut self,
        client: Option<Arc<tokio::sync::RwLock<crate::dns::dnscrypt_client::DnsCryptClient>>>,
    ) -> Self {
        self.dnscrypt_client = client;
        self
    }

    /// Enables dynamic randomized EDNS Client Subnet (ECS) spoofing.
    pub fn with_randomize_ecs(self, enable: bool) -> Self {
        self.randomize_ecs.store(enable, Ordering::Relaxed);
        self
    }

    /// Configures response type when a DNS query is blocked (hinfo, refused, a:<ip4>,aaaa:<ip6>).
    pub fn with_blocked_query_response(self, resp: &str) -> Self {
        *self.blocked_query_response.write().unwrap() = resp.to_string();
        self
    }

    /// Configures offline mode (disables all upstream network queries).
    pub fn with_offline_mode(self, offline: bool) -> Self {
        self.offline_mode.store(offline, Ordering::Relaxed);
        self
    }

    /// Configures whether to bypass system DNS during bootstrap.
    pub fn with_ignore_system_dns(self, ignore: bool) -> Self {
        self.ignore_system_dns.store(ignore, Ordering::Relaxed);
        self
    }

    /// Configures whether cloaked domains return synthetic PTR records.
    pub fn with_cloaked_ptr(self, enabled: bool) -> Self {
        self.cloaked_ptr.store(enabled, Ordering::Relaxed);
        self
    }

    /// Configures whether TLS session tickets are disabled for DoH.
    pub fn with_tls_disable_session_tickets(self, disabled: bool) -> Self {
        self.tls_disable_session_tickets.store(disabled, Ordering::Relaxed);
        self
    }

    /// Configures certificate refresh delay in minutes.
    pub fn with_cert_refresh_delay(self, delay: u32) -> Self {
        self.cert_refresh_delay.store(delay, Ordering::Relaxed);
        self
    }

    /// Configures whether to ignore certificate timestamps.
    pub fn with_cert_ignore_timestamp(self, ignore: bool) -> Self {
        self.cert_ignore_timestamp.store(ignore, Ordering::Relaxed);
        self
    }

    /// Configures whether UDP connection pooling is enabled.
    pub fn with_udp_pool(self, enabled: bool) -> Self {
        self.udp_pool_enabled.store(enabled, Ordering::Relaxed);
        self
    }

    /// Attaches DNSCrypt-compatible query_meta TXT strings to outgoing queries.
    pub fn with_query_meta(self, meta: Vec<String>) -> Self {
        *self.query_meta.write().unwrap() = meta;
        self
    }

    /// Sets custom local listening addresses (UDP and TCP).
    pub fn with_listen_addresses(mut self, addrs: Vec<SocketAddr>) -> Self {
        if !addrs.is_empty() {
            self.listen_addresses = addrs;
        }
        self
    }

    /// Configures maximum concurrent clients for quartic timeout load reduction.
    pub fn with_max_clients(self, max_c: usize) -> Self {
        self.max_clients.store(max_c, Ordering::Relaxed);
        self
    }

    /// Configures upstream load balancing strategy (wp2, p2, ph, first, random).
    pub fn with_lb_strategy(self, strategy: &str) -> Self {
        *self.lb_strategy.write().unwrap() = strategy.to_string();
        self
    }

    /// Configures broken fragments blocked workaround servers list.
    pub fn with_fragments_blocked(self, blocked: Vec<String>) -> Self {
        *self.fragments_blocked.write().unwrap() = blocked;
        self
    }

    /// Configures multi-relay routing matrix for Anonymized DNS.
    pub fn with_anonymized_dns_routes(
        self,
        routes: Vec<crate::app::config::AnonymizedDnsRoute>,
        skip_incomp: bool,
        direct_fallback: bool,
    ) -> Self {
        *self.anonymized_dns_routes.write().unwrap() = routes;
        self.skip_incompatible.store(skip_incomp, Ordering::Relaxed);
        self.direct_cert_fallback.store(direct_fallback, Ordering::Relaxed);
        self
    }

    /// Resolves matching anonymized relays for a target upstream resolver name using the configured routes matrix.
    /// Exact server name match has highest priority, followed by wildcard "*" rule.
    pub fn get_relays_for_server(&self, server_name: &str) -> Vec<String> {
        let routes = self.anonymized_dns_routes.read().unwrap_or_else(|p| p.into_inner());
        resolve_anonymized_dns_routes(&routes, server_name)
    }

    /// Configures TLS termination options for Local DoH (RFC 8484 HTTPS).
    pub fn with_local_doh_tls(
        mut self,
        tls: bool,
        cert_file: Option<String>,
        key_file: Option<String>,
    ) -> Self {
        self.local_doh_tls = tls;
        self.local_doh_cert_file = cert_file;
        self.local_doh_key_file = key_file;
        self
    }

    pub fn with_local_dot(
        mut self,
        enabled: bool,
        addr: SocketAddr,
        cert_file: Option<String>,
        key_file: Option<String>,
    ) -> Self {
        self.local_dot = enabled;
        self.local_dot_addr = addr;
        self.local_dot_cert_file = cert_file;
        self.local_dot_key_file = key_file;
        self
    }

    pub fn is_http3(&self) -> bool {
        self.http3.load(Ordering::Relaxed)
    }

    pub fn resolver(&self) -> Arc<tokio::sync::RwLock<DoHResolver>> {
        self.resolver.clone()
    }

    /// Dynamically reloads upstream resolver, post-quantum settings, security policies, and filters
    /// in-place without dropping existing socket listeners or restarting the process.
    pub async fn reload_from_config(
        &self,
        cfg: &crate::app::config::Config,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let new_resolver = DoHResolver::new_full(
            &cfg.doh_upstream,
            &cfg.doh_bootstrap_ips,
            cfg.pqc,
            cfg.http3,
            cfg.effective_proxy().as_deref(),
            self.tls_auth.as_deref(),
            cfg.tls_key_log_file.as_deref(),
            cfg.tls_disable_session_tickets,
            cfg.ignore_system_dns,
        )?;

        *self.resolver.write().await = new_resolver;
        *self.upstream_desc.write().unwrap() = cfg.doh_upstream.clone();
        self.block_ipv6.store(cfg.block_ipv6, Ordering::Relaxed);
        self.dnssec.store(cfg.dnssec, Ordering::Relaxed);
        self.pqc.store(cfg.pqc, Ordering::Relaxed);
        self.http3.store(cfg.http3, Ordering::Relaxed);
        self.racing.store(cfg.dns_racing, Ordering::Relaxed);
        self.anti_dns_rebinding.store(cfg.anti_dns_rebinding, Ordering::Relaxed);
        self.block_undelegated.store(cfg.block_undelegated, Ordering::Relaxed);
        self.edns_padding.store(cfg.edns_padding, Ordering::Relaxed);
        self.uncloak_cnames.store(cfg.uncloak_cnames, Ordering::Relaxed);
        self.dns64.store(cfg.dns64, Ordering::Relaxed);
        *self.query_meta.write().unwrap() = cfg.query_meta.clone();
        self.max_clients.store(cfg.max_clients, Ordering::Relaxed);
        *self.lb_strategy.write().unwrap() = cfg.lb_strategy.clone();
        *self.fragments_blocked.write().unwrap() = cfg.fragments_blocked.clone();
        *self.anonymized_dns_routes.write().unwrap() = cfg.anonymized_dns_routes.clone();
        self.skip_incompatible.store(cfg.skip_incompatible, Ordering::Relaxed);
        self.direct_cert_fallback.store(cfg.direct_cert_fallback, Ordering::Relaxed);
        *self.blocked_query_response.write().unwrap() = cfg.blocked_query_response.clone();
        self.offline_mode.store(cfg.offline_mode, Ordering::Relaxed);
        self.ignore_system_dns.store(cfg.ignore_system_dns, Ordering::Relaxed);
        self.cloaked_ptr.store(cfg.cloaked_ptr, Ordering::Relaxed);
        self.tls_disable_session_tickets.store(cfg.tls_disable_session_tickets, Ordering::Relaxed);
        self.cert_refresh_delay.store(cfg.cert_refresh_delay, Ordering::Relaxed);
        self.cert_ignore_timestamp.store(cfg.cert_ignore_timestamp, Ordering::Relaxed);
        self.udp_pool_enabled.store(cfg.udp_pool, Ordering::Relaxed);
        self.reject_ttl.store(cfg.reject_ttl, Ordering::Relaxed);
        self.cache.clear();

        info!(
            upstream = %cfg.doh_upstream,
            pqc = cfg.pqc,
            http3 = cfg.http3,
            dnssec = cfg.dnssec,
            lb_strategy = %cfg.lb_strategy,
            offline_mode = cfg.offline_mode,
            blocked_response = %cfg.blocked_query_response,
            "DNS server configuration dynamically reloaded in real time"
        );
        Ok(())
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
            false,
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
            None,
            Arc::new(RwLock::new(ScheduleManager::new())),
            None,
            false,
            "127.0.0.1:9153".parse().unwrap(),
            None,
            Arc::new(RwLock::new(ForwardingEngine::new())),
            None,
            None,
            0.0,
            60,
            600,
            60,
            86400,
            false,
            Arc::new(CaptiveMap::new()),
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
    addr: SocketAddr,
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
                let level = if addr.is_ipv6() { libc::IPPROTO_IPV6 } else { libc::IPPROTO_IP };
                let opt = if addr.is_ipv6() { libc::IPV6_FREEBIND } else { libc::IP_FREEBIND };
                let _ = libc::setsockopt(
                    fd,
                    level,
                    opt,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&one) as libc::socklen_t,
                );
            }

            if addr.is_ipv4() {
                let tos: libc::c_int = 0x70; // DSCP Interactive / Low Latency
                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_TOS,
                    &tos as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&tos) as libc::socklen_t,
                );
            } else {
                let tclass: libc::c_int = 0x70;
                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_TCLASS,
                    &tclass as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&tclass) as libc::socklen_t,
                );
            }

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
    // spawns background asynchronous udp receive loop on configured listen addresses
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addrs = if self.listen_addresses.is_empty() {
            vec!["127.0.0.1:53".parse().unwrap()]
        } else {
            self.listen_addresses.clone()
        };

        let mut udp_sockets = Vec::new();
        if let Some(systemd) = crate::dns::system::get_systemd_sockets() {
            for std_sock in systemd.udp {
                if let Ok(addr) = std_sock.local_addr() {
                    if let Ok(tokio_sock) = tokio::net::UdpSocket::from_std(std_sock) {
                        info!(addr = %addr, "Using systemd activated UDP socket");
                        udp_sockets.push((addr, Arc::new(tokio_sock)));
                    }
                }
            }
        }

        if udp_sockets.is_empty() {
            for addr in &addrs {
                let socket = match create_tuned_udp_socket(*addr) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(
                            format!("failed to bind tuned UDP socket to {}: {}", addr, e).into(),
                        );
                    }
                };
                udp_sockets.push((*addr, Arc::new(socket)));
            }
        }

        info!(
            listen_addresses = ?addrs,
            upstream = %self.upstream_desc.read().unwrap_or_else(|p| p.into_inner()),
            block_ipv6 = self.block_ipv6.load(Ordering::Relaxed),
            dnssec = self.dnssec.load(Ordering::Relaxed),
            pqc = self.pqc.load(Ordering::Relaxed),
            uncloak_cnames = self.uncloak_cnames.load(Ordering::Relaxed),
            dns64 = self.dns64.load(Ordering::Relaxed),
            netmon = self.netmon.load(Ordering::Relaxed),
            tcp_listener = self.tcp_listener,
            local_doh = self.local_doh,
            local_doh_addr = %self.local_doh_addr,
            query_log = self.query_logger.is_some(),
            cache_capacity = 2048,
            "DNS server started"
        );

        // 1. spawn network sentinel (netmon) for interface and routing transitions
        if self.netmon.load(Ordering::Relaxed) {
            let net_mon = NetworkMonitor::new();
            let cache_ref = self.cache.clone();
            let resolver_ref = self.resolver.clone();
            let stats_ref = self.stats.clone();
            net_mon.start(
                std::time::Duration::from_secs(5),
                move |_epoch| {
                    cache_ref.clear();
                    let r = resolver_ref.clone();
                    tokio::spawn(async move {
                        r.read().await.reset_balancer();
                    });
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
            let stats_path = crate::app::config::Config::volatile_stats_path();
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let _ = stats_dump.dump_to_file(&stats_path);
                    }
                    _ = stats_shutdown_rx.recv() => break,
                }
            }
        });

        // 3. spawn periodic anti-injection stale flow state cleanup
        if let Some(anti_inj) = self.anti_injection.clone() {
            let mut anti_inj_shutdown_rx = self.shutdown_tx.subscribe();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            anti_inj.cleanup_stale(std::time::Duration::from_secs(300));
                        }
                        _ = anti_inj_shutdown_rx.recv() => break,
                    }
                }
            });
        }

        let canary_probe_target = addrs.iter().find(|a| a.is_ipv4()).copied().unwrap_or(addrs[0]);
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

                        // Active watchdog check: actively probe local resolver on configured target every 60s
                        if tick_count % 4 == 0 {
                            run_active_canary_probe(canary_probe_target).await;
                        }
                    }
                    _ = canary_shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        // 2b. spawn periodic certificate and upstream health refresh (cert_refresh_delay in minutes)
        let cert_delay = self.cert_refresh_delay.load(Ordering::Relaxed);
        if cert_delay > 0 {
            let mut cert_shutdown_rx = self.shutdown_tx.subscribe();
            let resolver_ref = self.resolver.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(cert_delay as u64 * 60));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            debug!("Periodic certificate and upstream health refresh tick triggered");
                            let r = resolver_ref.read().await;
                            r.reset_balancer();
                        }
                        _ = cert_shutdown_rx.recv() => break,
                    }
                }
            });
        }

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

        // spawn live file watcher for split-dns forwarding rules hot-reload
        if let Some(ref path_str) = self.forwarding_rules_path {
            let p = PathBuf::from(path_str);
            if p.exists() {
                let fw_ref = self.forwarding.clone();
                let path_clone = path_str.clone();
                let rx = self.shutdown_tx.subscribe();
                FileWatcher::watch_async(
                    p,
                    Duration::from_secs(3),
                    move || {
                        let fw = fw_ref.clone();
                        let path = path_clone.clone();
                        async move {
                            match ForwardingEngine::from_file(&path) {
                                Ok(new_fw) => {
                                    let mut lock = fw.write().await;
                                    *lock = new_fw;
                                    info!("split-dns forwarding rules hot-reloaded successfully from {}", path);
                                }
                                Err(e) => {
                                    warn!(
                                        "failed to hot-reload forwarding rules from {}: {}",
                                        path, e
                                    );
                                }
                            }
                        }
                    },
                    rx,
                );
            }
        }

        // 5. spawn RFC 7766 TCP listener on all configured listen_addresses
        if self.tcp_listener {
            for addr in &addrs {
                let s_tcp = server_arc.clone();
                let rx = self.shutdown_tx.subscribe();
                let tcp_bind = *addr;
                DnsTcpServer::start(
                    tcp_bind,
                    move |query, peer| {
                        let s = s_tcp.clone();
                        async move {
                            s.stats.queries_tcp.fetch_add(1, Ordering::Relaxed);
                            s.resolve_packet(&query, peer.ip()).await
                        }
                    },
                    rx,
                );
            }
        }

        // 6. spawn RFC 8484 Local DoH listener on local_doh_addr (e.g. 127.0.0.1:8053)
        if self.local_doh {
            let s_doh = server_arc.clone();
            let rx = self.shutdown_tx.subscribe();
            let tls_acceptor = if self.local_doh_tls {
                if let (Some(ref cert), Some(ref key)) = (&self.local_doh_cert_file, &self.local_doh_key_file) {
                    match crate::dns::local_doh::create_tls_acceptor_from_files(cert, key) {
                        Ok(acc) => Some(acc),
                        Err(e) => {
                            warn!("failed to create TLS acceptor for local DoH: {}; falling back to HTTP", e);
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };
            LocalDoHServer::start_with_tls(
                self.local_doh_addr,
                tls_acceptor,
                move |query, peer| {
                    let s = s_doh.clone();
                    async move {
                        s.stats.queries_doh.fetch_add(1, Ordering::Relaxed);
                        s.resolve_packet(&query, peer.ip()).await
                    }
                },
                rx,
            );
        }

        // 6.0. spawn local DNS-over-TLS (DoT port 853) listener if enabled
        if self.local_dot {
            let s_dot = server_arc.clone();
            let rx = self.shutdown_tx.subscribe();
            let cert_file = self.local_dot_cert_file.as_deref().or(self.local_doh_cert_file.as_deref());
            let key_file = self.local_dot_key_file.as_deref().or(self.local_doh_key_file.as_deref());

            if let (Some(c), Some(k)) = (cert_file, key_file) {
                match crate::dns::local_dot::create_dot_tls_acceptor_from_files(c, k) {
                    Ok(tls_acceptor) => {
                        crate::dns::LocalDoTServer::start(
                            self.local_dot_addr,
                            tls_acceptor,
                            move |query, peer| {
                                let s = s_dot.clone();
                                async move {
                                    s.stats.queries_dot.fetch_add(1, Ordering::Relaxed);
                                    s.resolve_packet(&query, peer.ip()).await
                                }
                            },
                            rx,
                        );
                        info!(addr = %self.local_dot_addr, "Local DoT server started (TLS on port 853)");
                    }
                    Err(e) => {
                        warn!("failed to create TLS acceptor for local DoT: {}", e);
                    }
                }
            } else {
                warn!("local DoT listener requires TLS certificate and private key files");
            }
        }

        // 6.1. spawn Prometheus metrics endpoint (/metrics) on metrics_addr (e.g. 127.0.0.1:9153)
        if self.metrics {
            let rx = self.shutdown_tx.subscribe();
            MetricsServer::start(self.metrics_addr, self.stats.clone(), rx);
        }

        // 7. spawn UDP receive loops
        const MAX_CONCURRENT_DNS_TASKS: usize = 512;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DNS_TASKS));

        for (bind_addr, socket) in udp_sockets {
            let server_udp = server_arc.clone();
            let mut udp_shutdown_rx = self.shutdown_tx.subscribe();
            let sem_clone = semaphore.clone();

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
                                    let sem = sem_clone.clone();

                                    tokio::spawn(async move {
                                        let _permit = match sem.try_acquire() {
                                            Ok(permit) => permit,
                                            Err(_) => {
                                                if query_data.len() >= 12 {
                                                    let fail_resp = build_servfail_response(&query_data);
                                                    let _ = socket_clone.send_to(&fail_resp, peer_addr).await;
                                                }
                                                return;
                                            }
                                        };

                                        s.stats.queries_udp.fetch_add(1, Ordering::Relaxed);
                                        if let Some(resp) = s.resolve_packet(&query_data, peer_addr.ip()).await {
                                            let _ = socket_clone.send_to(&resp, peer_addr).await;
                                        }
                                    });
                                }
                                Err(e) => {
                                    warn!("UDP recv_from error on {}: {}; continuing", bind_addr, e);
                                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                                }
                            }
                        }
                        _ = udp_shutdown_rx.recv() => {
                            debug!("DNS UDP server shutting down on {}", bind_addr);
                            break;
                        }
                    }
                }
            });
        }

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
    /// with transparent automatic fallback to direct doh pool upon error and adaptive timeout under load
    async fn resolve_upstream(
        &self,
        outgoing_query: &[u8],
    ) -> Result<(Vec<u8>, String), Box<dyn std::error::Error + Send + Sync>> {
        if self.offline_mode.load(Ordering::Relaxed) {
            return Err("offline mode enabled: upstream network queries disabled".into());
        }

        let active = self.stats.active_queries.load(Ordering::Relaxed);
        let max_c = self.max_clients.load(Ordering::Relaxed).max(1) as u64;
        let base_timeout = Duration::from_secs(5);
        let effective_timeout =
            compute_adaptive_timeout(base_timeout, active, max_c, self.timeout_load_reduction);

        // Broken implementations workaround: clamp EDNS buffer size if upstream matches fragments_blocked
        let effective_query = {
            let upstream = self.upstream_desc.read().unwrap_or_else(|p| p.into_inner());
            let blocked = self.fragments_blocked.read().unwrap_or_else(|p| p.into_inner());
            let is_blocked = blocked.iter().any(|b| upstream.to_ascii_lowercase().contains(&b.to_ascii_lowercase()));
            if is_blocked && outgoing_query.len() > 1252 {
                &outgoing_query[..1252]
            } else {
                outgoing_query
            }
        };

        let start_time = std::time::Instant::now();
        let query_fut = async {
            if let Some(ref odoh) = self.odoh_client {
                match odoh.resolve(effective_query).await {
                    Ok(resp) => return Ok((resp, "odoh".to_string())),
                    Err(e) => {
                        warn!(
                            "ODoH resolution failed ({}), falling back to direct DoH upstream",
                            e
                        );
                    }
                }
            }
            if let Some(ref dnscrypt) = self.dnscrypt_client {
                let mut needs_cert = false;
                {
                    let dc = dnscrypt.read().await;
                    if dc.cert.is_none() {
                        needs_cert = true;
                    }
                }
                if needs_cert {
                    let mut dc = dnscrypt.write().await;
                    if dc.cert.is_none() {
                        if let Err(e) = dc.fetch_cert(effective_timeout).await {
                            warn!("DNSCrypt failed to fetch certificate: {}", e);
                        }
                    }
                }
                let dc = dnscrypt.read().await;
                if dc.cert.is_some() {
                    match dc.resolve(effective_query, effective_timeout).await {
                        Ok(resp) => return Ok((resp, "dnscrypt".to_string())),
                        Err(e) => {
                            warn!("DNSCrypt resolution failed ({}), falling back to DoH", e);
                        }
                    }
                }
            }
            if self.racing.load(Ordering::Relaxed) {
                let r = self.resolver.read().await;
                r.resolve_racing(effective_query).await
            } else {
                let r = self.resolver.read().await;
                r.resolve(effective_query).await
            }
        };

        let doh_result = tokio::time::timeout(effective_timeout, query_fut).await;
        match doh_result {
            Ok(Ok((res, via))) => {
                self.load_balancer.record_result(0, start_time.elapsed(), true);
                Ok((res, via))
            }
            Ok(Err(e)) => {
                self.load_balancer.record_result(0, start_time.elapsed(), false);
                if let Some(ref dnscrypt) = self.dnscrypt_client {
                    let dc = dnscrypt.read().await;
                    if dc.cert.is_some() {
                        if let Ok(dc_resp) = dc.resolve(effective_query, effective_timeout).await {
                            debug!("DNS query successfully resolved via DNSCrypt failover");
                            return Ok((dc_resp, "dnscrypt_failover".to_string()));
                        }
                    }
                }
                if let Some(ref doq) = self.doq_client {
                    debug!("DoH resolution failed ({}), attempting failover to DNS-over-QUIC (DoQ)", e);
                    match doq.query(effective_query).await {
                        Ok(doq_resp) => {
                            debug!("DNS query successfully resolved via DoQ failover");
                            return Ok((doq_resp, "doq_failover".to_string()));
                        }
                        Err(doq_err) => {
                            warn!("DoQ failover also failed: {}", doq_err);
                        }
                    }
                }
                if let Some(ref dot) = self.dot_client {
                    debug!("DoH resolution failed ({}), attempting failover to DNS-over-TLS (DoT)", e);
                    match dot.query(effective_query).await {
                        Ok(dot_resp) => {
                            debug!("DNS query successfully resolved via DoT failover");
                            return Ok((dot_resp, "dot_failover".to_string()));
                        }
                        Err(dot_err) => {
                            warn!("DoT failover also failed: {}", dot_err);
                        }
                    }
                }
                Err(e)
            }
            Err(_) => {
                self.load_balancer.record_result(0, effective_timeout, false);
                if let Some(ref dnscrypt) = self.dnscrypt_client {
                    let dc = dnscrypt.read().await;
                    if dc.cert.is_some() {
                        if let Ok(dc_resp) = dc.resolve(effective_query, effective_timeout).await {
                            debug!("DNS query successfully resolved via DNSCrypt failover");
                            return Ok((dc_resp, "dnscrypt_failover".to_string()));
                        }
                    }
                }
                if let Some(ref doq) = self.doq_client {
                    debug!("DoH query timed out, attempting failover to DNS-over-QUIC (DoQ)");
                    match doq.query(effective_query).await {
                        Ok(doq_resp) => {
                            debug!("DNS query successfully resolved via DoQ failover");
                            return Ok((doq_resp, "doq_failover".to_string()));
                        }
                        Err(doq_err) => {
                            warn!("DoQ failover also failed: {}", doq_err);
                        }
                    }
                }
                if let Some(ref dot) = self.dot_client {
                    debug!("DoH query timed out, attempting failover to DNS-over-TLS (DoT)");
                    match dot.query(effective_query).await {
                        Ok(dot_resp) => {
                            debug!("DNS query successfully resolved via DoT failover");
                            return Ok((dot_resp, "dot_failover".to_string()));
                        }
                        Err(dot_err) => {
                            warn!("DoT failover also failed: {}", dot_err);
                        }
                    }
                }
                Err(format!(
                    "upstream query timed out under load (timeout: {:?}, active: {})",
                    effective_timeout, active
                )
                .into())
            }
        }
    }

    // common unified query resolution pipeline shared across udp, tcp 53 (rfc 7766), and local doh (rfc 8484)
    pub async fn resolve_packet(&self, query_data: &[u8], client_ip: IpAddr) -> Option<Vec<u8>> {
        // validate minimal DNS header length and ensure packet is a query (QR == 0)
        if query_data.len() < 12 || (query_data[2] & 0x80) != 0 {
            return None;
        }

        struct ActiveQueryGuard<'a>(&'a std::sync::atomic::AtomicU64);
        impl<'a> Drop for ActiveQueryGuard<'a> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }

        self.stats.active_queries.fetch_add(1, Ordering::SeqCst);
        let _active_guard = ActiveQueryGuard(&self.stats.active_queries);

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

        let client_decision = self.client_rules.evaluate(client_ip, &domain, qtype);
        match client_decision {
            crate::dns::client_rules::ClientDecision::Blocked(reason) => {
                debug!(domain = %domain, client = %client_ip, reason = %reason, "Blocked by per-client filtering rule");
                self.stats.blocked_domains.fetch_add(1, Ordering::Relaxed);
                self.maybe_log_query(
                    client_ip,
                    &domain,
                    qtype,
                    QueryStatus::BlockedName,
                    start_time,
                    Some(reason),
                );
                return Some(build_sinkhole_response(query_data, qtype));
            }
            crate::dns::client_rules::ClientDecision::DropIPv6 => {
                debug!(domain = %domain, client = %client_ip, "Dropped AAAA query per client profile IPv6 policy");
                self.stats.blocked_domains.fetch_add(1, Ordering::Relaxed);
                return Some(build_nodata_response(query_data));
            }
            _ => {}
        }
        let client_bypassed = matches!(client_decision, crate::dns::client_rules::ClientDecision::Allowed(_));

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
            if let Some(captive_ip) = self.captive_map.check(&key.name, key.qtype) {
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

        // 2.5 enforce SafeSearch & YouTube restricted mode redirects
        if let Some(key) = &query_key {
            if let Some(ovr) = self.safesearch.check(&key.name, key.qtype) {
                debug!(domain = %key.name, "Applying SafeSearch / YouTube restricted mode override");
                self.stats.cloaked_responses.fetch_add(1, Ordering::Relaxed);
                self.maybe_log_query(
                    client_ip,
                    &domain,
                    qtype,
                    QueryStatus::Cloak0ms,
                    start_time,
                    Some("safesearch"),
                );
                return Some(crate::dns::safesearch::build_safesearch_response(
                    query_data,
                    &key.name,
                    key.qtype,
                    &ovr,
                ));
            }
        }

        // 3. check local cloaking table (0ms local hosts / synthetic overrides)
        if let Some(key) = &query_key {
            if key.qtype != 12 || self.cloaked_ptr.load(Ordering::Relaxed) {
                if let Some(cloaked_resp) =
                    self.cloak.resolve_cloaked(&key.name, key.qtype, query_data)
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
        }

        // 4. check split-dns forwarding rules
        if let Some(key) = &query_key {
            let fw = self.forwarding.read().await;
            if let Some(forward_res) = fw.forward_query_for_domain(query_data, &key.name).await {
                match forward_res {
                    Ok(resp) => {
                        debug!(domain = %key.name, "Resolved via ForwardingEngine split-DNS");
                        self.maybe_log_query(
                            client_ip,
                            &domain,
                            qtype,
                            QueryStatus::Pass,
                            start_time,
                            Some("split_dns_forward"),
                        );
                        return Some(resp);
                    }
                    Err(e) => {
                        debug!(
                            "ForwardingEngine split-dns failed for {}: {}",
                            key.name, e
                        );
                    }
                }
            } else if let Some(target_forwarder) = self.cloak.get_forward_target(&key.name) {
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
        if self.block_undelegated.load(Ordering::Relaxed) {
            if let Some(key) = &query_key {
                if is_undelegated_zone(&key.name) {
                    debug!(domain = %key.name, "Blocked undelegated/unqualified domain from leaking upstream");
                    self.stats
                        .blocked_undelegated
                        .fetch_add(1, Ordering::Relaxed);
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

        // 7. check active time schedules and memory-optimized hagezi ad/tracker/malware blocklist
        if !is_whitelisted {
            if let Some(key) = &query_key {
                let scheduled_block = {
                    let sm = self.schedule_manager.read().await;
                    sm.check_blocked(&key.name).map(|s| s.to_string())
                };

                if let Some(sched_name) = scheduled_block {
                    self.stats.blocked_domains.fetch_add(1, Ordering::Relaxed);
                    self.stats.blocked_schedule.fetch_add(1, Ordering::Relaxed);
                    info!(
                        domain = %key.name,
                        schedule = %sched_name,
                        "DNS query blocked by active time schedule"
                    );
                    self.maybe_log_query(
                        client_ip,
                        &domain,
                        qtype,
                        QueryStatus::BlockHagezi,
                        start_time,
                        Some(&format!("schedule:{}", sched_name)),
                    );
                    let blocked_strategy = self.blocked_query_response.read().unwrap_or_else(|p| p.into_inner()).clone();
                    return Some(build_blocked_response(query_data, key.qtype, &blocked_strategy, self.reject_ttl.load(Ordering::Relaxed)));
                }

                let is_blocked = if client_bypassed {
                    false
                } else {
                    let bl = self.blocklist.read().await;
                    bl.check(&key.name)
                };
                if is_blocked {
                    self.stats.blocked_domains.fetch_add(1, Ordering::Relaxed);
                    self.stats.blocked_blocklist.fetch_add(1, Ordering::Relaxed);
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
                    let blocked_strategy = self.blocked_query_response.read().unwrap_or_else(|p| p.into_inner()).clone();
                    return Some(build_blocked_response(query_data, key.qtype, &blocked_strategy, self.reject_ttl.load(Ordering::Relaxed)));
                }
            }
        }

        // 8. synthesize instant nodata response for aaaa queries if ipv6 blocking is enabled
        if self.block_ipv6.load(Ordering::Relaxed) && !self.dns64.load(Ordering::Relaxed) && is_aaaa_query(query_data) {
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
            let rcode = if cached_resp.len() >= 4 {
                cached_resp[3] & 0x0F
            } else {
                0
            };
            let status = if rcode == 3 {
                QueryStatus::NxDomain
            } else {
                QueryStatus::CacheHit
            };
            self.maybe_log_query(
                client_ip,
                &domain,
                qtype,
                status,
                start_time,
                Some("cache_0ms"),
            );
            return Some(cached_resp);
        }

        // 10. prepare outgoing query with RFC 8467 EDNS Padding, RFC 7871 ECS, and DNSSEC DO-bit
        self.stats.upstream_queries.fetch_add(1, Ordering::Relaxed);
        let is_padding = self.edns_padding.load(Ordering::Relaxed);
        let is_dnssec = self.dnssec.load(Ordering::Relaxed);
        let is_random_ecs = self.randomize_ecs.load(Ordering::Relaxed);
        let outgoing_query = if is_padding || self.edns_client_subnet.is_some() || is_random_ecs {
            let random_subnet;
            let default_zero = ClientSubnet::zero_scope();
            let effective_ecs = if is_random_ecs {
                random_subnet = ClientSubnet::random_prefix();
                &random_subnet
            } else {
                self.edns_client_subnet.as_ref().unwrap_or(&default_zero)
            };
            apply_edns_options_with_ecs(
                query_data,
                is_dnssec,
                is_padding,
                Some(effective_ecs),
            )
        } else if is_dnssec {
            enable_dnssec_do(query_data)
        } else {
            query_data.to_vec()
        };

        let qm = self.query_meta.read().unwrap_or_else(|p| p.into_inner()).clone();
        let outgoing_query = if !qm.is_empty() {
            inject_query_meta(&outgoing_query, &qm)
        } else {
            outgoing_query
        };

        if self.offline_mode.load(Ordering::Relaxed) {
            debug!(domain = %domain, "Offline mode enabled: refusing query without upstream network access");
            self.maybe_log_query(
                client_ip,
                &domain,
                qtype,
                QueryStatus::Refused,
                start_time,
                Some("offline_mode"),
            );
            return Some(build_refused_response(query_data));
        }

        match self.resolve_upstream(&outgoing_query).await {
            Ok((mut resp_bytes, via)) => {
                // Ensure wire response transaction ID strictly matches client query ID (RFC 1035)
                if resp_bytes.len() >= 2 && query_data.len() >= 2 {
                    resp_bytes[0] = query_data[0];
                    resp_bytes[1] = query_data[1];
                }

                // Anti-DNS-Rebinding validation
                if self.anti_dns_rebinding.load(Ordering::Relaxed) {
                    if let Some(private_ip) = detect_dns_rebinding(&resp_bytes) {
                        warn!(
                            domain = ?query_key.as_ref().map(|k| &k.name),
                            private_ip = %private_ip,
                            "Anti-DNS-Rebinding triggered: public response resolved to private IP! Blocking response."
                        );
                        self.stats.rebinding_drops.fetch_add(1, Ordering::Relaxed);
                        self.stats.blocked_rebinding.fetch_add(1, Ordering::Relaxed);
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

                // Stateful Anti-Injection filter (middlebox poisoning detection)
                if let Some(ref anti_inj) = self.anti_injection {
                    let ips = extract_resolved_ips(&resp_bytes);
                    if !ips.is_empty() {
                        let verdict = anti_inj.inspect_dns_response(&domain, &ips);
                        if let crate::core::anti_injection::InjectionVerdict::DropInjectedDns(reason) = verdict {
                            warn!(
                                domain = %domain,
                                reason = %reason,
                                "Censor-injected DNS response detected and dropped by Anti-Injection filter"
                            );
                            self.stats.injected_dns_dropped.fetch_add(1, Ordering::Relaxed);
                            self.maybe_log_query(
                                client_ip,
                                &domain,
                                qtype,
                                QueryStatus::Refused,
                                start_time,
                                Some("anti_injection_drop"),
                            );
                            return Some(build_refused_response(query_data));
                        }
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
                        self.stats.blocked_bogon.fetch_add(1, Ordering::Relaxed);
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
                if self.uncloak_cnames.load(Ordering::Relaxed) && !is_whitelisted {
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
                                 let blocked_strategy = self.blocked_query_response.read().unwrap_or_else(|p| p.into_inner()).clone();
                                return Some(build_blocked_response(query_data, qtype, &blocked_strategy, self.reject_ttl.load(Ordering::Relaxed)));
                            }
                        }
                    }
                }

                // DNS64 IPv6 synthesis for IPv4-only domains (RFC 6052 / RFC 6147)
                if self.dns64.load(Ordering::Relaxed) {
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

                let is_ad = is_dnssec_authenticated(&resp_bytes);
                if self.dnssec.load(Ordering::Relaxed) {
                    let dnssec_report = crate::dns::dnssec::inspect_response_dnssec(&resp_bytes);
                    if dnssec_report.authenticated {
                        self.stats.dnssec_validated.fetch_add(1, Ordering::Relaxed);
                    }
                    if dnssec_report.has_pqc_rrsig && dnssec_report.authenticated {
                        self.stats.pqc_dnssec_validated.fetch_add(1, Ordering::Relaxed);
                    }
                    if self.pqc.load(Ordering::Relaxed) {
                        if let Err(downgrade_err) = crate::dns::dnssec::check_anti_downgrade(&dnssec_report) {
                            warn!(
                                domain = %domain,
                                violation = %downgrade_err,
                                "Anti-downgrade policy triggered: returning SERVFAIL"
                            );
                            self.stats.pqc_downgrade_prevented.fetch_add(1, Ordering::Relaxed);
                            self.maybe_log_query(
                                client_ip,
                                &domain,
                                qtype,
                                QueryStatus::PqcDowngradeDrop,
                                start_time,
                                Some("anti_downgrade_pqc"),
                            );
                            return Some(build_servfail_response(query_data));
                        }
                    }
                } else if resp_bytes.len() >= 4 {
                    // RFC 6840 Section 5.7: If local DNSSEC validation is not enabled, clear AD bit
                    resp_bytes[3] &= !0x20;
                }

                // insert response into cache (supports negative caching and serve-stale)
                self.cache.insert(query_data, &resp_bytes);
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

                let rcode = if resp_bytes.len() >= 4 {
                    resp_bytes[3] & 0x0F
                } else {
                    0
                };
                let status = if rcode == 3 {
                    QueryStatus::NxDomain
                } else {
                    QueryStatus::Pass
                };

                self.maybe_log_query(client_ip, &domain, qtype, status, start_time, Some(&via));
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

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
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

/// Injects DNSCrypt-compatible query_meta TXT resource record to the Additional records section.
pub fn inject_query_meta(query: &[u8], query_meta: &[String]) -> Vec<u8> {
    if query.len() < 12 || query_meta.is_empty() {
        return query.to_vec();
    }

    let mut out = query.to_vec();
    let arcount = ((out[10] as u16) << 8) | (out[11] as u16);
    let new_arcount = arcount.saturating_add(1);
    out[10] = (new_arcount >> 8) as u8;
    out[11] = (new_arcount & 0xff) as u8;

    // Root domain (".")
    out.push(0x00);
    // Type: TXT (16 = 0x0010)
    out.extend_from_slice(&16u16.to_be_bytes());
    // Class: IN (1 = 0x0001)
    out.extend_from_slice(&1u16.to_be_bytes());
    // TTL: 86400 (0x00015180)
    out.extend_from_slice(&86400u32.to_be_bytes());

    // Build RDATA: sequence of length-prefixed strings
    let mut rdata = Vec::new();
    for meta in query_meta {
        let bytes = meta.as_bytes();
        let chunk_len = bytes.len().min(255) as u8;
        rdata.push(chunk_len);
        rdata.extend_from_slice(&bytes[..chunk_len as usize]);
    }

    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);

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
async fn run_active_canary_probe(target: SocketAddr) {
    let probe_res = tokio::time::timeout(std::time::Duration::from_millis(1500), async {
        let bind_local = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let sock = tokio::net::UdpSocket::bind(bind_local).await?;
        let query = build_canary_query();
        sock.send_to(&query, target).await?;

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

// calculates adaptive query timeout using quartic load reduction under concurrency
pub fn compute_adaptive_timeout(
    base_timeout: Duration,
    active_queries: u64,
    max_expected_queries: u64,
    load_reduction: f64,
) -> Duration {
    if load_reduction <= 0.0 {
        return base_timeout;
    }
    let ratio = (active_queries as f64 / max_expected_queries.max(1) as f64).clamp(0.0, 1.0);
    let reduction = ratio.powi(4) * load_reduction.clamp(0.0, 0.99);
    let factor = (1.0 - reduction).max(0.1);
    let effective_millis = (base_timeout.as_millis() as f64 * factor) as u64;
    Duration::from_millis(effective_millis.max(200))
}

/// Resolves matching anonymized relays from a routing matrix for a target server name.
/// Matches exact name (case-insensitive) first, then falls back to wildcard "*" if present.
pub fn resolve_anonymized_dns_routes(
    routes: &[crate::app::config::AnonymizedDnsRoute],
    server_name: &str,
) -> Vec<String> {
    let clean = server_name.trim().to_lowercase();
    // 1. Exact match
    for route in routes {
        if route.server_name.trim().to_lowercase() == clean {
            return route.via.clone();
        }
    }
    // 2. Wildcard fallback
    for route in routes {
        if route.server_name.trim() == "*" {
            return route.via.clone();
        }
    }
    Vec::new()
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

    #[test]
    fn test_load_adaptive_timeout() {
        let base = Duration::from_secs(5);

        // Disabled (load_reduction = 0.0) -> unchanged
        assert_eq!(compute_adaptive_timeout(base, 100, 200, 0.0), base);

        // Under 0 active queries -> unchanged
        assert_eq!(compute_adaptive_timeout(base, 0, 250, 0.75), base);

        // Under moderate load (half load: ratio = 0.5, 0.5^4 = 0.0625, reduction = 0.0625 * 0.75 = ~0.0468)
        let mid_timeout = compute_adaptive_timeout(base, 125, 250, 0.75);
        assert!(mid_timeout < base && mid_timeout > Duration::from_secs(4));

        // Under max load (250 active, ratio = 1.0, reduction = 0.75) -> 5s * 0.25 = 1.25s
        let max_timeout = compute_adaptive_timeout(base, 250, 250, 0.75);
        assert_eq!(max_timeout, Duration::from_millis(1250));

        // Extreme load saturation clamp
        let extreme_timeout = compute_adaptive_timeout(base, 500, 250, 0.75);
        assert_eq!(extreme_timeout, Duration::from_millis(1250));
    }

    #[test]
    fn test_dns_server_post_quantum_dnssec_and_anti_downgrade() {
        use crate::dns::dnssec::{check_anti_downgrade, inspect_response_dnssec, DowngradeViolation};
        use std::sync::atomic::Ordering;

        let stats = Arc::new(DnsStats::default());

        // 1. Valid Post-Quantum DNSSEC response (ML-DSA-44 / Algorithm 18)
        let mut valid_pqc_resp = vec![
            0x12, 0x34, // ID
            0x81, 0xA0, // QR=1, RD=1, RA=1, AD=1 (authenticated)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x02, // ANCOUNT = 2 (A record + RRSIG)
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: example.com IN A
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // Answer 1: A record
            0xC0, 0x0C, // Name pointer
            0x00, 0x01, 0x00, 0x01, // Type A, Class IN
            0x00, 0x00, 0x01, 0x2C, // TTL = 300
            0x00, 0x04, 93, 184, 216, 34, // RDATA IP
            // Answer 2: RRSIG record with ML-DSA-44 (18)
            0xC0, 0x0C, // Name pointer
            0x00, 0x2E, 0x00, 0x01, // Type RRSIG (46), Class IN
            0x00, 0x00, 0x01, 0x2C, // TTL = 300
        ];
        // RRSIG RDATA:
        let mut rrsig_rdata = Vec::new();
        rrsig_rdata.extend_from_slice(&1u16.to_be_bytes()); // Type Covered = A
        rrsig_rdata.push(18); // Algorithm = ML-DSA-44
        rrsig_rdata.push(2); // Labels = 2
        rrsig_rdata.extend_from_slice(&300u32.to_be_bytes()); // Original TTL
        rrsig_rdata.extend_from_slice(&1789166009u32.to_be_bytes()); // Expiration
        rrsig_rdata.extend_from_slice(&1789076009u32.to_be_bytes()); // Inception
        rrsig_rdata.extend_from_slice(&1234u16.to_be_bytes()); // Key Tag
        rrsig_rdata.extend_from_slice(b"\x07example\x03com\x00"); // Signer name uncompressed
        rrsig_rdata.extend_from_slice(&vec![0xAA; 2420]); // 2,420 byte signature

        valid_pqc_resp.extend_from_slice(&(rrsig_rdata.len() as u16).to_be_bytes());
        valid_pqc_resp.extend_from_slice(&rrsig_rdata);

        // Verify report and stats increment
        let report = inspect_response_dnssec(&valid_pqc_resp);
        assert!(report.authenticated);
        assert!(report.has_pqc_rrsig);
        assert!(check_anti_downgrade(&report).is_ok());

        if report.authenticated {
            stats.dnssec_validated.fetch_add(1, Ordering::Relaxed);
        }
        if report.has_pqc_rrsig && report.authenticated {
            stats.pqc_dnssec_validated.fetch_add(1, Ordering::Relaxed);
        }

        assert_eq!(stats.dnssec_validated.load(Ordering::Relaxed), 1);
        assert_eq!(stats.pqc_dnssec_validated.load(Ordering::Relaxed), 1);
        assert_eq!(stats.pqc_downgrade_prevented.load(Ordering::Relaxed), 0);

        // 2. Downgraded response: Parent DS signals ML-DSA-44 (18), but adversary stripped PQC signature
        let mut downgraded_resp = vec![
            0x12, 0x34, // ID
            0x81, 0xA0, // QR=1, RD=1, RA=1, AD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1 (A only, no PQC RRSIG)
            0x00, 0x01, // NSCOUNT = 1 (DS record in authority)
            0x00, 0x00, // ARCOUNT = 0
            // Question: example.com IN A
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // Answer 1: A record
            0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x01, 0x2C,
            0x00, 0x04, 93, 184, 216, 34,
            // Authority 1: DS record signaling Algorithm 18
            0xC0, 0x0C,
            0x00, 0x2B, 0x00, 0x01, // Type DS (43), Class IN
            0x00, 0x00, 0x01, 0x2C,
            0x00, 0x24, // RDLENGTH = 36
            0x04, 0xD2, // Key Tag = 1234
            18, // Algorithm = ML-DSA-44
            2,  // Digest Type = SHA-256
        ];
        downgraded_resp.extend_from_slice(&[0xBB; 32]); // SHA-256 digest

        let downgraded_report = inspect_response_dnssec(&downgraded_resp);
        assert!(downgraded_report.has_pqc_ds_signal);
        assert!(!downgraded_report.has_pqc_rrsig);

        let check_res = check_anti_downgrade(&downgraded_report);
        assert_eq!(check_res, Err(DowngradeViolation::PqcSignatureStripped));

        // When downgrade is detected:
        stats.pqc_downgrade_prevented.fetch_add(1, Ordering::Relaxed);
        let servfail = build_servfail_response(&downgraded_resp);
        assert_eq!(servfail[3] & 0x0F, 0x02); // RCODE = 2 (SERVFAIL)
        assert_eq!(stats.pqc_downgrade_prevented.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_inject_query_meta() {
        let base_query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];

        let meta = vec!["token:SecretValue123".to_string(), "user:alice".to_string()];
        let with_meta = inject_query_meta(&base_query, &meta);

        assert!(with_meta.len() > base_query.len());
        // ARCOUNT must be 1
        assert_eq!(with_meta[10], 0x00);
        assert_eq!(with_meta[11], 0x01);

        // Verify TXT record content: contains root "." (0x00) and type TXT (0x0010)
        let tail = &with_meta[base_query.len()..];
        assert_eq!(tail[0], 0x00); // Root name "."
        assert_eq!(&tail[1..3], &16u16.to_be_bytes()); // Type TXT
        assert_eq!(&tail[3..5], &1u16.to_be_bytes()); // Class IN
        assert_eq!(&tail[5..9], &86400u32.to_be_bytes()); // TTL 86400
        assert!(tail.windows("token:SecretValue123".len()).any(|w| w == b"token:SecretValue123"));
        assert!(tail.windows("user:alice".len()).any(|w| w == b"user:alice"));
    }

    #[test]
    fn test_with_listen_addresses() {
        let server = DnsServer::with_defaults("https://cloudflare-dns.com/dns-query", &[], false, false, false)
            .unwrap();
        assert_eq!(server.listen_addresses, vec!["127.0.0.1:53".parse::<SocketAddr>().unwrap()]);

        let custom_addrs = vec![
            "127.0.0.1:5353".parse::<SocketAddr>().unwrap(),
            "127.0.0.2:53".parse::<SocketAddr>().unwrap(),
        ];
        let server_custom = server.with_listen_addresses(custom_addrs.clone());
        assert_eq!(server_custom.listen_addresses, custom_addrs);
    }

    #[tokio::test]
    async fn test_dns_server_http3_configuration() {
        let server = DnsServer::new(
            "https://cloudflare-dns.com/dns-query",
            &[],
            false,
            false,
            false,
            true, // http3 = true
            false,
            false,
            false,
            false,
            Arc::new(CloakEngine::new()),
            Arc::new(RwLock::new(build_seed_blocklist())),
            Arc::new(RwLock::new(DomainAllowlist::new())),
            Arc::new(IpFilter::default()),
            false,
            false,
            false,
            DnsStats::new(),
            false,
            false,
            "127.0.0.1:8053".parse().unwrap(),
            None,
            None,
            None,
            None,
            None,
            Arc::new(RwLock::new(ScheduleManager::new())),
            None,
            false,
            "127.0.0.1:9153".parse().unwrap(),
            None,
            Arc::new(RwLock::new(ForwardingEngine::new())),
            None,
            None,
            0.0,
            60,
            600,
            60,
            86400,
            false,
            Arc::new(CaptiveMap::new()),
        )
        .unwrap();

        assert!(server.is_http3());
        assert!(server.resolver.read().await.clients()[0].http3);
    }

    #[tokio::test]
    async fn test_safesearch_and_youtube_resolution_interception() {
        let safesearch = Arc::new(crate::dns::SafeSearchEngine::new(
            true,
            crate::dns::YouTubeMode::Strict,
        ));

        let server = DnsServer::new(
            "https://cloudflare-dns.com/dns-query",
            &[],
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            Arc::new(CloakEngine::new()),
            Arc::new(RwLock::new(CompactBlocklist::empty())),
            Arc::new(RwLock::new(DomainAllowlist::new())),
            Arc::new(IpFilter::default()),
            false,
            false,
            false,
            DnsStats::new(),
            false,
            false,
            "127.0.0.1:8053".parse().unwrap(),
            None,
            None,
            None,
            None,
            None,
            Arc::new(RwLock::new(ScheduleManager::new())),
            None,
            false,
            "127.0.0.1:9153".parse().unwrap(),
            None,
            Arc::new(RwLock::new(ForwardingEngine::new())),
            None,
            None,
            0.0,
            60,
            600,
            60,
            86400,
            false,
            Arc::new(CaptiveMap::new()),
        )
        .unwrap()
        .with_safesearch(safesearch);

        // Test Google SafeSearch A query interception
        let google_query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        let resp = server
            .resolve_packet(&google_query, "127.0.0.1".parse().unwrap())
            .await
            .expect("should return safesearch response");
        // Check Google SafeSearch VIP 216.239.38.120
        assert!(resp.windows(4).any(|w| w == [216, 239, 38, 120]));

        // Test YouTube Strict Mode A query interception (VIP 216.239.38.119)
        let yt_query = vec![
            0x56, 0x78, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'y', b'o', b'u', b't', b'u', b'b', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        let yt_resp = server
            .resolve_packet(&yt_query, "127.0.0.1".parse().unwrap())
            .await
            .expect("should return youtube strict response");
        assert!(yt_resp.windows(4).any(|w| w == [216, 239, 38, 119]));
    }

    #[test]
    fn test_anonymized_dns_routing_matrix() {
        use crate::app::config::AnonymizedDnsRoute;

        let routes = vec![
            AnonymizedDnsRoute {
                server_name: "cloudflare".to_string(),
                via: vec!["anon-de".to_string(), "anon-nl".to_string()],
            },
            AnonymizedDnsRoute {
                server_name: "quad9".to_string(),
                via: vec!["anon-ch".to_string()],
            },
            AnonymizedDnsRoute {
                server_name: "*".to_string(),
                via: vec!["anon-fallback".to_string()],
            },
        ];

        // Exact match
        assert_eq!(
            resolve_anonymized_dns_routes(&routes, "cloudflare"),
            vec!["anon-de", "anon-nl"]
        );
        assert_eq!(
            resolve_anonymized_dns_routes(&routes, "Cloudflare"),
            vec!["anon-de", "anon-nl"]
        );
        assert_eq!(
            resolve_anonymized_dns_routes(&routes, "quad9"),
            vec!["anon-ch"]
        );

        // Wildcard match
        assert_eq!(
            resolve_anonymized_dns_routes(&routes, "google"),
            vec!["anon-fallback"]
        );

        // No routes configured
        assert_eq!(
            resolve_anonymized_dns_routes(&[], "cloudflare"),
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn test_response_transaction_id_and_ad_bit_preservation() {
        let mut cloak = CloakEngine::new();
        cloak.add_cloak_rule("local.example", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let server = DnsServer::new(
            "cloudflare",
            &[],
            false,
            false, // DNSSEC disabled
            false,
            false,
            true,
            true,
            true,
            true,
            Arc::new(cloak),
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
            None,
            Arc::new(RwLock::new(ScheduleManager::new())),
            None,
            false,
            "127.0.0.1:9153".parse().unwrap(),
            None,
            Arc::new(RwLock::new(ForwardingEngine::new())),
            None,
            None,
            0.0,
            60,
            600,
            60,
            86400,
            false,
            Arc::new(CaptiveMap::new()),
        )
        .unwrap();

        // 1. Canary query with distinct transaction ID
        let canary_query = vec![
            0xDE, 0xAD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x09, b'l', b'e', b'a', b'k', b'-', b't', b'e', b's', b't',
            0x05, b'a', b'l', b'b', b'u', b's',
            0x08, b'i', b'n', b't', b'e', b'r', b'n', b'a', b'l', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        let resp = server
            .resolve_packet(&canary_query, "127.0.0.1".parse().unwrap())
            .await
            .expect("should return canary response");

        // Transaction ID must match query exactly (RFC 1035)
        assert_eq!(resp[0], 0xDE);
        assert_eq!(resp[1], 0xAD);
        // AD bit must be cleared because dnssec is disabled (RFC 6840)
        assert_eq!(resp[3] & 0x20, 0);

        // 2. Cloaked local query with different transaction ID
        let cloak_query = vec![
            0xBE, 0xEF, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x05, b'l', b'o', b'c', b'a', b'l',
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        let cloak_resp = server
            .resolve_packet(&cloak_query, "127.0.0.1".parse().unwrap())
            .await
            .expect("should return cloaked response");

        assert_eq!(cloak_resp[0], 0xBE);
        assert_eq!(cloak_resp[1], 0xEF);
        assert_eq!(cloak_resp[3] & 0x20, 0);
    }
}

