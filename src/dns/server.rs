//! udp listener on 127.0.0.1:53 forwarding to encrypted doh with dnssec and ipv6 aaaa filtering.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, error, info, warn};

use super::cache::DnsCache;
use super::doh::DoHResolver;

// local dns server instance wrapping doh client pool and response cache
pub struct DnsServer {
    resolver: DoHResolver,
    upstream_desc: String,
    block_ipv6: bool,
    dnssec: bool,
    pqc: bool,
    cache: Arc<DnsCache>,
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
        let resolver = self.resolver.clone();
        let cache = self.cache.clone();
        let ip_queue = self.ip_queue.clone();
        let block_ipv6 = self.block_ipv6;
        let dnssec = self.dnssec;
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        let mut canary_shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut tick_count: u64 = 0;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        tick_count = tick_count.wrapping_add(1);

                        // 1. Passive check: verify resolv.conf still directs queries to loopback
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

                        // 2. Active watchdog check: actively probe local resolver on 127.0.0.1:53 every 60s
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

        const MAX_CONCURRENT_DNS_TASKS: usize = 512;
        const MAX_IP_QUEUE_ENTRIES: usize = 4096;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DNS_TASKS));

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];

            loop {
                tokio::select! {
                    recv_res = socket.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((len, peer_addr)) => {
                                let query_data = buf[..len].to_vec();
                                let socket_clone = socket.clone();
                                let resolver_clone = resolver.clone();
                                let cache_clone = cache.clone();
                                let ip_queue_clone = ip_queue.clone();
                                let sem_clone = semaphore.clone();

                                tokio::spawn(async move {
                                    // shed load under flooding attacks to prevent unbounded task/socket spawning
                                    let _permit = match sem_clone.try_acquire() {
                                        Ok(permit) => permit,
                                        Err(_) => {
                                            if query_data.len() >= 4 {
                                                let mut fail_resp = query_data.clone();
                                                fail_resp[2] |= 0x80;
                                                fail_resp[3] = (fail_resp[3] & 0xF0) | 0x02; // SERVFAIL
                                                let _ = socket_clone.send_to(&fail_resp, peer_addr).await;
                                            }
                                            return;
                                        }
                                    };

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
                                            // insert response into cache
                                            cache_clone.insert(&query_data, &resp_bytes);

                                            let is_ad = is_dnssec_authenticated(&resp_bytes);
                                            if let Some((domain, ips)) = parse_dns_response(&resp_bytes) {
                                                if !ips.is_empty() {
                                                    debug!(
                                                        domain = %domain,
                                                        ips = ?ips,
                                                        via = %via,
                                                        dnssec_authenticated = is_ad,
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
            0x00,
            0x00, 0x29, // type: opt (41)
            0x10, 0x00, // payload size: 4096
            0x00,       // extended rcode
            0x00,       // edns version
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
    }).await;

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
            warn!("Active DNS Leak Canary probe network error ({}). Auto-healing system DNS...", e);
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
        let server = DnsServer::new("cloudflare", &[], true, true, true).unwrap();
        let test_ip = Ipv4Addr::new(10, 0, 0, 1);

        {
            let mut map = server.ip_queue.lock().await;
            let q = map.entry(test_ip).or_default();
            q.push_back("first.com".to_string());
            q.push_back("second.com".to_string());
        }

        assert_eq!(server.pop_domain(test_ip).await, Some("first.com".to_string()));
        assert_eq!(server.pop_domain(test_ip).await, Some("second.com".to_string()));
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
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,       // end of name
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
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01,
            0x00, 0x01,
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
}
