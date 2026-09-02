//! udp listener on 127.0.0.1:53 forwarding to encrypted doh with dnssec and ipv6 aaaa filtering.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, error, info};

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

                                tokio::spawn(async move {
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
}
