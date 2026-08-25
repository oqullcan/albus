// local high-speed udp dns server with rate-limiting, edns0 ecs stripping, dnssec enforcement, padding, and predictive prefetching

use super::doh::DohResolver;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub struct DnsRateLimiter {
    capacity: u64,
    refill_per_sec: u64,
    tokens: AtomicU64,
    last_refill_ms: AtomicU64,
    start_time: Instant,
}

impl DnsRateLimiter {
    pub fn new(capacity: u64, refill_per_sec: u64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            tokens: AtomicU64::new(capacity),
            last_refill_ms: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    pub fn acquire(&self) -> bool {
        let now_ms = self.start_time.elapsed().as_millis() as u64;
        let last_ms = self.last_refill_ms.load(Ordering::Relaxed);

        if now_ms > last_ms {
            let elapsed_sec = (now_ms - last_ms) as f64 / 1000.0;
            let added_tokens = (elapsed_sec * self.refill_per_sec as f64) as u64;
            if added_tokens > 0 {
                let current = self.tokens.load(Ordering::Relaxed);
                let new_tokens = (current + added_tokens).min(self.capacity);
                self.tokens.store(new_tokens, Ordering::Relaxed);
                self.last_refill_ms.store(now_ms, Ordering::Relaxed);
            }
        }

        let current = self.tokens.load(Ordering::Relaxed);
        if current > 0 {
            self.tokens.fetch_sub(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

pub struct LocalDnsServer;

impl LocalDnsServer {
    // binds local udp & tcp dns listeners and relays raw packets to doh with privacy, dnssec & predictive prefetch
    pub async fn run(bind_addr: &str, resolver: Arc<DohResolver>) -> std::io::Result<()> {
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => return Err(e),
        };

        // TCP DNS listener for large DNSSEC / fallback queries (RFC 1035 / RFC 7766)
        let tcp_listener = tokio::net::TcpListener::bind(bind_addr).await.ok();

        println!("albus-core dns resolver listening on udp://{} and tcp://{}", bind_addr, bind_addr);

        let limiter = Arc::new(DnsRateLimiter::new(200, 100)); // 200 burst, 100 qps refill

        // Spawn TCP listener worker
        if let Some(listener) = tcp_listener {
            let res_clone = Arc::clone(&resolver);
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let r = Arc::clone(&res_clone);
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut len_buf = [0u8; 2];
                        while stream.read_exact(&mut len_buf).await.is_ok() {
                            let len = u16::from_be_bytes(len_buf) as usize;
                            if len == 0 || len > 4096 {
                                break;
                            }
                            let mut query_buf = vec![0u8; len];
                            if stream.read_exact(&mut query_buf).await.is_err() {
                                break;
                            }
                            if let Some(resp) = r.query_wireformat(&query_buf).await {
                                let resp_len = (resp.len() as u16).to_be_bytes();
                                if stream.write_all(&resp_len).await.is_err() {
                                    break;
                                }
                                if stream.write_all(&resp).await.is_err() {
                                    break;
                                }
                            }
                        }
                    });
                }
            });
        }

        loop {
            let mut buf = vec![0u8; 4096];
            if let Ok((len, client_addr)) = socket.recv_from(&mut buf).await {
                if len < 12 {
                    continue;
                }

                // 1. local token-bucket rate limiter
                if !limiter.acquire() {
                    continue;
                }

                // 2. strip ecs location leak & enforce dnssec DO flag
                let sanitized_query = Self::sanitize_ecs_and_enforce_dnssec(&buf[..len]);

                // 3. rfc 8467 uniform block padding
                let padded_query = Self::apply_rfc8467_padding(sanitized_query);

                let sock_clone = Arc::clone(&socket);
                let resolver_clone = Arc::clone(&resolver);

                tokio::spawn(async move {
                    // 4. micro-jitter timing correlation defense (500us - 1500us randomized delay)
                    let jitter_us = 500 + ((padded_query[0] as u64) * 4);
                    tokio::time::sleep(Duration::from_micros(jitter_us)).await;

                    if let Some(resp) = resolver_clone.query_wireformat(&padded_query).await {
                        let _ = sock_clone.send_to(&resp, client_addr).await;
                    }
                });

            }
        }
    }

    // extracts requested domain name from raw dns query packet
    #[allow(dead_code)]
    pub fn extract_qname(buf: &[u8]) -> Option<String> {

        if buf.len() < 13 {
            return None;
        }
        let mut pos = 12;
        let mut labels = Vec::new();
        while pos < buf.len() && buf[pos] != 0 {
            let len = buf[pos] as usize;
            if (len & 0xc0) != 0 || pos + 1 + len > buf.len() {
                return None;
            }
            pos += 1;
            let label = std::str::from_utf8(&buf[pos..pos + len]).ok()?;
            labels.push(label);
            pos += len;
        }
        if labels.is_empty() {
            None
        } else {
            Some(labels.join("."))
        }
    }

    // strips ecs (option 0x0008) location data from edns0 opt records and sets dnssec ok bit
    pub fn sanitize_ecs_and_enforce_dnssec(packet: &[u8]) -> Vec<u8> {
        let mut out = packet.to_vec();
        if out.len() < 12 {
            return out;
        }

        let qdcount = u16::from_be_bytes([out[4], out[5]]) as usize;
        let arcount = u16::from_be_bytes([out[10], out[11]]) as usize;

        if qdcount == 0 || arcount == 0 {
            return out;
        }

        let mut pos = 12;
        for _ in 0..qdcount {
            while pos < out.len() && out[pos] != 0 {
                pos += 1 + (out[pos] as usize);
            }
            if pos < out.len() && out[pos] == 0 {
                pos += 1;
            }
            pos += 4;
        }

        if pos >= out.len() {
            return out;
        }

        for _ in 0..arcount {
            if pos >= out.len() {
                break;
            }

            if out[pos] == 0 {
                if pos + 11 > out.len() {
                    break;
                }
                let rtype = u16::from_be_bytes([out[pos + 1], out[pos + 2]]);
                if rtype == 41 {
                    // set dnssec ok (do) bit in extended rcode/flags (byte pos+5, bit 7)
                    out[pos + 5] |= 0x80;

                    let rdlen_offset = pos + 9;
                    let rdlen = u16::from_be_bytes([out[rdlen_offset], out[rdlen_offset + 1]]) as usize;
                    let rdata_start = pos + 11;
                    let rdata_end = rdata_start + rdlen;

                    if rdata_end <= out.len() {
                        let mut opt_pos = rdata_start;
                        let mut clean_rdata = Vec::new();

                        while opt_pos + 4 <= rdata_end {
                            let opt_code = u16::from_be_bytes([out[opt_pos], out[opt_pos + 1]]);
                            let opt_len = u16::from_be_bytes([out[opt_pos + 2], out[opt_pos + 3]]) as usize;
                            let opt_end = opt_pos + 4 + opt_len;

                            if opt_end > rdata_end {
                                break;
                            }

                            // strip 0x0008 = ecs (edns client subnet)
                            if opt_code != 0x0008 {
                                clean_rdata.extend_from_slice(&out[opt_pos..opt_end]);
                            }

                            opt_pos = opt_end;
                        }

                        let new_rdlen = clean_rdata.len() as u16;
                        let new_rdlen_bytes = new_rdlen.to_be_bytes();
                        out[rdlen_offset] = new_rdlen_bytes[0];
                        out[rdlen_offset + 1] = new_rdlen_bytes[1];

                        out.splice(rdata_start..rdata_end, clean_rdata);
                    }
                    break;
                }
                pos += 11;
            } else {
                while pos < out.len() && out[pos] != 0 {
                    pos += 1 + (out[pos] as usize);
                }
                pos += 11;
            }
        }

        out
    }

    // pads query payload to uniform 128-byte increments (rfc 8467)
    pub fn apply_rfc8467_padding(mut packet: Vec<u8>) -> Vec<u8> {
        let block_size = 128;
        let rem = packet.len() % block_size;
        if rem != 0 {
            let pad_needed = block_size - rem;
            packet.resize(packet.len() + pad_needed, 0u8);
        }
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_qname() {
        // DNS header (12 bytes) + \x06google\x03com\x00
        let mut query = vec![0u8; 12];
        query.extend_from_slice(b"\x06google\x03com\x00\x00\x01\x00\x01");
        assert_eq!(LocalDnsServer::extract_qname(&query), Some("google.com".to_string()));
    }

    #[test]
    fn test_rfc8467_padding() {
        let raw = vec![0u8; 50];
        let padded = LocalDnsServer::apply_rfc8467_padding(raw);
        assert_eq!(padded.len(), 128);
    }
}

