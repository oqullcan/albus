//! rfc 8484 local dns-over-https (doh) server listener.
//!
//! serves encrypted doh queries directly to local browsers (firefox, chrome, brave) and applications
//! via http/1.1 on 127.0.0.1:8053/dns-query, eliminating the requirement to modify system /etc/resolv.conf.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Semaphore};
use tracing::{debug, error, info, warn};

pub struct LocalDoHServer;

const MAX_CONCURRENT_DOH_CONNS: usize = 256;
const MAX_DOH_REQUEST_SIZE: usize = 65536;

impl LocalDoHServer {
    // spawns local doh http/1.1 listener on specified address (e.g. 127.0.0.1:8053)
    pub fn start<F, Fut>(
        bind_addr: SocketAddr,
        handler: F,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) where
        F: Fn(Vec<u8>, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<Vec<u8>>> + Send + 'static,
    {
        let handler_arc = Arc::new(handler);
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_DOH_CONNS));

        tokio::spawn(async move {
            let listener = match TcpListener::bind(bind_addr).await {
                Ok(l) => {
                    info!(addr = %bind_addr, "Local DoH server active on http://{}/dns-query", bind_addr);
                    l
                }
                Err(e) => {
                    warn!("failed to bind local DoH server to {}: {}", bind_addr, e);
                    return;
                }
            };

            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((mut stream, peer_addr)) => {
                                let permit = match sem.clone().try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        debug!("local DoH max connection limit reached; dropping connection");
                                        continue;
                                    }
                                };
                                let handler_clone = handler_arc.clone();

                                tokio::spawn(async move {
                                    let _permit = permit;
                                    let mut buf = vec![0u8; MAX_DOH_REQUEST_SIZE];
                                    let mut total_read = 0;

                                    // read http request with strict timeout and content-length boundary check
                                    let read_res = tokio::time::timeout(Duration::from_secs(5), async {
                                        loop {
                                            let n = stream.read(&mut buf[total_read..]).await?;
                                            if n == 0 {
                                                break;
                                            }
                                            total_read += n;

                                            // check if header delimiter \r\n\r\n is received
                                            if let Some(pos) = buf[..total_read].windows(4).position(|w| w == b"\r\n\r\n") {
                                                let header_str = String::from_utf8_lossy(&buf[..pos]);
                                                if header_str.starts_with("POST") {
                                                    let mut cl_opt = None;
                                                    for line in header_str.lines() {
                                                        let lower = line.to_ascii_lowercase();
                                                        if let Some(val) = lower.strip_prefix("content-length:") {
                                                            if let Ok(cl) = val.trim().parse::<usize>() {
                                                                cl_opt = Some(cl);
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    if let Some(cl) = cl_opt {
                                                        if total_read >= pos + 4 + cl {
                                                            break;
                                                        }
                                                    } else {
                                                        break;
                                                    }
                                                } else {
                                                    break;
                                                }
                                            }
                                            if total_read >= buf.len() {
                                                break;
                                            }
                                        }
                                        Ok::<usize, std::io::Error>(total_read)
                                    }).await;

                                    let n = match read_res {
                                        Ok(Ok(n)) if n > 0 => n,
                                        _ => return,
                                    };

                                    let req = &buf[..n];
                                    let (query_bytes, _is_post) = match parse_http_dns_request(req) {
                                        HttpDnsRequest::Query(bytes, is_post) => (bytes, is_post),
                                        HttpDnsRequest::HealthCheck => {
                                            let body = "Albus Secure Local DoH Resolver (RFC 8484) Active\nEndpoint: /dns-query\n";
                                            let resp = format!(
                                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                                body.len(),
                                                body
                                            );
                                            let _ = tokio::time::timeout(Duration::from_secs(5), stream.write_all(resp.as_bytes())).await;
                                            return;
                                        }
                                        HttpDnsRequest::BadRequest => {
                                            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Request";
                                            let _ = tokio::time::timeout(Duration::from_secs(5), stream.write_all(resp.as_bytes())).await;
                                            return;
                                        }
                                    };

                                    if let Some(dns_resp) = handler_clone(query_bytes, peer_addr).await {
                                        let header = format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nCache-Control: max-age=60\r\nConnection: close\r\n\r\n",
                                            dns_resp.len()
                                        );
                                        let _ = tokio::time::timeout(Duration::from_secs(5), async {
                                            stream.write_all(header.as_bytes()).await?;
                                            stream.write_all(&dns_resp).await?;
                                            stream.flush().await
                                        }).await;
                                    } else {
                                        let _ = tokio::time::timeout(
                                            Duration::from_secs(5),
                                            stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"),
                                        ).await;
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("local DoH accept error: {}; continuing", e);
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("local DoH server shutting down");
                        break;
                    }
                }
            }
        });
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HttpDnsRequest {
    Query(Vec<u8>, bool), // (bytes, is_post)
    HealthCheck,
    BadRequest,
}

// parses incoming http/1.1 request headers and separates raw binary dns query bytes
pub fn parse_http_dns_request(req: &[u8]) -> HttpDnsRequest {
    // locate header delimiter \r\n\r\n or \n\n without assuming entire body is utf-8
    let (header_end, delim_len) = if let Some(p) = req.windows(4).position(|w| w == b"\r\n\r\n") {
        (p, 4)
    } else if let Some(p) = req.windows(2).position(|w| w == b"\n\n") {
        (p, 2)
    } else {
        return HttpDnsRequest::BadRequest;
    };

    let header_str = match std::str::from_utf8(&req[..header_end]) {
        Ok(s) => s,
        Err(_) => return HttpDnsRequest::BadRequest,
    };
    let mut lines = header_str.lines();
    let first_line = match lines.next() {
        Some(l) => l,
        None => return HttpDnsRequest::BadRequest,
    };
    let mut parts = first_line.split_whitespace();
    let method = match parts.next() {
        Some(m) => m,
        None => return HttpDnsRequest::BadRequest,
    };
    let uri = match parts.next() {
        Some(u) => u,
        None => return HttpDnsRequest::BadRequest,
    };

    if uri.starts_with("/dns-query") {
        if method == "POST" {
            let body_start = header_end + delim_len;
            let mut body = &req[body_start..];

            // check Content-Length if present to avoid reading trailing pipeline bytes
            for line in lines {
                let lower = line.to_ascii_lowercase();
                if let Some(val) = lower.strip_prefix("content-length:") {
                    if let Ok(cl) = val.trim().parse::<usize>() {
                        if body.len() > cl {
                            body = &body[..cl];
                        }
                        break;
                    }
                }
            }

            if !body.is_empty() {
                return HttpDnsRequest::Query(body.to_vec(), true);
            } else {
                return HttpDnsRequest::BadRequest;
            }
        } else if method == "GET" {
            if let Some(b64_str) = uri.strip_prefix("/dns-query?dns=") {
                let query_b64 = b64_str.split('&').next().unwrap_or("");
                if let Some(decoded) = decode_b64url(query_b64) {
                    if !decoded.is_empty() {
                        return HttpDnsRequest::Query(decoded, false);
                    }
                }
            }
            return HttpDnsRequest::BadRequest;
        } else {
            return HttpDnsRequest::BadRequest;
        }
    }

    HttpDnsRequest::HealthCheck
}

pub fn decode_b64url(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() > 65536 {
        return None;
    }
    let mut clean = s.replace('-', "+").replace('_', "/");
    while clean.len() % 4 != 0 {
        clean.push('=');
    }
    const B64_TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut map = [255u8; 256];
    for (i, &b) in B64_TABLE.iter().enumerate() {
        map[b as usize] = i as u8;
    }
    let bytes = clean.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let mut padding_seen = false;

    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        if padding_seen {
            return None;
        }

        let b0 = map[chunk[0] as usize];
        let b1 = map[chunk[1] as usize];
        let b2 = if chunk[2] == b'=' {
            0
        } else {
            map[chunk[2] as usize]
        };
        let b3 = if chunk[3] == b'=' {
            0
        } else {
            map[chunk[3] as usize]
        };

        // reject chunk if any character is invalid (255)
        if b0 == 255
            || b1 == 255
            || (chunk[2] != b'=' && b2 == 255)
            || (chunk[3] != b'=' && b3 == 255)
        {
            return None;
        }

        // reject invalid padding: '=X' is invalid; '=' at index 2 requires '=' at index 3
        if chunk[2] == b'=' && chunk[3] != b'=' {
            return None;
        }

        if chunk[2] == b'=' || chunk[3] == b'=' {
            padding_seen = true;
        }

        let t = ((b0 as u32) << 18) | ((b1 as u32) << 12) | ((b2 as u32) << 6) | (b3 as u32);
        out.push(((t >> 16) & 0xff) as u8);
        if chunk[2] != b'=' {
            out.push(((t >> 8) & 0xff) as u8);
        }
        if chunk[3] != b'=' {
            out.push((t & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_post_doh_request() {
        let raw = b"POST /dns-query HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/dns-message\r\n\r\n\x12\x34\x01\x00";
        let parsed = parse_http_dns_request(raw);
        assert_eq!(
            parsed,
            HttpDnsRequest::Query(b"\x12\x34\x01\x00".to_vec(), true)
        );
    }

    #[test]
    fn test_parse_post_doh_request_binary_non_utf8() {
        // High byte 0x80, 0xff, 0xfe are invalid UTF-8 sequences in raw wire format
        let raw = b"POST /dns-query HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/dns-message\r\nContent-Length: 4\r\n\r\n\x80\xff\xfe\x01";
        let parsed = parse_http_dns_request(raw);
        assert_eq!(
            parsed,
            HttpDnsRequest::Query(b"\x80\xff\xfe\x01".to_vec(), true)
        );
    }

    #[test]
    fn test_decode_b64url_rejects_invalid_chars() {
        assert!(decode_b64url("Ej!Q").is_none());
        assert!(decode_b64url("EjQ@").is_none());
        assert!(decode_b64url("EjQ=").is_some());
    }

    #[test]
    fn test_parse_get_doh_request() {
        // Base64URL encoding of [0x12, 0x34] is "EjQ"
        let raw = b"GET /dns-query?dns=EjQ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        let parsed = parse_http_dns_request(raw);
        assert_eq!(parsed, HttpDnsRequest::Query(vec![0x12, 0x34], false));
    }

    #[tokio::test]
    async fn test_local_doh_server_roundtrip() {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let bind_addr: SocketAddr = "127.0.0.1:18053".parse().unwrap();

        LocalDoHServer::start(
            bind_addr,
            |query, _peer| async move {
                // echo back with high bit set
                let mut resp = query;
                if resp.len() >= 3 {
                    resp[2] |= 0x80;
                }
                Some(resp)
            },
            shutdown_rx,
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let resp = client
            .post("http://127.0.0.1:18053/dns-query")
            .header("Content-Type", "application/dns-message")
            .body(vec![0x12, 0x34, 0x01, 0x00])
            .send()
            .await
            .expect("local DoH POST failed");

        assert_eq!(resp.status(), 200);
        let body = resp.bytes().await.unwrap();
        assert_eq!(body[2] & 0x80, 0x80);

        let _ = shutdown_tx.send(());
    }

    #[test]
    fn test_parse_http_dns_request_health_check_and_bad_request() {
        let health = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        assert_eq!(parse_http_dns_request(health), HttpDnsRequest::HealthCheck);

        let bad_get = b"GET /dns-query?dns=INVALID!BASE64 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        assert_eq!(parse_http_dns_request(bad_get), HttpDnsRequest::BadRequest);

        let empty_post =
            b"POST /dns-query HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_http_dns_request(empty_post),
            HttpDnsRequest::BadRequest
        );
    }
}
