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
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

pub struct LocalDoHServer;

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
                                let handler_clone = handler_arc.clone();
                                tokio::spawn(async move {
                                    let mut buf = [0u8; 4096];
                                    let n = match stream.read(&mut buf).await {
                                        Ok(n) if n > 0 => n,
                                        _ => return,
                                    };

                                    let req = &buf[..n];
                                    let (query_bytes, is_post) = match parse_http_dns_request(req) {
                                        Some(parsed) => parsed,
                                        None => {
                                            // return simple 200 health check info page for browser visits
                                            let body = "Albus Secure Local DoH Resolver (RFC 8484) Active\nEndpoint: /dns-query\n";
                                            let resp = format!(
                                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                                body.len(),
                                                body
                                            );
                                            let _ = stream.write_all(resp.as_bytes()).await;
                                            return;
                                        }
                                    };

                                    if let Some(dns_resp) = handler_clone(query_bytes, peer_addr).await {
                                        let header = format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nCache-Control: max-age=60\r\nConnection: close\r\n\r\n",
                                            dns_resp.len()
                                        );
                                        let _ = stream.write_all(header.as_bytes()).await;
                                        let _ = stream.write_all(&dns_resp).await;
                                    } else {
                                        let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
                                    }
                                });
                            }
                            Err(e) => {
                                debug!("local DoH accept error: {}", e);
                                break;
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

// parses incoming http/1.1 request into raw dns query bytes
fn parse_http_dns_request(req: &[u8]) -> Option<(Vec<u8>, bool)> {
    let req_str = std::str::from_utf8(req).ok()?;
    let mut lines = req_str.lines();
    let first_line = lines.next()?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let uri = parts.next()?;

    if method == "POST" && uri.starts_with("/dns-query") {
        // locate http body delimiter \r\n\r\n
        let body_pos = req.windows(4).position(|w| w == b"\r\n\r\n")?;
        let body = &req[body_pos + 4..];
        if !body.is_empty() {
            return Some((body.to_vec(), true));
        }
    } else if method == "GET" && uri.starts_with("/dns-query?dns=") {
        let b64_str = uri.strip_prefix("/dns-query?dns=")?;
        let query_b64 = b64_str.split('&').next()?;
        let decoded = decode_b64url(query_b64)?;
        return Some((decoded, false));
    }

    None
}

fn decode_b64url(s: &str) -> Option<Vec<u8>> {
    let mut clean = s.replace('-', "+").replace('_', "/");
    while clean.len() % 4 != 0 {
        clean.push('=');
    }
    const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut map = [255u8; 256];
    for (i, &b) in B64_TABLE.iter().enumerate() {
        map[b as usize] = i as u8;
    }
    let bytes = clean.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let b0 = map[chunk[0] as usize];
        let b1 = map[chunk[1] as usize];
        let b2 = if chunk[2] == b'=' { 0 } else { map[chunk[2] as usize] };
        let b3 = if chunk[3] == b'=' { 0 } else { map[chunk[3] as usize] };
        if b0 == 255 || b1 == 255 {
            return None;
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
        assert!(parsed.is_some());
        let (bytes, is_post) = parsed.unwrap();
        assert!(is_post);
        assert_eq!(&bytes, b"\x12\x34\x01\x00");
    }

    #[test]
    fn test_parse_get_doh_request() {
        // Base64URL encoding of [0x12, 0x34] is "EjQ"
        let raw = b"GET /dns-query?dns=EjQ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        let parsed = parse_http_dns_request(raw);
        assert!(parsed.is_some());
        let (bytes, is_post) = parsed.unwrap();
        assert!(!is_post);
        assert_eq!(&bytes, &[0x12, 0x34]);
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
}
