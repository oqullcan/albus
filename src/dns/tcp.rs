//! rfc 7766 local tcp port 53 listener with length-prefixed framing.
//!
//! serves dns queries over tcp, enabling full standards-compliance for large dnssec responses,
//! zone transfers, and stub resolvers (systemd-resolved, dig +tcp) when udp queries trigger truncation.

use std::future::Future;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

pub struct DnsTcpServer;

impl DnsTcpServer {
    // spawns tcp listener on 127.0.0.1:53 with tcp_quickack and rfc 7766 length-prefixed framing
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
            let std_listener = match std::net::TcpListener::bind(bind_addr) {
                Ok(l) => l,
                Err(e) => {
                    warn!("failed to bind TCP DNS listener to {}: {}", bind_addr, e);
                    return;
                }
            };

            #[cfg(unix)]
            {
                let fd = std_listener.as_raw_fd();
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
                }
            }

            let _ = std_listener.set_nonblocking(true);
            let listener = match TcpListener::from_std(std_listener) {
                Ok(l) => {
                    info!(addr = %bind_addr, "TCP DNS listener active on {}", bind_addr);
                    l
                }
                Err(e) => {
                    warn!("failed to convert TCP DNS listener to tokio: {}", e);
                    return;
                }
            };

            const MAX_CONCURRENT_TCP_CONNS: usize = 256;
            let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_TCP_CONNS));

            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((mut stream, peer_addr)) => {
                                let permit = match sem.clone().try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        debug!("TCP DNS max connection limit reached; dropping connection");
                                        continue;
                                    }
                                };
                                let handler_clone = handler_arc.clone();

                                #[cfg(unix)]
                                {
                                    let fd = stream.as_raw_fd();
                                    unsafe {
                                        let one: libc::c_int = 1;
                                        // TCP_QUICKACK disables delayed ACKs for sub-millisecond local latency
                                        let _ = libc::setsockopt(
                                            fd,
                                            libc::IPPROTO_TCP,
                                            libc::TCP_QUICKACK,
                                            &one as *const _ as *const libc::c_void,
                                            std::mem::size_of_val(&one) as libc::socklen_t,
                                        );
                                    }
                                }

                                tokio::spawn(async move {
                                    let _permit = permit;
                                    let mut len_buf = [0u8; 2];

                                    // handle pipelined consecutive queries over persistent tcp connection
                                    loop {
                                        // read 2-byte rfc 7766 big-endian length prefix with timeout
                                        let read_len = tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len_buf)).await;
                                        let msg_len = match read_len {
                                            Ok(Ok(2)) => u16::from_be_bytes(len_buf) as usize,
                                            _ => break,
                                        };

                                        if msg_len == 0 || msg_len > 65535 {
                                            break;
                                        }

                                        let mut msg_buf = vec![0u8; msg_len];
                                        let read_msg = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut msg_buf)).await;
                                        if !matches!(read_msg, Ok(Ok(_))) {
                                            break;
                                        }

                                        if let Some(resp_bytes) = handler_clone(msg_buf, peer_addr).await {
                                            let resp_len = (resp_bytes.len() as u16).to_be_bytes();
                                            let write_res = tokio::time::timeout(Duration::from_secs(5), async {
                                                stream.write_all(&resp_len).await?;
                                                stream.write_all(&resp_bytes).await?;
                                                stream.flush().await
                                            }).await;
                                            if !matches!(write_res, Ok(Ok(_))) {
                                                break;
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("TCP DNS accept error: {}; continuing", e);
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("TCP DNS server shutting down");
                        break;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tcp_dns_roundtrip_rfc7766() {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let bind_addr: SocketAddr = "127.0.0.1:15353".parse().unwrap();

        DnsTcpServer::start(
            bind_addr,
            |query, _peer| async move {
                let mut resp = query;
                if resp.len() >= 3 {
                    resp[2] |= 0x80;
                }
                Some(resp)
            },
            shutdown_rx,
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut stream = tokio::net::TcpStream::connect(bind_addr).await.expect("connect failed");

        // send length-prefixed query (RFC 7766)
        let query_data = vec![0xAB, 0xCD, 0x01, 0x00];
        let len_prefix = (query_data.len() as u16).to_be_bytes();
        stream.write_all(&len_prefix).await.unwrap();
        stream.write_all(&query_data).await.unwrap();

        // read length-prefixed response
        let mut resp_len_buf = [0u8; 2];
        stream.read_exact(&mut resp_len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        assert_eq!(resp_len, query_data.len());

        let mut resp_data = vec![0u8; resp_len];
        stream.read_exact(&mut resp_data).await.unwrap();
        assert_eq!(resp_data[2] & 0x80, 0x80);

        let _ = shutdown_tx.send(());
    }
}
