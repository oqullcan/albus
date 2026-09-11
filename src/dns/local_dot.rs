//! rfc 7858 local dns-over-tls (dot) listener for secure lan and android private dns.
//!
//! binds tcp port 853 with tls termination, accepting client queries from android devices,
//! routers, and local workstations, forwarding them into the unified dns resolution pipeline.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// creates tokio-rustls TlsAcceptor configured with ALPN "dot" for RFC 7858 DNS-over-TLS
pub fn create_dot_tls_acceptor_from_files(
    cert_path: &str,
    key_path: &str,
) -> Result<tokio_rustls::TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let cert_pem = std::fs::read_to_string(cert_path)?;
    let key_pem = std::fs::read_to_string(key_path)?;
    let certs = crate::dns::tls_auth::parse_pem_certificates(&cert_pem)?;
    let key = crate::dns::tls_auth::parse_pem_private_key(&key_pem)?;
    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_cfg.alpn_protocols = vec![b"dot".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg)))
}

pub struct LocalDoTServer;

impl LocalDoTServer {
    // starts background tcp 853 tls listener
    pub fn start<F, Fut>(
        listen_addr: SocketAddr,
        tls_acceptor: TlsAcceptor,
        handler: F,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) where
        F: Fn(Vec<u8>, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Option<Vec<u8>>> + Send + 'static,
    {
        let handler = Arc::new(handler);

        tokio::spawn(async move {
            let listener = match TcpListener::bind(listen_addr).await {
                Ok(l) => {
                    info!(addr = %listen_addr, "Local DoT (RFC 7858, Port 853) server listening");
                    l
                }
                Err(e) => {
                    error!(addr = %listen_addr, "Failed to bind Local DoT server: {}", e);
                    return;
                }
            };

            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, peer_addr)) => {
                                let acceptor = tls_acceptor.clone();
                                let h = handler.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_dot_client(stream, peer_addr, acceptor, h).await {
                                        debug!(peer = %peer_addr, "DoT client connection error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("Error accepting DoT TCP connection: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Local DoT server shutting down gracefully");
                        break;
                    }
                }
            }
        });
    }
}

async fn handle_dot_client<F, Fut>(
    stream: TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    handler: Arc<F>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: Fn(Vec<u8>, SocketAddr) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Option<Vec<u8>>> + Send + 'static,
{
    let _ = stream.set_nodelay(true);
    let mut tls_stream = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await??;

    loop {
        let mut len_buf = [0u8; 2];
        let read_len = match tls_stream.read_exact(&mut len_buf).await {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Box::new(e)),
        };

        if read_len == 0 {
            break;
        }

        let query_len = u16::from_be_bytes(len_buf) as usize;
        if query_len < 12 || query_len > 65535 {
            return Err(format!("invalid dot query length: {}", query_len).into());
        }

        let mut query_buf = vec![0u8; query_len];
        tls_stream.read_exact(&mut query_buf).await?;

        if let Some(resp) = (handler)(query_buf, peer_addr).await {
            let resp_len = (resp.len() as u16).to_be_bytes();
            tls_stream.write_all(&resp_len).await?;
            tls_stream.write_all(&resp).await?;
            tls_stream.flush().await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_dot_structure_exists() {
        let _ = LocalDoTServer;
    }
}
