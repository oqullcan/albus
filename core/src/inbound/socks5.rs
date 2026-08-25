// universal inbound proxy handler (transparent so_original_dst + socks5 + http connect)

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Result};
use tokio::net::TcpStream;

#[derive(Debug)]
pub enum TargetAddr {
    Ip(String),
    Domain(String, u16),
}

pub struct Socks5Handler;

impl Socks5Handler {
    // extracts original destination for transparent proxy or performs socks5/http handshake
    pub async fn handshake(stream: &mut TcpStream) -> Result<TargetAddr> {
        // check for so_original_dst (iptables/nftables transparent redirect)
        if let Some(orig_dst) = Self::get_original_dst(stream) {
            if orig_dst.port() != 1080 && orig_dst.ip() != IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)) {
                return Ok(TargetAddr::Ip(orig_dst.to_string()));
            }
        }

        let mut initial_byte = [0u8; 1];
        let n = stream.peek(&mut initial_byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "empty stream",
            ));
        }

        if initial_byte[0] == 0x05 {
            Self::socks5_handshake(stream).await
        } else if initial_byte[0] == b'C' || initial_byte[0] == b'c' {
            Self::http_connect_handshake(stream).await
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported proxy protocol",
            ))
        }
    }

    fn get_original_dst(stream: &TcpStream) -> Option<SocketAddr> {
        let fd = stream.as_raw_fd();
        unsafe {
            let mut sockaddr: libc::sockaddr_in = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let res = libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut sockaddr as *mut _ as *mut libc::c_void,
                &mut len,
            );
            if res == 0 {
                let ip = Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr));
                let port = u16::from_be(sockaddr.sin_port);
                return Some(SocketAddr::new(IpAddr::V4(ip), port));
            }
        }
        None
    }

    async fn socks5_handshake(stream: &mut TcpStream) -> Result<TargetAddr> {
        let mut buf = [0u8; 256];
        stream.read_exact(&mut buf[0..2]).await?;
        let num_methods = buf[1] as usize;
        stream.read_exact(&mut buf[0..num_methods]).await?;
        stream.write_all(&[0x05, 0x00]).await?;

        stream.read_exact(&mut buf[0..4]).await?;
        let cmd = buf[1];
        let addr_type = buf[3];

        if cmd != 0x01 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported socks5 cmd",
            ));
        }

        let target = match addr_type {
            0x01 => {
                let mut ip_buf = [0u8; 4];
                stream.read_exact(&mut ip_buf).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                let ip = Ipv4Addr::from(ip_buf);
                TargetAddr::Ip(format!("{}:{}", ip, port))
            }
            0x03 => {
                let len = stream.read_u8().await? as usize;
                let mut domain_buf = vec![0u8; len];
                stream.read_exact(&mut domain_buf).await?;
                let domain = String::from_utf8_lossy(&domain_buf).to_string();
                let port = stream.read_u16().await?;
                TargetAddr::Domain(domain, port)
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported addr",
                ))
            }
        };

        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        Ok(target)
    }

    async fn http_connect_handshake(stream: &mut TcpStream) -> Result<TargetAddr> {
        let mut buf = [0u8; 2048];
        let mut total_read = 0;

        while total_read < buf.len() {
            let n = stream.read(&mut buf[total_read..total_read + 1]).await?;
            if n == 0 {
                break;
            }
            total_read += n;
            if total_read >= 4 && &buf[total_read - 4..total_read] == b"\r\n\r\n" {
                break;
            }
        }

        let header_str = String::from_utf8_lossy(&buf[..total_read]);
        let first_line = header_str.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.len() >= 2 && parts[0].eq_ignore_ascii_case("CONNECT") {
            let host_port = parts[1];
            let target = if let Some((host, port_str)) = host_port.split_once(':') {
                let port = port_str.parse::<u16>().unwrap_or(443);
                if host.parse::<Ipv4Addr>().is_ok() {
                    TargetAddr::Ip(format!("{}:{}", host, port))
                } else {
                    TargetAddr::Domain(host.to_string(), port)
                }
            } else {
                TargetAddr::Domain(host_port.to_string(), 443)
            };

            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            stream.flush().await?;
            return Ok(target);
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid http connect request",
        ))
    }
}
