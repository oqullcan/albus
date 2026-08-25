// marked outbound tcp socket connector with loop prevention

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use tokio::net::TcpStream;

pub struct MarkedConnector;

impl MarkedConnector {
    // connects to destination with socket mark 0x1337 applied prior to connect for loop prevention
    pub async fn connect(target: SocketAddr) -> std::io::Result<TcpStream> {
        let domain = if target.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;
        let _ = socket.set_nodelay(true);

        unsafe {
            let raw_fd = socket.as_raw_fd();
            let mark: u32 = 0x1337;
            let _ = libc::setsockopt(
                raw_fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );

            // TCP_NOTSENT_LOWAT (16384 bytes): caps unsent data in the socket write queue.
            // Technical trade-off: Prevents the Linux TCP stack from coalescing micro-segments into
            // full MTU frames (ensuring 1-byte splits and disorder chunks survive on the wire),
            // at the expense of a slight theoretical throughput ceiling on gigabit links.
            const TCP_NOTSENT_LOWAT: libc::c_int = 25;
            let lowat: libc::c_uint = 16384;
            let _ = libc::setsockopt(
                raw_fd,
                libc::IPPROTO_TCP,
                TCP_NOTSENT_LOWAT,
                &lowat as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            );
        }




        let sock_addr = SockAddr::from(target);
        match socket.connect(&sock_addr) {
            Ok(_) => {}
            Err(e) => {
                if e.raw_os_error() != Some(libc::EINPROGRESS) {
                    return Err(e);
                }
            }
        }

        let std_stream: std::net::TcpStream = socket.into();
        let tokio_stream = TcpStream::from_std(std_stream)?;

        // wait for connection to become writable
        tokio_stream.writable().await?;

        // verify no socket error
        if let Some(err) = tokio_stream.take_error()? {
            return Err(err);
        }

        Ok(tokio_stream)
    }
}
