//! raw network socket creation and direct ipv4/ipv6 packet transmission via ip_hdrincl.

pub mod packet;
pub mod types;

pub use packet::build_packet_stack_opts;
pub use types::ConnInfo;

use std::io::{Error, Result};
use std::os::raw::c_int;

// raw socket wrapper configured with ip_hdrincl to construct custom l3/l4 headers
pub struct RawSocket {
    fd: c_int,
    fd_v6: Option<c_int>,
}

impl RawSocket {
    // initializes raw socket descriptors bound to ipv4 and optional ipv6
    pub fn new() -> Result<Self> {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
            if fd < 0 {
                return Err(Error::last_os_error());
            }

            // set ip_hdrincl socket option indicating user-provided ipv4 header
            let optval: c_int = 1;
            let res = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<c_int>() as libc::socklen_t,
            );

            if res < 0 {
                let err = Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            // attempt raw ipv6 socket initialization (optional, graceful fallback if ipv6 disabled)
            let fd_v6 = libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_RAW);
            let fd_v6_opt = if fd_v6 >= 0 {
                const IPV6_HDRINCL: c_int = 36;
                let res6 = libc::setsockopt(
                    fd_v6,
                    libc::IPPROTO_IPV6,
                    IPV6_HDRINCL,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<c_int>() as libc::socklen_t,
                );
                if res6 >= 0 {
                    Some(fd_v6)
                } else {
                    libc::close(fd_v6);
                    None
                }
            } else {
                None
            };

            Ok(Self { fd, fd_v6: fd_v6_opt })
        }
    }

    // transmits raw packet payload with custom ip time-to-live and tcp checksum control
    pub fn send_fake_opts(&self, conn: &ConnInfo, payload: &[u8], ttl: u8, bad_checksum: bool) -> Result<usize> {
        let pkt = build_packet_stack_opts(conn, payload, ttl, bad_checksum);

        match (conn.src_ip, conn.dst_ip) {
            (std::net::IpAddr::V4(_), std::net::IpAddr::V4(dst_v4)) => {
                let mut dest_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                dest_addr.sin_family = libc::AF_INET as libc::sa_family_t;
                dest_addr.sin_port = 0;
                dest_addr.sin_addr.s_addr = u32::from_ne_bytes(dst_v4.octets());

                let res = unsafe {
                    libc::sendto(
                        self.fd,
                        pkt.as_slice().as_ptr() as *const libc::c_void,
                        pkt.len(),
                        0,
                        &dest_addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };

                if res < 0 {
                    Err(Error::last_os_error())
                } else {
                    Ok(res as usize)
                }
            }
            (std::net::IpAddr::V6(_), std::net::IpAddr::V6(dst_v6)) => {
                let fd_v6 = self.fd_v6.ok_or_else(|| Error::other("IPv6 raw socket not available"))?;
                let mut dest_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                dest_addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                dest_addr.sin6_port = 0;
                dest_addr.sin6_addr.s6_addr = dst_v6.octets();

                let res = unsafe {
                    libc::sendto(
                        fd_v6,
                        pkt.as_slice().as_ptr() as *const libc::c_void,
                        pkt.len(),
                        0,
                        &dest_addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                };

                if res < 0 {
                    Err(Error::last_os_error())
                } else {
                    Ok(res as usize)
                }
            }
            _ => Err(Error::other("Mismatched IP families in ConnInfo")),
        }
    }

    #[inline]
    pub fn send_fake(&self, conn: &ConnInfo, payload: &[u8], ttl: u8) -> Result<usize> {
        self.send_fake_opts(conn, payload, ttl, false)
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            if self.fd >= 0 {
                libc::close(self.fd);
            }
            if let Some(fd6) = self.fd_v6 {
                if fd6 >= 0 {
                    libc::close(fd6);
                }
            }
        }
    }
}

unsafe impl Send for RawSocket {}
unsafe impl Sync for RawSocket {}
