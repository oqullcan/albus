//! raw network socket creation and direct ipv4 packet transmission via ip_hdrincl.

pub mod packet;
pub mod types;

pub use packet::build_packet_stack_opts;
pub use types::ConnInfo;

use std::io::{Error, Result};
use std::os::raw::c_int;

// raw socket wrapper configured with ip_hdrincl to construct custom l3/l4 headers
pub struct RawSocket {
    fd: c_int,
}

impl RawSocket {
    // initializes raw socket descriptor bound to ipproto_raw
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

            Ok(Self { fd })
        }
    }

    // transmits raw packet payload with custom ip time-to-live and tcp checksum control
    pub fn send_fake_opts(&self, conn: &ConnInfo, payload: &[u8], ttl: u8, bad_checksum: bool) -> Result<usize> {
        let pkt = build_packet_stack_opts(conn, payload, ttl, bad_checksum);

        let mut dest_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        dest_addr.sin_family = libc::AF_INET as libc::sa_family_t;
        dest_addr.sin_port = 0;
        dest_addr.sin_addr.s_addr = u32::from_ne_bytes(conn.dst_ip.octets());

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

    #[inline]
    pub fn send_fake(&self, conn: &ConnInfo, payload: &[u8], ttl: u8) -> Result<usize> {
        self.send_fake_opts(conn, payload, ttl, false)
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

unsafe impl Send for RawSocket {}
unsafe impl Sync for RawSocket {}
