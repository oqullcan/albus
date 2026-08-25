// linux tun virtual network interface driver with in-process ioctl configuration

use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Result;

pub struct TunDevice {
    name: String,
    fd: RawFd,
    async_fd: Arc<AsyncFd<RawFd>>,
}

impl TunDevice {
    // creates and brings up a new tun interface with non-blocking async io
    pub fn create(name: &str) -> Result<Self> {
        let dev_path = b"/dev/net/tun\0";
        let fd = unsafe {
            libc::open(
                dev_path.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK,
            )
        };

        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

        let name_bytes = name.as_bytes();
        let len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr() as *const libc::c_char,
                ifr.ifr_name.as_mut_ptr(),
                len,
            );
        }

        let res = unsafe { libc::ioctl(fd, libc::TUNSETIFF as libc::c_ulong, &ifr) };
        if res < 0 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }

        let async_fd = Arc::new(AsyncFd::new(fd)?);

        let dev = Self {
            name: name.to_string(),
            fd,
            async_fd,
        };

        // configure interface ip and bring it up via in-process ioctls
        dev.bring_up_interface(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(255, 254, 0, 0))?;

        Ok(dev)
    }

    // configures ip address and sets link up using socket ioctls with cap_net_admin
    fn bring_up_interface(&self, ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        unsafe {
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let mut ifr: libc::ifreq = std::mem::zeroed();
            let name_bytes = self.name.as_bytes();
            let len = name_bytes.len().min(libc::IFNAMSIZ - 1);
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr() as *const libc::c_char,
                ifr.ifr_name.as_mut_ptr(),
                len,
            );

            // 1. set ipv4 address
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
            std::ptr::copy_nonoverlapping(
                &addr as *const _ as *const libc::sockaddr,
                &mut ifr.ifr_ifru.ifru_addr,
                1,
            );
            libc::ioctl(sock, libc::SIOCSIFADDR as libc::c_ulong, &ifr);

            // 2. set netmask
            let mut mask: libc::sockaddr_in = std::mem::zeroed();
            mask.sin_family = libc::AF_INET as libc::sa_family_t;
            mask.sin_addr.s_addr = u32::from_ne_bytes(netmask.octets());
            std::ptr::copy_nonoverlapping(
                &mask as *const _ as *const libc::sockaddr,
                &mut ifr.ifr_ifru.ifru_netmask,
                1,
            );
            libc::ioctl(sock, libc::SIOCSIFNETMASK as libc::c_ulong, &ifr);

            // 3. get flags and set IFF_UP | IFF_RUNNING
            libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::c_ulong, &mut ifr);
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::c_ulong, &ifr);

            libc::close(sock);
        }

        Ok(())
    }

    // reads raw ip packet from tun interface
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.async_fd.readable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        *inner.get_ref(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }

    // writes raw ip packet to tun interface
    pub async fn write_packet(&self, buf: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.async_fd.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(
                        *inner.get_ref(),
                        buf.as_ptr() as *const libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }

    // cleans up interface on drop
    pub fn cleanup(&self) {
        unsafe {
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock >= 0 {
                let mut ifr: libc::ifreq = std::mem::zeroed();
                let name_bytes = self.name.as_bytes();
                let len = name_bytes.len().min(libc::IFNAMSIZ - 1);
                std::ptr::copy_nonoverlapping(
                    name_bytes.as_ptr() as *const libc::c_char,
                    ifr.ifr_name.as_mut_ptr(),
                    len,
                );
                libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::c_ulong, &mut ifr);
                ifr.ifr_ifru.ifru_flags &= !(libc::IFF_UP as libc::c_short);
                libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::c_ulong, &ifr);
                libc::close(sock);
            }
        }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        self.cleanup();
        unsafe {
            libc::close(self.fd);
        }
    }
}
