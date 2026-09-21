//! encrypted dns-over-https (doh) subsystem, in-memory wire cache, and resolv.conf manager.

pub mod cache;
pub mod dnssec;
pub mod doh;
pub mod ech;
pub mod server;
pub mod ssrf;
pub mod system;

pub use dnssec::{DnssecState, DnssecValidator};
pub use doh::{extract_upstream_ips, extract_upstream_ips_v6};
pub use server::DnsServer;
pub use system::{cleanup_system_dns, restore_system_dns, set_system_dns};

/// CSPRNG 16-bit transaction ID via getrandom(2); falls back to
/// time-derived bits only if the syscall fails (never returns a constant).
/// No new dependencies: libc is already linked. Used for DNS/DoH chain
/// query IDs so concurrent queries cannot collide trivially.
pub(crate) fn secure_rand_u16() -> u16 {
    let mut buf = [0u8; 2];
    let r = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, 2, 0) };
    if r == 2 {
        return u16::from_ne_bytes(buf);
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() & 0xffff) as u16)
        .unwrap_or(0x1234)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_rand_u16_distributes() {
        // statistical: 512 draws from 2^16 must be overwhelmingly unique
        // (expected collisions ~2; assert with huge margin, no flakiness)
        let ids: Vec<u16> = (0..512).map(|_| secure_rand_u16()).collect();
        let uniq: std::collections::HashSet<u16> = ids.iter().cloned().collect();
        assert!(
            uniq.len() > 480,
            "CSPRNG IDs must distribute, unique={}",
            uniq.len()
        );
    }
}
