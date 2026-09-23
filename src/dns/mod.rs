//! encrypted dns-over-https (doh) subsystem, in-memory wire cache, and resolv.conf manager.

pub mod cache;
pub mod dnssec;
pub mod doh;
pub mod ech;
pub mod server;
pub mod system;

pub use dnssec::{DnssecState, DnssecValidator};
pub use doh::{extract_upstream_ips, extract_upstream_ips_v6};
pub use server::DnsServer;
pub use system::{cleanup_system_dns, restore_system_dns, set_system_dns};

/// Unpredictable 16-bit DNS transaction ID from the OS CSPRNG, with a
/// time+pid fallback (never a constant) if the RNG is unavailable.
/// Single shared helper so ECH, DNSSEC chain queries, and the leak canary all
/// get the same strength (run-4: previously three different strengths).
pub(crate) fn secure_query_id() -> u16 {
    let mut buf = [0u8; 2];
    if getrandom::getrandom(&mut buf).is_ok() {
        let v = u16::from_ne_bytes(buf);
        if v != 0 {
            return v;
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0x5678);
    let fallback = (nanos ^ (std::process::id().wrapping_mul(0x9E37)) as u32) as u16;
    if fallback == 0 {
        1
    } else {
        fallback
    }
}
