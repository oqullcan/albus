//! encrypted dns-over-https (doh) subsystem, in-memory wire cache, and resolv.conf manager.

pub mod cache;
pub mod doh;
pub mod ech;
pub mod server;
pub mod system;

pub use doh::extract_upstream_ips;
pub use server::DnsServer;
pub use system::{cleanup_system_dns, restore_system_dns, set_system_dns};
