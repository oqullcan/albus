//! ebpf sock_ops kernel instrumentation and doh resolver library.
#![allow(dead_code, unused_imports, unused_variables, clippy::all)]

pub mod app;
pub mod core;
pub mod dns;

// re-exports for public interface and integration test crates
pub use app::cli;
pub use app::config;
pub use app::monitor;
pub use app::service;
pub use app::status;

pub use core::autottl;
pub use core::ebpf;
pub use core::engine;
pub use core::fake;
pub use core::firewall;
pub use core::rawsock;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_reexports_accessibility() {
        let _cfg = config::Config::default();
        let _ = autottl::resolve_optimal_restore_mss();
        let _is_root = ebpf::is_root();
    }
}
