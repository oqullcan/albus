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

pub use core::active_probe;
pub use core::anti_injection;
pub use core::autottl;
pub use core::ebpf;
pub use core::engine;
pub use core::fake;
pub use core::firewall;
pub use core::ja4_mimic;
pub use core::rawsock;
pub use core::stack_morph;
pub use core::traffic_morph;
pub use core::xdp_filter;
pub use app::defense_profile;

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
