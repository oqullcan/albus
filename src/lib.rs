//! ebpf sock_ops kernel instrumentation and doh resolver library.
//!
//! NOTE: no crate-wide lint allows — dead code and warnings must be fixed
//! or suppressed narrowly with justification at the item level, so CI's
//! `clippy --workspace -- -D warnings` stays meaningful.

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
