//! kernel ebpf instrumentation, raw socket injection, and packet desynchronization engine.

pub mod anti_injection;
pub mod autottl;
pub mod ebpf;
pub mod engine;
pub mod fake;
pub mod firewall;
pub mod ja4_mimic;
pub mod rawsock;
pub mod stack_morph;

pub use anti_injection::{AntiInjectionFilter, InjectionVerdict};
pub use ja4_mimic::{compute_ja4_fingerprint, synthesize_client_hello, BrowserProfile};
pub use stack_morph::OsProfile;
