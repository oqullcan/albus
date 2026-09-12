//! kernel ebpf instrumentation, raw socket injection, and packet desynchronization engine.

pub mod active_probe;
pub mod anti_injection;
pub mod autottl;
pub mod ebpf;
pub mod engine;
pub mod fake;
pub mod firewall;
pub mod ja4_mimic;
pub mod rawsock;
pub mod stack_morph;
pub mod traffic_morph;
pub mod xdp_filter;

pub use active_probe::{ActiveProbeDetector, HoneytokenGenerator, ProbeAction, RollingBloomFilter};
pub use anti_injection::{AntiInjectionFilter, InjectionVerdict};
pub use ja4_mimic::{compute_ja4_fingerprint, synthesize_client_hello, BrowserProfile};
pub use stack_morph::OsProfile;
pub use traffic_morph::{calculate_poisson_delay, generate_chaff_packet, pad_packet_to_bin, TrafficProtocol};
pub use xdp_filter::{XdpAction, XdpFilterManager, XdpFilterRule};
