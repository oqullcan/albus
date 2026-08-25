// zero-log dns subsystem with rfc 8484 wireformat, micro-cache, and latency probing

pub mod cache;
pub mod doh;
pub mod probe;
pub mod server;

pub use doh::DohResolver;
pub use server::LocalDnsServer;
