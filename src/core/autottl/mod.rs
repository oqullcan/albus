//! TTL selection for middlebox desynchronization (static contract — see
//! probe.rs docs): operator-configured default with bounds, no probing.

pub mod cache;
pub mod probe;

pub use probe::{AutoTtlConfig, AutoTtlEstimator};
