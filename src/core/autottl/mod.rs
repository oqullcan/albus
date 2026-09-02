//! automated hop distance estimation and optimal time-to-live calculation for middlebox desynchronization.

pub mod cache;
pub mod probe;

pub use probe::{AutoTtlConfig, AutoTtlEstimator};
