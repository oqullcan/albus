//! automated hop distance estimation and optimal time-to-live calculation for middlebox desynchronization.

pub mod cache;
pub mod probe;

pub use probe::{
    detect_interface_mtu, resolve_optimal_restore_mss, AutoTtlConfig, AutoTtlEstimator,
};
