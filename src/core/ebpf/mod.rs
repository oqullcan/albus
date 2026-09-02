//! linux kernel ebpf sock_ops loader, map management, and cgroup v2 attachment.

pub mod features;
pub mod loader;
pub mod manager;

pub use features::is_root;
pub use manager::{BpfManager, BpfManagerConfig};
