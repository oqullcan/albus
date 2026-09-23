//! linux kernel ebpf sock_ops loader, map management, and cgroup v2 attachment.

pub mod features;
pub mod loader;
pub mod manager;

pub use features::is_root;
pub use features::{has_service_privileges, service_uid};
pub use manager::{BpfManager, BpfManagerConfig};
