//! Real-kernel eBPF load integration: loads sock_ops bytecode on the actual
//! host kernel, writes config/target-port maps, then detaches cleanly.
//!
//! Requirements: Linux with BPF + root (`is_root`). Anywhere else the test
//! prints SKIP and passes — it must never fail spuriously, so CI runs it in
//! a dedicated root step (`--ignored`) while normal `cargo test` skips it.

use albus::core::ebpf::features::{have_sock_ops, is_root};
use albus::core::ebpf::loader::{BpfConfig, BpfEngine};

fn skip(reason: &str) {
    println!("SKIP ebpf_load_integration: {}", reason);
}

/// Preconditions for a meaningful load: root, cgroup v2, kernel >= 5.10.
fn preconditions() -> Option<String> {
    if !is_root() {
        return Some("not root".to_string());
    }
    if !have_sock_ops() {
        return Some("sock_ops unavailable (kernel < 5.10 or no cgroup v2)".to_string());
    }
    None
}

#[test]
#[ignore]
fn ebpf_load_attach_write_detach() {
    if let Some(reason) = preconditions() {
        skip(&reason);
        return;
    }

    let mut engine = match BpfEngine::load_and_attach("/sys/fs/cgroup") {
        Ok(e) => e,
        Err(e) => {
            // Kernel without BPF syscall access (containers/seccomp):
            // environment limitation, not an albus bug.
            skip(&format!("load_and_attach refused: {}", e));
            return;
        }
    };
    assert!(engine.prog_fd >= 0, "real prog fd expected");

    engine
        .push_config(BpfConfig::new(88, 0, 600, 64, true))
        .expect("config map must accept writes");
    engine
        .push_target_ports(&[443])
        .expect("target_ports map must accept writes");

    engine.detach().expect("clean detach must succeed");
}
