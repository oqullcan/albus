//! Real kernel eBPF program load and attach integration test.
//! Requires root privileges (CAP_BPF / CAP_NET_ADMIN / CAP_SYS_ADMIN).
//! Run with: `sudo -E $(which cargo) test --release --test ebpf_load_integration -- --ignored`

use albus::core::ebpf::loader::{BpfConfig, BpfEngine};
use std::path::Path;

#[test]
#[ignore]
fn test_ebpf_real_kernel_load_and_attach() {
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        eprintln!("SKIPPING: test_ebpf_real_kernel_load_and_attach requires root privileges (run with sudo)");
        return;
    }

    // Determine viable cgroup v2 mount path
    let cgroup_path = if Path::new("/sys/fs/cgroup/unified").exists() {
        "/sys/fs/cgroup/unified"
    } else if Path::new("/sys/fs/cgroup").exists() {
        "/sys/fs/cgroup"
    } else {
        panic!("cgroup v2 filesystem not found at /sys/fs/cgroup");
    };

    println!(
        "Testing real eBPF sock_ops load and cgroup attachment on: {}",
        cgroup_path
    );

    // Attempt loading and attaching to the real kernel
    let mut engine = BpfEngine::load_and_attach(cgroup_path)
        .expect("BpfEngine::load_and_attach failed on real kernel");

    assert!(engine.prog_fd >= 0, "valid BPF program fd expected");
    assert!(engine.config_map_fd >= 0, "valid config_map fd expected");
    assert!(
        engine.target_ports_fd >= 0,
        "valid target_ports fd expected"
    );
    assert!(engine.connections_fd >= 0, "valid connections fd expected");
    assert!(engine.attached, "engine must be marked attached");

    // Push test parameters to verify map write operations
    let config = BpfConfig::new(1200, 1460, 4096, 536, true);
    engine
        .push_config(config)
        .expect("push_config must succeed");
    engine
        .push_target_ports(&[80, 443])
        .expect("push_target_ports must succeed");

    // Detach program cleanly from cgroup hierarchy
    let detach_res = engine.detach();
    assert!(detach_res.is_ok(), "detach should succeed without error");
}
