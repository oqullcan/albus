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

    // Attach to an isolated child cgroup, NEVER the live hierarchy root:
    // attaching at /sys/fs/cgroup would silently displace a running
    // daemon's program (single-attach slot), and our detach would then
    // leave production unprotected with zero alarm. (Found the hard way:
    // a test run left the live daemon shapeless until restart.)
    let child = format!("/sys/fs/cgroup/albus-test-{}", std::process::id());
    if std::fs::create_dir(&child).is_err() {
        skip("cannot create isolated test cgroup");
        return;
    }
    struct RmDir<'a>(&'a str);
    impl Drop for RmDir<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(self.0);
        }
    }
    let _cleanup = RmDir(&child);

    let mut engine = match BpfEngine::load_and_attach(&child) {
        Ok(e) => e,
        Err(e) => {
            // L28: distinguish environmental refusal from implementation
            // failure. EPERM/EACCES (containers, seccomp, dropped caps) is an
            // environment limitation — SKIP. Anything else after passing
            // preconditions (verifier reject, missing maps, attach failure)
            // is a genuine albus bug and must FAIL loudly, never SKIP.
            let msg = format!("{e}");
            if msg.contains("Permission denied") || msg.contains("Operation not permitted") {
                skip(&format!("load_and_attach refused (environment): {e}"));
                return;
            }
            panic!("load_and_attach failed despite passing preconditions: {e}");
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
