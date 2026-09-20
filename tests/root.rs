//! Privileged live tests: real iptables symmetry + service binary checks.
//!
//! Requirements: root (`is_root`). Anywhere else each test prints SKIP and
//! passes — never fail spuriously. CI runs this file explicitly:
//! `sudo -E cargo test --test root -- --ignored --nocapture`.
//! Only QUIC rules are touched (UDP 443): no DNS or web breakage window.

use albus::core::ebpf::is_root;
use albus::core::firewall::{block_quic, unblock_quic};
use std::process::Command;
fn skip(reason: &str) {
    println!("SKIP root test: {}", reason);
}

fn iptables_bin(v6: bool) -> Option<&'static str> {
    for cand in if v6 {
        ["/usr/sbin/ip6tables", "/sbin/ip6tables"]
    } else {
        ["/usr/sbin/iptables", "/sbin/iptables"]
    } {
        if std::path::Path::new(cand).exists() {
            return Some(cand);
        }
    }
    None
}

fn albus_rules(v6: bool) -> Option<Vec<String>> {
    let bin = iptables_bin(v6)?;
    let out = Command::new(bin).args(["-S", "OUTPUT"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rules: Vec<String> = text
        .lines()
        .filter(|l| l.contains("albus"))
        .map(|l| l.to_string())
        .collect();
    rules.sort();
    Some(rules)
}

#[test]
#[ignore]
fn root_quic_block_unblock_symmetry() {
    if !is_root() {
        skip("not root");
        return;
    }
    for v6 in [false, true] {
        let before = match albus_rules(v6) {
            Some(r) => r,
            None => {
                skip("iptables unavailable");
                return;
            }
        };
        // daemon may already hold the rule: assert convergence, not growth
        let had_quic = before.iter().any(|r| r.contains("albus-quic"));
        block_quic();
        let during = albus_rules(v6).unwrap_or_default();
        assert!(
            during.iter().any(|r| r.contains("albus-quic")),
            "albus-quic rule must be present after block (v6={})",
            v6
        );
        // restore even on failure paths below
        unblock_quic();
        let after = albus_rules(v6).unwrap_or_default();
        assert!(
            !after.iter().any(|r| r.contains("albus-quic")),
            "unblock_quic must remove the rule it manages (v6={})",
            v6
        );
        // put the live daemon's rule back if we found one
        if had_quic {
            block_quic();
            let restored = albus_rules(v6).unwrap_or_default();
            assert!(
                restored.iter().any(|r| r.contains("albus-quic")),
                "daemon rule must be restored (v6={})",
                v6
            );
        }
        // unrelated albus rules untouched
        for r in &before {
            if !r.contains("albus-quic") {
                assert!(
                    albus_rules(v6).unwrap_or_default().contains(r),
                    "non-quic rule must survive: {}",
                    r
                );
            }
        }
    }
}

#[test]
#[ignore]
fn root_service_binary_pinned() {
    use std::os::unix::fs::MetadataExt;
    if !is_root() {
        skip("not root");
        return;
    }
    // service installs must land root-owned at the fixed path (no fallback)
    let path = "/usr/local/bin/albus";
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        skip("albus not installed at /usr/local/bin/albus");
        return;
    };
    assert!(!meta.file_type().is_symlink(), "must not be a symlink");
    assert!(meta.file_type().is_file(), "must be a regular file");
    assert_eq!(meta.uid(), 0, "must be root-owned");
}

#[test]
#[ignore]
fn root_rawsocket_send_loopback() {
    use albus::core::rawsock::{ConnInfo, RawSocket};
    use std::net::Ipv4Addr;
    if !is_root() {
        skip("not root");
        return;
    }
    let sock = match RawSocket::new() {
        Ok(s) => s,
        Err(e) => {
            skip(&format!("raw socket unavailable: {}", e));
            return;
        }
    };
    // loopback discard: exercises build + sendto path, replies ignored
    let conn = ConnInfo::new(
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(127, 0, 0, 1),
        40000,
        9,
        1000,
        0,
    );
    let n = sock
        .send_fake(&conn, b"hello", 64)
        .expect("loopback raw send must succeed");
    assert!(n > 0, "must report bytes sent");
    // mixed families must fail closed even as root
    let mut mixed = conn;
    mixed.dst_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    assert!(sock.send_fake(&mixed, b"hello", 64).is_err());
}
