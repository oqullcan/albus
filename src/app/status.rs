//! kernel feature inspection, cgroup v2 verification, and status bar telemetry emission.

use crate::core::ebpf::features::{
    has_service_privileges, have_sock_ops, is_cgroup_v2, is_root, service_uid,
};
use std::env;
use std::process::Command;

// dispatches status query to plaintext or json formatter
pub fn handle_status_command(json: bool) {
    if json {
        show_status_json();
    } else {
        show_status();
    }
}

// prints diagnostic summary of kernel ebpf sock_ops support and privilege level
pub fn show_status() {
    println!("albus status");
    println!("  platform:   linux/{}", env::consts::ARCH);
    println!("  engine:     ebpf-sockops");

    if !has_service_privileges() {
        println!("  (run with sudo for accurate capability detection)");
        return;
    }

    println!("  root:       {}", format_bool(is_root()));
    println!(
        "  cgroup_v2:  {}",
        format_bool(is_cgroup_v2("/sys/fs/cgroup"))
    );
    println!("  sock_ops:   {}", format_bool(have_sock_ops()));
    println!("  setsockopt: {}", format_bool(have_sock_ops()));
}

// FP-11: name-only pgrep is spoofable (exec -a albus). A candidate PID counts
// only when its /proc exe resolves to this binary (or the installed system
// binary) AND it runs as root. Unreadable /proc entries (other users' view of
// a manually-run daemon) fail closed to inactive for the process leg — the
// systemctl leg still covers the managed service.
fn verified_albus_process() -> bool {
    let self_exe = std::env::current_exe().ok();
    let my_pid = std::process::id();

    let out = std::process::Command::new("/usr/bin/pgrep")
        .args(["-x", "albus"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        let pid: u32 = match line.trim().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid_is_verified_albus(pid, &self_exe, my_pid) {
            return true;
        }
    }
    false
}

// FP-11: single-PID verification step (pure logic over live /proc reads,
// split out for testing). Counts only non-self PIDs whose exe is this binary
// (or the installed system binary) and whose uid is root or the L1 service user.
fn pid_is_verified_albus(pid: u32, self_exe: &Option<std::path::PathBuf>, my_pid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;

    if pid == my_pid || pid == 0 {
        return false;
    }
    let system_bin = std::path::PathBuf::from("/usr/local/bin/albus");
    let exe_ok = match std::fs::read_link(format!("/proc/{}/exe", pid)) {
        Ok(exe) => Some(&exe) == self_exe.as_ref() || exe == system_bin,
        Err(_) => false,
    };
    if !exe_ok {
        return false;
    }
    std::fs::metadata(format!("/proc/{}", pid))
        .map(|m| m.uid() == 0 || Some(m.uid()) == service_uid())
        .unwrap_or(false)
}

// generates structured json payload consumed by desktop panels and status bars
pub fn show_status_json() {
    let is_service_active = Command::new("/usr/bin/systemctl")
        .args(["is-active", "--quiet", "albus.service"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    // FP-11: OR-composition kept for manually-run daemons, but the process leg
    // now requires exe+uid verification instead of a bare name match.
    let is_process_running = verified_albus_process();

    let is_active = is_service_active || is_process_running;
    let cfg = crate::app::config::Config::load_or_default();

    println!("{}", status_payload(is_active, &cfg.doh_upstream));
}

// pure payload constructor (no I/O): serde_json escaping prevents
// doh_upstream JSON injection into panel widgets.
pub fn status_payload(is_active: bool, doh_upstream: &str) -> serde_json::Value {
    if is_active {
        serde_json::json!({
            "text": "󰞌",
            "alt": "active",
            "tooltip": "albus DPI Bypass: ACTIVE\nEngine: eBPF sock_ops\nDNS: 127.0.0.1 (Encrypted DoH)",
            "class": "active",
            "active": true,
            "doh_upstream": doh_upstream,
        })
    } else {
        serde_json::json!({
            "text": "󰞏",
            "alt": "inactive",
            "tooltip": "albus DPI Bypass: INACTIVE\nRun 'sudo albus run' or 'sudo albus service start'",
            "class": "inactive",
            "active": false,
            "doh_upstream": doh_upstream,
        })
    }
}

fn format_bool(ok: bool) -> &'static str {
    if ok {
        "supported"
    } else {
        "NOT supported"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_payload_is_valid_json() {
        for active in [true, false] {
            let v = status_payload(active, "quad9");
            assert_eq!(v["active"], serde_json::json!(active));
            assert_eq!(v["doh_upstream"], serde_json::json!("quad9"));
            // must serialize without error
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn test_status_payload_escapes_hostile_upstream() {
        // attacker-controlled upstream must not break panel JSON parsing
        let evil = "quad9\"}, {\"injected\":true, \"x\":\"";
        let v = status_payload(true, evil);
        assert_eq!(v["doh_upstream"], serde_json::json!(evil));
        // round-trips through the serializer intact
        let reparsed: serde_json::Value =
            serde_json::from_str(&v.to_string()).expect("payload must stay valid JSON");
        assert_eq!(reparsed["doh_upstream"], serde_json::json!(evil));
        assert!(reparsed.get("injected").is_none());
    }

    // FP-11: a same-named foreign binary (exec -a spoof) must never verify,
    // regardless of any real daemon that may or may not be running.
    #[test]
    fn test_pid_spoof_rejected() {
        let self_exe = std::env::current_exe().ok();
        let my_pid = std::process::id();
        // self is always excluded
        assert!(!pid_is_verified_albus(my_pid, &self_exe, my_pid));
        // init/systemd (pid 1) is never the albus test binary
        if self_exe
            .as_ref()
            .map(|p| p.to_string_lossy().contains("albus-"))
            .unwrap_or(false)
        {
            assert!(!pid_is_verified_albus(1, &self_exe, my_pid));
        }
        // live spoof: process named albus backed by /usr/bin/sleep
        let mut child = std::process::Command::new("/usr/bin/bash")
            .args(["-c", "exec -a albus sleep 30"])
            .spawn()
            .expect("spawn spoof");
        let spoof_pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !pid_is_verified_albus(spoof_pid, &self_exe, my_pid),
            "exec -a spoof must not verify"
        );
        let _ = child.kill();
        let _ = child.wait();
    }
}
