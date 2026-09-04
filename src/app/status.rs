//! kernel feature inspection, cgroup v2 verification, and status bar telemetry emission.

use std::env;
use std::process::Command;
use crate::core::ebpf::features::{have_sock_ops, is_cgroup_v2, is_root};

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

    if !is_root() {
        println!("  (run with sudo for accurate capability detection)");
        return;
    }

    println!("  root:       {}", format_bool(is_root()));
    println!("  cgroup_v2:  {}", format_bool(is_cgroup_v2("/sys/fs/cgroup")));
    println!("  sock_ops:   {}", format_bool(have_sock_ops()));
    println!("  setsockopt: {}", format_bool(have_sock_ops()));
}

// generates structured json payload consumed by desktop panels and status bars
pub fn show_status_json() {
    let is_service_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "albus.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let is_process_running = Command::new("pgrep")
        .args(["-x", "albus"])
        .output()
        .map(|out| {
            let s = String::from_utf8_lossy(&out.stdout);
            let my_pid = std::process::id().to_string();
            s.lines().any(|line| line.trim() != my_pid && !line.trim().is_empty())
        })
        .unwrap_or(false);

    let is_active = is_service_active || is_process_running;
    let cfg = crate::app::config::Config::load_or_default();

    if is_active {
        println!(
            "{{\"text\":\"󰞌\",\"alt\":\"active\",\"tooltip\":\"albus DPI Bypass: ACTIVE\\nEngine: eBPF sock_ops\\nDNS: 127.0.0.1 (Encrypted DoH)\",\"class\":\"active\",\"active\":true,\"doh_upstream\":\"{}\"}}",
            cfg.doh_upstream
        );
    } else {
        println!(
            "{{\"text\":\"󰞏\",\"alt\":\"inactive\",\"tooltip\":\"albus DPI Bypass: INACTIVE\\nRun 'sudo albus run' or 'sudo albus service start'\",\"class\":\"inactive\",\"active\":false,\"doh_upstream\":\"{}\"}}",
            cfg.doh_upstream
        );
    }
}

fn format_bool(ok: bool) -> &'static str {
    if ok {
        "supported"
    } else {
        "NOT supported"
    }
}
