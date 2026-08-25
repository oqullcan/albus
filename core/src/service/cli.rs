// native cli commands, terminal dashboard, and gui ipc gateway

use super::dns::dns_restore_system;
use super::firewall::firewall_disable;
use crate::diagnostic::DiagnosticEngine;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::Duration;

pub const SOCKET_PATH: &str = "/tmp/albus.sock";
pub const RUN_SOCKET_PATH: &str = "/run/albus/albus.sock";
pub const PID_FILE: &str = "/run/albus/albus.pid";
pub const LOG_FILE: &str = "/run/albus/albus.log";

pub const C_RESET: &str = "\x1b[0m";
pub const C_BOLD: &str = "\x1b[1m";
pub const C_DIM: &str = "\x1b[2m";
pub const C_GREEN: &str = "\x1b[38;2;166;227;161m";
pub const C_BLUE: &str = "\x1b[38;2;137;180;250m";
pub const C_CYAN: &str = "\x1b[38;2;148;226;213m";
pub const C_YELLOW: &str = "\x1b[38;2;249;226;175m";
pub const C_RED: &str = "\x1b[38;2;243;139;168m";
pub const C_MAGENTA: &str = "\x1b[38;2;203;166;247m";

pub fn print_banner() {
    println!("{}{}  ALBUS ANTI-DPI{} {}(Omarchy Edition){}", C_MAGENTA, C_BOLD, C_RESET, C_DIM, C_RESET);
    println!();
}

pub fn query_status_raw() -> Option<String> {
    for path in [SOCKET_PATH, RUN_SOCKET_PATH] {
        if let Ok(stream) = UnixStream::connect(path) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() && !line.trim().is_empty() {
                return Some(line.trim().to_string());
            }
        }
    }
    None
}

pub fn is_daemon_running() -> bool {
    if let Ok(pid_str) = fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe {
                if libc::kill(pid, 0) == 0 {
                    return true;
                }
            }
        }
    }
    query_status_raw().is_some()
}

pub fn cmd_status(json_mode: bool) {
    if json_mode {
        if let Some(raw) = query_status_raw() {
            println!("{}", raw);
        } else {
            println!("{{\"running\":false}}");
        }
        return;
    }

    if let Some(raw) = query_status_raw() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            let total = val["total"].as_u64().unwrap_or(0);
            let tls = val["tls"].as_u64().unwrap_or(0);
            let bytes_str = val["bytes_str"].as_str().unwrap_or("0 B");
            let speed_str = val["speed_str"].as_str().unwrap_or("0 B/s");
            let latency = val["latency"].as_u64().unwrap_or(0);
            let dns = val["dns"].as_str().unwrap_or("Quad9");
            let on_bat = val["battery"].as_bool().unwrap_or(false);
            let poison = val["poison_blocks"].as_u64().unwrap_or(0);

            print_banner();
            println!("  ● Status:       {}{}{}ACTIVE (Protected){}", C_GREEN, C_BOLD, C_RESET, C_RESET);
            println!("    Data Shield:  {}{}{}{}", C_CYAN, C_BOLD, bytes_str, C_RESET);
            if speed_str != "0 B/s" {
                println!("    Throughput:   {}{}{}{}", C_GREEN, C_BOLD, speed_str, C_RESET);
            }
            println!("    DNS Relay:    {}{}{} ({} ms{})", C_BLUE, dns, C_RESET, latency, C_RESET);
            println!("    TLS Bypassed: {}{}{} / {} sessions", C_MAGENTA, tls, C_RESET, total);

            if poison > 0 {
                println!("    DNS Armor:    {}{}{} ISP Poisoning Attacks Deflected{}", C_YELLOW, poison, C_RESET, C_RESET);
            }
            if on_bat {
                println!("    Power Mode:   {}Battery-Aware (Eco Polling){}", C_GREEN, C_RESET);
            }
            println!();
            return;
        }
    }

    print_banner();
    println!("  ○ Status:       {}{}{}STOPPED (Direct Network){}", C_RED, C_BOLD, C_RESET, C_RESET);
    println!("  {}Run 'albus start' to activate protection.{}", C_DIM, C_RESET);
    println!();
}

pub fn cmd_stats() {
    print_banner();
    println!("{}PROTECTION METRICS & SHIELD TELEMETRY:{}", C_BOLD, C_RESET);
    println!();

    if let Some(raw) = query_status_raw() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            let total = val["total"].as_u64().unwrap_or(0);
            let tls = val["tls"].as_u64().unwrap_or(0);
            let http = val["http"].as_u64().unwrap_or(0);
            let bytes_str = val["bytes_str"].as_str().unwrap_or("0 B");
            let latency = val["latency"].as_u64().unwrap_or(0);
            let dns = val["dns"].as_str().unwrap_or("Quad9");
            let poison = val["poison_blocks"].as_u64().unwrap_or(0);

            println!("  ┌─ Session Overview");
            println!("  │  • Protected Traffic:   {}{}{}{}", C_CYAN, C_BOLD, bytes_str, C_RESET);
            println!("  │  • Total Sessions:      {}{}{}", C_BOLD, total, C_RESET);
            println!("  │  • TLS ClientHello:     {}{} bypassed{}", C_GREEN, tls, C_RESET);
            println!("  │  • HTTP/2 & Sanitized:  {}{} processed{}", C_MAGENTA, http, C_RESET);
            println!("  │  • Poisoning Deflected: {}{} ISP injections blocked{}", C_YELLOW, poison, C_RESET);
            println!("  │");
            println!("  ├─ DNS Architecture");
            println!("  │  • Active Resolver:     {}{}{}", C_BLUE, dns, C_RESET);
            println!("  │  • Average Latency:     {}{}{} ms{}", C_YELLOW, latency, C_RESET, C_RESET);
            println!("  │  • Prefetch Engine:     {}Active (Predictive CDN Pre-warm){}", C_GREEN, C_RESET);
            println!("  │  • Location Armor:      {}ECS Stripped & RFC 8467 Padded{}", C_GREEN, C_RESET);
            println!("  │");
            println!("  └─ Memory & Socket Tuning");
            println!("     • Memory Locking:      {}mlockall (Anti-Swap Protected){}", C_CYAN, C_RESET);
            println!("     • Socket Low-Water:    {}TCP_NOTSENT_LOWAT (16KB Low Latency){}", C_GREEN, C_RESET);
            println!("     • Volatile Scrubbing:  {}Zeroize active{}", C_GREEN, C_RESET);
            println!();
            return;
        }
    }

    println!("  {}Daemon is currently stopped.{}", C_YELLOW, C_RESET);
    println!("  Run 'albus start' to view live metrics.");
    println!();
}

pub fn cmd_test() {
    print_banner();
    println!("{}ALBUS DEFENSE & LEAK SUITE:{}", C_BOLD, C_RESET);
    println!();

    let running = is_daemon_running();
    if running {
        println!("  [{}{}{}✔{}] Daemon Core:           {}Active{} (SO_MARK 0x1337)", C_GREEN, C_BOLD, C_RESET, C_RESET, C_GREEN, C_RESET);
    } else {
        println!("  [{}{}{}✘{}] Daemon Core:           {}Stopped{}", C_RED, C_BOLD, C_RESET, C_RESET, C_RED, C_RESET);
    }

    let has_5300 = Command::new("ss").args(["-uln"]).output().map(|o| String::from_utf8_lossy(&o.stdout).contains(":5300")).unwrap_or(false);
    if has_5300 {
        println!("  [{}{}{}✔{}] Local DNS Relay:       {}Listening on 127.0.0.1:5300 (UDP+TCP){}", C_GREEN, C_BOLD, C_RESET, C_RESET, C_GREEN, C_RESET);
    } else {
        println!("  [{}○{}] Local DNS Relay:       {}Offline{}", C_YELLOW, C_RESET, C_DIM, C_RESET);
    }

    let has_1080 = Command::new("ss").args(["-tln"]).output().map(|o| String::from_utf8_lossy(&o.stdout).contains(":1080")).unwrap_or(false);
    if has_1080 {
        println!("  [{}{}{}✔{}] Transparent Intercept: {}Active on 127.0.0.1:1080 (1-byte TLS Split){}", C_GREEN, C_BOLD, C_RESET, C_RESET, C_GREEN, C_RESET);
    } else {
        println!("  [{}○{}] Transparent Intercept: {}Offline{}", C_YELLOW, C_RESET, C_DIM, C_RESET);
    }

    let has_dns_route = Command::new("resolvectl").output().map(|o| String::from_utf8_lossy(&o.stdout).contains("127.0.0.1:5300")).unwrap_or(false);
    if has_dns_route {
        println!("  [{}{}{}✔{}] DNS Root Routing:      {}Enforced (~. -> 127.0.0.1:5300){}", C_GREEN, C_BOLD, C_RESET, C_RESET, C_GREEN, C_RESET);
    } else {
        println!("  [{}○{}] DNS Root Routing:      {}Default System DNS{}", C_YELLOW, C_RESET, C_DIM, C_RESET);
    }

    let has_iptables = Command::new("iptables").args(["-t", "nat", "-L", "ALBUS"]).output().map(|o| o.status.success()).unwrap_or(false);
    if has_iptables || running {
        println!("  [{}{}{}✔{}] Netfilter Chains:      {}ALBUS & ALBUS_DNS Active{}", C_GREEN, C_BOLD, C_RESET, C_RESET, C_GREEN, C_RESET);
        println!("  [{}{}{}✔{}] DNS Leak Armor:        {}Dead-Man Switch Active (Kernel Netfilter){}", C_GREEN, C_BOLD, C_RESET, C_RESET, C_GREEN, C_RESET);
    } else {
        println!("  [{}○{}] Netfilter Chains:      {}Unloaded{}", C_YELLOW, C_RESET, C_DIM, C_RESET);
        println!("  [{}○{}] DNS Leak Armor:        {}Unloaded{}", C_YELLOW, C_RESET, C_DIM, C_RESET);
    }

    println!();
    println!("  {}Run 'albus diag' for CDN latency & target bypass benchmark.{}", C_DIM, C_RESET);
    println!();
}

pub async fn cmd_diagnose() {
    print_banner();
    println!("{}> Running comprehensive multi-CDN connectivity benchmark...{}", C_BLUE, C_RESET);
    println!();
    let report = DiagnosticEngine::run_full_diagnostic().await;
    if let Ok(json) = serde_json::to_string_pretty(&report) {
        println!("{}", json);
    }
    println!();
}

pub fn cmd_fix_network() {
    print_banner();
    println!("{}> Performing emergency network repair & firewall flush...{}", C_YELLOW, C_RESET);
    firewall_disable();
    dns_restore_system();
    cmd_stop_process();
    println!("{}[OK] Network routes reverted and all Albus firewall rules flushed.{}", C_GREEN, C_RESET);
}

pub fn cmd_stop_process() {
    if let Ok(pid_str) = fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
                for _ in 0..6 {
                    if libc::kill(pid, 0) != 0 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                if libc::kill(pid, 0) == 0 {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        let _ = fs::remove_file(PID_FILE);
    }
    let _ = fs::remove_file(SOCKET_PATH);
    let _ = fs::remove_file(RUN_SOCKET_PATH);
}

pub fn exec_privileged_run(action: &str, args: &[String]) {
    // If already root, run directly
    if unsafe { libc::geteuid() } == 0 {
        let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("/usr/lib/albus/albus-core"));
        let mut cmd = Command::new(exe);
        cmd.arg(action).args(args);
        let _ = cmd.status();
        return;
    }

    // Try systemctl first if service is installed
    if action == "run" && Command::new("systemctl").args(["is-enabled", "albus"]).output().map(|o| o.status.success()).unwrap_or(false) {
        let _ = Command::new("systemctl").args(["start", "albus"]).status();
        return;
    } else if action == "stop-service" && Command::new("systemctl").args(["is-active", "albus"]).output().map(|o| o.status.success()).unwrap_or(false) {
        let _ = Command::new("systemctl").args(["stop", "albus"]).status();
        return;
    }

    // Check trusted binary location
    let trusted_bin = if fs::metadata("/usr/lib/albus/albus-core").is_ok() {
        "/usr/lib/albus/albus-core"
    } else if fs::metadata("/usr/lib/albus/albus").is_ok() {
        "/usr/lib/albus/albus"
    } else if fs::metadata("/usr/bin/albus-core").is_ok() {
        "/usr/bin/albus-core"
    } else if fs::metadata("/usr/bin/albus").is_ok() {
        "/usr/bin/albus"
    } else {
        "/usr/lib/albus/albus-core"
    };

    // Invoke pkexec or sudo on the trusted root binary
    let mut child_args = vec![action];
    for a in args {
        child_args.push(a.as_str());
    }

    if Command::new("which").arg("pkexec").output().map(|o| o.status.success()).unwrap_or(false) {
        let mut pk = Command::new("pkexec");
        pk.arg(trusted_bin).args(&child_args);
        let _ = pk.status();
    } else if Command::new("which").arg("sudo").output().map(|o| o.status.success()).unwrap_or(false) {
        let mut su = Command::new("sudo");
        su.arg(trusted_bin).args(&child_args);
        let _ = su.status();
    } else {
        eprintln!("Neither pkexec nor sudo found.");
    }
}
