// native dns and systemd-resolved lifecycle manager with raii drop guard

use std::fs;
use std::process::Command;

pub struct DnsGuard {
    active: bool,
}

impl DnsGuard {
    pub fn enable() -> Self {
        dns_set_albus();
        Self { active: true }
    }

    pub fn disarm(&mut self) {
        if self.active {
            dns_restore_system();
            self.active = false;
        }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        if self.active {
            dns_restore_system();
        }
    }
}

fn run_cmd(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}

pub fn get_active_interfaces() -> Vec<String> {
    let mut ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo"
                || name.starts_with("tun")
                || name.starts_with("tap")
                || name.starts_with("docker")
                || name.starts_with("veth")
                || name.starts_with("br-")
                || name.starts_with("virbr")
            {
                continue;
            }
            ifaces.push(name);
        }
    }
    if ifaces.is_empty() {
        ifaces.push("enp3s0".to_string());
    }
    ifaces
}

fn get_default_gateway() -> Option<String> {
    if let Ok(output) = Command::new("ip").args(["route", "show", "default"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = stdout.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
            let gw = parts[2];
            if gw.parse::<std::net::Ipv4Addr>().is_ok() {
                return Some(gw.to_string());
            }
        }
    }
    None
}

pub fn dns_set_albus() {
    let ifaces = get_active_interfaces();
    for iface in &ifaces {
        run_cmd("resolvectl", &["dns", iface, "127.0.0.1:5300"]);
        run_cmd("resolvectl", &["domain", iface, "~."]);
        run_cmd("resolvectl", &["default-route", iface, "true"]);
        run_cmd("resolvectl", &["dnsovertls", iface, "no"]);
        run_cmd("resolvectl", &["dnssec", iface, "no"]);
    }
    run_cmd("resolvectl", &["flush-caches"]);
}

pub fn dns_restore_system() {
    let ifaces = get_active_interfaces();
    let gw = get_default_gateway();

    let mut nameservers = vec!["1.1.1.1", "8.8.8.8", "1.0.0.1"];
    let gw_ref = gw.as_deref();
    if let Some(g) = gw_ref {
        nameservers.push(g);
    }

    for iface in &ifaces {
        run_cmd("resolvectl", &["revert", iface]);
        run_cmd("resolvectl", &["default-route", iface, "true"]);
        run_cmd("resolvectl", &["domain", iface, ""]);
        run_cmd("resolvectl", &["dnsovertls", iface, "opportunistic"]);
        run_cmd("resolvectl", &["dnssec", iface, "no"]);

        let mut dns_args = vec!["dns", iface.as_str()];
        dns_args.extend_from_slice(&nameservers);
        run_cmd("resolvectl", &dns_args);
    }

    // Ensure /etc/resolv.conf points to systemd stub resolver if running
    if fs::metadata("/run/systemd/resolve/stub-resolv.conf").is_ok() {
        let _ = std::os::unix::fs::symlink("/run/systemd/resolve/stub-resolv.conf", "/etc/resolv.conf.tmp");
        let _ = fs::rename("/etc/resolv.conf.tmp", "/etc/resolv.conf");
    }

    run_cmd("resolvectl", &["flush-caches"]);
    run_cmd("ip", &["route", "flush", "cache"]);
}
