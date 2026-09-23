//! linux kernel capability probing, euid privilege verification, and cgroup v2 mount validation.

use std::fs;
use std::path::Path;

// verifies effective user id is zero (root/cap_sys_admin)
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

// Linux capability numbers (linux/capability.h) backing the systemd unit's
// AmbientCapabilities set (L1 rootless runtime). A non-root daemon holding
// exactly these runs everything albus needs (raw sockets, iptables, eBPF,
// :53 bind, resolv.conf writes) with nothing else.
pub const CAP_DAC_OVERRIDE: u64 = 1;
pub const CAP_NET_BIND_SERVICE: u64 = 10;
pub const CAP_NET_ADMIN: u64 = 12;
pub const CAP_NET_RAW: u64 = 13;
pub const CAP_PERFMON: u64 = 38;
pub const CAP_BPF: u64 = 39;

pub const REQUIRED_SERVICE_CAPS: u64 = (1 << CAP_DAC_OVERRIDE)
    | (1 << CAP_NET_BIND_SERVICE)
    | (1 << CAP_NET_ADMIN)
    | (1 << CAP_NET_RAW)
    | (1 << CAP_PERFMON)
    | (1 << CAP_BPF);

/// Whether this process may run the engine: uid 0, or a dedicated service
/// user holding exactly the capability set above (see the systemd unit).
/// Service MANAGEMENT commands (install/start/stop via systemctl) still
/// require real root — capabilities do not authorize those.
pub fn has_service_privileges() -> bool {
    if is_root() {
        return true;
    }
    match cap_eff_self() {
        Some(eff) => eff & REQUIRED_SERVICE_CAPS == REQUIRED_SERVICE_CAPS,
        None => false,
    }
}

/// Parse helper, pure and unit-tested: effective capability mask from
/// /proc/self/status text. Unknown/malformed input yields None (fail
/// closed: has_service_privileges then refuses).
pub fn cap_eff_from_status(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let rest = line.strip_prefix("CapEff:")?;
        u64::from_str_radix(rest.trim(), 16).ok()
    })
}

fn cap_eff_self() -> Option<u64> {
    let text = fs::read_to_string("/proc/self/status").ok()?;
    cap_eff_from_status(&text)
}

/// Resolves the dedicated service account uid, if the account exists.
/// Used to extend root-only ownership checks to the L1 runtime user.
pub fn service_uid() -> Option<libc::uid_t> {
    let c_user = std::ffi::CString::new("albus").ok()?;
    unsafe {
        let pwd = libc::getpwnam(c_user.as_ptr());
        if pwd.is_null() {
            return None;
        }
        let uid = (*pwd).pw_uid;
        // a service account must never be uid 0; treat that as absent
        if uid == 0 {
            return None;
        }
        Some(uid)
    }
}

// inspects /proc/mounts to verify presence of cgroup2 filesystem at target mount path
pub fn is_cgroup_v2(path: &str) -> bool {
    let p = Path::new(path);
    if !p.exists() || !p.is_dir() {
        return false;
    }

    // parse /proc/mounts entries for cgroup2 filesystem declaration
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[2] == "cgroup2" && mount_covers(parts[1], path) {
                return true;
            }
        }
    }

    // fallback verification via standard cgroup control files
    p.join("cgroup.procs").exists() || p.join("cgroup.controllers").exists()
}

/// Pure mount-coverage check: exact match, root mount, or proper `/`-bounded
/// prefix. A naive starts_with would accept `/sys/fs/cgroupfoo`.
pub fn mount_covers(mount_point: &str, path: &str) -> bool {
    mount_point == path || mount_point == "/" || path.starts_with(&format!("{}/", mount_point))
}

// verifies kernel support for bpf type format (btf) runtime relocation
pub fn has_btf() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

// parses linux kernel release string (e.g. "6.13.5-arch1", "5.15.0-generic") into (major, minor)
pub fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split('.');
    let major = parts
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse::<u32>()
        .ok()?;
    let minor = parts
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse::<u32>()
        .ok()?;
    Some((major, minor))
}

// checks kernel support for ebpf sock_ops hook points, minimum kernel version (>= 5.10), and cgroup v2
pub fn have_sock_ops() -> bool {
    // L1: capability-holding service user qualifies, not just uid 0.
    if !has_service_privileges() {
        return false;
    }

    // verify kernel version is at least 5.10
    if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        if let Some((major, minor)) = parse_kernel_version(&release) {
            if major < 5 || (major == 5 && minor < 10) {
                return false;
            }
        }
    }

    // verify cgroup v2 hierarchy is accessible
    if !is_cgroup_v2("/sys/fs/cgroup") {
        return false;
    }

    true
}

// inspects /proc/net/dev to enumerate active physical and virtual network interfaces
pub fn list_active_interfaces() -> Vec<String> {
    let mut interfaces = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/net/dev") {
        for line in content.lines().skip(2) {
            if let Some(colon_idx) = line.find(':') {
                let iface_name = line[..colon_idx].trim().to_string();
                if iface_name != "lo" && !iface_name.is_empty() {
                    interfaces.push(iface_name);
                }
            }
        }
    }
    interfaces
}

// aggregates root, cgroup v2, sock_ops, and btf co-re capability flags
pub fn capability_summary() -> (bool, bool, bool, bool) {
    (
        is_root(),
        is_cgroup_v2("/sys/fs/cgroup"),
        have_sock_ops(),
        has_btf(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_root_boolean() {
        let _ = is_root();
    }

    #[test]
    fn test_list_active_interfaces_non_empty_or_valid() {
        let ifaces = list_active_interfaces();
        // loopback is filtered out
        assert!(!ifaces.contains(&"lo".to_string()));
    }

    #[test]
    fn test_parse_kernel_version() {
        assert_eq!(parse_kernel_version("6.13.5-arch1"), Some((6, 13)));
        assert_eq!(parse_kernel_version("5.10.0-8-amd64"), Some((5, 10)));
        assert_eq!(parse_kernel_version("4.19.128"), Some((4, 19)));
        assert_eq!(parse_kernel_version("invalid"), None);
    }

    #[test]
    fn test_capability_summary() {
        let (root, cgroup, sockops, btf) = capability_summary();
        let _ = (root, cgroup, sockops, btf);
    }

    #[test]
    fn test_cap_eff_parsing() {
        let sample = "Name:\talbus\nUid:\t996\t996\t996\t996\nCapEff:\t00000000800405fb\n";
        assert_eq!(cap_eff_from_status(sample), Some(0x800405fb));
        assert_eq!(cap_eff_from_status("no caps here\n"), None);
        assert_eq!(cap_eff_from_status("CapEff:\tZZZ\n"), None);
        assert_eq!(cap_eff_from_status(""), None);
    }

    #[test]
    fn test_required_caps_shape() {
        // exactly the six unit capabilities, nothing else
        let mut count = 0u32;
        let mut bits = REQUIRED_SERVICE_CAPS;
        while bits != 0 {
            count += (bits & 1) as u32;
            bits >>= 1;
        }
        assert_eq!(count, 6);
        for cap in [
            CAP_DAC_OVERRIDE,
            CAP_NET_BIND_SERVICE,
            CAP_NET_ADMIN,
            CAP_NET_RAW,
            CAP_PERFMON,
            CAP_BPF,
        ] {
            assert_ne!(REQUIRED_SERVICE_CAPS & (1 << cap), 0);
        }
    }

    #[test]
    fn test_mount_covers() {
        assert!(mount_covers("/sys/fs/cgroup", "/sys/fs/cgroup"));
        assert!(mount_covers("/sys/fs/cgroup", "/sys/fs/cgroup/albus"));
        assert!(mount_covers("/", "/etc/albus"));
        assert!(!mount_covers("/sys/fs/cgroup", "/sys/fs/cgroupfoo"));
        assert!(!mount_covers("/sys/fs/cgroup", "/sys/fs/other"));
    }

    #[test]
    fn test_service_privileges_boolean() {
        // must not panic; true for root, false-or-true for service user
        let _ = has_service_privileges();
        // a nonexistent-user lookup path: service_uid returns None or a uid
        let _ = service_uid();
    }
}
