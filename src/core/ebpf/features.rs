//! linux kernel capability probing, euid privilege verification, and cgroup v2 mount validation.

use std::fs;
use std::path::Path;

// verifies effective user id is zero (root/cap_sys_admin)
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
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
            if parts.len() >= 3 {
                let mount_point = parts[1];
                let fs_type = parts[2];
                if (mount_point == path || path.starts_with(mount_point)) && fs_type == "cgroup2" {
                    return true;
                }
            }
        }
    }

    // fallback verification via standard cgroup control files
    p.join("cgroup.procs").exists() || p.join("cgroup.controllers").exists()
}

// verifies kernel support for bpf type format (btf) runtime relocation
pub fn has_btf() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

// parses linux kernel release string (e.g. "6.13.5-arch1", "5.15.0-generic") into (major, minor)
pub fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split('.');
    let major = parts.next()?.split(|c: char| !c.is_ascii_digit()).next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.split(|c: char| !c.is_ascii_digit()).next()?.parse::<u32>().ok()?;
    Some((major, minor))
}

// checks kernel support for ebpf sock_ops hook points, minimum kernel version (>= 5.10), and cgroup v2
pub fn have_sock_ops() -> bool {
    if !is_root() {
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
    (is_root(), is_cgroup_v2("/sys/fs/cgroup"), have_sock_ops(), has_btf())
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
}
