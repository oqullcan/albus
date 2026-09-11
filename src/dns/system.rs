//! linux resolver configuration manager modifying /etc/resolv.conf and systemd-resolved links.

use std::fs;
use std::io::Result;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

// enumerates physical and virtual network interfaces excluding loopback and container bridges
fn get_network_interfaces() -> Vec<String> {
    let mut ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "lo" && !name.starts_with("docker") && !name.starts_with("veth") {
                ifaces.push(name);
            }
        }
    }
    ifaces
}

// updates systemd-resolved link-specific nameservers via resolvectl dbus interface
fn configure_resolvectl_dns(dns_ip: &str) {
    for iface in get_network_interfaces() {
        let _ = Command::new("resolvectl")
            .args(["dns", &iface, dns_ip])
            .output();
        let _ = Command::new("resolvectl")
            .args(["domain", &iface, "~."])
            .output();
        let _ = Command::new("resolvectl")
            .args(["default-route", &iface, "true"])
            .output();
    }
    let _ = Command::new("resolvectl").arg("flush-caches").output();
}

// restores link-specific dns configuration in systemd-resolved
fn revert_resolvectl_dns() {
    for iface in get_network_interfaces() {
        let _ = Command::new("resolvectl").args(["revert", &iface]).output();
    }
    let _ = Command::new("resolvectl").arg("flush-caches").output();
}

// checks if nameserver line points to a local resolver loopback address (127.0.0.0/8 or ::1)
fn is_loopback_nameserver(trimmed: &str) -> bool {
    if let Some(ns) = trimmed.strip_prefix("nameserver").map(|s| s.trim()) {
        if let Ok(ip) = ns.parse::<std::net::IpAddr>() {
            ip.is_loopback()
        } else {
            ns == "127.0.0.1" || ns == "127.0.0.53" || ns == "::1"
        }
    } else {
        false
    }
}

// modifies system resolver configuration to target 127.0.0.1 while preserving original upstream entries
pub fn set_system_dns() -> Result<()> {
    configure_resolvectl_dns("127.0.0.1");
    set_system_dns_at(RESOLV_CONF_PATH)
}

pub fn set_system_dns_at<P: AsRef<Path>>(path: P) -> Result<()> {
    let content = fs::read_to_string(&path)?;
    let mut new_lines = Vec::new();

    new_lines.push("# albus: DoH DNS active — original lines commented below".to_string());
    new_lines.push("nameserver 127.0.0.1".to_string());

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("# albus:") {
            continue;
        }

        // preserve existing saved upstreams across repeated or recovered runs
        if trimmed.starts_with("# albus-saved:") {
            new_lines.push(trimmed.to_string());
            continue;
        }

        // comment out preexisting real nameserver declarations (skipping loopback)
        if trimmed.starts_with("nameserver") {
            if !is_loopback_nameserver(trimmed) {
                new_lines.push(format!("# albus-saved: {}", trimmed));
            }
        } else {
            new_lines.push(line.to_string());
        }
    }

    let mut out = new_lines.join("\n");
    out.push('\n');
    fs::write(path, out)
}

// restores original nameserver entries in /etc/resolv.conf and flushes resolver caches
pub fn restore_system_dns() -> Result<()> {
    revert_resolvectl_dns();
    restore_system_dns_at(RESOLV_CONF_PATH)
}

pub fn restore_system_dns_at<P: AsRef<Path>>(path: P) -> Result<()> {
    let content = fs::read_to_string(&path)?;
    let mut new_lines = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# albus-saved: ") {
            let restored = trimmed.trim_start_matches("# albus-saved: ").trim();
            if !is_loopback_nameserver(restored) {
                new_lines.push(restored.to_string());
            }
        } else if trimmed.starts_with("# albus") || is_loopback_nameserver(trimmed) {
            continue;
        } else if !trimmed.is_empty() {
            new_lines.push(line.to_string());
        }
    }

    if new_lines.is_empty() {
        new_lines.push("nameserver 8.8.8.8".to_string()); // safe fallback
    }

    let mut out = new_lines.join("\n");
    out.push('\n');
    fs::write(path, out)
}

// detects un-restored albus configuration tags and recovers original system state
pub fn cleanup_system_dns() -> Result<bool> {
    revert_resolvectl_dns();
    cleanup_system_dns_at(RESOLV_CONF_PATH)
}

pub fn cleanup_system_dns_at<P: AsRef<Path>>(path: P) -> Result<bool> {
    if let Ok(content) = fs::read_to_string(&path) {
        if content.contains("# albus-saved:")
            || content.contains("# albus:")
            || content.contains("nameserver 127.0.0.1")
        {
            restore_system_dns_at(path)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Looks up the UID and GID for a given username or numeric UID string.
#[cfg(unix)]
pub fn lookup_user_ids(user_name: &str) -> std::result::Result<(libc::uid_t, libc::gid_t), String> {
    use std::ffi::CString;
    let c_user = CString::new(user_name).map_err(|e| format!("invalid user name: {}", e))?;
    unsafe {
        let pwd = libc::getpwnam(c_user.as_ptr());
        if !pwd.is_null() {
            Ok(((*pwd).pw_uid, (*pwd).pw_gid))
        } else if let Ok(parsed_uid) = user_name.parse::<u32>() {
            Ok((parsed_uid as libc::uid_t, parsed_uid as libc::gid_t))
        } else {
            Err(format!("user '{}' not found in system user database", user_name))
        }
    }
}

/// Drops process privileges to the target user after binding low ports (e.g. port 53).
#[cfg(unix)]
pub fn drop_privileges(user_name: &str) -> std::result::Result<(), String> {
    let (uid, gid) = lookup_user_ids(user_name)?;

    unsafe {
        #[cfg(target_os = "linux")]
        {
            // Retain permitted capabilities across UID change if running as root
            libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        }

        if libc::setgroups(0, std::ptr::null()) != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!("failed to clear supplementary groups: {}", err);
        }
        if libc::setgid(gid) != 0 {
            return Err(format!(
                "failed to switch GID to {}: {}",
                gid,
                std::io::Error::last_os_error()
            ));
        }
        if libc::setuid(uid) != 0 {
            return Err(format!(
                "failed to switch UID to {}: {}",
                uid,
                std::io::Error::last_os_error()
            ));
        }
    }

    tracing::info!(user = user_name, uid = uid, gid = gid, "process privileges successfully dropped");
    Ok(())
}

#[cfg(not(unix))]
pub fn lookup_user_ids(_user_name: &str) -> std::result::Result<(u32, u32), String> {
    Err("user lookup is not supported on non-unix platforms".to_string())
}

#[cfg(unix)]
#[derive(Debug)]
pub struct SystemdSockets {
    pub udp: Vec<std::net::UdpSocket>,
    pub tcp: Vec<std::net::TcpListener>,
}

#[cfg(not(unix))]
#[derive(Debug)]
pub struct SystemdSockets {
    pub udp: Vec<()>,
    pub tcp: Vec<()>,
}

/// Detects systemd socket activation via LISTEN_PID and LISTEN_FDS environment variables.
#[cfg(unix)]
pub fn get_systemd_sockets() -> Option<SystemdSockets> {
    use std::os::unix::io::FromRawFd;

    let pid_str = std::env::var("LISTEN_PID").ok()?;
    let pid: u32 = pid_str.parse().ok()?;
    if pid != std::process::id() {
        return None;
    }

    let fds_str = std::env::var("LISTEN_FDS").ok()?;
    let count: usize = fds_str.parse().ok()?;
    if count == 0 {
        return None;
    }

    let mut udp = Vec::new();
    let mut tcp = Vec::new();

    const SD_LISTEN_FDS_START: i32 = 3;
    for i in 0..count {
        let fd = SD_LISTEN_FDS_START + i as i32;
        let mut sock_type: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut sock_type as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret == 0 {
            if sock_type == libc::SOCK_DGRAM {
                let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
                let _ = sock.set_nonblocking(true);
                udp.push(sock);
            } else if sock_type == libc::SOCK_STREAM {
                let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
                let _ = listener.set_nonblocking(true);
                tcp.push(listener);
            }
        }
    }

    if udp.is_empty() && tcp.is_empty() {
        None
    } else {
        tracing::info!(
            udp_count = udp.len(),
            tcp_count = tcp.len(),
            "Inherited systemd activated sockets"
        );
        Some(SystemdSockets { udp, tcp })
    }
}

#[cfg(not(unix))]
pub fn get_systemd_sockets() -> Option<SystemdSockets> {
    None
}

/// RAII Guard that creates a PID file storing the current process ID on creation,
/// and automatically removes the PID file when dropped or upon process termination.
#[derive(Debug)]
pub struct PidFileGuard {
    path: PathBuf,
}

impl PidFileGuard {
    /// Creates a PID file at the specified path with the current process ID.
    /// Creates intermediate directories if they do not exist.
    pub fn create<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        let pid = std::process::id();
        fs::write(&path, format!("{}\n", pid))?;
        tracing::info!(path = %path.display(), pid = pid, "created PID file");
        Ok(Self { path })
    }

    /// Returns the path to the managed PID file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        if self.path.exists() {
            if let Err(e) = fs::remove_file(&self.path) {
                tracing::warn!(path = %self.path.display(), error = %e, "failed to remove PID file");
            } else {
                tracing::info!(path = %self.path.display(), "removed PID file");
            }
        }
    }
}

/// Audits file and directory permissions along the path.
/// Emits a warning if any non-sticky directory or file is writable by other unprivileged users.
pub fn warn_if_maybe_writable_by_other_users<P: AsRef<Path>>(path: P) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut curr = path.as_ref();
        while let Some(parent) = curr.parent() {
            if curr.as_os_str().is_empty() || curr == Path::new("/") {
                break;
            }
            if let Ok(meta) = fs::metadata(curr) {
                let mode = meta.permissions().mode();
                // Check if group or other has write permission (0o022 or 0o002)
                if (mode & 0o002) != 0 {
                    let is_sticky_dir = meta.is_dir() && (mode & 0o1000) != 0;
                    if !is_sticky_dir {
                        tracing::warn!(
                            path = %curr.display(),
                            "path is writable by other system users; it is recommended to restrict file permissions"
                        );
                        break;
                    }
                }
            }
            curr = parent;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_restore_resolv_conf() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("test_resolv_conf_{}", std::process::id()));

        let initial_content = "nameserver 192.168.1.1\nsearch localdomain\nnameserver 1.1.1.1\n";
        fs::write(&temp_file, initial_content).unwrap();

        // 1. set system dns
        set_system_dns_at(&temp_file).unwrap();
        let modified = fs::read_to_string(&temp_file).unwrap();
        assert!(modified.contains("nameserver 127.0.0.1"));
        assert!(modified.contains("# albus-saved: nameserver 192.168.1.1"));
        assert!(modified.contains("# albus-saved: nameserver 1.1.1.1"));
        assert!(modified.contains("search localdomain"));

        // 2. restore system dns
        restore_system_dns_at(&temp_file).unwrap();
        let restored = fs::read_to_string(&temp_file).unwrap();
        assert!(!restored.contains("127.0.0.1"));
        assert!(!restored.contains("# albus"));
        assert!(restored.contains("nameserver 192.168.1.1"));
        assert!(restored.contains("nameserver 1.1.1.1"));
        assert!(restored.contains("search localdomain"));

        let _ = fs::remove_file(&temp_file);
    }

    #[test]
    fn test_resolv_conf_idempotency_and_loopback_skipping() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!(
            "test_resolv_conf_idempotent_{}",
            std::process::id()
        ));

        // Initial setup contains systemd-resolved stub (127.0.0.53) and real DHCP upstream
        let initial_content = "nameserver 127.0.0.53\nnameserver 10.0.0.1\n";
        fs::write(&temp_file, initial_content).unwrap();

        // 1. First invocation
        set_system_dns_at(&temp_file).unwrap();
        let after_first = fs::read_to_string(&temp_file).unwrap();
        // 127.0.0.53 should NOT be saved
        assert!(!after_first.contains("# albus-saved: nameserver 127.0.0.53"));
        // 10.0.0.1 should be saved
        assert!(after_first.contains("# albus-saved: nameserver 10.0.0.1"));
        assert!(after_first.contains("nameserver 127.0.0.1"));

        // 2. Second invocation (idempotency check)
        set_system_dns_at(&temp_file).unwrap();
        let after_second = fs::read_to_string(&temp_file).unwrap();
        // Should NOT save 127.0.0.1 into # albus-saved
        assert!(!after_second.contains("# albus-saved: nameserver 127.0.0.1"));
        // 10.0.0.1 must still be saved once
        assert_eq!(
            after_second
                .matches("# albus-saved: nameserver 10.0.0.1")
                .count(),
            1
        );
        assert_eq!(after_second.matches("nameserver 127.0.0.1").count(), 1);

        // 3. Restore
        restore_system_dns_at(&temp_file).unwrap();
        let restored = fs::read_to_string(&temp_file).unwrap();
        assert!(restored.contains("nameserver 10.0.0.1"));
        assert!(!restored.contains("127.0.0.1"));
        assert!(!restored.contains("127.0.0.53"));

        let _ = fs::remove_file(&temp_file);
    }

    #[test]
    fn test_lookup_user_ids() {
        #[cfg(unix)]
        {
            // Root user always exists on unix systems
            let root_lookup = lookup_user_ids("root");
            assert!(root_lookup.is_ok());
            let (uid, gid) = root_lookup.unwrap();
            assert_eq!(uid, 0);
            assert_eq!(gid, 0);

            // Numeric UID string
            let num_lookup = lookup_user_ids("65534");
            assert!(num_lookup.is_ok());
            assert_eq!(num_lookup.unwrap().0, 65534);

            // Non-existent user
            let invalid_lookup = lookup_user_ids("__albus_non_existent_user_999__");
            assert!(invalid_lookup.is_err());
        }
    }

    #[test]
    fn test_systemd_socket_activation_none_by_default() {
        // Without LISTEN_PID and LISTEN_FDS set, should safely return None
        let sockets = get_systemd_sockets();
        assert!(sockets.is_none());
    }

    #[test]
    fn test_pid_file_guard_lifecycle() {
        let temp_dir = std::env::temp_dir();
        let pid_path = temp_dir.join(format!("albus_test_pid_{}.pid", std::process::id()));

        {
            let guard = PidFileGuard::create(&pid_path).expect("PID file creation should succeed");
            assert!(pid_path.exists(), "PID file must exist while guard is active");
            let content = fs::read_to_string(&pid_path).expect("PID file must be readable");
            let parsed_pid: u32 = content.trim().parse().expect("PID content must be numeric");
            assert_eq!(parsed_pid, std::process::id());
            assert_eq!(guard.path(), pid_path.as_path());
        }

        // After guard is dropped, PID file must be automatically removed
        assert!(!pid_path.exists(), "PID file must be cleaned up on guard drop");
    }

    #[test]
    fn test_warn_if_maybe_writable_by_other_users() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join(format!("albus_perm_test_{}.tmp", std::process::id()));
        let _ = fs::write(&test_file, b"test");
        // Running function should not panic or error
        warn_if_maybe_writable_by_other_users(&test_file);
        let _ = fs::remove_file(&test_file);
    }
}
