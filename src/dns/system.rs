//! linux resolver configuration manager modifying /etc/resolv.conf and systemd-resolved links.

use std::fs;
use std::io::Result;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
const RESOLVECTL_BIN: &str = "/usr/bin/resolvectl";

fn resolvectl() -> Command {
    let mut c = Command::new(RESOLVECTL_BIN);
    c.env_clear();
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

fn is_valid_iface(name: &str) -> bool {
    if name.is_empty() || name.len() > 16 {
        return false;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return false;
    }
    // excluded virtual/tunnel/bridge interfaces — only touch physical + common veth-excluded set
    const EXCLUDE_PREFIX: &[&str] = &[
        "lo",
        "docker",
        "veth",
        "br-",
        "virbr",
        "tun",
        "tap",
        "wg",
        "ppp",
        "tailscale",
        "zt",
    ];
    for p in EXCLUDE_PREFIX {
        if name == *p || name.starts_with(p) {
            return false;
        }
    }
    true
}

// enumerates physical and virtual network interfaces excluding loopback and container bridges
fn get_network_interfaces() -> Vec<String> {
    let mut ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if is_valid_iface(&name) {
                ifaces.push(name);
            }
        }
    }
    ifaces
}

// updates systemd-resolved link-specific nameservers via resolvectl dbus interface
fn configure_resolvectl_dns(dns_ip: &str) {
    for iface in get_network_interfaces() {
        let _ = resolvectl().args(["dns", &iface, dns_ip]).output();
        let _ = resolvectl().args(["domain", &iface, "~."]).output();
        let _ = resolvectl()
            .args(["default-route", &iface, "true"])
            .output();
    }
    let _ = resolvectl().arg("flush-caches").output();
}

// restores link-specific dns configuration in systemd-resolved
pub(crate) fn revert_resolvectl_dns() {
    for iface in get_network_interfaces() {
        let _ = resolvectl().args(["revert", &iface]).output();
    }
    let _ = resolvectl().arg("flush-caches").output();
}

/// Resolves write target safely: if `path` is a symlink (e.g. /etc/resolv.conf ->
/// /run/systemd/resolve/stub-resolv.conf), only follow it when canonical target lives
/// under /run/ or /etc/. Refuses attacker-controlled targets (/tmp, /home, /dev...).
fn resolve_write_target(path: &Path) -> std::io::Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let canon = fs::canonicalize(path)?;
            let s = canon.to_string_lossy();
            if canon.starts_with("/run/") || canon.starts_with("/etc/") {
                Ok(canon)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "security violation: refusing to follow resolv.conf symlink to {}",
                        s
                    ),
                ))
            }
        }
        _ => Ok(path.to_path_buf()),
    }
}

fn atomic_write_nofollow(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "security violation: refusing to write non-regular file at {}",
                path.display()
            ),
        ));
    }
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

// modifies system resolver configuration to target 127.0.0.1 while preserving original upstream entries
pub fn set_system_dns() -> Result<()> {
    configure_resolvectl_dns("127.0.0.1");
    set_system_dns_at(RESOLV_CONF_PATH)
}

pub fn set_system_dns_at<P: AsRef<Path>>(path: P) -> Result<()> {
    let target = resolve_write_target(path.as_ref())?;
    let content = fs::read_to_string(&target)?;
    // idempotency: already active and no unsaved nameservers -> no-op
    let has_marker = content.contains("# albus:");
    let has_loopback = content.lines().any(|l| l.trim() == "nameserver 127.0.0.1");
    let has_unsaved_ns = content.lines().any(|l| {
        let t = l.trim();
        t.starts_with("nameserver")
            && t != "nameserver 127.0.0.1"
            && !t.starts_with("# albus-saved:")
    });
    if has_marker && has_loopback && !has_unsaved_ns {
        return Ok(());
    }

    let mut new_lines = Vec::new();

    new_lines.push("# albus: DoH DNS active — original lines commented below".to_string());
    new_lines.push("nameserver 127.0.0.1".to_string());

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("# albus") {
            continue;
        }

        // comment out preexisting nameserver declarations
        if trimmed.starts_with("nameserver") {
            new_lines.push(format!("# albus-saved: {}", trimmed));
        } else {
            new_lines.push(line.to_string());
        }
    }

    let mut out = new_lines.join("\n");
    out.push('\n');
    atomic_write_nofollow(&target, &out)
}

// restores original nameserver entries in /etc/resolv.conf and flushes resolver caches
pub fn restore_system_dns() -> Result<()> {
    revert_resolvectl_dns();
    restore_system_dns_at(RESOLV_CONF_PATH)
}

pub fn restore_system_dns_at<P: AsRef<Path>>(path: P) -> Result<()> {
    let target = resolve_write_target(path.as_ref())?;
    let content = fs::read_to_string(&target)?;
    let mut new_lines = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# albus-saved: ") {
            let restored = trimmed.trim_start_matches("# albus-saved: ");
            new_lines.push(restored.to_string());
        } else if trimmed.starts_with("# albus") || trimmed == "nameserver 127.0.0.1" {
            continue;
        } else if !trimmed.is_empty() {
            new_lines.push(line.to_string());
        }
    }

    if new_lines.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no original nameserver entries to restore — refusing to write fallback",
        ));
    }

    let mut out = new_lines.join("\n");
    out.push('\n');
    atomic_write_nofollow(&target, &out)
}

// detects un-restored albus configuration tags and recovers original system state
pub fn cleanup_system_dns() -> Result<bool> {
    revert_resolvectl_dns();
    cleanup_system_dns_at(RESOLV_CONF_PATH)
}

pub fn cleanup_system_dns_at<P: AsRef<Path>>(path: P) -> Result<bool> {
    // resolve through the same symlink policy as writes: never scan
    // through an attacker-planted link, even for a read-only decision.
    let target = resolve_write_target(path.as_ref())?;
    if let Ok(content) = fs::read_to_string(&target) {
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

        // 2. idempotent second set must preserve saved entries
        set_system_dns_at(&temp_file).unwrap();
        let modified2 = fs::read_to_string(&temp_file).unwrap();
        assert!(modified2.contains("# albus-saved: nameserver 192.168.1.1"));

        // 3. restore system dns
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
    fn test_restore_empty_refuses_fallback() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("test_resolv_empty_{}", std::process::id()));
        fs::write(
            &temp_file,
            "# albus: DoH DNS active\nnameserver 127.0.0.1\n",
        )
        .unwrap();
        let res = restore_system_dns_at(&temp_file);
        assert!(res.is_err());
        let _ = fs::remove_file(&temp_file);
    }

    #[test]
    fn test_iface_validation() {
        assert!(is_valid_iface("eth0"));
        assert!(is_valid_iface("wlan0"));
        assert!(!is_valid_iface("lo"));
        assert!(!is_valid_iface("docker0"));
        assert!(!is_valid_iface("vethabc"));
        assert!(!is_valid_iface("tun0"));
        assert!(!is_valid_iface("wg0"));
        assert!(!is_valid_iface("../evil"));
        assert!(!is_valid_iface(""));
    }
}
