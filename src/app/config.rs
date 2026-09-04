//! persistent and ephemeral runtime configuration schema, default values, and json persistence.

use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_mss")]
    pub mss: u16,
    #[serde(default = "default_min_mss")]
    pub min_mss: u16,
    #[serde(default)]
    pub restore_mss: u16,
    #[serde(default = "default_restore_bytes")]
    pub restore_after_bytes: u32,
    #[serde(default = "default_ports")]
    pub ports: Vec<u16>,
    #[serde(default = "default_cgroup")]
    pub cgroup_path: String,
    #[serde(default = "default_ttl")]
    pub fake_ttl: u8,
    #[serde(default)]
    pub fake_sni: Option<String>,
    #[serde(default)]
    pub fake_bad_checksum: bool,
    #[serde(default = "default_true")]
    pub auto_ttl: bool,
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u8,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u8,
    #[serde(default = "default_true")]
    pub doh_enabled: bool,
    #[serde(default = "default_upstream")]
    pub doh_upstream: String,
    #[serde(default)]
    pub doh_bootstrap_ips: Vec<Ipv4Addr>,
    #[serde(default = "default_true")]
    pub block_quic: bool,
    #[serde(default = "default_true")]
    pub block_stun: bool,
    #[serde(default = "default_true")]
    pub kill_switch: bool,
    #[serde(default)]
    pub network_lockdown: bool,
    #[serde(default = "default_true")]
    pub block_ipv6: bool,
    #[serde(default = "default_true")]
    pub dnssec: bool,
    #[serde(default = "default_true")]
    pub pqc: bool,
    #[serde(default = "default_true")]
    pub ram_only: bool,
    #[serde(default)]
    pub verbose: bool,
}

// default initial mss clamped to 88 bytes to force clienthello fragmentation across packets
fn default_mss() -> u16 { 88 }
// default lower bound for mss jitter randomization (64 bytes)
fn default_min_mss() -> u16 { 64 }
// default byte threshold before kernel returns to native line-rate mss
fn default_restore_bytes() -> u32 { 600 }
// standard https port
fn default_ports() -> Vec<u16> { vec![443] }
// default unified cgroup v2 mount point
fn default_cgroup() -> String { "/sys/fs/cgroup".to_string() }
// fallback hop ttl value
fn default_ttl() -> u8 { 8 }
// lower bound clamp for auto-ttl
fn default_min_ttl() -> u8 { 3 }
// upper bound clamp for auto-ttl
fn default_max_ttl() -> u8 { 12 }
fn default_true() -> bool { true }
// default upstream resolver
fn default_upstream() -> String { "quad9".to_string() }

impl Default for Config {
    fn default() -> Self {
        Self {
            mss: 88,
            min_mss: 64,
            restore_mss: 0,
            restore_after_bytes: 600,
            ports: vec![443],
            cgroup_path: "/sys/fs/cgroup".to_string(),
            fake_ttl: 8,
            fake_sni: None,
            fake_bad_checksum: false,
            auto_ttl: true,
            min_ttl: 3,
            max_ttl: 12,
            doh_enabled: true,
            doh_upstream: "quad9".to_string(),
            doh_bootstrap_ips: Vec::new(),
            block_quic: true,
            block_stun: true,
            kill_switch: true,
            network_lockdown: false,
            block_ipv6: true,
            dnssec: true,
            pqc: true,
            ram_only: false,
            verbose: false,
        }
    }
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// validates username against Linux / POSIX rules (1..=32 chars, [a-zA-Z_][a-zA-Z0-9_-]*)
fn is_valid_username(username: &str) -> bool {
    if username.is_empty() || username.len() > 32 {
        return false;
    }
    let bytes = username.as_bytes();
    let first = bytes[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// safely resolves the home directory of SUDO_USER validating format and passwd entry
fn get_sudo_user_home() -> Option<PathBuf> {
    let sudo_user = std::env::var("SUDO_USER").ok()?;

    // 1. Validate username format (standard POSIX / Linux username conventions)
    if !is_valid_username(&sudo_user) {
        return None;
    }

    // 2. Query system user database via libc::getpwnam
    #[cfg(unix)]
    {
        let c_user = std::ffi::CString::new(sudo_user).ok()?;
        let pwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
        if pwd.is_null() {
            return None;
        }

        // 3. Cross-check SUDO_UID if present
        if let Ok(uid_str) = std::env::var("SUDO_UID") {
            if let Ok(expected_uid) = uid_str.trim().parse::<libc::uid_t>() {
                if unsafe { (*pwd).pw_uid } != expected_uid {
                    return None;
                }
            }
        }

        // 4. Extract canonical home directory path from passwd
        let dir_cstr = unsafe { std::ffi::CStr::from_ptr((*pwd).pw_dir) };
        let dir_str = dir_cstr.to_str().ok()?;
        let home_path = PathBuf::from(dir_str);

        if home_path.is_absolute() && !dir_str.contains('\0') {
            Some(home_path)
        } else {
            None
        }
    }
    #[cfg(not(unix))]
    None
}

// safely writes content to path while rejecting symlinks and enforcing restrictive permissions (0700/0600)
fn safe_write<P: AsRef<Path>>(path: P, content: &str) -> std::io::Result<()> {
    let p = path.as_ref();
    if let Ok(meta) = fs::symlink_metadata(p) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("security violation: refusing to follow symlink at {}", p.display()),
            ));
        }
    }
    if let Some(parent) = p.parent() {
        if let Ok(pmeta) = fs::symlink_metadata(parent) {
            if pmeta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("security violation: refusing to write into symlinked directory at {}", parent.display()),
                ));
            }
        }
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            if let (Ok(uid_s), Ok(gid_s)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
                if let (Ok(uid), Ok(gid)) = (uid_s.trim().parse::<libc::uid_t>(), gid_s.trim().parse::<libc::gid_t>()) {
                    let p_str = parent.to_string_lossy();
                    if !p_str.starts_with("/run/albus") && !p_str.starts_with("/etc/albus") {
                        if let Ok(cp) = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes()) {
                            unsafe { libc::chown(cp.as_ptr(), uid, gid); }
                        }
                    }
                }
            }
        }
    }
    fs::write(p, content)?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o600));
        if let (Ok(uid_s), Ok(gid_s)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
            if let (Ok(uid), Ok(gid)) = (uid_s.trim().parse::<libc::uid_t>(), gid_s.trim().parse::<libc::gid_t>()) {
                let p_str = p.to_string_lossy();
                if !p_str.starts_with("/run/albus") && !p_str.starts_with("/etc/albus") {
                    if let Ok(cp) = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) {
                        unsafe { libc::chown(cp.as_ptr(), uid, gid); }
                    }
                }
            }
        }
    }
    Ok(())
}

// safely reads content while rejecting symlinks and enforcing strict ownership checks
fn safe_read<P: AsRef<Path>>(path: P) -> std::io::Result<String> {
    let p = path.as_ref();
    if let Ok(meta) = fs::symlink_metadata(p) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("security violation: refusing to read symlink config at {}", p.display()),
            ));
        }

        if let Some(parent) = p.parent() {
            if let Ok(pmeta) = fs::symlink_metadata(parent) {
                if pmeta.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("security violation: refusing to read config in symlinked directory at {}", parent.display()),
                    ));
                }
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let file_uid = meta.uid();
            let current_uid = unsafe { libc::getuid() };

            if current_uid == 0 {
                let p_str = p.to_string_lossy();
                if p_str.starts_with("/run/albus") || p_str.starts_with("/etc/albus") {
                    if file_uid != 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("security violation: system config {} owned by untrusted uid {}", p.display(), file_uid),
                        ));
                    }
                } else if let Ok(sudo_uid_str) = std::env::var("SUDO_UID") {
                    if let Ok(sudo_uid) = sudo_uid_str.trim().parse::<libc::uid_t>() {
                        if file_uid != 0 && file_uid != sudo_uid {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("security violation: user config {} owned by untrusted uid {}", p.display(), file_uid),
                            ));
                        }
                    }
                }
            } else if file_uid != current_uid && file_uid != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("security violation: config {} owned by untrusted uid {}", p.display(), file_uid),
                ));
            }
        }
    }
    fs::read_to_string(p)
}

impl Config {
    // resolves secure volatile shared memory / runtime directory path
    pub fn volatile_config_path() -> PathBuf {
        if crate::core::ebpf::is_root() {
            PathBuf::from("/run/albus/config.json")
        } else if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join("albus/config.json")
        } else {
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/run/user/{}/albus/config.json", uid))
        }
    }

    // resolves durable persistent configuration path on physical disk (never returns volatile memory)
    pub fn default_config_path() -> PathBuf {
        // 1. check sudo user environment with strict format and passwd validation
        if let Some(sudo_home) = get_sudo_user_home() {
            let sudo_cfg = sudo_home.join(".config/albus/config.json");
            if !sudo_cfg.starts_with("/root") {
                return sudo_cfg;
            }
        }
        // 2. check current process home (for user-level execution)
        if let Ok(home) = std::env::var("HOME") {
            let user_cfg = PathBuf::from(&home).join(".config/albus/config.json");
            if !user_cfg.starts_with("/root") {
                return user_cfg;
            }
        }
        // 3. system-wide fallback (never arbitrarily guess a user from /home when root)
        PathBuf::from("/etc/albus/config.json")
    }

    // loads configuration payload from a specified filesystem path safely rejecting symlinks
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = safe_read(path)?;
        let cfg: Config = serde_json::from_str(&content)?;
        Ok(cfg)
    }

    // writes serialized json payload to disk and volatile tmpfs safely rejecting symlinks
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_string_pretty(self)?;

        // 1. write volatile runtime copy (in isolated tmpfs: /run/albus or $XDG_RUNTIME_DIR/albus)
        let volatile_path = Self::volatile_config_path();
        let _ = safe_write(&volatile_path, &json);

        // if user explicitly configured volatile ram-only operation, skip physical disk persistence
        if self.ram_only {
            return Ok(());
        }

        // 2. persist master configuration to disk so user preferences survive reboots
        let target_path = path.as_ref();
        safe_write(target_path, &json)?;

        // 3. also sync to /etc/albus/config.json if running as root or directory exists
        let etc = Path::new("/etc/albus/config.json");
        if crate::core::ebpf::is_root() || etc.exists() {
            let _ = safe_write(etc, &json);
        }

        Ok(())
    }

    // loads existing configuration or initializes default schema
    pub fn load_or_default() -> Self {
        // 1. first check active runtime volatile memory (/run/albus or $XDG_RUNTIME_DIR/albus)
        let volatile_path = Self::volatile_config_path();
        if volatile_path.exists() {
            if let Ok(cfg) = Self::load_from_file(&volatile_path) {
                return cfg;
            }
        }

        // 2. check /run/albus/config.json (system daemon volatile path)
        let run_root = PathBuf::from("/run/albus/config.json");
        if run_root.exists() {
            if let Ok(cfg) = Self::load_from_file(&run_root) {
                return cfg;
            }
        }

        // 3. load from durable user configuration path on disk
        let path = Self::default_config_path();
        if path.exists() {
            if let Ok(cfg) = Self::load_from_file(&path) {
                return cfg;
            }
        }

        // 4. check system-wide /etc/albus/config.json fallback
        let etc_path = PathBuf::from("/etc/albus/config.json");
        if etc_path.exists() {
            if let Ok(cfg) = Self::load_from_file(&etc_path) {
                return cfg;
            }
        }

        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_validation() {
        // Valid username format
        assert!(is_valid_username("ogy"));
        assert!(is_valid_username("albus_user"));
        assert!(is_valid_username("user-123"));
        assert!(is_valid_username("_daemon"));

        // Path traversal attempts
        assert!(!is_valid_username("../root"));
        assert!(!is_valid_username(".."));
        assert!(!is_valid_username("/bin/sh"));
        assert!(!is_valid_username("user/name"));
        assert!(!is_valid_username("user\0name"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("-invalid_start"));
        assert!(!is_valid_username("a".repeat(33).as_str()));
    }

    #[test]
    fn test_safe_read_rejects_symlink() {
        let temp_dir = std::env::temp_dir().join(format!("albus_test_symlink_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let real_file = temp_dir.join("real.json");
        let symlink_file = temp_dir.join("symlink.json");

        let _ = fs::write(&real_file, "{\"mss\": 88}");
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink(&real_file, &symlink_file);

        let result = safe_read(&symlink_file);
        assert!(result.is_err(), "safe_read must reject symlinks");

        let _ = fs::remove_file(&symlink_file);
        let _ = fs::remove_file(&real_file);
        let _ = fs::remove_dir(&temp_dir);
    }
}
