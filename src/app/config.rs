//! persistent and ephemeral runtime configuration schema, default values, and json persistence.

use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::app::cli::RunArgs;

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
    #[serde(default)]
    pub shaping_watchdog: bool,
    #[serde(default = "default_true")]
    pub dnssec: bool,
    #[serde(default = "default_true")]
    pub pqc: bool,
    #[serde(default)]
    pub ram_only: bool,
    #[serde(default)]
    pub verbose: bool,
}

// default initial mss clamped to 88 bytes to force clienthello fragmentation across packets
fn default_mss() -> u16 {
    88
}
// default lower bound for mss jitter randomization (64 bytes)
fn default_min_mss() -> u16 {
    64
}
// default byte threshold before kernel returns to native line-rate mss
fn default_restore_bytes() -> u32 {
    600
}
// standard https port
fn default_ports() -> Vec<u16> {
    vec![443]
}
// default unified cgroup v2 mount point
fn default_cgroup() -> String {
    "/sys/fs/cgroup".to_string()
}
// fallback hop ttl value
fn default_ttl() -> u8 {
    8
}
// lower bound clamp for auto-ttl
fn default_min_ttl() -> u8 {
    3
}
// upper bound clamp for auto-ttl
fn default_max_ttl() -> u8 {
    12
}
fn default_true() -> bool {
    true
}
// default upstream resolver
fn default_upstream() -> String {
    "quad9".to_string()
}

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
            shaping_watchdog: false,
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
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
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

#[cfg(unix)]
struct FsPrivilegeGuard {
    active: bool,
}

#[cfg(unix)]
impl FsPrivilegeGuard {
    // temporarily drops filesystem credentials (fsuid/fsgid) to the unprivileged caller when running under sudo
    fn drop_to_sudo_user() -> Self {
        let current_euid = unsafe { libc::geteuid() };
        if current_euid == 0 {
            if let (Ok(uid_s), Ok(gid_s)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
                if let (Ok(uid), Ok(gid)) = (
                    uid_s.trim().parse::<libc::uid_t>(),
                    gid_s.trim().parse::<libc::gid_t>(),
                ) {
                    if uid != 0 {
                        // cross-check SUDO_UID against passwd database (anti-spoof)
                        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                            if is_valid_username(&sudo_user) {
                                if let Ok(c_user) = std::ffi::CString::new(sudo_user) {
                                    unsafe {
                                        let pwd = libc::getpwnam(c_user.as_ptr());
                                        if !pwd.is_null() && (*pwd).pw_uid != uid {
                                            return Self { active: false };
                                        }
                                    }
                                }
                            }
                        }
                        unsafe {
                            // drop supplementary groups first to close DAC bypass
                            let _ = libc::setgroups(0, std::ptr::null());
                            if libc::setfsgid(gid) != 0 {
                                return Self { active: false };
                            }
                            if libc::setfsuid(uid) != 0 {
                                libc::setfsgid(0);
                                return Self { active: false };
                            }
                            // verify drop actually took effect
                            if libc::setfsgid(gid) != 0 || libc::setfsuid(uid) != 0 {
                                libc::setfsuid(0);
                                libc::setfsgid(0);
                                return Self { active: false };
                            }
                        }
                        return Self { active: true };
                    }
                }
            }
        }
        Self { active: false }
    }
}

#[cfg(unix)]
impl Drop for FsPrivilegeGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::setfsuid(0);
                libc::setfsgid(0);
            }
        }
    }
}

// safely writes content to path atomically rejecting symlinks and dropping privileges on user paths
fn safe_write<P: AsRef<Path>>(path: P, content: &str) -> std::io::Result<()> {
    let p = path.as_ref();
    let is_system_path = p.starts_with("/run/albus") || p.starts_with("/etc/albus");

    #[cfg(unix)]
    let _guard = if !is_system_path {
        FsPrivilegeGuard::drop_to_sudo_user()
    } else {
        FsPrivilegeGuard { active: false }
    };

    if let Some(parent) = p.parent() {
        // refuse symlink parents (TOCTOU mitigation for create_dir_all -> open window)
        if let Ok(meta) = fs::symlink_metadata(parent) {
            if meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "security violation: parent is symlink at {}",
                        parent.display()
                    ),
                ));
            }
        }
        let existed = parent.exists();
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            // only chmod newly created dirs — never downgrade existing ~/.config etc.
            if !existed {
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
    }

    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    let mut file = options.open(p)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "security violation: refusing to write non-regular file at {}",
                p.display()
            ),
        ));
    }
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

// safely reads content while atomically rejecting symlinks and enforcing strict ownership checks
fn safe_read<P: AsRef<Path>>(path: P) -> std::io::Result<String> {
    let p = path.as_ref();
    let is_system_path = p.starts_with("/run/albus") || p.starts_with("/etc/albus");

    #[cfg(unix)]
    let _guard = if !is_system_path {
        FsPrivilegeGuard::drop_to_sudo_user()
    } else {
        FsPrivilegeGuard { active: false }
    };

    let mut options = fs::OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    let mut file = options.open(p)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "security violation: refusing to read non-regular file at {}",
                p.display()
            ),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let file_uid = meta.uid();
        let current_uid = unsafe { libc::getuid() };

        if current_uid == 0 {
            if is_system_path {
                if file_uid != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "security violation: system config {} owned by untrusted uid {}",
                            p.display(),
                            file_uid
                        ),
                    ));
                }
            } else if let Ok(sudo_uid_str) = std::env::var("SUDO_UID") {
                if let Ok(sudo_uid) = sudo_uid_str.trim().parse::<libc::uid_t>() {
                    if file_uid != 0 && file_uid != sudo_uid {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!(
                                "security violation: user config {} owned by untrusted uid {}",
                                p.display(),
                                file_uid
                            ),
                        ));
                    }
                }
            }
        } else if file_uid != current_uid && file_uid != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "security violation: config {} owned by untrusted uid {}",
                    p.display(),
                    file_uid
                ),
            ));
        }
    }

    use std::io::Read;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

/// Validates cgroup path: absolute, no symlink, is dir, looks like cgroup2.
pub fn validate_cgroup_path(path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if path.is_empty() || path.len() > 256 || !path.starts_with('/') {
        return Err("cgroup path must be absolute".into());
    }
    if path.contains("..") {
        return Err("cgroup path must not contain ..".into());
    }
    let p = Path::new(path);
    if let Ok(meta) = fs::symlink_metadata(p) {
        if meta.file_type().is_symlink() {
            return Err("security violation: cgroup path must not be a symlink".into());
        }
    }
    // only enforce dir shape when path exists (allows --help / tests without cgroup mounted)
    if p.exists() && !p.is_dir() {
        return Err("cgroup path must be a directory".into());
    }
    Ok(())
}

impl Config {
    /// Validates tunable ranges to prevent DoS / BPF map overflow / malformed state.
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.mss < 64 || self.mss > 1460 {
            return Err(format!("invalid mss {} (expected 64..=1460)", self.mss).into());
        }
        if self.min_mss > self.mss {
            return Err(format!("min_mss {} > mss {}", self.min_mss, self.mss).into());
        }
        if self.min_mss < 32 || self.min_mss > 1460 {
            return Err(format!("invalid min_mss {}", self.min_mss).into());
        }
        if self.restore_mss != 0 && (self.restore_mss < 64 || self.restore_mss > 1460) {
            return Err(format!(
                "invalid restore_mss {} (expected 0=auto or 64..=1460)",
                self.restore_mss
            )
            .into());
        }
        if self.ports.is_empty() || self.ports.len() > 64 {
            return Err(format!("invalid ports len {} (expected 1..=64)", self.ports.len()).into());
        }
        let mut seen = std::collections::HashSet::new();
        for p in &self.ports {
            if *p == 0 {
                return Err("port 0 is invalid".into());
            }
            if !seen.insert(p) {
                return Err(format!("duplicate port {}", p).into());
            }
        }
        if self.min_ttl > self.max_ttl {
            return Err(format!("min_ttl {} > max_ttl {}", self.min_ttl, self.max_ttl).into());
        }
        if self.max_ttl > 64 {
            return Err(format!("max_ttl {} too large", self.max_ttl).into());
        }
        if let Some(ref sni) = self.fake_sni {
            if sni.len() > 253
                || sni.contains(|c: char| c.is_whitespace() || c == ';' || c == '$' || c == '`')
            {
                return Err("invalid fake_sni".into());
            }
            // basic hostname shape
            if !sni
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            {
                return Err("invalid fake_sni charset".into());
            }
        }
        validate_cgroup_path(&self.cgroup_path)?;
        if self.doh_upstream.len() > 1024 {
            return Err("doh_upstream too long".into());
        }
        Ok(())
    }

    /// Root daemons must not load attacker-owned --config files.
    pub fn load_from_file_root_checked<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(unix)]
        {
            if crate::core::ebpf::is_root() {
                let meta = fs::symlink_metadata(path.as_ref())?;
                if meta.file_type().is_symlink() {
                    return Err(
                        "security violation: --config must not be a symlink when running as root"
                            .into(),
                    );
                }
                use std::os::unix::fs::MetadataExt;
                if meta.uid() != 0 {
                    return Err(format!(
                        "security violation: --config owned by uid {} (expected root) when running as root",
                        meta.uid()
                    )
                    .into());
                }
            }
        }
        Self::load_from_file(path)
    }
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
        // 2. check current process home (for user-level execution) — validate shape
        if let Ok(home) = std::env::var("HOME") {
            if home.starts_with('/') && !home.contains("..") && home.len() <= 256 {
                let user_cfg = PathBuf::from(&home).join(".config/albus/config.json");
                if !user_cfg.starts_with("/root") {
                    return user_cfg;
                }
            }
        }
        // 3. system-wide fallback (never arbitrarily guess a user from /home when root)
        PathBuf::from("/etc/albus/config.json")
    }

    // loads configuration payload from a specified filesystem path safely rejecting symlinks
    pub fn load_from_file<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = safe_read(path)?;
        let cfg: Config = serde_json::from_str(&content)?;
        Ok(cfg)
    }

    // writes serialized json payload to disk and volatile tmpfs safely rejecting symlinks
    pub fn save_to_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

/// Maps CLI run arguments onto a config (pure; validation stays with the
/// caller). Shared by `albus config set` and `albus service install` so both
/// persist identical semantics.
pub fn apply_run_args(
    mut cfg: Config,
    args: &RunArgs,
) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    // update runtime tuning parameters
    cfg.mss = args.mss;
    cfg.min_mss = args.min_mss;
    cfg.restore_mss = args.restore_mss;
    cfg.restore_after_bytes = args.restore_after_bytes;
    cfg.ports = args.ports.clone();
    cfg.cgroup_path = args.cgroup.clone();
    cfg.fake_ttl = args.fake_ttl;
    cfg.fake_sni = args.fake_sni.clone();
    cfg.fake_bad_checksum = args.fake_bad_checksum;
    cfg.auto_ttl = args.auto_ttl;
    cfg.min_ttl = args.min_ttl;
    cfg.max_ttl = args.max_ttl;
    cfg.doh_enabled = args.doh;
    cfg.doh_upstream = args.doh_upstream.clone();
    cfg.doh_bootstrap_ips = args.doh_bootstrap_ips.clone();
    cfg.block_quic = args.block_quic;
    cfg.block_stun = args.block_stun;
    cfg.kill_switch = args.kill_switch;
    cfg.network_lockdown = args.network_lockdown;
    cfg.block_ipv6 = args.block_ipv6;
    cfg.shaping_watchdog = args.shaping_watchdog;
    cfg.dnssec = args.dnssec;
    cfg.pqc = args.pqc;
    cfg.ram_only = args.ram_only;
    cfg.verbose = args.verbose;
    Ok(cfg)
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
        let temp_dir =
            std::env::temp_dir().join(format!("albus_test_symlink_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let real_file = temp_dir.join("real.json");
        let symlink_file = temp_dir.join("symlink.json");

        let _ = fs::write(&real_file, "{\"mss\": 88}");
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink(&real_file, &symlink_file);

        let result = safe_read(&symlink_file);
        assert!(result.is_err(), "safe_read must reject symlinks");

        let write_result = safe_write(&symlink_file, "{\"mss\": 99}");
        assert!(
            write_result.is_err(),
            "safe_write must reject symlinks via O_NOFOLLOW"
        );

        let _ = fs::remove_file(&symlink_file);
        let _ = fs::remove_file(&real_file);
        let _ = fs::remove_dir(&temp_dir);
    }

    fn valid_cfg() -> Config {
        Config::default()
    }

    #[test]
    fn test_validate_accepts_default() {
        assert!(valid_cfg().validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_bad_ranges() {
        // (mutator, reason)
        let cases: Vec<(Box<dyn Fn(&mut Config)>, &str)> = vec![
            (Box::new(|c: &mut Config| c.mss = 0), "mss zero"),
            (Box::new(|c: &mut Config| c.mss = 1500), "mss over 1460"),
            (Box::new(|c: &mut Config| c.min_mss = 200), "min_mss > mss"),
            (Box::new(|c: &mut Config| c.min_mss = 0), "min_mss under 32"),
            (
                Box::new(|c: &mut Config| c.restore_mss = 1),
                "restore_mss under 64",
            ),
            (
                Box::new(|c: &mut Config| c.restore_mss = 1500),
                "restore_mss over 1460",
            ),
            (Box::new(|c: &mut Config| c.ports = vec![]), "empty ports"),
            (
                Box::new(|c: &mut Config| c.ports = vec![443, 443]),
                "duplicate ports",
            ),
            (Box::new(|c: &mut Config| c.ports = vec![0]), "port zero"),
            (
                Box::new(|c: &mut Config| c.ports = vec![0u16; 65]),
                "too many ports",
            ),
            (
                Box::new(|c: &mut Config| {
                    c.min_ttl = 10;
                    c.max_ttl = 5;
                }),
                "min_ttl > max_ttl",
            ),
            (
                Box::new(|c: &mut Config| c.max_ttl = 65),
                "max_ttl too large",
            ),
            (
                Box::new(|c: &mut Config| c.fake_sni = Some("a;b".into())),
                "sni metachar",
            ),
            (
                Box::new(|c: &mut Config| c.fake_sni = Some("x".repeat(300))),
                "sni too long",
            ),
            (
                Box::new(|c: &mut Config| c.cgroup_path = "relative/path".into()),
                "relative cgroup",
            ),
            (
                Box::new(|c: &mut Config| c.cgroup_path = "/x/../y".into()),
                "cgroup traversal",
            ),
            (
                Box::new(|c: &mut Config| c.doh_upstream = "x".repeat(2000)),
                "upstream too long",
            ),
        ];
        for (mutate, reason) in cases {
            let mut cfg = valid_cfg();
            mutate(&mut cfg);
            assert!(cfg.validate().is_err(), "must reject: {}", reason);
        }
    }

    #[test]
    fn test_validate_accepts_boundary_values() {
        let mut cfg = valid_cfg();
        cfg.mss = 1460;
        cfg.min_mss = 1460;
        cfg.max_ttl = 64;
        cfg.restore_mss = 1460;
        cfg.fake_sni = Some("valid-host.example".into());
        assert!(cfg.validate().is_ok());
        // 0 = auto line-rate is the default and must stay valid
        cfg.restore_mss = 0;
        assert!(cfg.validate().is_ok());
    }
}
