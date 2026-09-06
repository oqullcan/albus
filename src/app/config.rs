//! persistent and ephemeral runtime configuration schema, default values, and json persistence.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    #[serde(default)]
    pub fake_seq_offset: i32,
    #[serde(default = "default_true")]
    pub auto_ttl: bool,
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u8,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u8,
    #[serde(default = "default_true")]
    pub doh_enabled: bool,
    #[serde(default = "default_true")]
    pub dns_racing: bool,
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
    #[serde(default)]
    pub ram_only: bool,
    #[serde(default)]
    pub verbose: bool,
    #[serde(default = "default_true")]
    pub anti_dns_rebinding: bool,
    #[serde(default = "default_true")]
    pub block_undelegated: bool,
    #[serde(default = "default_true")]
    pub edns_padding: bool,
    #[serde(default = "default_true")]
    pub blocklist: bool,
    #[serde(default)]
    pub blocklist_path: Option<String>,
    #[serde(default)]
    pub cloaking_rules: HashMap<String, String>,
    #[serde(default)]
    pub forwarding_rules: HashMap<String, String>,
    #[serde(default)]
    pub allow_domains: Vec<String>,
    #[serde(default)]
    pub allowlist_path: Option<String>,
    #[serde(default)]
    pub dns64: bool,
    #[serde(default = "default_true")]
    pub block_bogons: bool,
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    #[serde(default = "default_true")]
    pub uncloak_cnames: bool,
    #[serde(default = "default_true")]
    pub netmon: bool,
    #[serde(default = "default_true")]
    pub tcp_listener: bool,
    #[serde(default = "default_true")]
    pub local_doh: bool,
    #[serde(default = "default_local_doh_addr")]
    pub local_doh_addr: String,
    #[serde(default)]
    pub query_log: bool,
    #[serde(default)]
    pub query_log_path: Option<String>,
    #[serde(default)]
    pub ipcrypt_key: Option<String>,
    #[serde(default)]
    pub odoh_enabled: bool,
    #[serde(default)]
    pub odoh_relay: Option<String>,
    #[serde(default)]
    pub odoh_target: Option<String>,
    #[serde(default)]
    pub socks5_proxy: Option<String>,
    #[serde(default)]
    pub tor: bool,
    #[serde(default)]
    pub nx_log: bool,
    #[serde(default)]
    pub nx_log_path: Option<String>,
    #[serde(default)]
    pub schedules: HashMap<String, crate::dns::ScheduleConfig>,
    #[serde(default)]
    pub edns_client_subnet: Option<String>,
    #[serde(default)]
    pub metrics: bool,
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: String,
    #[serde(default)]
    pub tls_client_cert: Option<String>,
    #[serde(default)]
    pub tls_client_key: Option<String>,
    #[serde(default)]
    pub sources: HashMap<String, crate::dns::SourceConfig>,
    #[serde(default = "default_forwarding_rules_path")]
    pub forwarding_rules_path: Option<String>,
    #[serde(default = "default_cache_neg_min_ttl")]
    pub cache_neg_min_ttl: u32,
    #[serde(default = "default_cache_neg_max_ttl")]
    pub cache_neg_max_ttl: u32,
    #[serde(default)]
    pub tls_key_log_file: Option<String>,
    #[serde(default = "default_timeout_load_reduction")]
    pub timeout_load_reduction: f64,
    #[serde(default = "default_web_ui")]
    pub web_ui: bool,
    #[serde(default = "default_web_ui_addr")]
    pub web_ui_addr: String,
    #[serde(default)]
    pub web_ui_user: Option<String>,
    #[serde(default)]
    pub web_ui_pass: Option<String>,
    #[serde(default)]
    pub dnscrypt_servers: Vec<String>,
    #[serde(default)]
    pub dnscrypt_relays: Vec<String>,
}

fn default_forwarding_rules_path() -> Option<String> {
    Some("/etc/albus/forwarding-rules.txt".to_string())
}

fn default_timeout_load_reduction() -> f64 {
    0.75
}

fn default_web_ui() -> bool {
    false
}

fn default_metrics_addr() -> String {
    "127.0.0.1:9153".to_string()
}

fn default_cache_neg_min_ttl() -> u32 {
    60
}

fn default_cache_neg_max_ttl() -> u32 {
    600
}

fn default_web_ui_addr() -> String {
    "127.0.0.1:205".to_string()
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
fn default_local_doh_addr() -> String {
    "127.0.0.1:8053".to_string()
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
            fake_seq_offset: 0,
            auto_ttl: true,
            min_ttl: 3,
            max_ttl: 12,
            doh_enabled: true,
            dns_racing: true,
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
            anti_dns_rebinding: true,
            block_undelegated: true,
            edns_padding: true,
            blocklist: true,
            blocklist_path: None,
            cloaking_rules: HashMap::new(),
            forwarding_rules: HashMap::new(),
            allow_domains: Vec::new(),
            allowlist_path: None,
            dns64: false,
            block_bogons: true,
            blocked_ips: Vec::new(),
            uncloak_cnames: true,
            netmon: true,
            tcp_listener: true,
            local_doh: true,
            local_doh_addr: "127.0.0.1:8053".to_string(),
            query_log: false,
            query_log_path: None,
            ipcrypt_key: None,
            odoh_enabled: false,
            odoh_relay: None,
            odoh_target: None,
            socks5_proxy: None,
            tor: false,
            nx_log: false,
            nx_log_path: None,
            schedules: HashMap::new(),
            edns_client_subnet: None,
            metrics: false,
            metrics_addr: "127.0.0.1:9153".to_string(),
            tls_client_cert: None,
            tls_client_key: None,
            sources: HashMap::new(),
            forwarding_rules_path: Some("/etc/albus/forwarding-rules.txt".to_string()),
            cache_neg_min_ttl: 60,
            cache_neg_max_ttl: 600,
            tls_key_log_file: None,
            timeout_load_reduction: 0.75,
            web_ui: false,
            web_ui_addr: "127.0.0.1:205".to_string(),
            web_ui_user: None,
            web_ui_pass: None,
            dnscrypt_servers: Vec::new(),
            dnscrypt_relays: Vec::new(),
        }
    }
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// validates username against Linux / POSIX rules (1..=32 chars, [a-zA-Z_][a-zA-Z0-9_-]*)
pub(crate) fn is_valid_username(username: &str) -> bool {
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

// safely resolves the user info (uid, home) from ALBUS_CONFIG_USER environment variable
pub fn get_configured_user_info() -> Option<(libc::uid_t, PathBuf)> {
    #[cfg(unix)]
    {
        if let Ok(user) = std::env::var("ALBUS_CONFIG_USER") {
            let user = user.trim();
            if is_valid_username(user) {
                if let Ok(c_user) = std::ffi::CString::new(user) {
                    let pwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
                    if !pwd.is_null() {
                        let uid = unsafe { (*pwd).pw_uid };
                        let dir_cstr = unsafe { std::ffi::CStr::from_ptr((*pwd).pw_dir) };
                        if let Ok(dir_str) = dir_cstr.to_str() {
                            let home_path = PathBuf::from(dir_str);
                            if home_path.is_absolute() && !dir_str.contains('\0') {
                                return Some((uid, home_path));
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// safely resolves the sudo caller's user info (uid, home) with format and passwd validation
pub fn get_sudo_user_info() -> Option<(libc::uid_t, PathBuf)> {
    #[cfg(unix)]
    {
        let sudo_user = std::env::var("SUDO_USER").ok()?;
        if !is_valid_username(&sudo_user) {
            return None;
        }
        let c_user = std::ffi::CString::new(sudo_user).ok()?;
        let pwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
        if pwd.is_null() {
            return None;
        }
        let uid = unsafe { (*pwd).pw_uid };
        if let Ok(uid_str) = std::env::var("SUDO_UID") {
            if let Ok(expected_uid) = uid_str.trim().parse::<libc::uid_t>() {
                if uid != expected_uid {
                    return None;
                }
            }
        }
        let dir_cstr = unsafe { std::ffi::CStr::from_ptr((*pwd).pw_dir) };
        let dir_str = dir_cstr.to_str().ok()?;
        let home_path = PathBuf::from(dir_str);
        if home_path.is_absolute() && !dir_str.contains('\0') {
            Some((uid, home_path))
        } else {
            None
        }
    }
    #[cfg(not(unix))]
    None
}

// safely resolves the home directory of SUDO_USER validating format and passwd entry
pub fn get_sudo_user_home() -> Option<PathBuf> {
    get_sudo_user_info().map(|(_, home)| home)
}

#[cfg(unix)]
struct FsPrivilegeGuard {
    active: bool,
}

#[cfg(unix)]
impl FsPrivilegeGuard {
    // temporarily drops filesystem credentials (fsuid/fsgid) to the unprivileged caller when running under sudo or ALBUS_CONFIG_USER
    fn drop_to_user() -> Self {
        let current_euid = unsafe { libc::geteuid() };
        if current_euid == 0 {
            // 1. check SUDO_UID / SUDO_GID
            if let (Ok(uid_s), Ok(gid_s)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
                if let (Ok(uid), Ok(gid)) = (
                    uid_s.trim().parse::<libc::uid_t>(),
                    gid_s.trim().parse::<libc::gid_t>(),
                ) {
                    if uid != 0 {
                        unsafe {
                            libc::setfsgid(gid);
                            libc::setfsuid(uid);
                        }
                        return Self { active: true };
                    }
                }
            }

            // 2. check ALBUS_CONFIG_USER
            if let Some((uid, _)) = get_configured_user_info() {
                if uid != 0 {
                    let gid = if let Ok(u_str) = std::env::var("ALBUS_CONFIG_USER") {
                        if let Ok(c_user) = std::ffi::CString::new(u_str.trim()) {
                            let pwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
                            if !pwd.is_null() {
                                unsafe { (*pwd).pw_gid }
                            } else {
                                uid as libc::gid_t
                            }
                        } else {
                            uid as libc::gid_t
                        }
                    } else {
                        uid as libc::gid_t
                    };

                    unsafe {
                        libc::setfsgid(gid);
                        libc::setfsuid(uid);
                    }
                    return Self { active: true };
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
        FsPrivilegeGuard::drop_to_user()
    } else {
        FsPrivilegeGuard { active: false }
    };

    let parent = p.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path has no parent directory",
        )
    })?;

    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        let dir_mode = if is_system_path { 0o755 } else { 0o700 };
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(dir_mode));
    }

    // reject writing if destination is a symlink
    #[cfg(unix)]
    if let Ok(meta) = fs::symlink_metadata(p) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing to write through symlink",
            ));
        }
    }

    // atomic write via temporary file in the same directory followed by atomic rename
    let tmp_name = format!(
        ".{}.tmp.{}",
        p.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    );
    let tmp_path = parent.join(tmp_name);

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file_mode = if is_system_path { 0o644 } else { 0o600 };
        options
            .mode(file_mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    let write_res = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = options.open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, p)?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    write_res
}

// validates file ownership against strict security policies depending on execution context
#[cfg(unix)]
pub(crate) fn verify_file_ownership(
    path: &Path,
    current_uid: libc::uid_t,
    file_uid: libc::uid_t,
    is_system_path: bool,
    trusted_uids: &[libc::uid_t],
) -> std::io::Result<()> {
    if current_uid == 0 {
        // Root daemon execution context
        if is_system_path {
            if file_uid != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "security violation: system config {} owned by untrusted uid {}",
                        path.display(),
                        file_uid
                    ),
                ));
            }
        } else {
            // Non-system path read by root: MUST belong to a trusted UID (root or explicitly configured user)
            if !trusted_uids.contains(&file_uid) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "security violation: config {} owned by untrusted uid {} (allowed uids: {:?})",
                        path.display(),
                        file_uid,
                        trusted_uids
                    ),
                ));
            }
        }
    } else if file_uid != current_uid && file_uid != 0 {
        // Non-root execution context: only allow current user or root files
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "security violation: config {} owned by untrusted uid {}",
                path.display(),
                file_uid
            ),
        ));
    }

    Ok(())
}

// safely reads content while atomically rejecting symlinks and enforcing strict ownership checks
fn safe_read<P: AsRef<Path>>(path: P) -> std::io::Result<String> {
    let p = path.as_ref();
    let is_system_path = p.starts_with("/run/albus") || p.starts_with("/etc/albus");

    #[cfg(unix)]
    let _guard = if !is_system_path {
        FsPrivilegeGuard::drop_to_user()
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

    const MAX_CONFIG_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB maximum config size
    if meta.len() > MAX_CONFIG_FILE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "config file {} exceeds maximum safety limit (10 MB)",
                p.display()
            ),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let file_uid = meta.uid();
        let current_uid = unsafe { libc::getuid() };

        let mut trusted_uids = vec![0 as libc::uid_t];
        if let Some((sudo_uid, _)) = get_sudo_user_info() {
            if !trusted_uids.contains(&sudo_uid) {
                trusted_uids.push(sudo_uid);
            }
        }
        if let Some((cfg_uid, _)) = get_configured_user_info() {
            if !trusted_uids.contains(&cfg_uid) {
                trusted_uids.push(cfg_uid);
            }
        }

        verify_file_ownership(p, current_uid, file_uid, is_system_path, &trusted_uids)?;
    }

    use std::io::Read;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
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
        // 1. check explicit ALBUS_CONFIG_USER environment variable
        if let Some((_uid, home)) = get_configured_user_info() {
            let cfg = home.join(".config/albus/config.json");
            if !cfg.starts_with("/root") {
                return cfg;
            }
        }
        // 2. check sudo user environment with strict format and passwd validation
        if let Some((_uid, sudo_home)) = get_sudo_user_info() {
            let sudo_cfg = sudo_home.join(".config/albus/config.json");
            if !sudo_cfg.starts_with("/root") {
                return sudo_cfg;
            }
        }
        // 3. check current process home (for user-level execution only)
        if !crate::core::ebpf::is_root() {
            if let Ok(home) = std::env::var("HOME") {
                let user_cfg = PathBuf::from(&home).join(".config/albus/config.json");
                if !user_cfg.starts_with("/root") {
                    return user_cfg;
                }
            }
        }
        // 4. system-wide fallback (never arbitrarily guess a user from /home when root)
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

        // 3. load from default config path on disk (ALBUS_CONFIG_USER, SUDO_USER, $HOME if unprivileged, or /etc/albus/config.json)
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

    // returns the effective upstream socks5 proxy url if explicit socks5_proxy or tor mode is configured
    pub fn effective_proxy(&self) -> Option<String> {
        if let Some(ref p) = self.socks5_proxy {
            let clean = p.trim();
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }
        if self.tor {
            return Some("socks5://127.0.0.1:9050".to_string());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default_values() {
        let cfg = Config::default();
        assert_eq!(cfg.mss, 88);
        assert_eq!(cfg.min_mss, 64);
        assert_eq!(cfg.restore_mss, 0);
        assert_eq!(cfg.restore_after_bytes, 600);
        assert_eq!(cfg.ports, vec![443]);
        assert_eq!(cfg.cgroup_path, "/sys/fs/cgroup");
        assert_eq!(cfg.fake_ttl, 8);
        assert_eq!(cfg.fake_sni, None);
        assert_eq!(cfg.fake_bad_checksum, false);
        assert_eq!(cfg.fake_seq_offset, 0);
        assert_eq!(cfg.auto_ttl, true);
        assert_eq!(cfg.min_ttl, 3);
        assert_eq!(cfg.max_ttl, 12);
        assert_eq!(cfg.doh_enabled, true);
        assert_eq!(cfg.dns_racing, true);
        assert_eq!(cfg.doh_upstream, "quad9");
        assert!(cfg.doh_bootstrap_ips.is_empty());
        assert_eq!(cfg.block_quic, true);
        assert_eq!(cfg.block_stun, true);
        assert_eq!(cfg.kill_switch, true);
        assert_eq!(cfg.network_lockdown, false);
        assert_eq!(cfg.block_ipv6, true);
        assert_eq!(cfg.dnssec, true);
        assert_eq!(cfg.pqc, true);
        assert_eq!(cfg.ram_only, false);
        assert_eq!(cfg.verbose, false);
        assert_eq!(cfg.anti_dns_rebinding, true);
        assert_eq!(cfg.block_undelegated, true);
        assert_eq!(cfg.edns_padding, true);
        assert_eq!(cfg.blocklist, true);
        assert_eq!(cfg.blocklist_path, None);
        assert_eq!(cfg.dns64, false);
        assert_eq!(cfg.block_bogons, true);
        assert_eq!(cfg.uncloak_cnames, true);
        assert_eq!(cfg.netmon, true);
        assert_eq!(cfg.tcp_listener, true);
        assert_eq!(cfg.local_doh, true);
        assert_eq!(cfg.local_doh_addr, "127.0.0.1:8053");
        assert_eq!(cfg.query_log, false);
        assert_eq!(cfg.odoh_enabled, false);
        assert_eq!(cfg.socks5_proxy, None);
        assert_eq!(cfg.tor, false);
        assert_eq!(cfg.nx_log, false);
        assert_eq!(cfg.nx_log_path, None);
        assert!(cfg.schedules.is_empty());
        assert_eq!(cfg.edns_client_subnet, None);
        assert_eq!(cfg.metrics, false);
        assert_eq!(cfg.metrics_addr, "127.0.0.1:9153");
        assert_eq!(cfg.tls_client_cert, None);
        assert_eq!(cfg.tls_client_key, None);
        assert!(cfg.sources.is_empty());

        // Verify serde deserialization of empty json "{}" yields identical defaults
        let from_empty: Config =
            serde_json::from_str("{}").expect("empty json must parse with all defaults");
        assert_eq!(from_empty.mss, 88);
        assert_eq!(from_empty.min_mss, 64);
        assert_eq!(from_empty.doh_upstream, "quad9");
        assert_eq!(from_empty.auto_ttl, true);
        assert_eq!(from_empty.block_quic, true);
        assert_eq!(from_empty.block_stun, true);
        assert_eq!(from_empty.kill_switch, true);
        assert_eq!(from_empty.network_lockdown, false);
        assert_eq!(from_empty.blocklist, true);
        assert_eq!(from_empty.local_doh, true);
        assert_eq!(from_empty.local_doh_addr, "127.0.0.1:8053");
        assert_eq!(from_empty.socks5_proxy, None);
        assert_eq!(from_empty.tor, false);
        assert_eq!(from_empty.nx_log, false);
        assert_eq!(from_empty.nx_log_path, None);
        assert!(from_empty.schedules.is_empty());
        assert_eq!(from_empty.edns_client_subnet, None);
        assert_eq!(from_empty.metrics, false);
        assert_eq!(from_empty.metrics_addr, "127.0.0.1:9153");
        assert_eq!(from_empty.tls_client_cert, None);
        assert_eq!(from_empty.tls_client_key, None);
        assert!(from_empty.sources.is_empty());
    }

    #[test]
    fn test_effective_proxy() {
        let mut cfg = Config::default();
        assert_eq!(cfg.effective_proxy(), None);

        cfg.tor = true;
        assert_eq!(
            cfg.effective_proxy().as_deref(),
            Some("socks5://127.0.0.1:9050")
        );

        // explicit socks5_proxy takes precedence over tor default
        cfg.socks5_proxy = Some("socks5://10.0.0.1:1080".to_string());
        assert_eq!(
            cfg.effective_proxy().as_deref(),
            Some("socks5://10.0.0.1:1080")
        );
    }

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

    #[test]
    fn test_file_ownership_verification() {
        #[cfg(unix)]
        {
            let path = Path::new("/home/attacker/.config/albus/config.json");
            let sys_path = Path::new("/etc/albus/config.json");

            // Case 1: Root daemon reading /etc/albus/config.json owned by root (uid 0) -> ALLOWED
            assert!(verify_file_ownership(sys_path, 0, 0, true, &[0]).is_ok());

            // Case 2: Root daemon reading /etc/albus/config.json owned by attacker (uid 1001) -> FORBIDDEN
            assert!(verify_file_ownership(sys_path, 0, 1001, true, &[0]).is_err());

            // Case 3: Root daemon without SUDO_UID / ALBUS_CONFIG_USER reading user config owned by attacker -> FORBIDDEN
            let res = verify_file_ownership(path, 0, 1001, false, &[0]);
            assert!(
                res.is_err(),
                "Root daemon must reject untrusted user config without explicit trusted UID"
            );
            assert_eq!(
                res.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );

            // Case 4: Root daemon with trusted user (uid 1000) reading trusted user config -> ALLOWED
            assert!(verify_file_ownership(path, 0, 1000, false, &[0, 1000]).is_ok());

            // Case 5: Root daemon with trusted user (uid 1000) reading attacker's config (uid 1001) -> FORBIDDEN
            assert!(verify_file_ownership(path, 0, 1001, false, &[0, 1000]).is_err());

            // Case 6: Unprivileged process (uid 1000) reading other user's file (uid 1001) -> FORBIDDEN
            assert!(verify_file_ownership(path, 1000, 1001, false, &[1000]).is_err());

            // Case 7: Unprivileged process (uid 1000) reading own file (uid 1000) -> ALLOWED
            assert!(verify_file_ownership(path, 1000, 1000, false, &[1000]).is_ok());

            // Case 8: Unprivileged process (uid 1000) reading root-owned template (uid 0) -> ALLOWED
            assert!(verify_file_ownership(path, 1000, 0, false, &[1000]).is_ok());
        }
    }

    #[test]
    fn test_root_does_not_load_untrusted_home_config() {
        // Ensure no leftover environment variables interfere with test
        let prev_sudo_user = std::env::var("SUDO_USER").ok();
        let prev_sudo_uid = std::env::var("SUDO_UID").ok();
        let prev_cfg_user = std::env::var("ALBUS_CONFIG_USER").ok();

        std::env::remove_var("SUDO_USER");
        std::env::remove_var("SUDO_UID");
        std::env::remove_var("ALBUS_CONFIG_USER");

        // When running as root without explicit user env, default_config_path must return /etc/albus/config.json
        if crate::core::ebpf::is_root() {
            let def_path = Config::default_config_path();
            assert_eq!(def_path, PathBuf::from("/etc/albus/config.json"));
        }

        // Restore env vars
        if let Some(v) = prev_sudo_user {
            std::env::set_var("SUDO_USER", v);
        }
        if let Some(v) = prev_sudo_uid {
            std::env::set_var("SUDO_UID", v);
        }
        if let Some(v) = prev_cfg_user {
            std::env::set_var("ALBUS_CONFIG_USER", v);
        }
    }
}
