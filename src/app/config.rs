//! persistent and ephemeral runtime configuration schema, default values, and json persistence.

use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_mss")]
    pub mss: u16,
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
            block_ipv6: true,
            dnssec: true,
            pqc: true,
            ram_only: true,
            verbose: false,
        }
    }
}

impl Config {
    // resolves configuration path across user directories, sudo callers, and system daemon paths
    pub fn default_config_path() -> PathBuf {
        // check volatile ram-backed shared memory first
        let shm_path = PathBuf::from("/dev/shm/albus/config.json");
        if shm_path.exists() {
            return shm_path;
        }

        // 1. check sudo user environment
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            let sudo_home = PathBuf::from(format!("/home/{}", sudo_user)).join(".config/albus/config.json");
            if sudo_home.exists() {
                return sudo_home;
            }
        }
        // 2. check current process home
        if let Ok(home) = std::env::var("HOME") {
            let user_cfg = PathBuf::from(&home).join(".config/albus/config.json");
            if user_cfg.exists() || !user_cfg.starts_with("/root") {
                return user_cfg;
            }
        }
        // 3. iterate standard home entries
        if let Ok(entries) = fs::read_dir("/home") {
            for entry in entries.flatten() {
                let candidate = entry.path().join(".config/albus/config.json");
                if candidate.exists() {
                    return candidate;
                }
            }
        }
        // 4. system-wide fallback
        PathBuf::from("/etc/albus/config.json")
    }

    // loads configuration payload from a specified filesystem path
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = fs::read_to_string(path)?;
        let cfg: Config = serde_json::from_str(&content)?;
        Ok(cfg)
    }

    // writes serialized json payload to disk and volatile ram-backed tmpfs (/dev/shm)
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_string_pretty(self)?;

        // 1. write volatile shared memory copy for active runtime inspection
        let shm_path = PathBuf::from("/dev/shm/albus/config.json");
        if let Some(parent) = shm_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&shm_path, &json);

        // 2. persist master configuration so user preferences are retained across reboots
        let target_path = path.as_ref();
        if let Some(parent) = target_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(target_path, &json)?;

        // 3. mirror to system-wide location if executing with superuser capabilities
        if crate::core::ebpf::is_root() {
            let etc = Path::new("/etc/albus/config.json");
            if let Some(p) = etc.parent() {
                let _ = fs::create_dir_all(p);
            }
            let _ = fs::write(etc, &json);
        }

        Ok(())
    }

    // loads existing configuration or initializes default schema
    pub fn load_or_default() -> Self {
        let path = Self::default_config_path();
        if path.exists() {
            Self::load_from_file(&path).unwrap_or_default()
        } else {
            let etc_path = PathBuf::from("/etc/albus/config.json");
            if etc_path.exists() {
                Self::load_from_file(&etc_path).unwrap_or_default()
            } else {
                Self::default()
            }
        }
    }
}
