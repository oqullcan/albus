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
    #[serde(default)]
    pub fake_window_size: Option<u16>,
    #[serde(default)]
    pub fake_tcp_flags: Option<String>,
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
    #[serde(default, alias = "cloak_file", alias = "cloaking_rules_file")]
    pub cloaking_rules_path: Option<String>,
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
    #[serde(default = "default_privacy_level", alias = "privacy_level")]
    pub web_ui_privacy_level: u8,
    #[serde(default = "default_max_query_log_entries", alias = "max_query_log_entries")]
    pub web_ui_max_query_log_entries: usize,
    #[serde(default)]
    pub dnscrypt_servers: Vec<String>,
    #[serde(default)]
    pub dnscrypt_relays: Vec<String>,
    #[serde(default = "default_log_format")]
    pub query_log_format: String,
    #[serde(default = "default_log_format")]
    pub nx_log_format: String,
    #[serde(default)]
    pub query_meta: Vec<String>,
    #[serde(default = "default_true")]
    pub dnscrypt_ephemeral_keys: bool,
    #[serde(default = "default_listen_addresses")]
    pub listen_addresses: Vec<String>,
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub http3: bool,
    #[serde(default = "default_netprobe_timeout")]
    pub netprobe_timeout: i32,
    #[serde(default = "default_netprobe_address")]
    pub netprobe_address: String,
    #[serde(default = "default_bootstrap_resolvers")]
    pub bootstrap_resolvers: Vec<String>,
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,
    #[serde(default = "default_lb_strategy")]
    pub lb_strategy: String,
    #[serde(default = "default_true")]
    pub lb_estimator: bool,
    #[serde(default)]
    pub anonymized_dns_routes: Vec<AnonymizedDnsRoute>,
    #[serde(default)]
    pub skip_incompatible: bool,
    #[serde(default = "default_true")]
    pub direct_cert_fallback: bool,
    #[serde(default = "default_fragments_blocked")]
    pub fragments_blocked: Vec<String>,
    #[serde(default)]
    pub local_doh_tls: bool,
    #[serde(default)]
    pub local_doh_cert_file: Option<String>,
    #[serde(default)]
    pub local_doh_key_file: Option<String>,
    #[serde(default = "default_blocked_query_response")]
    pub blocked_query_response: String,
    #[serde(default)]
    pub offline_mode: bool,
    #[serde(default = "default_true")]
    pub ignore_system_dns: bool,
    #[serde(default = "default_true")]
    pub cloaked_ptr: bool,
    #[serde(default)]
    pub tls_disable_session_tickets: bool,
    #[serde(default = "default_cert_refresh_delay")]
    pub cert_refresh_delay: u32,
    #[serde(default)]
    pub cert_ignore_timestamp: bool,
    #[serde(default)]
    pub ignored_qtypes: Vec<String>,
    #[serde(default = "default_true")]
    pub udp_pool: bool,
    #[serde(default = "default_cache_min_ttl")]
    pub cache_min_ttl: u32,
    #[serde(default = "default_cache_max_ttl")]
    pub cache_max_ttl: u32,
    #[serde(default)]
    pub blocked_ips_file: Option<String>,
    #[serde(default)]
    pub allowed_ips_file: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub blocked_names_log_path: Option<String>,
    #[serde(default = "default_log_format")]
    pub blocked_names_log_format: String,
    #[serde(default)]
    pub blocked_ips_log_path: Option<String>,
    #[serde(default = "default_log_format")]
    pub blocked_ips_log_format: String,
    #[serde(default)]
    pub allowed_names_log_path: Option<String>,
    #[serde(default = "default_log_format")]
    pub allowed_names_log_format: String,
    #[serde(default)]
    pub allowed_ips_log_path: Option<String>,
    #[serde(default = "default_log_format")]
    pub allowed_ips_log_format: String,
    #[serde(default)]
    pub force_tcp: bool,
    #[serde(default)]
    pub captive_portals_map_file: Option<String>,
    #[serde(default)]
    pub server_names: Vec<String>,
    #[serde(default)]
    pub disabled_server_names: Vec<String>,
    #[serde(default = "default_true")]
    pub ipv4_servers: bool,
    #[serde(default)]
    pub ipv6_servers: bool,
    #[serde(default = "default_true")]
    pub doh_servers: bool,
    #[serde(default)]
    pub odoh_servers: bool,
    #[serde(default)]
    pub require_dnssec: bool,
    #[serde(default = "default_true")]
    pub require_nolog: bool,
    #[serde(default = "default_true")]
    pub require_nofilter: bool,
    #[serde(default)]
    pub dot_upstream: Option<String>,
    #[serde(default)]
    pub client_rules: Vec<crate::dns::client_rules::ClientProfileConfig>,
    #[serde(default)]
    pub client_rules_file: Option<String>,
    #[serde(default)]
    pub anonymized_doh_relays: Vec<String>,
    #[serde(default = "default_true")]
    pub load_system_hosts: bool,
    #[serde(default)]
    pub safe_search: bool,
    #[serde(default)]
    pub youtube_restricted_mode: Option<String>,
    #[serde(default)]
    pub local_dot: bool,
    #[serde(default = "default_local_dot_addr")]
    pub local_dot_addr: String,
    #[serde(default)]
    pub local_dot_cert_file: Option<String>,
    #[serde(default)]
    pub local_dot_key_file: Option<String>,
    #[serde(default)]
    pub randomize_ecs: bool,
    #[serde(default)]
    pub doq_upstream: Option<String>,
    #[serde(default)]
    pub pid_file: Option<String>,
    #[serde(default = "default_cloak_ttl")]
    pub cloak_ttl: u32,
    #[serde(default = "default_reject_ttl")]
    pub reject_ttl: u32,
    #[serde(default)]
    pub defense_profile: Option<String>,
    #[serde(default)]
    pub ja4_mimic: Option<String>,
    #[serde(default)]
    pub stack_morph: Option<String>,
    #[serde(default)]
    pub anti_injection: bool,
    #[serde(default = "default_anti_injection_ttl_tolerance")]
    pub anti_injection_ttl_tolerance: u8,
    #[serde(default)]
    pub simd_accel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnonymizedDnsRoute {
    pub server_name: String,
    pub via: Vec<String>,
}

fn default_local_dot_addr() -> String {
    "127.0.0.1:853".to_string()
}

fn default_cloak_ttl() -> u32 {
    300
}

fn default_reject_ttl() -> u32 {
    10
}

fn default_blocked_query_response() -> String {
    "hinfo".to_string()
}

fn default_cache_min_ttl() -> u32 {
    60
}

fn default_cache_max_ttl() -> u32 {
    86400
}

fn default_cert_refresh_delay() -> u32 {
    240
}

fn default_netprobe_timeout() -> i32 {
    60
}

fn default_netprobe_address() -> String {
    "9.9.9.9:53".to_string()
}

fn default_bootstrap_resolvers() -> Vec<String> {
    vec!["9.9.9.11:53".to_string(), "8.8.8.8:53".to_string()]
}

fn default_max_clients() -> usize {
    250
}

fn default_lb_strategy() -> String {
    "wp2".to_string()
}

fn default_fragments_blocked() -> Vec<String> {
    vec!["cisco".to_string(), "cleanbrowsing-adult".to_string()]
}

fn default_log_format() -> String {
    "tsv".to_string()
}

fn default_listen_addresses() -> Vec<String> {
    vec!["127.0.0.1:53".to_string()]
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
    "127.0.0.1:0205".to_string()
}

fn default_privacy_level() -> u8 {
    1
}

fn default_max_query_log_entries() -> usize {
    100
}

fn default_anti_injection_ttl_tolerance() -> u8 {
    4
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
            fake_window_size: None,
            fake_tcp_flags: None,
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
            cloaking_rules_path: None,
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
            web_ui_addr: "127.0.0.1:0205".to_string(),
            web_ui_user: None,
            web_ui_pass: None,
            web_ui_privacy_level: 1,
            web_ui_max_query_log_entries: 100,
            dnscrypt_servers: Vec::new(),
            dnscrypt_relays: Vec::new(),
            query_log_format: "tsv".to_string(),
            nx_log_format: "tsv".to_string(),
            query_meta: Vec::new(),
            dnscrypt_ephemeral_keys: true,
            listen_addresses: vec!["127.0.0.1:53".to_string()],
            user_name: None,
            http3: false,
            netprobe_timeout: 60,
            netprobe_address: "9.9.9.9:53".to_string(),
            bootstrap_resolvers: vec!["9.9.9.11:53".to_string(), "8.8.8.8:53".to_string()],
            max_clients: 250,
            lb_strategy: "wp2".to_string(),
            lb_estimator: true,
            anonymized_dns_routes: Vec::new(),
            skip_incompatible: false,
            direct_cert_fallback: true,
            fragments_blocked: vec!["cisco".to_string(), "cleanbrowsing-adult".to_string()],
            local_doh_tls: false,
            local_doh_cert_file: None,
            local_doh_key_file: None,
            blocked_query_response: "hinfo".to_string(),
            offline_mode: false,
            ignore_system_dns: true,
            cloaked_ptr: true,
            tls_disable_session_tickets: false,
            cert_refresh_delay: 240,
            cert_ignore_timestamp: false,
            ignored_qtypes: Vec::new(),
            udp_pool: true,
            cache_min_ttl: 60,
            cache_max_ttl: 86400,
            blocked_ips_file: None,
            allowed_ips_file: None,
            allowed_ips: Vec::new(),
            blocked_names_log_path: None,
            blocked_names_log_format: "tsv".to_string(),
            blocked_ips_log_path: None,
            blocked_ips_log_format: "tsv".to_string(),
            allowed_names_log_path: None,
            allowed_names_log_format: "tsv".to_string(),
            allowed_ips_log_path: None,
            allowed_ips_log_format: "tsv".to_string(),
            force_tcp: false,
            captive_portals_map_file: None,
            server_names: Vec::new(),
            disabled_server_names: Vec::new(),
            ipv4_servers: true,
            ipv6_servers: false,
            doh_servers: true,
            odoh_servers: false,
            require_dnssec: false,
            require_nolog: true,
            require_nofilter: true,
            dot_upstream: None,
            client_rules: Vec::new(),
            client_rules_file: None,
            anonymized_doh_relays: Vec::new(),
            load_system_hosts: true,
            safe_search: false,
            youtube_restricted_mode: None,
            local_dot: false,
            local_dot_addr: "127.0.0.1:853".to_string(),
            local_dot_cert_file: None,
            local_dot_key_file: None,
            randomize_ecs: false,
            doq_upstream: None,
            pid_file: None,
            cloak_ttl: 300,
            reject_ttl: 10,
            defense_profile: None,
            ja4_mimic: None,
            stack_morph: None,
            anti_injection: false,
            anti_injection_ttl_tolerance: 4,
            simd_accel: false,
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
        let target_res = safe_write(target_path, &json);

        // 3. also sync to /etc/albus/config.json if running as root or directory exists
        let etc = Path::new("/etc/albus/config.json");
        let mut etc_written = false;
        if crate::core::ebpf::is_root() || etc.exists() {
            if safe_write(etc, &json).is_ok() {
                etc_written = true;
            }
        }

        if let Err(e) = target_res {
            if !etc_written {
                return Err(Box::new(e));
            }
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

    /// Applies active defense profile settings if defense_profile is set.
    pub fn apply_defense_profile(&mut self) {
        if let Some(ref prof_str) = self.defense_profile {
            if let Some(profile) = crate::app::defense_profile::DefenseProfile::from_str(prof_str) {
                profile.apply(self);
            }
        }
    }

    /// Merges command-line arguments into configuration schema.
    pub fn merge_run_args(&mut self, args: &crate::app::cli::RunArgs) {
        if args.fake_ttl != 8 {
            self.fake_ttl = args.fake_ttl;
        }
        if let Some(ref sni) = args.fake_sni {
            self.fake_sni = Some(sni.clone());
        }
        if args.fake_bad_checksum {
            self.fake_bad_checksum = true;
        }
        if args.fake_seq_offset != 0 {
            self.fake_seq_offset = args.fake_seq_offset;
        }
        if let Some(win) = args.fake_window_size {
            self.fake_window_size = Some(win);
        }
        if let Some(ref flags) = args.fake_tcp_flags {
            self.fake_tcp_flags = Some(flags.clone());
        }
        if !args.auto_ttl {
            self.auto_ttl = false;
        }
        if args.min_ttl != 3 {
            self.min_ttl = args.min_ttl;
        }
        if args.max_ttl != 12 {
            self.max_ttl = args.max_ttl;
        }
        if !args.doh {
            self.doh_enabled = false;
        }
        if !args.dns_racing {
            self.dns_racing = false;
        }
        if args.doh_upstream != "quad9" {
            self.doh_upstream = args.doh_upstream.clone();
        }
        if !args.doh_bootstrap_ips.is_empty() {
            self.doh_bootstrap_ips = args.doh_bootstrap_ips.clone();
        }
        if !args.dnssec {
            self.dnssec = false;
        }
        if !args.block_quic {
            self.block_quic = false;
        }
        if !args.block_stun {
            self.block_stun = false;
        }
        if !args.kill_switch {
            self.kill_switch = false;
        }
        if args.network_lockdown {
            self.network_lockdown = true;
        }
        if !args.block_ipv6 {
            self.block_ipv6 = false;
        }
        if args.mss != 88 {
            self.mss = args.mss;
        }
        if args.min_mss != 64 {
            self.min_mss = args.min_mss;
        }
        if args.restore_after_bytes != 600 {
            self.restore_after_bytes = args.restore_after_bytes;
        }
        if args.restore_mss != 0 {
            self.restore_mss = args.restore_mss;
        }
        if args.ports != [443] {
            self.ports = args.ports.clone();
        }
        if args.cgroup != "/sys/fs/cgroup" {
            self.cgroup_path = args.cgroup.clone();
        }
        if !args.pqc {
            self.pqc = false;
        }
        if args.ram_only {
            self.ram_only = true;
        }
        if !args.anti_dns_rebinding {
            self.anti_dns_rebinding = false;
        }
        if !args.block_undelegated {
            self.block_undelegated = false;
        }
        if !args.edns_padding {
            self.edns_padding = false;
        }
        if !args.blocklist {
            self.blocklist = false;
        }
        if let Some(ref path) = args.blocklist_path {
            self.blocklist_path = Some(path.clone());
        }
        if let Some(ref domains) = args.allow_domains {
            self.allow_domains = domains.clone();
        }
        if let Some(ref path) = args.allowlist_path {
            self.allowlist_path = Some(path.clone());
        }
        if args.dns64 {
            self.dns64 = true;
        }
        if !args.block_bogons {
            self.block_bogons = false;
        }
        if !args.uncloak_cnames {
            self.uncloak_cnames = false;
        }
        if !args.netmon {
            self.netmon = false;
        }
        if !args.tcp_listener {
            self.tcp_listener = false;
        }
        if !args.local_doh {
            self.local_doh = false;
        }
        if args.local_doh_addr != "127.0.0.1:8053" {
            self.local_doh_addr = args.local_doh_addr.clone();
        }
        if args.query_log {
            self.query_log = true;
        }
        if let Some(ref path) = args.query_log_path {
            self.query_log_path = Some(path.clone());
        }
        if let Some(ref key) = args.ipcrypt_key {
            self.ipcrypt_key = Some(key.clone());
        }
        if args.odoh {
            self.odoh_enabled = true;
        }
        if let Some(ref relay) = args.odoh_relay {
            self.odoh_relay = Some(relay.clone());
        }
        if let Some(ref target) = args.odoh_target {
            self.odoh_target = Some(target.clone());
        }
        if let Some(ref proxy) = args.socks5_proxy {
            self.socks5_proxy = Some(proxy.clone());
        }
        if args.tor {
            self.tor = true;
        }
        if args.nx_log {
            self.nx_log = true;
        }
        if let Some(ref path) = args.nx_log_path {
            self.nx_log_path = Some(path.clone());
        }
        if let Some(ref ecs) = args.edns_client_subnet {
            self.edns_client_subnet = Some(ecs.clone());
        }
        if args.metrics {
            self.metrics = true;
        }
        if args.metrics_addr != "127.0.0.1:9153" {
            self.metrics_addr = args.metrics_addr.clone();
        }
        if let Some(ref cert) = args.tls_client_cert {
            self.tls_client_cert = Some(cert.clone());
        }
        if let Some(ref key) = args.tls_client_key {
            self.tls_client_key = Some(key.clone());
        }
        if let Some(ref path) = args.forwarding_rules_path {
            self.forwarding_rules_path = Some(path.clone());
        }
        if args.cache_neg_min_ttl != 60 {
            self.cache_neg_min_ttl = args.cache_neg_min_ttl;
        }
        if args.cache_neg_max_ttl != 600 {
            self.cache_neg_max_ttl = args.cache_neg_max_ttl;
        }
        if let Some(ref path) = args.tls_key_log_file {
            self.tls_key_log_file = Some(path.clone());
        }
        if (args.timeout_load_reduction - 0.75).abs() > f64::EPSILON {
            self.timeout_load_reduction = args.timeout_load_reduction;
        }
        if let Some(w) = args.web_ui {
            self.web_ui = w;
        }
        if let Some(ref addr) = args.web_ui_addr {
            self.web_ui_addr = addr.clone();
        }
        if let Some(ref user) = args.web_ui_user {
            self.web_ui_user = Some(user.clone());
        }
        if let Some(ref pass) = args.web_ui_pass {
            self.web_ui_pass = Some(pass.clone());
        }
        if let Some(ref s) = args.dnscrypt_servers {
            self.dnscrypt_servers = s.clone();
        }
        if let Some(ref r) = args.dnscrypt_relays {
            self.dnscrypt_relays = r.clone();
        }
        if args.cache_min_ttl != 60 {
            self.cache_min_ttl = args.cache_min_ttl;
        }
        if args.cache_max_ttl != 86400 {
            self.cache_max_ttl = args.cache_max_ttl;
        }
        if let Some(ref path) = args.blocked_ips_file {
            self.blocked_ips_file = Some(path.clone());
        }
        if let Some(ref path) = args.allowed_ips_file {
            self.allowed_ips_file = Some(path.clone());
        }
        if let Some(ref ips) = args.allowed_ips {
            self.allowed_ips = ips.clone();
        }
        if let Some(ref path) = args.blocked_names_log {
            self.blocked_names_log_path = Some(path.clone());
        }
        if let Some(ref path) = args.blocked_ips_log {
            self.blocked_ips_log_path = Some(path.clone());
        }
        if let Some(ref path) = args.allowed_names_log {
            self.allowed_names_log_path = Some(path.clone());
        }
        if let Some(ref path) = args.allowed_ips_log {
            self.allowed_ips_log_path = Some(path.clone());
        }
        if args.force_tcp {
            self.force_tcp = true;
        }
        if let Some(ref path) = args.captive_map_file {
            self.captive_portals_map_file = Some(path.clone());
        }
        if let Some(ref dot) = args.dot_upstream {
            self.dot_upstream = Some(dot.clone());
        }
        if let Some(ref path) = args.client_rules_file {
            self.client_rules_file = Some(path.clone());
        }
        if let Some(ref relays) = args.anonymized_doh_relays {
            self.anonymized_doh_relays = relays.clone();
        }
        if let Some(v) = args.safe_search {
            self.safe_search = v;
        }
        if let Some(ref mode) = args.youtube_restricted_mode {
            self.youtube_restricted_mode = Some(mode.clone());
        }
        if let Some(v) = args.local_dot {
            self.local_dot = v;
        }
        if let Some(ref addr) = args.local_dot_addr {
            self.local_dot_addr = addr.clone();
        }
        if let Some(v) = args.randomize_ecs {
            self.randomize_ecs = v;
        }
        if let Some(v) = args.load_system_hosts {
            self.load_system_hosts = v;
        }
        if let Some(ref doq) = args.doq_upstream {
            self.doq_upstream = Some(doq.clone());
        }
        if let Some(ref p) = args.pidfile {
            self.pid_file = Some(p.clone());
        }
        if args.cloak_ttl != 10 && args.cloak_ttl != 300 {
            self.cloak_ttl = args.cloak_ttl;
        }
        if args.reject_ttl != 10 {
            self.reject_ttl = args.reject_ttl;
        }
        if let Some(ref fb) = args.fragments_blocked {
            self.fragments_blocked = fb.clone();
        }
        if let Some(ref path) = args.cloaking_rules_path {
            self.cloaking_rules_path = Some(path.clone());
        }
        if let Some(lvl) = args.web_ui_privacy_level {
            self.web_ui_privacy_level = lvl;
        }
        if let Some(ref prof) = args.defense_profile {
            self.defense_profile = Some(prof.clone());
        }
        if let Some(ref j4) = args.ja4_mimic {
            self.ja4_mimic = Some(j4.clone());
        }
        if let Some(ref sm) = args.stack_morph {
            self.stack_morph = Some(sm.clone());
        }
        if args.anti_injection {
            self.anti_injection = true;
        }
        if let Some(tol) = args.anti_injection_ttl_tolerance {
            self.anti_injection_ttl_tolerance = tol;
        }
        if args.simd_accel {
            self.simd_accel = true;
        }
        if args.verbose {
            self.verbose = true;
        }

        self.apply_defense_profile();
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
        assert_eq!(cfg.web_ui, false);
        assert_eq!(cfg.web_ui_user, None);
        assert_eq!(cfg.web_ui_pass, None);
        assert_eq!(cfg.web_ui_addr, "127.0.0.1:0205");

        assert_eq!(cfg.cache_min_ttl, 60);
        assert_eq!(cfg.cache_max_ttl, 86400);
        assert_eq!(cfg.force_tcp, false);
        assert_eq!(cfg.require_nolog, true);
        assert_eq!(cfg.require_nofilter, true);
        assert_eq!(cfg.ipv4_servers, true);
        assert_eq!(cfg.ipv6_servers, false);

        // Verify serde deserialization of empty json "{}" yields identical defaults
        let from_empty: Config =
            serde_json::from_str("{}").expect("empty json must parse with all defaults");
        assert_eq!(from_empty.cache_min_ttl, 60);
        assert_eq!(from_empty.cache_max_ttl, 86400);
        assert_eq!(from_empty.force_tcp, false);
        assert_eq!(from_empty.require_nolog, true);
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
        assert_eq!(from_empty.web_ui, false);
        assert_eq!(from_empty.web_ui_user, None);
        assert_eq!(from_empty.web_ui_pass, None);
        assert_eq!(from_empty.web_ui_addr, "127.0.0.1:0205");
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

    #[test]
    fn test_config_security_defaults_and_doc_parity() {
        let cfg = Config::default();
        assert_eq!(cfg.web_ui, false, "web_ui must default to false for defense-in-depth");
        assert_eq!(cfg.web_ui_user, None, "web_ui_user must default to None");
        assert_eq!(cfg.web_ui_pass, None, "web_ui_pass must default to None");

        let cli_doc_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("wiki/CLI-Reference-and-Configuration.md");
        if cli_doc_path.exists() {
            let doc_content = std::fs::read_to_string(&cli_doc_path)
                .expect("CLI-Reference-and-Configuration.md should be readable");
            // Parity check 1: No legacy hardcoded credentials "ogy" or "12345"
            assert!(
                !doc_content.contains("\"web_ui_user\": \"ogy\""),
                "documentation must not claim 'ogy' is default web_ui_user"
            );
            assert!(
                !doc_content.contains("\"web_ui_pass\": \"12345\""),
                "documentation must not claim '12345' is default web_ui_pass"
            );
            assert!(
                !doc_content.contains("| `ogy` |"),
                "CLI table must not claim 'ogy' is default username"
            );
            assert!(
                !doc_content.contains("| `12345` |"),
                "CLI table must not claim '12345' is default password"
            );

            // Parity check 2: web_ui default documented as false
            assert!(
                doc_content.contains("\"web_ui\": false"),
                "documentation example must have web_ui: false"
            );

            // Parity check 3: volatile_config_path documented as priority 1
            assert!(
                doc_content.contains("1. `volatile_config_path()`"),
                "documentation must list volatile_config_path as priority 1"
            );
        }
    }
}
