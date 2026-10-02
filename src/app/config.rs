//! persistent and ephemeral runtime configuration schema, default values, and json persistence.

use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use tracing::warn;

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
    #[serde(default = "default_true")]
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
            shaping_watchdog: true,
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

        // 3. Cross-check SUDO_UID when it is present. PRIV-02: this used to be
        // a bare "if the uid parses and matches" with no requirement that it
        // parse at all, so an unparseable SUDO_UID skipped the comparison and
        // the caller proceeded on an unverified identity. It now shares the one
        // fail-closed predicate with the privilege-drop guard.
        if std::env::var("SUDO_UID").is_ok() {
            let expected_uid: libc::uid_t = std::env::var("SUDO_UID").ok()?.trim().parse().ok()?;
            let gid: Option<libc::gid_t> = std::env::var("SUDO_GID")
                .ok()
                .and_then(|s| s.trim().parse().ok());
            if unsafe { (*pwd).pw_uid } != expected_uid {
                return None;
            }
            if !sudo_identity_verified(expected_uid, gid) {
                return None;
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
                        // PRIV-02: cross-check SUDO_UID/SUDO_GID against the
                        // passwd database before dropping. Fail-closed: an
                        // SUDO_USER with no passwd entry, or a missing/unparseable
                        // SUDO_GID, now DENIES the drop instead of skipping the
                        // comparison and proceeding with the environment-declared
                        // uid.
                        if !sudo_identity_verified(uid, Some(gid)) {
                            return Self { active: false };
                        }
                        unsafe {
                            // drop supplementary groups first to close DAC bypass (fail closed)
                            if libc::setgroups(0, std::ptr::null()) != 0 {
                                return Self { active: false };
                            }
                            // NOTE: setfsuid/setfsgid return the *previous* fsid on both
                            // success and failure (man setfsuid(2) BUGS), so their return
                            // values must never be treated as 0 == success error codes.
                            // Ignore them here and verify with a -1 probe below.
                            let _ = libc::setfsgid(gid);
                            let _ = libc::setfsuid(uid);
                            // verify drop actually took effect: setfsuid(-1)/setfsgid(-1)
                            // always fail but return the current fsuid/fsgid.
                            let cur_gid = libc::setfsgid(-1i32 as libc::gid_t);
                            let cur_uid = libc::setfsuid(-1i32 as libc::uid_t);
                            if (cur_gid as u32) != gid || (cur_uid as u32) != uid {
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
                let _ = libc::setfsuid(0);
                let _ = libc::setfsgid(0);
            }
        }
    }
}

#[cfg(unix)]
/// Uids trusted to own system paths (/run/albus, /etc/albus): uid 0 plus the
/// L1 dedicated service user when that account exists. Centralizes the L1
/// ownership model so no check can drift back to root-only.
fn is_trusted_system_uid(uid: libc::uid_t) -> bool {
    if uid == 0 {
        return true;
    }
    matches!(crate::core::ebpf::service_uid(), Some(suid) if suid == uid)
}

#[cfg(unix)]
/// True when this process runs as the L1 dedicated service user (non-root).
/// Used to resolve daemon paths (shared /run/albus, /etc/albus) instead of
/// per-user sudo/XDG/HOME paths.
fn is_service_user_process() -> bool {
    let euid = unsafe { libc::geteuid() };
    euid != 0 && matches!(crate::core::ebpf::service_uid(), Some(suid) if suid == euid)
}

/// The single decision behind every `SUDO_*` trust site.
///
/// PRIV-02: the rule "a SUDO_* identity is trusted only when the passwd
/// database confirms it" was enforced as "the database is consulted IF IT
/// HAPPENS TO ANSWER". Every call site had the shape
/// `if !pwd.is_null() && (...mismatch...) { deny }`, so a `getpwnam` that
/// returned NULL — an SUDO_USER that passes the syntax check but has no passwd
/// entry, or an unparseable SUDO_GID — skipped the comparison entirely and the
/// environment-declared uid was trusted verbatim.
///
/// That one value is simultaneously the privilege-drop target, the DAC identity
/// used for directory creation and rename, and the allow-list entry in
/// `check_parent_ownership` / `check_write_owner`. So a fail-open here is a
/// dropped-privilege failure, not merely a skipped check.
///
/// Fail-closed: if SUDO_USER is present, the lookup must SUCCEED and both
/// pw_uid and pw_gid must match. If SUDO_USER is absent there is nothing to
/// cross-check against and the existing euid rules govern, so that case is left
/// as it was.
#[cfg(unix)]
fn sudo_identity_verified(uid: libc::uid_t, gid: Option<libc::gid_t>) -> bool {
    let Ok(sudo_user) = std::env::var("SUDO_USER") else {
        // No name to cross-check: nothing is being asserted about passwd, so the
        // pre-existing euid/privilege_drop_expected rules apply unchanged.
        return true;
    };
    if !is_valid_username(&sudo_user) {
        return false;
    }
    let Ok(c_user) = std::ffi::CString::new(sudo_user) else {
        return false;
    };
    unsafe {
        let pwd = libc::getpwnam(c_user.as_ptr());
        // PRIV-02: an unanswerable database is NOT a pass. Previously a NULL
        // here fell straight through to trusting the environment.
        if pwd.is_null() {
            return false;
        }
        if (*pwd).pw_uid != uid {
            return false;
        }
        // SUDO_GID must be present AND parseable whenever SUDO_UID is trusted:
        // an env-spoofed primary group would otherwise survive the drop while
        // the guard reports itself active.
        match gid {
            Some(g) => g == (*pwd).pw_gid,
            None => false,
        }
    }
}

#[cfg(unix)]
fn validated_sudo_uid() -> Option<libc::uid_t> {
    let uid: libc::uid_t = std::env::var("SUDO_UID").ok()?.trim().parse().ok()?;
    if uid == 0 {
        return None;
    }
    let gid: Option<libc::gid_t> = std::env::var("SUDO_GID")
        .ok()
        .and_then(|s| s.trim().parse().ok());
    if !sudo_identity_verified(uid, gid) {
        return None;
    }
    Some(uid)
}

/// Rejects `..` components before path classification: `Path::starts_with`
/// is component-lexical, so `/run/albus/../tmp/x` would classify as a system
/// path while resolving outside it. All constructed paths already exclude
/// `..`; this is defense-in-depth for explicit user-supplied paths.
fn reject_dotdot(path: &Path) -> std::io::Result<()> {
    use std::path::Component;
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("security violation: `..` in path {}", path.display()),
        ));
    }
    Ok(())
}

fn reject_symlink_ancestors(path: &Path) -> std::io::Result<()> {
    // walk every ancestor (including the full path itself): any symlink -> deny.
    // This does not close the lstat->open race by itself; O_NOFOLLOW on open
    // plus post-open fstat checks below are the atomic enforcement point.
    for ancestor in path.ancestors() {
        // stop at filesystem root to bound the walk
        if ancestor.as_os_str().is_empty() {
            break;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "security violation: symlink in path chain at {}",
                        ancestor.display()
                    ),
                ));
            }
            // missing intermediate components are fine (create_dir_all will make them)
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => continue,
            _ => {}
        }
        if ancestor == Path::new("/") {
            break;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn check_parent_ownership(parent: &Path, is_system_path: bool) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(parent).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "security violation: cannot stat parent {}: {}",
                parent.display(),
                e
            ),
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "security violation: parent is symlink at {}",
                parent.display()
            ),
        ));
    }
    if !meta.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "security violation: parent is not a directory at {}",
                parent.display()
            ),
        ));
    }
    let dir_uid = meta.uid();
    let euid = unsafe { libc::geteuid() };
    if is_system_path {
        // L1: root or the dedicated service user may own system parents.
        if !is_trusted_system_uid(dir_uid) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "security violation: system parent {} owned by uid {}",
                    parent.display(),
                    dir_uid
                ),
            ));
        }
    } else if euid == 0 {
        if let Some(sudo_uid) = validated_sudo_uid() {
            if dir_uid != 0 && dir_uid != sudo_uid {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "security violation: user parent {} owned by untrusted uid {}",
                        parent.display(),
                        dir_uid
                    ),
                ));
            }
        } else if dir_uid != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "security violation: root parent {} owned by uid {} (no validated sudo user)",
                    parent.display(),
                    dir_uid
                ),
            ));
        }
    } else {
        let ruid = unsafe { libc::getuid() };
        if dir_uid != ruid && dir_uid != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "security violation: parent {} owned by untrusted uid {}",
                    parent.display(),
                    dir_uid
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
/// Pure decision helper (unit-tested): a privilege drop is EXPECTED exactly
/// when running as euid 0 with a validated sudo user on a non-system path.
fn drop_expected_for(
    euid: libc::uid_t,
    sudo_uid: Option<libc::uid_t>,
    is_system_path: bool,
) -> bool {
    euid == 0 && sudo_uid.is_some() && !is_system_path
}

#[cfg(unix)]
fn privilege_drop_expected(is_system_path: bool) -> bool {
    let euid = unsafe { libc::geteuid() };
    drop_expected_for(euid, validated_sudo_uid(), is_system_path)
}

// safely writes content to path atomically rejecting symlinks and dropping privileges on user paths
pub(crate) fn safe_write<P: AsRef<Path>>(path: P, content: &str) -> std::io::Result<()> {
    let p = path.as_ref();
    reject_dotdot(p)?;
    let is_system_path = p.starts_with("/run/albus") || p.starts_with("/etc/albus");

    #[cfg(unix)]
    let _guard = if !is_system_path {
        FsPrivilegeGuard::drop_to_sudo_user()
    } else {
        FsPrivilegeGuard { active: false }
    };

    // HANCORE follow-up (fail-closed guard): when a drop was expected (root +
    // validated sudo user + user path) but the guard is inactive (setgroups
    // failure, spoofed env, failed -1 probe), REFUSE the operation instead of
    // continuing with root filesystem credentials on a user-writable path —
    // a parent-directory swap could otherwise redirect the privileged write.
    // Direct root (no sudo), plain users, and system paths never expect a
    // drop, so their flows are untouched.
    #[cfg(unix)]
    {
        if privilege_drop_expected(is_system_path) && !_guard.active {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "security violation: privilege drop failed for {} — refusing privileged write to user path",
                    p.display()
                ),
            ));
        }
    }

    // 1. pre-check: reject any symlink in the full chain before touching the fs
    reject_symlink_ancestors(p)?;

    if let Some(parent) = p.parent() {
        let existed = parent.exists();
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            // only chmod newly created dirs — never downgrade existing ~/.config etc.
            if !existed {
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
            // 2. post-mkdir revalidation (narrows create_dir_all -> open window):
            // parent must still be a real dir owned by the expected uid.
            check_parent_ownership(parent, is_system_path)?;
        }
        #[cfg(not(unix))]
        {
            let _ = existed;
        }
    }

    // FP-02: unix uses the atomic temp+rename path (no truncate-before-authz,
    // no torn files); other platforms keep the legacy direct write.
    #[cfg(unix)]
    {
        atomic_safe_write(p, content, is_system_path)
    }
    #[cfg(not(unix))]
    {
        return legacy_safe_write(p, content);
    }
}

#[cfg(unix)]
fn check_write_owner(file_uid: libc::uid_t, is_system_path: bool, p: &Path) -> std::io::Result<()> {
    let euid = unsafe { libc::geteuid() };
    if is_system_path {
        // L1: root or the dedicated service user may own system files.
        if !is_trusted_system_uid(file_uid) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "security violation: refusing to write system file {} owned by uid {}",
                    p.display(),
                    file_uid
                ),
            ));
        }
    } else if euid == 0 {
        match validated_sudo_uid() {
            Some(sudo_uid) => {
                if file_uid != 0 && file_uid != sudo_uid {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "security violation: refusing to write user file {} owned by uid {}",
                            p.display(),
                            file_uid
                        ),
                    ));
                }
            }
            None => {
                if file_uid != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "security violation: refusing root write to {} owned by uid {} (no validated sudo user)",
                            p.display(),
                            file_uid
                        ),
                    ));
                }
            }
        }
    } else {
        let ruid = unsafe { libc::getuid() };
        if file_uid != ruid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "security violation: refusing to write {} owned by uid {}",
                    p.display(),
                    file_uid
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// FP-02: atomic durable write — temp file in the same directory + fsync +
// rename + dir fsync. The previous truncate-in-place destroyed content
// before authorization and left torn files on crash.
#[cfg(unix)]
fn atomic_write_temp(parent: &Path, content: &str) -> std::io::Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let id = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_name = format!(".albus-{}-{}.tmp", std::process::id(), id);
    let tmp_path = parent.join(&tmp_name);
    let tmp_cstr = std::ffi::CString::new(tmp_path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "security violation: temp path contains NUL",
        )
    })?;

    // O_EXCL: never follow/truncate anything pre-existing.
    let fd = unsafe {
        libc::open(
            tmp_cstr.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let result = (|| -> std::io::Result<()> {
        let _ = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result?;
    Ok(tmp_path)
}

#[cfg(unix)]
fn fsync_dir(parent: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let cstr = std::ffi::CString::new(parent.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "security violation: parent path contains NUL",
        )
    })?;
    let fd = unsafe {
        libc::open(
            cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let res = unsafe { libc::fsync(fd) };
    unsafe { libc::close(fd) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// FP-02: unix atomic write body — pre-check existing target (no modification),
// temp+fsync in same dir, rename, dir fsync. Denial never clobbers (NV-01);
// FIFOs are rejected without blocking (O_NONBLOCK pre-check).
#[cfg(unix)]
fn atomic_safe_write(p: &Path, content: &str, is_system_path: bool) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;

    let parent: &Path = p.parent().unwrap_or(Path::new("."));

    // 1. pre-check existing target read-only: regular + owner-approved, else deny
    // before anything is modified.
    match fs::symlink_metadata(p) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "security violation: refusing to write symlink at {}",
                    p.display()
                ),
            ));
        }
        Ok(_) => {
            let probe = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(p);
            match probe {
                Ok(f) => {
                    let fm = f.metadata()?;
                    if !fm.file_type().is_file() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!(
                                "security violation: refusing to write non-regular file at {}",
                                p.display()
                            ),
                        ));
                    }
                    check_write_owner(fm.uid(), is_system_path, p)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(std::io::Error::new(
                        e.kind(),
                        format!(
                            "security violation: cannot pre-check {}: {}",
                            p.display(),
                            e
                        ),
                    ));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    // 2. temp + fsync in the same directory (O_EXCL, 0600, dropped fsuid owner).
    let tmp_path = atomic_write_temp(parent, content)?;

    // 3. atomic publish + durability.
    if let Err(e) = fs::rename(&tmp_path, p) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    fsync_dir(parent)?;
    Ok(())
}

#[cfg(not(unix))]
fn legacy_safe_write(p: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    let mut file = options.open(p)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

// safely reads content while atomically rejecting symlinks and enforcing strict ownership checks
fn safe_read<P: AsRef<Path>>(path: P) -> std::io::Result<String> {
    let p = path.as_ref();
    reject_dotdot(p)?;
    let is_system_path = p.starts_with("/run/albus") || p.starts_with("/etc/albus");

    #[cfg(unix)]
    let _guard = if !is_system_path {
        FsPrivilegeGuard::drop_to_sudo_user()
    } else {
        FsPrivilegeGuard { active: false }
    };

    // HANCORE follow-up, same fail-closed rule as safe_write.
    #[cfg(unix)]
    {
        if privilege_drop_expected(is_system_path) && !_guard.active {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "security violation: privilege drop failed for {} — refusing privileged read of user path",
                    p.display()
                ),
            ));
        }
    }

    let mut options = fs::OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // NV-02 follow-up: O_NONBLOCK so a planted FIFO (e.g. via explicit
        // --config path) is rejected by the is_file gate below instead of
        // hanging the caller. Harmless for regular files.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
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

    // NV-02: clear O_NONBLOCK for the subsequent read (FIFO would already
    // have been rejected above; regular files are unaffected either way).
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags >= 0 {
            unsafe {
                libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
            }
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let file_uid = meta.uid();
        let current_uid = unsafe { libc::getuid() };

        if current_uid == 0 {
            if is_system_path {
                // L1: root or the dedicated service user may own system files.
                if !is_trusted_system_uid(file_uid) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "security violation: system config {} owned by untrusted uid {}",
                            p.display(),
                            file_uid
                        ),
                    ));
                }
            } else if let Some(sudo_uid) = validated_sudo_uid() {
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
            } else if file_uid != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "security violation: user config {} owned by uid {} (no validated sudo user)",
                        p.display(),
                        file_uid
                    ),
                ));
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

/// Test-only re-export so  can assert that the config validator and
/// the attach-time opener accept and reject the same set. PRIV-03: two
/// independent implementations of "is this an acceptable cgroup path" is the
/// same class of defect as the leak detector/repair pair in W4-01.
#[cfg(test)]
pub(crate) fn validate_cgroup_path_for_test(
    path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    validate_cgroup_path(path)
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
        // FP-08: restore path reaches kernel TCP_MAXSEG unclamped — bound it here
        // so every entry path (CLI, JSON, QML) is covered by the single validator.
        // 0 for restore_after_bytes would restore immediately (fail-open, no shrinking).
        if self.restore_after_bytes < 64 {
            return Err(format!(
                "invalid restore_after_bytes {} (expected >= 64)",
                self.restore_after_bytes
            )
            .into());
        }
        // 0 for restore_mss means 1460 auto; any explicit value must be a sane MSS.
        if self.restore_mss != 0 && (self.restore_mss < 64 || self.restore_mss > 1460) {
            return Err(format!(
                "invalid restore_mss {} (expected 0 or 64..=1460)",
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
        // TTL bytes reach the wire unclamped (rawsock writes them verbatim):
        // 0 dies on the local host (fail-open while shaping claims active),
        // so the floor is 1 everywhere; the 64 ceiling matches max_ttl so
        // decoys stay TTL-limited by design. Single validator covers CLI,
        // JSON, QML and SIGHUP paths alike.
        if !(1..=64).contains(&self.fake_ttl) {
            return Err(format!("invalid fake_ttl {} (expected 1..=64)", self.fake_ttl).into());
        }
        if self.min_ttl == 0 || self.min_ttl > 64 {
            return Err(format!("invalid min_ttl {} (expected 1..=64)", self.min_ttl).into());
        }
        if self.max_ttl == 0 {
            return Err(format!("invalid max_ttl {} (expected >= 1)", self.max_ttl).into());
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
    /// Opens with O_NOFOLLOW first, then fstat-checks (no lstat->open TOCTOU).
    pub fn load_from_file_root_checked<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(unix)]
        {
            if crate::core::ebpf::is_root() {
                let p = path.as_ref();
                reject_symlink_ancestors(p)?;
                let mut options = fs::OpenOptions::new();
                options.read(true);
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    // NV-02 follow-up: same O_NONBLOCK rationale as safe_read.
                    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
                }
                let mut file = options.open(p).map_err(|e| {
                    format!(
                        "security violation: cannot open --config {}: {}",
                        p.display(),
                        e
                    )
                })?;
                let meta = file.metadata()?;
                if !meta.file_type().is_file() {
                    return Err(
                        "security violation: --config must be a regular file when running as root"
                            .into(),
                    );
                }
                {
                    use std::os::unix::fs::MetadataExt;
                    use std::os::unix::io::AsRawFd;
                    // L1: root or the dedicated service user may own --config
                    // (/etc/albus is service-owned post-migration).
                    if !is_trusted_system_uid(meta.uid()) {
                        return Err(format!(
                            "security violation: --config owned by uid {} (expected root or service user) when running privileged",
                            meta.uid()
                        )
                        .into());
                    }
                    let fd = file.as_raw_fd();
                    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                    if flags >= 0 {
                        unsafe {
                            libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
                        }
                    }
                }
                use std::io::Read;
                let mut content = String::new();
                file.read_to_string(&mut content)?;
                let cfg: Config = serde_json::from_str(&content)?;
                return Ok(cfg);
            }
        }
        Self::load_from_file(path)
    }
    // FP-01: per-invoker volatile name (pure, testable).
    fn sudo_volatile_path(uid: libc::uid_t) -> PathBuf {
        PathBuf::from(format!("/run/albus/config-{}.json", uid))
    }

    // FP-01: /etc promotion only for true-root invocations, never for sudo
    // user invocations (pure, testable). A sudo user's settings must not
    // silently become system-wide.
    fn should_sync_etc(is_root: bool, sudo_uid: Option<libc::uid_t>) -> bool {
        is_root && sudo_uid.is_none()
    }

    // resolves secure volatile shared memory / runtime directory path
    pub fn volatile_config_path() -> PathBuf {
        if crate::core::ebpf::is_root() {
            // FP-01: isolate sudo invocations per validated uid so one user's
            // `config set` never overwrites the shared daemon volatile.
            #[cfg(unix)]
            {
                if let Some(uid) = validated_sudo_uid() {
                    return Self::sudo_volatile_path(uid);
                }
            }
            PathBuf::from("/run/albus/config.json")
        } else if is_service_user_process() {
            // L1: the daemon runs as the service user with RuntimeDirectory;
            // its volatile state lives in the shared daemon path, never in
            // per-user XDG runtime dirs.
            PathBuf::from("/run/albus/config.json")
        } else if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            // validate attacker-controlled env: absolute, bounded, no traversal,
            // must live under /run (standard XDG_RUNTIME_DIR location)
            let uid = unsafe { libc::getuid() };
            let fallback = PathBuf::from(format!("/run/user/{}/albus/config.json", uid));
            if runtime_dir.starts_with('/')
                && !runtime_dir.contains("..")
                && runtime_dir.len() <= 256
                && (runtime_dir.starts_with("/run/user/") || runtime_dir.starts_with("/run/"))
            {
                let candidate = PathBuf::from(&runtime_dir).join("albus/config.json");
                // must stay under /run and never escape to /run/albus (root daemon path)
                if candidate.starts_with("/run/") && !candidate.starts_with("/run/albus") {
                    return candidate;
                }
            }
            fallback
        } else {
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/run/user/{}/albus/config.json", uid))
        }
    }

    // resolves durable persistent configuration path on physical disk (never returns volatile memory)
    pub fn default_config_path() -> PathBuf {
        // L1: the daemon runs as the service user — its durable config is the
        // system file, never a sudo/XDG/HOME-derived user path.
        #[cfg(unix)]
        {
            if is_service_user_process() {
                return PathBuf::from("/etc/albus/config.json");
            }
        }
        // 1. check sudo user environment with strict format and passwd validation
        if let Some(sudo_home) = get_sudo_user_home() {
            let sudo_cfg = sudo_home.join(".config/albus/config.json");
            if !sudo_cfg.starts_with("/root") {
                return sudo_cfg;
            }
        }
        // 2. check current process home (for user-level execution) — validate shape.
        // When running as root without a validated sudo user, never trust $HOME
        // (e.g. `sudo HOME=/tmp/evil ...` or `su` with attacker HOME would otherwise
        // redirect a root write into an attacker-controlled tree).
        #[cfg(unix)]
        {
            let euid = unsafe { libc::geteuid() };
            if euid == 0 && validated_sudo_uid().is_none() && get_sudo_user_home().is_none() {
                return PathBuf::from("/etc/albus/config.json");
            }
        }
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

        // 3. sync to /etc/albus/config.json for true-root invocations only.
        // FP-01: sudo user invocations must not silently promote user settings
        // to system-wide (that was the /etc persistence channel).
        let etc = Path::new("/etc/albus/config.json");
        #[cfg(unix)]
        let sync_etc = Self::should_sync_etc(crate::core::ebpf::is_root(), validated_sudo_uid());
        #[cfg(not(unix))]
        let sync_etc = crate::core::ebpf::is_root() || etc.exists();
        if sync_etc {
            let _ = safe_write(etc, &json);
        }

        Ok(())
    }

    // loads existing configuration or initializes default schema
    pub fn load_or_default() -> Self {
        // PRIV-01: this used to discard the error from EVERY candidate and fall
        // through to `Self::default()` with no log, no error and no marker, so
        // "nothing configured" and "something is configured but unreadable"
        // were indistinguishable to every caller.
        //
        // The damage was a silent policy downgrade. The only field in
        // `Config::default()` that is weaker than a configured state is
        // `network_lockdown` (false in the default), which is the fail-closed
        // "block outbound http/https if eBPF fails" mode. A config that
        // explicitly enabled it came up with it off, and engine.rs even logged
        // "network_lockdown is OFF" as though that were the operator's choice.
        // A corrupted or foreign-schema file hid in the same ignored Result.
        match Self::load_strict() {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!(
                    "no usable configuration found ({}). Falling back to built-in \
                     defaults — note that network_lockdown will be OFF, so a \
                     configured fail-closed policy is NOT in effect.",
                    e
                );
                Self::default()
            }
        }
    }

    /// Loads configuration from the first candidate that both EXISTS and parses.
    ///
    /// PRIV-01: the distinction that matters is absence vs. failure. A missing
    /// file is a legitimate "not configured" and falls through to the next
    /// candidate; a file that exists but cannot be read or parsed is an ERROR,
    /// because silently replacing it with defaults can only reduce the
    /// configured protection. The two are no longer collapsed.
    pub fn load_strict() -> std::result::Result<Self, String> {
        let mut seen: Vec<String> = Vec::new();

        // 1. active runtime volatile memory (/run/albus or $XDG_RUNTIME_DIR/albus)
        let volatile_path = Self::volatile_config_path();
        if volatile_path.exists() {
            match Self::load_from_file(&volatile_path) {
                Ok(cfg) => return Ok(cfg),
                Err(e) => seen.push(format!("{}: {}", volatile_path.display(), e)),
            }
        }

        // 2. /run/albus/config.json (system daemon volatile path) —
        // FP-01: skipped for validated sudo invocations (not their file).
        #[cfg(unix)]
        let skip_shared = validated_sudo_uid().is_some();
        #[cfg(not(unix))]
        let skip_shared = false;
        let run_root = PathBuf::from("/run/albus/config.json");
        if !skip_shared && run_root.exists() {
            match Self::load_from_file(&run_root) {
                Ok(cfg) => return Ok(cfg),
                Err(e) => seen.push(format!("{}: {}", run_root.display(), e)),
            }
        }

        // 3. durable user configuration path on disk
        let path = Self::default_config_path();
        if path.exists() {
            match Self::load_from_file(&path) {
                Ok(cfg) => return Ok(cfg),
                Err(e) => seen.push(format!("{}: {}", path.display(), e)),
            }
        }

        // 4. system-wide /etc/albus/config.json fallback
        let etc_path = PathBuf::from("/etc/albus/config.json");
        if etc_path.exists() {
            match Self::load_from_file(&etc_path) {
                Ok(cfg) => return Ok(cfg),
                Err(e) => seen.push(format!("{}: {}", etc_path.display(), e)),
            }
        }

        if seen.is_empty() {
            Err("no configuration file present".into())
        } else {
            // A file existed at every one of these locations but none parsed.
            Err(format!(
                "{} configuration file(s) present but unreadable: {}",
                seen.len(),
                seen.join("; ")
            ))
        }
    }

    /// Loads the system-wide daemon config strictly (`/etc/albus/config.json`,
    /// what the running daemon actually uses). No fallback cascade: a missing
    /// file is an error (daemon never installed?), so callers can distinguish
    /// "no system config" from defaults. Used by `config get --system`.
    pub fn load_system() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::load_system_from(Path::new("/etc/albus/config.json"))
    }

    pub(crate) fn load_system_from<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::load_from_file(path)
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
#[allow(clippy::field_reassign_with_default, clippy::type_complexity)]
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
    fn test_load_system_strict_no_fallback() {
        // --system semantics: an explicit file parses, a missing file
        // errors (never silently degrades to defaults — the panel relies
        // on the distinction to fall back to the user file itself)
        let dir = std::env::temp_dir().join(format!("albus_syscfg_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.json");
        assert!(
            Config::load_system_from(&path).is_err(),
            "missing system file must error, not default"
        );
        let mut cfg = valid_cfg();
        cfg.doh_upstream = "cloudflare".to_string();
        cfg.save_to_file(&path).expect("temp save works");
        let loaded = Config::load_system_from(&path).expect("explicit file parses");
        assert_eq!(loaded.doh_upstream, "cloudflare");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
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
            (Box::new(|c: &mut Config| c.max_ttl = 0), "max_ttl zero"),
            (Box::new(|c: &mut Config| c.min_ttl = 0), "min_ttl zero"),
            (
                Box::new(|c: &mut Config| c.min_ttl = 200),
                "min_ttl over 64",
            ),
            (
                Box::new(|c: &mut Config| c.fake_ttl = 0),
                "fake_ttl zero (fail-open)",
            ),
            (
                Box::new(|c: &mut Config| c.fake_ttl = 65),
                "fake_ttl over 64",
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
        cfg.min_ttl = 1;
        cfg.fake_ttl = 64;
        cfg.restore_mss = 1460;
        cfg.fake_sni = Some("valid-host.example".into());
        assert!(cfg.validate().is_ok());
        // 0 = auto line-rate is the default and must stay valid
        cfg.restore_mss = 0;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_reject_symlink_ancestors() {
        let base = std::env::temp_dir().join(format!("albus_test_chain_{}", std::process::id()));
        let real_dir = base.join("real");
        let _ = fs::create_dir_all(&real_dir);
        let link_dir = base.join("link");
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink(&real_dir, &link_dir);
        let target = link_dir.join("sub").join("config.json");
        let result = reject_symlink_ancestors(&target);
        assert!(result.is_err(), "ancestor symlink chain must be rejected");
        let _ = fs::remove_file(&link_dir);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_safe_write_roundtrip_and_parent_ownership() {
        let base = std::env::temp_dir().join(format!("albus_test_rt_{}", std::process::id()));
        let target = base.join("sub").join("config.json");
        let res = safe_write(&target, "{\"mss\": 88}");
        assert!(res.is_ok(), "safe_write roundtrip failed: {:?}", res.err());
        let back = safe_read(&target);
        assert!(back.is_ok());
        assert!(back.unwrap().contains("88"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_restore_bounds_fp08() {
        // defaults must pass
        assert!(Config::default().validate().is_ok());
        // fail-open / DoS payloads must be rejected
        let mut bad = Config::default();
        bad.restore_after_bytes = 0;
        assert!(bad.validate().is_err());
        let mut bad = Config::default();
        bad.restore_mss = 1;
        assert!(bad.validate().is_err());
        let mut bad = Config::default();
        bad.restore_mss = 65535;
        assert!(bad.validate().is_err());
        // explicit sane values pass (0 restore_mss = 1460 auto)
        let mut ok = Config::default();
        ok.restore_after_bytes = 600;
        ok.restore_mss = 0;
        assert!(ok.validate().is_ok());
        let mut ok = Config::default();
        ok.restore_after_bytes = 64;
        ok.restore_mss = 1460;
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn test_fp01_isolation_helpers() {
        // per-invoker volatile is uid-tagged under the daemon dir
        assert_eq!(
            Config::sudo_volatile_path(1000),
            PathBuf::from("/run/albus/config-1000.json")
        );
        // /etc promotion: true root only, never sudo invocations
        assert!(Config::should_sync_etc(true, None));
        assert!(!Config::should_sync_etc(true, Some(1000)));
        assert!(!Config::should_sync_etc(false, None));
        assert!(!Config::should_sync_etc(false, Some(1000)));
    }

    #[test]
    fn test_l1_trusted_system_uids() {
        // root is always trusted
        assert!(is_trusted_system_uid(0));
        // the service account, if present, is trusted; an unrelated uid is not
        match crate::core::ebpf::service_uid() {
            Some(suid) => {
                assert!(is_trusted_system_uid(suid));
            }
            None => {
                // no albus account here: a high uid must be untrusted
                assert!(!is_trusted_system_uid(60000));
            }
        }
    }

    // HANCORE follow-up: drop is expected exactly for root + validated sudo
    // user + user path. Every other combination must NOT expect one, so legit
    // direct-root, plain-user, and system-path flows are untouched.
    #[test]
    fn test_drop_expected_matrix() {
        // the HANCORE case: sudo invocation on a user path expects a drop
        assert!(drop_expected_for(0, Some(1000), false));
        // system paths never expect a drop (written with ambient creds)
        assert!(!drop_expected_for(0, Some(1000), true));
        assert!(!drop_expected_for(0, None, true));
        // direct root (no sudo user): nobody to drop to
        assert!(!drop_expected_for(0, None, false));
        // plain users: nothing privileged to drop
        assert!(!drop_expected_for(1000, None, false));
        assert!(!drop_expected_for(1000, Some(1000), false));
        assert!(!drop_expected_for(1000, None, true));
    }

    // NV-02 follow-up: a planted FIFO must be rejected, not block on open.    // (Pre-fix this test hangs; post-fix O_NONBLOCK makes open succeed and
    // the is_file gate deny. No writer ever opens the fifo.)
    #[test]
    fn test_fifo_read_rejected_without_hang() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("albus_test_fifo_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let fifo = dir.join("config.fifo");
        let cstr = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cstr.as_ptr(), 0o600) }, 0);
        let res = safe_read(&fifo);
        assert!(res.is_err(), "FIFO must be rejected, not read or hung");
        let _ = fs::remove_file(&fifo);
        let _ = fs::remove_dir(&dir);
    }

    // `..` must be rejected before path classification (defense-in-depth;
    // constructors never emit it, explicit paths might).
    #[test]
    fn test_dotdot_rejected() {
        assert!(reject_dotdot(Path::new("/run/albus/../tmp/x")).is_err());
        assert!(reject_dotdot(Path::new("/etc/albus/config.json")).is_ok());
        assert!(safe_write("/run/albus/../tmp/x", "{}").is_err());
    }

    #[test]
    fn test_volatile_path_rejects_evil_xdg() {
        // XDG_RUNTIME_DIR outside /run must fall back to /run/user/<uid>
        let uid = unsafe { libc::getuid() };
        let expected = PathBuf::from(format!("/run/user/{}/albus/config.json", uid));
        // SAFETY: single-threaded test env manipulation; restored afterwards.
        let old = std::env::var("XDG_RUNTIME_DIR").ok();
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/tmp/evil") };
        // is_root() is false in test env (non-root CI); if root, path is /run/albus
        let got = Config::volatile_config_path();
        if !crate::core::ebpf::is_root() {
            assert_eq!(got, expected);
        }
        unsafe {
            if let Some(v) = old {
                std::env::set_var("XDG_RUNTIME_DIR", v);
            } else {
                std::env::remove_var("XDG_RUNTIME_DIR");
            }
        }
    }
}

#[cfg(test)]
mod config_load_failure_tests {
    use super::*;

    /// PRIV-01: the fallback must never be MORE PERMISSIVE than what is on disk.
    ///
    /// `Config::default()` differs from a configured state in exactly one
    /// security-relevant field — `network_lockdown` is false — and that field is
    /// the fail-closed "block outbound http/https if eBPF fails" mode. So if a
    /// file on disk enabled it and loading failed, the old code silently came up
    /// with the guarantee off, and engine.rs logged "network_lockdown is OFF" as
    /// if the operator had chosen that.
    #[test]
    fn test_the_default_is_never_more_permissive_than_configured_lockdown() {
        // This is the property the fix depends on: knowing the default's
        // network_lockdown value is enough to reason about the downgrade.
        assert!(
            !Config::default().network_lockdown,
            "if this ever becomes true, the downgrade reasoning in PRIV-01 changes \\
             and this test must be revisited"
        );
        assert!(
            Config::default().dnssec,
            "every other default field is expected to be at least as protective \
             as a configured state"
        );
        assert!(Config::default().kill_switch);
        assert!(Config::default().block_ipv6);
        assert!(Config::default().doh_enabled);
    }

    /// The load logic must distinguish absence from failure.
    ///
    /// `load_strict` returns Err with a diagnostic when a file existed but could
    /// not be loaded, and Ok only when a candidate actually parsed. A missing
    /// file is legitimately "not configured" and must NOT be reported as a
    /// failure — otherwise a first run would look like a broken install.
    #[test]
    fn test_load_strict_distinguishes_absent_from_unreadable() {
        // On a machine with no configuration at all, absence must be the
        // "nothing present" case, not a corruption report.
        match Config::load_strict() {
            Ok(_) => {} // a real config exists here; nothing to assert about absence
            Err(e) => {
                assert!(
                    !e.contains("unreadable"),
                    "with no configuration present the error must say so plainly, \\
                     not report unreadable files: {}",
                    e
                );
                assert_eq!(e, "no configuration file present");
            }
        }
    }

    /// And the diagnostic must name the files, so an operator can act on it.
    #[test]
    fn test_load_failure_diagnostic_names_the_paths() {
        let err = Config::load_strict().err();
        if let Some(e) = err {
            if e != "no configuration file present" {
                assert!(
                    e.contains("present but unreadable"),
                    "a failure diagnostic must distinguish itself from absence: {}",
                    e
                );
                assert!(
                    e.contains("/"),
                    "the diagnostic must name the offending paths: {}",
                    e
                );
            }
        }
    }

    /// Regression guard: `load_or_default` must not go back to discarding the
    /// error and stepping silently into `Self::default()`. The fallback is still
    /// permitted (a first run needs it), but it must be logged and it must say
    /// that the configured fail-closed policy is not in effect.
    #[test]
    fn test_load_or_default_announces_a_policy_downgrade() {
        let src = include_str!("config.rs");
        let prod = src
            .split_once("\n#[cfg(test)]\nmod config_load_failure_tests")
            .map(|(p, _)| p)
            .unwrap_or(src);

        let at = prod
            .find("pub fn load_or_default()")
            .expect("load_or_default");
        let tail = &prod[at..];
        let end = tail
            .find("pub fn load_strict()")
            .map(|o| at + o)
            .unwrap_or(prod.len());
        let body = &prod[at..end];

        assert!(
            body.contains("load_strict()"),
            "load_or_default must go through load_strict, not re-implement the \\
             candidate walk"
        );
        assert!(
            body.contains("warn!"),
            "a fallback to defaults must be logged"
        );
        assert!(
            body.contains("network_lockdown will be OFF"),
            "the warning must say that the configured fail-closed policy is not \\
             in effect, rather than presenting the default as a choice"
        );
    }

    /// And the candidate walk must record the failure of each existing file
    /// rather than swallowing it with `if let Ok(..)`.
    #[test]
    fn test_candidate_walk_records_failures() {
        let src = include_str!("config.rs");
        let prod = src
            .split_once("\n#[cfg(test)]\nmod config_load_failure_tests")
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod.find("pub fn load_strict()").expect("load_strict");
        let body = &prod[at..];
        assert!(
            !body.contains("if let Ok(cfg) = Self::load_from_file"),
            "PRIV-01: `if let Ok(..)` is exactly the swallow that made absence and \\
             unreadability indistinguishable — each candidate's error must be \
             recorded"
        );
        assert!(
            body.contains("seen.push("),
            "each existing-but-unloadable candidate must be recorded"
        );
        assert!(
            body.contains("present but unreadable"),
            "the summary must distinguish failure from absence"
        );
    }
}

#[cfg(test)]
mod sudo_identity_tests {
    /// PRIV-02's decision, mirrored as a pure predicate so it can be tested
    /// without mutating the process environment or touching the passwd
    /// database. `pwd` is what `getpwnam` answered.
    ///
    /// The bug was that the real code had the shape
    /// `if !pwd.is_null() && (mismatch) { deny }`, so a NULL answer skipped the
    /// comparison entirely and the environment-declared identity was trusted.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Passwd {
        uid: libc::uid_t,
        gid: libc::gid_t,
    }

    fn sudo_identity_ok(pwd: Option<Passwd>, uid: libc::uid_t, gid: Option<libc::gid_t>) -> bool {
        // Mirrors validated_sudo_uid's own precondition: uid 0 is never a valid
        // drop target, and drop_to_sudo_user gates on `uid != 0` too.
        if uid == 0 {
            return false;
        }
        match pwd {
            // PRIV-02: an unanswerable database is NOT a pass.
            None => false,
            Some(p) => {
                if p.uid != uid {
                    return false;
                }
                match gid {
                    // SUDO_GID must be present and parseable whenever SUDO_UID
                    // is trusted, or an env-spoofed primary group survives the
                    // drop with the guard reporting itself active.
                    Some(g) => p.gid == g,
                    None => false,
                }
            }
        }
    }

    /// The reference case: everything agrees.
    #[test]
    fn test_matching_identity_is_accepted() {
        assert!(sudo_identity_ok(
            Some(Passwd {
                uid: 1000,
                gid: 1000
            }),
            1000,
            Some(1000)
        ));
    }

    /// The headline bug: `getpwnam` returned NULL. The old code skipped the
    /// comparison and trusted the environment.
    #[test]
    fn test_missing_passwd_entry_is_refused() {
        assert!(
            !sudo_identity_ok(None, 1000, Some(1000)),
            "PRIV-02: an SUDO_USER with no passwd entry must NOT be trusted"
        );
    }

    /// SUDO_GID missing or unparseable: the environment cannot prove which
    /// primary group it is claiming.
    #[test]
    fn test_missing_gid_is_refused() {
        assert!(
            !sudo_identity_ok(
                Some(Passwd {
                    uid: 1000,
                    gid: 1000
                }),
                1000,
                None
            ),
            "PRIV-02: SUDO_GID must be present whenever SUDO_UID is trusted"
        );
    }

    /// A uid mismatch and a gid mismatch are each independently fatal.
    #[test]
    fn test_mismatches_are_refused() {
        let p = Some(Passwd {
            uid: 1000,
            gid: 1000,
        });
        assert!(
            !sudo_identity_ok(p, 999, Some(1000)),
            "uid mismatch must refuse"
        );
        assert!(
            !sudo_identity_ok(p, 1000, Some(999)),
            "gid mismatch must refuse"
        );
        assert!(
            !sudo_identity_ok(p, 999, Some(999)),
            "both mismatching must refuse"
        );
    }

    /// Regression guard on the production code: the `!pwd.is_null() && (...)`
    /// shape is what made an unanswerable database a silent pass. It must not
    /// come back at any of the three call sites.
    #[test]
    fn test_no_call_site_skips_a_null_lookup() {
        let src = include_str!("config.rs");
        let prod = src
            .split_once("\n#[cfg(test)]\nmod sudo_identity_tests")
            .map(|(p, _)| p)
            .unwrap_or(src);
        // Strip line comments first: the surrounding prose names the bad pattern
        // in order to document it, and matching the documentation would make the
        // assertion meaningless.
        let code: String = prod
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("!pwd.is_null()"),
            "PRIV-02: `!pwd.is_null() && <mismatch>` is the fail-open shape — an \
             unanswerable database skipped the comparison"
        );
        assert!(
            !code.contains("if pwd.is_null() &&"),
            "the guard must never combine a NULL-tolerant test with a mismatch test"
        );
        // And the fail-closed direction must be present in production.
        assert!(
            code.contains("if pwd.is_null() {\n            return false;"),
            "sudo_identity_verified must treat a NULL lookup as a refusal"
        );
    }

    /// And all three sites must route through the one predicate.
    #[test]
    fn test_all_sudo_sites_share_one_predicate() {
        let src = include_str!("config.rs");
        let uses = src.matches("sudo_identity_verified(").count();
        // definition + validated_sudo_uid + drop_to_sudo_user + get_sudo_user_home
        assert!(
            uses >= 4,
            "expected the predicate to be defined and used at every SUDO_* trust \\
             site, found {} occurrences",
            uses
        );
    }

    /// uid 0 is never a valid drop target — the guard drops to whatever it is
    /// told, so a zero would leave the process at full privilege.
    #[test]
    fn test_uid_zero_is_refused() {
        assert!(
            !sudo_identity_ok(Some(Passwd { uid: 0, gid: 0 }), 0, Some(0)),
            "uid 0 must never be a privilege-drop target"
        );
    }
}
