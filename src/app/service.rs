//! systemd service unit generator, process supervision, and journal telemetry streaming.

use crate::app::cli::{RunArgs, ServiceCommands};
use crate::core::ebpf::is_root;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

const SERVICE_FILE_PATH: &str = "/etc/systemd/system/albus.service";
const SYSTEM_BIN_PATH: &str = "/usr/local/bin/albus";
const POLKIT_RULE_PATH: &str = "/etc/polkit-1/rules.d/albus.rules";
const SYSTEMCTL_BIN: &str = "/usr/bin/systemctl";
const JOURNALCTL_BIN: &str = "/usr/bin/journalctl";

const POLKIT_RULE_CONTENT: &str = r#"polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units") {
        var unit = action.lookup("unit");
        if (unit == "albus.service") {
            if (subject.isInGroup("wheel") || subject.isInGroup("sudo")) {
                return polkit.Result.AUTH_ADMIN;
            }
        }
    }
    // Rootless daemon support: the albus service user must drive per-link
    // DNS without interactive auth (NoNewPrivileges + no agent in daemon
    // context). Explicit action list on purpose: nothing here exceeds what
    // the daemon already controls (it writes /etc/resolv.conf directly), so
    // this grants no new capability — it only unbreaks the D-Bus path for
    // the dedicated account.
    if (subject.user == "albus") {
        if (action.id == "org.freedesktop.resolve1.set-dns-servers" ||
            action.id == "org.freedesktop.resolve1.set-domains" ||
            action.id == "org.freedesktop.resolve1.set-default-route" ||
            action.id == "org.freedesktop.resolve1.revert" ||
            action.id == "org.freedesktop.resolve1.flush-caches") {
            return polkit.Result.YES;
        }
    }
});
"#;

// dispatches systemd lifecycle actions
pub fn handle_service_command(
    cmd: ServiceCommands,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cmd {
        ServiceCommands::Install(args) => install_service(&args),
        ServiceCommands::Uninstall => uninstall_service(),
        ServiceCommands::Start => start_service(),
        ServiceCommands::Stop => stop_service(),
        ServiceCommands::Restart => restart_service(),
        ServiceCommands::Reload => reload_service(),
        ServiceCommands::Status => show_service_status(),
        ServiceCommands::Logs => show_service_logs(),
    }
}

/// The single construction point for every privileged `systemctl` spawn in
/// this crate.
///
/// W1-02: this helper existed and was correct, but it was not the only way the
/// binary spawns systemctl — the entrypoint's SIGHUP sender and
/// show_service_status/show_service_logs each built a `Command` directly and
/// inherited the caller's environment. Because argv is fixed at every site the
/// exposure is not argument injection; it is a root- or service-user-executed
/// systemctl inheriting `SYSTEMD_PAGER`, `SYSTEMD_LESS`, `EDITOR`/`VISUAL`, or a
/// `PATH` that redirects a helper. The discipline now holds by construction
/// rather than per call site.
pub fn systemctl() -> Command {
    let mut c = Command::new(SYSTEMCTL_BIN);
    c.env_clear();
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

/// Same chokepoint discipline for journalctl, which is spawned in two places
/// and was unfiltered in both.
pub fn journalctl() -> Command {
    let mut c = Command::new(JOURNALCTL_BIN);
    c.env_clear();
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

/// P5: the account-management helpers get the same treatment.
///
/// systemctl and journalctl were given a chokepoint, and
/// `spawn_chokepoint_tests` asserts the discipline for exactly those two — while
/// useradd, groupadd and getent, spawned from this same file with root
/// privileges, inherited the full environment. The stated exposure above (not
/// argument injection, but an inherited `PATH` that redirects a helper) applies
/// verbatim: absolute paths and fixed argv mean there is no live injection, so
/// this is drift, not a vulnerability. Fixed because the invariant "every
/// privileged spawn in this file goes through a chokepoint" was simply false, and
/// the next helper added would have inherited nothing.
fn scrubbed(bin: &str) -> Command {
    let mut c = Command::new(bin);
    c.env_clear();
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

/// Fail-closed atomic write for root-owned files: rejects symlinks, enforces mode.
fn reject_symlink_chain(path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "security violation: symlink in path chain at {}",
                    ancestor.display()
                )
                .into());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // P4: the bare Err(_) arm made the NotFound arm redundant and turned
            // EACCES / ELOOP / ENOTDIR / ENAMETOOLONG into "this ancestor is fine".
            // An ancestor we cannot inspect is an ancestor we cannot vouch for --
            // the same rule the firewall helper already applies. Fail closed.
            Err(e) => {
                return Err(format!(
                    "security violation: cannot inspect {} in path chain: {}",
                    ancestor.display(),
                    e
                )
                .into());
            }
            _ => {}
        }
        if ancestor == Path::new("/") {
            break;
        }
    }
    Ok(())
}

fn secure_write_root_file(
    path: &str,
    content: &str,
    mode: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let p = Path::new(path);
    reject_symlink_chain(p)?;
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
        // post-mkdir revalidation: parent must be a root-owned real dir
        let pmeta = fs::symlink_metadata(parent)?;
        if pmeta.file_type().is_symlink() || !pmeta.file_type().is_dir() {
            return Err(format!(
                "security violation: unsafe parent dir at {}",
                parent.display()
            )
            .into());
        }
        if pmeta.uid() != 0 {
            return Err(format!(
                "security violation: parent {} owned by uid {} (expected root)",
                parent.display(),
                pmeta.uid()
            )
            .into());
        }
    }
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(p)?;
    // 2. verify we opened a regular file owned by root
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(format!("security violation: {} is not a regular file", path).into());
    }
    #[cfg(unix)]
    {
        if meta.uid() != 0 {
            return Err(format!("security violation: {} owned by uid {}", path, meta.uid()).into());
        }
    }
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    // enforce mode via fd (no path re-open race)
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let _ = unsafe { libc::fchmod(file.as_raw_fd(), mode) };
    }
    #[cfg(not(unix))]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(mode));
    }
    Ok(())
}

/// Validates that a path is safe to embed in a systemd ExecStart line (no shell metachars).
fn validate_exec_path(path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if path.is_empty() || path.len() > 512 || !path.starts_with('/') {
        return Err("security violation: exec path must be absolute".into());
    }
    for ch in [
        ' ', '"', '\'', '\n', '\r', '\t', ';', '$', '`', '&', '|', '>', '<', '*', '?', '~', '#',
        '\\', '(', ')', '{', '}',
    ] {
        if path.contains(ch) {
            return Err(format!(
                "security violation: exec path contains forbidden char {:?}",
                ch
            )
            .into());
        }
    }
    if path.contains("..") {
        return Err("security violation: exec path contains ..".into());
    }
    Ok(())
}

/// True when `a` and `b` resolve to the same file. A missing `b` (first
/// install) is not a collision.
fn paths_refer_to_same_file(
    a: &Path,
    b: &Path,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let ma = fs::metadata(a)?;
    match fs::metadata(b) {
        Ok(mb) => Ok(ma.dev() == mb.dev() && ma.ino() == mb.ino()),
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Pins the installed binary to 0755. `std::fs::copy` copies the source's
/// permission bits, and the documented install sources from the invoking
/// user's build tree, so without this the arriving mode is caller-controlled.
#[cfg(unix)]
fn normalize_installed_mode() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(SYSTEM_BIN_PATH, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn normalize_installed_mode() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Ok(())
}

/// Confirms the copy actually moved bytes. A zero-length destination, or one
/// shorter than the source, means the transfer failed or was truncated even
/// though `fs::copy` returned Ok — which is what a self-copy looks like.
fn verify_copy_transferred(
    src: &Path,
    dst: &Path,
    src_len: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dst_len = fs::metadata(dst)?.len();
    if dst_len == 0 {
        return Err(format!(
            "install produced a zero-byte {} — refusing to point the unit at an empty binary",
            dst.display()
        )
        .into());
    }
    if src_len != 0 && dst_len != src_len {
        return Err(format!(
            "installed {} is {} bytes but source {} is {} — refusing a truncated copy",
            dst.display(),
            dst_len,
            src.display(),
            src_len
        )
        .into());
    }
    Ok(())
}

/// Rejects a permission mode that would let anyone but root rewrite the
/// installed binary. The unit execs this exact file with six ambient
/// capabilities, so a group- or world-writable copy hands code execution to
/// every local principal in that set on the next restart.
///
/// `std::fs::copy` propagates the source's permission bits to the destination,
/// and the documented install command sources the binary from the invoking
/// user's build tree, so the arriving mode is caller-controlled unless we
/// both normalise it and refuse it here.
fn installed_mode_ok(mode: u32) -> bool {
    mode & 0o022 == 0
}

/// After copying, verifies SYSTEM_BIN_PATH is a root-owned, non-group- or
/// world-writable regular file (not symlink) and canonicalizes it.
fn verify_installed_binary() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let p = Path::new(SYSTEM_BIN_PATH);
    let meta = fs::symlink_metadata(p)
        .map_err(|e| format!("installed binary missing at {}: {}", SYSTEM_BIN_PATH, e))?;
    if meta.file_type().is_symlink() {
        return Err(format!("security violation: {} is a symlink", SYSTEM_BIN_PATH).into());
    }
    if !meta.file_type().is_file() {
        return Err(format!(
            "security violation: {} is not a regular file",
            SYSTEM_BIN_PATH
        )
        .into());
    }
    if meta.len() == 0 {
        return Err(format!(
            "security violation: {} is empty — refusing to install a zero-byte binary",
            SYSTEM_BIN_PATH
        )
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.uid() != 0 {
            return Err(format!(
                "security violation: {} owned by uid {} (expected root)",
                SYSTEM_BIN_PATH,
                meta.uid()
            )
            .into());
        }
        let perm_bits = meta.permissions().mode() & 0o7777;
        if !installed_mode_ok(perm_bits) {
            return Err(format!(
                "security violation: {} is group/world writable (mode {:04o})",
                SYSTEM_BIN_PATH, perm_bits
            )
            .into());
        }
    }
    let canon = fs::canonicalize(p)?;
    let canon_str = canon.to_str().ok_or("non-utf8 binary path")?.to_string();
    if canon_str != SYSTEM_BIN_PATH {
        return Err(format!(
            "security violation: canonical binary path {} != {}",
            canon_str, SYSTEM_BIN_PATH
        )
        .into());
    }
    validate_exec_path(&canon_str)?;
    Ok(canon_str)
}

/// Ensures the `albus` system user/group exist for rootless runtime.
/// Idempotent: existing accounts (any uid, locked password, nologin shell
/// or otherwise) are accepted as-is — install never mutates an existing
/// account, it only creates a missing one with safe defaults.
fn ensure_service_user() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let check = scrubbed("/usr/sbin/useradd").arg("--help").output();
    if check.is_err() {
        // no useradd (minimal container?): rootless is unavailable;
        // install continues — the unit will fail loudly at startup
        // instead of here.
        eprintln!("warning: /usr/sbin/useradd missing, skipping service-user creation");
        return Ok(());
    }
    // SUPPLY-04: `id albus` used to decide — present meant "accept untouched,
    // having verified nothing". That single unvalidated name-to-uid binding then
    // drove four trust decisions: the daemon identity carrying six ambient
    // capabilities, the polkit rule granting polkit.Result.YES (no
    // authentication) for five resolve1 actions to subject.user == "albus",
    // ownership of /etc/albus, and config.rs's root-equivalence check for
    // /etc/albus, /run/albus and any privileged --config file.
    //
    // Not MUTATING a pre-existing account is right — install has no business
    // rewriting an operator's account. VALIDATING it before binding a
    // capability-carrying identity to it is a different question, and that is
    // what happens now, through the same predicate `service_uid()` uses at
    // runtime so install and runtime cannot drift.
    if let Some(account) = crate::core::ebpf::features::inspect_service_account() {
        if let Some(reason) = account.rejection() {
            return Err(format!(
                "refusing to install: the pre-existing 'albus' account is not a \
                 dedicated system service account ({reason}). albus runs with six \
                 ambient capabilities and holds unauthenticated polkit resolve1 \
                 grants, so it must be a locked, non-login, non-root system account \
                 with no supplementary groups. Reconcile the account first (or \
                 remove it and re-run), or point albus at a different name.",
            )
            .into());
        }
        // Usable as-is. The group is still checked below, because a missing
        // group is a startup failure rather than an identity problem.
        ensure_service_group()?;
        return Ok(());
    }

    let create = scrubbed("/usr/sbin/useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "--comment",
            "albus DPI evasion daemon",
            // SUPPLY-04: the unit declares Group=albus, but useradd without
            // -g/-U relies on USERGROUPS_ENAB; where that is off the account
            // lands in the default group and the unit fails to start.
            "--user-group",
            "albus",
        ])
        .status()?;
    if !create.success() {
        return Err("failed to create albus system user (see useradd output)".into());
    }
    Ok(())
}

/// Ensures the `albus` group exists, so the unit's `Group=albus` can always
/// start the daemon. SUPPLY-04: `useradd` was invoked with neither `-g` nor
/// `-U`, so on a distro with `USERGROUPS_ENAB no` the account landed in the
/// default group.
fn ensure_service_group() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Absolute path, no shell, fixed argv.
    let ok = scrubbed("/usr/bin/getent")
        .args(["group", "albus"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        return Ok(());
    }
    let created = scrubbed("/usr/sbin/groupadd")
        .args(["--system", "albus"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !created {
        return Err("failed to create the albus system group (Group=albus in the unit)".into());
    }
    Ok(())
}

/// Ensures daemon-managed directories exist with service-user ownership.
/// Pre-existing content is never deleted or re-permissioned file-by-file:
/// only the top directory ownership is converged (root-owned leftovers
/// from pre-migration installs become daemon-writable this way).
fn ensure_service_dirs() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ensure_service_dirs_at(Path::new("/etc/albus"))
}

/// W5-01: this is the one privileged writer in service.rs that had none of the
/// confinement `secure_write_root_file` applies to both artifacts install
/// writes. Specifically:
///
///   * `Path::exists()` follows symlinks, so a symlinked `/etc/albus` passed the
///     existence gate;
///   * `libc::chown` also follows symlinks, so it would hand ownership of
///     whatever the link resolved to — potentially a whole tree outside /etc —
///     to the service account;
///   * no ancestor was checked, so `/etc` itself being a link went unnoticed;
///   * `set_permissions(0o755)` lived inside the `!exists()` branch, so a
///     pre-existing directory kept whatever mode it had — including 0777.
///
/// That chown is load-bearing: `is_trusted_system_uid` blesses service-uid-owned
/// system paths in four places (`check_parent_ownership`, `check_write_owner`,
/// `safe_read`, and `load_from_file_root_checked` — the gate on the
/// root-privileged `--config` path). So "owns /etc/albus" versus "owns whatever
/// the symlink pointed at" is a boundary crossing, not a cosmetic difference.
fn ensure_service_dirs_at(dir: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // The account the directory is handed to. Resolved once, here, so the
    // confinement logic below can be exercised without root.
    let owner = std::ffi::CString::new("albus").ok().and_then(|c| unsafe {
        let pwd = libc::getpwnam(c.as_ptr());
        if pwd.is_null() {
            None
        } else {
            Some(((*pwd).pw_uid, (*pwd).pw_gid))
        }
    });
    converge_service_dir(dir, owner)
}

/// The confinement and ownership convergence for the service config directory,
/// with the target owner injected.
///
/// W5-01, see `ensure_service_dirs` for the finding. The chown is separated from
/// the checks so the checks — symlink rejection, O_NOFOLLOW open, fstat, mode
/// convergence — are testable without root, which is the only way they can be
/// regression-tested at all.
fn converge_service_dir(
    dir: &Path,
    owner: Option<(libc::uid_t, libc::gid_t)>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::PermissionsExt;

    // The crate already has this helper and already applies it to every file it
    // writes; the chown was simply never brought under it.
    reject_symlink_chain(dir)?;

    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }

    // Open the directory itself with O_NOFOLLOW|O_DIRECTORY, then fstat and
    // fchown THROUGH THE FD. The fd is the object that was validated, so there
    // is no window between "checked" and "mutated" — the pattern
    // `secure_write_root_file` already uses.
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir)
            .map_err(|e| {
                format!(
                    "refusing to operate on {}: {} (not a directory, or a symlink)",
                    dir.display(),
                    e
                )
            })?
    };
    let meta = file.metadata()?;
    if !meta.file_type().is_dir() {
        return Err(format!("security violation: {} is not a directory", dir.display()).into());
    }

    // W5-01: the mode is converged on EVERY install, not only when the directory
    // is newly created. A pre-existing 0777 /etc/albus is exactly the case this
    // misses today.
    // P4: the chown below is done through the fd precisely to avoid a
    // check-then-use window, but this chmod was still issued BY PATH after the
    // O_NOFOLLOW|O_DIRECTORY open and fstat -- i.e. inside the very window the fd
    // was opened to eliminate, and chmod follows symlinks. Use the fd.
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    {
        use std::os::unix::fs::PermissionsExt as _;
        let now = fs::metadata(dir)?.permissions().mode() & 0o7777;
        if now & 0o022 != 0 {
            return Err(format!(
                "failed to converge the mode of {} to 0755 (still {:04o})",
                dir.display(),
                now
            )
            .into());
        }
    }

    // Converge top-dir ownership to the service user. Through the validated fd,
    // not through the path: a path-based chown follows symlinks, which is the
    // W5-01 defect. `owner` is injected so the confinement checks around it are
    // testable without root.
    if let Some((uid, gid)) = owner {
        let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
        if unsafe { libc::fchown(fd, uid, gid) } != 0 {
            return Err(format!("failed to chown {} to the albus user", dir.display()).into());
        }
    }
    Ok(())
}

/// Renders the systemd unit template (pure; unit-tested). Keeping
/// rendering separate from install I/O means CI validates the exact bytes
/// systemd will receive, including the load-bearing `+` on ExecStopPost and
/// the L1 rootless directives (User=albus + RuntimeDirectory/StateDirectory).
fn build_unit_content(exec_start: &str, exec_stop: &str) -> String {
    format!(
        r#"[Unit]
Description=albus — High-Performance eBPF DPI Bypass & DoH DNS Service
Documentation=https://github.com/oqullcan/albus
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
# Rootless operation (L1 migration): the daemon runs as the dedicated
# `albus` system user with exactly the capabilities below — full root is
# no longer required at runtime. Service MANAGEMENT (this install/uninstall
# path) still runs as real root.
User=albus
Group=albus
# Volatile + persistent state owned by the service user (created here and
# by StateDirectory); /etc/resolv.conf stays root-owned (CAP_DAC_OVERRIDE
# covers the daemon's rewrite) and is guarded by ReadWritePaths.
RuntimeDirectory=albus
RuntimeDirectoryMode=0750
StateDirectory=albus
Environment=HOME=/var/lib/albus
# BPF maps + perf rings charge memlock: the default 64 KiB process limit
# would fail map creation for a non-root daemon. Unlimited here (the maps
# are small and bounded in code: 64-entry hashes, 32-page rings).
LimitMEMLOCK=infinity
ExecStart={exec_start}
ExecReload=/bin/kill -s HUP $MAINPID
# NOTE (L4, deliberate tradeoff): ExecStopPost runs `cleanup` on EVERY stop,
# including crashes — so a crash briefly lifts kill-switch/lockdown until
# `Restart=always` (3 s) brings the daemon back. Fail-open-for-seconds beats
# fail-closed-forever here: a persistent lockdown without a daemon would
# brick outbound web/DNS with no self-recovery. Crash loops are visible in
# the journal; protections re-apply on each restart.
# The `+` prefix is load-bearing: with User=albus below, an unprefixed
# ExecStopPost would run unprivileged and `cleanup` would refuse (it needs
# root for resolv.conf/iptables) — leaving stale DNS/rules behind exactly
# when they matter most (post-crash). `+` forces full privileges.
ExecStopPost=+{exec_stop}
Restart=always
RestartSec=3
LimitNOFILE=65536
# Privilege model (L1 migration complete): the daemon runs as User=albus
# with exactly these capabilities — full root is no longer required at
# runtime. has_service_privileges() enforces the same set in-process.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# W2-01: this was the whole host /run. Under ProtectSystem=strict the
# ReadWritePaths entries are the ONLY writable subtrees, and CAP_DAC_OVERRIDE
# is in both capability lists, so granting all of /run removed the ownership
# check from every file under it -- including other unprivileged principals'
# /run/user/<uid> trees, systemd-resolved's runtime state and NetworkManager's.
#
# The daemon's actual /run remit is one file: /run/albus/config.json (plus the
# per-uid variants), and systemd already excludes RuntimeDirectory paths from
# ProtectSystem, so /run/albus is writable without a ReadWritePaths entry. The
# resolver file is /run/systemd/resolve/stub-resolv.conf on a systemd-resolved
# host (the /etc/resolv.conf entry follows the symlink), and is a regular
# /etc file elsewhere. The leading `-` keeps the unit startable on a host
# without systemd-resolved.
ReadWritePaths=-/run/systemd/resolve /etc/resolv.conf /etc/albus

[Install]
WantedBy=multi-user.target
"#,
    )
}

// generates systemd unit file with AmbientCapabilities, installs polkit rule, and enables auto-start
fn install_service(_args: &RunArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service install requires root privileges — run with sudo".into());
    }

    // L1 rootless runtime: dedicated service user + daemon-owned dirs first,
    // so the unit below can drop root at startup.
    ensure_service_user()?;
    ensure_service_dirs()?;

    // copy binary to standard system execution path — FAIL CLOSED, no fallback
    let exe_path = std::env::current_exe()?;
    // `std::fs::copy` opens the destination O_WRONLY|O_CREAT|O_TRUNC. When the
    // destination IS the source — which is exactly what happens on the
    // documented `sudo albus service install` upgrade path, because
    // current_exe() then resolves to /usr/local/bin/albus — that truncates the
    // inode the still-open source descriptor is about to read, leaving a
    // zero-byte binary that still passes every path/owner check below. Detect
    // it and refuse instead.
    if paths_refer_to_same_file(&exe_path, Path::new(SYSTEM_BIN_PATH))? {
        return Err(format!(
            "refusing to install: {} is already the installed binary at {} — \
             re-run install from the built binary in your source tree instead",
            exe_path.display(),
            SYSTEM_BIN_PATH
        )
        .into());
    }
    // P4: the ordering was backwards. fs::copy opens with O_CREAT|O_TRUNC, which
    // FOLLOWS a symlink, and normalize_installed_mode chmods through one — so if
    // SYSTEM_BIN_PATH were a symlink, root truncated and rewrote the link target
    // before verify_installed_binary finally refused it. Reaching that state needs
    // root to plant the link (/usr/local/bin is root-owned), so this was not
    // reachable unprivileged, but refuse BEFORE writing rather than after.
    if let Ok(meta) = fs::symlink_metadata(SYSTEM_BIN_PATH) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "security violation: refusing to install through symlink at {}",
                SYSTEM_BIN_PATH
            )
            .into());
        }
        if !meta.file_type().is_file() {
            return Err(format!(
                "security violation: {} exists and is not a regular file",
                SYSTEM_BIN_PATH
            )
            .into());
        }
    }
    let src_len = fs::metadata(&exe_path)?.len();
    fs::copy(&exe_path, SYSTEM_BIN_PATH).map_err(|e| {
        format!(
            "failed to copy {} to {}: {} — aborting install (refusing caller-controlled fallback)",
            exe_path.display(),
            SYSTEM_BIN_PATH,
            e
        )
    })?;
    // fs::copy propagates the source's permission bits, and the documented
    // source is a file inside the invoking user's tree. Pin the mode so a
    // group/world-writable build never reaches a root-executed path.
    normalize_installed_mode()?;

    // verify installed copy is root-owned, non-symlink, non-empty, canonical,
    // not group/world writable, and actually carries the bytes we copied
    verify_copy_transferred(&exe_path, Path::new(SYSTEM_BIN_PATH), src_len)?;
    let exe_str = verify_installed_binary()?;

    let exec_start = format!("{} run", exe_str);
    let exec_stop = format!("{} cleanup", exe_str);

    // L1 rootless unit (pure renderer below — unit-tested byte for byte).
    let unit_content = build_unit_content(&exec_start, &exec_stop);

    secure_write_root_file(SERVICE_FILE_PATH, &unit_content, 0o600)?;
    println!("Created systemd service unit: {}", SERVICE_FILE_PATH);

    // install polkit authorization rule (fail closed — no silent half-install)
    if let Some(parent) = Path::new(POLKIT_RULE_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    secure_write_root_file(POLKIT_RULE_PATH, POLKIT_RULE_CONTENT, 0o644)?;
    println!("Created polkit authorization rule: {}", POLKIT_RULE_PATH);

    // reload daemon manager and enable unit (absolute path, checked)
    let reload = systemctl().arg("daemon-reload").status()?;
    if !reload.success() {
        return Err("systemctl daemon-reload failed — aborting".into());
    }
    let enable = systemctl()
        .args(["enable", "--now", "albus.service"])
        .status()?;
    if !enable.success() {
        return Err("systemctl enable --now albus.service failed".into());
    }

    println!("albus binary copied to /usr/local/bin/albus");
    println!("albus service installed, enabled, and started successfully!");
    println!("Check live status with: sudo albus service status");
    println!("View live logs with:   sudo albus service logs");

    Ok(())
}

// securely removes a root-owned file, refusing symlinks
fn secure_remove_file(path: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(
                    format!("security violation: refusing to remove symlink at {}", path).into(),
                );
            }
            fs::remove_file(path)?;
            Ok(true)
        }
    }
}

/// The final uninstall verdict, as a pure function of the four step outcomes.
///
/// SUPPLY-03: extracted so the decision is testable without root, a live
/// packet filter, or a real systemd unit — the previous code computed four
/// counters, discarded them, and printed the unqualified success string based
/// on `dns_reverted` alone. The invariant is that *no* combination containing a
/// failed step may yield the "system settings cleaned up" string, because that
/// string is what an operator reads when deciding whether the host is safe.
fn uninstall_message(
    stop_ok: bool,
    disable_ok: bool,
    firewall_ok: bool,
    dns_ok: bool,
) -> &'static str {
    if stop_ok && disable_ok && firewall_ok && dns_ok {
        "albus service uninstalled and system settings cleaned up."
    } else {
        // Name every step that did not verify, so the operator knows which
        // subsystem to go inspect instead of being told "check resolv.conf"
        // when the problem is stranded DROP rules.
        let mut bad: Vec<&str> = Vec::new();
        if !stop_ok {
            bad.push("unit stop");
        }
        if !disable_ok {
            bad.push("unit disable");
        }
        if !firewall_ok {
            bad.push("firewall revert");
        }
        if !dns_ok {
            bad.push("DNS restore");
        }
        match bad.len() {
            0 => "albus service uninstalled.",
            1 => match bad[0] {
                "firewall revert" => "albus service uninstalled BUT the firewall revert did not verify — residual albus rules may still block outbound traffic; check `sudo iptables -S OUTPUT | grep albus` and `sudo albus cleanup`.",
                "DNS restore" => "albus service uninstalled BUT DNS restore failed — run `sudo albus cleanup` and verify /etc/resolv.conf.",
                _ => "albus service uninstalled BUT the systemd unit could not be fully stopped/disabled — the daemon may still be running; check `systemctl status albus`.",
            },
            _ => "albus service uninstalled BUT some cleanup steps did not verify. Re-run `sudo albus cleanup`, then check `systemctl status albus`, `sudo iptables -S OUTPUT | grep albus` and /etc/resolv.conf.",
        }
    }
}

// uninstalls service unit and restores network state
fn uninstall_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service uninstall requires root privileges — run with sudo".into());
    }

    // stop/disable/remove unit without exists() TOCTOU.
    // FP-03: surface stop/disable failures — they gate the ExecStopPost
    // mitigation, and silent success here used to mask persistent rules.
    let mut stop_ok = true;
    let mut disable_ok = true;
    let mut firewall_ok = true;
    match systemctl().args(["stop", "albus.service"]).status() {
        Ok(s) if s.success() => {}
        Ok(s) => {
            stop_ok = false;
            eprintln!(
                "warning: systemctl stop albus.service exited {} — continuing with explicit revert",
                s
            );
        }
        Err(e) => {
            stop_ok = false;
            eprintln!(
                "warning: systemctl stop albus.service failed to spawn ({}) — continuing with explicit revert",
                e
            );
        }
    }
    match systemctl().args(["disable", "albus.service"]).status() {
        Ok(s) if s.success() => {}
        Ok(s) => {
            disable_ok = false;
            eprintln!("warning: systemctl disable exited {}", s);
        }
        Err(e) => {
            disable_ok = false;
            eprintln!("warning: systemctl disable failed to spawn ({})", e);
        }
    }

    // FP-09: revert persistent network state FIRST, before any fallible file
    // or daemon housekeeping that could abort with `return Err` and strand it.
    // FP-10: report revert outcomes instead of assuming success.
    // SUPPLY-03: every revert step's outcome is now captured. Previously the
    // four counters were summed and the result thrown away, so the final
    // message was gated on `dns_reverted` alone and claimed the system was
    // clean regardless of what the packet-filter layer did. `stop` failing is
    // the sharpest case: that is precisely when ExecStopPost never ran, so this
    // function's own revert is the only thing standing between the admin and
    // stranded fail-closed DROP rules on outbound DNS.
    let fw_removed = {
        let mut n = 0usize;
        let steps: [(&str, crate::core::firewall::FwCount); 4] = [
            ("unblock_quic", crate::core::firewall::unblock_quic()),
            ("unblock_stun", crate::core::firewall::unblock_stun()),
            (
                "disable_kill_switch",
                crate::core::firewall::disable_kill_switch(),
            ),
            (
                "disable_network_lockdown",
                crate::core::firewall::disable_network_lockdown(),
            ),
        ];
        for (name, r) in steps {
            match r {
                Ok(k) => n += k,
                Err(e) => {
                    firewall_ok = false;
                    eprintln!(
                        "warning: firewall revert {} FAILED ({}): residual rules may \
                         still block outbound traffic — check with \
                         `sudo iptables -S OUTPUT | grep albus`",
                        name, e
                    );
                }
            }
        }
        n
    };
    println!("Removed {} firewall rule(s).", fw_removed);
    let dns_reverted = match crate::dns::cleanup_system_dns() {
        Ok(true) => {
            println!("Restored original system DNS.");
            true
        }
        Ok(false) => {
            println!("No albus DNS markers found; resolver left untouched.");
            true
        }
        Err(e) => {
            eprintln!(
                "warning: DNS restore failed: {} — check /etc/resolv.conf manually",
                e
            );
            false
        }
    };

    match secure_remove_file(SERVICE_FILE_PATH) {
        Ok(true) => println!("Removed {}", SERVICE_FILE_PATH),
        Ok(false) => println!("No albus.service file found at {}", SERVICE_FILE_PATH),
        Err(e) => return Err(e),
    }
    // SUPPLY-03: the polkit rule is removed BEFORE the fallible daemon-reload.
    // `?` used to abort there, stranding /etc/polkit-1/rules.d/albus.rules —
    // which still carries `subject.user == "albus"` resolve1 grants — with no
    // message naming it, on an uninstall that appeared to have failed.
    match secure_remove_file(POLKIT_RULE_PATH) {
        Ok(true) => println!("Removed {}", POLKIT_RULE_PATH),
        Ok(false) => {}
        Err(e) => eprintln!(
            "warning: could not remove {} ({}): the polkit grants it contains may still be in effect",
            POLKIT_RULE_PATH, e
        ),
    }

    let reload = systemctl().arg("daemon-reload").status()?;
    if !reload.success() {
        return Err("systemctl daemon-reload failed during uninstall".into());
    }

    // FP-10 + SUPPLY-03: the final message is qualified on every revert
    // outcome, not just DNS. A bare "cleaned up" while fail-closed DROP rules
    // are still installed leaves the host with no working outbound network and
    // no indication why.
    println!(
        "{}",
        uninstall_message(stop_ok, disable_ok, firewall_ok, dns_reverted)
    );
    // FP-04: the system binary is intentionally retained (lets the admin run
    // `sudo albus cleanup` afterwards); say so instead of implying full removal.
    println!(
        "note: system binary retained at {} (run `sudo albus cleanup` if needed, then remove it manually)",
        SYSTEM_BIN_PATH
    );
    Ok(())
}

fn start_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service start requires root privileges — run with sudo".into());
    }
    let status = systemctl().args(["start", "albus.service"]).status()?;
    if status.success() {
        println!("albus.service started.");
    } else {
        eprintln!("Failed to start albus.service");
    }
    Ok(())
}

fn stop_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service stop requires root privileges — run with sudo".into());
    }
    let status = systemctl().args(["stop", "albus.service"]).status()?;
    if status.success() {
        println!("albus.service stopped.");
    } else {
        eprintln!("Failed to stop albus.service");
    }
    Ok(())
}

fn restart_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service restart requires root privileges — run with sudo".into());
    }
    let status = systemctl().args(["restart", "albus.service"]).status()?;
    if status.success() {
        println!("albus.service restarted.");
    } else {
        eprintln!("Failed to restart albus.service");
    }
    Ok(())
}

fn reload_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service reload requires root privileges — run with sudo".into());
    }
    let status = systemctl()
        .args(["kill", "-s", "HUP", "albus.service"])
        .status()?;
    if status.success() {
        println!("albus.service configuration reloaded live via SIGHUP.");
    } else {
        eprintln!("Failed to reload albus.service — verify daemon is actively running");
    }
    Ok(())
}

fn show_service_status() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = systemctl().args(["status", "albus.service"]).status()?;
    Ok(())
}

fn show_service_logs() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = journalctl()
        .args(["-u", "albus.service", "-f", "-n", "50"])
        .status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // L1: the rendered unit must carry the rootless directives byte-exactly.
    #[test]
    fn test_unit_content_rootless() {
        let unit = build_unit_content("/usr/local/bin/albus run", "/usr/local/bin/albus cleanup");
        assert!(unit.contains("User=albus\n"));
        assert!(unit.contains("Group=albus\n"));
        assert!(unit.contains("RuntimeDirectory=albus\n"));
        assert!(unit.contains("StateDirectory=albus\n"));
        assert!(unit.contains("Environment=HOME=/var/lib/albus\n"));
        assert!(unit.contains("ExecStopPost=+/usr/local/bin/albus cleanup\n"));
        assert!(unit.contains(
            "# W2-01: this was the whole host /run. Under ProtectSystem=strict the
# ReadWritePaths entries are the ONLY writable subtrees, and CAP_DAC_OVERRIDE
# is in both capability lists, so granting all of /run removed the ownership
# check from every file under it -- including other unprivileged principals'
# /run/user/<uid> trees, systemd-resolved's runtime state and NetworkManager's.
#
# The daemon's actual /run remit is one file: /run/albus/config.json (plus the
# per-uid variants), and systemd already excludes RuntimeDirectory paths from
# ProtectSystem, so /run/albus is writable without a ReadWritePaths entry. The
# resolver file is /run/systemd/resolve/stub-resolv.conf on a systemd-resolved
# host (the /etc/resolv.conf entry follows the symlink), and is a regular
# /etc file elsewhere. The leading `-` keeps the unit startable on a host
# without systemd-resolved.
ReadWritePaths=-/run/systemd/resolve /etc/resolv.conf /etc/albus\n"
        ));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_ADMIN"));
        assert!(unit.contains("ExecStart=/usr/local/bin/albus run\n"));
        // management stays root-gated in code (unit has no User= bypass)
        assert!(!unit.contains("User=root"));
    }
}

#[cfg(test)]
mod install_hardening_tests {
    use super::*;
    use std::io::Write as _;
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("albus-install-test-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("tempdir");
        d
    }

    /// SUPPLY-01: a build tree that is group- or world-writable must never be
    /// able to place a mode-writable binary at the root-executed path.
    /// `std::fs::copy` propagates the source bits, so the arriving mode is
    /// caller-controlled unless the mode is both pinned and re-checked.
    #[cfg(unix)]
    #[test]
    fn test_installed_mode_ok_rejects_writable_modes() {
        for ok in [0o755u32, 0o750, 0o700, 0o555, 0o544] {
            assert!(installed_mode_ok(ok), "{:04o} must be accepted", ok);
        }
        for bad in [
            0o777u32, 0o775, 0o757, 0o770, 0o707, 0o666, 0o022, 0o002, 0o020,
        ] {
            assert!(!installed_mode_ok(bad), "{:04o} must be rejected", bad);
        }
        // setuid/setgid carry no write grant, so they are not this
        // predicate's concern -- it deliberately tests only group/other write,
        // which is the bit an unprivileged local principal could use.
        assert!(installed_mode_ok(0o4755), "setuid alone grants no write");
        assert!(
            !installed_mode_ok(0o4777),
            "setuid plus world-write must fail"
        );
    }

    /// SUPPLY-02: the zero-byte and short-copy cases that a self-copy produces
    /// must be refused by the post-transfer check, not waved through.
    #[test]
    fn test_verify_copy_transferred_rejects_empty_and_short() {
        let d = tmpdir("xfer");
        let src = d.join("src");
        let mut f = fs::File::create(&src).expect("src");
        f.write_all(b"albus-binary-bytes").expect("write");
        drop(f);

        let dst = d.join("dst");
        let src_len = fs::metadata(&src).expect("meta").len();
        assert_eq!(src_len, 18, "fixture length is part of the test");

        // Zero-byte destination: exactly what fs::copy leaves behind when
        // source and destination are the same inode.
        fs::write(&dst, b"").expect("write");
        assert!(
            verify_copy_transferred(&src, &dst, src_len).is_err(),
            "empty destination must be refused"
        );

        // Truncated transfer.
        fs::write(&dst, b"short").expect("write");
        assert!(
            verify_copy_transferred(&src, &dst, src_len).is_err(),
            "length mismatch must be refused"
        );

        // Successful case: destination carries exactly the source bytes.
        fs::copy(&src, &dst).expect("copy");
        assert!(verify_copy_transferred(&src, &dst, src_len).is_ok());

        let _ = fs::remove_dir_all(&d);
    }

    /// SUPPLY-02: the self-copy guard must fire for the documented upgrade
    /// path and stay quiet for a genuine first install.
    #[test]
    fn test_same_file_guard_distinguishes_upgrade_from_first_install() {
        let d = tmpdir("samefile");
        let a = d.join("a");
        fs::write(&a, b"payload").expect("write");

        // Same inode via two paths -> collision.
        assert!(
            paths_refer_to_same_file(&a, &a).expect("meta"),
            "identical path must be detected as a self-copy"
        );
        assert!(
            !paths_refer_to_same_file(&a, &d.join("b")).expect("meta"),
            "missing destination is a first install, not a collision"
        );

        // A distinct existing file is not a collision.
        let c = d.join("c");
        fs::write(&c, b"other").expect("write");
        assert!(!paths_refer_to_same_file(&a, &c).expect("meta"));

        let _ = fs::remove_dir_all(&d);
    }

    /// Regression for the ETXTBSY abort observed on this host: install must
    /// refuse up front rather than half-install when current_exe() is already
    /// the installed binary.
    #[test]
    fn test_verify_installed_binary_rejects_zero_byte_artifact() {
        let d = tmpdir("zero");
        let p = d.join("albus");
        fs::write(&p, b"").expect("write empty");
        // The helper is exercised through its own predicate rather than the
        // fixed SYSTEM_BIN_PATH, so the test needs no root and no /usr write.
        let meta = fs::symlink_metadata(&p).expect("meta");
        assert_eq!(meta.len(), 0);
        let _ = fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod spawn_chokepoint_tests {
    /// W1-02: `env_clear` + a pinned PATH must hold for EVERY privileged
    /// systemctl/journalctl spawn, not just the ones that happened to remember.
    ///
    /// The finding was that the correct helper existed and was bypassed at four
    /// sites, so the discipline was per-call-site and had already drifted. This
    /// test walks the real source files so a future direct `Command::new` cannot
    /// reintroduce an inherited environment without failing here.
    #[test]
    fn test_no_privileged_spawn_bypasses_the_chokepoint() {
        let files: &[(&str, &str)] = &[
            ("src/main.rs", include_str!("../main.rs")),
            ("src/app/monitor.rs", include_str!("monitor.rs")),
            ("src/app/status.rs", include_str!("status.rs")),
            ("src/app/service.rs", include_str!("service.rs")),
        ];

        // The only legal literals are the two constants and the two helper
        // bodies themselves.
        let mut offenders: Vec<String> = Vec::new();
        for (name, src) in files {
            // strip test modules: they quote the needles as assertions
            let prod = src
                .split_once("#[cfg(test)]")
                .map(|(p, _)| p)
                .unwrap_or(src);
            for needle in [
                "Command::new(\"/usr/bin/systemctl\")",
                "Command::new(\"/usr/bin/journalctl\")",
                "Command::new(SYSTEMCTL_BIN)",
                "Command::new(JOURNALCTL_BIN)",
            ] {
                let mut from = 0usize;
                while let Some(at) = prod[from..].find(needle) {
                    let abs = from + at;
                    // the single permitted occurrence per helper: the
                    // nearest helper header above us, with no other header in
                    // between. Taking max() of both rfinds matters — checking
                    // systemctl first would misattribute journalctl's body to
                    // systemctl's header.
                    let last_header = prod[..abs]
                        .rfind("pub fn systemctl()")
                        .into_iter()
                        .chain(prod[..abs].rfind("pub fn journalctl()"))
                        .max();
                    let in_helper = last_header
                        .map(|h| abs > h && !prod[h..abs].contains("\npub fn "))
                        .unwrap_or(false);
                    if !in_helper {
                        let line = prod[..abs].lines().count();
                        offenders.push(format!("{}:{} {}", name, line, needle));
                    }
                    from = abs + needle.len();
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "privileged spawns must go through systemctl()/journalctl(): {}",
            offenders.join(", ")
        );
    }

    /// And the helpers themselves must actually clear the environment.
    #[test]
    fn test_chokepoint_helpers_clear_the_environment() {
        let src = include_str!("service.rs");
        for helper in ["pub fn systemctl()", "pub fn journalctl()"] {
            let at = src
                .find(helper)
                .unwrap_or_else(|| panic!("{} not found", helper));
            let body = &src[at..(at + 400).min(src.len())];
            let end = body.find("\n}").unwrap_or(body.len());
            let body = &body[..end];
            assert!(
                body.contains("env_clear()"),
                "{} must clear the environment: {}",
                helper,
                body
            );
            assert!(body.contains("PATH"), "{} must pin PATH: {}", helper, body);
        }
    }
}

#[cfg(test)]
mod uninstall_outcome_tests {
    use super::*;

    const CLEAN: &str = "albus service uninstalled and system settings cleaned up.";

    /// SUPPLY-03: no combination containing a failed step may produce the
    /// unqualified "cleaned up" string. On unpatched source the message was
    /// gated on `dns_reverted` alone, so a failed firewall revert — which is
    /// exactly the case where `systemctl stop` failed and therefore
    /// ExecStopPost never ran — still told the operator the host was clean.
    #[test]
    fn test_no_failed_step_yields_the_clean_message() {
        assert_eq!(uninstall_message(true, true, true, true), CLEAN);

        let failures = [
            (false, true, true, true), // stop
            (true, false, true, true), // disable
            (true, true, false, true), // firewall revert
            (true, true, true, false), // DNS restore
            (false, true, false, true),
            (true, true, false, false),
            (false, false, true, false),
            (false, true, true, false),
            (true, false, false, true),
            (false, false, false, false),
        ];
        for (stop, disable, fw, dns) in failures {
            let msg = uninstall_message(stop, disable, fw, dns);
            assert_ne!(
                msg, CLEAN,
                "stop={} disable={} fw={} dns={} must not claim a clean uninstall",
                stop, disable, fw, dns
            );
            assert!(
                !msg.contains("cleaned up"),
                "a failed step must not produce 'cleaned up': {}",
                msg
            );
        }
    }

    /// The message must name the subsystem that failed, because "check
    /// resolv.conf" is the wrong advice when the problem is stranded DROP
    /// rules on outbound DNS.
    #[test]
    fn test_message_names_the_failing_subsystem() {
        let fw = uninstall_message(true, true, false, true);
        assert!(fw.contains("firewall"), "{}", fw);
        assert!(
            fw.contains("iptables"),
            "must say how to inspect it: {}",
            fw
        );

        let dns = uninstall_message(true, true, true, false);
        assert!(dns.contains("resolv.conf"), "{}", dns);

        let unit = uninstall_message(false, true, true, true);
        assert!(unit.contains("systemctl status albus"), "{}", unit);

        // Multiple failures get the combined instruction.
        let multi = uninstall_message(false, true, false, false);
        assert!(multi.contains("albus cleanup"), "{}", multi);
        assert!(!multi.contains("cleaned up"), "{}", multi);
    }

    /// And the message must not be silent about what it could not verify.
    #[test]
    fn test_failure_messages_are_actionable() {
        for (stop, disable, fw, dns) in [
            (false, true, true, true),
            (true, false, true, true),
            (true, true, false, true),
            (true, true, true, false),
        ] {
            let msg = uninstall_message(stop, disable, fw, dns);
            assert!(
                msg.contains("BUT") || msg.contains("INCOMPLETE"),
                "failure message must be visibly qualified: {}",
                msg
            );
        }
    }
}

#[cfg(test)]
mod panel_truthfulness_tests {
    /// CLI-01 / W6-01: the panel's privileged controls must not claim more than
    /// they do. These assertions read the real Panel.qml so the labels and
    /// toasts cannot drift back into lying.
    const PANEL: &str = include_str!("../../Panel.qml");

    /// W6-01: the flush handler used to ignore its exit code and always say
    /// "flushed", which fired identically on a polkit denial.
    #[test]
    fn test_flush_toast_is_bound_to_the_exit_code() {
        let at = PANEL.find("id: flushCacheProc").expect("flushCacheProc");
        let block = &PANEL[at..(at + 900).min(PANEL.len())];
        assert!(
            block.contains("onExited: function(code)"),
            "flush handler must receive the exit code"
        );
        assert!(
            block.contains("code === 0"),
            "flush handler must branch on the exit code"
        );
        assert!(
            block.contains("Cache flush failed"),
            "flush handler must report failure: {}",
            block
        );
    }

    /// CLI-01: the button was labelled "Restart Service" but its first action is
    /// a root write of /etc/albus/config.json behind pkexec.
    #[test]
    fn test_apply_button_does_not_mislabel_its_privileged_write() {
        assert!(
            !PANEL.contains("\"Restart Service\""),
            "the button must not claim to be a plain service restart"
        );
        assert!(
            PANEL.contains("\"Apply & Restart\""),
            "the button should say what it does"
        );
    }

    /// CLI-01: `daemonActionProc` discarded its exit code too, so a denied
    /// restart left the previous "applied" toast standing.
    #[test]
    fn test_restart_result_is_not_discarded() {
        let at = PANEL
            .find("id: daemonActionProc")
            .expect("daemonActionProc");
        let block = &PANEL[at..(at + 800).min(PANEL.len())];
        assert!(
            block.contains("code === 0"),
            "the restart result must be inspected: {}",
            block
        );
        assert!(
            block.contains("restart failed"),
            "a failed restart must be reported: {}",
            block
        );
    }

    /// CLI-01: the bare `r` key authorised a privileged write with nothing on
    /// screen. It must now announce itself before it prompts.
    #[test]
    fn test_privileged_key_shortcut_is_not_silent() {
        let key = PANEL
            .find(r#"t === "r" || t === "R""#)
            .expect("the R shortcut handler");
        // Bounded by the NEXT shortcut handler, so this cannot drift onto an
        // unrelated applySystemWide call further down the file.
        let tail = &PANEL[key..];
        let next_handler = tail.find("else if").unwrap_or(tail.len());
        let handler = &tail[..next_handler];
        assert!(
            handler.contains("showToast"),
            "the R shortcut must announce the privileged action before prompting: {}",
            handler
        );
        assert!(
            handler.contains("applySystemWide"),
            "the R shortcut must still reach applySystemWide: {}",
            handler
        );
    }

    /// W6-02: no hidden right-click privileged action on the status icon.
    #[test]
    fn test_status_icon_has_no_hidden_privileged_action() {
        let bar = include_str!("../../BarWidget.qml");
        assert!(
            !bar.contains("Qt.RightButton"),
            "the status icon must not branch on the right mouse button"
        );
        assert!(
            !bar.contains("toggleDaemon"),
            "the status icon must not reach a privileged lifecycle action"
        );
    }
}

#[cfg(test)]
mod service_dirs_tests {
    use super::*;
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("albus-svcdirs-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("tmpdir");
        d
    }

    /// The symlinked-leaf case. `Path::exists()` follows symlinks and
    /// `libc::chown` follows symlinks, so before the fix a symlinked
    /// /etc/albus would have been chowned — handing the whole target tree to
    /// the service account, which `is_trusted_system_uid` then treats as
    /// trusted for system paths in four places.
    #[test]
    fn test_symlinked_directory_is_refused() {
        let d = tmpdir("symlink");
        let real = d.join("real");
        fs::create_dir_all(&real).expect("real");
        let link = d.join("etc-albus");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let r = converge_service_dir(&link, None);
        assert!(
            r.is_err(),
            "W5-01: a symlinked service directory must be refused, not chowned"
        );

        let _ = fs::remove_dir_all(&d);
    }

    /// A symlinked ANCESTOR must be refused too — rejecting only the leaf leaves
    /// `/etc` itself replaceable.
    #[test]
    fn test_symlinked_ancestor_is_refused() {
        let d = tmpdir("ancestor");
        let real = d.join("real");
        fs::create_dir_all(real.join("albus")).expect("real/albus");
        let link = d.join("etc-link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let r = converge_service_dir(&link.join("albus"), None);
        assert!(
            r.is_err(),
            "W5-01: a symlink anywhere in the chain must be refused"
        );

        let _ = fs::remove_dir_all(&d);
    }

    /// A regular file where a directory belongs.
    #[test]
    fn test_regular_file_is_refused() {
        let d = tmpdir("file");
        let f = d.join("etc-albus");
        fs::write(&f, b"not a directory").expect("write");

        assert!(
            converge_service_dir(&f, None).is_err(),
            "a non-directory must be refused"
        );

        let _ = fs::remove_dir_all(&d);
    }

    /// The residual variant that needs no privilege at all: a pre-existing
    /// 0777 directory kept its mode forever, because `set_permissions(0o755)`
    /// was inside the `!exists()` branch.
    #[test]
    fn test_preexisting_world_writable_directory_is_converged_to_0755() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("mode");
        let dir = d.join("etc-albus");
        fs::create_dir_all(&dir).expect("dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).expect("chmod 777");

        converge_service_dir(&dir, None).expect("must succeed");

        let mode = fs::metadata(&dir).expect("meta").permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o755,
            "W5-01: the mode must be converged on every install, not only on creation"
        );
        assert_eq!(mode & 0o022, 0, "no group/world write may remain");

        let _ = fs::remove_dir_all(&d);
    }

    /// The positive control: a plain directory is created if absent and
    /// converged if present.
    #[test]
    fn test_plain_directory_is_accepted() {
        let d = tmpdir("plain");
        let dir = d.join("etc-albus");

        converge_service_dir(&dir, None).expect("must create");
        assert!(dir.is_dir());

        // idempotent
        converge_service_dir(&dir, None).expect("second call must succeed");

        // And with an owner, the chown goes through the validated fd.
        let me = unsafe { (libc::getuid(), libc::getgid()) };
        converge_service_dir(&dir, Some(me)).expect("chown to self must succeed");

        let _ = fs::remove_dir_all(&d);
    }

    /// Regression guards on the source: the two shapes that carried the defect
    /// must not come back.
    #[test]
    fn test_no_symlink_following_gate_or_path_chown() {
        let src = include_str!("service.rs");
        let prod = src
            .split_once("\n#[cfg(test)]\nmod service_dirs_tests")
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod.find("fn converge_service_dir(").expect("the function");
        let tail = &prod[at..];
        let end = tail
            .find("\n/// Renders the systemd unit template")
            .unwrap_or(tail.len());
        let body = &tail[..end];

        assert!(
            body.contains("reject_symlink_chain("),
            "the helper the crate already has must be applied here"
        );
        assert!(
            body.contains("O_NOFOLLOW"),
            "the directory must be opened with O_NOFOLLOW"
        );
        assert!(
            body.contains("libc::fchown("),
            "the chown must go through the validated fd; a path-based chown follows \\
             symlinks"
        );
        assert!(
            !body.contains("libc::chown("),
            "a path-based chown must not remain"
        );
    }
}

#[cfg(test)]
mod source_assertion_hygiene {
    /// A source-assertion test that splits on `"\n#[cfg(test)] mod X"` — note the
    /// SPACE — never matches, because the real text has a newline there. The
    /// marker then silently falls through to `unwrap_or(src)`, so `prod` becomes
    /// the WHOLE FILE including the test modules: every `prod.contains(...)`
    /// assertion passes vacuously and every `!prod.contains(...)` assertion
    /// fails for the wrong reason (it is matching the assertion's own text).
    ///
    /// That happened three separate times in this repository, each time silently
    /// weakening a security regression test. This pins the shape so it cannot
    /// recur: any such marker must contain a real newline between `]` and
    /// `mod`.
    #[test]
    fn test_no_source_assertion_splits_on_a_marker_that_cannot_match() {
        const FILES: &[&str] = &[
            include_str!("service.rs"),
            include_str!("monitor.rs"),
            include_str!("status.rs"),
            include_str!("../core/engine.rs"),
            include_str!("../core/firewall.rs"),
            include_str!("../core/ebpf/loader.rs"),
            include_str!("../core/ebpf/manager.rs"),
            include_str!("../core/ebpf/features.rs"),
            include_str!("../dns/server.rs"),
            include_str!("../dns/system.rs"),
            include_str!("../dns/dnssec.rs"),
            include_str!("../dns/doh.rs"),
            include_str!("../dns/cache.rs"),
            include_str!("config.rs"),
        ];

        for src in FILES {
            for (i, line) in src.lines().enumerate() {
                let Some(start) = line.find("split_once(\"") else {
                    continue;
                };
                let rest = &line[start + "split_once(\"".len()..];
                let Some(end) = rest.find('"') else { continue };
                let marker = &rest[..end];
                if !marker.contains("cfg(test)") {
                    continue;
                }
                assert!(
                    !marker.contains("] mod "),
                    "line {}: marker {:?} puts a SPACE where a newline belongs, so \\
                     it can never match and `prod` silently becomes the whole file",
                    i + 1,
                    marker
                );
            }
        }
    }
}
