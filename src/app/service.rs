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
    // context). Without this, SetLinkDNS et al. fail with "requires
    // interactive authentication", set_system_dns aborts startup, and every
    // NSS lookup hangs behind the kill-switch with zero diagnostics (seen
    // live 2026-09-22). Explicit action list on purpose: nothing here
    // exceeds what the daemon already controls (it writes /etc/resolv.conf
    // directly), so this grants no new capability — it only unbreaks the
    // D-Bus path for the dedicated account.
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

fn systemctl() -> Command {
    let mut c = Command::new(SYSTEMCTL_BIN);
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
            Err(_) => {}
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

/// After copying, verifies SYSTEM_BIN_PATH is a root-owned regular file (not symlink) and canonicalizes it.
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
    #[cfg(unix)]
    {
        if meta.uid() != 0 {
            return Err(format!(
                "security violation: {} owned by uid {} (expected root)",
                SYSTEM_BIN_PATH,
                meta.uid()
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

/// Persists `service install` CLI tuning through the same load/apply/
/// validate/save path as `config set`. Semantics match `config set`
/// exactly: flags fully specify the config, so a bare reinstall resets
/// prior tuning to defaults — explicit and visible, unlike the old silent
/// drop. Split into `_at` for testability: production passes the standard
/// config path, tests pass a temp file.
fn persist_install_config(args: &RunArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    persist_install_config_at(args, &crate::app::config::Config::default_config_path())
}

fn persist_install_config_at(
    args: &RunArgs,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg =
        crate::app::config::apply_run_args(crate::app::config::Config::load_or_default(), args)?;
    cfg.validate()?;
    cfg.save_to_file(path)?;
    Ok(())
}

/// Ensures the `albus` system user/group exist for rootless runtime.
/// Idempotent: existing accounts (any uid, locked password, nologin shell
/// or otherwise) are accepted as-is — install never mutates an existing
/// account, it only creates a missing one with safe defaults.
fn ensure_service_user() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let check = std::process::Command::new("/usr/sbin/useradd")
        .arg("--help")
        .output();
    if check.is_err() {
        // no useradd (minimal container?): rootless is unavailable;
        // install continues — the unit will fail loudly at startup
        // instead of here, and has_service_privileges documents why.
        eprintln!("warning: /usr/sbin/useradd missing, skipping service-user creation");
        return Ok(());
    }
    // `id albus` decides: present -> accept untouched, absent -> create.
    // Absolute paths, no shell, fixed argv (no user input reaches exec).
    let id_status = std::process::Command::new("/usr/bin/id")
        .arg("albus")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if id_status.success() {
        return Ok(());
    }
    let create = std::process::Command::new("/usr/sbin/useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "--comment",
            "albus DPI evasion daemon",
            "albus",
        ])
        .status()?;
    if !create.success() {
        return Err("failed to create albus system user (see useradd output)".into());
    }
    Ok(())
}

/// Ensures daemon-managed directories exist with service-user ownership.
/// Pre-existing content is never deleted or re-permissioned file-by-file:
/// only the top directory ownership is converged (root-owned leftovers
/// from pre-migration installs become daemon-writable this way).
fn ensure_service_dirs() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::PermissionsExt;
    let etc_albus = Path::new("/etc/albus");
    if !etc_albus.exists() {
        fs::create_dir_all(etc_albus)?;
        fs::set_permissions(etc_albus, fs::Permissions::from_mode(0o755))?;
    }
    // converge top-dir ownership to the service user when the account exists
    if let Ok(c_user) = std::ffi::CString::new("albus") {
        unsafe {
            let pwd = libc::getpwnam(c_user.as_ptr());
            if !pwd.is_null() {
                let (uid, gid) = ((*pwd).pw_uid, (*pwd).pw_gid);
                // chown the DIRECTORY (not recursive): files keep their
                // owners; the daemon only needs traversal + its own files
                if let Ok(c_dir) = std::ffi::CString::new("/etc/albus") {
                    if libc::chown(c_dir.as_ptr(), uid, gid) != 0 {
                        return Err("failed to chown /etc/albus to the albus user".into());
                    }
                }
            }
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
ReadWritePaths=/run /etc/resolv.conf /etc/albus

[Install]
WantedBy=multi-user.target
"#,
    )
}

// generates systemd unit file with AmbientCapabilities, installs polkit rule, and enables auto-start
fn install_service(args: &RunArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service install requires root privileges — run with sudo".into());
    }

    // L1 rootless runtime: dedicated service user + daemon-owned dirs first,
    // so the unit below can drop root at startup. Idempotent: existing
    // installs, custom uids, and re-runs all converge here without damage.
    // Daemon-managed paths are owned by the service user (config, marker
    // dir); /etc/resolv.conf itself stays root-owned (daemon rewrites it
    // via CAP_DAC_OVERRIDE under ReadWritePaths).
    ensure_service_user()?;
    ensure_service_dirs()?;

    // copy binary to standard system execution path — FAIL CLOSED, no fallback
    let exe_path = std::env::current_exe()?;
    fs::copy(&exe_path, SYSTEM_BIN_PATH).map_err(|e| {
        format!(
            "failed to copy {} to {}: {} — aborting install (refusing caller-controlled fallback)",
            exe_path.display(),
            SYSTEM_BIN_PATH,
            e
        )
    })?;

    // verify installed copy is root-owned, non-symlink, canonical
    let exe_str = verify_installed_binary()?;

    // L5: persist CLI tuning (previously silently dropped) so the bare
    // `ExecStart={exe} run` below picks it up via the standard config path
    persist_install_config(args)?;

    let exec_start = format!("{} run", exe_str);
    let exec_stop = format!("{} cleanup", exe_str);

    // L1 rootless unit: systemd service spec (least-privilege capabilities +
    // hardening; pure renderer below — unit-tested byte for byte).
    let unit_content = build_unit_content(&exec_start, &exec_stop);

    secure_write_root_file(SERVICE_FILE_PATH, &unit_content, 0o600)?;

    println!("Created systemd service unit: {}", SERVICE_FILE_PATH);

    // install polkit authorization rule (fail closed — no silent half-install)
    if let Some(parent) = Path::new(POLKIT_RULE_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    secure_write_root_file(POLKIT_RULE_PATH, POLKIT_RULE_CONTENT, 0o644)?;
    println!("Created polkit authorization rule: {}", POLKIT_RULE_PATH);

    // managed-install marker: proves albus lived here so firewall cleanup
    // may sweep legacy uncommented rules without risking admin rules
    secure_write_root_file(
        crate::core::firewall::MANAGED_MARKER_PATH,
        "managed\n",
        0o600,
    )?;

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

// uninstalls service unit and restores network state
fn uninstall_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service uninstall requires root privileges — run with sudo".into());
    }

    // stop/disable/remove unit without exists() TOCTOU.
    // FP-03: surface stop/disable failures — they gate the ExecStopPost
    // mitigation, and silent success here used to mask persistent rules.
    match systemctl().args(["stop", "albus.service"]).status() {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "warning: systemctl stop albus.service exited {} — continuing with explicit revert",
            s
        ),
        Err(e) => eprintln!(
            "warning: systemctl stop albus.service failed to spawn ({}) — continuing with explicit revert",
            e
        ),
    }
    match systemctl().args(["disable", "albus.service"]).status() {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("warning: systemctl disable exited {}", s),
        Err(e) => eprintln!("warning: systemctl disable failed to spawn ({})", e),
    }

    // FP-09: revert persistent network state FIRST, before any fallible file
    // or daemon housekeeping that could abort with `return Err` and strand it.
    // FP-10: report revert outcomes instead of assuming success.
    let fw_removed = crate::core::firewall::unblock_quic()
        + crate::core::firewall::unblock_stun()
        + crate::core::firewall::disable_kill_switch()
        + crate::core::firewall::disable_network_lockdown();
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
    let reload = systemctl().arg("daemon-reload").status()?;
    if !reload.success() {
        return Err("systemctl daemon-reload failed during uninstall".into());
    }

    match secure_remove_file(POLKIT_RULE_PATH) {
        Ok(true) => println!("Removed {}", POLKIT_RULE_PATH),
        Ok(false) => {}
        Err(e) => return Err(e),
    }
    match secure_remove_file(crate::core::firewall::MANAGED_MARKER_PATH) {
        Ok(true) => println!("Removed {}", crate::core::firewall::MANAGED_MARKER_PATH),
        Ok(false) => {}
        Err(e) => return Err(e),
    }

    // FP-10: qualify the final message on the revert outcomes above.
    if dns_reverted {
        println!("albus service uninstalled and system settings cleaned up.");
    } else {
        println!(
            "albus service uninstalled BUT DNS restore failed — run `sudo albus cleanup` and verify /etc/resolv.conf."
        );
    }
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
    let mut logs = Command::new(JOURNALCTL_BIN);
    logs.env_clear();
    logs.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    let _ = logs
        .args(["-u", "albus.service", "-f", "-n", "50"])
        .status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_exec_path_accepts_system_binary() {
        assert!(validate_exec_path("/usr/local/bin/albus").is_ok());
    }

    #[test]
    fn test_unit_content_carries_load_bearing_lines() {
        // the template is what systemd will execute: assert the exact
        // security-critical lines render (unsubstituted placeholders or a
        // lost `+` prefix would silently weaken stop-cleanup or privileges)
        let unit = build_unit_content("/usr/local/bin/albus run", "/usr/local/bin/albus cleanup");
        assert!(
            unit.contains("ExecStopPost=+/usr/local/bin/albus cleanup"),
            "cleanup must run privileged (+ prefix)"
        );
        assert!(
            unit.contains("ExecStart=/usr/local/bin/albus run"),
            "daemon entrypoint must render"
        );
        assert!(unit.contains("User=albus"), "rootless user must render");
        assert!(
            unit.contains("AmbientCapabilities=CAP_NET_ADMIN"),
            "capability set must render"
        );
        assert!(
            unit.contains("LimitMEMLOCK=infinity"),
            "memlock limit must render (else maps fail as non-root)"
        );
        assert!(!unit.contains("{exec_"), "no unsubstituted placeholders");
    }

    #[test]
    fn test_validate_exec_path_rejects_injection() {
        for bad in [
            "/tmp/my albus",
            "/tmp/x;reboot",
            "/tmp/$(id)",
            "/tmp/`id`",
            "/tmp/a|b",
            "/tmp/a&b",
            "/tmp/a>b",
            "/tmp/a#b",
            "/tmp/x\\y",
            "/tmp/../bin/albus",
            "relative/path",
            "",
        ] {
            assert!(validate_exec_path(bad).is_err(), "must reject {:?}", bad);
        }
    }
}

#[cfg(test)]
mod service_fs_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "albus_svc_{}_{}_{}",
            tag,
            std::process::id(),
            nanos
        ));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_secure_remove_regular_file() {
        let dir = tmpdir("reg");
        let f = dir.join("unit");
        fs::write(&f, "x").unwrap();
        assert!(secure_remove_file(f.to_str().unwrap()).unwrap());
        assert!(!f.exists());
        // second call: idempotent NotFound -> false
        assert!(!secure_remove_file(f.to_str().unwrap()).unwrap());
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_secure_remove_refuses_symlink() {
        let dir = tmpdir("link");
        let target = dir.join("target");
        let link = dir.join("link");
        fs::write(&target, "precious").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(unix)]
        {
            assert!(secure_remove_file(link.to_str().unwrap()).is_err());
            assert_eq!(fs::read_to_string(&target).unwrap(), "precious");
        }
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_persist_install_config_applies_args() {
        // L5 regression: `service install --mss 100` must persist tuning
        // (previously dropped). Uses a temp path — never the live config.
        use clap::Parser;
        let args = match crate::app::cli::Cli::try_parse_from([
            "albus",
            "service",
            "install",
            "--mss",
            "100",
            "--doh-upstream",
            "cloudflare",
        ])
        .unwrap()
        .command
        {
            Some(crate::app::cli::Commands::Service(svc)) => match svc.command {
                crate::app::cli::ServiceCommands::Install(a) => a,
                _ => panic!("expected install subcommand"),
            },
            _ => panic!("expected service command"),
        };
        let dir = tmpdir("persist");
        let path = dir.join("config.json");
        persist_install_config_at(&args, &path).expect("persist must succeed");
        let loaded = crate::app::config::Config::load_from_file(&path).expect("reload must work");
        assert_eq!(loaded.mss, 100);
        assert_eq!(loaded.doh_upstream, "cloudflare");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_service_mgmt_requires_root() {
        // install/uninstall touch system state: unprivileged callers must
        // be refused before anything happens. Skipped as root (that path
        // belongs to the manual root lab, never unit CI).
        if is_root() {
            return;
        }
        use clap::Parser;
        let args = match crate::app::cli::Cli::try_parse_from(["albus", "service", "install"])
            .unwrap()
            .command
        {
            Some(crate::app::cli::Commands::Service(svc)) => match svc.command {
                crate::app::cli::ServiceCommands::Install(a) => a,
                _ => panic!("expected install subcommand"),
            },
            _ => panic!("expected service command"),
        };
        assert!(install_service(&args).is_err());
        assert!(uninstall_service().is_err());
    }

    #[test]
    fn test_polkit_rule_covers_service_user_resolve1() {
        // the rootless daemon's SetLinkDNS calls die with "requires
        // interactive authentication" without this (seen live): assert the
        // exact action IDs + account + YES verdict are present, and that the
        // unit-management gate is unchanged.
        for action in [
            "org.freedesktop.resolve1.set-dns-servers",
            "org.freedesktop.resolve1.set-domains",
            "org.freedesktop.resolve1.set-default-route",
            "org.freedesktop.resolve1.revert",
            "org.freedesktop.resolve1.flush-caches",
        ] {
            assert!(
                POLKIT_RULE_CONTENT.contains(action),
                "rule must authorize {}",
                action
            );
        }
        assert!(POLKIT_RULE_CONTENT.contains("subject.user == \"albus\""));
        assert!(POLKIT_RULE_CONTENT.contains("polkit.Result.YES"));
        assert!(POLKIT_RULE_CONTENT.contains("org.freedesktop.systemd1.manage-units"));
        assert!(POLKIT_RULE_CONTENT.contains("polkit.Result.AUTH_ADMIN"));
    }

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
        assert!(unit.contains("ReadWritePaths=/run /etc/resolv.conf /etc/albus\n"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_ADMIN"));
        assert!(unit.contains("ExecStart=/usr/local/bin/albus run\n"));
        // management stays root-gated in code (unit has no User= bypass)
        assert!(!unit.contains("User=root"));
    }
}
