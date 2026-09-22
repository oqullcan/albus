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

// generates systemd unit file with AmbientCapabilities, installs polkit rule, and enables auto-start
fn install_service(_args: &RunArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service install requires root privileges — run with sudo".into());
    }

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

    let exec_start = format!("{} run", exe_str);
    let exec_stop = format!("{} cleanup", exe_str);

    // format systemd service specification (least-privilege capabilities + hardening)
    let unit_content = format!(
        r#"[Unit]
Description=albus — High-Performance eBPF DPI Bypass & DoH DNS Service
Documentation=https://github.com/oqullcan/albus
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
ExecReload=/bin/kill -s HUP $MAINPID
ExecStopPost={exec_stop}
Restart=always
RestartSec=3
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/run /etc/resolv.conf

[Install]
WantedBy=multi-user.target
"#,
    );

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

    // FP-03: mirror Cleanup — revert all four families unconditionally so no
    // fail-closed rules outlive the daemon regardless of stop outcome.
    crate::core::firewall::unblock_quic();
    crate::core::firewall::unblock_stun();
    crate::core::firewall::disable_kill_switch();
    crate::core::firewall::disable_network_lockdown();
    let _ = crate::dns::cleanup_system_dns();
    println!("albus service uninstalled and system settings cleaned up.");
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
    let _ = Command::new(SYSTEMCTL_BIN)
        .args(["status", "albus.service"])
        .status()?;
    Ok(())
}

fn show_service_logs() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = Command::new(JOURNALCTL_BIN)
        .args(["-u", "albus.service", "-f", "-n", "50"])
        .status()?;
    Ok(())
}
