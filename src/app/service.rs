//! systemd service unit generator, process supervision, and journal telemetry streaming.

use std::fs;
use std::path::Path;
use std::process::Command;
use crate::app::cli::{RunArgs, ServiceCommands};
use crate::core::ebpf::is_root;

const SERVICE_FILE_PATH: &str = "/etc/systemd/system/albus.service";
const SYSTEM_BIN_PATH: &str = "/usr/local/bin/albus";
const POLKIT_RULE_PATH: &str = "/etc/polkit-1/rules.d/albus.rules";

const POLKIT_RULE_CONTENT: &str = r#"polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units") {
        var unit = action.lookup("unit");
        if (unit == "albus.service") {
            return polkit.Result.YES;
        }
    }
});
"#;

// dispatches systemd lifecycle actions
pub fn handle_service_command(cmd: ServiceCommands) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

// generates systemd unit file with AmbientCapabilities, installs polkit rule, and enables auto-start
fn install_service(_args: &RunArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service install requires root privileges — run with sudo".into());
    }

    // copy binary to standard system execution path
    let exe_path = std::env::current_exe()?;
    let _ = fs::copy(&exe_path, SYSTEM_BIN_PATH);

    let exe_str = if Path::new(SYSTEM_BIN_PATH).exists() {
        SYSTEM_BIN_PATH
    } else {
        exe_path.to_str().unwrap_or(SYSTEM_BIN_PATH)
    };

    let exec_start = format!("{} run", exe_str);
    let exec_stop = format!("{} cleanup", exe_str);

    // format systemd service specification
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
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_SYS_ADMIN CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_SYS_ADMIN CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE

[Install]
WantedBy=multi-user.target
"#,
    );

    fs::write(SERVICE_FILE_PATH, unit_content)?;
    println!("Created systemd service unit: {}", SERVICE_FILE_PATH);

    // install passwordless polkit authorization rule for desktop widget management
    if let Some(parent) = Path::new(POLKIT_RULE_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(e) = fs::write(POLKIT_RULE_PATH, POLKIT_RULE_CONTENT) {
        println!("Warning: Could not write polkit rule: {}", e);
    } else {
        println!("Created polkit authorization rule: {}", POLKIT_RULE_PATH);
    }

    // reload daemon manager and enable unit
    let _ = Command::new("systemctl").arg("daemon-reload").status()?;
    let _ = Command::new("systemctl").args(["enable", "--now", "albus.service"]).status()?;

    println!("albus binary copied to /usr/local/bin/albus");
    println!("albus service installed, enabled, and started successfully!");
    println!("Check live status with: sudo albus service status");
    println!("View live logs with:   sudo albus service logs");

    Ok(())
}

// uninstalls service unit and restores network state
fn uninstall_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service uninstall requires root privileges — run with sudo".into());
    }

    if Path::new(SERVICE_FILE_PATH).exists() {
        println!("Stopping and disabling albus.service...");
        let _ = Command::new("systemctl").args(["stop", "albus.service"]).status();
        let _ = Command::new("systemctl").args(["disable", "albus.service"]).status();
        let _ = fs::remove_file(SERVICE_FILE_PATH);
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        println!("Removed {}", SERVICE_FILE_PATH);
    } else {
        println!("No albus.service file found at {}", SERVICE_FILE_PATH);
    }

    if Path::new(POLKIT_RULE_PATH).exists() {
        let _ = fs::remove_file(POLKIT_RULE_PATH);
        println!("Removed {}", POLKIT_RULE_PATH);
    }

    crate::core::firewall::unblock_quic();
    let _ = crate::dns::cleanup_system_dns();
    println!("albus service uninstalled and system settings cleaned up.");
    Ok(())
}

fn start_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_root() {
        return Err("albus service start requires root privileges — run with sudo".into());
    }
    let status = Command::new("systemctl").args(["start", "albus.service"]).status()?;
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
    let status = Command::new("systemctl").args(["stop", "albus.service"]).status()?;
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
    let status = Command::new("systemctl").args(["restart", "albus.service"]).status()?;
    if status.success() {
        println!("albus.service restarted.");
    } else {
        eprintln!("Failed to restart albus.service");
    }
    Ok(())
}

fn reload_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let status = Command::new("systemctl").args(["kill", "-s", "HUP", "albus.service"]).status()?;
    if status.success() {
        println!("albus.service configuration reloaded live via SIGHUP.");
    } else {
        eprintln!("Failed to reload albus.service — verify daemon is actively running");
    }
    Ok(())
}

fn show_service_status() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = Command::new("systemctl").args(["status", "albus.service"]).status()?;
    Ok(())
}

fn show_service_logs() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = Command::new("journalctl").args(["-u", "albus.service", "-f", "-n", "50"]).status()?;
    Ok(())
}
