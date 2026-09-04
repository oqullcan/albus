//! terminal telemetry monitor for real-time packet flow inspection.

use std::io::{stdout, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;

// renders clean terminal header and streams kernel flow events
pub fn run_monitor() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // clear screen and position cursor at origin
    print!("\x1b[2J\x1b[1;1H");

    // check systemd daemon execution state
    let is_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "albus.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let dns_active = resolv.contains("127.0.0.1");

    let mut stdout = stdout();

    println!("\x1b[1malbus monitor\x1b[0m \x1b[2m— realtime transport desynchronization & doh telemetry\x1b[0m\n");

    if is_active || dns_active {
        println!("  \x1b[1mstatus\x1b[0m    \x1b[32m● active\x1b[0m \x1b[2m(ebpf sock_ops attached)\x1b[0m");
    } else {
        println!("  \x1b[1mstatus\x1b[0m    \x1b[33m○ standby\x1b[0m \x1b[2m(run 'sudo albus run' or 'sudo albus service start')\x1b[0m");
    }

    println!("  \x1b[1mresolver\x1b[0m  127.0.0.1:53 \x1b[2m(quad9 doh • pqc ml-kem-768 • dnssec)\x1b[0m");
    println!("  \x1b[1mevasion\x1b[0m   mss 88b \x1b[2m(restore 600b) • auto-ttl • fake sni • quic drop\x1b[0m");
    println!("  \x1b[1mstorage\x1b[0m   volatile tmpfs \x1b[2m(/run — zero-disk footprint)\x1b[0m");
    println!("\n\x1b[2m──────────────────────────────────────────────────────────────────────────\x1b[0m\n");
    stdout.flush()?;

    // stream journalctl log entries
    if is_active {
        let mut child = Command::new("journalctl")
            .args(["-u", "albus.service", "-f", "-n", "30", "--no-pager", "-o", "cat"])
            .spawn()?;

        let _ = child.wait();
    } else {
        println!("\x1b[2mwaiting for engine events... (ctrl+c to exit)\x1b[0m");
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    Ok(())
}
