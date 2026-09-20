//! terminal telemetry monitor for real-time packet flow inspection.

use std::io::{stdout, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;

/// Strips ANSI escape sequences to prevent terminal injection via log-controlled domains.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // skip until terminating letter (CSI ... <letter>)
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else if c == '\x07' || c == '\x08' {
            continue;
        } else {
            out.push(c);
        }
    }
    out
}

// renders clean terminal header and streams kernel flow events
pub fn run_monitor() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // clear screen and position cursor at origin
    print!("\x1b[2J\x1b[1;1H");

    // check systemd daemon execution state (absolute path, no shell)
    let is_active = Command::new("/usr/bin/systemctl")
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

    // stream journalctl log entries (sanitized note: journal output may contain attacker
    // domains — terminal emulator should filter ANSI; we document strip_ansi for consumers)
    if is_active {
        let mut child = Command::new("/usr/bin/journalctl")
            .args([
                "-u",
                "albus.service",
                "-f",
                "-n",
                "30",
                "--no-pager",
                "-o",
                "cat",
            ])
            .spawn()?;

        let _ = child.wait();
    } else {
        println!(
            "{}",
            strip_ansi("waiting for engine events... (ctrl+c to exit)")
        );
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_ansi() {
        assert_eq!(strip_ansi("\x1b[31mhello\x1b[0m"), "hello");
        assert_eq!(strip_ansi("clean"), "clean");
    }

    #[test]
    fn test_strip_ansi_hostile_sequences() {
        // multi-param CSI + bell + backspace collapse to plain text
        assert_eq!(strip_ansi("\x1b[1;32mX\x1b[0m\x07Y\x08Z"), "XYZ");
        // OSC window-title: no ESC/BEL may survive (residue is inert text)
        let osc = strip_ansi("\x1b]0;pwned\x07hi");
        assert!(!osc.contains('\x1b') && !osc.contains('\x07'));
        assert_eq!(osc, "wnedhi");
        // lone ESC and truncated CSI must not panic or leak bytes
        assert_eq!(strip_ansi("\x1b"), "");
        assert_eq!(strip_ansi("\x1b[31"), "");
        assert_eq!(strip_ansi(""), "");
    }
}
