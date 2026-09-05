//! terminal telemetry monitor for real-time packet flow inspection.

use std::io::{stdout, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;

// renders formatted terminal header representation of telemetry state
pub fn render_monitor_header(
    is_active: bool,
    dns_active: bool,
    snap: Option<&crate::dns::DnsStatsSnapshot>,
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    out.push_str("\x1b[1malbus monitor\x1b[0m \x1b[2m— realtime transport desynchronization & doh telemetry\x1b[0m\n\n");

    if is_active || dns_active {
        out.push_str("  \x1b[1mstatus\x1b[0m    \x1b[32m● active\x1b[0m \x1b[2m(ebpf sock_ops attached)\x1b[0m\n");
    } else {
        out.push_str("  \x1b[1mstatus\x1b[0m    \x1b[33m○ standby\x1b[0m \x1b[2m(run 'sudo albus run' or 'sudo albus service start')\x1b[0m\n");
    }

    out.push_str("  \x1b[1mresolver\x1b[0m  127.0.0.1:53 \x1b[2m(multi-doh wp2 • pqc ml-kem-768 • dnssec • edns padding • ecs-zero • dns64)\x1b[0m\n");
    out.push_str("  \x1b[1msecurity\x1b[0m  hagezi pro+tif \x1b[2m(arena radix) • cname uncloaking • allowlist • bogon drop • netmon\x1b[0m\n");
    out.push_str("  \x1b[1mevasion\x1b[0m   mss 88b \x1b[2m(restore 600b) • auto-ttl • fake sni • quic drop\x1b[0m\n");
    out.push_str(
        "  \x1b[1mstorage\x1b[0m   volatile tmpfs \x1b[2m(/run — zero-disk footprint)\x1b[0m\n",
    );

    if let Some(snap) = snap {
        let _ = writeln!(
            out,
            "  \x1b[1mqueries\x1b[0m   {} total • {} cached ({:.1}%) • {} blocked (HaGeZi) • {} CNAME uncloaked",
            snap.total_queries, snap.cache_hits, snap.cache_hit_ratio, snap.blocked_domains, snap.uncloaked_cnames
        );
        if snap.rebinding_drops > 0 || snap.network_changes > 0 || snap.dns64_synthesized > 0 {
            let _ = writeln!(
                out,
                "  \x1b[1mdefense\x1b[0m   {} rebinding drops • {} network transitions • {} DNS64 synthesized",
                snap.rebinding_drops, snap.network_changes, snap.dns64_synthesized
            );
        }
    }

    out.push_str("\n\x1b[2m──────────────────────────────────────────────────────────────────────────\x1b[0m\n");
    out
}

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

    let snap_opt: Option<crate::dns::DnsStatsSnapshot> =
        std::fs::read_to_string("/run/albus/stats.json")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());

    let header = render_monitor_header(is_active, dns_active, snap_opt.as_ref());
    print!("{}", header);
    stdout.flush()?;

    // stream journalctl log entries
    if is_active {
        let mut child = Command::new("journalctl")
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
        println!("\x1b[2mwaiting for engine events... (ctrl+c to exit)\x1b[0m");
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsStatsSnapshot;

    #[test]
    fn test_render_monitor_header_active() {
        let header = render_monitor_header(true, false, None);
        assert!(header.contains("● active"));
        assert!(header.contains("ebpf sock_ops attached"));
        assert!(header.contains("albus monitor"));
        assert!(header.contains("127.0.0.1:53"));
    }

    #[test]
    fn test_render_monitor_header_standby() {
        let header = render_monitor_header(false, false, None);
        assert!(header.contains("○ standby"));
        assert!(header.contains("run 'sudo albus run'"));
    }

    #[test]
    fn test_render_monitor_header_with_stats() {
        let snap = DnsStatsSnapshot {
            total_queries: 100,
            cache_hits: 45,
            cache_hit_ratio: 45.0,
            blocked_domains: 12,
            uncloaked_cnames: 3,
            rebinding_drops: 2,
            network_changes: 1,
            dns64_synthesized: 5,
            ..Default::default()
        };

        let header = render_monitor_header(false, true, Some(&snap));
        assert!(header.contains("● active")); // dns_active is true
        assert!(header.contains("100 total"));
        assert!(header.contains("45 cached (45.0%)"));
        assert!(header.contains("12 blocked"));
        assert!(header.contains("3 CNAME uncloaked"));
        assert!(header.contains("2 rebinding drops"));
        assert!(header.contains("1 network transitions"));
        assert!(header.contains("5 DNS64 synthesized"));
    }
}
