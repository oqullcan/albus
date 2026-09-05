//! terminal telemetry monitor for real-time packet flow inspection.

use std::io::{stdout, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;

// calculates live service uptime using systemd monotonic enter timestamp and /proc/uptime
fn get_service_uptime() -> Option<String> {
    let output = Command::new("systemctl")
        .args([
            "show",
            "albus.service",
            "--property=ActiveEnterTimestampMonotonic",
            "--value",
        ])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    let mono_us: u64 = text.trim().parse().ok()?;
    if mono_us == 0 {
        return None;
    }

    let uptime_content = std::fs::read_to_string("/proc/uptime").ok()?;
    let sys_uptime_secs: f64 = uptime_content.split_whitespace().next()?.parse().ok()?;
    let service_enter_secs = mono_us as f64 / 1_000_000.0;
    let diff_secs = (sys_uptime_secs - service_enter_secs).max(0.0) as u64;

    let d = diff_secs / 86400;
    let h = (diff_secs % 86400) / 3600;
    let m = (diff_secs % 3600) / 60;
    let s = diff_secs % 60;

    if d > 0 {
        Some(format!("{}d {}h", d, h))
    } else if h > 0 {
        Some(format!("{}h {}m", h, m))
    } else if m > 0 {
        Some(format!("{}m {}s", m, s))
    } else {
        Some(format!("{}s", s))
    }
}

// formats upstream resolver url or preset to a clean human-readable representation
fn format_upstream_display(upstream: &str) -> String {
    if upstream.starts_with("https://") {
        if let Ok(url) = url::Url::parse(upstream) {
            if let Some(host) = url.host_str() {
                if host.contains("nextdns.io") {
                    let path = url.path().trim_start_matches('/');
                    if !path.is_empty() {
                        format!("NextDNS ({})", path)
                    } else {
                        "NextDNS".to_string()
                    }
                } else if host.contains("cloudflare") {
                    "Cloudflare (DoH)".to_string()
                } else if host.contains("quad9") {
                    "Quad9 (DoH)".to_string()
                } else if host.contains("mullvad") {
                    "Mullvad (DoH)".to_string()
                } else {
                    host.to_string()
                }
            } else {
                upstream.to_string()
            }
        } else {
            upstream.to_string()
        }
    } else if upstream.starts_with("sdns://") {
        "DNS Stamp".to_string()
    } else {
        match upstream {
            "quad9" => "Quad9".to_string(),
            "cloudflare" => "Cloudflare".to_string(),
            "mullvad" => "Mullvad".to_string(),
            u if u.starts_with("mullvad-") => {
                let profile = u.trim_start_matches("mullvad-");
                format!("Mullvad ({})", profile)
            }
            other => other.to_string(),
        }
    }
}

// renders formatted terminal header representation of telemetry state
pub fn render_monitor_header(
    is_active: bool,
    dns_active: bool,
    snap: Option<&crate::dns::DnsStatsSnapshot>,
) -> String {
    let cfg = crate::app::config::Config::load_or_default();
    render_monitor_header_with_cfg(is_active, dns_active, snap, &cfg)
}

// renders terminal header with explicitly provided runtime configuration
pub fn render_monitor_header_with_cfg(
    is_active: bool,
    dns_active: bool,
    snap: Option<&crate::dns::DnsStatsSnapshot>,
    cfg: &crate::app::config::Config,
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    out.push_str("\x1b[1malbus monitor\x1b[0m \x1b[2m— realtime transport desynchronization & doh telemetry\x1b[0m\n\n");

    if is_active || dns_active {
        let uptime_suffix = if is_active {
            if let Some(up) = get_service_uptime() {
                format!(" • uptime {}", up)
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        out.push_str(&format!(
            "  \x1b[1mstatus\x1b[0m    \x1b[32m● active\x1b[0m \x1b[2m(ebpf sock_ops attached{})\x1b[0m\n",
            uptime_suffix
        ));
    } else {
        out.push_str("  \x1b[1mstatus\x1b[0m    \x1b[33m○ standby\x1b[0m \x1b[2m(run 'sudo albus run' or 'sudo albus service start')\x1b[0m\n");
    }

    // dynamic resolver details
    let mut res_features = Vec::new();
    if cfg.dns_racing {
        res_features.push("racing");
    }
    if cfg.pqc {
        res_features.push("pqc ml-kem-768");
    }
    if cfg.dnssec {
        res_features.push("dnssec");
    }
    if cfg.edns_padding {
        res_features.push("edns padding");
    }
    if cfg.dns64 {
        res_features.push("dns64");
    }
    if cfg.odoh_enabled {
        res_features.push("odoh");
    }
    if cfg.local_doh {
        res_features.push("local-doh");
    }

    let upstream_display = format_upstream_display(&cfg.doh_upstream);
    let res_detail = if res_features.is_empty() {
        upstream_display
    } else {
        format!("{} • {}", upstream_display, res_features.join(" • "))
    };
    out.push_str(&format!(
        "  \x1b[1mresolver\x1b[0m  127.0.0.1:53 \x1b[2m({})\x1b[0m\n",
        res_detail
    ));

    // dynamic security details
    let mut sec_features = Vec::new();
    if cfg.blocklist {
        if let Some(ref p) = cfg.blocklist_path {
            sec_features.push(format!("custom-blocklist ({})", p));
        } else {
            sec_features.push("hagezi pro+tif (arena radix)".to_string());
        }
    }
    if cfg.uncloak_cnames {
        sec_features.push("cname uncloaking".to_string());
    }
    if !cfg.allow_domains.is_empty() || cfg.allowlist_path.is_some() {
        sec_features.push("allowlist".to_string());
    }
    if cfg.anti_dns_rebinding {
        sec_features.push("anti-rebinding".to_string());
    }
    if cfg.block_bogons {
        sec_features.push("bogon drop".to_string());
    }
    if cfg.kill_switch {
        sec_features.push("kill-switch".to_string());
    }
    if cfg.network_lockdown {
        sec_features.push("lockdown".to_string());
    }
    if cfg.netmon {
        sec_features.push("netmon".to_string());
    }

    let sec_detail = if sec_features.is_empty() {
        "disabled".to_string()
    } else {
        sec_features.join(" • ")
    };
    out.push_str(&format!(
        "  \x1b[1msecurity\x1b[0m  \x1b[2m{}\x1b[0m\n",
        sec_detail
    ));

    // dynamic evasion details
    let mut eva_features = Vec::new();
    if cfg.min_mss != cfg.mss {
        eva_features.push(format!("mss {}b (min {}b)", cfg.mss, cfg.min_mss));
    } else {
        eva_features.push(format!("mss {}b", cfg.mss));
    }
    if cfg.restore_after_bytes > 0 {
        eva_features.push(format!("restore {}b", cfg.restore_after_bytes));
    }
    if cfg.auto_ttl {
        eva_features.push("auto-ttl".to_string());
    } else {
        eva_features.push(format!("fake-ttl {}", cfg.fake_ttl));
    }
    if let Some(ref sni) = cfg.fake_sni {
        if !sni.is_empty() {
            eva_features.push(format!("fake-sni {}", sni));
        }
    }
    if cfg.fake_bad_checksum {
        eva_features.push("0xdead desync".to_string());
    }
    if cfg.block_quic {
        eva_features.push("quic drop".to_string());
    }
    if cfg.block_stun {
        eva_features.push("stun drop".to_string());
    }

    let eva_detail = eva_features.join(" • ");
    out.push_str(&format!(
        "  \x1b[1mevasion\x1b[0m   \x1b[2m{}\x1b[0m\n",
        eva_detail
    ));

    // dynamic storage details
    let storage_desc = if cfg.ram_only {
        "volatile tmpfs \x1b[2m(/run — zero-disk footprint)\x1b[0m"
    } else {
        "persistent \x1b[2m(/etc/albus/config.json)\x1b[0m"
    };
    out.push_str(&format!("  \x1b[1mstorage\x1b[0m   {}\n", storage_desc));

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

    #[test]
    fn test_render_monitor_header_dynamic_config() {
        let mut cfg = crate::app::config::Config::default();
        cfg.doh_upstream = "https://dns.nextdns.io/795926/testdevice".to_string();
        cfg.mss = 64;
        cfg.min_mss = 64;
        cfg.fake_bad_checksum = true;
        cfg.auto_ttl = false;
        cfg.fake_ttl = 4;
        cfg.fake_sni = Some("decoy.com".to_string());
        cfg.blocklist = false;
        cfg.network_lockdown = true;
        cfg.ram_only = true;

        let header = render_monitor_header_with_cfg(true, true, None, &cfg);
        assert!(header.contains("● active"));
        assert!(header.contains("NextDNS (795926/testdevice)"));
        assert!(header.contains("mss 64b"));
        assert!(header.contains("fake-ttl 4"));
        assert!(header.contains("fake-sni decoy.com"));
        assert!(header.contains("0xdead desync"));
        assert!(header.contains("lockdown"));
        assert!(header.contains("volatile tmpfs"));
        assert!(!header.contains("hagezi pro+tif")); // blocklist is false
    }
}
