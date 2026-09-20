//! README/CLI-default sync: Config::default() values must match the
//! "Default" column of the flag table in README.md. Fails loudly on drift.

use albus::app::config::Config;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn readme() -> String {
    std::fs::read_to_string(repo_root().join("README.md")).expect("README.md must exist")
}

/// (flag, type, default-as-shown-in-readme)
fn expected_rows(cfg: &Config) -> Vec<(&'static str, &'static str, String)> {
    vec![
        ("--mss", "u16", cfg.mss.to_string()),
        ("--min-mss", "u16", cfg.min_mss.to_string()),
        (
            "--restore-after-bytes",
            "u32",
            cfg.restore_after_bytes.to_string(),
        ),
        (
            "--ports",
            "Vec<u16>",
            format!(
                "[{}]",
                cfg.ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        ("--fake-ttl", "u8", cfg.fake_ttl.to_string()),
        ("--auto-ttl", "bool", cfg.auto_ttl.to_string()),
        (
            "--fake-sni",
            "String",
            cfg.fake_sni.clone().unwrap_or_else(|| "None".to_string()),
        ),
        (
            "--fake-bad-checksum",
            "bool",
            cfg.fake_bad_checksum.to_string(),
        ),
        ("--doh", "bool", cfg.doh_enabled.to_string()),
        (
            "--doh-upstream",
            "String",
            format!("\"{}\"", cfg.doh_upstream),
        ),
        (
            "--doh-bootstrap-ips",
            "Vec<IPv4>",
            if cfg.doh_bootstrap_ips.is_empty() {
                "[]".to_string()
            } else {
                format!("{:?}", cfg.doh_bootstrap_ips)
            },
        ),
        ("--dnssec", "bool", cfg.dnssec.to_string()),
        ("--pqc", "bool", cfg.pqc.to_string()),
        ("--ram-only", "bool", cfg.ram_only.to_string()),
        ("--block-quic", "bool", cfg.block_quic.to_string()),
        ("--block-stun", "bool", cfg.block_stun.to_string()),
        ("--kill-switch", "bool", cfg.kill_switch.to_string()),
        (
            "--network-lockdown",
            "bool",
            cfg.network_lockdown.to_string(),
        ),
        ("--block-ipv6", "bool", cfg.block_ipv6.to_string()),
    ]
}

#[test]
fn readme_flag_table_matches_config_defaults() {
    let cfg = Config::default();
    let doc = readme();
    let mut missing = Vec::new();
    for (flag, ty, default) in expected_rows(&cfg) {
        let row = format!("| `{}` | `{}` | `{}` |", flag, ty, default);
        if !doc.contains(&row) {
            missing.push(row);
        }
    }
    assert!(
        missing.is_empty(),
        "README flag table drifted from Config::default():\n{}",
        missing.join("\n")
    );
}

#[test]
fn readme_has_no_broken_local_links() {
    let doc = readme();
    let root = repo_root();
    let mut broken = Vec::new();
    for line in doc.lines() {
        // markdown links/images pointing at repo files
        for cap in line.split("](").skip(1) {
            if let Some(end) = cap.find(')') {
                let target = cap[..end].split('#').next().unwrap_or("");
                if target.starts_with("http") || target.is_empty() {
                    continue;
                }
                if !root.join(target).exists() {
                    broken.push(target.to_string());
                }
            }
        }
    }
    assert!(broken.is_empty(), "broken local links: {:?}", broken);
}
