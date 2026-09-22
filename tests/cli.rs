//! CLI surface smoke tests: help, version, parse rejection, read-only
//! inspection. All unprivileged, no network, no firewall, no daemon.
//! `CARGO_BIN_EXE_albus` is set for integration targets (not for unit
//! tests inside src/main.rs, which is why these live here).

fn bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_albus"))
}

#[test]
fn cli_help_and_version() {
    let help = std::process::Command::new(bin())
        .arg("--help")
        .output()
        .expect("binary runs");
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("albus"), "help names the binary");
    assert!(text.contains("run"), "help lists the run command");
    let ver = std::process::Command::new(bin())
        .arg("--version")
        .output()
        .expect("binary runs");
    assert!(ver.status.success());
    assert!(
        String::from_utf8_lossy(&ver.stdout).contains(env!("CARGO_PKG_VERSION")),
        "version matches package version (no drift)"
    );
}

#[test]
fn cli_rejects_out_of_range_flag() {
    // clap value parsing is the first validation layer: u16 overflow must
    // fail before any engine code runs
    let bad = std::process::Command::new(bin())
        .args(["run", "--mss", "99999"])
        .output()
        .expect("binary runs");
    assert!(
        !bad.status.success(),
        "out-of-range --mss must be rejected at parse"
    );
}

#[test]
fn cli_config_get_prints_json() {
    // read-only inspection path: must succeed unprivileged and emit
    // parseable JSON (config holds no credentials, safe to assert shape)
    let out = std::process::Command::new(bin())
        .args(["config", "get"])
        .output()
        .expect("binary runs");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\"mss\""),
        "config JSON carries tunables: {}",
        &text[..text.len().min(120)]
    );
}

#[test]
fn cli_status_without_privilege() {
    // `albus status` is read-only diagnostics: must exit 0 unprivileged
    // (it degrades to a capability hint instead of probing the kernel)
    let out = std::process::Command::new(bin())
        .arg("status")
        .output()
        .expect("binary runs");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("albus status"), "status header present");
}

#[test]
fn cli_status_json_is_parseable() {
    // panel widgets consume this: must always be valid JSON with the
    // documented shape, even unprivileged (mirrors the unit test in
    // app::status, end-to-end through the real binary)
    let out = std::process::Command::new(bin())
        .args(["status", "--json"])
        .output()
        .expect("binary runs");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(text.trim()).expect("status --json prints JSON");
    assert!(v.get("active").is_some(), "payload carries active flag");
    assert!(v.get("class").is_some(), "payload carries class");
}

#[test]
fn cli_cleanup_refuses_unprivileged() {
    // `albus cleanup` rewrites resolv.conf + iptables: must refuse
    // without root (fail-closed) and touch nothing. Skipped as root —
    // that path belongs to the manual root lab, not unit CI.
    if std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
    {
        return;
    }
    let before = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let out = std::process::Command::new(bin())
        .arg("cleanup")
        .output()
        .expect("binary runs");
    assert!(out.status.success(), "refusal is Ok, not a crash");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("root"),
        "must say why it refused: {}",
        stderr.trim()
    );
    let after = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    assert_eq!(before, after, "refused cleanup must not touch resolv.conf");
}

#[test]
fn cli_service_status_passthrough() {
    // `service status` shells to systemctl (read-only): must terminate
    // promptly with some output, unprivileged. Exit code is systemctl's
    // business (polkit may deny); survival + output is ours.
    let out = std::process::Command::new(bin())
        .args(["service", "status"])
        .output()
        .expect("binary runs");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.trim().is_empty(),
        "systemctl passthrough must produce output, not hang or crash silent"
    );
}
