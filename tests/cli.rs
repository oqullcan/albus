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
