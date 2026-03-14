#![allow(missing_docs)]

use std::process::Command;

#[test]
fn version_flag_prints_the_package_version() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_albus"))
        .arg("--version")
        .output()?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("albus {}", env!("CARGO_PKG_VERSION"))
    );
    assert!(String::from_utf8_lossy(&output.stderr).trim().is_empty());
    Ok(())
}

#[test]
fn help_flag_prints_usage() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_albus"))
        .arg("--help")
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("albus --version"));
    Ok(())
}

#[test]
fn unknown_flag_returns_usage_error() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_albus"))
        .arg("--definitely-not-a-real-flag")
        .output()?;

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unrecognized argument"));
    assert!(stderr.contains("Usage:"));
    Ok(())
}
