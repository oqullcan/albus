use std::{io, path::Path};

#[cfg(unix)]
use std::fs;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(windows)]
use std::{process::Command, sync::OnceLock};

/// Applies owner-focused privacy permissions to a directory.
///
/// On Unix this sets mode `0700`. On Windows this replaces inherited ACLs with
/// explicit full-control entries for the current user, `SYSTEM`, and local
/// administrators.
///
/// # Errors
///
/// Returns [`io::Error`] when the platform-specific permission hardening step
/// fails.
pub fn harden_private_directory(path: &Path) -> io::Result<()> {
    set_private_permissions(path, true)
}

/// Applies owner-focused privacy permissions to a file.
///
/// On Unix this sets mode `0600`. On Windows this replaces inherited ACLs with
/// explicit full-control entries for the current user, `SYSTEM`, and local
/// administrators.
///
/// # Errors
///
/// Returns [`io::Error`] when the platform-specific permission hardening step
/// fails.
pub fn harden_private_file(path: &Path) -> io::Result<()> {
    set_private_permissions(path, false)
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, directory: bool) -> io::Result<()> {
    let mode = if directory { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(windows)]
fn set_private_permissions(path: &Path, directory: bool) -> io::Result<()> {
    let current_user_sid = current_user_sid()?;
    let mut grants = Vec::with_capacity(3);
    if directory {
        grants.push(format!("*{current_user_sid}:(OI)(CI)(F)"));
        grants.push("*S-1-5-18:(OI)(CI)(F)".to_owned());
        grants.push("*S-1-5-32-544:(OI)(CI)(F)".to_owned());
    } else {
        grants.push(format!("*{current_user_sid}:(F)"));
        grants.push("*S-1-5-18:(F)".to_owned());
        grants.push("*S-1-5-32-544:(F)".to_owned());
    }

    run_icacls(path, &grants)
}

#[cfg(not(any(unix, windows)))]
fn set_private_permissions(_path: &Path, _directory: bool) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn run_icacls(path: &Path, grants: &[String]) -> io::Result<()> {
    let output = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .args(grants)
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    if detail.to_ascii_lowercase().contains("access is denied") {
        // Windows may refuse ACL replacement on some temp/profile paths even
        // for caller-owned files. Privacy hardening is best-effort, so do not
        // fail the primary vault or config operation in this case.
        return Ok(());
    }
    Err(io::Error::other(format!(
        "icacls failed while hardening {}: {detail}",
        path.display()
    )))
}

#[cfg(windows)]
fn current_user_sid() -> io::Result<String> {
    static CURRENT_USER_SID: OnceLock<Result<String, String>> = OnceLock::new();

    match CURRENT_USER_SID
        .get_or_init(|| current_user_sid_uncached().map_err(|error| error.to_string()))
    {
        Ok(sid) => Ok(sid.clone()),
        Err(message) => Err(io::Error::other(message.clone())),
    }
}

#[cfg(windows)]
fn current_user_sid_uncached() -> io::Result<String> {
    let output = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        return Err(io::Error::other(format!(
            "whoami /user failed while resolving the current SID: {detail}"
        )));
    }

    let output = String::from_utf8_lossy(&output.stdout);
    parse_whoami_user_csv(&output).ok_or_else(|| {
        io::Error::other("could not parse the current user SID from whoami /user output")
    })
}

#[cfg(windows)]
fn parse_whoami_user_csv(output: &str) -> Option<String> {
    let line = output.lines().find(|line| !line.trim().is_empty())?.trim();
    let mut parts = line.split("\",\"");
    let _account_name = parts.next()?.trim_start_matches('"');
    let sid = parts.next()?.trim_end_matches('"');
    if parts.next().is_some() || sid.is_empty() || !sid.starts_with("S-1-") {
        return None;
    }

    Some(sid.to_owned())
}

#[cfg(all(test, windows))]
mod tests {
    use super::parse_whoami_user_csv;

    #[test]
    fn parses_whoami_user_csv_output() {
        let output = "\"DESKTOP\\\\eva\",\"S-1-5-21-1000-2000-3000-1001\"\r\n";
        assert_eq!(
            parse_whoami_user_csv(output),
            Some("S-1-5-21-1000-2000-3000-1001".to_owned())
        );
    }
}
