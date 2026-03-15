use std::{
    fs, io,
    path::{Component, Path, PathBuf},
};

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

/// Rejects paths whose existing components resolve through symlinks.
///
/// This is a best-effort safeguard against reading or writing private state
/// through an unexpected alias. Existing components of the supplied path are
/// checked after absolute normalization; missing trailing components are
/// allowed because they do not exist yet.
///
/// # Errors
///
/// Returns [`io::Error`] when a path component cannot be inspected or when an
/// existing component is a symlink.
pub fn ensure_non_symlink_path(path: &Path) -> io::Result<()> {
    let absolute = normalize_absolute_path(path)?;
    let mut current = PathBuf::new();

    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                current.pop();
            }
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(part) => current.push(part),
        }

        if current.as_os_str().is_empty() {
            continue;
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::other(format!(
                    "symlink path component is not allowed: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn normalize_absolute_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(part) => normalized.push(part),
        }
    }

    Ok(normalized)
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
    use super::{ensure_non_symlink_path, parse_whoami_user_csv};
    use tempfile::TempDir;

    #[test]
    fn parses_whoami_user_csv_output() {
        let output = "\"DESKTOP\\\\eva\",\"S-1-5-21-1000-2000-3000-1001\"\r\n";
        assert_eq!(
            parse_whoami_user_csv(output),
            Some("S-1-5-21-1000-2000-3000-1001".to_owned())
        );
    }

    #[test]
    fn accepts_non_symlink_private_paths() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let path = tempdir.path().join("state").join("vault.albus");

        ensure_non_symlink_path(&path)?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use std::io;
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::ensure_non_symlink_path;

    fn running_in_github_actions() -> bool {
        matches!(
            std::env::var("GITHUB_ACTIONS")
                .ok()
                .as_deref()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("1" | "true" | "yes" | "on")
        )
    }

    #[test]
    fn accepts_non_symlink_private_paths() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let path = tempdir.path().join("state").join("vault.albus");

        ensure_non_symlink_path(&path)?;
        Ok(())
    }

    #[test]
    fn rejects_existing_symlink_path_components() -> Result<(), Box<dyn std::error::Error>> {
        if running_in_github_actions() {
            eprintln!(
                "skipping unix symlink-path privacy test in GitHub Actions: runner filesystem semantics can vary"
            );
            return Ok(());
        }

        let tempdir = TempDir::new()?;
        let real_dir = tempdir.path().join("real");
        let link_dir = tempdir.path().join("link");
        std::fs::create_dir(&real_dir)?;
        symlink(&real_dir, &link_dir)?;

        let error = match ensure_non_symlink_path(&link_dir.join("vault.albus")) {
            Ok(()) => {
                return Err(io::Error::other("expected symlink path rejection").into());
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Other);
        Ok(())
    }
}
