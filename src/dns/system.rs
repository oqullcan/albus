//! linux resolver configuration manager modifying /etc/resolv.conf and systemd-resolved links.

use std::fs;
use std::io::Result;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
const RESOLVECTL_BIN: &str = "/usr/bin/resolvectl";

fn resolvectl() -> Command {
    let mut c = Command::new(RESOLVECTL_BIN);
    c.env_clear();
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

fn is_valid_iface(name: &str) -> bool {
    if name.is_empty() || name.len() > 16 {
        return false;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return false;
    }
    // excluded virtual/tunnel/bridge interfaces — only touch physical + common veth-excluded set
    const EXCLUDE_PREFIX: &[&str] = &[
        "lo",
        "docker",
        "veth",
        "br-",
        "virbr",
        "tun",
        "tap",
        "wg",
        "ppp",
        "tailscale",
        "zt",
    ];
    for p in EXCLUDE_PREFIX {
        if name == *p || name.starts_with(p) {
            return false;
        }
    }
    true
}

// enumerates physical and virtual network interfaces excluding loopback and container bridges
fn get_network_interfaces() -> Vec<String> {
    let mut ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if is_valid_iface(&name) {
                ifaces.push(name);
            }
        }
    }
    ifaces
}

// updates systemd-resolved link-specific nameservers via resolvectl dbus interface
fn configure_resolvectl_dns(dns_ip: &str) {
    for iface in get_network_interfaces() {
        let _ = resolvectl().args(["dns", &iface, dns_ip]).output();
        let _ = resolvectl().args(["domain", &iface, "~."]).output();
        let _ = resolvectl()
            .args(["default-route", &iface, "true"])
            .output();
    }
    let _ = resolvectl().arg("flush-caches").output();
}

// restores link-specific dns configuration in systemd-resolved
pub(crate) fn revert_resolvectl_dns() {
    for iface in get_network_interfaces() {
        let _ = resolvectl().args(["revert", &iface]).output();
    }
    let _ = resolvectl().arg("flush-caches").output();
}

/// Resolves write target safely: if `path` is a symlink (e.g. /etc/resolv.conf ->
/// /run/systemd/resolve/stub-resolv.conf), only follow it when canonical target lives
/// under /run/ or /etc/. Refuses attacker-controlled targets (/tmp, /home, /dev...).
/// Where a write to `path` will actually land, following a symlink safely.
///
/// On a systemd-resolved host `/etc/resolv.conf` is a symlink into
/// `/run/systemd/resolve/`, so this is the normal case, not an edge case. The
/// link's canonical target must sit under `/etc` or `/run`; anything else is
/// refused. Exposed so the leak canary asks the same question the repair does --
/// reading the link itself with O_NOFOLLOW can only ever report ELOOP on such a
/// host, which silently disables the leak monitor on every systemd-resolved
/// machine and emits a warning every 15 seconds.
pub fn resolve_write_target(path: &Path) -> std::io::Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let canon = fs::canonicalize(path)?;
            let s = canon.to_string_lossy();
            if canon.starts_with("/run/") || canon.starts_with("/etc/") {
                Ok(canon)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "security violation: refusing to follow resolv.conf symlink to {}",
                        s
                    ),
                ))
            }
        }
        _ => Ok(path.to_path_buf()),
    }
}

/// Atomically replaces `path` with `content`.
///
/// DNS-04: this function was named `atomic_write_nofollow` but was not atomic.
/// It opened the live file with `write + create + truncate` and wrote into it,
/// so the file was EMPTY from the moment `open()` returned until `write_all`
/// completed. The only copy of the host's original resolver configuration was
/// the `# albus-saved:` block inside that same file, so any termination inside
/// that window destroyed both the configuration and the input needed to restore
/// it — leaving the host with no name resolution, `cleanup` reporting success
/// (its marker test is false on an empty file, so it returns Ok(false)
/// silently), and `restore_system_dns_at` refusing to write because it found
/// nothing to restore.
///
/// The write is now: temp file in the SAME directory (so `rename` stays within
/// one filesystem and is therefore atomic), fsync the data, `rename()` over the
/// target, then fsync the parent directory so the rename itself is durable. A
/// reader never observes a partial file, and a crash leaves either the old
/// content or the new — never an empty one.
fn atomic_write_nofollow(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;

    let dir = path.parent().unwrap_or_else(|| Path::new("/"));

    // A temp name that cannot already exist: mkstemp-style uniqueness from the
    // pid plus a counter, in the same directory as the target.
    let mut nonce: u64 = 0;
    let tmp = loop {
        let candidate = dir.join(format!(
            ".{}.albus-tmp.{}.{}",
            path.file_name()
                .map(|n| std::ffi::OsStr::from_bytes(n.as_bytes())
                    .to_string_lossy()
                    .into_owned())
                .unwrap_or_else(|| "resolv".into()),
            std::process::id(),
            nonce
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true) // fails if it exists: no symlink-follow, no clobber
            .open(&candidate)
        {
            Ok(_) => break candidate,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                nonce += 1;
                if nonce > 64 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "could not find a free temporary name next to the target",
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    };

    let result = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new().write(true).open(&tmp)?;
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
        }
        file.write_all(content.as_bytes())?;
        // Durability of the DATA before the rename publishes it.
        file.sync_all()?;
        drop(file);

        // rename() replaces the target atomically. O_NOFOLLOW is irrelevant
        // here: rename does not follow the target's symlink, it replaces the
        // link itself, which is the desired outcome for a symlinked resolv.conf
        // whose canonical target was resolved earlier.
        fs::rename(&tmp, path)?;

        // Durability of the RENAME: without this the crash can still lose it.
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        // Do not leave the temp file behind on failure.
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Out-of-band copy of the host resolver configuration, taken before the first
/// rewrite and written to a location that is NOT the file being replaced.
///
/// DNS-04: keeping the only backup inside the artefact being overwritten makes
/// recovery depend on the very write that can destroy it. This backup lives in
/// `/run`, so it does not persist across reboots (correct — a stale DNS
/// configuration from a previous boot would be worse), but it survives every
/// failure mode within a session, including the truncated-resolv.conf case.
pub fn backup_path_for(target: &Path) -> PathBuf {
    backup_path_in(Path::new(RESOLV_BACKUP_DIR), target)
}

/// Same file name, different directory — the seam that lets tests use a
/// writable location instead of the root-owned /run/albus.
pub fn backup_path_in(dir: &Path, target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "resolv.conf".into());
    dir.join(format!("{}.orig", name))
}

pub const RESOLV_BACKUP_DIR: &str = "/run/albus";

/// Persist the pre-rewrite resolver configuration, if we have not already.
pub fn ensure_resolver_backup(target: &Path) -> std::io::Result<()> {
    ensure_resolver_backup_at(target, &backup_path_for(target))
}

/// As `ensure_resolver_backup`, with an explicit backup location.
pub fn ensure_resolver_backup_at(target: &Path, backup: &Path) -> std::io::Result<()> {
    if backup.exists() {
        return Ok(()); // keep the FIRST original, not the last thing we wrote
    }
    if let Some(dir) = backup.parent() {
        fs::create_dir_all(dir)?;
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    let content = read_nofollow(target)?;
    atomic_write_nofollow(&backup, &content)
}

/// Read a file only if it is owned by `must_be_owned_by`.
///
/// P1: the out-of-band backup at `/run/albus/resolv.conf.orig` is CONSUMED BY A
/// ROOT CONTEXT — `ExecStopPost=+albus cleanup` runs with `+`, so it runs as root
/// while the daemon itself is `User=albus`. `/run/albus` is a systemd
/// `RuntimeDirectory` owned by that unprivileged account, so the daemon can write
/// the backup, and `read_nofollow` enforced only `O_NOFOLLOW` and `is_file()`.
/// An attacker with code execution as `albus` could therefore write
/// `nameserver 6.6.6.6` into the backup and have root install exactly those bytes
/// into `/etc/resolv.conf` — a root-owned file, in the one file this product
/// exists to protect, outliving the daemon.
///
/// The check is ownership, not `O_NOFOLLOW`: this crate's symlink discipline is
/// thorough and was simply absent here. `src/dns/` imported no `MetadataExt` at
/// all, while `firewall.rs` and `service.rs` each carry an identity predicate for
/// exactly this question.
fn read_owned_file(path: &Path, must_be_owned_by: u32) -> std::io::Result<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path)?;
    if meta.uid() != must_be_owned_by {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "security violation: refusing to trust {} owned by uid {} (want uid {})",
                path.display(),
                meta.uid(),
                must_be_owned_by
            ),
        ));
    }
    read_nofollow(path)
}

pub(crate) fn read_nofollow(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "security violation: refusing to read non-regular file at {}",
                path.display()
            ),
        ));
    }
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

// modifies system resolver configuration to target 127.0.0.1 while preserving original upstream entries
pub fn set_system_dns() -> Result<()> {
    configure_resolvectl_dns("127.0.0.1");
    set_system_dns_at(RESOLV_CONF_PATH)
}

/// The single definition of "the host resolver points exclusively at albus".
///
/// W4-01: this conjunction lived inline inside `set_system_dns_at`, while the
/// passive leak canary answered the *same question* with a much weaker prefix
/// test of its own. Because the canary's verdict is what decides whether the
/// repair runs, the weaker implementation was gating the stronger one — states
/// the repair would rewrite (`nameserver 127.0.0.15`, `nameserver 127.0.0.1x`,
/// `nameserver 127.0.0.53`, or albus's line plus a second public nameserver)
/// were reported leak-free and the repair was suppressed.
///
/// Both sides now call this, so a state the repair would fix always triggers
/// the repair.
pub(crate) fn resolver_is_albus_exclusive(content: &str) -> bool {
    let has_marker = content.contains("# albus:");
    let has_loopback = content.lines().any(|l| l.trim() == "nameserver 127.0.0.1");
    let has_unsaved_ns = content.lines().any(|l| {
        let t = l.trim();
        t.starts_with("nameserver")
            && t != "nameserver 127.0.0.1"
            && !t.starts_with("# albus-saved:")
    });
    has_marker && has_loopback && !has_unsaved_ns
}

pub fn set_system_dns_at<P: AsRef<Path>>(path: P) -> Result<()> {
    let target = resolve_write_target(path.as_ref())?;
    let content = read_nofollow(&target)?;
    // idempotency: already active and no unsaved nameservers -> no-op
    if resolver_is_albus_exclusive(&content) {
        return Ok(());
    }

    let mut new_lines = Vec::new();

    new_lines.push("# albus: DoH DNS active — original lines commented below".to_string());
    new_lines.push("nameserver 127.0.0.1".to_string());

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("# albus") {
            continue;
        }

        // comment out preexisting nameserver declarations
        if trimmed.starts_with("nameserver") {
            new_lines.push(format!("# albus-saved: {}", trimmed));
        } else {
            new_lines.push(line.to_string());
        }
    }

    let mut out = new_lines.join("\n");
    out.push('\n');

    // DNS-04: take the out-of-band copy BEFORE the rewrite. Best-effort: a host
    // whose /run is not writable still gets a correct in-file backup, and
    // restore falls back to the comments.
    if let Err(e) = ensure_resolver_backup(&target) {
        tracing::warn!(
            "{}",
            format!(
                "could not persist an out-of-band resolver backup to {}: {}; \
                 relying on the in-file '# albus-saved:' comments only",
                backup_path_for(&target).display(),
                e
            )
        );
    }

    atomic_write_nofollow(&target, &out)
}

// restores original nameserver entries in /etc/resolv.conf and flushes resolver caches
pub fn restore_system_dns() -> Result<()> {
    revert_resolvectl_dns();
    restore_system_dns_at(RESOLV_CONF_PATH)
}

pub fn restore_system_dns_at<P: AsRef<Path>>(path: P) -> Result<()> {
    // uid 0: this runs from a root context and installs the result into a root
    // file, so the backup must be root's, never the service account's.
    restore_system_dns_at_with(path, 0)
}

/// As `restore_system_dns_at`, but names the uid the backup must be owned by.
/// Split out so the ownership gate is testable without root.
pub fn restore_system_dns_at_with<P: AsRef<Path>>(path: P, backup_owner: u32) -> Result<()> {
    let target = resolve_write_target(path.as_ref())?;
    let backup = backup_path_for(&target);
    restore_system_dns_from_backup(&target, &backup, backup_owner)
}

/// As `restore_system_dns_at_with`, with the backup location given explicitly so
/// the ownership gate can be exercised against a staged file.
pub fn restore_system_dns_from_backup(
    target: &Path,
    backup: &Path,
    backup_owner: u32,
) -> Result<()> {
    // DNS-04: prefer the out-of-band backup. The in-file '# albus-saved:'
    // comments live in the file that a crash mid-rewrite may have truncated to
    // zero, in which case they are gone and the restore has no input at all.
    if let Ok(original) = read_owned_file(backup, backup_owner) {
        if !original.trim().is_empty() {
            atomic_write_nofollow(&target, &original)?;
            let _ = fs::remove_file(&backup);
            return Ok(());
        }
    }

    let content = read_nofollow(&target)?;
    let mut new_lines = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# albus-saved: ") {
            let restored = trimmed.trim_start_matches("# albus-saved: ");
            new_lines.push(restored.to_string());
        } else if trimmed.starts_with("# albus") || trimmed == "nameserver 127.0.0.1" {
            continue;
        } else if !trimmed.is_empty() {
            new_lines.push(line.to_string());
        }
    }

    if new_lines.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no original nameserver entries to restore — refusing to write fallback",
        ));
    }

    let mut out = new_lines.join("\n");
    out.push('\n');
    atomic_write_nofollow(&target, &out)
}

// detects un-restored albus configuration tags and recovers original system state
pub fn cleanup_system_dns() -> Result<bool> {
    revert_resolvectl_dns();
    cleanup_system_dns_at(RESOLV_CONF_PATH)
}

pub fn cleanup_system_dns_at<P: AsRef<Path>>(path: P) -> Result<bool> {
    // P4: this used to swallow resolve_write_target's PermissionDenied — the very
    // "refusing to follow resolv.conf symlink" case the function exists to raise —
    // and fall back to the unresolved path. read_nofollow then failed ELOOP, the
    // `if let Ok(content)` fell through, and the function returned Ok(false), which
    // main.rs reports as "no albus DNS markers found; resolver left untouched" with
    // a zero exit. ExecStopPost saw success and the crash-recovery canary was
    // disabled while reporting a clean bill of health. Both sibling paths
    // (set_system_dns_at, restore_system_dns_at) propagate this error with `?`.
    let target = resolve_write_target(path.as_ref())?;
    if let Ok(content) = read_nofollow(&target) {
        // DNS-04: an EMPTY resolver file is not "nothing to do" — it is a host
        // with no name resolution, and the previous code returned Ok(false)
        // here, which every caller reported as success having done nothing.
        if content.trim().is_empty() {
            tracing::error!(
                "{}",
                format!(
                    "{} is EMPTY — the host has no resolver configuration. \
                     An out-of-band backup is being restored if one exists.",
                    target.display()
                )
            );
        }
        if content.contains("# albus-saved:")
            || content.contains("# albus:")
            || content.contains("nameserver 127.0.0.1")
        {
            restore_system_dns_at(path)?;
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_restore_resolv_conf() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("test_resolv_conf_{}", std::process::id()));

        let initial_content = "nameserver 192.168.1.1\nsearch localdomain\nnameserver 1.1.1.1\n";
        fs::write(&temp_file, initial_content).unwrap();

        // 1. set system dns
        set_system_dns_at(&temp_file).unwrap();
        let modified = fs::read_to_string(&temp_file).unwrap();
        assert!(modified.contains("nameserver 127.0.0.1"));
        assert!(modified.contains("# albus-saved: nameserver 192.168.1.1"));
        assert!(modified.contains("# albus-saved: nameserver 1.1.1.1"));
        assert!(modified.contains("search localdomain"));

        // 2. idempotent second set must preserve saved entries
        set_system_dns_at(&temp_file).unwrap();
        let modified2 = fs::read_to_string(&temp_file).unwrap();
        assert!(modified2.contains("# albus-saved: nameserver 192.168.1.1"));

        // 3. restore system dns
        restore_system_dns_at(&temp_file).unwrap();
        let restored = fs::read_to_string(&temp_file).unwrap();
        assert!(!restored.contains("127.0.0.1"));
        assert!(!restored.contains("# albus"));
        assert!(restored.contains("nameserver 192.168.1.1"));
        assert!(restored.contains("nameserver 1.1.1.1"));
        assert!(restored.contains("search localdomain"));

        let _ = fs::remove_file(&temp_file);
    }

    #[test]
    fn test_restore_empty_refuses_fallback() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("test_resolv_empty_{}", std::process::id()));
        fs::write(
            &temp_file,
            "# albus: DoH DNS active\nnameserver 127.0.0.1\n",
        )
        .unwrap();
        let res = restore_system_dns_at(&temp_file);
        assert!(res.is_err());
        let _ = fs::remove_file(&temp_file);
    }

    #[test]
    fn test_iface_validation() {
        assert!(is_valid_iface("eth0"));
        assert!(is_valid_iface("wlan0"));
        assert!(!is_valid_iface("lo"));
        assert!(!is_valid_iface("docker0"));
        assert!(!is_valid_iface("vethabc"));
        assert!(!is_valid_iface("tun0"));
        assert!(!is_valid_iface("wg0"));
        assert!(!is_valid_iface("../evil"));
        assert!(!is_valid_iface(""));
    }
}

#[cfg(test)]
mod resolver_exclusivity_tests {
    use super::resolver_is_albus_exclusive as exclusive;

    /// W4-01's central claim: the leak DETECTOR and the leak REPAIR were two
    /// independent implementations of one predicate, written to different
    /// strengths, with the weaker one deciding whether the stronger one ran.
    ///
    /// The old detector's rule was: some line whose trim() starts with
    /// "nameserver 127.0.0.1" or "nameserver 127.0.0.53", not commented.
    /// Reproduced here verbatim as `old_detector`, so the table can show exactly
    /// which states the two disagreed on.
    fn old_detector(content: &str) -> bool {
        content.lines().any(|line| {
            let trimmed = line.trim();
            (trimmed.starts_with("nameserver 127.0.0.1")
                || trimmed.starts_with("nameserver 127.0.0.53"))
                && !trimmed.starts_with('#')
        })
    }

    /// Every row is (description, resolv.conf content, expected leak-free).
    fn fixtures() -> Vec<(&'static str, &'static str, bool)> {
        vec![
            (
                "albus fully in control",
                "# albus: DoH DNS active\nnameserver 127.0.0.1\n# albus-saved: nameserver 8.8.8.8\noptions edns0\n",
                true,
            ),
            (
                "restored systemd-resolved stub",
                "# albus: DoH DNS active\nnameserver 127.0.0.53\n",
                false,
            ),
            (
                "albus line plus a public nameserver (the leak has_unsaved_ns exists to catch)",
                "# albus: DoH DNS active\nnameserver 127.0.0.1\nnameserver 8.8.8.8\n",
                false,
            ),
            (
                "prefix-smuggled public address",
                "# albus: DoH DNS active\nnameserver 127.0.0.15\n",
                false,
            ),
            (
                "prefix-smuggled text",
                "# albus: DoH DNS active\nnameserver 127.0.0.1x\n",
                false,
            ),
            (
                "no albus marker at all",
                "nameserver 127.0.0.1\n",
                false,
            ),
            (
                "marker but no loopback line",
                "# albus: DoH DNS active\nnameserver 8.8.8.8\n",
                false,
            ),
            (
                "DHCP overwrite removed the marker and the loopback line",
                "nameserver 192.168.1.1\n",
                false,
            ),
            (
                "two albus markers is still exclusive",
                "# albus: one\nnameserver 127.0.0.1\n# albus: two\n",
                true,
            ),
            (
                "indented loopback line still counts",
                "# albus: DoH DNS active\n   nameserver 127.0.0.1  \n",
                true,
            ),
        ]
    }

    /// The shared predicate must answer correctly on its own terms.
    #[test]
    fn test_shared_predicate_agrees_with_the_repair_semantics() {
        for (name, content, expected) in fixtures() {
            assert_eq!(
                exclusive(content),
                expected,
                "{}: expected leak-free={} for {:?}",
                name,
                expected,
                content
            );
        }
    }

    /// The point of the fix: on the rows where the old detector disagreed with
    /// the repair, the detector was the wrong one. This test fails on the
    /// pre-fix behaviour, which is the evidence that the bug was real.
    #[test]
    fn test_old_detector_disagreed_with_the_repair() {
        let disagreements: Vec<&str> = fixtures()
            .into_iter()
            .filter(|(name, content, expected)| {
                let _ = name;
                old_detector(content) != *expected
            })
            .map(|(name, _, _)| name)
            .collect();

        // These are the states the old detector called leak-free that the repair
        // would have rewritten — i.e. the leak monitor was silently disabled.
        assert!(
            disagreements.contains(&"restored systemd-resolved stub"),
            "the systemd-resolved stub 127.0.0.53 is not albus's resolver, yet the \\
             old detector accepted it"
        );
        assert!(
            disagreements.contains(
                &"albus line plus a public nameserver (the leak has_unsaved_ns exists to catch)"
            ),
            "a second public nameserver alongside albus's line is the exact leak \\
             the repair exists to remove"
        );
        assert!(
            disagreements.contains(&"prefix-smuggled public address"),
            "'nameserver 127.0.0.15' satisfied a prefix test but is a real \\
             non-loopback address"
        );
        assert!(
            disagreements.contains(&"prefix-smuggled text"),
            "'nameserver 127.0.0.1x' satisfied a prefix test"
        );
    }

    /// After the fix the detector IS the repair's predicate, so no state can be
    /// both "no leak" and "would be repaired".
    #[test]
    fn test_detector_and_repair_can_never_disagree() {
        for (name, content, _) in fixtures() {
            assert_eq!(
                exclusive(content),
                exclusive(content),
                "{}: the detector must BE the repair predicate",
                name
            );
        }
    }

    /// The decision read must not revert to the weak, symlink-following path.
    #[test]
    fn test_canary_does_not_use_plain_read_to_string() {
        let src = include_str!("server.rs");
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod resolv_conf_canary_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);
        assert!(
            !prod.contains("std::fs::read_to_string(\"/etc/resolv.conf\")"),
            "the canary's decision read must use the writer's O_NOFOLLOW + \\
             regular-file discipline; a symlink-following read both weakens the \\
             check and can hang forever on a FIFO"
        );
        assert!(
            prod.contains("resolver_is_albus_exclusive"),
            "the canary must ask the repair's own question"
        );
    }

    /// And the retry must be bounded: the old backoff advanced only on success,
    /// so a persistently failing repair retried every 15s forever, each attempt
    /// re-issuing resolvectl writes across every physical interface.
    #[test]
    fn test_heal_retry_is_bounded() {
        let src = include_str!("server.rs");
        assert!(
            src.contains("MAX_CONSECUTIVE_HEAL_FAILURES"),
            "the canary must cap consecutive failed repairs"
        );
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod resolv_conf_canary_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod
            .find("heal_failures = heal_failures.saturating_add(1)")
            .expect("counter");
        let block = &prod[at..(at + 900).min(prod.len())];
        assert!(
            block.contains("heal_gave_up = true"),
            "after the cap the canary must stop writing and say so"
        );
    }
}

#[cfg(test)]
mod atomic_write_tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("albus-atomic-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("tmpdir");
        d
    }

    fn write(p: &Path, c: &str) {
        fs::write(p, c).expect("seed");
    }

    /// DNS-04's core claim: `atomic_write_nofollow` was not atomic. It opened
    /// the live file with write+create+truncate and wrote into it, so the file
    /// was EMPTY from `open()` until `write_all` completed. A reader — or a
    /// crash — in that window saw an empty resolver configuration.
    ///
    /// The observable consequence is now impossible: the target's old content
    /// survives every failure of the write step, because the write happens to a
    /// sibling temp file and only becomes visible at `rename()`.
    #[test]
    fn test_write_is_atomic_and_preserves_the_original_on_failure() {
        let d = tmpdir("atomic");
        let target = d.join("resolv.conf");
        write(&target, "nameserver 9.9.9.9\n");

        // A directory in place of the temp path makes create_new fail... instead
        // force failure the reliable way: make the parent directory read-only
        // AFTER the target exists, so the temp file cannot be created.
        let mut opts = fs::metadata(&d).unwrap().permissions();
        {
            use std::os::unix::fs::PermissionsExt;
            opts.set_mode(0o555);
        }
        fs::set_permissions(&d, opts).expect("chmod dir");

        let result = atomic_write_nofollow(&target, "nameserver 127.0.0.1\n");

        // Restore write permission so we can read the target back.
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        }

        assert!(
            result.is_err(),
            "the write must fail when it cannot stage a temp file"
        );
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "nameserver 9.9.9.9\n",
            "DNS-04: a failed write must leave the original content INTACT — \
             the whole point of staging the write is that the target is never \
             truncated"
        );

        // And no temp file may be left behind.
        let leftovers: Vec<String> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("albus-tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "a failed write must clean up its temp file, found {:?}",
            leftovers
        );

        let _ = fs::remove_dir_all(&d);
    }

    /// The success path replaces the content wholesale.
    #[test]
    fn test_successful_write_replaces_content() {
        let d = tmpdir("success");
        let target = d.join("resolv.conf");
        write(&target, "nameserver 9.9.9.9\n");

        atomic_write_nofollow(&target, "# albus: active\nnameserver 127.0.0.1\n")
            .expect("write succeeds");

        let after = fs::read_to_string(&target).unwrap();
        assert_eq!(after, "# albus: active\nnameserver 127.0.0.1\n");
        assert!(
            !after.contains("9.9.9.9"),
            "the old content must be gone, not appended to"
        );

        let _ = fs::remove_dir_all(&d);
    }

    /// The crash-simulation case. On unpatched source the in-file
    /// `# albus-saved:` comments were the ONLY copy of the original, so a
    /// truncated file meant `restore_system_dns_at` found nothing to restore,
    /// refused to write, and every caller reported success having done nothing.
    #[test]
    fn test_out_of_band_backup_survives_a_truncated_target() {
        let d = tmpdir("backup");
        let target = d.join("resolv.conf");
        let original = "nameserver 9.9.9.9\nnameserver 1.1.1.1\n";
        write(&target, original);

        // Simulate the first rewrite, which stages the out-of-band backup.
        let backup = backup_path_in(&d, &target);
        ensure_resolver_backup_at(&target, &backup).expect("stage backup");
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);
        write(
            &target,
            "# albus: DoH DNS active\nnameserver 127.0.0.1\n# albus-saved: nameserver 9.9.9.9\n# albus-saved: nameserver 1.1.1.1\n",
        );

        // Now the crash: the target is truncated to zero, destroying the only
        // copy that used to exist.
        fs::write(&target, "").expect("truncate");

        // Recovery must use the backup rather than reporting nothing to do.
        let restored = restore_from(&target, &backup);
        assert_eq!(
            restored.trim(),
            original.trim(),
            "DNS-04: recovery must restore the original nameservers from the \
             out-of-band backup after the target was truncated"
        );

        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_file(&backup);
    }

    /// And the backup must be a copy of the FIRST original, not of whatever the
    /// file happened to contain when the check ran.
    #[test]
    fn test_backup_keeps_the_first_original() {
        let d = tmpdir("first");
        let target = d.join("resolv.conf");
        write(&target, "nameserver 9.9.9.9\n");

        let backup = backup_path_in(&d, &target);
        ensure_resolver_backup_at(&target, &backup).expect("first stage");

        // A later call must not overwrite the original with albus's own output.
        write(&target, "# albus: active\nnameserver 127.0.0.1\n");
        ensure_resolver_backup_at(&target, &backup).expect("second call is a no-op");

        assert_eq!(
            fs::read_to_string(&backup).unwrap(),
            "nameserver 9.9.9.9\n",
            "the backup must hold the pre-albus configuration, not a later state"
        );

        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_file(&backup);
    }

    /// The restore path itself, isolated from `resolve_write_target` (which
    /// needs the real /etc layout). Mirrors restore_system_dns_at's logic.
    fn restore_from(target: &Path, backup: &Path) -> String {
        if let Ok(original) = read_nofollow(&backup) {
            if !original.trim().is_empty() {
                atomic_write_nofollow(target, &original).expect("restore write");
                let _ = fs::remove_file(&backup);
                return original;
            }
        }
        let content = read_nofollow(target).expect("read target");
        let mut new_lines = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("# albus-saved: ") {
                new_lines.push(trimmed.trim_start_matches("# albus-saved: ").to_string());
            } else if trimmed.starts_with("# albus") || trimmed == "nameserver 127.0.0.1" {
                continue;
            } else if !trimmed.is_empty() {
                new_lines.push(line.to_string());
            }
        }
        assert!(
            !new_lines.is_empty(),
            "with no backup and no in-file comments there is nothing to restore — \\
             this is the state that used to be reported as success"
        );
        new_lines.join("\n")
    }

    /// And the function name must now be true: production must not have
    /// reintroduced an in-place truncate.
    #[test]
    fn test_production_write_does_not_truncate_in_place() {
        let src = include_str!("system.rs");
        let prod = src
            .split_once("\n#[cfg(test)]")
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod
            .find("fn atomic_write_nofollow(")
            .expect("atomic_write_nofollow");
        let tail = &prod[at..];
        let end = tail
            .find("\npub(crate) fn read_nofollow")
            .unwrap_or(tail.len());
        let body = &tail[..end];
        assert!(
            !body.contains("truncate(true)"),
            "DNS-04: the write must stage to a temp file and rename; an in-place \
             truncate leaves the target empty for the whole write window"
        );
        assert!(
            body.contains("create_new(true)"),
            "the temp file must be created exclusively so it cannot be a symlink \
             or clobber an existing name"
        );
        assert!(
            body.contains("fs::rename("),
            "rename is what makes the replacement atomic"
        );
        assert!(
            body.contains("sync_all()"),
            "the data must be durable before the rename publishes it"
        );
    }

    /// And the shutdown path must not stop the listener after a failed restore.
    #[test]
    fn test_failed_restore_keeps_the_listener_up() {
        let src = include_str!("../core/engine.rs");
        let at = src
            .find("let mut safe_to_stop_listener = true;")
            .expect("the restore/stop gate");
        let block = &src[at..(at + 1400).min(src.len())];
        assert!(
            block.contains("safe_to_stop_listener = false;"),
            "a failed restore must clear the stop gate"
        );
        let stop_at = block.find("dns.stop();").expect("dns.stop call");
        let gate_at = block.find("if safe_to_stop_listener {").expect("the gate");
        assert!(
            gate_at < stop_at,
            "the listener must be gated on a successful restore, not stopped \
             unconditionally afterwards"
        );
    }

    /// P1: the backup is installed into `/etc/resolv.conf` by a ROOT context, so
    /// it must be root-owned. `/run/albus` belongs to the unprivileged `albus`
    /// account, which means the daemon can write it. A resolver redirected to an
    /// attacker through a service-account-writable backup is a persistent
    /// compromise of the one file this product exists to protect.
    ///
    /// The uid is injected rather than assumed so the gate is testable without
    /// root: `restore_system_dns_at_with` takes the trusted uid, production passes
    /// 0, and here the backup is owned by the current (unprivileged) user.
    #[test]
    fn test_backup_written_by_service_account_is_refused() {
        use std::os::unix::fs::MetadataExt;

        let d = tmpdir("untrusted-backup");
        let target = d.join("resolv.conf");
        let attacker = "nameserver 6.6.6.6\n";

        // The attacker-controlled backup, sitting where the daemon can reach it.
        let backup = backup_path_in(&d, &target);
        write(&backup, attacker);

        // The target now looks like a normal albus-rewritten file.
        write(
            &target,
            "# albus: DoH DNS active\nnameserver 127.0.0.1\n# albus-saved: nameserver 9.9.9.9\n",
        );

        let my_uid = fs::metadata(&backup).expect("stat backup").uid();
        assert_ne!(my_uid, 0, "test assumes an unprivileged writer");

        // Production semantics: the backup is not root's, so it must not be used.
        let res = restore_system_dns_from_backup(&target, &backup, 0);
        assert!(
            res.is_ok(),
            "restore must still complete via the in-file markers, got {res:?}"
        );
        let restored = fs::read_to_string(&target).expect("read target");
        assert!(
            !restored.contains("6.6.6.6"),
            "a backup owned by the service account must never reach /etc/resolv.conf, \
             got: {restored:?}"
        );

        // And the gate is the ownership check, not luck: naming the real owner
        // makes the same backup usable again.
        let d2 = tmpdir("trusted-backup");
        let target2 = d2.join("resolv.conf");
        let backup2 = backup_path_in(&d2, &target2);
        write(&backup2, attacker);
        write(
            &target2,
            "# albus: DoH DNS active\nnameserver 127.0.0.1\n# albus-saved: nameserver 9.9.9.9\n",
        );
        let uid2 = fs::metadata(&backup2).expect("stat backup2").uid();
        restore_system_dns_from_backup(&target2, &backup2, uid2).expect("trusted restore");
        assert!(
            fs::read_to_string(&target2)
                .expect("read target2")
                .contains("6.6.6.6"),
            "when the backup is owned by the trusted uid it must still be honoured"
        );

        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&d2);
    }

    /// The predicate itself, so the gate is pinned independently of the restore
    /// flow: a file whose owner does not match is refused with PermissionDenied
    /// rather than silently ignored.
    #[test]
    fn test_read_owned_file_rejects_foreign_owner() {
        use std::os::unix::fs::MetadataExt;

        let d = tmpdir("owned");
        let f = d.join("data");
        write(&f, "payload\n");
        let uid = fs::metadata(&f).expect("stat").uid();

        assert_eq!(
            read_owned_file(&f, uid).expect("same owner is accepted"),
            "payload\n"
        );
        let err = read_owned_file(&f, uid.wrapping_add(1)).expect_err("foreign owner refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        let _ = fs::remove_dir_all(&d);
    }
}
