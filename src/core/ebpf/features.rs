//! linux kernel capability probing, euid privilege verification, and cgroup v2 mount validation.

use std::fs;
use std::path::Path;

// verifies effective user id is zero (root/cap_sys_admin)
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

// Linux capability numbers (linux/capability.h) backing the systemd unit's
// AmbientCapabilities set (L1 rootless runtime). A non-root daemon holding
// exactly these runs everything albus needs (raw sockets, iptables, eBPF,
// :53 bind, resolv.conf writes) with nothing else.
pub const CAP_DAC_OVERRIDE: u64 = 1;
pub const CAP_NET_BIND_SERVICE: u64 = 10;
pub const CAP_NET_ADMIN: u64 = 12;
pub const CAP_NET_RAW: u64 = 13;
pub const CAP_PERFMON: u64 = 38;
pub const CAP_BPF: u64 = 39;

pub const REQUIRED_SERVICE_CAPS: u64 = (1 << CAP_DAC_OVERRIDE)
    | (1 << CAP_NET_BIND_SERVICE)
    | (1 << CAP_NET_ADMIN)
    | (1 << CAP_NET_RAW)
    | (1 << CAP_PERFMON)
    | (1 << CAP_BPF);

/// Whether this process may run the engine: uid 0, or a dedicated service
/// user holding exactly the capability set above (see the systemd unit).
/// Service MANAGEMENT commands (install/start/stop via systemctl) still
/// require real root — capabilities do not authorize those.
pub fn has_service_privileges() -> bool {
    if is_root() {
        return true;
    }
    match cap_eff_self() {
        Some(eff) => eff & REQUIRED_SERVICE_CAPS == REQUIRED_SERVICE_CAPS,
        None => false,
    }
}

/// Parse helper, pure and unit-tested: effective capability mask from
/// /proc/self/status text. Unknown/malformed input yields None (fail
/// closed: has_service_privileges then refuses).
pub fn cap_eff_from_status(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let rest = line.strip_prefix("CapEff:")?;
        u64::from_str_radix(rest.trim(), 16).ok()
    })
}

fn cap_eff_self() -> Option<u64> {
    let text = fs::read_to_string("/proc/self/status").ok()?;
    cap_eff_from_status(&text)
}

/// The properties a dedicated, non-login service account must have.
///
/// SUPPLY-04: this is the trust anchor of the whole rootless privilege model,
/// and its only validation used to be "the name resolves and uid != 0". One
/// unverified passwd entry drives four decisions: the daemon identity that
/// carries six ambient capabilities, the polkit rule that grants
/// `polkit.Result.YES` with no authentication for five resolve1 actions to
/// `subject.user == "albus"`, ownership of /etc/albus (which the unit declares
/// writable), and `service_uid()`'s root-equivalence in config.rs for
/// /etc/albus, /run/albus and any privileged --config file.
///
/// Not mutating a pre-existing account is correct — an install has no business
/// rewriting an operator's account. VALIDATING it before binding a privileged
/// identity to it is a different question, and it is this predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccountCheck {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    /// Shell from the passwd entry; must be a nologin/false shell.
    pub shell_is_nologin: bool,
    /// Password field state: an account with a usable password can be logged
    /// into, which would hand its uid (and therefore the capabilities) to a
    /// human.
    pub password_is_locked: bool,
    /// Membership in any supplementary group (wheel, disk, ...) — such an
    /// account is not a dedicated service identity.
    pub supplementary_groups: Vec<libc::gid_t>,
}

impl ServiceAccountCheck {
    /// Why the account is not usable as the daemon identity, or None if it is.
    pub fn rejection(&self) -> Option<String> {
        if self.uid == 0 {
            return Some("uid 0 is root, not a service account".into());
        }
        // A system account: below the login range the admin allocates. Matches
        // the `--system` intent of the create path, which is what makes the
        // difference from an interactive account detectable at all.
        if self.uid >= 1000 {
            return Some(format!(
                "uid {} is in the normal-login range, so this is an interactive \
                 account rather than a dedicated system service",
                self.uid
            ));
        }
        if !self.shell_is_nologin {
            return Some("shell is not a nologin/false shell".into());
        }
        if !self.password_is_locked {
            return Some("password is not locked, so the account can be logged into".into());
        }
        if let Some(g) = self.supplementary_groups.first() {
            return Some(format!(
                "account is a member of supplementary group {}, so it is not a \
                 dedicated identity",
                g
            ));
        }
        None
    }

    pub fn is_usable(&self) -> bool {
        self.rejection().is_none()
    }
}

/// Inspects the `albus` passwd entry. Returns None when the name does not
/// resolve at all.
pub fn inspect_service_account() -> Option<ServiceAccountCheck> {
    let c_user = std::ffi::CString::new("albus").ok()?;
    unsafe {
        let pwd = libc::getpwnam(c_user.as_ptr());
        if pwd.is_null() {
            return None;
        }

        let shell = std::ffi::CStr::from_ptr((*pwd).pw_shell);
        let shell_s = shell.to_string_lossy();
        let shell_is_nologin = matches!(
            shell_s.as_ref(),
            "" | "/usr/sbin/nologin" | "/sbin/nologin" | "/bin/false" | "/usr/bin/false"
        );

        // passwd stores "!" or "*" (and sometimes "!!") for a locked password,
        // and "x" when the hash lives in /etc/shadow. Anything else could be a
        // usable credential.
        let pwfield = std::ffi::CStr::from_ptr((*pwd).pw_passwd);
        let pw_s = pwfield.to_string_lossy();
        let password_is_locked = pw_s.is_empty()
            || pw_s.starts_with('!')
            || pw_s.starts_with('*')
            || pw_s == "x"
            || pw_s == "!!";

        // `getgroups()` returns the CALLING PROCESS's groups, not the account's
        // — using it here would inspect the wrong thing entirely (and would
        // report the installer's supplementary groups). `getgrouplist` is the
        // API that answers "which groups is this NAME in", and it puts the
        // primary gid first.
        let supplementary_groups = {
            let mut buf: Vec<libc::gid_t> = vec![0; 32];
            // "albus\0" has no interior NUL by construction, so this cannot
            // fail and needs no fallible CString round-trip.
            let c_name = std::ffi::CStr::from_bytes_with_nul(b"albus\0").expect("literal");
            loop {
                let mut n: libc::c_int = buf.len() as libc::c_int;
                let rc =
                    libc::getgrouplist(c_name.as_ptr(), (*pwd).pw_gid, buf.as_mut_ptr(), &mut n);
                if rc >= 0 {
                    buf.truncate(n.max(0) as usize);
                    // getgrouplist puts the primary gid first; the rest are the
                    // supplementary memberships.
                    break buf.split_off(1.min(buf.len()));
                }
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ERANGE) && buf.len() < 4096 {
                    buf.resize(buf.len() * 2, 0);
                    continue;
                }
                // Could not enumerate. This must not silently become "no
                // supplementary groups": a sentinel that is not a real gid makes
                // the check reject, which is the safe direction.
                break vec![libc::gid_t::MAX];
            }
        };

        Some(ServiceAccountCheck {
            uid: (*pwd).pw_uid,
            gid: (*pwd).pw_gid,
            shell_is_nologin,
            password_is_locked,
            supplementary_groups,
        })
    }
}

/// Resolves the dedicated service account uid, if the account exists AND passes
/// validation.
///
/// SUPPLY-04: `uid != 0` was the entire check. That is far too weak to stand in
/// for "a locked, non-login, dedicated system account", and it is this uid that
/// config.rs treats as root-equivalent for /etc/albus, /run/albus and any
/// privileged --config file. A pre-existing human-login account named `albus`
/// would have become root-equivalent.
pub fn service_uid() -> Option<libc::uid_t> {
    let c = inspect_service_account()?;
    if c.uid == 0 {
        return None;
    }
    if let Some(reason) = c.rejection() {
        tracing::warn!(
            "refusing to trust the 'albus' passwd entry as the daemon identity: {}",
            reason
        );
        return None;
    }
    Some(c.uid)
}

// inspects /proc/mounts to verify presence of cgroup2 filesystem at target mount path
pub fn is_cgroup_v2(path: &str) -> bool {
    let p = Path::new(path);
    if !p.exists() || !p.is_dir() {
        return false;
    }

    // parse /proc/mounts entries for cgroup2 filesystem declaration
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[2] == "cgroup2" && mount_covers(parts[1], path) {
                return true;
            }
        }
    }

    // fallback verification via standard cgroup control files
    p.join("cgroup.procs").exists() || p.join("cgroup.controllers").exists()
}

/// Pure mount-coverage check: exact match, root mount, or proper `/`-bounded
/// prefix. A naive starts_with would accept `/sys/fs/cgroupfoo`.
pub fn mount_covers(mount_point: &str, path: &str) -> bool {
    mount_point == path || mount_point == "/" || path.starts_with(&format!("{}/", mount_point))
}

// verifies kernel support for bpf type format (btf) runtime relocation
pub fn has_btf() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

// parses linux kernel release string (e.g. "6.13.5-arch1", "5.15.0-generic") into (major, minor)
pub fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split('.');
    let major = parts
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse::<u32>()
        .ok()?;
    let minor = parts
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse::<u32>()
        .ok()?;
    Some((major, minor))
}

// checks kernel support for ebpf sock_ops hook points, minimum kernel version (>= 5.10), and cgroup v2
pub fn have_sock_ops() -> bool {
    // L1: capability-holding service user qualifies, not just uid 0.
    if !has_service_privileges() {
        return false;
    }

    // verify kernel version is at least 5.10
    if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        if let Some((major, minor)) = parse_kernel_version(&release) {
            if major < 5 || (major == 5 && minor < 10) {
                return false;
            }
        }
    }

    // verify cgroup v2 hierarchy is accessible
    if !is_cgroup_v2("/sys/fs/cgroup") {
        return false;
    }

    true
}

// inspects /proc/net/dev to enumerate active physical and virtual network interfaces
pub fn list_active_interfaces() -> Vec<String> {
    let mut interfaces = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/net/dev") {
        for line in content.lines().skip(2) {
            if let Some(colon_idx) = line.find(':') {
                let iface_name = line[..colon_idx].trim().to_string();
                if iface_name != "lo" && !iface_name.is_empty() {
                    interfaces.push(iface_name);
                }
            }
        }
    }
    interfaces
}

// aggregates root, cgroup v2, sock_ops, and btf co-re capability flags
pub fn capability_summary() -> (bool, bool, bool, bool) {
    (
        is_root(),
        is_cgroup_v2("/sys/fs/cgroup"),
        have_sock_ops(),
        has_btf(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_root_boolean() {
        let _ = is_root();
    }

    #[test]
    fn test_list_active_interfaces_non_empty_or_valid() {
        let ifaces = list_active_interfaces();
        // loopback is filtered out
        assert!(!ifaces.contains(&"lo".to_string()));
    }

    #[test]
    fn test_parse_kernel_version() {
        assert_eq!(parse_kernel_version("6.13.5-arch1"), Some((6, 13)));
        assert_eq!(parse_kernel_version("5.10.0-8-amd64"), Some((5, 10)));
        assert_eq!(parse_kernel_version("4.19.128"), Some((4, 19)));
        assert_eq!(parse_kernel_version("invalid"), None);
    }

    #[test]
    fn test_capability_summary() {
        let (root, cgroup, sockops, btf) = capability_summary();
        let _ = (root, cgroup, sockops, btf);
    }

    #[test]
    fn test_cap_eff_parsing() {
        let sample = "Name:\talbus\nUid:\t996\t996\t996\t996\nCapEff:\t00000000800405fb\n";
        assert_eq!(cap_eff_from_status(sample), Some(0x800405fb));
        assert_eq!(cap_eff_from_status("no caps here\n"), None);
        assert_eq!(cap_eff_from_status("CapEff:\tZZZ\n"), None);
        assert_eq!(cap_eff_from_status(""), None);
    }

    #[test]
    fn test_required_caps_shape() {
        // exactly the six unit capabilities, nothing else
        let mut count = 0u32;
        let mut bits = REQUIRED_SERVICE_CAPS;
        while bits != 0 {
            count += (bits & 1) as u32;
            bits >>= 1;
        }
        assert_eq!(count, 6);
        for cap in [
            CAP_DAC_OVERRIDE,
            CAP_NET_BIND_SERVICE,
            CAP_NET_ADMIN,
            CAP_NET_RAW,
            CAP_PERFMON,
            CAP_BPF,
        ] {
            assert_ne!(REQUIRED_SERVICE_CAPS & (1 << cap), 0);
        }
    }

    #[test]
    fn test_mount_covers() {
        assert!(mount_covers("/sys/fs/cgroup", "/sys/fs/cgroup"));
        assert!(mount_covers("/sys/fs/cgroup", "/sys/fs/cgroup/albus"));
        assert!(mount_covers("/", "/etc/albus"));
        assert!(!mount_covers("/sys/fs/cgroup", "/sys/fs/cgroupfoo"));
        assert!(!mount_covers("/sys/fs/cgroup", "/sys/fs/other"));
    }

    #[test]
    fn test_service_privileges_boolean() {
        // must not panic; true for root, false-or-true for service user
        let _ = has_service_privileges();
        // a nonexistent-user lookup path: service_uid returns None or a uid
        let _ = service_uid();
    }
}

#[cfg(test)]
mod service_account_tests {
    use super::*;

    fn ok_account() -> ServiceAccountCheck {
        ServiceAccountCheck {
            uid: 957,
            gid: 956,
            shell_is_nologin: true,
            password_is_locked: true,
            supplementary_groups: vec![],
        }
    }

    /// A dedicated system account with a nologin shell, a locked password and
    /// no supplementary groups is what install creates, so it must be accepted.
    #[test]
    fn test_system_nologin_account_is_accepted() {
        let a = ok_account();
        assert!(a.is_usable(), "{:?}", a.rejection());
    }

    /// uid 0 is root, not a service identity.
    #[test]
    fn test_uid_zero_is_rejected() {
        let a = ServiceAccountCheck {
            uid: 0,
            ..ok_account()
        };
        assert!(!a.is_usable());
        assert!(a.rejection().unwrap().contains("root"));
    }

    /// SUPPLY-04's main case: an interactive login account that happens to be
    /// named `albus`. Its uid would carry six ambient capabilities and hold
    /// unauthenticated polkit resolve1 grants, and config.rs would treat files
    /// it owns as root-equivalent.
    #[test]
    fn test_login_range_account_is_rejected() {
        let a = ServiceAccountCheck {
            uid: 1000,
            ..ok_account()
        };
        let reason = a.rejection().expect("must be rejected");
        assert!(reason.contains("normal-login range"), "{}", reason);
    }

    /// A login shell makes it a human account regardless of uid.
    #[test]
    fn test_login_shell_is_rejected() {
        let a = ServiceAccountCheck {
            shell_is_nologin: false,
            ..ok_account()
        };
        let reason = a.rejection().expect("must be rejected");
        assert!(reason.contains("nologin"), "{}", reason);
    }

    /// An unlocked password means the account can be logged into, handing its
    /// uid — and therefore the capabilities — to a person.
    #[test]
    fn test_unlocked_password_is_rejected() {
        let a = ServiceAccountCheck {
            password_is_locked: false,
            ..ok_account()
        };
        let reason = a.rejection().expect("must be rejected");
        assert!(reason.contains("password"), "{}", reason);
    }

    /// Supplementary groups (wheel, disk, …) mean it is not a dedicated
    /// identity — a dedicated service account needs no additional groups.
    #[test]
    fn test_supplementary_group_is_rejected() {
        let a = ServiceAccountCheck {
            supplementary_groups: vec![10], // wheel
            ..ok_account()
        };
        let reason = a.rejection().expect("must be rejected");
        assert!(reason.contains("supplementary group"), "{}", reason);
    }

    /// Install and runtime must not drift: `service_uid()` is the single
    /// predicate both use.
    #[test]
    fn test_service_uid_is_root_equivalent_only_for_a_valid_account() {
        // On this host the account exists; assert the predicate agrees with a
        // direct inspection rather than hard-coding an expectation about the
        // machine.
        match inspect_service_account() {
            None => {
                // No 'albus' entry at all: service_uid must be None.
                assert_eq!(service_uid(), None);
            }
            Some(a) => {
                if a.is_usable() {
                    assert_eq!(service_uid(), Some(a.uid));
                } else {
                    assert_eq!(
                        service_uid(),
                        None,
                        "SUPPLY-04: an invalid account must not be treated as the \\
                         root-equivalent service uid (rejection: {:?})",
                        a.rejection()
                    );
                }
            }
        }
    }

    /// And the supplementary-group probe must read the ACCOUNT's groups, not
    /// the calling process's. `getgroups()` would have returned this test
    /// runner's groups and silently passed or failed for the wrong reason.
    #[test]
    fn test_supplementary_group_probe_is_account_scoped() {
        let src = include_str!("features.rs");
        let prod = src
            .split_once("\n#[cfg(test)]\nmod service_account_tests")
            .map(|(p, _)| p)
            .unwrap_or(src);
        assert!(
            !prod.contains("libc::getgroups("),
            "SUPPLY-04: getgroups() returns the CALLING PROCESS's groups, not the \\
             account's — the check would inspect the wrong principal entirely"
        );
        assert!(
            prod.contains("getgrouplist("),
            "getgrouplist is the API that answers 'which groups is this NAME in'"
        );
    }
}
