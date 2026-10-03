//! iptables and ip6tables packet filtering rules for quic fallback, webrtc stun drop, and dns leak kill-switch.

use std::path::Path;
use std::process::Command;
use tracing::{debug, info};

const IPTABLES_CANDIDATES: &[&str] = &["/usr/sbin/iptables", "/sbin/iptables"];
const IP6TABLES_CANDIDATES: &[&str] = &["/usr/sbin/ip6tables", "/sbin/ip6tables"];
const MAX_RULE_DELETE_ITER: usize = 32;

/// True when `path` is safe to exec with the daemon's elevated capabilities.
///
/// EBPF-06: `resolve_binary` selected the helper with `Path::exists()` alone.
/// That follows symlinks, returns true for directories, and never establishes
/// *who* owns the thing being executed — while the exec'ing process holds
/// CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF, CAP_PERFMON, CAP_NET_BIND_SERVICE and
/// CAP_DAC_OVERRIDE. Code in a substituted binary would run with all of those.
///
/// The surrounding hygiene was already good and is kept: absolute paths defeat
/// PATH search entirely and `env_clear()` drops the IPTABLES/IP6TABLES/locale
/// environment overrides iptables honours. The gap was identity, so identity is
/// what this checks:
///
///   * `metadata` (not `symlink_metadata`) is deliberate — on Arch
///     `/usr/sbin/iptables` is a symlink to `xtables-nft-multi`, so refusing
///     symlinks outright would break the shipped install. What matters is the
///     *resolved target*, and a dangling symlink fails at `metadata` here;
///   * the target must be a regular file, not a directory or device;
///   * it must be owned by root or the albus service account, reusing the
///     repo's own notion of a trusted system uid;
///   * no directory in the chain may be writable by group or other, so a
///     writable ancestor cannot be used to swap the target after the check.
#[cfg(unix)]
fn helper_is_trusted_with(path: &Path, trusted_uids: &[libc::uid_t]) -> bool {
    helper_trusted_real_path(path, trusted_uids).is_some()
}

/// As `helper_is_trusted_with`, but returns the RESOLVED path — the same one that
/// must then be handed to `execve`.
///
/// P2: `resolve_binary_with` used to return the original candidate string while
/// this check validated `canonicalize(candidate)`. The kernel re-resolves the
/// path at exec time, so a symlink swapped between the check and the exec was
/// never the file that got vetted, and the comment above claiming the window
/// was closed was describing only one of the two paths in play. Returning the
/// resolved path makes the check and the exec refer to the same object.
///
/// P3: the ancestor walk below checks directory modes, but never the helper's own
/// mode. `service.rs` states the reasoning for its own binary outright — a
/// group- or world-writable file exec'd under six ambient capabilities hands code
/// execution to every local principal in that set — and it applies verbatim to
/// `/usr/sbin/iptables`, which `RealIptables::run` execs from inside the same
/// capability-bearing daemon.
fn helper_trusted_real_path(
    path: &Path,
    trusted_uids: &[libc::uid_t],
) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;

    // Resolve FIRST, then judge the resolved target and the directories it
    // actually lives in. Judging the symlink's own location instead is the
    // hole this replaces: an attacker who can create a link inside a
    // group/world-writable directory can aim it at anything, and the link's
    // parent chain can look pristine. `canonicalize` also fails on a dangling
    // link, which is the other case `exists()` used to wave through differently.
    let real = match std::fs::canonicalize(path) {
        Ok(r) => r,
        Err(_) => return None, // missing, or a dangling symlink
    };

    let meta = match std::fs::metadata(&real) {
        Ok(m) => m,
        Err(_) => return None,
    };
    if !meta.is_file() {
        return None; // directory, socket, device, fifo
    }
    if !trusted_uids.contains(&meta.uid()) {
        return None;
    }
    // P3: the file itself must not be group- or world-writable.
    if meta.mode() & 0o022 != 0 {
        return None;
    }

    // Walk the RESOLVED chain: a component writable by group or other would
    // let a less-trusted principal replace the target between this check and
    // the exec that follows it.
    let mut dir = real.parent();
    while let Some(d) = dir {
        match std::fs::metadata(d) {
            Ok(dm) => {
                if dm.mode() & 0o022 != 0 {
                    return None;
                }
            }
            // An ancestor we cannot stat is an ancestor we cannot vouch for.
            Err(_) => return None,
        }
        dir = d.parent();
    }
    Some(real)
}

/// The uids allowed to own a privileged helper: root, plus the albus service
/// account when one exists (the daemon legitimately runs as that account).
#[cfg(unix)]
fn trusted_helper_uids() -> Vec<libc::uid_t> {
    let mut uids = vec![0u32];
    if let Some(su) = crate::core::ebpf::features::service_uid() {
        uids.push(su);
    }
    uids
}

#[cfg(all(unix, test))]
fn helper_is_trusted(path: &Path) -> bool {
    helper_is_trusted_with(path, &trusted_helper_uids())
}

#[cfg(all(not(unix), test))]
fn helper_is_trusted(_path: &Path) -> bool {
    true
}

/// First candidate whose identity checks out.
///
/// EBPF-06: the old fallback returned `candidates.first()` when nothing
/// existed, so a missing helper silently became an exec attempt against a path
/// that may not be there, and an untrusted one was never rejected at all. An
/// absent or untrusted helper is now an explicit error that EBPF-01's
/// `Result` plumbing propagates to the caller.
fn resolve_binary_with(
    candidates: &[&str],
    trusted_uids: &[libc::uid_t],
) -> Result<std::path::PathBuf, FirewallError> {
    for c in candidates {
        if let Some(real) = helper_trusted_real_path(Path::new(c), trusted_uids) {
            return Ok(real);
        }
    }
    Err(FirewallError(format!(
        "no trusted iptables/ip6tables helper found among {:?}: each candidate must be a \
         root- or albus-owned regular file reached through no group/world-writable \
         directory",
        candidates
    )))
}

#[cfg(unix)]
fn resolve_binary(candidates: &[&str]) -> Result<std::path::PathBuf, FirewallError> {
    resolve_binary_with(candidates, &trusted_helper_uids())
}

#[cfg(not(unix))]
fn resolve_binary(candidates: &[&str]) -> Result<std::path::PathBuf, FirewallError> {
    candidates
        .first()
        .map(std::path::PathBuf::from)
        .ok_or_else(|| FirewallError("no iptables candidates configured".into()))
}

fn iptables_base() -> Result<Command, FirewallError> {
    let bin = resolve_binary(IPTABLES_CANDIDATES)?;
    let mut c = Command::new(bin);
    c.env_clear();
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    Ok(c)
}

fn ip6tables_base() -> Result<Command, FirewallError> {
    let bin = resolve_binary(IP6TABLES_CANDIDATES)?;
    let mut c = Command::new(bin);
    c.env_clear();
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    Ok(c)
}

pub type FwResult = Result<(), FirewallError>;

/// Outcome of a rule-removal step: how many rules went away, or why we cannot
/// say. SUPPLY-03: the delete path used to return a bare `usize` whose normal
/// value equalled its failure value.
/// A firewall rule could not be installed. Carries the kernel-side reason so
/// the journal cannot claim a control is active when the packet filter never
/// accepted the rule.
pub type FwCount = Result<usize, FirewallError>;

#[derive(Debug)]
pub struct FirewallError(pub String);

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for FirewallError {}

/// Outcome of one iptables invocation: exit code, or a spawn failure.
///
/// EBPF-01: `Command::status()` yields `Ok(ExitStatus)` for a *failed*
/// invocation, so the previous code warned only on `Err` — which means
/// "could not run iptables at all" — and treated every non-zero exit as
/// success. xtables lock contention, a legacy/nft backend mismatch, a missing
/// `xt_comment` or `REJECT` target, or a rejected transaction all exit non-zero
/// and all took the silent path. Modelling the exit code explicitly is what
/// makes the failure observable.
pub type ExecResult = Result<i32, std::io::Error>;

/// The invocation seam. Production uses `run_iptables`; tests supply a
/// synthetic executor so the decision logic is exercised hermetically, with no
/// iptables binary and no host mutation.
pub trait Executor {
    fn run(&self, v6: bool, args: &[&str]) -> ExecResult;
}

pub struct RealIptables;

impl Executor for RealIptables {
    fn run(&self, v6: bool, args: &[&str]) -> ExecResult {
        // An absent or untrusted helper is reported as a spawn-class error
        // carrying the selection failure's message, so it lands in the same
        // "could not run" channel rather than being mistaken for a rule state.
        let base = if v6 {
            ip6tables_base()
        } else {
            iptables_base()
        };
        let mut cmd = match base {
            Ok(c) => c,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    e.to_string(),
                ))
            }
        };
        match cmd.args(args).output() {
            Ok(o) => Ok(o.status.code().unwrap_or(-1)),
            Err(e) => Err(e),
        }
    }
}

/// Idempotent insert with a falsifiable outcome: `iptables -C OUTPUT ... || iptables -I OUTPUT ...`
///
/// EBPF-01: the invariant this now enforces is *"no caller may record or log a
/// firewall control as applied unless the rule was observed present after the
/// attempt."* Three things were wrong before:
///   * the `-C` probe collapsed "check could not run" into "rule absent",
///     because `unwrap_or(false)` maps a spawn failure to the same value as a
///     clean miss;
///   * the insert's exit status was discarded entirely;
///   * the function returned `()`, so no caller could react — and callers did
///     not need to, because they logged `... ACTIVE` unconditionally.
///
/// The check's exit code is now interpreted rather than assumed: xtables
/// reserves 1 for "rule does not exist" and uses 2/3/4 for syntax,
/// module and resource errors respectively, so only exit 1 counts as absent.
/// After a successful insert the rule is re-checked, which turns "iptables said
/// OK" into "the rule is observably there".
pub fn ensure_rule(v6: bool, args: &[&str], comment: &str) -> FwResult {
    ensure_rule_with(&RealIptables, v6, args, comment)
}

pub fn ensure_rule_with<E: Executor + ?Sized>(
    exec: &E,
    v6: bool,
    args: &[&str],
    comment: &str,
) -> FwResult {
    let mut spec: Vec<&str> = Vec::with_capacity(args.len() + 4);
    spec.extend_from_slice(args);
    spec.extend_from_slice(&["-m", "comment", "--comment", comment]);

    let mut check_args: Vec<&str> = vec!["-C", "OUTPUT"];
    check_args.extend_from_slice(&spec);

    match exec.run(v6, &check_args) {
        Ok(0) => return Ok(()), // already installed
        Ok(1) => {}             // documented "no such rule" -> insert it
        Ok(code) => {
            return Err(FirewallError(format!(
                "iptables -C OUTPUT {:?} exited {} (not 0, not 1): the rule state \
                 could not be determined, so it is not being installed",
                args, code
            )));
        }
        Err(e) => {
            return Err(FirewallError(format!(
                "iptables -C OUTPUT {:?} could not run: {}; refusing to assume \
                 the rule is absent and insert over an unknown filter state",
                args, e
            )));
        }
    }

    let mut insert_args: Vec<&str> = vec!["-I", "OUTPUT"];
    insert_args.extend_from_slice(&spec);
    match exec.run(v6, &insert_args) {
        Ok(0) => {}
        Ok(code) => {
            return Err(FirewallError(format!(
                "iptables -I OUTPUT {:?} exited {}: the rule was NOT installed",
                args, code
            )));
        }
        Err(e) => {
            return Err(FirewallError(format!(
                "iptables -I OUTPUT {:?} could not run: {}: the rule was NOT installed",
                args, e
            )));
        }
    }

    // Authoritative verification: the insert's own exit status is a claim by
    // the same process that wrote the rule, so confirm it is really present.
    match exec.run(v6, &check_args) {
        Ok(0) => Ok(()),
        Ok(code) => Err(FirewallError(format!(
            "iptables -C OUTPUT {:?} exited {} immediately after a successful \
             insert: the rule is not present",
            args, code
        ))),
        Err(e) => Err(FirewallError(format!(
            "iptables -C OUTPUT {:?} could not run for verification: {}",
            args, e
        ))),
    }
}

/// Bounded delete: avoids infinite loop if binary is shimmed.
/// FP-10: returns the number of rules actually deleted so callers can report.
fn delete_rule_bounded_with<E: Executor + ?Sized>(exec: &E, v6: bool, args: &[&str]) -> FwCount {
    let mut removed = 0;
    // 1. new-style rules (with per-feature comments)
    for comment in [
        "albus-quic",
        "albus-stun",
        "albus-kill",
        "albus-lockdown",
        "albus",
    ] {
        for _ in 0..MAX_RULE_DELETE_ITER {
            let mut del_args: Vec<&str> = vec!["-D", "OUTPUT"];
            del_args.extend_from_slice(args);
            del_args.extend_from_slice(&["-m", "comment", "--comment", comment]);
            match exec.run(v6, &del_args) {
                Ok(0) => {
                    removed += 1;
                    continue;
                }
                // SUPPLY-03: xtables' documented "no such rule". This is the
                // *expected* outcome on the normal path, because
                // ExecStopPost=albus cleanup has already removed every rule
                // before uninstall's own calls run — so "Removed 0 rules" and
                // "the delete failed" used to be the same integer. Distinguish
                // them so teardown can report what actually happened.
                Ok(1) => break,
                Ok(code) => {
                    return Err(FirewallError(format!(
                        "iptables -D OUTPUT {:?} exited {}: rule removal state is \
                         unknown, so residual rules may still be installed",
                        args, code
                    )));
                }
                Err(e) => {
                    return Err(FirewallError(format!(
                        "iptables -D OUTPUT {:?} could not run: {}: rule removal state \
                         is unknown, so residual rules may still be installed",
                        args, e
                    )));
                }
            }
        }
    }
    // FP-07: legacy unscoped phase REMOVED. It built `-D OUTPUT <args>` with no
    // `-m comment` match and ran unconditionally, stripping third-party
    // comment-less rules sharing the tuple. Pre-hardening residue (comment-less
    // albus rules) is fail-closed and stays until removed manually — documented
    // instead of blindly deleted. See REPORT run-1 FP-07.
    Ok(removed)
}

/// Bounded delete with an honest outcome.
///
/// Returns the number of rules actually removed. `Ok(0)` means "there was
/// nothing to remove", which is the expected success case after
/// `ExecStopPost` cleanup has already run. `Err` means the removal state could
/// not be established — the caller must not report the host as clean.
pub fn delete_rule_bounded(v6: bool, args: &[&str]) -> FwCount {
    delete_rule_bounded_with(&RealIptables, v6, args)
}

// injects icmp port unreachable / tcp reset via iptables reject on udp 443
pub fn block_quic() -> FwResult {
    ensure_rule(
        false,
        &["-p", "udp", "--dport", "443", "-j", "REJECT"],
        "albus-quic",
    )?;
    ensure_rule(
        true,
        &["-p", "udp", "--dport", "443", "-j", "REJECT"],
        "albus-quic",
    )?;

    info!("QUIC (UDP 443) blocked — forcing browsers to TCP for DPI bypass");
    Ok(())
}

// purges injected reject rules for udp 443. Returns rules deleted (FP-10).
pub fn unblock_quic() -> FwCount {
    let mut n = 0;
    n += delete_rule_bounded(false, &["-p", "udp", "--dport", "443", "-j", "REJECT"])?;
    n += delete_rule_bounded(true, &["-p", "udp", "--dport", "443", "-j", "REJECT"])?;

    debug!("QUIC firewall rules cleaned up");
    Ok(n)
}

// blocks outbound webrtc stun traffic (udp 3478, 5349) to prevent client public/local ip leaks
pub fn block_stun() -> FwResult {
    for port in &["3478", "5349"] {
        ensure_rule(
            false,
            &["-p", "udp", "--dport", port, "-j", "REJECT"],
            "albus-stun",
        )?;
        ensure_rule(
            true,
            &["-p", "udp", "--dport", port, "-j", "REJECT"],
            "albus-stun",
        )?;
    }

    info!("WebRTC STUN (UDP 3478, 5349) blocked — preventing browser IP address leaks");
    Ok(())
}

// purges stun packet filtering rules. Returns rules deleted (FP-10).
pub fn unblock_stun() -> FwCount {
    let mut n = 0;
    for port in &["3478", "5349"] {
        n += delete_rule_bounded(false, &["-p", "udp", "--dport", port, "-j", "REJECT"])?;
        n += delete_rule_bounded(true, &["-p", "udp", "--dport", port, "-j", "REJECT"])?;
    }

    debug!("STUN firewall rules cleaned up");
    Ok(n)
}

// enables strict dns kill-switch: drops all non-loopback outbound port 53 traffic
// guarantees no application or rogue dhcp server can leak plaintext dns to the isp
// NOTE: uses DROP (stealth) instead of REJECT to avoid signaling DPI/middleboxes.
pub fn enable_kill_switch() -> FwResult {
    let udp = ["!", "-o", "lo", "-p", "udp", "--dport", "53", "-j", "DROP"];
    let tcp = ["!", "-o", "lo", "-p", "tcp", "--dport", "53", "-j", "DROP"];
    // DoT 853 also blocked to prevent plaintext-adjacent leak
    let dot = ["!", "-o", "lo", "-p", "tcp", "--dport", "853", "-j", "DROP"];
    ensure_rule(false, &udp, "albus-kill")?;
    ensure_rule(false, &tcp, "albus-kill")?;
    ensure_rule(false, &dot, "albus-kill")?;
    ensure_rule(true, &udp, "albus-kill")?;
    ensure_rule(true, &tcp, "albus-kill")?;
    ensure_rule(true, &dot, "albus-kill")?;

    info!("DNS Kill-Switch ACTIVE — all non-loopback plaintext DNS queries blocked");
    Ok(())
}

// removes dns kill-switch filtering rules. Returns rules deleted (FP-10).
pub fn disable_kill_switch() -> FwCount {
    // remove both DROP (new) and REJECT (legacy) variants to clean old installs.
    // FP-07: only comment-scoped deletes; pre-hardening comment-less residue stays.
    let mut n = 0;
    for target in ["DROP", "REJECT"] {
        let udp = ["!", "-o", "lo", "-p", "udp", "--dport", "53", "-j", target];
        let tcp = ["!", "-o", "lo", "-p", "tcp", "--dport", "53", "-j", target];
        let dot = ["!", "-o", "lo", "-p", "tcp", "--dport", "853", "-j", target];
        n += delete_rule_bounded(false, &udp)?;
        n += delete_rule_bounded(false, &tcp)?;
        n += delete_rule_bounded(false, &dot)?;
        n += delete_rule_bounded(true, &udp)?;
        n += delete_rule_bounded(true, &tcp)?;
        n += delete_rule_bounded(true, &dot)?;
    }

    debug!("DNS Kill-Switch deactivated");
    Ok(n)
}

// enables fail-closed network lockdown: blocks outbound non-loopback tcp traffic on ports 80 and 443
// prevents unfragmented/unprotected web traffic from leaking to the isp if the ebpf subsystem fails
pub fn enable_network_lockdown() -> FwResult {
    for port in &["80", "443"] {
        let rule = ["!", "-o", "lo", "-p", "tcp", "--dport", port, "-j", "DROP"];
        ensure_rule(false, &rule, "albus-lockdown")?;
        ensure_rule(true, &rule, "albus-lockdown")?;
    }

    info!("Network Lockdown ACTIVE (fail-closed) — outbound HTTP/HTTPS (ports 80, 443) blocked");
    Ok(())
}

// purges fail-closed network lockdown rules. Returns rules deleted (FP-10).
pub fn disable_network_lockdown() -> FwCount {
    let mut n = 0;
    for port in &["80", "443"] {
        for target in ["DROP", "REJECT"] {
            let rule = ["!", "-o", "lo", "-p", "tcp", "--dport", port, "-j", target];
            n += delete_rule_bounded(false, &rule)?;
            n += delete_rule_bounded(true, &rule)?;
        }
    }

    debug!("Network Lockdown deactivated — outbound HTTP/HTTPS restored");
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records every invocation so the tests can assert *which* iptables calls
    /// were made, not just the final verdict.
    struct Recorder {
        /// exit code per (args[0] op, occurrence index)
        script: Vec<(String, ExecResult)>,
        calls: std::cell::RefCell<Vec<String>>,
    }

    impl Recorder {
        fn new(script: &[(&str, ExecResult)]) -> Self {
            Self {
                script: script
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.clone_shallow()))
                    .collect(),
                calls: std::cell::RefCell::new(Vec::new()),
            }
        }
    }

    // `std::io::Error` is not Clone; this is a test-only shim that carries the
    // kind and message, which is all the assertions need.
    trait ShallowClone {
        fn clone_shallow(&self) -> ExecResult;
    }
    impl ShallowClone for ExecResult {
        fn clone_shallow(&self) -> ExecResult {
            match self {
                Ok(c) => Ok(*c),
                Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
            }
        }
    }

    impl Executor for &Recorder {
        fn run(&self, _v6: bool, args: &[&str]) -> ExecResult {
            let op = args[0].to_string();
            self.calls
                .borrow_mut()
                .push(format!("{} {}", op, args[1..].join(" ")));
            let mut idx = 0;
            for (k, _) in &self.script {
                if *k == op {
                    if idx == 0 {
                        return self
                            .script
                            .iter()
                            .find(|(kk, _)| kk == &op)
                            .unwrap()
                            .1
                            .clone_shallow();
                    }
                    idx += 1;
                }
            }
            Ok(0)
        }
    }

    fn io_err(kind: std::io::ErrorKind) -> ExecResult {
        Err(std::io::Error::new(kind, "synthetic spawn failure"))
    }

    /// The headline EBPF-01 case: the insert returns a non-zero exit, which the
    /// old code discarded entirely — `Command::status()` yields
    /// `Ok(ExitStatus)` for a failed run, so `if let Err(e) = res` never fired
    /// and the daemon logged "Kill-Switch ACTIVE" over a rule the kernel never
    /// accepted. A check exit of 1 is xtables' documented "absent", so the
    /// insert is attempted and its failure must be reported.
    #[test]
    fn test_nonzero_exit_on_insert_is_an_error() {
        let rec = Recorder::new(&[("-C", Ok(1)), ("-I", Ok(4))]);
        let r = ensure_rule_with(
            &&rec,
            false,
            &["-p", "udp", "--dport", "443", "-j", "REJECT"],
            "albus-quic",
        );
        assert!(
            r.is_err(),
            "a non-zero insert exit must not be reported as a working rule"
        );
        let calls = rec.calls.borrow();
        assert!(
            calls.iter().any(|c| c.starts_with("-C")),
            "probe must have run"
        );
        assert!(
            calls.iter().any(|c| c.starts_with("-I")),
            "insert must have been attempted"
        );
        assert_eq!(
            calls.len(),
            2,
            "a failed insert must not be followed by a verification probe: {:?}",
            calls
        );
    }

    /// The state of the filter cannot be determined when the probe itself
    /// errors, so nothing may be inserted over it.
    #[test]
    fn test_indeterminate_check_does_not_insert() {
        for code in [2, 3, 4] {
            let rec = Recorder::new(&[("-C", Ok(code))]);
            let r = ensure_rule_with(
                &&rec,
                false,
                &["-p", "udp", "--dport", "443", "-j", "REJECT"],
                "albus-quic",
            );
            assert!(r.is_err(), "check exit {} must be an error", code);
            assert!(
                !rec.calls.borrow().iter().any(|c| c.starts_with("-I")),
                "check exit {} must not lead to an insert",
                code
            );
        }
    }

    /// A check that exits 0 short-circuits: the rule is present, so no insert.
    #[test]
    fn test_check_exit_zero_short_circuits_without_insert() {
        let rec = Recorder::new(&[("-C", Ok(0))]);
        let r = ensure_rule_with(
            &&rec,
            true,
            &["-p", "udp", "--dport", "53", "-j", "DROP"],
            "albus-kill",
        );
        assert!(r.is_ok());
        let calls = rec.calls.borrow();
        assert_eq!(calls.len(), 1, "expected a single probe, got {:?}", calls);
        assert!(calls[0].starts_with("-C"));
    }

    /// A spawn failure must be distinguishable from "rule absent". The old
    /// `unwrap_or(false)` mapped both to the same value, so a broken iptables
    /// path silently proceeded to the insert over an unknown filter state.
    #[test]
    fn test_spawn_failure_is_distinguishable_from_absent() {
        let rec = Recorder::new(&[("-C", io_err(std::io::ErrorKind::NotFound))]);
        let r = ensure_rule_with(
            &&rec,
            false,
            &["-p", "tcp", "--dport", "80", "-j", "DROP"],
            "albus-lockdown",
        );
        assert!(
            r.is_err(),
            "an unrunnable probe must not be treated as 'rule absent'"
        );
        let calls = rec.calls.borrow();
        assert!(
            !calls.iter().any(|c| c.starts_with("-I")),
            "no insert should be attempted over an unknown filter state: {:?}",
            calls
        );
    }

    /// Exit 1 is xtables' documented "no such rule" and the only code that may
    /// be read as absent. 2/3/4 mean syntax error / module problem / resource
    /// problem and must abort rather than insert.
    #[test]
    fn test_only_exit_one_is_read_as_absent() {
        for code in [2, 3, 4] {
            let rec = Recorder::new(&[("-C", Ok(code))]);
            let r = ensure_rule_with(
                &&rec,
                false,
                &["-p", "udp", "--dport", "853", "-j", "DROP"],
                "albus-kill",
            );
            assert!(r.is_err(), "check exit {} must be an error", code);
            assert!(
                !rec.calls.borrow().iter().any(|c| c.starts_with("-I")),
                "check exit {} must not lead to an insert",
                code
            );
        }
        // exit 1 does lead to the insert
        let rec = Recorder::new(&[("-C", Ok(1))]);
        let _ = ensure_rule_with(
            &&rec,
            false,
            &["-p", "udp", "--dport", "853", "-j", "DROP"],
            "albus-kill",
        );
        assert!(
            rec.calls.borrow().iter().any(|c| c.starts_with("-I")),
            "exit 1 means absent and must lead to an insert"
        );
    }

    /// The insert's own exit status is a claim by the process that wrote the
    /// rule, so a successful insert is re-verified. This test models the worst
    /// case: insert reports success, then the verification check disagrees.
    #[test]
    fn test_insert_success_is_verified_not_assumed() {
        // -C returns 1 (absent) then 4 (still absent after "insert")
        struct TwoPhase(RefCell<usize>);
        impl Executor for TwoPhase {
            fn run(&self, _v6: bool, args: &[&str]) -> ExecResult {
                if args[0] == "-C" {
                    let mut n = self.0.borrow_mut();
                    *n += 1;
                    Ok(if *n == 1 { 1 } else { 4 })
                } else {
                    Ok(0)
                }
            }
        }
        use std::cell::RefCell;
        let tp = TwoPhase(RefCell::new(0));
        let r = ensure_rule_with(
            &tp,
            false,
            &["-p", "udp", "--dport", "443", "-j", "REJECT"],
            "albus-quic",
        );
        assert!(
            r.is_err(),
            "an unverified insert must not be reported as a working rule"
        );
    }

    /// The success path end to end: absent -> insert -> verified present.
    #[test]
    fn test_absent_then_inserted_then_verified_succeeds() {
        struct Happy(RefCell<usize>);
        impl Executor for Happy {
            fn run(&self, _v6: bool, args: &[&str]) -> ExecResult {
                if args[0] == "-C" {
                    let mut n = self.0.borrow_mut();
                    *n += 1;
                    Ok(if *n == 1 { 1 } else { 0 })
                } else {
                    Ok(0)
                }
            }
        }
        use std::cell::RefCell;
        let h = Happy(RefCell::new(0));
        let r = ensure_rule_with(
            &h,
            true,
            &["-p", "udp", "--dport", "53", "-j", "DROP"],
            "albus-kill",
        );
        assert!(r.is_ok(), "the ordinary absent-then-install path must work");
    }
}

#[cfg(test)]
mod delete_outcome_tests {
    use super::*;

    /// Returns 0 on delete (rule removed) for the first `n` calls, then 1
    /// (no such rule — the expected steady state).
    struct Deleter {
        remaining: std::cell::Cell<usize>,
    }
    impl Executor for Deleter {
        fn run(&self, _v6: bool, args: &[&str]) -> ExecResult {
            assert_eq!(args[0], "-D");
            let n = self.remaining.get();
            if n == 0 {
                Ok(1)
            } else {
                self.remaining.set(n - 1);
                Ok(0)
            }
        }
    }

    /// SUPPLY-03: `Ok(0)` — "there was nothing to remove" — is the normal case
    /// on the real uninstall path, because ExecStopPost=albus cleanup already
    /// removed every rule first. It must be reported as success, not confused
    /// with a failure.
    #[test]
    fn test_nothing_to_remove_is_ok() {
        let d = Deleter {
            remaining: std::cell::Cell::new(0),
        };
        let r = delete_rule_bounded_with(&d, false, &["-p", "udp", "--dport", "53", "-j", "DROP"]);
        assert_eq!(r.expect("absent rules are not a failure"), 0);
    }

    #[test]
    fn test_rules_actually_removed_are_counted() {
        let d = Deleter {
            remaining: std::cell::Cell::new(3),
        };
        let r = delete_rule_bounded_with(&d, false, &["-p", "udp", "--dport", "53", "-j", "DROP"]);
        assert_eq!(r.expect("clean removal"), 3);
    }

    /// The case that used to be invisible: a delete that fails for a reason
    /// other than "no such rule". xtables lock contention, a bad backend, a
    /// missing target — all exit non-1 and all mean residual rules may remain.
    #[test]
    fn test_non_one_exit_on_delete_is_an_error() {
        struct Failing;
        impl Executor for Failing {
            fn run(&self, _v6: bool, _args: &[&str]) -> ExecResult {
                Ok(4) // xtables lock held
            }
        }
        let r = delete_rule_bounded_with(
            &Failing,
            false,
            &["-p", "udp", "--dport", "443", "-j", "REJECT"],
        );
        assert!(
            r.is_err(),
            "a locked xtables must not be reported as a clean removal"
        );
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("unknown") || msg.contains("may still"),
            "{}",
            msg
        );
    }

    /// A spawn failure on the delete path is equally invisible today.
    #[test]
    fn test_spawn_failure_on_delete_is_an_error() {
        struct Broken;
        impl Executor for Broken {
            fn run(&self, _v6: bool, _args: &[&str]) -> ExecResult {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no iptables",
                ))
            }
        }
        assert!(delete_rule_bounded_with(
            &Broken,
            true,
            &["-p", "tcp", "--dport", "80", "-j", "DROP"]
        )
        .is_err());
    }
}

#[cfg(test)]
mod helper_identity_tests {
    use super::*;
    use std::path::PathBuf;

    /// Per-test fixture directory with a unique name, removed on drop. Every
    /// assertion below runs entirely inside it: no exec, no firewall mutation,
    /// no capability requirement.
    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            // Deliberately NOT under std::env::temp_dir(): /tmp is 1777, and the
            // production check rejects any group/world-writable ancestor — which
            // is correct for a privileged helper and means a /tmp fixture could
            // never be accepted. target/ is 0755 and owned by the build user.
            let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
            let dir = base.join(format!("albus-helper-{}-{}", tag, std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("fixture dir");
            // 0755: a group/world-writable ancestor is itself a rejection case.
            set_mode(&dir, 0o755);
            Self { dir }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[cfg(unix)]
    fn set_mode(p: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
    }

    #[cfg(unix)]
    fn uid_of(p: &Path) -> Option<u32> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).ok().map(|m| m.uid())
    }

    /// The suite runs as the build user, so "trusted owner" is injected rather
    /// than faked. Every OTHER rejection (directory, missing, dangling symlink,
    /// writable ancestor) is exercised by the real production logic.
    #[cfg(unix)]
    fn test_uids() -> Vec<libc::uid_t> {
        vec![0, unsafe { libc::getuid() }]
    }

    #[cfg(unix)]
    fn trusted(p: &Path) -> bool {
        helper_is_trusted_with(p, &test_uids())
    }

    /// A root-owned regular file with no writable ancestor is the accept case.
    /// Running the suite as an unprivileged user, "root-owned" is unreproducible,
    /// so the positive control accepts either trusted owner (root or the albus
    /// service account) and otherwise asserts the *other* rejections still bite.
    #[test]
    fn test_accepts_root_owned_regular_file() {
        let f = Fixture::new("accept");
        let p = f.path("iptables");
        std::fs::write(&p, b"#!/bin/true\n").expect("write");
        set_mode(&p, 0o755);

        let is_root_owned = uid_of(&p) == Some(0);
        let is_service = crate::core::ebpf::features::service_uid()
            .map(|su| su == uid_of(&p).unwrap_or(u32::MAX))
            .unwrap_or(false);

        assert!(
            trusted(&p),
            "a trusted-owned regular file at a non-writable path must be accepted \
             (root_owned={} service_owned={} uid={:?})",
            is_root_owned,
            is_service,
            uid_of(&p)
        );
    }

    /// EBPF-06: `exists()` accepted a directory, and the old code then exec'd it.
    #[test]
    fn test_rejects_directory() {
        let f = Fixture::new("dir");
        let p = f.path("iptables");
        std::fs::create_dir_all(&p).expect("dir");
        set_mode(&p, 0o755);
        assert!(
            !helper_is_trusted(&p),
            "a directory must never be selected as a helper"
        );
    }

    /// A path that does not exist, and a dangling symlink, must both fail.
    #[test]
    fn test_rejects_missing_and_dangling_symlink() {
        let f = Fixture::new("missing");
        assert!(!trusted(&f.path("nope")));

        #[cfg(unix)]
        {
            let link = f.path("dangling");
            std::os::unix::fs::symlink(f.path("gone"), &link).expect("symlink");
            assert!(
                !trusted(&link),
                "a dangling symlink must be rejected (metadata() cannot resolve it)"
            );
        }
    }

    /// The legitimate Arch layout is a symlink to xtables-nft-multi. Following
    /// it is required — what matters is that the RESOLVED target is trusted.
    #[test]
    fn test_symlink_to_trusted_target_is_accepted() {
        let f = Fixture::new("symlink-ok");
        let real = f.path("xtables-multi");
        std::fs::write(&real, b"#!/bin/true\n").expect("write");
        set_mode(&real, 0o755);
        let link = f.path("iptables");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, &link).expect("symlink");
            assert!(
                trusted(&link),
                "the shipped /usr/sbin/iptables -> xtables-nft-multi layout must keep working"
            );
        }
    }

    /// A symlink whose target lives under a group/world-writable directory is
    /// exactly the substitution the check exists to stop.
    #[test]
    fn test_rejects_symlink_into_untrusted_directory() {
        let f = Fixture::new("symlink-bad");
        let world = f.path("world");
        std::fs::create_dir_all(&world).expect("dir");
        std::fs::write(world.join("evil"), b"#!/bin/true\n").expect("write");
        set_mode(&world, 0o777);
        let link = f.path("iptables");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(world.join("evil"), &link).expect("symlink");
            assert!(
                !trusted(&link),
                "a helper reached through a world-writable directory must be rejected"
            );
        }
    }

    /// The whole point: the candidate list yields Err rather than guessing, so
    /// an absent helper is an explicit failure EBPF-01 can propagate.
    #[test]
    fn test_resolve_binary_reports_an_untrusted_or_absent_helper() {
        let f = Fixture::new("resolve");
        let good = f.path("good");
        std::fs::write(&good, b"#!/bin/true\n").expect("write");
        set_mode(&good, 0o755);
        let good_s = good.to_string_lossy().to_string();

        // A trusted candidate is selected and the untrusted one is skipped.
        let bad = f.path("bad");
        std::fs::write(&bad, b"#!/bin/true\n").expect("write");
        set_mode(&bad, 0o755);
        let _bad_s = bad.to_string_lossy().to_string();
        // make the "bad" one world-writable at its own path level is not enough;
        // instead drop trust via an untrusted owner is root-only, so use the
        // writable-ancestor route on a dedicated dir.
        let untrusted_dir = f.path("loose");
        std::fs::create_dir_all(&untrusted_dir).expect("dir");
        let inside = untrusted_dir.join("iptables");
        std::fs::write(&inside, b"#!/bin/true\n").expect("write");
        set_mode(&inside, 0o755);
        set_mode(&untrusted_dir, 0o777);
        let loose_s = inside.to_string_lossy().to_string();

        let uids = test_uids();
        let cands = vec![loose_s.as_str(), good_s.as_str()];
        assert_eq!(
            resolve_binary_with(&cands, &uids).expect("a trusted candidate exists"),
            std::fs::canonicalize(&good_s).expect("canonicalize good"),
            "an untrusted candidate must be skipped in favour of a trusted one"
        );

        let only_bad = vec![loose_s.as_str()];
        let err = resolve_binary_with(&only_bad, &uids).expect_err("must not guess");
        assert!(
            err.to_string().contains("no trusted"),
            "the failure must name the problem: {}",
            err
        );
    }

    /// P2: the path `resolve_binary_with` hands back must be the RESOLVED one —
    /// the same object `helper_trusted_real_path` vetted. Returning the original
    /// candidate string meant `Command::new` re-resolved it, so a symlink swapped
    /// after the check was never the file that got vetted.
    #[test]
    fn test_resolve_binary_returns_the_resolved_path() {
        let f = Fixture::new("resolved-exec");
        let real = f.path("iptables");
        std::fs::write(&real, "#!/bin/sh\n").expect("write helper");
        set_mode(&real, 0o755);
        let link = f.path("iptables-link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let uids = test_uids();
        let got = resolve_binary_with(&[link.to_str().expect("utf8")], &uids)
            .expect("a symlink to a trusted regular file is still trusted");

        assert_eq!(
            got,
            std::fs::canonicalize(&real).expect("canonicalize"),
            "the returned path must be the resolved target, not the candidate"
        );
        assert_ne!(
            got, link,
            "returning the candidate would leave a check-then-use window at exec time"
        );
    }

    /// P3: the helper's OWN mode was never checked, only its ancestors'. A
    /// world-writable /usr/sbin/iptables passes every other test here and is
    /// exec'd inside a capability-bearing daemon — the exact reasoning
    /// `service.rs` states for its own binary.
    #[test]
    fn test_world_writable_helper_is_refused() {
        let f = Fixture::new("loose-exec");
        let bin = f.path("iptables");
        std::fs::write(&bin, "#!/bin/sh\n").expect("write helper");
        set_mode(&bin, 0o777);

        let uids = test_uids();
        assert!(
            !helper_is_trusted_with(&bin, &uids),
            "a world-writable helper must not be trusted just because it is root-owned"
        );
        let err = resolve_binary_with(&[bin.to_str().expect("utf8")], &uids)
            .expect_err("a world-writable helper must not resolve");
        assert!(
            err.0.contains("no trusted iptables"),
            "unexpected error shape: {err:?}"
        );
    }
}
