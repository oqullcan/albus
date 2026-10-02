//! iptables and ip6tables packet filtering rules for quic fallback, webrtc stun drop, and dns leak kill-switch.

use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn};

const IPTABLES_CANDIDATES: &[&str] = &["/usr/sbin/iptables", "/sbin/iptables"];
const IP6TABLES_CANDIDATES: &[&str] = &["/usr/sbin/ip6tables", "/sbin/ip6tables"];
const MAX_RULE_DELETE_ITER: usize = 32;

fn resolve_binary<'a>(candidates: &'a [&str]) -> &'a str {
    for c in candidates {
        if Path::new(c).exists() {
            return c;
        }
    }
    // fallback to first candidate (will error clearly if missing)
    candidates.first().copied().unwrap_or("/usr/sbin/iptables")
}

fn iptables_base() -> Command {
    let bin = resolve_binary(IPTABLES_CANDIDATES);
    let mut c = Command::new(bin);
    c.env_clear();
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

fn ip6tables_base() -> Command {
    let bin = resolve_binary(IP6TABLES_CANDIDATES);
    let mut c = Command::new(bin);
    c.env_clear();
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

/// A firewall rule could not be installed. Carries the kernel-side reason so
/// the journal cannot claim a control is active when the packet filter never
/// accepted the rule.
pub type FwResult = Result<(), FirewallError>;

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
        let out = if v6 {
            ip6tables_base().args(args).output()
        } else {
            iptables_base().args(args).output()
        };
        match out {
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
fn delete_rule_bounded(v6: bool, args: &[&str]) -> usize {
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
            let status = if v6 {
                ip6tables_base().args(&del_args).status()
            } else {
                iptables_base().args(&del_args).status()
            };
            match status {
                Ok(s) if s.success() => {
                    removed += 1;
                    continue;
                }
                _ => break,
            }
        }
    }
    // FP-07: legacy unscoped phase REMOVED. It built `-D OUTPUT <args>` with no
    // `-m comment` match and ran unconditionally, stripping third-party
    // comment-less rules sharing the tuple. Pre-hardening residue (comment-less
    // albus rules) is fail-closed and stays until removed manually — documented
    // instead of blindly deleted. See REPORT run-1 FP-07.
    removed
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
pub fn unblock_quic() -> usize {
    let mut n = 0;
    n += delete_rule_bounded(false, &["-p", "udp", "--dport", "443", "-j", "REJECT"]);
    n += delete_rule_bounded(true, &["-p", "udp", "--dport", "443", "-j", "REJECT"]);

    debug!("QUIC firewall rules cleaned up");
    n
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
pub fn unblock_stun() -> usize {
    let mut n = 0;
    for port in &["3478", "5349"] {
        n += delete_rule_bounded(false, &["-p", "udp", "--dport", port, "-j", "REJECT"]);
        n += delete_rule_bounded(true, &["-p", "udp", "--dport", port, "-j", "REJECT"]);
    }

    debug!("STUN firewall rules cleaned up");
    n
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
pub fn disable_kill_switch() -> usize {
    // remove both DROP (new) and REJECT (legacy) variants to clean old installs.
    // FP-07: only comment-scoped deletes; pre-hardening comment-less residue stays.
    let mut n = 0;
    for target in ["DROP", "REJECT"] {
        let udp = ["!", "-o", "lo", "-p", "udp", "--dport", "53", "-j", target];
        let tcp = ["!", "-o", "lo", "-p", "tcp", "--dport", "53", "-j", target];
        let dot = ["!", "-o", "lo", "-p", "tcp", "--dport", "853", "-j", target];
        n += delete_rule_bounded(false, &udp);
        n += delete_rule_bounded(false, &tcp);
        n += delete_rule_bounded(false, &dot);
        n += delete_rule_bounded(true, &udp);
        n += delete_rule_bounded(true, &tcp);
        n += delete_rule_bounded(true, &dot);
    }

    debug!("DNS Kill-Switch deactivated");
    n
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
pub fn disable_network_lockdown() -> usize {
    let mut n = 0;
    for port in &["80", "443"] {
        for target in ["DROP", "REJECT"] {
            let rule = ["!", "-o", "lo", "-p", "tcp", "--dport", port, "-j", target];
            n += delete_rule_bounded(false, &rule);
            n += delete_rule_bounded(true, &rule);
        }
    }

    debug!("Network Lockdown deactivated — outbound HTTP/HTTPS restored");
    n
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
