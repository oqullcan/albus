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

/// Idempotent insert: `iptables -C OUTPUT ... || iptables -I OUTPUT ...`
fn ensure_rule(v6: bool, args: &[&str], comment: &str) {
    let mut spec: Vec<&str> = Vec::with_capacity(args.len() + 4);
    spec.extend_from_slice(args);
    spec.extend_from_slice(&["-m", "comment", "--comment", comment]);

    let mut check_args: Vec<&str> = vec!["-C", "OUTPUT"];
    check_args.extend_from_slice(&spec);
    // use output() so the expected "Bad rule" miss on absent rules stays out of the journal
    let check_ok = if v6 {
        ip6tables_base()
            .args(&check_args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    } else {
        iptables_base()
            .args(&check_args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    if check_ok {
        return;
    }
    let mut insert_args: Vec<&str> = vec!["-I", "OUTPUT"];
    insert_args.extend_from_slice(&spec);
    match if v6 {
        ip6tables_base().args(&insert_args).status()
    } else {
        iptables_base().args(&insert_args).status()
    } {
        Err(e) => warn!("failed to spawn firewall binary for {:?}: {}", args, e),
        Ok(s) if !s.success() => warn!(
            "firewall insert exited {} for {:?} (rule not applied)",
            s.code().unwrap_or(-1),
            args
        ),
        _ => {}
    }
}

/// Marker proving albus was installed on this machine (written on successful
/// install, removed on uninstall). Gates the legacy uncommented-rule sweep
/// below: without it, a textually identical administrator rule could be
/// removed by mistake.
pub const MANAGED_MARKER_PATH: &str = "/etc/albus/.managed";

fn managed_install_present() -> bool {
    managed_install_present_at(MANAGED_MARKER_PATH)
}

fn managed_install_present_at(path: &str) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_file(),
        Err(_) => false,
    }
}

/// Bounded delete: avoids infinite loop if binary is shimmed.
/// Returns true when at least one commented (ours, namespaced) rule was
/// removed; the legacy uncommented sweep only runs then, or when the
/// managed-install marker proves albus lived here — otherwise an
/// administrator rule identical to ours would be indistinguishable.
fn delete_rule_bounded(v6: bool, args: &[&str]) -> bool {
    let mut removed_any = false;
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
                    removed_any = true;
                    continue;
                }
                _ => break,
            }
        }
    }
    // 2. legacy rules without comment match (pre-hardening installs).
    if removed_any || managed_install_present() {
        for _ in 0..MAX_RULE_DELETE_ITER {
            let mut del_args: Vec<&str> = vec!["-D", "OUTPUT"];
            del_args.extend_from_slice(args);
            let status = if v6 {
                ip6tables_base().args(&del_args).status()
            } else {
                iptables_base().args(&del_args).status()
            };
            match status {
                Ok(s) if s.success() => continue,
                _ => break,
            }
        }
    }
    removed_any
}

// pure rule-spec constructors below: every iptables invocation in this
// module goes through these, so ordering/content is unit-testable
// without root. Comment strings namespace each feature for safe deletion.

fn quic_rule_specs() -> Vec<(Vec<&'static str>, &'static str)> {
    vec![(
        vec!["-p", "udp", "--dport", "443", "-j", "REJECT"],
        "albus-quic",
    )]
}

fn stun_rule_specs() -> Vec<(Vec<&'static str>, &'static str)> {
    ["3478", "5349"]
        .iter()
        .map(|port| {
            (
                vec!["-p", "udp", "--dport", port, "-j", "REJECT"],
                "albus-stun",
            )
        })
        .collect()
}

fn kill_switch_rule_specs() -> Vec<(Vec<&'static str>, &'static str)> {
    let mut specs = Vec::new();
    for proto in ["udp", "tcp"] {
        specs.push((
            vec!["!", "-o", "lo", "-p", proto, "--dport", "53", "-j", "DROP"],
            "albus-kill",
        ));
    }
    // DoT 853 also blocked to prevent plaintext-adjacent leak
    specs.push((
        vec!["!", "-o", "lo", "-p", "tcp", "--dport", "853", "-j", "DROP"],
        "albus-kill",
    ));
    specs
}

// injects icmp port unreachable / tcp reset via iptables reject on udp 443
pub fn block_quic() {
    for (spec, comment) in quic_rule_specs() {
        ensure_rule(false, &spec, comment);
        ensure_rule(true, &spec, comment);
    }

    info!("QUIC (UDP 443) blocked — forcing browsers to TCP for DPI bypass");
}

// purges injected reject rules for udp 443
pub fn unblock_quic() {
    for (spec, _) in quic_rule_specs() {
        delete_rule_bounded(false, &spec);
        delete_rule_bounded(true, &spec);
    }

    debug!("QUIC firewall rules cleaned up");
}

// blocks outbound webrtc stun traffic (udp 3478, 5349) to prevent client public/local ip leaks
pub fn block_stun() {
    for (spec, comment) in stun_rule_specs() {
        ensure_rule(false, &spec, comment);
        ensure_rule(true, &spec, comment);
    }

    info!("WebRTC STUN (UDP 3478, 5349) blocked — preventing browser IP address leaks");
}

// purges stun packet filtering rules
pub fn unblock_stun() {
    for (spec, _) in stun_rule_specs() {
        delete_rule_bounded(false, &spec);
        delete_rule_bounded(true, &spec);
    }

    debug!("STUN firewall rules cleaned up");
}

// enables strict dns kill-switch: drops all non-loopback outbound port 53 traffic
// guarantees no application or rogue dhcp server can leak plaintext dns to the isp
// NOTE: uses DROP (stealth) instead of REJECT to avoid signaling DPI/middleboxes.
pub fn enable_kill_switch() {
    for (spec, comment) in kill_switch_rule_specs() {
        ensure_rule(false, &spec, comment);
        ensure_rule(true, &spec, comment);
    }

    info!("DNS Kill-Switch ACTIVE — all non-loopback plaintext DNS queries blocked");
}

// removes dns kill-switch filtering rules
pub fn disable_kill_switch() {
    // remove both DROP (new) and REJECT (legacy) variants to clean old installs
    for target in ["DROP", "REJECT"] {
        let udp = ["!", "-o", "lo", "-p", "udp", "--dport", "53", "-j", target];
        let tcp = ["!", "-o", "lo", "-p", "tcp", "--dport", "53", "-j", target];
        let dot = ["!", "-o", "lo", "-p", "tcp", "--dport", "853", "-j", target];
        // legacy rules had no comment; bounded delete handles both
        delete_rule_bounded(false, &udp);
        delete_rule_bounded(false, &tcp);
        delete_rule_bounded(false, &dot);
        delete_rule_bounded(true, &udp);
        delete_rule_bounded(true, &tcp);
        delete_rule_bounded(true, &dot);
    }

    debug!("DNS Kill-Switch deactivated");
}

// enables fail-closed network lockdown: blocks outbound non-loopback tcp traffic on ports 80 and 443
// prevents unfragmented/unprotected web traffic from leaking to the isp if the ebpf subsystem fails.
//
// Ordered specs (ACCEPT first): already-established flows — including the
// daemon's own upstream DoH connections — are exempted via conntrack state,
// so lockdown drops only NEW unprotected flows instead of killing DNS too.
fn lockdown_rule_specs<'a>(port: &'a str) -> Vec<(Vec<&'a str>, &'static str)> {
    vec![
        (
            vec![
                "!",
                "-o",
                "lo",
                "-p",
                "tcp",
                "--dport",
                port,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            "albus-lockdown",
        ),
        (
            vec!["!", "-o", "lo", "-p", "tcp", "--dport", port, "-j", "DROP"],
            "albus-lockdown",
        ),
    ]
}

pub fn enable_network_lockdown() {
    for port in &["80", "443"] {
        // insert in reverse: `ensure_rule` prepends (`-I OUTPUT`), so the
        // ACCEPT fast-path must be inserted last to land on top.
        for (spec, comment) in lockdown_rule_specs(port).iter().rev() {
            ensure_rule(false, spec, comment);
            ensure_rule(true, spec, comment);
        }
    }

    info!("Network Lockdown ACTIVE (fail-closed) — outbound HTTP/HTTPS (ports 80, 443) blocked");
}

// purges fail-closed network lockdown rules
pub fn disable_network_lockdown() {
    for port in &["80", "443"] {
        for (spec, _) in lockdown_rule_specs(port) {
            delete_rule_bounded(false, &spec);
            delete_rule_bounded(true, &spec);
        }
        // legacy DROP/REJECT shapes without comments (pre-hardening installs)
        for target in ["DROP", "REJECT"] {
            let rule = ["!", "-o", "lo", "-p", "tcp", "--dport", port, "-j", target];
            delete_rule_bounded(false, &rule);
            delete_rule_bounded(true, &rule);
        }
    }

    debug!("Network Lockdown deactivated — outbound HTTP/HTTPS restored");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockdown_accept_precedes_drop() {
        // the conntrack fast-path must sort before the DROP, otherwise the
        // daemon's own established DoH connections die with lockdown on.
        for port in ["80", "443"] {
            let specs = lockdown_rule_specs(port);
            assert_eq!(specs.len(), 2);
            let accept = specs[0].0.join(" ");
            let drop = specs[1].0.join(" ");
            assert!(
                accept.contains("conntrack")
                    && accept.contains("ESTABLISHED,RELATED")
                    && accept.ends_with("ACCEPT"),
                "first spec must be the established fast-path: {}",
                accept
            );
            assert!(drop.ends_with("DROP"), "second spec must drop: {}", drop);
            assert!(accept.contains(port) && drop.contains(port));
            assert_eq!(specs[0].1, "albus-lockdown");
            assert_eq!(specs[1].1, "albus-lockdown");
        }
    }

    fn spec_strs(specs: &[(Vec<&str>, &str)]) -> Vec<String> {
        specs
            .iter()
            .map(|(args, comment)| format!("{} #{}", args.join(" "), comment))
            .collect()
    }

    #[test]
    fn test_quic_specs_shape() {
        let specs = quic_rule_specs();
        assert_eq!(specs.len(), 1);
        let s = spec_strs(&specs);
        assert!(s[0].contains("--dport 443"), "{}", s[0]);
        assert!(s[0].ends_with("REJECT #albus-quic"), "{}", s[0]);
        assert!(!s[0].contains("-o lo"), "quic rule is not loopback-scoped");
    }

    #[test]
    fn test_stun_specs_cover_both_ports() {
        let specs = stun_rule_specs();
        assert_eq!(specs.len(), 2);
        let joined = spec_strs(&specs).join("\n");
        assert!(joined.contains("--dport 3478"), "{}", joined);
        assert!(joined.contains("--dport 5349"), "{}", joined);
        for (args, comment) in &specs {
            assert_eq!(*comment, "albus-stun");
            assert!(args.contains(&"-j") && args.contains(&"REJECT"));
        }
    }

    #[test]
    fn test_kill_switch_specs_shape() {
        let specs = kill_switch_rule_specs();
        assert_eq!(specs.len(), 3);
        let joined = spec_strs(&specs).join("\n");
        // udp/53 + tcp/53 + tcp/853, all non-loopback DROP
        assert!(joined.contains("-p udp --dport 53"), "{}", joined);
        assert!(joined.contains("-p tcp --dport 53"), "{}", joined);
        assert!(joined.contains("--dport 853"), "{}", joined);
        for (args, comment) in &specs {
            assert_eq!(*comment, "albus-kill");
            assert!(args.contains(&"!") && args.contains(&"lo"));
            assert!(args.last() == Some(&"DROP"));
        }
    }

    #[test]
    fn test_managed_marker_gating() {
        let dir = std::env::temp_dir().join(format!(
            "albus_fw_marker_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let marker = dir.join(".managed");
        let missing = dir.join("absent");
        // absent -> false
        assert!(!managed_install_present_at(missing.to_str().unwrap()));
        // regular file -> true
        std::fs::write(&marker, "managed\n").unwrap();
        assert!(managed_install_present_at(marker.to_str().unwrap()));
        // symlink (even to a file) -> false, never follow
        let link = dir.join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&marker, &link).unwrap();
        #[cfg(unix)]
        assert!(!managed_install_present_at(link.to_str().unwrap()));
        // directory -> false
        assert!(!managed_install_present_at(dir.to_str().unwrap()));
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&marker);
        let _ = std::fs::remove_dir(&dir);
    }
}
