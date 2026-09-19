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

/// Idempotent insert: `iptables -C ... || iptables -I ...`
fn ensure_rule(v6: bool, args: &[&str], comment: &str) {
    let mut check_args: Vec<&str> = vec!["-C"];
    check_args.extend_from_slice(args);
    let check_ok = if v6 {
        ip6tables_base()
            .args(&check_args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        iptables_base()
            .args(&check_args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if check_ok {
        return;
    }
    let mut insert_args: Vec<&str> = vec!["-I", "OUTPUT"];
    insert_args.extend_from_slice(args);
    insert_args.extend_from_slice(&["-m", "comment", "--comment", comment]);
    // strip duplicate OUTPUT if caller included it
    let res = if v6 {
        ip6tables_base().args(&insert_args[1..]).status()
    } else {
        iptables_base().args(&insert_args[1..]).status()
    };
    if let Err(e) = res {
        warn!("failed to insert firewall rule {:?}: {}", args, e);
    }
}

/// Bounded delete: avoids infinite loop if binary is shimmed.
fn delete_rule_bounded(v6: bool, args: &[&str]) {
    for _ in 0..MAX_RULE_DELETE_ITER {
        let mut del_args: Vec<&str> = vec!["-D", "OUTPUT"];
        del_args.extend_from_slice(args);
        let status = if v6 {
            ip6tables_base().args(&del_args[1..]).status()
        } else {
            iptables_base().args(&del_args[1..]).status()
        };
        match status {
            Ok(s) if s.success() => continue,
            _ => break,
        }
    }
    // also try with comment match (for rules created by new version)
    for _ in 0..MAX_RULE_DELETE_ITER {
        let mut del_args: Vec<&str> = vec!["-D", "OUTPUT"];
        del_args.extend_from_slice(args);
        del_args.extend_from_slice(&["-m", "comment", "--comment", "albus"]);
        let status = if v6 {
            ip6tables_base().args(&del_args[1..]).status()
        } else {
            iptables_base().args(&del_args[1..]).status()
        };
        match status {
            Ok(s) if s.success() => continue,
            _ => break,
        }
    }
}

// injects icmp port unreachable / tcp reset via iptables reject on udp 443
pub fn block_quic() {
    ensure_rule(
        false,
        &["-p", "udp", "--dport", "443", "-j", "REJECT"],
        "albus-quic",
    );
    ensure_rule(
        true,
        &["-p", "udp", "--dport", "443", "-j", "REJECT"],
        "albus-quic",
    );

    info!("QUIC (UDP 443) blocked — forcing browsers to TCP for DPI bypass");
}

// purges injected reject rules for udp 443
pub fn unblock_quic() {
    delete_rule_bounded(false, &["-p", "udp", "--dport", "443", "-j", "REJECT"]);
    delete_rule_bounded(true, &["-p", "udp", "--dport", "443", "-j", "REJECT"]);

    debug!("QUIC firewall rules cleaned up");
}

// blocks outbound webrtc stun traffic (udp 3478, 5349) to prevent client public/local ip leaks
pub fn block_stun() {
    for port in &["3478", "5349"] {
        ensure_rule(
            false,
            &["-p", "udp", "--dport", port, "-j", "REJECT"],
            "albus-stun",
        );
        ensure_rule(
            true,
            &["-p", "udp", "--dport", port, "-j", "REJECT"],
            "albus-stun",
        );
    }

    info!("WebRTC STUN (UDP 3478, 5349) blocked — preventing browser IP address leaks");
}

// purges stun packet filtering rules
pub fn unblock_stun() {
    for port in &["3478", "5349"] {
        delete_rule_bounded(false, &["-p", "udp", "--dport", port, "-j", "REJECT"]);
        delete_rule_bounded(true, &["-p", "udp", "--dport", port, "-j", "REJECT"]);
    }

    debug!("STUN firewall rules cleaned up");
}

// enables strict dns kill-switch: drops all non-loopback outbound port 53 traffic
// guarantees no application or rogue dhcp server can leak plaintext dns to the isp
// NOTE: uses DROP (stealth) instead of REJECT to avoid signaling DPI/middleboxes.
pub fn enable_kill_switch() {
    let udp = ["!", "-o", "lo", "-p", "udp", "--dport", "53", "-j", "DROP"];
    let tcp = ["!", "-o", "lo", "-p", "tcp", "--dport", "53", "-j", "DROP"];
    // DoT 853 also blocked to prevent plaintext-adjacent leak
    let dot = ["!", "-o", "lo", "-p", "tcp", "--dport", "853", "-j", "DROP"];
    ensure_rule(false, &udp, "albus-kill");
    ensure_rule(false, &tcp, "albus-kill");
    ensure_rule(false, &dot, "albus-kill");
    ensure_rule(true, &udp, "albus-kill");
    ensure_rule(true, &tcp, "albus-kill");
    ensure_rule(true, &dot, "albus-kill");

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
// prevents unfragmented/unprotected web traffic from leaking to the isp if the ebpf subsystem fails
pub fn enable_network_lockdown() {
    for port in &["80", "443"] {
        let rule = ["!", "-o", "lo", "-p", "tcp", "--dport", port, "-j", "DROP"];
        ensure_rule(false, &rule, "albus-lockdown");
        ensure_rule(true, &rule, "albus-lockdown");
    }

    info!("Network Lockdown ACTIVE (fail-closed) — outbound HTTP/HTTPS (ports 80, 443) blocked");
}

// purges fail-closed network lockdown rules
pub fn disable_network_lockdown() {
    for port in &["80", "443"] {
        for target in ["DROP", "REJECT"] {
            let rule = ["!", "-o", "lo", "-p", "tcp", "--dport", port, "-j", target];
            delete_rule_bounded(false, &rule);
            delete_rule_bounded(true, &rule);
        }
    }

    debug!("Network Lockdown deactivated — outbound HTTP/HTTPS restored");
}
