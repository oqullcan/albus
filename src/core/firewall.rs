//! iptables and ip6tables packet filtering rules for quic fallback, webrtc stun drop, and dns leak kill-switch.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use tracing::{debug, info};

// injects icmp port unreachable / tcp reset via iptables reject on udp 443
pub fn block_quic() {
    let _ = Command::new("iptables")
        .args([
            "-I", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT",
        ])
        .status();

    let _ = Command::new("ip6tables")
        .args([
            "-I", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT",
        ])
        .status();

    info!("QUIC (UDP 443) blocked — forcing browsers to TCP for DPI bypass");
}

// helper to delete iptables rules up to a bounded maximum iterations
fn flush_rule(cmd: &str, args: &[&str]) {
    for _ in 0..50 {
        match Command::new(cmd).args(args).status() {
            Ok(status) if status.success() => continue,
            _ => break,
        }
    }
}

// purges injected reject rules for udp 443
pub fn unblock_quic() {
    flush_rule(
        "iptables",
        &[
            "-D", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT",
        ],
    );
    flush_rule(
        "ip6tables",
        &[
            "-D", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT",
        ],
    );

    debug!("QUIC firewall rules cleaned up");
}

// blocks outbound webrtc stun traffic (udp 3478, 5349) to prevent client public/local ip leaks
pub fn block_stun() {
    for port in &["3478", "5349"] {
        let _ = Command::new("iptables")
            .args(["-I", "OUTPUT", "-p", "udp", "--dport", port, "-j", "REJECT"])
            .status();

        let _ = Command::new("ip6tables")
            .args(["-I", "OUTPUT", "-p", "udp", "--dport", port, "-j", "REJECT"])
            .status();
    }

    info!("WebRTC STUN (UDP 3478, 5349) blocked — preventing browser IP address leaks");
}

// purges stun packet filtering rules
pub fn unblock_stun() {
    for port in &["3478", "5349"] {
        flush_rule(
            "iptables",
            &["-D", "OUTPUT", "-p", "udp", "--dport", port, "-j", "REJECT"],
        );
        flush_rule(
            "ip6tables",
            &["-D", "OUTPUT", "-p", "udp", "--dport", port, "-j", "REJECT"],
        );
    }

    debug!("STUN firewall rules cleaned up");
}

// enables strict dns kill-switch: drops all non-loopback outbound port 53 traffic
// guarantees no application or rogue dhcp server can leak plaintext dns to the isp
pub fn enable_kill_switch() {
    // block unencrypted udp and tcp port 53 leaving non-loopback interfaces
    let _ = Command::new("iptables")
        .args([
            "-I", "OUTPUT", "!", "-o", "lo", "-p", "udp", "--dport", "53", "-j", "REJECT",
        ])
        .status();
    let _ = Command::new("iptables")
        .args([
            "-I", "OUTPUT", "!", "-o", "lo", "-p", "tcp", "--dport", "53", "-j", "REJECT",
        ])
        .status();

    let _ = Command::new("ip6tables")
        .args([
            "-I", "OUTPUT", "!", "-o", "lo", "-p", "udp", "--dport", "53", "-j", "REJECT",
        ])
        .status();
    let _ = Command::new("ip6tables")
        .args([
            "-I", "OUTPUT", "!", "-o", "lo", "-p", "tcp", "--dport", "53", "-j", "REJECT",
        ])
        .status();

    info!("DNS Kill-Switch ACTIVE — all non-loopback plaintext DNS queries blocked");
}

// removes dns kill-switch filtering rules
pub fn disable_kill_switch() {
    flush_rule(
        "iptables",
        &[
            "-D", "OUTPUT", "!", "-o", "lo", "-p", "udp", "--dport", "53", "-j", "REJECT",
        ],
    );
    flush_rule(
        "iptables",
        &[
            "-D", "OUTPUT", "!", "-o", "lo", "-p", "tcp", "--dport", "53", "-j", "REJECT",
        ],
    );
    flush_rule(
        "ip6tables",
        &[
            "-D", "OUTPUT", "!", "-o", "lo", "-p", "udp", "--dport", "53", "-j", "REJECT",
        ],
    );
    flush_rule(
        "ip6tables",
        &[
            "-D", "OUTPUT", "!", "-o", "lo", "-p", "tcp", "--dport", "53", "-j", "REJECT",
        ],
    );

    debug!("DNS Kill-Switch deactivated");
}

/// Enables fail-closed network lockdown with connection state tracking and DoH resolver exemptions.
///
/// # Architecture & Threat Model
/// When the eBPF subsystem fails or is intentionally disabled while `network_lockdown = true`
/// is configured, Albus enters a strict "fail-closed" state to prevent unfragmented/unprotected
/// HTTP/HTTPS traffic from leaking to the ISP.
///
/// # Connection State & DoH Exemption Mechanism
/// 1. Stateful Conntrack: Injects `-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`
///    to ensure active sessions and protocol handshakes are not abruptly severed.
/// 2. DoH Resolver Exceptions: Explicitly allows outbound TCP port 443 traffic destined
///    to the configured upstream DoH resolver IP endpoints (`exempt_v4` and `exempt_v6`).
///    Without these exemptions, blocking port 443 would kill the daemon's own DoH connections,
///    causing total DNS failure and breaking connectivity entirely.
/// 3. Fail-Closed Web Quarantine: Rejects all other outbound TCP traffic on ports 80 and 443
///    originating from non-loopback interfaces.
pub fn enable_network_lockdown_with_exemptions(exempt_v4: &[Ipv4Addr], exempt_v6: &[Ipv6Addr]) {
    // 1. Inject blanket REJECT rules for non-loopback HTTP/HTTPS (ports 80, 443)
    for port in &["80", "443"] {
        let _ = Command::new("iptables")
            .args([
                "-I", "OUTPUT", "!", "-o", "lo", "-p", "tcp", "--dport", port, "-j", "REJECT",
            ])
            .status();

        let _ = Command::new("ip6tables")
            .args([
                "-I", "OUTPUT", "!", "-o", "lo", "-p", "tcp", "--dport", port, "-j", "REJECT",
            ])
            .status();
    }

    // 2. Prepend DoH resolver IP exemptions so they take precedence over the REJECT rules
    for ip in exempt_v4 {
        let _ = Command::new("iptables")
            .args([
                "-I",
                "OUTPUT",
                "-p",
                "tcp",
                "-d",
                &ip.to_string(),
                "--dport",
                "443",
                "-j",
                "ACCEPT",
            ])
            .status();
    }
    for ip in exempt_v6 {
        let _ = Command::new("ip6tables")
            .args([
                "-I",
                "OUTPUT",
                "-p",
                "tcp",
                "-d",
                &ip.to_string(),
                "--dport",
                "443",
                "-j",
                "ACCEPT",
            ])
            .status();
    }

    // 3. Prepend conntrack state matching at the very top of OUTPUT chain
    let _ = Command::new("iptables")
        .args([
            "-I",
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ])
        .status();
    let _ = Command::new("ip6tables")
        .args([
            "-I",
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ])
        .status();

    info!(
        exempt_v4_count = exempt_v4.len(),
        exempt_v6_count = exempt_v6.len(),
        "Network Lockdown ACTIVE (fail-closed) — stateful conntrack active, upstream DoH endpoints exempted, outbound HTTP/HTTPS blocked"
    );
}

/// Convenience wrapper for enabling network lockdown without explicit exemptions.
pub fn enable_network_lockdown() {
    enable_network_lockdown_with_exemptions(&[], &[]);
}

/// Purges fail-closed network lockdown rules, connection tracking filters, and resolver exemptions.
pub fn disable_network_lockdown_with_exemptions(exempt_v4: &[Ipv4Addr], exempt_v6: &[Ipv6Addr]) {
    // 1. Flush conntrack state filter
    flush_rule(
        "iptables",
        &[
            "-D",
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    );
    flush_rule(
        "ip6tables",
        &[
            "-D",
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    );

    // 2. Flush DoH exemptions
    for ip in exempt_v4 {
        flush_rule(
            "iptables",
            &[
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "-d",
                &ip.to_string(),
                "--dport",
                "443",
                "-j",
                "ACCEPT",
            ],
        );
    }
    for ip in exempt_v6 {
        flush_rule(
            "ip6tables",
            &[
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "-d",
                &ip.to_string(),
                "--dport",
                "443",
                "-j",
                "ACCEPT",
            ],
        );
    }

    // 3. Flush REJECT rules
    for port in &["80", "443"] {
        flush_rule(
            "iptables",
            &[
                "-D", "OUTPUT", "!", "-o", "lo", "-p", "tcp", "--dport", port, "-j", "REJECT",
            ],
        );
        flush_rule(
            "ip6tables",
            &[
                "-D", "OUTPUT", "!", "-o", "lo", "-p", "tcp", "--dport", port, "-j", "REJECT",
            ],
        );
    }

    debug!("Network Lockdown deactivated — outbound HTTP/HTTPS restored");
}

/// Convenience wrapper for disabling network lockdown.
pub fn disable_network_lockdown() {
    disable_network_lockdown_with_exemptions(&[], &[]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flush_rule_nonexistent_binary() {
        // flush_rule should terminate quickly without panic even if the binary does not exist
        flush_rule("nonexistent_firewall_cmd_xyz", &["-D", "OUTPUT"]);
    }

    #[test]
    fn test_flush_rule_loop_termination() {
        // "false" immediately exits with non-zero status; flush_rule terminates on first attempt
        flush_rule("false", &[]);
        // "true" exits with 0; flush_rule terminates after at most 50 iterations
        flush_rule("true", &[]);
    }
}
