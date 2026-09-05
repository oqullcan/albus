//! iptables and ip6tables packet filtering rules for quic fallback, webrtc stun drop, and dns leak kill-switch.

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

// enables fail-closed network lockdown: blocks outbound non-loopback tcp traffic on ports 80 and 443
// prevents unfragmented/unprotected web traffic from leaking to the isp if the ebpf subsystem fails
pub fn enable_network_lockdown() {
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

    info!("Network Lockdown ACTIVE (fail-closed) — outbound HTTP/HTTPS (ports 80, 443) blocked");
}

// purges fail-closed network lockdown rules
pub fn disable_network_lockdown() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flush_rule_nonexistent_binary() {
        // flush_rule should terminate quickly without panic even if the binary does not exist
        flush_rule("nonexistent_firewall_cmd_xyz", &["-D", "OUTPUT"]);
    }

    #[test]
    fn test_firewall_quic_lifecycle_no_panic() {
        block_quic();
        unblock_quic();
    }

    #[test]
    fn test_firewall_stun_lifecycle_no_panic() {
        block_stun();
        unblock_stun();
    }

    #[test]
    fn test_firewall_kill_switch_lifecycle_no_panic() {
        enable_kill_switch();
        disable_kill_switch();
    }

    #[test]
    fn test_firewall_network_lockdown_lifecycle_no_panic() {
        enable_network_lockdown();
        disable_network_lockdown();
    }
}
