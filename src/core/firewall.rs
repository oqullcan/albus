//! iptables and ip6tables packet filtering rules to enforce tcp fallback from http/3 quic.

use std::process::Command;
use tracing::{debug, info};

// injects icmp port unreachable / tcp reset via iptables reject on udp 443
pub fn block_quic() {
    let _ = Command::new("iptables")
        .args(["-I", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"])
        .status();

    let _ = Command::new("ip6tables")
        .args(["-I", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"])
        .status();

    info!("QUIC (UDP 443) blocked — forcing browsers to TCP for DPI bypass");
}

// purges injected reject rules from output filter chain
pub fn unblock_quic() {
    // iterate until no matching reject rules remain in ipv4 output chain
    while let Ok(status) = Command::new("iptables")
        .args(["-D", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"])
        .status()
    {
        if !status.success() {
            break;
        }
    }

    // iterate until no matching reject rules remain in ipv6 output chain
    while let Ok(status) = Command::new("ip6tables")
        .args(["-D", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"])
        .status()
    {
        if !status.success() {
            break;
        }
    }

    debug!("QUIC firewall rules cleaned up");
}
