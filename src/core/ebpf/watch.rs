//! Shaping-loss watchdog, v2: connection/event reconciliation.
//!
//! Model: the eBPF program emits exactly one perf event per newly
//! established tracked connection (target port, non-excluded). The worker
//! therefore expects: every NEW ESTABLISHED target-port connection visible
//! in /proc/net/tcp{,6} to be accompanied by fresh perf events in the same
//! window. New connections with zero new events over consecutive intervals
//! mean the program stopped firing (displaced, detached, or wedged) — trip
//! the fail-closed lockdown.
//!
//! Why not getsockopt probing (v1): on GSO/loopback paths the kernel
//! reports huge MSS values even with the clamp attached, so a local probe
//! reads Unhealthy on a healthy daemon and bricked the machine (incident
//! 2026-09-21). Why not BPF_PROG_QUERY: the reference kernel answers
//! EINVAL to every query variant. Measuring effects beats asking.
//!
//! Anti-false-positive rules (all unit-tested):
//! - first snapshot is BASELINE (pre-existing connections never count;
//!   they were established before we could observe their events),
//! - excluded IPs (DoH upstreams — BPF skips them by design) never count,
//! - idle windows (no new connections) reset suspicion,
//! - any fresh events reset suspicion (evidence of life),
//! - only two consecutive suspicious windows trip, once.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// ESTABLISHED sockets with a remote port in `target_ports` and a remote IP
/// outside the exclusion lists, minus already-known inodes. Identity is
/// (family, inode): `(4|6, inode)`.
pub fn newcomers(
    tcp4: &str,
    tcp6: &str,
    target_ports: &[u16],
    exclude_v4: &[Ipv4Addr],
    exclude_v6: &[Ipv6Addr],
    known: &mut HashSet<(u8, u64)>,
) -> HashSet<(u8, u64)> {
    let mut fresh = HashSet::new();
    for (port, inode, ip) in parse_tcp4(tcp4) {
        if !target_ports.contains(&port) || exclude_v4.contains(&ip) {
            continue;
        }
        if known.insert((4, inode)) {
            fresh.insert((4, inode));
        }
    }
    for (port, inode, ip) in parse_tcp6(tcp6) {
        if !target_ports.contains(&port) || exclude_v6.contains(&ip) {
            continue;
        }
        if known.insert((6, inode)) {
            fresh.insert((6, inode));
        }
    }
    fresh
}

/// Parse /proc/net/tcp ESTABLISHED rows into (remote port, inode, remote
/// IPv4). Malformed rows are skipped, never fatal. `known` is updated as a
/// side effect so callers only track one set... (no: kept pure — the caller
/// owns `known`; see newcomers).
pub fn parse_tcp4(content: &str) -> Vec<(u16, u64, Ipv4Addr)> {
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // sl local rem st ... inode(idx 9)
        if f.len() < 10 || f[3] != "01" {
            continue;
        }
        let Some((ip_hex, port_hex)) = f[2].rsplit_once(':') else {
            continue;
        };
        let (Ok(port), Some(ip)) = (u16::from_str_radix(port_hex, 16), parse_proc_ipv4(ip_hex))
        else {
            continue;
        };
        let Ok(inode) = f[9].parse::<u64>() else {
            continue;
        };
        out.push((port, inode, ip));
    }
    out
}

/// Parse /proc/net/tcp6 ESTABLISHED rows into (remote port, inode, remote
/// IPv6). Same skip-malformed discipline as parse_tcp4.
pub fn parse_tcp6(content: &str) -> Vec<(u16, u64, Ipv6Addr)> {
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || f[3] != "01" {
            continue;
        }
        let Some((ip_hex, port_hex)) = f[2].rsplit_once(':') else {
            continue;
        };
        let (Ok(port), Some(ip)) = (u16::from_str_radix(port_hex, 16), parse_proc_ipv6(ip_hex))
        else {
            continue;
        };
        let Ok(inode) = f[9].parse::<u64>() else {
            continue;
        };
        out.push((port, inode, ip));
    }
    out
}

/// IPv4 address as printed in /proc/net/tcp: 8 hex digits, byte-reversed
/// per 32-bit word on little-endian (e.g. "010011AC" == 172.17.0.1).
pub fn parse_proc_ipv4(hex8: &str) -> Option<Ipv4Addr> {
    if hex8.len() != 8 {
        return None;
    }
    let w = u32::from_str_radix(hex8, 16).ok()?;
    Some(Ipv4Addr::from(w.to_be()))
}

/// IPv6 address as printed in /proc/net/tcp6: 32 hex digits, each 32-bit
/// word byte-reversed (same quirk per group as v4).
pub fn parse_proc_ipv6(hex32: &str) -> Option<Ipv6Addr> {
    if hex32.len() != 32 {
        return None;
    }
    let mut groups = [0u16; 8];
    for (i, chunk) in hex32.as_bytes().chunks(8).enumerate() {
        let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        // same little-endian word quirk as v4: reverse to wire bytes
        let b = word.to_le_bytes();
        groups[i * 2] = u16::from_be_bytes([b[0], b[1]]);
        groups[i * 2 + 1] = u16::from_be_bytes([b[2], b[3]]);
    }
    Some(Ipv6Addr::new(
        groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7],
    ))
}

/// Watchdog streak state. Pure logic, fully unit-tested; the worker only
/// feeds snapshots and acts on `trip`.
///
/// Core invariant: an inode that first appears during a zero-event window
/// is UNEXPLAINED (no event ever accompanied it). Unexplained inodes that
/// survive (stay ESTABLISHED) across a second zero-event window trip.
/// Fresh events exonerate everything currently visible; dead inodes are
/// pruned so closed connections can neither trip nor shield.
#[derive(Debug, Default)]
pub struct WatchState {
    known: HashSet<(u8, u64)>,
    unexplained: HashSet<(u8, u64)>,
    last_events: u64,
    misses: u32,
    initialized: bool,
}

impl WatchState {
    /// Feed one interval. Returns true exactly when fail-closed must engage.
    pub fn observe(
        &mut self,
        tcp4: &str,
        tcp6: &str,
        target_ports: &[u16],
        exclude_v4: &[Ipv4Addr],
        exclude_v6: &[Ipv6Addr],
        events_seen: u64,
    ) -> bool {
        let fresh = newcomers(
            tcp4,
            tcp6,
            target_ports,
            exclude_v4,
            exclude_v6,
            &mut self.known,
        );
        // prune dead inodes from both sets (closed connections neither
        // accuse nor shield)
        {
            let mut live = HashSet::new();
            for (_, inode, _) in parse_tcp4(tcp4) {
                live.insert((4u8, inode));
            }
            for (_, inode, _) in parse_tcp6(tcp6) {
                live.insert((6u8, inode));
            }
            self.known.retain(|k| live.contains(k));
            self.unexplained.retain(|k| live.contains(k));
        }
        if !self.initialized {
            self.initialized = true;
            self.last_events = events_seen;
            return false; // baseline never trips
        }
        let events_delta = events_seen.saturating_sub(self.last_events);
        self.last_events = events_seen;
        if events_delta > 0 {
            // evidence of life: the program is firing, exonerate all
            self.unexplained.clear();
            self.misses = 0;
            return false;
        }
        // fresh inodes seen with zero accompanying events are unexplained
        for key in &fresh {
            self.unexplained.insert(*key);
        }
        if self.unexplained.is_empty() {
            self.misses = 0; // idle: nothing to be suspicious of
            return false;
        }
        self.misses = self.misses.saturating_add(1);
        self.misses >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T6EMPTY: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    // 172.17.0.1:443 ESTABLISHED inode 100; 93.184.216.34:80 non-target; 1.1.1.1:443 TIME_WAIT
    const T4: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 010011AC:01BB 01 00000000:00000000 00:00000000 00000000     0        0 100 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:1F91 22D8B85D:0050 01 00000000:00000000 00:00000000 00000000     0        0 101 1 0000000000000000 100 0 0 10 0\n   2: 0100007F:1F92 01010101:01BB 06 00000000:00000000 00:00000000 00000000     0        0 102 1 0000000000000000 100 0 0 10 0\n";

    #[test]
    fn test_parse_proc_ipv4_quirk() {
        assert_eq!(
            parse_proc_ipv4("010011AC"),
            Some(Ipv4Addr::new(172, 17, 0, 1))
        );
        assert_eq!(
            parse_proc_ipv4("0100007F"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(parse_proc_ipv4("ZZZZZZZZ"), None);
        assert_eq!(parse_proc_ipv4("123"), None);
    }

    #[test]
    fn test_parse_proc_ipv6_shape() {
        // ::1 prints with the last word byte-swapped ("01000000")
        assert_eq!(
            parse_proc_ipv6("00000000000000000000000001000000"),
            Some(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(parse_proc_ipv6("short"), None);
        assert_eq!(parse_proc_ipv6(&"zz".repeat(16)), None);
    }

    #[test]
    fn test_parse_tcp4_filters() {
        let rows = parse_tcp4(T4);
        // all three ESTABLISHED-or-not rows parse; filtering happens in newcomers
        assert_eq!(rows.len(), 2, "TIME_WAIT row must be skipped: {:?}", rows);
        assert!(rows.iter().any(|(p, i, _)| *p == 443 && *i == 100));
    }

    #[test]
    fn test_newcomers_target_and_exclude() {
        let mut known = HashSet::new();
        let fresh = newcomers(T4, T6EMPTY, &[443], &[], &[], &mut known);
        assert_eq!(fresh, HashSet::from([(4u8, 100u64)]));
        // excluded IP never counts (DoH upstreams emit no events by design)
        let mut known_excl = HashSet::new();
        let fresh2 = newcomers(
            T4,
            T6EMPTY,
            &[443],
            &[Ipv4Addr::new(172, 17, 0, 1)],
            &[],
            &mut known_excl,
        );
        assert!(fresh2.is_empty());
        // known inodes are not fresh twice
        let fresh3 = newcomers(T4, T6EMPTY, &[443], &[], &[], &mut known);
        assert!(fresh3.is_empty());
    }

    #[test]
    fn test_watch_baseline_trip_and_reset() {
        let mut w = WatchState::default();
        // interval 1: baseline, never trips even with fresh conns
        assert!(!w.observe(T4, T6EMPTY, &[443], &[], &[], 0));
        // interval 2: same conns known now -> idle -> reset, no trip
        assert!(!w.observe(T4, T6EMPTY, &[443], &[], &[], 0));
        // interval 3: a NEW connection, still no events -> miss 1, no trip
        let t4b = T4.to_string()
            + "   3: 0100007F:1F93 0B0B0B0B:01BB 01 00000000:00000000 00:00000000 00000000     0        0 200 1 0000000000000000 100 0 0 10 0\n";
        assert!(!w.observe(&t4b, T6EMPTY, &[443], &[], &[], 0));
        // interval 4: still no events -> miss 2 -> TRIP
        assert!(w.observe(&t4b, T6EMPTY, &[443], &[], &[], 0));
        // interval 5: the unexplained connection closed -> pruned, reset
        assert!(!w.observe(T4, T6EMPTY, &[443], &[], &[], 0));
        // fresh WatchState: events reset suspicion
        let mut w2 = WatchState::default();
        assert!(!w2.observe(T4, T6EMPTY, &[443], &[], &[], 0));
        assert!(!w2.observe(&t4b, T6EMPTY, &[443], &[], &[], 5));
    }

    #[test]
    fn test_malformed_tables_never_panic() {
        let junk = ["", "\n", "garbage line here\n", "  sl  x\n", "0: a b c\n"];
        for j in junk {
            let _ = parse_tcp4(j);
            let _ = parse_tcp6(j);
            let mut w = WatchState::default();
            let _ = w.observe(j, j, &[443], &[], &[], 0);
        }
    }
}
