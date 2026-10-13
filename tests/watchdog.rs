//! Shaping-watchdog displacement scenario (no root, no eBPF, fully offline).
//!
//! Models a displaced/dead eBPF program: fresh ESTABLISHED target-port
//! connections keep appearing in /proc/net/tcp while the perf-event
//! counter stays flat (a firing program emits one event per new tracked
//! connection). Uses REAL /proc snapshots around a REAL loopback
//! connection we own, so the parser and the state machine are exercised
//! together — only the event counter is synthesized (0 = displaced).
//!
//! Contrast case pins the anti-false-positive direction: identical
//! snapshots WITH fresh events must never trip.

use albus::core::ebpf::watch::{WatchState, Window};

/// Target ports shared by the fixtures: each test binds one loopback port and
/// passes the same list, so the slice is stored per-test in a leaked one-shot
/// box (a test-only convenience; the production caller owns `&watch_ports`).
fn win<'a>(t4: &'a str, t6: &'a str, port: u16, events: u64) -> Window<'a> {
    let ports: &'static [u16] = Box::leak(Box::new([port]));
    Window {
        tcp4: t4,
        tcp6: t6,
        target_ports: ports,
        exclude_v4: &[],
        exclude_v6: &[],
        events_seen: events,
    }
}
use std::io::Read;
use std::net::TcpListener;

fn read_proc(name: &str) -> String {
    let mut s = String::new();
    let _ =
        std::fs::File::open(format!("/proc/net/{name}")).and_then(|mut f| f.read_to_string(&mut s));
    s
}

fn snapshots() -> (String, String) {
    (read_proc("tcp"), read_proc("tcp6"))
}

#[test]
fn watchdog_trips_when_connections_outlive_events() {
    // own listener on an ephemeral loopback port: only OUR sockets can
    // ever match the target set, so the test is hermetic.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();

    let mut w = WatchState::default();
    // window 1: baseline (never trips, establishes `known`)
    let (t4, t6) = snapshots();
    assert!(!w.observe(&t4, &t6, &[port], &[], &[], 0));

    // fresh ESTABLISHED connection our program (if alive) would report
    let _client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let (t4, t6) = snapshots();
    // window 2: first zero-event window with a newcomer — suspicious, no trip
    assert!(
        !w.observe(&t4, &t6, &[port], &[], &[], 0),
        "first unexplained window must not trip"
    );
    // window 3: newcomer survives a second zero-event window — TRIP
    // (this is the displaced-program signature: connections without events)
    let (t4, t6) = snapshots();
    assert!(
        w.observe(&t4, &t6, &[port], &[], &[], 0),
        "displaced program (connections, zero events x2) must trip"
    );
    drop(_client);
}

#[test]
fn watchdog_stays_quiet_when_events_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();

    let mut w = WatchState::default();
    let (t4, t6) = snapshots();
    assert!(!w.observe(&t4, &t6, &[port], &[], &[], 0));

    let _client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // same snapshots as the trip case, but the program is alive (events>0):
    // evidence of life exonerates everything visible — never trips.
    for events in [7u64, 12, 19] {
        let (t4, t6) = snapshots();
        assert!(
            !w.observe(&t4, &t6, &[port], &[], &[], events),
            "flowing events must exonerate (events={events})"
        );
    }
    drop(_client);
    // closed connection pruned: idle again, no trip
    let (t4, t6) = snapshots();
    assert!(!w.observe(&t4, &t6, &[port], &[], &[], 19));
}

/// BULGU-1 regression: a perf-ring overflow must not be mistaken for a
/// displaced BPF program.
///
/// When `bpf_perf_event_output` returns -E2BIG the event is dropped and the
/// kernel does NOT advance `data_head`, so the userspace overrun detector —
/// which compares head against tail — sees no backlog and stays silent. The
/// event stream then goes quiet for exactly the same reason a dead program
/// would go quiet, and the watchdog read that silence as evidence of traffic
/// displacement and engaged its fail-closed network lockdown.
///
/// This replays that scenario with real loopback snapshots and a synthetic
/// drop counter: identical to `watchdog_trips_when_connections_outlive_events`
/// except the drop counter moves, so the quiet window is explained.
#[test]
fn watchdog_does_not_trip_when_events_were_dropped() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();

    let mut w = WatchState::default();
    let (t4, t6) = snapshots();
    assert!(!w.observe_with_drops(win(&t4, &t6, port, 0), 0));

    let _client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");

    // Zero events, but the ring reported drops: the stream is known
    // incomplete, so quiet says nothing about whether the program is alive.
    let (t4, t6) = snapshots();
    assert!(
        !w.observe_with_drops(win(&t4, &t6, port, 0), 3),
        "a window with dropped events must not count as a missed window"
    );

    // Even across a second consecutive quiet window, while drops keep
    // arriving, the watchdog must hold fire: without the counter this case is
    // indistinguishable from the trip case.
    let (t4, t6) = snapshots();
    assert!(
        !w.observe_with_drops(win(&t4, &t6, port, 0), 9),
        "continued drops must keep the watchdog quiet"
    );

    drop(_client);
    let (t4, t6) = snapshots();
    assert!(!w.observe_with_drops(win(&t4, &t6, port, 0), 9));
}

/// Counter-probe: with the drop counter pinned at zero, the same snapshots and
/// event stream DO trip. This pins that the counter — not some incidental
/// difference in the fixtures — is what suppresses the trip.
#[test]
fn watchdog_still_trips_when_no_events_were_dropped() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();

    let mut w = WatchState::default();
    let (t4, t6) = snapshots();
    assert!(!w.observe_with_drops(win(&t4, &t6, port, 0), 0));

    let _client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let (t4, t6) = snapshots();
    assert!(!w.observe_with_drops(win(&t4, &t6, port, 0), 0));

    let (t4, t6) = snapshots();
    assert!(
        w.observe_with_drops(win(&t4, &t6, port, 0), 0),
        "quiet windows with no drops are still the displaced-program signature"
    );
}
