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

use albus::core::ebpf::watch::WatchState;
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
