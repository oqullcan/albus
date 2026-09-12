//! Wire-level integration tests verifying behavioral and wire packet differences
//! when ja4_mimic, stack_morph, and anti_injection subsystems are active.

use albus::core::anti_injection::{AntiInjectionFilter, InjectionVerdict};
use albus::core::fake::clienthello::{
    build_fake_client_hello_advanced, build_fake_client_hello_opts,
};
use albus::core::ja4_mimic::{compute_ja4_fingerprint, synthesize_client_hello, BrowserProfile};
use albus::core::rawsock::packet::build_packet_stack_morphed;
use albus::core::rawsock::ConnInfo;
use albus::core::stack_morph::OsProfile;
use albus::dns::ipcrypt::IpCrypt;
use albus::dns::ipcrypt_batch::{batch_decrypt_v4, batch_encrypt_v4};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn test_wire_level_ja4_mimic_difference() {
    let host = "decoy.cloudflare.com";

    // 1. Default basic decoy ClientHello (no JA4 mimicry)
    let default_raw = build_fake_client_hello_opts(host, false);

    // 2. JA4 mimicked decoy ClientHello (Chrome 130)
    let chrome_raw = build_fake_client_hello_advanced(host, true, true);

    // 3. Synthesized Firefox 130 and Safari 18 ClientHellos
    let firefox_raw = synthesize_client_hello(BrowserProfile::Firefox130, host, &["h2", "http/1.1"]);
    let safari_raw = synthesize_client_hello(BrowserProfile::Safari18, host, &["h2", "http/1.1"]);

    // Wire verification:
    // Both must be valid TLS records (Handshake type 0x16, TLS 1.0 record legacy version 0x0301)
    assert_eq!(default_raw[0], 0x16);
    assert_eq!(default_raw[1], 0x03);
    assert_eq!(default_raw[2], 0x01);

    assert_eq!(chrome_raw[0], 0x16);
    assert_eq!(chrome_raw[1], 0x03);
    assert_eq!(chrome_raw[2], 0x01);

    assert_eq!(firefox_raw[0], 0x16);
    assert_eq!(safari_raw[0], 0x16);

    // Default raw ClientHello is minimal (only 1 cipher suite: 0x1301 = 2 bytes)
    // In default_raw:
    // Offset 43 is cipher suites length
    // Chrome raw ClientHello contains full realistic browser cipher suites (15 suites = 30 bytes)
    assert!(
        chrome_raw.len() > default_raw.len(),
        "Chrome mimicked ClientHello must be richer than barebones decoy"
    );

    // Verify JA4 fingerprints for the profiles
    let chrome_fp = compute_ja4_fingerprint(
        true,
        true,
        BrowserProfile::Chrome130.cipher_suites(),
        BrowserProfile::Chrome130.extension_order(),
        Some("h2"),
    );
    assert_eq!(chrome_fp, BrowserProfile::Chrome130.expected_ja4());

    let firefox_fp = compute_ja4_fingerprint(
        true,
        true,
        BrowserProfile::Firefox130.cipher_suites(),
        BrowserProfile::Firefox130.extension_order(),
        Some("h2"),
    );
    assert_eq!(firefox_fp, BrowserProfile::Firefox130.expected_ja4());

    let safari_fp = compute_ja4_fingerprint(
        true,
        true,
        BrowserProfile::Safari18.cipher_suites(),
        BrowserProfile::Safari18.extension_order(),
        Some("h2"),
    );
    assert_eq!(safari_fp, BrowserProfile::Safari18.expected_ja4());

    // Passive middlebox observes three distinct, genuine browser fingerprints
    assert_ne!(chrome_fp, firefox_fp);
    assert_ne!(firefox_fp, safari_fp);
    assert_ne!(chrome_fp, safari_fp);
}

#[test]
fn test_wire_level_stack_morph_difference() {
    let conn = ConnInfo::new_v4(
        Ipv4Addr::new(192, 168, 1, 50),
        Ipv4Addr::new(1, 1, 1, 1),
        49152,
        443,
        1000,
        0,
    );
    let payload = b"FAKE_SYN_OR_PAYLOAD";

    // 1. Unmorphed packet (default raw TCP segment)
    let pkt_default = build_packet_stack_morphed(&conn, payload, 64, false, None, None, None);

    // 2. Morphed packet: Windows 11 profile
    let pkt_win11 = build_packet_stack_morphed(
        &conn,
        payload,
        0, // 0 = use profile default TTL
        false,
        None,
        None,
        Some(OsProfile::Windows11),
    );

    // 3. Morphed packet: MacOs Sequoia profile
    let pkt_macos = build_packet_stack_morphed(
        &conn,
        payload,
        0,
        false,
        None,
        None,
        Some(OsProfile::MacOsSequoia),
    );

    // Wire verification:
    // Default packet has standard 20-byte IP header + 20-byte TCP header (data offset = 5 = 0x50)
    let def_bytes = pkt_default.as_slice();
    assert_eq!(def_bytes[20 + 12] >> 4, 5, "default data offset is 5 (no options)");
    let def_win = u16::from_be_bytes([def_bytes[20 + 14], def_bytes[20 + 15]]);
    assert_eq!(def_win, 502, "default window size is 502");

    // Windows 11 packet has TCP options (MSS, WScale, SACK, TS) -> data offset > 5
    let win_bytes = pkt_win11.as_slice();
    let win_offset = win_bytes[20 + 12] >> 4;
    assert!(win_offset > 5, "Windows 11 TCP header must include TCP options");
    let win_ttl = win_bytes[8];
    assert_eq!(win_ttl, 128, "Windows 11 default TTL is 128");
    let win_window = u16::from_be_bytes([win_bytes[20 + 14], win_bytes[20 + 15]]);
    assert_eq!(win_window, 64240, "Windows 11 default window is 64240");

    // MacOS Sequoia packet has Apple TCP options and window size 65535, TTL 64
    let mac_bytes = pkt_macos.as_slice();
    let mac_offset = mac_bytes[20 + 12] >> 4;
    assert!(mac_offset > 5, "macOS TCP header must include TCP options");
    let mac_ttl = mac_bytes[8];
    assert_eq!(mac_ttl, 64, "macOS default TTL is 64");
    let mac_window = u16::from_be_bytes([mac_bytes[20 + 14], mac_bytes[20 + 15]]);
    assert_eq!(mac_window, 65535, "macOS default window is 65535");

    // Wire length of morphed packets must be larger due to injected options
    assert!(pkt_win11.len() > pkt_default.len());
    assert!(pkt_macos.len() > pkt_default.len());
}

#[test]
fn test_wire_level_anti_injection_defense() {
    let filter = AntiInjectionFilter::new(3);
    let server_addr: SocketAddr = "104.16.132.229:443".parse().unwrap();

    // Establish legitimate flow state: server packets arrive with TTL 55, seq 50000, win 65535
    filter.record_legitimate_flow(server_addr, 50000, 65535, 55);

    // 1. In-band legitimate RST with TTL 54 (drift = 1 <= tolerance of 3)
    let verdict_legit = filter.inspect_tcp_rst(server_addr, 50001, 54);
    assert_eq!(verdict_legit, InjectionVerdict::Legitimate);

    // 2. Middlebox injected RST arriving with ISP TTL 64 (drift = 9 > tolerance of 3)
    let verdict_injected_ttl = filter.inspect_tcp_rst(server_addr, 50001, 64);
    match verdict_injected_ttl {
        InjectionVerdict::DropInjectedRst(reason) => {
            assert!(reason.contains("ttl hop-count divergence"));
        }
        _ => panic!("injected RST with divergent TTL must be dropped"),
    }

    // 3. Middlebox blind injected RST with random seq out of window
    let verdict_injected_seq = filter.inspect_tcp_rst(server_addr, 888_888_888, 55);
    match verdict_injected_seq {
        InjectionVerdict::DropInjectedRst(reason) => {
            assert!(reason.contains("out-of-window"));
        }
        _ => panic!("blind injected RST with invalid sequence must be dropped"),
    }

    // 4. DNS injection: legitimate query response
    let legit_ips = [IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229))];
    assert_eq!(
        filter.inspect_dns_response("cloudflare.com", &legit_ips),
        InjectionVerdict::Legitimate
    );

    // 5. DNS injection: middlebox poisoned response with GFW fake IP (37.61.54.158)
    let poisoned_ips = [IpAddr::V4(Ipv4Addr::new(37, 61, 54, 158))];
    match filter.inspect_dns_response("blocked-news.org", &poisoned_ips) {
        InjectionVerdict::DropInjectedDns(reason) => {
            assert!(reason.contains("middlebox DNS poisoning signature"));
        }
        _ => panic!("GFW poisoned DNS IP must be dropped"),
    }
}

#[test]
fn test_wire_level_ipcrypt_batch_and_secure_mem() {
    let key = [0x5au8; 16];
    let crypt = IpCrypt::new(key);

    // Verify key memory is locked in physical RAM via mlock
    assert!(crypt.is_locked(), "IpCrypt key must be locked in physical RAM via mlock");

    let client_ips = vec![
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(10, 0, 0, 5),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(8, 8, 4, 4),
    ];

    // Batch encryption vs scalar encryption equivalence
    let batch_encrypted = batch_encrypt_v4(&crypt, &client_ips);
    for (i, &ip) in client_ips.iter().enumerate() {
        assert_eq!(batch_encrypted[i], crypt.encrypt(ip));
        // Encrypted IP must be distinct from original (pseudonymized)
        assert_ne!(batch_encrypted[i], ip);
    }

    // Decryption roundtrip restores authentic IPs
    let decrypted = batch_decrypt_v4(&crypt, &batch_encrypted);
    assert_eq!(decrypted, client_ips);
}

#[test]
fn test_wire_level_defense_profile_pipeline_activation() {
    use albus::app::cli::{Cli, Commands};
    use albus::app::config::Config;
    use clap::Parser;

    // Simulate CLI run with albus run --defense-profile paranoid
    let cli = Cli::parse_from(["albus", "run", "--defense-profile", "paranoid"]);
    let run_args = match cli.command {
        Some(Commands::Run(args)) => args,
        _ => cli.run_args,
    };

    let mut cfg = Config::default();
    assert!(!cfg.anti_injection);
    assert!(cfg.ja4_mimic.is_none());
    assert!(cfg.stack_morph.is_none());
    assert!(!cfg.simd_accel);

    cfg.merge_run_args(&run_args);

    assert!(cfg.anti_injection);
    assert_eq!(cfg.ja4_mimic.as_deref(), Some("chrome130"));
    assert_eq!(cfg.stack_morph.as_deref(), Some("windows11"));
    assert!(cfg.simd_accel);

    // Verify OsProfile and BrowserProfile parsing from strings
    assert_eq!(OsProfile::from_str("macos"), Some(OsProfile::MacOsSequoia));
    assert_eq!(OsProfile::from_str("linux"), Some(OsProfile::LinuxStock));
    assert_eq!(BrowserProfile::from_str("firefox"), Some(BrowserProfile::Firefox130));

    // Verify wire-level packets for LinuxStock profile
    let conn = ConnInfo::new_v4(
        Ipv4Addr::new(192, 168, 1, 50),
        Ipv4Addr::new(1, 1, 1, 1),
        49152,
        443,
        2000,
        0,
    );
    let pkt_linux = build_packet_stack_morphed(
        &conn,
        b"PING",
        64,
        false,
        None,
        None,
        Some(OsProfile::LinuxStock),
    );
    let linux_bytes = pkt_linux.as_slice();
    assert_eq!(linux_bytes[8], 64); // Linux TTL = 64
    assert_eq!(u16::from_be_bytes([linux_bytes[20 + 14], linux_bytes[20 + 15]]), 64240); // Linux Window = 64240
}
