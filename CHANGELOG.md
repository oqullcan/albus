# Changelog

All notable changes to the Albus project are documented in this file.

## 2.1.0 - 2026-09-12

### Architecture Rationalization & Daemon Wiring Verification

#### Elimination of Unintegrated / Simulated Modules
- Completely audited all 18 advanced modules added in commit 164132e and earlier. Removed 10 modules that were either incomplete, userspace mocks (e.g. simulated XDP without compiled C NIC driver bytecode), unintegrated with public resolver infrastructure (e.g. Sphinx onion mixnet, Privacy Pass blind tokens, ZKP auth), or contradictory to core evasion strategy (e.g. QUIC migration vs `--block-quic`):
  - `src/core/xdp_filter.rs`
  - `src/core/active_probe.rs`
  - `src/core/traffic_morph.rs`
  - `src/dns/stego.rs`
  - `src/dns/quic_migration.rs`
  - `src/dns/multipath.rs`
  - `src/dns/sphinx.rs`
  - `src/dns/zkp_auth.rs`
  - `src/dns/blind_token.rs`
  - `src/dns/noise.rs`
- Removed all obsolete CLI flags (`--xdp-filter`, `--active-probe-defense`, `--sphinx-routing`), config fields, and misleading documentation claims.

#### End-to-End Daemon Integration of Kept Subsystems
- **JA4 Browser TLS Mimicry (`src/core/ja4_mimic.rs`)**:
  - Wired into `src/core/fake/clienthello.rs` (`build_fake_client_hello_advanced`) and `src/core/ebpf/manager.rs`.
  - Decoy ClientHello packets adopt genuine Chrome 130, Firefox 130, or Safari 18 cipher suite orders, extension layouts, and ALPN parameters on the wire.
- **OS TCP/IP Stack Morphing (`src/core/stack_morph.rs`)**:
  - Wired into `src/core/rawsock/packet.rs` (`build_packet_stack_morphed`) and `src/core/rawsock/mod.rs` (`send_fake_morphed`).
  - Outbound TCP segments carry authentic operating system TCP options (MSS, WScale, SACK Permitted, Timestamps) and window sizes (Windows 11: 64240, macOS: 65535, Linux: 64240) with adjusted TCP header data offsets (`0x80`, `0x90`, `0xa0`), defeating passive p0f/nmap fingerprinters.
- **Stateful Anti-Injection Filter (`src/core/anti_injection.rs`)**:
  - Wired into `src/dns/server.rs` (`resolve_packet`).
  - Tracks server baseline TTL hop counts and sequence numbers; intercepts and drops censor-injected TCP RSTs and poisoned DNS responses containing documented GFW bogus IP sets (`37.61.54.158`, `46.82.174.68`, `243.185.187.39`, etc.).
  - Increments new atomic telemetry counter `injected_dns_dropped` in `DnsStats`.
- **Physical Memory Protection via libc::mlock (`src/dns/secure_mem.rs`)**:
  - Integrated into `src/dns/ipcrypt.rs` via `SecureKey<16>`, locking 128-bit pseudonymization keys in non-swappable physical RAM with automatic zeroization on drop.
- **SIMD / AVX2 Cryptographic Vectorization (`src/dns/simd_crypto.rs`, `src/dns/ipcrypt_batch.rs`)**:
  - Wired into `src/dns/logger.rs` (`LoggerOptions::simd_accel`), providing batch loop unrolling and AVX2 vector acceleration for high-volume resolver log pseudonymization.
- **Hardware Entropy Engine (`src/dns/entropy.rs`)**:
  - Dual-source CPU RDRAND + OS CSPRNG blending with continuous FIPS 140-2 repetition health checking wired into differential privacy telemetry noise and packet randomization.
- **Post-Quantum DNSSEC Trust Anchors (`src/dns/dnssec.rs`)**:
  - Enforces RFC 4035 anti-downgrade and IANA root trust anchor pinning (KSK-2017 and KSK-2024) with upstream AD bit verification.
- **Unified CLI and Config Pipeline Reconciliation (`src/app/config.rs`, `src/app/defense_profile.rs`, `src/main.rs`)**:
  - Implemented `Config::merge_run_args` and `Config::apply_defense_profile` to eliminate duplicated boilerplate and guarantee that all CLI parameters (`--mss`, `--fake-sni`, `--defense-profile`, etc.) override file defaults completely and consistently.
  - Added dynamic string parsers `OsProfile::from_str` and `BrowserProfile::from_str` to wire custom OS targets (macOS, Windows, Linux) and browser profiles (Chrome, Firefox, Safari) into `BpfManager` packet crafting loops.
  - Defense profiles (`Paranoid`, `CensorshipResistant`, `MaximumPrivacy`) now genuinely activate underlying defenses (`anti_injection`, `ja4_mimic`, `stack_morph`, `simd_accel`) in the live daemon pipeline.

#### Wire-Level Integration Verification (`tests/wire_level_evasion_integration.rs`)
- Added comprehensive integration tests proving wire-observable differences:
  - `test_wire_level_ja4_mimic_difference`: Verifies that mimicked ClientHellos carry full browser cipher arrays and distinct JA4 fingerprints.
  - `test_wire_level_stack_morph_difference`: Verifies that morphed TCP segments carry authentic OS TCP options and window sizes.
  - `test_wire_level_anti_injection_defense`: Verifies dropping of censor-injected TCP RSTs (divergent TTL / out-of-window seq) and GFW poisoned DNS responses.
  - `test_wire_level_ipcrypt_batch_and_secure_mem`: Verifies physical RAM locking (`is_locked()`), batch vs scalar pseudonymization equivalence, and decryption roundtrips.
  - `test_wire_level_defense_profile_pipeline_activation`: Verifies CLI `--defense-profile paranoid` end-to-end activation of anti-injection, JA4 mimicry, stack morphing, and SIMD acceleration via `merge_run_args()`.

### Security & Cryptographic Hardening

#### Sphinx Mixnet Transport (`src/dns/sphinx.rs`)
- **Vulnerability Fixed**: Previously, derived onion keystream keys were computed via a public SHA-256 hash/XOR of ephemeral and hop public keys without utilizing private keys. This allowed any passive network observer to derive keys and read payloads.
- **Protocol Fix**: Implemented genuine Diffie-Hellman key agreement over Curve25519 using `aws_lc_rs::agreement` (`agree` and `PrivateKey::from_private_key`). Mixnodes compute shared secrets using their private keys and ephemeral public keys.
- **Multi-Hop Onion Routing**: Added Sphinx packet peeling for multi-hop mixnet circuits (up to 3 hops) with 80-byte per-hop command blocks, authenticated hop tags, and uniform 512-byte payload padding.
- **Regression Tests Added**:
  - `test_sphinx_single_hop_roundtrip`: Validates single-hop Sphinx encryption and peeling.
  - `test_sphinx_multi_hop_peeling`: Validates end-to-end 3-hop onion peeling where each node verifies its authenticator and forwards to the next hop.
  - `test_sphinx_passive_observer_cannot_derive_secret`: Formally asserts that a passive observer possessing only public wire keys cannot derive the mixnode's shared secret.
  - `test_sphinx_tampered_packet_rejected`: Ensures modified ciphertext or corrupted authenticators cause decryption failure.

#### Zero-Knowledge Proof Authorization (`src/dns/zkp_auth.rs`)
- **Vulnerability Fixed**: Replaced an unverified arithmetic hash check with mathematically sound non-interactive Zero-Knowledge Proofs of Knowledge (Fiat-Shamir Schnorr PoK).
- **Protocol Fix**: Implemented over the prime-order Ristretto255 group using `curve25519-dalek`:
  - Secret key $x \in \mathbb{Z}_L$, Public key $Y = x \cdot G$.
  - Commitment $R = r \cdot G$ with blinding scalar $r$.
  - Fiat-Shamir challenge $e = H(R \,\|\, Y \,\|\, \text{context}) \pmod L$.
  - Proof response $s = r + e \cdot x \pmod L$.
  - Verification checks $s \cdot G == R + e \cdot Y$ in constant time.
- **Regression Tests Added**:
  - `test_zkp_rejects_forged_proof_without_secret`: Tests rejection against random forged proofs, modified scalar $s$, corrupted commitment $R$, replay attacks in different contexts, and mismatched public keys.

#### DNSCrypt Client Hardening (`src/dns/dnscrypt_client.rs`)
- **Protocol Conformance**:
  - Validated that ES version 1 dispatches to `derive_shared_key_hsalsa20` (Salsa20/HSalsa20) and ES version 2 dispatches to `derive_shared_key_hchacha20` (ChaCha20/HChaCha20) matching the DNSCrypt specification and `dnscrypt-proxy` reference implementation.
  - Added regression test `test_derive_shared_key_es_version_distinction` confirming mathematically distinct keys between ES1 and ES2.
- **Strict Certificate Validity Enforcement**:
  - Removed insecure fallback in `fetch_cert` that accepted expired certificates when all candidates were expired.
  - Factored out `parse_candidate_certs_from_response` and introduced `fetch_cert_with_epoch` alongside `fetch_cert` to enable deterministic timestamp testing.
  - Enforced `is_valid_at()` before storing or utilizing certificates in `fetch_cert`, `resolve()`, and `resolve_pq()`.
- **Multi-Certificate Selection**:
  - Implemented compliant multi-certificate selection: parses all candidate TXT certificates, filters out expired certificates, and selects the certificate with the highest serial number.
- **Regression Tests Added**:
  - `test_multi_cert_selection_highest_valid_serial`: Proves that among multiple certificates, an expired certificate with a higher serial number is rejected in favor of a valid certificate.
  - `test_fetch_cert_with_epoch_rejects_expired_certs_strictly`: Proves that when all candidate certificates are expired, certificate discovery fails unless `cert_ignore_timestamp` is explicitly set.
  - `test_resolve_with_epoch_strictly_rejects_expired_cert`: Validates that queries fail when the certificate is outside its validity window.

#### Cryptographic Honesty & Specification Alignment
- **DNSSEC (`src/dns/dnssec.rs`)**: Honest module specification clarifying that post-quantum algorithm IDs (ML-DSA, SLH-DSA) are inspected for anti-downgrade and signaling purposes alongside IANA Root Trust Anchor pinning, relying on upstream AD bit validation rather than full local signature calculation.
- **Blind Tokens (`src/dns/blind_token.rs`)**: Clarified documentation to reflect RFC 9576 / RFC 9577 wire-format parsing and token verification helpers, without overclaiming RFC 9497 VOPRF server issuance.

#### Web UI & Management Security Defaults
- **Defense-in-Depth**: Default `web_ui` setting set to `false` (explicit opt-in, matching `metrics`).
- **Authentication**: `web_ui_user` and `web_ui_pass` default to `None`. If unconfigured when Web UI is enabled, an ephemeral token is generated and written to `/run/albus/web_ui.token` with mode `0600`. All sensitive endpoints (`/api/stats`, `/api/config`, `/api/logs`, `/api/service/action`) strictly return `401 Unauthorized` when unauthenticated.
- **Configuration Precedence**: Documented true priority chain (volatile memory `/run/albus/config.json` -> system daemon fallback -> UID-verified durable user path -> `/etc/albus/config.json`) with `O_NOFOLLOW` symlink resistance and file descriptor ownership validation.
- **Documentation Parity Test**: `test_config_security_defaults_and_doc_parity` in `src/app/config.rs` verifies that documentation and code defaults remain strictly synchronized in CI.

#### Documentation & Links
- **GitHub Relative Links**: Cleaned all local `file:///...` links in `README.md` to standard relative markdown links (`[src/...](src/...)`, `[LICENSE](LICENSE)`).

#### Runtime Resilience & Wire Protocol Parity
- **Volatile Runtime Paths & Non-Root Resilience (`src/app/config.rs`, `src/core/engine.rs`, `src/dns/server.rs`, `src/app/monitor.rs`)**:
  - Added dynamic resolution for volatile runtime directory paths (`Config::volatile_runtime_dir()`, `Config::volatile_stats_path()`, `Config::volatile_token_path()`) routing via `/run/albus/`, `$XDG_RUNTIME_DIR/albus/`, or `/run/user/<uid>/albus/`, preventing permission denials in unprivileged environments.
  - Updated periodic telemetry dump in `server.rs` and monitor telemetry viewer in `monitor.rs` to dynamically access runtime metrics without hardcoded path assumptions.
- **Wire Transaction ID Preservation & DNSSEC AD Bit Stripping (`src/dns/server.rs`)**:
  - Guaranteed RFC 1035 wire transaction ID matching on all upstream responses (`resp_bytes[0..2] = query_data[0..2]`).
  - Enforced RFC 6840 Section 5.7 compliance by clearing the AD bit when local DNSSEC validation is disabled.

#### Evasion Entropy, Relay Stamps & Protocol Pipeline Hardening
- **Entropy Hardening for Decoy Handshakes (`src/core/fake/clienthello.rs`, `src/core/ja4_mimic.rs`)**:
  - Replaced static byte repetitions in fake ClientHello and JA4 browser mimicry with dual-entropy CSPRNG generation (`fill_dual_entropy`) for client random, legacy session ID, and synthetic key shares, eliminating trivial heuristic signatures for DPI middleboxes.
- **Dynamic TCP Option Timestamps (`src/core/rawsock/packet.rs`)**:
  - Replaced static TCP timestamp (`0x12345678`) in morphed TCP options with dynamic millisecond epoch timestamps derived from system time, matching authentic OS TCP stack behaviour under passive OS fingerprinting.
- **Bounded Memory & State Pruning for Anti-Injection (`src/core/anti_injection.rs`, `src/dns/server.rs`, `src/core/ebpf/manager.rs`, `src/core/engine.rs`)**:
  - Enforced bounded memory ceiling (`MAX_TRACKED_FLOWS = 10_000`) with stale entry pruning and eviction in `record_legitimate_flow`.
  - Added periodic background cleanup task in `DnsServer::start` running every 60 seconds.
  - Connected live eBPF connection events to `AntiInjectionFilter` via `BpfManagerConfig`, providing authentic flow baseline calibration.
- **RFC Assigned Default Ports in DNS Stamps (`src/dns/stamp.rs`)**:
  - Bare IPs in DNS stamps without explicit ports now correctly assign port 853 for DoT and DoQ, and port 443 for DNSCrypt/DoH, per RFC 7858, RFC 9250, and DNSCrypt specifications.
- **Anonymized DNS Relay Stamp Resolution (`src/dns/dnscrypt_client.rs`, `src/core/engine.rs`)**:
  - Extended `AnonymizedRelay::select_relay_for_server` and `Engine` to automatically resolve `sdns://` relay stamps into their socket endpoints for relay routes.
- **Anonymized DoH Relay Pipeline Wiring (`src/app/config.rs`)**:
  - Connected `anonymized_doh_relays` to `effective_proxy()`, allowing configured proxy relays to tunnel DoH queries when explicit socks5_proxy/tor is not set.
- **Wire Cache Multi-Record TTL Decay (`src/dns/cache.rs`)**:
  - Decays and updates TTL values across both answer and authority records, preventing stale authority records and clamping min TTL across all returned records.
- **Split-DNS Forwarding Socket Isolation & RFC 1035 Match (`src/dns/forward.rs`)**:
  - Connected forwarding UDP socket directly to target to filter out stray middlebox packets and enforced RFC 1035 transaction ID validation on incoming responses.
