# albus

> **Kernel-level deep packet inspection evasion engine, post-quantum cryptographic defenses, and zero-knowledge privacy networking stack for Linux.**

[![author](https://img.shields.io/badge/author-oqullcan-blue.svg)](https://github.com/oqullcan)
[![rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![ebpf](https://img.shields.io/badge/kernel-eBPF%20CO--RE-success.svg)](https://docs.kernel.org/bpf/)
[![crypto](https://img.shields.io/badge/pqc-ML--KEM--768%20%2F%20ML--DSA-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![license](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](file:///home/ogy/albusdpi/albus/LICENSE)

---

## Overview

Albus is an advanced network defense and anti-censorship platform engineered in pure Rust and eBPF. Moving beyond conventional DNS proxies or simplistic fragmentation utilities, Albus provides comprehensive kernel-level packet manipulation, provable post-quantum cryptography, side-channel immunity, traffic morphing, and zero-knowledge anonymity to defeat sophisticated national firewalls and statistical deep packet inspection middleboxes.

---

## Threat Model & Defense Objectives

Modern state-level firewalls (including GFW, TSPU, and enterprise deep packet inspection appliances) utilize multi-vector detection techniques:

1. **Passive Fingerprinting & Traffic Analysis**: Classifying protocols via packet length distributions, inter-arrival times, TLS Client Hello extension orders (JA3/JA4), and passive OS TCP/IP stack signatures (p0f).
2. **Active Probing & Replay Attacks**: Sending forged probes or replaying captured TLS handshakes to confirm suspected proxy endpoints.
3. **Active Packet Injection**: Forging TCP RST packets or spoofed DNS responses with manipulated TTLs and sequence numbers to disrupt user sessions.
4. **Quantum Eavesdropping**: Recording encrypted traffic flows for retroactive decryption via future quantum computers (Harvest Now, Decrypt Later).
5. **Memory and Side-Channel Exploitation**: Extracting cryptographic keys and session tokens via CPU cache-timing analysis, core dumps, or swap file memory leaks.

Albus systematically neutralizes each of these vectors through dedicated kernel, transport, and cryptographic subsystems.

---

## Architectural Blueprint

```
                     +----------------------------------------------------+
                     |                 User Application                   |
                     +-------------------------+--------------------------+
       DNS Requests (UDP/TCP, DoH)             |             Outbound TCP / TLS Connections
                                               v
+---------------------------------------------------------------------------------------------------------+
|                                    KERNEL & NETWORK CARD DRIVER (XDP / eBPF)                            |
+---------------------------------------------------------------------------------------------------------+
| [src/core/xdp_filter.rs](file:///home/ogy/albusdpi/albus/src/core/xdp_filter.rs)                       |
|   Zero-Copy Line-Rate Drop (XDP_DROP) for Censor Injected RSTs and Spoofed DNS Answers                  |
| [src/core/ebpf/manager.rs](file:///home/ogy/albusdpi/albus/src/core/ebpf/manager.rs)                   |
|   In-Kernel sock_ops MSS Clamping, Micro-Jitter Randomization, and Zero-Downtime BPF Map Pinning        |
| [src/core/anti_injection.rs](file:///home/ogy/albusdpi/albus/src/core/anti_injection.rs)               |
|   Stateful Anti-Injection: TTL Hop-Count Variance and TCP Sequence Window Boundary Tracking             |
+---------------------------------------------------------------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------------+
|                                   TRANSPORT EVASION & OBFUSCATION ENGINE                                |
+---------------------------------------------------------------------------------------------------------+
| [src/core/traffic_morph.rs](file:///home/ogy/albusdpi/albus/src/core/traffic_morph.rs)                 |
|   Poisson Inter-Packet Delay Jitter, Packet Size Quantization Bins, and Decoy Chaff Generation         |
| [src/core/stack_morph.rs](file:///home/ogy/albusdpi/albus/src/core/stack_morph.rs)                     |
|   OS TCP/IP Stack Signature Morphing (Windows 11, macOS Sequoia, iOS 18 p0f Emulation)                  |
| [src/core/ja4_mimic.rs](file:///home/ogy/albusdpi/albus/src/core/ja4_mimic.rs)                         |
|   TLS Client Hello Synthesizer with Genuine Browser JA3 / JA4 Fingerprint Camouflage                   |
| [src/core/active_probe.rs](file:///home/ogy/albusdpi/albus/src/core/active_probe.rs)                   |
|   Active Probing Defense: Sliding-Window Rolling Bloom Filter and Deceptive Honeytokens                 |
| [src/dns/ech.rs](file:///home/ogy/albusdpi/albus/src/dns/ech.rs)                                       |
|   RFC 9460 GREASE Encrypted Client Hello (ECH) Generation Preventing Targeted Protocol Filtering        |
+---------------------------------------------------------------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------------+
|                                 POST-QUANTUM & ZERO-KNOWLEDGE CRYPTOGRAPHY                              |
+---------------------------------------------------------------------------------------------------------+
| [src/dns/secure_mem.rs](file:///home/ogy/albusdpi/albus/src/dns/secure_mem.rs)                         |
|   Memory Hardening: libc::mlock Page Locking, Zeroize-on-Drop, and Memory Dump Redaction                |
| [src/dns/dnssec.rs](file:///home/ogy/albusdpi/albus/src/dns/dnssec.rs)                                 |
|   Post-Quantum Hybrid DNSSEC: ML-DSA-65/87, SLH-DSA, and Embedded IANA Root Trust Anchors             |
| [src/dns/noise.rs](file:///home/ogy/albusdpi/albus/src/dns/noise.rs)                                   |
|   Post-Quantum Noise IKpsk2 Protocol Handshake (ChaCha20-Poly1305 + SHA-256 + Pre-Shared Keys)         |
| [src/dns/sphinx.rs](file:///home/ogy/albusdpi/albus/src/dns/sphinx.rs)                                 |
|   Sphinx Multi-Hop Onion Mixnet Packet Routing with Bitwise Unlinkability and Uniform Padding           |
| [src/dns/zkp_auth.rs](file:///home/ogy/albusdpi/albus/src/dns/zkp_auth.rs)                             |
|   Non-Interactive Zero-Knowledge Proofs (Fiat-Shamir Schnorr PoK) for Anonymous Resolver Authorization |
| [src/dns/blind_token.rs](file:///home/ogy/albusdpi/albus/src/dns/blind_token.rs)                       |
|   Privacy Pass RFC 9576 / RFC 9577 VOPRF Blind Tokens for Unlinkable Query Authorizations               |
| [src/dns/entropy.rs](file:///home/ogy/albusdpi/albus/src/dns/entropy.rs)                               |
|   Dual-Source Hardware Entropy Engine (x86_64 RDRAND + OS CSPRNG) with Continuous FIPS 140-2 Health Run|
| [src/dns/ipcrypt.rs](file:///home/ogy/albusdpi/albus/src/dns/ipcrypt.rs)                               |
|   Format-Preserving 128-bit IPv6 and 32-bit IPv4 Encryption via 8-Round Constant-Time Feistel Cipher   |
| [src/dns/simd_crypto.rs](file:///home/ogy/albusdpi/albus/src/dns/simd_crypto.rs)                       |
|   SIMD / AVX2 Cryptographic Vectorization Accelerator for Parallel High-Throughput Feistel Permutations|
| [src/dns/stats.rs](file:///home/ogy/albusdpi/albus/src/dns/stats.rs)                                   |
|   Differential Privacy Telemetry: Calibrated Laplace Noise Injection into Prometheus Metrics           |
+---------------------------------------------------------------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------------+
|                                    CENSORSHIP-RESISTANT DNS SUBSYSTEM                                   |
+---------------------------------------------------------------------------------------------------------+
| [src/dns/multipath.rs](file:///home/ogy/albusdpi/albus/src/dns/multipath.rs)                           |
|   Multipath Racing: Concurrent Happy Eyeballs Across DoH, DoQ, and DNSCrypt Channels                    |
| [src/dns/stego.rs](file:///home/ogy/albusdpi/albus/src/dns/stego.rs)                                   |
|   Steganographic Covert Channels: Encapsulating Encrypted DNS inside HTTP Cookies and NTP Extensions    |
| [src/dns/quic_migration.rs](file:///home/ogy/albusdpi/albus/src/dns/quic_migration.rs)                 |
|   QUIC Connection Migration and Autonomous Connection ID (CID) Rotation                                 |
| [src/dns/blocklist.rs](file:///home/ogy/albusdpi/albus/src/dns/blocklist.rs)                           |
|   In-Memory HaGeZi Multi PRO + TIF Radix Trie Filtering (200,000+ Domains in Under 5 MB RAM)           |
+---------------------------------------------------------------------------------------------------------+
```

---

## Operational Defense Profiles

Albus includes predefined, battle-tested operational defense profiles that orchestrate kernel filtering, transport obfuscation, and cryptographic safeguards simultaneously:

| Profile | Command Flag | Target Threat Scenario | Active Subsystems |
| :--- | :--- | :--- | :--- |
| **Balanced** | `--defense-profile balanced` | Default production browsing | In-kernel eBPF MSS clamping, DNSSEC, DoH/DoQ, ECH, and HaGeZi threat sinkhole |
| **Paranoid** | `--defense-profile paranoid` | Heavy surveillance, targeted DPI, active probing | Traffic morphing (Poisson delay + padding), OS stack morphing, JA4 mimicry, active probe honeytokens, stateful anti-injection filter, multipath racing |
| **MaximumPrivacy** | `--defense-profile maximum-privacy` | Untraceable identities, zero metadata retention | Differential privacy metrics, ZKP resolver authorization, Privacy Pass blind tokens, 128-bit IPcrypt, and Sphinx multi-hop onion routing |
| **CensorshipResistant**| `--defense-profile censorship-resistant`| Total national firewall blackout, blocked ports | Steganographic covert channels (HTTP/NTP), GREASE ECH, QUIC connection migration, and XDP driver-level packet drop |

---

## Deep-Dive Feature Catalog

### 1. In-Kernel XDP and eBPF Packet Filtering
* [src/core/xdp_filter.rs](file:///home/ogy/albusdpi/albus/src/core/xdp_filter.rs): Executes at the network card driver layer before Linux allocates socket buffers (sk_buff). Drops censor-injected TCP RST packets and poisoned DNS responses at wire speed with zero CPU overhead.
* [src/core/ebpf/manager.rs](file:///home/ogy/albusdpi/albus/src/core/ebpf/manager.rs): Manages sock_ops BPF programs clamping initial TCP MSS to 88 bytes with randomized jitter to split TLS ClientHello records across multiple TCP segments.

### 2. Stateful Anti-Injection Defense
* [src/core/anti_injection.rs](file:///home/ogy/albusdpi/albus/src/core/anti_injection.rs): Maintains connection state to track expected IP TTL hop counts and TCP sequence/acknowledgment numbers. Forged middlebox RST packets or out-of-order injected spoof responses are immediately dropped.

### 3. Traffic Morphing & Jitter Engine
* [src/core/traffic_morph.rs](file:///home/ogy/albusdpi/albus/src/core/traffic_morph.rs): Neutralizes machine-learning statistical DPI by quantizing packet sizes into discrete geometric bins, adding Poisson-distributed random transmission delays, and injecting synthetic chaff packets into idle streams.

### 4. OS TCP/IP Stack Morphing
* [src/core/stack_morph.rs](file:///home/ogy/albusdpi/albus/src/core/stack_morph.rs): Modifies outbound TCP and IP headers (Window Size, MSS, Window Scale, TTL, and TCP options order) to match genuine Windows 11, macOS Sequoia, or iOS 18 devices, defeating passive OS fingerprinters (p0f).

### 5. TLS Client Hello JA3 / JA4 Mimicry
* [src/core/ja4_mimic.rs](file:///home/ogy/albusdpi/albus/src/core/ja4_mimic.rs): Synthesizes authentic TLS 1.3 ClientHello records replicating exact browser cipher suite orders, extension sequences, ALPN parameters, and supported elliptic curves to disguise upstream DoH connections as genuine web browser traffic.

### 6. Active Probing and Replay Protection
* [src/core/active_probe.rs](file:///home/ogy/albusdpi/albus/src/core/active_probe.rs): Features a sliding-window Rolling Bloom Filter that identifies replayed handshakes in zero allocation. Unauthenticated scanners and active probes are served deceptive honeytoken responses (authentic Nginx HTTP 404s or benign DNS Refused packets).

### 7. Secure Memory Hardening & Constant-Time Execution
* [src/dns/secure_mem.rs](file:///home/ogy/albusdpi/albus/src/dns/secure_mem.rs): Locks cryptographic keys in RAM via libc mlock, preventing swap file leakage. Memory is automatically zeroized on drop.
* Constant-time equality checks via subtle::ConstantTimeEq are enforced across [src/dns/dnscrypt_client.rs](file:///home/ogy/albusdpi/albus/src/dns/dnscrypt_client.rs), [src/dns/odoh.rs](file:///home/ogy/albusdpi/albus/src/dns/odoh.rs), and [src/dns/web_ui.rs](file:///home/ogy/albusdpi/albus/src/dns/web_ui.rs), preventing microarchitectural cache-timing attacks.

### 8. Post-Quantum Cryptographic Transports
* [src/dns/dnssec.rs](file:///home/ogy/albusdpi/albus/src/dns/dnssec.rs): Implements post-quantum signature verification for ML-DSA-65, ML-DSA-87, and SLH-DSA algorithms alongside embedded IANA Root Trust Anchors (KSK-2017 and KSK-2024).
* [src/dns/noise.rs](file:///home/ogy/albusdpi/albus/src/dns/noise.rs): Provides Noise_IKpsk2_25519_ChaChaPoly_SHA256 authenticated hybrid handshakes with pre-shared quantum resistance.

### 9. Sphinx Multi-Hop Onion Mixnet Transport
* [src/dns/sphinx.rs](file:///home/ogy/albusdpi/albus/src/dns/sphinx.rs): Formats queries into fixed-size Sphinx onion packets. Each intermediary mixnode peels a layer using ChaCha20 keystream encryption and verifies hop authenticators without learning the overall path or payload origin.

### 10. Zero-Knowledge Authorization & Blind Tokens
* [src/dns/zkp_auth.rs](file:///home/ogy/albusdpi/albus/src/dns/zkp_auth.rs): Implements Fiat-Shamir transformed Schnorr proofs of knowledge, enabling clients to prove query permissions without revealing identities.
* [src/dns/blind_token.rs](file:///home/ogy/albusdpi/albus/src/dns/blind_token.rs): Implements Privacy Pass RFC 9576 / RFC 9577 VOPRF blind tokens for unlinkable cryptographic access.

### 11. Format-Preserving IP Encryption & SIMD Vectorization
* [src/dns/ipcrypt.rs](file:///home/ogy/albusdpi/albus/src/dns/ipcrypt.rs): Encrypts 128-bit IPv6 and 32-bit IPv4 addresses via an 8-round constant-time Feistel cipher, preserving address structure while anonymizing client logs.
* [src/dns/ipcrypt_batch.rs](file:///home/ogy/albusdpi/albus/src/dns/ipcrypt_batch.rs) and [src/dns/simd_crypto.rs](file:///home/ogy/albusdpi/albus/src/dns/simd_crypto.rs): Provide multithreaded Rayon batch acceleration and hardware AVX2/SIMD vectorization for processing IP streams at line rate.

### 12. Steganographic Covert Channels
* [src/dns/stego.rs](file:///home/ogy/albusdpi/albus/src/dns/stego.rs): Conceals encrypted DNS payloads inside benign HTTP Cookie headers or authenticated NTP extension fields when standard DNS/DoH ports are completely blocked.

### 13. QUIC Connection Migration & Multipath Racing
* [src/dns/quic_migration.rs](file:///home/ogy/albusdpi/albus/src/dns/quic_migration.rs): Rotates Connection IDs and manages local socket rebinding without interrupting established QUIC sessions.
* [src/dns/multipath.rs](file:///home/ogy/albusdpi/albus/src/dns/multipath.rs): Renders single-protocol filtering ineffective by racing queries simultaneously across DoH, DoQ, and DNSCrypt channels.

---

## Command Line Interface & Options

### Quick Start

```bash
# Run foreground daemon with Paranoid defense profile
sudo albus run --defense-profile paranoid

# Run with Maximum Privacy profile and Tor proxy routing
sudo albus run --defense-profile maximum-privacy --tor

# Run with Censorship-Resistant profile and XDP packet dropping
sudo albus run --defense-profile censorship-resistant --xdp-filter
```

### Complete Flag Reference

| Category | Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| **Defense Profiles** | `--defense-profile` | None | Operational profile: `balanced`, `paranoid`, `maximum-privacy`, `censorship-resistant` |
| | `--ja4-mimic` | None | Emulated browser TLS ClientHello: `chrome`, `firefox`, `safari` |
| | `--active-probe-defense` | `false` | Enable rolling bloom filter replay detection and honeytoken decoys |
| | `--xdp-filter` | `false` | Enable in-kernel XDP zero-copy packet drop at the NIC driver |
| | `--sphinx-routing` | `false` | Enable Sphinx multi-hop onion mixnet packet transport |
| | `--simd-accel` | `false` | Enable AVX2/SIMD cryptographic vectorization |
| **DPI Evasion** | `--mss`, `--min-mss` | `88`, `64` | Initial TCP MSS clamp and per-flow jitter range |
| | `--auto-ttl`, `--fake-ttl` | `true`, `8` | Dynamic hop-distance path measurement or fallback TTL |
| | `--fake-sni`, `--fake-seq-offset` | rotating, `0` | Decoy SNI override and TCP sequence shift offset |
| | `--fake-bad-checksum` | `false` | Invalidate TCP checksums (`0xDEAD`) to desynchronize middleboxes |
| **DNS Resolution** | `--doh-upstream` | `"quad9"` | Upstream resolver (`quad9`, `cloudflare`, `mullvad-*`, `sdns://...`) |
| | `--dns-racing` | `true` | Concurrent multi-upstream Happy Eyeballs resolution |
| | `--odoh`, `--odoh-relay`, `--odoh-target` | `false` | RFC 9230 Oblivious DoH HPKE proxy relay client |
| | `--pqc`, `--dnssec` | `true`, `true` | Post-quantum hybrid key exchange and DNSSEC validation |
| | `--ipcrypt-key` | None | 128-bit hex key for client IP pseudonymization |
| **Privacy & Firewall**| `--blocklist`, `--blocklist-path` | `true`, auto | Compact in-memory HaGeZi Multi PRO + TIF ad/threat sinkhole |
| | `--uncloak-cnames`, `--block-bogons`| `true`, `true` | CNAME/HTTPS tracker uncloaking and Martian/Bogon IP filter |
| | `--kill-switch`, `--network-lockdown` | `true`, `false` | Strict firewall DNS kill-switch and fail-closed lockdown |
| | `--block-quic`, `--block-stun` | `true`, `true` | Drop outbound UDP 443 (force TCP) and WebRTC STUN UDP 3478/5349 |
| | `--ram-only` | `false` | Volatile execution in tmpfs (zero persistent disk traces) |

---

## Build & Verification

Albus is tested against an extensive test suite verifying cryptographic invariants, side-channel bounds, memory safety, and kernel packet parsing.

```bash
# Build optimized release binary
cargo build --release

# Run the complete test suite (326+ tests)
cargo test --workspace

# Run fuzz robustness tests
cargo test --test fuzz_robustness

# Install release binary to local path
sudo cp target/release/albus /usr/local/bin/
```

---

## Desktop Integration (Omarchy Shell)

Albus includes a native desktop panel widget for the Omarchy Quattro shell (`BarWidget.qml` and `Panel.qml`) providing real-time telemetry, resolver selection, live threat counters, and security controls.

```bash
mkdir -p ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev
cp manifest.json BarWidget.qml Panel.qml ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev/
omarchy-shell shell rescanPlugins
```

---

## License

This project is licensed under the [GNU General Public License v3.0 (GPL-3.0)](file:///home/ogy/albusdpi/albus/LICENSE).
