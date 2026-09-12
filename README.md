# albus

> **Kernel-level deep packet inspection evasion engine, post-quantum cryptographic defenses, and zero-knowledge privacy networking stack for Linux.**

[![author](https://img.shields.io/badge/author-oqullcan-blue.svg)](https://github.com/oqullcan)
[![rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![ebpf](https://img.shields.io/badge/kernel-eBPF%20CO--RE-success.svg)](https://docs.kernel.org/bpf/)
[![crypto](https://img.shields.io/badge/pqc-ML--KEM--768%20%2F%20ML--DSA-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![license](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

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
| [src/core/xdp_filter.rs](src/core/xdp_filter.rs)                                                        |
|   Zero-Copy Line-Rate Drop (XDP_DROP) for Censor Injected RSTs and Spoofed DNS Answers                  |
| [src/core/ebpf/manager.rs](src/core/ebpf/manager.rs)                                                   |
|   In-Kernel sock_ops MSS Clamping, Micro-Jitter Randomization, and Zero-Downtime BPF Map Pinning        |
| [src/core/anti_injection.rs](src/core/anti_injection.rs)                                               |
|   Stateful Anti-Injection: TTL Hop-Count Variance and TCP Sequence Window Boundary Tracking             |
+---------------------------------------------------------------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------------+
|                                   TRANSPORT EVASION & OBFUSCATION ENGINE                                |
+---------------------------------------------------------------------------------------------------------+
| [src/core/stack_morph.rs](src/core/stack_morph.rs)                                                     |
|   OS TCP/IP Stack Signature Morphing (Windows 11, macOS Sequoia, iOS 18, Linux p0f Emulation)           |
| [src/core/ja4_mimic.rs](src/core/ja4_mimic.rs)                                                         |
|   TLS Client Hello Synthesizer with Genuine Browser JA3 / JA4 Fingerprint Camouflage (Chrome, Firefox)  |
| [src/core/anti_injection.rs](src/core/anti_injection.rs)                                               |
|   Stateful Anti-Injection Defense: Middlebox TTL Hop Drift, Sequence Window & DNS Poisoning Intercept   |
| [src/dns/ech.rs](src/dns/ech.rs)                                                                       |
|   RFC 9460 GREASE Encrypted Client Hello (ECH) Generation Preventing Targeted Protocol Filtering        |
+---------------------------------------------------------------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------------+
|                                 POST-QUANTUM & CRYPTOGRAPHIC SECURITY LAYER                             |
+---------------------------------------------------------------------------------------------------------+
| [src/dns/secure_mem.rs](src/dns/secure_mem.rs)                                                         |
|   Memory Hardening: libc::mlock Page Locking, Zeroize-on-Drop, and Memory Dump Redaction                |
| [src/dns/dnssec.rs](src/dns/dnssec.rs)                                                                 |
|   Post-Quantum Hybrid DNSSEC: ML-DSA / SLH-DSA Signaling Inspection, Anti-Downgrade & Trust Anchors    |
| [src/dns/entropy.rs](src/dns/entropy.rs)                                                               |
|   Dual-Source Hardware Entropy Engine (x86_64 RDRAND + OS CSPRNG) with Continuous FIPS 140-2 Health Run|
| [src/dns/ipcrypt.rs](src/dns/ipcrypt.rs)                                                               |
|   Format-Preserving 128-bit IPv6 and 32-bit IPv4 Encryption via 8-Round Constant-Time Feistel Cipher   |
| [src/dns/ipcrypt_batch.rs](src/dns/ipcrypt_batch.rs) & [src/dns/simd_crypto.rs](src/dns/simd_crypto.rs) |
|   Batch Processing & SIMD / AVX2 Cryptographic Vectorization for High-Throughput Log Pseudonymization   |
| [src/dns/stats.rs](src/dns/stats.rs)                                                                   |
|   Differential Privacy Telemetry: Calibrated Laplace Noise Injection into Prometheus Metrics           |
+---------------------------------------------------------------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------------+
|                                    CENSORSHIP-RESISTANT DNS SUBSYSTEM                                   |
+---------------------------------------------------------------------------------------------------------+
| [src/dns/server.rs](src/dns/server.rs)                                                                 |
|   Multi-Upstream Racing: Concurrent Happy Eyeballs Across DoH, DoQ, and DNSCrypt Channels               |
| [src/dns/odoh.rs](src/dns/odoh.rs)                                                                     |
|   RFC 9230 Oblivious DoH (ODoH) Relay Transport with HPKE Hybrid Public Key Encryption                  |
| [src/dns/blocklist.rs](src/dns/blocklist.rs)                                                           |
|   In-Memory HaGeZi Multi PRO + TIF Radix Trie Filtering (200,000+ Domains in Under 5 MB RAM)           |
+---------------------------------------------------------------------------------------------------------+
```

---

## Operational Defense Profiles

Albus includes predefined, battle-tested operational defense profiles that orchestrate kernel filtering, transport obfuscation, and cryptographic safeguards simultaneously:

| Profile | Command Flag | Target Threat Scenario | Active Subsystems |
| :--- | :--- | :--- | :--- |
| **Balanced** | `--defense-profile balanced` | Default production browsing | In-kernel eBPF MSS clamping, DNSSEC, DoH/DoQ, ECH, and HaGeZi threat sinkhole |
| **Paranoid** | `--defense-profile paranoid` | Heavy surveillance, targeted DPI, middlebox injection | OS TCP stack morphing, JA4 browser mimicry, stateful anti-injection defense, and SIMD vector acceleration |
| **MaximumPrivacy** | `--defense-profile maximum-privacy` | Untraceable identities, zero metadata retention | Differential privacy metrics, 128-bit IPcrypt with physical RAM locking (libc::mlock), and ODoH HPKE proxy relay |
| **CensorshipResistant**| `--defense-profile censorship-resistant`| Aggressive national firewalls, poisoned DNS | In-kernel eBPF MSS clamping, Auto-TTL fake injection, GREASE ECH, and stateful anti-injection filter |

---

## Deep-Dive Feature Catalog

### 1. In-Kernel eBPF Packet Filtering
* [src/core/ebpf/manager.rs](src/core/ebpf/manager.rs): Manages sock_ops BPF programs clamping initial TCP MSS to 88 bytes with randomized jitter to split TLS ClientHello records across multiple TCP segments.

### 2. Stateful Anti-Injection Defense
* [src/core/anti_injection.rs](src/core/anti_injection.rs): Evaluates incoming packets and DNS responses for middlebox tampering. Tracks server TTL hop drift, TCP sequence window validity, and intercepts known middlebox DNS poisoning signatures (GFW bogus IP sets).

### 3. OS TCP/IP Stack Morphing
* [src/core/stack_morph.rs](src/core/stack_morph.rs): Modifies outbound TCP and IP headers (Window Size, MSS, Window Scale, TTL, and TCP options order) to match genuine Windows 11, macOS Sequoia, or iOS 18 devices, defeating passive OS fingerprinters (p0f).

### 4. TLS Client Hello JA3 / JA4 Mimicry
* [src/core/ja4_mimic.rs](src/core/ja4_mimic.rs): Synthesizes authentic TLS 1.3 ClientHello records replicating exact browser cipher suite orders, extension sequences, and ALPN parameters to disguise upstream DoH connections as genuine web browser traffic.

### 5. Secure Memory Hardening & Constant-Time Execution
* [src/dns/secure_mem.rs](src/dns/secure_mem.rs): Locks cryptographic keys in RAM via libc mlock, preventing swap file leakage. Memory is automatically zeroized on drop.
* Constant-time equality checks via subtle::ConstantTimeEq are enforced across [src/dns/dnscrypt_client.rs](src/dns/dnscrypt_client.rs), [src/dns/odoh.rs](src/dns/odoh.rs), and [src/dns/web_ui.rs](src/dns/web_ui.rs), preventing microarchitectural cache-timing attacks.

### 6. Post-Quantum Cryptographic Transports & Trust Anchors
* [src/dns/dnssec.rs](src/dns/dnssec.rs): Implements post-quantum algorithm signaling inspection and downgrade protection for ML-DSA and SLH-DSA alongside embedded IANA Root Trust Anchors (KSK-2017 and KSK-2024) and upstream AD bit enforcement.
* [src/dns/dnscrypt_client.rs](src/dns/dnscrypt_client.rs): Provides DNSCrypt v2 transport with X-Wing hybrid post-quantum key encapsulation.

### 7. Dual-Source Hardware Entropy Engine
* [src/dns/entropy.rs](src/dns/entropy.rs): Blends CPU hardware RDRAND with operating system CSPRNG, subjecting the output stream to continuous FIPS 140-2 repetition health checking before deriving nonces or session keys.

### 8. Format-Preserving IP Encryption & SIMD Vectorization
* [src/dns/ipcrypt.rs](src/dns/ipcrypt.rs): Encrypts 128-bit IPv6 and 32-bit IPv4 addresses via an 8-round constant-time Feistel cipher, preserving address structure while anonymizing client logs.
* [src/dns/ipcrypt_batch.rs](src/dns/ipcrypt_batch.rs) & [src/dns/simd_crypto.rs](src/dns/simd_crypto.rs): Provide batch loop unrolling and AVX2/SIMD vectorization for processing high-throughput IP pseudonymization.

### 9. Oblivious DoH (ODoH) Relay Transport
* [src/dns/odoh.rs](src/dns/odoh.rs): RFC 9230 Oblivious DoH HPKE client separating client IP addresses from query contents through intermediate privacy proxies.

---

## Command Line Interface & Options

### Quick Start

```bash
# Run foreground daemon with Paranoid defense profile
sudo albus run --defense-profile paranoid

# Run with Maximum Privacy profile and Tor proxy routing
sudo albus run --defense-profile maximum-privacy --tor

# Run with custom browser TLS mimicry and OS stack morphing
sudo albus run --ja4-mimic chrome --stack-morph windows11 --anti-injection
```

### Complete Flag Reference

| Category | Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| **Defense Profiles** | `--defense-profile` | None | Operational profile: `balanced`, `paranoid`, `maximum-privacy`, `censorship-resistant` |
| | `--ja4-mimic` | None | Emulate browser TLS ClientHello fingerprint: `chrome`, `firefox`, `safari` |
| | `--stack-morph` | None | Emulate OS TCP/IP stack signature: `windows11`, `macos`, `ios`, `linux` |
| | `--anti-injection` | `false` | Enable stateful middlebox injection and DNS poisoning defense |
| | `--anti-injection-ttl-tolerance` | `4` | Maximum allowable TTL hop-count drift before dropping injected packets |
| | `--simd-accel` | `false` | Enable AVX2/SIMD cryptographic vectorization for IP pseudonymization |
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
| **Web UI & Management**| `--web-ui` | `false` | Embedded web management dashboard (opt-in defense-in-depth) |
| | `--web-ui-addr` | `"127.0.0.1:0205"` | HTTP bind address for Web Control Center |
| | `--web-ui-user`, `--web-ui-pass` | `None`, `None` | HTTP Basic Auth credentials |
| | `--metrics` | `false` | Expose Prometheus `/metrics` endpoint on the Web UI port |

### Configuration Precedence & Security Model

Albus checks configuration files in the following strict priority chain:
1. `volatile_config_path()`: Runtime volatile memory (`/run/albus/config.json` for root or `$XDG_RUNTIME_DIR/albus/config.json` / `/run/user/<uid>/albus/config.json` for unprivileged users).
2. `/run/albus/config.json`: System daemon volatile path fallback.
3. `default_config_path()`: Durable persistent user path resolved via `ALBUS_CONFIG_USER`, verified `SUDO_USER` home directory, unprivileged process `$HOME/.config/albus/config.json`, or `/etc/albus/config.json`.
4. `/etc/albus/config.json`: System-wide durable fallback configuration.

This priority chain enforces strict UID verification and symlink defense (`O_NOFOLLOW` / `fstat` descriptor checks), preventing unprivileged local users from injecting malicious configurations into the privileged daemon process.

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

This project is licensed under the [GNU General Public License v3.0 (GPL-3.0)](LICENSE).
