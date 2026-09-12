# Albus v2.1.0 Subsystem Triage & Architecture Rationalization

This document records the architectural audit, triage decisions, and integration verification for the 18 advanced modules evaluated in Albus v2.1.0.

## Triage Matrix

| Module | Decision | Rationale & Integration Plan |
| :--- | :---: | :--- |
| `src/core/ja4_mimic.rs` | **KEEP & CONNECT** | High value for defeating TLS ClientHello fingerprinting (GFW/TSPU). Fully wired into `src/core/fake/mod.rs` and `src/core/rawsock/packet.rs` to synthesize authentic Chrome 130, Firefox 130, and Safari 18 TLS ClientHello records. Tested with wire-level integration tests. |
| `src/core/stack_morph.rs` | **KEEP & CONNECT** | High value for defeating passive OS fingerprinters (p0f). Fully wired into raw TCP SYN and desync packet generation in `rawsock/packet.rs`. Injects genuine TCP options layouts and window parameters for Windows 11, macOS, and iOS. |
| `src/core/anti_injection.rs` | **KEEP & CONNECT** | High value for stateful defense against middlebox out-of-band packet injection. Fully wired into `src/dns/server.rs` to track hop-count TTL discrepancies and isolate spoofed responses. |
| `src/dns/entropy.rs` | **KEEP & CONNECT** | Cryptographic utility providing dual-source hardware RDRAND + OS CSPRNG blending with continuous FIPS 140-2 repetition health checking. Wired into DNSCrypt nonce generation, session key generation, and packet randomization. |
| `src/dns/secure_mem.rs` | **KEEP & CONNECT** | Hardened memory abstraction locking secret keys in physical RAM via `libc::mlock` with `zeroize` on drop. Wired into `dnscrypt_client` and `ipcrypt` session key storage. |
| `src/dns/ipcrypt_batch.rs` | **KEEP & CONNECT** | High-throughput batch IP pseudonymization for query logging and Prometheus differential privacy telemetry. |
| `src/dns/simd_crypto.rs` | **KEEP & CONNECT** | AVX2/SSE/64-bit vector acceleration for parallel IP encryption in high-volume resolver environments. |
| `src/dns/dnssec.rs` | **KEEP & CLARIFY** | RFC 4035 anti-downgrade and IANA root trust anchor pinning (KSK-2017 & KSK-2024). Retained with honest scope documentation: enforces trust anchor pinning and upstream AD bit validation without claiming local ML-DSA signature calculation. |
| `src/core/xdp_filter.rs` | **REMOVE** | Userspace frame parser simulating XDP. True XDP requires a dedicated in-kernel C BPF driver program (`SEC("xdp")`) attached to the NIC. Completely removed: code, CLI flag `--xdp-filter`, config field, and README claims. |
| `src/core/active_probe.rs` | **REMOVE** | Standalone Bloom filter and decoy generator that was never hooked into the daemon's ingress socket pipeline. Completely removed. |
| `src/core/traffic_morph.rs` | **REMOVE** | Standalone delay/padding functions that were not wired into outbound TCP/TLS socket loops. Completely removed. |
| `src/dns/stego.rs` | **REMOVE** | HTTP Cookie / NTP covert channel steganography is unsupported by public upstream resolvers and poses operational/ToS risks. Completely removed. |
| `src/dns/quic_migration.rs` | **REMOVE** | Albus by default drops QUIC (UDP 443) via `--block-quic` to force browsers onto TCP for eBPF MSS clamping. QUIC migration is contradictory to this core evasion strategy. Completely removed. |
| `src/dns/multipath.rs` | **REMOVE** | Multi-upstream query racing is already natively implemented in `src/dns/server.rs::race_upstreams`. `multipath.rs` was a redundant unintegrated struct. Completely removed. |
| `src/dns/sphinx.rs` | **REMOVE** | Albus is a local stub resolver and DPI bypass daemon. It does not operate an external mixnet network with distributed nodes across the Internet. Running `--sphinx-routing` without mixnode infrastructure was misleading. Completely removed. |
| `src/dns/zkp_auth.rs` | **REMOVE** | Public upstream resolvers do not accept ZKP proofs for standard DNS queries, and no upstream authorization protocol exists in the daemon pipeline. Completely removed. |
| `src/dns/blind_token.rs` | **REMOVE** | Requires full RFC 9497 VOPRF server issuance and client evaluation (`voprf` crate), neither of which is supported by public DoH resolvers. Completely removed. |
| `src/dns/noise.rs` | **REMOVE** | Standalone Noise_IKpsk2 handshake not integrated into standard DoH/DoT/DoQ transports. Completely removed. |

