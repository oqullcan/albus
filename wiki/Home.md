# Albus Wiki

Welcome to the official documentation and technical wiki for **Albus**, a kernel-level deep packet inspection (DPI) evasion engine and hardened post-quantum DNS subsystem engineered in pure Rust for Linux.

---

## Architectural Overview

Albus operates at the intersection of Linux kernel networking and modern cryptographic DNS transport. It combines in-kernel eBPF bytecode instrumentation, raw socket desynchronization, and an encrypted DNS resolver to provide comprehensive censorship circumvention and privacy enforcement.

```
                  +----------------------------------------+
                  |              Application               |
                  +---+--------------------------------+---+
        DNS (UDP/TCP, |                                | TCP SYN (:443)
        DoH :8053)    v                                v
+--------------------------------------+ +--------------------------------------+
|       Hardened DNS Subsystem         | |      Kernel eBPF & Packet Stack      |
+--------------------------------------+ +--------------------------------------+
| * Happy Eyeballs Racing & DoH/ODoH   | | * eBPF sock_ops MSS Clamping & Jitter|
| * ML-KEM-768 Post-Quantum Key Exch   | | * Zero-Alloc Raw Socket Fake Injector|
| * HaGeZi Radix Trie Threat Sinkhole  | | * Auto-TTL & Decoy SNI Pool Rotation |
| * CNAME / HTTPS Alias Uncloaking     | | * Dynamic Line-Rate MSS Restoration  |
| * Anti-Rebinding & Bogon IP Filter   | | * Zero-Downtime Map Pinning (/sys/fs)|
| * DNS Kill-Switch & Canary Watchdog  | | * Dual-Stack IPv4 & IPv6 Support     |
+--------------------------------------+ +--------------------------------------+
```

---

## Core Pillars

### 1. In-Kernel eBPF Transport Shaping
Albus attaches `BPF_PROG_TYPE_SOCK_OPS` programs to the root cgroup v2 hierarchy. Upon TCP connection establishment, the kernel clamps the Maximum Segment Size (MSS) to 88 bytes with per-connection randomized jitter. This forces the initial TLS `ClientHello` payload to split across multiple TCP segments, defeating stateful deep packet inspection without requiring userspace packet proxying. Once the handshake traverses the middlebox, Albus automatically restores standard line-rate MSS (1460 bytes).

### 2. Active Middlebox Desynchronization
For advanced DPI equipment that reassembles TCP streams, Albus employs a zero-allocation raw socket engine. It injects synthetic `ClientHello` packets carrying dynamic Auto-TTL hop estimation, rotating decoy Server Name Indication (SNI) domains, sequence number offsets, or intentional L4 checksum corruption (`0xDEAD`). State-tracking middleboxes consume the invalid payload and drop synchronization, while the true destination server ignores the corrupted frame and accepts the genuine handshake.

### 3. Post-Quantum Hardened DNS Subsystem
The integrated DNS server functions as a local stub resolver listening on UDP/TCP port 53 and local RFC 8484 DoH on `127.0.0.1:8053`. Outbound queries are secured using DNS-over-HTTPS (DoH) or Oblivious DoH (RFC 9230 HPKE) with hybrid `X25519 + Kyber768` (`ML-KEM-768`) post-quantum key exchange. Multi-upstream Happy Eyeballs racing minimizes query resolution latency.

### 4. Comprehensive Threat Shield & Leak Prevention
An in-memory radix trie compiles more than 350,000 HaGeZi Multi PRO and Threat Intelligence rules into a compact binary arena consuming under 5 MB of RAM. Queries are protected against CNAME and HTTPS/SVCB alias cloaking, private RFC 1918 rebinding attacks, and Martian/Bogon IP ranges. Kernel firewall rules enforce a strict plaintext DNS kill-switch and block QUIC (UDP 443) and WebRTC STUN leaks.

### 5. Web & Desktop Control Surfaces
System state and telemetry can be inspected and configured live through:
* **Web Control Center**: An embedded zero-dependency HTTP dashboard running on `127.0.0.1:0205` featuring real-time telemetry sparkline graphs, live log stream cockpit, and hot-reload controls.
* **Omarchy Shell Widget**: Native QML desktop panel integration (`BarWidget.qml` and `Panel.qml`) for the Omarchy Quattro shell.
* **Terminal CLI & TUI**: Interactive terminal monitoring (`albus monitor`) and configuration CLI (`albus config`).

---

## Wiki Navigation

* [Installation and Getting Started](Installation-and-Getting-Started.md) - System requirements, compilation, systemd service deployment, and first run.
* [DPI Evasion Engine](DPI-Evasion-Engine.md) - Deep dive into eBPF `sock_ops`, MSS clamping, fake packet synthesis, Auto-TTL, and HTTP fragmentation.
* [Hardened DNS Subsystem](Hardened-DNS-Subsystem.md) - DoH upstream racing, ML-KEM-768 PQC, Oblivious DoH, HaGeZi blocklist compilation, and leak shields.
* [Web Control Center](Web-Control-Center.md) - Embedded HTTP dashboard architecture, 6 functional views, REST API endpoints, and real-time monitoring.
* [CLI Reference and Configuration](CLI-Reference-and-Configuration.md) - Command line options, JSON configuration specification, and live SIGHUP reloads.
* [Desktop Integration (QML)](Desktop-Integration-QML.md) - Integration with the Omarchy Quattro desktop shell panel and widget system.
* [Troubleshooting and FAQ](Troubleshooting-and-FAQ.md) - Common diagnostics, kernel requirements, permission management, and FAQ.
