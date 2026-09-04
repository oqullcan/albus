# albus

> A kernel-level deep packet inspection (DPI) evasion engine and post-quantum DNS-over-HTTPS resolver for Linux.

[![author](https://img.shields.io/badge/author-oqullcan-blue.svg)](https://github.com/oqullcan)
[![rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![ebpf](https://img.shields.io/badge/kernel-eBPF%20CO--RE-success.svg)](https://docs.kernel.org/bpf/)
[![crypto](https://img.shields.io/badge/pqc-ML--KEM--768-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![license](https://img.shields.io/badge/license-MIT-lightgrey.svg)](LICENSE)

---

## Abstract

**albus** implements transparent transport-layer desynchronization and post-quantum encrypted domain name resolution directly within the Linux network stack. By leveraging BPF CO-RE (`BPF_PROG_TYPE_SOCK_OPS`) attached to the unified cgroup v2 hierarchy, the engine dynamically modulates TCP Maximum Segment Size (MSS) during initial connection establishment to fragment TLS ClientHello records across multiple IP datagrams. Concurrently, a zero-allocation raw socket engine injects synthetic desynchronization payloads with destination-adaptive Time-to-Live (Auto-TTL) values, inducing state desynchronization in stateful middleboxes without disrupting end-to-end transport semantics.

---

## Technical Specifications

| Component | Standard / Mechanism | Implementation Details |
| :--- | :--- | :--- |
| **Transport Modulation** | RFC 793, eBPF `sock_ops` | `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` clamps MSS (88 bytes or jittered 64–88 bytes via `bpf_get_prandom_u32`); restored to line-rate (1460 bytes) via `BPF_SOCK_OPS_HDR_OPT_LEN_CB` after 600 bytes. |
| **Packet Injection** | RFC 791, RFC 8200, RFC 1071, `SOCK_RAW` | Stack-allocated dual-stack IPv4/IPv6 L3/L4 serialization with `IP_HDRINCL`/`IPV6_HDRINCL`, rotating decoy SNI pool, and optional `0xDEAD` checksum corruption. |
| **Kernel Portability** | BPF CO-RE & BTF | Ahead-of-time bytecode compilation with runtime BTF (`/sys/kernel/btf/vmlinux`) struct relocation across Linux 5.10–6.x+ kernels. |
| **Interface Roaming** | Dynamic Route Resolver | `/proc/net/route` gateway tracking seamlessly preserves state across Wi-Fi (`wlan0`), Ethernet (`eth0`), and VPN (`tailscale0`, `wg0`) transitions. |
| **Live Map Reload** | Runtime eBPF Reconfiguration | Zero-downtime updates of target ports, exclusion maps, and MSS limits via `SIGHUP` (`albus service reload` / `albus config set`). |
| **Path Heuristics** | Auto-TTL Estimation | Dynamic hop-distance probing with boundary clamping (3–12 hops) and in-memory TTL caching. |
| **Encrypted Resolver** | RFC 8484 (DoH), RFC 6891 (EDNS0) | Multi-upstream HTTP/2 client pool, EDNS0 DO-bit validation, and optional AAAA record filtering. |
| **Post-Quantum Security** | NIST FIPS 203 (ML-KEM-768) | Hybrid `X25519 + Kyber768` key exchange via `aws-lc-rs` cryptographic provider. |
| **Storage & Memory** | Dual-Tier Isolation | Durable master configuration in `~/.config/albus/config.json` with volatile `/run` tmpfs runtime execution and `write_volatile` zeroization. |
| **Access Control** | Polkit Rules | Scoped `/etc/polkit-1/rules.d/albus.rules` enables unprivileged desktop management of `albus.service`. |

---

## Architecture

```
                  ┌──────────────────────────────────────────────────┐
                  │          Application (Browser / Client)          │
                  └──────────────┬────────────────────┬──────────────┘
                    DNS (UDP 53) │                    │ TCP SYN (:443)
                                 ▼                    ▼
┌──────────────────────────────────────────┐ ┌──────────────────────────────────────────┐
│         Local Encrypted Resolver         │ │        Kernel eBPF & Packet Stack        │
│                                          │ │                                          │
│ ├─ In-Memory Response Cache (0ms)        │ │ 1. eBPF ACTIVE_ESTABLISHED               │
│ ├─ Post-Quantum ML-KEM-768 Key Exchange  │ │    Clamps initial TCP MSS = 88 bytes     │
│ ├─ DNSSEC DO-bit & AD Validation         │ │    Notifies userspace via perf event ring│
│ ├─ IPv6 (AAAA) Leak Filtering            │ │                                          │
│ └─ Upstream Dispatch:                    │ │ 2. Raw Socket Packet Injector            │
│    • Quad9 / Cloudflare / Mullvad        │ │    Emits fake ClientHello (Optimal TTL)  │
│    • Custom Bootstrap IP Resolution      │ │    Middlebox state table desynchronizes  │
│                                          │ │                                          │
│                                          │ │ 3. ClientHello Transmission              │
│                                          │ │    Segmented records bypass DPI filter   │
│                                          │ │                                          │
│                                          │ │ 4. eBPF WRITE_HDR_OPT                    │
│                                          │ │    Restores native MSS (1460 bytes)      │
└──────────────────────────────────────────┘ └──────────────────────────────────────────┘
```

---

## Evasion Mechanisms

### 1. TCP Segmentation & Dynamic MSS Jitter (`--min-mss`)
Middlebox DPI systems inspect initial TCP payloads for plaintext Server Name Indication (SNI) extensions (RFC 6066). Albus programmatically sets `bpf_setsockopt(skops, SOL_TCP, TCP_BPF_MSS, mss)` on established sockets to split the ClientHello handshake across multiple TCP segments. To prevent DPI statistical fingerprinting based on static segment boundaries, Albus supports MSS Jitter: when `--min-mss` (default: `64`) is configured below `--mss` (default: `88`), the eBPF kernel hook invokes `bpf_get_prandom_u32()` to randomize the initial MSS per connection within the `[min_mss, mss]` range. After the ClientHello phase exceeds `--restore-after-bytes` (default: 600 bytes), native line-rate MSS (1460 bytes) is restored automatically.

### 2. Decoy SNI Pool Rotation & Auto-TTL Desynchronization
Albus probes the network path to estimate the router hop distance $H$ to the destination IP and computes an optimal injection TTL:
$$TTL_{opt} = \text{clamp}\left(H_{estimated} - \delta, TTL_{min}, TTL_{max}\right)$$
The zero-allocation raw socket engine synthesizes and injects a fake ClientHello matching the socket 4-tuple. To defeat middlebox heuristics that filter static fake payloads, Albus rotates across a pre-compiled pool of high-reputation decoy SNIs (Google, Cloudflare, Microsoft, AWS, Apple) unless a specific `--fake-sni` override is provided. The fake segment expires at or just past the DPI middlebox, poisoning its state table, while the authentic segmented payload reaches the destination intact.

### 3. Dual-Stack IPv6 & IPv4 eBPF Evasion
The eBPF kernel program (`sockops.bpf.c`) natively processes both `AF_INET` and `AF_INET6` socket families. For IPv6 connections, it extracts 128-bit IPv6 endpoints (`remote_ip6` / `local_ip6`), checks the dedicated `exclude_ips_v6` 16-byte BPF hash map, modulates MSS, and emits 128-bit connection events. The userspace injector synthesizes valid RFC 8200 IPv6 raw packets with full TCP pseudo-header checksum computation transmitted via `IPV6_HDRINCL`.

### 4. Zero-Downtime Live Map Reload (SIGHUP)
Runtime configurations—including target ports, exclusion IP lists, and MSS bounds—can be updated instantly without restarting `albus.service` or severing active network connections. Dispatching `SIGHUP` (or executing `sudo albus service reload` / `albus config set ...`) synchronizes running eBPF maps atomically in kernel space.

### 5. Post-Quantum DoH Resolution
To mitigate "Harvest Now, Decrypt Later" surveillance, the DNS subsystem employs hybrid post-quantum key encapsulation (`X25519Kyber768Draft00` / `SecP256r1MLKEM768`). Upstream queries to Quad9, Cloudflare, and Mullvad are protected against future cryptanalytic attacks on elliptic-curve discrete logarithms.

### 6. DNS Leak Protection & Active Canary Watchdog
- **DNS Kill-Switch (`--kill-switch`)**: Injects kernel-level firewall (`iptables`/`ip6tables`) drop rules on all outbound non-loopback UDP/TCP port 53 traffic. Ensures no misconfigured background processes can leak plaintext DNS queries to the local ISP.
- **Active Leak Canary Watchdog**: An autonomous background prober actively queries `leak-test.albus.internal` every 60 seconds over loopback (`127.0.0.1:53`), verifying the synthetic canary record (`127.0.0.99`). If queries fail or return unexpected data (due to VPN route takeovers, network managers overwriting `/etc/resolv.conf`, or DNS hijacking), it triggers instant autonomous self-healing.
- **Fail-Closed Network Lockdown (`--network-lockdown`)**: Distinct from the DNS Kill-Switch, Network Lockdown drops all outbound non-loopback web traffic (TCP 80 and 443) if the eBPF subsystem fails to attach. This guarantees that unfragmented, unevaded cleartext traffic is never leaked to the ISP if DPI evasion cannot be sustained.
- **WebRTC STUN Blocking (`--block-stun`)**: Drops outbound UDP traffic on standard STUN/TURN ports 3478 and 5349 to eliminate real IPv4/IPv6 exposure through WebRTC peer connection candidates.

---

## Installation & Build

### Prerequisites
- **Kernel**: Linux 5.10+ with `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, and cgroup v2.
- **Toolchain**: Rust 1.75+ (Cargo). *(Pre-built binary runs standalone via BPF CO-RE without clang or kernel headers).*
- **Permissions**: `CAP_NET_RAW`, `CAP_BPF`, `CAP_NET_ADMIN` (or `sudo`).

### Compilation
```bash
git clone https://github.com/oqullcan/albus.git
cd albus
git checkout v2.1.0

# Compile release profile with LTO and binary stripping
cargo build --release

# Install binary to system path
sudo cp target/release/albus /usr/local/bin/albus
```

---

## Command-Line Interface

### Core Execution
```bash
# Start engine with default parameters
sudo albus run

# Enforce volatile Only-RAM execution in /run tmpfs
sudo albus run --ram-only=true --pqc=true

# Configure Mullvad upstream with malware and tracker blocking
sudo albus run --doh-upstream mullvad-base

# Custom DoH endpoint with dedicated bootstrap IP addressing
sudo albus run --doh-upstream "https://doh.example.com/dns-query" --doh-bootstrap-ips "93.184.216.34"
```

### Daemon Management
```bash
sudo albus service install   # Install systemd unit and provision albus.rules
sudo albus service start     # Start background daemon
sudo albus service status    # Inspect operational metrics
sudo albus service reload    # Send SIGHUP for zero-downtime runtime map reload
albus monitor                # Interactive curses-style telemetry TUI
```

### Options Reference
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--mss` | `u16` | `88` | Initial TCP MSS size for TLS ClientHello fragmentation |
| `--min-mss` | `u16` | `64` | Minimum TCP MSS for randomized per-connection jitter (`0` disables jitter) |
| `--restore-after-bytes` | `u32` | `600` | Transmitted byte threshold prior to line-rate MSS restoration |
| `--fake-ttl` | `u8` | `8` | Fallback TTL for raw socket packet injection |
| `--auto-ttl` | `bool` | `true` | Dynamic hop-distance path measurement |
| `--fake-sni` | `String` | `None` | Server Name Indication override (defaults to rotating high-reputation pool) |
| `--fake-bad-checksum` | `bool` | `false` | Invalidate TCP checksum (`0xDEAD`) for middlebox corruption |
| `--doh` | `bool` | `true` | Spawn local DNS-over-HTTPS resolver on `127.0.0.1:53` |
| `--doh-upstream` | `String` | `"quad9"` | Upstream resolver (`quad9`, `cloudflare`, `mullvad-*`, URL) |
| `--doh-bootstrap-ips` | `Vec<IPv4>`| `[]` | Static IPv4 bootstrap endpoints for DoH host resolution |
| `--dnssec` | `bool` | `true` | Enforce EDNS0 DO-bit and Authenticated Data validation |
| `--pqc` | `bool` | `true` | Enable hybrid ML-KEM-768 post-quantum key exchange |
| `--ram-only` | `bool` | `true` | Isolate runtime state in volatile `/run` tmpfs while retaining preferences |
| `--block-quic` | `bool` | `true` | Drop outbound UDP 443 to force TLS/TCP transport |
| `--block-stun` | `bool` | `true` | Drop outbound STUN (UDP 3478, 5349) to prevent WebRTC IP leaks |
| `--kill-switch` | `bool` | `true` | Strict DNS kill-switch dropping non-loopback UDP/TCP 53 |
| `--network-lockdown` | `bool` | `false` | Fail-closed network kill-switch dropping TCP 80/443 if eBPF fails |
| `--block-ipv6` | `bool` | `true` | Filter AAAA queries to prevent IPv6 inspection bypass leaks |

---

## Desktop Integration (Omarchy Shell)

Albus includes a first-party Omarchy Quattro desktop panel widget (`BarWidget.qml` & `Panel.qml`) providing live packet stream monitoring, one-click resolver switching (Quad9, Cloudflare, Mullvad profiles), security toggles, and keyboard shortcuts (`1-3` tabs, `Space` toggle, `P` pause, `J/K` scroll).

```bash
# Deploy plugin to active user configuration directory
mkdir -p ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev
cp manifest.json BarWidget.qml Panel.qml ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev/
omarchy-shell shell rescanPlugins
```

---

## License

This project is licensed under the **MIT License**.  
Author: **oqullcan**
