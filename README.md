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
| **Transport Modulation** | RFC 793, eBPF `sock_ops` | `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` clamps MSS (88 bytes); restored to line-rate (1460 bytes) via `BPF_SOCK_OPS_HDR_OPT_LEN_CB` after 600 bytes. |
| **Packet Injection** | RFC 791, RFC 1071, `SOCK_RAW` | Stack-allocated L3/L4 serialization with `IP_HDRINCL` and optional `0xDEAD` checksum corruption. |
| **Kernel Portability** | BPF CO-RE & BTF | Ahead-of-time bytecode compilation with runtime BTF (`/sys/kernel/btf/vmlinux`) struct relocation across Linux 5.10–6.x+ kernels. |
| **Interface Roaming** | Dynamic Route Resolver | `/proc/net/route` gateway tracking seamlessly preserves state across Wi-Fi (`wlan0`), Ethernet (`eth0`), and VPN (`tailscale0`, `wg0`) transitions. |
| **Path Heuristics** | Auto-TTL Estimation | Dynamic hop-distance probing with boundary clamping (3–12 hops) and in-memory TTL caching. |
| **Encrypted Resolver** | RFC 8484 (DoH), RFC 6891 (EDNS0) | Multi-upstream HTTP/2 client pool, EDNS0 DO-bit validation, and AAAA record filtering. |
| **Post-Quantum Security** | NIST FIPS 203 (ML-KEM-768) | Hybrid `X25519 + Kyber768` key exchange via `aws-lc-rs` cryptographic provider. |
| **Storage & Memory** | Dual-Tier Isolation | Durable master configuration in `~/.config/albus/config.json` with volatile `/dev/shm` runtime execution and `write_volatile` zeroization. |
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

### 1. TCP Segmentation (MSS Clamping)
Middlebox DPI systems inspect the initial TCP payload for plaintext Server Name Indication (SNI) extensions (RFC 6066). By programmatically setting `bpf_setsockopt(skops, SOL_TCP, TCP_BPF_MSS, 88)`, the kernel splits the ClientHello handshake into multiple TCP segments. The middlebox fails stream reassembly while the destination TCP endpoint reconstructs the stream seamlessly.

### 2. Auto-TTL Middlebox Desynchronization
Albus probes the network path to determine the router hop distance $H$ to the destination IP. It computes an optimal injection TTL:
$$TTL_{opt} = \text{clamp}\left(H_{estimated} - \delta, TTL_{min}, TTL_{max}\right)$$
The raw socket injects a synthetic TLS record matching the connection 4-tuple. The fake segment expires after traversing the middlebox but before reaching the destination, poisoning the inspection state machine.

### 3. Post-Quantum DoH Resolution
To mitigate "Harvest Now, Decrypt Later" surveillance, the DNS subsystem employs hybrid post-quantum key encapsulation (`X25519Kyber768Draft00` / `SecP256r1MLKEM768`). Upstream queries to Quad9, Cloudflare, and Mullvad are protected against future cryptanalytic attacks on elliptic-curve discrete logarithms.

---

## Installation & Build

### Prerequisites
- **Kernel**: Linux 5.10+ with `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, and cgroup v2.
- **Toolchain**: Rust 1.75+ (Cargo). *(Pre-built binary runs standalone via BPF CO-RE without clang or kernel headers).*
- **Permissions**: `CAP_NET_RAW`, `CAP_BPF`, `CAP_NET_ADMIN` (or `sudo`).

### Compilation
```bash
git clone https://github.com/albusdpi/albus.git
cd albus

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

# Enforce volatile Only-RAM execution in /dev/shm
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
albus monitor                # Interactive curses-style telemetry TUI
```

### Options Reference
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--mss` | `u16` | `88` | Initial TCP MSS size for TLS ClientHello fragmentation |
| `--restore-after-bytes` | `u32` | `600` | Transmitted byte threshold prior to line-rate MSS restoration |
| `--fake-ttl` | `u8` | `8` | Fallback TTL for raw socket packet injection |
| `--auto-ttl` | `bool` | `true` | Dynamic hop-distance path measurement |
| `--fake-sni` | `String` | `"www.google.com"` | Server Name Indication string embedded in fake payloads |
| `--fake-bad-checksum` | `bool` | `false` | Invalidate TCP checksum (`0xDEAD`) for middlebox corruption |
| `--doh` | `bool` | `true` | Spawn local DNS-over-HTTPS resolver on `127.0.0.1:53` |
| `--doh-upstream` | `String` | `"quad9"` | Upstream resolver (`quad9`, `cloudflare`, `mullvad-*`, URL) |
| `--doh-bootstrap-ips` | `Vec<IPv4>`| `[]` | Static IPv4 bootstrap endpoints for DoH host resolution |
| `--dnssec` | `bool` | `true` | Enforce EDNS0 DO-bit and Authenticated Data validation |
| `--pqc` | `bool` | `true` | Enable hybrid ML-KEM-768 post-quantum key exchange |
| `--ram-only` | `bool` | `true` | Isolate runtime state in volatile `/dev/shm` while retaining preferences |
| `--block-quic` | `bool` | `true` | Drop outbound UDP 443 to force TLS/TCP transport |
| `--block-ipv6` | `bool` | `true` | Filter AAAA queries to prevent IPv6 inspection bypass leaks |

---

## Desktop Integration (Omarchy Shell)

Albus includes a first-party Omarchy Quattro desktop panel widget in `extra/omarchy/` providing live packet stream monitoring, one-click resolver switching (Quad9, Cloudflare, Mullvad profiles), security toggles, and keyboard shortcuts (`1-3` tabs, `Space` toggle, `P` pause, `J/K` scroll).

```bash
# Deploy plugin to active user configuration directory
mkdir -p ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev
cp -r extra/omarchy/* ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev/
omarchy-shell shell rescanPlugins
```

---

## License

This project is licensed under the **MIT License**.  
Author: **oqullcan**
