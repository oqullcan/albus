# albus

> **Kernel-level deep packet inspection (DPI) evasion engine and post-quantum DNS subsystem for Linux.**

[![author](https://img.shields.io/badge/author-oqullcan-blue.svg)](https://github.com/oqullcan)
[![rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![ebpf](https://img.shields.io/badge/kernel-eBPF%20CO--RE-success.svg)](https://docs.kernel.org/bpf/)
[![crypto](https://img.shields.io/badge/pqc-ML--KEM--768-purple.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![license](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

---

### Highlights

* **eBPF Transport Shaping**: In-kernel `sock_ops` hooks (`BPF_PROG_TYPE_SOCK_OPS`) clamp initial TCP MSS to 88 bytes with per-connection jitter (`[min_mss..mss]`), fragmenting TLS `ClientHello` across packet boundaries before restoring line-rate (1460 B).
* **Desync Packet Injection**: Zero-allocation raw socket engine synthesizes and injects fake `ClientHello` packets with dynamic Auto-TTL hop estimation, rotating decoy SNI pool, sequence number shifts (`fake-seq-offset`), and middlebox checksum poisoning (`0xDEAD`).
* **HTTP/1.1 Evasion**: Request pipeline method fragmentation (`G` + `ET /`) breaks cleartext middlebox pattern matching and deep regex inspection.
* **Quantum-Safe Resolution**: Native DoH & Oblivious DoH (RFC 9230 HPKE) client pool supporting hybrid `X25519 + Kyber768` (`ML-KEM-768`).
* **Happy Eyeballs Racing**: Multi-upstream concurrent query racing across Quad9, Cloudflare, and Mullvad for sub-millisecond response latency.
* **Radix Trie Threat Shield**: High-performance in-memory HaGeZi Multi PRO + TIF filter (200,000+ rules in <5 MB RAM), CNAME & HTTPS/SVCB uncloaking, Bogon/Martian IP filtering, and anti-DNS rebinding.
* **Leak-Proof Resilience**: Kernel-level firewall DNS kill-switch, fail-closed network lockdown, active canary watchdog (`leak-test.albus.internal`), and WebRTC STUN drops.
* **Zero-Downtime Hot Reload**: Atomic eBPF map synchronization via `SIGHUP` and persistent map pinning under `/sys/fs/bpf/albus`.

---

## Architecture

```
                  ┌────────────────────────────────────────┐
                  │              Application               │
                  └───┬────────────────────────────────┬───┘
        DNS (UDP/TCP, │                                │ TCP SYN (:443)
        DoH :8053)    ▼                                ▼
┌──────────────────────────────────────┐ ┌──────────────────────────────────────┐
│       Hardened DNS Subsystem         │ │      Kernel eBPF & Packet Stack      │
├──────────────────────────────────────┤ ├──────────────────────────────────────┤
│ • Happy Eyeballs Racing & DoH/ODoH   │ │ • eBPF sock_ops MSS Clamping & Jitter│
│ • ML-KEM-768 Post-Quantum Key Exch   │ │ • Zero-Alloc Raw Socket Fake Injector│
│ • HaGeZi Radix Trie Threat Sinkhole  │ │ • Auto-TTL & Decoy SNI Pool Rotation │
│ • CNAME / HTTPS Alias Uncloaking     │ │ • Dynamic Line-Rate MSS Restoration  │
│ • Anti-Rebinding & Bogon IP Filter   │ │ • Zero-Downtime Map Pinning (/sys/fs)│
│ • DNS Kill-Switch & Canary Watchdog  │ │ • Dual-Stack IPv4 & IPv6 Support     │
└──────────────────────────────────────┘ └──────────────────────────────────────┘
```

---

## Quick Start

### Build & Install

```bash
git clone https://github.com/oqullcan/albus.git && cd albus
cargo build --release
sudo cp target/release/albus /usr/local/bin/
```

### Run

```bash
# Run in foreground with defaults
sudo albus run

# Or manage as a systemd background daemon
sudo albus service install
sudo albus service start

# Launch real-time telemetry TUI
albus monitor
```

---

## Configuration & CLI

```bash
# Inspect active configuration (JSON)
albus config get

# Apply changes live without restarting the daemon (SIGHUP)
sudo albus config set --doh-upstream cloudflare --dns-racing true --fake-bad-checksum true

# Flush DNS cache
sudo albus service reload
```

### Core Options

| Category | Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| **DPI Evasion** | `--mss`, `--min-mss` | `88`, `64` | Initial TCP MSS clamp & jitter randomization bounds |
| | `--auto-ttl`, `--fake-ttl` | `true`, `8` | Dynamic hop-distance path measurement (3–12) or fallback TTL |
| | `--fake-sni`, `--fake-seq-offset` | rotating, `0` | Decoy SNI override & TCP sequence number shift offset |
| | `--fake-bad-checksum` | `false` | Invalidate TCP checksum (`0xDEAD`) to desynchronize middleboxes |
| **DNS Subsystem** | `--doh-upstream` | `"quad9"` | Upstream resolver (`quad9`, `cloudflare`, `mullvad-*`, `sdns://...`) |
| | `--dns-racing` | `true` | Concurrent multi-upstream Happy Eyeballs resolution |
| | `--odoh`, `--odoh-relay`, `--odoh-target` | `false` | RFC 9230 Oblivious DoH HPKE proxy relay client |
| | `--pqc`, `--dnssec` | `true`, `true` | ML-KEM-768 hybrid key exchange & DNSSEC DO-bit validation |
| | `--local-doh`, `--local-doh-addr` | `true`, `:8053` | Local RFC 8484 HTTP/1.1 endpoint on `127.0.0.1:8053/dns-query` |
| **Security & Privacy** | `--blocklist`, `--blocklist-path` | `true`, auto | Compact in-memory HaGeZi Multi PRO + TIF ad/threat sinkhole |
| | `--uncloak-cnames`, `--block-bogons`| `true`, `true` | CNAME/HTTPS tracker uncloaking & Martian/Bogon IP filter |
| | `--kill-switch`, `--network-lockdown` | `true`, `false` | Strict port 53 firewall drop & fail-closed web traffic lockdown |
| | `--block-quic`, `--block-stun` | `true`, `true` | Drop outbound UDP 443 (force TCP) & WebRTC STUN UDP 3478/5349 |
| | `--ram-only` | `false` | Volatile execution in `/run` tmpfs (zero persistent disk traces) |

---

## Desktop Integration (Omarchy Shell)

Albus includes a native desktop panel widget for the Omarchy Quattro shell (`BarWidget.qml` & `Panel.qml`) featuring real-time packet flow telemetry, one-click resolver selection, live threat counters, and interactive security controls.

<p align="center">
  <img src="assets/panel_settings.png" alt="Albus Panel Settings" width="48%" />
  <img src="assets/panel_logs.png" alt="Albus Panel Live Logs" width="48%" />
</p>

```bash
mkdir -p ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev
cp manifest.json BarWidget.qml Panel.qml ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev/
omarchy-shell shell rescanPlugins
```

---

## License

This project is licensed under the [GNU General Public License v3.0 (GPL-3.0)](LICENSE).
