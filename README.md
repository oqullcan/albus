# Albus

A local anti-censorship and DPI evasion daemon for Linux desktop environments, natively integrated with the Omarchy shell bar.

Albus modifies outbound TLS and HTTP packet boundaries locally using TCP segmentation, socket low-water tuning, and encrypted DNS resolution, without routing client traffic through third-party VPN servers or remote relays.

---

## Technical Overview

Deep Packet Inspection (DPI) systems deployed by internet service providers inspect the initial unencrypted bytes of network handshakes, primarily the TLS ClientHello Server Name Indication (SNI) extension or HTTP/1.1 `Host` headers.

Albus intercepts local outbound connections transparently and applies targeted packet fragmentation, socket queue pacing, and header normalization evasion. Because compliant destination servers buffer and reassemble TCP streams according to RFC standards while many on-path DPI middleboxes operate with shallow packet inspection buffers or incomplete TCP reassembly states, the fragmented packets traverse inspection filters without modifying the end-to-end payload.

---

## Core Evasion & Transport Components

### 1. TLS Record Segmentation (`0x16`)
* **Mechanism**: Splits the TLS ClientHello record across multiple TCP segments (1-byte head segmentation at offset 1).
* **Objective**: Prevents shallow DPI pattern matchers from extracting the full SNI hostname within a single IP packet.

### 2. Socket Queue Tuning (`TCP_NOTSENT_LOWAT`)
* **Mechanism**: Sets `TCP_NOTSENT_LOWAT` to 16,384 bytes (16 KB) on all outbound sockets.
* **Technical Trade-Off**: Caps the amount of unsent data buffered in the socket write queue. This prevents the Linux kernel TCP stack from coalescing micro-segments (such as 1-byte ClientHello chunks) into large MTU frames before transmission, ensuring segment boundaries survive on the wire. This introduces a minor throughput ceiling on very high-bandwidth links in exchange for strict segment separation.

### 3. Out-of-Order TCP Pacing (Disorder) & RST Recovery
* **Mechanism**: Transmits TLS handshake segments out-of-order with microsecond window pacing.
* **Adaptive Escalation**: Tracks per-domain connection health in volatile memory. If an ISP-injected spoofed TCP RST packet or connection drop is detected during initial handshakes, the engine automatically escalates that destination to disorder segmentation.

### 4. HTTP/1.1 Host Header Case Permutation (RFC 7230)
* **Mechanism**: Permutes the case of plain HTTP `Host:` headers (e.g. `hOsT:`) and strips client tracking headers (`Referer`, `X-Forwarded-For`, `Client-IP`).
* **Scope & Limitation**: Serves as a lightweight heuristic against legacy middleboxes that rely on case-sensitive string matching. Modern L7 inspection engines normalize header casing; this feature is an opportunistic layer and not an absolute bypass mechanism for unencrypted traffic.

### 5. Encrypted DNS Relay (DoH) with Dual UDP+TCP
* **Dual UDP + TCP Listeners**: Listens on `127.0.0.1:5300` for both UDP and TCP queries (RFC 1035 / RFC 7766), ensuring compatibility with large DNSSEC responses and truncation fallback.
* **EDNS0 ECS Stripping**: Sanitizes EDNS0 Option `0x0008` (Client Subnet) to prevent client IP subnet leakage.
* **RFC 8467 Block Padding**: Pads DNS queries to uniform 128-byte increments to mitigate packet size fingerprinting.
* **Micro-Jitter**: Introduces non-blocking 500µs–1500µs randomized delays to mitigate timing correlation analysis.
* **DNSSEC Enforcement**: Enforces the DNSSEC `DO` bit on outgoing upstream queries.
* **Bounded In-Memory Micro-Cache**: Maintains an in-memory TTL cache (capped at 2048 entries) for instant resolution.

### 6. Volatile Memory Scrubbing & Physical Locking
* **Volatile Zeroization**: Uses the `zeroize` crate to erase handshake buffers in RAM immediately after socket dispatch.
* **Physical RAM Locking**: Executes `libc::mlockall` on startup to keep daemon memory in physical RAM, preventing sensitive buffers from being written to swap partitions (requires `CAP_IPC_LOCK` or sufficient `RLIMIT_MEMLOCK`).

---

## Packet Routing & Firewall Specification

```
[ Application / Browser ]
         │
         │ (Plain TCP traffic & UDP 53 DNS)
         ▼
[ Linux Network Layer (iptables / Netfilter) ]
         │
         ├───► Marked with 0x1337? ──► YES ──► Pass directly to Network Interface (No Loop)
         │
         ├───► Destination is Private IP / Whitelist? ──► YES ──► Pass directly to Network Interface
         │
         ├───► UDP/TCP Port 53 (DNS) ──► REDIRECT to 127.0.0.1:5300 (Albus DoH Relay)
         │
         ├───► External UDP Port 53 (Leak Protection) ──► DROP (Dead-Man Switch)
         │
         ├───► UDP Port 443 (QUIC / HTTP3) ──► REJECT (Forces browser to use TLS 1.3 TCP)
         │
         └───► TCP Port 80 / 443 ──► REDIRECT to 127.0.0.1:1080 (Albus Core Proxy)
                                                    │
                                                    ▼
                                     [ Albus Core (User Space) ]
                                                    │
                                                    ├── Applies 1-byte TLS Split / Disorder
                                                    ├── Queries DoH Upstream
                                                    ├── Sets Socket Mark 0x1337
                                                    └── Dispatches to Origin Server
```

### Netfilter Chain Layout

1. **`ALBUS` Chain (`nat` Table, `OUTPUT`)**
   * Packets carrying `SO_MARK 0x1337` are returned (`RETURN`) to prevent proxy loops.
   * Private IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) and upstream DoH bootstrap IPs bypass redirection.
   * Outbound TCP traffic to ports 80 and 443 is redirected to `127.0.0.1:1080`.

2. **`ALBUS_DNS` Chain (`nat` Table, `OUTPUT`)**
   * Packets carrying `SO_MARK 0x1337` are returned.
   * Private subnet DNS queries bypass redirection to preserve local LAN / Pi-hole resolvers.
   * Outbound UDP and TCP traffic to port 53 is redirected to `127.0.0.1:5300`.

3. **Dead-Man Switch (`filter` Table, `OUTPUT`)**
   * Any external unencrypted UDP 53 packets bypassing the NAT chain are dropped (`DROP`), preventing unencrypted DNS leakage.

4. **QUIC Blocker (`filter` Table, `OUTPUT`)**
   * Outbound UDP 443 is rejected with `icmp-port-unreachable` to force HTTP/3 clients to negotiate TCP TLS 1.3.

5. **Loopback Port Isolation (`filter` Table, `INPUT`)**
   * Non-loopback packets targeting local ports 1080 and 5300 are dropped to prevent local network scanning.

---

## Privilege Model & System Requirements

* **Operating System**: Linux with Kernel ≥ 5.10 (x86_64 or aarch64).
* **Dependencies**: `iptables`, `iproute2`, `systemd`, `zenity` (optional, for GUI profile picker), `quickshell` (for Omarchy bar UI).
* **Privilege Separation & TOCTOU Protection**:
  * **Privileged System Helper (`/usr/lib/albus/albus-service.sh`)**: Immutable, root-owned helper installed to `/usr/lib/albus/` with `0755` permissions, strictly isolated from user-writable directories to prevent Time-of-Check to Time-of-Use (TOCTOU) prompt hijacking.
  * **Polkit Action Policy (`io.github.oqullcan.albus.policy`)**: Registered under `/usr/share/polkit-1/actions/` to enforce authenticated execution of the root helper.
  * **Desktop UI & CLI**: Runs entirely unprivileged in the user session, communicating with the daemon over a local Unix domain socket (`/tmp/albus.sock`).

---

## Desktop Integration (Omarchy Shell)

The Omarchy desktop plugin provides an integrated panel adhering to Omarchy design guidelines:

* **Visual Identity**: High-contrast, sharp-cornered surface cards with Catppuccin-aligned accents.
* **Oscilloscope Waveform**: Real-time quadratic Bézier curve telemetry pulse with organic idle breathing wave.
* **Interactive Whitelist Management**: In-line tag chips with 1-click domain removal.
* **Keyboard Hotkeys**:
  * `[1]` : Switch to Overview
  * `[2]` : Switch to Routing & DNS
  * `[3]` : Switch to Sessions & Whitelist
  * `[4]` : Switch to Settings & Diagnostics
  * `[Space]` / `[T]` : Toggle Protection
  * `[Esc]` : Close Panel

---

## CLI Reference

Albus includes a management command installed to `/usr/bin/albus` (or `~/.local/bin/albus`):

```bash
albus status       # Show live protection status, data shield meter & DNS latency
albus test         # Run 6-point live defense & DNS leak verification suite
albus start        # Start daemon with saved profile & configure systemd-resolved
albus stop         # Stop daemon & cleanly restore network firewall rules
albus restart      # Restart daemon
albus stats        # Display detailed memory, socket, and session telemetry
albus diag         # Run multi-CDN latency & reachability benchmark
albus fix-network  # Emergency network recovery & firewall flush
albus purge        # Flush local DNS resolver and socket caches
albus logs         # Follow real-time daemon logs
```

---

## Installation & Setup

### Install as Omarchy Plugin

```bash
git clone https://github.com/oqullcan/albus.git
cd albus
./install.sh
```

The installer will:
1. Compile the high-performance Rust core binary with `cargo --release`.
2. Symlink the plugin into `~/.config/omarchy/plugins/io.github.oqullcan.albus`.
3. Install the root-owned helper to `/usr/lib/albus/` and register the Polkit policy.
4. Install the `albus` management CLI tool to `~/.local/bin/albus`.

After installation, reload Omarchy shell (`omarchy restart shell`) and click on the **ALBUS** widget in your bar to open the dashboard.

### Removal & Cleanup

To cleanly remove Albus, unregister system helpers, and restore default network routing:

```bash
# 1. Stop daemon and safely flush firewall rules
albus stop

# 2. Disable plugin and remove user files
omarchy plugin disable io.github.oqullcan.albus
rm -rf ~/.config/omarchy/plugins/io.github.oqullcan.albus ~/.local/bin/albus

# 3. Clean up root-owned system helpers (optional)
pkexec rm -rf /usr/lib/albus /usr/share/polkit-1/actions/io.github.oqullcan.albus.policy

# 4. Reload Omarchy shell
omarchy restart shell
```




---

## Legal & Ethical Notice

Albus is developed for privacy preservation, network telemetry research, and defense against unauthenticated DNS spoofing. It does not provide anonymization, IP masking, or VPN tunnel encryption. Users are responsible for complying with applicable local regulations and terms of service.

---

## License

Released under the **MIT License**.
