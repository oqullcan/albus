# Web Control Center

The Albus Web Control Center is a zero-dependency, embedded HTTP dashboard and administration interface built directly into the daemon (`src/dns/web_ui.rs`). It allows real-time telemetry inspection, live packet flow analysis, and immediate hot-reload configuration from any web browser.

---

## Access & Authentication

By default, the Web Control Center is bound to the loopback interface on port `205`:

```
http://127.0.0.1:0205/
```

### Security & Authentication
* **HTTP Basic Authentication**: Enforced when configured via CLI (`--web-ui-user`, `--web-ui-pass`) or `config.json`. If unconfigured, an ephemeral password token is generated and saved securely with mode 0600 to `/run/albus/web_ui.token`.
* **Configurable Credentials**: Custom username and password can be specified via configuration or CLI flags (both default to `None`).
* **Timing-Attack Resistance**: Authentication verification uses constant-time string comparison (`constant_time_eq_str`) to prevent side-channel timing attacks.
* **Zero External Dependencies**: The server is implemented directly over Tokio asynchronous TCP streams without external web frameworks or dynamic script engines.

---

## 2026 UI/UX Design System

The Control Center implements an ultra-responsive, dark-mode terminal visual language engineered with modern 2026 design principles:

* **Canvas & Surfaces**: Deep pitch-black background (`#040507`) with subtle dot-matrix grid alignment and glassmorphic cards (`backdrop-filter: blur(16px)`).
* **Accents**: Neon emerald green (`#10b981`), cyber cyan (`#06b6d4`), and electric purple (`#c084fc`).
* **Fluid Sliding Navigation**: The top navigation bar features an animated pill indicator that glides smoothly beneath the active tab.
* **Real-Time SVG Sparkline**: Live dual-wave telemetry graph rendering queries per second and DPI packet desync injections.
* **Spring Toggles**: Interactive switches with smooth spring kinematics (`cubic-bezier(0.34, 1.56, 0.64, 1)`) and glowing active halos.
* **Floating Cyber Toast**: Non-intrusive floating HUD notifications that slide in with auto-dismiss progress indicators upon saving settings.
* **Keyboard Shortcuts**: Full power-user keyboard navigation (`1-6` for tabs, `Space` for master switch, `P` for pause, `F` for cache flush, `R` for SIGHUP reload, `Esc` to blur).

---

## Dashboard Views (Tabs)

### 1. Overview Tab
The central telemetry command center:
* **4 Hero Metric Cards**: Total Queries Processed (broken down by UDP, TCP, and DoH), DNS Cache Hit Ratio with animated gradient progress bar, Threats & Leaks Blocked, and eBPF DPI Engine Status.
* **Real-Time Telemetry Sparkline**: Live SVG waveform charting query frequency and packet bypass injections over the past 30 intervals.
* **Active Protection Matrix**: 8 interactive status tiles (`eBPF Engine`, `PQC Kyber`, `DNSSEC`, `DNS Kill-Switch`, `HaGeZi Blocklist`, `Anti-Rebinding`, `QUIC Block`, `WebRTC STUN Drop`). Clicking any tile navigates directly to that setting's configuration tab.
* **Security & Drop Telemetry**: Tabular summary of intercepted threats categorized by layer (Malware, Rebinding, Bogons, Undelegated TLDs, CNAME Uncloaking).
* **Live Telemetry Stream Preview**: Real-time snapshot of the latest kernel events with one-click transition to the full streaming console.

### 2. DPI Evasion Tab
Full control over in-kernel transport shaping and desynchronization:
* **Packet Fragmentation Engine**: TCP MSS clamping slider (40 to 1460 bytes) with instant preset chips (`64 B Jitter`, `88 B Optimal`, `120 B Safe`, `1400 B Bypass`), Min MSS floor bound, Restore After Bytes threshold, and CGroup v2 mount path.
* **Auto-TTL Desync & Fake Packet Injection**: Dynamic hop estimation toggle, fallback fake TTL, decoy SNI domain specification, and L4 Bad Checksum (`0xDEAD`) middlebox poisoning.
* **Protocol Blocking**: Toggles to drop outbound QUIC (UDP 443) and WebRTC STUN (UDP 3478/5349).

### 3. Upstream Resolver Tab
Encrypted resolution and routing management:
* **Encrypted Upstream Resolver (DoH)**: Single-click presets for Quad9, Cloudflare, Mullvad, and Custom DoH.
* **Mullvad Profile Drawer**: Animated sub-grid exposing 6 Mullvad DNS profiles (`Standard`, `Adblock`, `Malware`, `Family`, `Social`, `All-in-one`).
* **DNS Racing & Latency Tuning**: Happy Eyeballs concurrent racing toggle, negative cache min/max TTLs, and timeout reduction factors.
* **Tor & SOCKS5 Routing**: Tor Onion routing (`socks5://127.0.0.1:9050`) and custom SOCKS5 proxy endpoints.
* **Client mTLS Authentication**: Mutual TLS X.509 client certificate and private key paths for private corporate DoH infrastructure.

### 4. Security Policies Tab
Cryptographic and network hardening rules:
* **Post-Quantum Cryptography (PQC)**: Hybrid ML-KEM-768 key exchange toggle.
* **DNSSEC Validation**: Cryptographic verification of resource record signatures and Authenticated Data (AD) bit enforcement.
* **Ephemeral RAM-Only Storage**: Disables disk persistence; resets configuration to factory defaults on reboot.
* **Leak Shields**: DNS Leak Kill-Switch, Fail-Closed Network Lockdown, and IPv6 AAAA Leak Prevention.

### 5. Hardened DNS & Filters Tab
Local services, threat filters, and auditing:
* **Protocol Listeners**: Local TCP port 53 listener, local RFC 8484 DoH server (`127.0.0.1:8053`), network interface hotplug monitor, Prometheus metrics (`/metrics`), and Web Control Center listen address/credentials.
* **Threat Subsystem**: HaGeZi Multi PRO + TIF filter toggle, Anti-DNS Rebinding, Bogon IP filtering, CNAME uncloaking, and DNS64 IPv4 synthesis.
* **Split DNS & Oblivious DoH**: Split domain forwarding rules path, Oblivious DoH (RFC 9230 HPKE), EDNS0 request padding, and EDNS Client Subnet (ECS).
* **Audit & Forensics**: Local rotating DNS query audit log, IPcrypt 128-bit client IP pseudonymization, NXDomain botnet detection log, and TLS Master Keylog (`SSLKEYLOGFILE`) for Wireshark analysis.

### 6. Live Event Stream Tab
An interactive cockpit streaming live daemon logs:
* **Category Filters**: Filter events by `ALL`, `INJECT` (packet shaping/fake ClientHello), `DNS` (encrypted queries), `QUIC` (UDP drops), `SHIELD` (threat blocks), and `ERROR`.
* **Real-Time Search**: Instant regex and substring filtering by domain, IP, or log detail.
* **Controls**: Live stream pause/resume, buffer clear, and one-click copy to clipboard.

---

## REST API Reference

The Web Control Center exposes a REST API for automated scripting, monitoring, and integration:

### 1. `GET /api/stats`
Returns a real-time JSON snapshot of daemon telemetry and atomic counters.

**Request:**
```bash
curl -u <username>:<password> http://127.0.0.1:0205/api/stats
```

**Response:**
```json
{
  "total_queries": 1284,
  "queries_udp": 1102,
  "queries_tcp": 140,
  "queries_doh": 42,
  "cache_hits": 450,
  "cache_hit_ratio": 35.04,
  "upstream_queries": 834,
  "blocked_blocklist": 68,
  "blocked_rebinding": 12,
  "blocked_bogon": 4,
  "uncloaked_cnames": 15,
  "dns64_synthesized": 0,
  "uptime_secs": 8420,
  "version": "2.1.0"
}
```

### 2. `GET /api/config`
Retrieves the active daemon configuration object in JSON format.

**Request:**
```bash
curl -u <username>:<password> http://127.0.0.1:0205/api/config
```

### 3. `POST /api/config`
Updates configuration parameters, saves them to persistent storage (`/etc/albus/config.json`), and automatically dispatches a `SIGHUP` signal to reload in-kernel eBPF maps and DNS parameters with zero downtime.

**Request:**
```bash
curl -X POST -u <username>:<password> \
  -H "Content-Type: application/json" \
  -d '{"mss": 64, "doh_upstream": "cloudflare", "dns_racing": true}' \
  http://127.0.0.1:0205/api/config
```

### 4. `GET /api/logs`
Retrieves the latest 100 log lines from the systemd journal for `albus.service`.

**Request:**
```bash
curl -u <username>:<password> http://127.0.0.1:0205/api/logs
```

### 5. `POST /api/service/action`
Executes service management operations:
* `flush-cache`: Flushes the in-memory DNS cache.
* `reload`: Dispatches SIGHUP daemon reload.
* `restart`: Restarts the systemd daemon.
* `stop` / `start`: Toggles active protection.

**Request:**
```bash
curl -X POST -u <username>:<password> \
  -H "Content-Type: application/json" \
  -d '{"action": "flush-cache"}' \
  http://127.0.0.1:0205/api/service/action
```

### 6. `GET /api/health` and `GET /live`
Lightweight healthcheck endpoints returning `200 OK` for monitoring probes.
