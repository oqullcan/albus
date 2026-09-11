# Hardened DNS Subsystem

The Albus Hardened DNS Subsystem provides an encrypted, authenticated, and threat-filtered name resolution environment. It acts as a local stub resolver that insulates Linux applications from ISP snooping, DNS poisoning, and telemetry profiling.

---

## Architecture

```
Application (Browser / System Stub)
       |
       v  UDP/TCP port 53 or RFC 8484 DoH :8053
+-----------------------------------------------------------+
| Albus Local DNS Subsystem (127.0.0.1)                     |
|                                                           |
| +-------------------------------------------------------+ |
| | Threat Filter & Security Shield (Radix Trie <5 MB)    | |
| | - HaGeZi Multi PRO + TIF (~350,000 rules)             | |
| | - Anti-DNS Rebinding (RFC 1918 Suppression)           | |
| | - Bogon & Martian IP Range Drop                       | |
| | - CNAME & HTTPS/SVCB Alias Uncloaking                 | |
| +-------------------------------------------------------+ |
|                            |                              |
|                            v Validated Query              |
| +-------------------------------------------------------+ |
| | In-Memory LRU Cache (Prefetch & Negative Cache)       | |
| +-------------------------------------------------------+ |
|                            |                              |
|                            v Cache Miss                   |
| +-------------------------------------------------------+ |
| | Multi-Upstream Racing Pool (Happy Eyeballs)           | |
| | - Hybrid PQC (X25519 + ML-KEM-768 / Kyber)            | |
| | - RFC 9230 Oblivious DoH (HPKE Relay)                 | |
| | - TLS mTLS Client Authentication                      | |
| +-------------------------------------------------------+ |
+-----------------------------------------------------------+
       |                                   |
       v DoH HTTPS                         v DoH HTTPS
  Quad9 Anycast                      Cloudflare / Mullvad
```

---

## 1. Local Protocol Listeners

Albus exposes multiple local listening endpoints:
* **Standard DNS Listener (`127.0.0.1:53` UDP/TCP)**: Transparent drop-in replacement for traditional Linux stub resolvers (compatible with `glibc`, `musl`, and `systemd-resolved`).
* **Local DoH Server (`127.0.0.1:8053/dns-query`)**: RFC 8484 compliant HTTP/1.1 endpoint allowing web browsers and native applications to configure direct DNS-over-HTTPS without plaintext loopback sockets.
* **TCP Port 53 Listener**: RFC 7766 compliant TCP listener for large DNS payloads (DNSSEC key exchanges and zone transfers).

---

## 2. Upstream Resolvers & Provider Profiles

Albus natively integrates high-reputation encrypted upstream providers with hardcoded, zero-DNS bootstrap IP addresses:

| Provider Preset | Endpoint URL | Bootstrap IPs | Features |
| :--- | :--- | :--- | :--- |
| **Quad9** | `https://dns.quad9.net/dns-query` | `9.9.9.9`, `149.112.112.112` | Anycast, threat intelligence blocking, DNSSEC validation |
| **Cloudflare** | `https://cloudflare-dns.com/dns-query` | `1.1.1.1`, `1.0.0.1` | Ultra-low latency, global edge anycast network |
| **Mullvad** | `https://doh.mullvad.net/dns-query` | `194.242.2.2`, `194.242.2.3` | Zero logging, strict European jurisdiction |
| **Custom** | User configurable DoH URL | User configurable | Private corporate DoH, NextDNS, AdGuard, or Pi-hole |

### Mullvad Specialized Profiles
Albus supports Mullvad's dedicated filter feeds via single-click selection:
* `mullvad-standard`: Unfiltered encrypted resolution.
* `mullvad-adblock`: Advertising and tracking domain suppression.
* `mullvad-malware`: High-risk malware and phishing sinkhole.
* `mullvad-family`: Blocks adult content and malware.
* `mullvad-social`: Restricts social media networks.
* `mullvad-all`: Comprehensive combined filter feed.

---

## 3. Happy Eyeballs Upstream Racing

To eliminate single-provider latency spikes or intermittent regional throttling, Albus includes a multi-upstream query racing engine (`src/dns/racing.rs`):

1. When a cache miss occurs, Albus dispatches simultaneous speculative DoH queries across configured upstreams (e.g., Quad9, Cloudflare, and Mullvad).
2. The engine tracks response times and adopts the earliest verified, cryptographically valid answer.
3. Pending requests are immediately aborted to minimize connection overhead.
4. Latency statistics update dynamic weight tables to prioritize faster upstreams for subsequent queries.

---

## 4. Post-Quantum Cryptography (ML-KEM-768)

Standard TLS 1.3 key exchange relies on classical elliptic curves (such as X25519), which are susceptible to future cryptanalysis by quantum computers under "Harvest Now, Decrypt Later" scenarios.

Albus integrates the NIST FIPS 203 Post-Quantum Cryptography standard using **ML-KEM-768** (formerly Kyber-768) via `aws-lc-rs`:
* **Hybrid Key Exchange (`X25519MLKEM768`)**: Combines classical X25519 with ML-KEM-768. Even if one mathematical primitive is compromised, the remaining algorithm guarantees confidentiality.
* **Seamless Negotiation**: Albus advertises hybrid PQC support during the TLS handshake with compatible upstream resolvers (such as Cloudflare and Quad9), transparently securing queries against future quantum adversaries.

---

## 5. Oblivious DoH (RFC 9230 HPKE)

Under standard DoH, the upstream resolver observes both the client IP address and the queried domain. Oblivious DoH eliminates this linkage using Hybrid Public Key Encryption (HPKE):

```
Client (Albus)                Proxy Relay                 Target Resolver
      |                            |                             |
      |--- Encrypted Query ------->|                             |
      |    (HPKE encrypted for     |--- Proxied Query ---------->|
      |     Target Resolver)       |    (Relay IP visible,       |
      |                            |     query is unreadable)    |
      |                            |                             |
      |                            |<-- Encrypted Response ------|
      |<-- Proxied Response -------|                             |
```

* **The Proxy Relay** sees the client IP address but cannot read the query payload because it is encrypted with the Target Resolver's public HPKE key.
* **The Target Resolver** decrypts and resolves the query but sees only the Relay's IP address.
* Neither entity possesses complete knowledge of who requested what domain.

---

## 6. Radix Trie Threat Shield (HaGeZi Multi PRO + TIF)

Albus compiles the comprehensive HaGeZi Multi PRO and Threat Intelligence Feeds (~350,000 rules) into an optimized in-memory Radix Trie arena (`src/dns/blocklist.rs`):

* **Compact Arena Memory Layout**: Over 350,000 domain rules consume less than 5 MB of physical RAM through string-interned label trees.
* **Reverse Label Lookup**: Matches domains from right to left (e.g., `com` $\rightarrow$ `tracker` $\rightarrow$ `sub`) with $O(k)$ complexity where $k$ is domain depth, executing lookups in under 120 nanoseconds.
* **Local Binary Cache (`/var/lib/albus/blocklist.bin`)**: Compiled rules are cached on disk to enable instant sub-millisecond cold starts without requiring repeated downloads.
* **Live Dynamic Upgrades**: Albus checks CDN mirrors in the background and hot-swaps the active Radix Trie atomically without interrupting query resolution.

---

## 7. Advanced Defense Shields

### Anti-DNS Rebinding
Malicious websites can return private RFC 1918 IPv4 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`) or private IPv6 addresses (`fc00::/7`, `::1`) in response to public domain queries to hijack client routers and IoT devices. Albus verifies IP answers against a strict boundary matrix and drops illicit intranet responses.

### CNAME & HTTPS/SVCB Alias Uncloaking
Ad trackers frequently conceal third-party endpoints behind first-party subdomains using CNAME aliases. Albus recursively traverses CNAME chains and inspects HTTPS/SVCB record targets against the threat database, blocking cloaked trackers.

### Bogon and Martian IP Filtering
Albus filters unallocated, reserved, and martian IP addresses (`0.0.0.0/8`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`), ensuring that invalid routing information cannot pollute local caches.

### DNS64 IPv4 Synthesis
In IPv6-only environments without native IPv4 routing, Albus synthesizes `AAAA` records for IPv4-only domains using the RFC 6052 Well-Known Prefix (`64:ff9b::/96`), enabling NAT64 connectivity.

---

## 8. Leak Shield & Firewall Controls

Albus applies kernel firewall rules to prevent identity and query leaks:
* **DNS Leak Kill-Switch**: Injects `iptables` drop rules for all outbound UDP and TCP traffic to port 53 targeting non-loopback interfaces. Plaintext DNS queries originating from rogue applications are dropped at the kernel boundary.
* **Fail-Closed Network Lockdown**: If the Albus daemon is terminated unexpectedly, optional lockdown rules sever outbound web connections until the service is restored, preventing unencrypted leakage.
* **IPv6 AAAA Leak Prevention**: Disables AAAA synthesis and resolution if IPv6 DPI bypass is not configured, preventing dual-stack operating systems from leaking requests over unbypassed IPv6 routes.
