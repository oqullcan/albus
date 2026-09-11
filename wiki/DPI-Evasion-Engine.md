# DPI Evasion Engine

The Albus DPI Evasion Engine operates directly within the Linux network stack, manipulating TCP connections at the socket and packet layers to circumvent stateful Deep Packet Inspection (DPI) middleboxes.

---

## The Censorship Problem

Commercial and state-level DPI firewalls inspect network traffic to identify forbidden domain names and protocols:
* **SNI Filtering**: The Server Name Indication (SNI) extension in cleartext TLS `ClientHello` messages reveals the target domain before encryption is negotiated.
* **TCP Stream Reassembly**: DPI appliances maintain connection state tables to reassemble split packets up to standard Maximum Segment Sizes (MSS).
* **Cleartext HTTP Verbs**: Plaintext HTTP/1.1 requests are scanned using pattern-matching algorithms for forbidden hostnames and URIs.

Albus neutralizes these inspection techniques through in-kernel packet shaping and active protocol desynchronization.

---

## 1. In-Kernel eBPF `sock_ops` Transport Shaping

Unlike user-space proxies (which introduce context-switch latency and memory copying overhead), Albus shapes connections directly in kernel space via eBPF bytecode (`bpf/sockops.bpf.c`).

```
Application Socket (connect())
             |
             v
+----------------------------+
| BPF_SOCK_OPS Hook Point    |  <-- Attached to cgroup v2
+----------------------------+
             |
             +---> Event: BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
             |     Action: Set TCP_MAXSEG = 88 bytes (with randomized jitter)
             |
             +---> Data Transfer (0..600 bytes):
             |     TLS ClientHello split into 88-byte chunks
             |
             +---> Event: BPF_SOCK_OPS_STATE_CHK (Bytes > 600):
                   Action: Restore TCP_MAXSEG = 1460 bytes (Line-rate)
```

### Initial MSS Clamping
When an application initiates a TCP connection on port 443 (or any configured target port), the eBPF hook intercepts the `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` event and modifies the socket options:

$$\text{Initial MSS} = \text{clamp\_size} \quad (\text{default: } 88 \text{ bytes})$$

Because a standard TLS 1.3 `ClientHello` spans between 300 and 800 bytes, clamping the MSS to 88 bytes forces the Linux TCP stack to segment the `ClientHello` across 4 to 10 discrete TCP packets. The SNI extension is split across segment boundaries, defeating pattern-matching regex engines that operate on single packets.

### Per-Connection Randomized Jitter
To prevent censorship middleboxes from detecting a fixed 88-byte packet signature, Albus applies pseudo-randomized jitter between `min_mss` and `mss`:

$$\text{Connection MSS} = \text{random}(\text{min\_mss}, \text{mss}) \quad (\text{default: } [64..88] \text{ bytes})$$

Each outgoing TCP stream exhibits a distinct segment size distribution, rendering static fingerprinting ineffective.

### Dynamic Line-Rate Restoration
After the handshake passes through the middlebox, maintaining an 88-byte MSS would degrade bulk throughput. Albus tracks cumulative sent bytes in an eBPF hash map (`albus_conn_map`). Once the connection exceeds `restore_after_bytes` (default: 600 bytes), the kernel restores the standard MTU-derived MSS (typically 1460 bytes). Subsequent application data flows at native hardware line rate.

---

## 2. Active Desynchronization and Fake Packet Injection

For sophisticated DPI middleboxes that reassemble TCP fragments across connection state tables, Albus employs an active injection engine via zero-allocation raw AF_INET and AF_INET6 sockets (`src/core/fake.rs`, `src/core/rawsock.rs`).

```
Client               DPI Middlebox             Target Server
  |                        |                         |
  |--- SYN ----------------------------------------->|
  |<-- SYN+ACK --------------------------------------|
  |--- ACK ----------------------------------------->|
  |                        |                         |
  |=== Fake ClientHello ==>| (Expires at TTL hop)    |
  |    (Decoy SNI, TTL=8,  |                         |
  |     Bad Checksum)      |                         |
  |                        |                         |
  |--- Genuine ClientHello ------------------------->|
  |    (Segmented MSS 88)  |                         |
  |                        | (Middlebox desynced)    |
  |<== Encrypted Traffic ===========================>|
```

### Auto-TTL Dynamic Hop Estimation
If a fake packet reaches the destination server, the server may terminate the connection with a `TCP RST`. To ensure the fake packet reaches only the DPI middlebox and expires before reaching the destination, Albus measures round-trip latency (RTT) during the TCP handshake:

1. Handshake SYN-ACK latency is sampled to estimate the total network hop count $H_{\text{total}}$.
2. The DPI middlebox typically resides within the regional ISP infrastructure ($H_{\text{dpi}} \approx 3 \text{ to } 8$ hops).
3. Albus injects the fake packet with:
   $$\text{TTL}_{\text{fake}} = \text{clamp}(H_{\text{estimated}} - \Delta, 3, 12)$$
4. The packet traverses the ISP middlebox, poisoning its reassembly buffer, and expires due to TTL expiration before arriving at the destination.

### Decoy SNI Pool Rotation
The injected fake payload contains a valid TLS record header but carries an innocuous decoy SNI hostname (e.g., `www.google.com`, `cloudflare.com`, or user-specified domain). The middlebox records the innocuous domain in its inspection cache and permits subsequent stream data.

### L4 Checksum Poisoning (`0xDEAD`)
When `fake_bad_checksum` is enabled, Albus intentionally invalidates the TCP layer 4 checksum on the injected fake packet by substituting `0xDEAD`.
* **Middlebox behavior:** High-throughput DPI hardware frequently disables L4 checksum validation to reduce processing latency, thereby accepting and parsing the fake packet.
* **Destination behavior:** The destination server kernel hardware offloading checks the checksum, identifies corruption, and silently discards the frame without resetting the genuine TCP session.

### Sequence Number Shift (`fake-seq-offset`)
Albus can shift the sequence numbers of injected fake packets relative to genuine stream markers, confusing TCP sequence-tracking middleboxes and causing them to desynchronize their reassembly buffers.

---

## 3. HTTP/1.1 Request Verb Splitting

Cleartext HTTP connections are inspected for forbidden HTTP Host headers and URL paths. Albus fragments HTTP verbs across packet boundaries:
* Segment 1 transmits the initial character: `G`
* Segment 2 transmits the remainder: `ET /path HTTP/1.1\r\nHost: ...`

DPI regex parsers expecting `GET `, `POST `, or `CONNECT ` in the initial packet fail to match the stream signature.

---

## 4. Protocol Blocking and Enforcement

### QUIC Protocol Drop (UDP 443)
Modern web browsers attempt HTTP/3 over QUIC (UDP 443) by default. Because UDP is connectionless and does not utilize TCP `sock_ops`, unbypassed QUIC packets can trigger SNI censorship.

Albus installs in-kernel firewall rules:
```bash
iptables -A OUTPUT -p udp --dport 443 -j DROP
ip6tables -A OUTPUT -p udp --dport 443 -j DROP
```
When browsers encounter a blocked UDP 443 path, standard Happy Eyeballs fallback instantly degrades the connection to TCP (HTTP/2 or HTTP/1.1), where Albus eBPF MSS clamping and desynchronization take full effect.

### WebRTC STUN Leak Drop (UDP 3478, 5349)
Browsers using WebRTC can query remote STUN/TURN servers to discover the client's genuine local and public IP addresses, bypassing encrypted tunnels. Albus drops outbound UDP packets to ports 3478 and 5349, eliminating WebRTC identity leaks.

---

## 5. Kernel Map Pinning & Zero-Downtime Reload

Albus pins its BPF maps under `/sys/fs/bpf/albus/`. When configuration adjustments are made via CLI or Web UI, Albus updates the pinned kernel maps atomically without reloading the BPF program or terminating established TCP connections:

```bash
# Atomic reload via SIGHUP
sudo systemctl kill -s HUP albus.service
```
Active connections retain their state while newly established connections immediately inherit the updated MSS and evasion parameters.
