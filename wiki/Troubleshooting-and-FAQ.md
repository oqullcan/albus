# Troubleshooting and FAQ

This guide provides diagnostic procedures for resolving common issues with eBPF attachments, DNS resolution, system permissions, and DPI middlebox evasion.

---

## Diagnostic Checklist

When investigating an operational issue, run the following diagnostic commands:

```bash
# 1. Check Albus service status and recent journal logs
sudo systemctl status albus.service
journalctl -u albus.service -n 50 --no-pager

# 2. Verify eBPF sock_ops cgroup attachment
sudo bpftool cgroup tree /sys/fs/cgroup

# 3. Test local DNS resolution on port 53
dig @127.0.0.1 -p 53 google.com +dnssec

# 4. Check active listening ports
sudo ss -tulpn | grep -E ':53|:8053|:205'

# 5. Check firewall drop rules
sudo iptables -L OUTPUT -n -v | grep -E '443|3478|53'
```

---

## 1. Port 53 Conflicts with `systemd-resolved`

### Problem
When starting Albus, the daemon logs:
`Address already in use (os error 98): bind 127.0.0.1:53`

### Cause
Ubuntu, Fedora, Arch, and other modern distributions run `systemd-resolved` on `127.0.0.53:53`. In some configurations, it binds to `0.0.0.0:53`.

### Solution
Disable the stub listener in `systemd-resolved`:

1. Edit `/etc/systemd/resolved.conf`:
   ```ini
   [Resolve]
   DNS=127.0.0.1
   DNSStubListener=no
   ```
2. Restart `systemd-resolved`:
   ```bash
   sudo systemctl restart systemd-resolved
   ```
3. Ensure `/etc/resolv.conf` points to `127.0.0.1`:
   ```bash
   sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
   ```
4. Start Albus:
   ```bash
   sudo systemctl restart albus.service
   ```

---

## 2. DPI Evasion Tuning & Diagnostics

### Sites Still Blocked or Timing Out
If a specific HTTPS website remains inaccessible or times out:

1. **Verify QUIC is Blocked**: Modern browsers use HTTP/3 over UDP 443 by default. Because eBPF `sock_ops` shapes TCP, ensure `block_quic` is enabled in Albus:
   ```bash
   sudo albus config set block_quic true
   ```
   Alternatively, disable HTTP/3 in browser settings (`chrome://flags/#enable-quic` $\rightarrow$ Disabled).

2. **Adjust TCP MSS Clamping**: Some middleboxes use larger or smaller reassembly windows:
   * Try lowering MSS to `64` bytes:
     ```bash
     sudo albus config set mss 64
     ```
   * Or test with `120` bytes for networks that drop extremely small segments.

3. **Enable L4 Bad Checksum Deception**: Some ISP middleboxes assemble TCP streams unless the fake packet invalidates their checksum cache:
   ```bash
   sudo albus config set fake_bad_checksum true
   ```

4. **Verify Auto-TTL Hop Estimation**: If the middlebox resides farther down the routing path, increase the fallback TTL or check RTT latency:
   ```bash
   sudo albus config set fake_ttl 10
   ```

---

## 3. eBPF & CGroup v2 Errors

### Problem
`Error: failed to attach BPF program to cgroup: No such file or directory` or `Invalid argument`

### Cause
The unified CGroup v2 hierarchy is either not mounted or mounted at a non-standard path.

### Solution
1. Verify cgroup v2 mount:
   ```bash
   mount | grep cgroup2
   ```
   If not mounted, mount cgroup v2:
   ```bash
   sudo mount -t cgroup2 none /sys/fs/cgroup
   ```
2. If your distribution mounts cgroup v2 at a different path (e.g., `/sys/fs/cgroup/unified`), update `cgroup_path`:
   ```bash
   sudo albus config set cgroup_path /sys/fs/cgroup/unified
   ```

---

## 4. Permission Denied Errors

### Problem
Running `albus run` without root results in `Operation not permitted (os error 1)` when creating raw sockets or loading BPF bytecode.

### Solution
Either run Albus via `sudo` or grant ambient Linux capabilities to the binary:

```bash
sudo setcap 'cap_net_admin,cap_net_raw,cap_bpf+ep' /usr/local/bin/albus
```

---

## Frequently Asked Questions (FAQ)

### Does Albus decrease internet download or upload speeds?
**No.** Albus clamps the TCP MSS only for the initial connection setup (first 600 bytes) to fragment the TLS `ClientHello` and HTTP request verbs. Once the handshake traverses the middlebox, the in-kernel eBPF shaper automatically restores full line-rate MSS (1460 bytes). Bulk transfers flow at hardware line speed with zero userspace proxy overhead.

### Is Albus a VPN or SOCKS proxy?
**No.** Albus is not a VPN or proxy. It does not route your internet traffic through a remote server or third-party infrastructure. All connections travel directly between your machine and the destination server. Albus shapes the packet framing locally in your Linux kernel to prevent middleboxes from identifying what domains you access.

### Does Albus work on Wi-Fi and Ethernet switches?
**Yes.** The eBPF transport shaper operates on the socket layer (`sock_ops`), which is device-agnostic and applies equally to Ethernet, Wi-Fi, cellular (LTE/5G), and WireGuard/tunnel interfaces.

### How does Albus compare to userspace DPI circumvention tools?
Userspace tools require intercepting all packets via `tun` devices or `NFQUEUE`, copying packet buffers between kernel and userspace, parsing protocols, and re-injecting them. Albus operates entirely in kernel space via eBPF bytecode and zero-allocation raw sockets, achieving nanosecond-level packet processing latency with minimal CPU and RAM usage (<20 MB).

### Can Albus run inside Docker or LXC containers?
Yes, provided the container is granted `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_BPF`, and has access to the host's `/sys/fs/cgroup` and `/sys/fs/bpf` mounts.
