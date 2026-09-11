# Installation and Getting Started

This guide covers system prerequisites, building Albus from source, configuring system privileges, and managing the background daemon.

---

## System Requirements

| Component | Minimum Requirement | Recommended |
| :--- | :--- | :--- |
| **Operating System** | Linux Kernel 5.8+ | Linux Kernel 6.1+ LTS |
| **Architecture** | x86_64, aarch64 | x86_64 with modern vector extensions |
| **Kernel Configuration** | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_CGROUP_BPF=y` | BTF (`CONFIG_DEBUG_INFO_BTF=y`) enabled |
| **CGroup Version** | Unified CGroup v2 mounted at `/sys/fs/cgroup` | Standard systemd default cgroup v2 hierarchy |
| **Toolchain** | Rust 1.75+ (Stable) | Rust 1.80+ with Cargo |
| **Build Dependencies** | `clang`, `llvm`, `libbpf-dev`, `make` | Clang 14+ for CO-RE bytecode generation |
| **Runtime Firewall** | `iptables`, `ip6tables` (legacy or nft backend) | Standard Linux network stack |

To verify that your running kernel has BPF and cgroup v2 enabled:

```bash
# Verify cgroup v2 mount
mount -t cgroup2

# Verify BTF support
ls -la /sys/kernel/btf/vmlinux
```

---

## Building from Source

Albus is written in pure Rust with embedded, pre-compiled eBPF bytecode. Compiling standard release builds does not require an external BPF compiler unless you modify `bpf/sockops.bpf.c`.

### 1. Install Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### 2. Clone and Compile

```bash
git clone https://github.com/oqullcan/albus.git
cd albus

# Build release profile with LTO and binary stripping
cargo build --release
```

The resulting optimized binary is located at `target/release/albus`.

### 3. Install Executable

```bash
sudo cp target/release/albus /usr/local/bin/albus
sudo chmod 755 /usr/local/bin/albus
```

---

## Privileges and Linux Capabilities

Albus attaches eBPF bytecode to the kernel socket layer, opens raw sockets for TCP desynchronization packets, and configures local firewall drop rules. Consequently, it requires elevated network and kernel privileges.

You can run Albus either as `root` or as a dedicated service user with ambient Linux capabilities:

```bash
sudo setcap 'cap_net_admin,cap_net_raw,cap_bpf+ep' /usr/local/bin/albus
```

* `CAP_NET_ADMIN`: Configures iptables firewall rules, attaches eBPF programs to cgroups, and modifies socket parameters.
* `CAP_NET_RAW`: Synthesizes and transmits raw IPv4/IPv6 packets for fake ClientHello injection.
* `CAP_BPF`: Loads and verifies in-kernel eBPF programs and manages BPF maps.

---

## Running Albus

### Interactive Foreground Mode

To test Albus immediately in the terminal with active tracing output:

```bash
sudo albus run
```

Albus initializes the eBPF sock_ops engine, compiles the HaGeZi threat blocklist into memory, starts the local DNS resolver on `127.0.0.1:53` and `127.0.0.1:8053`, and activates the Web Control Center on `http://127.0.0.1:0205`.

Press `Ctrl+C` to cleanly detach all eBPF programs, flush firewall rules, and restore system DNS settings.

### Production Systemd Service

For continuous background protection, install Albus as a managed systemd unit:

```bash
# Install and register the systemd service file
sudo albus service install

# Enable and start daemon
sudo systemctl enable --now albus.service

# Check daemon health
sudo systemctl status albus.service
```

To view live kernel events and injection logs from systemd:

```bash
journalctl -u albus.service -f -o cat
```

---

## Verifying the Deployment

### 1. Check eBPF Program Attachment

Verify that `sockops` is actively attached to the root cgroup:

```bash
sudo bpftool cgroup tree /sys/fs/cgroup
```

You should see a program of type `sock_ops` named `albus_sockops` attached to the cgroup hierarchy.

### 2. Test Local DNS Resolution

Query the local stub resolver on UDP 53:

```bash
dig @127.0.0.1 -p 53 google.com +dnssec
```

Query the local RFC 8484 DoH server:

```bash
curl -H "accept: application/dns-message" \
  "http://127.0.0.1:8053/dns-query?dns=AAABAAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ"
```

### 3. Verify DPI Evasion in Browser / cURL

Test an HTTPS connection through the eBPF transport shaper:

```bash
curl -v https://www.google.com
```

Notice in the output or kernel log that initial segments are segmented into 88-byte chunks before transparent line-rate restoration occurs.

### 4. Access the Web Control Center

Open your web browser and navigate to:

```
http://127.0.0.1:0205/
```

* **Authentication:** Disabled by default when unconfigured, or authenticated via `--web-ui-user` and `--web-ui-pass`. When started without configured credentials, an ephemeral token is generated and stored securely in `/run/albus/web_ui.token` (mode 0600).

The dashboard provides real-time traffic sparklines, threat drop counters, MSS tuning controls, and an event streaming terminal.
