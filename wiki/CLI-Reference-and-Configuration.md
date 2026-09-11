# CLI Reference and Configuration

Albus provides a comprehensive Command-Line Interface (CLI) for controlling daemon operations, tuning kernel parameters, and inspecting real-time telemetry.

---

## Command Structure

```bash
albus [OPTIONS] <COMMAND>
```

### Top-Level Commands

| Command | Description |
| :--- | :--- |
| `run` | Starts the eBPF shaper, DNS resolver, and Web UI in the foreground |
| `service` | Manages the systemd background service (install, start, stop, reload) |
| `config` | Views, modifies, and validates persistent configuration parameters |
| `monitor` | Launches the interactive terminal TUI telemetry dashboard |
| `status` | Displays system status, kernel attachments, and operational health |

---

## 1. Subcommand: `albus run`

Launches the core daemon in the foreground. Accepts command-line flags to override parameters defined in `config.json`.

```bash
sudo albus run [OPTIONS]
```

### Comprehensive Flag Reference

#### DPI Evasion Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--mss <BYTES>` | Integer | `88` | Clamped TCP Maximum Segment Size for initial handshake packets |
| `--min-mss <BYTES>` | Integer | `64` | Lower bound for per-connection randomized jitter |
| `--restore-after <BYTES>` | Integer | `600` | Sent byte threshold before restoring standard line-rate MSS |
| `--auto-ttl` | Boolean | `true` | Enables dynamic RTT-based hop-distance estimation for fake packets |
| `--fake-ttl <HOPS>` | Integer | `8` | Static fallback TTL for injected fake packets when Auto-TTL is disabled |
| `--fake-sni <DOMAIN>` | String | `None` | Decoy domain name injected inside fake TLS ClientHello frames |
| `--fake-seq-offset <NUM>` | Integer | `0` | Relative sequence number shift for fake desync packets |
| `--fake-bad-checksum` | Boolean | `false` | Sets invalid TCP checksum (`0xDEAD`) on fake packets |
| `--cgroup-path <PATH>` | Path | `/sys/fs/cgroup` | Path to the unified cgroup v2 mount point |
| `--ports <LIST>` | Comma List | `443` | Target destination ports subject to eBPF MSS clamping |

#### DNS Subsystem Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--dns-addr <ADDR>` | SocketAddr | `127.0.0.1:53` | Local UDP/TCP listening address for the stub DNS resolver |
| `--doh-upstream <URL>` | String | `quad9` | Encrypted upstream resolver (`quad9`, `cloudflare`, `mullvad-*`, or URL) |
| `--bootstrap-ip <IP>` | Comma List | `9.9.9.9` | Hardcoded IP addresses used to bootstrap upstream DoH hostnames |
| `--dns-racing` | Boolean | `true` | Enables Happy Eyeballs concurrent speculative upstream racing |
| `--pqc` | Boolean | `true` | Enables ML-KEM-768 hybrid post-quantum key exchange |
| `--dnssec` | Boolean | `true` | Enforces cryptographic DNSSEC signature validation |
| `--local-doh` | Boolean | `true` | Activates local RFC 8484 HTTP/1.1 DoH server |
| `--local-doh-addr <ADDR>` | SocketAddr | `127.0.0.1:8053` | Listening address for the local DoH endpoint |
| `--tcp-listener` | Boolean | `true` | Enables local TCP port 53 listener alongside UDP |

#### Security & Firewall Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--blocklist` | Boolean | `true` | Enables in-memory HaGeZi Multi PRO + TIF ad and malware filter |
| `--blocklist-path <PATH>` | Path | Auto | Path to persistent compiled blocklist cache (`/var/lib/albus/blocklist.bin`) |
| `--anti-dns-rebinding` | Boolean | `true` | Drops private RFC 1918 IP addresses in public domain responses |
| `--block-bogons` | Boolean | `true` | Filters unroutable and reserved Martian IP addresses |
| `--uncloak-cnames` | Boolean | `true` | Recursively resolves CNAME chains to defeat tracker cloaking |
| `--dns64` | Boolean | `false` | Enables RFC 6052 DNS64 IPv4 synthesis using `64:ff9b::/96` |
| `--kill-switch` | Boolean | `true` | Blocks all outbound port 53 traffic to non-loopback interfaces |
| `--network-lockdown` | Boolean | `false` | Blocks all outbound web traffic if Albus daemon terminates |
| `--block-quic` | Boolean | `true` | Drops outbound UDP 443 to force browsers to TCP for DPI evasion |
| `--block-stun` | Boolean | `true` | Drops WebRTC STUN traffic (UDP 3478, 5349) to prevent IP leaks |
| `--ram-only` | Boolean | `false` | Runs entirely in volatile memory; disables persistent disk writes |

#### Web UI & Management Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--web-ui` | Boolean | `false` | Activates embedded Web Monitoring Dashboard |
| `--web-ui-addr <ADDR>` | SocketAddr | `127.0.0.1:0205` | HTTP bind address for the Web Control Center |
| `--web-ui-user <NAME>` | String | `None` | HTTP Basic Authentication username. If omitted, basic authentication is not enforced on the local loopback interface, or an ephemeral token is written to `/run/albus/web_ui.token`. |
| `--web-ui-pass <PASS>` | String | `None` | HTTP Basic Authentication password. If omitted when dashboard is enabled, an ephemeral token is written with mode 0600 to `/run/albus/web_ui.token`. |
| `--metrics` | Boolean | `false` | Exposes Prometheus `/metrics` endpoint on the Web UI port |

---

## 2. Subcommand: `albus service`

Manages the systemd background service.

```bash
# Install systemd unit file and register with systemctl
sudo albus service install

# Start background service
sudo albus service start

# Stop service and cleanly flush firewall rules
sudo albus service stop

# Restart service
sudo albus service restart

# Flush in-memory DNS cache (SIGUSR1)
sudo albus service reload

# Remove systemd unit file
sudo albus service uninstall
```

---

## 3. Subcommand: `albus config`

Reads and modifies persistent configuration settings without manually editing JSON files.

```bash
# Print current active configuration in formatted JSON
albus config get

# Update specific parameters
sudo albus config set doh_upstream cloudflare
sudo albus config set mss 64
sudo albus config set fake_bad_checksum true

# Reset configuration to factory defaults
sudo albus config reset

# Show active configuration file path
albus config path
```

---

## 4. Subcommand: `albus monitor`

Launches an interactive terminal TUI telemetry cockpit rendering real-time metrics:
* Query resolution throughput and cache hit rates.
* Live packet interception events and desync injections.
* System uptime, memory consumption, and active firewall rules.

```bash
albus monitor
```

---

## Configuration File Specification (`config.json`)

Albus stores its configuration in JSON format. The daemon checks the following paths in priority order:
1. `volatile_config_path()`: Runtime volatile memory (`/run/albus/config.json` for root or `$XDG_RUNTIME_DIR/albus/config.json` / `/run/user/<uid>/albus/config.json` for unprivileged users).
2. `/run/albus/config.json`: System daemon volatile path fallback.
3. `default_config_path()`: Durable persistent user path resolved via `ALBUS_CONFIG_USER`, verified `SUDO_USER` home directory, unprivileged process `$HOME/.config/albus/config.json`, or `/etc/albus/config.json`.
4. `/etc/albus/config.json`: System-wide durable fallback configuration.

### Security and Ownership Verification

When running with root privileges (such as the systemd service), Albus enforces strict ownership and file descriptor validation via `safe_read()` and `verify_file_ownership()`. Configuration files must be owned by root (UID 0) or the verified invoking user UID (`SUDO_USER` or `ALBUS_CONFIG_USER`). Files with untrusted ownership are rejected. In addition, symlink traversal attacks are strictly mitigated using `O_NOFOLLOW` and `fstat` checks on the opened file descriptor, preventing unprivileged local users from manipulating symlinks to inject malicious configurations into the privileged daemon.

### Annotated `config.json` Example

```json
{
  "mss": 88,
  "min_mss": 64,
  "restore_after_bytes": 600,
  "auto_ttl": true,
  "fake_ttl": 8,
  "fake_sni": null,
  "fake_seq_offset": 0,
  "fake_bad_checksum": false,
  "cgroup_path": "/sys/fs/cgroup",
  "ports": [443],
  "dns_addr": "127.0.0.1:53",
  "doh_upstream": "quad9",
  "doh_bootstrap_ips": [
    "9.9.9.9",
    "149.112.112.112"
  ],
  "dns_racing": true,
  "pqc": true,
  "dnssec": true,
  "local_doh": true,
  "local_doh_addr": "127.0.0.1:8053",
  "tcp_listener": true,
  "blocklist": true,
  "blocklist_path": null,
  "anti_dns_rebinding": true,
  "block_bogons": true,
  "uncloak_cnames": true,
  "dns64": false,
  "kill_switch": true,
  "network_lockdown": false,
  "block_quic": true,
  "block_stun": true,
  "block_ipv6": true,
  "ram_only": false,
  "socks5_proxy": null,
  "tor": false,
  "tls_client_cert": null,
  "tls_client_key": null,
  "forwarding_rules_path": "/etc/albus/forwarding-rules.txt",
  "odoh_enabled": false,
  "edns_padding": true,
  "edns_client_subnet": null,
  "query_log": false,
  "nx_log": false,
  "tls_key_log_file": null,
  "ipcrypt_key": null,
  "netmon": true,
  "metrics": false,
  "web_ui": false,
  "web_ui_addr": "127.0.0.1:0205",
  "web_ui_user": null,
  "web_ui_pass": null
}
```

---

## Signal Handling

The Albus daemon responds to standard POSIX signals for zero-downtime administration:

| Signal | Number | Action |
| :--- | :--- | :--- |
| `SIGHUP` | `1` | Reloads `config.json`, updates in-kernel eBPF maps atomically, and hot-swaps DNS resolver configuration without dropping active connections. |
| `SIGUSR1` | `10` | Flushes the in-memory DNS cache. |
| `SIGINT` | `2` | Initiates graceful termination (detaches eBPF programs, restores firewall rules, resets resolv.conf). |
| `SIGTERM` | `15` | Clean shutdown requested by systemd. |

**Example: Reloading via SIGHUP:**
```bash
sudo kill -HUP $(pgrep albus)
```
