# albus

Kernel-level DPI evasion and validating DNS-over-HTTPS resolver for Linux.

## Overview

- Fragments TLS ClientHellos with an eBPF `sock_ops` MSS clamp (~88 bytes).
- Injects TTL-limited decoy hellos to desync middlebox state.
- Resolves DNS locally over DoH with DNSSEC validation (fail-closed).
- Reconciles live connections with kernel perf events via a shaping watchdog.
- Runs as a single static binary under a dedicated, least-privilege service user.

## Requirements

- Linux 5.10+ (`CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, cgroup v2), `sudo`
- Rust 1.89 (pinned by `rust-toolchain.toml`)
- Source builds: `clang` + kernel headers (provided by CI).

## Build & install

```bash
git clone https://github.com/oqullcan/albus.git
cd albus
git checkout v2.2.0   # latest release (or stay on develop)
cargo build --release
sudo cp target/release/albus /usr/local/bin/albus
```

## Run

```bash
sudo albus run                                          # foreground, defaults
sudo albus run --doh-upstream cloudflare         # quad9, cloudflare, mullvad-*
sudo albus service install && sudo albus service start   # daemon
```

```bash
sudo albus service status          # health + metrics
sudo albus service reload          # SIGHUP, zero-downtime map reload
albus config get                   # active configuration (JSON)
sudo albus config set --doh-upstream cloudflare
albus monitor                      # live telemetry TUI
albus status --json                # machine-readable status
```

## Daemon privilege model

Root runs management. The runtime drops to a dedicated `albus` user with
scoped capabilities: `NET_ADMIN`, `NET_RAW`, `BPF`, `PERFMON`,
`NET_BIND_SERVICE` only. The unit sets `User=/Group=albus`,
`RuntimeDirectory=/StateDirectory=albus`, `LimitMEMLOCK=infinity`, and
`ExecStopPost=+... cleanup`. A scoped polkit rule lets only `albus` drive
per-link DNS (`resolve1`) without interactive auth. `service uninstall`
reverts firewall + DNS first and retains the binary by design.

Omarchy panel widget: see [docs/OMARCHY.md](docs/OMARCHY.md).

## Configuration

Defaults are kept in sync with `Config::default()` by CI.

| Flag | Type | Default |
| :--- | :--- | :--- |
| `--mss` | `u16` | `88` |
| `--min-mss` | `u16` | `64` |
| `--restore-after-bytes` | `u32` | `600` |
| `--ports` | `Vec<u16>` | `[443]` |
| `--fake-ttl` | `u8` | `8` |
| `--auto-ttl` | `bool` | `true` |
| `--min-ttl` | `u8` | `3` |
| `--max-ttl` | `u8` | `12` |
| `--fake-sni` | `String` | `None` |
| `--fake-bad-checksum` | `bool` | `false` |
| `--doh` | `bool` | `true` |
| `--doh-upstream` | `String` | `"quad9"` |
| `--doh-bootstrap-ips` | `Vec<IPv4>` | `[]` |
| `--dnssec` | `bool` | `true` |
| `--pqc` | `bool` | `true` |
| `--ram-only` | `bool` | `false` |
| `--block-quic` | `bool` | `true` |
| `--block-stun` | `bool` | `true` |
| `--kill-switch` | `bool` | `true` |
| `--network-lockdown` | `bool` | `false` |
| `--block-ipv6` | `bool` | `true` |
| `--shaping-watchdog` | `bool` | `true` |

DNSSEC: Bogus answers become SERVFAIL (never cached, never served). Unsigned
zones are served insecure; RSASHA1/NSEC3RSASHA1 answers are rejected.
Query IDs come from the OS CSPRNG.

## Verification

Evasion is gated on a live RST-injection simulator in CI; see
[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md). To verify locally:

```bash
sudo python3 scripts/dpi/dpi_sim.py run --iface lo --targets roblox.com,discord.com
```

## Troubleshooting

- eBPF won't load → check kernel ≥5.10, BTF (`/sys/kernel/btf/vmlinux`), cgroup v2.
- No network after stop → `sudo albus cleanup` restores `/etc/resolv.conf` + firewall.
- QUIC still leaks → `--block-quic` is on by default; verify `iptables -S OUTPUT | grep albus`.
- DNS leaks → kill-switch drops non-loopback port 53; check `albus service status`.

## Removal

```bash
sudo albus service uninstall
sudo albus cleanup          # restores DNS + firewall rules
```

`cleanup` and `service uninstall` retain `/usr/local/bin/albus`, `/etc/albus/config.json`,
and `~/.config/albus/config.json` by design; remove manually if needed.

## Docs

| Doc | Topic |
| :--- | :--- |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Gates, commits, dependencies |
| [SECURITY.md](SECURITY.md) | Scope, reporting, disclosure |
| [docs/TESTING.md](docs/TESTING.md) | Every test suite |
| [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md) | Recorded DPI-evasion proof |
| [docs/OMARCHY.md](docs/OMARCHY.md) | Omarchy panel widget |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Repository tree and module map |

## Repository layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

[GNU GPL-3.0](LICENSE).
