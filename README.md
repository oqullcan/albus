# albus

Kernel-level DPI evasion engine and DNS-over-HTTPS resolver for Linux. Fragments TLS ClientHellos (eBPF MSS clamp) and poisons middlebox state (TTL-limited decoy injection), while resolving DNS locally over DoH with DNSSEC validation.

## How it works

1. eBPF (`sock_ops`) clamps TCP MSS to ~88 bytes → ClientHello fragments across segments.
2. Raw-socket injector sends TTL-limited decoy hellos → DPI state desync.
   (Decoy TTL is a static operator-set value, not probed — see `src/core/autottl`.)
3. Local DoH resolver on 127.0.0.1:53 answers DNS (DNSSEC-validated, kill-switched).
4. Shaping watchdog reconciles fresh connections against perf events; unexplained connections across consecutive windows engage fail-closed network lockdown until restart (`--shaping-watchdog=false` opts out).

## Requirements

- Linux 5.10+ (`CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, cgroup v2), `sudo`
- Rust 1.89 (pinned via `rust-toolchain.toml`)
- Source builds need `clang` + kernel headers (CI installs them); the release binary runs standalone

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
sudo albus run --doh-upstream cloudflare         # preset: quad9, cloudflare, mullvad-*
sudo albus service install && sudo albus service start   # background daemon
```

```bash
sudo albus service status    # health + metrics
sudo albus service reload    # zero-downtime map reload (SIGHUP)
albus config get             # active configuration (JSON)
sudo albus config set --doh-upstream cloudflare
albus monitor                # live telemetry TUI
albus status --json          # machine-readable status for bars and panels
```

## Daemon privilege model

Root runs management; the daemon runs as the dedicated `albus` user with six
ambient capabilities (`NET_ADMIN`, `NET_RAW`, `BPF`, `PERFMON`,
`NET_BIND_SERVICE`, `DAC_OVERRIDE`). Unprivileged users are refused before
anything is touched. The systemd unit sets `User=/Group=albus`,
`RuntimeDirectory=/StateDirectory=albus`, `LimitMEMLOCK=infinity`, and
`ExecStopPost=+… cleanup` (privileged stop-cleanup); a scoped polkit rule
lets only the `albus` user drive per-link DNS (`resolve1` actions) without
interactive auth. `service uninstall` reverts firewall + DNS first, then
reports honestly: the system binary is retained by design (it says so).

Omarchy panel widget: see [docs/OMARCHY.md](docs/OMARCHY.md).

Full flag list: `albus run --help`. Defaults (kept in sync with `Config::default()` by CI):

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

DNSSEC validation: Bogus → SERVFAIL (never cached), unsigned → served
insecure, unsigned delegations without DS in the parent → insecure (never
Bogus). Query IDs (ECH, DNSSEC chain, leak canary) come from the OS CSPRNG.

### Verification
DPI evasion is verified against a live RST-injection simulator on every CI run — see docs/TEST_RESULTS.md for the latest recorded proof. To verify your own setup: see docs/TESTING.md.

```bash
sudo python3 scripts/dpi_sim.py run --iface lo --targets roblox.com,discord.com
```

## Troubleshooting

- eBPF won't load → check kernel ≥5.10, BTF (`/sys/kernel/btf/vmlinux`), cgroup v2.
- No network after stop → `sudo albus cleanup` restores `/etc/resolv.conf` + firewall.
- QUIC still leaks → `--block-quic` is on by default; verify with `iptables -S OUTPUT | grep albus`.
- DNS leaks → kill-switch drops non-loopback port 53 by default; check `albus service status`.

## Removal

```bash
sudo albus service uninstall
sudo albus cleanup     # restores /etc/resolv.conf, purges firewall rules
```

What `cleanup` does not delete: `/usr/local/bin/albus`, `/etc/albus/config.json`, `~/.config/albus/config.json` (remove manually if needed).
`service uninstall` likewise retains the system binary by design and says so — run `sudo albus cleanup` afterwards if needed.

## Docs

| Doc | What it answers |
| :--- | :--- |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute (gates, commits, deps) |
| [SECURITY.md](SECURITY.md) | Scope, reporting, disclosure |
| [docs/TESTING.md](docs/TESTING.md) | How to run every test suite |
| [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md) | Recorded DPI-evasion proof |
| [docs/OMARCHY.md](docs/OMARCHY.md) | Omarchy panel widget |

## License

[GNU GPL-3.0](LICENSE).
