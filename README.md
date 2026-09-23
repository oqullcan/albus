# albus

DPI bypass and encrypted DNS for Linux: eBPF packet
desynchronization plus a local validating DoH resolver.

Evade — fragment TLS ClientHello across packets (eBPF MSS clamp + jitter, raw-socket
decoys) so middleboxes can't read SNI. Encrypt — resolve DNS locally over DoH with
DNSSEC validation, kill-switch, and leak canary. Enforce — fail-closed firewall rules
and a rootless daemon that refuses to run unprivileged.

## Requirements

Linux 5.10+, cgroup v2, Rust 1.75+. Source builds need clang + kernel headers
(CI installs them); the release binary runs standalone.

## Quickstart

```bash
git clone https://github.com/oqullcan/albus.git && cd albus
cargo build --release
sudo ./target/release/albus service install    # binary + unit + polkit, starts daemon
albus status --json                            # active check for bars and panels
```

```bash
sudo albus run --doh-upstream mullvad-base       # foreground with options
sudo albus config set --doh-upstream cloudflare  # persist + live-reload daemon
sudo albus cleanup                               # restore DNS + firewall
albus monitor                                    # traffic TUI
```

## Daemon

Privileged commands (root — install, control, configure, clean up):

- `sudo albus service install` — install binary, systemd unit, polkit rule; creates the `albus` user and starts the daemon
- `sudo albus service uninstall` — stop, remove unit and rule, revert firewall and DNS (binary is kept by design, with a printed notice)
- `sudo albus service start` — start the background daemon
- `sudo albus service stop` — stop the background daemon
- `sudo albus service restart` — restart (crash-safe: rules re-applied on start)
- `sudo albus service reload` — SIGHUP, zero-downtime eBPF map reload
- `sudo albus service status` — systemd unit state
- `sudo albus service logs` — stream the daemon journal
- `sudo albus run [--flags]` — run the engine in the foreground with options
- `sudo albus config set KEY VALUE` — persist a setting and live-reload the daemon
- `sudo albus cleanup` — restore `/etc/resolv.conf` and purge firewall rules

Unprivileged commands (inspect only):

- `albus status` — kernel capability and privilege summary
- `albus status --json` — machine-readable status for bars and panels
- `albus config get` — print the active configuration as JSON
- `albus monitor` — interactive traffic telemetry TUI

Root runs management; the daemon runs as the dedicated `albus` user with six
ambient capabilities (`NET_ADMIN`, `NET_RAW`, `BPF`, `PERFMON`, `NET_BIND_SERVICE`,
`DAC_OVERRIDE`). Uninstall keeps `/usr/local/bin/albus` by design (it says so —
remove it manually if wanted).

## Options

Evasion:

- `--mss 88` — initial TCP MSS size that fragments the ClientHello
- `--min-mss 64` — per-connection jitter floor (must stay ≤ mss)
- `--restore-after-bytes 600` — byte threshold before restoring line-rate MSS (≥ 64)
- `--restore-mss 0` — MSS restored afterwards (`0` = 1460 auto, else 64–1460)
- `--ports 443` — target ports for sock_ops interception (up to 64, comma-separated)
- `--fake-ttl 8` — TTL stamped on injected fake packets
- `--auto-ttl` — heuristic hop-distance TTL instead of the fallback (conservative constant, not measured probing)
- `--min-ttl 3`, `--max-ttl 12` — clamps for the auto-TTL heuristic
- `--fake-sni` — override the rotating high-reputation decoy SNI pool
- `--fake-bad-checksum` — corrupt TCP checksums with `0xDEAD` to confuse stateful middleboxes

DNS:

- `--doh` — spawn the local DoH proxy listener on 127.0.0.1:53 (on by default)
- `--doh-upstream quad9` — presets (`quad9`, `cloudflare`, `mullvad-*`) or an `https://` URL (https-only, enforced)
- `--doh-bootstrap-ips` — static IPv4 endpoints to resolve custom DoH hosts
- `--dnssec` — validate RRSIG chains locally: Bogus → SERVFAIL (never cached), unsigned → served insecure, unsigned delegations without DS → insecure (never Bogus)
- `--pqc` — offer hybrid ML-KEM-768 where the upstream negotiates it (transport KEX only, logged per upstream)
- `--block-ipv6` — filter AAAA queries so IPv6 can't bypass inspection unfragmented

Containment:

- `--block-quic` — drop outbound UDP 443 to force TLS/TCP fallback
- `--block-stun` — drop outbound STUN (UDP 3478, 5349) against WebRTC IP leaks
- `--kill-switch` — drop all non-loopback plaintext DNS (UDP/TCP 53, TCP 853)
- `--network-lockdown` — fail-closed: drop outbound TCP 80/443 if eBPF fails (off by default)
- `--ram-only` — keep runtime state in `/run` tmpfs only
- `-c`, `--config PATH` — load an explicit config file (must be root-owned, non-symlink when privileged)
- `--cgroup /sys/fs/cgroup` — cgroup v2 mount point for BPF attachment
- `--verbose` — debug logging

## Omarchy panel

Quattro widget (`BarWidget.qml`, `Panel.qml`): status, resolver profiles, toggles,
live logs (`1/2` tabs, `Space`, `R` reload, `C` flush).

```bash
mkdir -p ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev
cp manifest.json BarWidget.qml Panel.qml ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev/
```

## License

[GPL-3.0](LICENSE)
