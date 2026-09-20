# Testing

How to prove albus works, without spending money or trusting claims.
Everything runs on one machine; no VPS, no external hardware.

## Automated suites (no root, always green)

```bash
cargo fmt --check && cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo test --test fuzz --test docs --test net
```

Privileged suites need interactive root and never fail spuriously
(they SKIP when preconditions are missing):

```bash
sudo -E cargo test --test ebpf -- --ignored --nocapture
sudo -E cargo test --test root -- --ignored --nocapture
```

## DPI lab (`scripts/dpi_sim.py`, stdlib only)

A naive in-path DPI reads the **first TCP segment** of a TLS handshake,
extracts SNI, and RSTs banned names. albus defeats it two ways:
MSS clamp (ClientHello fragments, first segment carries no complete SNI)
and fake injection (TTL-limited decoys confuse reassembly). The script
models exactly this DPI: passive L3 observer, SNI-from-first-segment
classification, spoofed RST on match, silence on fragmentation / overlap /
bad checksum.

Requirements: Linux, root (AF_PACKET + raw RST), Python 3.10+,
`openssl` CLI, albus installed. Add targets in `TARGETS` or pass
`--targets host1,host2` (current: `roblox.com`, `discord.com`).

```bash
# baseline WITHOUT shaping: expect handshake_ok=false, sim_decision=rst
sudo systemctl stop albus.service
sudo python3 scripts/dpi_sim.py run --iface lo --targets roblox.com,discord.com
# with shaping: expect handshake_ok=true, sim_decision=pass-fragmented
sudo systemctl start albus.service && sleep 5
sudo python3 scripts/dpi_sim.py run --iface lo --targets roblox.com,discord.com
```

## Root verification checklist (manual, interactive root)

```bash
sudo iptables -S OUTPUT | grep -c albus   # baseline count B
sudo /usr/local/bin/albus service stop
sudo iptables -S OUTPUT | grep -c albus   # expect 0
sudo /usr/local/bin/albus service start
sleep 5
curl -s -o /dev/null -w "%{http_code}\n" https://example.com  # 200
sudo /usr/local/bin/albus service stop
grep "^nameserver" /etc/resolv.conf      # must NOT be 127.0.0.1
sudo iptables -S OUTPUT | grep -c albus   # expect 0
sudo /usr/local/bin/albus service start
sleep 8
systemctl is-active albus.service          # expect: active
```

Config hot-path: as normal user, change a panel toggle and save — toast
only, **no** polkit dialog. Then "Restart Service" — exactly **one**
polkit dialog is expected.

## Results log (append-only; never invent results)

### 2026-09-20 — logic self-tests (no root)
- Env: `Linux 7.2.5-3-omarchy`, Python 3.14.7, albus @ `develop`.
- SNI parser (`roblox.com`/`discord.com`, empty + 32-byte session id,
  garbage rejection) — PASS.
- Frame parse + TCP checksum round-trip (valid passes, 1-bit flip
  fails) — PASS.
- TLS stub + client handshake on 127.0.0.1:19443 (`discord.com`) —
  `handshake_ok=true` — PASS.

### 2026-09-20 — full root lab run (interactive root via pkexec)
- Env: `Linux 7.2.5-3-omarchy`, albus `2.1.0` (develop), targets
  `roblox.com`, `discord.com`, iface `lo`.
- Service stopped: `sim_rst clean-sni-first-segment` on both targets,
  `bypassed=false` — sim correctly blocks unprotected handshakes.
- Service running: no RST on either target, `bypassed=true` — MSS clamp
  fragments the hello and decoy injection confuses reassembly, so the
  sim never sees a clean blocked SNI.
- Loopback caveat (documented in code): our own decoys poison the local
  stub, so verdicts rest on sim observations, never on handshake success.
