# DPI Testing Runbook

How to prove albus actually evades DPI, without spending money or trusting
claims. Everything runs on one machine; no VPS, no external hardware.

## Model under test

A naive in-path DPI reads the **first TCP segment** of a TLS handshake,
extracts SNI, and RSTs banned names. albus defeats it two ways:

1. **MSS clamp** — ClientHello fragments across segments, so the first
   segment carries no complete SNI.
2. **Fake injection** — TTL-limited decoys with overlapping sequence
   ranges confuse reassembly.

`scripts/dpi_sim.py` models exactly this DPI: passive L3 observer,
SNI-from-first-segment classification, spoofed RST on match, silence on
fragmentation / overlap / bad checksum. stdlib only (no scapy).

## Requirements

- Linux, root (AF_PACKET sniffing + raw RST injection), Python 3.10+.
- `openssl` CLI (stub certificate generation).
- albus installed (`/usr/local/bin/albus`) for the bypass half.

## Full lab run (needs interactive root: `sudo` or `pkexec` session)

```bash
# 1. baseline WITHOUT albus shaping: expect RST (sim wins)
sudo systemctl stop albus.service
sudo python3 scripts/dpi_sim.py run --iface lo --targets roblox.com,discord.com
# -> handshake_ok=false, sim_decision=rst

# 2. with albus shaping: expect bypass
sudo systemctl start albus.service
sleep 5
sudo python3 scripts/dpi_sim.py run --iface lo --targets roblox.com,discord.com
# -> handshake_ok=true, sim_decision=pass-fragmented (or pass-allowlist)

# 3. restore normal state
sudo systemctl start albus.service  # if you stopped it in step 1
```

## Adding targets

Edit `TARGETS` in `scripts/dpi_sim.py`, or pass them inline:

```bash
sudo python3 scripts/dpi_sim.py run --targets roblox.com,discord.com,example.com
```

Subcommands for debugging: `stub` (TLS stub on 127.0.0.1:9443),
`sim` (observer only), `client <sni>` (single handshake).

## Logic self-tests (no root, always green)

```bash
python3 scripts/dpi_sim.py --help
# SNI parser + frame/checksum paths are exercised inline in development;
# networked assertions live in tests/net.rs.
```

## Recording results

After a real run, append a dated entry to `docs/TEST_RESULTS.md`:
date, kernel (`uname -r`), albus version/commit, targets, verdicts.
Never invent results — unrun configurations stay marked PENDING.
