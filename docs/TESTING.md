# Testing

How to prove albus works, without spending money or trusting claims.
Everything runs on one machine; no VPS, no external hardware.

## Automated suites (no root, always green)

```bash
cargo fmt --check && cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo test --test fuzz --test docs --test net
cargo llvm-cov --workspace --fail-under-lines 55 --summary-only  # needs stable + llvm-tools
```

QML (`BarWidget.qml`, `Panel.qml`) has no automated tests: no Quickshell
runtime exists in CI or here — reviewed by reading (process spawning uses
absolute paths + arg arrays, all text is `PlainText`, inputs validated).
Best available evidence: the installed copy under
`~/.config/omarchy/plugins/` is byte-identical to the repo, and the live
Omarchy shell journal shows zero QML errors for it. If Qt tooling ever
becomes available, add at least a parse smoke test.

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

Migration note (managed-install marker): installs by the new binary
write `/etc/albus/.managed` (root-only, `O_NOFOLLOW`). Rule cleanup
deletes legacy `albus-*` rules **only** when the marker is absent
(first stop after upgrade); once the marker exists, teardown removes
only rules the daemon knows it applied. Verify with:
`sudo ls -l /etc/albus/.managed` (present after fresh install,
absent on pre-marker installs until next stop/start cycle).

## Results

This file is procedures only. Recorded evidence lives in
docs/TEST_RESULTS.md (signed DPI records + history of earlier runs) and in
the CI logs of the `dpi-evasion` job. Never invent results.
