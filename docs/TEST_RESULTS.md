# DPI Lab Test Results

Append-only log. Unrun configurations stay PENDING — never invent results.

## 2026-09-20 — logic self-tests (no root)

- Env: `Linux 7.2.5-3-omarchy`, Python 3.14.7, albus @ `develop`.
- SNI parser: `roblox.com` / `discord.com` (empty + 32-byte session id),
  garbage rejection — PASS.
- Frame parse + TCP checksum round-trip (valid passes, 1-bit flip fails)
  — PASS.
- TLS stub + client handshake on 127.0.0.1:19443 (`discord.com`) —
  `handshake_ok=true` — PASS.

## PENDING — full root lab run (needs interactive root session)

- `scripts/dpi_sim.py run --iface lo --targets roblox.com,discord.com`
  first with the service stopped (expect `rst`), then running
  (expect `pass-fragmented`). Blocked on: no polkit agent in the
  automation session (`pkexec` hangs). Run manually per
  `docs/DPI_TESTING.md` and record verdicts here.
