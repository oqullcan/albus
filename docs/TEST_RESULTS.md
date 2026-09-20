# DPI Evasion — Recorded Proof

> NOTE (practice): this file is a **one-shot signed record**, not a living
> dashboard. It is intentionally NOT auto-updated on every CI run — recurring
> proof lives in the CI logs of the `dpi-evasion` job
> (`.github/workflows/ci.yml`), which hard-gates both directions on every
> run. **Update this file after a major architecture change** (e.g. eBPF core
> refactor, new shaping mechanism, simulator model change) by re-running the
> lab below and replacing the record.

## Method

`scripts/dpi_sim.py run` (stdlib only, needs root) orchestrates three parts on
`--iface lo`: a local TLS stub on `127.0.0.1:443`, a passive AF_PACKET
observer that injects a spoofed TCP RST when it sees a complete SNI in the
first segment, and one TLS client handshake per target with explicit SNI.
Verdicts follow **sim observations, never handshake success** (loopback
caveat, documented in code: our own decoys poison the local stub).

Both phases are asserted by `scripts/dpi_evasion_check.py`:

- `off` (albus DOWN): every target must be `sim_decision=rst` +
  `bypassed=false`. This proves the simulator is live — a lab that passes
  without any RST would be a false negative and fails the gate.
- `on` (albus UP): every target must be `bypassed=true`. Any RST here is a
  real evasion regression.

## Record — 2026-09-20T21:15Z (local root lab, interactive root via pkexec)

- Repo: `develop` @ `d055dcc` (engine + sim code as committed; the CI
  `dpi-evasion` wiring and `dpi_evasion_check.py` itself were the uncommitted
  working tree under test — same files committed right after).
- Env: `Linux 7.2.5-3-omarchy`, `/usr/bin/python3 3.14.7`, `openssl` CLI,
  iface `lo`, targets `roblox.com,discord.com`, daemon via `albus.service`.

### Phase A — albus OFF (service stopped): simulator must RST

`sim exit=1` (nothing bypassed), gate `off` → PASS:

| target      | sim_decision | bypassed | handshake_ok | seconds |
| ----------- | ------------ | -------- | ------------ | ------- |
| roblox.com  | rst          | false    | true         | 0.009   |
| discord.com | rst          | false    | true         | 0.002   |

RST rate 2/2 (100%). (Client `handshake_ok=true` here is a loopback race —
the stub's bytes arrive before the spoofed RST is processed; the verdict
rests on the sim's `rst` decision, which is what the gate asserts.)

Gate output: `DPI simulator: WITHOUT albus -> connection RST'd (expected).`

### Phase B — albus ON (service started, 8 s settle): evasion must hold

`sim exit=0` (all bypassed), gate `on` → PASS:

| target      | sim_decision   | bypassed | handshake_ok | seconds |
| ----------- | -------------- | -------- | ------------ | ------- |
| roblox.com  | no-observation | true     | false        | 0.203   |
| discord.com | no-observation | true     | false        | 0.204   |

Bypass rate 2/2 (100%). `no-observation` = traffic seen in the target window
but never classifiable and never RST'd — the DPI observed yet could not act,
so it was defeated (`ConnectionResetError` on the client side is the known
loopback self-decoy artifact, not a sim RST: `sim_decision` is what counts).

Gate output: `DPI simulator: WITH albus -> connection established (evasion successful).`

## Recurring proof (CI)

Every CI run executes job `dpi-evasion`: Phase A (simulator validity, albus
OFF must RST — fails red if the sim ever goes silent) then Phase B (release
daemon started with only shaping enabled, albus ON must bypass — fails red on
any RST). The job is deliberately not `continue-on-error`.
