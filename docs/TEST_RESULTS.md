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
  `dpi-evasion` wiring and `dpi_evasion_check.py` were committed right after
  as `77ac0e2`).
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

## History (moved from docs/TESTING.md results log, 2026-09-20)
Earlier runs, kept as context. Procedures for re-running any of these live in
docs/TESTING.md; new signed DPI records go at the top of this file.

### Logic self-tests (no root)

- Env: `Linux 7.2.5-3-omarchy`, Python 3.14.7, albus @ `develop`.
- SNI parser (`roblox.com`/`discord.com`, empty + 32-byte session id,
  garbage rejection) — PASS.
- Frame parse + TCP checksum round-trip (valid passes, 1-bit flip
  fails) — PASS.
- TLS stub + client handshake on 127.0.0.1:19443 (`discord.com`) —
  `handshake_ok=true` — PASS.

### Full root lab run (interactive root via pkexec)

- Env: `Linux 7.2.5-3-omarchy`, albus `2.1.0` (develop), targets
  `roblox.com`, `discord.com`, iface `lo`.
- Service stopped: `sim_rst clean-sni-first-segment` on both targets,
  `bypassed=false` — sim correctly blocks unprotected handshakes.
- Service running: no RST on either target, `bypassed=true` — MSS clamp
  fragments the hello and decoy injection confuses reassembly, so the
  sim never sees a clean blocked SNI.
- Loopback caveat (documented in code): our own decoys poison the local
  stub, so verdicts rest on sim observations, never on handshake success.

### Wave-2 unit + privileged suites (develop)

- `cargo test --lib`: **104 passed**, 0 failed, 2 ignored. New: firewall
  marker-gating test (`managed_install_present_at`: absent/file/symlink/dir)
  and NSEC3 closest-encloser test (parent/grandparent/self match,
  unrelated miss, non-NSEC3 ignored). `cargo clippy --lib`: clean.
- `cargo test --test root -- --ignored` as root via pkexec: **3 passed**
  (QUIC block/unblock symmetry; "Bad rule" lines are the test's own
  idempotent-cleanup noise on absent rules).
- Live daemon untouched by the suite: `albus.service` still `active`,
  6×`albus` rules in v4 + 6× in v6 OUTPUT; `/etc/albus/.managed` absent
  (live install predates the marker — first stop/start with the new
  binary will take the one-shot legacy-cleanup path, then behave as
  managed).

### Coverage gate (local, 2026-09-20)

- `cargo llvm-cov --workspace --fail-under-lines 55 --summary-only`
  (stable toolchain + llvm-tools): **PASS** (`rc=0`), TOTAL lines
  **61.13%** (functions 61.52%, regions 57.88%) — above the 55% CI bar
  with ~6 points of margin. Thinnest files: `core/rawsock/mod.rs` (0%),
  `main.rs` (40.74%), `core/firewall.rs` (42.75%).

### Marker migration cycle + eBPF suite (local root lab, 2026-09-20)

- Installed `/usr/local/bin/albus` predated the marker logic (`strings`
  count for `managed`: 0) → rebuilt `--release` from HEAD, confirmed
  marker strings present, installed it. (Installed binary == HEAD code;
  only docs differ in the working tree.)
- Baseline (old daemon): `active`, 6×v4 + 6×v6 `albus` OUTPUT rules,
  `/etc/albus/.managed` absent.
- `systemctl stop` (old binary): `inactive`, 0/0 rules.
- `albus service start` (new binary): `active`, 6+6 rules,
  `curl https://example.com → 200`.
- `albus service stop` (new binary, marker **absent** → one-shot legacy
  sweep path): `inactive`, **0/0 rules**, `resolv.conf` restored to
  `nameserver 127.0.0.53` (not 127.0.0.1), marker still absent (only
  `service install` writes it — expected).
- `albus service start` again: `active`, 6+6 rules, `curl → 200`
  (machine left protected).
- `cargo test --test ebpf -- --ignored` as root: **1 passed**
  (`ebpf_load_attach_write_detach` — real kernel load/attach on
  `7.2.5-3-omarchy`).

### Phase 2 remediation validation (local, 2026-09-21)

- `cargo fmt --check`: clean. `cargo clippy --workspace -- -D warnings`:
  clean (blanket `allow(dead_code, clippy::all)` removed from `lib.rs`;
  19 surfaced lints fixed individually).
- `cargo test --workspace`: **all green** — 122 lib (was 104; +18: SSRF
  mapped-v6, base32hex roundtrip/adversarial, neg-cache policy, NSEC
  span/coverage, static TTL contract ×2, L2 firewall, L3 engine ×2, T5
  reload, L5 install persist, L10 cache policy, sanitize, qclass split,
  secure-rand distribution, IP-ID variance, atomic-write perms, L16 ×2)
  + 3 bin + integration (fuzz 6→8 with ECH/canary gates), 0 failed.
- `cargo llvm-cov --workspace --fail-under-lines 55`: **PASS** (`rc=0`),
  TOTAL lines **66.60%** (was 61.13%).
- `cargo audit` (1256 advisories, 196 crates): clean. `cargo deny check`:
  fully clean (allow-list tightened to encountered licenses only).
- Root suites (`root`, `ebpf`) and DPI re-run against the remediated code:
  were BLOCKED when this was written (`pkexec` agent dead) — **resolved in
  Phase 2.5 below** once the agent recovered. Non-root validation above was
  and remains complete.

### Phase 2.5 release gate (local root lab, 2026-09-21)

- `pkexec` recovered mid-gate (flaky auth agent — works, then hangs for
  minutes; `sudo -N` unusable). All privileged ops below ran during live
  windows; nothing was fabricated.
- Remediated binary rebuilt `--release`, installed, service restarted:
  `active`, 6+6 `albus` OUTPUT rules, `curl https://example.com → 200`.
- `cargo test --test root -- --ignored`: **3 passed** (incl. Drop-guard
  restore). `cargo test --test ebpf -- --ignored`: **1 passed** (real
  kernel attach; plus child-cgroup SKIP path verified live, see below).
- DPI ON with remediated binary: **bypassed 2/2** (`no-observation`,
  gate PASS) — matches the pre-remediation evasion profile.
- **Incident during gating (root-caused, not a regression):** an earlier
  ON run showed 4× clean-SNI RST. Investigation (segment-size sniffing via
  a `/tmp` instrumented sim copy — repo untouched) proved the MSS clamp was
  absent AND no decoys flowed, while the daemon believed itself attached.
  Root cause: the `ebpf` privileged test had attached its own program to
  `/sys/fs/cgroup` minutes earlier, silently displacing the daemon's
  program; its `detach()` then left the cgroup empty. A/B against a
  pre-remediation worktree build confirmed old code behaves identically
  when undisplaced. Fixes from this incident:
  (a) `tests/ebpf.rs` now attaches to an isolated child cgroup
  (`/sys/fs/cgroup/albus-test-<pid>`, removed on Drop) — verified live:
  full pass with daemon stopped, clean EPERM-SKIP with daemon running;
  (b) new standing limitation (see below).
- **New limitation (operational hazard, future work):** any eBPF
  (re)attach to the hierarchy root silently displaces albus's program with
  zero alarm — the daemon never re-verifies attachment. No health check
  exists for "shaping actually applied". Recommend periodic attach
  verification or an MSS-effectiveness watchdog.
- Loopback methodology note: MSS clamp does not fragment on `lo` the way
  the lab once assumed (`ss` showed `mss:32741` unshaped; instrumented
  capture showed a whole 1526 B first segment when undisplaced vs 127 B +
  decoy overlap when attached). Lab verdicts on `lo` rest on decoy
  confusion as much as fragmentation — recorded here so future runs are
  interpreted correctly.
- CI workflow re-verified: all 5 actions on full SHAs (mutable-tag scan
  empty), `contents:read` top-level, `actions:write` on `build` only,
  llvm-cov pinned `0.9.1` consistently, YAML parses. GitHub CI itself is
  unrun (nothing pushed — inherent).
- QML: `qml6` cannot load the panel (missing Quickshell imports, no
  `qmllint`); runtime verification remains unavailable, limitation stands.
- M1 consistency grep: no remaining dynamic-probing claims (3 stale code
  comments fixed in this gate: `cli.rs` flag docs, `manager.rs` comment).
- Security suites re-run individually: ssrf 7, system 7, dnssec 16, cache
  9 (incl. qclass), server 12, firewall 7, engine 3, packet 8, autottl 10 —
  all green.
- Diff integrity: no secrets (scan clean), no artifacts, no `Cargo.lock`
  changes, `/tmp` worktree + instrumented copies removed.
