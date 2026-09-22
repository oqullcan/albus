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

### Coverage gaps + deny warnings closed out (local, 2026-09-21)

- `tests/cli.rs` (new): `--help`/`--version`/parse-rejection/`config get`
  smoke via `CARGO_BIN_EXE_albus` (verified the var is integration-only;
  an attempt inside `src/main.rs` unit tests fails to compile — recorded
  so nobody retries it).
- `run_engine` unprivileged-refusal unit test (root-gated skip).
- `rawsock` root send tests (v4/v6/mixed-families): 3/3 PASS in root lab.
- Deny `warning[parse-error]` root-caused: it is OUR OWN deprecated
  `GPL-3.0` SPDX spelling (already a deliberate decision), not a
  third-party fail-open; `warning[duplicate]` matches the deliberate
  `multiple-versions = "warn"` policy. Both documented in `deny.toml`.
  CI and local deny are the same version (0.20.2) — no skew.
- Watchdog soak: daemon up 1 h+ with flag ON and real traffic, 0 trips,
  0 lockdown (the 4 historic SHAPING LOST lines are all accounted for:
  3× v1 false positives + 1× overrun-era trip).
- M1 consistency grep: no remaining dynamic-probing claims (3 stale code
  comments fixed in this gate: `cli.rs` flag docs, `manager.rs` comment).
- Security suites re-run individually: ssrf 7, system 7, dnssec 16, cache
  9 (incl. qclass), server 12, firewall 7, engine 3, packet 8, autottl 10 —
  all green.
- Diff integrity: no secrets (scan clean), no artifacts, no `Cargo.lock`
  changes, `/tmp` worktree + instrumented copies removed.

### Island-of-security false-BOGUS fix (user-reported outage, 2026-09-21)

- Symptoms with albus active: `chatgpt.com` → `DNS_PROBE_POSSIBLE`
  (SERVFAIL), Instagram stories/media failing. Two stacked causes found:
  1. Watchdog false-positive lockdown (separate incident above) killed
     new :443 — explained the Instagram media failures and most SERVFAILs.
  2. Genuine validator bug for `chatgpt.com`/`quad9.net`: signed answers
     under an **unsigned delegation** (no DS in parent — verified: DS
     query returns NSEC3 denial) were judged Bogus. Root cause: chain-walk
     failure (missing DS) was indistinguishable from crypto failure.
- Fix (`src/dns/dnssec.rs`): split the verdict — signatures that VERIFY
  but cannot chain serve as Insecure (island; no downgrade vs unsigned
  baseline, which is already served); only proven crypto failure stays
  Bogus; denial records keep the strict rule (forgery direction).
- Regression test `test_island_of_security_is_insecure_offline`
  (self-signed fixture without anchor — fully offline): Insecure, was
  Bogus before the fix. Existing tampered-data test still Bogus.
- Live verification after reinstall: `chatgpt.com` NOERROR an=3,
  `quad9.net` NOERROR an=2, all instagram/fbcdn hosts resolve; journal
  shows zero BOGUS after restart. Instagram app itself may need a restart
  (it cached lockdown-era failures); QUIC→TCP fallback is normal.
- Install note: a stray `albus monitor` TUI holds the binary busy
  (`Text file busy` on cp) — remove-then-copy (`rm -f` + `cp`) replaces
  it safely; the running monitor keeps its old pages.
- Rootless install caveat: `service install` run from the INSTALLED
  binary always fails self-copy (`current_exe == SYSTEM_BIN_PATH` →
  ETXTBSY fail-closed). Always install from the build tree
  (`./target/release/albus service install`).

### "Internet dies with albus on" triage, part 2: PQ-intolerance (2026-09-22)

- After the island fix, remaining failures narrowed per-destination:
  packet capture showed the server (or on-path box) answering curl's
  ClientHello with fatal `15 03 01 00 02 02 28` (alert 40).
- Hello forensics (curl `--trace` parse): 1546-byte hello offering
  `SecP256r1MLKEM768 (0x11ec)` FIRST with a 1216-byte share. Deterministic
  repro: `openssl s_client -groups SecP256r1MLKEM768` → alert 40;
  `-groups X25519MLKEM768` → negotiates fine; `-groups X25519` → fine.
  Conclusion: something on that path kills 0x11ec hellos specifically —
  external to albus (reproduced with shaping fully off, DNS+firewall only;
  albus never touches hello bytes).
- Our own DoH (aws-lc-rs defaults) still completes — different edges
  tolerate; no albus change made (would fix nothing user-side).
- Fastly (93.184.216.34) and Meta (157.240.1.1) paths dead even with
  daemon stopped and zero rules loaded (ICMP-proven) — upstream/ISP-side.
### "Internet dies with albus on" triage, part 3: polkit-locked NSS (2026-09-22)

- Symptom: total outage with daemon active, instant recovery when off —
  but ICMP/TCP matrices showed selective path failures, masking the real
  mechanism: `nsswitch.conf` puts systemd `resolve` FIRST, and resolved's
  upstreams (:53/:853) are kill-switch-dropped, so EVERY glibc lookup
  hung (not failed) whenever resolved had no per-link DNS to loopback.
- Root cause, two layers: (a) `configure_resolvectl_dns` swallowed ALL
  errors (`let _`), so missing per-link DNS was invisible — and my own
  spike-test `revert` had wiped it; (b) under the rootless unit
  (`User=albus` + `NoNewPrivileges`), SetLinkDNS et al. fail with
  "requires interactive authentication" — reproduced exactly via
  `systemd-run` with the unit's sandbox flags (plain setpriv worked,
  sandboxed failed).
- Fix: explicit polkit allowlist for the `albus` user
  (`set-dns-servers`, `set-domains`, `set-default-route`, `revert`,
  `flush-caches` → YES; nothing beyond what the daemon already controls
  via `/etc/resolv.conf`) + `configure`/`revert` return `Result` with
  loud errors + startup treats configure failure as fatal + canary
  re-verifies per-link DNS every 60 s and self-heals (own 5-min gate).
- Regression tests: polkit content asserts, `parse_link_dns_output`
  fixtures. Live validation after reinstall: per-link `127.0.0.1` applied
  by the daemon itself, `getent` instant, chatgpt 403 in 0.02 s, github
  200 in 0.5 s, eBPF attached, 0 lockdown, 0 BOGUS.
- Suite: 138 lib green, clippy/fmt clean.

### Round-up: CLI surface, QML evidence, ExecStopPost+, unit render test

- `tests/cli.rs` extended to 7 (status, status --json shape, cleanup
  refusal with resolv.conf untouched, service status passthrough).
- QML best-available evidence: installed copy byte-identical; live
  shell journal zero QML errors. Recorded in TESTING.md.
- `ExecStopPost=+albus cleanup` (rootless made the old line a no-op):
  unit template extracted to pure `build_unit_content()` + regression
  test asserting the `+` prefix, User=albus, caps, memlock lines; rendered
  output passes `systemd-analyze verify` clean (checker sanity-checked
  against a broken fixture).
- Live install test of the new unit: BLOCKED (pkexec agent dead this
  session); will run on next root window before any release.

### "Internet dies with albus on" triage (live, 2026-09-21)

- Method: ICMP matrix (albus has NO code path affecting ICMP — any ping
  failure is definitionally external) + DNS matrix + IP-literal TCP
  matrix + iptables counters, daemon on vs off.
- Proven albus-independent: `93.184.216.34` (Fastly/example.com) and
  `157.240.1.1` (Meta) ping-fail with daemon STOPPED and zero albus
  rules loaded; 1.1.1.1/8.8.8.8/9.9.9.9 fine throughout. Traceroute-by-TTL
  dies after hop 4 (81.212.211.204) with no further replies — upstream
  path issue toward those networks, not on-host.
- Proven albus-healthy at the same time: TCP:443 to 1.1.1.1 in 0.02 s
  and to 8.8.8.8 in 0.08 s with daemon active; no lockdown rules;
  validator BOGUS-quiet post-restart; all instagram/fbcdn hostnames
  resolve.
- Earlier "off=works" correlation was flapping paths + the two real
  albus bugs already fixed above (lockdown incident, island SERVFAIL).
  UFW is active with default policies throughout (coexists, not involved).

### Shaping watchdog validation (local root lab, 2026-09-21)

- Choice: BPF query-first + fail-closed + flagged (default on).
- Design pivot (honest): `BPF_PROG_QUERY` proved **non-functional on this
  kernel — raw syscall returns EINVAL for every attach type, flag set, and
  attr size (both 32 B and 64 B), verified down to hand-packed bytes via
  ctypes as root. Watchdog therefore measures effectiveness directly
  (loopback MSS probe on a target port) instead of asking the kernel; the
  query code was deleted, not left to rot. Streak policy (2× Unhealthy
  trips; Healthy resets; Inconclusive freezes) replaces double-confirmation.
- Quiet on healthy daemon: 75 s+ uptime, 0 lockdown rules, 0 SHAPING LOST
  lines, service active (no false trip).
- Live trip test: dummy no-op program attached at the hierarchy root via
  ctypes (displacing the daemon's program, same hazard class as the Phase
  2.5 incident) → within ~2 watchdog intervals: **4 `albus-lockdown`
  rules + exactly 1 SHAPING LOST journal line**, daemon alive (fail-closed
  as designed, no log spam).
- Recovery: `service restart` → `active`, 0 lockdown, 6 albus rules,
  `curl → 200` (re-armed cleanly).
- DPI ON after restart: **bypassed 2/2** (no-observation profile).
- Root loader roundtrip test (attach/detach at child cgroup): PASS.
- Coverage with watchdog code: **66.44%** lines, gate PASS.

### Watchdog v2 — reconciliation detector (local root lab, 2026-09-21)

- v1 MSS probe abandoned with cause: on GSO/loopback paths the kernel
  reports huge MSS even with the clamp attached (observed `mss:32741`
  on a shaping daemon), so the probe read Unhealthy on healthy daemons
  and triple-bricked the machine (3 lockdowns, one per restart). The
  probe code was deleted outright — a misleading instrument is worse
  than none.
- v2 model (`src/core/ebpf/watch.rs`): every NEW ESTABLISHED target-port
  connection must be accompanied by fresh perf events in the same window;
  unexplained newcomers across 2 consecutive windows trip. Baseline
  snapshot (pre-existing conns never count), DoH exclusions honored,
  idle/event windows reset, dead inodes pruned. 6 unit tests (fixtures,
  exclusion, trip/reset lifecycle, malformed input).
- v6 parsing cross-checked live: `/proc/net/tcp6` remote
  `00470626000078009000000042010000` decodes (per-word reversal) to a
  `2606:4700:...` address matching `ss` output family.
- Quiet with v2 armed + real browser traffic: 0 lockdown, 0 warnings.
- Live trip (ctypes displacement + curl traffic): **4 lockdown rules +
  exactly 1 SHAPING LOST**, daemon alive; restart recovered fully
  (`active`, 0 lockdown, 6 rules, `curl → 200`).
- DPI ON after recovery: **bypassed 2/2**. Machine left with watchdog
  ENABLED (validated); code default stays `false` until v2 soaks.
- Root loader test hardened: Drop-guard cgroup cleanup + EPERM-skip when
  the daemon holds the root slot (kernel design, not a bug).

### Watchdog overrun fix (root-caused false trip, local root lab, 2026-09-21)

- A daemon tripped with **zero external interference**: fresh :443 conns,
  zero new events, 2 consecutive windows. Root cause, code-reading +
  elimination: the perf ring silently drops events on overrun (8 pages;
  media-burst connection storms), and the worker counted only what it
  read — a burst that overruns the ring looks exactly like a dead
  program. eBPF attach was healthy throughout (verified at boot).
- Fix: (a) `read_events`/`poll_events` now report overrun
  (`head - tail > capacity` → resync + `true`); (b) watchdog rounds with
  an overrun **freeze** (neither trip nor reset); (c) ring 8 → 32 data
  pages/CPU. Rationale documented in code: overrun implies events WERE
  flowing, so skipping is the safe direction.
- Validation: 300-connection burst (25 parallel) against a live stub with
  watchdog armed → 0 lockdown, 0 warnings, service active. DPI ON after:
  **bypassed 2/2**. (Incidental catch while fixing: the event counter had
  been glued onto a comment line by a bad edit — zero counting, guaranteed
  future false trip. Fixed + verified green.)
- Caveat recorded: unit tests cannot force a kernel ring overrun; the
  freeze path is integration-proven (this burst run), not unit-proven.

### CI#40 DPI flap RCA + deterministic lab (local + CI, 2026-09-21)

- CI run on `6f50d09` failed Phase B on ONE target (`discord` RST,
  `roblox` bypassed, same daemon seconds apart) — race signature, not
  regression (no commit content touches the shaping path).
- Root cause, measured locally: loopback GSO delivers whole ClientHellos
  (~1526 B first segment) past the MSS clamp; with GSO off, first segment
  is ~127 B (fragmented) and decoys overlap. Previous green runs rested
  on decoy-timing luck.
- Fix (`ci.yml` + `dpi_sim.py`): `ethtool -K lo gso/gro/tso off` with
  loud verification before the lab (real middleboxes sit behind
  segmenting NICs, so this is the faithful setup), plus per-flow
  `sim_first_seg` length logging for future forensics. Validated locally
  (3/3 clean bypass, GSO restored after) and in CI run on `9d76e02`:
  **5/5 green** — Phase A first-seg 517 B (whole, RST as designed),
  Phase B first-seg 127/130 B (fragmented, bypass as designed). The
  mechanism is now visible in CI logs, not inferred.

### Round-up: CLI surface, QML evidence, watchdog default-on (2026-09-21)

- `tests/cli.rs` extended: `status`, `status --json` (shape-asserted),
  `cleanup` refusal (asserts the root message + `resolv.conf` untouched),
  `service status` passthrough (asserts output, not hang). 7/7 green.
  (One authored test asserted nothing — caught in review, replaced with
  a real output assertion before commit.)
- QML best-available evidence: installed plugin copy byte-identical to
  repo; live Omarchy shell journal shows zero QML errors for it (only an
  unrelated bluetooth DBus warning + my own `qml6` probe failure, which
  cannot resolve Quickshell imports by design). Recorded in TESTING.md.
- Watchdog default flipped to **on** (code + README table): 1 h+ soak
  with flag on and real traffic, 0 trips, 0 lockdown; trip-on-demand and
  burst-proof proven earlier. Machine config already had it on; fresh
  installs now get it too. QML untouched (it never sends the flag).