# Panel.qml Testing Protocol

`Panel.qml` / `BarWidget.qml` have no compiler: correctness is established
by (1) schema validation, (2) live-shell load with journal check, (3) the
JS-logic harness below, (4) backend↔QML key cross-check. Run all four
after any Panel change; record in `docs/TEST_RESULTS.md` (pointer entry).

## 1. Schema validation

```bash
omarchy-plugin-validate ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev/
```

Must exit 0. (Also sync `manifest.json` version with the release.)

## 2. Live-shell load (Omarchy host only)

```bash
# sync repo files to the DEV plugin copy (never the marketplace copy)
cp Panel.qml manifest.json ~/.config/omarchy/plugins/io.github.oqullcan.albus.dev/
omarchy-plugin-enable io.github.oqullcan.albus.dev
# ...wait ~15s, or: omarchy-restart-shell (blinks the bar)
journalctl --user -b --no-pager --since "5 minutes ago" | grep -iE "albus|qml.*error"
omarchy-plugin-disable io.github.oqullcan.albus.dev   # restore bar state
```

Pass = file-watcher `reloading:` lines and/or fresh-start logs show
**zero** errors mentioning albus/Panel (the `IpcHandler ... will not be
used` WARNs affect every stock panel and are not failures). The panel
overlay itself opens only on widget click — not exercisable headlessly;
logic below covers what the click path would execute.

CAUTION: `omarchy-refresh-shell --help` is not a help flag — it REPLACES
`~/.config/omarchy/shell.json` with defaults (backup kept next to it).
Never run it for panel work; restore from `.bak` if it happens.

## 3. JS-logic harness (node, throwaway)

`canon`, `numOr`, `uiConfigShape`, `cfgFingerprint`, `parseConfigJson`
are pure JS (only `root.*` is ambient). Copy them verbatim into a temp
file with a global `root`, feed REAL backend JSON
(`cargo run -q -- config get > /tmp/backend.json`), and assert:

1. `canon` sorts keys stably.
2. `cfgFingerprint` is key-order invariant on real JSON.
3. Draft mirroring backend values → fingerprint equal (clean).
4. One toggle flipped → mismatch (dirty); flipped back → clean.
5. Mullvad round-trip (`mullvad-base` → profile → shape).
6. `parseConfigJson("")` / garbage → null (fallback retry trigger).

9 checks, all must pass. Do NOT commit the harness (verbatim drift
risk); this protocol is the durable artifact.

## 3. JS-logic harness (CI-gated, single-source)

`scripts/panel-logic-test.mjs` (`node --test`, CI `panel logic tests`
step): extracts `canon`, `numOr`, `uiConfigShape`, `cfgFingerprint`,
`parseConfigJson` VERBATIM from the shipped `Panel.qml` (string- and
comment-aware brace matching — no copied logic to drift) and asserts,
against an embedded backend fixture mirroring `config get` output:
key-order stability, fingerprint invariance, clean/dirty toggle cycle,
mullvad round-trip, fallback null parses, `numOr` defaults. 6 checks.
Run locally with the same command; edit the QML freely — the tests run
whatever ships.

## 4. Backend↔QML key cross-check

Every key `cfgFingerprint` reads must exist in `config get` output;
every key `uiConfigShape` emits must round-trip through `buildConfigArgs`
normalization (mss/min_mss defaults, ttl clamp 1..255, mullvad collapse).
Known deliberate gap (2026-09-25): the dirty check covers only the
panel-managed subset — `doh_enabled`, `min_ttl`, `max_ttl`,
`shaping_watchdog`, `verbose` are invisible to it. Adding them needs UI
toggles first (else permanent-dirty), so this stays a documented
limitation, not a bug.

## 5. Backend legs (no GUI needed)

- `cargo run -q -- config get --system` as user → PermissionDenied
  (fallback path engaged by design).
- Same as root → full system JSON (primary path).
- Old installed binary: `--system` unknown flag → non-zero exit →
  one-shot plain retry (migration path).

## Automation gap (narrowed 2026-09-27)

`qmllint`/`qmltestrunner`/Qt6 remain unavailable here and in CI, so
widget rendering and the click path stay manual (protocol above).
What IS automated now: the pure-logic layer (§3) runs in CI on every
push. Remaining manual-only surface: visual layout, overlay open
behavior, live daemon round-trips.
