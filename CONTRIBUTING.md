# Contributing

## Toolchain & gates

- Rust **1.89**, pinned via `rust-toolchain.toml` (matches CI). Audit tools
  (`cargo audit`, `cargo deny`) run on stable — code stays pinned.
- Every change must pass, in this order:
  ```bash
  cargo fmt --check && cargo clippy --workspace -- -D warnings
  cargo test --workspace
  cargo test --test fuzz --test docs --test net
  ```
- Coverage gate: `cargo llvm-cov --workspace --fail-under-lines 55`
  (same bar CI enforces; run it before pushing).
- `tests/docs.rs` enforces that the README flag table matches
  `Config::default()` cell-for-cell: any default change must update the
  README table in the same commit, or CI goes red.
- Privileged suites need root and SKIP without it (never fail spuriously):
  `sudo -E cargo test --test ebpf -- --ignored`,
  `sudo -E cargo test --test root -- --ignored`.

## Pull requests

- Fork, branch from `develop`, open the PR against `develop` (never `main`).
- One concern per PR; describe what you measured, not just what you changed
  (test output or sim verdicts beat adjectives).
- A maintainer squash-merges; keep your branch in sync if CI drifts.

## Evasion changes

- Any shaping change (MSS, injection, eBPF maps) must be validated against
  the live simulator:
  ```bash
  sudo python3 scripts/dpi_sim.py run --iface lo --targets roblox.com,discord.com | tee /tmp/dpi.log
  python3 scripts/dpi_evasion_check.py off|on /tmp/dpi.log
  ```
  RST with albus off (proves the sim is live) and bypass with albus on
  (proves evasion) — both are hard gates, in CI and locally.
- Architecture-level changes also refresh the signed record in
  `docs/TEST_RESULTS.md`. Procedures: `docs/TESTING.md`.

## Commits

- Style: `feat(scope): ...` / `fix(scope): ...`, concise, no secrets.
- Only commit what you reviewed (`git status`, `git diff`); never
  `--force-push`, never amend a commit someone else pulled.

## Dependency Maintenance

- Every new dependency must pass `cargo deny check` against `deny.toml`.
  If it needs a license outside the allow-list, update `deny.toml`
  **and** explain why in the PR — new licenses are a deliberate decision,
  never an accident.
- The weekly scheduled CI run executes `cargo audit` and `cargo deny`.
  If it goes red: open a GitHub Issue titled `deps: <advisory-or-crate>`,
  pin or patch within 14 days, and link the issue from the fix PR.
- Prefer `cargo update -p <crate>` (surgical) over blanket `cargo update`.
  After any update, run the full suite: `cargo fmt --check`,
  `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`,
  `cargo test --test fuzz --test docs --test net`.
- Supply-chain rules: no git/crates-io-external sources without review
  (`deny.toml` `[sources]` denies them by default), lockfile always
  committed, `cargo audit` clean before every release tag.
