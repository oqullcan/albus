# Contributing

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
  `cargo test --test fuzz`, `cargo test --test docs`.
- Supply-chain rules: no git/crates-io-external sources without review
  (`deny.toml` `[sources]` denies them by default), lockfile always
  committed, `cargo audit` clean before every release tag.
