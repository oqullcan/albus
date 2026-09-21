# Pinned CI action SHAs (supply-chain discipline: tags move, SHAs don't).
# Refresh procedure: `git ls-remote <repo> refs/tags/<tag>`, verify the
# commit on GitHub, update the full SHA below and in ci.yml (form:
# `uses: <action>@<sha> # <tag>` — never a bare tag).
#
# ci.yml also pins cargo-llvm-cov to a crates.io version:
# cargo-llvm-cov 0.9.1 (locally validated; bump deliberately).
#
# Rust stable is pinned to an exact version in ci.yml (1.98.0, locally
# validated 2026-09-21) wherever audit tooling needs it — floating `stable`
# made runs non-reproducible over time. Bump deliberately.
#
- sigstore/cosign-installer
  sha: 828df1e55de306ba29db814d6057ddae71883cda
  cosign-release: v3.1.3 (verified 2026-09-21; latest upstream release)
#
# Node20 deprecation notices (CI #37 forensics, 2026-09-21): the v4 tags
# above still resolve to node20-runtime commits upstream — there is NO newer
# v4 SHA to refresh to. Pins stay; warnings are acknowledged noise until
# upstream cuts node24-based v4 releases. Verified 2026-09-21 via ls-remote.

- actions/checkout@v4
  sha: 11d5960a326750d5838078e36cf38b85af677262
- dtolnay/rust-toolchain@stable
  sha: 6bed0761d98439e5a578e2877258200ad565ba87
- actions/upload-artifact@v4
  sha: ea165f8d65b6e75b540449e92b4886f43607fa02
- rustsec/audit-check@v2
  sha: 858dc40f52ca2b8570b7a997c1c4e35c6fc9a432
- EmbarkStudios/cargo-deny-action@v2
  sha: b66acf5e9fe20f8aba065be86778a8a4c846f902
