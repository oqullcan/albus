# Pinned CI action SHAs (supply-chain discipline: tags move, SHAs don't).
# Refresh procedure: `git ls-remote <repo> refs/tags/<tag>`, verify the
# commit on GitHub, update the full SHA below and in ci.yml (form:
# `uses: <action>@<sha> # <tag>` — never a bare tag).
#
# ci.yml also pins cargo-llvm-cov to a crates.io version:
# cargo-llvm-cov 0.9.1 (locally validated; bump deliberately).

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
