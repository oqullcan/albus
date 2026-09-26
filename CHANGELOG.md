# Changelog

All notable changes to the Albus project are documented in this file.
Branch discipline: `develop` is the integration branch; `origin/master`
holds audited releases; `origin/develop` is the pushed integration tip.
A stale parallel lineage (`origin/dev`, tip `465655e`) was archived as
tag `archive/dev-465655e` on 2026-09-25 and pruned — see Unreleased.

## Unreleased (develop)

### Fixed (run-12/13 audit findings, uncommitted)
- DOH-REDIRECT-FOLLOW (medium): shared reqwest builder now sets
  `Policy::none()` on both DoH client builders; upstream 307 can no
  longer re-POST queries elsewhere, downgrade scheme, or escape SSRF
  screening. Locked by `test_redirect_is_not_followed_offline`
  (plaintext stub + decoy listener, no-follow proven incl. negative
  control against pre-fix behavior).
- DNS-CACHE-KEY-COLLISION (medium): exact `qlabels` vector in
  `Hash`/`Eq` (dotted `name` kept for validator/display) + bounded
  8-jump pointer resolution instead of target-skipping; validation
  still runs (fail-open avoided). Locked by 3 hermetic tests
  (dot-vs-split, pointer targets, loop/truncation).
- LOG-QLABEL-FORGERY (low): BOGUS `qlabel` wrapped in
  `sanitize_log_token`, extended with BiDi/format set; unit test
  extended.
- Fuzz corpora (robustness, no findings): OPT/DO shapes incl.
  per-offset truncation, per-offset SVCB truncation + overlong/
  overrun shapes, coherent-ELF section images, validate-level wire
  fuzz (unsigned/CNAME-loop/denial/truncation/mutation, never-Secure
  invariant) — 12/12 green.

### Fixed (run-10/11 audit findings, uncommitted)

### Fixed (run-10/11 audit findings, uncommitted)
- DNSSEC-DS-WALK-DEPTH-2 (low): apex-discovery walk with zone-cut
  stop; 2-deep seeded Bogus lock + delegation Insecure lock.
- Upstream AD no longer forwarded without local proof
  (`strip_ad_unless_secure`; only Secure keeps AD). Timeout still
  serves unverified (availability tradeoff, documented) but never
  as authenticated.
- TTL validator gaps (low, self-inflicted): `fake_ttl`/`min_ttl`/
  `max_ttl` now bounded 1..=64 in `validate` + clap parsers + QML
  clamp (was 255); 0 TTL fail-open closed.

### Fixed (run-9 audit finding)
- DNSSEC-STRIP-ALL-UNSIGNED (low): unsigned answers/denials in a
  proven-signed owner zone now fail closed (Bogus) instead of served
  Insecure. The `any_signed` fast path is gone — every unsigned link
  consults DS. Offline behavior preserved (failed fetch counts as
  not-signed → Insecure). Cost accepted: DS round-trips per unsigned
  answer. Locked by `test_stripped_signed_zone_answer_is_bogus_offline`
  and `test_stripped_denial_in_signed_zone_is_bogus_offline`
  (cache-seeded DS, hermetic); unsigned-island tests moved to
  RFC 2606 `.invalid` fixtures after real-zone drift (example.com
  gained edge-signing/DS).

### Merged upstream
- `master` v2.2.0 (`9cd55ae..a2f32d4`, 12 commits: FP-01..FP-19 audit
  closure, L1 rootless daemon, DNSSEC island handling, rustls bump,
  v2.2.0 release) merged into develop (`6a025a6`). Conflict
  resolutions favor the audited release semantics; develop features
  (shaping watchdog v2, DPI lab, NSS-gated paths, Panel dirty-badge,
  `config get --system`) carried over.
- `master` `10de595` (HANCORE privilege-guard fail-closed + GID
  cross-check) merged cleanly after.

### Security decisions (locked)
- RSASHA1/NSEC3RSASHA1 stay EXCLUDED from `secure_algorithms()`.
  Zones using them SERVFAIL (Bogus) rather than risk collision
  forgery. Rationale + offline Bogus test: see `src/dns/dnssec.rs`
  and README § DNSSEC. (Decision A, 2026-09-25.)
- Signed-CNAME → unsigned-terminal currently validates Secure
  (early return on the verified CNAME, cdb9ce6 design). Kept for
  release stability; filed as an open audit question in
  `docs/OPEN_QUESTIONS.md` (strict RFC 4035 reading would say Bogus
  when the terminal zone is signed).

### Tests added
- Live (ignored, need internet): `test_unsigned_delegation_is_insecure_live`
  (neverssl.com → Insecure), `test_signed_but_unchained_is_bogus_live`
  (chatgpt.com → Bogus, FP-19 lock; domain drifted 09-23→09-24 from
  unsigned to signed-unanchored — documented in-test).
- `tests/watchdog.rs` (offline, hermetic): displacement trip +
  events-flow quiet contrast around real loopback connections and
  real /proc snapshots.
- `test_reload_maps_without_handles_*` updated to the FP-17 honest-error
  contract. Retired (superseded by audit architecture): offline
  root-island test, signed-CNAME Insecure test, NSEC3 Secure-path
  tests, wildcard-Secure test.

### Known open items
- eBPF cgroup sock_ops ATTACH is environmentally refused on the
  Omarchy dev host (EPERM from user-session scope despite full caps;
  live daemon in system.slice proves the mechanism). `reload_maps`
  live-kernel sync unproven here — needs a CI root runner.
- Panel.qml has no automated runner; manual protocol in
  `docs/PANEL_TESTING.md`.

## v2.2.0 - 2026-09-23 (origin/master)

- Run-1..run-4 audit findings FP-01..FP-19 closed (privdrop/file IO,
  status verification, DNS label hygiene, autottl, canary, ECH,
  TXID unification, NV-02 nonblocking reads).
- L1 rootless daemon (`albus` user + 6 ambient caps, User/Group unit,
  scoped polkit resolve1 rules).
- DNSSEC: unsigned delegations → Insecure (never Bogus); mixed
  signed/unsigned answers served with deferred crypto-failure verdict.
- Deps: rustls 0.23.43 → 0.23.45 (RUSTSEC-2026-0285).
