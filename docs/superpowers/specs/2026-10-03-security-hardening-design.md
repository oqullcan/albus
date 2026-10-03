# Security hardening design — 2026-10-03

## Why this exists

HANCORE (marketplace security reviewer) has reported four DNSSEC findings against
`master`, all confirmed correct:

1. `185a66e` — DS-less answer with an unauthenticated SOA/NSEC/NSEC3 was accepted
   as proof of an unsigned delegation.
2. `d481cb8` — `authenticate_denial` proved the denial was signed by the parent,
   but the parent DNSKEY came off the wire and was never chained to the root.
3. `cbd5da5` — `owner_zone_signed` treated any resolver-supplied DS record as
   proof a zone was signed.
4. open — the NSEC3 branch of `authenticate_denial` accepts a parent-signed
   opt-out NSEC3 without checking it covers the requested delegation.

All four are the same class: **a resolver-supplied assertion is accepted without
cryptographic authentication, or authenticated without proving it belongs to the
zone it is claimed to describe.**

A parallel reconnaissance pass over `src/dns/`, `src/core/`, `src/app/` and the
QML surface found 22 further candidates. One of them is worse than all of the
above and is not yet known to the reviewer.

## The critical finding (Phase 1)

`verify_rrset` never checks that an RRSIG's **Signer Name** is the RRset owner or
an ancestor of it. It verifies that the signature is valid and that the signing
key chains to the root. It never verifies that the signing key belongs to a zone
that *contains* the record being verified.

RFC 4035 §5.3.1 requires Signer Name to be the owner or a superdomain of it.
`hickory-proto` is a raw crypto primitive: `TBS::new` filters records by owner
and `type_covered`, but never references `signer_name` as a name. Enforcing
§5.3.1 is the caller's job, and albus is that caller.

**Attack.** An attacker who owns any one DNSSEC-signed domain (`evilzone.com` —
registering a domain and enabling DNSSEC is free):

1. client asks for `bank.com A`
2. upstream answers `bank.com. A 6.6.6.6` (attacker address) plus an RRSIG
   whose Signer Name is `evilzone.com.`, signed with the attacker's own
   legitimate private key
3. upstream also serves the genuine `evilzone.com` DNSKEY RRset
4. signature valid, key genuine, chain to root genuine, and nothing anywhere
   asserts that `evilzone.com` contains `bank.com`
5. verdict `Secure` → `normalize_ad_bit` sets **AD=1** → response cached for
   600 s → forwarded

The client receives an attacker-chosen address authenticated. RFC 6840
`trust-ad` validating stubs do not re-validate AD=1.

Three sibling call sites in the same file get this right
(`name_eq(&signer, parent)` at `ds_proves_signed_zone` and both branches of
`authenticate_denial`). The main answer path is the only one of four that omits
the identity assertion — the same inconsistency pattern as findings 2 and 3.

## Phase 2 — the rest of the DNSSEC class

| ID | Finding | Decision |
|---|---|---|
| F2 | NSEC3 opt-out island accepts a denial with **no name relation at all** — `zone` is unused on that branch | Withdraw the claim. NSEC3-only denial → `Indeterminate` |
| F3 | `owner_zone_signed` does not chain the validating parent to the root — the second half of the `cbd5da5` fix | Recurse into `chain_to_root(parent)`, require `!= Fail` |
| F4 | `chain_to_root` never verifies the DNSKEY RRset's own `RRSIG(DNSKEY)` | Verify it |
| F5 | `Indeterminate` is pinned in the response cache for 600 s while the negative-verdict cache holds it 60 s | Do not cache `Indeterminate` |
| F6 | `NXDOMAIN` + `CoversNodata` yields `Secure`, setting AD=1 on an NXDOMAIN | Require `NoError` for `Secure` |
| F7 | `ech.rs` feeds a resolver-supplied ECHConfigList into the TLS handshake with no DNSSEC involvement | **Not fixed.** Document as an accepted, reasoned trade-off |

### F2: why withdraw rather than implement

`hickory-proto` 0.26 exposes NSEC3 RDATA but no hashing API — `hash_name`,
closest-encloser and next-closer are all absent (they live in
`hickory-resolver`). A real fix means implementing RFC 5155 §8.4/§8.7: SHA-1
over the canonical wire name, iterated by the record's iteration count, salted,
base32hex-encoded. Roughly 150 lines of new cryptography.

Withdrawing is not a workaround — it is the correct epistemic position. Claiming
`Insecure` is a claim that a delegation is unsigned. Without a coverage proof we
cannot support the claim, so the honest verdict is `Indeterminate`, which clears
AD and is never cached as secure. The answer path already caps NSEC3 denials at
`Indeterminate` for exactly this reason.

Observable effect: a real delegation like `chatgpt.com` under `com.` (NSEC3
opt-out) reports `Indeterminate` instead of `Insecure`. AD is 0 either way; the
difference is a log warning. The live test asserting `Insecure` is updated, not
quietly removed.

Implementing the hash later is documented follow-up work, not deferred silently.

### F7: why not fixed

The upstream supplying the ECH config is the same party supplying the DNS
answers, and albus already trusts it for DNSSEC-absent names. The marginal risk
is real but low, and ECH is a privacy feature the tool opts into. Same treatment
as `engine.rs`'s `block_quic` failure: warn and continue, documented.

## Phase 3 — privileged code

Live in the deployed binary, ordered by that fact.

| ID | Finding | Fix |
|---|---|---|
| P1 | `/run/albus/resolv.conf.orig` is service-writable and is trusted to author `/etc/resolv.conf` as root on `ExecStopPost` | Move outside the service-owned `RuntimeDirectory`; verify `uid` before trusting; `chown root:root` the restored file |
| P2 | `firewall.rs` identity-checks one path, then `resolve_binary` re-resolves the chain at exec time | Canonicalize once, exec that exact path |
| P3 | `iptables` helper's mode is unchecked; `resolvectl` has no identity check | Shared identity helper for both |
| P4 | Fail-opens: `cleanup_system_dns_at` swallows `resolve_write_target`'s violation; `readers_complete` stays true when `bpf_map_update` fails; `reject_symlink_chain` treats every `stat` error as clean; install writes through a symlink before the only symlink check; `converge_service_dir` chmods by path after opening by fd | Propagate / count / narrow / reorder / fd-based |
| P5 | `useradd`, `groupadd`, `getent` spawn without `env_clear()` | `env_clear()` + pinned PATH, matching the `systemctl` chokepoint |

### P1 in detail

The unit runs the daemon as `User=albus` with `NoNewPrivileges=true` so that
compromising the proxy is not root. `RuntimeDirectory=albus` is therefore owned by
`albus`, and the code path that creates the backup directory never `chown`s it.
`read_nofollow` enforces only `O_NOFOLLOW` and `is_file()`; `src/dns/` imports no
`MetadataExt` at all.

An attacker with code execution as `albus` writes `nameserver 6.6.6.6` to the
backup file. On the next stop, `ExecStopPost=+albus cleanup` runs as root and
root writes those bytes into `/etc/resolv.conf`. The attacker gets a
root-owned file with their content, in the one file this product exists to
protect, and it outlives the daemon.

The same lines never `chown` the atomic-write temp file, so the daemon's own
shutdown path leaves a service-account-owned `/etc/resolv.conf`.

The pattern that produced this bug is a missing **ownership** check, not a
missing `O_NOFOLLOW`. The codebase has an excellent, tested `O_NOFOLLOW`/`fstat`
discipline and no ownership-validation helper for trusted data files.

## Deliberately not done

- NSEC3 hashing (RFC 5155 §8.4/§8.7). Documented follow-up.
- Promoting `develop` to `master`. `master` receives security hotfixes only.
- `v2.2.0` tag, live binary reinstall. Untouched.

## Discipline

- Failing test before every fix. Proof obligation: revert the fix and confirm
  the new test fails.
- Every phase runs `cargo fmt --check`, `cargo clippy --all-targets -D warnings`,
  `cargo test --lib`, all live-network tests, and `cargo audit`.
- No Claude co-author trailers.
- F1 ships as its own commit and push. It is a complete authentication bypass in
  a security product; one verification cycle is cheaper than leaving it live.
  Everything else batches into one push, because every push moves the
  marketplace issue's target commit and invalidates prior verification.
