# Open questions for independent audit

These are deliberate, documented judgment calls the maintainers want a
future independent review (HANCORE or other) to pressure-test. Per
`SECURITY.md` (7/14/30-day process), anyone reporting a concrete
exploit against the current behavior gets the full coordinated-
disclosure treatment — this file tracks *design uncertainty*, not
known vulnerabilities.

## OQ-1: signed-CNAME → unsigned-terminal validates Secure

Status (2026-09-25): KEPT, questioned.

Current behavior (`src/dns/dnssec.rs`, cdb9ce6 design): when a CNAME
link chain-verifies Secure, `validate()` returns Secure immediately —
the unsigned terminal RRset is never evaluated. So a signed CNAME
pointing at an unsigned terminal validates Secure.

Strict RFC 4035 reading (§4/§5: every link of the chain must
validate): if the terminal's owner zone is itself SIGNED (DS exists),
the unsigned terminal smells like a stripped signature, and the
answer arguably should be Bogus. If the terminal zone is unsigned,
Insecure is the honest verdict. Either way, "Secure" overstates what
was proven about the terminal data.

Why kept: (1) release stability — v2.2.0 shipped this flow and the
live CDN regression test (`test_unsigned_cname_to_signed_target_is_
secure_live`, video.twimg.com) pins served-ness; changing the verdict
risks SERVFAIL-roulette on round-robin CDN shapes the deferred-Bogus
design was built to avoid. (2) The scenario is artificial in practice:
the retired offline test used a single root-anchored fixture where
*everything* (including the "unsigned" terminal) lived under the
signed root.

What would settle it: a real-world signed-zone/unsigned-terminal
pair observed live, traced through both verdict options, measuring
false-SERVFAIL rate vs forgery coverage. Until then: behavior locked
by the live CDN test (asserts never-Bogus), question stays open.

### Measurement 2026-09-27 (6-domain live corpus, Quad9 DO-bit)

Searched for a live specimen of the exact OQ-1 shape
(signed CNAME + unsigned terminal, both verifiable):

- `ietf.org` → Secure (fully signed control).
- `example.com` → Secure. DRIFT COMPLETE: 09-24 edge-signed without
  DS → 09-27 full chain verifies. Zones move under our feet; no live
  domain is a permanent fixture.
- `neverssl.com` → Insecure (unsigned; island lock holds).
- `video.twimg.com` → Insecure (today fully unsigned: CNAME + A,
  zero RRSIGs anywhere — plain-unsigned path, not the OQ-1 shape).
- `chatgpt.com` → Bogus (FP-19 lock holds).
- `dnssec-failed.org` → Indeterminate, empty answers. The canonical
  negative control never reaches us as bad signatures: Quad9 SERVFAILs
  upstream, so our pipeline sees infrastructure failure, not crypto
  failure. True-Bogus coverage rests on the local byte-flip test
  (`test_tampered_signed_response_is_bogus_live`), not on this domain.

RESULT: no live specimen of signed-CNAME→unsigned-terminal found in
this corpus — the early-Secure path with an unsigned terminal remains
UNOBSERVED live. The question stays open for lack of a specimen, not
for lack of looking.

## OQ-2: NSEC3 denial ceiling (context, already decided)

NSEC3 denials cap at Indeterminate (no hash verification without new
crypto deps) — FP-18. This is a deliberate completeness ceiling, not
a bug: adding SHA-1-hash verification for NSEC3 would reintroduce
hash-bridging complexity for records that only gate denial, never
positive answers. Revisit only if a deployment needs Secure NSEC3
denials (e.g. aggressive-NSEC caching). Offline coverage: forged
NSEC3 groups still fail closed (Bogus) via
`test_nxdomain_denial_forged_group_is_bogus_offline`.

### Measurement 2026-09-27 (NXDOMAIN denials, Quad9 DO-bit)

`missing-xyz-123.ietf.org` and `missing-xyz-123.example.com` both
returned NSEC (not NSEC3) denials with covering spans → Secure via
the FP-18 gate. The NSEC coverage path is live-proven; the NSEC3
Indeterminate cap did not trigger in this sample, so its live
frequency is still unmeasured. No action — recorded for the record.
