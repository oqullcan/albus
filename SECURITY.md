# Security Policy

## Scope

In scope: DPI-evasion correctness (shaping must not leak clean SNI),
DNS privacy (DoH transport, kill-switch, lockdown fail-closed behavior),
firewall rule hygiene (no touching rules albus did not apply), custom-DoH
SSRF screening (`src/dns/ssrf.rs` — loopback/private/link-local/metadata
targets are refused fail-closed).

Out of scope: browser-side ECH, upstream certificate/PQ-signature choices.
The Omarchy panel widget is UI-only — its only privilege boundary is the
polkit gate on service control, which is covered under the service itself.

Hardening is continuous: `cargo audit` (RustSec) + `cargo deny` run in CI
on every push and weekly; lockfile is always committed.

## Crash tradeoff (documented, deliberate)

On crash, systemd runs `ExecStopPost` cleanup (restores DNS/firewall) and
restarts the daemon within ~3 s. That window is fail-open by design: a
fail-closed crash policy would risk bricking outbound connectivity with no
self-recovery. Crash loops are journal-visible and re-apply protections on
every restart.

## Supported versions

| Track                | Status                  |
| -------------------- | ----------------------- |
| `develop`            | Receives security fixes |
| Latest release tag   | Receives security fixes |
| Older tags           | Unsupported — upgrade   |

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting**: repository page
→ Security tab → Advisories → **Report a vulnerability**. Reports stay
private until a fix ships. Do not open public issues for unpatched
vulnerabilities.

Test only systems you own or are authorized to test. albus is a DPI-evasion
tool: probing third-party networks with it is out of bounds for any report
and may be unlawful.

## Response commitment

- First human response within **7 days**.
- Severity assessment and fix plan within **14 days** of confirmation.

## Coordinated disclosure

We publish the fix first then disclose **30 days** after the patched
release (or sooner by mutual agreement). Reporters may request an
extension for complex rollouts.

## Crediting reporters

Fixed findings credit the reporter by handle in the release notes and the
fix commit message trailer, e.g. `Reported-by: <handle>`, unless the
reporter asks to stay anonymous. Past external findings are referenced
the same way (handle + finding class), never with exploit details.
