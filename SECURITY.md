# Security

Albus is pre-1.0, not audited, and not hardened against a compromised host.

The current technical boundary is summarized in [docs/specs.md](docs/specs.md).

Report suspected vulnerabilities privately:

- `ogber@proton.me`

In scope:

- crypto and key handling
- vault or backup parsing
- unintended secret exposure

Out of scope:

- a compromised host while unlocked
- keylogging or screen capture
- third-party issuer weaknesses
