# Albus Roadmap

## Product Thesis

Albus should aim to become the best local-first desktop authenticator for
people who do not want OTP secrets in cloud-backed services, browser
extensions, or opaque vendor silos.

That means competing on trust, clarity, and reliability more than on
consumer-sync convenience.

## Positioning

Albus should be optimized for:

- local encrypted storage
- conservative security boundaries
- transparent file formats
- reliable backup and restore
- migration away from mainstream authenticator apps

Albus should not try to become:

- a password manager
- a cloud sync platform
- a browser autofill product
- a catch-all consumer identity suite

## Product Pillars

### 1. Trust

Users should be able to understand what Albus protects, what it does not
protect, and how to verify releases independently.

Priority work:

- reproducible release builds
- signed release artifacts
- SBOM generation
- public threat-model documentation
- third-party security audit before `1.0`

### 2. Desktop UX

The core security model is already strong for a pre-1.0 project. The next
large gap is usability.

Priority work:

- native desktop GUI
- faster navigation and search
- favorites, tags, notes, and custom icons
- better import and recovery flows
- clipboard auto-clear and timed secret reveal

### 3. Interoperability

The easiest way to win users is to make leaving other apps painless.

Priority work:

- import from major authenticator formats
- export in documented, stable formats
- vault inspection and repair tools
- compatibility test corpus for real-world otpauth URIs

### 4. Operational Maturity

Albus should feel boring and dependable to install, update, and recover.

Priority work:

- signed installers for Windows and macOS
- Homebrew, Scoop, winget, AUR, and AppImage distribution
- deterministic release checklist
- backup validation command
- corruption and rollback diagnostics

## Near Term: `v0.2`

Goal: become easier to adopt without expanding scope.

Deliverables:

- stable import/export compatibility layer
- tags, favorites, notes, and richer entry metadata
- better search and list organization
- release signing
- packaged desktop binaries for the major platforms
- public roadmap and release policy

Exit criteria:

- a new user can migrate from at least three popular authenticator ecosystems
- release artifacts are signed and documented
- backups can be validated before restore

## Mid Term: `v0.3`

Goal: become the best polished local-first desktop authenticator.

Deliverables:

- native GUI with the TUI retained as a power-user interface
- multiple vault profiles
- richer keyboard shortcuts and batch actions
- better emergency export and recovery workflows
- platform-specific hardening polish for clipboard and screen exposure

Exit criteria:

- desktop GUI reaches feature parity with the TUI for core flows
- onboarding and recovery no longer require reading source or specs
- migration friction is substantially reduced

## Pre-1.0: `v0.5`

Goal: become audit-ready.

Deliverables:

- reproducible builds
- SBOM and dependency policy
- formal test matrix for platform hardening
- fuzzing expansion for container and URI parsing
- external audit preparation and remediation

Exit criteria:

- release process is deterministic and documented
- audit scope is stable
- security claims in the README and spec are fully aligned with implementation

## `v1.0`

Goal: become the most trusted local-first authenticator in the category.

Deliverables:

- external security audit completed
- polished GUI and packaging on all target platforms
- strong migration story
- durable backup and recovery story
- long-term support and compatibility commitments

Exit criteria:

- independent audit with remediated critical findings
- stable file format compatibility guarantees
- clear support and release expectations

## Highest-Leverage Epics

If development time is limited, these are the highest ROI investments:

1. Native GUI
2. Import and migration suite
3. Signed installers and reproducible releases
4. Tags, notes, icons, and favorites
5. External audit readiness

## Metrics That Matter

Albus should measure progress with a few simple signals:

- time to first successful migration
- backup restore success rate
- number of supported import formats
- release reproducibility and signing coverage
- bug reports involving data loss, corruption, or recovery failure

## Non-Goals

These should stay out unless the product strategy changes explicitly:

- cloud sync accounts
- browser extension autofill
- password management
- collaborative vault sharing

## Working Principle

Albus should only add features that make the local-first promise stronger,
clearer, or easier to adopt.
