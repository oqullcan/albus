# Albus

Albus is a local-first TOTP vault written in Rust.

It is for people who want OTP secrets to stay in an encrypted local file, off
cloud platforms, and outside browser extensions.

## Principles

- offline by default
- no sync
- no cloud account
- no telemetry
- no browser integration
- conservative security claims

## Privacy

Secrets stay on the machine. Vaults and backups are encrypted at rest, codes
are generated locally, and the project keeps its scope intentionally narrow.

## Security

Albus is built to protect:

- locked vault files
- locked backup files
- passphrase-derived file keys
- routine local state with private filesystem permissions
- optional per-user OS-native device binding

Current host binding options:

- Windows: DPAPI
- macOS: Keychain
- Linux: Secret Service

The app also applies best-effort local hardening such as private file
permissions, anti-symlink path checks, rollback trust anchors, and process
dump/crash-report reduction where the platform allows it.

## Limits

Albus does not claim protection against:

- malware on an unlocked host
- keylogging or screen capture
- a machine that is already compromised
- account recovery mistakes
- secure deletion guarantees

## Status

- pre-1.0
- no external audit yet
- conservative scope and claims

## Features

- encrypted local vault
- encrypted backup and restore
- manual entry and `otpauth://` import
- local code generation
- passphrase rotation
- idle auto-lock
- rollback detection
- optional OS-native device binding

## Run

```powershell
cargo test --workspace
cargo run -p albus-tui --bin albus
```

Rust `1.94.0` is pinned in `rust-toolchain.toml`.

## Docs

- [specification](docs/specs.md)
- [security policy](SECURITY.md)

Release notes can live in GitHub Releases.

## License

`AGPL-3.0-only`
