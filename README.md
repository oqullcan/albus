# Albus

Albus is a local-first TOTP vault written in Rust.

It is built for people who want OTP secrets to stay off cloud services, out of
browser extensions, and inside a small local workflow with conservative
security claims.

## Privacy

- no sync
- no cloud account
- no browser integration
- no telemetry
- local TOTP generation only

Secrets stay on the machine. Vaults and backups are encrypted at rest.

## Security Model

Albus is designed to protect locked vault and backup files, keep the storage
format simple, and reduce routine local exposure with a strong passphrase.

It does not claim protection against malware, keylogging, or a host that is
already compromised while the vault is unlocked.

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
- optional Windows device binding

## Run

```powershell
cargo test --workspace
cargo run -p albus-tui --bin albus
```

Rust `1.94.0` is pinned in `rust-toolchain.toml`.

## Docs

- [Specification](docs/specs.md)
- [Security Policy](SECURITY.md)

Release notes can live in GitHub Releases.

## License

`AGPL-3.0-only`
