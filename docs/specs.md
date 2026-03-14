# Albus Spec

## Scope

Albus is a local TOTP vault. It stores OTP secrets in an encrypted vault,
supports encrypted backups, and generates codes locally.

It does not do sync, browser integration, password management, or account
recovery.

## Threat Model

Protected assets:

- OTP secrets
- vault and backup files
- passphrase-derived keys
- local rollback anchor state
- optional per-user device-binding secrets

Assumptions:

- the host is not compromised while the vault is unlocked
- the passphrase is not trivial
- system time is close enough for TOTP

Out of scope:

- malware resistance on an unlocked host
- keylogging and screen capture resistance
- secure deletion guarantees
- cloud or multi-device conflict handling

## Platform Security Parity

The encrypted container format is platform-neutral.

Local hardening is applied per platform where possible:

- Windows: private ACL tightening, WER crash-report reduction, optional DPAPI device binding
- macOS: private permissions, core-dump reduction, optional Keychain device binding
- Linux: private permissions, core-dump reduction, non-dumpable process flag, optional Secret Service device binding

All three platforms aim to protect locked data at rest. None of them claim to
protect an already compromised unlocked session.

## Crypto

- TOTP: RFC 4226 / RFC 6238
- Hashes: `SHA1`, `SHA256`, `SHA512`
- KDF: `Argon2id`
- Key schedule for new files: `Argon2id -> HKDF-SHA256`
- Encryption: `XChaCha20Poly1305`
- New vault and backup passphrases must have at least `16` non-whitespace characters

New files written by the interactive app may raise Argon2 memory cost upward on
faster hosts. Read compatibility still accepts a broader shared ceiling so
vaults remain portable across supported machines.

Vaults may optionally use OS-native local device binding:

- Windows: DPAPI
- macOS: Keychain
- Linux: Secret Service

Device binding is scoped to the current local user profile. It adds a local
secret requirement alongside the passphrase in key derivation, so moving a
bound vault to another machine or user profile is expected to fail unless
restored through a backup workflow.

## Format

The vault and backup containers share the same outer structure:

1. `magic`
2. `header_len_le`
3. `header_json`
4. `ciphertext`

The authenticated data is the exact persisted preamble and header bytes.

Headers carry format metadata, KDF settings, cipher metadata, and vault
revision information. Plaintext vault data is JSON and contains the vault id,
revision, and entries. Plaintext backup data is a full vault snapshot plus
export metadata.
