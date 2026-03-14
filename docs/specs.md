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

Assumptions:

- the host is not compromised while the vault is unlocked
- the passphrase is not trivial
- system time is close enough for TOTP

Out of scope:

- malware resistance on an unlocked host
- secure deletion guarantees
- cloud or multi-device conflict handling

## Crypto

- TOTP: RFC 4226 / RFC 6238
- Hashes: `SHA1`, `SHA256`, `SHA512`
- KDF: `Argon2id`
- Encryption: `XChaCha20Poly1305`
- New vault and backup passphrases must have at least `12` non-whitespace characters

Vaults may optionally use Windows DPAPI-backed local device binding.

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
