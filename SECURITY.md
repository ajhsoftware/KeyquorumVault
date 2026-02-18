# Security policy

## Reporting a vulnerability
Please report security issues privately.

- Prefer: open a GitHub Security Advisory (if enabled) or email the maintainer.
- Include: affected version, steps to reproduce, impact, and any proof-of-concept.

## Supported versions
- `main` is under active development.
- Releases are supported on a best-effort basis.

## What not to include
Do **not** include real vault data, passwords, private keys, or personal information in reports.

## Cryptography Notes
Keyquorum uses modern cryptographic primitives:

- Argon2id (via argon2-cffi) for password-based key derivation
- AES-GCM for authenticated encryption
- Ed25519 for signature verification
- HMAC-SHA256 for key separation and integrity binding
- SHA256 for file integrity and deterministic fingerprints

SHA256 is not used for password storage.

Some static analysis tools may flag generic hash usage; in this project,
SHA256 is used for integrity checks, fingerprints, and key derivation contexts
—not as a standalone password hashing mechanism.
