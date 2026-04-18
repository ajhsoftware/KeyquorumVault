# Security policy

## Reporting a vulnerability
Please report security issues privately.
- Prefer: open a GitHub Security Advisory (if enabled) or email the maintainer.
- Include: affected version, steps to reproduce, impact, and any proof-of-concept.

## Supported versions
- 'main' is under active development.
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

## Threat Model & User Responsibilities

Keyquorum Vault is designed as **local, user-side software**.

### System Security Assumption
If your system is compromised (malware, trojans, etc.), you should assume your data may already be exposed. Attackers may use techniques such as keylogging or file exfiltration to obtain sensitive information.
No local application can fully protect against an attacker with system-level access.

---

### Offline Attacks
If an attacker obtains your vault files, they may attempt **offline brute-force attacks**.
While Keyquorum Vault is designed to make this difficult (via strong encryption and KDFs), given enough time and computing power—especially with modern GPUs—this is always a possibility.

---

### Additional Protections
To reduce risk:
- Use strong, unique passwords
- Keep your system clean and trusted
- Secure any cloud storage with 2FA if used
- Consider using hardware protection such as a YubiKey
Keyquorum includes optional **YubiKey WRAP protection**, which adds an additional layer of protection to the vault file and increases the cost of offline attacks.

---

### Backups
Users are strongly encouraged to:
- Create regular backups
- Store backups offline (e.g. USB drive)
This helps protect against ransomware, hardware failure, and data corruption.

---

### Disclaimer
This project is:
- Not security audited
- Under active development
- Provided **as-is, at your own risk**

Users are responsible for reviewing the code and determining whether it meets their security requirements.
