# Contributing

Thanks for your interest in contributing to Keyquorum Vault.

This is a security-focused, offline-first password manager project.  
Clarity, reviewability, and user trust are more important than speed.

---

## General Guidelines

- Keep changes small and focused (one logical change per PR).
- Do not commit secrets, personal data, or real vault files.
- Avoid large rewrites unless discussed in an Issue first.
- Prefer clear, readable code over clever or complex solutions.
- No telemetry, tracking, analytics, or hidden “phone home” behaviour.

If you’re unsure whether something is appropriate, open an Issue and ask first.

---

## Security Expectations

Because this is a security-sensitive project:

- All pull requests require review before merging.
- No obfuscated code or intentionally hard-to-read logic.
- No packed binaries or “download and execute” scripts.
- No new network access unless clearly documented and user-visible.
- Crypto, key handling, or vault format changes must be discussed in an Issue before implementation.

Security changes should include a short explanation of:
- What is changing
- Why it improves security
- Any compatibility impact

---

## Current Priorities

Contributions are welcome anywhere, but these areas are especially helpful right now:

### Python / Qt Desktop App
- Refactoring to reduce duplication and improve structure.
- Improving test coverage for vault operations and import/export.
- Packaging and build workflow improvements.
- Documentation improvements.

### Future Direction: Native Core + Android

Long-term, security-critical vault logic may move into a native core (C++ target)  
to allow tighter memory handling and explicit zeroisation patterns.

Helpful contributions in this direction include:

- Improving or starting documentation of the vault file format.
- Defining a clean "VaultCore" API boundary.
- Prototyping a minimal native VaultCore (encrypt/decrypt + load/save).
- Android groundwork (Kotlin UI prepared to call a shared core library).

This is a gradual architectural direction, not an immediate rewrite.

---

## Code Style

- Prefer descriptive naming.
- Keep logging useful but minimal.
- Avoid unnecessary abstraction.
- Write code that is easy for others to review.

---

## Running the Project Locally

See `README.md` for setup instructions.

---

## Branding & Fork Policy

“Keyquorum Vault” and “AJH Software” are names used by the original author.

While the code is licensed under GPL-3.0 and may be forked and redistributed under that license,
the official project name, branding, and logos are not covered by the GPL license.

Forks and redistributions must not use the official branding without prior permission.
Modified versions should clearly distinguish themselves from the original project.
