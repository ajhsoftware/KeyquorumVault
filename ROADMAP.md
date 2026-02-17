# Roadmap (high level)

This repository is being reorganised so it’s easier for users to read and for contributors to help.

## In progress
- Split large modules into smaller, well-named packages.
- Reduce duplication between "legacy" and "new" feature folders.
- Improve resource/path handling for dev vs frozen builds.

## Planned (near-term)
- Add a pinned `requirements.txt` (and/or proper packaging metadata).
- Add CI for linting (ruff) and basic import checks.
- Document build steps for fbs Pro / Windows packaging.

## Planned (mid-term)
- Stabilise and document the vault file format and crypto parameters (so multiple clients can interoperate).
- Expand automated tests for vault read/write, import/export, and migration safety.
- Improve security hardening (clipboard clear, lockout integrity, audit log protections, etc.).

## Long-term direction (future)
The long-term goal is to move security-critical parts of Keyquorum into a native core (C++/Qt or a native library),
primarily to improve memory handling (e.g., reducing accidental copies and supporting explicit zeroisation).

This does **not** mean an immediate full rewrite. The intent is to:
- Define a stable “VaultCore” API and file format contract.
- Implement VaultCore as a native library (C++ first target).
- Reuse that core for an Android client (likely Kotlin UI + native core integration).
- Keep the current Python desktop app maintained while the core is developed.

## Non-goals
- No cloud account requirement.
- No server-side vault storage by default.
