# Authentication & Identity Model

Status: Living document  
Scope: High-level authentication, identity, and key management design

This document describes how users authenticate, how encryption keys are derived,
and how advanced protection features (YubiKey, recovery keys, 2FA, etc.) interact.

Keyquorum is offline-first.
There is no cloud account and no remote authentication server.

All security decisions happen locally.

---

# 1. Core Principle

Authentication (who you are)
≠
Encryption (can you decrypt the vault)

Both must succeed for full vault access.

Authentication validates identity.
Encryption unlocks vault contents.

---

# 2. Identity Components Per User

Each user account may contain:

- Username
- Password
- Salt (for Argon2id)
- Vault encryption key (derived or generated)
- Optional wrapped vault key
- Optional recovery key (one-time shown)
- Optional YubiKey configuration
- Optional TOTP secret
- Backup codes (stored as hashes)
- Lockout metadata

User metadata is stored separately from the encrypted vault file.

---

# 3. Password-Based Vault Access

When logging in:

1. User enters password.
2. Argon2id derives a 32-byte key using password + salt.
3. That key is used to decrypt the vault file using AES-256-GCM.
4. Authentication tag must verify.
5. If tag verification fails → access denied.

Password strength is critical.
Plaintext passwords are never stored.

---

# 4. Account Security Modes

Keyquorum supports multiple protection configurations.

---

## A. Direct-Derived Mode (Maximum Security)

- Vault encryption key is derived directly from password.
- No wrapped vault key stored.
- No recovery mechanism.
- If password is lost → vault is unrecoverable.

This minimizes stored key material.

---

## B. Recovery Mode (Wrapped Vault Key)

- A random vault key is generated.
- That vault key is wrapped (encrypted) using a password-derived key.
- Allows password changes without re-encrypting the entire vault.
- Enables recovery workflows.

This mode supports password rotation and safer recovery mechanisms.

---

# 5. Recovery Key (One-Time Shown)

When recovery mode is enabled:

- A recovery key string may be generated.
- It is shown once to the user.
- It can be used to re-wrap the vault key if password is lost.

The recovery key must be stored securely offline.

If lost:
- Recovery is not possible.

---

# 6. Backup Codes

Backup codes:

- Are randomly generated.
- Are stored only as hashed values.
- Are single-use.
- Can bypass TOTP second factor.

Backup codes do NOT decrypt the vault.
They only bypass second-factor login checks.

---

# 7. Forgot Password Flow

Forgot password works only if:

- Recovery mode is enabled
- A valid recovery key is provided
- Or a valid recovery mechanism is available

Typical flow:

1. User verifies identity (backup code or recovery key).
2. New password is set.
3. Vault key is re-wrapped using the new password-derived key.

In maximum-security mode:
- Forgot password is not available.
- Password loss means permanent vault loss.

---

# 8. YubiKey Integration

Keyquorum supports hardware-backed protection using YubiKey.

There are two distinct conceptual modes.

---

## A. Gate Mode (Authentication Gate)

YubiKey acts as an additional authentication factor.

- Password must be correct.
- YubiKey challenge-response must succeed.
- Vault encryption still depends on password-derived key.

If YubiKey is unavailable:
- Login may be blocked depending on configuration.

Gate mode strengthens authentication but does not replace password-based encryption.

---

## B. Wrap Mode (Hardware-Bound Encryption)

In Wrap Mode:

- The vault key is encrypted (wrapped) using key material derived from YubiKey.
- YubiKey challenge-response is required to unwrap the vault key.
- Password alone is insufficient to decrypt the vault.
- Hardware presence is required for decryption.

Without the correct YubiKey:
- Vault cannot be decrypted.
- Even a correct password will fail to unlock.

This creates a hardware dependency.

Loss of YubiKey may make the vault unrecoverable unless recovery mode is separately configured.

---

# 9. Hardware Dependency Notice (Important for Contributors)

If YubiKey Wrap Mode is enabled:

- The vault encryption key depends on YubiKey-derived material.
- Any compatible client (Android, macOS, C++ native core, CLI, etc.)
  must implement YubiKey challenge-response support to unlock the vault.
- Platforms that do not support YubiKey integration cannot open such vaults.
- Recovery mode must be used if hardware support is unavailable.

Contributors implementing new platform clients must detect:

- Whether Wrap Mode is enabled.
- Whether hardware integration is required before attempting vault decryption.

Failure to implement this correctly will result in vault unlock failures.

---

# 10. TOTP (Authenticator)

If enabled:

- A TOTP secret is stored in user metadata.
- User must provide valid time-based code at login.
- Backup codes provide emergency bypass.

TOTP protects login,
but encryption still depends on password and/or wrapped key configuration.

---

# 11. Lockout Protection

The system may:

- Track failed login attempts.
- Temporarily lock account after repeated failures.
- Automatically reset lockout after cooldown.

This mitigates brute-force attempts.

---

# 12. Security Boundaries

Security depends on:

- Password strength
- Argon2id parameters
- AES-GCM correctness
- Protection of salt and metadata files
- Secure storage of recovery key
- Protection of YubiKey hardware
- System memory safety

There is no central recovery authority.

---

# 13. Data Loss Scenarios

If the following are lost:

Password (maximum-security mode):
→ Vault permanently lost.

Password + Recovery Key (recovery mode):
→ Vault permanently lost.

YubiKey (wrap mode without recovery configured):
→ Vault permanently lost.

Vault file corruption:
→ Decryption fails.

---

# 14. Future Enhancements

Possible future improvements:

- Versioned identity format
- Unified wrapper format
- Hardware-backed key storage improvements
- Native VaultCore key management
- Stronger memory zeroisation

All future changes will aim to preserve backward compatibility where possible.
