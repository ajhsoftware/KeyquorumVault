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

Encryption (can you decrypt the vault)

Both must succeed for full vault access.

Authentication validates identity.

Encryption unlocks vault contents.
---

# 2. Identity Components Per User

Each user account may contain:

   - Username
   - Password hash
   - Salt (stored in identity header)
   - KDF profile (Argon2 parameters)
   - Vault encryption key (derived or generated)
   - Optional wrapped vault key
   - Optional recovery key (one-time shown)
   - Optional YubiKey configuration
   - Optional TOTP secret
   - Backup codes (stored as hashes)
   - Lockout metadata
   - Backup metadata

User metadata is stored separately from the encrypted vault file.

---

# 3. Key Derivation (Argon2id)

Keyquorum uses Argon2id to derive a 32-byte key from:

Password + Salt

## KDF Versioning

Each user stores a KDF profile:

	"kdf": {
	  "algo": "argon2id",
	  "kdf_v": 2,
	  "time_cost": 4,
	  "memory_kib": 512000,
	  "parallelism": 4,
	  "hash_len": 32
	}

This allows future upgrades without breaking older vaults.

## KDF v1 (Legacy Profile)

   - Fixed Argon2id parameters compiled into the native core.
   - No per-user parameters stored.
   - Used by accounts created before KDF versioning.

### Login uses:
	kq_session_open(password, salt)

## KDF v2 (Current Profile – Stronger)

Default for new accounts:
	
	Parameter	|	Value
	time_cost	|	4
	memory_kib	|	512000 (~512MB)
	parallelism	|	2–4
	hash_len	|	32

### Login uses:
	kq_session_open_ex(password, salt, t, m, p)

This significantly increases resistance against offline password cracking.


# 4. Strict Native Core Enforcement

All cryptographic operations are performed by the native core (DLL).

There is no Python fallback.

If the native core is unavailable:
   - Vault operations fail
   - Account creation fails
   - No cryptographic downgrade occurs

This ensures consistent cryptographic enforcement across builds.


# 5. Password-Based Vault Access

When logging in:

1. User enters password.
2. Native core derives key using Argon2id (v1 or v2 profile).
3. AES-256-GCM decrypts vault file.
4. Authentication tag must verify.
5. If tag verification fails → access denied.

Password strength is critical.
Plaintext passwords are never stored.

---

# 6. Account Security Modes

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
- Allows password rotation.
- Enables recovery workflows.

This mode supports password rotation and safer recovery mechanisms.

---

# 7. Recovery Key (One-Time Shown)

When recovery mode is enabled:

- A recovery key string may be generated.
- It is shown once to the user.
- It can be used to re-wrap the vault key if password is lost.

The recovery key must be stored securely offline.

If lost:
- Recovery is not possible.

---

# 8. DPAPI (Remember This Device)

Keyquorum supports device-bound unlock using Windows DPAPI.

Current implementation:
   - Native session key is exported using:
	  - kq_session_export_key_dpapi
   - Session can be restored using:
      - kq_dpapi_unprotect_to_session

DPAPI tokens are versioned internally (v4 session-based).

## Important:

After a KDF upgrade (v1 → v2), the remembered-device token must be regenerated because the derived key changes.
DPAPI unlock restores a native session but does not bypass encryption verification.

---

# 9. Backup Codes

Backup codes:

- Are randomly generated.
- Are stored only as hashed values.
- Are single-use.
- Can bypass TOTP second factor.

Backup codes do NOT decrypt the vault.
They only bypass second-factor login checks.

---

# 10. Forgot Password Flow

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

# 11. TOTP (Authenticator)

If enabled:
   - TOTP secret stored in metadata.
   - Valid code required at login.
   - Backup codes provide emergency bypass.

TOTP protects authentication, not encryption.

---

# 12. YubiKey Integration
	
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

Loss of YubiKey may make the vault unrecoverable unless recovery mode is configured.

---

# 13. Hardware Dependency Notice (Important for Contributors)

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

# 14. Lockout Protection

The system may:

- Track failed login attempts.
- Temporarily lock account after repeated failures.
- Automatically reset lockout after cooldown.

This mitigates brute-force attempts.

---

# 15. Security Boundaries

Security depends on:

- Password strength
- Argon2id parameters
- AES-GCM correctness
- Native core integrity
- Protection of salt and metadata
- Secure recovery key storage
- Hardware device protection
- Memory safety

No central recovery authority exists.

---

# 16. Data Loss Scenarios

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

# 17. Future Enhancements

Possible future improvements:
- Additional KDF profiles
- Extended hardware support
- Unified wrapper format
- Enhanced memory zeroisation
- Multi-platform parity improvements

All future changes will aim to preserve backward compatibility where possible.

---

# 18. Migration & Compatibility

Keyquorum maintains backward compatibility:
   - KDF v1 vaults remain accessible.
   - Users may upgrade to KDF v2 via Security Center.
   - Future KDF versions may be introduced without breaking older vaults.
Vault encryption format remains AES-256-GCM.

---
