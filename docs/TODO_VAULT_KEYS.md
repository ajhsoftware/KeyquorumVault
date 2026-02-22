# TODO — Vault Key Hierarchy Upgrade (Remove Salt File + Optional Keyfile)

## Goals

- Remove reliance on external `*.slt` salt files for vault decryption going forward.
- Unify unlock flow under Identity Store (KQID1) using DMK → VK wrapping.
- Maintain full backward compatibility for existing users.
- Add an optional “Keyfile” feature (USB/offline) to harden against offline brute-force.

---

## A) Remove Salt File Usage (New Architecture)

### Target Unlock Flow (No salt file)
Password → Identity Store (Argon2id wrapper salt) → unwrap DMK → unwrap Vault Key (VK) → decrypt Vault

- Identity store already contains password wrapper salt.
- Vault encryption key becomes a random 32-byte VK, not derived from the password directly.
- VK is stored **wrapped by DMK**, inside the identity store (recommended: inside identity payload JSON).

### Work Items

- [ ] Define identity payload fields for wrapped VK:
  - Example: `vault_key_wrap: { nonce_b64, ct_b64, alg: "aesgcm", aad: "KQID-VK" }`
- [ ] Add unwrap/wrap functions:
  - `wrap_vault_key_dmk(dmk, vk) -> (nonce, ct)`
  - `unwrap_vault_key_dmk(dmk, nonce, ct) -> vk`
- [ ] Update vault open session logic:
  - On login: decrypt identity → get DMK → unwrap VK → decrypt vault envelope
- [ ] Stop creating `*.slt` for **new accounts**.
- [ ] Update CLI tool `cli_decrypt_store.py`:
  - Support end-to-end: password → identity → DMK → VK → vault
  - Keep legacy mode for password+salt vaults (migration support)

### Acceptance Criteria

- [ ] New accounts do not create `*.slt` files.
- [ ] Vault decrypt works using identity store + password only.
- [ ] Existing accounts continue to work unchanged until migrated.

---

## B) Migration Plan (Backward Compatible)

### On Next Login (Migration)
If legacy salt-based vault detected:

Password + legacy salt → decrypt vault → generate new random VK → re-encrypt vault with VK →
store wrapped VK in identity store → remove or archive legacy salt

### Work Items

- [ ] Detection logic:
  - Check presence of legacy `*.slt` OR identity meta field missing `vault_mode`
- [ ] Migration steps (safe order):
  - [ ] Decrypt using legacy method
  - [ ] Generate new VK (32 bytes random)
  - [ ] Re-encrypt vault with VK
  - [ ] Store wrapped VK under DMK in identity store
  - [ ] Commit identity + vault atomically (write temp files then rename)
  - [ ] Delete/retire salt file only after success
- [ ] Store a marker in identity meta:
  - `meta.vault_mode = "vk_wrapped"`
  - `meta.vault_migrated_at = <iso datetime>`

### Acceptance Criteria

- [ ] Legacy users login successfully and vault remains intact.
- [ ] After migration, salt file is no longer required.
- [ ] Integrity checks still pass and no data loss occurs.

---

## C) Optional “Keyfile” Feature (USB / Offline File)

### Why
A keyfile adds a second factor that makes offline brute-force much harder:
Attacker needs vault files **and** the keyfile (stored on USB/offline).

This is not “security by obscurity”; it changes the brute-force requirements.

### Proposed Unlock Modes

#### Mode 1: Password-only (default)
Password → Identity → DMK → VK → Vault

#### Mode 2: Password + Keyfile (recommended optional)
Password + Keyfile → derive KEK2 → unwrap DMK (or unwrap VK) → Vault

- Keyfile can be stored on USB drive.
- If keyfile is missing, the vault cannot be unlocked.

#### Mode 3: Password + Keyfile + YubiKey (strongest optional)
Password + Keyfile + YubiKey → unwrap DMK/VK → Vault

- YubiKey can provide an additional unwrap step (HMAC/Challenge-Response wrapping).

### Work Items

- [ ] Define keyfile format:
  - Option A (simple): 32 random bytes stored as a file (binary)
  - Option B (portable): JSON with base64 bytes + metadata (version, created_at)
- [ ] Add UI:
  - [ ] “Enable Keyfile” toggle in Security Center / Settings
  - [ ] “Generate Keyfile” button (save to removable drive)
  - [ ] “Use existing Keyfile” (select file)
  - [ ] “Disable Keyfile” (requires password + current keyfile)
- [ ] Decide where keyfile is applied:
  - Option 1: Keyfile used to unwrap DMK (more central)
  - Option 2: Keyfile used to unwrap VK (simpler integration)
- [ ] Add identity store wrapper type for keyfile:
  - `wrappers: [{ type: "keyfile", salt, nonce, ct, ... }]`
- [ ] Add safe recovery options:
  - [ ] If user loses keyfile: require recovery key / backup codes / “max security no recovery” policy
- [ ] Update CLI tool:
  - Allow `--keyfile <path>` for unlocking in keyfile mode

### Acceptance Criteria

- [ ] Enabling keyfile requires creating/selecting a keyfile.
- [ ] Vault cannot be unlocked without keyfile when enabled.
- [ ] Clear warnings about permanent lockout if keyfile is lost (unless recovery mode exists).

---

## D) Documentation Updates

- [ ] Update `tools/release/README.md` and/or main docs with new key hierarchy.
- [ ] Update “Portable Users” notes if file layout changes.
- [ ] Add Security Center status:
  - “Vault Key Mode: Legacy (salt)” / “VK wrapped (identity)” / “Keyfile enabled”
- [ ] Add migration note in release notes.

---

## E) Safety / Implementation Notes

- Use unique AEAD Additional Data (AAD) strings for each layer:
  - Example:
    - `KQID-DMK` (password wrapper)
    - `KQID-PAYLOAD` (identity payload)
    - `KQID-VK` (vault key wrap)
    - `KQID-KF` (keyfile wrapper, if used)
- Prefer atomic writes:
  - write temp files → fsync → rename
- Never store plaintext VK/DMK on disk.
- Consider optional “summary only” output for CLI by default to avoid accidental leaks.

---

## F) Advanced Unlock Chain (Optional Security Modes)
🔐 Unlock Mode Matrix
        Mode	|       Requirements	            |            Description
    Standard	|   Password	                    |  Password unwraps DMK → unwrap VK → decrypt vault
    Hardened    |  	Password + Keyfile	            |  Keyfile required to unwrap DMK or VK
    Maximum	    |   Password + Keyfile + YubiKey    |  Hardware challenge-response required before vault access

🔒 Proposed Hardened Flow

Mode 2: Password + Keyfile

- Password → Argon2 (wrapper salt) → KEK
- Keyfile (32 random bytes) → HKDF combine with KEK → KEK2
- KEK2 → unwrap DMK (or unwrap VK) → decrypt vault

- This prevents offline brute-force unless attacker also has the keyfile.

Mode 3: Password + Keyfile + YubiKey

- Password → Argon2 → KEK
- Keyfile → mix into KEK → KEK2
- YubiKey challenge-response → final KEK3
- KEK3 → unwrap DMK/VK → decrypt vault

This requires:

    - Password
    - Keyfile
    - Physical YubiKey
    - Security Considerations

Keyfile must never be stored alongside the vault.
Recommend storing keyfile on USB.
Losing keyfile = permanent lockout unless recovery mode exists.
Provide clear warnings in UI before enabling.
