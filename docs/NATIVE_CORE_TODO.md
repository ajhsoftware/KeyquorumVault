# Keyquorum Vault – Native Core (C++ DLL) Migration Status

This document tracks the migration from Python-based crypto to the
Keyquorum native C++ crypto core (Argon2id + AES-256-GCM).

Goal:
- The vault master key must never live in Python memory long-term.
- All vault encryption/decryption must occur inside the native DLL.
- Decrypt failure must never appear as an "empty vault".
- Backward compatibility must be preserved.

---
## Native C++ core (DLL)

	Keyquorum Vault includes a native C++ helper module used for cryptographic primitives (Argon2id + AES-GCM).
	Source: `src/cpp/keyquorum_core/`
---

## ✅ A) Vault Master Key – Fully DLL-Driven

### 1. Password Login
- [x] `open_session(pw_buf, salt)` used
- [x] `pw_buf` wiped in `finally`
- [x] `self.userKey` NOT set if session exists
- [x] No password-derived key stored long-term in Python

### 2. DPAPI (Remember Device)
- [x] `open_session_from_key(vault_kek)` used
- [x] `vault_kek` temp buffer wiped
- [x] `self.userKey` not set (unless fallback)
- [x] Backward compatible fallback exists

### 3. YubiKey WRAP
- [x] DO NOT open session from `_pw_kek`
- [x] After unwrap → `open_session_from_key(master_key)`
- [x] Wipe temp `master_key`
- [x] `self.userKey` not stored unless fallback
- [x] Login aborts if decrypt fails

---

## ✅ B) Vault Decryption Safety

### 4. Decrypt Failure Must Never Equal Empty Vault
- [x] `load_encrypted()` raises on:
  - AES-GCM tag failure
  - Native decrypt error (rc != 0)
  - JSON parse failure
- [x] `load_vault()` only returns `[]` when:
  - File missing (new account)
  - Vault genuinely empty
- [x] Login aborts if decrypt fails

---

## 🟡 C) Memory Lifecycle Hardening (Polish Remaining)

### 5. Unified Wipe Function (Recommended Improvement)
Create `_wipe_session_and_keys()` and call it from:
- [ ] Logout
- [ ] App close
- [ ] Login abort
- [ ] Switch user
- [ ] Lock screen

Function should:
- [ ] `close_session()`
- [ ] Clear `core_session_handle`
- [ ] Wipe legacy `userKey`
- [ ] Clear clipboard
- [ ] Re-mask revealed fields

---

### 6. Secret Reveal Safety
- [x] Password reveal not cached long-term
- [x] Clipboard cleared on logout
- [x] Masking restored on lock/logout

---

## 🟡 D) Backward Compatibility (Minor Improvements Optional)

### 7. DLL Feature Detection
- [ ] Check `kq_version()` or export presence
- [ ] Graceful message if required export missing
- [x] Fallback only if safe

### 8. Legacy Key Fallback
- [x] Only used when native session creation fails
- [x] Never used silently for decrypt if session exists

---

## 🟡 E) Native DLL Final Review (Optional Hardening)

### 9. KqSession Structure
- [x] 32-byte fixed key buffer
- [x] Wiped in destructor / close
- [x] OpenSSL contexts freed

### 10. Error Codes
- [x] Distinct negative return codes
- [x] Python maps to clear errors
- [x] No silent decrypt failures

---

## 🔍 Verification Checklist Before Release

- [x] Password login works
- [x] DPAPI passwordless login works
- [x] Yubi WRAP login works
- [x] Vault loads correctly
- [x] Wrong password aborts login
- [x] Wrong Yubi aborts login
- [x] No empty-vault-on-error behavior
- [x] Session closes cleanly on logout
- [x] Clipboard clears on logout
- [x] No crashes on app close

---

## 🎯 Security Objective Status

✔ Vault master key lives only in DLL memory.  
✔ Python does not store vault key long-term.  
✔ All decrypt failures abort login.  
✔ No silent fallback behavior.  
✔ Backward compatibility preserved.

---

### Current Status: Phase 1 – Native Session Architecture Complete

Remaining items are polish-level hardening, not structural security issues.
