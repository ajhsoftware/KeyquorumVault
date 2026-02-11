"""
Keyquorum Vault
Copyright (C) 2025-2026 Anthony Hatton (AJH Software)

This file is part of Keyquorum Vault.

Keyquorum Vault is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Keyquorum Vault is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
"""

from __future__ import annotations
from typing import Optional, Tuple, Dict
import base64, secrets, hashlib, hmac
import os

# Crypto: AES-GCM + HKDF(SHA256)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from auth.yubi.yk_backend import YKBackend
from auth.login.login_handler import get_user_setting, set_user_setting, get_user_record, set_user_backup_codes, use_backup_code

SAFE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

# =============================================================================
# Utilities / error shaping
# =============================================================================

def _friendly_error(e: Exception) -> RuntimeError:
    s = (str(e) or "").lower()
    if any(p in s for p in (
        "ykman", "no yubikey", "no device", "unexpected error",
        "click/core.py", "timeout", "operation timed out",
    )):
        return RuntimeError("Your YubiKey isn’t responding. Insert it and touch the gold contact, then try again.")
    return RuntimeError(str(e) or "YubiKey error.")

def _get_backend(username: str,
                 yk_backend: Optional[YKBackend] = None,
                 ykman_path: Optional[str] = None) -> YKBackend:
    if yk_backend:
        return yk_backend
    if ykman_path is None:
        try:
            ykman_path = get_user_setting(username, "ykman_path")
        except Exception:
            ykman_path = None
    explicit = None if (ykman_path in (None, "pycli")) else ykman_path
    return YKBackend(explicit_path=explicit)

# =============================================================================
# Backup codes (one-time)
# =============================================================================

def try_recovery_unwrap_file(username: str, recovery_key: str) -> Optional[bytes]:
    """
    Unwrap the vault/master key using the Recovery Key + per-user salt and
    the *file* written at account creation. Returns bytes or None.
    """
    try:
        salt_path = get_salt_path(username)
        if not os.path.exists(salt_path):
            return None
        with open(salt_path, "rb") as f:
            salt = f.read()

        wkp = get_wrapped_key_path(username)
        if not os.path.exists(wkp):
            return None
        wrapped_text = open(wkp, "r", encoding="utf-8").read().strip()

        last_err = None
        for rk_try in _rk_variants(recovery_key):
            try:
                wkey = _derive_wrapping_key_from_recovery_key(rk_try, salt)
                if ku_decrypt_key is not None:
                    vk = ku_decrypt_key(wrapped_text, wkey)     # string -> bytes
                else:
                    vk = load_encrypted(wkp, wkey)              # path + key -> bytes
                if vk and isinstance(vk, (bytes, bytearray)) and len(vk) >= 16:
                    return vk
            except Exception as e:
                last_err = e
                continue
        return None
    except Exception:
        return None

# =============================================================================
# Recovery Key wrap (v2)
# =============================================================================

def has_recovery_wrap(username: str) -> bool:
    rec = get_user_setting(username, "twofactor_recovery")
    return bool(isinstance(rec, dict) and rec.get("mode") == "rk_wrap" and int(rec.get("ver", 0)) >= 2)

def enable_recovery_2of2_wrap(username: str, master_key: bytes, recovery_key: str,
                              *, require_recovery_mode: bool = True) -> dict:
    """
    Wrap MK using Recovery Key (+ password tag) so login can proceed without YK in recovery mode.
    """
    try:
        is_recovery_mode = bool(get_user_setting(username, "recovery_mode"))
    except Exception:
        is_recovery_mode = True
    if require_recovery_mode and not is_recovery_mode:
        raise RuntimeError("Recovery Key is disabled in Maximum Security mode.")

    salt  = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    rk_tag  = hashlib.sha256((recovery_key or "").encode("utf-8")).digest()
    pwd_tag = hashlib.sha256(bytes(master_key)).digest()
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"kq.recwrap.v2").derive(rk_tag + pwd_tag)
    wrapped = AESGCM(kek).encrypt(nonce, bytes(master_key), salt)

    rec = {
        "mode": "rk_wrap", "ver": 2,
        "salt_b64": base64.b64encode(salt).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "wrapped_b64": base64.b64encode(wrapped).decode(),
    }
    set_user_setting(username, "twofactor_recovery", rec)
    return rec

def try_recovery_unwrap(username: str, candidate_master_key: bytes, recovery_key: str) -> Optional[bytes]:
    """
    Try to unwrap MK using Recovery Key + password tag. Returns MK or None.
    """
    rec = get_user_setting(username, "twofactor_recovery") or {}
    if not (isinstance(rec, dict) and rec.get("mode") == "rk_wrap" and int(rec.get("ver", 0)) >= 2):
        return None
    salt   = base64.b64decode(rec.get("salt_b64") or b"")
    nonce  = base64.b64decode(rec.get("nonce_b64") or b"")
    wrapped= base64.b64decode(rec.get("wrapped_b64") or b"")
    if not (salt and nonce and wrapped):
        return None

    rk_tag  = hashlib.sha256((recovery_key or "").encode("utf-8")).digest()
    pwd_tag = hashlib.sha256(bytes(candidate_master_key)).digest()
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"kq.recwrap.v2").derive(rk_tag + pwd_tag)
    try:
        return AESGCM(kek).decrypt(nonce, wrapped, salt)
    except Exception:
        return None

def disable_recovery_wrap(username: str) -> bool:
    """
    Remove any stored Recovery-Key wrap material (v2 + legacy).
    Returns True if something changed.
    """
    changed = False
    try:
        if get_user_setting(username, "twofactor_recovery") is not None:
            set_user_setting(username, "twofactor_recovery", None)
            changed = True
    except Exception:
        pass
    for k in ("rk_wrap", "rk_nonce_b64", "rk_salt_b64", "rk_wrapped_b64", "rk_nonce", "rk_salt", "rk_wrapped"):
        try:
            if get_user_setting(username, k) is not None:
                set_user_setting(username, k, None)
                changed = True
        except Exception:
            pass
    return changed

# =============================================================================
# YubiKey HMAC gate/wrap
# =============================================================================

def yk_twofactor_enabled(username: str) -> Tuple[Optional[str], Dict]:
    """
    Returns (mode, rec) where mode in {"yk_hmac_gate", "yk_hmac_wrap", None}.
    Understands legacy flags for display-only purposes.
    """
    rec = get_user_setting(username, "twofactor")
    if isinstance(rec, dict) and rec.get("mode") in ("yk_hmac_gate", "yk_hmac_wrap"):
        return rec.get("mode"), rec

    # Legacy hints (do not use for unlocking, only to show status)
    legacy_mode = (get_user_setting(username, "yubi_2of2_mode") or "").upper()
    if legacy_mode == "GATE":
        return "yk_hmac_gate", {}
    if legacy_mode == "WRAP" or get_user_setting(username, "yubi_wrap_enabled"):
        return "yk_hmac_wrap", {}
    return None, {}

def enable_yk_2of2_gate(username: str, *, serial: str, slot: int = 2,
                        yk_backend: Optional[YKBackend] = None, ykman_path: Optional[str] = None,
                        challenge_hex: Optional[str] = None) -> dict:
    """
    Record a challenge/expected response pair to require YubiKey at login (GATE).
    """
    yk = _get_backend(username, yk_backend, ykman_path)
    challenge = (challenge_hex or secrets.token_hex(16)).lower()
    try:
        expected = (yk.calculate_hmac(slot, challenge, serial) or "").lower()
    except Exception as e:
        raise _friendly_error(e)

    rec = {
        "mode": "yk_hmac_gate",
        "serial": str(serial),
        "slot": int(slot),
        "challenge": challenge,
        "expected": expected,
        "ykman_path": (ykman_path or get_user_setting(username, "ykman_path") or None),
    }
    set_user_setting(username, "twofactor", rec)
    return rec

def enable_yk_2of2_wrap(username: str, master_key: bytes, *, serial: str, slot: int = 2,
                        yk_backend: Optional[YKBackend] = None, ykman_path: Optional[str] = None) -> dict:
    """
    Wrap the master key using HMAC from the YubiKey + password tag (WRAP v2).
    """
    yk = _get_backend(username, yk_backend, ykman_path)
    salt = secrets.token_bytes(16)

    try:
        resp_hex = yk.calculate_hmac(slot, salt.hex(), serial)
    except Exception as e:
        raise _friendly_error(e)

    yk_hmac = bytes.fromhex(resp_hex)
    pwd_tag = hashlib.sha256(bytes(master_key)).digest()
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"kq.ykwrap.v2").derive(yk_hmac + pwd_tag)
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(kek).encrypt(nonce, bytes(master_key), salt)

    rec = {
        "mode": "yk_hmac_wrap", "ver": 2,
        "serial": str(serial), "slot": int(slot),
        "salt_b64": base64.b64encode(salt).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "wrapped_b64": base64.b64encode(wrapped).decode(),
        "ykman_path": (ykman_path or get_user_setting(username, "ykman_path") or None),
    }
    set_user_setting(username, "twofactor", rec)
    return rec

def disable_yk_2of2(username: str) -> bool:
    """
    Remove the YubiKey twofactor record (and legacy hints).
    Returns True if something changed.
    """
    changed = False
    try:
        if get_user_setting(username, "twofactor") is not None:
            set_user_setting(username, "twofactor", None)
            changed = True
    except Exception:
        pass
    for k in ("yubi_2of2_mode", "yubi_wrap_enabled"):
        try:
            if get_user_setting(username, k) is not None:
                set_user_setting(username, k, None)
                changed = True
        except Exception:
            pass
    return changed

# old removeing
def _unwrap_master_key(rec: Dict, yk: YKBackend, candidate_master_key: bytes) -> bytes:
    """
    Support WRAP v2 (HKDF)
    """
    serial = rec.get("serial")
    slot   = int(rec.get("slot", 2))
    salt   = base64.b64decode(rec.get("salt_b64") or b"")
    nonce  = base64.b64decode(rec.get("nonce_b64") or b"")
    wrapped= base64.b64decode(rec.get("wrapped_b64") or b"")
    if not (serial and salt and nonce and wrapped):
        raise RuntimeError("YubiKey wrap config is incomplete.")

    try:
        resp_hex = yk.calculate_hmac(slot, salt.hex(), serial)
    except Exception as e:
        raise _friendly_error(e)
    yk_hmac = bytes.fromhex(resp_hex)

    ver = int(rec.get("ver", 1))
    if ver >= 2:
        pwd_tag = hashlib.sha256(bytes(candidate_master_key)).digest()
        kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"kq.ykwrap.v2").derive(yk_hmac + pwd_tag)
    else:
        # Pre-release legacy format – no longer supported
        raise RuntimeError(
            "This account uses an obsolete YubiKey wrap format from an early build. "
            "Disable YubiKey for this user and reconfigure it with the current version."
        )

    try:
        mk = AESGCM(kek).decrypt(nonce, wrapped, salt)
    
        # verify against stored hash
        expected_hash = rec.get("mk_hash_b64")
        if expected_hash:
            actual_hash = base64.b64encode(hashlib.sha256(mk).digest()).decode()
            if actual_hash != expected_hash:
                raise RuntimeError("YubiKey unwrap succeeded but master key is incorrect.")
    
        return mk
    except Exception as e:
        if "mac check failed" in str(e).lower():
            raise RuntimeError("Wrong YubiKey or password (authentication failed).")
        raise RuntimeError(f"YubiKey unwrap failed: {e}")


from typing import Optional, Tuple, Dict
import hmac

def unlock_with_yk_if_needed(
    username: str,
    candidate_master_key: Optional[bytes],
    *,
    backup_code: Optional[str] = None,
    recovery_key: Optional[str] = None,
    identity_password: Optional[str] = None,   # ✅ NEW
    yk_backend: Optional[YKBackend] = None,
    ykman_path: Optional[str] = None,
) -> Tuple[Optional[bytes], Dict]:
    """
    Returns (master_key_after, record_dict)

    Modes:
      - None: returns candidate_master_key
      - yk_hmac_gate: primary = YubiKey HMAC check; rescue requires BOTH backup_code + recovery_key
      - yk_hmac_wrap: primary = unwrap with YubiKey; rescue requires BOTH backup_code + recovery_key (file-based)
    """
    mode, rec = yk_twofactor_enabled(username)
    if not mode:
        return candidate_master_key, {}

    # --------------------------
    # GATE mode
    # --------------------------
    if mode == "yk_hmac_gate":
        from auth.login.login_handler import use_backup_code
        # Rescue path: require BOTH secrets
        if backup_code and recovery_key:
            if not identity_password:
                raise RuntimeError("Password required to verify backup code.")
    
            # 1) Verify backup code FIRST (consume it)
            if not use_backup_code(username, backup_code, "login", password_for_identity=identity_password):
                raise RuntimeError("Backup code is invalid.")
    
            # 2) THEN try Recovery Key (no leakage if this fails)
            mk_probe = try_recovery_unwrap_file(username, recovery_key)
            if not mk_probe:
                raise RuntimeError("Recovery Key is invalid.")
    
            return candidate_master_key, {"bypassed": "backup+recovery"}

        # Normal YubiKey gate path (unchanged) ...
        yk = _get_backend(username, yk_backend, ykman_path)
        challenge = rec.get("challenge") or ""
        expected  = (rec.get("expected") or "").lower()
        slot      = int(rec.get("slot", 2))
        serial    = rec.get("serial")
        if not (challenge and expected and serial):
            raise RuntimeError("YubiKey gate config is incomplete.")
        try:
            got = (yk.calculate_hmac(slot, challenge, serial) or "").lower()
        except Exception as e:
            raise _friendly_error(e)
        if not hmac.compare_digest(got, expected):
            raise RuntimeError("YubiKey verification failed.")
        return candidate_master_key, rec

    # --------------------------
    # WRAP mode
    # --------------------------
    if mode == "yk_hmac_wrap":
        # Rescue path: require BOTH secrets
        if backup_code and recovery_key:
            # Rescue path must not leak whether the Recovery Key is valid.
            # 1) Verify/consume backup code first.
            if not identity_password:
                raise RuntimeError("Password required to verify backup code.")

            from auth.login.login_handler import use_backup_code
            if not use_backup_code(username, backup_code, "login", password_for_identity=identity_password):
                raise RuntimeError("Backup code is invalid.")

            # 2) Then attempt Recovery Key unwrap.
            mk2 = try_recovery_unwrap_file(username, recovery_key)
            if not mk2:
                raise RuntimeError("Recovery Key is invalid.")

            return mk2, {"recovery": "unwrap_ok_both"}

        # Normal YubiKey unwrap path (unchanged) ...
        if not candidate_master_key:
            raise RuntimeError("Password required before YubiKey step.")
        yk = _get_backend(username, yk_backend, ykman_path)
        try:
            mk = _unwrap_master_key(rec, yk, candidate_master_key)
            return mk, rec
        except Exception as e:
            raise _friendly_error(e)

    # Fallback
    return candidate_master_key, rec

from auth.login.login_handler import set_user_setting
import secrets, string, hashlib

from pathlib import Path

# Use Phase-2 single source of truth for paths
from app.paths import salt_file, vault_wrapped_file
# Keep the crypto loader from vault_store (function, not paths)
from vault_store.vault_store import load_encrypted

def get_salt_path(username: str) -> str:
    # ensure_parent + name_only=False to get a concrete file path
    return str(salt_file(username, ensure_parent=False, name_only=False))

def get_wrapped_key_path(username: str) -> str:
    return str(vault_wrapped_file(username, ensure_parent=False, name_only=False))
# prefer project-native helpers if present
try:
    from vault_store.key_utils import decrypt_key as ku_decrypt_key
except Exception:
    ku_decrypt_key = None

try:
    from vault_store.key_utils import derive_wrapping_key_from_recovery_key as ku_derive_wrapping_key
    _HAVE_KU_DERIVE = True
except Exception:
    _HAVE_KU_DERIVE = False
    from vault_store.kdf_utils import derive_key_argon2id_safe as _derive_key_argon2id

def _derive_wrapping_key_from_recovery_key(recovery_key: str, salt: bytes) -> bytes:
    if _HAVE_KU_DERIVE:
        try:
            return ku_derive_wrapping_key(recovery_key, salt, length=32)
        except Exception:
            pass
    return _derive_key_argon2id(recovery_key, salt, length=32)

def _rk_variants(rk: str):
    """Return a small set of normalized Recovery Key variants.

    We intentionally keep this list short to avoid excessive oracle surface:
      - raw trimmed input
      - canonical form (remove spaces/dashes, upper-case)

    Note: The UI should encourage users to paste the key exactly as shown.
    """
    import re as _re
    rk_raw = (rk or "").strip()
    rk_can = _re.sub(r"[\s\-]", "", rk_raw).upper()
    out, seen = [], set()
    for v in (rk_raw, rk_can):
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out

# =============================================================================
# Backup codes and TOTP verification (delegated to login_handler / identity_store)
# =============================================================================

def gen_backup_codes(username: str, b_type="login", n: int = 10, L: int = 12, *, password_for_identity: str) -> list[str]:
    """Generate backup codes using the single identity_store implementation."""
    from auth.identity_store import gen_backup_codes as _gen
    return _gen(username, b_type=b_type, n=n, L=L, password_for_identity=password_for_identity)

