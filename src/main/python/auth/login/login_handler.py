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
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path

log = logging.getLogger("keyquorum")

# --- Paths / helpers ---
from app.paths import ensure_dirs, users_root, salt_file
from vault_store.key_utils import verify_password as _verify_hash  # stored_hash: bytes, password: str
import app.paths as _paths

# Identity store: authoritative for TOTP + backup codes
from auth.identity_store import (
    has_totp_quick as id_has_totp_quick,
    get_totp_secret as id_get_totp_secret,
    replace_backup_codes as id_replace_2fa_codes,
    consume_backup_code as id_consume_2fa_code,
    get_2fa_backup_count_quick as id_2fa_count,
    replace_login_backup_codes as id_replace_login_codes,
    consume_login_backup_code as id_consume_login_code,
    get_login_backup_count_quick as id_login_count,
)

# ==============================
# Per-user DB I/O (no global user_db usage)
# ==============================

def _udb_path(username: str) -> Path:
    from app.paths import user_db_file
    return Path(user_db_file(username, ensure_parent=False))

def _read_user(username: str) -> dict:
    """Load a user's record from users/<username>/user_db.json (returns {} if missing)."""
    username = (username or "").strip()
    if not username:
        return {}
    p = _udb_path(username)
    try:
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8")) or {}
            return data.get(username, {}) or {}
    except Exception as e:
        log.error("[login] failed to read %s: %s", p, e)
    return {}

def _write_user(username: str, rec: dict) -> bool:
    """Atomically write the user's record into users/<username>/user_db.json."""
    username = (username or "").strip()
    if not username:
        return False
    try:
        p = _udb_path(username)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        txt = json.dumps({username: rec or {}}, indent=2, ensure_ascii=False)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(txt); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, p)
        return True
    except Exception as e:
        log.error("[login] write failed for %s: %s", username, e)
        return False

# ==============================
# Username canonicalization (case-insensitive)
# ==============================

def _canonical_username_ci(typed: str) -> str | None:
    """
    Map typed username to canonical folder, case-insensitive.
    Returns None if no match or blank input.
    """
    try:
        typed = (typed or "").strip()
        if not typed:
            return None
        root = users_root()
        tl = typed.casefold()
        for d in root.iterdir():
            if d.is_dir() and d.name.casefold() == tl:
                return d.name
    except Exception:
        pass
    return None

# ==============================
# Public helpers used around the app
# ==============================

def save_user_record_new(username: str, rec: dict) -> bool:
    """Writer: allowed to create dirs."""
    try:
        from app.paths import user_db_file
        p = Path(user_db_file(username, ensure_parent=True))
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(rec or {}, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(p)
        try: os.chmod(p, 0o600)
        except Exception: pass
        return True
    except Exception as e:
        log.error("[login] write error for %s: %s", username, e)
        return False

def get_user_record(username: str) -> dict:
    """
    Read and return this user's record dictionary from their per-user DB.
    Ensures core dirs exist first. Returns {} if not found or unreadable.
    """
    username = (username or "").strip()
    if not username:
        return {}
    p = _udb_path(username)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data.get(username, {}) or {}
    except Exception as e:
        log.error("[login] read error for %s: %s", p, e)
        return {}

def set_user_record(username: str, rec: dict) -> bool:
    """Write this user's record dictionary atomically."""
    if not isinstance(rec, dict):
        return False
    try:
        ensure_dirs()
    except Exception:
        pass
    return _write_user(username, rec)

def _read_user_salt(username: str) -> bytes:
    """Read-only salt load via new paths."""
    from app.paths import salt_file
    try:
        p = salt_file(username)
        return p.read_bytes() if p.exists() else b""
    except Exception:
        return b""

def _load_vault_salt_for(user: str) -> bytes:
    # legacy helper used for baseline writes; keep behavior
    try:
        log.debug(f"[USB] salt_file fn id={id(salt_file)} "
            f"mode={_paths.is_portable_mode()} users_root={users_root()}")
        sp = salt_file(user, ensure_parent=False)
        return sp.read_bytes()
    except Exception:
        return _read_user_salt(user) or b""

# --- Settings ---

def get_user_setting(username: str, key: str, default=None):
    rec = _read_user(username)
    if not rec:
        return None if key != "all" else {}
    settings = rec.get("settings", {})
    if key == "all":
        return settings
    return settings.get(key, default)

def set_user_setting(username: str, key: str, value) -> bool:
    rec = _read_user(username)
    if not rec:
        return False

    settings = rec.get("settings") or {}

    if key == "all":
        if not isinstance(value, dict):
            return False
        settings = value
    else:
        settings[key] = value

    rec["settings"] = settings
    return _write_user(username, rec)

def get_recovery_mode(username: str) -> Optional[bool]:
    rec = _read_user(username)
    if not rec:
        return None
    return bool(rec.get("recovery_mode"))

def set_recovery_mode(username: str, value: bool) -> bool:
    """
    Update the user's recovery_mode flag.

    Semantics:
      True  = Recovery mode enabled (account has a recovery path)
      False = Max security (no recovery; wrap-only / no recovery wrapper)
    """
    rec = _read_user(username)
    if not rec:
        return False
    rec["recovery_mode"] = bool(value)
    return _write_user(username, rec)

# --- Cloud profile (structure preserved) ---

def _default_sync_profile() -> dict:
    return {
        "enabled": False,
        "provider": "localpath",
        "remote_path": "",
        "cloud_wrap": False,
        "last_sync_ts": 0,
        "last_local_sha256": "",
        "last_remote_sha256": "",
        "last_remote_version": "",
        "sync_enable": False,
    }

def get_user_cloud(username: str) -> dict:
    rec = _read_user(username)
    if not rec:
        return _default_sync_profile()
    cloud = rec.get("cloud") or {}
    prof = _default_sync_profile()
    for k in prof.keys():
        prof[k] = cloud.get(k, prof[k])
    return prof

def set_user_cloud(
    username: str,
    enable: Optional[bool] = None,
    provider: Optional[str] = None,
    path: Optional[str] = None,
    wrap: Optional[bool] = None,
    *,
    sync_enable: Optional[bool] = None,
    last_sync_ts: Optional[int] = None,
    last_local_sha256: Optional[str] = None,
    last_remote_sha256: Optional[str] = None,
    last_remote_version: Optional[str] = None,
) -> Optional[dict]:
    rec = _read_user(username)
    if not rec:
        return None
    prof = rec.get("cloud") or _default_sync_profile()

    old_provider = prof.get("provider")
    old_path     = prof.get("remote_path")

    if enable is not None:
        prof["enabled"] = bool(enable)
    if provider is not None:
        prof["provider"] = provider or "localpath"
    if path is not None:
        prof["remote_path"] = (path or "").replace("\\", "/")
    if wrap is not None:
        prof["cloud_wrap"] = bool(wrap)
    if sync_enable is not None:
        prof["sync_enable"] = bool(sync_enable)

    target_changed = ((old_provider or "") != (prof.get("provider") or "")) or \
                     ((old_path or "")     != (prof.get("remote_path") or ""))

    if target_changed:
        prof["last_sync_ts"]       = 0
        prof["last_local_sha256"]  = ""
        prof["last_remote_sha256"] = ""
        prof["last_remote_version"]= ""
    else:
        if last_sync_ts is not None:
            prof["last_sync_ts"] = int(last_sync_ts)
        if last_local_sha256 is not None:
            prof["last_local_sha256"] = last_local_sha256 or ""
        if last_remote_sha256 is not None:
            prof["last_remote_sha256"] = last_remote_sha256 or ""
        if last_remote_version is not None:
            prof["last_remote_version"] = last_remote_version or ""

    rec["cloud"] = prof
    _write_user(username, rec)
    return prof

# --- Login lockout (per-user settings blob) ---

def _now() -> datetime:
    return datetime.now()

def get_login_fail_state(username: str) -> dict:
    st = get_user_setting(username, "login_fail") or {}
    return {
        "fail_count": int(st.get("fail_count") or st.get("count") or 0),
        "lock_until": st.get("lock_until") or "",
    }

def save_login_fail_state(username: str, st: dict) -> None:
    set_user_setting(username, "login_fail", {
        "fail_count": int(st.get("fail_count") or 0),
        "lock_until": st.get("lock_until") or "",
    })

def is_locked_out(username: str, threshold: int = 5) -> tuple[bool, Optional[str]]:
    st = get_login_fail_state(username)
    lu = st.get("lock_until") or ""
    if not lu:
        return False, None
    try:
        until = datetime.fromisoformat(lu)
    except Exception:
        st["lock_until"] = ""
        save_login_fail_state(username, st)
        return False, None

    if _now() < until:
        left = max(0, int((until - _now()).total_seconds()))
        return True, f"Too many attempts. Try again in {left}s."

    # expired: clear state
    st["fail_count"] = 0
    st["lock_until"] = ""
    save_login_fail_state(username, st)
    return False, None

def register_login_failure(username: str, max_attempts: int = 5, lock_minutes: int = 5) -> int:
    st = get_login_fail_state(username)
    st["fail_count"] = int(st.get("fail_count") or 0) + 1
    if max_attempts > 0 and st["fail_count"] >= max_attempts and not st.get("lock_until"):
        st["lock_until"] = (_now() + timedelta(minutes=int(lock_minutes))).isoformat()
    save_login_fail_state(username, st)
    return st["fail_count"]

def reset_login_failures(username: str) -> None:
    save_login_fail_state(username, {"fail_count": 0, "lock_until": ""})

# ==============================
# 2FA / backup-code API (identity store wrappers)
# ==============================

from typing import Optional
import json, os, base64, hashlib
from pathlib import Path

from vault_store.key_utils import encrypt_key, decrypt_key
from vault_store.kdf_utils import derive_key_argon2id_safe
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def id_consume_login_code_with_mk(username: str, master_key: bytes, code_plain: str) -> bool:
    """
    Consume a LOGIN backup code using a master key (e.g. from Recovery Key).

    This opens the identity using the recovery wrapper, then:
      - hashes the user-provided code with the same salted scheme used in the
        identity store (twofa.salt + code)
      - removes the matching entry from recovery.login_backup_code_hashes
      - updates the header mirror (meta.login_backup_count)
      - writes the updated identity back via update_inner(...)
    """
    code = (code_plain or "").strip()
    if not code:
        return False

    # Import helpers from identity_store lazily to avoid circular imports
    try:
        from auth.identity_store import _open_identity_with_master_key, update_inner, _b64d
    except Exception as e:
        log.debug("[2FA] login-backup verify failed (imports): %r", e)
        return False

    # 1) Open identity with MK → (dmk, inner, hdr)
    try:
        dmk, inner, hdr = _open_identity_with_master_key(username, master_key)
    except Exception as e:
        log.debug("[2FA] login-backup verify failed: %r", e)
        return False

    try:
        # 2) Get the same salt used for backup-code hashing
        twofa = inner.get("twofa") or {}
        try:
            salt = _b64d(twofa.get("salt"))
        except Exception:
            salt = b""
        if not salt:
            log.debug("[2FA] login-backup verify failed: missing twofa.salt")
            return False

        # 3) Get the legacy login backup bucket
        rec = inner.setdefault("recovery", {})
        bucket = rec.get("login_backup_code_hashes") or []
        if not isinstance(bucket, list) or not bucket:
            log.debug("[2FA] login-backup verify failed: no login_backup_code_hashes")
            return False

        # 4) Compute salted hash exactly like identity_store does
        from auth.pw.utils_recovery import verify_and_consume_backup_code

        ok, new_bucket = verify_and_consume_backup_code(
            code_plain,
            bucket,
            salt=salt,
        )
        if not ok:
            return False

        rec["login_backup_code_hashes"] = new_bucket
        # 5) Write updated list + header mirror count
        try:
            meta = hdr.setdefault("meta", {})
            meta["login_backup_count"] = int(len(bucket))
        except Exception:
            # mirror is only a UI convenience
            pass

        # 6) Persist the updated inner payload
        update_inner(username, dmk, inner)
        return True

    except Exception as e:
        log.warning("[2FA] failed to consume login backup via MK for %s: %s", username, e)
        return False

def id_consume_2fa_code_with_mk(username: str, master_key: bytes, code_plain: str) -> bool:
    """
    Open the identity using recovery wrapper (MK) and consume a 2FA backup code.
    """
    return _consume_backup_code_core(username, code_plain, kind="login", master_key=master_key)

def _kek_from_password(password: str, salt: bytes) -> bytes:
    return derive_key_argon2id_safe(password, salt, length=32)

def _kek_from_mk(master_key: bytes, salt: bytes) -> bytes:
    # Isolate MK usage for recovery wrapping
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"kq/identity/recovery").derive(master_key)

def _find_wrapper(hdr: dict, typ: str) -> dict:
    for w in (hdr.get("wrappers") or []):
        if (w.get("type") or "").lower() == typ:
            return w
    raise KeyError(f"wrapper '{typ}' not found")

def _unwrap_cek_with_password(hdr: dict, pwd: str, salt: bytes) -> bytes:
    w = _find_wrapper(hdr, "password")
    return decrypt_key(w["ct"], _kek_from_password(pwd, salt))

def _unwrap_cek_with_recovery(hdr: dict, mk: bytes, salt: bytes) -> bytes:
    w = _find_wrapper(hdr, "recovery")
    return decrypt_key(w["ct"], _kek_from_mk(mk, salt))

def _load_header_and_salt(username: str):
    """
    Binary-safe loader: extracts the header JSON from the identity blob.
    Returns (header_dict, salt_bytes, id_path: Path).
    """
    from app.paths import identities_file, salt_file

    id_path = Path(identities_file(username))   # ❗ no ensure_dir kwarg
    blob = id_path.read_bytes()

    # Identity file format (observed): b'KQID1\\x00\\x00\\x01' + header_json + payload_bytes
    # Strategy: find the first '{' and parse balanced braces until the matching '}'.
    try:
        start = blob.index(b'{')
    except ValueError:
        raise ValueError("Identity header JSON not found")

    depth = 0
    end = None
    for i in range(start, len(blob)):
        b = blob[i]
        if b == 0x7B:       # '{'
            depth += 1
        elif b == 0x7D:     # '}'
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        raise ValueError("Identity header JSON appears truncated")

    header_bytes = blob[start:end]
    header = json.loads(header_bytes.decode("utf-8"))

    # Use per-user salt file (authoritative)
    s_path = Path(salt_file(username))
    salt = s_path.read_bytes()

    return header, salt, id_path

def _decrypt_payload_with_cek(hdr: dict, cek: bytes) -> dict:
    # Your payload field name might be 'payload_ct' or similar; keep as-is:
    ct_b64 = hdr.get("payload_ct") or hdr.get("ciphertext")
    if not ct_b64:
        raise ValueError("Missing identity payload")
    pt = decrypt_key(ct_b64, cek)
    return json.loads(pt.decode("utf-8"))

def _encrypt_payload_with_cek(hdr: dict, cek: bytes, payload: dict) -> None:
    pt = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    hdr["payload_ct"] = encrypt_key(pt, cek)

def _hash_backup_code_plain(code: str) -> str:
    # Use existing scheme; this mirrors current base64-encoded SHA256
    h = hashlib.sha256(code.strip().encode("utf-8")).digest()
    return base64.b64encode(h).decode("ascii")

def _consume_backup_code_core(
    username: str,
    code_plain: str,
    *,
    kind: str,                       # "login" or "2fa"
    master_key: bytes | None = None,
    password_for_identity: str | None = None,
) -> bool:
    hdr, salt, id_path = _load_header_and_salt(username)

    # Unwrap CEK via MK (recovery wrapper) or password wrapper
    if master_key is not None:
        cek = _unwrap_cek_with_recovery(hdr, master_key, salt)
    else:
        if not password_for_identity:
            raise ValueError("password_for_identity is required if master_key is not provided")
        cek = _unwrap_cek_with_password(hdr, password_for_identity, salt)

    payload = _decrypt_payload_with_cek(hdr, cek)

    # Expect payload["backup_codes"][kind] = list of base64(sha256(code))
    bucket = (payload.get("backup_codes") or {}).get(kind)
    if not isinstance(bucket, list):
        return False

    want = _hash_backup_code_plain(code_plain)
    try:
        idx = bucket.index(want)
    except ValueError:
        return False  # invalid or already used

    del bucket[idx]
    payload.setdefault("backup_codes", {})[kind] = bucket
    _encrypt_payload_with_cek(hdr, cek, payload)
 
    return True


BTYPE_LOGIN = "login"  # forgot-password / Yubi recovery codes
BTYPE_2FA   = "2fa"    # TOTP backup codes

def _norm_btype(b: str) -> str:
    b = (b or BTYPE_LOGIN).strip().lower()
    if b not in (BTYPE_LOGIN, BTYPE_2FA):
        raise ValueError("b_type must be 'login' or '2fa'")
    return b

def get_user_secret_twofa(username: str, password: Optional[str] = None, quick_check: bool = False):
    """
    TOTP secret from identity store.
      - quick_check=True  -> return True/False (no password required)
      - quick_check=False -> return base32 secret (password required) or None
    """
    try:
        if quick_check:
            return id_has_totp_quick(username)
        if not password:
            return None
        return id_get_totp_secret(username, password)
    except Exception as e:
        log.warning("get_user_secret_twofa failed for %s: %s", username, e)
        return None

def is_2fa_enabled(username: str) -> bool:
    """True if identity store indicates TOTP set or 2FA backup codes exist."""
    try:
        return bool(id_has_totp_quick(username) or id_2fa_count(username) > 0)
    except Exception:
        return False

def get_backup_count_quick(username: str, b_type: str) -> int:
    """Count badge without password (non-sensitive, from identity header)."""
    b = _norm_btype(b_type)
    return id_login_count(username) if b == BTYPE_LOGIN else id_2fa_count(username)

def set_user_backup_codes(
    username: str,
    codes_plain: list[str],
    b_type: str,
    *,
    password_for_identity: str
) -> None:
    """
    Store (hash) backup codes in identity store. Requires user's password.
      b_type: "login" or "2fa"
    """
    b = _norm_btype(b_type)
    if b == BTYPE_LOGIN:
        id_replace_login_codes(username, password_for_identity, codes_plain or [])
    else:
        id_replace_2fa_codes(username, password_for_identity, codes_plain or [])

def use_backup_code(
    username: str,
    code_plain: str,
    which: str,
    *,
    password_for_identity: str | None = None,
    master_key: bytes | None = None,
) -> bool:
    """
    Consume a backup code from identity store.

    Supports two auth routes:
      - master_key: derived from Recovery Key (Forgot Password flow; no password needed)
      - password_for_identity: normal route

    which: "login" or "2fa"
    """
    w = _norm_btype(which)

    # Prefer MK route if provided (works even when user forgot password)
    if master_key is not None:
        if w == BTYPE_LOGIN:
            return id_consume_login_code_with_mk(username, master_key, code_plain)
        else:
            return id_consume_2fa_code_with_mk(username, master_key, code_plain)

    # Backward-compat: original behavior (requires password)
    if not password_for_identity:
        raise ValueError("password_for_identity is required when master_key is not provided")
    if w == BTYPE_LOGIN:
        return id_consume_login_code(username, password_for_identity, code_plain)
    
    return id_consume_2fa_code(username, password_for_identity, code_plain)

def verify_2fa_code(username: str, code: str, password: str, *, window: int = 1) -> bool:
    """
    Verify a user-provided code against either TOTP or a 2FA backup code.
    Requires user's password to read identity store.
    """
    try:
        code_norm = (code or "").strip().replace(" ", "")
        # TOTP path
        if code_norm.isdigit() and 6 <= len(code_norm) <= 8:
            secret = id_get_totp_secret(username, password)
            if not secret:
                return False
            import pyotp
            return bool(pyotp.TOTP(secret).verify(code_norm, valid_window=window))
        # Backup code path (2FA)
        return bool(id_consume_2fa_code(username, password, code_norm))
    except Exception as e:
        log.error(f"[2FA] verification failed: {e}")
        return False

# ==============================
# Login
# ==============================

def validate_login(username: str, password: str) -> bool:
    """
    Validate username/password against stored password hash in per-user DB.
    """
    rec = _read_user(username)
    if not rec:
        return False
    stored = rec.get("password")
    if not stored:
        return False
    try:
        # stored hash may be str -> bytes
        if isinstance(stored, str):
            stored = stored.encode("utf-8", "ignore")
        return bool(_verify_hash(stored, password))
    except Exception as e:
        log.error("[login] password verify failed: %s", e)
        return False
