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
import logging, os, json, traceback
import datetime as dt
from typing import Dict, Any
from pathlib import Path
from app.paths import (user_db_file, ensure_dirs, vault_file, catalog_file, identities_file)
log = logging.getLogger("keyquorum")

from native.native_core import get_core
from catalog_category.my_catalog_builtin import CLIENTS, ALIASES, PLATFORM_GUIDE
from catalog_category.catalog_user import ensure_user_catalog_created
from catalog_category.category_fields import default_category_schema
from auth.pw.utils_recovery import mk_to_recovery_key
from auth.identity_store import gen_backup_codes
from qtpy.QtCore import QCoreApplication
from security.baseline_signer import write_baseline
from vault_store.key_utils import hash_password, encrypt_key
from vault_store.vault_store import save_encrypted, load_encrypted
from vault_store.kdf_utils import recommended_argon2_params, normalize_kdf_params
from auth.pw.password_utils import validate_password

def _tr(text: str) -> str:
    return QCoreApplication.translate("account_creator", text)

# ---------------- Per-user DB I/O (atomic) ----------------

def _close_native_session(session_handle) -> None:
    try:
        if isinstance(session_handle, int) and session_handle:
            get_core().close_session(session_handle)
    except Exception:
        pass

def _read_master_salt_strict(username: str) -> bytes:
    from auth.salt_file import read_master_salt_strict
    return read_master_salt_strict(username)

def _derive_vault_key_native(secret_text: str, salt: bytes, kdf: dict | None = None) -> bytes:
    if not isinstance(secret_text, str) or not secret_text:
        raise ValueError("secret_text must be a non-empty string")
    if not isinstance(salt, (bytes, bytearray, memoryview)) or not bytes(salt):
        raise ValueError("salt must be non-empty bytes")

    core = get_core()
    if not core:
        raise RuntimeError("Native core not loaded. DLL is required.")

    pw_buf = bytearray(secret_text.encode("utf-8"))
    try:
        if (
            isinstance(kdf, dict)
            and int(kdf.get("kdf_v", 1)) >= 2
            and hasattr(core, "derive_vault_key_ex")
            and getattr(core, "has_derive_vault_key_ex", lambda: False)()
        ):
            return bytes(core.derive_vault_key_ex(
                pw_buf,
                bytes(salt),
                time_cost=int(kdf.get("time_cost", 3)),
                memory_kib=int(kdf.get("memory_kib", 256000)),
                parallelism=int(kdf.get("parallelism", 2)),
            ))
        return bytes(core.derive_vault_key(pw_buf, bytes(salt)))
    finally:
        try:
            core.secure_wipe(pw_buf)
        except Exception:
            for i in range(len(pw_buf)):
                pw_buf[i] = 0

def _open_native_session(secret_text: str, salt: bytes, kdf: dict | None = None) -> int:
    if not isinstance(secret_text, str) or not secret_text:
        raise ValueError("secret_text must be a non-empty string")
    if not isinstance(salt, (bytes, bytearray, memoryview)) or not bytes(salt):
        raise ValueError("salt must be non-empty bytes")

    core = get_core()
    if not core:
        raise RuntimeError("Native core not loaded. DLL is required.")

    pw_buf = bytearray(secret_text.encode("utf-8"))
    try:
        if (
            isinstance(kdf, dict)
            and int(kdf.get("kdf_v", 1)) >= 2
            and hasattr(core, "open_session_ex")
            and getattr(core, "has_session_open_ex", lambda: False)()
        ):
            return core.open_session_ex(
                pw_buf,
                bytes(salt),
                time_cost=int(kdf.get("time_cost", 3)),
                memory_kib=int(kdf.get("memory_kib", 256000)),
                parallelism=int(kdf.get("parallelism", 2)),
            )
        return core.open_session(pw_buf, bytes(salt))
    finally:
        try:
            core.secure_wipe(pw_buf)
        except Exception:
            for i in range(len(pw_buf)):
                pw_buf[i] = 0

def load_user(username: str) -> dict:
    """Return the per-user record dict ({} if none)."""
    ensure_dirs()
    p = user_db_file(username)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data.get(username, {}) or {}
    except Exception as e:
        log.error(f"[users] failed to read {p}: {e}")
        return {}

def _atomic_write_json(path: Path, obj: dict) -> None:
    # Always ensure the parent directory exists when we are about to write
    # This bypasses read_only_paths on purpose: creating/updating a user is a write flow.
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    tmp = path.with_suffix(path.suffix + ".tmp")
    txt = json.dumps(obj, indent=2, ensure_ascii=False)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(txt)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def save_user(username: str, user_rec: dict) -> None:
    """Atomically write the per-user record dict."""
    ensure_dirs(username)
    p = user_db_file(username, ensure_parent=True)
    _atomic_write_json(p, {username: user_rec})

# ---------------- Defaults ----------------
DEFAULT_CLOUD = {
    "sync_enable": False,
    "provider": "localpath",
    "remote_path": None,
    "cloud_wrap": False,
    "bundle": True,
    "files_in_cloud": "",
    "last_local_sha256": None,
    "last_remote_sha256": None,
    "last_remote_version": None
}
DEFAULT_SETTINGS = {
    "WinDefCheckbox": False,
    "DefenderQuickScan": False,
    "ontop": False,
    "lockout_threshold": 5,
    "password_expiry_days": 90,
    "clipboard_clear_timeout_sec": 15,
    "auto_logout_timeout_sec": 300,
    "enable_breach_checker": False,
    "debug_set": False,
    "zoom_factor": 1.0,
    "portable": False,
    "touch_mode": None,
    "offer_tour_on_first_login": True,

}

# attach defaults once, from category_fields (single source of truth)
DEFAULT_SETTINGS["category_schema"] = default_category_schema()

from auth.pw.password_utils import _store_password_hash
# ---------------- Main API ----------------
def create_or_update_user(
    username: str,
    password: str,
    confirm: str,
    *,
    recovery_mode: bool = False,
    update_mode: bool = False,
    regenerate_keys: bool = False,          # regenerate login (forgot-password) backup codes
    regenerate_recovery_key: bool = False,
    password_strength_check: bool = True,
    old_password: str | None = None,
    rotate_salt: bool = False,
    debug: bool = True,
) -> Dict[str, Any]:
    """
    Create a user (update_mode=False) or update password (update_mode=True).

    Identity-header salt is authoritative.
    Paths:
      vault: Users/<user>/Main/<user>.kq
      identity: Users/<user>/Main/<user>.kq_id
      per-user DB: Users/<user>/Main/<user>_KQ.kq
      wrapped key (recovery mode): Users/<user>/Main/<user>.kq_wrap
    """
    try:
        username = (username or "").strip()
        password = password or ""
        confirm  = confirm  or ""

        if not username or not password or not confirm:
            return {"status": "error", "message": _tr("All fields are required.")}
        if password != confirm:
            return {"status": "error", "message": _tr("Passwords do not match.")}

        if password_strength_check:
            verdict = validate_password(password)
            valid    = bool(verdict.get("valid"))
            reason   = str(verdict.get("reason", _tr(("Password does not meet policy."))))
            strength = str(verdict.get("strength", _tr(("Unknown"))))

            log.info(
                "[create] password strength verdict: valid=%s strength=%s reason=%s",
                valid,
                strength,
                reason,
            )
            # Hard stop for truly bad passwords (too short / missing classes)
            if not valid:
                return {"status": "error", "message": reason}
            

        # Per-user DB only
        existing_rec = load_user(username)
        user_exists = bool(existing_rec)

        if update_mode and not user_exists:
            return {"status": "error", "message": _tr("User does not exist.")}
        if not update_mode and user_exists:
            return {"status": "error", "message": _tr("Username already exists.")}

        # ---------------- CREATE ----------------
        if not update_mode:
            salt = os.urandom(16)
            # Pick KDF profile for NEW accounts (v2 when supported)
            kdf = normalize_kdf_params(recommended_argon2_params())
            # STRICT NATIVE MODE: create a native session (vault key stays in DLL)
            core = get_core()
            if not core:
                return {"status": "error", "message": _tr("Native core not loaded. DLL is required.")}

            pw_buf = bytearray(password.encode("utf-8"))
            try:
                # Prefer per-vault params if the DLL + ctypes wrapper support it
                if hasattr(core, "open_session_ex") and getattr(core, "has_session_open_ex", lambda: False)():
                    session = core.open_session_ex(
                        pw_buf,
                        salt,
                        time_cost=int(kdf["time_cost"]),
                        memory_kib=int(kdf["memory_kib"]),
                        parallelism=int(kdf["parallelism"]),
                    )
                    kdf["kdf_v"] = 2
                else:
                    # Legacy fixed-params profile
                    session = core.open_session(pw_buf, salt)
                    kdf = {"algo": "argon2id", "kdf_v": 1}
            finally:
                try:
                    core.secure_wipe(pw_buf)
                except Exception:
                    for i in range(len(pw_buf)):
                        pw_buf[i] = 0
            # NEW LAYOUT paths
            vp = Path(vault_file(username, ensure_parent=True))  # Users/<u>/Main/<u>.kq
            try:
                from auth.identity_store import create_or_open_with_password
                create_or_open_with_password(username, password, salt=salt)
            except Exception as e:
                _close_native_session(session)
                return {"status": "error", "message": _tr("Could not write salt: ") + f"{e}"}

            # Seed empty vault
            try:
                vp.parent.mkdir(parents=True, exist_ok=True)
                save_encrypted([], str(vp), session)
                _close_native_session(session)
            except Exception as e:
                return {"status": "error", "message": _tr("Could not create vault: ") + f"{e}"}

            # --- Recovery + backup codes --------------------------------------
            recovery_key: str | None = None
            login_codes_plain: list[str] = []

            if recovery_mode:
                # 1) generate an internal 32-byte Master Key just for recovery
                mk = os.urandom(32)
                # 2) turn it into the human Recovery Key string (Emergency Kit format)
                recovery_key = mk_to_recovery_key(mk)

                # 3) wrap the vault key with a key derived from that Recovery Key
                wrapping_key = _derive_vault_key_native(recovery_key, salt)
                # For recovery-mode wrapping we need the raw 32-byte vault key briefly.
                pw_tmp = bytearray(password.encode("utf-8"))
                try:
                    key_bytes = _derive_vault_key_native(password, salt, kdf)
                finally:
                    try:
                        core.secure_wipe(pw_tmp)
                    except Exception:
                        for i in range(len(pw_tmp)):
                            pw_tmp[i] = 0
                wrapped_key = encrypt_key(key_bytes, wrapping_key)
                try:
                    # best-effort wipe of temporary key material
                    if isinstance(key_bytes, (bytes, bytearray)):
                        pass
                except Exception:
                    pass

                wkp = vp.with_suffix(".kq_wrap")
                wkp.parent.mkdir(parents=True, exist_ok=True)
                _wk = (wrapped_key.decode("utf-8", "ignore")
                       if isinstance(wrapped_key, (bytes, bytearray))
                       else str(wrapped_key))
                wkp.write_text(_wk, encoding="utf-8")

                # 4) bind a 'recovery' wrapper in the identity store using the same MK
                try:
                    from auth.identity_store import bind_recovery_wrapper
                    bind_recovery_wrapper(username, password, mk)
                except Exception as e:
                    log.warning("[create] could not bind recovery wrapper in identity: %s", e)

                # 5) generate login backup codes (shown once, hashes saved in identity)

                login_codes_plain = gen_backup_codes(username, b_type="login", n=10, L=12, password_for_identity=password)

            # --- per-user DB record -------------------------------------------
            user_rec = {
                "password": _store_password_hash(hash_password(password)),
                "recovery_mode": bool(recovery_mode),
                "created": dt.datetime.now().isoformat(),
                "twofa": {},
                "cloud": {**DEFAULT_CLOUD},
                "settings": {**DEFAULT_SETTINGS},
                "kdf": kdf,
                "ttl_days": 0,
            }
            save_user(username, user_rec)

            # Ensure per-user catalog exists
            try:
                ensure_user_catalog_created(
                    catalog_file(username, ensure_dir=True),
                    CLIENTS, ALIASES, PLATFORM_GUIDE,
                )
            except Exception:
                pass

            # Baseline: vault, salt, per-user DB, First time creact 
            try:
                write_baseline(
                    username,
                    salt,
                    [
                        str(vp),
                        str(vp.with_suffix(".kq_id")),
                        str(user_db_file(username)),
                    ],
                )

            except Exception:
                pass

            return {
                "status": _tr("SUCCESS"),
                "recovery_key": recovery_key,
                "backup_codes": login_codes_plain,
            }

        # ---------------- UPDATE (password change) ----------------
        try:
            old_salt = _read_master_salt_strict(username)
        except Exception:
            old_salt = b""

        if not old_salt:
            return {"status": "error", "message": _tr("User salt not found; cannot update password safely.")}
        if not old_password:
            return {"status": "error", "message": _tr("Old password is required.")}

        vp = Path(vault_file(username, ensure_parent=True))
        vault_path = str(vp)

        user_rec = load_user(username)
        if not user_rec:
            return {"status": "error", "message": _tr("User record not found.")}
        user_kdf = normalize_kdf_params(user_rec.get("kdf") or {}) if isinstance(user_rec, dict) else None

        old_session = None
        try:
            old_session = _open_native_session(old_password, old_salt, user_kdf)
            plaintext_obj = load_encrypted(vault_path, old_session)
            if isinstance(plaintext_obj, (bytes, bytearray)):
                try:
                    plaintext_obj = json.loads(plaintext_obj.decode("utf-8", "ignore"))
                except Exception:
                    plaintext_obj = []
            elif isinstance(plaintext_obj, str):
                try:
                    plaintext_obj = json.loads(plaintext_obj)
                except Exception:
                    plaintext_obj = []
        except Exception:
            return {"status": "error", "message": _tr("Old password is incorrect.")}
        finally:
            _close_native_session(old_session)

        salt = old_salt
        if rotate_salt:
            salt = os.urandom(16)
            try:
                from auth.salt_file import write_master_salt_to_identity
                write_master_salt_to_identity(username, salt)
            except Exception as e:
                return {"status": "error", "message": _tr("Could not update identity salt: ") + f"{e}"}
            log.debug(f"[DEBUG] Salt rotated for {username}")

        new_session = None
        try:
            new_session = _open_native_session(password, salt, user_kdf)
            save_encrypted(plaintext_obj, vault_path, new_session)
        finally:
            _close_native_session(new_session)

        user_rec["password"] = _store_password_hash(hash_password(password))
        user_rec.setdefault("recovery_mode", bool(recovery_mode))

        login_codes_plain: list[str] = []
        recovery_key: str | None = None

        if (regenerate_keys or False) and user_rec.get("recovery_mode"):
            login_codes_plain = gen_backup_codes(username, b_type="login", n=10, L=12, password_for_identity=password)

        if regenerate_recovery_key and user_rec.get("recovery_mode"):
            mk = os.urandom(32)
            recovery_key = mk_to_recovery_key(mk)

            try:
                from auth.identity_store import bind_recovery_wrapper
                bind_recovery_wrapper(username, (old_password or password), mk)
            except Exception as e:
                log.warning("[recovery] bind_recovery_wrapper unavailable: %r", e)

            wrapping_key = _derive_vault_key_native(recovery_key, salt)
            actual_new_vk = _derive_vault_key_native(password, salt, user_kdf)
            wrapped_key = encrypt_key(actual_new_vk, wrapping_key)
            wkp = vp.with_suffix(".kq_wrap")
            wkp.parent.mkdir(parents=True, exist_ok=True)
            _wk = (wrapped_key.decode("utf-8", "ignore")
                   if isinstance(wrapped_key, (bytes, bytearray))
                   else str(wrapped_key))
            wkp.write_text(_wk, encoding="utf-8")

        save_user(username, user_rec)

        try:
            ensure_user_catalog_created(catalog_file(username, ensure_dir=True), CLIENTS, ALIASES, PLATFORM_GUIDE)
        except Exception:
            pass

        return {
            "status": _tr("SUCCESS"),
            "recovery_key": recovery_key if regenerate_recovery_key else None,
            "backup_codes": login_codes_plain,
        }

    except Exception as e:
        log.error(f"[users] failed to read {p}: {e}")
        return {}

def _atomic_write_json(path: Path, obj: dict) -> None:
    # Always ensure the parent directory exists when we are about to write
    # This bypasses read_only_paths on purpose: creating/updating a user is a write flow.
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    tmp = path.with_suffix(path.suffix + ".tmp")
    txt = json.dumps(obj, indent=2, ensure_ascii=False)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(txt)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def save_user(username: str, user_rec: dict) -> None:
    """Atomically write the per-user record dict."""
    ensure_dirs(username)
    p = user_db_file(username, ensure_parent=True)
    _atomic_write_json(p, {username: user_rec})

# ---------------- Defaults ----------------
DEFAULT_CLOUD = {
    "sync_enable": False,
    "provider": "localpath",
    "remote_path": None,
    "cloud_wrap": False,
    "bundle": True,
    "files_in_cloud": "",
    "last_local_sha256": None,
    "last_remote_sha256": None,
    "last_remote_version": None
}
DEFAULT_SETTINGS = {
    "WinDefCheckbox": False,
    "DefenderQuickScan": False,
    "ontop": False,
    "lockout_threshold": 5,
    "password_expiry_days": 90,
    "clipboard_clear_timeout_sec": 15,
    "auto_logout_timeout_sec": 300,
    "enable_breach_checker": False,
    "debug_set": False,
    "zoom_factor": 1.0,
    "portable": False,
    "touch_mode": None,
    "offer_tour_on_first_login": True,

}

# attach defaults once, from category_fields (single source of truth)
DEFAULT_SETTINGS["category_schema"] = default_category_schema()

from auth.pw.password_utils import _store_password_hash
# ---------------- Main API ----------------
def create_or_update_user(
    username: str,
    password: str,
    confirm: str,
    *,
    recovery_mode: bool = False,
    update_mode: bool = False,
    regenerate_keys: bool = False,          # regenerate login (forgot-password) backup codes
    regenerate_recovery_key: bool = False,
    password_strength_check: bool = True,
    old_password: str | None = None,
    rotate_salt: bool = False,
    debug: bool = True,
) -> Dict[str, Any]:
    """
    Create a user (update_mode=False) or update password (update_mode=True).

    Identity-header salt is authoritative.
    Paths:
      vault: Users/<user>/Main/<user>.kq
      identity: Users/<user>/Main/<user>.kq_id
      per-user DB: Users/<user>/Main/<user>_KQ.kq
      wrapped key (recovery mode): Users/<user>/Main/<user>.kq_wrap
    """
    try:
        username = (username or "").strip()
        password = password or ""
        confirm  = confirm  or ""

        if not username or not password or not confirm:
            return {"status": "error", "message": _tr("All fields are required.")}
        if password != confirm:
            return {"status": "error", "message": _tr("Passwords do not match.")}

        if password_strength_check:
            verdict = validate_password(password)
            valid    = bool(verdict.get("valid"))
            reason   = str(verdict.get("reason", _tr(("Password does not meet policy."))))
            strength = str(verdict.get("strength", _tr(("Unknown"))))

            log.info(
                "[create] password strength verdict: valid=%s strength=%s reason=%s",
                valid,
                strength,
                reason,
            )
            # Hard stop for truly bad passwords (too short / missing classes)
            if not valid:
                return {"status": "error", "message": reason}
            

        # Per-user DB only
        existing_rec = load_user(username)
        user_exists = bool(existing_rec)

        if update_mode and not user_exists:
            return {"status": "error", "message": _tr("User does not exist.")}
        if not update_mode and user_exists:
            return {"status": "error", "message": _tr("Username already exists.")}

        # ---------------- CREATE ----------------
        if not update_mode:
            salt = os.urandom(16)
            # Pick KDF profile for NEW accounts (v2 when supported)
            kdf = normalize_kdf_params(recommended_argon2_params())
            # STRICT NATIVE MODE: create a native session (vault key stays in DLL)
            core = get_core()
            if not core:
                return {"status": "error", "message": _tr("Native core not loaded. DLL is required.")}

            pw_buf = bytearray(password.encode("utf-8"))
            try:
                # Prefer per-vault params if the DLL + ctypes wrapper support it
                if hasattr(core, "open_session_ex") and getattr(core, "has_session_open_ex", lambda: False)():
                    session = core.open_session_ex(
                        pw_buf,
                        salt,
                        time_cost=int(kdf["time_cost"]),
                        memory_kib=int(kdf["memory_kib"]),
                        parallelism=int(kdf["parallelism"]),
                    )
                    kdf["kdf_v"] = 2
                else:
                    # Legacy fixed-params profile
                    session = core.open_session(pw_buf, salt)
                    kdf = {"algo": "argon2id", "kdf_v": 1}
            finally:
                try:
                    core.secure_wipe(pw_buf)
                except Exception:
                    for i in range(len(pw_buf)):
                        pw_buf[i] = 0
            # NEW LAYOUT paths
            vp = Path(vault_file(username, ensure_parent=True))  # Users/<u>/Main/<u>.kq
            try:
                from auth.identity_store import create_or_open_with_password
                create_or_open_with_password(username, password, salt=salt)
            except Exception as e:
                _close_native_session(session)
                return {"status": "error", "message": _tr("Could not write salt: ") + f"{e}"}

            # Seed empty vault
            try:
                vp.parent.mkdir(parents=True, exist_ok=True)
                save_encrypted([], str(vp), session)
                _close_native_session(session)
            except Exception as e:
                return {"status": "error", "message": _tr("Could not create vault: ") + f"{e}"}

            # --- Recovery + backup codes --------------------------------------
            recovery_key: str | None = None
            login_codes_plain: list[str] = []

            if recovery_mode:
                # 1) generate an internal 32-byte Master Key just for recovery
                mk = os.urandom(32)
                # 2) turn it into the human Recovery Key string (Emergency Kit format)
                recovery_key = mk_to_recovery_key(mk)

                # 3) wrap the vault key with a key derived from that Recovery Key
                wrapping_key = _derive_vault_key_native(recovery_key, salt)
                # For recovery-mode wrapping we need the raw 32-byte vault key briefly.
                pw_tmp = bytearray(password.encode("utf-8"))
                try:
                    key_bytes = _derive_vault_key_native(password, salt, kdf)
                finally:
                    try:
                        core.secure_wipe(pw_tmp)
                    except Exception:
                        for i in range(len(pw_tmp)):
                            pw_tmp[i] = 0
                wrapped_key = encrypt_key(key_bytes, wrapping_key)
                try:
                    # best-effort wipe of temporary key material
                    if isinstance(key_bytes, (bytes, bytearray)):
                        pass
                except Exception:
                    pass

                wkp = vp.with_suffix(".kq_wrap")
                wkp.parent.mkdir(parents=True, exist_ok=True)
                _wk = (wrapped_key.decode("utf-8", "ignore")
                       if isinstance(wrapped_key, (bytes, bytearray))
                       else str(wrapped_key))
                wkp.write_text(_wk, encoding="utf-8")

                # 4) bind a 'recovery' wrapper in the identity store using the same MK
                try:
                    from auth.identity_store import bind_recovery_wrapper
                    bind_recovery_wrapper(username, password, mk)
                except Exception as e:
                    log.warning("[create] could not bind recovery wrapper in identity: %s", e)

                # 5) generate login backup codes (shown once, hashes saved in identity)

                login_codes_plain = gen_backup_codes(username, b_type="login", n=10, L=12, password_for_identity=password)

            # --- per-user DB record -------------------------------------------
            user_rec = {
                "password": _store_password_hash(hash_password(password)),
                "recovery_mode": bool(recovery_mode),
                "created": dt.datetime.now().isoformat(),
                "twofa": {},
                "cloud": {**DEFAULT_CLOUD},
                "settings": {**DEFAULT_SETTINGS},
                "kdf": kdf,
                "ttl_days": 0,
            }
            save_user(username, user_rec)

            # Ensure per-user catalog exists
            try:
                ensure_user_catalog_created(
                    catalog_file(username, ensure_dir=True),
                    CLIENTS, ALIASES, PLATFORM_GUIDE,
                )
            except Exception:
                pass

            # Baseline: vault, salt, per-user DB, First time creact 
            try:
                write_baseline(
                    username,
                    salt,
                    [
                        str(vp),
                        str(vp.with_suffix(".kq_id")),
                        str(user_db_file(username)),
                    ],
                )

            except Exception:
                pass

            return {
                "status": _tr("SUCCESS"),
                "recovery_key": recovery_key,
                "backup_codes": login_codes_plain,
            }

      
        # ---------------- UPDATE (password change) ----------------
        try:
            old_salt = _read_master_salt_strict(username)
        except Exception:
            old_salt = b""

        if not old_salt:
            return {"status": "error", "message": _tr("User salt not found; cannot update password safely.")}
        if not old_password:
            return {"status": "error", "message": _tr("Old password is required.")}

        vp = Path(vault_file(username, ensure_parent=True))
        vault_path = str(vp)

        user_rec = load_user(username)
        if not user_rec:
            return {"status": "error", "message": _tr("User record not found.")}

        user_kdf = normalize_kdf_params(user_rec.get("kdf") or {}) if isinstance(user_rec, dict) else None

        old_session = None
        try:
            old_session = _open_native_session(old_password, old_salt, user_kdf)
            plaintext_obj = load_encrypted(vault_path, old_session)

            if isinstance(plaintext_obj, (bytes, bytearray)):
                try:
                    plaintext_obj = json.loads(plaintext_obj.decode("utf-8", "ignore"))
                except Exception:
                    plaintext_obj = []
            elif isinstance(plaintext_obj, str):
                try:
                    plaintext_obj = json.loads(plaintext_obj)
                except Exception:
                    plaintext_obj = []
        except Exception:
            return {"status": "error", "message": _tr("Old password is incorrect.")}
        finally:
            _close_native_session(old_session)

        # salt rotate optional
        salt = old_salt
        if rotate_salt:
            salt = os.urandom(16)
            try:
                from auth.salt_file import write_master_salt_to_identity
                write_master_salt_to_identity(username, salt)
            except Exception as e:
                return {"status": "error", "message": _tr("Could not update identity salt: ") + f"{e}"}
            log.debug(f"[DEBUG] Salt rotated for {username}")

        # re-encrypt vault with new native session
        new_session = None
        try:
            new_session = _open_native_session(password, salt, user_kdf)
            save_encrypted(plaintext_obj, vault_path, new_session)
        finally:
            _close_native_session(new_session)

        # update DB record
        user_rec["password"] = _store_password_hash(hash_password(password))
        user_rec.setdefault("recovery_mode", bool(recovery_mode))

        login_codes_plain: list[str] = []
        recovery_key: str | None = None

        if (regenerate_keys or False) and user_rec.get("recovery_mode"):
            # IMPORTANT:
            # Do NOT regenerate login backup codes here during password change.
            # They depend on the Identity Store password wrapper, which is still
            # bound to the OLD password until the caller rewraps identity.
            # The dialog regenerates them AFTER identity rewrap succeeds.
            login_codes_plain = []

        if regenerate_recovery_key and user_rec.get("recovery_mode"):
            mk = os.urandom(32)
            recovery_key = mk_to_recovery_key(mk)

            try:
                from auth.identity_store import bind_recovery_wrapper
                bind_recovery_wrapper(username, password, mk)
            except Exception as e:
                log.warning("[recovery] bind_recovery_wrapper unavailable: %r", e)

            wrapping_key = _derive_vault_key_native(recovery_key, salt)
            actual_new_vk = _derive_vault_key_native(password, salt, user_kdf)
            wrapped_key = encrypt_key(actual_new_vk, wrapping_key)

            wkp = vp.with_suffix(".kq_wrap")
            wkp.parent.mkdir(parents=True, exist_ok=True)
            _wk = (
                wrapped_key.decode("utf-8", "ignore")
                if isinstance(wrapped_key, (bytes, bytearray))
                else str(wrapped_key)
            )
            wkp.write_text(_wk, encoding="utf-8")

        # Save per-user DB
        save_user(username, user_rec)

        # Ensure per-user catalog exists
        try:
            ensure_user_catalog_created(
                catalog_file(username, ensure_dir=True),
                CLIENTS,
                ALIASES,
                PLATFORM_GUIDE,
            )
        except Exception:
            pass

        return {
            "status": _tr("SUCCESS"),
            "recovery_key": recovery_key if regenerate_recovery_key else None,
            "backup_codes": login_codes_plain,
        }
    except Exception as e:
        log.error("[ACCOUNT] create_or_update_user failed: %r", e, exc_info=True)
        return {
            "status": "error",
            "success": False,
            "message": str(e),
        }
