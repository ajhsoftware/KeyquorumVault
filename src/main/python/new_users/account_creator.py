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
import logging, os, json
import datetime as dt
from typing import Dict, Any
from pathlib import Path
from app.paths import (
    user_db_file, ensure_dirs,
    vault_file, salt_file, catalog_file
)
log = logging.getLogger("keyquorum")

from catalog_category.my_catalog_builtin import CLIENTS, ALIASES, PLATFORM_GUIDE
from catalog_category.catalog_user import ensure_user_catalog_created
from catalog_category.category_fields import default_category_schema
from auth.pw.utils_recovery import mk_to_recovery_key
from auth.identity_store import gen_backup_codes
from qtpy.QtCore import QCoreApplication
from security.baseline_signer import write_baseline
from vault_store.key_utils import hash_password, encrypt_key
from vault_store.vault_store import save_encrypted, load_encrypted
from vault_store.kdf_utils import derive_key_argon2id
from vault_store.vault_store import load_user_salt
from auth.pw.password_utils import validate_password
from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("account_creator", text)

# ---------------- Per-user DB I/O (atomic) ----------------

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
    "last_sync_ts": 0,
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
    NEW PATHS:
      vault: Users/<user>/Main/<user>.kq_user
      salt : Users/<user>/KQ_Store/kq_user_<user>.bin
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
            key = derive_key_argon2id(password, salt)  # 32 bytes

            # NEW LAYOUT paths
            vp = Path(vault_file(username, ensure_parent=True))  # Users/<u>/Main/<u>.kq
            sp = salt_file(username, ensure_parent=True)         # Users/<u>/KQ_Store/kq_user_<u>.bin

            # Persist salt
            try:
                sp.parent.mkdir(parents=True, exist_ok=True)
                sp.write_bytes(salt)
            except Exception as e:
                return {"status": "error", "message": _tr("Could not write salt: ") + f"{e}"}

            # Seed empty vault
            try:
                vp.parent.mkdir(parents=True, exist_ok=True)
                save_encrypted([], str(vp), key)
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
                wrapping_key = derive_key_argon2id(recovery_key, salt)
                wrapped_key = encrypt_key(key, wrapping_key)

                wkp = vp.with_suffix(".kq_wrap")
                wkp.parent.mkdir(parents=True, exist_ok=True)
                _wk = (wrapped_key.decode("utf-8", "ignore")
                       if isinstance(wrapped_key, (bytes, bytearray))
                       else str(wrapped_key))
                wkp.write_text(_wk, encoding="utf-8")

                # 4) bind a 'recovery' wrapper in the identity store using the same MK
                try:
                    from auth.identity_store import bind_recovery_wrapper
                    bind_recovery_wrapper(username, (old_password or password), mk)
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
                        str(sp),
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
        # Read old salt (prefer new path first; fallback to legacy if needed)
        try:
            old_salt = Path(salt_file(username, ensure_parent=True)).read_bytes()
        except Exception:
            try:
                old_salt = load_user_salt(username)  # legacy fallback if you still ship it
            except Exception:
                old_salt = b""

        if not old_salt:
            return {"status": "error", "message": _tr("User salt not found; cannot update password safely.")}
        if not old_password:
            return {"status": "error", "message": _tr("Old password is required.")}

        old_key = derive_key_argon2id(old_password, old_salt)
        vp = Path(vault_file(username, ensure_parent=True))
        vault_path = str(vp)

        try:
            plaintext_obj = load_encrypted(vault_path, old_key)
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

        # salt rotate optional
        salt = old_salt
        if rotate_salt:
            salt = os.urandom(16)
            Path(salt_file(username, ensure_parent=True)).write_bytes(salt)
            log.debug(f"[DEBUG] Salt rotated for {username}")

        # re-encrypt vault with new key
        new_key = derive_key_argon2id(password, salt)
        save_encrypted(plaintext_obj, vault_path, new_key)

        # update DB record
        user_rec = load_user(username)
        if not user_rec:
            return {"status": "error", "message": _tr("User record not found.")}

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

            wrapping_key = derive_key_argon2id(recovery_key, salt)
            wrapped_key = encrypt_key(new_key, wrapping_key)
            wkp = vp.with_suffix(".kq_wrap")
            wkp.parent.mkdir(parents=True, exist_ok=True)
            _wk = (wrapped_key.decode("utf-8", "ignore")
                   if isinstance(wrapped_key, (bytes, bytearray))
                   else str(wrapped_key))
            wkp.write_text(_wk, encoding="utf-8")

        # Save per-user DB
        save_user(username, user_rec)

        # Ensure per-user catalog exists
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
        log.error(f"[account] Exception: {e}")
        return {"status": "error", "message": _tr("Exception occurred:") + f" {e}"}
