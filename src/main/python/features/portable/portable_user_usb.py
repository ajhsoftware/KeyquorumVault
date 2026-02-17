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
import json, shutil
from pathlib import Path
from typing import Dict, Any

# All path resolution must go through paths.*
from app.paths import (
    vault_file, salt_file, user_db_file, identities_file, settings_dir,
    security_prefs_file, software_dir, config_dir, baseline_file,
)

# --- Back-compat wrapper for older main.py ---
from pathlib import Path as _Path

def move_user_to_usb_store(parent, target_root, username: str) -> bool:
    """
    Legacy alias kept for backward compatibility.
    Redirects to portable_manager.move_user_data_to_usb(...).
    """
    try:
        from features.portable.portable_manager import move_user_data_to_usb
    except Exception as e:
        # Shouldn't happen, but surface a clear error in logs.
        import logging
        logging.getLogger("keyquorum").error(f"[USB] move_user_to_usb_store: {e}")
        return False
    return move_user_data_to_usb(parent, _Path(target_root), username)

# ----------------------- USB layout helpers -----------------------

def portable_root(usb_root: Path) -> Path:
    return Path(usb_root) / "KeyquorumPortable"

def ensure_portable_layout(usb_root: Path) -> tuple[Path, Path]:
    pr = portable_root(usb_root)
    users = pr / "Users"
    users.mkdir(parents=True, exist_ok=True)
    return pr, users

# ----------------------- Binding overrides (runtime) -----------------------
def install_binding_overrides(username: str, user_dir: Path) -> None:
    """
    Repoint per-user path helpers to the USB user_dir by overriding functions in 'paths'.
    Keeps the rest of the app unchanged while running from USB.

    IMPORTANT: Uses ORIGINAL paths.* for name derivation to avoid recursion loops.
    """
    import importlib, logging
    from pathlib import Path as _Path
    import app.paths as _paths

    log = logging.getLogger("keyquorum")
    log.info(f"[USB] Installing binding overrides for user={username} dir={user_dir}")

    # >>> NEW: force portable mode so any paths.* that still branch on is_portable_mode() pick USB
    try:
        # user_dir = <USB>\KeyquorumPortable\Users\<user>
        portable_root = user_dir.parent.parent  # <USB>\KeyquorumPortable
        if (portable_root.name != "KeyquorumPortable") and (portable_root / "KeyquorumPortable").exists():
            portable_root = portable_root / "KeyquorumPortable"
        _paths.set_portable_root(portable_root)
        log.info(f"[USB] Portable root forced → {portable_root}")
    except Exception as e:
        log.warning(f"[USB] Could not force portable root: {e}")

    # Snapshot originals ONCE
    if not hasattr(_paths, "_KQ_ORIG_FUNCS") or not _paths._KQ_ORIG_FUNCS:
        _paths._KQ_ORIG_FUNCS = {
            "user_db_file": getattr(_paths, "user_db_file", None),
            "vault_file": getattr(_paths, "vault_file", None),
            "salt_file": getattr(_paths, "salt_file", None),
            "software_dir": getattr(_paths, "software_dir", None),
            "settings_dir": getattr(_paths, "settings_dir", None),
            "security_prefs_file": getattr(_paths, "security_prefs_file", None),
            "identities_file": getattr(_paths, "identities_file", None),
            "config_dir": getattr(_paths, "config_dir", None),
            "baseline_file": getattr(_paths, "baseline_file", None),
        }

    ORIG = _paths._KQ_ORIG_FUNCS  # shorthand

    # Helpers to get canonical file names using ORIGINAL path logic (non-recursive)
    def _name_userdb(u: str) -> str:
        return _Path(ORIG["user_db_file"](u, ensure_parent=False)).name

    def _name_vault(u: str) -> str:
        return _Path(ORIG["vault_file"](u, name_only=True)).name

    def _name_salt(u: str) -> str:
        return _Path(ORIG["salt_file"](u, name_only=True)).name

    def _name_ids(u: str) -> str:
        return _Path(ORIG["identities_file"](u, name_only=True)).name

    def _name_prefs(u: str) -> str:
        return _Path(ORIG["security_prefs_file"](u, name_only=True)).name

    def _name_baseline(u: str) -> str:
        return _Path(ORIG["baseline_file"](u, name_only=True)).name

    # Canonical subfolders for Phase-2
    MAIN    = user_dir / "Main"
    VAULT_D = MAIN / "Vault"
    KQSTORE = user_dir / "KQ_Store"
    CONFIG  = user_dir / "Config"
    SETDIR  = user_dir / "settings"
    SOFTDIR = user_dir / "Software"

    # --- Override implementations using user_dir (mirror Phase-2) ---
    def user_db_file_override(u: str, *, ensure_parent: bool = False, name_only: bool = False):
        fname = _name_userdb(u)
        if name_only:
            return fname
        p = MAIN / fname
        if ensure_parent:
            p.parent.mkdir(parents=True, exist_ok=True)
        return _Path(p)

    def vault_file_override(u: str, *, ensure_parent: bool = False, name_only: bool = False):
        fname = _name_vault(u)
        if name_only:
            return fname
        p = VAULT_D / fname
        if ensure_parent:
            p.parent.mkdir(parents=True, exist_ok=True)
        return _Path(p)

    def salt_file_override(u: str, *, ensure_parent: bool = False, name_only: bool = False):
        fname = _name_salt(u)
        if name_only:
            return fname
        p = KQSTORE / fname
        if ensure_parent:
            p.parent.mkdir(parents=True, exist_ok=True)
        return _Path(p)

    def identities_file_override(u: str, *, ensure_parent: bool = True, name_only: bool = False):
        fname = _name_ids(u)
        if name_only:
            return fname
        p = MAIN / fname
        if ensure_parent:
            p.parent.mkdir(parents=True, exist_ok=True)
        return _Path(p)

    def security_prefs_file_override(u: str, *, ensure_parent: bool = True, name_only: bool = False):
        fname = _name_prefs(u)
        if name_only:
            return fname
        p = CONFIG / fname
        if ensure_parent:
            p.parent.mkdir(parents=True, exist_ok=True)
        return _Path(p)

    def baseline_file_override(u: str, *, ensure_parent: bool = True, name_only: bool = False):
        fname = _name_baseline(u)
        if name_only:
            return fname
        p = CONFIG / fname
        if ensure_parent:
            p.parent.mkdir(parents=True, exist_ok=True)
        return _Path(p)

    def settings_dir_override(u: str, *, ensure_dir: bool = True):
        p = SETDIR
        if ensure_dir:
            p.mkdir(parents=True, exist_ok=True)
        return _Path(p)

    def software_dir_override(u: str, *, ensure_dir: bool = True):
        p = SOFTDIR
        if ensure_dir:
            p.mkdir(parents=True, exist_ok=True)
        return _Path(p)

    def config_dir_override(u: str | None = None, *, ensure_parent: bool = False):
        # Per-user config when u is provided, otherwise portable root Config
        p = CONFIG if u else user_dir.parent.parent / "Config"
        if ensure_parent:
            p.mkdir(parents=True, exist_ok=True)
        return _Path(p)

    # --- Install overrides into the active paths module ---
    _paths.user_db_file = user_db_file_override                # type: ignore
    _paths.vault_file = vault_file_override                    # type: ignore
    _paths.salt_file = salt_file_override                      # type: ignore
    _paths.identities_file = identities_file_override          # type: ignore
    _paths.security_prefs_file = security_prefs_file_override  # type: ignore
    _paths.baseline_file = baseline_file_override              # type: ignore
    _paths.settings_dir = settings_dir_override                # type: ignore
    _paths.software_dir = software_dir_override                # type: ignore
    _paths.config_dir = config_dir_override                    # type: ignore

    # Reflect USB users root for any code that inspects USERS_DIR
    try:
        _paths.USERS_DIR = user_dir.parent
    except Exception:
        pass

    # --- Reload modules that cache paths ---
    for mod_name in (
        "secure_audit",
        "security.secure_audit",
        "security.baseline_signer",
        "auth.identity_store",
        "auth.login_handler",
    ):
        try:
            mod = __import__(mod_name, fromlist=["_"])
            importlib.reload(mod)  # type: ignore
        except Exception:
            pass

    # --- Reload vault_store ---
    try:
        import vault_store as vstore
        importlib.reload(vstore)

        def _gp(u: str) -> str:
            return str(vault_file_override(u, ensure_parent=True))

        def _sp(u: str) -> str:
            return str(salt_file_override(u, ensure_parent=True))

        setattr(vstore, "get_vault_path", _gp)
        setattr(vstore, "get_salt_path",  _sp)

        def _load_user_salt_override(u: str) -> bytes:
            return _Path(_sp(u)).read_bytes()

        setattr(vstore, "load_user_salt", _load_user_salt_override)
        log.info("[USB] vault_store rebound successfully")
    except Exception as e:
        log.debug(f"[USB] vault_store reload failed: {e}")

    # --- Final: sanitize any legacy top-level 'Vault' that may have been created ---
    try:
        LEGACY_VAULT = user_dir / "Vault"
        MAIN = user_dir / "Main"
        VAULT_CANON = MAIN / "Vault"
        if LEGACY_VAULT.exists():
            log.info("[USB] Sanitizing legacy top-level 'Vault' → 'Main/Vault'")
            VAULT_CANON.mkdir(parents=True, exist_ok=True)
            for p in LEGACY_VAULT.iterdir():
                tgt = VAULT_CANON / p.name
                try:
                    if p.is_dir():
                        shutil.copytree(p, tgt, dirs_exist_ok=True)
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        shutil.copy2(p, tgt)
                        p.unlink(missing_ok=True)
                except Exception as _e:
                    log.warning(f"[USB] Vault sanitize move failed for {p}: {_e}")
            try:
                LEGACY_VAULT.rmdir()
            except Exception:
                pass
    except Exception as _e:
        log.debug(f"[USB] post-bind sanitize skipped: {_e}")
