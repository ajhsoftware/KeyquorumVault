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
import json, os
import datetime as dt
from typing import Dict, Any, Optional

# --- log ---
import logging
log = logging.getLogger("keyquorum")

# --- helpers ---
from app.paths import audit_tamper, config_dir
from pathlib import Path
from app.paths import (users_root, is_portable_mode, users_root, config_dir, )
from features.portable.portable_user_usb import install_binding_overrides
from auth.login.login_handler import set_user_setting, get_user_setting

# --- qtpy = pysider backend---
from qtpy.QtWidgets import QMessageBox, QCheckBox
from qtpy.QtCore import QCoreApplication


# =============================================================================
# --- language
# =============================================================================

def _tr(text: str) -> str:
    # context name can be anything stable, e.g. "MainWindow" or "Keyquorum"
    return QCoreApplication.translate("main", text)





# Single source of truth
try:
    from app.paths import config_dir
except Exception:
    def config_dir(username: str | None = None, *, ensure_parent: bool = False) -> Path:
        base = Path(os.getenv("APPDATA", "")) / "Keyquorum"
        p = base if not username else base / "Users" / username
        if ensure_parent:
            p.mkdir(parents=True, exist_ok=True)
        return p

def _binding_file() -> Path:
    cfg = config_dir(ensure_parent=True)
    cfg.mkdir(parents=True, exist_ok=True)
    return cfg / "portable_binding.json"

def _now_utc_iso() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def load_bindings() -> Dict[str, Any]:
    bf = _binding_file()
    if not bf.exists():
        return {"users": {}, "version": 2}
    try:
        return json.loads(bf.read_text(encoding="utf-8"))
    except Exception:
        return {"users": {}, "version": 2}

def save_bindings(data: Dict[str, Any]) -> None:
    bf = _binding_file()
    tmp = bf.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    os.replace(tmp, bf)

def set_user_usb_binding(username: str, usb_root: Path, user_dir: Path) -> None:
    data = load_bindings()
    data.setdefault("users", {})
    data["version"] = 2
    data["users"][username] = {
        "usb_root": str(Path(usb_root).resolve()),
        "user_dir": str(Path(user_dir).resolve()),
        "updated_utc": _now_utc_iso(),
    }
    save_bindings(data)

def get_user_usb_binding(username: str) -> Optional[Dict[str, Any]]:
    data = load_bindings()
    return (data.get("users") or {}).get(username)

def clear_user_usb_binding(username: str) -> None:
    data = load_bindings()
    users = data.get("users") or {}
    if username in users:
        del users[username]
        save_bindings(data)

def get_user_usb_dir(username: str) -> Optional[Path]:
    rec = get_user_usb_binding(username)
    if not rec:
        return None
    p = Path(rec.get("user_dir") or "")
    return p if p.exists() else None


def check_usb_binding(parent=None) -> bool:
    """
    Check if this installation is bound to a portable copy on a USB drive.

    Uses unified paths.py (config_dir()) instead of CONFIG_DIR.
    Returns True if either no binding exists or the USB is present.
    """
    bind_file = Path(config_dir()) / "portable_binding.json"
    if not bind_file.exists():
        return True

    try:
        info = json.loads(bind_file.read_text(encoding="utf-8"))
    except Exception:
        return True

    if not info.get("require_usb"):
        return True

    portable_root = Path(info.get("portable_root", ""))
    if portable_root.exists():
        return True

    # USB missing → prompt user
    QMessageBox.information(
        parent,
        _tr("Portable Vault Required"),
        (
            _tr("This installation is linked to a portable copy on a USB drive.\n"
            "Please insert the USB stick and relaunch Keyquorum.")
        ),
    )
    return False


def _maybe_install_binding_for(username: str):

    b = _compat_get_user_usb_binding(username) or {}
    if (b.get("username") or "").strip().lower() != (username or "").strip().lower():
        return

    user_dir = Path(b.get("user_dir") or "")
    try:
        if is_portable_mode() and users_root() == user_dir.parent:
            return
    except Exception:
        pass

    if user_dir.exists():
        install_binding_overrides(username, user_dir)
        log.info(f"[USB] On-demand binding activated for {username} @ {user_dir}")

def _compat_get_user_usb_binding(username: str):
    """
    Call portable_binding.get_user_usb_binding() whether it expects 0 args or (username).
    Returns {} on error.
    """
    import logging, inspect
    log = logging.getLogger("keyquorum")
    try:
        from features.portable.portable_binding import get_user_usb_binding as _get
    except Exception as e:
        log.debug(f"[USB] get_user_usb_binding import failed: {e}")
        return {}

    try:
        sig = inspect.signature(_get)
        if len(sig.parameters) == 0:
            # 0-arg API
            return _get()
        # else assume it wants username
        return _get(username)
    except TypeError:
        # Fallback if signature introspection lies in frozen builds
        try:
            return _get(username)
        except Exception:
            try:
                return _get()
            except Exception as e:
                log.debug(f"[USB] get_user_usb_binding compat failed: {e}")
                return {}
    except Exception as e:
        log.debug(f"[USB] get_user_usb_binding call failed: {e}")
        return {}

