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

"""
This module is currently being refactored and split into smaller parts.

At present, it still serves as both the main window implementation and a
central hub for application bootstrap logic, shared imports, and utility
wiring. This is a temporary arrangement and will be improved as the codebase
is further separated into clearer functional areas.

Current refactor goals:
- Move as much logic as possible out of the main window class
- Separate code by responsibility without breaking working behaviour
- Keep the application stable during the transition
- Improve maintainability, readability, and security

During this process, some duplicate or overlapping functions may still exist
across files. This is temporary and part of the staged refactor.

Current rough structure:
- app_window.py: main window class, bootstrap logic, imports, logging, paths,
  baseline handling, USB binding, and shared integration points
- app_window_ui.py: UI layout generated from the Qt Designer `.ui` file
- Other modules: gradually split out by feature and responsibility

This note is here to explain the temporary structure while the refactor is in progress.
"""


# ==============================
# --- sysimport/environ/pyside6 backend(important)/F401/
# ==============================

from unittest import skip
import _fbs_bootstrap
import hmac, hashlib
from app.platform_utils import open_path
from features.url.main_url import open_url
from app.qt_imports import *
from vault_store.soft_delete_ops import _pwlast_save, _pwlast_load
# Force QtPy to use PySide6 BEFORE importing qtpy
os.environ["QT_API"] = "pyside6"


# ==============================
# --- PySide6
# ==============================
from qtpy import PYSIDE6, API_NAME
assert PYSIDE6, f"[API NAME] QtPy backend is {API_NAME}, expected PySide6"
from app.single_app import get_app

# ==============================
# --- Dev
# ==============================
from app.dev import dev_ops
dev_ops.set_dev_values()
is_dev = dev_ops.dev_set

# ==============================
# - touchscreen frendly
# ==============================
from qtpy.QtCore import Qt
from qtpy import PYSIDE6

# Make Qt synthesize touch/mouse events both ways (helps hybrid devices)
try:
    from qtpy.QtWidgets import QApplication
    QApplication.setAttribute(Qt.AA_SynthesizeTouchForUnhandledMouseEvents, True)
    QApplication.setAttribute(Qt.AA_SynthesizeMouseForUnhandledTouchEvents, True)
except Exception:
    pass

# ---- Touch detection (Qt + Windows fallback) ----
def _qt_has_touch() -> bool:
    """Try multiple Qt bindings to detect any touch devices."""
    # Try PySide6 / PyQt6
    for mod, attr in (("PySide6.QtGui", "QTouchDevice"), ("PyQt6.QtGui", "QTouchDevice")):
        try:
            QTD = __import__(mod, fromlist=[attr]).__dict__.get(attr)
            if QTD and callable(getattr(QTD, "devices", None)):
                devs = QTD.devices()
                return bool(devs) and len(devs) > 0
        except Exception:
            pass
    # Try Qt5 (PySide2/PyQt5) API name
    for mod, attr in (("PySide2.QtGui", "QTouchDevice"), ("PyQt5.QtGui", "QTouchDevice")):
        try:
            QTD = __import__(mod, fromlist=[attr]).__dict__.get(attr)
            if QTD and callable(getattr(QTD, "devices", None)):
                devs = QTD.devices()
                return bool(devs) and len(devs) > 0
        except Exception:
            pass
    return False

def has_touch_device() -> bool:
    """Single entry point you can call anywhere."""  
    return _qt_has_touch() or _win_has_touch()

app = get_app()

from app.qt_imports import *

# --- logging ---
import app.kq_logging as kql
from app.kq_logging import (
    apply_debug_flag,
    get_logfile_path,)

from pathlib import Path
from app.paths import (
    log_dir, users_root, profile_pic,  
    vault_file, shared_key_file, catalog_file, salt_file, identities_file, breach_cache,
    debug_log_paths, is_portable_mode, users_root,
    config_dir, trash_path, pw_cache_file, vault_dir, vault_wrapped_file,
    user_log_file, user_db_file, LICENSES_DIR, 
    LICENSE_CACHE_DIR, ui_file, icon_file)

# per_user_db_file → user_db_file
def per_user_db_file(username: str, *, ensure_parent: bool = False, name_only: bool = False):
    # Delegate to the Phase-2 canonical API
    return user_db_file(username, ensure_parent=ensure_parent, name_only=name_only)

def per_user_root(username: str, *, ensure_parent: bool = False):
    p = users_root() / username
    if ensure_parent:
        p.mkdir(parents=True, exist_ok=True)
    return p
from features.portable.portable_user_usb import install_binding_overrides
from workers.worker_status import Worker 
from ui.frameless_window import FramelessWindowMixin
from security.preflight import (
    load_security_prefs, save_security_prefs, add_process_to_watch, add_allowlist_process,
    run_preflight_checks, ensure_preflight_defaults,)
from security.secure_audit import is_locked_out, log_event_encrypted
from auth.change_pw.change_password_dialog import ChangePasswordDialog
from security.security_prefs_dialog import SecurityPrefsDialog

from catalog_category.category_editor import patch_mainwindow_class
# --- passkey ---
import features.passkeys.capabilities as cap
import features.passkeys.passkeys_windows as pkwin

from auth.login.login_handler import (
     is_locked_out,
     _canonical_username_ci,
    get_user_setting, get_user_cloud,
    set_user_setting, get_user_record)

from catalog_category.catalog_user import (
    ensure_user_catalog_created,
    load_effective_catalogs_from_user,)

from catalog_category.my_catalog_builtin import CLIENTS, ALIASES, PLATFORM_GUIDE
from auth.identity_store import get_login_backup_count_quick, set_totp_secret, replace_backup_codes, mark_totp_header, verify_recovery_key
from auth.pw.password_generator import show_password_generator_dialog, generate_strong_password
from vault_store.vault_store import (
    add_vault_entry, load_vault, save_vault,)

# ==============================
# --- Third party link 
# ==============================
from functools import wraps
from typing import Optional
import weakref
import ctypes
from ctypes import wintypes
from urllib.parse import urlparse
import urllib.request, urllib.error
import http.client
import datetime as dt 
import time as _t
             
# ==============================
# --- Standard library, import at top(os, sys, traceback)
# ==============================
import re as _re
import tempfile
import json, socket, secrets
import subprocess
import string
from shutil import copy2
import hashlib
try:
    import winreg
except ImportError:
    winreg = None
try:
    import cv2  # OpenCV for QR decoding
except Exception:
    cv2 = None

# ==============================
# --- message ---
# ==============================
from ui.message_ops import show_message_vault_change, message_backup_error, show_message_user_login

# ==============================
# --- logging ---
# ==============================
# --- Logging bootstrap (unified paths) ---
from app.paths import log_dir



# Tell kq_logging where to write files (use the unified log_dir())
os.environ.setdefault("KEYQUORUM_LOG_DIR", str(log_dir()))

# Init logging
log = kql.setup_logging("keyquorum")
kql.install_global_excepthook(log)
try:
    kql.install_qt_message_logging(log)
except Exception:
    pass

# Keep console + debug level in sync with dev mode
from app.kq_logging import apply_debug_flag
apply_debug_flag(enabled=dev_ops.dev_set, keep_console=dev_ops.dev_set)


# --- Unified helpers (per-user logging + licensing + baseline wrappers) ---
import logging, os, json, hashlib, hmac

_KQ_USER_HANDLER = None  # type: logging.Handler | None

def _find_file_handler_for(path: Path):
    for h in logging.getLogger().handlers:
        if isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None):
            try:
                if Path(h.baseFilename) == path:
                    return h
            except Exception:
                pass
    return None

def switch_to_user_log(username: str) -> None:
    """Add a per-user FileHandler without removing your app's base handler."""
    global _KQ_USER_HANDLER
    root = logging.getLogger()
    app_log = logging.getLogger("keyquorum")
    try:
        # Preferred: paths.user_log_file(); Fallback: log_dir()/users/<user>.log
        try:
            target = Path(user_log_file(username, ensure_parent=True))
            log.info(f"LOG DIR: {target}")
        except Exception:
            target = Path(log_dir()) / "users" / f"{username}.log"
            log.info(f"LOG DIR: {target}")
            target.parent.mkdir(parents=True, exist_ok=True)
        
        existing = _find_file_handler_for(target)
        
        if existing:
            _KQ_USER_HANDLER = existing
            app_log.info("%s using existing per-user log → %s", kql.i("ok"), target)
            return

        if _KQ_USER_HANDLER:
            root.removeHandler(_KQ_USER_HANDLER)
            _KQ_USER_HANDLER.close()
            _KQ_USER_HANDLER = None

        fh = logging.FileHandler(target, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        fh.setLevel(root.getEffectiveLevel())
        root.addHandler(fh)
        _KQ_USER_HANDLER = fh
        app_log.info("%s switched to per-user log → %s", kql.i("ok"), target)
    except Exception as e:
        app_log.error("%s failed switching to user log: %s", kql.i("err"), e)

def restore_app_log() -> None:
    """Remove only the per-user handler; keep the app's base handler."""
    global _KQ_USER_HANDLER
    root = logging.getLogger()
    app_log = logging.getLogger("keyquorum")
    try:
        if _KQ_USER_HANDLER:
            root.removeHandler(_KQ_USER_HANDLER)
            _KQ_USER_HANDLER.close()
            _KQ_USER_HANDLER = None
        app_log.info("%s restored application log", kql.i("ok"))
    except Exception as e:
        app_log.error("%s failed restoring app log: %s", kql.i("err"), e)

# ==============================
# Baseline convenience
# ==============================
try:
    from app.paths import is_portable
    _mode = 'portable' if is_portable() else 'installed'
except Exception:
    _mode = 'installed'

def _bootstrap_usb_binding_if_any():
    from pathlib import Path
    try:
        # use compat shim; username isn't known yet, pass "" (ignored if 0-arg API)
        binding = _compat_get_user_usb_binding("")
        if not binding:
            log.info(f"{kql.i('portable')} [USB] No persisted USB binding found.")
            return

        username = (binding.get("username") or "").strip()
        user_dir = Path(binding.get("user_dir") or "")
        if username and user_dir.exists():
            install_binding_overrides(username, user_dir)
            log.info(f"{kql.i('portable')} [USB] Boot binding applied → {user_dir} (user={username})")
        else:
            log.warning(f"[USB] Persisted binding invalid: user={username} dir={user_dir}")
    except Exception as e:
        log.warning(f"[USB] Boot binding failed: {e}")

def _compat_get_user_usb_binding(_username: str = "") -> dict | None:
    try:
        from features.portable.portable_manager import get_persisted_boot_binding
    except Exception:
        return None

    try:
        return get_persisted_boot_binding()
    except Exception:
        return None

try:
    _bootstrap_usb_binding_if_any()
except Exception as e:
    log.error(f"{kql.i('build')} [ERROR] Bootstrap USB Binding Error {e}")

# app version
from app.basic import get_app_version
get_app_version()
debug_log_paths()
# Directory that contains the current log file
LOG_DIR_ = str(Path(get_logfile_path()).parent)
log.debug(f"{kql.i('path')} [LOG] Open Path {get_logfile_path()}")

# ==============================
# - bridge
# ==============================
from bridge.bridge_ops import ensure_origins_file


# ==============================
# --- uppdate windows header with tint
# ==============================
if sys.platform == "win32":
    _DWMWA_USE_IMMERSIVE_DARK_MODE_TRY = (20, 19)
    _DWMWA_CAPTION_COLOR = 35  # Win11+
    _DWMWA_TEXT_COLOR    = 36  # Win11+
    _DWORD = wintypes.DWORD

    def _COLORREF(r, g, b):
        # Windows COLORREF is 0x00BBGGRR; the RGB() macro lays it out like this:
        return _DWORD(int(r) | (int(g) << 8) | (int(b) << 16))

    def set_win_titlebar(win, *, dark: bool, caption_rgb=None, text_rgb=None):
        """
        Enable Windows dark titlebar; optionally set caption/text colors (Win11+).
        Silently no-ops on unsupported systems.
        """
        try:
            hwnd = int(win.winId())
            DwmSetWindowAttribute = ctypes.windll.dwmapi.DwmSetWindowAttribute

            # 1) Toggle immersive dark mode for the title bar
            val = _DWORD(1 if dark else 0)
            for attr in _DWMWA_USE_IMMERSIVE_DARK_MODE_TRY:
                try:
                    DwmSetWindowAttribute(hwnd, attr, ctypes.byref(val), ctypes.sizeof(val))
                    break
                except Exception:
                    continue

            # 2) set explicit colors (Windows 11+ only)
            if caption_rgb is not None:
                col = _COLORREF(*caption_rgb)
                DwmSetWindowAttribute(hwnd, _DWMWA_CAPTION_COLOR, ctypes.byref(col), ctypes.sizeof(col))
            if text_rgb is not None:
                col = _COLORREF(*text_rgb)
                DwmSetWindowAttribute(hwnd, _DWMWA_TEXT_COLOR, ctypes.byref(col), ctypes.sizeof(col))
        except Exception:
            pass

# ==============================
# --- Login
# ==============================
def _read_user_salt(username: str) -> bytes:
    """Read-only salt load via new paths."""
    from app.paths import salt_file
    try:
        p = salt_file(username)
        return p.read_bytes() if p.exists() else b""
    except Exception:
        return b""

# ==============================
# --- language
# ==============================

def _tr(text: str) -> str:
    return QCoreApplication.translate("main", text)

def _load_ui_language() -> str:
    from ui.ui_language import _load_ui_language as __load_ui_language
    return __load_ui_language()


# ==============================
# --- first time run wizard
# ==============================

# --- Existing users discovery (new per-user layout; no mkdirs) ---
def _list_existing_users() -> list[str]:
    from app.paths import read_only_paths
    """
    Return usernames that actually have a readable per-user DB in the new layout.
    - Looks under paths.users_root() (portable -> USB, installed -> Local)
    - Treats a user as valid only if get_user_record(username) returns a non-empty dict
    - Never creates directories during detection
    """
    users: list[str] = []
    try:
        with read_only_paths(True):  # ensure no accidental mkdirs during scan
            root = users_root(ensure=False)
            if not root.is_dir():
                return []

            for entry in root.iterdir():
                if not entry.is_dir():
                    continue
                u = entry.name.strip()
                if not u or u.startswith("."):
                    continue

                # Must have a per-user DB file in the new location
                db_path = user_db_file(u, ensure_parent=False)
                if not Path(db_path).exists():
                    continue

                try:
                    rec = get_user_record(u)
                    if isinstance(rec, dict) and rec:
                        users.append(u)
                except Exception:
                    continue

        users.sort(key=str.lower)
        return users
    except Exception:
        return []

def _needs_first_run() -> bool:
    """
    True if no valid users are discovered in the new per-user structure.
    Uses read_only probe (won't create folders).
    """
    try:
        return len(_list_existing_users()) == 0
    except Exception:
        return True


# - how long to wait before showing recovery or failed screen 
# PRESENCE_GRACE_SECS = 25.0           

# --- backup code + recovery key verification (login-backup, not TOTP) ---
from auth.login.login_handler import use_backup_code as _use_backup_code  # uses identity store

def _verify_and_consume_login_backup_with_pw(username: str, password_for_identity: str, code: str) -> bool:
    """
    Validate and consume a LOGIN backup code stored in the identity file.
    Requires the user's account password to open the identity payload.
    """
    try:
        return bool(_use_backup_code(
            username,
            code,
            "login",
            password_for_identity=password_for_identity or ""
        ))
    except Exception as e:
        log.info(f"[2FA] login-backup check failed: {e}")
        return False

def _verify_recovery_key(username: str, recovery_key: str) -> bool:
    from auth.pw.utils_recovery import _verify_recovery_key_local
    return bool(_verify_recovery_key_local(username, recovery_key))



# ==============================
# --- Touch Finder --- (Tuchscreen)
# ==============================
def _win_has_touch() -> bool:
    """Best-effort Windows touch detection via GetSystemMetrics."""
    try:
        import sys, ctypes
        if sys.platform != "win32":
            return False
        user32 = ctypes.windll.user32
        SM_DIGITIZER = 94
        SM_MAXIMUMTOUCHES = 95
        NID_READY = 0x0080
        dig = user32.GetSystemMetrics(SM_DIGITIZER)
        mt  = user32.GetSystemMetrics(SM_MAXIMUMTOUCHES)
        return bool(dig & NID_READY) and (mt or 0) > 0
    except Exception:
        return False
    

# ==============================
# --- Manifest Mismatch ---
# ==============================
def show_error_and_exit(message):
    QMessageBox.critical(None, "Security Alert ❌ Exiting !!!", message)
    sys.exit(1)

def log_manifest_tamper(reason: str, username: str | None = None) -> None:
    """
    Append a manifest tamper line to the per-user (or global) tamper log.
    Uses Phase-2 paths.audit_tamper().
    """
    # If don't know the user yet (pre-login), write to a global log in config dir.
    if not username:
        # Use a single shared file for pre-login events
        global_log = Path(config_dir("global", ensure_dir=True)) / "manifest_tamper.log"
        global_log.parent.mkdir(parents=True, exist_ok=True)
        with open(global_log, "a", encoding="utf-8") as f:
            f.write(f"[{dt.datetime.now().isoformat(timespec='seconds')}] [TAMPER] {reason}\n")
        return

    # Per-user tamper file (Phase-2)
    p = Path(audit_tamper(username, ensure_dir=True, name_only=False))
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(f"[{dt.datetime.now().isoformat(timespec='seconds')}] [TAMPER] {reason}\n")

# ==============================
# --- baseline ---
# ==============================

from app.paths import audit_tamper, config_dir
from security.baseline_signer import verify_baseline, ensure_baseline
from security.secure_audit import log_event_encrypted


def update_baseline(username: str, *, verify_after: bool = True, who: str = "Unknow") -> bool:
    username = (username or "").strip()
    if not username:
        log.error("[baseline] (In Settings) update_baseline called with empty username")
        return False
    try:
        # Load salt
        try:
            salt = _load_vault_salt_for(username)
        except Exception as e:
            log.error(f"{kql.i('err')} [baseline] (In Settings) failed to load salt for {username}: {e}")
            salt = b""

        # Build full tracked file set (mandatory + optional)
        files = _baseline_tracked_files(username)
        log.info(f"[baseline] files : to update:{files}")

        log.info(f"{kql.i('info')} [baseline] (In Settings) updating for user={username}")
       
        # Write baseline
        ensure_baseline(username, salt, files)
        log.info(f"{kql.i('ok')} [baseline] (In Settings) wrote baseline (files={len(files)})")

        # Log all baseline
        msg = "Who:" + f"{who}"
        log_event_encrypted(username, "📜 [Baseline Update]", msg)
        log.info(f"📜 [Baseline Update] {msg},->Verify on Update->{verify_after} ")
        
        if verify_after:
            # post-verify
            changed, missing, new, mac_ok = verify_baseline(username, salt, files)
            log.info(
                f"{kql.i('check')} [baseline] (In Settings) post-verify: mac_ok={mac_ok} "
                f"changed={len(changed)} missing={len(missing)} new={len(new)}"
            )
            if changed:
                log.debug(f"{kql.i('warn')} [baseline] (In Settings) changed: {changed}")
            if missing:
                log.debug(f"{kql.i('warn')} [baseline] (In Settings) missing: {missing}")
            if new:
                log.debug(f"{kql.i('ok')} [baseline] (In Settings) new: {new}")
        return True

    except Exception as e:
        log.error(f"{kql.i('err')} [baseline] (In Settings) update failed for {username}: {e}")
        return False

def _load_vault_salt_for(user: str) -> bytes:
    """Load the master salt for baseline/integrity.

    Preferred: identity store header (user .kq_id).
    Fallback: legacy .slt file.

    NOTE: We only *read* here. Any migration/cleanup should happen after a
    successful login, not inside baseline code.
    """
    u = (user or "").strip()
    if not u:
        return b""

    # Unified reader (identity-store first, fallback to legacy .slt)
    try:
        from auth.salt_file import read_master_salt_readonly
        salt = read_master_salt_readonly(u) or b""
        if salt:
            return salt
    except Exception as e:
        log.debug(f"[baseline] salt read failed for {u}: {e}")

    # Legacy: read salt file directly
    try:
        log.debug(
            f"[USB] salt_file fn id={id(salt_file)} mode={is_portable_mode()} users_root={users_root()}"
        )
        sp = salt_file(u, ensure_parent=False)
        return sp.read_bytes()
    except Exception:
        return _read_user_salt(u) or b""

def _baseline_tracked_files(username: str) -> list[str]:
    from app.paths import security_prefs_file, profile_image_file
    """
    Build the list of files used for per-user integrity checks.

    For now we deliberately *exclude* the per-user catalog/user_db file
    (KQ_Dev_KQ.kq), because it is touched frequently by the category editor
    and causes constant 'CHANGED' noise. We still protect the critical
    crypto state: vault, salt, identity, and prefs.
    """
    username = (username or "").strip()
    files: list[str] = []

    # --- MANDATORY FILES (crypto-critical) ---
    mandatory_paths: list[Path] = [
        vault_file(username, ensure_parent=False),
        salt_file(username, ensure_parent=False),
        identities_file(username, ensure_parent=False),
        user_db_file(username, ensure_parent=False),
    ]

    for p in mandatory_paths:
        log.debug(f"🧭 [baseline tracked files]: vault file:{str(p)}")
        files.append(str(p))   # always tracked, even if currently missing

    # --- OPTIONAL FILES (only if present) ---
    optional_paths: list[Path] = [
        security_prefs_file(username, ensure_parent=False, name_only=False),
        catalog_file(username, ensure_parent=False),         
        shared_key_file(username, ensure_parent=False),
        profile_image_file(username, ensure_parent=False),
        breach_cache(username, ensure_parent=False),
        profile_pic(username),
        trash_path(username, ensure_parent=False),
        profile_image_file(username, ensure_parent=False),
        pw_cache_file(username, ensure_parent=False),
        vault_wrapped_file(username, ensure_parent=False),
    ]

    for p in optional_paths:
        if p and isinstance(p, Path) and p.exists():
            log.debug(f"🧭 [baseline tracked files]: vault file:{str(p)}")
            files.append(str(p))
    return files

# ==============================
# --- USB Binding (unified paths) ---
# ==============================

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
            return _get(username)
    except TypeError:       
        try:
            return _get()
        except Exception as e:
            log.debug(f"[USB] get_user_usb_binding compat failed: {e}")
            return {}
    except Exception as e:
        log.debug(f"[USB] get_user_usb_binding call failed: {e}")
        return {}

def notify_usb_loaded_once(parent, username: str) -> None:
    """
    If running from USB, show a one-time notice with a 'Don't show again' checkbox.
    Persists a per-user suppress flag. Safe to call multiple times.
    """
    # Only show if actually in portable mode (USB)
    try:
        if not is_portable_mode():
            return
    except Exception:
        return

    # Read "don't show again" flag (prefer app's user settings; fallback to QSettings)
    def _get_suppress(u: str) -> bool:
        try:
            return bool(get_user_setting(u, "suppress_usb_notice", False))
        except Exception:
            # Fallback to QSettings
            try:
                from qtpy.QtCore import QSettings
                s = QSettings("AJH Software", "Keyquorum")
                return s.value(f"{u}/suppress_usb_notice", False, type=bool)
            except Exception:
                return False

    def _set_suppress(u: str, val: bool) -> None:
        try:
            # Prefer app's setter if available
            set_user_setting(u, "suppress_usb_notice", bool(val))
            return
        except Exception:
            pass
        try:
            # Fallback to QSettings
            from qtpy.QtCore import QSettings
            s = QSettings("AJH Software", "Keyquorum")
            s.setValue(f"{u}/suppress_usb_notice", bool(val))
        except Exception:
            pass

    if _get_suppress(username):
        return

    # Build the dialog
    text = (
        "You have loaded Keyquorum from a USB drive.\n\n"
        "If you plan to sign in to a local (installed, non-portable) user next, "
        "please restart the app and unplug the USB before logging in."
    )

    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Information)
    box.setWindowTitle(parent.tr("Running from USB"))
    box.setText(text)
    box.setStandardButtons(QMessageBox.Ok)

    chk = QCheckBox(parent.tr("Don't show this again"))
    box.setCheckBox(chk)
    box.exec_()

    _set_suppress(username, bool(chk.isChecked()))
    log.info("[USB] notice shown (suppress=%s)", bool(chk.isChecked()))

# ==============================
# --- Migrating Vault To USB ---
# ==============================
class MigrationPopup(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Migrating to USB"))
        self.setMinimumWidth(300)

        layout = QVBoxLayout(self)
        self.label = QLabel("Migrating your vault to USB drive...\nPlease wait.", self)
        self.progress = QProgressBar(self)
        self.progress.setRange(0, 0)  # indefinite spinner
        layout.addWidget(self.label)
        layout.addWidget(self.progress)

def show_progress_popup(parent):
    
    msg = QMessageBox(parent)
    msg.setWindowTitle(parent.tr("Keyquorum"))
    msg.setText(parent.tr("Migrating vault to USB..."))
    msg.setIcon(QMessageBox.Icon.Information)
    msg.setStandardButtons(QMessageBox.StandardButton.NoButton)
    msg.show()
    return msg

def fade_out_popup(msg_box):
    effect = QGraphicsOpacityEffect()
    msg_box.setGraphicsEffect(effect)

    anim = QPropertyAnimation(effect, b"opacity")
    anim.setDuration(800)
    anim.setStartValue(1)
    anim.setEndValue(0)
    anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
    anim.finished.connect(msg_box.close)
    anim.start()

class USBMigrator(QObject):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    file_copied = pyqtSignal(str)

    def __init__(self, source: str, target: str):
        super().__init__()
        self.source = source
        self.target = target

    def run(self):
        try:
            for root, dirs, files in os.walk(self.source):
                rel_path = os.path.relpath(root, self.source)
                dest_dir = os.path.join(self.target, rel_path)
                os.makedirs(dest_dir, exist_ok=True)

                for file in files:
                    src_file = os.path.join(root, file)
                    dest_file = os.path.join(dest_dir, file)
                    copy2(src_file, dest_file)
                    self.file_copied.emit(file)

            if QThread.currentThread().isRunning():
                self.finished.emit(f"✅ Migration complete at:\n{self.target}")

        except Exception as e:
            self.error.emit(f"❌ Migration failed:\n{str(e)}")



class PortableBuildWorker(QObject):
    finished = pyqtSignal(bool, str)

    def __init__(self, drive: str):
        super().__init__()
        self.drive = drive

    def run(self):
        from pathlib import Path
        try:
            from features.portable.portable_manager import build_portable_app
            ok = bool(build_portable_app(None, Path(self.drive), show_ui=False))
            if ok:
                msg = f"Portable app updated successfully.\n\nLocation:\n{self.drive}"
            else:
                msg = "Portable rebuild failed. Please check the log for details."
            self.finished.emit(ok, msg)
        except Exception as e:
            try:
                log.error(f"[PORTABLE] build_portable_app worker failed: {e}")
            except Exception:
                pass
            self.finished.emit(False, str(e))

# ==============================
# --- Resource Paths ---
# ==============================
def _global_excepthook(exc_type, exc_value, exc_tb):
    tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    log.debug(str(tb))

    try:
        QMessageBox.critical(None, "Unhandled Error", tb)
    except Exception:
        pass

sys.excepthook = _global_excepthook


# ==============================
# --- Clipboard Safty Check History Is On ---
# ==============================
def _win_clipboard_risk_state() -> dict:
    from features.clipboard.secure_clipboard import _win_clipboard_risk_state as __win_clipboard_risk_state
    return __win_clipboard_risk_state()
    
def maybe_warn_windows_clipboard(username: str, copy=True) -> None:
    from ui.ui_flags import maybe_warn_windows_clipboard as _maybe_warn_windows_clipboard
    return _maybe_warn_windows_clipboard(copy)

def secure_copy(text: str, ttl_ms: int = None, username:str = None):
    from features.clipboard.secure_clipboard import secure_copy as _secure_copy
    return _secure_copy(text, ttl_ms, username)


# ==============================
# --- URL ---
# ==============================
def _ui_async(fn):
        try:
            QtCore.QTimer.singleShot(0, fn)
        except Exception:
            pass

def open_path_in_explorer(p: Path | str):
    p = Path(p)
    p.mkdir(parents=True, exist_ok=True)
    try:
        if sys.platform.startswith("win"):
            open_path(str(p))
        elif sys.platform == "darwin":
            subprocess.run(["open", str(p)])
        else:
            subprocess.run(["xdg-open", str(p)])
    except Exception:
        # fall back to file://
        open_url(p.as_uri())

# ==============================
# --- Helpers for create account and app ---
# ==============================

def _mask_secret(s: str | None) -> str | None:    # - make secert 
            if not s: return None
            return (s[:4] + ("*" * max(0, len(s) - 6)) + s[-2:]) if len(s) > 6 else "***"

def center_on_screen(w):
    scr = w.screen() or QApplication.primaryScreen()
    geo = scr.availableGeometry() if scr else QApplication.desktop().availableGeometry(w)
    w.resize(w.size())  # keep current size, but ensure frameGeometry is valid
    w.move(
        geo.x() + (geo.width()  - w.frameGeometry().width())  // 2,
        geo.y() + (geo.height() - w.frameGeometry().height()) // 2,
    )

# ==============================
# --- Main Values ---
# ==============================
from features.url.main_url import SITE_HELP, PRIVACY_POLICY

# ----------------------------------------
# --- Touch CSS (one place) ---
_TOUCH_MARKER = "/*__TOUCH_MODE__*/"

_TOUCH_CSS = """
* { font-size: 11pt; }
QPushButton, QToolButton { min-height: 40px; padding: 8px 14px; }
QComboBox { min-height: 26px; padding: 4px 8px; }                      /* sane default for touch */
QCheckBox::indicator, QRadioButton::indicator { width: 22px; height: 22px; }
QSlider::handle:horizontal { width: 26px; margin: -8px 0; }
QSlider::handle:vertical   { height: 26px; margin: 0 -8px; }
QScrollBar:vertical { width: 18px; }
QScrollBar:horizontal { height: 18px; }
QMenu { padding: 6px; }
QMenu::item { padding: 8px 16px; }
""" + _TOUCH_MARKER


QWIDGETSIZE_MAX = 16777215  # Qt's max widget size

# Tweak these to taste
LOGIN_SIZE = QSize(400, 620)  # - w, h
VAULT_SIZE = QSize(1000, 400) # - w, h



# ==============================
# --- Software/Install --------------------------------

def _expand_path(p: str) -> str:
    if not p:
        return ""
    # Expand %VARS% and ~
    p = os.path.expandvars(os.path.expanduser(p))
    # Normalise and return
    return os.path.normpath(p)

def _is_executable_path(p: str) -> bool:
    if not p:
        return False
    p = _expand_path(p)
    # Accept .exe, .lnk, .bat, .cmd
    return os.path.exists(p) and os.path.splitext(p)[1].lower() in (".exe", ".lnk", ".bat", ".cmd")

def _reveal_in_explorer(p: str):
    try:
        p = _expand_path(p)
        if os.path.isdir(p):
            subprocess.Popen(["explorer", p])
        elif os.path.isfile(p):
            subprocess.Popen(["explorer", "/select,", p])
    except Exception as e:
        log.info(f"[WARN] reveal failed: {e}")

def run_software_exec(exec_path: str) -> bool:
    """
    Launch the given executable (exe/lnk/bat/cmd).
    Returns True if started, else False.
    """
    try:
        p = _expand_path(exec_path)
        if not _is_executable_path(p):
            return False
        # Use os.startfile for Windows shell associations
        open_path(p)  # nosec - user-triggered
        return True
    except Exception as e:
        log.info(f"[WARN] run_software_exec: {e}")
        return False

# ==============================
# --- (UI) Main App ---
# ==============================
class KeyquorumApp(QMainWindow, FramelessWindowMixin,):
  
    # ==============================
    # --- __init__ Main App ----------------
    # ==============================

    def init_catalogs_for_user(self, username: str):
        h = getattr(self, "core_session_handle", None)

        if isinstance(h, int) and h:
            from catalog_category.catalog_category_ops import _load_catalog_effective
            self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE, _, _ = _load_catalog_effective(self, username)
            return

        ensure_user_catalog_created(username, CLIENTS, ALIASES, PLATFORM_GUIDE)
        self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE, _ = load_effective_catalogs_from_user(
            username, CLIENTS, ALIASES, PLATFORM_GUIDE
        )

    def __init__(self):
        super().__init__()

        # ==============================
        # Session key state (must always exist; DPAPI/Yubi flows may set later)
        # ==============================
        self.vault_unlocked = False
        self._login_requires_yubi_wrap = False
     

        # ==============================
        # Language startup (prefer global file over user_db)
        # ==============================
        ui_lang = _load_ui_language()
        if not ui_lang:
            ui_lang = self._startup_language_code()                     # fallback to old per-user/global stored system
        try:                                                            
            self._install_translator_for_code(ui_lang, persist=False)   # Apply translator right now
        except Exception as e:
            log.warning(f"[LANG] failed to apply startup language: {e}")

        # ==============================
        # --- load UI via unified resource lookup (no RES_DIR) ---
        # ==============================
        try:
            ui_path = ui_file("keyquorum_ui")
            uic.loadUi(str(ui_path), self)
            # force retranslation
            
            self.setWindowIcon(QIcon(str(icon_file("64.ico"))))
            log.debug(f"{kql.i('build')} UI Loaded")
        except Exception as e:
            log.error(f"{kql.i('err')} Failed to load UI: {e}")
            raise

        # ==============================
        # bridge
        # ==============================
        ensure_origins_file()

        # ==============================
        # Security Center: Vault Security Update button (added in UI)
        # ==============================
        try:
            btn = getattr(self, "vault_security_update", None)
            if btn is not None and hasattr(btn, "clicked"):
                btn.clicked.connect(self.on_vault_security_update_clicked)
        except Exception:
            pass
        
        # ==============================
        # frameless/window chrome
        # ==============================
        self._init_frameless("Keyquorum Vault", use_translucency=False, glow=False)

        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setAutoFillBackground(True)
        pal = self.palette()
        pal.setColor(self.backgroundRole(), QColor(18, 18, 18))  # dark base
        self.setPalette(pal)

        # Global settings (per machine/user, not per Keyquorum account)
        self.settings = QSettings("AJH Software", "Keyquorum Vault")

        # Load last theme without touching user_db
        last_theme = self.settings.value("ui/last_theme", "dark") 
        self._current_theme = None  # track current so don’t re-apply for no reason
        self.apply_theme(last_theme, initial=True)

        log.debug(f"{kql.i('build')} Apply App")

        self.setFixedSize(380, 600)         # set initial size (Login Box)

        # ==============================
        # -- new import
        # ==============================
        from ui.ui_bind import bind_all

        # ==============================
        # init internals
        # ==============================
        bind_all(self)       # link Ui buttons, text, menu       

        # --- Reminders button (optional UI element) ---
        try:
            btn = getattr(self, "reminder_btn", None)
            if btn is not None and hasattr(btn, "clicked"):
                try:
                    btn.clicked.disconnect()
                except Exception:
                    pass
                btn.clicked.connect(self.open_reminders_dialog)
        except Exception:
            pass
        
        # ==============================
        # Category Editor Hooks
        # ==============================

        try:
            patch_mainwindow_class(KeyquorumApp)
        except Exception as e:
            log.error(f"{kql.i('err')} [ERROR] Category editor hooks patch failed: {e}")

        # ==============================
        # enable/disable touch mode
        # ==============================
        self._enable_touch_mode(force=False)
        if not has_touch_device():
            try:
                self._enable_touch_mode(force=False)
                self.tuchmode_.hide()
                self.tuchmode_2.hide()
            except Exception:
                pass


        # ==============================
        # ----- login widgets toggle together -----
        # ==============================
        self.loginWidgets = [
            self.loginTitle,
            self.usernameField,
            self.passwordField,
            self.rememberDeviceCheckbox,
            self.loginButton,
            self.createAccountButton,
        ]
        self.update_portable_actions()

        # Remember-this-device checkbox availability/state (Windows DPAPI)
        try:
            from auth.windows_hello.windows_hello_dpapi import dpapi_available
            self.rememberDeviceCheckbox.setEnabled(bool(dpapi_available()))
            # wire refresh
            try:
                self.usernameField.textChanged.disconnect(self._refresh_remember_device_checkbox)
            except Exception:
                pass
            self.usernameField.textChanged.connect(self._refresh_remember_device_checkbox)

            self._refresh_remember_device_checkbox()

        except Exception as e:
            log.error(f"[ERROR] rememberDeviceCheckbox {e}")

        # ==============================
        # Position avatar relative to username field
        # ==============================
        try:
            username_geo = self.usernameField.geometry()
            x = username_geo.right() + 50
            y = username_geo.top()
            self.loginPicLabel.move(x, y)
        except Exception:
            pass

        # ==============================
        # Initially show login and hide tabs
        # ==============================
        self.show_login_ui()

        # ==============================
        # Table selection behavior
        # ==============================
        if self.vaultTable is not None:
            self.vaultTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
            self.vaultTable.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
            self.vaultTable.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.vaultTable.setSelectionMode(QAbstractItemView.ExtendedSelection)

        # ==============================
        # Extend category list, remove obsolete item, refresh list
        # ==============================
        if self.categorySelector_2:
            existing = [self.categorySelector_2.itemText(i) for i in range(self.categorySelector_2.count())]
            if "Login Reports" in existing:
                idx = self.categorySelector_2.findText("Login Reports")
                if idx >= 0:
                    self.categorySelector_2.removeItem(idx)
            self.refresh_category_selector()
        
        # ==============================
        # ---------------- Theme Selector ----------------
        # ==============================
                
        if self.themeSelector:
            legacy_alias = {
                "Blue Mode":   "Light Blue (Color)",
                "Gray Mode":   "Light Gray (Color)",
                "Purple Mode": "Light Purple (Color)",
                "Green Mode":  "Light Green (Color)",
            }
            cur = self.themeSelector.currentText().strip()
            if cur in legacy_alias:
                idx = self.themeSelector.findText(cur)
                if idx >= 0:
                    self.themeSelector.setItemText(idx, legacy_alias[cur])

            desired = [
                "System Default",
                "Light Mode",
                "Dark Mode",
                # Light accents
                "Light Blue (Light)",  "Light Blue (Color)",  "Light Blue (Deep)",
                "Light Purple (Light)","Light Purple (Color)","Light Purple (Deep)",
                "Light Green (Light)", "Light Green (Color)", "Light Green (Deep)",
                "Light Gray (Light)",  "Light Gray (Color)",  "Light Gray (Deep)",
                # Dark accents
                "Dark Blue (Light)",   "Dark Blue (Color)",   "Dark Blue (Deep)",
                "Dark Purple (Light)", "Dark Purple (Color)", "Dark Purple (Deep)",
                "Dark Green (Light)",  "Dark Green (Color)",  "Dark Green (Deep)",
                "Dark Gray (Light)",   "Dark Gray (Color)",   "Dark Gray (Deep)",
            ]
            existing_set = {self.themeSelector.itemText(i) for i in range(self.themeSelector.count())}
            for label in desired:
                if label not in existing_set:
                    self.themeSelector.addItem(label)
            self.themeSelector.currentTextChanged.connect(self.apply_theme)

        # ==============================
        # Profile picture controls
        # ==============================
        self.init_profile_picture(self.profile_layout)

        # ==============================
        # Main tab
        # ==============================
        self.mainTabs: QTabWidget = self.findChild(QTabWidget, "mainTabs")
        self.mainTabs.setCurrentIndex(0)
        ## NoteRemove self._connect_ui_scale_controls()


        # ==============================
        # status task start
        # ==============================
        self.set_status_txt(self.tr("Loading components…"))

        # ==============================
        # Refresh category-dependent UI
        # ==============================
        self.refresh_category_dependent_ui()

        # ==============================
        # Init tabs/features
        # ==============================
        self._init_auto_sync()
      
        self.software_root = self._init_software_root()
        
        # ==============================
        # defer thread start until after showEvent
        # ==============================
        QTimer.singleShot(100, self.start_long_task)

    # ==============================
    # --- Restart App ---
    # ==============================
    def _restart_application(self):
        """
        Attempt to restart the application in-place.
        Works for both dev (python main.py) and frozen .exe.
        """
        try:
            log.info("%s [LANG] attempting to logout user", kql.i("build"))
            self.logout_user()
            log.info("%s [LANG] attempting app restart after language change", kql.i("build"))
            python = sys.executable
            os.execl(python, python, *sys.argv)
        except Exception as e:
            log.error("%s [LANG] restart failed, quitting instead: %s", kql.i("err"), e)
            app = QApplication.instance()
            if app is not None:
                app.quit()

    # ==============================
    # --- Security Center tab Split ---
    # ==============================

    def _sc_on_progress(self, msg: str):
        # Runs on GUI thread (Qt signal); safe to touch UI
        self.set_status_txt(self.tr(msg))
  
    def _sc_on_finished(self, data: dict | None = None, error: object | None = None) -> None:
        """Security Center worker completion handler.
        NOTE: the background worker emits (results, error)."""

        from features.security_center.security_center_ui import _sc_on_finished as __sc_on_finished
        return __sc_on_finished(self, data, error)

    def _run_security_center_scan(self):
        from features.security_center.security_center_ui import _run_security_center_scan as __run_security_center_scan
        return __run_security_center_scan(self)

    def on_security_refresh_clicked(self) -> None:
        from features.security_center.security_center_ui import on_security_refresh_clicked as _on_security_refresh_clicked
        return _on_security_refresh_clicked(self)

    def _update_security_vault_section(self, username: str) -> bool:
        from features.security_center.security_center_ui import _update_security_vault_section as __update_security_vault_section
        return __update_security_vault_section(self, username)
       
    def _update_security_clipboard_section(self) -> bool:
        from features.security_center.security_center_ui import _update_security_clipboard_section as __update_security_clipboard_section
        return __update_security_clipboard_section(self)

    def on_security_open_integrity_clicked(self) -> None:
        from features.security_center.security_center_ui import on_security_open_integrity_clicked as _on_security_open_integrity_clicked
        return _on_security_open_integrity_clicked(self)

    def on_vault_security_update_clicked(self) -> None:
        """Run the vault KDF security upgrade (v1 -> v2) from Security Center."""
        from features.security_center.vault_security_update_ops import run_vault_security_update
        return run_vault_security_update(self)
            
    def _update_security_score(
        self,
        *,
        baseline_ok: bool,
        manifest_ok: bool,
        preflight_ok: bool,
        av_ok: bool,
        twofa_on: bool,
        yubikey_on: bool,
        backups_ok: bool,
        strong_password: bool,
        system_ok: bool,
        updates_ok: bool,
        clipboard_ok: bool,
        vault_ok: bool,
    ) -> None:

        from features.security_center.security_center_ui import _update_security_score as __update_security_score
        return __update_security_score(self,
        baseline_ok=baseline_ok,
        manifest_ok=manifest_ok,
        preflight_ok=preflight_ok,
        av_ok=av_ok,
        twofa_on=twofa_on,
        yubikey_on=yubikey_on,
        backups_ok=backups_ok,
        strong_password=strong_password,
        system_ok=system_ok,
        updates_ok=updates_ok,
        clipboard_ok=clipboard_ok,
        vault_ok=vault_ok,)

    def _update_security_account_section(self, username: str):
        from features.security_center.security_center_ui import _update_security_account_section as __update_security_account_section
        return __update_security_account_section(self, username)
     
    def _update_security_system_section(self):
        from features.security_center.security_center_ui import _update_security_system_section as __update_security_system_section
        return __update_security_system_section(self)

    def _update_security_windows_updates(self):
        from features.security_center.security_center_ui import _update_security_windows_updates as __update_security_windows_updates
        return __update_security_windows_updates(self)

    def _sec_center_collect_system_info(self, force: bool = False) -> dict:
        from features.security_center.security_center_ui import _sec_center_collect_system_info as __sec_center_collect_system_info
        return __sec_center_collect_system_info(self, force)

    def _update_backup_timestamp(self, username: str, field: str) -> None:
        from features.security_center.security_center_ui import _update_backup_timestamp as __update_backup_timestamp
        return __update_backup_timestamp(self, username, field)

    def _security_center_clear_ui(self) -> None:
        from features.security_center.security_center_ui import _security_center_clear_ui as __security_center_clear_ui
        return __security_center_clear_ui(self)


    # ==============================
    # --- lock vault
    # ==============================

    def _require_unlocked(self) -> bool:
        if not getattr(self, 'vault_unlocked', False) or not getattr(self, 'core_session_handle', None) or not getattr(self, 'current_username', None):
            self.safe_messagebox_warning(
                self,
                "Vault Locked",
                """Oops — your vault didn’t unlock correctly.
                    You’re signed in, but the vault is still locked.
                    This usually means something didn’t load properly on our side.
                    What you can try:
                    1. Close the app completely (this clears temporary memory).
                    2. Reopen the app and log in again using your correct password.
                       • Did the vault unlock normally?
                    3. Log out, then try logging in again using a wrong password.
                       • Did it still sign you in with the vault locked?
                    If the issue happens again, please send:
                    • A screenshot of what you see
                    • Your logs (check they contain no personal data)
                    • A short description of the steps you took
                    Thanks — this helps me fix the issue quickly!
                    """)
            return False
        return True

    # set worker for status update

    def start_long_task(self):
        self.thread = QThread(self)
        self.worker = Worker()
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.status.connect(self.set_status_txt)     # safe: signal to GUI
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.set_status_txt(self.tr("Preparing…"))
        self.thread.start()

    def set_status_txt(self, text: str, timeout_ms: int = 1000):
        """Show a status message immediately and clear it after `timeout_ms`."""
        try:
            self.status.setText(str(text))
            QApplication.processEvents()   # paint immediately

            # cancel any previous timer
            if hasattr(self, "_status_clear_timer") and self._status_clear_timer:
                self._status_clear_timer.stop()

            # start a new clear timer
            self._status_clear_timer = QTimer.singleShot(timeout_ms, lambda: self.status.setText(""))
        except Exception as e:
            log.info(f"[set_status_txt] Failed to update: {e}") 

    def categury_load_schema(self):
        self.show_category_editor(self.currentUsername.text())
        self.stackedWidget.setCurrentIndex(6)

    # ==============================
    # --- Backup Advisor
    # ==============================

    def _cleanup_on_logout(self):
        from features.backup_advisor.ui_backup_bind import cleanup_on_logout as __cleanup_on_logout
        return __cleanup_on_logout(self)

    # ==============================
    # Default state reset
    # ==============================

    def _on_any_entry_changed(self):
        from auth.logout.logout_flow import _on_any_entry_changed as __on_any_entry_changed
        return __on_any_entry_changed(self)

    # ==============================
    # --- software
    # ==============================

    def _init_software_root(self) -> str:
        try:
            val = getattr(self, "settings", None)
            if val:
                sr = val.value("paths/software_root", type=str)
                if sr:
                    sr = os.path.expandvars(os.path.expanduser(sr))
                    os.makedirs(sr, exist_ok=True)
                    return sr
        except Exception:
            pass

        # derive a sensible base directory
        base_candidates = [
            getattr(self, "appdata_dir", None),
            os.getenv("KEYQUORUM_DATA_DIR"),
            os.path.join(os.path.expanduser("~"), "AppData", "Local", "Keyquorum"),
            os.path.join(os.path.expanduser("~"), "Documents", "Keyquorum"),
            os.path.dirname(os.path.abspath(sys.argv[0])),  # app folder
            os.getcwd(),
        ]
        for base in base_candidates:
            if not base:
                continue
            try:
                root = os.path.normpath(os.path.join(base, "software"))
                os.makedirs(root, exist_ok=True)
                return root
            except Exception:
                continue

        # absolute last resort
        root = os.path.join(os.path.expanduser("~"), "Keyquorum", "software")
        os.makedirs(root, exist_ok=True)
        return root

    # ==============================
    # --- open password gen  
    def open_generator(self):
        # Translate literal message directly without f‑string
        self.set_status_txt(self.tr("Opening Password Generator"))
        return show_password_generator_dialog(target_field=None, confirm_field=None)

    # ==============================
    # --- Maybe dont show again popups ---  Maybe Popups ---
    # ==============================

    # --- new = show app whats new
    def _maybe_show_release_notes(self, *args, **kwargs):
        from ui.ui_flags import _maybe_show_release_notes as __maybe_show_release_notes
        return __maybe_show_release_notes(self)

    def _get_selected_entry(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _get_selected_entry as _impl
        return _impl(self, *args, **kwargs)

    def _maybe_launch_app(self, entry) -> bool:
        """
        Try to start the target app if we know which one it is.
        Returns True if a launch was attempted (and likely succeeded), False if we didn't try.
        """
        exe = (entry.get("app_exe") or "").strip()            
        title_hint = (entry.get("app_window") or "").strip()
        if not exe and not title_hint:
            return False  # nothing to launch

        # Attempt a simple launch
        try:
            if exe:
                # If an absolute path is stored, use it; otherwise let the shell resolve from PATH
                if os.path.isabs(exe) and os.path.exists(exe):
                    subprocess.Popen([exe], shell=False)
                else:
                    subprocess.Popen([exe])
            else:
                return False
            return True
        except Exception:
            return False

    def _wait_window_ready(self, title_regex: str, timeout_sec: float = 12.0) -> bool:
        """
        Wait until a window whose title matches title_regex is foreground/ready.
        If you already have a 'find_window_by_regex' or 'WindowPickerDialog' util, call that here instead.
        """
        try:
            import win32gui
        except Exception:
            return False

        pat = _re.compile(title_regex, _re.I) if title_regex else None
        end = _t.time() + timeout_sec
        while _t.time() < end:
            hwnd = win32gui.GetForegroundWindow()
            title = (win32gui.GetWindowText(hwnd) or "").strip()
            if not pat or pat.search(title):
                return True
            _t.sleep(0.25)
        return False

    # ==============================
    # --- Autofill helpers (V2) ----
    # ==============================
    def on_toggle_launch_before_autofill(self, checked: bool):
        KeyquorumApp.set_status_txt(self, "Launch App before Autofill Toggled")
        """User toggled: Launch target app before autofill."""
        try:
            u = self._active_username()
            set_user_setting(u, "autofill_launch_first", bool(checked))
            update_baseline(username=u, verify_after=False, who=self.tr("AutoFill Setting Changed"))

        except Exception as e:
            log.error(f"[SETTINGS] save autofill_launch_first failed: {e}")

    def _clear_and_type(self, control, text: str, is_password: bool = False):
        from pywinauto.keyboard import send_keys
        try:
            control.set_edit_text("")
            control.set_edit_text(text)
            return
        except Exception:
            pass
        try:
            control.set_focus()
        except Exception:
            pass
        send_keys("^a{BACKSPACE}", pause=0.002)
        send_keys(text, with_spaces=True, pause=0.002 if is_password else 0.0)

    def _connect_window(self, hwnd=None, title_re: str = "", pid=None):
        """Connect to target window either by handle or by regex (+ optional PID)."""
        from pywinauto.application import Application
        from pywinauto.findwindows import find_window, ElementNotFoundError

        if hwnd:
            app = Application(backend="uia").connect(handle=hwnd, timeout=7)
            return app.window(handle=hwnd)

        # fallback: find by regex
        try:
            if pid:
                Application(backend="uia").connect(process=pid, timeout=7)
                wh = find_window(title_re=title_re, process=pid)
            else:
                wh = find_window(title_re=title_re)
        except Exception:
            raise ElementNotFoundError(f"No window matches {title_re!r}")

        app = Application(backend="uia").connect(handle=wh, timeout=7)
        return app.window(handle=wh)

    def _find_email_edit(self, dlg):
        """
        Prefer an Edit control that looks like an email field.
        Falls back to None if nothing clearly email-like is found.
        """
        try:
            edits = dlg.descendants(control_type="Edit")
        except Exception:
            return None

        for e in edits:
            try:
                # combine visible text + accessible name
                label = ((e.window_text() or "") + " " + (e.element_info.name or "")).lower()
                # common signals of an email field
                if ("email" in label) or ("e-mail" in label) or ("mail" in label):
                    return e
                # some apps show a placeholder with '@'
                if "@" in (e.window_text() or ""):
                    return e
            except Exception:
                continue
        return None

    def _find_username_edit(self, dlg):
        try:
            edits = dlg.descendants(control_type="Edit")
        except Exception:
            return None
        for e in edits:
            try:
                nm = (e.window_text() or e.element_info.name or "").lower()
                if "pass" in nm:
                    continue
                return e
            except Exception:
                continue
        return edits[0] if edits else None

    def _find_password_edit(self, dlg):
        try:
            edits = dlg.descendants(control_type="Edit")
        except Exception:
            return None
        for e in edits:
            try:
                nm = (e.window_text() or e.element_info.name or "").lower()
                if "pass" in nm:
                    return e
            except Exception:
                pass
        return edits[-1] if edits else None

    def _find_next_button(self, dlg):
        labels = ("next", "continue", "sign in", "log in", "proceed", "weiter", "avanti")
        try:
            btns = dlg.descendants(control_type="Button")
        except Exception:
            btns = []
        for b in btns:
            try:
                nm = (b.window_text() or b.element_info.name or "").strip().lower()
                if any(lbl in nm for lbl in labels):
                    return b
            except Exception:
                continue
        return None

    def _find_submit_button(self, dlg):
        labels = ("sign in", "log in", "login", "submit", "anmelden", "se connecter")
        try:
            btns = dlg.descendants(control_type="Button")
        except Exception:
            btns = []
        for b in btns:
            try:
                nm = (b.window_text() or b.element_info.name or "").strip().lower()
                if any(lbl in nm for lbl in labels):
                    return b
            except Exception:
                continue
        return None

    def _autofill_split_flow(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _autofill_split_flow as _impl
        return _impl(self, *args, **kwargs)

    def _key_from_hint(self, hint: str) -> str | None:
        h = (hint or "").strip().lower()
        if not h:
            return None
        ALIASES = getattr(self, "ALIASES", {})  # merged user+builtin
        CLIENTS = getattr(self, "CLIENTS", {})

        if h in ALIASES:
            return ALIASES[h]
        if h in CLIENTS:
            return h

        for k in list(ALIASES.keys()) + list(CLIENTS.keys()):
            if h in k or k in h:
                return ALIASES.get(k, k)

        if "battle" in h and "net" in h: return "battlenet"
        if "ubisoft" in h or "uplay" in h: return "uplay"
        if "steam" in h: return "steam"
        if "epic" in h: return "epic"
        return None

    # ==============================
    # --- Passkeys: table + helpers (V1) ---
    # ==============================

    def launch_passkey_manager_with_token(base_dir: str, token_file: str) -> tuple[bool, str]:
        from app.paths import find_passkey_manager_exe

        exe = find_passkey_manager_exe(base_dir)
        if not exe:
            return False, "PasskeyManager.exe not found in bundled resources/bin."

        try:
            tok = Path(token_file).read_text(encoding="utf-8").splitlines()[0].strip()
            if not tok:
                return False, "Token file is empty."

            env = os.environ.copy()
            env["KEYQUORUM_TOKEN"] = tok

            subprocess.Popen([exe], env=env, close_fds=True)
            return True, "PasskeyManager launched."
        except Exception as e:
            return False, f"Launch failed: {e}"

    def _init_passkeys_table(self) -> None:
        # Safely get the table (avoids AttributeError if it ever changes)
        tbl = getattr(self, "passkeysTable", None)
        if not tbl:
            return

        tbl.setColumnCount(5)
        headers = [
            self.tr("Website"),
            self.tr("Account"),
            self.tr("Created"),
            self.tr("Last used"),
            self.tr("Status"),
        ]
        tbl.setHorizontalHeaderLabels(headers)

        # Use QAbstractItemView enums, not tbl.SelectRows etc.
        tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        tbl.setSelectionMode(QAbstractItemView.SingleSelection)
        tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)

        tbl.horizontalHeader().setStretchLastSection(True)

    def _current_username_normalized(self) -> str | None:
        raw = self._active_username() if hasattr(self, "currentUsername") else ""
        if not raw:
            return None
        try:
            return _canonical_username_ci(raw) or raw
        except Exception:
            return raw

    def _reload_passkeys_for_current_user(self) -> None:
        tbl = self.passkeysTable
        if not tbl:
            return

        uname = self._current_username_normalized()
        if not uname:
            tbl.setRowCount(0)
            return

        try:
            from features.passkeys.passkeys_store import load_passkeys
        except Exception:
            # No storage module yet: just clear.
            tbl.setRowCount(0)
            return

        try:
            items = load_passkeys(uname) or []
        except Exception as e:
            tbl.setRowCount(0)
            try:
                log.warning(f"[PASSKEY] failed to load passkeys for {uname}: {e}")
            except Exception:
                pass
            return

        tbl.setRowCount(len(items))
        for row, pk in enumerate(items):
            rp = (pk.get("rp_name") or "") or (pk.get("rp_id") or "")
            if pk.get("rp_name") and pk.get("rp_id"):
                rp = f"{pk['rp_name']} ({pk['rp_id']})"

            account = pk.get("user_display_name") or pk.get("user_name") or ""
            created = (pk.get("created_utc") or "").replace("T", " ").replace("Z", "")
            last_used = (pk.get("last_used_utc") or "").replace("T", " ").replace("Z", "")
            status = self.tr("Disabled") if pk.get("disabled") else self.tr("Active")

            for col, val in enumerate([rp, account, created, last_used, status]):
                it = QTableWidgetItem(str(val))
                # stash the full dict on column 0 for easy access
                if col == 0:
                    it.setData(Qt.UserRole, pk)
                tbl.setItem(row, col, it)

    def _selected_passkey_index(self):
        tbl = self.passkeysTable
        if not tbl:
            return None, None
        sel = tbl.selectionModel().selectedRows() if tbl.selectionModel() else []
        if not sel:
            return None, None
        row = sel[0].row()
        item = tbl.item(row, 0)
        data = item.data(Qt.UserRole) if item else None
        return row, data

    def _delete_selected_passkey(self):
        row, data = self._selected_passkey_index()
        if data is None:
            return
        # TODO: call passkey_store.save_passkeys after removing it
        QMessageBox.information(self, self.tr("Passkeys"), self.tr("Delete logic not wired yet – coming next."))

    def _set_selected_passkey_disabled(self, disabled: bool):
        row, data = self._selected_passkey_index()
        if data is None:
            return
        # TODO: flip data["disabled"] and save
        QMessageBox.information(self, self.tr("Passkeys"), self.tr("Enable/Disable logic not wired yet – coming next."))

    def _rename_selected_passkey(self):
        row, data = self._selected_passkey_index()
        if data is None:
            return
        # TODO: QInputDialog to ask for new label, then save
        QMessageBox.information(self, self.tr("Passkeys"), self.tr("Rename logic not wired yet – coming next."))

    def _dev_seed_dummy_passkey(self):
        """
        DEV ONLY: create a fake passkey entry in the current user's vault
        so we can test the Passkeys tab and encrypted storage.
        """
        from qtpy.QtWidgets import QMessageBox
        try:
            try:
                import features.passkeys.passkeys_store as pk
            except Exception:
                import features.passkeys.passkeys_store as pk  # fallback if it's on PYTHONPATH
        except Exception as e:
            QMessageBox.critical(self, "Passkeys", f"Cannot import passkeys_store:\n{e}")
            return

        if not getattr(self, 'core_session_handle', None):
            QMessageBox.warning(self, "Passkeys", "Vault is locked – log in first.")
            return

        try:
            cred = pk.create_credential(
                rp_id="example.com",
                user_id=b"test-user",
                alg=-7,              # ES256 (standard WebAuthn alg id)
                resident_key=True,
                require_uv=False,
                display_name="Dummy Test Passkey",
            )
        except Exception as e:
            QMessageBox.critical(self, "Passkeys", f"Failed to create dummy passkey:\n{e}")
            return

        try:
            if hasattr(self, "passkeysPanel") and self.passkeysPanel:
                self.passkeysPanel.reload()
        except Exception:
            pass

        QMessageBox.information(
            self,
            "Passkeys",
            f"Dummy passkey added for RP ID: {getattr(cred, 'rpId', 'example.com')}",
        )

    def _init_passkeys_store(self):
        """
        Wire the passkeys_store module to our vault I/O + crypto,
        then refresh the Passkeys table in Settings.

        This runs after login, once the native session is available.
        """
        try:
            import features.passkeys.passkeys_store as pkstore
        except Exception as e:
            try:
                log.debug(f"[PASSKEY] passkeys_store not available: {e}")
            except Exception:
                pass
            return

        # 2) wire the vault I/O + crypto hooks (native session)
        def _read_blob(name: str) -> bytes | None:
            return self.vault_read_encrypted_blob(name)

        def _write_blob(name: str, data: bytes) -> None:
            self.vault_write_encrypted_blob(name, data)

        def _encrypt(plaintext: bytes) -> bytes:
            from native.native_core import get_core
            core = get_core()
            iv = os.urandom(12)
            ct_ba, tag_ba = core.session_encrypt(self.core_session_handle, iv, plaintext)
            return b"KQ1" + iv + bytes(tag_ba) + bytes(ct_ba)

        def _decrypt(blob: bytes) -> bytes:
            from native.native_core import get_core
            core = get_core()
            if not blob or len(blob) < (3 + 12 + 16):
                return b""
            if blob[:3] != b"KQ1":
                # Unknown format
                return b""
            iv = blob[3:15]
            tag = blob[15:31]
            ct = blob[31:]
            pt_ba = core.session_decrypt(self.core_session_handle, iv, ct, tag)
            try:
                return bytes(pt_ba)
            finally:
                try:
                    core.secure_wipe(pt_ba)
                except Exception:
                    pass

        pkstore.set_io(_read_blob, _write_blob, _encrypt, _decrypt)

        # 3) now refresh the Passkeys table on the PassKeys page
        try:
            self._reload_passkeys_table()
        except Exception as e:
            try:
                log.debug(f"[PASSKEY] table reload failed: {e}")
            except Exception:
                pass
        # NOTE:  passkey dev TEST 🔧 DEV ONLY – seed a dummy entry once to prove it works
        # try:
        #     self._dev_seed_dummy_passkey()
        # except Exception:
        #     pass

    def _fmt_passkey_ts(self, ts: float) -> str:
        """Nice human-readable timestamp for passkeys table."""
        try:
            from datetime import datetime
            if not ts:
                return "—"
            return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M")
        except Exception:
            return "—"

    def _reload_passkeys_table(self) -> None:
        """
        Load entries from passkeys_store and populate passkeysTable.
        Called after login and when the user clicks Refresh.
        """
        tbl = getattr(self, "passkeysTable", None)
        if not tbl:
            return

        # No user logged in? Just clear.
        uname = self._active_username() if hasattr(self, "currentUsername") else ""
        if not uname:
            tbl.setRowCount(0)
            return

        try:
            import features.passkeys.passkeys_store as pkstore
            entries = pkstore.list_entries()
        except Exception as e:
            tbl.setRowCount(0)
            try:
                log.debug(f"[PASSKEY] list_entries failed: {e}")
            except Exception:
                pass
            return

        # sort: by rp_id, then last-updated desc
        entries = sorted(
            entries,
            key=lambda e: (getattr(e, "rp_id", ""), -(getattr(e, "updated", 0.0) or 0.0)),
        )

        tbl.setRowCount(len(entries))
        for row, e in enumerate(entries):
            rp = getattr(e, "rp_id", "") or ""
            account = getattr(e, "display_name", "") or ""
            created = self._fmt_passkey_ts(getattr(e, "created", 0.0))
            last_used = self._fmt_passkey_ts(getattr(e, "updated", 0.0) or getattr(e, "created", 0.0))
            status = self.tr("Active") 

            # Column 0: Website (RP ID) + store the credential id in UserRole
            it0 = QTableWidgetItem(rp)
            it0.setData(Qt.UserRole, getattr(e, "id", ""))
            tbl.setItem(row, 0, it0)

            tbl.setItem(row, 1, QTableWidgetItem(account))
            tbl.setItem(row, 2, QTableWidgetItem(created))
            tbl.setItem(row, 3, QTableWidgetItem(last_used))
            tbl.setItem(row, 4, QTableWidgetItem(status))

    def _selected_passkey_cred_id(self) -> str | None:
        tbl = getattr(self, "passkeysTable", None)
        if not tbl or not tbl.currentItem():
            return None
        row = tbl.currentRow()
        if row < 0:
            return None
        item0 = tbl.item(row, 0)
        if not item0:
            return None
        cred_id = item0.data(Qt.UserRole)
        return cred_id or None

    def _delete_selected_passkey(self) -> None:
        cred_id = self._selected_passkey_cred_id()
        if not cred_id:
            return
        if QMessageBox.question(
            self,
            self.tr("Delete Passkey"),
            self.tr("Delete this passkey? This cannot be undone."),
        ) != QMessageBox.Yes:
            return
        try:
            import features.passkeys.passkeys_store as pkstore
            pkstore.delete_by_id(str(cred_id))
            self._reload_passkeys_table()
        except Exception as e:
            QMessageBox.critical(
                self,
                self.tr("Passkeys"),
                self.tr("Could not delete passkey:\n{err}").format(err=e),
            )

    def _rename_selected_passkey(self) -> None:
        cred_id = self._selected_passkey_cred_id()
        if not cred_id:
            return
        name, ok = QInputDialog.getText(
            self,
            self.tr("Rename Passkey"),
            self.tr("New label / display name:"),
        )
        if not ok:
            return
        try:
            import features.passkeys.passkeys_store as pkstore
            pkstore.rename_entry(str(cred_id), name)
            self._reload_passkeys_table()
        except Exception as e:
            QMessageBox.critical(
                self,
                self.tr("Passkeys"),
                self.tr("Could not rename passkey:\n{err}").format(err=e),
            )

    def _refresh_passkey_ui(self,):
        status = pkwin.provider_status_text()
        # show status in the main status bar
        self.set_status_txt(self.tr("Passkey provider status: ") + status)

        helper_ok = self._has_provider_helper()

        # Install / uninstall buttons
        try:
            self.installPasskeysButton.setEnabled(helper_ok and not cap.is_portable_mode())
            self.uninstallPasskeysButton.setEnabled(helper_ok and not cap.is_portable_mode())
        except Exception:
            pass

        grp = getattr(self, "passkeysGroup", None)
        note = getattr(self, "passkeysNote", None)

        if cap.is_portable_mode():
            if grp:
                grp.setEnabled(False)
            if note:
                note.setText(self.tr(
                    "Passkeys require the installed edition.\n"
                    "The browser extension/bridge can still use your vault in Portable mode."
                ))
        else:
            if grp:
                grp.setEnabled(True)
            if note:
                if not cap.is_windows11_23h2_plus():
                    note.setText(self.tr("Requires Windows 11 23H2 or later."))
                elif not cap.is_passkey_provider_registered():
                    note.setText(self.tr(
                        "Click a button below to open Windows Settings and enable "
                        "Keyquorum as a passkey provider."
                    ))
                else:
                    note.setText(self.tr(
                        "Keyquorum is available to apps and browsers as a passkey provider."
                    ))

    # --- install ---
    def _provider_exe_path(self, *args, **kwargs):
        from app.misc_ops import _provider_exe_path as _impl
        return _impl(self, *args, **kwargs)

    def _has_provider_helper(self) -> bool:
        return bool(self._provider_exe_path())

    def on_install_passkeys_clicked(self):
        exe = self._provider_exe_path()
        if not exe:
            QMessageBox.information(
                self, self.tr("Passkeys"),self.tr(
                "This build doesn’t include the Keyquorum Passkey Provider helper.\n\n"
                "You can still use the desktop app and the browser extension, "
                "but system-wide Windows passkey provider isn’t available in this version.")
            )
            return
        try:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            startupinfo = None
            if os.name == "nt":
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                startupinfo = si
            r = subprocess.run(
                [exe, "--register"],
                check=False,
                capture_output=True,
                text=True,
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
            if r.returncode == 0:
                QMessageBox.information(self, self.tr("Passkeys"), self.tr(
                    "Registered. Opening Windows Settings → Accounts → Passkeys.\nEnable Keyquorum there."))
                try:
                    from features.passkeys.capabilities import open_windows_passkey_settings
                    open_windows_passkey_settings()
                except Exception:
                    try:
                        open_path("ms-settings:accounts")
                    except Exception:
                        os.system("start ms-settings:accounts")
            else:
                err = r.stderr.strip() or r.stdout.strip() or f"exit code {r.returncode}"
                QMessageBox.critical(
                self,
                self.tr("Passkeys"),
                self.tr("Registration failed:\n{err}").format(err=err),)
        except Exception as e:
            QMessageBox.critical(
                self,
                self.tr("Passkeys"),
                self.tr("Could not run provider helper:\n{e}").format(e=e),
            )

    def on_uninstall_passkeys_clicked(self):
        exe = self._provider_exe_path()
        if not exe:
            QMessageBox.information(self, self.tr("Passkeys"),
                self.tr("No helper is bundled in this build, so there’s nothing to uninstall."))
            return
        try:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            startupinfo = None
            if os.name == "nt":
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                startupinfo = si
            r = subprocess.run(
                [exe, "--unregister"],
                check=False,
                capture_output=True,
                text=True,
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
            if r.returncode == 0:
                QMessageBox.information(self, self.tr("Passkeys"), self.tr("Unregistered."))
            else:
                err = r.stderr.strip() or r.stdout.strip() or self.tr("exit code ") + f"{r.returncode}"
                QMessageBox.warning(
                    self,
                    self.tr("Passkeys"),
                    self.tr("Unregister failed:\n{err}").format(err=err),
                )
        except Exception as e:
            QMessageBox.critical(self, self.tr("Passkeys"), self.tr("Could not run provider helper:\n{e}").format(e))


    # ==============================
    # --- create account
    # ==============================
    
    def create_account(self):
        """
        Start the Create Account flow.
        If user is not Pro, show the pre-activation mini-dialog first.
        """
        # Respect “don’t ask again” flag
        try:
            skip = bool(get_user_setting("__global__", "skip_activation_pre"))
        except Exception:
            skip = False

        # Proceed to the onboarding wizard
        try:
            from new_users.ui_wizard_create_account import InlineOnboardingWizard
            wiz = InlineOnboardingWizard(parent=self)
        except NameError:
            raise

        try:
            center_on_screen(wiz)
        except Exception:
            pass

        wiz.exec()
    

      

    # ==============================
    # --- first run tour ----------------
    # ==============================
    
    def _run_quick_tour(self):
        """
        Super-short tour that focuses on: double-click editing, expiry flags/watchtower,
        password generator, browser extension, preflight/process scanning & allow/deny lists,
        Defender quick scan on login, integrity/baseline alerts, recovery PDFs guidance,
        support link, and duplicate warnings.
        """
        try:
            tips = [
                ("Vault Basics",
                 "• Double-click any row to view/edit (red means attention: expiry/duplicate).\n"
                 "• Expiry & weak/reused checks live under Watchtower.\n"
                 "• You can sort/filter by category to spot dupes quickly."),
                ("Password Tools",
                 "• Use the Password Generator (Tools → Password Generator) for strong creds.\n"
                 "• Browser Extension: pair from Tools → Browser Extension → Pair. "
                 "Auto-fill works only on matching HTTPS sites."),
                ("Security & Preflight",
                 "• Preflight can run on login (includes Defender quick scan if enabled).\n"
                 "• Add known processes to 'watch' or 'allow' in Security Prefs.\n"
                 "• Integrity baseline watches your vault/salt/user_db for changes and warns."),
                ("Recovery & Safety",
                 "• Keep recovery PDFs/backup codes OFF this machine and OFF the same drive.\n"
                 "• Store them physically or on a separate, offline USB."),
                ("Support",
                 "• If you like the app, a small support helps improve it (Help → Support Me). ❤️")
            ]

            # Step through tips with simple dialogs and jump the UI to relevant places
            def _tip(i: int):
                if i >= len(tips):
                    return
                title, body = tips[i]

                # Navigate/punt to relevant UI place per step
                try:
                    if i == 0:  # Vault
                        self.mainTabs.setCurrentWidget(self.findChild(QWidget, "vaultTab"))
                    elif i == 1:  # Generator / Extension
                        self.mainTabs.setCurrentWidget(self.findChild(QWidget, "vaultTab"))
                    elif i == 2:  # Preflight / Prefs
                        pass
                    elif i == 3:  # Recovery
                        pass
                    elif i == 4:  # Support
                        pass
                except Exception:
                    pass

                QMessageBox.information(self, title, body)
                QTimer.singleShot(0, lambda: _tip(i + 1))

            _tip(0)

        except Exception:
            pass

    def maybe_show_quick_tour(self, *args, **kwargs):
        from new_users.start_app_ops import maybe_show_quick_tour as _impl
        return _impl(self, *args, **kwargs)

    def _clear_fixed_size(self):
        """Allow the window to resize again if something called setFixedSize()."""
        try:
            self.setMinimumSize(0, 0)
            self.setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX)
        except Exception:
            pass

    def _center_on_screen(self):
        try:
            QTimer.singleShot(0, lambda: center_on_screen(self))
        except Exception:
            pass

    def _apply_login_geometry(self):
        """Shrink to login size (called after login UI is visible)."""
        self._clear_fixed_size()
        self.showNormal()
        self.resize(LOGIN_SIZE)
        self._center_on_screen()

    def _apply_vault_geometry(self):
        """Grow to main-app size (called after vault UI becomes visible)."""
        self._clear_fixed_size()
        was_max = getattr(self, "_restore_maximized", False)
        self.showNormal()
        self.resize(VAULT_SIZE)
        if was_max:
            self.showMaximized()
        self._center_on_screen()

   
    # ==============================
    # --- cloud autoSynic -------
    # ==============================

    def _init_auto_sync(self, *args, **kwargs):
        from features.sync.sync_ops import _init_auto_sync as _impl
        return _impl(self, *args, **kwargs)

    def _schedule_auto_sync(self, *args, **kwargs):
        from features.sync.sync_ops import _schedule_auto_sync as _impl
        return _impl(self, *args, **kwargs)

    # ==============================
    # --- Size Change UI ---
    # ==============================

    def _apply_text_size_force_widgets(self, pt: int) -> None:
        """Force font point size across widgets (helps when Designer set per-widget fonts)."""
        try:
            from qtpy.QtGui import QFont
            if pt <= 0:
                # restore: let default/app font flow
                return

            base = QFont(self.font())
            base.setPointSize(pt)
            base.setUnderline(False)
            base.setStrikeOut(False)
            
            # Apply to main window + all children
            self.setFont(base)

            for w in self.findChildren(object):
                try:
                    if hasattr(w, "setFont"):
                        w.setFont(base)
                except Exception:
                    pass
        except Exception:
            pass

    def _load_ui_scale_prefs_apply(self) -> None:
        """Read saved values into spinboxes (without firing events), then apply."""
        try:
            from qtpy.QtCore import QSettings
            s = QSettings("AJH Software", "Keyquorum")

            txt = int(s.value("ui/text_pt", 0) or 0)
            btn = int(s.value("ui/button_h", 0) or 0)
            tbl = int(s.value("ui/table_row_h", 0) or 0)

            # Load into UI (block signals so don't double-apply)
            try:
                if hasattr(self, "text_size") and self.text_size is not None:
                    self.text_size.blockSignals(True)
                    self.text_size.setValue(txt)
                    self.text_size.blockSignals(False)
            except Exception:
                pass

            try:
                if hasattr(self, "button_size") and self.button_size is not None:
                    self.button_size.blockSignals(True)
                    self.button_size.setValue(btn)
                    self.button_size.blockSignals(False)
            except Exception:
                pass

            try:
                if hasattr(self, "button_size_2") and self.button_size_2 is not None:
                    self.button_size_2.blockSignals(True)
                    self.button_size_2.setValue(tbl)
                    self.button_size_2.blockSignals(False)
            except Exception:
                pass

            # Apply them (once)
            self._apply_text_size(txt)
            self._apply_button_size(btn)
            self._apply_table_row_size(tbl)

        except Exception:
            # If QSettings fails, still try apply 0 (defaults)
            try:
                self._apply_text_size(0)
                self._apply_button_size(0)
                self._apply_table_row_size(0)
            except Exception:
                pass

    def on_text_size_changed(self, value: int | float) -> None:
        v = int(round(value))
        if v < 0:
            v = 0
        self.reset_logout_timer()
        self._apply_text_size(v)

        try:
            from qtpy.QtCore import QSettings
            QSettings("AJH Software", "Keyquorum").setValue("ui/text_pt", v)
        except Exception:
            pass

    def on_button_size_changed(self, value: int | float) -> None:
        v = int(round(value))
        if v < 0:
            v = 0
        self.reset_logout_timer()
        self._apply_button_size(v)
        try:
            from qtpy.QtCore import QSettings
            QSettings("AJH Software", "Keyquorum").setValue("ui/button_h", v)
        except Exception:
            pass

    def on_table_size_changed(self, value: int | float) -> None:
        v = int(round(value))
        if v < 0:
            v = 0
        self.reset_logout_timer()
        self._apply_table_row_size(v)
        try:
            from qtpy.QtCore import QSettings
            QSettings("AJH Software", "Keyquorum").setValue("ui/table_row_h", v)
        except Exception:
            pass

    def _apply_text_size(self, pt: int) -> None:
        """pt=0 restores default."""
        try:
            from qtpy.QtWidgets import QApplication
            from qtpy.QtGui import QFont

            if pt <= 0:
                if getattr(self, "_default_app_font", None) is not None:
                    QApplication.setFont(self._default_app_font)
                return

            f = QFont(QApplication.font())
            f.setPointSize(pt)
            f.setUnderline(False)
            f.setStrikeOut(False)
            QApplication.setFont(f)
            self._apply_text_size_force_widgets(pt)


        except Exception:
            pass

    def _apply_button_size(self, h: int) -> None:
        """h=0 restores default min height (best-effort)."""
        try:
            from qtpy.QtWidgets import QAbstractButton
            buttons = self.findChildren(QAbstractButton)

            # Capture defaults once (per button)
            if not hasattr(self, "_default_btn_min_heights"):
                self._default_btn_min_heights = {}

            for b in buttons:
                try:
                    if b not in self._default_btn_min_heights:
                        self._default_btn_min_heights[b] = int(b.minimumHeight() or 0)

                    if h <= 0:
                        b.setMinimumHeight(self._default_btn_min_heights.get(b, 0))
                    else:
                        b.setMinimumHeight(h)
                except Exception:
                    pass
        except Exception:
            pass

    def _apply_table_row_size(self, h: int) -> None:
        """h=0 restores default row height for tables (best-effort)."""
        try:
            from qtpy.QtWidgets import QTableView, QTableWidget

            tables = []
            try:
                tables.extend(self.findChildren(QTableWidget))
            except Exception:
                pass
            try:
                tables.extend(self.findChildren(QTableView))
            except Exception:
                pass

            for t in tables:
                try:
                    vh = t.verticalHeader()
                    if t not in self._default_table_row_heights:
                        self._default_table_row_heights[t] = int(vh.defaultSectionSize() or 0)

                    if h <= 0:
                        vh.setDefaultSectionSize(self._default_table_row_heights.get(t, 0))
                    else:
                        vh.setDefaultSectionSize(h)
                except Exception:
                    pass
        except Exception:
            pass

    # ==============================
    # --- Safe Quit/Exit----------------
    # ==============================
    def closeEvent(self, event):
        """Mandatory logout before window closes."""
        try:
            event.accept()
            self.logout_user()
           
        except Exception:
            pass
        event.accept() 
        # Graceful quit
        try:
            QApplication.instance().quit()
        except Exception:
            pass
        # Hard kill after a short delay in case something hangs
        QTimer.singleShot(200, lambda: os._exit(0))

    # ==============================
    # --- YubiKey 2-of-2 ----------------
    # ==============================

    def refresh_recovery_controls(self) -> None:
        from auth.login.auth_flow_ops import refresh_recovery_controls as _impl
        return _impl(self)

    def _show_login_rescue_both(self, *args, **kwargs):
        from auth.login.auth_flow_ops import _show_login_rescue_both as _impl
        return _impl(self, *args, **kwargs)

    def _load_user_record(self,  *args, **kwargs) -> dict:
        from auth.login.auth_flow_ops import _load_user_record as _impl
        return _impl(self, *args, **kwargs)
    
    def _show_login_rescue(self, *args, **kwargs):
        from auth.login.auth_flow_ops import _show_login_rescue as _impl
        return _impl(self, *args, **kwargs)

    def _finish_login(self, *args, **kwargs):
        from auth.login.auth_flow_ops import _finish_login as _impl
        return _impl(self, *args, **kwargs)



    def _is_risky_category(self, category_name: str) -> bool:
        """
        Define categories you don’t want to share by default (safety).
        Tune this list to your schema.
        """
        if not category_name:
            return False
        risky = {
            "Bank Accounts", "Credit Cards", "SSH Keys", "API Keys", "Private Keys",
            "VPN Config", "Encrypted Drives", "Windows Key", "Software Licenses",
            "Crypto Wallets", "2FA Recovery", "Identity Documents",
        }
        return category_name.strip().casefold() in {r.casefold() for r in risky}

    def _is_blocked_target(self, cat: str) -> bool:
        """
        Block importing into risky categories if the user preference forbids it.
        If self.user_remove_risk is True (or missing), we allow; if False, we block.
        """
        allow_risky = bool(getattr(self, "user_remove_risk", True))
        return (not allow_risky) and self._is_risky_category(cat)

    def _set_hint_flag(self, key: str, value: bool) -> None:
        username = getattr(self, "currentUsername", None)
        username = username.text().strip() if username else ""
        p = Path(config_dir(username)) / "hints.json"
        try:
            data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        except Exception:
            data = {}
        data[str(key)] = bool(value)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _get_hint_flag(self, key: str, default: bool = False) -> bool:
        username = getattr(self, "currentUsername", None)
        username = username.text().strip() if username else ""
        p = Path(config_dir(username)) / "hints.json"
        try:
            if not p.exists():
                return default
            data = json.loads(p.read_text(encoding="utf-8"))
            return bool(data.get(str(key), default))
        except Exception:
            return default



    # --- Utilities used by import flow ---
    def _active_username(self) -> str | None:
        # 1) Prefer session username if set
        u = (getattr(self, "current_username", None) or "").strip()
        if u:
            return u

        # 2) Try the login username widget (may be blank after login)
        try:
            raw = self._active_username()
        except Exception:
            raw = ""

        if not raw:
            return None

        # 3) Canonicalise (case-insensitive match to existing user folder)
        try:
            canon = (_canonical_username_ci(raw) or "").strip()
        except Exception:
            canon = raw

        self.current_username = canon
        return canon


    def _norm(self, v):
        if v is None: return ""
        if isinstance(v, (list, tuple)): return self._norm(v[0]) if len(v) == 1 else ", ".join(self._norm(x) for x in v)
        return str(v)

    def _map_for_dialog(self, entry: dict) -> dict:
        """
        Map sanitized packet keys into what AddEntryDialog usually expects.
        Keep both lower/Titlecase so different code paths can consume.
        """
        e = entry or {}
        out = {}
        out["title"]    = self._norm(e.get("Title") or e.get("Name") or e.get("title") or e.get("name") or "")
        out["Name"]     = out["title"]
        out["username"] = self._norm(e.get("Username") or e.get("Email") or e.get("username") or e.get("email") or "")
        out["User"]     = out["username"]
        out["url"]      = self._norm(e.get("Website") or e.get("URL") or e.get("url") or e.get("website") or "")
        out["URL"]      = out["url"]
        out["password"] = self._norm(e.get("Password") or e.get("password") or "")
        out["Password"] = out["password"]
        out["notes"]    = self._norm(e.get("Notes") or e.get("notes") or "")
        out["Notes"]    = out["notes"]
        for k, v in e.items():
            if k not in out:
                out[k] = v
        return out

    def _prefill_dialog_for_entry(self, dlg, mapped: dict):
        """Prefill AddEntryDialog using either dialog.prefill_from_dict or heuristic mapping."""
        mapped = mapped or {}
        try:
            if hasattr(dlg, "prefill_from_dict") and callable(dlg.prefill_from_dict):
                dlg.prefill_from_dict(mapped)
                return
        except Exception:
            pass

        def take(*keys):
            for k in keys:
                if k in mapped and str(mapped.get(k, "")).strip():
                    return mapped.get(k)
            return None

        # Provider / Title
        self._set_field_text(dlg, ("providerEdit","titleEdit","nameEdit"),
                             take("provider","Provider","title","Title","name","Name","website","Website","url","URL","Email Provider","email provider"))

        # Email
        self._set_field_text(dlg, ("emailEdit",), take("email","Email"))

        # Username
        self._set_field_text(dlg, ("usernameEdit",), take("username","User","Username"))

        # URL / Website
        self._set_field_text(dlg, ("urlEdit","websiteEdit","siteEdit"),
                             take("url","URL","website","Website"))

        # Password
        self._set_field_text(dlg, ("passwordEdit","passEdit"), take("password","Password","pass","Pass"))

        # Phone
        self._set_field_text(dlg, ("phoneEdit",), take("phone number","Phone Number","phone","mobile"))

        # Backup Code
        self._set_field_text(dlg, ("backupCodeEdit",), take("backup code","Backup Code","recovery code","Recovery Code"))

        # TOTP / 2FA Secret
        self._set_field_text(dlg, ("totpEdit","otpEdit","twofaEdit"),
                             take("totp","otp","2fa secret","2FA Secret","secret","Secret"))

        # IMAP / SMTP
        self._set_field_text(dlg, ("imapEdit",), take("imap","imap server","IMAP Server"))
        self._set_field_text(dlg, ("smtpEdit",), take("smtp","smtp server","SMTP Server"))

        # Notes
        self._set_field_text(dlg, ("notesEdit","noteEdit"), take("notes","Notes","description","Description"))

        try:
            if hasattr(dlg, "on_password_changed"):
                dlg.on_password_changed()
        except Exception:
            pass

    def _open_reference_window(self, mapped: dict, title: str = "Reference — Mapped Values", on_autofill=None):
        """Modeless helper window that shows the mapped dict and offers Copy All / Auto Fill / Close."""
        ref = QDialog(self)
        ref.setWindowTitle(title)
        ref.setModal(False)
        v = QVBoxLayout(ref); v.setContentsMargins(12,12,12,12); v.setSpacing(10)

        lab = QLabel(self.tr("You can copy values from here while filling the form."))
        v.addWidget(lab)

        txt = QTextEdit(); txt.setReadOnly(True); txt.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        try:
            txt.setPlainText(json.dumps(mapped or {}, ensure_ascii=False, indent=2))
        except Exception:
            txt.setPlainText(str(mapped or {}))
        txt.setMinimumSize(560, 420)
        v.addWidget(txt, 1)

        h = QHBoxLayout()
        btn_copy = QPushButton(self.tr("Copy All"))
        btn_fill = QPushButton(self.tr("Auto Fill"))
        btn_close = QPushButton(self.tr("Close"))
        h.addWidget(btn_copy); h.addStretch(1); h.addWidget(btn_fill); h.addWidget(btn_close)
        v.addLayout(h)

        def do_copy():
            try:
                txt.selectAll(); txt.copy()
            except Exception: pass

        def do_fill():
            try:
                if callable(on_autofill):
                    on_autofill()
            except Exception:
                pass

        btn_copy.clicked.connect(do_copy)
        btn_fill.clicked.connect(do_fill)
        btn_close.clicked.connect(ref.close)

        ref.show()
        return ref

    def _packet_mode(self, packet: dict) -> str | None:
        """
        Return one of: 'encrypted', 'plain', 'bundle', or None
        """
        if not isinstance(packet, dict):
            return None

        # Encrypted envelope (v=… + sender/recipient/payload/wrapped_key)
        if all(k in packet for k in ("ver", "sender", "recipient", "payload", "wrapped_key")):
            return "encrypted"

        # Plain single
        if str(packet.get("kq_share")) in ("1", 1) and isinstance(packet.get("entry"), dict):
            return "plain"

        # Plain bundle (multi)
        if str(packet.get("kq_share")) in ("1", 1) and isinstance(packet.get("entries"), list):
            return "bundle"

        return None

    def _validate_share_packet(self, *args, **kwargs):
        from features.share.share_ops import _validate_share_packet as _impl
        return _impl(self, *args, **kwargs)

    def _sanitize_share_entry(self, entry: dict) -> dict:
        """
        Keep human-useful fields, normalize common aliases, drop noisy metadata.
        """
        if not isinstance(entry, dict):
            return {}
        ALLOW = {
            "category", "Title", "Name", "Username", "Email", "Password",
            "Website", "URL", "Notes", "2FA Enabled", "TOTP", "TOTP Secret",
            "Phone Number", "Backup Code", "IMAP Server", "SMTP Server"
        }
        DROP = {
            "Date", "created_at", "updated_at", "_id", "_uid", "__version__", "__meta__",
            "last_viewed", "last_rotated", "history", "history_hashes",
        }
        clean = {}
        def put(key, val):
            if val is None: return
            s = str(val)
            if not s.strip(): return
            clean[key] = val
        for k, v in entry.items():
            if k in DROP: continue
            if k in ALLOW: put(k, v); continue
            kl = str(k).lower().strip()
            if     kl == "title": put("Title", v)
            elif   kl == "name": put("Name", v)
            elif   kl in ("user", "login", "username", "account", "accountname", "userid"): put("Username", v)
            elif   kl in ("email", "mail", "emailaddress"): put("Email", v)
            elif   kl in ("password", "pass", "passwd", "secret", "key"): put("Password", v)
            elif   kl in ("website",): put("Website", v)
            elif   kl in ("url", "link", "domain", "site"): put("URL", v)
            elif   kl in ("phone", "phonenumber", "mobile", "tel", "telephone"): put("Phone Number", v)
            elif   kl in ("backupcode", "backupcodes", "recoverycodes", "recoverycode"): put("Backup Code", v)
            elif   kl in ("totp", "totpkey", "totpsecret", "2fasecret", "mfa secret", "authsecret"): put("TOTP Secret", v)
            elif   kl == "notes": put("Notes", v)
            elif   kl in ("imap", "imapserver"): put("IMAP Server", v)
            elif   kl in ("smtp", "smtpserver"): put("SMTP Server", v)
            elif   kl in ("email provider", "provider", "login url", "signin url"): put("Website", v)
            elif   kl == "category": put("category", v)
        if "Website" in clean and "URL" in clean and str(clean["Website"]).strip() == str(clean["URL"]).strip():
            clean.pop("URL", None)
        return clean

    def _minimal_share_entry(self, *args, **kwargs):
        from features.share.share_ops import _minimal_share_entry as _impl
        return _impl(self, *args, **kwargs)

    def _preview_full_entry(self, *args, **kwargs):
        from  features.share.share_ops import _preview_full_entry as _impl
        return _impl(self, *args, **kwargs)


    def _selected_entries_dicts(self, username: str) -> list[dict]:
        """Return minimalized dict(s) for selected row(s). Falls back to currentRow if single selection."""
        table = getattr(self, "vaultTable", None)
        if table is None:
            return []

        try:
            try:
                all_entries = load_vault(username, self.core_session_handle) or []
            except TypeError:
                all_entries = load_vault(username) or []
        except Exception:
            all_entries = []

        rows = set()
        sel = getattr(table, "selectionModel", None)
        if sel and sel():
            for idx in sel().selectedRows():
                rows.add(idx.row())

        if not rows and table.currentRow() >= 0:
            rows = {table.currentRow()}

        # Map visible row -> global index if we’re using an index map
        idx_map = getattr(self, "current_entries_indices", None)
        result = []
        for r in sorted(rows):
            try:
                gi = idx_map[r] if isinstance(idx_map, list) and 0 <= r < len(idx_map) else r
                src = dict(all_entries[gi])
                result.append(self._minimal_share_entry(src))
            except Exception:
                pass
        return result


    def _bulk_preview_entries(self, *args, **kwargs):
        from features.share.share_ops import _bulk_preview_entries as _impl
        return _impl(self, *args, **kwargs)

    def vault_read_encrypted_blob(self, name: str) -> bytes | None:
        base = self._vault_dir_for_user(self.currentUsername.text().strip())
        p = os.path.join(base, name)
        try:
            return Path(p).read_bytes()
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def vault_write_encrypted_blob(self, name: str, data: bytes) -> None:
        base = self._vault_dir_for_user(self.currentUsername.text().strip())
        Path(base).mkdir(parents=True, exist_ok=True)
        p = os.path.join(base, name)
        tmp = p + ".tmp"
        Path(tmp).write_bytes(data)
        os.replace(tmp, p)

    def vault_encrypt_with_master(self, user_key: bytes, plaintext: bytes) -> bytes:
        # AES-GCM with a subkey derived from master key
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        sk = self._hkdf_subkey(user_key, b"passkeys-store:aesgcm-32")
        nonce = os.urandom(12)
        ct = AESGCM(sk).encrypt(nonce, plaintext, None)
        return nonce + ct

    def vault_decrypt_with_master(self, user_key: bytes, ciphertext: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if not ciphertext:
            return b""
        nonce, ct = ciphertext[:12], ciphertext[12:]
        sk = self._hkdf_subkey(user_key, b"passkeys-store:aesgcm-32")
        return AESGCM(sk).decrypt(nonce, ct, None)


    # --- subkey derivation (HKDF-SHA256) ---------------------------------
    def _hkdf_subkey(self, user_key: bytes, info: bytes) -> bytes:
        # tiny HKDF-SHA256 for a 32B subkey
        salt = b"\x00" * 32
        prk = hmac.new(salt, user_key, hashlib.sha256).digest()
        t = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        return t

    def _vault_dir_for_user(self, username: str) -> str:
        return vault_dir(username, ensure_parent=True)

    # --- json encrypt/decrypt using vault helpers Synic -------------------

    def _enc_json_write(self, path: str | os.PathLike, key: bytes, data: dict | list) -> None:
        p = str(path)
        try:
            from features.sync.engine import encrypt_json_file
            encrypt_json_file(p, key, data)
        except Exception:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)

    def _enc_json_read(self, path: str | os.PathLike, key: bytes) -> dict | list:
        p = str(path)
        if not os.path.exists(p):
            return {}
        try:
            from features.sync.engine import decrypt_json_file
            return decrypt_json_file(p, key) or {}
        except Exception:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)


    # ==============================
    # --- login/out ---
    # ==============================

    def _prelogin_baseline_peek(self, *args, **kwargs):
        from auth.login.auth_flow_ops import _prelogin_baseline_peek as _impl
        return _impl(self, *args, **kwargs)

    def _show_login_baseline_warning(self, msg: str) -> None:
        """Non-blocking friendly warning during login (no baseline mutation)."""
        try:
            box = QMessageBox(self)
            box.setWindowTitle("Security Warning")
            box.setIcon(QMessageBox.Icon.Warning)
            box.setText(msg)
            # Qt5/6 compat
            if hasattr(box, "exec_"):
                box.exec_()
            else:
                box.exec()
        except Exception:
            # Fallback to log if UI not ready
            try:
                log.warning(msg)
            except Exception:
                log.info(msg)
                
   
    def _is_locked_out_tuple(self, username: str, threshold: int):
        try:
            res = is_locked_out(username , threshold)  # new signature
        except TypeError:
            res = is_locked_out(username)

        if isinstance(res, tuple):
            return res  # (locked, msg)
        return bool(res), None

    # - select usb
    def on_select_usb_clicked(self, *args, **kwargs):
        from features.portable.portable_ops import on_select_usb_clicked as _impl
        return _impl(self, *args, **kwargs)

    def _remaining_attempts(self, username: str, threshold: int) -> int:
            """
            Reads the current failure counter to compute attempts left.
            Works with your login_handler's storage.
            """
            try:
                data = get_user_setting(username, "lockout_fail_count", 0)
                count = int(data or 0)
                return max(0, threshold - count)
            except Exception:
                return threshold

    def attempt_login(self, *args, **kwargs):
        from auth.login.auth_flow_ops import attempt_login as _impl
        return _impl(self, *args, **kwargs)

    def _prepare_identity_before_login(self, typed_username: str) -> tuple[str, bool]:
        """
        Ensure the user's identity blob is located in the new per-user directory.
        Returns (canonical_username, has_identity).
        Runs before password validation or 2FA checks.
        """
        from auth.identity_store import ensure_identity_ready
        try:
            id_path, canonical, exists = ensure_identity_ready(typed_username)
            log.info(f"Identity file: {id_path, canonical, exists}")

            if exists:
                log.debug(f"[LOGIN] Identity ready at {id_path}")
            else:
                log.debug(f"[LOGIN] No identity found for {typed_username} (canonical={canonical})")
            return canonical, exists
        except Exception as e:
            log.error(f"[LOGIN] Identity prep failed for {typed_username}: {e}")
            return (typed_username, False)

    
    def _refresh_remember_device_checkbox(self, *_args) -> None:
        """Auto-tick 'Remember this device' if this user already has a DPAPI device unlock blob."""
        try:          
            cb = getattr(self, "rememberDeviceCheckbox", None)
            if cb is None:
                return

            uname = (self.usernameField.text() or "").strip()
            if not uname:
                cb.setChecked(False)
                return
            # If DPAPI isn't available, keep it disabled.
            try:
                from auth.windows_hello.windows_hello_dpapi import dpapi_available
                if not dpapi_available():
                    log.debug("[DPAPI] Not Available")
                    cb.setEnabled(False)
                    cb.setChecked(False)
                    return
                log.debug("[DPAPI] Available")
                cb.setEnabled(True)
            except Exception:
                pass

            uname = (self.usernameField.text() or "").strip()
            if not uname:
                cb.setChecked(False)
                return

            from auth.login.login_handler import get_user_record
            from auth.windows_hello.session import has_device_unlock

            rec = get_user_record(uname) or {}
            cb.setChecked(bool(has_device_unlock(rec)))
        except Exception:
            # Never break login UI for a convenience toggle.
            return

    # --- shows main widget/hide login widget, log_audit

    def successful_login(self, *args, **kwargs):
        from auth.login.auth_flow_ops import successful_login as _impl
        return _impl(self, *args, **kwargs)




    def show_login_ui(self) -> None:
        """Hide tabs, show the login panel, and focus the username field."""
        # Hide main app tabs
        if getattr(self, "mainTabs", None):
            try:
                self.mainTabs.setVisible(False)
                self.setFixedSize(380, 600)
            except Exception:
                pass

        # Show the login container + inner widgets
        self.set_login_visible(True)

        # Focus username for a better UX
        for name in ("usernameField", "loginUsername", "usernameEdit", "userEdit", "txtUsername"):
            w = getattr(self, name, None)
            if w:
                try:
                    w.clear()
                    w.setFocus()
                except Exception:
                    pass
                break

    
        # Re-bind login typing hooks (logout can clear/recreate widgets or timers)
        try:
            from ui.ui_bind import init_text_change as _init_text_change
            _init_text_change(self)
        except Exception:
            pass

        # Refresh login picture/tick state immediately
        try:
            self.update_login_picture()
        except Exception:
            pass

    def set_login_visible(self, visible: bool) -> None:
            """Show/hide the login container and its child widgets."""
            # Show/hide the container panel itself (central login area)
            container = getattr(self, "widget", None) or getattr(self, "loginPanel", None)
            if container:
                try:
                    container.setVisible(bool(visible))
                except Exception:
                    pass

            for w in getattr(self, "loginWidgets", []):
                if w:
                    try:
                        w.setVisible(bool(visible))
                    except Exception:
                        pass


    def logout_user(self, skip_backup=True):
        from auth.logout.logout_flow import logout_user as _logout_user
        return _logout_user(self, skip_backup)
     
    # --- setup auto logout time (called on login)
    def setup_auto_logout(self):
        from auth.logout.logout_flow import setup_auto_logout as _setup_auto_logout
        return _setup_auto_logout(self)
     
    # --- reset auto logout (call this on *any* user activity you already track)
    def reset_logout_timer(self):
        from auth.logout.logout_flow import reset_logout_timer as _reset_logout_timer
        return _reset_logout_timer(self)

    # --- detect setting tab clicked

    def on_tab_changed(self, index):
        widget = self.mainTabs.widget(index)
        if widget.objectName() == "settingsTab":
            self.load_setting()

    # --- force logout (timer hit 0 or safety check)
    def force_logout(self):
        log.debug(str(f"{kql.i('locked')} [AUTOF] Force Logout"))  
        # Close warning if open
        if getattr(self, "_warning_dialog", None) is not None:
            try:
                self._warning_dialog.close()
            except Exception:
                pass
            self._warning_dialog = None

        # Stop all timers to avoid callbacks after logout
        for t in ("logout_timer", "logout_warning_timer", "_tick"):
            tm = getattr(self, t, None)
            if tm:
                try:
                    tm.stop()
                except Exception:
                    pass
        log.debug(str(f"{kql.i('locked')} [AUTOF]  Stop all timers to avoid callbacks after logout"))  
        # Close any other windows (best-effort)
        try:
            for w in getattr(self, "_child_windows", []) or []:
                try:
                    w.close()
                except Exception:
                    pass
        except Exception:
            pass
        log.debug(str(f"{kql.i('locked')} [AUTOF]  Close any other windows"))
        self.logout_user()

    # --- helper: show warning dialog with live countdown & extend
    def _show_logout_warning(self, *args, **kwargs):
        from auth.logout.logout_flow import _show_logout_warning as _impl
        return _impl(self, *args, **kwargs)

    def _on_tick(self):
        if not getattr(self, "_auto_logout_enabled", False):
            return
        elapsed = (_t.monotonic() - getattr(self, "_last_activity_monotonic", _t.monotonic()))
        if elapsed * 1000 >= self.logout_timeout + 2_000:
            self.force_logout()

    # --- capture app resume/activate to re-evaluate timers
    def eventFilter(self, obj, event):
        try:
            # if disabled, don’t enforce anything here
            if not getattr(self, "_auto_logout_enabled", False):
                return super().eventFilter(obj, event)

            if event.type() == QEvent.Type.ApplicationStateChange:
                if QApplication.instance().applicationState() == Qt.ApplicationState.ApplicationActive:
                    if self._seconds_until_logout() <= 0:
                        self.force_logout()
                    elif getattr(self, "_warning_dialog", None) is not None:
                        self._show_logout_warning()
        except Exception:
            pass
        return super().eventFilter(obj, event)

    # --- utility: compute seconds left using monotonic/remaining time
    def _seconds_until_logout(self) -> int:
        if not getattr(self, "_auto_logout_enabled", False):
            return 2_147_483_647  # ~INT_MAX seconds

        try:
            if getattr(self, "logout_timer", None):
                ms = self.logout_timer.remainingTime()
                if ms >= 0:
                    return max(0, ms // 1000)
        except Exception:
            pass

        remaining_ms = (self.logout_timeout - int((_t.monotonic() - self._last_activity_monotonic) * 1000))
        return max(0, remaining_ms // 1000)

    # --- stop logout on other windows ---------------------------

    def safe_messagebox_question(self, *args, **kwargs):
        self.reset_logout_timer()
        return QMessageBox.question(*args, **kwargs)

    def safe_messagebox_warning(self, *args, **kwargs):
        self.reset_logout_timer()
        return QMessageBox.warning(*args, **kwargs)

    def safe_messagebox_info(self, *args, **kwargs):
        self.reset_logout_timer()
        return QMessageBox.information(*args, **kwargs)

    # --- Check and verfy, (checks before allowed change)

    # ==============================
    # SENSITIVE ACTION RE-AUTH
    # ==============================
    def _prompt_account_password(self, username: str) -> Optional[str]:
        """Prompt the user to confirm their identity with their account password."""
        try:
            from qtpy.QtWidgets import QInputDialog, QLineEdit
        except Exception:
            return None

        username = (username or "").strip()
        if not username:
            return None

        message = self.tr(
            "For the security of this account '{user}',\n\n"
            "please enter your password to continue:"
        ).format(user=username)

        pwd, ok = QInputDialog.getText(
            self,
            self.tr("Confirm Your Identity"),
            message,
            QLineEdit.EchoMode.Password
        )
        if not ok:
            return None
        pwd = (pwd or "")
        return pwd if pwd else None

    def verify_sensitive_action(self, *args, **kwargs):
        from auth.login.auth_flow_ops import verify_sensitive_action as _impl
        return _impl(self, *args, **kwargs)

    def open_forgot_password_dialog(self, *args, **kwargs):
        from features.url.url_ops import open_forgot_password_dialog as _impl
        return _impl(self, *args, **kwargs)

    def open_delete_account_dialog(self, *args, **kwargs):
        """Open the Delete Account dialog.

        Some UI wiring calls this with an extra parent arg:
            self.open_delete_account_dialog(self, username)
        This wrapper tolerates both forms.
        """
        # Accept either (username,) or (parent, username)
        username = ""
        if args:
            if len(args) == 1:
                username = args[0]
            elif len(args) >= 2:
                username = args[1]
        username = (kwargs.get("username") or username or "").strip()
        from auth.delete_account_dialog import open_delete_account_dialog as _impl
        return _impl(self, username)

    # --- open change password window
    def open_change_password_dialog(self):
        self.reset_logout_timer()
        who =  self.tr("Change Password")
        username = self._active_username()
        if not username:
            show_message_user_login(self, who)
            return
        try:
            if show_message_vault_change(self):
                try:
                    self.export_vault()
                except Exception as e:
                    message_backup_error(self, e)

        except Exception as e:
            log.error(f"[PW CHANGE] Change password  error {e}")

        self.set_status_txt(self.tr("Opening Change Password dialog"))
        log.debug("%s [UI OPEN] open change password dialog", kql.i("ui"))

        dialog = ChangePasswordDialog(username, self.core_session_handle, self)
        self._track_window(dialog)
        dialog.exec()

    # --- open reminders window ---
    def open_reminders_dialog(self):
        """Open the Reminders panel (in-app list of due/overdue reminders)."""
        try:
            self.reset_logout_timer()
        except Exception:
            pass

        username = (self._active_username() or "").strip()
        if not username:
            try:
                username = self._active_username()
            except Exception:
                username = ""
        if not username:
            who =  self.tr("Reminders")
            show_message_user_login(self, who)
            return

        from features.reminders.reminders_dialog import RemindersDialog
        dlg = RemindersDialog(parent=self, username=username, user_key=getattr(self, 'core_session_handle', None))
        try:
            self._track_window(dlg)
        except Exception:
            pass
        dlg.exec()

    def open_add_entry_dialog(self, *args, **kwargs):
        from vault_store.vault_ui_ops import open_add_entry_dialog as _impl
        return _impl(self, *args, **kwargs)

    def open_security_prefs(self, username: str | None = None):
        """Open security prefs. If username is None, use active user."""
        self.set_status_txt(self.tr("Opening security prefs"))
        self.reset_logout_timer()
        username = (username or self._active_username() or "").strip()
        if not username:
            who = self.tr("Security Preferences")
            show_message_user_login(self, who)
            #return

        try:
            dlg = SecurityPrefsDialog(username=username, parent=self)
        except TypeError:
            # - back-compat fallback
            dlg = SecurityPrefsDialog(parent=self)
            if hasattr(dlg, "setUsername"):
                dlg.setUsername(username)

        self._track_window(dlg)

        result = dlg.exec_() if hasattr(dlg, "exec_") else dlg.exec()
        if result:
            try:
                if hasattr(self, "preflight_reload_security_cache"):
                    self.preflight_reload_security_cache(username)
            except Exception:
                pass

    def open_security_prefs_startup(self):
        """Open GLOBAL (default) preflight prefs (startup settings)."""
        self.open_security_prefs("default")

    def run_preflight_now_startup(self):
        """Run preflight using GLOBAL default prefs (startup settings)."""
        try:
            from security.preflight import load_security_prefs, run_preflight_checks
            prefs = load_security_prefs(None)  # None -> "default" via _prefs_path :contentReference[oaicite:1]{index=1}
            ok = run_preflight_checks(parent=self, prefs=prefs)
            return ok
        except Exception as e:
            try:
                from qtpy.QtWidgets import QMessageBox
                QMessageBox.critical(self, "Preflight failed", f"Startup preflight failed:\n\n{e}")
            except Exception:
                pass
            return False

    # --- open password generator window
    def show_password_generator_dialog_1(self, target_field=None, confirm_field=None):
        show_password_generator_dialog(target_field=target_field, confirm_field=confirm_field)


    # ==============================
    # --- table/vault Managemen ---
    # ==============================
    # load vault into table (called from load_setting and any refresh)
    def load_vault_table(self, *args, **kwargs):
        from vault_store.vault_ui_ops import load_vault_table as _impl
        return _impl(self, *args, **kwargs)



    def update_table(self, category):
        log.debug(str(f"{kql.i('vault')} [UPDATE TABLE] Update table called with category: {category}"))
        self.reset_logout_timer()
        # Always refresh the table based on the selected category
        try:
            self.load_vault_table()
        except Exception as e:
            self.vaultTable.clear()

    # --- refresh category edit
    def refresh_category_editor(self):
        if hasattr(self, "categoryEditor") and self.categoryEditor is not None:
            try:
                from catalog_category.category_fields import _load_schema
                self.categoryEditor.schema = _load_schema()
                self.categoryEditor._refresh_lists()
            except Exception as e:
                log.error(str(f"{kql.i('vault')} [REFRESH EDIT] Category editor refresh failed: {e}"))

    # --- new
    def _install_vault_reload_debouncer(self):
        if getattr(self, "_vault_reload_timer", None) is None:
            self._vault_reload_timer = QTimer(self)
            self._vault_reload_timer.setSingleShot(True)
            self._vault_reload_timer.setInterval(300)  # coalesce bursts
            self._vault_reload_timer.timeout.connect(self._do_vault_schema_refresh)

    def schedule_vault_schema_refresh(self):
        """
        Public entry used by CategoryEditor and CSV import. Uses a short timer
        to batch multiple quick changes into a single UI refresh.
        """
        log.debug("[CAT] schedule_vault_schema_refresh called")
        try:
            from qtpy.QtCore import QTimer
            QTimer.singleShot(0, self._do_vault_schema_refresh)
        except Exception as e:
            log.debug("[CAT] schedule_vault_schema_refresh: timer failed (%s); running synchronously", e)
            self._do_vault_schema_refresh()

    def _do_vault_schema_refresh(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _do_vault_schema_refresh as _impl
        return _impl(self, *args, **kwargs)

    def edit_selected_vault_entry(self, *args, **kwargs):
        from vault_store.vault_ui_ops import edit_selected_vault_entry as _impl
        return _impl(self, *args, **kwargs)

    def handle_edit_button(self):
        self.set_status_txt(self.tr("Edit Selected Item"))
        log.debug(str(f"{kql.i('vault')} [VAULT] handle edit button called"))
        self.reset_logout_timer()
        try:
            """
            Trigger editing of the currently selected entry via the Edit button.

            If a row is selected, this method delegates to
            ``edit_selected_vault_entry`` using the row index.  If no row is
            selected, nothing happens.
            """

            row = self.vaultTable.currentRow() if self.vaultTable else -1
            if row >= 0:
                self.edit_selected_vault_entry(row, 0)
        except Exception as e:
            log.error(str(f"{kql.i('vault')} [ERROR] {kql.i('err')} Hadle edit button {e}"))

    # ==============================
    # --- search box (look for item loaded in table)
    # ==============================
    def filter_vault_table(self, text):
        log.debug(str(f"{kql.i('search')} [SEARCH] filter vault table called Filtering with text: {text}"))

        """
        Filter the displayed entries in the vault table based on a search string.

        Each row is hidden if none of its cells contain the search text.
        If the search yields no visible rows, a brief information message
        informs the user that no matches were found.  Blank search strings
        restore all rows.
        """
        try:
            self.reset_logout_timer()
            text_lower = text.lower() if text else ""
            for row in range(self.vaultTable.rowCount()):
                visible = False
                for col in range(self.vaultTable.columnCount()):
                    item = self.vaultTable.item(row, col)
                    if item and text_lower in item.text().lower():
                        visible = True
                        break
                self.vaultTable.setRowHidden(row, not visible)
            self.reset_logout_timer()
        except Exception as e:
            log.error(str(f"{kql.i('search')} [ERROR] {kql.i('err')} filtering vault table: {e}"))
            return

    # --- search full
    def _search_vault_all(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _search_vault_all as _impl
        return _impl(self, *args, **kwargs)

    def on_vault_search_committed(self, *args, **kwargs):
        from vault_store.vault_ui_ops import on_vault_search_committed as _impl
        return _impl(self, *args, **kwargs)

    def _disconnect_search_signals(self, dlg, thread, worker):
        try:
            if worker:
                try: worker.finished.disconnect()   
                except Exception: pass
                try: worker.error.disconnect()     
                except Exception: pass
            if dlg:
                try: dlg.canceled.disconnect()   
                except Exception: pass
        except Exception:
            pass

    def _on_search_finished_collect(self, results: list[dict]):
        # Runs on GUI thread (queued)
        try:
            if self._search_ctx is not None:
                self._search_ctx["results"] = results
        except Exception:
            pass

    def _on_search_error_collect(self, msg: str):
        # Runs on GUI thread (queued). Stash the error.
        try:
            if self._search_ctx is not None:
                self._search_ctx["error"] = msg
        except Exception:
            pass

    def _on_search_thread_finished(self):
        """
        Runs after the worker thread's event loop has fully stopped.
        Safe point to hide/delete dialogs and show results/messages.
        """
        ctx = getattr(self, "_search_ctx", None)
        self._search_busy = False
        try:
            dlg = ctx.get("dlg") if ctx else None
            if dlg:
                try: dlg.hide()
                except Exception: pass
                try: QTimer.singleShot(0, dlg.deleteLater)  # GUI thread only
                except Exception: pass
        except Exception:
            pass

        try:
            if ctx and ctx.get("error"):
                msg = self.tr("Search failed:\n") + f"{ctx['error']}"
                QMessageBox.warning(self, self.tr("Search"), msg)
            else:
                results = (ctx.get("results") if ctx else None) or []
                try:
                    query = (self.vaultSearchBox.text() or "").strip()
                except Exception:
                    query = ""
                try:
                    d = self._build_global_search_results_dialog(query, results)
                    d.open()  # non-modal
                    log.debug("[SEARCH] results dialog opened")
                except Exception as e:
                    log.debug(f"[SEARCH] show results failed: {e}")
        finally:
            # clear context last
            self._search_ctx = None

    def _on_search_done(self, dlg, thread, worker, results):
        log.debug(f"[SEARCH] finished with {len(results)} results; closing progress and posting results dialog…")
        self._disconnect_search_signals(dlg, thread, worker)
        try:
            if dlg: dlg.hide()
        except Exception:
            pass
        QTimer.singleShot(0, lambda: self._show_results_and_finalize(dlg, thread, worker, results))

    def _on_search_error(self, dlg, thread, worker, msg):
        log.debug(f"[SEARCH] worker error: {msg}")
        self._disconnect_search_signals(dlg, thread, worker)
        try:
            if dlg: dlg.hide()
        except Exception:
            pass
        QTimer.singleShot(
            0,
            lambda: QMessageBox.warning(
                self,
                self.tr("Search"),
                self.tr("Search failed:\n{msg}").format(msg=msg),
            ),)
        QTimer.singleShot(0, lambda: self._finalize_search(dlg, thread, worker))

    def _show_results_and_finalize(self, dlg, thread, worker, results):
        # Show results first (non-modal, PySide6-only)
        try:
            query = (self.vaultSearchBox.text() or "").strip()
        except Exception:
            query = ""
        try:
            d = self._build_global_search_results_dialog(query, results)
            d.open()
            log.debug("[SEARCH] results dialog opened")
        except Exception as e:
            log.debug(f"[SEARCH] show results failed: {e}")
        # Final teardown
        self._finalize_search(dlg, thread, worker)

    def _finalize_search(self, dlg, thread, worker):
        # delete dialog on next tick
        try:
            if dlg: QTimer.singleShot(0, dlg.deleteLater)
        except Exception:
            pass
        # stop thread without blocking; delete when it finishes
        try:
            if thread:
                if thread.isRunning():
                    def _finalize():
                        try:
                            if worker: worker.deleteLater()
                        except Exception: pass
                        try:
                            thread.deleteLater()
                        except Exception: pass
                    try:
                        thread.finished.disconnect()
                    except Exception:
                        pass
                    thread.finished.connect(_finalize, type=Qt.QueuedConnection)
                    thread.quit()
                else:
                    try:
                        if worker: worker.deleteLater()
                    except Exception: pass
                    try:
                        thread.deleteLater()
                    except Exception: pass
        except Exception:
            pass
        self._search_busy = False
        self._search_ctx = None

    # Results dialog builder (PySide6-only)
    def _build_global_search_results_dialog(self, query: str, results: list[dict]):
        dlg = QDialog(self)
        dlg.setWindowTitle(self.tr("Search results – \"{query1}\" ({num} hits)").format(query1=query, num=len(results)))
        layout = QVBoxLayout(dlg)
        table = QTableWidget(dlg)
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels([self.tr("Category"),self.tr("Title/Name"),self.tr("Username/Email"),self.tr("URL"),self.tr("Matched Fields"),self.tr("Score")])
        table.setRowCount(len(results))
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        def first(*vals):
            for v in vals:
                v = (v or "").strip()
                if v: return v
            return ""

        for r, hit in enumerate(results):
            e = hit["entry"]
            cat   = first(e.get("category"), e.get("Category"))
            title = first(e.get("Title"), e.get("Name"), e.get("label"))
            user  = first(e.get("Username"), e.get("User"), e.get("Email"))
            url   = first(e.get("URL"), e.get("Site"), e.get("Website"), e.get("Login URL"))
            mfields = ", ".join(sorted(hit.get("matched") or ()))
            score = f"{hit.get('score', 0):.2f}"
            table.setItem(r, 0, QTableWidgetItem(cat))
            table.setItem(r, 1, QTableWidgetItem(title))
            table.setItem(r, 2, QTableWidgetItem(user))
            table.setItem(r, 3, QTableWidgetItem(url))
            table.setItem(r, 4, QTableWidgetItem(mfields))
            table.setItem(r, 5, QTableWidgetItem(score))

        layout.addWidget(table)
        btn_row = QHBoxLayout(); layout.addLayout(btn_row)
        btn_open = QPushButton(self.tr("Go to item")); btn_close = QPushButton(self.tr("Close"))
        btn_row.addStretch(1); btn_row.addWidget(btn_open); btn_row.addWidget(btn_close)

        def _goto_selected():
            r = table.currentRow()
            if r < 0:
                return
            global_index = results[r]["index"]
            try:
                self._select_global_entry(global_index)
                dlg.accept()
            except Exception:
                pass

        btn_open.clicked.connect(_goto_selected)
        btn_close.clicked.connect(dlg.accept)
        dlg.resize(900, 480)
        return dlg

    # ==============================
    # Go-to-item from global search
    # ==============================

    def _first(self, *vals):
        for v in vals:
            v = (v or "").strip()
            if v:
                return v
        return ""

    def _set_active_category(self, name: str) -> bool:
        """Try to switch the visible table to the given category by setting a matching combo item."""
        target = (name or "").strip()
        if not target:
            return False

        # Try common attribute names first
        for attr in ("categoryCombo", "category_filter", "vaultCategoryCombo",
                     "categoryBox", "categoryDropdown"):
            cb = getattr(self, attr, None)
            if isinstance(cb, QComboBox):
                # exact match first
                idx = next((i for i in range(cb.count()) if cb.itemText(i).strip().lower() == target.lower()), -1)
                if idx < 0:
                    # loose match (starts-with)
                    idx = next((i for i in range(cb.count()) if cb.itemText(i).strip().lower().startswith(target.lower())), -1)
                if idx >= 0:
                    cb.setCurrentIndex(idx)
                    return True

        # Fallback: search any QComboBox in the window
        try:
            for cb in self.findChildren(QComboBox):
                idx = next((i for i in range(cb.count()) if cb.itemText(i).strip().lower() == target.lower()), -1)
                if idx < 0:
                    idx = next((i for i in range(cb.count()) if cb.itemText(i).strip().lower().startswith(target.lower())), -1)
                if idx >= 0:
                    cb.setCurrentIndex(idx)
                    return True
        except Exception:
            pass
        return False

    def _row_matches_entry(self, row: int, e: dict) -> bool:
        """Heuristic: match by Category + (Title/Name/Label) + (Username/Email) + (URL/Site)."""
        table = self.vaultTable
        try:
            title = self._first(e.get("Title"), e.get("Name"), e.get("label"))
            user  = self._first(e.get("Username"), e.get("User"), e.get("Email"))
            url   = self._first(e.get("URL"), e.get("Site"), e.get("Website"), e.get("Login URL"))

            # Build a lowercase signature of the row text
            def cell_text(col_name_candidates):
                headers = [table.horizontalHeaderItem(c).text().strip().lower() if table.horizontalHeaderItem(c) else ""
                           for c in range(table.columnCount())]
                for names in col_name_candidates:
                    for c, h in enumerate(headers):
                        if h == names:
                            it = table.item(row, c)
                            return (it.text() if it else "").strip().lower()
                # fallback: just scan all cells concatenated
                parts = []
                for c in range(table.columnCount()):
                    it = table.item(row, c)
                    if it:
                        parts.append((it.text() or "").strip().lower())
                return " | ".join(parts)

            row_blob = " ".join([
                cell_text([("website"), ("title"), ("name"), ("label")]),
                cell_text([("username"), ("user"), ("email")]),
                cell_text([("url"), ("site"), ("website"), ("login url")]),
            ])

            ok_title = (title.lower() in row_blob) if title else True
            ok_user  = (user.lower()  in row_blob) if user  else True
            ok_url   = (url.lower()   in row_blob) if url   else True
            return ok_title and ok_user and ok_url
        except Exception:
            return False

    def _focus_table_row(self, row: int):
        try:
            self.vaultTable.setCurrentCell(row, 0)
            it = self.vaultTable.item(row, 0)
            if it:
                self.vaultTable.scrollToItem(it, self.vaultTable.ScrollHint.PositionAtCenter)
            self.vaultTable.setFocus()
        except Exception:
            pass

    def _select_global_entry(self, global_index: int):
        """
        Jump to a specific entry from the 'all entries' ordering used by global search:
        1) Load its category
        2) Find the matching row
        3) Focus it in the table
        """
        # 1) fetch the same ordering as _search_vault_all used
        try:
            entries = self.vault_store.get_all_entries()
        except Exception:
            entries = load_vault(self.currentUsername.text(), getattr(self, 'core_session_handle', None)) or []

        if not entries or global_index < 0 or global_index >= len(entries):
            return

        e = entries[global_index]
        cat = self._first(e.get("category"), e.get("Category"))
        if cat:
            self._set_active_category(cat)

        # Give the UI a tick to refresh the table after category change
        def _find_and_focus():
            # 2) find the row that best matches the entry
            for r in range(self.vaultTable.rowCount()):
                if not self.vaultTable.isRowHidden(r) and self._row_matches_entry(r, e):
                    self._focus_table_row(r)
                    return
            # fallback: just focus first visible row
            for r in range(self.vaultTable.rowCount()):
                if not self.vaultTable.isRowHidden(r):
                    self._focus_table_row(r)
                    return

        QTimer.singleShot(0, _find_and_focus)


    # ==============================
    # --- move to diffent category
    # ==============================
    def _move_row_to_category_full(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _move_row_to_category_full as _impl
        return _impl(self, *args, **kwargs)

    def _quick_move_row_to_category(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _quick_move_row_to_category as _impl
        return _impl(self, *args, **kwargs)

    def _update_category_cell(self, row: int, new_category: str) -> bool:
        try:
            headers = self._header_map()
            for key in ("type", "category"):
                if key in headers:
                    col = headers[key]
                    it = self.vaultTable.item(row, col)
                    if it is None:
                        it = QTableWidgetItem(new_category)
                        self.vaultTable.setItem(row, col, it)
                    else:
                        it.setText(new_category)
            if hasattr(self, "save_vault"):
                try:
                    self.save_vault()
                    self._on_any_entry_changed()
                except Exception:
                    pass
            return True
        except Exception as e:
            try:
                log.error(str(f"{kql.i('update')} [ERROR] {kql.i('warn')} Move category failed: {e}"))
            except Exception:
                pass
            return False

    def on_move_category_clicked(self, *args, **kwargs):
        from vault_store.vault_ui_ops import on_move_category_clicked as _impl
        return _impl(self, *args, **kwargs)

    def on_move_category_with_edit(self):
       
        table = getattr(self, "vaultTable", None)
        if table is None or table.selectionModel() is None:
            QMessageBox.warning(self, self.tr("Move"), self.tr("Table not available."))
            return
        sel = table.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, self.tr("Move"), self.tr("Select a row to move first."))
            return
        row = sel[0].row()

        try:
            current_cat = self._category_for_row(row)
        except Exception:
            current_cat = ""

        if self._is_blocked_source(current_cat):
            QMessageBox.information(self, self.tr("Move"), self.tr("Entries in 'Bank' or 'Credit Cards' cannot be moved."))
            return

        options = [c for c in self._schema_category_names() if not self._is_blocked_target(c)]
        if not options:
            QMessageBox.information(self, self.tr("Move"), self.tr("No available target categories."))
            return

        default_idx = options.index(current_cat) if current_cat in options else 0
        target, ok = QInputDialog.getItem(self, "Move to category", "Choose the new category/type:",
                                          options, default_idx, False)
        if not ok or not target:
            return
        target = target.strip()
        if self._is_blocked_target(target):
            QMessageBox.information(self, self.tr("Move"), self.tr("You can’t move entries into that category."))
            return

        status = self._move_row_to_category_full(row, target)
        if status == "success":
            QMessageBox.information(self, self.tr("Move"), self.tr("Entry moved."))
        elif status == "cancelled":
            QMessageBox.information(self, self.tr("Move"), self.tr("Move cancelled."))
        else:
            QMessageBox.information(self, self.tr("Move"), self.tr("Move failed."))

    def _user_schema_field_labels(self, category: str) -> list[str]:
        """
        Field labels for a category from the active user's schema (user_db).
        Falls back to legacy get_fields_for(category).
        """
        # Prefer per-user schema (you already expose this)
        try:
            meta = self.user_field_meta_for_category(category)
            if meta:
                seen = set()
                labels = []
                for m in meta:
                    if not isinstance(m, dict):
                        continue
                    lab = (m.get("label") or "").strip()
                    key = lab.lower()
                    if lab and key not in seen:
                        labels.append(lab)
                        seen.add(key)
                if labels:
                    return labels
        except Exception:
            pass

        # Fallback: global schema
        try:
            from catalog_category.category_fields import get_fields_for
            return list(get_fields_for(category))
        except Exception:
            return []

    def _on_table_selection_changed_for_move(self, *_):
        """Slot: keep Move button enabled/disabled based on current row's category."""
        self._update_move_button_enabled()

    def _wire_move_selection_guard(self):
        """(Re)connect selectionChanged -> _update_move_button_enabled safely."""
        table = getattr(self, "vaultTable", None)
        if not table:
            return
        sm = table.selectionModel()
        if sm is None:
            try:
                QTimer.singleShot(0, self._wire_move_selection_guard)
            except Exception:
                pass
            return
        # avoid duplicate connections
        try:
            sm.selectionChanged.disconnect(self._on_table_selection_changed_for_move)
        except Exception:
            pass
        sm.selectionChanged.connect(self._on_table_selection_changed_for_move)
        # set initial state
        self._update_move_button_enabled()

    def _wire_move_button(self):
        btn = getattr(self, "move_category_", None)
        if not btn:
            return
        # detach old slots; ignore if not connected
        try: btn.clicked.disconnect(self._move_row_to_category)   # legacy
        except Exception: pass
        try: btn.clicked.disconnect(self.on_move_category_clicked)
        except Exception: pass
        btn.clicked.connect(self.on_move_category_clicked)
        self._wire_move_selection_guard()

    # ---- move restrictions -------
    def _update_move_button_enabled(self):
        btn = getattr(self, "move_category_", None)
        table = getattr(self, "vaultTable", None)
        if not btn or not table or not table.selectionModel():
            return 
        sel = table.selectionModel().selectedRows()
        if not sel:
            btn.setEnabled(False); return
        row = sel[0].row()
        try:
            cat = self._category_for_row(row)
        except Exception:
            cat = ""
        
        btn.setEnabled(not self._is_blocked_source(cat))

    def _norm_cat(self, name: str) -> str:
        # lower + strip all non-alphanumerics so "Credit Cards" == "creditcards"
        s = (name or "").lower()
        return "".join(ch for ch in s if ch.isalnum())

    def BLOCKED_MOVE_SOURCES(self) -> set[str]:
        # rows currently in any of these categories cannot be moved
        return {"banks", "creditcards", "bankaccount", "bankaccounts", "creditcard", "MAC", "wifi"}

    def _is_blocked_source(self, cat: str) -> bool:
        return self._norm_cat(cat) in self.BLOCKED_MOVE_SOURCES()

    def _is_blocked_target(self, cat: str) -> bool:
        return self._norm_cat(cat) in self.BLOCKED_MOVE_SOURCES()

    # ==============================
    # --- sets and load all settings (called after successful_login)
    # ==============================
    
    def load_setting(self, *args, **kwargs):
        from ui.settings_ops import load_setting as _impl
        return _impl(self, *args, **kwargs)

    def _wire_spin(self, spin, handler, cast=float):
        from app.on_setting_change_ops import _wire_spin as _impl
        return _impl(self, spin, handler, cast)
        
    # ============================== 
    # --- catalog
    # ============================== 

    def export_user_catalog_encrypted(self, *args, **kwargs):
        from features.backup_advisor.ui_backup_bind import export_user_catalog_encrypted as _impl
        return _impl(self, *args, **kwargs)

    def import_user_catalog_encrypted(self, *args, **kwargs):
        from features.backup_advisor.ui_backup_bind import import_user_catalog_encrypted as _impl
        return _impl(self, *args, **kwargs)

    def on_user_logged_in(self, canonical_user: str, _users_base_ignored: str = ""):
        from catalog_category.catalog_category_ops import on_user_logged_in as _impl
        return _impl(self, canonical_user, _users_base_ignored)
        
    def open_catalog_editor(self):
        from catalog_category.catalog_category_ops import open_catalog_editor as _impl
        return _impl(self)
        
    def _on_catalog_saved(self, user_root: str):
        from catalog_category.catalog_category_ops import _on_catalog_saved as _impl
        return _impl(self, user_root)
      
    def _is_probably_user_added(self, url: str, built_value: str | None) -> bool:
        """If built-ins had a value and this one differs, treat as user-added/overridden; or new key entirely."""
        return not built_value or (built_value.strip() != (url or "").strip())

    # ==============================
    # --- flag
    # ==============================
    def _maybe_warn_first_time(self, pref_key: str, title: str, message: str) -> bool:
        from ui.ui_flags import _maybe_warn_first_time as _impl
        return _impl(self, pref_key, title, message)
        
    def open_vendor_url(self, url: str, builtins_url: str | None = None) -> None:
        from ui.ui_flags import open_vendor_url as _impl
        return _impl(self, url, builtins_url)


    # ==============================
    # --- update current theme
    # ==============================

    def _persist_theme_choice(self, label: str):
        """
        Save the theme choice globally (pre-login safe).

        Why:
        - Theme changes should NOT touch per-user user_db, otherwise baseline can
          show "changed on next login" if your integrity checks track user_db.json.
        - QSettings is perfect for "last used theme" and does not affect baseline.
        """
        try:
            theme = (label or "").strip()
            if not theme:
                return

            # Global / last-used theme via QSettings (no username needed)
            try:
                if hasattr(self, "settings") and isinstance(self.settings, QSettings):
                    self.settings.setValue("ui/last_theme", theme)
                    self.settings.sync()
                else:
                    # Fallback in case self.settings isn't set for some reason
                    s = QSettings("AJHSoftware", "KeyquorumVault")
                    s.setValue("ui/last_theme", theme)
                    s.sync()

                try:
                    log.debug(f"{kql.i('theme')} [SETTINGS] saved last_theme (QSettings) → {theme}")
                except Exception:
                    pass

            except Exception:
                # QSettings failure should never break theme change
                pass

        except Exception as e:
            try:
                log.error(f"{kql.i('theme')} [ERROR] persist theme failed: {e}")
            except Exception:
                pass

    def _bars_qss(self, pal, force_black: bool = False) -> str:
        """Theme-aware header/footer styles (or forced black)."""
        win  = pal.color(pal.ColorRole.Window)
        text = pal.color(pal.ColorRole.WindowText)
        mid  = pal.color(pal.ColorRole.Mid)

        if force_black:
            bg  = "#000000"
            fg  = "rgba(255,255,255,0.92)"
            brd = "rgba(255,255,255,0.15)"
        else:
            bg  = f"rgb({win.red()},{win.green()},{win.blue()})"
            fg  = f"rgb({text.red()},{text.green()},{text.blue()})"
            brd = f"rgba({mid.red()},{mid.green()},{mid.blue()},120)"

    def _titlebar_btn_qss(self) -> str:
        """Soft rounded titlebar buttons (frameless controls only)."""
        return """
        QPushButton#BtnMenu, QPushButton#BtnMin, QPushButton#BtnMax, QPushButton#BtnClose {
            border: none; border-radius: 10px; padding: 4px 8px; background: transparent; font-size: 16px;
        }
        QPushButton#BtnMenu:hover, QPushButton#BtnMin:hover, QPushButton#BtnMax:hover {
            background: rgba(255,255,255,0.10);
        }
        QPushButton#BtnClose:hover { background: rgba(255,0,0,0.18); }
        """

    # --- update current theme get qsettings then using apply_theme2 to set
    def apply_theme(self, theme: str, persist: bool = True, *, initial: bool = False):
        """
        Thin wrapper around apply_theme2 that adds:
        - QSettings + user_db persistence (when persist=True)
        - support for initial=True (startup / pre-login).

        All the actual palette/QSS logic lives in apply_theme2.
        """
        theme = (theme or "").strip()

        # Persist choice (QSettings + user_db) unless explicitly disabled.
        if persist:
            try:
                self._persist_theme_choice(theme)
            except Exception:
                pass

        # Delegate the real theming to the original implementation.
        # pass persist=False to avoid double-saving in _persist_theme_choice.
        try:
            try:
                self.apply_theme2(theme, persist=False)
            except TypeError:
                # In case apply_theme2 has the old signature 
                self.apply_theme2(theme)
        finally:
            # Only show a status message for interactive changes
            if not initial:
                try:
                    self.set_status_txt(self.tr("Theme Set"))
                except Exception:
                    pass

    # --- update current theme
    def apply_theme2(self, *args, **kwargs):
        from app.theme_lang_ops import apply_theme2 as _impl
        return _impl(self, *args, **kwargs)

    def _set_theme_stylesheet(self, css: str) -> None:
        """Remember theme CSS and apply with Touch suffix if needed."""
        self._base_css = css or ""
        self._refresh_stylesheet()

    def _refresh_stylesheet(self) -> None:
        """
        Apply theme + (optional) touch CSS together, preserving marker.
        Do NOT try to also style individual widgets here.
        """
        base = getattr(self, "_base_css", "")  # don’t reuse current applied sheet

        # Touch mode on/off using the marker
        if getattr(self, "_touch_mode_active", False):
            if _TOUCH_MARKER not in base:
                base = (base + ("\n" if base else "") + _TOUCH_CSS)
        else:
            if _TOUCH_MARKER in base:
                base = base.split(_TOUCH_MARKER)[0]

        self.setStyleSheet(base)

    # ==============================
    # --- UI language preference (per-user) -----------------------------------
    # ==============================

    def _init_language_from_file(self) -> None:
        from ui.ui_language import _init_language_from_file as __init_language_from_file
        return __init_language_from_file(self)

    def _available_languages(self) -> list[tuple[str, str]]:
        from ui.ui_language import _available_languages as __available_languages
        return __available_languages(self)

    def _init_language_selector(self, selected_code: str | None = None) -> None:
        from ui.ui_language import _init_language_selector as __init_language_selector
        return __init_language_selector(self)
       
    def _on_language_combo_changed(self, idx: int):
        from ui.ui_language import _on_language_combo_changed as __on_language_combo_changed
        return __on_language_combo_changed(self, idx)

    def _persist_language_choice(self, code: str, flush: bool = True) -> None:
        from ui.ui_language import _persist_language_choice as __persist_language_choice
        return __persist_language_choice(self, code, flush)
      
    def _startup_language_code(self) -> str:
        from ui.ui_language import _startup_language_code as __startup_language_code
        return __startup_language_code(self)

    def _effective_lang_code(self, code: str | None) -> str:
        from ui.ui_language import _effective_lang_code as __effective_lang_code
        return __effective_lang_code(self, code)

    def _install_translator_for_code(self, ui_lang: str | None, *, persist: bool = False) -> None:
        from ui.ui_language import _install_translator_for_code as __install_translator_for_code
        return __install_translator_for_code(self, ui_lang)
      
    # ==============================
    # --- ontop ---
    # ==============================
    def set_topmost_no_flash(self, on: bool) -> None:
        from app.on_setting_change_ops import set_topmost_no_flash as _impl
        return _impl(self, on)

    def on_enable_ontop_toggled(self, checked: bool) -> None:
        from app.on_setting_change_ops import on_enable_ontop_toggled as _impl
        return _impl(self, checked)

    # ==============================
    # --- toast ---
    # ==============================
    def _toast(self, message: str, msec: int = 2500):
        from features.systemtray.systemtry_ops import _toast as _impl
        return _impl(self, message, msec)
           
    # ==============================
    # --- portable app ---
    # ==============================

    def action_move_user_to_usb(self, *args, **kwargs):
        from features.portable.portable_ops import action_move_user_to_usb as _impl
        return _impl(self, *args, **kwargs)

    def _detect_portable_root2(self, usb_root):
        """
        Try to detect the Keyquorum portable root folder on a given USB drive.
        e.g., I:/KeyquorumPortable
        Falls back to the drive itself if no subfolder found.
        """
        from pathlib import Path
        try:
            from features.portable.portable_user_usb import get_portable_root
            return get_portable_root(Path(usb_root))
        except Exception:
            usb_root = Path(usb_root)
            candidate = usb_root / "KeyquorumPortable"
            return candidate if candidate.exists() else usb_root

    def action_move_user_from_usb(self, *args, **kwargs):
        from features.portable.portable_ops import action_move_user_from_usb as _impl
        return _impl(self, *args, **kwargs)

    def on_rebuild_portable_clicked(self):
        """
        Rebuild / create the portable app on a selected USB drive
        without blocking the UI thread.
        """
        self.set_status_txt(self.tr("Updating App to USB"), timeout_ms=3000)

        from pathlib import Path
        from features.portable.portable_manager import pick_usb_drive

        try:
            if getattr(self, "_portable_build_thread", None) and self._portable_build_thread.isRunning():
                QMessageBox.information(
                    self,
                    self.tr("Portable Rebuild"),
                    self.tr("A portable rebuild is already running."),
                )
                return
        except Exception:
            pass

        drive = pick_usb_drive(self)
        if not drive:
            self.set_status_txt(self.tr("Portable rebuild cancelled"))
            return

        self._portable_progress_dlg = QProgressDialog(self)
        self._portable_progress_dlg.setWindowTitle(self.tr("Rebuilding Portable"))
        self._portable_progress_dlg.setLabelText(self.tr("Preparing portable app…"))
        self._portable_progress_dlg.setRange(0, 0)
        self._portable_progress_dlg.setWindowModality(Qt.WindowModal)
        self._portable_progress_dlg.setCancelButton(None)
        self._portable_progress_dlg.setMinimumDuration(0)
        self._portable_progress_dlg.show()
        QApplication.processEvents()

        self._portable_build_thread = QThread(self)
        self._portable_build_worker = PortableBuildWorker(str(Path(drive)))
        self._portable_build_worker.moveToThread(self._portable_build_thread)

        self._portable_build_thread.started.connect(self._portable_build_worker.run)
        self._portable_build_worker.finished.connect(self._on_portable_build_finished)
        self._portable_build_worker.finished.connect(self._portable_build_thread.quit)
        self._portable_build_worker.finished.connect(self._portable_build_worker.deleteLater)
        self._portable_build_thread.finished.connect(self._portable_build_thread.deleteLater)
        self._portable_build_thread.finished.connect(self._cleanup_portable_build_refs)

        self._portable_build_thread.start()

    def _on_portable_build_finished(self, ok: bool, msg: str):
        try:
            dlg = getattr(self, "_portable_progress_dlg", None)
            if dlg is not None:
                dlg.close()
                dlg.deleteLater()
        except Exception:
            pass
        finally:
            self._portable_progress_dlg = None

        if ok:
            QMessageBox.information(
                self, self.tr("Portable Rebuild"), self.tr(msg)
            )
            self.set_status_txt(self.tr("Portable app updated."), timeout_ms=4000)
        else:
            QMessageBox.critical(
                self,
                self.tr("Portable Rebuild Failed"),
                self.tr("Portable rebuild failed. Please check the log for details.\n\n{msg}").format(msg=msg),
            )
            self.set_status_txt(self.tr("Portable rebuild failed"), timeout_ms=4000)

    def _cleanup_portable_build_refs(self):
        self._portable_build_thread = None
        self._portable_build_worker = None

    def on_wipe_portable_clicked(self):
        from features.portable.portable_manager import wipe_portable
        target = QFileDialog.getExistingDirectory(self, "Select portable root (drive root or 'KeyquorumPortable')")
        if not target:
            return
        msg = self.tr("This will securely erase the portable app at:") + f"\n\n{target}\n\n" + self.tr("Are you sure you want to continue?")
        confirm = QMessageBox.question(
            self,
            self.tr("Confirm Wipe"),
            msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
            )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        wipe_portable(self, Path(target), mode="portable_only", passes=1)
   
    def _release_local_handles_for_user(self, username: str | None):
        """Best-effort: stop watchers, lock vault, and release log/file handles so Windows can copy/delete."""
        try:
            if hasattr(self, "_vault_watcher") and self._vault_watcher:
                try:
                    self._vault_watcher.deleteLater()
                except Exception:
                    pass
                self._vault_watcher = None
        except Exception:
            pass
        try:
            if hasattr(self, "lock_vault") and callable(self.lock_vault):
                self.lock_vault()
        except Exception:
            pass
        try:
            import logging
            root = logging.getLogger()
            for h in list(root.handlers):
                try: h.flush()
                except Exception: pass
                try: h.close()
                except Exception: pass
            logging.shutdown()
            _t.sleep(0.05)
        except Exception:
            pass


    # ============================== 
    # rapid change control
    # ==============================
    def _ensure_debounce_store(self):
        from app.on_setting_change_ops import _ensure_debounce_store as _impl
        _impl(self)
        
    def _debounce_setting(self, *args, **kwargs):
        from app.on_setting_change_ops import _debounce_setting as _impl
        return _impl(self, *args, **kwargs)

    def _queue_setting_save(self, key: str, value: float, commit_fn, *, delay_ms: int = 700, flush: bool = False):
        from app.on_setting_change_ops import _queue_setting_save as _impl
        return _impl(self, key, value, commit_fn, delay_ms, flush)

    def on_enable_preflight_toggled(self, checked: bool):
        from app.on_setting_change_ops import on_enable_preflight_toggled as _impl
        return _impl(self, checked)

    def on_enable_WinDefCheckbox_toggled(self, checked: bool) -> None:
        from app.on_setting_change_ops import on_enable_WinDefCheckbox_toggled as _impl
        return _impl(self, checked)

    def on_enable_DefenderQuickScan_toggled(self, checked: bool) -> None:
        from app.on_setting_change_ops import on_enable_DefenderQuickScan_toggled as _impl
        return _impl(self, checked)

    def on_run_preflight_now_clicked(self, *args, **kwargs):
        from security.security_ops import on_run_preflight_now_clicked as _impl
        return _impl(self, *args, **kwargs)

    def on_password_expiry_days_change(self, value: int | float, *, flush: bool = False) -> None:
        from app.on_setting_change_ops import on_password_expiry_days_change as _impl
        return _impl(self, value, flush)

    def on_lockout_threshold_changed(self, value: int | float, *, flush: bool = False) -> None:
        from app.on_setting_change_ops import on_lockout_threshold_changed as _impl
        return _impl(self, value, flush)

    def on_clipboard_clear_timeout_sec_change(self, value: int | float, *, flush: bool = False) -> None:
        from app.on_setting_change_ops import on_clipboard_clear_timeout_sec_change as _impl
        return _impl(self, value, flush)
      
    def on_auto_logout_timeout_sec_change(self, value: int | float, *, flush: bool = False) -> None:
        from app.on_setting_change_ops import on_auto_logout_timeout_sec_change as _impl
        return _impl(self, value, flush)


    # ==============================
    # --- two 2fa enable/disable 
    # ==============================
    # ---------------- Manual Emergency Kit input (no persistence) ----------------
    def prompt_manual_kit_entries(self, *args, **kwargs):
        from auth.login.auth_flow_ops import prompt_manual_kit_entries as _impl
        return _impl(self, *args, **kwargs)

    def emg_ask(self, *args, **kwargs):
        from auth.login.auth_flow_ops import emg_ask as _impl
        return _impl(self, *args, **kwargs)

    def toggle_2fa_setting(self, *args, **kwargs):
        from auth.login.auth_flow_ops import toggle_2fa_setting as _impl
        return _impl(self, *args, **kwargs)

    def disable_twofa(self, username: str, password: str | None = None) -> bool:
        """
        Clears TOTP (secret + codes) and flips the identity header flag OFF.
        Does NOT delete username.data (preserves YubiKey & other identity metadata).
        """
        # Ensure a password to rewrap identity blob
        if not password:
            password = getattr(self, "current_password", None)
        if not password:
            password = self._prompt_account_password(username)
            if not password:
                return False
        if isinstance(password, bytes):
            try: password = password.decode("utf-8")
            except Exception: pass

        try:
            # Clear secret (use empty string, not None) and backup codes
            set_totp_secret(username, password, "")
            replace_backup_codes(username, password, [])
            # Flip header OFF so login stops prompting
            mark_totp_header(username, password, False)

            self.totp = None
            msg = self.tr("{ok} User Disabled 2FA").format(ok=kql.i('ok'))
            log_event_encrypted(self.currentUsername.text(), self.tr("2FA Disabled"), msg)
            try:
                update_baseline(username=username, verify_after=False, who=self.tr("2FA Changed"))
            except Exception:
                log.error(f"{kql.i('err')} [BASELINE] Error updating baseline")

            self.regen_key_both.setEnabled(False)
            self.regen_key_2fa.setEnabled(False)
            self.regen_key_2fa_2.setEnabled(False)
            log.debug(f"{kql.i('tool')} [2FA] {kql.i('ok')} 2FA disabled (identity cleared + header false)")
            return True
        except Exception as e:
            log.error(f"{kql.i('err')} [2FA] disable_twofa error: {e}")
            QMessageBox.critical(self, self.tr("2FA"), f"Failed to disable 2FA for this account.\n\n{e}")
            return False

    # ==============================
    # --- Portable Version ----
    # ==============================

    def update_portable_actions(self, *args, **kwargs):
        from features.portable.portable_ops import update_portable_actions as _impl
        return _impl(self, *args, **kwargs)

    def _open_path(self, p: Path):
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(p)))

    def show_licenses_dialog(self, *args, **kwargs):
        from app.misc_ops import show_licenses_dialog as _impl
        return _impl(self, *args, **kwargs)

    def _about_link_handler(self, url: str):
        if url == "app:open_licenses":
            open_path_in_explorer(LICENSES_DIR)
        elif url == "app:open_license_cache":
            open_path_in_explorer(LICENSE_CACHE_DIR)
        elif url == "app:open_logs":
            open_path_in_explorer(LOG_DIR_)
        else:
            # http/https/mailto
            open_url(url)

    def open_licenses_folder(self):
        open_path_in_explorer(LICENSES_DIR)

    def open_license_cache_folder(self):
        open_path_in_explorer(LICENSE_CACHE_DIR)

    def open_logs_folder(self):
        open_path_in_explorer(LOG_DIR_)

    # ==============================
    # --- table context actions
    # ==============================

    def _header_map(self):
        """Return a dict of lowercase header -> column index for vaultTable."""
        headers = {}
        try:
            cols = self.vaultTable.columnCount()
            for i in range(cols):
                h = self.vaultTable.horizontalHeaderItem(i)
                if h and h.text():
                    headers[h.text().strip().lower()] = i
        except Exception:
            pass
        return headers

    def _is_masked(self, s: str) -> bool:
        if not isinstance(s, str) or not s:
            return False
        bullets = {'•', '●', '▪', '▮', '∙', '∗', '*', '◦'}
        # Heuristic: mostly bullets or typical "********" masking
        return all(ch in bullets for ch in set(s.strip())) or _re.fullmatch(r'\*{4,}', s.strip()) is not None

    def _extract_cell_value(self, item):
        """Prefer hidden/unmasked data stored in item roles; fallback to text."""
        try:
            # In PyQt5, roles moved to Qt.ItemDataRole; +1 works on the int value.
            roles = [
                Qt.ItemDataRole.UserRole,
                Qt.ItemDataRole.EditRole,
                Qt.ItemDataRole.DisplayRole,
            ]
            extra_role = int(Qt.ItemDataRole.UserRole) + 1
            for role in [*roles, extra_role]:
                val = item.data(role)  # IntEnum works here; it's an int underneath


                if isinstance(val, str) and val.strip():
                    if self._is_masked(val):
                        continue
                    return val
                elif val is not None and val is not False:
                    return str(val)
        except Exception:
            pass
        # Fallback to text, but if masked return empty to avoid copying bullets
        txt = item.text() if hasattr(item, "text") else ""
        return "" if self._is_masked(txt) else txt

    def _find_url_in_row(self, row: int) -> str:
        """Scan the row for something that looks like a URL; return first match or ''."""
        if not self.vaultTable:
            return ""

        # 1) Full URLs or www.*
        url_re = _re.compile(r'(?i)^(?:https?://|www\.)\S+$')

        # 2) Naked domains: example.com, example.co.uk, www.example.co.uk, etc.
        #    - no scheme
        #    - no '@' (don't confuse emails)
        naked_domain_re = _re.compile(
            r'(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        )

        cols = self.vaultTable.columnCount()
        for c in range(cols):
            it = self.vaultTable.item(row, c)
            if not it:
                continue

            # Prefer the unmasked / hidden value
            candidate = self._extract_cell_value(it)
            if not candidate:
                candidate = (it.text() or "")
            candidate = candidate.strip()
            if not candidate:
                continue

            # --- Case 1: proper http(s) or explicit www. ---
            if url_re.match(candidate):
                return candidate

            # --- Case 2: naked domain (example.com, example.co.uk, etc.) ---
            # Must NOT contain '@' (to avoid emails) and must not already have a scheme.
            if "@" not in candidate and "://" not in candidate:
                if naked_domain_re.match(candidate):
                    return candidate

        return ""

    def _get_row_entry_dict(self, row: int) -> dict:
        """Build a dict of header->value for a table row, preferring unmasked values."""
        data = {}
        try:
            headers = self._header_map()
            for name, col in headers.items():
                it = self.vaultTable.item(row, col)
                if not it:
                    continue
                val = self._extract_cell_value(it)
                if not val:
                    txt = it.text() or ""
                    val = "" if self._is_masked(txt) else txt
                data[name] = val
        except Exception as e:
            log.debug(' '.join(map(str, ("[DEBUG] _get_row_entry_dict error:", e))))
            
        return data

    def open_url_with_warnings(self, *args, **kwargs):
        from features.url.url_ops import open_url_with_warnings as _impl
        return _impl(self, *args, **kwargs)

    def on_open_site_clicked(self):
        """Open the best website/URL for the currently selected vault entry."""
        self.set_status_txt(self.tr("Open Site"))
        self.reset_logout_timer()

        tbl = getattr(self, "vaultTable", None)
        if not tbl:
            return

        row = tbl.currentRow()
        if row < 0 and tbl.selectionModel():
            sel = tbl.selectionModel().selectedRows()
            if sel:
                row = sel[0].row()

        if row < 0:
            QMessageBox.information(
                self,
                self.tr("Open Website"),
                self.tr("Please select an entry first."),
            )
            return

        url = self._find_url_in_row(row)
        if not url:
            QMessageBox.information(
                self,
                self.tr("Open Website"),
                self.tr("No website or URL was found for this entry."),
            )
            return

        self.open_url_with_warnings(url)

    def _category_for_row(self, row:int) -> str:
        headers = self._header_map()
        for key in ("category", "type"):
            if key in headers:
                it = self.vaultTable.item(row, headers[key])
                if it:
                    val = self._extract_cell_value(it) or (it.text() or "")
                    return val.strip()
        # fallback to selector
        try:
            if hasattr(self, "categorySelector_2") and self.categorySelector_2:
                return self.categorySelector_2.currentText()
        except Exception:
            pass
        return ""
    
    # --- schema for both main and move

    def _schema_category_names(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _schema_category_names as _impl
        return _impl(self, *args, **kwargs)

    def _schema_category_names(self) -> list[str]:
        """
        Category names for the active user, using the same logic
        as the Category Editor (find_user + load_schema_for).
        Falls back to built-in defaults. Never returns an empty list.
        """
        names: list[str] = []

        try:
            # Work out current username as shown in the UI
            raw_name = ""
            if hasattr(self, "currentUsername") and hasattr(self.currentUsername, "text"):
                raw_name = self._active_username()

            canonical = ""
            if raw_name:
                try:
                    canonical = _canonical_username_ci(raw_name) or raw_name
                except Exception:
                    canonical = raw_name

            # Load the same schema the Category Editor uses
            if canonical:
                try:
                    from catalog_category.category_editor import load_schema_for
                    schema = load_schema_for(canonical) or {}
                except Exception:
                    schema = {}
            else:
                schema = {}

            # Extract names from schema
            for c in schema.get("categories", []):
                if not isinstance(c, dict):
                    continue
                nm = (c.get("name") or "").strip()
                if nm:
                    names.append(nm)

        except Exception as e:
            try:
                log.debug(f"[DEBUG] _schema_category_names failed: {e}")
            except Exception:
                pass

        # Fallback if got nothing
        if not names:
            try:
                from catalog_category.category_fields import get_categories
                names = list(get_categories())
            except Exception:
                names = ["Passwords"]

        return names

    def refresh_category_selector(self):
        self.set_status_txt(self.tr("refresh category selector"))
        combo: QComboBox = getattr(self, "categorySelector_2", None)

        if not isinstance(combo, QComboBox):
            log.debug("[CAT] refresh_category_selector: no categorySelector_2 found")
            return

        combo.clear()
        log.info("old category cleared")

        # remember & repopulate
        current = combo.currentText() if combo.count() else ""
        cats = list(self._schema_category_names() or [])

        combo.blockSignals(True)
        combo.addItems([str(c) for c in cats])
        combo.blockSignals(False)

        # restore selection
        idx = combo.findText(current)
        if idx >= 0:
            combo.setCurrentIndex(idx)

        # (re)connect
        try:
            if hasattr(self, "update_table"):
                combo.currentTextChanged.connect(self.update_table)
        except Exception:
            # ignore "already connected" style errors
            pass

        # enforce size/scroll behavior (if you have this helper)
        try:
            self._enforce_category_compact()
        except Exception:
            pass

    def _enforce_category_compact(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _enforce_category_compact as _impl
        return _impl(self, *args, **kwargs)

    def refresh_category_dependent_ui(self):
        self.set_status_txt(self.tr("refresh category dependent ui"))
        combo = getattr(self, "categoryFilterCombo", None) or getattr(self, "categoryFilter", None)
        if combo:
            cats = self._schema_category_names()
            combo.blockSignals(True)
            combo.clear()
            combo.addItem("All")
            for c in cats:
                combo.addItem(c)
            combo.blockSignals(False)
            combo.update()

        # Main selector used elsewhere
        self.refresh_category_selector()

        # Reload the table so filters/headers apply right away
        if hasattr(self, "load_vault_table"):
            try:
                self.load_vault_table()
            except Exception as e:
                log.error(str(f"[DEBUG] load_vault_table failed: {e}"))

    # --- per-user field meta (table uses user_db first) ---
    def user_field_meta_for_category(self, *args, **kwargs):
        from catalog_category.catalog_category_ops import user_field_meta_for_category as _impl
        return _impl(self, *args, **kwargs)

    def on_table_double_clicked(self, row: int, column: int):
        log.debug(str(f"[DEBUG] on_table_double_clicked called at row column"))
        """
        Handle double-clicks on the vault table.

        When the user double-clicks any cell, open the edit dialog for
        the corresponding row.
        """
        self.reset_logout_timer()
        self.edit_selected_vault_entry(row, column)

    # ==============================
    # --- _cell
    
    def _cell(self, text):
        log.debug(str(f"[DEBUG] _cell called with text: {text}"))
        self.reset_logout_timer()
        return QTableWidgetItem(text)

    # ==============================
    # --- QR show for selected item
    
    def show_qr_for_selected(self, *args, **kwargs):
        from vault_store.vault_ui_ops import show_qr_for_selected as _impl
        return _impl(self, *args, **kwargs)

    def _make_wifi_qr_payload(self, ssid: str, password: str, encryption: str = "WPA", hidden: bool = False) -> str:
        """Builds a Wi-Fi QR payload (WIFI:T:...;S:...;P:...;H:...;;)."""
        def esc(s: str) -> str:
            s = s or ""
            return s.replace("\\", "\\\\").replace(";", r"\;").replace(":", r"\:")
        t = (encryption or "WPA").strip().upper()
        h = "true" if bool(hidden) else "false"
        return f"WIFI:T:{t};S:{esc(ssid)};P:{esc(password)};H:{h};;"

    # ==============================
    # --- Software Games --------------------------------
    # ==============================
    
    def run_selected_software(self):
        """
        Runs the 'Executable' of the currently selected row if category is 'Software'.
        """
        try:
            # 1) ensure Software category
            cat = getattr(self, "currentCategory", None)
            if not isinstance(cat, str) and hasattr(self, "comboCategory"):
                cat = self.comboCategory.currentText()
            if not isinstance(cat, str) or cat.strip().lower() != "software":
                QMessageBox.information(self, self.tr("Run"), self.tr("This action is for the Software category."))
                return

            # 2) fetch selected row data
            view = self.tableView if hasattr(self, "tableView") else self.table
            sel = view.selectionModel().selectedRows()
            if not sel:
                QMessageBox.information(self, self.tr("Run"), self.tr("Select a Software row first."))
                return

            idx = sel[0]

            model = view.model()
            def get(col_name: str, default=""):
                try:
                    for c in range(model.columnCount()):
                        if model.headerData(c, Qt.Horizontal) and \
                           str(model.headerData(c, Qt.Horizontal)).strip().lower() == col_name:
                            return str(model.index(idx.row(), c).data() or "").strip()
                except Exception:
                    pass
                return default

            exec_path = get("executable") or get("path") or get("exe")
            if not exec_path:
                QMessageBox.warning(self, self.tr("Run"), self.tr("No Executable path set for this item."))
                return

            if run_software_exec(exec_path):
                return

            ep = _expand_path(exec_path)
            if os.path.exists(ep):
                _reveal_in_explorer(ep)
            else:
                QMessageBox.warning(self, self.tr("Run"), self.tr("Invalid Executable path."))
        except Exception as e:
            log.info(f"[WARN] run_selected_software: {e}")

    def open_selected_software_folder(self):
        try:
            view = self.tableView if hasattr(self, "tableView") else self.table
            sel = view.selectionModel().selectedRows()
            if not sel:
                return
            model = view.model()
            r = sel[0].row()

            # Executable column name/index
            exec_col = None
            for c in range(model.columnCount()):
                if str(model.headerData(c, Qt.Horizontal)).strip().lower() in ("executable", "path", "exe"):
                    exec_col = c; break

            if exec_col is None:
                return

            exec_path = str(model.index(r, exec_col).data() or "")
            p = _expand_path(exec_path)
            if os.path.isfile(p):
                _reveal_in_explorer(p)
            elif os.path.isdir(p):
                _reveal_in_explorer(p)
        except Exception as e:
            log.info(f"[WARN] open_selected_software_folder: {e}")

    def open_selected_software_key(self):
        try:
            view = self.tableView if hasattr(self, "tableView") else self.table
            sel = view.selectionModel().selectedRows()
            if not sel:
                return
            model = view.model()
            r = sel[0].row()

            key_col = None
            for c in range(model.columnCount()):
                if str(model.headerData(c, Qt.Horizontal)).strip().lower() in ("key path", "key", "license", "keypath"):
                    key_col = c; break

            if key_col is None:
                QMessageBox.information(self, self.tr("Key"), self.tr("No Key Path column found."))
                return

            key_path = _expand_path(str(model.index(r, key_col).data() or ""))
            if not key_path:
                QMessageBox.information(self, self.tr("Key"), self.tr("No Key Path set."))
                return

            if os.path.isdir(key_path):
                subprocess.Popen(["explorer", key_path])
            elif os.path.isfile(key_path):
                open_path(key_path)  # open with default editor/viewer
            else:
                QMessageBox.warning(self, self.tr("Key"), self.tr("Key Path not found."))
        except Exception as e:
            log.info(f"[WARN] open_selected_software_key: {e}")


    # ==============================
    # --- Install/Download games --------------------------------
    # ==============================

    def _platform_from_link(self, link: str) -> str | None:
        u = (link or "").strip().lower()
        if not u:
            return None
        # protocol-based
        for name, cfg in CLIENTS.items():
            if any(u.startswith(p) for p in cfg["protocols"]):
                return name
        # domain-based
        try:
            if u.startswith(("http://", "https://")):
                host = urlparse(u).netloc.lower()
                for name, cfg in CLIENTS.items():
                    if any(host.endswith(d) for d in cfg["domains"]):
                        return name
        except Exception:
            pass
        return None

    def _client_installed(self, platform: str) -> bool:
        cfg = CLIENTS.get(platform)
        if not cfg:
            return False

        # 1) known exe paths
        for p in cfg.get("exe_paths", ()):
            if os.path.exists(os.path.expandvars(p)):
                return True

        # 2) protocol handler
        if winreg:
            try:
                for proto in cfg.get("protocols", ()):
                    with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, proto.replace("://","")):
                        return True
            except Exception:
                pass

        # 3) uninstall keys (best-effort, match by vendor/app)
        HINTS = {
            "nvidia": "nvidia",
            "amd": "amd",
            "msi": "msi center",
            "lianli": "l-connect",
            "corsair": "icue",
            "razer": "razer synapse",
        }
        return self._installed_via_uninstall_key(HINTS.get(platform, platform))

    def build_launch_install_menu(self, *args, **kwargs):
        from features.url.url_ops import build_launch_install_menu as _impl
        return _impl(self, *args, **kwargs)

    def on_platform_help_clicked(self):
        msg = "\n".join(f"{k} = {v}" for k, v in PLATFORM_GUIDE.items())
        QMessageBox.information(self, self.tr("Platform Keywords"), msg)

    def _download_to_temp(self, url: str) -> str:
        fn = os.path.basename(url.split("?")[0]) or "download.bin"
        dst = os.path.join(tempfile.gettempdir(), fn)
        urllib.request.urlretrieve(url, dst)
        return dst

    def _confirm(self, title: str, text: str) -> bool:
        # Avoid import cycles; import inline
        mb = QMessageBox(self)
        mb.setIcon(QMessageBox.Warning)
        mb.setWindowTitle(title)
        mb.setText(text)
        mb.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        mb.setDefaultButton(QMessageBox.No)
        return mb.exec() == QMessageBox.Yes

    def _normalize_platform(self, name: str) -> str:
        n = (name or "").strip().lower()
        return ALIASES.get(n, n)

    # --- Launch / Download handler ---

    def launch_or_download(self, *args, **kwargs):
        from features.url.url_ops import launch_or_download as _impl
        return _impl(self, *args, **kwargs)

    def _safe_qv(self, key, name: str) -> bool:
        """
        Return True if QueryValueEx(name) on this registry key succeeds safely.
        Prevents FileNotFoundError / OSError when the value is missing.
        """
        try:
            winreg.QueryValueEx(key, name)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return False

    def _installed_via_uninstall_key(self, product_key_hint: str) -> bool:
        """Quick scan of Uninstall keys for a matching DisplayName or InstallLocation."""
        if not winreg:
            return False
        HIVES = (
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        )
        hint = (product_key_hint or "").lower()
        try:
            for hive, path in HIVES:
                with winreg.OpenKey(hive, path) as root:
                    for i in range(0, winreg.QueryInfoKey(root)[0]):
                        try:
                            sub = winreg.EnumKey(root, i)
                            with winreg.OpenKey(root, sub) as k:
                                name = (winreg.QueryValueEx(k, "DisplayName")[0] or "").lower()
                                loc  = (winreg.QueryValueEx(k, "InstallLocation")[0] or "").lower() if self._safe_qv(k,"InstallLocation") else ""
                                if hint and (hint in name or hint in loc):
                                    return True
                        except Exception:
                            continue
        except Exception:
            pass
        return False

    def _safe_qv(key, value):
        try:
            winreg.QueryValueEx(key, value)
            return True
        except Exception:
            return False

    # ------------------------
    # --- right click on item show menu

    def show_entry_context_menu(self, *args, **kwargs):
        from vault_store.vault_ui_ops import show_entry_context_menu as _impl
        return _impl(self, *args, **kwargs)

    def get_column_index(self, label):
        self.reset_logout_timer()
        for col in range(self.vaultTable.columnCount()):
            header = self.vaultTable.horizontalHeaderItem(col)
            if header and label.lower() in header.text().lower():
                return col
        return None

    # --- count items category 
    def get_category_usage_counts(self) -> dict:
        """Return {'CategoryName': count, ...} by scanning the vault table."""
        counts = {}
        try:
            table = getattr(self, "vaultTable", None)
            if not table:
                return counts
            headers = {}
            for c in range(table.columnCount()):
                h = table.horizontalHeaderItem(c)
                if h and h.text():
                    headers[h.text().strip().lower()] = c
            cat_col = None
            for key in ("category", "type"):
                if key in headers:
                    cat_col = headers[key]
                    break
            if cat_col is None:
                return counts
            for r in range(table.rowCount()):
                it = table.item(r, cat_col)
                cat = (it.text().strip() if it else "")
                if cat:
                    counts[cat] = counts.get(cat, 0) + 1
        except Exception as e:
                        log.error(str(f"[DEBUG] get_category_usage_counts failed: {e}"))

        return counts

    # ==============================
    # --- add/edit tab
    # ==============================    

    def _on_editor_schema_saved(self, *args, **kwargs):
        from catalog_category.catalog_category_ops import _on_editor_schema_saved as _impl
        return _impl(self, *args, **kwargs)

    def set_rounded_profile_picture(self, *args, **kwargs):
        from auth.login.auth_flow_ops import set_rounded_profile_picture as _impl
        return _impl(self, *args, **kwargs)

    # --- change user profile pic ask user to select and update image after

    def change_profile_picture(self) -> None:
        """Let the logged-in user pick a picture and save it under Config/Profile."""
        self.reset_logout_timer()
        username = self._active_username()
        if not username:
            self.safe_messagebox_warning(self, "Profile", "Please log in before changing your picture.")
            return

        # 1) Choose an image
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Profile Picture",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp)"
        )
        if not file_path:
            return

        try:
            # 2) Canonical location: %APPDATA%\Keyquorum\\Users\<user>\Config\Profile\<user>.png
            prof_dir = config_dir(username, ensure_parent=True) / "Profile"
            prof_dir.mkdir(parents=True, exist_ok=True)
            dest_path = prof_dir / f"{username}.png"

            # 3) Copy (we keep it simple; convert-to-PNG only if you want via Pillow)
            copy2(file_path, dest_path)

            # 4) Refresh UI images
            zoom = float(get_user_setting(username, "zoom_factor", 1.0) or 1.0)
            self.set_rounded_profile_picture(self.profilePicLabel, str(dest_path), zoom)

            self.set_rounded_profile_picture(self.loginPicLabel, str(dest_path), zoom)
            
        except Exception as e:
            QMessageBox.warning(self, self.tr("Profile"), f"Could not update profile picture:\n{e}")

    # --- settings for profile/settings pic labes sizes ect
    def init_profile_picture(self, layout) -> None:
        self.profilePicLabel.setFixedSize(100, 100)
        self.profilePicLabel.setAlignment(Qt.AlignCenter)
        self.profilePicLabel.setText(self.tr("No Image"))
        self.profilePicLabel1.setFixedSize(100, 100)

    def _current_username_text(self) -> str:
        try:
            w = getattr(self, "currentUsername", None) or getattr(self, "usernameField", None)
            return (w.text() or "").strip() if w else ""
        except Exception:
            return ""

    def _canonical_ci(self, name: str) -> str:
        try:
            return _canonical_username_ci(name) or name
        except Exception:
            return name

    def _default_profile_icon_path(self) -> str:
        """
        Return a bundled default icon path for login/profile pictures.
        Tries several common resource names; returns "" if none are present.
        """
        try:
            p = icon_file("default_user.png")
            if p and Path(p).is_file():
                return str(p)
        except Exception:
           return ""

    # ==============================
    # ---------- login picture (login screen)
    # ==============================
    def update_login_picture(self, *args, **kwargs):
        from auth.login.auth_flow_ops import update_login_picture as _impl
        return _impl(self, *args, **kwargs)

    def load_profile_picture(self, *args, **kwargs):
        from auth.login.auth_flow_ops import load_profile_picture as _impl
        return _impl(self, *args, **kwargs)

    def ui_catch(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            try:
                return fn(*a, **kw)
            except Exception:
                sys.excepthook(*sys.exc_info())
        return wrapper

    # ==============================
    # --- track and close open ui's
    # ==============================

    def _init_window_tracker(self):
        if not hasattr(self, "_child_windows"):
            # store weakrefs so closed dialogs don’t keep the list alive
            self._child_windows: list[weakref.ReferenceType] = []

    def _track_window(self, w: QWidget):
        """Call this right after you create/show any dialog/window."""
        self._init_window_tracker()
        try:
            self._child_windows.append(weakref.ref(w))
            # auto-prune when it’s destroyed
            try:
                w.destroyed.connect(lambda *_: self._gc_child_windows())
            except Exception:
                pass
        except Exception:
            pass

    def _gc_child_windows(self):
        """Remove dead refs."""
        if not hasattr(self, "_child_windows"):
            return
        self._child_windows = [r for r in self._child_windows if r() is not None]

    def _close_all_child_windows(self):
        """Close/hide any opened UI (password gen, add/edit entry, etc.)."""
        self._init_window_tracker()

        # 1) close everything explicitly tracked
        for r in list(self._child_windows):
            w = r() if callable(r) else None
            if not w:
                continue
            try:
                # dialogs a chance to clean up (stop timers/threads)
                for attr in ("stop", "shutdown", "closeEventHook"):
                    m = getattr(w, attr, None)
                    if callable(m):
                        try: m()
                        except Exception: pass
                if isinstance(w, QDialog):
                    w.reject()  # closes modal dialogs gracefully
                else:
                    w.close()
            except Exception:
                pass
        self._gc_child_windows()

        # 2) belt-and-braces: sweep top-level widgets owned by us
        try:
            for tw in QApplication.topLevelWidgets():
                if tw is self:
                    continue
                # if we’re parent (or ancestor) of this widget, close it
                p = tw.parentWidget()
                owned = False
                while p is not None:
                    if p is self:
                        owned = True
                        break
                    p = p.parentWidget()
                if owned:
                    try:
                        if isinstance(tw, QDialog):
                            tw.reject()
                        else:
                            tw.close()
                    except Exception:
                        pass
        except Exception:
            pass

    # ==============================
    # --- Portable USB watchdog ---
    # ==============================
    def _start_usb_watch_if_needed(self) -> None:
        """
        If running in portable mode (KeyquorumPortable on a USB drive),
        start a small timer that checks whether the underlying drive
        is still present.

        If the drive disappears while the app is running, we log out
        and close the app so no decrypted data is left in memory.
        """
        try:
            from app.paths import portable_root
            if not is_portable_mode():
                return
            log.info("[USB] User in portable mode waiting for disconnect !!!")
            from pathlib import Path
            root = portable_root()
            # anchor is like "E:\\" on Windows
            anchor_str = Path(root).anchor or getattr(Path(root), "drive", None)
            if not anchor_str:
                return
            anchor = Path(anchor_str)
        except Exception as e:
            try:
                log.debug(f"[USB] unable to start USB watch: {e}")
            except Exception:
                pass
            return

        # Reuse an existing timer if already created
        t = getattr(self, "_usb_watch_timer", None)
        if t is None:
            t = QTimer(self)
            t.setInterval(2000)  # 2 seconds
            t.timeout.connect(self._check_usb_alive)
            self._usb_watch_timer = t

        self._usb_anchor_path = anchor
        self._usb_root_path = root

        if not t.isActive():
            try:
                log.info(f"[USB] starting portable USB watch: root={root}, anchor={anchor}")
            except Exception:
                pass
            t.start()

    def _check_usb_alive(self, *args, **kwargs):
        from features.portable.portable_ops import _check_usb_alive as _impl
        return _impl(self, *args, **kwargs)

    def mousePressEvent(self, event):  
        """Handle mouse press for frameless drag, restricted to the title bar."""
        self.reset_logout_timer()
        try:
            from PySide6.QtCore import Qt as _Qt
            # Only start a drag on left button
            if event.button() == _Qt.LeftButton:
                # Qt6: position() returns QPointF in widget coords; fall back to pos() if needed
                if hasattr(event, "position"):
                    pos_in_window = event.position().toPoint()
                else:
                    pos_in_window = event.pos()

                # Only treat this as a window drag if we're actually in the title bar
                in_titlebar = False
                hit_control = False
                try:
                    if hasattr(self, "_in_titlebar"):
                        in_titlebar = bool(self._in_titlebar(pos_in_window))
                    if hasattr(self, "_hit_titlebar_control"):
                        hit_control = bool(self._hit_titlebar_control(pos_in_window))
                except Exception:
                    in_titlebar = False
                    hit_control = False

                if in_titlebar and not hit_control:
                    # Record drag offset
                    if hasattr(event, "globalPosition"):
                        gp = event.globalPosition().toPoint()
                    else:
                        gp = event.globalPos()
                    self._dragPos = gp - self.frameGeometry().topLeft()
                    event.accept()
                    return

            # Not a drag start → reset and pass to base implementation
            self._dragPos = None
            super().mousePressEvent(event)
        except Exception:
            # Last-chance fallback to default behaviour
            try:
                super().mousePressEvent(event)
            except Exception:
                pass

    def mouseMoveEvent(self, event):  
        """Move the window while dragging the title bar only."""
        self.reset_logout_timer()
        try:
            from PySide6.QtCore import Qt as _Qt
            if getattr(self, "_dragPos", None) is not None and (event.buttons() & _Qt.LeftButton):
                if hasattr(event, "globalPosition"):
                    gp = event.globalPosition().toPoint()
                else:
                    gp = event.globalPos()
                self.move(gp - self._dragPos)
                event.accept()
                return

            # Otherwise, let normal widgets handle the move
            super().mouseMoveEvent(event)
        except Exception:
            try:
                super().mouseMoveEvent(event)
            except Exception:
                pass


    # ==============================
    # --- serecty ---
    # ==============================
    # --- Basline check
    def _shorten_path(self, p: str) -> str:
        """Make long absolute paths easier to read by replacing known roots."""
        try:
            s = str(Path(p))
        except Exception:
            return p
        try:
            home = str(Path.home())
            if s.startswith(home):
                s = "~" + s[len(home):]
        except Exception:
            pass

        roots = [
            ("APP", getattr(self, "APP_ROOT", None)),
            ("DATA", getattr(self, "DATA_DIR", None)),
            ("RES", getattr(self, "RES_DIR", None)),
        ]
        for label, root in roots:
            try:
                if root and s.startswith(str(root)):
                    s = f"{label}:/" + os.path.relpath(s, start=str(root)).replace("\\", "/")
            except Exception:
                continue
        return s

    def _format_list(self, title: str, items: list[str]) -> str:
        if not items:
            return f"{title} (0):\n  (none)\n"
        body = "\n".join(f"  - {self._shorten_path(p)}" for p in items)
        return f"{title} ({len(items)}):\n{body}\n"
   
    def integrity_check_and_prompt(self, *args, **kwargs):
        from features.security_center.security_center_ops import integrity_check_and_prompt as _impl
        return _impl(self, *args, **kwargs)

    def action_add_suspect(self):
        self.reset_logout_timer()
        name, ok = QInputDialog.getText(self, self.tr("Add Watch Process"), self.tr("Process name to watch (e.g., wireshark.exe):"))
        if ok and name.strip():
            add_process_to_watch(name.strip())

    def action_add_allow(self):
        self.reset_logout_timer()
        name, ok = QInputDialog.getText(self, self.tr("Add Allowlisted Process"), self.tr("Allowlist process name (exact match):"))
        if ok and name.strip():
            add_allowlist_process(name.strip())

    # ==============================
    # --- preflight
    # ==============================
    def maybe_prompt_enable_preflight(self, parent=None):
        from ui.ui_flags import maybe_prompt_enable_preflight as _impl
        return _impl(self, parent)

    def _load_user_preflight_overrides(self, username: str) -> dict:
        from security.security_ops import _load_user_preflight_overrides as _impl
        return _impl(self, username)


    # ==============================
    # --- Audit and Lockout Management
    # ==============================
    def load_audit_table(self, *args, **kwargs):
        from security.security_ops import load_audit_table as _impl
        return _impl(self, *args, **kwargs)

    def delete_audit_logs(self, *args, **kwargs):
        from security.security_ops import delete_audit_logs as _impl
        return _impl(self, *args, **kwargs)

    def on_export_audit_clicked(self, *args, **kwargs):
        from security.security_ops import on_export_audit_clicked as _impl
        return _impl(self, *args, **kwargs)

    # ==============================
    # --- export/import/back up ---
    # ==============================
    def export_vault_with_password(self, *args, **kwargs):
        from features.backup_advisor.ui_backup_bind import export_vault_with_password as _impl
        return _impl(self, *args, **kwargs)

    def import_vault_with_password(self):
        from features.backup_advisor.ui_backup_bind import import_vault_with_password as _impl
        return _impl(self)

    # ==============================
    # --- Full backup/export (vault + salt + user_db + wrapped_key if present)
    # ==============================
    def export_vault(self):
        from features.backup_advisor.ui_backup_bind import export_vault as _impl
        return _impl(self)

    def _ensure_user_dirs(self, username: str) -> None:
        from features.backup_advisor.ui_backup_bind import _ensure_user_dirs as _impl
        return _impl(self, username)

    def import_vault(self):
        from features.backup_advisor.ui_backup_bind import import_vault as _impl
        return _impl(self)

    def import_vault_custom(self):
        from features.backup_advisor.ui_backup_bind import import_vault_custom as _impl
        return _impl(self)



    def _detect_source_hint(self, file_path: str, headers: list[str]) -> str:
        """
        Return one of: "keyquorum", "chrome", "edge", "google", "samsung", "".
        Heuristics based on filename and column headers.
        """
        fn = (os.path.basename(file_path) or "").lower()
        hs_list = [(h or "").strip().lower() for h in (headers or [])]
        hs_set = set(hs_list)
        hs = ",".join(hs_list)

        # Keyquorum/App-native (explicit marker or rich schema cues)
        if "kq_format" in hs_set or "category" in hs_set or "created_at" in hs_set or "date" in hs_set:
            return "keyquorum"

        # Chrome/Edge (identical shape)
        chrome_edge = {"name","url","username","password"}
        if hs_set.issubset(chrome_edge) and ("url" in hs_set or "username" in hs_set or "password" in hs_set):
            if "edge" in fn:
                return "edge"
            if "chrome" in fn:
                return "chrome"
            return "chrome"

        # Samsung Pass
        if {"title","username","password","url","notes"}.issubset(hs_set):
            return "samsung"

        # Google Password Manager export
        if "google" in fn or hs.startswith("name,url,username,password") or "note" in hs_list or "notes" in hs_list:
            return "google"

        return ""

    def _normalize_fields_from_browser(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _normalize_fields_from_browser as _impl
        return _impl(self, *args, **kwargs)

    def _categorize_entry(self, e: dict, source_hint: str) -> tuple[str, dict]:
        """
        Decide a category and return (category, normalized_entry).
        - App-native (keyquorum): use CSV 'category' if present (auto-create later).
        - Browser CSVs: bucket into source-specific Web Logins buckets.
        - Android app rows: detect via android:// / app:// / package: URL.
        """
        e = self._normalize_fields_from_browser(e)
        url = (e.get("URL") or "").strip()

        # Android apps from Google exports
        if url.lower().startswith(("android://", "app://", "package:")):
            pkg = url.split("://", 1)[-1]
            e["Package"] = pkg
            e["App URL"] = url
            return ("Android Apps", e)

        # App-native → use provided category (or generic)
        if source_hint == "keyquorum":
            cat = (e.get("category") or e.get("Category") or "").strip()
            if not cat:
                cat = "Web Logins" if (e.get("URL") or e.get("Website")) else "Other"
            return (cat, e)

        # Browser-specific buckets
        if source_hint == "google":
            return ("Web Logins (Google)", e)
        if source_hint == "edge":
            return ("Web Logins (Edge)", e)
        if source_hint == "chrome":
            return ("Web Logins (Chrome)", e)
        if source_hint == "samsung":
            return ("Web Logins (Samsung Pass)", e)

        # Fallback
        return ("Web Logins", e)

    # --- one-shot rename dialog for suggested categories ---------------

    def _prompt_category_renames(self, suggested: set[str]) -> dict[str, str]:
        """
        Show a small dialog with one line-edit per suggested name so the user can
        rename categories once for this import. Returns mapping old->new.
        If dialog can't be shown, returns identity mapping.
        """
        try:
            dlg = QDialog(self)
            dlg.setWindowTitle(self.tr("Rename Categories (optional)"))
            root = QVBoxLayout(dlg)
            root.addWidget(QLabel(self.tr("You can rename the suggested categories for this import:")))
            form = QFormLayout()
            edits: dict[str, QLineEdit] = {}
            for name in sorted(suggested):
                le = QLineEdit(name)
                edits[name] = le
                form.addRow(QLabel(name), le)
            root.addLayout(form)
            btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            root.addWidget(btns)
            btns.accepted.connect(dlg.accept)
            btns.rejected.connect(dlg.reject)
            if not edits:
                return {}
            if dlg.exec():
                out = {}
                for old, le in edits.items():
                    new = (le.text() or old).strip()
                    out[old] = new
                return out
            return {n: n for n in suggested}
        except Exception:
            # Headless / any error: identity mapping
            return {n: n for n in suggested}

    # ==============================
    # --- import/export csv and add to vault

    def _add_category_to_user_schema(self, category_name: str) -> bool:
        """
        Ensure 'category_name' exists in the active user's category_schema in user_db.
        Returns True if it already existed, False if newly added.
        """
        try:
            name = (category_name or "").strip()
            if not name:
                return True
            uname = self._active_username()
            canonical = self._active_username()
            if not canonical:
                return True

            schema = get_user_setting(canonical, "category_schema") or {}
            cats = list(schema.get("categories") or [])
            # case-insensitive check
            lower = name.casefold()
            if any((c.get("name") or "").strip().casefold() == lower for c in cats if isinstance(c, dict)):
                return True  # exists

            # sensible default fields
            fields = [
                {"label": "Website"},
                {"label": "Email"},
                {"label": "UserName"},
                {"label": "Password", "sensitive": True},
                {"label": "Notes"},
            ]
            cats.append({"name": name, "fields": fields})
            schema["categories"] = cats
            set_user_setting(canonical, "category_schema", schema)
            return False
        except Exception:
            return True

    def _reconcile_category_schema_with_entries(self):
        """
        Merge all categories used by entries into the user's category schema.
        Non-destructive: only adds missing categories.
        """
        try:
            used = set()
            model = getattr(self, "vaultModel", None)
            if model is not None:
                for r in range(model.rowCount()):
                    cat = (model.data(model.index(r, 0), 0) or "").strip()
                    if cat:
                        used.add(cat)

            used |= set(getattr(self, "_last_import_categories", []))

            # Ensure they exist in schema
            for cat in sorted(used):
                self._add_category_to_user_schema(cat)

            # Reload UI controls so the editor + left menu are in sync
            if hasattr(self, "reload_category_controls"):
                self.reload_category_controls()
        except Exception:
            pass

    def _default_fields_for_category(self, name: str) -> list[dict]:
        n = (name or "").strip().lower()

        web_like = (
            "web logins", "web logins (google)", "web logins (edge)",
            "web logins (chrome)"
        )
        if any(n.startswith(w) for w in web_like) or n == "web logins":
            # Web Logins categories use a consistent set of fields.  Note: we use
            # "Username" (not "UserName") to align with alias mapping, and we
            # omit "Password Expired" here because it will be appended by the
            # table loader automatically.
            return [{"label": x} for x in [
                "Website", "Email", "Username", "Password",
                "Phone Number", "Backup Code", "2FA Enabled",
                "Notes", "Date"
            ]]

        if n == "android apps":
            # Android Apps category: use "Username" rather than "UserName"
            # and omit any automatically appended fields.
            return [{"label": x} for x in [
                "Title", "Package", "Username", "Password",
                "Email", "Notes", "Date"
            ]]

        # fallback minimal category fields.  Use "Username" consistently.
        return [{"label": x} for x in ["Title", "Username", "Password", "URL", "Notes"]]

    def _ensure_category_exists_from_import(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _ensure_category_exists_from_import as _impl
        return _impl(self, *args, **kwargs)

    def _collect_entries_for_csv(self) -> list[dict]:
        """Return all vault entries for the logged-in user, excluding authenticators.

        For security, authenticator/TOTP secrets are *never* exported via CSV
        (they are only included in encrypted backups).
        """
        try:
            username = self.currentUsername.text().strip() if hasattr(self, "currentUsername") else ""
            if not username or not getattr(self, 'core_session_handle', None):
                return []

            entries = load_vault(username, self.core_session_handle) or []
            filtered: list[dict] = []

            for e in entries:
                if not isinstance(e, dict):
                    continue

                etype = (e.get("_type") or "").strip().lower()
                cat   = (e.get("category") or "").strip().lower()

                # Heuristics: treat these as authenticator rows
                has_secret = "secret_enc_b64" in e

                if (
                    etype in ("authenticator", "totp", "otp", "2fa")
                    or cat == "authenticator"
                    or has_secret
                ):
                    # skip authenticator entries for CSV
                    continue

                filtered.append(e)

            return filtered
        except Exception:
            return []

    # ==============================
    # --- zoom user profile pic value change
    # ==============================
    def auto_zoom_factor(self, value: float, *, flush: bool = False) -> None:
        from app.on_setting_change_ops import auto_zoom_factor as _impl
        return _impl(self, value, flush)


    # ==============================
    # --- Touch Screen
    # ==============================
    def _enable_touch_mode(self, *args, **kwargs):
        from app.on_setting_change_ops import _enable_touch_mode as _impl
        return _impl(self, *args, **kwargs)

    def on_touch_mode_toggled_set(self, checked: bool):
        from app.on_setting_change_ops import on_touch_mode_toggled_set as _impl
        return _impl(self, checked)

    def save_to_user_on_touch(self, checked: bool):
        from app.on_setting_change_ops import save_to_user_on_touch as _impl
        return _impl(self, checked)

    # ==============================
    # --- Reminder/watchtower checks
    # ==============================
    def scan_due_reminders(self):
        from features.reminders.reminder_ops import scan_due_reminders as _impl
        return _impl(self)

    def run_reminder_checks(self):
        try:
            from features.reminders.reminder_ops import notify_due_reminders
            notify_due_reminders(self)
        except Exception as e:
            log.error(f"[REMINDERS] notify failed: {e}")

    def start_watchtower_reminder_worker(self):
        from features.reminders.reminder_ops import start_watchtower_reminder_worker
        start_watchtower_reminder_worker(self)

    def _on_worker_alert(self, data):
       from features.reminders.reminder_ops import _on_worker_alert
       _on_worker_alert(self, data)

    def _watchtower_rescan(self):
        """
        Trigger Watchtower rescan (legacy-safe). auto notify on call
        """
        wt = getattr(self, "watchtower", None)
        if wt and hasattr(wt, "start_scan"):
            wt.start_scan()

    # ==============================
    # --- breach
    # ==============================
    def open_password_breach_checker(self):
        from features.breach_check.breach_ops import open_password_breach_checker as _impl
        return _impl(self)

    def open_hibp_for_email(self, email: str) -> None:
        from features.breach_check.breach_ops import open_hibp_for_email as _impl
        return _impl(self, email)

    def check_selected_email_breach(self):
        from features.breach_check.breach_ops import check_selected_email_breach as _impl
        return _impl(self)

    def _show_email_check_modal(self) -> tuple[bool, bool]:
        from features.breach_check.breach_ops import _show_email_check_modal as _impl
        return _impl(self)

    def enable_breach_checker_change(self, checked):
        from app.on_setting_change_ops import enable_breach_checker_change as _impl
        return _impl(self, checked)

    def _show_hibp_consent_modal(self) -> bool:
        from features.breach_check.breach_ops import _show_hibp_consent_modal as _impl
        return _impl(self)

    # ==============================
    # --- other
    # ==============================

    def enable_debug_logging_change(self, checked: bool):
        from app.on_setting_change_ops import enable_debug_logging_change as _impl
        return _impl(self, checked)


    def set_always_on_top(self, enabled: bool):
        from app.on_setting_change_ops import set_always_on_top as _impl
        return _impl(self, enabled)


# ==============================
# --- FAST STARTUP
# ==============================
def main() -> int:    
    # --- cheap USB bind check (keep early) ---
    try:
        from features.portable.portable_binding import check_usb_binding as _check_usb_binding
    except Exception as e:
        log.warning(f"{kql.i('portable')} [USB] portable_manager.check_usb_binding not available Error: {e}; skipping USB bind check")
        def _check_usb_binding(_): return True
    if not _check_usb_binding(None):
        log.error(f"{kql.i('portable')} [USB] USB binding check failed; exiting.")
        sys.exit(0)

    # ------------------------
    # Immediately apply a dark background before anything paints
    # ------------------------

    pal = app.palette()
    dark_bg = QColor(0x12, 0x14, 0x18)  # dark gray
    pal.setColor(QPalette.Window, dark_bg)
    pal.setColor(QPalette.Base, dark_bg)
    pal.setColor(QPalette.AlternateBase, dark_bg)
    app.setPalette(pal)
    app.setStyleSheet("QWidget { background-color: #121418; }")

    # ------------------------
    # Show a splash instantly
    # ------------------------
    splash_pix = QPixmap(icon_file("splash.png"))
    splash = QSplashScreen(splash_pix)
    splash.setWindowFlag(Qt.FramelessWindowHint, True)
    splash.show()
    app.processEvents()

    # ------------------------
    # Build & show main window immediately (fast path)
    # ------------------------
    try:
        log.debug(f"{kql.i('build')} [boot] instantiating KeyquorumApp fast-path…")
        w = KeyquorumApp()
        w.show()
        center_on_screen(w)
        app.processEvents()
        log.info(f"{kql.i('build')} [boot] main window shown (fast)")

        try:
            if _needs_first_run():
                from new_users.ui_wizard_create_account import InlineOnboardingWizard
                wiz = InlineOnboardingWizard(parent=w)
                center_on_screen(wiz)
                wiz.exec()
        except Exception:
            log.exception(f"{kql.i('build')} [first-run] failed to show wizard")
    except Exception as e:
        log.exception("Startup Error before event loop")
        tb = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        QMessageBox.critical(None, "Startup Error", tb[:60000])
        sys.exit(1)

    # ------------------------
    # Close the splash once UI is ready
    # ------------------------
    QTimer.singleShot(150, splash.close)

    # ------------------------
    # Run heavy checks *after* window is visible
    # ------------------------
    def _run_post_show_checks():
        # Manifest + preflight from previous code, same logic
        try:
            if is_dev:
                return
            from security.integrity_manifest import verify_manifest_auto
            ok, msg = verify_manifest_auto(show_ui=False, parent=w, dev_app_name="keyquorum-vault")
            if not ok and msg and "skipped" not in (msg or "").lower():
                from security.secure_audit import log_manifest_tamper
                log_manifest_tamper(msg)
                box = QMessageBox(w)
                box.setIcon(QMessageBox.Critical)
                box.setWindowTitle(_tr("Integrity Alert"))
                box.setText(_tr("Keyquorum integrity check failed."))
                box.setInformativeText(
                    "One or more signed files appear to be missing or modified.\n"
                    "Recommended: Quit and re-download / reinstall the app."
                )
                try: box.setDetailedText(str(msg))
                except Exception: pass
                quit_btn = box.addButton(w.tr("Quit (Recommended)"), QMessageBox.AcceptRole)
                run_btn  = box.addButton(w.tr("Run anyway"), QMessageBox.RejectRole)
                box.setDefaultButton(quit_btn)
                box.exec()
                if box.clickedButton() is quit_btn:
                    QCoreApplication.quit()
                    return
        except Exception as e:
            log.exception("Manifest verification crashed (deferred)")
            QMessageBox.critical(w, w.tr("Startup Error"), f"Manifest verification crashed:\n{e}")
            QCoreApplication.quit()
            return

        # Deferred preflight
        try:
            ensure_preflight_defaults()
            if not run_preflight_checks(is_dev=False, parent=w):
                QCoreApplication.quit()
                return
        except Exception as e:
            log.exception("Deferred preflight crashed")
            QMessageBox.warning(w, w.tr("Preflight"), f"Preflight crashed:\n{e}\nContinuing…")

    # Run the heavy checks right after first event loop tick
    QTimer.singleShot(0, _run_post_show_checks)

    # ------------------------
    # Enter event loop
    # ------------------------
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())
