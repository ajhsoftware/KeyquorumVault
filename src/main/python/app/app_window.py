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

# ==============================
# --- sysimport/environ/pyside6 backend(important)/F401/
# ==============================
from unittest import skip
import _fbs_bootstrap
import os, hmac, hashlib, sys, traceback
from app.platform_utils import open_path
from features.url.main_url import open_url, pnwed_url

# Force QtPy to use PySide6 BEFORE importing qtpy
os.environ["QT_API"] = "pyside6"
STORE_BUILD = os.getenv("KQ_STORE_BUILD", "").lower() in ("1", "true", "yes")

# ==============================
# --- PySide6
# ==============================
from qtpy import PYSIDE6, API_NAME
assert PYSIDE6, f"[API NAME] QtPy backend is {API_NAME}, expected PySide6"
from app.single_app import get_app

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

# --- qtpy (pyside6 backend)
from qtpy import uic
from qtpy import QtCore, QtWidgets
from qtpy.QtCore import (
    QSettings, Qt, QUrl, QObject, QThread, QCoreApplication,
    QSize, QPoint, QEvent, QTimer,
    QPropertyAnimation, QEasingCurve, Signal,)
from qtpy.QtCore import Signal as pyqtSignal, Slot as pyqtSlot
from qtpy.QtGui import (
    QIcon, QPixmap, QColor, QPalette, QImage, QGuiApplication,
    QDesktopServices,) 
from qtpy.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDialog, QLabel, QLineEdit, QPushButton,
    QAbstractItemView, QTabWidget, QComboBox, QTableWidget, QTableWidgetItem,
    QMessageBox, QDialogButtonBox, QProgressDialog, QStackedLayout,
    QGraphicsOpacityEffect, QFileDialog, QVBoxLayout, QTextEdit, QFormLayout, QProgressBar,
    QInputDialog, QHBoxLayout, QToolTip, QCheckBox, QSplashScreen,)    

# --- logging ---
import app.kq_logging as kql
from app.kq_logging import (
    apply_debug_flag,
    get_logfile_path,)

from pathlib import Path
from app.paths import (
    log_dir, users_root, user_root, CONFIG_DIR, profile_pic,  
    vault_file, shared_key_file, catalog_file, salt_file, identities_file, breach_cache,
    catalog_seal_file, debug_log_paths, category_schema_file,
    is_portable_mode, users_root,
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
from features.qr.qr_tools import show_qr_for_object
from features.share.share_keys import ensure_share_keys
from ui.frameless_window import FramelessWindowMixin
from features.clipboard.secure_clipboard import install_clipboard_guard, copy_secret
from security.preflight import (
    load_security_prefs, save_security_prefs,add_process_to_watch, add_allowlist_process,
    run_preflight_checks, ensure_preflight_defaults,)
from security.secure_audit import is_locked_out, log_event_encrypted
from auth.change_pw.change_password_dialog import ChangePasswordDialog
from security.security_prefs_dialog import SecurityPrefsDialog
from features.breach_check.breach_check_dialog import BreachCheckDialog
from catalog_category.category_editor import patch_mainwindow_class
# --- passkey ---
import features.passkeys.capabilities as cap
import features.passkeys.passkeys_windows as pkwin
from vault_store.authenticator_store import (
    list_authenticators, add_authenticator, add_from_otpauth_uri, delete_authenticator,
    update_authenticator, get_current_code, import_otpauth_from_qr_image, build_otpauth_uri, export_otpauth_qr_bytes
)
from auth.tfa.twofactor import has_recovery_wrap, yk_twofactor_enabled
from auth.login.login_handler import (
    validate_login, is_locked_out,
    set_recovery_mode, _canonical_username_ci,
    get_user_setting, get_user_cloud, set_user_cloud,
    get_recovery_mode, set_user_setting, get_user_record)
from catalog_category.catalog_editor_user import CatalogEditorUserDialog
from catalog_category.catalog_user import (
            ensure_user_catalog_created, load_user_catalog_raw,
            load_effective_catalogs_from_user, verify_hmac_seal, write_hmac_seal)

from catalog_category.my_catalog_builtin import CLIENTS, ALIASES, PLATFORM_GUIDE
from auth.identity_store import get_login_backup_count_quick, set_totp_secret, replace_backup_codes, mark_totp_header, verify_recovery_key
from features.share.share_keys import ensure_share_keys, export_share_id_json
from auth.pw.password_generator import show_password_generator_dialog, generate_strong_password
from vault_store.vault_store import (
    add_vault_entry, load_vault, save_vault,
    export_full_backup,)

# ==============================
# --- Third party link 
# ==============================
from functools import wraps
from typing import Optional
import weakref
import ctypes
from ctypes import wintypes
from urllib.parse import urlparse, quote
import urllib.request, urllib.error
import http.client
import datetime as dt 
import time as _t
             
# ==============================
# --- Standard library, import at top(os, sys, traceback)
# ==============================
import re as _re
import tempfile
import json, threading, socket, secrets
import subprocess
import string
from shutil import copy2, rmtree
from contextlib import contextmanager
from zipfile import ZipFile
import hashlib
import numpy as np
try:
    import winreg
except ImportError:
    winreg = None
try:
    import cv2  # OpenCV for QR decoding
except Exception:
    cv2 = None
   
# ==============================
# --- logging ---
# ==============================
# --- Logging bootstrap (unified paths) ---
from app.paths import log_dir
from app.basic import is_dev
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
apply_debug_flag(enabled=is_dev, keep_console=is_dev)

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
        except Exception:
            target = Path(log_dir()) / "users" / f"{username}.log"
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

# --- main.py (very top-level bootstrap) ---
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
# --- uppdate windows header with tint ---
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

# ==============================
# --- YubiKey login worker --- (runs in background thread) 
# ==============================
# - YubiKey backend (bundle-first ykman with CLI fallbacks)
from auth.yubi.yk_backend import YKBackend
from auth.yubi.yubikeydialog import YubiKeySetupDialog
from auth.yubi.yk_backend import set_probe_enabled
# - how long to wait before showing recovery or failed screen 
PRESENCE_GRACE_SECS = 25.0           

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


from qtpy.QtCore import QThread, Signal

try:
    from auth.yubi.yk_backend import set_probe_enabled
except Exception:
    def set_probe_enabled(val: bool):
        pass

class _YKTouchWorker(QThread):
    ok = Signal()
    err = Signal(str)
    def __init__(self, *, slot: int, serial: str | None, ykman_path: str | None, challenge_hex: str, timeout_s: int = 25):
        super().__init__()
        self.slot = int(slot or 2)
        self.serial = (serial or "").strip() or None
        self.ykman_path = (ykman_path or "").strip() or None
        self.challenge_hex = (challenge_hex or "").strip()
        self.timeout_s = int(max(5, timeout_s))

    def run(self):
        try:

            # If cancelled before even start, just exit
            if self.isInterruptionRequested():
                return


            yk = YKBackend(self.ykman_path)
            # If the slot clearly doesn't require touch, fail early so don't hang
            try:
                if hasattr(yk, "slot_requires_touch") and not yk.slot_requires_touch(self.slot):
                    raise RuntimeError("This YubiKey slot isn’t set to require touch. Reprogram it with touch in Settings → YubiKey.")
            except Exception:
                pass

            # Break the wait into small slices so requestInterruption() can stop us fast
            deadline = _t.monotonic() + float(self.timeout_s)
            while _t.monotonic() < deadline and not self.isInterruptionRequested():
                if self.isInterruptionRequested():
                    return
                
                slice_s = min(3.0, deadline - _t.monotonic())
                if slice_s <= 0:
                    break
                # one short attempt
                try:
                    _ = yk.calculate_hmac(self.slot, self.challenge_hex, self.serial, timeout=float(slice_s))
                    if self.isInterruptionRequested():
                        return
                    self.ok.emit()
                    return
                except Exception as e:
                    # Only continue looping for touch/timeouts; surface other errors
                    msg = str(e).lower()
                    if any(x in msg for x in ("timed out", "touch")):
                        continue
                    raise
            raise RuntimeError("Timed out waiting for YubiKey touch.")
        except Exception as e:
            self.err.emit(str(e))


class _YKWrapWorker(QThread):
    ok = Signal(bytes)    # unwrapped master key
    err = Signal(str)

    def __init__(self, *, password_key: bytes, cfg: dict, timeout_s: int = 25):
        super().__init__()
        self.password_key = bytes(password_key or b"")
        self.cfg = dict(cfg or {})
        self.timeout_s = int(max(5, timeout_s))

    def run(self):
        try:
            if self.isInterruptionRequested():
                return
            # Run unwrap in background (may require touch)
            from auth.yubi.yubihmac_wrap import unwrap_master_key_with_yubi


            # unwrap_master_key_with_yubi will perform the YubiKey challenge internally
            mk = unwrap_master_key_with_yubi(b"", password_key=self.password_key, cfg=self.cfg)
            if self.isInterruptionRequested():
                return
            if not isinstance(mk, (bytes, bytearray)) or len(mk) < 16:
                raise RuntimeError("YubiKey unwrap returned empty key")
            self.ok.emit(bytes(mk))
        except Exception as e:
            self.err.emit(str(e) or repr(e))


class YubiKeyLoginGateDialog(QDialog):
    """
    Waits for insert → then touch.
    After timeout, auto-switches to Backup code + Recovery key.
    """
    fallback_success = Signal()

    def __init__(
        self,
        *,
        username: str,
        password: str,
        cfg: dict,
        challenge_hex: str,
        password_key: bytes | None = None,
        insert_poll_ms: int = 1200,
        touch_timeout_s: int = 25,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle(self.tr("YubiKey Required"))
        self.setModal(True)
        self.setMinimumWidth(460)

        self.username = username
        self.password = password
        self.cfg = dict(cfg or {})
        self.challenge_hex = challenge_hex
        self.password_key = bytes(password_key) if isinstance(password_key, (bytes, bytearray, memoryview)) else None
        self.insert_poll_ms = int(max(400, insert_poll_ms))
        self.touch_timeout_s = int(max(5, touch_timeout_s))
        self._t0 = _t.monotonic()

        # YK config
        self.slot = int(self.cfg.get("slot", 2) or 2)
        self.serial = (self.cfg.get("serial") or "").strip() or None
        self.ykman_path = (self.cfg.get("ykman_path") or "").strip() or None

        # Internal flags / workers
        self._presence_inflight = False
        self._touch_inflight = False
        self._presence_worker = None
        self._worker: _YKTouchWorker | None = None
        self._closed = False
        # Mode: gate vs wrap
        self.mode = (self.cfg.get("mode") or "").strip()  # "yk_hmac_gate" or "yk_hmac_wrap"
        self.stack = QStackedLayout()

        # ----------------------------
        # Page 0: insert + touch prompt
        # ----------------------------
        p0 = QVBoxLayout()
        self.p0_status = QLabel(self.tr("Insert your YubiKey…"))
        self.p0_status.setWordWrap(True)
        p0.addWidget(self.p0_status)

        self.p0_bar = QProgressBar()
        self.p0_bar.setRange(0, 0)
        p0.addWidget(self.p0_bar)

        row0 = QHBoxLayout()
        # Button text depends on mode
        if self.mode == "yk_hmac_gate":
            backup_btn_text = self.tr("Use backup code")
        else:
            backup_btn_text = self.tr("Use backup code + Recovery Key")

        self.p0_backup_btn = QPushButton(backup_btn_text)
        self.p0_cancel_btn = QPushButton(self.tr("Cancel"))
        row0.addWidget(self.p0_backup_btn)
        row0.addStretch(1)
        row0.addWidget(self.p0_cancel_btn)
        p0.addLayout(row0)

        w0 = QDialog(self)
        w0.setLayout(p0)
        w0.setWindowFlags(Qt.Widget)
        self.stack.addWidget(w0)

        # ----------------------------
        # Page 1: fallback (backup code [+ recovery key for WRAP])
        # ----------------------------
        p1 = QVBoxLayout()

        if self.mode == "yk_hmac_gate":
            label = QLabel(self.tr("Enter a login backup code:"))
        else:
            label = QLabel(self.tr("Enter a login backup code and your Recovery Key:"))

        p1.addWidget(label)

        # Backup code field (always present)
        self.backup_edit = QLineEdit()
        self.backup_edit.setPlaceholderText(self.tr("Login backup code (single-use)"))
        p1.addWidget(self.backup_edit)

        # Recovery Key field (only for WRAP)
        if self.mode == "yk_hmac_wrap":
            self.recovery_edit = QLineEdit()
            self.recovery_edit.setPlaceholderText(self.tr("Recovery Key"))
            p1.addWidget(self.recovery_edit)
        else:
            self.recovery_edit = None  # easier to check later

        row1 = QHBoxLayout()
        self.p1_submit = QPushButton(self.tr("Submit"))
        self.p1_back = QPushButton(self.tr("Back"))
        row1.addWidget(self.p1_submit)
        row1.addStretch(1)
        row1.addWidget(self.p1_back)
        p1.addLayout(row1)

        w1 = QDialog(self)
        w1.setLayout(p1)
        w1.setWindowFlags(Qt.Widget)
        self.stack.addWidget(w1)

        # ----------------------------
        # Overall layout
        # ----------------------------
        v = QVBoxLayout(self)
        v.addLayout(self.stack)
        self.setLayout(v)

        # Wire buttons (page 0 + page 1)
        try:
            self.p0_backup_btn.clicked.connect(self._enter_backup_mode)
        except Exception:
            pass
        try:
            self.p0_cancel_btn.clicked.connect(self.reject)
        except Exception:
            pass
        try:
            self.p1_submit.clicked.connect(self._try_backup)
        except Exception:
            pass
        try:
            self.p1_back.clicked.connect(self._back_to_insert)
        except Exception:
            pass

        # Wire buttons
        self.stack.setCurrentIndex(0)

        # Timers
        self._poll = QTimer(self)
        self._poll.setInterval(self.insert_poll_ms)
        self._poll.timeout.connect(self._tick_insert)
        self._poll.start()

        self._touch_to = QTimer(self)
        self._touch_to.setSingleShot(True)
        self._touch_to.setInterval(self.touch_timeout_s * 1000)
        self._touch_to.timeout.connect(self._fallback_auto)

        try:
            set_probe_enabled(False)
        except:
            pass


    def _tick_insert(self):
        if self._closed or self._presence_inflight or self._touch_inflight:
            return
        if self.stack.currentIndex() == 1: 
            return
        self._presence_inflight = True
        worker = _YKPresenceWorker(self.ykman_path, self.serial)
        worker.found.connect(self._on_presence_result)
        self._presence_worker = worker
        worker.start()

    def _enter_backup_mode(self):
        # Stop the periodic presence polling immediately
        try:
            if getattr(self, "_poll", None) and self._poll.isActive():
                self._poll.stop()
        except Exception:
            pass

        try:
            if getattr(self, "_touch_to", None):
                self._touch_to.stop()
        except Exception:
            pass
        # Also stop a presence worker that may be mid-flight
        pw = getattr(self, "_presence_worker", None)
        if pw is not None:
            try:
                if hasattr(pw, "found"):
                    pw.found.disconnect(self._on_presence_result)
            except Exception:
                pass
            self._stop_thread(pw)
             # 🚨 emergency fallback
            try:
                if isinstance(pw, QThread) and pw.isRunning():
                    pw.terminate()
                    pw.wait(500)
            except Exception:
                pass
            self._presence_worker = None
            self._presence_inflight = False

        # Show the fallback page
        self.stack.setCurrentIndex(1)

    def _back_to_insert(self):
        """Return from fallback page to insert/touch page."""
        if self._closed:
            return
        try:
            self.stack.setCurrentIndex(0)
        except Exception:
            pass
        # restart polling/timers
        try:
            self._t0 = _t.monotonic()
        except Exception:
            pass
        try:
            if getattr(self, "_poll", None):
                self._poll.start()
        except Exception:
            pass
        try:
            self.p0_status.setText(self.tr("Insert your YubiKey…"))
        except Exception:
            pass


    def _on_presence_result(self, present: bool, serials: list):
        if self._closed:
            return
        self._presence_inflight = False
        self._presence_worker = None   # <- allow GC
        if not present:
            waited = int(_t.monotonic() - self._t0)
            try:
                self.p0_status.setText(self.tr("Insert your YubiKey… (waiting {waited}s)").format(waited=waited))
            except Exception:
                self.p0_status.setText(self.tr("Insert your YubiKey…"))
            return
        if self._poll.isActive():
            self._poll.stop()
        if self.mode == "yk_hmac_wrap":
            self._start_wrap_unwrap()
        else:
            self._start_touch()

    def _shutdown_worker(self):
        """Stop any background polling (QThread or threading.Thread) and wait briefly."""
        try:
            if hasattr(self, "_poller") and self._poller:
                try:
                    if hasattr(self._poller, "stop"):
                        self._poller.stop()
                except Exception:
                    pass
        except Exception:
            pass

        try:
            if getattr(self, "_thread", None):
                # ask Qt thread to quit and wait
                try:
                    self._thread.quit()
                except Exception:
                    pass
                try:
                    self._thread.wait(2000)
                except Exception:
                    pass
                self._thread = None
        except Exception:
            pass

        # --- threading.Thread path ---
        try:
            if getattr(self, "_stop_evt", None):
                try:
                    self._stop_evt.set()
                except Exception:
                    pass
            if getattr(self, "_worker_thread", None):
                try:
                    if self._worker_thread.is_alive():
                        self._worker_thread.join(timeout=2.0)
                except Exception:
                    pass
                self._worker_thread = None
        except Exception:
            pass

    def _start_touch(self):
        if self._closed or self._touch_inflight:
            return
        self._touch_inflight = True
        self.p0_status.setText(self.tr("YubiKey detected. Touch the YubiKey to continue…"))
        self._touch_to.start()
        self._worker = _YKTouchWorker(
            slot=self.slot, serial=self.serial, ykman_path=self.ykman_path,
            challenge_hex=self.challenge_hex, timeout_s=self.touch_timeout_s
        )
        self._worker.ok.connect(self._touch_ok)
        self._worker.err.connect(self._touch_err)
        self._worker.start()

    def _start_wrap_unwrap(self):
        """WRAP: perform unwrap in background (single touch) and return MK."""
        if self._closed or self._touch_inflight:
            return
        if not (isinstance(self.password_key, (bytes, bytearray)) and len(self.password_key) >= 16):
            QMessageBox.critical(self, self.tr("Vault locked"), self.tr("Missing password context required for YubiKey WRAP."))
            self.reject()
            return
        self._touch_inflight = True
        self.p0_status.setText(self.tr("YubiKey detected. Touch the YubiKey to continue…"))
        try:
            self._touch_to.start()
        except Exception:
            pass
        self._worker = _YKWrapWorker(password_key=bytes(self.password_key), cfg=self.cfg, timeout_s=self.touch_timeout_s)
        self._worker.ok.connect(self._wrap_ok)
        self._worker.err.connect(self._wrap_err)
        self._worker.start()

    def _wrap_ok(self, mk: bytes):
        if self._closed:
            return
        self._touch_inflight = False
        try:
            self._touch_to.stop()
        except Exception:
            pass
        # Success: return MK to caller
        self.result_mk = bytes(mk)
        self.result_mode = "wrap-hw"
        self._cleanup()
        self.accept()

    def _wrap_err(self, msg: str):
        if self._closed:
            return
        self._touch_inflight = False
        try:
            self._touch_to.stop()
        except Exception:
            pass
        low = (msg or "").lower()
        if "no yubikey" in low or "not detected" in low:
            QMessageBox.information(self, self.tr("YubiKey required"), self.tr("No YubiKey was detected.\n\nInsert your YubiKey and try again."))
        elif "timed out" in low or "touch" in low:
            QMessageBox.information(self, self.tr("YubiKey required"), self.tr("Timed out waiting for YubiKey touch."))
        else:
            QMessageBox.critical(self, self.tr("YubiKey error"), msg or self.tr("YubiKey operation failed."))
        # Stay on page 0 for retry (poll can restart)
        try:
            self._poll.start()
        except Exception:
            pass


    def _touch_ok(self):
        if self._closed:
            return
        self._touch_inflight = False
        try: self._touch_to.stop()
        except Exception: pass
        # stop workers/timers before closing dialog to avoid late signals
        self._cleanup()
        self.accept()

    def _touch_err(self, msg: str):
        if self._closed:
            return
        self._touch_inflight = False
        self._worker = None
        self.p0_status.setText(
            self.tr("YubiKey error: {msg}\nYou can retry, or use a backup code + recovery key.").format(msg)
        )
        # Only restart polling if we're on the hardware page
        if self.stack.currentIndex() == 0 and getattr(self, "_poll", None) and not self._poll.isActive():
            self._poll.start()

    def _fallback_auto(self):
        self.stack.setCurrentIndex(1)

    # inside YubiKeyLoginGateDialog
    from auth.pw.utils_recovery import recovery_key_to_mk

    # yubi key recovery 
    def _try_backup(self):
        """Backup fallback.
        - GATE: consume login backup code (identity password required), then accept.
        - WRAP: require Recovery Key + login backup code, derive MK, then accept.
        """
        if getattr(self, "_closed", False):
            return

        code = (getattr(self, "backup_edit", None).text() if getattr(self, "backup_edit", None) else "").strip()
        rk = (getattr(self, "recovery_edit", None).text() if getattr(self, "recovery_edit", None) else "").strip()

        # Detect mode best-effort
        mode = (getattr(self, "mode", "") or "").strip().lower()

        def _norm_rk(s: str) -> str:
            return "".join(ch for ch in (s or "") if ch.isalnum()).upper()

        # --- Gate path
        if mode == "yk_hmac_gate":
            if not code:
                QMessageBox.critical(self, self.tr("Backup Code"), self.tr("Please enter your login backup code."))
                return
            if not _verify_and_consume_login_backup_with_pw(self.username, self.password, code):
                QMessageBox.critical(self, self.tr("Backup Code"), self.tr("That backup code is invalid or already used."))
                return

            self.result_mk = None
            self.result_mode = "gate-backup"
            if hasattr(self, "_cleanup"):
                self._cleanup()
            self.accept()
            return

        # --- Wrap path
        if not code or not rk:
            QMessageBox.critical(
                self,
                self.tr("Missing details"),
                self.tr("Enter both a Recovery Key and a login backup code."),
            )
            return

        rk_norm = _norm_rk(rk)

        if not _verify_recovery_key(self.username, rk_norm):
            QMessageBox.critical(self, self.tr("Recovery Key"), self.tr("That Recovery Key is not valid for this account."))
            return

        if not _verify_and_consume_login_backup_with_pw(self.username, self.password, code):
            QMessageBox.critical(self, self.tr("Backup Code"), self.tr("That backup code is invalid or already used."))
            return

        try:
            from auth.pw.utils_recovery import recovery_key_to_mk
            mk = recovery_key_to_mk(rk_norm)
        except Exception:
            QMessageBox.critical(self, self.tr("Recovery Key"), self.tr("Could not apply Recovery Key."))
            return

        self.result_mk = bytes(mk)
        self.result_mode = "recovery+backup"
        if hasattr(self, "_cleanup"):
            self._cleanup()
        self.accept()

    def accept(self):
        self._cleanup()
        super().accept()

    # stop timers
    def _stop_thread(self, worker_obj):
        """
        Stop a QThread *subclass* (_YKTouchWorker/_YKPresenceWorker) or a QObject-in-QThread,
        or a python threading.Thread. Never blocks on the GUI thread.
        """
        if not worker_obj:
            return

        # Case A: worker_obj *is* a QThread
        if isinstance(worker_obj, QThread):
            gui_th = QCoreApplication.instance().thread() if QCoreApplication.instance() else None
            if worker_obj is gui_th or worker_obj is QThread.currentThread():
                return
            try: worker_obj.requestInterruption()
            except Exception: pass
            try: worker_obj.quit()
            except Exception: pass
            try: worker_obj.wait(2000)
            except Exception: pass
            return

        # Case B: QObject moved to a QThread
        th = None
        try:
            th = worker_obj.thread() if hasattr(worker_obj, "thread") else None
        except Exception:
            th = None

        if isinstance(th, QThread):
            gui_th = QCoreApplication.instance().thread() if QCoreApplication.instance() else None
            if th is gui_th or th is QThread.currentThread():
                return
            try:
                # ask the QObject loop to stop
                if hasattr(worker_obj, "stop"):
                    worker_obj.stop()
            except Exception: pass
            try: th.requestInterruption()
            except Exception: pass
            try: th.quit()
            except Exception: pass
            try: th.wait(2000)
            except Exception: pass
            return

        # Case C: python threading.Thread
        try:
            if hasattr(worker_obj, "stop"):
                worker_obj.stop()
        except Exception:
            pass
        try:
            if hasattr(worker_obj, "is_alive") and worker_obj.is_alive():
                worker_obj.join(timeout=2.0)
        except Exception:
            pass

    def _cleanup(self):
        """Stop timers, detach signals, stop workers."""
        if getattr(self, "_closed", False):
            return
        self._closed = True

        # Timers
        for tname in ("_poll", "_touch_to"):
            t = getattr(self, tname, None)
            if t:
                try:
                    t.stop()
                except Exception:
                    pass
                try:
                    t.timeout.disconnect()
                except Exception:
                    pass
                setattr(self, tname, None)

        # Presence worker
        pw = getattr(self, "_presence_worker", None)
        if pw is not None:
            try:
                if hasattr(pw, "found"):
                    pw.found.disconnect(self._on_presence_result)
                if hasattr(pw, "finished"):
                    pw.finished.disconnect()
            except Exception:
                pass
            self._stop_thread(pw)
           # 🚨 emergency fallback
            try:
                if isinstance(pw, QThread) and pw.isRunning():
                    pw.terminate()
                    pw.wait(500)
            except Exception:
                pass

        self._presence_worker = None
        self._presence_inflight = False

        try:
            set_probe_enabled(False)
        except:
            pass

        # Touch worker
        tw = getattr(self, "_worker", None)
        if tw is not None:
            try:
                if hasattr(tw, "ok"):
                    tw.ok.disconnect(self._touch_ok)
                if hasattr(tw, "err"):
                    tw.err.disconnect(self._touch_err)
                if hasattr(tw, "finished"):
                    tw.finished.disconnect()
            except Exception:
                pass
            self._stop_thread(tw)
            # 🚨 emergency fallback
            try:
                if isinstance(tw, QThread) and tw.isRunning():
                    tw.terminate()
                    tw.wait(500)
                pass
            except Exception:
                pass
        self._worker = None
        self._touch_inflight = False
   
    # ------------------------
    # Robust cleanup helpers (override-safe)
    # ------------------------
    def _stop_thread(self, worker_obj):
        """Best-effort stop for QThread/worker objects and python threads."""
        try:
            if worker_obj is None:
                return
            # QThread (or subclass)
            if hasattr(worker_obj, "quit") and callable(getattr(worker_obj, "quit")):
                try:
                    worker_obj.quit()
                except Exception:
                    pass
            if hasattr(worker_obj, "requestInterruption") and callable(getattr(worker_obj, "requestInterruption")):
                try:
                    worker_obj.requestInterruption()
                except Exception:
                    pass
            if hasattr(worker_obj, "wait") and callable(getattr(worker_obj, "wait")):
                try:
                    worker_obj.wait(1500)
                except Exception:
                    pass
            # QObject worker with stop() / abort()
            for meth in ("stop", "abort", "cancel"):
                if hasattr(worker_obj, meth) and callable(getattr(worker_obj, meth)):
                    try:
                        getattr(worker_obj, meth)()
                    except Exception:
                        pass
            # python threading.Thread
            if hasattr(worker_obj, "join") and callable(getattr(worker_obj, "join")):
                try:
                    worker_obj.join(timeout=1.5)
                except Exception:
                    pass
        except Exception:
            pass

    def _cleanup(self):
        """Stop timers, detach signals, and stop workers (safe to call multiple times)."""
        if getattr(self, "_closed", False):
            return
        self._closed = True

        # timers
        for tname in ("_insert_timer", "_touch_timer", "_fallback_timer"):
            try:
                t = getattr(self, tname, None)
                if t:
                    t.stop()
            except Exception:
                pass

        # stop thread workers if present
        for wname in ("_presence_thread", "_touch_thread", "_wrap_thread", "_thread_worker"):
            try:
                w = getattr(self, wname, None)
                if w:
                    self._stop_thread(w)
            except Exception:
                pass

    def reject(self):
        set_probe_enabled(False)
        self._cleanup()
        self._shutdown_worker()
        super().reject()

    def closeEvent(self, e):
        set_probe_enabled(False)
        self._cleanup()
        super().closeEvent(e)

class _YKPresenceWorker(QThread):
    found = Signal(bool, list)   # (present, serials)
    def __init__(self, ykman_path: str | None, want_serial: str | None):
        super().__init__()
        self.ykman_path = (ykman_path or "").strip() or None
        self.want_serial = (want_serial or "").strip() or None
    
    def run(self):
        from PySide6.QtCore import QThread
        try:
            while not self.isInterruptionRequested():
                try:
                    yk = YKBackend(self.ykman_path)
                    serials = list(yk.list_serials() or [])
                    present = bool(serials) if not self.want_serial else (self.want_serial in serials or "(present)" in serials)
                    self.found.emit(present, serials)
                except Exception:
                    self.found.emit(False, [])
                QThread.msleep(600)  # allows interruption to work quickly
        finally:
            pass

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
# --- prefligh safe ---
# ==============================
def safe_preflight() -> tuple[bool, str]:
    """
    Call run_preflight_checks() safely.
    Works whether it returns a bool or (ok, reason).
    Returns: (ok, reason)
    """
    try:
        # try the simple style (bool or (ok, reason))
        result = run_preflight_checks()
        if isinstance(result, tuple) and len(result) >= 1:
            ok = bool(result[0])
            reason = str(result[1]) if len(result) >= 2 else ""
            return ok, reason
        return bool(result), ""
    except Exception as e:
        tb = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        log.error(str(f"{kql.i('err')} [ERROR] 🛑 Preflight checks crashed:\n{tb}"))
        return False, f"Preflight crashed: {e}"

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
        
        if verify_recovery_key:
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
    
    # legacy helper used for baseline writes; keep behavior
    try:
        log.debug(f"[USB] salt_file fn id={id(salt_file)} "
            f"mode={is_portable_mode()} users_root={users_root()}")
        sp = salt_file(user, ensure_parent=False)
        return sp.read_bytes()
    except Exception:
        return _read_user_salt(user) or b""

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
        category_schema_file(username, ensure_parent=False),
        catalog_file(username, ensure_parent=False),         
        catalog_seal_file(username, ensure_parent=False),
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
    """Returns dict with booleans for history/cloud and optional GPO flags (Windows only)."""
    from features.clipboard.secure_clipboard import _win_clipboard_risk_state as __win_clipboard_risk_state
    return __win_clipboard_risk_state()
    
def maybe_warn_windows_clipboard(username: str, copy=True) -> None:
    """Show a one-time warning if Windows Clipboard history / sync are ON."""
    from ui.ui_flags import maybe_warn_windows_clipboard as _maybe_warn_windows_clipboard
    return _maybe_warn_windows_clipboard(copy)

def secure_copy(text: str, ttl_ms: int = None, username:str = None):
    from features.clipboard.secure_clipboard import secure_copy as _secure_copy
    return _secure_copy(text, ttl_ms, username)

# ==============================
# --- CSV Import ---
# ==============================
class DedupeResolverDialog(QDialog):
    """
    Shows all duplicate collisions in one table.
    Each row: Category, Title/Name, Username, URL, Existing (summary), Incoming (summary), Action.
    Actions: Skip / Update existing / Keep both.
    """
    def __init__(self, parent, collisions: list[tuple[tuple, dict, dict]]):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Resolve Duplicate Entries"))
        self.resize(980, 520)
        self._collisions = collisions
        self.result_actions: list[str] = []  # "skip" | "update" | "keep"
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)

        help_lbl = QLabel(self.tr("Duplicates were found. Choose how to resolve each row:"))
        help_lbl.setWordWrap(True)
        layout.addWidget(help_lbl)

        self.table = QTableWidget(self)
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Category", "Title/Name", "Username", "URL",
            "Existing (summary)", "Incoming (summary)", "Action"
        ])
        self.table.setRowCount(len(self._collisions))
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        def get(o: dict, *keys):
            for k in keys:
                v = o.get(k)
                if v:
                    return v
            return ""

        def summarize(d: dict) -> str:
            keys = ["Title","Name","Username","URL","Email","Notes","Date","created_at"]
            parts = []
            for k in keys:
                v = d.get(k)
                if v:
                    v = v if len(v) <= 120 else (v[:117] + "…")
                    parts.append(f"{k}: {v}")
            extras = [k for k in d.keys() if k not in keys and k not in ("category",)]
            for k in sorted(extras)[:5]:
                v = d.get(k)
                if v:
                    v = v if len(v) <= 120 else (v[:117] + "…")
                    parts.append(f"{k}: {v}")
            return "\n".join(parts) if parts else "(empty)"

        for r, (key, existing, incoming) in enumerate(self._collisions):
            cat = (existing.get("category") or incoming.get("category") or "")
            title = get(existing, "Title", "Name", "label") or get(incoming, "Title", "Name", "label")
            user  = get(existing, "Username", "User") or get(incoming, "Username", "User")
            url   = get(existing, "URL", "Site") or get(incoming, "URL", "Site")

            self.table.setItem(r, 0, QTableWidgetItem(cat))
            self.table.setItem(r, 1, QTableWidgetItem(title))
            self.table.setItem(r, 2, QTableWidgetItem(user))
            self.table.setItem(r, 3, QTableWidgetItem(url))

            it_exist = QTableWidgetItem(summarize(existing))
            it_exist.setFlags(it_exist.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(r, 4, it_exist)

            it_in = QTableWidgetItem(summarize(incoming))
            it_in.setFlags(it_in.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(r, 5, it_in)

            combo = QComboBox(self.table)
            combo.addItems([self.tr("Update existing"), self.tr("Keep both"), self.tr("Skip")])
            combo.setCurrentIndex(0)
            self.table.setCellWidget(r, 6, combo)

        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        # Bulk action buttons
        btn_row = QHBoxLayout()
        btn_set_update = QPushButton(self.tr("All → Update"))
        btn_set_keep   = QPushButton(self.tr("All → Keep both"))
        btn_set_skip   = QPushButton(self.tr("All → Skip"))
        btn_row.addWidget(btn_set_update)
        btn_row.addWidget(btn_set_keep)
        btn_row.addWidget(btn_set_skip)
        btn_row.addStretch(1)
        layout.addLayout(btn_row)

        def set_all(idx: int):
            for r in range(self.table.rowCount()):
                w = self.table.cellWidget(r, 6)
                if isinstance(w, QComboBox):
                    w.setCurrentIndex(idx)

        btn_set_update.clicked.connect(lambda: set_all(0))
        btn_set_keep.clicked.connect(lambda: set_all(1))
        btn_set_skip.clicked.connect(lambda: set_all(2))

        # OK/Cancel
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        btn_ok = QPushButton(self.tr("Apply"))
        btn_cancel = QPushButton(self.tr("Cancel"))
        bottom.addWidget(btn_ok)
        bottom.addWidget(btn_cancel)
        layout.addLayout(bottom)

        btn_ok.clicked.connect(self._accept)
        btn_cancel.clicked.connect(self.reject)

    def _accept(self):
        mapping = {0: "update", 1: "keep", 2: "skip"}
        self.result_actions = []
        for r in range(self.table.rowCount()):
            w = self.table.cellWidget(r, 6)
            idx = w.currentIndex() if isinstance(w, QComboBox) else 0
            self.result_actions.append(mapping.get(idx, "update"))
        self.accept()

# ==============================
# --- Camera QR Scanner Dialog --- (Auth ADD)
# ==============================
class _QRCameraScannerDialog(QDialog):
    """Minimal webcam QR scanner that returns an otpauth:// URI if found."""
    found_uri = None

    def __init__(self, parent=None, device_index=0):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Scan TOTP QR"))
        self.setModal(True)
        self.setMinimumSize(640, 480)

        self._video = QLabel(self)
        self._video.setAlignment(Qt.AlignCenter)
        self._hint = QLabel(self.tr("Point your camera at the TOTP QR code…"))
        self._hint.setStyleSheet("color: gray;")

        self._cancel = QPushButton(self.tr("Cancel"))
        self._cancel.clicked.connect(self.reject)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn_row.addWidget(self._cancel)

        lay = QVBoxLayout(self)
        lay.addWidget(self._video)
        lay.addWidget(self._hint)
        lay.addLayout(btn_row)

        # OpenCV capture
        try:
            if not cv2 == None:
                self._cv2 = cv2
        except Exception:
            self._cv2 = None
            self._hint.setText(self.tr("OpenCV not available. Install with: pip install opencv-python"))
            return

        self._cap = self._cv2.VideoCapture(device_index, self._cv2.CAP_DSHOW)
        if not self._cap or not self._cap.isOpened():
            self._hint.setText(self.tr("Could not open camera."))
            return

        self._det = self._cv2.QRCodeDetector()

        self._timer = QTimer(self)
        self._timer.setInterval(33)  # ~33 fps
        self._timer.timeout.connect(self._on_tick)
        self._timer.start()

    def _on_tick(self):
        if not self._cv2 or not self._cap:
            return
        ok, frame = self._cap.read()
        if not ok or frame is None:
            return

        # Detect/decode (multi) QR
        try:
            # Newer OpenCV: detectAndDecodeMulti
            retval, decoded_infos, points, _ = self._det.detectAndDecodeMulti(frame)
            payloads = decoded_infos if (retval and decoded_infos) else []
        except Exception:
            # Fallback: single
            payload, pts = self._det.detectAndDecode(frame)
            payloads = [payload] if payload else []
            points = [pts] if pts is not None else None

        # If saw an otpauth URI, accept and close
        for s in payloads:
            if isinstance(s, str) and s.startswith("otpauth://"):
                self.found_uri = s.strip()
                self.accept()
                return

        # Draw boxes
        if points is not None and len(points) > 0:
            try:
                # points: list of arrays Nx1x2 or Nx2
                for p in points:
                    pts = p.reshape(-1, 2).astype(int)
                    for i in range(len(pts)):
                        a = tuple(pts[i]); b = tuple(pts[(i+1) % len(pts)])
                        self._cv2.line(frame, a, b, (0, 255, 0), 2)
            except Exception:
                pass

        rgb = self._cv2.cvtColor(frame, self._cv2.COLOR_BGR2RGB)
        h, w, ch = rgb.shape
        qimg = QImage(rgb.data, w, h, ch * w, QImage.Format.Format_RGB888)
        self._video.setPixmap(QPixmap.fromImage(qimg))

    def reject(self):
        self._cleanup()
        super().reject()

    def accept(self):
        self._cleanup()
        super().accept()

    def _cleanup(self):
        try:
            if hasattr(self, "_timer") and self._timer: self._timer.stop()
        except Exception:
            pass
        try:
            if hasattr(self, "_cap") and self._cap and self._cap.isOpened():
                self._cap.release()
        except Exception:
            pass

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
from features.url.main_url import SITE_HELP, PRIVACY_POLICY, APP_ID

# ==============================
# --- Browser  Extensions  ---
# ==============================
# --- URL Bridge Values  ---
COLUMN_URL      = 0     # - "Website" Match Table
COLUMN_USERNAME = 1     # - "Email" Match Table
COLUMN_PASSWORD = None  # - None if no visible password column
# --- Bridge/table roles (module-level) ---
ENTRY_ID_ROLE = int(Qt.ItemDataRole.UserRole) + 101
HAS_TOTP_ROLE = int(Qt.ItemDataRole.UserRole) + 102
SECRET_ROLE   = int(Qt.ItemDataRole.UserRole)          # real secret for sensitive cells
URL_ROLE      = int(Qt.ItemDataRole.UserRole) + 104    # optional canonical URL (if you ever set it)
# --- Local Server Set
appref = None  # set start_bridge_server
server_version = "KQBridge/1.0"
protocol_version = "HTTP/1.0"   # simpler; no keep-alive
# --- Allow Only
_ALLOW_METHODS = "GET, POST, OPTIONS"
_ALLOW_HEADERS = "Content-Type, Authorization, X-Auth-Token, X-KQ-Token"
# --- http/https (NOTE: make option in setting to allow/block http sites)
if is_dev:
    ALLOW_LOCAL_HTTP  = True  # True in dev HTTP Mode 
else:
    ALLOW_LOCAL_HTTP = False
    
from bridge.bridge_helpers import WEBFILL_COL

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

# --- Trash Delete
TRASH_KEEP_DAYS_DEFAULT = 30  # can be overridden by env KQ_TRASH_KEEP_DAYS # NOTE: Might add a setting

QWIDGETSIZE_MAX = 16777215  # Qt's max widget size

# Tweak these to taste
LOGIN_SIZE = QSize(400, 620)  # - w, h
VAULT_SIZE = QSize(1000, 400) # - w, h

# ==============================
# --- Bridge / Allowed Origins (unified paths) ---
# ==============================

# Default allowed origins (browser extensions)
_DEFAULT_ORIGINS = {
    # Store ID
    "chrome-extension://jcblpckopkkhokdjdojlblknikfahbgb",
    # Dev ID (found by loading dev extension locally)
    "chrome-extension://lciebglepcghjjlaldlejfiehibemgef",
}

# Use unified config_dir() instead of CONFIG_DIR
ORIGINS_PATH = Path(config_dir()) / "allowed_origins.json"

_origin_cache = {"set": set(_DEFAULT_ORIGINS), "mtime": 0.0}
_origin_lock = threading.Lock()

def _read_file() -> tuple[set[str], float]:
    """Read the JSON file and return (set, mtime). Returns (empty, 0.0) on error/missing."""
    if not ORIGINS_PATH.exists():
        return set(), 0.0
    try:
        mtime = ORIGINS_PATH.stat().st_mtime
        data = json.loads(ORIGINS_PATH.read_text(encoding="utf-8"))
        if isinstance(data, list):
            cleaned = {str(x).strip() for x in data if str(x).strip()}
            return cleaned, mtime
    except Exception:
        pass
    return set(), 0.0

def refresh_allowed_origins(force: bool = False) -> set[str]:
    """Refresh cache from disk (merged with defaults)."""
    with _origin_lock:
        file_set, mtime = _read_file()
        if force or mtime != _origin_cache["mtime"] or not _origin_cache["set"]:
            merged = set(_DEFAULT_ORIGINS) | file_set
            _origin_cache["set"] = merged
            _origin_cache["mtime"] = mtime
        return set(_origin_cache["set"])

def load_allowed_origins() -> set[str]:
    """Public loader: just refresh and return."""
    return refresh_allowed_origins(force=False)

def save_allowed_origins(new_set: set[str]) -> None:
    """Persist a set to disk (without losing defaults), update cache, keep dirs safe."""
    normalized = {str(x).strip() for x in new_set if str(x).strip()}
    # Always preserve defaults when saving
    out = sorted(set(_DEFAULT_ORIGINS) | normalized)
    ORIGINS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ORIGINS_PATH.write_text(json.dumps(out, indent=2), encoding="utf-8")
    # Update cache immediately
    with _origin_lock:
        _origin_cache["set"] = set(out)
        try:
            _origin_cache["mtime"] = ORIGINS_PATH.stat().st_mtime
        except Exception:
            pass

def is_origin_allowed(origin: str) -> bool:
    """Check if a given origin string is allowed."""
    return str(origin).strip() in load_allowed_origins()

def add_allowed_origin(origin: str) -> set[str]:
    """Add a single origin and persist."""
    cur = load_allowed_origins()
    cur.add(str(origin).strip())
    save_allowed_origins(cur)
    return load_allowed_origins()

def remove_allowed_origin(origin: str) -> set[str]:
    """Remove a single origin and persist (defaults are retained automatically)."""
    cur = load_allowed_origins()
    cur.discard(str(origin).strip())
    save_allowed_origins(cur)
    return load_allowed_origins()

ALLOWED_ORIGINS = refresh_allowed_origins(force=True)

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

    def init_catalogs_for_user(self, user_root: str):
        # If have the session key, use the proper encrypted + merged loader
        if isinstance(getattr(self, "userKey", None), (bytes, bytearray)):
            self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE, _ = self._load_catalog_effective(user_root)
            return

        # Fallback (should rarely happen): no key yet, load minimal built-ins
        ensure_user_catalog_created(user_root, CLIENTS, ALIASES, PLATFORM_GUIDE)
        self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE, _ = load_effective_catalogs_from_user(
            user_root, CLIENTS, ALIASES, PLATFORM_GUIDE
        )

    def __init__(self):
        super().__init__()

        # ==============================
        # Session key state (must always exist; DPAPI/Yubi flows may set later)
        # ==============================
        self.userKey = None        # master key / vault KEK in-memory after unlock
        self.current_mk = None     # alias used by some flows
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
        self._connect_ui_scale_controls()


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
        # self._init_passkeys_table() # NOTE: passkey not full working yet

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
        if not self.vault_unlocked or not self.current_mk or not self.current_username:
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

    def __init__backup_avisor(self, *args, **kwargs):
        from app.misc_ops import __init__backup_avisor as _impl
        return _impl(self, *args, **kwargs)

    def _resolve_backup_callable(self):
        from features.backup_advisor.ui_backup_bind import resolve_backup_callable as __resolve_backup_callable
        return __resolve_backup_callable(self)

        """
        Try likely method names on self; return a callable or a stub that warns and returns False.
        """
        candidates = [
            "export_evault_with_password", 
            "export_vault_with_password",
            "export_vault_secure",
            "export_vault",                
            "backup_now",                   
        ]
        for name in candidates:
            fn = getattr(self, name, None)
            if callable(fn):
                return fn

        # final fallback: a stub that informs the user
        def _no_backup_stub():
            QMessageBox.warning(
                self,
                "Backup",
                "No backup function is available in this build. "
                "Please add/enable an export/backup function."
            )
            return False
        return _no_backup_stub
   
    def _cleanup_on_logout(self):
        from features.backup_advisor.ui_backup_bind import cleanup_on_logout as __cleanup_on_logout
        return __cleanup_on_logout(self)

        self.set_status_txt(self.tr("cleaning up on logout"))
        # 1) Last-chance prompt (only if mode includes logout)
        try:
            if getattr(self, "_backup_remind_mode", "both") in ("logout", "both"):
                adv = getattr(self, "backupAdvisor", None)
                self.set_status_txt(self.tr("Last Changes backup"))
                if adv:
                    # On logout prompt if either:
                    #  - mode includes logout AND changes >= threshold (same rule as in-session), OR
                    #  - you prefer: always prompt on logout when mode includes logout (uncomment next line)
                    # changes = max(changes, threshold)  # <- forces prompt once on logout
                    changes   = int(adv.pending_changes())
                    threshold = max(1, int(getattr(adv, "threshold", 5) or 5))
                    if changes >= threshold:
                        adv.prompt_to_backup_now(force=True)
        except Exception:
            pass

        # 2) Stop timer (if you add scheduler later)
        try:
            self.set_status_txt(self.tr("Stoping Timers"))
            if getattr(self, "backupScheduler", None) and hasattr(self.backupScheduler, "timer"):
                self.backupScheduler.timer.stop()
        except Exception:
            pass

        # 3) Clear refs
        self.set_status_txt(self.tr("Backup Clean"))
        self.backupAdvisor = None
        self.backupScheduler = None

    # ==============================
    # Default state reset
    # ==============================
    def __init__default_values(self, *args, **kwargs):
        from app.misc_ops import __init__default_values as _impl
        return _impl(self, *args, **kwargs)

    def _on_any_entry_changed(self):
        if getattr(self, "_backup_remind_mode", "both") in ("changes", "both"):
            if hasattr(self, "backupAdvisor") and self.backupAdvisor:
                self.backupAdvisor.note_change()

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
        from app.misc_ops import _maybe_show_release_notes as _impl
        return _impl(self, *args, **kwargs)

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
            u = (self.currentUsername.text() or "").strip()
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
        raw = (self.currentUsername.text() or "").strip() if hasattr(self, "currentUsername") else ""
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

        if not getattr(self, "userKey", None):
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

        This runs after login, once self.userKey is available.
        """
        try:
            import features.passkeys.passkeys_store as pkstore
        except Exception as e:
            try:
                log.debug(f"[PASSKEY] passkeys_store not available: {e}")
            except Exception:
                pass
            return

        # 2) wire the vault I/O + crypto hooks (we have self.userKey now)
        def _read_blob(name: str) -> bytes | None:
            return self.vault_read_encrypted_blob(name)

        def _write_blob(name: str, data: bytes) -> None:
            self.vault_write_encrypted_blob(name, data)

        def _encrypt(plaintext: bytes) -> bytes:
            return self.vault_encrypt_with_master(self.userKey, plaintext)

        def _decrypt(ciphertext: bytes) -> bytes:
            return self.vault_decrypt_with_master(self.userKey, ciphertext)

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
        uname = (self.currentUsername.text() or "").strip() if hasattr(self, "currentUsername") else ""
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
    # --- Touch Screen ---------------- (V1)
    # ==============================
    def _enable_touch_mode(self, *args, **kwargs):
        from app.misc_ops import _enable_touch_mode as _impl
        return _impl(self, *args, **kwargs)

    def on_touch_mode_toggled_set(self, checked: bool):
        # apply immediately (enable when True, restore when False)
        self._touch_init_done = True
        self._enable_touch_mode(force=bool(checked))

    def save_to_user_on_touch(self, checked: bool):
        self.set_status_txt(self.tr("Saving Touch mode {state}").format(state=checked))
        log.info(f"{kql.i('ui')} [UI] on touch mode toggled: {checked}")
        """User flipped the Touch Mode checkbox."""
        try:
            u = (self.currentUsername.text() or "").strip()
            if u:
                set_user_setting(u, "touch_mode", bool(checked))
                update_baseline(username=u, verify_after=False, who=self.tr("TouchMode Settings Changed"))                
        except Exception:
            pass
        self.on_touch_mode_toggled_set(checked)
        self.set_status_txt(self.tr("Done"))

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
        from app.misc_ops import maybe_show_quick_tour as _impl
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
    # --- Cloud Sync----------------
    # ==============================

    def on_select_cloud_vault(self, *args, **kwargs):
        from vault_store.vault_ui_ops import on_select_cloud_vault as _impl
        return _impl(self, *args, **kwargs)

    def _show_cloud_risk_modal(self, *args, **kwargs):
        from app.misc_ops import _show_cloud_risk_modal as _impl
        return _impl(self, *args, **kwargs)

    def on_button_sync_cloud(self):
        try:
            self.set_status_txt(self.tr("Cloud: syncing…"))

            if not getattr(self, "cloud_enabled", False):
                QMessageBox.information(self, self.tr("Cloud sync"), self.tr("Cloud Sync is not enabled."))
                return

            username = self._active_username()
            if not username:
                QMessageBox.information(self, self.tr("Cloud sync"), self.tr("Please log in first."))
                return

            # Always (re)build the engine so its closures bind to THIS username
            self._configure_sync_engine(username)

            if (self.sync_engine is None) or (not self.sync_engine.configured()):
                QMessageBox.information(
                    self, self.tr("Cloud sync"),
                    self.tr("Sync engine is not configured. Choose a cloud vault file first."))
                return

            key = getattr(self, "userKey", None)
            if not key:
                QMessageBox.information(self, self.tr("Cloud sync"), self.tr("Please log in first."))
                return

            res = str(self.sync_engine.sync_now(key, interactive=True) or "")
            self.set_status_txt(self.tr("Cloud: done"))

            # If the result indicates a pull/merge, refresh integrity baseline
            _r = res.lower()
            if _r.startswith("pulled") or ("conflict" in _r) or ("download" in _r):
                try:
                    update_baseline(username=username, verify_after=False, who=self.tr("OnCloud Sync Settings Changed")) 
                except Exception:
                    pass  # keep UX smooth even if baseline refresh throws
            msg = self.tr("Result: ") + f"{res}"
            QMessageBox.information(self, self.tr("Cloud sync"), msg)

        except Exception as e:
            try:
                import logging
                logging.getLogger(__name__).exception("Cloud sync failed")
            except Exception:
                pass
            self.set_status_txt(self.tr("Cloud: failed"))
            QMessageBox.warning(self, self.tr("Cloud sync"), f"Error: {e}")

    def _toggle_cloud_wrap(self, *args, **kwargs):
        from app.misc_ops import _toggle_cloud_wrap as _impl
        return _impl(self, *args, **kwargs)

    def _post_login_cloud_ready(self):
        """Call right after successful unlock (userKey present)."""
        username = self._active_username()
        if not username:
            return
        # Bind engine to active user + current profile (including wrap flag)
        self._configure_sync_engine(username)

        # One controlled sync to reconcile remote/local with the present wrap state
        res = str(self.sync_engine.sync_now(self.userKey, interactive=False) or "")
        self._refresh_baseline_if_pulled(res, username)

        # Now it’s safe to start the watcher + auto-sync
        self._watch_local_vault()
        self._schedule_auto_sync()

    def _vault_enc_path(self) -> str | None:
        """
        Return absolute path to the *local* encrypted vault (.kqvault)
        based on the current username, using paths.vault_file(...).
        """
        try:
            username = self.currentUsername.text().strip()
        except Exception:
            username = ""
        if not username:
            # not logged in or no username typed yet
            QMessageBox.warning(self, self.tr("Vault path"), self.tr("Enter/select a username first."))
            return None
        # paths.vault_file will create the parent dir if ensure_parent=True
        return str(vault_file(username, ensure_parent=True))

    def _sha256_file(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1<<20), b""):
                h.update(chunk)
        return h.hexdigest()

    def _set_cloud_cfg(self, *args, **kwargs):
        from app.misc_ops import _set_cloud_cfg as _impl
        return _impl(self, *args, **kwargs)

    def on_copy_vault_to_cloud(self, *args, **kwargs):
        from vault_store.vault_ui_ops import on_copy_vault_to_cloud as _impl
        return _impl(self, *args, **kwargs)

    def _yubi_wrap_status(self, username: str) -> dict:
        """
        Return {'enabled': bool, 'mode': 'WRAP'|'GATE'|'' , 'available': bool|None}

        - 'mode' is derived from the current twofactor record (new) or legacy flags (old).
        - 'enabled' is True if mode is WRAP or GATE.
        - 'available' is True if YubiKey tooling is available on this machine,
          False if we can tell it isn't, or None if we can't determine.
        """
        mode = ""
        enabled = False
        available_flag = None

        # --- Read settings (prefer new, fall back to legacy) ---
        try:
            tf = get_user_setting(username, "twofactor") or {}
            m = (tf.get("mode") or "").lower()
            if m == "yk_hmac_wrap":
                mode = "WRAP"
            elif m == "yk_hmac_gate":
                mode = "GATE"
            else:
                # Legacy compatibility
                legacy = (get_user_setting(username, "yubi_2of2_mode") or "").upper()
                if legacy in ("WRAP", "GATE"):
                    mode = legacy
                elif get_user_setting(username, "yubi_wrap_enabled"):
                    mode = "WRAP"
            enabled = mode in ("WRAP", "GATE")
        except Exception:
            pass

        # --- Check YubiKey tooling availability (no console popups) ---
        YKBackend = None
        try:
            from auth.yubi.yk_backend import YKBackend  # packaged layout
        except Exception:
            try:
                from auth.yubi.yk_backend import YKBackend  # flat layout
            except Exception:
                YKBackend = None

        if YKBackend is None:
            available_flag = None  # unknown
        else:
            try:
                # If ykman (python or exe) is present/working, this succeeds.
                YKBackend().yk_version()
                available_flag = True
            except Exception:
                available_flag = False

        return {"enabled": bool(enabled), "mode": mode, "available": available_flag}

    def _show_cloud_risk_modal(self, current_wrap: bool) -> tuple[bool, bool, bool]:
        """
        One-time consent explaining cloud risks.
        Returns (accepted: bool, dont_ask_again: bool, enable_wrap: bool).
        """

        help_url = getattr(self, "SITE_HELP", SITE_HELP)
        privacy_url = PRIVACY_POLICY

        # Figure out YubiKey state for the active user (best-effort)
        uname = None
        try:
            uname = self._active_username()
        except Exception:
            try:
                uname = (self.currentUsername.text() or "").strip()
            except Exception:
                uname = None

        yk = {"enabled": False, "mode": "", "available": None}
        if uname:
            try:
                yk = self._yubi_wrap_status(uname)
            except Exception:
                pass

        # Build a YubiKey hint line based on state
        if yk["enabled"]:
            yubi_hint = (
                "• <b>YubiKey key-wrap: ON</b> — decrypting a leaked file would also require your physical YubiKey.<br>"
            )
        elif yk["available"] is True:
            yubi_hint = (
                "• <b>YubiKey key-wrap (optional):</b> enable this in Settings to require your YubiKey to decrypt a leaked file.<br>"
            )
        else:
            # Unknown / not available — skip or keep a generic note
            yubi_hint = ""

        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle(self.tr("Cloud storage — security warning"))
        msg.setTextFormat(Qt.RichText)
        msg.setText(
            self.tr(
                "<b>Cloud storage increases security risk</b><br>"
                "This app is designed for local security. Storing your vault in a cloud-synced folder increases exposure. "
                "If an attacker obtains the file from your cloud, they can attempt unlimited offline password-guessing against it.<br><br>"
                "<b>Recommendations:</b><br>"
                "• <b>Secure your cloud account</b> (Microsoft/Google/Dropbox): use a strong, unique password and <b>enable 2FA</b> with your cloud provider.<br>"
                "• <b>Use a strong master password</b> for the vault. In-app 2FA protects app access, but it <i>does not</i> protect a leaked file from offline guessing.<br>"
                "{yubi_hint}"
                "• Consider enabling <b>extra cloud wrapping</b> for an additional encryption layer.<br><br>"
                "<a href='{help_url}'>Learn more</a> · <a href='{privacy_url}'>Privacy Policy</a>"
            ).format(
                yubi_hint=yubi_hint,
                help_url=help_url,
                privacy_url=privacy_url,
            )
        )

        # Remember flag
        dont_ask_box = QCheckBox(self.tr("Don't ask me again"))
        msg.setCheckBox(dont_ask_box)

        # Buttons
        proceed_btn = msg.addButton("Proceed", QMessageBox.AcceptRole)
        cancel_btn = msg.addButton(self.tr("Cancel"), QMessageBox.RejectRole)

        res = msg.exec_() if hasattr(msg, "exec_") else msg.exec()
        accepted = (msg.clickedButton() is proceed_btn)
        if not accepted:
            return False, False, False

        # If extra cloud wrapping already ON
        if current_wrap:
            return True, bool(dont_ask_box.isChecked()), False

        # Ask to enable extra cloud wrapping now
        wrap_q = QMessageBox(self)
        wrap_q.setIcon(QMessageBox.Question)
        wrap_q.setWindowTitle(self.tr("Enable extra cloud wrapping?"))
        wrap_q.setText(
            "Enable extra encryption wrapping for cloud storage?\n\n"
            "This adds an additional encryption layer specifically for cloud sync targets."
        )
        wrap_yes = wrap_q.addButton("Enable wrapping", QMessageBox.AcceptRole)
        wrap_no = wrap_q.addButton("Not now", QMessageBox.RejectRole)
        wrap_q.exec_() if hasattr(wrap_q, "exec_") else wrap_q.exec()
        enable_wrap = (wrap_q.clickedButton() is wrap_yes)

        return True, bool(dont_ask_box.isChecked()), bool(enable_wrap)

    def on_stop_cloud_sync_keep_local(self, *args, **kwargs):
        from app.misc_ops import on_stop_cloud_sync_keep_local as _impl
        return _impl(self, *args, **kwargs)

    def on_toggle_extra_cloud_wrap(self, *args, **kwargs):
        from app.misc_ops import on_toggle_extra_cloud_wrap as _impl
        return _impl(self, *args, **kwargs)

    def one_time_mobile_transfer(self, *args, **kwargs):
        from app.misc_ops import one_time_mobile_transfer as _impl
        return _impl(self, *args, **kwargs)

    def cleanup_transfer_packages(self):
        """
        Offers to delete *.zip.enc transfer packages from a chosen folder.
        Handy after the Android import is done.
        """
        from qtpy.QtWidgets import QFileDialog, QMessageBox
        from pathlib import Path

        folder = QFileDialog.getExistingDirectory(self, "Select folder to clean (cloud)")
        if not folder:
            return
        p = Path(folder)
        candidates = sorted([x for x in p.glob("*.zip.enc") if x.is_file()])

        if not candidates:
            QMessageBox.information(self, self.tr("Cleanup"), self.tr("No .zip.enc packages found here."))
            return

        names = "\n".join(str(x.name) for x in candidates[:20])
        more = "" if len(candidates) <= 20 else self.tr("\n… and ") + f" {len(candidates)-20} " + self.tr("more")
        msg =  self.tr("Found ") + f"{len(candidates)}" + self.tr(" package(s):") + f"\n{names}{more}\n\n" + self.tr(" Delete them now?"),
        resp = QMessageBox.question(
            self, self.tr("Delete transfer packages?"), msg,
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if resp != QMessageBox.Yes:
            return

        errors = 0
        for x in candidates:
            try:
                x.unlink()
            except Exception:
                errors += 1
        if errors:
            msg = self.tr("Deleted with ") + f"{errors}" + self.tr(" error(s).")
            QMessageBox.warning(self, self.tr("Cleanup"), msg)
        else:
            msg = "✅ " + self.tr("All packages deleted.")
            QMessageBox.information(self, self.tr("Cleanup"), msg)

    def _cloud_sync_safe(self, *args, **kwargs):
        from app.misc_ops import _cloud_sync_safe as _impl
        return _impl(self, *args, **kwargs)

    def ensure_cloud_ready_before_login(self, *args, **kwargs):
        from auth.login.auth_flow_ops import ensure_cloud_ready_before_login as _impl
        return _impl(self, *args, **kwargs)

    def _logged_in_username(self) -> str | None:
        """
        Return the canonical username for the current session.
        In per-user mode this is simply the text in currentUsername,
        optionally normalized via _canonical_username_ci() for case-insensitive matches.
        """
        try:
            u = (self.currentUsername.text() or "").strip()
            if not u:
                return None

            try:
                canon = _canonical_username_ci(u)
                if canon:
                    return canon
            except Exception:
                pass

            return u
        except Exception:
            return None

    def cloud_vault_file(self, username: str) -> Path | None:
        """
        Return the FILE path configured for cloud sync for this user,
        or None if not configured. (Engine is file-based.)
        """
        try:
    
            prof = get_user_cloud(username) or {}
            rp = (prof.get("remote_path") or "").strip()
            return Path(rp) if rp else None
        except Exception:
            return None

    def _configure_sync_engine(self, username: str):
        from sync.engine import SyncEngine

        def load_cfg():
            prof = get_user_cloud(username) or {}
            return {"sync": prof}

        def save_cfg(cfg: dict):
            sc = (cfg or {}).get("sync") or {}
            set_user_cloud(
                username,
                enable=bool(sc.get("enabled")),
                provider=(sc.get("provider") or "localpath"),
                path=(sc.get("remote_path") or ""),
                wrap=bool(sc.get("cloud_wrap")),
            )

        def get_local_vault_path() -> str:
            return str(vault_file(username, ensure_parent=True))

        # (re)create if user changed
        if getattr(self, "_sync_user", None) != username:
            self.sync_engine = SyncEngine(load_cfg, save_cfg, get_local_vault_path)
            self._sync_user = username

        # If remote path already chosen, bind it
        rp = self.cloud_vault_file(username)
        if rp:
            self.sync_engine.set_localpath(str(rp))

    # ==============================
    # --- cloud encrtped wrap ---
    # ==============================
    def _read_bytes(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    def _write_bytes(self, path: str, data: bytes) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)

    def _cloud_wrap_encrypt(self, data: bytes, username: str) -> bytes:
        try:
            from sync.engine import wrap_encrypt
            return wrap_encrypt(self.userKey, data)
        except Exception:
            return data

    def _cloud_wrap_decrypt(self, data: bytes, username: str) -> bytes:
        try:
            from sync.engine import wrap_decrypt
            return wrap_decrypt(self.userKey, data)
        except Exception:
            return data

    def _seed_remote_from_local(self, username: str, remote_file: str):
        """
        First-time create/update the CLOUD file from LOCAL working copy.
        Applies wrap if enabled.
        """
        prof = get_user_cloud(username) or {}
        local_file = str(vault_file(username, ensure_parent=True))
        data = self._read_bytes(local_file)
        if bool(prof.get("cloud_wrap")):
            data = self._cloud_wrap_encrypt(data, username)
        os.makedirs(os.path.dirname(remote_file), exist_ok=True)
        self._write_bytes(remote_file, data)
        update_baseline(username=username, verify_after=False, who=self.tr("OnCloud Sync Settings Changed")) 

    def _restore_local_from_remote(self, username: str, remote_file: str):
        """
        Restore LOCAL working copy from CLOUD file.
        Removes wrap if enabled.
        """
        prof = get_user_cloud(username) or {}
        local_file = str(vault_file(username, ensure_parent=True))
        data = self._read_bytes(remote_file)
        if bool(prof.get("cloud_wrap")):
            data = self._cloud_wrap_decrypt(data, username)
        os.makedirs(os.path.dirname(local_file), exist_ok=True)
        self._write_bytes(local_file, data)
    
    # ==============================
    # --- cloud autoSynic -------
    # ==============================
    """ Call _init_auto_sync() once during UI setup (e.g., in your constructor or _init_cloud_sysnic). """
    """ add self._schedule_auto_sync() to save meather to save exp:"""
    """ self._schedule_auto_sync() after save"""
    """ """
    def _init_auto_sync(self):
        self._auto_sync_timer = QTimer(self)
        self._auto_sync_timer.setSingleShot(True)
        self._auto_sync_timer.setInterval(2500)  # 2.5s debounce
        self._auto_sync_timer.timeout.connect(self._run_auto_sync)

        # Guards/state
        self._is_syncing_cloud = False
        self._vault_watcher = None

    def _schedule_auto_sync(self):
        # ensure timer exists
        if getattr(self, "_auto_sync_timer", None) is None:
            self._init_auto_sync()

        # must be logged in + have key
        username = self._active_username()
        if not username or not getattr(self, "userKey", None):
            return

        # user/profile switches
        prof = (get_user_cloud(username) or {})
        if not prof.get("enabled"):
            return
        if not bool(get_user_setting(username, "auto_sync", True)):
            return

        # (re)bind engine to THIS user each time
        self._configure_sync_engine(username)

        # only if engine has a remote file configured
        if not (hasattr(self, "sync_engine") and self.sync_engine and self.sync_engine.configured()):
            return

        # if a sync is currently running, skip scheduling
        if getattr(self, "_is_syncing_cloud", False):
            return

        # debounce
        self._auto_sync_timer.start()

    def _run_auto_sync(self):
        username = self._active_username()
        if not username or not getattr(self, "userKey", None):
            return
        if not (hasattr(self, "sync_engine") and self.sync_engine and self.sync_engine.configured()):
            return

        # prevent re-entrant loops when our own pull/write triggers fileChanged
        if self._is_syncing_cloud:
            return

        try:
            self._is_syncing_cloud = True
            res = str(self.sync_engine.sync_now(self.userKey, interactive=False) or "")
            log.debug(
                self.tr("[AUTO-SYNC] {result}").format(result=res)
            )

            _r = res.lower()
            if _r.startswith("pulled") or ("conflict" in _r) or ("download" in _r):
                try:
                    update_baseline(username=username, verify_after=False, who=self.tr("Auto-Sync -> File Change")) 
                except Exception:
                    pass

        except Exception as e:
            log.warning(
                self.tr("[AUTO-SYNC] failed: {err}").format(err=e)
            )
        finally:
            self._is_syncing_cloud = False

    def _watch_local_vault(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _watch_local_vault as _impl
        return _impl(self, *args, **kwargs)

    def _unwatch_local_vault(self):
        try:
            w = getattr(self, "_vault_watcher", None)
            if not w:
                return
            # detach paths
            try:
                for p in list(w.files()):
                    try: w.removePath(p)
                    except Exception: pass
                for d in list(w.directories()):
                    try: w.removePath(d)
                    except Exception: pass
            except Exception:
                pass
            try:
                w.deleteLater()
            except Exception:
                pass
            self._vault_watcher = None
        except Exception:
            pass

    # ==============================
    # UI Scale: Text / Button / Table size (0 = default)
    # ==============================
    
    def _connect_ui_scale_controls(self) -> None:
        """
        Hook the Settings spinboxes:
          - text_size        -> app font point size (0 = default)
          - button_size      -> min button height px (0 = default)
          - button_size_2    -> table row height px (0 = default)
        """
        # Guard: only run once
        if getattr(self, "_ui_scale_controls_connected", False):
            return
        self._ui_scale_controls_connected = True

        # Defaults captured once (so "0" can restore)
        try:
            from qtpy.QtWidgets import QApplication
            self._default_app_font = QApplication.font()
        except Exception:
            self._default_app_font = None

        self._default_table_row_heights = {}

        # Load saved prefs + apply immediately
        self._load_ui_scale_prefs_apply()

        # Connect signals (best-effort, don’t crash if widget missing)
        try:
            if hasattr(self, "text_size") and self.text_size is not None:
                self.text_size.valueChanged.connect(self.on_text_size_changed)
        except Exception:
            pass

        try:
            if hasattr(self, "button_size") and self.button_size is not None:
                self.button_size.valueChanged.connect(self.on_button_size_changed)
        except Exception:
            pass

        try:
            if hasattr(self, "button_size_2") and self.button_size_2 is not None:
                self.button_size_2.valueChanged.connect(self.on_table_size_changed)
        except Exception:
            pass

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
    # --- Authenticator Store/ Tab Wiring ---------------
    # ==============================

    def _auth_after_login(self):
        """Enable the Authenticator tab and populate it after a successful login."""
        try:

            log.debug(f"[AUTH] after login active_user={self._active_username()!r}")
            self._auth_set_enabled(True)
            self._auth_reload_table()
        except Exception as e:
            log.debug(f"{kql.i('err')} AUTH after_login {e}")
            pass

    def _auth_show_qr_selected(self):
        """Show a QR for the selected authenticator so the user can add it to another app."""
        if not self._auth_require_login():
            QMessageBox.warning(self, self.tr("Authenticator"), self.tr("Please log in first."))
            return

        row = self._auth_selected_row()
        it = self._auth_row_entry(row)
        if not it:
            QMessageBox.information(self, self.tr("Show QR"), self.tr("Please select an authenticator entry first."))
            return

        # Safety confirmation
        msg =  self.tr("This will display the QR code for the authenticator secret.\n\nOnly do this on a trusted device.\n\nContinue?")
        res = QMessageBox.question(
            self,
            self.tr("Reveal 2FA QR"), msg,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if res != QMessageBox.Yes:
            return

        try:
            # Generate QR PNG bytes and URI
            png_bytes = export_otpauth_qr_bytes(self.userKey, it)
            uri = build_otpauth_uri(self.userKey, it)
            dlg = QDialog(self)
            dlg.setWindowTitle(self.tr("Authenticator QR"))
            layout = QVBoxLayout(dlg)

            img = QLabel()
            pix = QPixmap()
            pix.loadFromData(png_bytes, "PNG")
            img.setPixmap(pix)
            img.setAlignment(Qt.AlignCenter)
            layout.addWidget(img)

            btn_copy = QPushButton(self.tr("Copy otpauth:// URI"))
            btn_copy.clicked.connect(lambda: secure_copy(uri, ttl_ms=self.clipboard_timeout, username=self._active_username()))
            if hasattr(self, "_toast"): self._toast("Code copied")
            layout.addWidget(btn_copy)

            dlg.exec()

        except Exception as e:
            QMessageBox.warning(
                self,
                self.tr("QR Error"),
                self.tr("Could not generate QR:\n\n{err}").format(err=e),
            )

    def _auth_set_enabled(self, enabled: bool):
        t = getattr(self, "_auth_timer", None)
        if enabled:
            if t is None:
                self._auth_timer = t = QTimer(self)
                t.setInterval(1000)               # 1s tick
                t.timeout.connect(self._auth_tick)
            if not t.isActive():
                t.start()
        else:
            if t and t.isActive():
                t.stop()

    def _auth_tick(self):
        if not self._auth_entries:
            return
        table = getattr(self, "authTable", None)
        if not table:
            return

        for r, e in enumerate(self._auth_entries):
            try:
                code, rem = get_current_code(self.userKey, e)
            except Exception:
                code, rem = "—", 0

            if table.item(r, 1) is None:
                table.setItem(r, 1, QTableWidgetItem(str(code)))
            else:
                table.item(r, 1).setText(str(code))

            # Remaining column = 2
            if table.item(r, 2) is None:
                table.setItem(r, 2, QTableWidgetItem(str(int(rem))))
            else:
                table.item(r, 2).setText(str(int(rem)))

    def _auth_require_login(self) -> bool:
        return bool(getattr(self, "userKey", None) and self._active_username())

    def _auth_rows(self):
        uname = (self._active_username() or "").strip()
        if not uname:
            return []
        return list_authenticators(uname, self.userKey)

    def _auth_reload_table(self):
        if not self._auth_require_login():
            return

        rows = self._auth_rows() or []
        self._auth_entries = rows 

        self.authTable.setRowCount(len(rows))
        for i, it in enumerate(rows):
            vals = [
                it.get("label",""),          # 0 Label
                "—",                         # 1 Code
                "—",                         # 2 Remaining
                it.get("account",""),        # 3 Account
                it.get("issuer",""),         # 4 Issuer
                it.get("algorithm","SHA1"),  # 5 Algorithm
                str(it.get("digits",6)),     # 6 Digits
                str(it.get("period",30)),    # 7 Period
            ]
            for c, v in enumerate(vals):
                self.authTable.setItem(i, c, QTableWidgetItem(v))

            self.authTable.item(i, 0).setData(Qt.ItemDataRole.UserRole, it.get("id"))

        self._auth_refresh_codes()

    def _auth_selected_row(self) -> int:
        sel = self.authTable.selectionModel().selectedRows() if self.authTable.selectionModel() else []
        return sel[0].row() if sel else -1

    def _auth_row_entry(self, row: int) -> dict | None:
        rows = self._auth_entries or []
        return rows[row] if 0 <= row < len(rows) else None

    def _auth_refresh_codes(self):
        if not self._auth_require_login(): return
        rows = self._auth_rows()
        self._auth_entries = rows
        for i, it in enumerate(rows):
            try:
                code, rem = get_current_code(self.userKey, it)
            except Exception:
                code, rem = ("—", 0)
            if i < self.authTable.rowCount():
                self.authTable.item(i, 1).setText(code)
                self.authTable.item(i, 2).setText(str(rem))

    def _auth_add_manual(self):
        if not self._auth_require_login(): 
            QMessageBox.warning(self, self.tr("Authenticator"), self.tr("Please log in first."))
            return

        label, ok = QInputDialog.getText(self, self.tr("Add Authenticator"), self.tr("Label:"))
        if not ok or not label.strip(): return

        account, ok = QInputDialog.getText(self, self.tr("Add Authenticator"), self.tr("Account:"))
        if not ok: return

        issuer, ok = QInputDialog.getText(self, self.tr("Add Authenticator"), self.tr("Issuer:"))
        if not ok: return

        secret, ok = QInputDialog.getText(self, self.tr("Add Authenticator"), self.tr("Secret (BASE32):"))
        if not ok or not secret.strip(): return

        digits, ok = QInputDialog.getInt(self, self.tr("Add"), self.tr("Digits:"), 6, 6, 8, 1)
        if not ok: return

        period, ok = QInputDialog.getInt(self, self.tr("Add"), self.tr("Period (s):"), 30, 15, 90, 1)
        if not ok: return

        algo, ok = QInputDialog.getItem(self, self.tr("Add"), self.tr("Algorithm:"),
                                        ["SHA1","SHA256","SHA512"], 0, False)
        if not ok: return

        add_authenticator(self._active_username(), self.userKey,
                          label=label, account=account, issuer=issuer,
                          secret_base32=secret, digits=digits,
                          period=period, algorithm=algo)
        update_baseline(username=self._active_username(), verify_after=False, who=self.tr("Auth Store Added (Manually)"))
        self._auth_reload_table()

    def _auth_add_from_camera(self):
        if not self._auth_require_login():
            QMessageBox.warning(self, self.tr("Authenticator"), self.tr("Please log in first."))
            return
        try:
            dlg = self._QRCameraScannerDialog(self) if hasattr(self, "_QRCameraScannerDialog") else _QRCameraScannerDialog(self)
        except NameError:
            dlg = _QRCameraScannerDialog(self)
        if dlg.exec():
            uri = dlg.found_uri
            if uri and uri.startswith("otpauth://"):
                try:
                    uname = self._active_username()
                    add_from_otpauth_uri(uname, self.userKey, uri)
                    update_baseline(username=uname, verify_after=False, who=self.tr("Auth Store Added (On Screen QR)"))
                    self._auth_reload_table()
                    if hasattr(self, "_toast"): self._toast("Authenticator added")
                except Exception as e:
                    QMessageBox.critical(
                        self,
                        self.tr("Add from Camera"),
                        # Translate failure message with a template
                        self.tr("Failed: {err}").format(err=e),
                    )
            else:
                QMessageBox.information(self, self.tr("Add from Camera"), self.tr("No otpauth:// QR detected."))

    def _auth_add_from_qr(self):
        if not self._auth_require_login(): 
            QMessageBox.warning(self, self.tr("Authenticator"), self.tr("Please log in first.")); return
        fn, _ = QFileDialog.getOpenFileName(self, self.tr("Select QR Image"), "", "Images (*.png *.jpg *.jpeg *.bmp)")
        if not fn: return
        uri = import_otpauth_from_qr_image(fn)
        if not uri:
            QMessageBox.warning(self, self.tr("Add from QR"), self.tr("Could not read an otpauth:// QR from that image.")); return
        add_from_otpauth_uri(self._active_username(), self.userKey, uri)
        update_baseline(username=self._active_username(), verify_after=False, who=self.tr("Auth Store Added (QR Image)")) 
        self._auth_reload_table()

    def _auth_edit_selected(self):
        if not self._auth_require_login(): return
        row = self._auth_selected_row(); it = self._auth_row_entry(row)
        if not it: QMessageBox.information(self, self.tr("Edit"), self.tr("Select an entry first.")); return
        label, ok = QInputDialog.getText(self, self.tr("Edit"), self.tr("Label:"), text=it.get("label",""));           
        if not ok: return
        account, ok = QInputDialog.getText(self, self.tr("Edit"), self.tr("Account:"), text=it.get("account",""));     
        if not ok: return
        issuer, ok = QInputDialog.getText(self, self.tr("Edit"), self.tr("Issuer:"), text=it.get("issuer",""));        
        if not ok: return
        algo, ok = QInputDialog.getItem(self, self.tr("Edit"), self.tr("Algorithm:"), ["SHA1","SHA256","SHA512"],
                                        ["SHA1","SHA256","SHA512"].index(it.get("algorithm","SHA1")), False); 
        if not ok: return
        digits, ok = QInputDialog.getInt(self, self.tr("Edit"), self.tr("Digits:"), int(it.get("digits",6)), 6, 8, 1); 
        if not ok: return
        period, ok = QInputDialog.getInt(self, self.tr("Edit"), self.tr("Period:"), int(it.get("period",30)), 15, 90, 1); 
        if not ok: return
        if update_authenticator(
            self._active_username(),
            self.userKey,
            it["id"],
            label=label,
            account=account,
            issuer=issuer,
            algorithm=algo,
            digits=digits,
            period=period,
        ):
            update_baseline(username=self._active_username(), verify_after=False, who=self.tr("Auth Store Edited")) 
            self._auth_reload_table()

    def _auth_delete_selected(self):
        if not self._auth_require_login(): return
        row = self._auth_selected_row(); it = self._auth_row_entry(row)
        if not it: QMessageBox.information(self, self.tr("Delete"), self.tr("Select an entry first.")); return
        # Ask confirmation using a template to allow translation
        if (
            QMessageBox.question(
                self,
                self.tr("Delete"),
                self.tr("Remove '{label}'?").format(label=it.get("label", "Authenticator")),
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        if delete_authenticator(self._active_username(), self.userKey, it["id"]):
            self._auth_reload_table()
        update_baseline(self._active_username(), verify_after=False, who=self.tr("Auth Store Deleted Entry"))
   
    def _auth_copy_code(self):
        if not self._auth_require_login(): return
        row = self._auth_selected_row(); it = self._auth_row_entry(row)
        if not it: QMessageBox.information(self, self.tr("Copy"), self.tr("Select an entry first.")); return
        code, _ = get_current_code(self.userKey, it)
        try:
            uname = self._active_username()
            secure_copy(code, self.clipboard_timeout, uname)
            log_event_encrypted(uname, "Auth Store", "Code Copied")
            if hasattr(self, "_toast"): self._toast(self.tr("Code copied"))
        except Exception:
            QGuiApplication.clipboard().setText(code)
            if hasattr(self, "_toast"): self._toast(self.tr("Code copied"))
    
    # --- auth screen scan ---
    def _qimage_to_numpy(self, img: QImage) -> np.ndarray:
        """Convert QImage to an OpenCV BGR ndarray (PySide6-safe)."""
        # Normalize to a known 4-channel format
        img = img.convertToFormat(QImage.Format.Format_RGBA8888)
        w, h = img.width(), img.height()

        # PySide6 returns a memoryview; convert to bytes then to ndarray
        mv = img.constBits()  # or img.bits()
        data = mv.tobytes()   # length == img.sizeInBytes()
        arr = np.frombuffer(data, dtype=np.uint8).reshape((h, w, 4))

        # RGBA -> BGR (OpenCV default)
        bgr = arr[:, :, 2::-1].copy()
        return bgr

    def _confirm_auth_scan(self) -> bool:
        """
        Ask the user to make sure the QR code is visible before scanning.
        Includes a 'Don't show again' checkbox persisted in settings.
        Returns True if the user wants to proceed.
        """
        try:
            # Respect saved preference
            suppress = bool(get_user_setting("__global__", "suppress_auth_scan_prompt"))
        except Exception:
            suppress = False

        if suppress:
            return True
        msg = QMessageBox(self)
        msg.setWindowTitle(self.tr("QR Scan"))
        msg.setIcon(QMessageBox.Information)
        msg.setText(self.tr(
            "Make sure the TOTP QR code is visible on your screen.\n\n"
            "When you click OK, Keyquorum will briefly minimize, scan all screens, "
            "and auto-add any authenticator QR it finds.")
        )
        msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        msg.setDefaultButton(QMessageBox.Ok)

        chk = QCheckBox(self.tr("Don’t show this again"))
        msg.setCheckBox(chk)

        res = msg.exec()
        if res == QMessageBox.Ok:
            # Persist the preference if they checked the box
            try:
                set_user_setting("__global__", "suppress_auth_scan_prompt", bool(chk.isChecked()))
            except Exception:
                pass
            return True
        return False

    def _auth_add_from_screen(self, *args, **kwargs):
        from auth.login.auth_flow_ops import _auth_add_from_screen as _impl
        return _impl(self, *args, **kwargs)

    @contextmanager
    def _hide_for_screen_scan(self, delay_ms: int = 250):
        """Temporarily hide/minimize the window so it doesn't appear in the screenshot."""
        # NOTE: screenshot is only for scaning for qr on screen only
        was_visible = self.isVisible()
        prev_opacity = self.windowOpacity()
        try:
            # Hide quickly & flush events so the window is gone before grab the screen
            self.setWindowOpacity(0.0)
            self.hide()
            QApplication.processEvents()
            _t.sleep(max(0, delay_ms) / 1000.0)
            yield
        finally:
            if was_visible:
                self.show()
                self.raise_()
                self.activateWindow()
            self.setWindowOpacity(prev_opacity)
            QApplication.processEvents()

    # ==============================
    # --- YubiKey 2-of-2 ----------------
    # ==============================

    def on_yk_setup_clicked(self):
        self.set_status_txt(self.tr("YubiKey Setup"))
        uname = (self.currentUsername.text() or "").strip()
        if not uname:
            QMessageBox.warning(self, self.tr("YubiKey"), self.tr("Please select or log into a user first."))
            return

        # get password
        identity_pwd = self.verify_sensitive_action(
            uname,
            title=self.tr("Two-Factor Authentication"),
            return_pw=True,
            require_password=True,
            twofa_check=(True),  # disable -> True, enable -> False
            yubi_check=True,
        )
        if identity_pwd == False: return

        dlg = YubiKeySetupDialog(self, uname, getattr(self, "userKey", None), identity_password=identity_pwd)
        dlg.finished_setup.connect(self._on_enable_finished)
        self._track_window(dlg)
        dlg.exec()
        identity_pwd = ""

    def _on_enable_finished(self, res: dict):
        """
        Handle YubiKey enable completion (wrap or gate).
        Called when YubiKeySetupDialog emits done().
        """
        if not (res and res.get("ok")):
            return
        mode = res.get("mode", "").lower()
        rk = res.get("recovery_key")
        yubi_codes = res.get("backup_codes") or []
        if mode == "wrap":
            username=self.currentUsername.text()
            set_recovery_mode(username, False)
            if rk:
                try:
                    # update emergency kit / show to user
      
                    self.emg_ask(
                        username=username,
                        one_time_recovery_key=rk,
                        recovery_backup_codes=yubi_codes,
                    )
                except Exception:
                    # Fallback: copy + simple popup
                    try:
                        QApplication.clipboard().setText(rk)
                    except Exception:
                        pass
                    msg = self.tr("Save this Recovery Key in a safe offline place.\n\n") + rk,
                    QMessageBox.information(
                        self,
                        self.tr("Recovery Key (Shown Once)"), msg)
            log_event_encrypted(username, "user", "🗝️ YubiKey WRAP enabled")
            self.set_status_txt("✅ " + self.tr("YubiKey WRAP enabled"))

            # 🔐 For safety, force a fresh login so the session matches the new WRAP config
            QMessageBox.information(
                self,
                self.tr("YubiKey WRAP Enabled"),
                self.tr("YubiKey WRAP has been enabled for this account.\n\n"
                "For your security, you will now be logged out.\n"
                "Please log in again using your password and YubiKey.")
            )
            try:
                update_baseline(username=username, verify_after=False, who="Yubi Key Wrap")
                self.logout_user()
            except Exception:
                pass
            return 

        elif mode == "gate":
            self.set_status_txt("✅ " + self.tr("YubiKey GATE enabled"))
            log_event_encrypted(username, "user", "🗝️ YubiKey GATE enabled")
            update_baseline(username=username, verify_after=False, who="Yubi Key GATE")

        # Refresh recovery/2FA controls after any YubiKey enable (non-WRAP path)
        try:
            self.refresh_recovery_controls()
        except Exception:
            pass

    def refresh_recovery_controls(self) -> None:
        username = (self.currentUsername.text() or "").strip()
        is_rm = bool(get_recovery_mode(username))        # authoritative
        has_rk = has_recovery_wrap(username)             # wrapped key present
        has_mk = bool(getattr(self, "userKey", None))    # unlocked

        try:
            self.recovery_mode_.blockSignals(True)
            self.recovery_mode_.setChecked(is_rm)
        finally:
            self.recovery_mode_.blockSignals(False)

        self.regen_key_.setEnabled(is_rm and has_mk)
        self.regen_key_.setText(self.tr("Regenerate Recovery Key") if has_rk else self.tr("Add Recovery Key"))

        if not is_rm:
            self.regen_key_.setToolTip(self.tr("Enable Recovery Mode to add a Recovery Key."))
        elif not has_mk:
            self.regen_key_.setToolTip(self.tr("Unlock the vault first to bind a Recovery Key."))
        else:
            self.regen_key_.setToolTip(self.tr("Generate a Recovery Key (shown once). Store it offline."))

        if hasattr(self, "lblRecoveryStatus"):
            if not is_rm:
                self.lblRecoveryStatus.setText(self.tr("Maximum Security: Password + YubiKey only (no recovery)."))
            elif has_rk:
                self.lblRecoveryStatus.setText(self.tr("Recovery Mode: Password + (YubiKey OR Recovery Key)."))
            else:
                self.lblRecoveryStatus.setText(self.tr("Recovery Mode: Add a Recovery Key for fallback."))

    def on_generate_recovery_key_clicked(self, *args, **kwargs):
        from app.misc_ops import on_generate_recovery_key_clicked as _impl
        return _impl(self, *args, **kwargs)

    def _show_login_rescue_both(self, *args, **kwargs):
        from auth.login.auth_flow_ops import _show_login_rescue_both as _impl
        return _impl(self, *args, **kwargs)

    def _rescue_caps(self, username: str):
        """
        Returns (mode, allow_backup, allow_recovery)
          mode: "yk_hmac_gate" | "yk_hmac_wrap" | None
          allow_backup: True if login backup codes exist
          allow_recovery: True if recovery wrap is configured
        """
        mode, _rec = yk_twofactor_enabled(username)
        allow_backup   = get_login_backup_count_quick(username) > 0
        allow_recovery = bool(has_recovery_wrap(username))
        return mode, allow_backup, allow_recovery
        
    def _load_user_record(self, username: str) -> dict:
        """
        Load and return the per-user record dictionary for the given username.
        Returns an empty dict if no record exists or file is invalid.
        """
        try:
            rec = get_user_record(username)
            return rec if isinstance(rec, dict) else {}
        except Exception:
            return {}
    
    # --- the dialog (buttons enable on typing; capability checked on click)
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

    def _show_make_share_tip(self):
        if not self._get_hint_flag("show_make_share_tip", True):
            return
        dlg = QDialog(self)
        dlg.setWindowTitle(self.tr("How to Share (Zero-Knowledge)"))
        dlg.setModal(True)
        layout = QVBoxLayout(dlg)
        txt = (
            "<b>What this does</b><br>"
            "• Encrypts the selected entry with a one-time key.<br>"
            "• Wraps that key to the recipient’s public key from their Share ID.<br>"
            "• Produces a <code>.kqshare</code> file (and optional QR) that only they can open.<br><br>"
            "<b>How to use</b><br>"
            "1) Ask the recipient to send their <i>Share ID</i> (<code>.kqshareid</code>) first.<br>"
            "2) Click <i>Make Share Packet…</i>, pick their Share ID, then save or show QR.<br>"
            "3) The recipient opens your <code>.kqshare</code> via <i>Import Share Packet…</i> after logging in.<br><br>"
            "<b>Notes</b><br>"
            "• No server can decrypt; only the recipient’s private key works.<br>"
            "• Import will add the entry into their vault (you keep your copy)."
        )
        lbl = QLabel(txt, dlg); lbl.setTextFormat(Qt.TextFormat.RichText); lbl.setWordWrap(True)
        layout.addWidget(lbl)
        chk = QCheckBox(self.tr("Don’t show this tip again"), dlg)
        layout.addWidget(chk)
        btns = QHBoxLayout()
        ok = QPushButton(self.tr("OK"), dlg)
        ok.setDefault(True)
        btns.addStretch(1); btns.addWidget(ok); layout.addLayout(btns)
        ok.clicked.connect(dlg.accept); dlg.exec()
        if chk.isChecked(): self._set_hint_flag("show_make_share_tip", False)

    # --- Export my Share ID ---
    def export_my_share_id(self):
        try:
            username = (self.currentUsername.text() if hasattr(self, "currentUsername") else "").strip()
            if not getattr(self, "userKey", None) or not username:
                QMessageBox.warning(self, self.tr("Export Share ID"), self.tr("Please log in first."))
                return
            # Use the unified per-user shared_key_file path
            key_path = shared_key_file(username, ensure_dir=True, name_only=False)
            share_id = export_share_id_json(username, self.userKey)

            try:
                show_qr_for_object(
                    "My Share ID (scan to add me)",
                    {"type": "kqshareid", **share_id},
                    self,
                    mode="shareid",
                )
            except Exception:
                pass

            suggested = Path(config_dir()) / f"{username}.kqshareid"
            out_path, _ = QFileDialog.getSaveFileName(
                self,
                self.tr("Save My Share ID"),
                str(suggested),
                "Share ID (*.kqshareid)",
            )
            if not out_path:
                return

            Path(out_path).write_text(json.dumps(share_id, indent=2), encoding="utf-8")
            QMessageBox.information(
                self,
                self.tr("Export Share ID"),
                self.tr(
                    "Your Share ID was saved.\nShare it with people who want to send you entries."
                ),
            )

        except Exception as e:
            try:
                log.error("%s [SHARE] export id failed: %s", kql.i("err"), e)
            except Exception:
                pass
            QMessageBox.critical(
                self,
                self.tr("Export Share ID"),
                self.tr("Failed to export Share ID:\n{err}").format(err=e),
            )

    # --- Utilities used by import flow ---
    def _active_username(self) -> str | None:
        # 1) Prefer session username if set
        u = (getattr(self, "current_username", None) or "").strip()
        if u:
            return u

        # 2) Try the login username widget (may be blank after login)
        try:
            raw = (self.currentUsername.text() or "").strip()
        except Exception:
            raw = ""

        if not raw:
            log.error("[AUTH] active username missing (current_username empty and currentUsername widget blank)")
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
        from app.misc_ops import _validate_share_packet as _impl
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
        from vault_store.vault_ui_ops import _minimal_share_entry as _impl
        return _impl(self, *args, **kwargs)

    def quick_share_qr(self, *args, **kwargs):
        from app.misc_ops import quick_share_qr as _impl
        return _impl(self, *args, **kwargs)

    def _preview_full_entry(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _preview_full_entry as _impl
        return _impl(self, *args, **kwargs)

    def _ensure_share_keys_compat(self, key_dir, username, user_key=None):
        kd = str(key_dir) if key_dir is not None else ""
        try:
            return ensure_share_keys(kd, username)            # new signature
        except TypeError:
            return ensure_share_keys(kd, username, user_key)  # old signature

    def import_share_packet(self, *args, **kwargs):
        from app.misc_ops import import_share_packet as _impl
        return _impl(self, *args, **kwargs)

    def quick_import_from_qr(self, *args, **kwargs):
        from app.misc_ops import quick_import_from_qr as _impl
        return _impl(self, *args, **kwargs)

    def _selected_entries_dicts(self, username: str) -> list[dict]:
        """Return minimalized dict(s) for selected row(s). Falls back to currentRow if single selection."""
        table = getattr(self, "vaultTable", None)
        if table is None:
            return []

        try:
            try:
                all_entries = load_vault(username, self.userKey) or []
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

    def make_share_packet(self, *args, **kwargs):
        from app.misc_ops import make_share_packet as _impl
        return _impl(self, *args, **kwargs)

    def quick_export_scan_only(self, *args, **kwargs):
        from app.misc_ops import quick_export_scan_only as _impl
        return _impl(self, *args, **kwargs)

    def _bulk_preview_entries(self, *args, **kwargs):
        from app.misc_ops import _bulk_preview_entries as _impl
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

    def _trash_path(self, username: str, ensure_parent=False) -> str:
        return trash_path(username, ensure_parent=ensure_parent)

    # --- json encrypt/decrypt using vault helpers -------------------

    def _enc_json_write(self, path: str | os.PathLike, key: bytes, data: dict | list) -> None:
        p = str(path)
        try:
            from sync.engine import encrypt_json_file
            encrypt_json_file(p, key, data)
        except Exception:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)

    def _enc_json_read(self, path: str | os.PathLike, key: bytes) -> dict | list:
        p = str(path)
        if not os.path.exists(p):
            return {}
        try:
            from sync.engine import decrypt_json_file
            return decrypt_json_file(p, key) or {}
        except Exception:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)

    def _pwcache_path(self, username: str, ensure_parent=False) -> str:
        # Ensure parent exists and always return a string path
        return str(pw_cache_file(username, ensure_parent=ensure_parent))

    def _pwlast_load(self, username: str, user_key: bytes) -> dict:
        # HKDF 'info' MUST be bytes, not a Path
        info = f"pwcache:{username}".encode("utf-8")
        key  = self._hkdf_subkey(user_key, info)
        return self._enc_json_read(self._pwcache_path(username), key) or {}

    def _pwlast_save(self, username: str, user_key: bytes, obj: dict) -> None:
        info = f"pwcache:{username}".encode("utf-8")
        key  = self._hkdf_subkey(user_key, info)
        self._enc_json_write(self._pwcache_path(username, True), key, obj)

    def _pwlast_put(self, username: str, user_key: bytes, entry_id: str, old_pw: str):
        """Store exactly ONE plaintext (the last one) for this entry."""
        if not (entry_id and old_pw):
            return
        d = self._pwlast_load(username, user_key)
        d[str(entry_id)] = {
            "ts": dt.datetime.now().isoformat(timespec="seconds"),
            "hash": hashlib.sha256(old_pw.encode("utf-8")).hexdigest(),
            "pw": old_pw,
        }
        self._pwlast_save(username, user_key, d)

    def _pwlast_get(self, username: str, user_key: bytes, entry_id: str, *, max_age_days: int = 90) -> str | None:
        d = self._pwlast_load(username, user_key)
        rec = d.get(str(entry_id))
        if not rec:
            return None
        try:
            t = dt.datetime.fromisoformat(rec.get("ts", "").replace("Z", ""))
            if t < dt.datetime.now() - dt.timedelta(days=max_age_days):
                return None
        except Exception:
            pass
        return rec.get("pw") or None

    # ==============================
    # --- Trash storage (encrypted) ----------------
    # ==============================

    def _trash_load(self, username: str, user_key: bytes) -> list:   # - load trash
        """
        Load encrypted trash for this user.
        Returns a list of trashed entries (dicts), or [] if none.
        """
        try:
            key = self._hkdf_subkey(user_key, b"trash")
            return self._enc_json_read(self._trash_path(username), key) or []
        except Exception as e:
            log.error(f"[TRASH] load failed for {username}: {e}")
            return []

    def _trash_save(self, username: str, user_key: bytes, rows: list):       # - save to trash
        """
        Save encrypted trash for this user.
        Overwrites the trash file with the given list of entries.
        """
        try:
            key = self._hkdf_subkey(user_key, b"trash")
            self._enc_json_write(self._trash_path(username, True), key, rows or [])
        except Exception as e:
            log.error(f"[TRASH] save failed for {username}: {e}")
            raise


    # ==============================
    # --- Key-change migrations (reuse across password change / WRAP toggle) ------
    # ==============================
    def _run_key_change_migrations(
        self,
        username: str,
        old_key: bytes,
        new_key: bytes,
        *,
        show_popup: bool = True,
    ) -> tuple[list[dict], bool, bool]:
        """
        Migrate all per-user encrypted stores from old_key -> new_key.

        Returns (results, any_fail, any_changed)
          - results: list of dicts: {"name": str, "status": "ok|skip|fail", "detail": str}
        """
        results: list[dict] = []
        any_fail = False
        any_changed = False

        def _add_result(name: str, status: str, detail: str = ""):
            nonlocal any_fail, any_changed
            results.append({"name": name, "status": status, "detail": detail})
            if status == "fail":
                any_fail = True
            if status == "ok":
                any_changed = True

        if not (old_key and new_key and old_key != new_key):
            return results, False, False

        log.info("[MIGRATE] Detected key change for user=%s (running store migrations)", username)

        # 1) Authenticator Store
        try:
            from vault_store.authenticator_store import migrate_authenticator_store
            ok, msg, changed, failed = migrate_authenticator_store(username, old_key, new_key)
            if ok and changed:
                log.info("[AUTH] %s", msg)
                _add_result("Authenticator store", "ok", msg)
                try:
                    if hasattr(self, "_toast"):
                        self._toast(self.tr("Authenticator refreshed"))
                except Exception:
                    pass
            elif ok:
                log.info("[AUTH] %s", msg)
                _add_result("Authenticator store", "skip", msg)
            else:
                log.error("[AUTH] %s", msg)
                _add_result("Authenticator store", "fail", msg)
        except Exception as e:
            log.exception("[AUTH] post-login migration failed: %s", e)
            _add_result("Authenticator store", "fail", str(e))

        # 2) Password history cache (pwcache)
        try:
            d = self._pwlast_load(username, old_key) or {}
            if d:
                self._pwlast_save(username, new_key, d)
                log.info("[MIGRATE] pwcache migrated (%d records)", len(d))
                _add_result("Password history (pwcache)", "ok", f"Migrated {len(d)} record(s)")
            else:
                log.info("[MIGRATE] pwcache: nothing to migrate")
                _add_result("Password history (pwcache)", "skip", "Nothing to migrate")
        except Exception as e:
            log.warning("[MIGRATE] pwcache migration failed: %s", e)
            _add_result("Password history (pwcache)", "fail", str(e))

        # 3) Trash / soft delete
        try:
            rows = self._trash_load(username, old_key) or []
            if rows:
                self._trash_save(username, new_key, rows)
                log.info("[MIGRATE] trash migrated (%d items)", len(rows))
                _add_result("Trash", "ok", f"Migrated {len(rows)} item(s)")
            else:
                log.info("[MIGRATE] trash: nothing to migrate")
                _add_result("Trash", "skip", "Nothing to migrate")
        except Exception as e:
            log.warning("[MIGRATE] trash migration failed: %s", e)
            _add_result("Trash", "fail", str(e))

        # 4) Encrypted user catalog overlay (+ seal)
        try:
            from catalog_category.catalog_user import migrate_user_catalog_overlay
            ok, msg = migrate_user_catalog_overlay(username, old_key, new_key)
            log.info("[MIGRATE][CATALOG] %s", msg)
            if ok:
                _add_result("User catalog overlay", "ok", msg)
            else:
                _add_result("User catalog overlay", "fail", msg)
        except Exception as e:
            log.warning("[MIGRATE] catalog migration failed: %s", e)
            _add_result("User catalog overlay", "fail", str(e))

        # ---- One popup summary at the end ----
        if show_popup:
            try:
                if results:
                    if any_fail:
                        lines = []
                        for r in results:
                            if r.get("status") == "fail":
                                lines.append(f"• {r['name']}: FAILED — {r.get('detail','')}")
                        QMessageBox.warning(
                            self,
                            self.tr("Migration warnings"),
                            self.tr(
                                "Some files could not be updated after your key change.\n"
                                "{details}\n\n"
                                "What you can do:\n"
                                "• Log out and log in again.\n"
                                "• If it still fails, restore from your most recent FULL backup."
                            ).format(details="\n".join(lines)),
                        )
                    else:
                        QMessageBox.information(
                            self,
                            self.tr("Migration complete"),
                            self.tr("All files have been updated successfully."),
                        )
            except Exception as e:
                log.warning("[MIGRATE] summary popup failed: %s", e)

        return results, any_fail, any_changed

    def soft_delete_entry(self, *args, **kwargs):
        from vault_store.vault_ui_ops import soft_delete_entry as _impl
        return _impl(self, *args, **kwargs)

    def on_move_to_trash_clicked(self):       # - move to trash button click
        row = self.vaultTable.currentRow()
        if row < 0:
            QMessageBox.information(self, self.tr("Delete"), self.tr("Select an item to delete."))
            return

        # Map visible row → real vault index
        try:
            global_index = self.current_entries_indices[row]
        except Exception:
            global_index = row
        log.debug("[TRASH] UI row=%s -> global_index=%s", row, global_index)

        if QtWidgets.QMessageBox.question(
            self, self.tr("Move to Trash"),
            self.tr("This item will be moved to Trash and kept up to 30 days. Continue?")
        ) != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        ok, why = self.soft_delete_entry(self.currentUsername.text(), self.userKey, int(global_index))
        log.debug("[TRASH] soft_delete result ok=%s why='%s'", ok, why)

        if ok:
            try: self._toast(self.tr("Moved to Trash (kept up to 30 days)."))
            except Exception: pass
            try: 
                update_baseline(username=self.currentUsername.text(), verify_after=False, who="Trash Vault changed")
            except Exception: pass
            try: self.load_vault_table()
            except Exception: pass
            try:
                self._watchtower_rescan(self)
            except Exception: pass
        else:
            msg = self.tr("Could not delete this entry.\n\n") + f"{why}"
            QtWidgets.QMessageBox.critical(self, self.tr("Delete"), msg)

    def restore_from_trash_uid(self, username: str, key: bytes, uid: str) -> bool:       # - restore from trash using uid
        if not self._require_unlocked():
            return
        try:
            trash = self._trash_load(username, key) or []
            picked_i = -1
            for i, e in enumerate(trash):
                if str(e.get("_trash_uid") or "") == str(uid):
                    picked_i = i
                    break
            if picked_i < 0:
                return False

            picked = trash.pop(picked_i)
            self._trash_save(username, key, trash)

            picked.pop("_deleted_at", None)
            picked.pop("_trash_uid", None)
            try:

                add_vault_entry(username, key, picked)
                self._on_any_entry_changed()
            except Exception:
                rows = load_vault(username, key) or []
                rows.append(picked)
                save_vault(username, key, rows)
                self._on_any_entry_changed()
            return True
        except Exception:
            return False

    def restore_from_trash_index(self, username: str, key: bytes, index_in_trash: int) -> bool:             # - restore from trash using index  remove
        """
        Restore a trashed item by its index within the trash list.
        Useful when the trashed item has no persistent id.
        """
        if not self._require_unlocked():
            return
        try:
            trash = self._trash_load(username, key) or []
            if not (0 <= int(index_in_trash) < len(trash)):
                return False
            # remove from trash
            picked = trash.pop(int(index_in_trash))
            self._trash_save(username, key, trash)

            # add back to vault
            picked.pop("_deleted_at", None)
            try:
                add_vault_entry(username, key, picked)
                self._on_any_entry_changed()
            except Exception:
                # fallback if add_vault_entry not available
                rows = load_vault(username, key) or []
                rows.append(picked)
                save_vault(username, key, rows)
                self._on_any_entry_changed()
            return True
        except Exception as e:
            log.error(f"[Trash] restore_from_trash_index failed: {e}")
            return False

    def restore_from_trash(self, username: str, key: bytes, match_id: str) -> bool:    # - find item to restore id 
        """
        Restore a trashed item by persistent id (id/_id/row_id) or fingerprint ('fp:...').
        """
        if not self._require_unlocked():
            return
        try:
            trash = self._trash_load(username, key) or []
            picked = None
            picked_i = -1

            # exact id match
            def _rid(e):
                return str(e.get("id") or e.get("_id") or e.get("row_id") or "")

            for i, e in enumerate(trash):
                if _rid(e) and _rid(e) == str(match_id):
                    picked = e; picked_i = i
                    break

            # fingerprint fallback
            if picked is None and str(match_id).startswith("fp:"):
                def _norm(s): return (s or "").strip().lower()
                for i, e in enumerate(trash):
                    t = _norm(e.get("title") or e.get("site") or e.get("name"))
                    u = _norm(e.get("username") or e.get("user"))
                    url = _norm(e.get("url") or e.get("origin"))
                    pw = e.get("password") or e.get("Password") or ""
                    pwh = hashlib.sha256((pw or "").encode("utf-8")).hexdigest()
                    fp  = "fp:" + hashlib.sha256(f"{t}|{u}|{url}|{pwh}".encode("utf-8")).hexdigest()
                    if fp == str(match_id):
                        picked = e; picked_i = i
                        break

            if picked is None:
                return False

            # remove from trash
            trash.pop(picked_i)
            self._trash_save(username, key, trash)

            # add back to vault
            picked.pop("_deleted_at", None)
            try:
                
                add_vault_entry(username, key, picked)
                self._on_any_entry_changed()
            except Exception:
                rows = load_vault(username, key) or []
                rows.append(picked)
                save_vault(username, key, rows)
                self._on_any_entry_changed()
            return True
        except Exception as e:
            log.error(f"[Trash] restore_from_trash failed: {e}")
            return False
   
    # NOTE add option to change this on updates (in settings add option to change days)
    def _auto_purge_trash(self) -> int:  # - delete after 30 days
        """Purge trashed items older than TRASH_KEEP_DAYS; quiet if anything is missing."""
        try:
            username = (self.currentUsername.text() or "").strip()
            if not username:
                return 0
            self.set_status_txt(self.tr("KQ TRASH: Time to delete? "))
            keep_days = int(os.getenv("KQ_TRASH_KEEP_DAYS", TRASH_KEEP_DAYS_DEFAULT))
            cutoff = dt.datetime.utcnow() - dt.timedelta(days=keep_days)
            trash = self._trash_load(username) or []      # expects list of dicts
            keep, purge = [], []
            for it in trash:
                ts_str = (it.get("deleted_at") or it.get("ts") or it.get("deleted") or "")
                try:
                    ts = dt.datetime.fromisoformat(ts_str.replace("Z",""))
                except Exception:
                    # If no timestamp, treat as old → purge
                    ts = dt.datetime(1970,1,1)
                (purge if ts < cutoff else keep).append(it)
            if len(purge) == 0:
                return 0
            # Save trimmed trash
            self._trash_save(username, keep)
            # log & rescan
            try:
                for it in purge:
                    try:
                        log_event_encrypted(username, self.tr("trash_purge"), {"id": it.get("id") or it.get("uuid")})
                    except Exception:
                        pass
                    self._watchtower_rescan(self)
            except Exception:
                pass
            # quick heads-up
            try:
                if getattr(self, "_toast", None):
                    txt = self.tr("Purged ") + f"{len(purge)}" + self.tr(" old item(s) from Trash.")
                    self._toast(txt)
                    self.set_status_txt(txt)
            except Exception:
                pass
            return len(purge)
        except Exception:
            return 0

    def show_trash_manager(self, *args, **kwargs):
        from vault_store.vault_ui_ops import show_trash_manager as _impl
        return _impl(self, *args, **kwargs)

    def purge_trash(self, username: str, key: bytes, max_age_days: int = 30) -> int:   # - delete after 30 days
        """
        Remove soft-deleted items older than max_age_days from the encrypted trash.
        Return the number of items purged.
        """
        # After login/unlock
        trash = self._trash_load(username, key)
        if not trash:
            return 0

        cutoff = dt.datetime.now() - dt.timedelta(days=max_age_days)

        def _parse_iso(ts: str):
            """Best-effort parse for ISO-like timestamps (no dateutil)."""
            if not ts:
                return None
            s = ts.strip().replace("Z", "")
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    return dt.datetime.strptime(s, fmt)
                except Exception:
                    pass
            try:
                return dt.datetime.fromisoformat(s)
            except Exception:
                return None

        def _deleted_at(entry) -> dt.datetime | None:
            return _parse_iso(entry.get("_deleted_at") or "")

        kept = [e for e in trash if (t := _deleted_at(e)) is None or t >= cutoff]
        purged = len(trash) - len(kept)
        if purged:
            self._trash_save(username, key, kept)
        return purged

    def _trash_preview_for_entry(self, *args, **kwargs):
        from vault_store.vault_ui_ops import _trash_preview_for_entry as _impl
        return _impl(self, *args, **kwargs)

    def _redact_for_preview(self, entry: dict) -> dict: # - trash preview
        """
        Return a shallow copy with common secret fields masked.
        """
        secretish = {
            "password","Password","pwd","secret","otp","totp",
            "api_key","api key","token","access_key","private_key","ssh_private",
            "card_number","Card Number","cvv","cvc","pin","recovery key","recovery_key"
        }
        red = {}
        for k, v in (entry or {}).items():
            if isinstance(v, str) and k.lower() in secretish:
                red[k] = "••••••••"
            else:
                red[k] = v
        return red


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

    def _continue_after_factors(self, *args, **kwargs):
        from app.misc_ops import _continue_after_factors as _impl
        return _impl(self, *args, **kwargs)
    
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

    def _load_catalog_effective(self, username: str):
        # Key must exist (defensive guard)
        if not isinstance(getattr(self, "userKey", None), (bytes, bytearray)):
            log.info("[CATALOG] ERROR: userKey missing/invalid in _load_catalog_effective")
            return self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE, getattr(self, "AUTOFILL_RECIPES", {}), {}

        # 1) Ensure encrypted defaults exist for this user (expects username)
        ensure_user_catalog_created(
            username,
            CLIENTS, ALIASES, PLATFORM_GUIDE,
            user_key=self.userKey
        )

        # 2) Load decrypted overlay (expects username)
        overlay = load_user_catalog_raw(username, self.userKey) or {}

        # 3/4) Merge built-ins + overlay (returns 5 values)
        return load_effective_catalogs_from_user(
            username,
            CLIENTS, ALIASES, PLATFORM_GUIDE,
            user_key=self.userKey,
            user_overlay=overlay
        )

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

    def check_backup_codes_ok(self, *args, **kwargs):
        from app.misc_ops import check_backup_codes_ok as _impl
        return _impl(self, *args, **kwargs)

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
        from app.misc_ops import _show_logout_warning as _impl
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
        from app.misc_ops import verify_sensitive_action as _impl
        return _impl(self, *args, **kwargs)

    def _set_switch_checked(self, on: bool):
        """Set switch state without firing toggled again."""
        w = getattr(self, "bridgeEnableSwitch", None)
        if not w:
            return
        try:
            w.blockSignals(True)
            w.setChecked(bool(on))
        finally:
            try: w.blockSignals(False)
            except Exception: pass

    def _on_bridge_toggle(self, checked: bool):
        self.set_status_txt(self.tr("Bridge toggle Changed"))
        """Enable/disable the local bridge explicitly."""
        try:
            if checked:
                # Start
                tok = self.ensure_bridge_token(new=False)
                if not tok:
                    QMessageBox.warning(self, self.tr("Enable Bridge"), self.tr("Unlock your vault first."))
                    self._set_switch_checked(False)
                    return
                try:
                    self.start_bridge_server(strict=None)
                    self.start_bridge_monitoring()
                    # instant refresh
                    try: self._poll_bridge_once()
                    except Exception: pass
                    self._toast(self.tr("Bridge enabled (localhost only)."))
                except Exception as e:
                    self._set_switch_checked(False)
                    self._toast(self.tr("Bridge failed to start: ") + f"{e}")
            else:
                # Stop
                try: self.stop_bridge_monitoring()
                except Exception: pass
                try: self.stop_bridge_server()
                except Exception: pass
                try: self._set_bridge_offline()   # from earlier step
                except Exception: pass
                self._toast(self.tr("Bridge disabled."))
        except Exception as e:
            # Revert on error
            self._set_switch_checked(False)
            log.error(f"[BRIDGE] toggle failed: {e}")

    def stop_bridge_server(self):
        srv = getattr(self, "_bridge_httpd", None)
        if srv:
            try:
                srv.shutdown()
            except Exception:
                pass
            self._bridge_httpd = None

        try:
            self.stop_bridge_monitoring()
        except Exception:
            pass

        # Force the label to show offline
        self._set_bridge_offline()

    def _set_bridge_offline(self):
        """Force the bridge status label to show offline."""
        try:
            self.clear_bridge_token()
            if hasattr(self, "vault_connected_"):
                self.vault_connected_.setText(self.tr("Bridge: Offline — stopped"))
                self.vault_connected_.setStyleSheet("color: #ff5555;")  # red text
        except Exception:
            pass

    def _is_bridge_running(self) -> bool:
        try:
            return getattr(self, "_bridge_httpd", None) is not None
        except Exception:
            return False

    def on_toggle_autostart_bridge(self, checked: bool):
        self.set_status_txt(self.tr("Bridge saveing change ") + f"{checked}")
        """Persist user preference for Bridge autostart."""
        try:
            u = (self.currentUsername.text() or "").strip()
            if not u:
                return
            set_user_setting(u, "autostart_bridge", bool(checked))
            update_baseline(username=u, verify_after=False, who=f"Autostart Bridge Changed={checked}")
            if checked:
                self._toast(self.tr("Bridge will auto-start after login."))
            else:
                self._toast(self.tr("Bridge auto-start disabled."))
            self.set_status_txt(self.tr("Done"))
        except Exception as e:
            log.error(f"[SETTINGS] Failed to save autostart_bridge: {e}")

    def _rotate_bridge_token(self):
        self._bridge_token = secrets.token_urlsafe(32)
        try:
            log.debug("%s [BRIDGE] token rotated (%s…%s)",
                      kql.i('ok'), self._bridge_token[:6], self._bridge_token[-6:])
        except Exception:
            pass

    # 1) ---------- helpers that touch the table ----------
    def _header_texts_lower(self):
        out = []
        for c in range(self.vaultTable.columnCount()):
            hi = self.vaultTable.horizontalHeaderItem(c)
            out.append(hi.text().strip().lower() if hi else "")
        return out

    def _find_col_by_labels(self, names: set[str]) -> int:
        want = {s.lower() for s in names}
        for i, t in enumerate(self._header_texts_lower()):
            if t in want:
                return i
        return -1

    def _get_password_from_table(self, row: int) -> str:
        """Return the real secret stored in the table's UserRole for this row."""
        tbl = getattr(self, "vaultTable", None)
        if not tbl or row < 0 or row >= tbl.rowCount():
            return ""

        roles = [
            int(Qt.ItemDataRole.UserRole),
            int(Qt.ItemDataRole.UserRole) + 1,
            int(Qt.ItemDataRole.UserRole) + 42,
        ]

        def _secret_from_item(it) -> str:
            if not it:
                return ""
            for role in roles:
                val = it.data(role)
                if isinstance(val, bytes) and val:
                    try:
                        return val.decode("utf-8", "ignore")
                    except Exception:
                        continue
                if isinstance(val, str) and val.strip():
                    return val
            return ""

        if not hasattr(self, "_kq_pw_col"):
            labels = {
                "password", "pass", "passcode", "pwd", "secret",
                "backup code", "backup", "recovery code", "2fa code", "otp", "code",
            }
            self._kq_pw_col = self._find_col_by_labels(labels)

        if isinstance(self, object) and isinstance(self._kq_pw_col, int) and self._kq_pw_col >= 0:
            v = _secret_from_item(tbl.item(row, self._kq_pw_col))
            if v:
                return v

        for c in range(tbl.columnCount()):
            v = _secret_from_item(tbl.item(row, c))
            if v:
                return v

        cache = getattr(self, "_pw_cache_by_row", None)
        if isinstance(cache, dict) and cache.get(row):
            return cache[row]

        return ""

    def _get_text(self, row: int, col: int) -> str:
        if col < 0:
            return ""
        it = self.vaultTable.item(row, col)
        return (it.text() if it else "") or ""

    def _set_pw_cell(self, row: int, col: int, password: str):
        display = "●" * max(8, len(password or ""))
        it = QTableWidgetItem(display)
        it.setData(int(Qt.ItemDataRole.UserRole), password or "")
        it.setFlags(it.flags() & ~Qt.ItemIsEditable)
        self.vaultTable.setItem(row, col, it)

    # ---------- Webfill profile (read-only; not saved to vault) ----------

    def _webfill_profile_path(self) -> Path:
        """Where your local Webfill profile (address/contact) lives."""
        try:
            base = Path(CONFIG_DIR)
        except Exception:
            base = Path.home() / ".keyquorum"
        base.mkdir(parents=True, exist_ok=True)
        return base / "Webfill_profile.json"   

    def save_webfill_profile(self, profile: dict) -> None:
        """
        Optional helper if you later add a UI to edit the profile.
        NOT called by autofill; provided for completeness.
        """
        try:
            p = self._webfill_profile_path(self)
            p.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def load_webfill_profile(self) -> dict:

        defaults = {
            "honorific": "",
            "forename": "",
            "middle":   "",
            "surname":  "",
            "email":    "",
            "phone":    "",
            "address1": "",
            "address2": "",
            "city":     "",
            "region":   "",
            "postal":   "",
            "country":  "",
        }

        try:
            table = getattr(self, "vaultTable", None)
            if not table or table.rowCount() == 0:
                return defaults

            r = table.currentRow()
            if r is None or r < 0 or r >= table.rowCount():
                r = 0

            def cell(lbl: str, *fallbacks: str) -> str:
                # try new label first, then old ones
                for key in (lbl, *fallbacks):
                    try:
                        idx = self._column_index_case_insensitive(key)
                        if idx >= 0:
                            v = self._get_text(r, idx) or ""
                            if v:
                                return v.strip()
                    except Exception:
                        pass
                return ""

            out = defaults.copy()
            out["honorific"] = cell(WEBFILL_COL["HONORIFIC"], "Name title", "Name Title")
            out["forename"]  = cell(WEBFILL_COL["FORENAME"],   "Forename", "First")
            out["middle"]    = cell(WEBFILL_COL["MIDDLENAME"], "Middle", "Middle name")
            out["surname"]   = cell(WEBFILL_COL["SURNAME"],    "Surname", "Last")
            out["email"]     = cell(WEBFILL_COL["EMAIL"],      "Email address", "Email")
            out["phone"]     = cell(WEBFILL_COL["PHONE"],      "Phone", "Phone number")
            out["address1"]  = cell(WEBFILL_COL["ADDR1"],      "Address line 1")
            out["address2"]  = cell(WEBFILL_COL["ADDR2"],      "Address line 2")
            out["city"]      = cell(WEBFILL_COL["CITY"],       "City / Town")
            out["region"]    = cell(WEBFILL_COL["REGION"],     "County / State / Region", "Region", "State", "County")
            out["postal"]    = cell(WEBFILL_COL["POSTAL"],     "Postal code / ZIP", "Postcode", "ZIP")
            out["country"]   = cell(WEBFILL_COL["COUNTRY"],    "Country")
            return out
        except Exception:
            return defaults

    def webfill_synonyms(self) -> dict[str, list[str]]:
        return {
            "honorific": ["honorific-prefix","title","salutation","name title","honorific","prefix"],
            "forename":  ["first","first name","firstname","given","given name","forename","given-name"],
            "middle":    ["middle","middle name","middlename","additional-name","additional name"],
            "surname":   ["surname","last","last name","lastname","family","family name","family-name"],
            "email":     ["email","email address","emailaddress","e-mail","mailaddress"],
            "phone":     ["phone","phone number","phonenumber","tel","telephone","mobile","contact"],
            "address1":  ["address line 1","address-line1","addressline1","address1","street","street address","addr1"],
            "address2":  ["address line 2","address-line2","addressline2","address2","street2","apt","apartment","suite","unit","addr2"],
            "city":      ["city","town","city/town","city or town","locality","address-level2"],
            "region":    ["state / province / region","state/province/region","region","state","county","province","territory","address-level1","addressregion"],
            "postal":    ["postal code / zip","postal-code","postcode","zip","zip code","zipcode","postal"],
            "country":   ["country","country code","countryname","addresscountry"],
        }

    def card_synonyms(self) -> dict[str, list[str]]:
        """
        Synonym patterns the extension can use to map credit-card fields.
        These keys correspond to canonical credit card properties used by the browser extension.
        Each list contains lowercased substrings to match against name/id/label/placeholder attributes.
        """
        return {
            # Name on card / cardholder
            "name": ["name","cardholder","card holder","holder","cardholder name","name on card","cc-name"],
            # Primary card number
            "number": ["number","card number","card no","card no.","cardno","cc number","cc-number","ccnum"],
            # Expiry date (combined MM/YY or similar)
            # Expiry date (combined MM/YY or similar). Include explicit "expiry date"
            "expiry": [
                "exp",
                "expiry",
                "expiration",
                "expires",
                "exp date",
                "expiration date",
                "expiry date",
                "expdate",
                "mm/yy",
                "mm yy",
                "mm-yy",
            ],
            # Separate month of expiry
            "month": ["month","mm","exp-month","cc-exp-month","exp month","expire month"],
            # Separate year of expiry
            "year": ["year","yy","yyyy","exp-year","cc-exp-year","exp year","expire year"],
            # Card verification code
            "cvc": ["cvc","cvv","security code","cvn","cvc2","cvv2","cid","csc","cvc/cvv"],
        }

    def get_credit_cards(self, *args, **kwargs):
        from app.misc_ops import get_credit_cards as _impl
        return _impl(self, *args, **kwargs)

    def get_entries_for_origin(self, *args, **kwargs):
        from app.misc_ops import get_entries_for_origin as _impl
        return _impl(self, *args, **kwargs)

    def lookup_entries_by_domain(self, domain_or_origin: str):
        return self.get_entries_for_origin(domain_or_origin)

    def is_vault_unlocked(self) -> bool:
        uk = getattr(self, "userKey", None)
        return isinstance(uk, (bytes, bytearray)) and any(uk or [])

    # 3a) ---------- bridge token helpers ----------
    def _bridge_token_path(self) -> Path:
        from app.paths import bridge_token_dir
        return bridge_token_dir(self.currentUsername.text())

    def load_bridge_token(self) -> str:
        """Load the persisted bridge token from disk, if any."""
        try:
            return self._bridge_token_path().read_text(encoding="utf-8").strip()
        except Exception:
            return ""

    def save_bridge_token(self, token: str) -> None:
        """Persist the given bridge token to disk."""
        try:
            self._bridge_token_path().write_text(token.strip(), encoding="utf-8")
        except Exception:
            pass

    def ensure_bridge_token(self, *, new: bool = False) -> str:
        """
        Return the current bridge token.
        If new=True, always create a fresh one (ephemeral, not loaded from disk).
        """
        if new:
            tok = secrets.token_urlsafe(32)
            self.bridge_token = tok
            # NOTE: (V2) store in file for passkey and browser usage
            self.save_bridge_token(tok) 
            return tok

        tok = getattr(self, "bridge_token", "") or ""
        if tok:
            return tok

        # reuse from disk only when not rotating
        tok = (self.load_bridge_token() or "").strip()
        if not tok:
            tok = secrets.token_urlsafe(32)
            self.save_bridge_token(tok)  # persist only if you want non-ephemeral
        self.bridge_token = tok
        return tok

    def clear_bridge_token(self):
        """Clear token in memory (and on disk if you persisted it)."""
        self.bridge_token = ""
        # NOTE: Need to add new token file from last update
        try:
            self.save_bridge_token("") 
        except Exception:
            pass

    # 4) ---------- save new credential (runs in UI thread) ----------
    def _persist_now(self):
        """Call your existing save/persist function if present."""
        for name in ("save_vault", "persist_vault_changes", "save_vault_table", "save_all"):
            fn = getattr(self, name, None)
            if callable(fn):
                try: fn()
                except Exception: pass
                break

    def save_credential_ui(self, *args, **kwargs):
        from app.misc_ops import save_credential_ui as _impl
        return _impl(self, *args, **kwargs)

    def _with_always_on_top(self, fn):
        """Temporarily set the main window always-on-top while running fn()."""
        flags = self.windowFlags()
        try:
            self.setWindowFlag(Qt.WindowStaysOnTopHint, True)
            self.show(); self.raise_(); self.activateWindow()
            return fn()
        finally:
            try:
                self.setWindowFlags(flags)
                self.show()
            except Exception:
                pass

    def show_password_generator_from_bridge(self) -> bool:
        """
        Open the in-app password generator.  Returns True if shown.  Uses
        _with_always_on_top so the dialog appears on top of the main window.
        """
        try:
            def _open():
                try:
                    # open with no target fields; dialog will handle copy/insert
                    show_password_generator_dialog()
                except Exception:
                    pass
            self._with_always_on_top(_open)
            return True
        except Exception:
            return False

    def generate_password_headless(self, opts: dict | None = None) -> str:
        """
        Generate a strong password without showing the UI.  Options may
        include: length:int, use_symbols:bool, avoid_ambiguous:bool.  Falls
        back to a simple generator if the project’s generator is unavailable.
        """
        length = int((opts or {}).get("length", 20))
        use_symbols = bool((opts or {}).get("use_symbols", True))
        avoid_ambiguous = bool((opts or {}).get("avoid_ambiguous", True))
        try:
            return generate_strong_password(length=length)
        except Exception:
            letters = string.ascii_letters + string.digits
            symbols = "!@#$%^&*()-_=+[]{};:,./?"
            alphabet = letters + (symbols if use_symbols else "")
            if avoid_ambiguous:
                for ch in "O0Il":
                    alphabet = alphabet.replace(ch, "")
            return "".join(secrets.choice(alphabet) for _ in range(max(12, length)))

    # --- save a Webfill profile coming from the extension -------------

    def save_profile_from_bridge(self, *args, **kwargs):
        from app.misc_ops import save_profile_from_bridge as _impl
        return _impl(self, *args, **kwargs)

    def save_card_from_bridge(self, payload: dict) -> bool:
        if not self._require_unlocked(): 
            return
        try:
            name  = payload.get("name") or payload.get("cardholder") or ""
            number = payload.get("number") or ""
            cvc    = payload.get("cvv") or payload.get("cvc") or ""
            mm = (payload.get("month") or "").zfill(2)
            yy = (payload.get("year") or "")
            expiry = payload.get("expiry") or (f"{mm}/{yy[-2:]}" if (mm and yy) else "")
            title = payload.get("title") or (f"Card ••••{str(number)[-4:]}" if number else "Card")

            billing = " ".join(s for s in [
                payload.get("address1"), payload.get("address2"),
                payload.get("city"), payload.get("region"),
                payload.get("postal"), payload.get("country")
            ] if s)

            new_entry = {
                "category": "Credit Cards",
                "Title": title,
                "Card Type": payload.get("card_type") or "",
                "Cardholder Name": name,
                "Card Number": number,
                "Expiry Date": expiry,
                "CVV": cvc,
                "Billing Address": billing,
            }
            add_vault_entry(self.currentUsername.text(), self.userKey, new_entry)
            self._on_any_entry_changed()
            # schedule UI refresh (queued)
            _ui_async(lambda: (self.categorySelector_2.setCurrentText("Credit Cards"), self.load_vault_table()))
            _ui_async(lambda: update_baseline(username=self.currentUsername.text(), verify_after=False, who=f"Save from bridge (Credit Cards) -> Updated"))
            return True
        except Exception as e:
            log.error(f"[BRIDGE] save_card_from_bridge failed: {e}")
            return False
    
    def get_webfill_profiles(self, *args, **kwargs):
        from app.misc_ops import get_webfill_profiles as _impl
        return _impl(self, *args, **kwargs)

    def _set_bridge_indicator(self, *, online: bool, locked: bool | None = None, note: str = "") -> None:
        """
        Update the small status label: green when Online, red when Offline.
        If 'locked' is True/False, show a hint. 'note' shows short extra info.
        """
        try:
            lab = getattr(self, "vault_connected_", None)
            if not lab:
                lab = self.findChild(QLabel, "vault_connected_")
                if not lab:
                    return
            if online:
                txt = self.tr("● Bridge: Online")
                if locked is True:
                    txt += self.tr(" (vault locked)")
                elif locked is False:
                    txt += self.tr(" (vault unlocked)")
                if note:
                    txt += self.tr(" — {note1}").format(note1=note)
                lab.setText(txt)
                lab.setStyleSheet("color: #19a974; font-weight: 600;")  # green
            else:
                txt = self.tr("● Bridge: Offline")
                if note:
                    txt += self.tr(" — {note1}").format(note1=note)
                lab.setText(txt)
                lab.setStyleSheet("color: #e74c3c; font-weight: 600;")  # red
            try:
                self._set_switch_checked(bool(online))
            except Exception:
                pass

        except Exception:
            log.exception("%s [UI] bridge indicator update failed", kql.i('err'))

    def _tcp_ready(self, host: str, port: int, timeout: float = 0.35) -> bool:
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True
        except Exception:
            return False

    def _bridge_status_json(self, host: str, port: int, timeout: float = 0.7):
        """
        GET /v1/status. Returns (ok: bool, json: dict|None, http_status: int|None).
        Does not require token.
        """
        try:
            c = http.client.HTTPConnection(host, int(port), timeout=timeout)
            c.request("GET", "/v1/status")
            r = c.getresponse()
            body = r.read() or b""
            c.close()
            data = None
            try:
                data = json.loads(body.decode("utf-8", "replace")) if body else None
            except Exception:
                data = None
            return True, data, r.status
        except Exception:
            return False, None, None

    def _poll_bridge_once(self) -> None:
        """
        One-shot refresh of the indicator. Safe to call anytime.
        """
        host = "127.0.0.1"
        port = int(getattr(self, "_bridge_port", 8742))
        httpd = getattr(self, "_bridge_httpd", None)

        # If our server object isn't present, it's offline for our purposes.
        if httpd is None:
            self._set_bridge_indicator(online=False, note=self.tr("not running"))
            return

        # Fast TCP probe first (accepts + close → 'empty response' still counts as reachable)
        if not self._tcp_ready(host, port):
            self._set_bridge_indicator(online=False, note=self.tr("no listener on :{port1}").format(port1=port))
            return

        ok, data, code = self._bridge_status_json(host, port)
        if not ok or code not in (200, 401, 403):
            self._set_bridge_indicator(online=False, note=f"HTTP {code or '—'}")
            return

        # We’re online. Try to show locked state if the endpoint returns it.
        locked = None
        try:
            if isinstance(data, dict) and "locked" in data:
                locked = bool(data["locked"])
        except Exception:
            pass
        self._set_bridge_indicator(online=True, locked=locked)

    # --- Timer to keep it fresh (start after login, stop on logout)

    def start_bridge_monitoring(self):
        """Begin periodic status checks (idempotent)."""
        if getattr(self, "_bridge_mon_timer", None):
            return
        self._bridge_mon_timer = QTimer(self)
        self._bridge_mon_timer.setInterval(2500)  # 2.5s is snappy but light
        self._bridge_mon_timer.timeout.connect(self._poll_bridge_once)
        self._bridge_mon_timer.start()
        # prime it immediately
        self._poll_bridge_once()

    def stop_bridge_monitoring(self):
        t = getattr(self, "_bridge_mon_timer", None)
        if t:
            try:
                t.stop()
            except Exception:
                pass
            self._bridge_mon_timer = None
        # reflect offline unless we know otherwise
        self._set_bridge_indicator(online=False, note=self.tr("stopped"))

    # --- button diagnose

    def on_vault_diagButton_clicked(self, *args, **kwargs):
        from vault_store.vault_ui_ops import on_vault_diagButton_clicked as _impl
        return _impl(self, *args, **kwargs)

    def start_bridge_server(self, *args, **kwargs):
        from app.misc_ops import start_bridge_server as _impl
        return _impl(self, *args, **kwargs)

    def check_bridge_token_headless(self, presented: str) -> bool:
        # compare with store as the current token / auth mode
        expected = (self.bridgeToken.text() or "").strip()
        mode = (self.authMode.currentText() or "Authorization").lower()
        if mode in ("none", "disabled"):
            return True
        return bool(presented) and presented == expected

    def stop_bridge_server(self):
        srv = getattr(self, "_bridge_httpd", None)
        if srv:
            try: srv.shutdown()
            except Exception: pass
            self._bridge_httpd = None

    # --- install exitsion_ 
    def on_install_ext_(self):
        """
        Show security info, then open the store page so users can install the extension.
        """
        # --- Show info popup ---
        msg = QMessageBox(self)
        msg.setWindowTitle(self.tr("Browser Extension Security Info"))
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowFlags(msg.windowFlags() | Qt.WindowStaysOnTopHint)
        msg.setText(self.tr(
            "<b>Before installing the extension, please read:</b><br><br>"
            "• Everything happens locally on your PC – nothing is sent to the cloud.<br>"
            "• The bridge only listens on <code>localhost</code> (never leaves your computer).<br>"
            "• Your vault stays encrypted and locked until you unlock it.<br>"
            "• A random token protects the bridge – keep it secret.<br>"
            "• Auto-fill works only on matching, HTTPS-protected sites.<br><br>"
            "<i>Keep your system updated and malware-free – security depends on your device.</i>")
        )
        msg.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        msg.setDefaultButton(QMessageBox.StandardButton.Ok)

        ret = msg.exec()
        if ret != QMessageBox.StandardButton.Ok:
            return
        open_url(url="STORE_URL_CHROME", default_=True)
 
    def on_pair_browser_(self):
        """Start/verify the local bridge and show the pairing token + URL."""
        log.info("%s [PAIR] button clicked", kql.i('ok'))
        try:
            # 1) Ensure a token (don't rotate unless explicitly requested or logout ) 
            token = self.ensure_bridge_token(new=False)
            if not token:
                log.error("%s [BRIDGE] no token (user not logged in?)", kql.i('err'))
                QMessageBox.warning(self, self.tr("Pairing"), self.tr("No token available. Please unlock your vault first."))
                return

            # 2) Start (or verify) the local HTTP bridge (idempotent)
            try:
                self.start_bridge_server(strict=None)
                self.start_bridge_monitoring()
            except Exception:
                log.exception("%s [BRIDGE] start threw", kql.i('err'))

            httpd = getattr(self, "_bridge_httpd", None)
            if httpd is None:
                log.error("%s [BRIDGE] not running", kql.i('err'))
                QMessageBox.warning(
                    self, self.tr("Pairing"),
                    self.tr("The local bridge isn't running. Check antivirus/firewall and try again.")
                )
                return

            # 3) Use the actual bound port
            port = int(getattr(self, "_bridge_port", 8742))

            # Safer token mask
            def _mask(t: str) -> str:
                return t if len(t) < 12 else f"{t[:6]}…{t[-6:]}"
            log.info("✅ [PAIR] bridge ready on 127.0.0.1:%s • token=%s", port, _mask(token))

            # 4) Show dialog (with live URL)
            self._show_pairing_dialog(token, port)

        except Exception:
            log.exception("%s [PAIR] failed", kql.i('err'))
            QMessageBox.critical(self, self.tr("Pairing error"), self.tr("Could not start or show pairing. See log for details."))

    def _show_pairing_dialog(self, *args, **kwargs):
        from auth.login.auth_flow_ops import _show_pairing_dialog as _impl
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

        username = (self.currentUsername.text() or "").strip()
        if not username:
            QMessageBox.warning(
                self,
                self.tr("Change Password"),
                self.tr("Please log in to your account before changing the password."),
            )
            return

        # Recommend a full backup before any password / key changes
        reply = QMessageBox.question(
            self,
            self.tr("Safety Backup Recommended"),
            (
                self.tr("For safety, Keyquorum can create a FULL encrypted backup of your "
                "account before changing the password.\n\n"
                "This backup contains only encrypted data (no plain passwords) and "
                "can help you recover if something goes wrong during the change.\n\n"
                "Do you want to create a full backup now?")
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )

        if reply == QMessageBox.Yes:
            try:
                self.export_vault()
            except Exception as e:
                QMessageBox.warning(
                    self,
                    self.tr("Backup Error"),
                    (
                        self.tr("Keyquorum tried to create a full backup but an error occurred:\n\n"
                        "{e}\n\n"
                        "You can still continue with the password change, but it is "
                        "strongly recommended to resolve this backup issue first.").format(e)
                    ),
                )

        self.set_status_txt(self.tr("Opening Change Password dialog"))
        log.debug("%s [UI OPEN] open change password dialog", kql.i("ui"))

        dialog = ChangePasswordDialog(username, self.userKey, self)
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
                username = (self.currentUsername.text() or "").strip()
            except Exception:
                username = ""
        if not username:
            QMessageBox.information(
                self,
                self.tr("Reminders"),
                self.tr("Please log in first."),
            )
            return

        try:
            from features.reminders.reminders_dialog import RemindersDialog
        except Exception as e:
            QMessageBox.warning(
                self,
                self.tr("Reminders"),
                self.tr("Reminders feature isn't available in this build:{e}").format(e=e),
            )
            return

        dlg = RemindersDialog(parent=self, username=username, user_key=getattr(self, "userKey", None))
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
            QMessageBox.information(
                self,
                self.tr("Security Preferences"),
                self.tr("Please enter or select a user first."),
            )
            return

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

    def delete_selected_vault_entry(self, *args, **kwargs):
        from vault_store.vault_ui_ops import delete_selected_vault_entry as _impl
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
            entries = load_vault(self.currentUsername.text(), getattr(self, "userKey", None)) or []

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
    # - all lables, check boxs, timers, apply theme, ect
    # - then loads table
    
    def load_setting(self, *args, **kwargs):
        from ui.settings_ops import load_setting as _impl
        return _impl(self, *args, **kwargs)

    def _wire_spin(self, spin, handler, cast=float):
        """Wire a QSpinBox/QDoubleSpinBox with debounced live updates + flush on commit."""
        if not spin or not handler:
            return

        # Don't emit on every keystroke
        try: spin.setKeyboardTracking(False)
        except Exception: pass

        cb_val  = getattr(spin, "_kwire_value_cb", None)
        cb_edit = getattr(spin, "_kwire_edit_cb", None)
        if cb_val:
            try: spin.valueChanged.disconnect(cb_val)
            except Exception: pass
        if cb_edit:
            try: spin.editingFinished.disconnect(cb_edit)
            except Exception: pass

        # New callbacks (named so it can disconnect next time)
        def _on_val(v):
            try:
                handler(cast(v), flush=False)
            except TypeError:
                handler(cast(v))  # fallback if handler has no 'flush' kw

        def _on_edit():
            try:
                handler(cast(spin.value()), flush=True)
            except TypeError:
                handler(cast(spin.value()))
        spin.valueChanged.connect(_on_val)
        spin.editingFinished.connect(_on_edit)
        # Stash refs on the widget so we can disconnect later
        spin._kwire_value_cb = _on_val
        spin._kwire_edit_cb  = _on_edit

    # ============================== 
    # --- catalog
    # ============================== 

    def export_user_catalog_encrypted(self, *args, **kwargs):
        from app.misc_ops import export_user_catalog_encrypted as _impl
        return _impl(self, *args, **kwargs)

    def import_user_catalog_encrypted(self, *args, **kwargs):
        from app.misc_ops import import_user_catalog_encrypted as _impl
        return _impl(self, *args, **kwargs)

    def on_user_logged_in(self, canonical_user: str, _users_base_ignored: str = ""):
        username = (canonical_user or "").strip()
        if not username:
            return

        user_cfg = Path(config_dir(username))              # .../Users/<user>/Config
        self._catalog_user_root = str(user_cfg)            # keep for editor & reloads

        cat_path  = Path(catalog_file(username, ensure_dir=True, name_only=False))      # .../Config/<user>.enc
        seal_path = Path(catalog_seal_file(username, ensure_dir=True, name_only=False)) # .../Config/<user>.hmac

        # Ensure catalog exists (encrypted). Some installs expect a dir; others a file path.
        try:
            ensure_user_catalog_created(cat_path, CLIENTS, ALIASES, PLATFORM_GUIDE, user_key=self.userKey)
        except TypeError:
            ensure_user_catalog_created(user_cfg, CLIENTS, ALIASES, PLATFORM_GUIDE, user_key=self.userKey)

        # Load decrypted overlay (user edits)
        try:
            overlay = load_user_catalog_raw(cat_path, self.userKey)
        except TypeError:
            overlay = load_user_catalog_raw(user_cfg, self.userKey)

        # Verify/repair HMAC seal
        ok = False
        try:
            ok = verify_hmac_seal(cat_path, overlay, self.userKey, seal_path=seal_path)
        except TypeError:
            # older signature without seal_path kwarg
            ok = verify_hmac_seal(cat_path, overlay, self.userKey)

        if not ok:
            try:
                ensure_user_catalog_created(cat_path, CLIENTS, ALIASES, PLATFORM_GUIDE, user_key=self.userKey)
            except TypeError:
                ensure_user_catalog_created(user_cfg, CLIENTS, ALIASES, PLATFORM_GUIDE, user_key=self.userKey)

            try:
                overlay = load_user_catalog_raw(cat_path, self.userKey)
            except TypeError:
                overlay = load_user_catalog_raw(user_cfg, self.userKey)

            try:
                write_hmac_seal(cat_path, overlay, self.userKey, seal_path=seal_path)
            except TypeError:
                write_hmac_seal(cat_path, overlay, self.userKey)

        # Effective view (built-ins + user overlay)
        self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE, _ = load_effective_catalogs_from_user(
            user_cfg, CLIENTS, ALIASES, PLATFORM_GUIDE, user_key=self.userKey, user_overlay=overlay
        )

    def open_catalog_editor(self):
        try:
            from catalog_category.my_catalog_builtin import (
                CLIENTS,
                ALIASES,
                PLATFORM_GUIDE,
                AUTOFILL_RECIPES,
            )
            
            uname = (self.currentUsername.text() or "").strip()
            if not uname:
                QMessageBox.warning(self, self.tr("Catalog"), self.tr("Please log in first."))
                return

            user_cfg = str(config_dir(uname))   # editor works with a root dir
            self.set_status_txt(self.tr("Opening Catalog"))

            dlg = CatalogEditorUserDialog(
                user_cfg,
                CLIENTS,
                ALIASES,
                PLATFORM_GUIDE,
                AUTOFILL_RECIPES,
                parent=self,
                user_key=self.userKey,
                username=uname,
            )

            dlg.saved.connect(lambda: self._on_catalog_saved(user_cfg))

            if dlg.exec():
                self._on_catalog_saved(user_cfg)
        except Exception as e:
            log.error(f"CatalogEditorUserDialog: {e}")

    def _on_catalog_saved(self, user_root: str):
        try:
            uname = (self.currentUsername.text() or "").strip()
            cat_path  = Path(catalog_file(uname, ensure_dir=True, name_only=False))
            seal_path = Path(catalog_seal_file(uname, ensure_dir=True, name_only=False))

            try:
                overlay = load_user_catalog_raw(cat_path, self.userKey)
            except TypeError:
                overlay = load_user_catalog_raw(Path(user_root), self.userKey)

            try:
                write_hmac_seal(cat_path, overlay, self.userKey, seal_path=seal_path)
            except TypeError:
                write_hmac_seal(cat_path, overlay, self.userKey)

            self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE, _ = load_effective_catalogs_from_user(
                Path(user_root), CLIENTS, ALIASES, PLATFORM_GUIDE, user_key=self.userKey, user_overlay=overlay
            )
        except Exception:
            pass

        for attr in ("_client_domains_cache", "_client_exec_cache", "_client_protocol_cache"):
            if hasattr(self, attr):
                setattr(self, attr, None)
        try: self._refresh_platform_help_badge()
        except Exception: pass
        try: self._toast("Catalog updated")
        except Exception: pass

    def _is_probably_user_added(self, url: str, built_value: str | None) -> bool:
        """If built-ins had a value and this one differs, treat as user-added/overridden; or new key entirely."""
        return not built_value or (built_value.strip() != (url or "").strip())

    def _maybe_warn_first_time(self, pref_key: str, title: str, message: str) -> bool:
        """
        Show a one-time warning with 'Don't show again'. Returns True to continue.
        Store the user's choice in user settings prefs.
        """
        try:
            prefs = getattr(self, "userPrefs", {}) or {}
            if prefs.get(pref_key) is True:
                return True
        except Exception:
            prefs = {}

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle(title)
        box.setText(message)
        box.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        box.button(QMessageBox.Ok).setText(self.tr("I understand"))
        chk = QCheckBox(self.tr("Don't show again"))
        box.setCheckBox(chk)
        ret = box.exec()
        if ret == QMessageBox.Ok and chk.isChecked():
            prefs[pref_key] = True
            try:
                self.userPrefs = prefs
            except Exception:
                pass
        return ret == QMessageBox.Ok

    def open_vendor_url(self, url: str, builtins_url: str | None = None) -> None:
        """Open a URL safely. If it looks user-added, show one-time warning."""
        u = (url or "").strip()
        if not u:
            QMessageBox.warning(self, self.tr("URL missing"), self.tr("There is no URL configured for this item."))
            return
        try:
            p = urlparse(u)
            if p.scheme not in ("https", "http"):
                QMessageBox.warning(self, self.tr("Blocked URL"), self.tr("Only http/https links are allowed."))
                return
        except Exception:
            QMessageBox.warning(self, self.tr("Invalid URL"), self.tr("The link appears malformed."))
            return

        # One-time warning for user-added/overridden URLs
        if self._is_probably_user_added(u, builtins_url):
            cont = self._maybe_warn_first_time(
                pref_key="suppress_user_url_warning",
                title="Custom URL — be careful",
                message=(
                    "This link was added or changed by a user.\n\n"
                    "Only open official vendor sites or trusted direct download links.\n"
                    "Malicious links can harm your device."
                )
            )
            if not cont:
                return

        QDesktopServices.openUrl(QUrl(u))

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
    # --- ontop/toast  ---
    # ==============================
    def set_topmost_no_flash(self, on: bool) -> None:
        """Toggle always-on-top without setWindowFlags() (no white flash)."""
        try:
            if sys.platform != "win32":
                # Fallback: avoid recreating unless absolutely needed
                return
            HWND_TOPMOST     = -1
            HWND_NOTOPMOST   = -2
            SWP_NOMOVE       = 0x0002
            SWP_NOSIZE       = 0x0001
            SWP_NOACTIVATE   = 0x0010
            SWP_SHOWWINDOW   = 0x0040
            hwnd = int(self.winId())
            ctypes.windll.user32.SetWindowPos(
                wintypes.HWND(hwnd),
                wintypes.HWND(HWND_TOPMOST if on else HWND_NOTOPMOST),
                0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW
            )
        except Exception as e:
            log.error(f"{kql.i('err')} error seting new on top no recreate windows {e}. Using Recreate Windows")
            self.set_always_on_top(False)

    def on_enable_ontop_toggled(self, checked: bool) -> None:
        self.set_status_txt(self.tr("Saving ontop") + f" {checked}")
        log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('info')} ontop toggled: {checked}")
        try:
            self.reset_logout_timer()
        except Exception:
            pass

        username = (self.currentUsername.text() or "").strip()
        if not username:
            log.debug(f"{kql.i('tool')} [ERROR] {kql.i('err')}  Cannot update ontop — user not found")
            return

        try:
            set_user_setting(username, "ontop", bool(checked))
            self.set_status_txt(self.tr("Saving Done, Applying"))
            self.set_always_on_top(bool(checked))
            self.set_status_txt(self.tr("Done"))
            try:
                update_baseline(username=username, verify_after=False, who=self.tr("OnTop Settings Changed"))
                self.set_status_txt(self.tr("Baseline Done"))
                log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} ontop toggled/baseline Updated")
            except Exception:
                pass
        except Exception as e:
            log.error(f"{kql.i('tool')} [ERROR] {kql.i('err')} Failed to set ontop: {e}")
    
    def _toast(self, message: str, msec: int = 2500):
        # NOTE: Temp toast, will be moving to windows 11 Notifications on windows
        try: 
            pos = self.mapToGlobal(QPoint(20, 20))
            QToolTip.showText(pos, message, self, self.rect(), msec)
        except Exception:
            pass        
    
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
        # Prefer the non-blocking implementation if available
        try:
            if hasattr(self, 'on_rebuild_portable_clicked2'):
                return self.on_rebuild_portable_clicked2()
        except Exception:
            pass

        """
        Rebuild / create the portable app on a selected USB drive.
        Runs synchronously on the UI thread to avoid Qt crashes from
        showing QMessageBox in a worker thread.
        """
        self.set_status_txt(self.tr("Updating App to USB"))

        from pathlib import Path
        from features.portable.portable_manager import pick_usb_drive, build_portable_app

        # pick drive
        drive = pick_usb_drive(self)
        if not drive:
            self.set_status_txt(self.tr("Portable rebuild cancelled"))
            return

        # simple busy dialog (no threads, just pumps events)
        dlg = QProgressDialog(self)
        dlg.setWindowTitle(self.tr("Rebuilding Portable"))
        dlg.setLabelText("Preparing portable app…")
        dlg.setRange(0, 0)  # busy indicator
        dlg.setWindowModality(Qt.WindowModal)
        dlg.setCancelButton(None)
        dlg.show()
        QApplication.processEvents()

        try:
            ok = build_portable_app(self, Path(drive))
        except Exception as e:
            ok = False
            log = kql  
            log.error(f"[PORTABLE] build_portable_app failed: {e}")
        finally:
            try:
                dlg.close()
            except Exception:
                pass

        if ok:
            QMessageBox.information(
                self, self.tr("Portable Rebuild"),
                self.tr("Portable app updated successfully.")
            )
            self.set_status_txt(self.tr("Portable app updated."))
        else:
            QMessageBox.critical(
                self, self.tr("Portable Rebuild Failed"),
                self.tr("Portable rebuild failed. Please check the log for details.")
            )
            self.set_status_txt(self.tr("Portable rebuild failed"))

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
    # helper to stop crease on rapid change
    # ==============================

    def _ensure_debounce_store(self):
        if not hasattr(self, "_debounce_timers"):
            self._debounce_timers: dict[str, "QTimer"] = {}
            self._debounce_values: dict[str, object] = {}
            self._debounce_last_saved: dict[str, object] = {}

    def _debounce_setting(self, *args, **kwargs):
        from ui.settings_ops import _debounce_setting as _impl
        return _impl(self, *args, **kwargs)

    def _queue_setting_save(self, key: str, value: float, commit_fn, *, delay_ms: int = 700, flush: bool = False):
        """
        Debounce saves per 'key'. If flush=True, commit immediately.
        commit_fn(value) should raise on failure (we swallow & log).
        """
        self._pending_values[key] = value

        # immediate commit requested (editingFinished / Enter)
        if flush:
            # cancel any pending timer
            t = self._debouncers.get(key)
            if t:
                try: t.stop()
                except Exception: pass
            # don't re-save the same value
            if self._last_saved.get(key) == value:
                return
            try:
                commit_fn(value)
                self._last_saved[key] = value
            except Exception as e:
                log.error("save(%s) failed: %s", key, e)
            return

        # lazy: schedule (coalesces rapid changes)
        t = self._debouncers.get(key)
        if not t:
            t = QTimer(self)
            t.setSingleShot(True)
            self._debouncers[key] = t

            def _fire():
                v = self._pending_values.get(key)
                if v is None:  # nothing pending
                    return
                if self._last_saved.get(key) == v:  # unchanged
                    return
                try:
                    commit_fn(v)
                    self._last_saved[key] = v
                except Exception as e:
                    log.error("debounced save(%s) failed: %s", key, e)

            t.timeout.connect(_fire)

        try:
            t.stop()
        except Exception:
            pass
        t.start(delay_ms)

    # ==============================
    # --- preflight/AV enable/disable
    # ==============================
    def on_enable_preflight_toggled(self, checked: bool):
        self.set_status_txt(self.tr("Saving Preflight change") + f" {checked}")
        self.reset_logout_timer()
        log.debug("%s [TOOLS] %s preflight toggled -> %s", kql.i('tool'), kql.i('ok'), checked)

        # support two independent toggles in the UI:
        # - enablePreflightCheckbox   : per-user (runs after username is entered, before unlocking)
        # - enablePreflightCheckbox_2 : global (runs on app startup)
        try:
            sender = self.sender()
            sender_name = sender.objectName() if sender else ""
        except Exception:
            sender_name = ""
        is_startup_toggle = str(sender_name).endswith("_2")

        username = self._active_username()
        if not username and not is_startup_toggle:
            QMessageBox.information(self, self.tr("Preflight"), self.tr("Please enter or select a user first."))
            return

        try:
            target = None if is_startup_toggle else username
            prefs = load_security_prefs(target) or {}
            if is_startup_toggle:
                prefs["enable_preflight_startup"] = bool(checked)
            else:
                prefs["enable_preflight_login"] = bool(checked)
            prefs["enable_preflight"] = bool(checked)
            prefs["preflight_prompted"] = True
            save_security_prefs(prefs, target)
            log.debug("%s [TOOLS] %s Updated preflight toggled for %s", kql.i('tool'), kql.i('ok'), username)
            try:
                update_baseline(username=username, verify_after=False, who=self.tr("Preflight Settings Changed"))
            except Exception:
                pass
        except Exception as e:
            log.error("%s [ERROR] %s Could not update setting: %s", kql.i('tool'), kql.i('err'), e)
            QMessageBox.warning(self, self.tr("Preflight"), self.tr("Could not update setting:\n{err}").format(err=e))

    def on_enable_WinDefCheckbox_toggled(self, checked: bool) -> None:
        self.set_status_txt(self.tr("Saving Windows def") + " {checked}")
        log.debug("%s [TOOLS] %s WinDef Scan toggled %s", kql.i('tool'), kql.i('ok'), checked)

        # Two independent toggles:
        # - enableWinDefCheckbox_  : per-user (login)
        # - enableWinDefCheckbox_2 : global (startup)
        try:
            sender = self.sender()
            sender_name = sender.objectName() if sender else ""
        except Exception:
            sender_name = ""
        is_startup_toggle = str(sender_name).endswith("_2")

        try:
            sender = self.sender()
        except Exception:
            sender = None
        try:
            self.enforce_pro_feature(sender, "Windows Defender Scan")
        except Exception:
            pass

        try:
            self.reset_logout_timer()
        except Exception:
            pass

        username = self._active_username()
        if not username and not is_startup_toggle:
            log.debug("%s [WARN] %s Cannot update AV setting — user not found",
                      kql.i('tool'), kql.i('warn'))
            return

        try:
            # Persist in security prefs so it can be honored pre-login.
            target = None if is_startup_toggle else username
            prefs = load_security_prefs(target) or {}
            if is_startup_toggle:
                prefs["check_av_startup"] = bool(checked)
            else:
                prefs["check_av_login"] = bool(checked)
            prefs["check_av"] = bool(checked)  # back-compat
            save_security_prefs(prefs, target)

            # Back-compat: keep user_db flags (older builds may read these)
            if not is_startup_toggle and username:
                set_user_setting(username, "WinDefCheckbox", bool(checked))
                set_user_setting(username, "av_prompt_on_login", bool(checked))
            try:
                update_baseline(username=username, verify_after=False, who=self.tr("Win_Def Settings Changed"))
                log.debug("%s [TOOLS] %s WinDef Scan Set:%s / baseline updated",
                          kql.i('tool'), kql.i('ok'), checked)
            except Exception:
                pass
        except Exception as e:
            log.error("%s [ERROR] %s Failed to set WinDefCheckbox: %s",
                      kql.i('tool'), kql.i('err'), e)

    def on_enable_DefenderQuickScan_toggled(self, checked: bool) -> None:
        self.set_status_txt(self.tr("Saving Defender Change"))
        log.debug("%s [TOOLS] %s DefenderQuickScan toggled: %s",
                  kql.i('tool'), kql.i('ok'), checked)

        # Two independent toggles:
        # - DefenderQuickScan_  : per-user (login)
        # - DefenderQuickScan_2 : global (startup)
        try:
            sender = self.sender()
            sender_name = sender.objectName() if sender else ""
        except Exception:
            sender_name = ""
        is_startup_toggle = str(sender_name).endswith("_2")

        try:
            self.reset_logout_timer()
        except Exception:
            pass

        username = self._active_username()
        if not username and not is_startup_toggle:
            log.debug("%s [WARN] %s Cannot update DefenderQuickScan — user not found",
                      kql.i('tool'), kql.i('warn'))
            return

        try:
            target = None if is_startup_toggle else username
            prefs = load_security_prefs(target) or {}
            if is_startup_toggle:
                prefs["defender_quick_scan_startup"] = bool(checked)
            else:
                prefs["defender_quick_scan_login"] = bool(checked)
            prefs["defender_quick_scan"] = bool(checked)  # back-compat
            save_security_prefs(prefs, target)

            # Back-compat for older builds
            if not is_startup_toggle and username:
                set_user_setting(username, "DefenderQuickScan", bool(checked))
            try:
                update_baseline(username=username, verify_after=False, who=self.tr("Quick Scan Settings Changed"))
                log.debug("%s [TOOLS] %s DefenderQuickScan / baseline updated",
                          kql.i('tool'), kql.i('ok'))
            except Exception:
                pass
        except Exception as e:
            log.error("%s [ERROR] %s Failed to set DefenderQuickScan: %s",
                      kql.i('tool'), kql.i('err'), e)

    def on_run_preflight_now_clicked(self, *args, **kwargs):
        from app.misc_ops import on_run_preflight_now_clicked as _impl
        return _impl(self, *args, **kwargs)

    def on_autosync_clicked(self, checked: bool) -> None:
        self.set_status_txt(self.tr("Auto Sync to users Cloud"))
        username = self._active_username()
        if not username or not getattr(self, "userKey", None):
            return

        prof = get_user_cloud(username) or {}

        # Store user preference (recommended)
        try:
            set_user_setting(username, "auto_sync", bool(checked))
        except Exception:
            pass

        # Mirror to cloud profile
        set_user_cloud(
            username=username,
            enable=bool(prof.get("enabled")), 
            provider=(prof.get("provider") or "localpath"),
            path=(prof.get("remote_path") or ""),
            wrap=bool(prof.get("cloud_wrap")),
            sync_enable=bool(checked),
        )

        # Keep checkbox in sync without re-triggering
        try:
            self.autosync_.blockSignals(True)
            self.autosync_.setChecked(bool(checked))
            self.autosync_.blockSignals(False)
        except Exception:
            pass

        # Ensure engine exists & configured, then optionally kick a silent sync
        try:
            if not hasattr(self, "sync_engine") or self.sync_engine is None:
                self._configure_sync_engine(username)
            if self.sync_engine and self.sync_engine.configured() and checked:
                self.sync_engine.sync_now(self.userKey, interactive=False)
                self._watch_local_vault()

            elif not checked and hasattr(self, "_vault_watcher") and self._vault_watcher:
                self._vault_watcher.deleteLater()
                self._vault_watcher = None
            update_baseline(username=username, verify_after=False, who=self.tr("Cloud Sync Settings Changed"))

        except Exception as e:
            if "Sync not configured" in str(e):
                QMessageBox.information(
                        self, self.tr("Sync"),
                        self.tr("Cloud Sync not enabled goto Backup/Restore -> Move To Cloud to Enable"))
                self.autosync_.setChecked(False)
            else:
                log.debug(f"[AUTO-SYNC] setup failed: {e}")
        self.set_status_txt(self.tr("Done"))

    # ==============================
    # --- Password expiry days (int)
    # ==============================
    def on_password_expiry_days_change(self, value: int | float, *, flush: bool = False) -> None:
        self.set_status_txt(self.tr("Saving Password Expiry Change"))
        v = int(round(value))
        log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} on_password_expiry_days_change -> {v}")
        self.reset_logout_timer()

        username = (self.currentUsername.text() or "").strip()
        if not username:
            log.debug(f"{kql.i('tool')} [WARN] {kql.i('warn')} no user for expiry update")
            return

        self.expiry_days = v  # live apply

        def _persist(val: int):
            try:
                set_user_setting(username, "password_expiry_days", int(val))
                try: 
                    update_baseline(username=username, verify_after=False, who=self.tr("Password Expiry Settings Changed"))
                except Exception: pass
                log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} expiry saved {val}")
            except Exception as e:
                log.error(f"{kql.i('tool')} [ERROR] {kql.i('err')} expiry save failed: {e}")

        self._debounce_setting("password_expiry_days", v, 2000, _persist, flush=flush)
        self.set_status_txt(self.tr("Done"))

    # ==============================
    # Lockout threshold (int)
    # ==============================
    def on_lockout_threshold_changed(self, value: int | float, *, flush: bool = False) -> None:
        v = int(round(value))
        if v < 0: v = 0
        log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} lockout threshold -> {v}")
        self.reset_logout_timer()
        
        username = (self.currentUsername.text() or "").strip()
        if not username:
            log.debug(f"{kql.i('tool')} {kql.i('warn')} no user for lockout update")
            return

        def _persist(val: int):
            try:
                set_user_setting(username, "lockout_threshold", int(val))
                try: 
                    update_baseline(username=username, verify_after=False, who=self.tr("Lockout Settings Changed"))
                except Exception: pass
                log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} lockout saved {val}")
            except Exception as e:
                log.error(f"{kql.i('tool')} [ERROR] {kql.i('err')} lockout save failed: {e}")

        self._debounce_setting("lockout_threshold", v, 2000, _persist, flush=flush)

    # ==============================
    # Clipboard clear timeout (seconds, int)
    # ==============================
    def on_clipboard_clear_timeout_sec_change(self, value: int | float, *, flush: bool = False) -> None:
        self.set_status_txt(self.tr("Clipboard timeout changed"))
        v = int(round(value))
        if v < 0: v = 0
        log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} clipboard timeout -> {v}s")
        self.reset_logout_timer()

        username = (self.currentUsername.text() or "").strip()
        if not username:
            log.debug(f"{kql.i('tool')} {kql.i('warn')} no user for clipboard update")
            return

        # live apply
        try:
            self.clipboard_timeout = v * 1000
            install_clipboard_guard(self.clipboard_timeout)
        except Exception:
            pass

        def _persist(val: int):
            try:
                set_user_setting(username, "clipboard_clear_timeout_sec", int(val))
                try: 
                    update_baseline(username=username, verify_after=False, who=self.tr("Clipboard Timeout Settings Changed"))
                except Exception: pass
                log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} clipboard saved {val}")
            except Exception as e:
                log.error(f"{kql.i('tool')} [ERROR] {kql.i('err')} clipboard save failed: {e}")

        self._debounce_setting("clipboard_clear_timeout_sec", v, 2000, _persist, flush=flush)


    # ==============================
    # Auto logout timeout (seconds, int) — 0 = OFF
    # ==============================
    def on_auto_logout_timeout_sec_change(self, value: int | float, *, flush: bool = False) -> None:
        v = int(round(value))
        if v < 0: v = 0
        log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} auto-logout -> {v}s")
        self.reset_logout_timer()

        username = (self.currentUsername.text() or "").strip()
        if not username:
            log.debug(f"{kql.i('tool')} {kql.i('warn')} no user for auto-logout update")
            return

        self.logout_timeout = 0 if v == 0 else v * 1000
        try: self.setup_auto_logout()
        except Exception: pass

        def _persist(val: int):
            try:
                set_user_setting(username, "auto_logout_timeout_sec", int(val))
                try: 
                    update_baseline(username=username, verify_after=False, who=self.tr("Auto Logout Settings Changed"))
                except Exception: pass
                log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} auto-logout saved {val}")
            except Exception as e:
                log.error(f"{kql.i('tool')} [ERROR] {kql.i('err')} auto-logout save failed: {e}")

        self._debounce_setting("auto_logout_timeout_sec", v, 2000, _persist, flush=flush)


    def enable_debug_logging_change(self, checked: bool) -> None:
        self.set_status_txt(self.tr("saving logging set") + f" {checked}")
        log.debug("%s [TOOLS] %s enable_debug_logging_change(%s)",
                  kql.i('tool'), kql.i('ok'), checked)

        # Apply runtime logging mode (console in dev only)
        apply_debug_flag(bool(checked), keep_console=is_dev)

        # Programmatic changes (during logout) set this flag to suppress popups
        if getattr(self, "_suppress_logging_toasts", False):
            return

        # Persist per-user if theres a username
        try:
            username = (self.currentUsername.text() or "").strip()
        except Exception:
            username = ""

        if username:
            try:
                set_user_setting(username, "debug_set", bool(checked))
                self.set_status_txt(self.tr("Saving Done, Applying"))
                self.debug_set = bool(checked)
                update_baseline(username=username, verify_after=False, who=self.tr("Debug Settings Changed"))
            except Exception as e:
                log.warning("%s [TOOLS] %s Failed to persist debug setting: %s",
                            kql.i('tool'), kql.i('warn'), e)

        # Show user-facing info only for manual toggles
        try:
            if checked:
                QMessageBox.information(
                    self, self.tr("Logging"),
                    self.tr("Debug logging is ON.\n\nLog file:\n") + f"{get_logfile_path()}"
                )
            else:
                self.set_status_txt(self.tr("Logging is now minimized.\nNo log file will be written"))
        except Exception:
            pass

    # ==============================
    # --- breach checker
    # ==============================

    def enable_breach_checker_change(self, *args, **kwargs):
        from features.security_center.security_center_ops import enable_breach_checker_change as _impl
        return _impl(self, *args, **kwargs)

    def _show_hibp_consent_modal(self) -> bool:
        """
        Show a one-time consent explaining the HIBP 'range' API (k-anonymity).
        Returns True if the user accepts (Enable), False if Cancel.
        """
        # use configured help/privacy URLs; fall back to sensible defaults.
        help_url = getattr(self, "SITE_HELP", SITE_HELP)
        privacy_url = PRIVACY_POLICY

        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle(self.tr("Password breach check"))
        msg.setTextFormat(Qt.RichText)
        msg.setText(self.tr(
            "<b>Password breach check</b><br>"
            "When enabled, the app checks passwords using the Have I Been Pwned “range” API.<br>"
            "We send <b>only the first 5 characters of a SHA-1 hash</b>—"
            "<b>never your password</b> or the full hash.<br><br>"
            "<a href='{help_url}'>Learn more</a> · "
            "<a href='{privacy_url}'>Privacy Policy</a>"
        ).format(
            help_url=help_url,
            privacy_url=privacy_url
        ))

        # Buttons: Enable / Cancel
        enable_btn = msg.addButton("Enable", QMessageBox.AcceptRole)
        cancel_btn = msg.addButton(self.tr("Cancel"), QMessageBox.RejectRole)
        # Exec (Qt5/6 compatible)
        res = msg.exec_() if hasattr(msg, "exec_") else msg.exec()
        return msg.clickedButton() is enable_btn

    # ==============================
    # --- watchtower rescan 
    # ==============================
    def _watchtower_rescan(self):
        """
        Trigger Watchtower rescan (legacy-safe).
        """
        wt = getattr(self, "watchtower", None)
        if wt and hasattr(wt, "start_scan"):
            wt.start_scan()

    # ==============================
    # --- zoom user profile pic value change
    # ==============================

    def auto_zoom_factor(self, value: float, *, flush: bool = False) -> None:
        log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} zoom -> {value}")
        self.reset_logout_timer()

        try:
            self.zoom_factor = float(value)
            # force a re-render so the new zoom is applied immediately
            self.load_profile_picture(force=True)
        except Exception:
            pass

        def _persist(v):
            try:
                username = (self._current_username_text() or "").strip()
                set_user_setting(username, "zoom_factor", float(v))
                try:
                    update_baseline(username=username, verify_after=False, who=self.tr("Zoom Pic Settings Changed"))
                except Exception:
                    pass
                log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} zoom saved {v}")
            except Exception as e:
                log.error(f"{kql.i('tool')} [ERROR] {kql.i('err')} zoom save failed: {e}")

        self._debounce_setting("zoom_factor", value, 2000, _persist, flush=flush)

    # ==============================
    # --- two 2fa enable/disable 
    # ==============================
    # ---------------- Manual Emergency Kit input (no persistence) ----------------
    def prompt_manual_kit_entries(self, *args, **kwargs):
        from app.misc_ops import prompt_manual_kit_entries as _impl
        return _impl(self, *args, **kwargs)

    def emg_ask(self, *args, **kwargs):
        from app.misc_ops import emg_ask as _impl
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
    
    def _active_username(self) -> str:
        """Best-effort active username for reading user_db."""
        try:
            if hasattr(self, "currentUsername") and callable(getattr(self.currentUsername, "text", None)):
                u = (self.currentUsername.text() or "").strip()
                if u:
                    return u
        except Exception:
            pass

        # Fallbacks: plain attributes that may be set earlier in startup
        for attr in ("currentUsername", "currentUser", "username", "activeUser"):
            try:
                v = getattr(self, attr, "")
                if isinstance(v, str) and v.strip():
                    return v.strip()
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
                raw_name = (self.currentUsername.text() or "").strip()

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
        from vault_store.vault_ui_ops import user_field_meta_for_category as _impl
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
        from app.misc_ops import show_qr_for_selected as _impl
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
        from app.misc_ops import _on_editor_schema_saved as _impl
        return _impl(self, *args, **kwargs)

    def set_rounded_profile_picture(self, *args, **kwargs):
        from app.misc_ops import set_rounded_profile_picture as _impl
        return _impl(self, *args, **kwargs)

    # --- change user profile pic ask user to select and update image after

    def change_profile_picture(self) -> None:
        """Let the logged-in user pick a picture and save it under Config/Profile."""
        self.reset_logout_timer()
        username = (self.currentUsername.text() or "").strip()
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


    # ---------- login picture (login screen) ----------

    def update_login_picture(self, *args, **kwargs):
        from auth.login.auth_flow_ops import update_login_picture as _impl
        return _impl(self, *args, **kwargs)

    def load_profile_picture(self, *args, **kwargs):
        from app.misc_ops import load_profile_picture as _impl
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
    
    # --- preflight popup to user
    def maybe_prompt_enable_preflight(self, parent=None):
        prefs = load_security_prefs()
        if prefs.get("preflight_prompted", False):
            return

        box = QMessageBox(parent or self)
        box.setWindowTitle(self.tr("Security Preflight"))
        box.setIcon(QMessageBox.Icon.Question)
        box.setText(self.tr("Enable Security Preflight checks?"))
        box.setInformativeText(
            "Preflight can warn you about packet sniffers, debuggers, and other tools "
            "that increase risk. You can change this later in Settings."
        )
        enable_btn = box.addButton(self.tr("Enable (Recommended)"), QMessageBox.ButtonRole.AcceptRole)
        later_btn  = box.addButton(self.tr("Not Now"), QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(enable_btn)
        box.exec()

        prefs["preflight_prompted"] = True
        prefs["enable_preflight"] = (box.clickedButton() is enable_btn)
        save_security_prefs(prefs)

    def _load_user_preflight_overrides(self, username: str) -> dict:
        user = username
        # Login-time prefs are stored per-user in the *.sp file.
        user_sp = load_security_prefs(user) or {}
        enable_preflight = bool(
            user_sp.get("enable_preflight_login",
                        user_sp.get("enable_preflight", True))
        )
        # Master AV toggle (login)
        if "check_av_login" in user_sp:
            av_enabled = bool(user_sp.get("check_av_login", False))
        elif "check_av" in user_sp:
            av_enabled = bool(user_sp.get("check_av", False))
        else:
            try:
                av_enabled = bool(get_user_setting(user, "WinDefCheckbox", False))
            except TypeError:
                av_enabled = bool(get_user_setting(user, "WinDefCheckbox"))

        # quick-scan (login)
        if "defender_quick_scan_login" in user_sp:
            quick_scan = bool(user_sp.get("defender_quick_scan_login", False))
        elif "defender_quick_scan" in user_sp:
            quick_scan = bool(user_sp.get("defender_quick_scan", False))
        else:
            try:
                quick_scan = bool(get_user_setting(user, "DefenderQuickScan", False))
            except TypeError:
                quick_scan = bool(get_user_setting(user, "DefenderQuickScan"))
        try:
            vendor_prompt = bool(get_user_setting(user, "av_prompt_on_login", True))
        except TypeError:
            vendor_prompt = bool(get_user_setting(user, "av_prompt_on_login"))

        # If master is off, force all AV prompts off
        if not av_enabled:
            quick_scan = False
            vendor_prompt = False

        return {
            "enable_preflight": enable_preflight,
            "check_av": av_enabled,
            "defender_quick_scan": quick_scan,
            "offer_vendor_ui_on_login": vendor_prompt,
            "block_on_av_absent": True,
            "block_on_scan_issue": True,
            "debug": True,
        }


    # ------------------------
    # --- Audit and Lockout Management
   
    def load_audit_table(self, *args, **kwargs):
        from app.misc_ops import load_audit_table as _impl
        return _impl(self, *args, **kwargs)

    def delete_audit_logs(self, *args, **kwargs):
        from app.misc_ops import delete_audit_logs as _impl
        return _impl(self, *args, **kwargs)

    def on_export_audit_clicked(self, *args, **kwargs):
        from app.misc_ops import on_export_audit_clicked as _impl
        return _impl(self, *args, **kwargs)

    # ==============================
    # --- export/import/back up ---
    # ==============================
    
    # ==============================
    # --- export/import vault data (not full back) ------------------
    
    def export_vault_with_password(self, *args, **kwargs):
        from vault_store.vault_ui_ops import export_vault_with_password as _impl
        return _impl(self, *args, **kwargs)

    def import_vault_with_password(self, *args, **kwargs):
        from vault_store.vault_ui_ops import import_vault_with_password as _impl
        return _impl(self, *args, **kwargs)

    def backup_software_folder(self):
        self.reset_logout_timer()
        source_dir = os.path.join("app", "software")
        if not os.path.exists(source_dir):
            QMessageBox.information(self, self.tr("Software Backup"), self.tr("No software folder found to back up."))
            return

        timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = os.path.join("software_backups")
        os.makedirs(backup_dir, exist_ok=True)
        zip_path = os.path.join(backup_dir, f"software_backup_{timestamp}.zip")

        with ZipFile(zip_path, 'w') as zipf:
            for root, _, files in os.walk(source_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, start=source_dir)
                    zipf.write(full_path, arcname=arcname)
        msg = self.tr("{ok} Software folder backedup").format(ok=kql.i('ok'))
        log_event_encrypted(self.currentUsername.text(), self.tr("soft backed up"), msg)
        msg = self.tr("{ok} Software folder backed up to:\n{zip_p}").format(ok=kql.i('ok'), zip_p=zip_path)
        QMessageBox.information(self, self.tr("Software Backup"), msg)

    def restore_software_folder(self):
        self.reset_logout_timer()
        zip_path, _ = QFileDialog.getOpenFileName(self, self.tr("Select Software Backup"), "", "ZIP Files (*.zip)")
        if not zip_path:
            return

        restore_dir = os.path.join("app", "software")
        os.makedirs(restore_dir, exist_ok=True)

        # Optionally clear existing files
        confirm = QMessageBox.question(self, self.tr("Restore Software Folder"), self.tr("This will overwrite existing files. Continue?"))
        if confirm != QMessageBox.StandardButton.Yes:
            return
        self.reset_logout_timer()
        rmtree(restore_dir)
        os.makedirs(restore_dir, exist_ok=True)

        with ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(restore_dir)
        update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Soft Restored"))
        QMessageBox.information(self, self.tr("Software Restore"), self.tr("✅ Software folder restored successfully."))

    # ==============================
    # --- Full backup/export (vault + salt + user_db + wrapped_key if present)
    # ==============================

    # --- export/import vault + user_data + settings (full backup) 

    def export_vault(self):
        self.set_status_txt(self.tr("Exporting Vault"))
        """
        UI wrapper around auth.vault_store.export_full_backup.
        Exports a .zip.enc (encrypted with the account password) into a chosen folder.
        """
        self.reset_logout_timer()
        username = self.currentUsername.text().strip()
        if not username:
            self.safe_messagebox_warning(self, "Export", "Please log in before exporting.")
            return

        # Ask for account password to encrypt the backup
        pw, ok = QInputDialog.getText(
            self, self.tr("Confirm Password"),
            self.tr("Enter your account password:"),
            QLineEdit.EchoMode.Password
        )
        if not ok or not pw:
            return

        if not validate_login(username, pw):
            msg = "❌" + self.tr(" Wrong Password")
            QMessageBox.information(self, self.tr("Full Backup"), msg)
            msg = self.tr("{ok} Wrong Password").format(ok=kql.i('warn'))
            log_event_encrypted(self.currentUsername.text(), self.tr("Full Backup"), msg)
            return
        msg = self.tr("{ok} Password OK").format(ok=kql.i('ok'))
        log_event_encrypted(self.currentUsername.text(), self.tr("Full Backup"), msg)

        # Let the user choose a destination folder (export function expects a directory)
        out_dir = QFileDialog.getExistingDirectory(self, self.tr("Choose folder for backup"))
        if not out_dir:
            return

        self.reset_logout_timer()
        try:
            # NOTE: export_full_backup(username, [password], out_dir)
            written = export_full_backup(username, pw, out_dir)  # returns str path to the created file
            msg = self.tr("{ok} Full Backup OK").format(ok=kql.i('ok'))
            log_event_encrypted(self.currentUsername.text(), self.tr("Full Backup"), msg)
            self.full_backup_reminder.note_full_backup_done()

             # Record when this full backup was done (for Security Center)
            try:
                self._update_backup_timestamp(username, "last_full_backup")
            except Exception:
                pass
            msg = self.tr("{ok} Full backup saved:\n{writ}").format(ok=kql.i('ok'),writ=written)
            QMessageBox.information(self, self.tr("Export"), msg)
        except Exception as e:
            msg = self.tr("{ok} Export failed:\n{err}").format(ok=kql.i('err'), err=e)
            QMessageBox.critical(self, self.tr("Export Failed"), msg)

    def _ensure_user_dirs(self, username: str) -> None:
        """
        Make sure the per-user folder tree exists so imports can write files safely.
        """
        from app.paths import (
            ensure_dirs,
            vault_file, salt_file, vault_wrapped_file, shared_key_file,
            identities_file, user_db_file,
        )

        try:
            ensure_dirs()
        except Exception:
            pass

        targets = [
            Path(vault_file(username, ensure_parent=True)),
            Path(vault_wrapped_file(username, ensure_parent=True, name_only=False)),
            Path(salt_file(username, ensure_parent=True, name_only=False)),
            Path(shared_key_file(username, ensure_parent=True, name_only=False)),
            Path(identities_file(username, ensure_parent=True)),  # …/Users/<u>/identities/<u>.data
            Path(user_db_file(username, ensure_parent=True)),     # per-user JSON
        ]
        for p in targets:
            p.parent.mkdir(parents=True, exist_ok=True)

    def import_vault(self, *args, **kwargs):
        from vault_store.vault_ui_ops import import_vault as _impl
        return _impl(self, *args, **kwargs)

    def import_vault_custom(self, *args, **kwargs):
        from vault_store.vault_ui_ops import import_vault_custom as _impl
        return _impl(self, *args, **kwargs)

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
            uname = (self.currentUsername.text() or "").strip()
            canonical = (self.currentUsername.text() or "").strip()
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

    def import_csv_entries(self, *args, **kwargs):
        from app.misc_ops import import_csv_entries as _impl
        return _impl(self, *args, **kwargs)

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
            if not username or not getattr(self, "userKey", None):
                return []

            entries = load_vault(username, self.userKey) or []
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

    def export_csv(self, *args, **kwargs):
        from app.misc_ops import export_csv as _impl
        return _impl(self, *args, **kwargs)

    def _auth_export_safe(self, *args, **kwargs):
        from auth.login.auth_flow_ops import _auth_export_safe as _impl
        return _impl(self, *args, **kwargs)

    def _auth_import_safe(self, *args, **kwargs):
        from auth.login.auth_flow_ops import _auth_import_safe as _impl
        return _impl(self, *args, **kwargs)

    def check_selected_email_breach(self):
        self.reset_logout_timer()
        log.debug(str("[DEFULT] check_selected_email_breach started"))

        try:
            selected = self.vaultTable.currentRow()
            if selected < 0:
                return

            email_col = self.get_column_index("Email")
            if email_col is None:
                return

            item = self.vaultTable.item(selected, email_col)
            if item:
                self.open_hibp_for_email(item.text().strip())
        except Exception as e:
            log.error(str(f"[DEBUG] check_selected_email_breach error: {e}"))

    # ==============================
    # --- open password breach dulog (user can enter password)

    def open_password_breach_checker(self):
        """Open the password breach checker dialog from the Vault tab."""
        try:
            try:
                self.reset_logout_timer()
            except Exception:
                pass

            dlg = BreachCheckDialog(parent=self)
            dlg.setModal(False)  # run as utility tool
            dlg.show()

            # keep alive
            self._breachDlg = dlg

        except Exception as e:
            log.error(str(f"[DEBUG] Failed to open breach checker dialog: {e}"))
   
    # ==============================
    # --- used in check_selected_email_breach check if been porned site
    def open_hibp_for_email(self, email: str) -> None:
        """
        Open HaveIBeenPwned email breach lookup in the user's browser.
        On first use, show a one-time consent because this sends an *email address* to a third-party service.
        After accepting (with "Don't ask again"), we won't prompt again.
        """

        self.reset_logout_timer()
        log.debug("[DEBUG] open_hibp_for_email started")

        email = (email or "").strip()
        if not email or "@" not in email:
            log.debug("[WARN] Email breach check aborted — invalid or empty email.")
            return

        # Resolve active user for settings persistence
        try:
            username = (self.currentUsername.text() or "").strip()
        except Exception:
            username = None

        # Read the “don’t ask again” flag
        email_ack = False
        if username:
            try:
                email_ack = bool(get_user_setting(username, "email_check_ack"))
            except Exception:
                email_ack = False

        # If not previously acknowledged, show a one-time consent
        if not email_ack:
            accepted, dont_ask = self._show_email_check_modal()
            if not accepted:
                log.debug("[INFO] Email breach check cancelled by user.")
                return
            # Persist "don't ask again" if requested
            if username and dont_ask:
                try:
                    set_user_setting(username, "email_check_ack", True)
                except Exception as e:
                    log.debug(f"[WARN] Could not persist email_check_ack: {e}")

        # Launch HIBP (URL-escaped)
        try:
            safe_email = quote(email)
            pnwed_url(t="em", item=safe_email)
        except Exception as e:
            log.error(f"[DEBUG] Error opening browser: {e}")

    def _show_email_check_modal(self) -> tuple[bool, bool]:
        """
        One-time confirmation for sending an email address to a third-party (HIBP).
        Returns (accepted: bool, dont_ask_again: bool).
        """

        help_url = getattr(self, "SITE_HELP", SITE_HELP)
        privacy_url = PRIVACY_POLICY

        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle(self.tr("Check email for known breaches"))
        msg.setTextFormat(Qt.RichText)
        msg.setText(
            self.tr(
                "<b>Email breach lookup</b><br>"
                "This action sends the <b>email address you choose</b> to "
                "Have I Been Pwned to look up known breaches.<br>"
                "Your vault is not uploaded.<br><br>"
                "<a href='{help_url}'>Learn more</a> · "
                "<a href='{privacy_url}'>Privacy Policy</a>"
            ).format(help_url=help_url, privacy_url=privacy_url)
        )

        # "Don't ask me again" checkbox
        dont_ask_box = QCheckBox(self.tr("Don't ask me again"))
        msg.setCheckBox(dont_ask_box)

        cont_btn = msg.addButton(self.tr("Continue"), QMessageBox.AcceptRole)
        cancel_btn = msg.addButton(self.tr("Cancel"), QMessageBox.RejectRole)

        res = msg.exec_() if hasattr(msg, "exec_") else msg.exec()
        accepted = (msg.clickedButton() is cont_btn)
        return accepted, bool(dont_ask_box.isChecked())

    # ==============================
    # --- other
    # ==============================

    # --- clear passwordless
    def clear_passwordless_unlock_on_this_device(self):
        """Disable DPAPI device unlock for the current Windows account."""
        username = (self.currentUsername.text() or "").strip()
        if not username:
            QMessageBox.information(
                self,
                self.tr("No user"),
                self.tr("No active user to clear passwordless unlock for."),
            )
            return

        confirm = QMessageBox.warning(
            self,
            self.tr("Disable passwordless unlock"),
            self.tr(
                "This will disable passwordless (DPAPI) unlock for this user "
                "on THIS Windows account.\n\n"
                "You will need your full password next time.\n\n"
                "Continue?"
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if confirm != QMessageBox.Yes:
            return

        try:
            from auth.login.login_handler import get_user_record, set_user_record

            rec = get_user_record(username) or {}
            du = rec.get("device_unlock") or {}

            # Clear sensitive fields but keep audit metadata
            du.pop("wrapped_b64", None)
            du.pop("entropy_b64", None)
            du["enabled"] = False

            rec["device_unlock"] = du
            set_user_record(username, rec)

            QMessageBox.information(
                self,
                self.tr("Passwordless unlock cleared"),
                self.tr("Passwordless unlock has been disabled for this device."),
            )

        except Exception as e:
            log.exception("[LOGIN] failed clearing passwordless unlock")
            QMessageBox.critical(
                self,
                self.tr("Error"),
                self.tr("Failed to clear passwordless unlock:\n") + str(e),
            )

    # --- clear usernames
    def clear_remembered_username(self):
        resp = QMessageBox.question(
            self,
            self.tr("Clear remembered username"),
            self.tr("Remove the remembered username from this device?"),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if resp != QMessageBox.Yes:
            return

        try:
            s = QSettings("AJHSoftware", "KeyquorumVault")
            s.remove("login/remembered_username")
            s.sync()
        except Exception:
            pass

        #  update UI immediately
        try:
            self.usernameField.clear()
            if getattr(self, "remember_username", None):
                self.remember_username.setChecked(False)
        except Exception:
            pass

        QMessageBox.information(
            self,
            self.tr("Cleared"),
            self.tr("Remembered username cleared for this device."),
        )

    # --- Logging 
    def enable_debug_logging_change(self, checked: bool):
        """
        Connected to self.debug_set_.toggled in your UI wiring.
        When ON: start DEBUG logging to rotating file (and console if KQ_CONSOLE=1).
        When OFF: remove handlers and set level WARNING so nothing gets written.
        """
        try:
            apply_debug_flag(bool(checked))
            if checked:
                try:
                    msg = self.tr("Debug logging is ON.\n\nLog file:\n{logfile_p}").format(logfile_p=get_logfile_path())
                    QMessageBox.information(self, self.tr("Logging"), msg)
                except Exception:
                    pass
            else:
                try:
                    self.set_status_txt(self.tr("Logging is now minimized.\nNo log file will be written"))
                except Exception:
                    pass
        except Exception as e:
            try:
                QMessageBox.warning(self, self.tr("Logging"), self.tr("Failed to apply logging setting:\n") + f"{e}")
            except Exception:
                pass

    # --- Allways on top
    def set_always_on_top(self, enabled: bool):
        """
        Enable/disable always-on-top window behavior.
        """
        flags = self.windowFlags()
        if enabled:
            # add the flag
            flags |= Qt.WindowStaysOnTopHint
        else:
            # remove the flag
            flags &= ~Qt.WindowStaysOnTopHint

        self.setWindowFlags(flags)
        self.show()   # must re-show for the change to take effect
        log.debug(str(f"[DEBUG] Always-on-top set to {enabled}"))
    
    # --- updates lable to username in app
    def _active_username(self):
        try:
            if hasattr(self, "currentUsername") and hasattr(self.currentUsername, "text"):
                u = (self.currentUsername.text() or "").strip()
                if u:
                    return u
        except Exception:
            pass
        for attr in ("currentUsername", "currentUser", "username", "activeUser"):
            val = getattr(self, attr, None)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return None



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
