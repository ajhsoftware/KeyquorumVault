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

"""
Windows clipboard is backed by OLE/COM and *must* be accessed from the Qt GUI thread.
If clipboard operations happen from a worker thread, Qt will log:
  OleSetClipboard... CoInitialize has not been called (0x800401f0)

This module provides a small, safe API:

- secure_copy(text, ttl_ms=..., username=...)
    Copies text to the clipboard (Clipboard mode only on Windows) and arms an auto-clear timer.
- force_clear_clipboard_now()
    Clears the clipboard *only if* it still contains content we previously placed there.

Internally we tag clipboard content with a private mime token so we only clear what we set.
"""

import os
import sys
import logging
import hashlib
from typing import Optional

# --- pysider6 backend ---
from qtpy.QtCore import QObject, QTimer, QThread, Signal, Qt, QMimeData
from qtpy.QtGui import QGuiApplication, QClipboard
from qtpy.QtWidgets import QApplication

# --- log ---
log = logging.getLogger("keyquorum")

# --- start ---
_KQ_TOKEN_MIME = "application/x-kq-token"
_guard: Optional["_ClipGuard"] = None  # singleton


_invoker: Optional["_UiInvoker"] = None  # GUI-thread dispatcher

# --- Compatibility: legacy import support ---
_WIN_CLIPBOARD_CACHE = {
    "clipboard_written": False,
    "last_action": None,
}

def _win_clipboard_risk_state() -> dict:
    """
    Return Windows clipboard history/cloud clipboard status.

    Keys expected by Security Center:
      - history (bool)
      - cloud (bool)
      - history_gpo (Optional[int])
      - cloud_gpo (Optional[int])

    Also includes our internal fields:
      - clipboard_written (bool)
      - last_action (str|None)
    """
    state = dict(_WIN_CLIPBOARD_CACHE)

    # Non-Windows: treat as safe / not applicable
    if not sys.platform.startswith("win"):
        state.update({"history": False, "cloud": False, "history_gpo": None, "cloud_gpo": None})
        return state

    try:
        import winreg

        def _read_dword(root, path, name):
            try:
                k = winreg.OpenKey(root, path)
                val, typ = winreg.QueryValueEx(k, name)
                winreg.CloseKey(k)
                if typ in (winreg.REG_DWORD, winreg.REG_QWORD):
                    return int(val)
            except Exception:
                return None
            return None

        # Policy (GPO) values (most authoritative if present)
        # History policy: AllowClipboardHistory (0=disable, 1=enable)
        hist_gpo = _read_dword(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "AllowClipboardHistory")
        # Cloud policy: AllowCrossDeviceClipboard (0=disable, 1=enable)
        cloud_gpo = _read_dword(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Policies\Microsoft\Windows\System",
                                "AllowCrossDeviceClipboard")

        # User settings (if no GPO)
        # Windows stores these under the user CloudClipboard key
        hist_user = _read_dword(winreg.HKEY_CURRENT_USER,
                                r"SOFTWARE\Microsoft\Clipboard",
                                "EnableClipboardHistory")
        cloud_user = _read_dword(winreg.HKEY_CURRENT_USER,
                                 r"SOFTWARE\Microsoft\Clipboard",
                                 "EnableCloudClipboard")

        # Determine effective state:
        # If GPO is set, it takes precedence; else use user settings.
        history_on = (hist_gpo == 1) if hist_gpo is not None else (hist_user == 1)
        cloud_on   = (cloud_gpo == 1) if cloud_gpo is not None else (cloud_user == 1)

        state.update({
            "history": bool(history_on),
            "cloud": bool(cloud_on),
            "history_gpo": hist_gpo,
            "cloud_gpo": cloud_gpo,
        })
    except Exception:
        # If we can't read registry, fail safe: assume unknown -> treat as risky in UI layer
        state.update({"history": False, "cloud": False, "history_gpo": None, "cloud_gpo": None})

    return state


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _run_on_ui_thread(fn) -> None:
    """Run `fn` on the Qt GUI thread (required for clipboard on Windows)."""
    app = QGuiApplication.instance()
    if app is None:
        return

    try:
        if QThread.currentThread() is app.thread():
            fn()
            return
    except Exception:
        pass

    inv = _ensure_invoker()
    if inv is None:
        return
    try:
        inv.run.emit(fn)
    except Exception:
        pass


class _UiInvoker(QObject):
    run = Signal(object)

    def __init__(self):
        super().__init__()
        # ensure queued execution on the invoker's thread (GUI)
        self.run.connect(self._run, Qt.ConnectionType.QueuedConnection)

    def _run(self, fn):
        try:
            fn()
        except Exception:
            pass


def _ensure_invoker() -> Optional["_UiInvoker"]:
    global _invoker
    app = QGuiApplication.instance()
    if app is None:
        return None
    if _invoker is None:
        try:
            _invoker = _UiInvoker()
            _invoker.moveToThread(app.thread())
        except Exception:
            _invoker = None
    return _invoker


class _ClipGuard(QObject):
    """Tracks our clipboard content and clears it after a TTL if it is still ours."""

    def __init__(self, timeout_ms: int = 30_000):
        super().__init__()
        self.timeout_ms = int(timeout_ms or 30_000)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self._clear_clip)
        self._last_token: Optional[bytes] = None

        
        self._last_text_sig: Optional[tuple[int, str]] = None  # (utf8_len, sha256hex) for Windows
# Disarm if user changes clipboard away from our content
        try:
            cb = QGuiApplication.clipboard()
            cb.dataChanged.connect(self._on_clipboard_changed)
        except Exception:
            pass

    def set_timeout(self, timeout_ms: int) -> None:
        self.timeout_ms = int(timeout_ms or self.timeout_ms)


    def _sig(self, text: str) -> tuple[int, str]:
        b = (text or "").encode("utf-8", errors="replace")
        return (len(b), hashlib.sha256(b).hexdigest())

    # ---------------- public ----------------

    def copy_and_arm(self, text: str) -> None:
        app = QGuiApplication.instance()
        if not app:
            return

        token = os.urandom(16)
        self._last_token = token

        cb = app.clipboard()
        # Windows: avoid setMimeData() entirely (prevents OLE/COM warnings).
        if _is_windows():
            try:
                cb.setText(text or "", QClipboard.Mode.Clipboard)
                self._last_text_sig = self._sig(text or "")
            except Exception:
                return
        else:
            # X11/macOS: we can tag our content with a private mime token so we only clear what we set.
            modes = [QClipboard.Mode.Clipboard]
            # On X11 some modes may exist; only include if supported.
            if getattr(cb, "supportsSelection", lambda: False)():
                modes.append(QClipboard.Mode.Selection)
            if getattr(cb, "supportsFindBuffer", lambda: False)():
                modes.append(QClipboard.Mode.FindBuffer)

            for m in modes:
                try:
                    mime = QMimeData()
                    mime.setText(text or "")
                    try:
                        mime.setData(_KQ_TOKEN_MIME, token)
                    except Exception:
                        pass
                    cb.setMimeData(mime, m)
                except Exception:
                    pass

        _WIN_CLIPBOARD_CACHE["clipboard_written"] = True
        _WIN_CLIPBOARD_CACHE["last_action"] = "set"

        self.timer.start(self.timeout_ms)
        log.debug("[Clipboard] armed for %s ms", self.timeout_ms)


    def force_clear_now(self) -> None:
        self._clear_clip()

    # ---------------- internal ----------------

    def _ours_in_mode(self, mode: QClipboard.Mode) -> bool:
        # Windows: we can't reliably tag the clipboard with custom mime without OLE warnings.
        # Instead, compare the current clipboard text signature to what we last set.
        if _is_windows():
            sig = self._last_text_sig
            if not sig:
                return False
            try:
                cb = QGuiApplication.clipboard()
                current = cb.text(QClipboard.Mode.Clipboard)
                return self._sig(current) == sig
            except Exception:
                return False

        token = self._last_token
        if not token:
            return False
        try:
            cb = QGuiApplication.clipboard()
            md = cb.mimeData(mode)
            if md is None:
                return False
            try:
                data = bytes(md.data(_KQ_TOKEN_MIME))
            except Exception:
                return False
            return data == token
        except Exception:
            return False

    def _supported_modes(self):
        # Windows: avoid Selection/FindBuffer to prevent "unsupported mode" spam.
        if _is_windows():
            return [QClipboard.Mode.Clipboard]

        cb = QGuiApplication.clipboard()
        modes = [QClipboard.Mode.Clipboard]
        if getattr(cb, "supportsSelection", lambda: False)():
            modes.append(QClipboard.Mode.Selection)
        if getattr(cb, "supportsFindBuffer", lambda: False)():
            modes.append(QClipboard.Mode.FindBuffer)
        return modes

    def _clear_clip(self) -> None:
        app = QGuiApplication.instance()
        if not app:
            self._disarm()
            return

        cb = app.clipboard()
        for m in self._supported_modes():
            try:
                if self._ours_in_mode(m):
                    if _is_windows():
                        # Windows: keep it simple to avoid OLE warnings
                        cb.setText("", QClipboard.Mode.Clipboard)
                    else:
                        cb.clear(m)
                        # Some apps keep last text; overwrite too.
                        cb.setText("", m)
            except Exception:
                pass

        self._disarm()
        _WIN_CLIPBOARD_CACHE["clipboard_written"] = False
        _WIN_CLIPBOARD_CACHE["last_action"] = "clear"

    def _disarm(self) -> None:
        try:
            self.timer.stop()
        except Exception:
            pass
        self._last_token = None
        self._last_text_sig = None

    def _on_clipboard_changed(self) -> None:
        # If user/other app changed clipboard away from ours, disarm to avoid clearing their data.
        try:
            if not self._ours_in_mode(QClipboard.Mode.Clipboard):
                self._disarm()
        except Exception:
            self._disarm()


# ---------------- module API ----------------

def install_clipboard_guard(timeout_ms: int = 30_000) -> None:
    """Ensure the singleton guard exists (on GUI thread) and update its timeout."""

    def _do():
        global _guard
        if _guard is None:
            _guard = _ClipGuard(timeout_ms)
        else:
            _guard.set_timeout(timeout_ms)

    _run_on_ui_thread(_do)


def copy_secret(text: str, timeout_ms: int = 30_000) -> None:
    """Copy text (GUI thread) and arm the auto-clear timer."""

    def _do():
        global _guard
        if _guard is None:
            _guard = _ClipGuard(timeout_ms)
        else:
            _guard.set_timeout(timeout_ms)
        _guard.copy_and_arm(text or "")

    _run_on_ui_thread(_do)


def force_clear_clipboard_now() -> None:
    """Clear clipboard now, but only if it still contains our tagged content."""

    def _do():
        if _guard is not None:
            _guard.force_clear_now()
        else:
            # best-effort plain clear, GUI thread + Clipboard mode only on Windows
            try:
                cb = QGuiApplication.clipboard()
                cb.clear(QClipboard.Mode.Clipboard)
                cb.setText("", QClipboard.Mode.Clipboard)
            except Exception:
                pass

    _run_on_ui_thread(_do)


def secure_copy(text: str, ttl_ms: int | None = None, username: str | None = None) -> None:
    """Main entrypoint used by the app (warns about Windows clipboard history, then copies safely)."""
    try:
        from ui.ui_flags import maybe_warn_windows_clipboard
        maybe_warn_windows_clipboard(username)
    except Exception:
        pass

    tm = int(ttl_ms) if ttl_ms is not None else 8000
    copy_secret("" if text is None else str(text), tm)

def secure_copy(text: str, ttl_ms: int = None, username:str = None):
    try:
        tm = ttl_ms if ttl_ms is not None else int(getattr(self, "clipboard_timeout", 8000))
    except Exception:
        tm = 8000
    try:
        try:
            install_clipboard_guard(tm)
        except Exception:
            pass
        copy_secret("" if text is None else str(text), tm)
        return
    except Exception:
        pass
    QApplication.clipboard().setText("" if text is None else str(text))

