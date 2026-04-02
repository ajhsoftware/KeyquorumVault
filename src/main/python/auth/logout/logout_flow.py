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

# --- log ---
import logging
log = logging.getLogger("keyquorum")
import app.kq_logging as kql
from app.kq_logging import apply_debug_flag
from qtpy.QtCore import Qt, QEvent, QTimer, QSignalBlocker, QAbstractNativeEventFilter, QCoreApplication
from qtpy.QtWidgets import QApplication, QDialog, QMessageBox
from qtpy.QtGui import QPixmap
import os, sys, gc
from urllib.parse import urlparse
import ctypes
import time as _t
from ctypes import wintypes
from auth.pw.password_generator import show_password_generator_dialog


def _tr(text: str) -> str:
    """Qt translation helper scoped to the Watchtower UI."""
    return QCoreApplication.translate("uiwatchtower", text)

def cleanup_on_logout(w):
    w.set_status_txt(_tr("cleaning up on logout"))
    # 1) Last-chance prompt (only if mode includes logout)
    try:
        if getattr(w, "_backup_remind_mode", "both") in ("logout", "both"):
            adv = getattr(w, "backupAdvisor", None)
            w.set_status_txt(_tr("Last Changes backup"))
            if adv:
                changes   = int(adv.pending_changes())

                threshold = max(1, int(getattr(adv, "threshold", 5) or 5))
                # On logout we prompt if either:
                #  - mode includes logout AND changes >= threshold (same rule as in-session), OR
                #  - you prefer: always prompt on logout when mode includes logout (uncomment next line)
                # changes = max(changes, threshold)  # <- forces prompt once on logout
                if changes >= threshold:
                    adv.prompt_to_backup_now(force=True)
    except Exception:
        pass

    # 2) Stop timer (if you add scheduler later)
    try:
        w.set_status_txt(_tr("Stoping Timers"))
        if getattr(w, "backupScheduler", None) and hasattr(w.backupScheduler, "timer"):
            w.backupScheduler.timer.stop()
    except Exception:
        pass

    # 3) Clear refs
    w.set_status_txt(_tr("Backup Clean"))
    w.backupAdvisor = None
    w.backupScheduler = None

# ==============================
# Default state reset
# ==============================
def __init__default_values(w):
    """
    Reset per-session variables to sensible defaults.  This should be
    called once during application construction and again after each
    logout.  Its purpose is to avoid carrying over timers, watchers
    or counters between user sessions.  Many of these attributes are
    created lazily; setting them to None here ensures a clean slate.
    """
    # Reset cloud sync state and auto-sync timers
    try:
        
        # Stop and release the auto-sync timer if present
        t = getattr(w, "_auto_sync_timer", None)
        if t:
            try:
                t.stop()
            except Exception:
                pass
            try:
                t.deleteLater()
            except Exception:
                pass
        
        w._auto_sync_timer = None
    except Exception:
        pass
    # Release the vault file watcher
    try:
        _vw = getattr(w, "_vault_watcher", None)
        if _vw:
            try:
                _vw.deleteLater()
            except Exception:
                pass
        w._vault_watcher = None
    except Exception:
        pass
    # Clear the sync engine and bound user
    try:
        w.sync_engine = None
    except Exception:
        pass
    try:
        w._sync_user = None
    except Exception:
        pass
    # Guard flags for sync recursion
    try:
        w._sync_guard = False
    except Exception:
        pass
    # Drop debouncer timers (baseline/vault reload)
    try:
        br = getattr(w, "_baseline_timer", None)
        if br:
            try:
                br.stop()
            except Exception:
                pass
            try:
                br.deleteLater()
            except Exception:
                pass
        w._baseline_timer = None
    except Exception:
        pass
    try:
        vr = getattr(w, "_vault_reload_timer", None)
        if vr:
            try:
                vr.stop()
            except Exception:
                pass
            try:
                vr.deleteLater()
            except Exception:
                pass
        w._vault_reload_timer = None
    except Exception:
        pass
    # Reset the backup advisor and scheduler; clear counters in QSettings
    try:
        adv = getattr(w, "backupAdvisor", None)
        if adv:
            try:
                adv.reset_change_counter(clear_snooze=True, clear_session_suppress=True)
            except Exception:
                pass
    except Exception:
        pass
    try:
        w.backupAdvisor = None
    except Exception:
        pass
    try:
        w.backupScheduler = None
    except Exception:
        pass
    # Backup reminder mode default
    try:
        w._backup_remind_mode = "both"
    except Exception:
        pass
    # Reset session flags
    try:
        w._is_logging_out = False
    except Exception:
        pass

    # 4) Reset backup counter and session state on logout.  Without this, change
    # counters can spill over when switching accounts, causing stale
    # "X changes" prompts for a newly logged-in user.  We also clear
    # auto-sync timers, file watchers and any per-session sync state.
    try:
        adv = getattr(w, "backupAdvisor", None)
        if adv:
            # Clear pending changes and suppression flags
            adv.reset_change_counter(clear_snooze=True, clear_session_suppress=True)
    except Exception:
        pass
    # Use the helper to tear down auto-sync and sync engine and reinitialise
    try:
        __init__default_values(w)
    except Exception:
        pass

def _on_any_entry_changed(self):
    if getattr(self, "_backup_remind_mode", "both") in ("changes", "both"):
        if hasattr(self, "backupAdvisor") and self.backupAdvisor:
            self.backupAdvisor.note_change()

    # Also nudge cloud auto-sync directly after real entry edits.
    # This makes entry add/edit/delete reliable even if the filesystem watcher
    # misses an atomic replace or a non-vault bundle member changed.
    try:
        from qtpy.QtCore import QTimer
        QTimer.singleShot(900, self._schedule_auto_sync)
    except Exception:
        try:
            self._schedule_auto_sync()
        except Exception:
            pass

def logout_user(w, skip_backup=True):
    """
    Securely log out the user, stop timers, close open dialogs/windows,
    clear sensitive state, and switch back to the login screen.
    """
    from features.security_center.security_center_ui import _security_center_clear_ui

    w.set_status_txt(_tr("Logging User Out"))

    # ---- re-entrancy guard ----
    if getattr(w, "_is_logging_out", False):
        return
    w._is_logging_out = True

    # Keep a local copy in case anything later still needs it
    active_username = getattr(w, "current_username", None)

    # --- Stop USB watch timer if running ---
    try:
        t = getattr(w, "_usb_watch_timer", None)
        if t and t.isActive():
            t.stop()
    except Exception:
        pass

    # --- Cloud sync pause and reset ---
    w.cloudsync.setText("")
    try:
        if hasattr(w, "sync_engine") and w.sync_engine:
            w.set_status_txt(_tr("Pausing Cloud Sync"))
            w.sync_engine.pause()
            w.sync_engine.reset_state()
            if hasattr(w.sync_engine, "stop_all_threads"):
                try:
                    w.sync_engine.stop_all_threads()
                except Exception:
                    pass
            w.set_status_txt(_tr("Cloud Sync Paused"))
    except Exception as e:
        log.debug(f"[logout_user] cloud sync reset failed: {e}")

    # --- final chance to ask user to backup ---
    if not skip_backup:
        try:
            cleanup_on_logout(w)
        except Exception:
            pass

    # Mark vault locked early
    w.vault_unlocked = False
    w.current_mk = None

    # Clear Security Center UI/session state
    _security_center_clear_ui(w)

    def _secure_zeroize(buf):
        """Best-effort in-place zeroization for bytearray/memoryview."""
        try:
            if buf is None:
                return

            if isinstance(buf, bytearray):
                try:
                    mv = (ctypes.c_char * len(buf)).from_buffer(buf)
                    try:
                        RtlSecureZeroMemory = ctypes.windll.kernel32.RtlSecureZeroMemory
                        RtlSecureZeroMemory(ctypes.addressof(mv), len(buf))
                    except Exception:
                        ctypes.memset(ctypes.addressof(mv), 0, len(buf))
                except Exception:
                    for i in range(len(buf)):
                        buf[i] = 0

            elif isinstance(buf, memoryview):
                try:
                    mv = buf.cast("B")
                    for i in range(mv.nbytes):
                        mv[i] = 0
                except Exception:
                    pass

        except Exception:
            pass

    def _scrub_container(obj):
        try:
            if obj is None:
                return

            if isinstance(obj, bytearray):
                _secure_zeroize(obj)
                return

            if isinstance(obj, memoryview):
                _secure_zeroize(obj)
                return

            if isinstance(obj, bytes):
                _secure_zeroize(bytearray(obj))
                return

            if isinstance(obj, str):
                # immutable; best effort is to drop references only
                return

            if isinstance(obj, dict):
                for k, v in list(obj.items()):
                    if isinstance(v, bytearray):
                        _secure_zeroize(v)
                    elif isinstance(v, memoryview):
                        _secure_zeroize(v)
                    elif isinstance(v, bytes):
                        _secure_zeroize(bytearray(v))
                    elif isinstance(v, (dict, list, tuple)):
                        _scrub_container(v)

                    if str(k).lower() in ("password", "pass", "secret", "key", "token", "otp", "seed"):
                        obj[k] = None

            elif isinstance(obj, list):
                for i, v in enumerate(list(obj)):
                    if isinstance(v, bytearray):
                        _secure_zeroize(v)
                    elif isinstance(v, memoryview):
                        _secure_zeroize(v)
                    elif isinstance(v, bytes):
                        _secure_zeroize(bytearray(v))
                    elif isinstance(v, (dict, list, tuple)):
                        _scrub_container(v)
                    obj[i] = None

            elif isinstance(obj, tuple):
                for v in obj:
                    if isinstance(v, bytearray):
                        _secure_zeroize(v)
                    elif isinstance(v, memoryview):
                        _secure_zeroize(v)
                    elif isinstance(v, bytes):
                        _secure_zeroize(bytearray(v))
                    elif isinstance(v, (dict, list, tuple)):
                        _scrub_container(v)

        except Exception:
            pass

    def _safe_stop_timer(obj):
        try:
            if obj:
                obj.stop()
        except Exception:
            pass

    def _safe_close(widget):
        try:
            if not widget:
                return

            for attr in ("stop", "shutdown", "closeEventHook"):
                m = getattr(widget, attr, None)
                if callable(m):
                    try:
                        m()
                    except Exception:
                        pass

            if isinstance(widget, QDialog):
                try:
                    widget.reject()
                except Exception:
                    try:
                        widget.close()
                    except Exception:
                        pass
            else:
                try:
                    widget.close()
                except Exception:
                    pass

            try:
                log.debug("%s [LOGOUT] %s Closed: %s", kql.i("ok"), kql.i("auth"), type(widget).__name__)
            except Exception:
                pass
        except Exception:
            pass

    try:
        log.debug(f"{kql.i('auth')} -> {kql.i('ok')} [LOGOUT] %s Logout called")

        # ensure we shrink back AFTER the login panel becomes visible
        QTimer.singleShot(0, w._apply_login_geometry)

        # auth store logout
        try:
            from features.auth_store.auth_ops import _auth_set_enabled
            _auth_set_enabled(w, False)
        except Exception as e:
            log.debug(f"[auth] disable timer: {e}")

        # scrub authenticator entries before dropping refs
        try:
            w.set_status_txt(_tr("Scrubbing authenticator entries"))
            _scrub_container(getattr(w, "_auth_entries", None))
        except Exception:
            pass

        w._auth_entries = []
        if hasattr(w, "authTable") and w.authTable:
            try:
                w.authTable.setRowCount(0)
            except Exception:
                pass

        # --- close native session / clear handle ---
        try:
            w.set_status_txt(_tr("Scrubbing session"))
            try:
                from native.native_core import get_core
                core = get_core()
                handle = getattr(w, "core_session_handle", None)
                if core and handle:
                    core.close_session(handle)
            except Exception:
                pass
            w.core_session_handle = None
        except Exception:
            pass

        # Clear username after session-dependent cleanup is done
        w.current_username = None

        # scrub other cached sensitive blobs
        for attr in (
            "_decrypted_cache", "_current_entry", "_totp_cache",
            "_active_secret", "_session_token", "_api_key"
        ):
            try:
                v = getattr(w, attr, None)
                _scrub_container(v)
                setattr(w, attr, None)
            except Exception:
                pass

        # wipe in-memory models that may hold decrypted fields
        for name in ("vaultModel", "searchModel"):
            try:
                m = getattr(w, name, None)
                if m:
                    try:
                        m.removeRows(0, m.rowCount())
                    except Exception:
                        pass
                    setattr(w, name, None)
            except Exception:
                pass

        # stop named timers
        for name in (
            "logout_timer", "logout_warning_timer", "clipboard_timer",
            "_tick", "glow_fade", "color_timer"
        ):
            _safe_stop_timer(getattr(w, name, None))
            try:
                setattr(w, name, None)
                log.debug("%s [LOGOUT] %s Timer stopped: %s", kql.i("locked"), kql.i("auth"), name)
            except Exception:
                pass

        # stop lingering QTimers attached as attributes
        try:
            for k, v in list(vars(w).items()):
                if isinstance(v, QTimer):
                    _safe_stop_timer(v)
                    try:
                        setattr(w, k, None)
                    except Exception:
                        pass
        except Exception:
            pass

        # stop background threads
        try:
            w.set_status_txt(_tr("Stopping background threads"))
            for t in list(getattr(w, "_bg_threads", []) or []):
                try:
                    if isinstance(t, QThread):
                        try:
                            t.requestInterruption()
                        except Exception:
                            pass
                        try:
                            t.quit()
                        except Exception:
                            pass
                        try:
                            t.wait(1000)
                        except Exception:
                            pass
                    else:
                        try:
                            if hasattr(t, "stop"):
                                t.stop()
                        except Exception:
                            pass
                        try:
                            t.join(timeout=1.0)
                        except Exception:
                            pass
                except Exception:
                    pass
            w._bg_threads = []
        except Exception:
            pass

        # close tracked child windows
        try:
            w.set_status_txt(_tr("Closing child windows"))
            for ref in list(getattr(w, "_child_windows", []) or []):
                try:
                    child = ref() if callable(ref) else None
                except Exception:
                    child = None
                if child:
                    _safe_close(child)
            w._child_windows = []
        except Exception:
            pass

        # close all top-level windows except main
        try:
            _force_close_all_windows_except_main(w)
        except Exception:
            pass

        # close common dialogs by attribute
        for name in (
            "pwdGenDialog", "addEntryDialog", "editEntryDialog",
            "changePasswordDialog", "otpDialog", "settingsDialog"
        ):
            try:
                _safe_close(getattr(w, name, None))
                setattr(w, name, None)
            except Exception:
                pass

        # close any top-level windows owned by w
        try:
            for tw in QApplication.topLevelWidgets():
                if tw is w:
                    continue
                p, owned = tw.parentWidget(), False
                while p is not None:
                    if p is w:
                        owned = True
                        break
                    p = p.parentWidget()
                if owned:
                    _safe_close(tw)
        except Exception:
            pass

        # stop bridge
        try:
            from bridge.bridge_ops import stop_bridge_server, stop_bridge_monitoring
            w.set_status_txt(_tr("Stopping bridge"))
            try:
                w._set_bridge_offline()
            except Exception:
                pass
            try:
                stop_bridge_monitoring(w)
            except Exception:
                pass
            try:
                stop_bridge_server(w)
            except Exception:
                pass
        except Exception:
            pass

        # wipe env token copies best-effort
        try:
            for k in list(os.environ.keys()):
                if k.upper().startswith("KQ_BRIDGE") or k.upper().endswith("_TOKEN"):
                    os.environ[k] = ""
        except Exception:
            pass

        # clear clipboard
        try:
            w.set_status_txt(_tr("Clearing clipboard"))
            try:
                from features.clipboard.secure_clipboard import force_clear_clipboard_now
                force_clear_clipboard_now()
            except Exception:
                pass
            log.debug("%s [LOGOUT] %s Clipboard cleared", kql.i("ok"), kql.i("auth"))
        except Exception:
            log.exception("%s [ERROR] %s Clear clipboard failed", kql.i("locked"), kql.i("auth"))

        # turn off debug logging quietly
        w._suppress_logging_toasts = True
        try:
            if hasattr(w, "debug_set_") and w.debug_set_:
                blocker = QSignalBlocker(w.debug_set_)
                try:
                    w.debug_set_.setChecked(False)
                finally:
                    del blocker
            w.debug_set = False
        finally:
            w._suppress_logging_toasts = False

        # reset runtime flags / cached prefs
        w.expiry_days = None
        w.clipboard_clear_timeout_sec = None
        w.auto_logout_timeout_sec = None
        w.enable_breach_checker = None
        log.debug("%s [LOGOUT] %s Runtime flags reset", kql.i("ok"), kql.i("auth"))

        # UI cleanup
        try:
            w.set_status_txt(_tr("Clearing UI"))
            for name in ("currentUsername", "passwordField"):
                fld = getattr(w, name, None)
                if fld:
                    try:
                        t = fld.text()
                        if t:
                            fld.setText("\u200B" * len(t))
                        fld.clear()
                    except Exception:
                        pass

            for name in ("searchBox", "quickFindEdit"):
                fld2 = getattr(w, name, None)
                if fld2:
                    try:
                        fld2.clear()
                    except Exception:
                        pass

            if hasattr(w, "vaultTable") and w.vaultTable:
                try:
                    w.vaultTable.blockSignals(True)
                    w.vaultTable.clearContents()
                    w.vaultTable.setRowCount(0)
                except Exception:
                    pass
                finally:
                    try:
                        w.vaultTable.blockSignals(False)
                    except Exception:
                        pass

            for label_name in ("profilePicLabel", "loginPicLabel"):
                lab = getattr(w, label_name, None)
                if lab:
                    try:
                        lab.setPixmap(QPixmap())
                        lab.setText(_tr("No Image"))
                    except Exception:
                        pass

            if hasattr(w, "recovery_m"):
                try:
                    w.recovery_m.setText("")
                except Exception:
                    pass
        except Exception:
            pass

        log.debug("%s [LOGOUT] %s UI reset", kql.i("ok"), kql.i("auth"))

        # show login UI
        try:
            w.set_status_txt(_tr("Showing login screen"))
            w.show_login_ui()
            log.debug("%s [LOGOUT] %s set_login_visible -> OK", kql.i("ok"), kql.i("auth"))
        except Exception:
            log.exception("%s [ERROR] %s set_login_visible failed", kql.i("locked"), kql.i("auth"))
            try:
                cw = w.centralWidget()
                if cw:
                    cw.show()
            except Exception:
                pass

        # bring window to front
        try:
            w.showNormal()
            w.raise_()
            w.activateWindow()
        except Exception:
            pass

        # force a couple GC cycles after scrubbing buffers
        try:
            gc.collect()
            gc.collect()
        except Exception:
            pass

        # restore remembered username to login screen if applicable
        try:
            from ui.ui_bind import apply_remembered_username_to_login_screen
            QTimer.singleShot(0, lambda: apply_remembered_username_to_login_screen(w))
        except Exception:
            pass

        log.debug("%s [LOGOUT] %s Complete (user=%r)", kql.i("ok"), kql.i("auth"), active_username)

    finally:
        try:
            w._is_logging_out = False
        except Exception:
            pass

# ==============================
# --- timer logout
# ==============================

# --- tick: guard against sleep/resume & keep countdown accurate
def _on_tick(w):
    if not getattr(w, "_auto_logout_enabled", False):
        return
    elapsed = (_t.monotonic() - getattr(w, "_last_activity_monotonic", _t.monotonic()))
    if elapsed * 1000 >= w.logout_timeout + 2_000:
        w.force_logout()

# --- setup auto logout time (called on login)
def setup_auto_logout(w):
    # normalize + enable/disable flag
    try:
        timeout_ms = int(w.logout_timeout)
    except Exception:
        timeout_ms = 10 * 60 * 1000  # default 10 min

    # 0 => OFF
    w._auto_logout_enabled = timeout_ms > 0

    # if enabled, enforce a sensible minimum; else store 0
    MIN_TIMEOUT_MS = 15_000
    w.logout_timeout = (max(timeout_ms, MIN_TIMEOUT_MS) if w._auto_logout_enabled else 0)

    # warning offset only matters if enabled
    w.logout_warning_offset_ms = (
        min(2 * 60 * 1000, max(5_000, w.logout_timeout // 3)) if w._auto_logout_enabled else 0)

    # close any existing warning
    if getattr(w, "_warning_dialog", None) is not None:
        try: w._warning_dialog.close()
        except Exception: pass
        w._warning_dialog = None

    # stop existing timers if present
    for t in ("logout_timer", "logout_warning_timer", "_tick"):
        tm = getattr(w, t, None)
        if tm:
            try: tm.stop()
            except Exception: pass

    # install app event filter once (harmless if enabled/disabled)
    app = QApplication.instance()
    if app and not getattr(w, "_app_filter_installed", False):
        app.installEventFilter(w)
        w._app_filter_installed = True



    if not w._auto_logout_enabled:
        # fully disabled: clear timer refs so later checks short-circuit
        w.logout_timer = None
        w.logout_warning_timer = None
        w._tick = None
        # nothing else to do
        return

    # enabled: (re)create timers + start 1s tick
    w._last_activity_monotonic = _t.monotonic()

    w.logout_timer = QTimer(w)
    w.logout_timer.setSingleShot(True)
    w.logout_timer.timeout.connect(w.force_logout)

    w.logout_warning_timer = QTimer(w)
    w.logout_warning_timer.setSingleShot(True)
    w.logout_warning_timer.timeout.connect(lambda: _show_logout_warning(w))

    w._tick = QTimer(w)
    w._tick.setInterval(1000)
    w._tick.timeout.connect(lambda: _on_tick(w))
    w._tick.start()

    # prime timers
    reset_logout_timer(w)

# --- reset auto logout (call this on *any* user activity you already track)
def reset_logout_timer(w):
    if not getattr(w, "_auto_logout_enabled", False):
        return

    # record last activity
    w._last_activity_monotonic = _t.monotonic()

    # LOGOUT timer
    if getattr(w, "logout_timer", None):
        w.logout_timer.stop()
        w.logout_timer.start(w.logout_timeout)

    # WARNING timer
    if getattr(w, "logout_warning_timer", None):
        w.logout_warning_timer.stop()
        if w.logout_timeout > w.logout_warning_offset_ms:
            delay = w.logout_timeout - w.logout_warning_offset_ms
        else:
            delay = max(5_000, int(w.logout_timeout * 0.33))
        w.logout_warning_timer.start(delay)

    # close warning if open (user became active)
    if getattr(w, "_warning_dialog", None) is not None:
        try: w._warning_dialog.close()
        except Exception: pass
        w._warning_dialog = None

# --- force logout (timer hit 0 or safety check)
def force_logout(w):
    log.debug(str(f"{kql.i('locked')} [AUTOF] Force Logout"))  
    # Close warning if open
    if getattr(w, "_warning_dialog", None) is not None:
        try:
            w._warning_dialog.close()
        except Exception:
            pass
        w._warning_dialog = None

    # Stop all timers to avoid callbacks after logout
    for t in ("logout_timer", "logout_warning_timer", "_tick"):
        tm = getattr(w, t, None)
        if tm:
            try:
                tm.stop()
            except Exception:
                pass
    log.debug(str(f"{kql.i('locked')} [AUTOF]  Stop all timers to avoid callbacks after logout"))  
    # Close any other windows (best-effort)
    try:
        for child in (getattr(w, "_child_windows", []) or []):
            try:
                    child.close()
            except Exception:
                pass
    except Exception:
        pass
    log.debug(str(f"{kql.i('locked')} [AUTOF]  Close any other windows"))
    logout_user(w)

# --- helper: show warning dialog with live countdown & extend
def _show_logout_warning(w):
    # If already open, don't spawn another
    if getattr(w, "_warning_dialog", None) is not None:
        return

    # Compute seconds remaining
    secs_left = _seconds_until_logout(w)
    if secs_left <= 0:
        # Race: just logout
        w.force_logout()
        return

    msg = QMessageBox(w)
    msg.setWindowTitle(_tr("You’ll be signed out soon"))
    msg.setIcon(QMessageBox.Icon.Warning)
    msg.setStandardButtons(QMessageBox.StandardButton.Ok)
    # Add a custom "Stay signed in" button
    extend_btn = msg.addButton(_tr("Stay signed in"), QMessageBox.ButtonRole.AcceptRole)
    msg.setDefaultButton(extend_btn)

    # Use a small text that updates every second
    def _update_label():
        s = _seconds_until_logout(w)
        if s <= 0:
            try:
                msg.close()
            except Exception:
                pass
            w.force_logout()
            return
        msg.setText(_tr("Due to inactivity, you will be signed out in ") + f"<b>{s}</b>" + _tr(" seconds."))
    _update_label()

    # Hook the global 1s ticker to update the label while dialog is visible
    def _maybe_update():
        if getattr(w, "_warning_dialog", None) is msg:
            _update_label()
    try:
        w._warning_update_conn = w._tick.timeout.connect(_maybe_update)  
    except Exception:
        pass

    w._warning_dialog = msg
    res = msg.exec()

    # User clicked something; clear dialog
    w._warning_dialog = None
    try:
        # disconnect temporary updater
        w._tick.timeout.disconnect(_maybe_update)  
    except Exception:
        pass

    # If they clicked "Stay signed in", treat as activity
    if msg.clickedButton() == extend_btn:
        reset_logout_timer(w)
    else:
        # If they dismissed with OK, do nothing (timers continue counting down)
        pass


# --- optional: capture app resume/activate to re-evaluate timers
def eventFilter(w, obj, event):
    try:
        # if disabled, don’t enforce anything here
        if not getattr(w, "_auto_logout_enabled", False):
            return super().eventFilter(obj, event)

        if event.type() == QEvent.Type.ApplicationStateChange:
            if QApplication.instance().applicationState() == Qt.ApplicationState.ApplicationActive:
                if _seconds_until_logout(w) <= 0:
                    w.force_logout()
                elif getattr(w, "_warning_dialog", None) is not None:
                    _show_logout_warning(w)
    except Exception:
        pass
    return super().eventFilter(obj, event)

# --- utility: compute seconds left using monotonic/remaining time
def _seconds_until_logout(w) -> int:
    if not getattr(w, "_auto_logout_enabled", False):
        # effectively "infinite" so nothing else triggers
        return 2_147_483_647  # ~INT_MAX seconds

    try:
        if getattr(w, "logout_timer", None):
            ms = w.logout_timer.remainingTime()
            if ms >= 0:
                return max(0, ms // 1000)
    except Exception:
        pass

    remaining_ms = (w.logout_timeout - int((_t.monotonic() - w._last_activity_monotonic) * 1000))
    return max(0, remaining_ms // 1000)

# --- stop logout on other windows ---------------------------

# --- force windows closed ---

def _force_close_all_windows_except_main(w):
    """
    Best-effort: close ALL top-level Qt windows except the main window `w`.
    This is important for forced logout because many dialogs are not parented
    to `w` (so your 'owned-by-w' scan won't catch them).
    """
    try:
        app = QApplication.instance()
        if not app:
            return

        # Close any known warning dialog first
        try:
            if getattr(w, "_warning_dialog", None) is not None:
                try:
                    w._warning_dialog.close()
                except Exception:
                    pass
                w._warning_dialog = None
        except Exception:
            pass

        # Snapshot list once (closing widgets can mutate the list)
        top = list(QApplication.topLevelWidgets())

        for tw in top:
            try:
                if tw is None or tw is w:
                    continue
                if not tw.isVisible():
                    # Still close anyway; but visible ones matter most
                    pass

                # Try to close nicely depending on type
                if isinstance(tw, QDialog):
                    try:
                        tw.reject()
                    except Exception:
                        try:
                            tw.close()
                        except Exception:
                            pass
                else:
                    try:
                        tw.close()
                    except Exception:
                        pass
            except Exception:
                pass

        # Let Qt process close events immediately
        try:
            app.processEvents()
        except Exception:
            pass

    except Exception:
        pass


# ==============================
# --- show message to user
# ==============================
def safe_messagebox_question(w, *args, **kwargs):
    reset_logout_timer(w)
    return QMessageBox.question(*args, **kwargs)

def safe_messagebox_warning(w, *args, **kwargs):
    reset_logout_timer(w)
    return QMessageBox.warning(*args, **kwargs)

def safe_messagebox_info(w, *args, **kwargs):
    reset_logout_timer(w)
    return QMessageBox.information(*args, **kwargs)



# ==============================
# --- windows sleep, logout, ect (on evant logout user this making sure vault is always locked)
# ==============================

WM_WTSSESSION_CHANGE = 0x02B1
WTS_SESSION_LOCK = 0x7
WTS_SESSION_LOGOFF = 0x6

WM_POWERBROADCAST = 0x0218
PBT_APMSUSPEND = 0x0004

WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION = 0x0016

NOTIFY_FOR_THIS_SESSION = 0

wtsapi32 = None
if sys.platform.startswith("win"):
    wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)

    WTSRegisterSessionNotification = wtsapi32.WTSRegisterSessionNotification
    WTSRegisterSessionNotification.argtypes = [wintypes.HWND, wintypes.DWORD]
    WTSRegisterSessionNotification.restype = wintypes.BOOL

    WTSUnRegisterSessionNotification = wtsapi32.WTSUnRegisterSessionNotification
    WTSUnRegisterSessionNotification.argtypes = [wintypes.HWND]
    WTSUnRegisterSessionNotification.restype = wintypes.BOOL

class _WindowsSessionLockFilter(QAbstractNativeEventFilter):
    """
    Watches for Windows session lock/sleep/logoff/shutdown and calls a callback.
    """
    def __init__(self, hwnd: int, on_lock_cb):
        super().__init__()
        self._hwnd = hwnd
        self._cb = on_lock_cb

    def nativeEventFilter(self, eventType, message):
        if not sys.platform.startswith("win"):
            return False, 0

        # message is a MSG* on Windows
        msg = ctypes.cast(int(message), ctypes.POINTER(wintypes.MSG)).contents

        try:
            if msg.message == WM_WTSSESSION_CHANGE:
                # lock, logoff etc
                if msg.wParam in (WTS_SESSION_LOCK, WTS_SESSION_LOGOFF):
                    self._cb("windows_session")
            elif msg.message == WM_POWERBROADCAST:
                if msg.wParam == PBT_APMSUSPEND:
                    self._cb("sleep_or_hibernate")
            elif msg.message in (WM_QUERYENDSESSION, WM_ENDSESSION):
                self._cb("session_ending")
        except Exception:
            pass

        return False, 0

