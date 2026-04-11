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

from app.qt_imports import *
from app.kq_logging import apply_debug_flag, get_logfile_path
from security.baseline_signer import update_baseline
from auth.login.login_handler import set_user_setting, get_user_setting
from features.clipboard.secure_clipboard import install_clipboard_guard, copy_secret
import ctypes
from app.dev import dev_ops
is_dev = dev_ops.dev_set

# ============================== 
# helper to stop crease on rapid change
# ==============================
def _ensure_debounce_store(self):
    if not hasattr(self, "_debounce_timers"):
        self._debounce_timers: dict[str, "QTimer"] = {} # type: ignore
        self._debounce_values: dict[str, object] = {} # type: ignore
        self._debounce_last_saved: dict[str, object] = {} # type: ignore


def _debounce_setting(self, key: str, value, delay_ms: int, persist_fn, *, flush: bool = False):
    """
    Debounce persistence for a setting.
    - key: unique id for the setting (e.g. 'logout_timeout_sec')
    - value: latest value to persist
    - delay_ms: debounce window in ms
    - persist_fn(latest_value): function to call when the timer fires
    - flush=True runs persist immediately (e.g. on editingFinished)
    """
    self._ensure_debounce_store()
    self._debounce_values[key] = value

    # ---- immediate commit (editingFinished) ----
    if flush:
        # stop & remove any pending timer
        t = self._debounce_timers.pop(key, None)
        if t:
            try: t.stop()
            except Exception: pass

        # skip if not changed
        if self._debounce_last_saved.get(key) == value:
            return

        try:
            persist_fn(value)
            self._debounce_last_saved[key] = value
        except Exception as e:
            log.error("debounce(flush) %s failed: %s", key, e)
          
        finally:
            # clear any stale pending
            self._debounce_values.pop(key, None)
        return

    # ---- debounced commit (valueChanged) ----
    t = self._debounce_timers.get(key)
    if t is None:
        t = QTimer(self)
        t.setSingleShot(True)

        def _fire():
            latest = self._debounce_values.pop(key, None)
            if latest is None:
                return
            # avoid duplicate commit of same value
            if self._debounce_last_saved.get(key) == latest:
                return
            try:
                persist_fn(latest)
                self._debounce_last_saved[key] = latest
            except Exception as e:
                log.error("debounce(timer) %s failed: %s", key, e)
                
            finally:
                tm = self._debounce_timers.pop(key, None)
                if tm:
                    try: tm.stop()
                    except Exception: pass

        t.timeout.connect(_fire)
        self._debounce_timers[key] = t

    try: t.stop()
    except Exception: pass
    t.start(int(delay_ms))


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
# --- Logging
# ==============================
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
        username = self._active_username()
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
# Auto logout timeout (seconds, int) — 0 = OFF
# ==============================
def on_auto_logout_timeout_sec_change(self, value: int | float, flush: bool = False) -> None:
    v = int(round(value))
    if v < 0: v = 0
    log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} auto-logout -> {v}s")
    self.reset_logout_timer()

    username = self._active_username()
    if not username:
        log.debug(f"{kql.i('tool')} {kql.i('warn')} no user for auto-logout update")
        return

    self.logout_timeout = 0 if v == 0 else v * 1000
    try: self.setup_auto_logout()
    except Exception: pass

    def _persist(val: int):
        try:
            from auth.login.login_handler import set_user_setting
            set_user_setting(username, "auto_logout_timeout_sec", int(val))
            try:
                from security.baseline_signer import update_baseline
                update_baseline(username=username, verify_after=False, who=self.tr("Auto Logout Settings Changed"))
            except Exception: pass
            log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} auto-logout saved {val}")
        except Exception as e:
            log.error(f"{kql.i('tool')} [ERROR] {kql.i('err')} auto-logout save failed: {e}")

    self._debounce_setting("auto_logout_timeout_sec", v, 2000, _persist, flush=flush)


# ==============================
# Clipboard clear timeout (seconds, int)
# ==============================
def on_clipboard_clear_timeout_sec_change(self, value: int | float, flush: bool = False) -> None:
    self.set_status_txt(self.tr("Clipboard timeout changed"))
    v = int(round(value))
    if v < 0: v = 0
    log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} clipboard timeout -> {v}s")
    self.reset_logout_timer()

    username =  self._active_username()
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
# Lockout threshold (int)
# ==============================
def on_lockout_threshold_changed(self, value: int | float, flush: bool = False) -> None:
    v = int(round(value))
    if v < 0: v = 0
    log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} lockout threshold -> {v}")
    self.reset_logout_timer()
        
    username =  self._active_username()
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
# --- Password expiry days (int)
# ==============================
def on_password_expiry_days_change(self, value: int | float, flush: bool = False) -> None:
    self.set_status_txt(self.tr("Saving Password Expiry Change"))
    v = int(round(value))
    log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} on_password_expiry_days_change -> {v}")
    self.reset_logout_timer()

    username =  self._active_username()
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
# --- Allways on top
# ==============================
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


# ==============================
# --- Touch Screen
# ==============================
# touch mode: larger row heights, kinetic scrolling, touch event acceptance
def _enable_touch_mode(self, *, force: bool | None = None):
    log.info(f"{kql.i('ui')} -> {kql.i('ok')} [UI] enable touch mode: force={force}")
    # Provide template and format for dynamic value
    self.set_status_txt(self.tr("Applying Touch mode {state}").format(state=force))
    # - state slots
    if not hasattr(self, "_touch_mode_active"):
        self._touch_mode_active = False
    if not hasattr(self, "_orig_row_height"):
        self._orig_row_height = None

    if force is None:  # --- auto-detect ---
        def _qt_has_touch() -> bool:
            try:
                from PySide6.QtGui import QTouchDevice
                return bool(QTouchDevice.devices())
            except Exception:
                 return False

        def _win_has_touch() -> bool:
            try:
                SM_MAXIMUMTOUCHES = 95
                return ctypes.windll.user32.GetSystemMetrics(SM_MAXIMUMTOUCHES) > 0
            except Exception:
                return False

        has_touch = _qt_has_touch() or _win_has_touch()
        target = bool(has_touch)
    else:          # --- explicit override via checkbox ---
        target = bool(force)

    if target == self._touch_mode_active:                                # - no-op if already applied
        try:
            self.tuchmode_.blockSignals(True)
            self.tuchmode_.setChecked(target)
            self.tuchmode_2.setChecked(target)
            self.tuchmode_.blockSignals(False)
        except Exception:
            pass
        return

    if QScroller is not None:                                            # - kinetic scrolling on common scrollables
        try:
            # robust gesture constant (varies across Qt bindings)
            try:
                gesture = QScroller.ScrollerGestureType.TouchGesture
            except Exception:
                gesture = getattr(QScroller, "TouchGesture",
                          getattr(QScroller, "LeftMouseButtonGesture", None))

            def _apply_scroller(w):
                try:
                    vw = w.viewport() if hasattr(w, "viewport") else w
                    if target and gesture is not None:
                        QScroller.grabGesture(vw, gesture)
                    else:
                        QScroller.ungrabGesture(vw)
                except Exception:
                    pass

            for w in self.findChildren(QAbstractScrollArea):
                _apply_scroller(w)
            for c in self.findChildren(QComboBox):
                try:
                    v = c.view()
                    if v:
                        _apply_scroller(v)
                except Exception:
                    pass

            # optional tuning (ignore failures)
            try:
                sc = QScroller.scroller(self)
                sp = sc.scrollerProperties()
                sp.setScrollMetric(sp.DecelerationFactor, 0.10)
                sp.setScrollMetric(sp.OvershootScrollDistanceFactor, 0.20)
                sp.setScrollMetric(sp.OvershootDragDistanceFactor, 0.10)
                sc.setScrollerProperties(sp)
            except Exception:
                pass
        except Exception:
            pass

    try:                                                                 # - row height & per-table padding
        if getattr(self, "vaultTable", None):
            vh = self.vaultTable.verticalHeader()
            if target:
                if vh and self._orig_row_height is None:
                    self._orig_row_height = vh.defaultSectionSize()
                if vh:
                    vh.setDefaultSectionSize(max((self._orig_row_height or 24), 40))
                self.vaultTable.setStyleSheet("QTableWidget::item{ padding:6px 8px; }")
            else:
                if vh and self._orig_row_height is not None:
                    vh.setDefaultSectionSize(self._orig_row_height)
                self.vaultTable.setStyleSheet("")
    except Exception:
        pass

    try:                                                                 # - accept/unaccept touch events
        self.setAttribute(Qt.WA_AcceptTouchEvents, bool(target))
    except Exception:
        pass

    # - commit state and (re)apply combined stylesheet
    self._touch_mode_active = bool(target)                                                       
    self._refresh_stylesheet()                                         

    try:                                                                # - sync checkbox without loops
        self.tuchmode_.blockSignals(True)
        self.tuchmode_.setChecked(self._touch_mode_active)
        self.tuchmode_2.setChecked(self._touch_mode_active)
        self.tuchmode_.blockSignals(False)
    except Exception:
        pass


def on_touch_mode_toggled_set(self, checked: bool):
    # apply immediately (enable when True, restore when False)
    self._touch_init_done = True
    self._enable_touch_mode(force=bool(checked))


def save_to_user_on_touch(self, checked: bool):
    self.set_status_txt(self.tr("Saving Touch mode {state}").format(state=checked))
    log.info(f"{kql.i('ui')} [UI] on touch mode toggled: {checked}")
    """User flipped the Touch Mode checkbox."""
    try:
        u = self._active_username()
        if u:
            set_user_setting(u, "touch_mode", bool(checked))
            update_baseline(username=u, verify_after=False, who=self.tr("TouchMode Settings Changed"))                
    except Exception:
        pass
    self.on_touch_mode_toggled_set(checked)
    self.set_status_txt(self.tr("Done"))

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
# --- breach value change
# ==============================
def enable_breach_checker_change(self, checked) -> None:
    self.set_status_txt(self.tr("Saving breach checker") + f" {checked}")
    """
    Handle the 'Password Breach Checker' toggle.
    - On first enable: show one-time consent modal (k-anonymity explanation).
    - Persist setting and update baseline.
    """
    log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} Breach Checker Change Called {checked}")
    self.reset_logout_timer()

    # Resolve user
    try:
        username = (self.currentUsername.text() or "").strip()
    except Exception:
        username = None

    if not username:
        log.debug(f"{kql.i('tool')} [WARN] {kql.i('warn')} Cannot update breach checker setting — user not found")
        # Best-effort: revert UI toggle if this came from a QCheckBox
        src = self.sender()
        try:
            if isinstance(src, QCheckBox) and bool(checked):
                src.blockSignals(True)
                src.setChecked(False)
                src.blockSignals(False)
        except Exception:
            pass
        return

    try:
        prior_ack_ts = get_user_setting(username, "hibp_ack_ts") or 0
    except Exception:
        prior_ack_ts = 0  # fallback if getter not available

    # If enabling and no prior consent, show the one-time consent
    if bool(checked) and not prior_ack_ts:
        if not self._show_hibp_consent_modal():
            # User cancelled — revert the UI toggle and do not persist
            src = self.sender()
            try:
                if isinstance(src, QCheckBox):
                    src.blockSignals(True)
                    src.setChecked(False)
                    src.blockSignals(False)
            except Exception:
                pass
            log.debug(f"{kql.i('tool')} [INFO] {kql.i('warn')} Breach checker enable cancelled by user")
            return
        # Persist the consent timestamp so we don’t show again
        try:
            import time as _t
            set_user_setting(username, "hibp_ack_ts", int(_t.time()))
        except Exception as e:
            log.debug(f"{kql.i('tool')} [WARN] {kql.i('warn')} Failed to persist hibp_ack_ts: {e}")

    # Persist the enabled/disabled state
    try:
        set_user_setting(username, "enable_breach_checker", bool(checked))
        self.enable_breach_checker = bool(checked)           
        update_baseline(username=username, verify_after=False, who=self.tr("Breach Check Settings Changed"))
        log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} Breach Checker setting persisted; baseline updated")
    except Exception as e:
        log.debug(f"{kql.i('tool')} [ERROR] {kql.i('err')} Failed to set breach checker enabled: {e}")
        # Best-effort: revert UI toggle to the last known good value
        src = self.sender()
        try:
            if isinstance(src, QCheckBox):
                src.blockSignals(True)
                src.setChecked(not bool(checked))
                src.blockSignals(False)
        except Exception:
            pass


# ==============================
# --- ontop
# ==============================
def on_enable_ontop_toggled(self, checked: bool) -> None:
    self.set_status_txt(self.tr("Saving ontop") + f" {checked}")
    log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('info')} ontop toggled: {checked}")
    try:
        self.reset_logout_timer()
    except Exception:
        pass

    username = self._active_username()
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


# ==============================
# --- ontop
# ==============================
