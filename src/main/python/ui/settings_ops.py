"""Keyquorum Vault
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

# This module contains methods extracted from main.py to reduce file size.
# We intentionally "inherit" main module globals so the moved code can run unchanged.
import sys as _sys
from tkinter import E
from auth.login.login_handler import set_user_setting, get_user_setting, get_user_record
from new_users.tour import maybe_show_quick_tour
from features.backup_advisor.backup_advisor import BackupAdvisor
from ui.ui_flags import _maybe_show_release_notes
from security.secure_audit import log_event_encrypted
from auth.identity_store import get_login_backup_count_quick, get_2fa_backup_count_quick
from security.preflight import load_security_prefs 
from device.utils_device import get_device_fingerprint
from app.dev import dev_ops

is_dev = dev_ops.dev_set
DEBUG_ON = dev_ops.DEBUG_ON


_MAIN = (
    _sys.modules.get("__main__")
    or _sys.modules.get("main")
    or _sys.modules.get("app.app_window")
    or _sys.modules.get("app_window")
)
if _MAIN is not None:
    globals().update(_MAIN.__dict__)

# Safety net: ensure Qt symbols exist even when __main__ differs (e.g., frozen builds)
try:
    from app.qt_imports import *  # noqa: F401,F403
except Exception:
    pass


def load_setting(self, *args, **kwargs):
    log.debug(f"{kql.i('tool')} [SETTINGS] loading settings")
    self.set_status_txt(self.tr("Loading Settings"))
    self._init_language_from_file()
    user = self._active_username()

    # --- Device fingerprint → encrypted audit log (best-effort) ---
    try:
        fp, ctx = get_device_fingerprint()
        self.set_status_txt(self.tr("Loading Settings: System Finger"))

        # Hide fingerprint & identifiers if running in dev mode
        if is_dev:
            safe_fp = "****"
            safe_device = "DEV-DEVICE"
            safe_os = ctx.get("os", "") or "dev_os"
            safe_release = ctx.get("release", "") or ""
            safe_arch = ctx.get("arch", "") or ""
        else:
            safe_fp = fp
            safe_device = ctx.get("deviceName", "")
            safe_os = ctx.get("os", "")
            safe_release = ctx.get("release", "")
            safe_arch = ctx.get("arch", "")

        # Compose final message
        msg = (
            f"login: device_fp={safe_fp} "
            f"device={safe_device} "
            f"os={safe_os} {safe_release} {safe_arch}"
        )

        log_event_encrypted(user, "login", msg)
    except Exception as e:
        log.debug(f"[audit] device finger error {e}")

    # --- Defaults (code-side fallbacks) ---
    threshold = 5
    self.expiry_days = 60
    self.clipboard_clear_timeout_sec = 20
    self.auto_logout_timeout_sec = 200
    self.enable_breach_checker = False
    self.debug_set = False
    self.zoom_factor = 1.0
    self.ontop = False
    self.enableWinDefCheckbox = False
    self.DefenderQuickScan = False
    self.set_touch = False
    self.offer_tour_on_first_login = False
    self.auto = False
    self.cloud_wrap = False
    self.cloud_enabled = False

    # --- Helper to set widget value safely without emitting signals ---
    def _set(widget_name: str, setter: str, value):
        w = getattr(self, widget_name, None)
        if w is None:
            return
        try:
            if hasattr(w, "blockSignals"):
                w.blockSignals(True)
            getattr(w, setter)(value)
        finally:
            if hasattr(w, "blockSignals"):
                w.blockSignals(False)

    rec: dict = {}
    settings: dict = {}

    try:
        try:
            rec = get_user_record(user)
        except Exception as e:
            log.info(f"{kql.i('tool')} load_setting get_user_record error: {e}")
            rec = get_user_setting(user, "all") or {}

        if isinstance(rec, dict):
            settings.update(rec.get("settings", {}))
        else:
            log.error(f"{kql.i('tool')} [ERROR] user record not dict; using defaults.")
    except Exception as e:
        log.error(
            f"{kql.i('tool')} [ERROR] {kql.i('err')} "
            f"Load user settings failed, using defaults. Error: {e}"
        )

    # --- Read values (already clamped for Free) ---
    try:
        threshold = int(settings.get("lockout_threshold", 5))
        self.expiry_days = int(settings.get("password_expiry_days", 90))
        self.clipboard_clear_timeout_sec = int(
            settings.get("clipboard_clear_timeout_sec", 15)
        )
        self.auto_logout_timeout_sec = int(
            settings.get("auto_logout_timeout_sec", 300)
        )
        self.enable_breach_checker = bool(settings.get("enable_breach_checker", False))
        self.zoom_factor = float(settings.get("zoom_factor", 1.0))
        self.ontop = bool(settings.get("ontop", False))
        self.enableWinDefCheckbox = bool(settings.get("WinDefCheckbox", False))
        self.DefenderQuickScan = bool(settings.get("DefenderQuickScan", False))
        self.set_touch = bool(settings.get("touch_mode", False))
        self.offer_tour_on_first_login = bool(
            settings.get("offer_tour_on_first_login", False)
        )

        # debug flag: force-on in dev, else from settings (default False)
        if is_dev and DEBUG_ON:
            self.debug_set = True
            log.info(f"{kql.i('debug')} [DEBUG] Debug forced ON in dev mode")
        else:
            self.debug_set = bool(settings.get("debug_set", False))

        try:
            self.enable_debug_logging_change(bool(self.debug_set))
        except Exception as e:
            log.error(
                f"{kql.i('tool')} [ERROR] {kql.i('err')} "
                f"Failed to apply logging prefs: {e}"
            )

        # --- Recovery mode label (best-effort) ---
        recovery_mode = None
        if isinstance(rec, dict):
            recovery_mode = rec.get("recovery_mode", None)

        if recovery_mode is False:
            self.recovery_m.setText(self.tr("🔐 Maximum Security (no recovery)"))
        elif recovery_mode is True:
            self.recovery_m.setText(self.tr("🔐 Recovery Mode"))

        # --- Cloud prefs (per-user) ---
        try:
            cloud = (rec.get("cloud") if isinstance(rec, dict) else None) or {}
        except Exception as e:
            log.error(f"{kql.i('tool')} [ERROR] settings cloud data error: {e}")
            cloud = {}

        self.auto = bool(
            get_user_setting(
                user,
                "auto_sync",
                cloud.get("sync_enable", cloud.get("auto_sync", False)),
            )
        )
        self.cloud_wrap = bool(cloud.get("cloud_wrap", False))
        self.cloud_enabled = bool(cloud.get("enabled", False))

        # --- Cloud sync status labels (Settings → Cloud Sync) ---
        if cloud:
            try:
                from features.sync.sync_ops import _update_cloudsync_label
                _update_cloudsync_label(self, user)
            except Exception as e:
                log.error(f"cloud label update: {e}")

        # --- Backup counts (labels) ---
        try:
            _login_left = get_login_backup_count_quick(user)
            _2fa_left = get_2fa_backup_count_quick(user)
            if hasattr(self, "bkup_left_"):
                self.bkup_left_.setText(
                    self.tr("Forgot Password/Yubi Key Backup Codes Left: {_login_left}/5").format(
                        _login_left=_login_left
                    )
                )
            if hasattr(self, "bkup_left_1"):
                self.bkup_left_1.setText(
                    self.tr("2FA Backup Codes Left: {_2fa_left}/5").format(
                        _2fa_left=_2fa_left
                    )
                )
        except Exception as e:
            log.error(f"{kql.i('tool')} [ERROR] Could not update backup counts: {e}")

    except Exception as e:
        log.error(
            f"{kql.i('tool')} [ERROR] {kql.i('err')} Failed to read/apply settings: {e}"
        )

    # --- Push values to UI ---
    # We have two independent preflight modes:
    #  - Startup (global, before a user is selected)
    #  - Login   (per-user, after username is entered, before unlocking)
    global_prefs = load_security_prefs(None)  # resolves to shared "default" file
    user_prefs = load_security_prefs(user) if user else {}

    enable_preflight_startup = bool(
        global_prefs.get("enable_preflight_startup", global_prefs.get("enable_preflight", False))
    )
    enable_preflight_login = bool(
        user_prefs.get("enable_preflight_login", user_prefs.get("enable_preflight", False))
    )

    check_av_startup = bool(global_prefs.get("check_av_startup", global_prefs.get("check_av", False)))
    check_av_login = bool(user_prefs.get("check_av_login", user_prefs.get("check_av", False)))

    defender_qs_startup = bool(
        global_prefs.get("defender_quick_scan_startup", global_prefs.get("defender_quick_scan", False))
    )
    defender_qs_login = bool(
        user_prefs.get("defender_quick_scan_login", user_prefs.get("defender_quick_scan", False))
    )
    self.set_status_txt(self.tr("Set Settings"))

    _set("ontop_", "setChecked", bool(self.ontop))

    # Login controls
    _set("enablePreflightCheckbox", "setChecked", enable_preflight_login)
    _set("enablePreflightCheckbox_", "setChecked", enable_preflight_login)   # legacy/back-compat
    _set("enablePreflightCheckbox_1", "setChecked", enable_preflight_login)  # newer UI (explicit login)

    _set("enableWinDefCheckbox_", "setChecked", check_av_login)
    _set("enableWinDefCheckbox_1", "setChecked", check_av_login)

    _set("DefenderQuickScan_", "setChecked", defender_qs_login)
    _set("DefenderQuickScan_1", "setChecked", defender_qs_login)

    _set("preflight_check_now_1", "setEnabled", True)

    # Startup controls
    _set("enablePreflightCheckbox_2", "setChecked", enable_preflight_startup)
    _set("enableWinDefCheckbox_2", "setChecked", check_av_startup)
    _set("DefenderQuickScan_2", "setChecked", defender_qs_startup)
    _set("lockoutSpinBox", "setValue", int(threshold))
    _set("password_expiry_days", "setValue", int(self.expiry_days))
    _set("clipboard_clear_timeout_", "setValue", int(self.clipboard_clear_timeout_sec))
    _set("auto_logout_timeout_", "setValue", int(self.auto_logout_timeout_sec))
    _set("enable_breach_checker_", "setChecked", bool(self.enable_breach_checker))
    _set("debug_set_", "setChecked", bool(self.debug_set))
    _set("zoom_factor_", "setValue", float(self.zoom_factor))
    _set("autosync_", "setChecked", bool(self.auto))

    # manually wipe rec (avoid accidental reuse later)
    rec = {}

    # --- Bridge autostart (opt-in; default OFF) ---
    try:
        autostart = False
        try:
            autostart = bool(get_user_setting(user, "autostart_bridge"))
        except Exception:
            autostart = False

        _set("autoStartBridgeCheck", "setChecked", bool(autostart))

        if hasattr(self, "autoStartBridgeCheck") and self.autoStartBridgeCheck is not None:
            try:
                self.autoStartBridgeCheck.toggled.disconnect()
            except Exception:
                pass
            from bridge.bridge_ops import on_toggle_autostart_bridge
            self.autoStartBridgeCheck.toggled.connect(lambda t: on_toggle_autostart_bridge(self, t))

        # Conservative: do not auto-start unless explicitly checked by user
        if autostart:
            try:
                from bridge.bridge_helpers import ensure_bridge_token
                from bridge.bridge_ops import start_bridge_server, start_bridge_monitoring
                tok = ensure_bridge_token(user, new=False)
                if tok:
                    start_bridge_server(self, strict=None)
                    start_bridge_monitoring(self)
                    log.info("[BRIDGE] Autostart enabled by user; server started on 127.0.0.1")
            except Exception as e:
                log.error(f"[BRIDGE] Autostart failed: {e}")
    except Exception as e:
        log.error(f"[SETTINGS] Bridge autostart section failed: {e}")

    # --- Touch mode ---
    if self.set_touch is not None:
        self._enable_touch_mode(force=self.set_touch)

    # --- Timers ---
    self.set_status_txt(self.tr("Loading set: Timers"))
    self.clipboard_timeout = int(self.clipboard_clear_timeout_sec) * 1000
    self.logout_timeout = int(self.auto_logout_timeout_sec) * 1000
    log.debug(
        f"{kql.i('tool')} [SETTINGS] {kql.i('time')} "
        f"Clipboard timeout: {self.clipboard_timeout} ms"
    )
    log.debug(
        f"{kql.i('tool')} [SETTINGS] {kql.i('time')} "
        f"Auto logout timeout: {self.logout_timeout} ms"
    )
    log.debug(
        f"{kql.i('tool')} [SETTINGS] {kql.i('shield')} "
        f"Enable breach checker: {self.enable_breach_checker}"
    )
    log.debug(
        f"{kql.i('tool')} [SETTINGS] {kql.i('user')} Zoom factor: {self.zoom_factor}"
    )

    # --- Auto-logout + topmost ---
    self.set_status_txt(self.tr("Loading set: Auto-logout"))
    self.setup_auto_logout()
    self.set_topmost_no_flash(self.ontop)

    # --- Cloud UI enablement ---
    try:
        from features.sync.sync_ops import enable_buttons, disable_buttons
        if self.cloud_enabled:
            self.set_status_txt(self.tr("Loading set: Cloud UI Enablement"))
            enable_buttons(self)
        else:
            disable_buttons(self)
    except Exception as e:
        log.error(f"{kql.i('tool')} [ERROR] Cloud UI toggle failed: {e}")

    # --- Cloud engine init after successful login ---
    # DEBUG PATCH: configure only here. Do NOT arm watcher/timer from load_setting.
    try:
        log.warning("### DEBUG PATCH settings_ops.load_setting entered ###")
        log.warning(
            "### DEBUG PATCH settings_ops flags user=%r cloud_enabled=%r auto=%r ###",
            user,
            bool(getattr(self, "cloud_enabled", False)),
            bool(getattr(self, "auto", False)),
        )
        if bool(getattr(self, "cloud_enabled", False)):
            from features.sync.sync_ops import _configure_sync_engine

            user = self._active_username()
            if user:
                self.set_status_txt(self.tr("Loading set: Cloud Engine"))
                _configure_sync_engine(self, user, "load_setting")
                log.warning("### DEBUG PATCH settings_ops configured engine only after load_setting ###")
                log.info("[CLOUD] sync engine configured after load_setting (engine-only debug patch)")
                log.info("[AUTO-SYNC] load_setting intentionally did NOT arm watcher/timer")
            else:
                log.warning("### DEBUG PATCH settings_ops no active user during load_setting cloud init ###")
        else:
            log.info("[CLOUD] load_setting skipped cloud engine init (cloud disabled)")
    except Exception as e:
        log.error(f"[AUTO-SYNC] load_setting init failed: {e}")

    # --- Refresh tables/UI ---
    try:
        try:
            self.refresh_category_selector()
        except Exception:
            pass
        try:
            self.refresh_category_dependent_ui()
        except Exception:
            pass
    except Exception as e:
        log.error(f"{kql.i('tool')} [ERROR] Vault table load failed: {e}")

    # --- One-time 'What's New' popup ---
    try:
        # Slight delay so it appears after the main window is stable
        QTimer.singleShot(500, self._maybe_show_release_notes)
    except Exception:
        pass

    try:
        self.load_audit_table()
    except Exception as e:
        log.error(f"{kql.i('tool')} [ERROR] {kql.i('user')} Failed to load audit table: {e}")

    # --- Backup reminder prefs (per-user via QSettings) ---
    try:
        self.set_status_txt(self.tr("Backup reminder setup"))
        from features.backup_advisor.ui_backup_bind import init_backup_avisor
        init_backup_avisor(self)
        log.debug(f"[SETTINGS] Backup reminder mode={getattr(self, '_backup_remind_mode', 'both')}")

        pending = 0
        if hasattr(self, "backupAdvisor") and self.backupAdvisor:
            try:
                pending = int(self.backupAdvisor.pending_changes())
            except Exception:
                pending = 0
        self.changes_backup.setText(("(unbackedup changes counter") + f": {pending}).")
    except Exception as e:
        log.error(f"[SETTINGS] BackupAdvisor init failed: {e}")

    # --- First-time boot tour ---
    if self.offer_tour_on_first_login:
        self.logout_timeout = 0
        self.setup_auto_logout()
        try:
            set_user_setting(user, "offer_tour_on_first_login", False)
        except Exception as e:
            log.error(f"{kql.i('tool')} [ERROR] could not clear tour flag: {e}")
        try:
            from security.baseline_signer import update_baseline
            update_baseline(user, verify_after=False, who=self.tr("Tour Settings Changed"))
        except Exception as e:
            log.error(f"{kql.i('tool')} [ERROR] baseline/tour log failed: {e}")
        maybe_show_quick_tour("core")

    # --- Autofill: launch app before filling (opt-in; default OFF) ---
    try:
        self.set_status_txt(self.tr("AutoFill Setup"))
        launch_first = bool(get_user_setting(user, "autofill_launch_first") or False)

        # reflect UI WITHOUT emitting signals
        _set("launchBeforeAutofillCheck", "setChecked", launch_first)

        if (
            hasattr(self, "launchBeforeAutofillCheck")
            and self.launchBeforeAutofillCheck is not None
        ):
            # Connect exactly once; no disconnect = no RuntimeWarning
            if not getattr(self, "_wired_launch_autofill", False):
                try:
                    self.launchBeforeAutofillCheck.toggled.connect(
                        self.on_toggle_launch_before_autofill,
                        Qt.ConnectionType.UniqueConnection,
                    )
                except (TypeError, AttributeError):
                    self.launchBeforeAutofillCheck.toggled.connect(
                        self.on_toggle_launch_before_autofill
                    )
                self._wired_launch_autofill = True
    except Exception as e:
        log.error(f"{kql.i('tool')} [ERROR] Autofill launch-first init failed: {e}")

    self.set_status_txt(self.tr("Done"))
    log.debug(
        f"{kql.i('tool')} [SETTINGS] {kql.i('ok')} "
        f"Settings OK: topmost={self.ontop}, theme applied, categories refreshed"
    )


