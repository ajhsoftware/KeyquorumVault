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
from tkinter import E
from security.baseline_signer import update_baseline
import sys as _sys
import re as _re
import datetime as dt 
from vault_store.vault_store import load_vault, seed_vault
from vault_store.kdf_utils import derive_key_argon2id_from_buf
import http.client, json
import app.kq_logging as kql
import logging
import time
log = logging.getLogger("keyquorum")
from app.basic import get_app_version
from auth.identity_store import has_totp_quick, get_yubi_config, get_login_backup_count_quick
from auth.login.login_handler import (validate_login, _canonical_username_ci, get_user_setting, set_user_setting, reset_login_failures,
                                      set_recovery_mode, get_user_record, set_user_record, get_recovery_mode)
from features.clipboard.secure_clipboard import install_clipboard_guard
from app.paths import (debug_log_paths, config_dir, icon_file)
from auth.windows_hello.session import save_device_unlock_v4_from_session
from app.basic import _UiBus
from security.secure_audit import log_event_encrypted
from auth.tfa.twofactor import has_recovery_wrap, get_wrapped_key_path
from ui.ui_flags import maybe_warn_windows_clipboard
from device.utils_device import get_device_fingerprint
from auth.yubi.yubikeydialog import YubiKeySetupDialog
from ui_gen.emergency_kit_dialog import EmergencyKitDialog
from auth.yubi.yk_backend import set_probe_enabled
from app.paths import user_log_file
# - how long to wait before showing recovery or failed screen 
PRESENCE_GRACE_SECS = 25.0
from features.auth_store.auth_ops import _auth_set_enabled, _auth_after_login 
from bridge.bridge_helpers import ensure_bridge_token
from typing import Union
import socket

try:
    import cv2  # OpenCV for QR decoding
except Exception:
    cv2 = None

from app.dev import dev_ops
is_dev = dev_ops.dev_set

# --- app_window attribute access (avoid circular imports) ----------------------
def _aw(name, default=None):
    """Get an attribute from the running main module (app_window executed as __main__)."""
    m = (
        _sys.modules.get("__main__")
        or _sys.modules.get("main")
        or _sys.modules.get("app.app_window")
        or _sys.modules.get("app_window")
    )
    if m is None:
        return default
    return getattr(m, name, default)

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


_KQ_SETTINGS_ORG = "AJHSoftware"
_KQ_SETTINGS_APP = "KeyquorumVault"


def tr(text: str) -> str:
    """Qt translation helper scoped to the Watchtower UI."""
    return QCoreApplication.translate("uiwatchtower", text)


def _derive_vault_key_for_user(username: str, pw_buf: bytearray, salt: bytes) -> bytes:
    """Derive the password-side vault key using the account's authoritative KDF profile.

    This must match the KDF used by normal password login / account creation /
    WRAP enable. Using the legacy default derivation here can make Yubi WRAP
    unwrap fail immediately after enable on KDF v2+ accounts.
    """
    from auth.login.login_handler import get_user_record
    from vault_store.kdf_utils import normalize_kdf_params
    from native.native_core import get_core

    core = get_core()
    if not core:
        raise RuntimeError("Native core not loaded")

    try:
        rec = get_user_record(username) or {}
        kdf = normalize_kdf_params(rec.get("kdf") or {}) if isinstance(rec, dict) else {"kdf_v": 1}
    except Exception:
        kdf = {"kdf_v": 1}

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

# ==============================
# --- YubiKey 2-of-2 / 2FA
# ==============================

# Handler for YubiKey enable completion. Shows recovery key if WRAP, updates UI and logs event.
def _on_enable_finished(self, res: dict):
    """
    Handle YubiKey enable completion (wrap or gate).
    Called when YubiKeySetupDialog emits done().
    """
    if not (res and res.get("ok")):
        return
    username = self._active_username()
    mode = res.get("mode", "").lower()
    rk = res.get("recovery_key")
    yubi_codes = res.get("backup_codes") or []
    if mode == "wrap":
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

# Handler for YubiKey Setup button click. Opens the YubiKeySetupDialog and processes results.
def on_yk_setup_clicked(self):
    self.set_status_txt(self.tr("YubiKey Setup"))
    uname = self._active_username()
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

    dlg = YubiKeySetupDialog(self, uname, getattr(self, 'core_session_handle', None), identity_password=identity_pwd)
    dlg.finished_setup.connect(lambda res: _on_enable_finished(self, res))
    self._track_window(dlg)
    dlg.exec()
    identity_pwd = ""

# Refresh recovery controls based on current YubiKey and 2FA state. Called after YubiKey changes and on login.
def refresh_recovery_controls(self) -> None:
    username = self._active_username()
    is_rm = bool(get_recovery_mode(username))        # authoritative
    has_rk = has_recovery_wrap(username)             # wrapped key present
    has_mk = bool(getattr(self, 'core_session_handle', None))    # unlocked

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

# Helper to check if YubiKey 2FA (Gate/Wrap) is enabled for a user, with flexible context handling.
def yk_twofactor_enabled(username: str, password_or_kek: str | bytes | None = None):

    """Return (mode, yubi_dict) for the given user.

    This helper is intentionally **bytes-safe** so DPAPI passwordless logins can
    still detect YubiKey Gate/Wrap without a plaintext password.

    - If `password_or_kek` is `str`: treats it as the user's password.
    - If `password_or_kek` is `bytes`: treats it as a pre-derived identity-store KEK.
    - If `None`: uses the public header-only config (mode only).
    """

    try:
        # Fast header-only mode detection (no secrets)
        try:
            from auth.identity_store import get_yubi_config_public
            pub = get_yubi_config_public(username) or {}
            mode = (pub.get("mode") or "").strip() or None
        except Exception:
            mode = None

        # If we don't have a key context, return mode only
        if password_or_kek is None:
            return mode, None

        # If we only have a bytes-context (DPAPI passwordless), do NOT attempt to decrypt
        # the private identity payload here (get_yubi_config expects a plaintext password).
        # The public header-only mode is enough to enforce Gate/Wrap decisions.
        if isinstance(password_or_kek, (bytes, bytearray, memoryview)):
            return mode, None
        # If we do have password/KEK context, load full yubi dict
        try:
            yubi = get_yubi_config(username, password_or_kek)  
        except Exception:
            yubi = None

        # Prefer the full config's mode if present
        try:
            if isinstance(yubi, dict):
                m2 = (yubi.get("mode") or "").strip()
                if m2:
                    mode = m2
        except Exception:
            pass

        return mode, yubi if isinstance(yubi, dict) else None
    except Exception:
        return None, None

# Toggle 2FA setting with sensitive action gate (password + optional YubiKey + optional 2FA). 
# Handles both enable and disable flows, with appropriate checks and fallbacks.
def toggle_2fa_setting(self, checked: bool):
    self.set_status_txt(self.tr("2FA saving") + f" {checked}")

    try:
        from qtpy.QtWidgets import QMessageBox
    except Exception:
        # If QMessageBox isn't available, revert and bail safely
        try:
            self.twoFACheckbox.blockSignals(True)
            self.twoFACheckbox.setChecked(not checked)
            self.twoFACheckbox.blockSignals(False)
        except Exception:
            pass
        return

    log.debug(str(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} toggle 2FA setting called with value: {checked}"))

    username = self._active_username()
    if not username:
        self.safe_messagebox_warning(self, self.tr("No User"), self.tr("Please log in before changing 2FA settings."))
        self.twoFACheckbox.blockSignals(True)
        self.twoFACheckbox.setChecked(not checked)
        self.twoFACheckbox.blockSignals(False)
        log.debug(str(f"{kql.i('tool')} [WARN] {kql.i('warn')} user not found/reset"))
        return

    # ------------------------
    # WRAP warning (do NOT block by default): enabling TOTP does NOT bypass WRAP
    # ------------------------
    if checked:
        yubi_mode = ""
        try:
            from auth.identity_store import get_yubi_config_public
            pub = get_yubi_config_public(username) or {}
            yubi_mode = (pub.get("mode") or "").strip().lower()
        except Exception:
            yubi_mode = ""

        if yubi_mode == "yk_hmac_wrap":
            ans = QMessageBox.warning(
                self,
                self.tr("Two-Factor Authentication"),
                self.tr(
                    "YubiKey WRAP is enabled on this account.\n\n"
                    "Important: Authenticator 2FA will NOT bypass WRAP.\n"
                    "If your YubiKey is lost, only your Recovery Key + Password can unwrap your vault.\n\n"
                    "Do you still want to enable Authenticator 2FA for login protection?"
                ),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if ans != QMessageBox.Yes:
                self.twoFACheckbox.blockSignals(True)
                self.twoFACheckbox.setChecked(False)
                self.twoFACheckbox.blockSignals(False)
                return

    # ------------------------
    # Sensitive re-auth: enabling/disabling 2FA needs the user's password
    # - enabling: 2FA isn't enabled yet, so don't require 2FA check
    # - disabling: 2FA is enabled, so require it
    # ------------------------
    try:
        password = self.verify_sensitive_action(
            username,
            title=self.tr("Two-Factor Authentication"),
            return_pw=True,
            require_password=True,
            twofa_check=(not checked),  # disable -> True, enable -> False
            yubi_check=True,
        )
    except TypeError:
        # Backward compatibility if verify_sensitive_action() doesn't have require_password yet
        password = self.verify_sensitive_action(
            username,
            title=self.tr("Two-Factor Authentication"),
            return_pw=True,
            twofa_check=(not checked),
            yubi_check=True,
        )

    if not password:
        # revert UI to previous state (user cancelled / failed verification)
        self.twoFACheckbox.blockSignals(True)
        self.twoFACheckbox.setChecked(not checked)
        self.twoFACheckbox.blockSignals(False)
        return

    if checked:
        # If already enabled per identity, reset first
        if has_totp_quick(username):
            QMessageBox.information(
                self,
                self.tr("Two-Factor Authentication"),
                self.tr(
                    "2FA is already enabled — resetting now.\n\n"
                    "Please delete the old Keyquorum entry in your authenticator app"
                ),
            )
            try:
                self.disable_twofa(username, password=password)
            except Exception as e:
                log.error(f"{kql.i('tool')} [ERROR] {kql.i('err')} Trying to remove old 2FA: {e}")

        try:
            from auth.tfa.twofa_dialog import twofa_setup
            ok2fa = twofa_setup(self, username, pwd=password)
            # log.info(f"ok2fa = {ok2fa}")
        except Exception as e:
            log.error("%s -> %s [2FA] Setup error during signup for '%s': %s", kql.i('auth'), kql.i('err'), username, e)
            ok2fa = {"ok": False, "error": str(e)}

        if not (isinstance(ok2fa, dict) and ok2fa.get("ok")):
            self.twoFACheckbox.blockSignals(True)
            self.twoFACheckbox.setChecked(False)
            self.twoFACheckbox.blockSignals(False)

            try:
                self.regen_key_both.setEnabled(True)
                self.regen_key_2fa.setEnabled(True)
                self.regen_key_2fa_2.setEnabled(True)
            except Exception:
                pass

            self.safe_messagebox_warning(
                self,
                self.tr("Two-Factor Authentication"),
                self.tr("Two-factor setup was not completed. The setting has not been enabled."),
            )
            return

        # Emergency kit
        try:
            from login.auth_flow_ops import emg_ask
            emg_ask(self,
                username=username,
                twofa_backup_codes=(ok2fa.get("backup_codes") or []),
                totp_uri=ok2fa.get("otpauth_uri"),
                totp_secret_plain=ok2fa.get("secret"),
                totp_qr_png=ok2fa.get("qr_png"),
            )
        except Exception as e:
            log.error("%s [2FA] Emergency Kit generation error: %s", kql.i('err'), e)

        msg = self.tr("{ok} User Enabled 2FA").format(ok=kql.i('ok'))
        try:
            log_event_encrypted(username, self.tr("2FA"), msg)
        except Exception:
            pass

        try:
            update_baseline(username=username, verify_after=False, who=self.tr("User 2FA Changed"))
        except Exception:
            log.error(f"{kql.i('err')} [BASELINE] Error updating baseline")

    else:
        if not self.disable_twofa(username, password=password):
            # revert UI if disable failed
            self.twoFACheckbox.blockSignals(True)
            self.twoFACheckbox.setChecked(True)
            self.twoFACheckbox.blockSignals(False)
            return

        msg = self.tr("{ok} User Disabled 2FA").format(ok=kql.i('ok'))
        try:
            log_event_encrypted(username, self.tr("2FA"), msg)
        except Exception:
            pass

        try:
            update_baseline(username=username, verify_after=False, who=self.tr("User 2FA Changed"))
        except Exception:
            log.error(f"{kql.i('err')} [BASELINE] Error updating baseline")

    # Reflect live identity state in the checkbox (don’t emit)
    live = bool(has_totp_quick(username))
    self.twoFACheckbox.blockSignals(True)
    self.twoFACheckbox.setChecked(live)
    self.twoFACheckbox.blockSignals(False)

    # Best-effort clear
    password = ""
    self.set_status_txt(self.tr("Done"))

# Sensitive action gate: password + optional 2FA + optional YubiKey. Used for critical actions like enabling 2FA, exporting vault, etc.
def verify_sensitive_action(
    self,
    username: str,
    *,
    title: str = None,
    return_pw: bool = False,
    require_password: bool = False,   # <--- NEW
    twofa_check: bool = True,
    yubi_check: bool = True,
) -> Union[bool, str]:
    """
    Sensitive-action gate.

    If require_password=True:
        Always prompt + verify password (YubiKey can be extra).
        If return_pw=True -> returns the password on success.

    If require_password=False:
        May allow YubiKey-only success when available (fast confirm).
    """
    try:
        from qtpy.QtWidgets import QMessageBox
    except Exception:
        return False

    if title is None:
        title = self.tr("Confirm Action")

    username = (username or "").strip()
    if not username:
        return False

    # --- 0) TOTP enabled? ---
    totp_enabled = False
    try:
        from auth.tfa.twofactor import has_totp_enabled
        totp_enabled = bool(has_totp_enabled(username))
    except Exception:
        totp_enabled = False

    # --- 1) YubiKey quick gate (only allowed to short-circuit when password is NOT required) ---
    if yubi_check and hasattr(self, "_yk_quick_gate"):
        try:
            msg = self.tr(
                "For the security of this account '{user}',\n\n"
                "please touch your YubiKey to confirm this action."
            ).format(user=username)
            QMessageBox.information(self, title, msg)

            ok_yk = bool(self._yk_quick_gate(username))
            if not ok_yk:
                QMessageBox.warning(self, title, self.tr("YubiKey confirmation failed or was cancelled."))
                return False

            if not require_password:
                # YubiKey-only is acceptable for this action
                return "" if return_pw else True
            # else: continue (YubiKey becomes an extra layer)
        except Exception:
            # Fall back to password/2FA
            pass

    # --- 2) Password (REQUIRED for actions like enabling 2FA) ---
    pwd = self._prompt_account_password(username)
    if not pwd:
        return False

    try:
        if not validate_login(username, pwd):
            QMessageBox.critical(self, title, self.tr("Incorrect password."))
            return False
    except Exception:
        QMessageBox.critical(self, title, self.tr("Password verification is unavailable."))
        return False

    # --- 3) Optional 2FA check (if enabled) ---
    if twofa_check and totp_enabled:
        try:
            from auth.tfa.twofa_dialog import prompt_2fa_for_user
            msg = self.tr(
                "For the security of this account '{user}',\n\n"
                "please enter your 2FA verification code."
            ).format(user=username)

            QMessageBox.information(self, self.tr("Two-Factor Authentication"), msg)

            if not prompt_2fa_for_user(self, username):
                QMessageBox.warning(self, title, self.tr("Two-factor authentication was not completed."))
                return False
        except Exception:
            QMessageBox.critical(self, title, self.tr("Two-factor verification is unavailable."))
            return False

    return pwd if return_pw else True



# ===============================
# --- backup code
# ===============================

# Note: backup codes are a safety net, not a primary factor, so we allow the user to bypass the warning
def check_backup_codes_ok(self, username: str, b_type: str | None = "both") -> None:
    """
    Ensure the user has sufficient backup codes for the requested type.
    If only 0–1 left, offer to regenerate and show the Emergency Kit dialog.
    Supports a per-type 'Don't show again' preference.

    b_type:
      - "yubi"  -> YubiKey Gate/Wrap backup codes (only if yubi enabled)
      - "2fa"   -> TOTP/2FA backup codes (only if 2FA enabled)
      - None / "" / "both" / "all" / "auto" -> check all relevant types
    """
    try:
        log.debug("[B-CODE] Backup Check")
        username = (username or "").strip()
        if not username:
            return

        b_in = (b_type or "").strip().lower()

        # Auto / both: check 2FA then Yubi (but each worker will skip if not enabled)
        if b_type is None or b_in in ("", "both", "all", "auto"):
            try:
                _check_backup_codes_ok_one(self, username, "2fa")
            except Exception as e:
                log.debug("[B-CODE] 2fa check failed: %s", e)
            try:
                _check_backup_codes_ok_one(self, username, "yubi")
            except Exception as e:
                log.debug("[B-CODE] yubi check failed: %s", e)
            return
        _check_backup_codes_ok_one(self, username, b_in)

    except Exception as e:
        log.error("check_backup_codes_ok failed: %s", e)

# Internal worker for check_backup_codes_ok: checks one type ('yubi' or '2fa'), with all the logic for determining enabled state, 
# remaining codes, and showing the appropriate warning dialog.
def _check_backup_codes_ok_one(self, username: str, b_type: str) -> None:
    """Internal worker: checks exactly one type ('yubi' or '2fa')."""
    from auth.identity_store import (
        get_login_backup_count_quick,
        get_2fa_backup_count_quick,
        get_yubi_config_public,
    )

    try:
        from auth.login.login_handler import is_2fa_enabled as _is_2fa_enabled
    except Exception:
        _is_2fa_enabled = None

    # --- normalise type ---
    b = (b_type or "yubi").strip().lower()
    if b not in ("yubi", "2fa"):
        b = "yubi"

    try:
        self.set_status_txt(self.tr("Checking Backup Codes"))
    except Exception:
        pass

    # -------
    # Skip irrelevant checks (only warn if factor enabled)
    # -------
    if b == "yubi":
        try:
            # ✅ best: reads header.meta.yubi_enabled / yubi_mode
            from auth.identity_store import get_yubi_meta_quick
            yubi_enabled, yubi_mode = get_yubi_meta_quick(username)
            # treat having a mode as enabled too (defensive)
            yubi_enabled = bool(yubi_enabled or yubi_mode)
        except Exception:
            yubi_enabled = False
        if not yubi_enabled:
            log.debug("[B-CODE] yubi check skipped (not enabled) user=%s", username)
            return

    if b == "2fa":
        try:
            # quick proxy: if any 2fa backup codes exist, it's enabled;
            # stronger: also check TOTP enabled if helper exists
            cnt = int(get_2fa_backup_count_quick(username) or 0)
            twofa_enabled = bool(cnt > 0)
            if _is_2fa_enabled is not None:
                twofa_enabled = bool(twofa_enabled or _is_2fa_enabled(username))
        except Exception:
            twofa_enabled = False

        if not twofa_enabled:
            log.debug("[B-CODE] 2fa check skipped (not enabled) user=%s", username)
            return

    # -------
    # Now compute remaining + per-type UI strings/settings
    # -------
    if b == "2fa":
        human = "2FA"
        suppress_key = "suppress_backup_warning_2fa"
        emg_field = "twofa_backup_codes"
        remaining = int(get_2fa_backup_count_quick(username) or 0)
        log.debug("[B-CODE] 2fa remaining user=%s left=%s", username, remaining)
    else:
        human = "YubiKey"
        suppress_key = "suppress_backup_warning_login"
        emg_field = "recovery_backup_codes"
        remaining = int(get_login_backup_count_quick(username) or 0)
        log.info("[B-CODE] yubi remaining user=%s left=%s", username, remaining)

    # Respect per-type suppression
    try:
        suppressed = bool(get_user_setting(username, suppress_key, False))
    except Exception:
        suppressed = False

    log.debug(
        "Backup-codes check: user=%s type=%s remaining=%s suppressed=%s",
        username, b, remaining, suppressed
    )

    if suppressed:
        return

    # Enough codes? bail
    if remaining >= 2:
        return

    # Title/body per count
    if remaining == 1:
        title = f"{human} " + self.tr("Backup Codes Low")
        text = (
            self.tr("You have only 1") + f" {human.lower()} " + self.tr("backup code left.\n\n")
            + self.tr(
                "If this last code is used or lost and your primary login method is unavailable, "
                "you may be unable to access your account."
            )
            + "\n\n"
            + self.tr(
                "To reduce the risk of lockout, it is strongly recommended that you "
                "generate a new set of backup codes now."
            )
            + "\n\n"
            + self.tr("Old codes will be permanently invalidated.")
            + "\n\n"
            + self.tr("You can also regenerate them later from Settings → Profile.")
        )
    else:
        title = self.tr("No ") + f"{human}" + self.tr(" Backup Codes Left")
        text = (
            self.tr("You have no ") + f"{human.lower()}" + self.tr(" backup codes left.\n\n")
            + self.tr(
                "If your primary login method becomes unavailable, "
                "you may be unable to access your account."
            )
            + "\n\n"
            + self.tr(
                "To avoid the risk of lockout, it is strongly recommended that you "
                "generate a new set of backup codes now."
            )
            + "\n\n"
            + self.tr("Old codes will be permanently invalidated.")
            + "\n\n"
            + self.tr("You can also regenerate them later from Settings → Profile.")
        )

    # Custom QMessageBox so we can add a checkbox
    msg = QMessageBox(self)
    msg.setWindowTitle(title)
    msg.setText(text)
    msg.setIcon(QMessageBox.Warning)
    yes_btn = msg.addButton(self.tr("Regenerate Now"), QMessageBox.YesRole)
    msg.addButton(self.tr("Later"), QMessageBox.NoRole)

    dont_show = QCheckBox(self.tr("Don't show again for this warning"))
    msg.setCheckBox(dont_show)

    msg.exec()
    reply = msg.clickedButton()

    # Persist suppression per type if checked
    if dont_show.isChecked():
        try:
            set_user_setting(username, suppress_key, True)
        except Exception:
            pass

    # Regenerate on Yes
    if reply != yes_btn:
        return

    # ---- Collect password (needed to write identity payload) ----
    pwd = getattr(self, "current_password", None)

    if not pwd:
        # Use existing confirmation flow (handles yubi/2fa policies)
        try:
            pw = self._confirm_sensitive_action(
                username=username,
                title=self.tr("Confirm Password"),
                require_password=True,
                twofa_check=False,
                yubi_check=False,
                return_pw=True,
            )
            if isinstance(pw, str) and pw:
                pwd = pw
        except Exception:
            pwd = None

    if not pwd:
        msg_txt = (
            self.tr("Enter password for ") + f"'{username}'"
            + self.tr(" to generate new ") + f"{human} " + self.tr("backup codes:")
        )
        pwd, ok = QInputDialog.getText(self, self.tr("Confirm Password"), msg_txt, QLineEdit.Password)
        if not ok or not pwd:
            QMessageBox.information(self, self.tr("Cancelled"), self.tr("Backup code regeneration cancelled."))
            return

    # ---- Generate + persist; we expect plaintext codes returned (show once) ----
    new_codes = None
    try:
        new_codes = on_generate_recovery_key_clicked(self, b, password_for_identity=pwd)
    except TypeError:
        # Backward-compat if function signature doesn't accept password_for_identity
        new_codes = self.on_generate_recovery_key_clicked(self, b)

    if not new_codes or not isinstance(new_codes, list):
        # If  handler shows its own UI and doesn't return codes,
        # we can’t show Emergency Kit reliably.
        QMessageBox.information(
            self,
            self.tr("Backup Codes Updated"),
            self.tr("Backup codes were updated."),
        )
        return

    # Show in Emergency Kit with the correct field
    try:
        if emg_field == "recovery_backup_codes":
            self.emg_ask(
                username=username,
                recovery_backup_codes=new_codes,
                twofa_backup_codes=None,
                totp_secret_plain=None,
                totp_uri=None,
                totp_qr_png=None,
            )
        else:
            self.emg_ask(
                username=username,
                recovery_backup_codes=None,
                twofa_backup_codes=new_codes,
                totp_secret_plain=None,
                totp_uri=None,
                totp_qr_png=None,
            )
    except Exception:
        # fallback
        QMessageBox.information(
            self,
            f"{human}" + self.tr(" Backup Codes Updated"),
            self.tr("Generated ") + f"{len(new_codes)} {human} " + self.tr(" backup codes.\nPlease store them safely."),
        )

    # Re-check remaining
    try:
        if b == "yubi":
            remaining_after = int(get_login_backup_count_quick(username) or 0)
        else:
            remaining_after = int(get_2fa_backup_count_quick(username) or 0)
        log.info("[B-CODE] refreshed user=%s type=%s remaining_after=%s", username, b, remaining_after)
    except Exception as e:
        log.debug("[B-CODE] quick recheck failed: %s", e)

# Handler for "Generate Recovery Key" button click. Generates new backup codes for the specified type and shows them in the Emergency Kit dialog.
def on_generate_recovery_key_clicked(self, b_type: str = "login") -> None:
    self.set_status_txt(self.tr("Generating recovery Key for ") + f"{b_type}")
    # Normalize type
    b = (b_type or "login").strip().lower()
    if b not in ("login", "2fa", "both"):
        b = "login"

    # Target user
    username = self._active_username()
    if not username:
        QMessageBox.warning(self, self.tr("Backup Codes"), self.tr("No user selected."))
        return

    # Get password context (prompt if missing)
    pwd = getattr(self, "current_password", None) or getattr(self, "currentPassword", None)
    if not pwd:
        msg = self.tr("Enter password for ") + f"'{username}'" + self.tr(" to generate new backup codes:")
        pwd, ok = QInputDialog.getText(
            self, self.tr("Confirm Password"), msg,
            QLineEdit.Password
        )
        if not ok or not pwd:
            QMessageBox.information(self, self.tr("Cancelled"), self.tr("Backup code regeneration cancelled."))
            return

    # Generate and persist (identity store)
    login_codes: list[str] | None = None
    twofa_codes: list[str] | None = None
    try:
        from auth.tfa.twofactor import gen_backup_codes, yk_twofactor_enabled
        if b == "login":
            login_codes = gen_backup_codes(username, "login", password_for_identity=pwd)
        elif b == "2fa":
            twofa_codes = gen_backup_codes(username, "2fa", password_for_identity=pwd)
        else:  # both (and recovery mode allowed)
            login_codes = gen_backup_codes(username, "login", password_for_identity=pwd)
            twofa_codes = gen_backup_codes(username, "2fa",  password_for_identity=pwd)
    except Exception as e:
        # Most common cause: wrong password for identity store
        QMessageBox.critical(
            self, self.tr("Backup Codes"),
            self.tr("Could not generate backup codes.\n\n"
            "{err}\n\nIf this was a password error, please try again.").format(err=e)
        )
        return

    # Baseline/audit (best effort)
    try:
        update_baseline(username=username, verify_after=False, who=self.tr("Backup Code -> Updated")) 
    except Exception:
        pass
    try:
        msg = self.tr("{ok} (userdb) -> Regenerate Backup codes").format(ok=kql.i('ok'))
        log_event_encrypted(username, self.tr("USER"), msg)
    except Exception:
        pass

    # Helper to stringify lists
    def _fmt_codes(codes: list[str] | None) -> str:
        if not codes:
            return "(none)"
        try:
            return "\n".join(str(x).strip() for x in codes if str(x).strip())
        except Exception:
            return str(codes)

    # Try Emergency Kit dialog first
    try:
        if b == "login":
            if not self.emg_ask(username=username, recovery_backup_codes=login_codes):
                raise RuntimeError("EmergencyKitDialog declined/failed")
        elif b == "2fa":
            if not self.emg_ask(username=username, twofa_backup_codes=twofa_codes):
                raise RuntimeError("EmergencyKitDialog declined/failed")
        else:  # both
            if not self.emg_ask(
                username=username,
                recovery_backup_codes=login_codes,
                twofa_backup_codes=twofa_codes
            ):
                raise RuntimeError("EmergencyKitDialog declined/failed")
        return
    except Exception as e:
        # Fallback: copy to clipboard and show once
        try:
            log.error(f"Emg Error = {e}")
            clip = QApplication.clipboard()
            if b == "login":
                clip.setText(_fmt_codes(login_codes))
            elif b == "2fa":
                clip.setText(_fmt_codes(twofa_codes))
            else:
                clip.setText(
                    f"Login backup codes:\n{_fmt_codes(login_codes)}\n\n"
                    f"2FA backup codes:\n{_fmt_codes(twofa_codes)}"
                )
        except Exception:
            pass

        if b == "login":
            QMessageBox.information(
                self, self.tr("Backup Codes (Shown Once)"),
                self.tr("Save these Login backup codes in a safe offline place.\n\n")
                + _fmt_codes(login_codes)
            )
        elif b == "2fa":
            QMessageBox.information(
                self, self.tr("Backup Codes (Shown Once)"),
                self.tr("Save these 2FA backup codes in a safe offline place.\n\n")
                + _fmt_codes(twofa_codes)
            )
        else:
            QMessageBox.information(
                self, self.tr("Backup Codes (Shown Once)"),
                self.tr("Save these backup codes in a safe offline place.\n\nLogin backup codes:") + 
                f"\n{_fmt_codes(login_codes)}\n\n" + 
                self.tr("2FA backup codes:") + 
                f"\n{_fmt_codes(twofa_codes)}"
            )

# Emergency Kit dialog: shows current or imported recovery/2FA backup codes and TOTP secret, allowing the user to save them safely. 
# No secrets are persisted here; it's just for display and PDF generation.
def emg_ask(
    self,
    username,
    one_time_recovery_key=None,
    recovery_backup_codes=None,   # list[str] | str | None
    twofa_backup_codes=None,      # list[str] | str | None
    totp_secret_plain=None,
    totp_uri=None,
    totp_qr_png=None,
):
    """
    Show Emergency Kit dialog, allowing:
      - Use current data only
      - Load / merge from an existing Emergency Kit PDF
      - Manual entry / edits

    No secrets are persisted here — only used for building the PDF
    and showing the on-screen emergency info.
    """
    from auth.emergency_kit.emergency_kit import (
        parse_emergency_kit_pdf,
        merge_kit_into_account_snapshot,
    )

    def _normalize_codes(val):
        """
        Accepts list[str] | str | None and returns list[str] (unique, trimmed).
        Splits strings by newline, commas, spaces.
        """
        if val is None:
            return []
        if isinstance(val, list):
            items = val
        else:
            # split on newlines, commas, semicolons, or whitespace runs
            items = _re.split(r"[,\s;]+", str(val))
        # trim, drop empties, dedupe preserving order
        seen, out = set(), []
        for x in (s.strip() for s in items):
            if x and x not in seen:
                seen.add(x); out.append(x)
        return out

    # --- Start from provided values (do NOT overwrite with "N/A") ---
    rec_key = one_time_recovery_key or None
    rec_codes = _normalize_codes(recovery_backup_codes)
    tfa_codes = _normalize_codes(twofa_backup_codes)
    totp_secret = totp_secret_plain or None   
    totp = totp_uri or None
    qr_png = totp_qr_png

    # --- Ask how to build the Emergency Kit data ---
    mode_box = QMessageBox(self)
    mode_box.setWindowTitle(self.tr("Emergency Kit"))
    mode_box.setText(self.tr(
        "How do you want to build your Emergency Kit?\n\n"
        "• Use current data only\n"
        "• Load & merge from an existing Emergency Kit PDF\n"
        "• Add or edit details manually")
    )
    btn_current = mode_box.addButton(self.tr("Use current only"), QMessageBox.AcceptRole)
    btn_import = mode_box.addButton(self.tr("Load from PDF"), QMessageBox.ActionRole)
    btn_manual = mode_box.addButton(self.tr("Add / edit manually"), QMessageBox.DestructiveRole)
    mode_box.setDefaultButton(btn_current)
    mode_box.exec()

    clicked = mode_box.clickedButton()
    mode = "current"
    if clicked is btn_import:
        mode = "import"
    elif clicked is btn_manual:
        mode = "manual"

    # --- If user chose "Load from PDF", merge in old kit data (add-only) ---
    if mode == "import":
        pdf_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select existing Emergency Kit PDF to merge",
            "",
            "PDF files (*.pdf)",
        )
        if pdf_path:
            try:
                parsed = parse_emergency_kit_pdf(pdf_path)

                # Build a lightweight "snapshot" from what we have in memory.
                # We don't track used_* codes here, so we pass empty lists.
                snapshot = {
                    "recovery_backup_codes": rec_codes,
                    "used_recovery_codes": [],
                    "twofa_backup_codes": tfa_codes,
                    "used_twofa_codes": [],
                    "totp_secret_hint": totp_secret,
                }

                merged = merge_kit_into_account_snapshot(snapshot, parsed)

                rec_codes = merged.get("recovery_backup_codes", rec_codes)
                tfa_codes = merged.get("twofa_backup_codes", tfa_codes)
                # merged["totp_secret_hint"] is just a hint string, safe to use
                if merged.get("totp_secret_hint") and not totp_secret:
                    totp_secret = merged["totp_secret_hint"]

                QMessageBox.information(
                    self,
                    self.tr("Emergency Kit"),
                    self.tr("Existing Emergency Kit data was merged successfully.\n\n"
                    "New codes were added where available. Your current data was not overwritten."))
            except Exception as e:
                QMessageBox.critical(
                    self,
                    self.tr("Emergency Kit"),
                    self.tr("Could not read or merge the selected Emergency Kit PDF:" + f"\n\n{e}"))

        # If user cancels file selection, just fall back to current data + optional manual below.

    # --- If user chose "manual", open manual-entry dialog ---
    if mode == "manual":
        manual = self.prompt_manual_kit_entries(
            defaults={
                "recovery_key": rec_key,
                "recovery_backup_codes": rec_codes,
                "twofa_backup_codes": tfa_codes,
                "totp_secret": totp_secret,
                "totp_uri": totp,
            }
        ) or {}
        if manual.get("ok"):
            if manual.get("recovery_key"):
                rec_key = str(manual["recovery_key"]).strip() or None

            rbc = manual.get("recovery_backup_codes")
            if rbc is not None:
                rec_codes = _normalize_codes(rbc)

            tfa = manual.get("twofa_backup_codes")
            if tfa is not None:
                tfa_codes = _normalize_codes(tfa)

            if manual.get("totp_uri"):
                totp = str(manual["totp_uri"]).strip() or None
                # If URI exists, we can ignore raw secret unless you want to keep both
                totp_secret = None
            elif manual.get("totp_secret"):
                totp_secret = str(manual["totp_secret"]).strip() or None

    # --- Only show if we have *real* content ---
    show_kit = any([
        bool(rec_key),
        bool(rec_codes),
        bool(tfa_codes),
        bool(totp),
        bool(qr_png),
        bool(totp_secret),
    ])

    app_version = get_app_version()

    if show_kit:
        try:
            dlg = EmergencyKitDialog(
                self,
                username=username,
                app_version=app_version,
                recovery_key=rec_key,
                recovery_backup_codes=rec_codes,    # list[str]
                twofa_backup_codes=tfa_codes,        # list[str]
                totp_uri=totp,
                totp_secret_hint=totp_secret,
                totp_qr_png=qr_png,
            )
            dlg.exec()
        except Exception as e:
            log.warning("%s [KIT] EmergencyKitDialog unavailable, fallback text: %s", kql.i('warn'), e)

            # --- Minimal fallback popup ---
            recovery_popup = QDialog(self)
            recovery_popup.setWindowTitle(self.tr("Your Emergency Kit"))
            recovery_popup.setMinimumSize(560, 480)

            layout = QVBoxLayout(recovery_popup)
            instructions = QTextEdit(); instructions.setReadOnly(True)

            def _fmt_list(lst):
                return "<br>".join(map(lambda s: Qt.escape(str(s)), lst)) if lst else "<i>None</i>"

            rk_html = f"<code style='font-size: 16px;'>{Qt.escape(str(rec_key))}</code>" if rec_key else "<i>No recovery key</i>"
            instructions.setHtml(
                "<b>📢 Emergency Kit</b><br><br>"
                f"<b>Recovery Key</b><br>{rk_html}<br><br>"
                "<b>Recovery Backup Codes</b><br>"
                f"<pre style='font-size: 14px;'>{_fmt_list(rec_codes)}</pre><br>"
                "<b>2FA Backup Codes</b><br>"
                f"<pre style='font-size: 14px;'>{_fmt_list(tfa_codes)}</pre><br>"
                + ("<i>TOTP QR/URI included.</i>" if (totp or qr_png or totp_secret) else "")
            )
            layout.addWidget(instructions)
            close_btn = QPushButton(self.tr("I have stored these safely"))
            close_btn.clicked.connect(recovery_popup.accept)
            layout.addWidget(close_btn)
            recovery_popup.exec()

    # --- Cleanup: wipe secrets in memory as best we can ---
    try:
        # Overwrite lists in place
        for i in range(len(rec_codes)): rec_codes[i] = ""
        for i in range(len(tfa_codes)): tfa_codes[i] = ""
        # Overwrite and drop refs
        totp_secret = None
        totp = None
        qr_png = None
    except Exception:
        pass

    return True

# Emergency Kit manual entry prompt. Returns a dict with the entered values, or "ok": False if cancelled.
def prompt_manual_kit_entries(self, *, defaults: dict | None = None) -> dict:
    """
    Returns:
      {
        "ok": bool,
        "recovery_key": str|None,
        "recovery_backup_codes": list[str],
        "twofa_backup_codes": list[str],
        "totp_secret": str|None,
        "totp_uri": str|None
      }
    Only used for Emergency Kit rendering; does NOT save to disk.
    """
    dfl = defaults or {}
    rec_key_d = dfl.get("recovery_key", "")
    rec_codes_d = "\n".join(dfl.get("recovery_backup_codes", []))
    twofa_codes_d = "\n".join(dfl.get("twofa_backup_codes", []))
    totp_secret_d = dfl.get("totp_secret", "")
    totp_uri_d = dfl.get("totp_uri", "")

    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Add items manually to your Emergency Kit"))
    dlg.setModal(True)
    dlg.setMinimumWidth(520)
    lay = QVBoxLayout(dlg)

    # Recovery key
    lay.addWidget(QLabel(self.tr("Recovery Key (optional):")))
    rec_key = QLineEdit(); rec_key.setText(rec_key_d); lay.addWidget(rec_key)

    # Recovery backup codes (one per line)
    lay.addWidget(QLabel(self.tr("Recovery Backup Codes (one per line):")))
    rec_codes = QTextEdit(); rec_codes.setPlainText(rec_codes_d); lay.addWidget(rec_codes)

    # 2FA backup codes (one per line)
    lay.addWidget(QLabel(self.tr("2FA Backup Codes (one per line):")))
    twofa_codes = QTextEdit(); twofa_codes.setPlainText(twofa_codes_d); lay.addWidget(twofa_codes)

    # TOTP manual
    lay.addWidget(QLabel(self.tr("TOTP Manual Fields (optional — use either):")))
    totp_secret = QLineEdit(); totp_secret.setPlaceholderText(self.tr("BASE32SECRET (e.g., JBSWY3DPEHPK3PXP)"))
    totp_secret.setText(totp_secret_d); lay.addWidget(totp_secret)
    totp_uri = QLineEdit(); totp_uri.setPlaceholderText(self.tr("otpauth://totp/Issuer:User?...")) 
    totp_uri.setText(totp_uri_d); lay.addWidget(totp_uri)

    confirm_cb = QCheckBox(self.tr("I have double-checked the entries above (typos can lock me out)."))
    lay.addWidget(confirm_cb)

    row = QHBoxLayout()
    btn_ok = QPushButton(self.tr("Use These"))
    btn_cancel = QPushButton(self.tr("Cancel"))
    row.addWidget(btn_ok); row.addWidget(btn_cancel)
    lay.addLayout(row)

    def _use():
        if not confirm_cb.isChecked():
            QMessageBox.warning(dlg, self.tr("Please confirm"), self.tr("Tick the checkbox to confirm you've double-checked the entries."))
            return
        dlg.accept()

    btn_ok.clicked.connect(_use)
    btn_cancel.clicked.connect(dlg.reject)

    if dlg.exec() != QDialog.DialogCode.Accepted:
        return {"ok": False, "recovery_key": None, "recovery_backup_codes": [], "twofa_backup_codes": [], "totp_secret": None, "totp_uri": None}

    # Normalize lists (strip empties/spaces)
    def _split_lines(widget: QTextEdit) -> list[str]:
        return [ln.strip() for ln in widget.toPlainText().splitlines() if ln.strip()]
    return {
        "ok": True,
        "recovery_key": rec_key.text().strip() or None,
        "recovery_backup_codes": _split_lines(rec_codes),
        "twofa_backup_codes": _split_lines(twofa_codes),
        "totp_secret": totp_secret.text().strip() or None,
        "totp_uri": totp_uri.text().strip() or None,
    }

# ===============================
# --- rescue
# ===============================

# Rescue dialog when no YubiKey is present, but BOTH backup code and Recovery Key are available.
def _show_login_rescue_both(self, username: str):
    """
    Rescue dialog shown when no YubiKey is available.
    Requires BOTH:
        - a login backup code (identity-store count > 0), and
        - a Recovery Key (wrap present).
    Returns {"backup": "...", "rk": "..."} on success, else None.
    """
    username = (username or "").strip()
    if not username:
        return None

    # Canonicalize (case-insensitive) without find_user()
    canon = _canonical_username_ci(username) or username

    # YubiKey configured?
    yk_mode, _ = yk_twofactor_enabled(canon)  # "yk_hmac_gate" | "yk_hmac_wrap" | None
    yk_present = bool(yk_mode)

    # Recovery-wrap present? (helper or file check)
    try:
        wrapped_exists = Path(str(get_wrapped_key_path(canon))).exists()
    except Exception:
        wrapped_exists = False
    wrap_present = bool(has_recovery_wrap(canon) or wrapped_exists)

    # Any login backup codes?
    try:
        has_backup = int(get_login_backup_count_quick(canon)) > 0
    except Exception:
        has_backup = False

    # --- hard gates BEFORE showing any inputs ---
    if not yk_present:
        QMessageBox.information(
            self, self.tr("Login"),
            self.tr("This account isn’t configured with a YubiKey yet.\n"
            "Please log in normally and set it up in Settings.")
        )
        return None

    # This dialog specifically requires BOTH backup code + Recovery Key
    if not wrap_present:
        msg = self.tr("Your account is configured for YubiKey presence (Gate) but no Recovery Key is set.\nEnable Recovery Mode and create a Recovery Key first.")
        QMessageBox.information(
            self, self.tr("Recovery Key not available"), msg)
        return None

    if not has_backup:
        QMessageBox.information(
            self,
            self.tr("Backup Codes"),
            self.tr(
                "No login backup codes are available.\n"
                "Please log in normally and generate new backup codes in Settings."
            ),
        )
        return None

    # --- dialog (only shown when prereqs are satisfied) ---
    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Other ways to log in"))
    dlg.setModal(True)
    dlg.setMinimumWidth(480)

    v = QVBoxLayout(dlg)
    lab = QLabel(
        self.tr(
            "No YubiKey available.\n\n"
            "To continue without your key, enter BOTH your Login Backup Code and your Recovery Key."
        )
    )
    lab.setWordWrap(True)
    v.addWidget(lab)

    bc = QLineEdit(dlg)
    bc.setPlaceholderText(self.tr("Backup code"))
    bc.setMaxLength(64)
    v.addWidget(bc)

    rk = QLineEdit(dlg)
    rk.setPlaceholderText(self.tr("Recovery Key"))
    rk.setEchoMode(QLineEdit.Password)
    rk.setMaxLength(256)
    v.addWidget(rk)

    row = QHBoxLayout()
    row.addStretch(1)
    btn_cancel = QPushButton(self.tr("Cancel"), dlg)
    btn_go = QPushButton(self.tr("Continue"), dlg)
    btn_go.setEnabled(False)
    row.addWidget(btn_cancel)
    row.addWidget(btn_go)
    v.addLayout(row)

    def _update():
        bc_ok = len((bc.text() or "").strip()) >= 6
        rk_ok = len((rk.text() or "").strip()) >= 12
        btn_go.setEnabled(bc_ok and rk_ok)

    bc.textChanged.connect(_update)
    rk.textChanged.connect(_update)
    bc.returnPressed.connect(btn_go.click)
    rk.returnPressed.connect(btn_go.click)

    chosen = {"backup": None, "rk": None}

    def _submit():
        chosen["backup"] = (bc.text() or "").strip()
        chosen["rk"]     = (rk.text() or "").strip()
        dlg.accept()

    btn_go.clicked.connect(_submit)
    btn_cancel.clicked.connect(dlg.reject)

    ok = dlg.exec() == QDialog.DialogCode.Accepted
    return chosen if ok else None

# Rescue dialog when no YubiKey is present, but at least one of backup code or Recovery Key is available. Shows options based on what's available.
def _rescue_caps(username: str):
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

# Rescue dialog when no YubiKey is present, but at least one of backup code or Recovery Key is available. Shows options based on what's available.
def _show_login_rescue(self, username: str):
    mode, allow_backup, allow_recovery = _rescue_caps(username)

    dlg = QDialog(self); dlg.setWindowTitle(self.tr("Other ways to log in")); dlg.setModal(True); dlg.setMinimumWidth(460)
    v = QVBoxLayout(dlg)
    head = QLabel(self.tr("Can’t use your YubiKey? Choose an alternative below."));
    head.setWordWrap(True)
    v.addWidget(head)

    backup_edit = QLineEdit(dlg)
    backup_edit.setPlaceholderText(self.tr("Enter a backup code"))
    v.addWidget(backup_edit)
    btn_backup = QPushButton(self.tr("Use Backup Code"), dlg)
    btn_backup.setEnabled(False)
    v.addWidget(btn_backup)

    rk_edit = QLineEdit(dlg)
    rk_edit.setPlaceholderText(self.tr("Enter your Recovery Key"))
    rk_edit.setEchoMode(QLineEdit.Password)
    v.addWidget(rk_edit)
    btn_rk = QPushButton(self.tr("Use Recovery Key"), dlg)
    btn_rk.setEnabled(False)
    v.addWidget(btn_rk)

    row = QHBoxLayout()
    row.addStretch(1)
    btn_cancel = QPushButton(self.tr("Cancel"), dlg)
    row.addWidget(btn_cancel)
    v.addLayout(row)

    backup_edit.textChanged.connect(lambda t: btn_backup.setEnabled(len(t.strip()) >= 6))
    rk_edit.textChanged.connect(lambda t: btn_rk.setEnabled(len(t.strip()) >= 12))
    backup_edit.returnPressed.connect(lambda: btn_backup.click())
    rk_edit.returnPressed.connect(lambda: btn_rk.click())

    chosen = {"backup": None, "rk": None}

    def _use_backup():
        if not allow_backup:
            QMessageBox.information(
                dlg,
                self.tr("Backup code not available"),
                self.tr(
                    "Backup codes aren’t configured for this account.\n"
                    "Log in once and generate backup codes."
                ),
            )
            return
        chosen["backup"] = backup_edit.text().strip()
        dlg.accept()

    def _use_rk():
        if not allow_recovery:
            QMessageBox.information(
                dlg,
                self.tr("Recovery Key not available"),
                self.tr(
                    "A Recovery Key isn’t configured for this account.\n"
                    "Enable Recovery Mode and create a Recovery Key."))
            return
        chosen["rk"] = rk_edit.text().strip()
        dlg.accept()

        btn_backup.clicked.connect(_use_backup); btn_rk.clicked.connect(_use_rk); btn_cancel.clicked.connect(dlg.reject)
        return chosen if dlg.exec() == QDialog.DialogCode.Accepted else None    

# ==============================
# --- "Get User" STRICT NATIVE: unwrap vault session if a wrapped-key file exists
# ==============================

# This is a "rescue" path for users who have a wrapped vault session but can't load it properly (e.g. due to a bug or missing YubiKey). 
# It tries to read the wrap blob and unwrap it into the current session, so that vault load can proceed as normal. If it fails, 
# it just keeps the existing session and lets vault load fail gracefully.
def _try_read_wrap_blob(username: str):
    import base64, json
    """Return (iv, ct, tag) bytes from the user's .kq_wrap file, or None if missing/invalid."""
    try:
        from app.paths import vault_wrapped_file
        p = vault_wrapped_file(username, ensure_parent=False)
        if not p.exists():
            return None
        raw = p.read_bytes()
        if not raw:
            return None

        # JSON form: {"iv": "...", "ct": "...", "tag": "..."} or {"iv","ciphertext","tag"} or {"nonce","ct","tag"}
        try:
            s = raw.decode("utf-8", "strict").strip()
            if s.startswith("{"):
                obj = json.loads(s)
                b64_iv  = obj.get("iv") or obj.get("nonce")
                b64_ct  = obj.get("ct") or obj.get("ciphertext") or obj.get("wrapped") or obj.get("data")
                b64_tag = obj.get("tag") or obj.get("mac")
                if b64_iv and b64_ct and b64_tag:
                    iv  = base64.b64decode(b64_iv)
                    ct  = base64.b64decode(b64_ct)
                    tag = base64.b64decode(b64_tag)
                    return iv, ct, tag
        except Exception:
            pass

        # Token form: kqwrap:v1.<nonce>.<ct>  (legacy python wrap) — not supported in pure-native unwrap
        return None
    except Exception:
        return None

# Attempt to unwrap the current session into a vault session if a wrap blob exists for the user. This is a "rescue" path for users who 
# have a wrapped vault session but can't load it properly (e.g. due to a bug or missing YubiKey). If unwrap fails, it just keeps the existing 
# session and lets vault load fail gracefully.
def _maybe_unwrap_to_vault_session(self, username: str) -> None:
    """If an account is still in WRAP mode and a .kq_wrap file exists, unwrap the current
    session into a vault session handle (in-place).

    IMPORTANT:
    After WRAP is disabled there may still be a stale .kq_wrap file on disk from an older
    session or backup flow. In that state the current native session is already the real
    password-only vault session, so trying to unwrap again will convert a good session into
    the wrong one and later vault decrypts fail with rc=-10.

    Therefore we only unwrap when the public identity header still says WRAP is enabled.
    """
    try:
        wrapping_sess = getattr(self, "core_session_handle", None)
        if not isinstance(wrapping_sess, int) or wrapping_sess <= 0:
            return

        # Guard against stale .kq_wrap blobs after WRAP disable.
        try:
            from auth.identity_store import get_yubi_config_public
            pub = get_yubi_config_public(username) or {}
            mode = (pub.get("mode") or "").strip().lower()
        except Exception:
            mode = ""

        if mode != "yk_hmac_wrap":
            try:
                log.info("[LOGIN] wrap blob ignored because account is not in WRAP mode user=%s mode=%s", username, mode or "none")
            except Exception:
                pass
            return

        blob = _try_read_wrap_blob(username)
        if not blob:
            return  # no wrap file => current session is already the vault session

        iv, ct, tag = blob
        from native.native_core import get_core
        core = get_core()
        try:
            vault_sess = int(core.session_unwrap_to_session(wrapping_sess, iv, ct, tag))
        except Exception as e:
            # If unwrap fails, keep current session; vault load will still fail and report properly.
            log.warning("[LOGIN] unwrap-to-session failed (keeping existing session) user=%s err=%r", username, e)
            return

        # Swap session handles: new vault session becomes active; close wrapping session.
        try:
            core.close_session(wrapping_sess)
        except Exception:
            pass
        self.core_session_handle = vault_sess
        try:
            self._vault_session_ready = True
        except Exception:
            pass
        log.info("[LOGIN] vault session unwrapped (handle=%s) user=%s", vault_sess, username)
    except Exception:
        pass

# load the per-user record dict for the given username. This is a best-effort, read-only operation that won't create or modify any files. 
# Returns an empty dict if no record exists or if the file is invalid.
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

# Best-effort, read-only check to see if a username exists. Returns (exists: bool, canonical: str|None).
def precheck_username_exists(typed: str):
    
    """Best-effort, READ-ONLY check to see if a username exists.
    Returns (exists: bool, canonical: str|None).
    Safe to call from UI typing hooks (e.g. update_login_picture).
    """

    if not typed:
        return False, None
    try:
        # Canonicalize case-insensitively if possible
        try:
            canonical = _canonical_username_ci(typed)
        except Exception:
            canonical = None
        username = canonical or typed

        # Primary: user record
        try:
            rec = get_user_record(username) or {}
            if rec:
                return True, username
        except Exception:
            pass

        # Fallback: per-user DB file (read-only)
        try:
            from pathlib import Path
            from app.paths import user_db_file
            p = Path(user_db_file(username, ensure_parent=False))
            if p.is_file():
                return True, username
        except Exception:
            pass

        return False, canonical or None
    except Exception:
        return False, None

# ==============================
# --- "Remember Username" 
# ==============================

# Per-user "remember username" using QSettings. This is just a convenience to pre-fill the username field on the login screen, and is
#  NOT used for any security or authentication purposes. It can be cleared by the user at any time.
def _load_remembered_username() -> str:
    s = QSettings(_KQ_SETTINGS_ORG, _KQ_SETTINGS_APP)
    return (s.value("login/remembered_username", "") or "").strip()

# Save the remembered username to QSettings. Pass None or empty string to clear.
def _save_remembered_username(username: str | None):
    s = QSettings(_KQ_SETTINGS_ORG, _KQ_SETTINGS_APP)
    if username:
        s.setValue("login/remembered_username", username)
    else:
        s.remove("login/remembered_username")

# Clear the remembered username after confirming with the user. This updates QSettings and also clears the username field and 
# unchecks the "remember" box immediately.
def clear_remembered_username(self):
    from ui.message_ops import message_clear_username

    if not message_clear_username(self):
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

# ==============================
# --- DPAPI "Remember this device" UX helpers 
# ==============================

# Clear passwordless unlock tokens for this user on this device, after confirming with the user. 
# This updates the user record and also forces the "remember this device" checkbox to be unchecked immediately.
def clear_passwordless_unlock_on_this_device(self, show_warn=True):

    from ui.message_ops import show_message_user_login, message_disable_passwordless, message_disable_passwordless
    """Disable DPAPI device unlock for THIS Windows account only."""
    username = self._active_username()
    if not username:
        msg = "Clear Passwordless"
        show_message_user_login(self, msg)
        return

    if show_warn:
        if not message_disable_passwordless(self):
            return

    try:
        from auth.login.login_handler import get_user_record, set_user_record
        from device.utils_device import hwfp_sha256

        rec = get_user_record(username) or {}
        current_hwfp = hwfp_sha256()
        removed_count = 0
        toks = rec.get("device_unlock_tokens") or []

        if isinstance(toks, list):
            new_toks = []
            for tok in toks:
                if (
                    isinstance(tok, dict)
                    and tok.get("v") == 4
                    and tok.get("kind") == "dpapi_session"
                    and tok.get("hwfp_sha256") == current_hwfp):
                    removed_count += 1
                    continue  # skip this device's tokens
                new_toks.append(tok)

            rec["device_unlock_tokens"] = new_toks

        # Remove legacy/latest pointer if it belongs to this device
        du = rec.get("device_unlock")
        if isinstance(du, dict) and du.get("hwfp_sha256") == current_hwfp:
            rec.pop("device_unlock", None)

        set_user_record(username, rec)

        log.info(
            "[LOGIN] cleared %s passwordless token(s) for current device",
            removed_count,
        )

        # reset login fileds
        self.rememberDeviceCheckbox.setChecked(False)
        self.rememberDeviceCheckbox.setToolTip(
            "Your login credentials or security settings have changed. "
            "Please sign in again with your password to re-enable this device.")
        log.info("Passwordless unlock cleared")
        self.passwordField.setPlaceholderText("Enter Password")

        if show_warn:
            message_disable_passwordless(self)
        try:
            update_baseline(username=username, verify_after=False, who="Clear Hello")
        except Exception as e:
            log.error(f"[baseline] update after login failed for {username}: {e}")
            
    except Exception as e:
        log.exception("[LOGIN] failed clearing passwordless unlock")
        QMessageBox.critical(
            self,
            self.tr("Error"),
            self.tr("Failed to clear passwordless unlock:\n") + str(e),
        )


# Enable/disable the "Remember this device" checkbox based on whether the current user can use DPAPI passwordless unlock. 
# This is called when the username field changes, and also after login to reflect any changes.
def set_remember_checkbox(self, check=False):
    cb = self.rememberDeviceCheckbox
    was = cb.blockSignals(True)
    try:
        cb.setEnabled(check)
        if check == False:
            cb.setChecked(check)
            cb.setToolTip(
                self.tr(
                    "Blocked because your security baseline has changed.\n"
                    "Review Security Center → Baseline before enabling this."))
    finally:
        cb.blockSignals(was)

# Auto-sync the "Remember this device" checkbox state based on the typed username's DPAPI status. This is called on username field changes.
def _sync_remember_device_checkbox_for_username(self, typed_username: str):
    """Auto-reflect per-user DPAPI state in the checkbox while typing/selecting a username.

    - If username is empty or user not found -> disable + untick
    - If user has a saved device_unlock blob -> enable + tick
    - Otherwise -> enable + untick
    """
    cb = getattr(self, "rememberDeviceCheckbox", None)
    if cb is None:
        return
    # If we just logged in via DPAPI, don't auto-toggle the checkbox while the UI is mid-transition.
    if getattr(self, "_dpapi_login_active", False):
        return

    typed = (typed_username or "").strip()
    if not typed:
        try:
            was = cb.blockSignals(True)
            cb.setChecked(False)
            cb.setEnabled(False)
        finally:
            try:
                cb.blockSignals(was)
            except Exception:
                pass
        return

    # Resolve canonical (case-insensitive)
    lookup_name = typed
    try:
        exists, canon = precheck_username_exists(typed)
        if exists and canon:
            lookup_name = canon
    except Exception:
        lookup_name = typed

    # Load record (best-effort)
    rec = None
    try:
        rec = get_user_record(lookup_name)
    except Exception as e:
        rec = None

    if not rec:
        # Unknown user -> disable
        try:
            self.passwordField.setPlaceholderText("Password")
            self.rememberDeviceCheckbox.setToolTip(
                "Enable 'Remember this device' to unlock without entering your password on this Windows device."
            )
            self.passwordField.setToolTip("Stores an encrypted unlock token on this Windows account (DPAPI). Not portable, and Not Yubi_key Wrap")
            was = cb.blockSignals(True)
            cb.setChecked(False)
            cb.setEnabled(False)
        finally:
            try:
                cb.blockSignals(was)
            except Exception:
                pass
        return

    else:
        enabled = False
        try:
            from auth.windows_hello.session import has_device_unlock
            enabled = bool(has_device_unlock(rec))
        except Exception:
            du = (rec.get("device_unlock") or {})
            enabled = bool(du.get("wrapped_b64") and du.get("entropy_b64")) or bool(du.get("enabled", False))

        # Set UI without triggering toggled handler
        try:
            self.passwordField.setPlaceholderText("Press Enter or click Unlock")
            self.passwordField.setToolTip(
                "This device can unlock the vault without your password. "
                "You can still enter your password if you prefer.")
            self.rememberDeviceCheckbox.setToolTip("Uncheck to disable passwordless unlock on this device.")
            was = cb.blockSignals(True)
            cb.setEnabled(True)
            cb.setChecked(bool(enabled))
        finally:
            try:
                cb.blockSignals(was)
            except Exception:
                pass

# Show a clear security warning about the risks of enabling passwordless DPAPI unlock on a device, and ask for confirmation. 
# Returns (allowed: bool, dont_ask_again: bool).
def _remember_device_security_warning(self, username: str) -> tuple[bool, bool]: # move this to flags 
    """Warn before enabling passwordless DPAPI unlock.

    Returns (allowed: bool, dont_ask_again: bool).
    """
    try:
        # Use QMessageBox if available; fallback to allow if UI isn't available
        _QMessageBox = QMessageBox
        _QCheckBox = QCheckBox
    except Exception:
        return True, False

    title = self.tr("Security warning")
    body = self.tr(
        "⚠️ Passwordless unlock on this Windows device\n\n"
        "Enabling 'Remember this device' allows your vault to unlock WITHOUT your password on THIS Windows account.\n\n"
        "Security risks:\n"
        "• Anyone who can sign into this Windows account may unlock your vault.\n"
        "• Malware running as you (or a remote session as you) could access your vault.\n"
        "• This lowers protection on shared PCs, stolen PCs (while unlocked), or compromised systems.\n\n"
        "Only enable this on a trusted personal PC with:\n"
        "• A strong Windows sign-in (PIN/biometrics/password)\n"
        "• Full disk encryption (e.g., BitLocker)\n\n"
        "Do you want to enable this for the selected user?"
    )

    box = _QMessageBox(self)
    try:
        box.setIcon(_QMessageBox.Warning)
    except Exception:
        pass
    box.setWindowTitle(title)
    box.setText(body)
    box.setStandardButtons(_QMessageBox.Yes | _QMessageBox.No)
    box.setDefaultButton(_QMessageBox.No)

    dont = _QCheckBox(self.tr("Don’t ask again for this user on this device"))
    try:
        box.setCheckBox(dont)
    except Exception:
        dont = None

    resp = box.exec() if hasattr(box, "exec") else box.exec_()
    allowed = (resp == _QMessageBox.Yes)
    dont_ask = bool(dont and dont.isChecked())
    return allowed, dont_ask

# Save the user's choice to not show the DPAPI security warning again for this user on this device. 
# This is stored in the user record and checked before showing the warning.
def _set_device_unlock_consent_flag(username: str, dont_ask_again: bool) -> None:
    """Persist the 'don't ask again' consent flag inside user_db record."""
    try:
        # Prefer live globals if present; fallback to importing login_handler
        _get = globals().get("get_user_record", None)
        _set = globals().get("set_user_record", None)
        if not callable(_get) or not callable(_set):
            from auth.login.login_handler import get_user_record as _get, set_user_record as _set  # type: ignore
        rec = _get(username) or {}
        du = rec.get("device_unlock") or {}
        du["consent_dont_ask"] = bool(dont_ask_again)
        rec["device_unlock"] = du
        _set(username, rec)
    except Exception:
        try:
            log.exception("[HELLO] failed to save remember-device consent flag")
        except Exception:
            pass

# Ensure the "Remember this device" checkbox is hooked up to show the security warning when toggled on. This should be called once during UI setup.
def _ensure_remember_device_checkbox_hooked(self):
    """Connect checkbox toggled handler once (safe if UI reuses this module)."""
    if getattr(self, "_kq_remember_device_hooked", False):
        return
    cb = getattr(self, "rememberDeviceCheckbox", None)
    if cb is None:
        return
    try:
        cb.toggled.connect(lambda checked: _on_remember_device_toggled(self, checked))
        self._kq_remember_device_hooked = True
    except Exception:
        # Don't crash if signal isn't available
        self._kq_remember_device_hooked = True

# Handler for when the "Remember this device" checkbox is toggled. Shows a security warning when enabling, and reverts if the user cancels.
def _on_remember_device_toggled(self, checked: bool):
    """Intercept enabling DPAPI remember-device to show a clear security warning."""
    try:
        cb = getattr(self, "rememberDeviceCheckbox", None)
        if cb is None:
            return
        uname_typed = (getattr(self, "usernameField", None).text() or "").strip() if hasattr(self, "usernameField") else ""
        if not uname_typed:
            return

        # Resolve canonical username
        lookup_name = uname_typed
        try:
            exists, canon = precheck_username_exists(uname_typed)
            if exists and canon:
                lookup_name = canon
        except Exception:
            lookup_name = uname_typed

        if not checked:
            return

        # Check if user already opted out of the warning
        rec = {}
        try:
            rec = get_user_record(lookup_name) or {}
        except Exception:
            rec = {}

        du = (rec.get("device_unlock") or {})
        dont_ask = bool(du.get("consent_dont_ask", False))

        if dont_ask:
            return

        allowed, dont_ask_again = _remember_device_security_warning(self, lookup_name)
        if not allowed:
            # Revert checkbox safely
            if cb:
                was = cb.blockSignals(True)
                try:
                    cb.setChecked(False)
                finally:
                    try:
                        cb.blockSignals(was)
                    except Exception:
                        pass
            return

        if dont_ask_again:
            _set_device_unlock_consent_flag(lookup_name, True)


    except Exception:
        try:
            log.exception("[HELLO] remember-device toggle handler failed")
        except Exception:
            pass

# =============================
# --- DPAPI Token update
# =============================

# Helper to check if a DPAPI token dict is valid and not expired as of "now". 
# This is used to filter out invalid/expired tokens when looking for a matching device token.
def _token_is_valid_now(tok: dict, now: int) -> bool:
    if not isinstance(tok, dict):
        return False
    if tok.get("v") != 4:
        return False
    if tok.get("kind") != "dpapi_session":
        return False

    exp = tok.get("expires_ts") or 0
    # exp==0 means "no expiry" (valid)
    if isinstance(exp, int) and exp > 0 and now >= exp:
        return False
    return True

# Find the best matching DPAPI device unlock token for the current device (identified by hwfp) from the user record.
def _find_best_device_token_v4(rec: dict, *, hwfp: str, now: int) -> tuple[int, dict] | tuple[None, None]:
    toks = rec.get("device_unlock_tokens") or []
    if not isinstance(toks, list):
        return (None, None)

    best_i = None
    best_tok = None
    for i, tok in enumerate(toks):
        if not isinstance(tok, dict):
            continue
        if tok.get("v") != 4 or tok.get("kind") != "dpapi_session":
            continue
        if tok.get("hwfp_sha256") != hwfp:
            continue
        if not _token_is_valid_now(tok, now):
            continue

        # Prefer the one that expires latest (or never expires)
        exp = tok.get("expires_ts") or 0
        if best_tok is None:
            best_i, best_tok = i, tok
        else:
            best_exp = best_tok.get("expires_ts") or 0
            # exp==0 => never expires, treat as "best"
            if best_exp == 0:
                continue
            if exp == 0 or exp > best_exp:
                best_i, best_tok = i, tok

    return (best_i, best_tok) if best_tok is not None else (None, None)

# Check if a DPAPI token is close to expiring (within refresh_window_days), and thus we should mint a new one proactively.
def _should_refresh_token(tok: dict, *, now: int, refresh_window_days: int = 3) -> bool:
    """Return True if token is close to expiring and we should mint a new one."""
    exp = tok.get("expires_ts") or 0
    if not isinstance(exp, int) or exp <= 0:
        return False  # never-expiring token doesn't need refresh
    return (exp - now) <= (refresh_window_days * 86400)

# ==============================
# --- attempt login
# ============================== 

# USB drive selection flow: pick drive, pick user folder, validate layout, then bind and install overrides for the session.
def on_select_usb_clicked(self):
    """
    Pick a USB drive, choose a portable user folder, validate it against
    Phase-2 canonical filenames/locations, then bind and install overrides.
    """
    w = self
    from pathlib import Path
    from qtpy.QtWidgets import QFileDialog, QMessageBox, QInputDialog
    from features.portable.portable_manager import pick_usb_drive
    from features.portable.portable_user_usb import ensure_portable_layout, install_binding_overrides
    from features.portable.portable_binding import set_user_usb_binding
    from app.paths import vault_file, salt_file, user_db_file, debug_log_paths

    # 1) Pick the USB root
    usb_root = pick_usb_drive(w)
    if not usb_root:
        picked = QFileDialog.getExistingDirectory(w, w.tr("Select your USB (root)"))
        if not picked:
            return
        usb_root = Path(picked)

    # 2) Find user folders on <USB>\KeyquorumPortable\Users
    pr, users_dir = ensure_portable_layout(usb_root)
    try:
        user_dirs = [p for p in users_dir.iterdir() if p.is_dir()]
    except Exception:
        user_dirs = []

    if not user_dirs:
        QMessageBox.warning(
            w, w.tr("Select USB"),
            w.tr("No users found under KeyquorumPortable/Users on this drive.\n\n"
            "Use Settings → Move User To USB first.")
        )
        return

    # 3) Choose the user folder
    names = [p.name for p in user_dirs]
    choice, ok = QInputDialog.getItem(
        w, w.tr("Select USB user"),
        w.tr("Choose the user folder to bind:"), names, 0, False
    )
    if not ok or not choice:
        return

    username = choice.strip()
    user_dir = users_dir / username

    # 4) Validate Phase-2 layout (with legacy fallbacks)
    canon_vault = Path(vault_file(username, name_only=True)).name
    canon_salt  = Path(salt_file(username,  name_only=True)).name
    canon_db    = Path(user_db_file(username, name_only=True)).name

    # canonical locations
    vault_path = user_dir / "Main" / "Vault"   / canon_vault
    salt_path  = user_dir / "KQ_Store"         / canon_salt
    db_path    = user_dir / "Main"             / canon_db

    # fallback candidates (legacy flat layout)
    legacy_vaults = [
        user_dir / "vault.dat",
        user_dir / f"{username}.vault",
        user_dir / canon_vault,  # same name but wrong place
    ]
    legacy_salts = [
        user_dir / "salt.bin",
        user_dir / f"salt_{username}.bin",
        user_dir / canon_salt,   # same name but wrong place
    ]
    legacy_dbs = [
        user_dir / "user_db.json",
        user_dir / canon_db,     # same name but wrong place
    ]

    def _exists_any(paths):
        return any(p.exists() for p in paths)

    vault_ok = vault_path.exists() or _exists_any(legacy_vaults)
    salt_ok  = salt_path.exists()  or _exists_any(legacy_salts)
    db_ok    = db_path.exists()    or _exists_any(legacy_dbs)

    if not (vault_ok and salt_ok and db_ok):
        exp_lines = [
            f"• Main/Vault/{canon_vault} (or vault.dat / {username}.vault)",
            f"• KQ_Store/{canon_salt} (or salt.bin / salt_{username}.bin)",
            f"• Main/{canon_db} (or user_db.json)",
        ]
        QMessageBox.warning(
            w, "Select USB",
            "That folder doesn’t contain a valid Keyquorum dataset.\n\n"
            "Expected files like:\n" + "\n".join(exp_lines)
        )
        return

    # 5) Persist binding and install runtime overrides NOW
    try:
        set_user_usb_binding(username, usb_root=Path(usb_root), user_dir=Path(user_dir))
        install_binding_overrides(username, Path(user_dir))  # redirect paths.* to USB for this process

        # ensure any cached imports pick up the new paths
        import importlib
        import vault_store as vstore  # <-- correct module
        importlib.reload(vstore)
        globals().update({"vstore": vstore})

        # Helpful logs
        try:
            debug_log_paths(username)
        except Exception:
            pass

        # Prefill login username (nice UX)
        try:
            if hasattr(w, "usernameField"):
                w.usernameField.setText(username)
        except Exception:
            pass
        msg = w.tr("Saved. ") + f"{username} " + w.tr("is now bound to this USB.\n You can log in and the app will read from the USB data.")
        QMessageBox.information(
            w, w.tr("USB Selected"), msg)
    except Exception as e:
        QMessageBox.critical(w, w.tr("USB Selection Failed"), str(e))

# check if we need to enforce YubiKey factors for this user, and if so, show the YubiKey login gate BEFORE any 2FA dialog or successful login. 
# This ensures that the YubiKey factors are always enforced at the correct point in the flow, regardless of DPAPI, passwordless, or other factors.
def _continue_after_factors(self, username: str) -> None:
    # ------------------------
    # YubiKey mode detection
    # - Prefer PUBLIC header (works for passwordless / DPAPI)
    # - Fall back to private identity payload only if we have context
    # ------------------------
    mode = None
    cfg = None

    try:
        from auth.identity_store import get_yubi_config_public
        pub = get_yubi_config_public(username) or {}
        mode = (pub.get("mode") or "").strip().lower() or None
    except Exception:
        pub = {}
        mode = None

    # If we still don't know, try private config (requires password or bytes-KEK)
    if not mode:
        try:
            from auth.identity_store import get_yubi_config
            cfg = get_yubi_config(username, getattr(self, "current_password", "") or "") or {}
            mode = (cfg.get("mode") or "").strip().lower() or None
        except Exception:
            cfg = None
            mode = None

    # ------------------------
    # Enforce YubiKey factors BEFORE any 2FA dialog / successful_login
    # ------------------------
    # IMPORTANT: Use the existing threaded YubiKey login dialog so we:
    # - don't freeze the UI
    # - keep the original UX (Insert → Touch, plus Backup/Recovery fallbacks)

    if mode in ("yk_hmac_gate", "yk_hmac_wrap"):
        # Build the most complete config we can.
        # - Public header is always safe (works for DPAPI/passwordless).
        # - Private config requires either the plaintext password OR identity_kek (DPAPI v3).
        cfg_seed = None
        try:
            cfg_seed = pub if isinstance(pub, dict) else None
        except Exception:
            cfg_seed = None

        # Password for identity operations (backup-code consumption).
        # Password/identity context used for consuming backup codes.
        # NOTE: This may be a plaintext password (normal login) OR an identity_kek bytes value
        # (DPAPI v3 passwordless). identity_store supports both for existing identities.
        pw_for_identity = getattr(self, "current_password", "") or ""
        if isinstance(pw_for_identity, memoryview):
            pw_for_identity = bytes(pw_for_identity)


        # Always try to load the PRIVATE YubiKey config when we have a plaintext password,
        # even if the mode came from the public header. The original worker/dialog often
        # relies on private fields (slot/serial/etc).
        if not (isinstance(cfg, dict) and cfg):
            if pw_for_identity:
                try:
                    from auth.identity_store import get_yubi_config, sync_yubi_public_meta
                    cfg = get_yubi_config(username, pw_for_identity) or {}
                    # One-time upgrade path for older identities that do not yet mirror
                    # WRAP metadata into the public header.
                    try:
                        sync_yubi_public_meta(username, pw_for_identity)
                        pub = get_yubi_config_public(username) or pub or {}
                    except Exception:
                        pass
                except Exception:
                    cfg = cfg if isinstance(cfg, dict) else None

        # For WRAP we MUST have the wrapped MK payload.
        if mode == "yk_hmac_wrap":
            if not (isinstance(cfg, dict) and cfg.get("wrapped_b64")):
                try:
                    from auth.identity_store import get_yubi_config, sync_yubi_public_meta
                    ik = getattr(self, "_identity_kek", None)
                    if isinstance(ik, (bytes, bytearray, memoryview)) and bytes(ik):
                        cfg = get_yubi_config(username, bytes(ik)) or {}
                        try:
                            sync_yubi_public_meta(username, bytes(ik))
                            pub = get_yubi_config_public(username) or pub or {}
                        except Exception:
                            pass
                    elif pw_for_identity:
                        cfg = get_yubi_config(username, pw_for_identity) or {}
                        try:
                            sync_yubi_public_meta(username, pw_for_identity)
                            pub = get_yubi_config_public(username) or pub or {}
                        except Exception:
                            pass
                except Exception:
                    cfg = cfg if isinstance(cfg, dict) else None

            if not (isinstance(cfg, dict) and cfg.get("wrapped_b64")):
                # Final fallback: if the public header already contains mirrored WRAP metadata,
                # use that directly. This allows strict DPAPI/native-session logins to continue
                # without requiring the encrypted identity payload to be opened first.
                if isinstance(pub, dict) and pub.get("wrapped_b64"):
                    cfg = dict(pub)

            if not (isinstance(cfg, dict) and cfg.get("wrapped_b64")):
                sess = getattr(self, "core_session_handle", None)
                if not (isinstance(sess, int) and sess > 0):
                    QMessageBox.information(
                        self,
                        self.tr("Remembered device needs upgrade"),
                        self.tr(
                            "Keyquorum could not load the YubiKey WRAP data needed to unlock this vault. "
                            "If you are using a remembered-device token, sign in once with your password (and tick "
                            "'Remember this device') to upgrade the token to v3."
                        ),
                    )
                    return

        # Compose final cfg for the dialog (must include the mode).
        dlg_cfg = {}
        try:
            if isinstance(cfg_seed, dict):
                dlg_cfg.update(cfg_seed)
        except Exception:
            pass
        try:
            if isinstance(cfg, dict):
                dlg_cfg.update(cfg)
        except Exception:
            pass
        dlg_cfg["mode"] = mode
        wrap_confirm_only = False
        if mode == "yk_hmac_wrap":
            sess = getattr(self, "core_session_handle", None)
            if isinstance(sess, int) and sess > 0 and not (isinstance(dlg_cfg, dict) and dlg_cfg.get("wrapped_b64")):
                wrap_confirm_only = True
                dlg_cfg["mode"] = "yk_hmac_gate"

        # Gate/Wrap should always run BEFORE 2FA prompt.
        try:
            from auth.yubi.login_gate_dialog import YubiKeyLoginGateDialog
        except Exception:
            YubiKeyLoginGateDialog = None

        if not YubiKeyLoginGateDialog:
            QMessageBox.critical(
                self,
                self.tr("YubiKey required"),
                self.tr("YubiKey login dialog is missing from this build."),
            )
            return

        pwk = getattr(self, "_pw_kek", None)
        import secrets as _secrets
        dlg = YubiKeyLoginGateDialog(
            username=username,
            password=pw_for_identity,
            cfg=dlg_cfg,
            challenge_hex=_secrets.token_hex(16),
            parent=self,
            password_key=(bytes(pwk) if (mode == "yk_hmac_wrap" and isinstance(pwk, (bytes, bytearray, memoryview))) else None),
        )

        try:
            ok_dialog = bool(dlg.exec())
        except Exception:
            ok_dialog = False
        if not ok_dialog:
            return

        # If they used the fallback paths:
        mk_from_dialog = getattr(dlg, "result_mk", None)
        result_mode = (getattr(dlg, "result_mode", "") or "").strip().lower()

        if mode == "yk_hmac_gate":
            # Gate is satisfied either by hardware touch or backup-code bypass.
            self._yk_gate_satisfied = True
            # Continue to 2FA logic below (it will short-circuit for gate).
            pass


        if mode == "yk_hmac_wrap":  
            # WRAP returns the real vault master key (bytes). In strict DLL-only mode we must
            # open a native session from it and then finalize login.
            mk_from_dialog = getattr(dlg, "result_mk", None)
            if isinstance(mk_from_dialog, (bytes, bytearray)) and len(mk_from_dialog) >= 16:
                try:
                    try:
                        self._login_requires_yubi_wrap = False
                    except Exception:
                        pass
                    try:
                        self._yk_gate_satisfied = True
                    except Exception:
                        pass

                    self._finish_login(username, bytes(mk_from_dialog), yk_record={"mode": "yk_hmac_wrap"})
                    if bool(getattr(self, "_login_finalized", False)):
                        try:
                            self.successful_login(username=username)
                        except Exception as e:
                            log.exception("[LOGIN][YUBI] post-WRAP successful_login failed for %s: %s", username, e)
                            QMessageBox.critical(self, self.tr("Login failed"), self.tr("YubiKey unlock succeeded, but the app could not finish signing you in."))
                    return
                except Exception:
                    QMessageBox.critical(self, self.tr("Vault locked"), self.tr("Unable to finalize WRAP login."))
                    return

            if wrap_confirm_only:
                try:
                    self._login_requires_yubi_wrap = False
                except Exception:
                    pass
                try:
                    self._yk_gate_satisfied = True
                except Exception:
                    pass
                self.successful_login(username=username)
                return

            QMessageBox.critical(
                self,
                self.tr("Vault locked"),
                self.tr("YubiKey WRAP was not completed."),
            )
            return

        if False and mode == "yk_hmac_wrap":
            # WRAP: dialog may have returned an MK (recovery+backup path).
            if isinstance(mk_from_dialog, (bytes, bytearray)) and len(mk_from_dialog) >= 16:
                self.core_session_handle = bytes(mk_from_dialog)
                try:
                    self._login_requires_yubi_wrap = False
                except Exception:
                    pass
                try:
                    self._yk_gate_satisfied = True
                except Exception:
                    pass
            else:
                # Hardware path: unwrap MK using YubiKey + password-context (pw_kek).
                pwk = getattr(self, "_pw_kek", None)
                if not isinstance(pwk, (bytes, bytearray, memoryview)) or len(bytes(pwk)) < 16:
                    QMessageBox.critical(
                        self,
                        self.tr("Vault locked"),
                        self.tr("Missing password context required for YubiKey WRAP."),
                    )
                    return

                try:
                    from qtpy.QtCore import QThread, Signal
                    from qtpy.QtWidgets import QProgressDialog
                except Exception:
                    QThread = None
                    Signal = None
                    QProgressDialog = None

                try:
                    try:
                        from yubi.yubihmac_wrap import unwrap_master_key_with_yubi
                    except Exception:
                        from auth.yubi.yubihmac_wrap import unwrap_master_key_with_yubi
                except Exception as e:
                    QMessageBox.critical(self, self.tr("Vault locked"), self.tr("Missing WRAP module: {e}").format(e=e))
                    return

                # Friendly error type (optional)
                try:
                    from auth.yubi.yk_backend import YubiKeyError
                except Exception:
                    YubiKeyError = Exception

                # Run unwrap off the UI thread to avoid freezes.
                if QThread and Signal and QProgressDialog:

                    class _WrapUnwrapWorker(QThread):
                        ok = Signal(bytes)
                        err = Signal(str)

                        def __init__(self, *, pwk_bytes: bytes, cfg_dict: dict):
                            super().__init__()
                            self._pwk = pwk_bytes
                            self._cfg = cfg_dict

                        def run(self):
                            try:
                                mk = unwrap_master_key_with_yubi(b"", password_key=self._pwk, cfg=self._cfg or {})
                                if not isinstance(mk, (bytes, bytearray)) or len(mk) < 16:
                                    raise RuntimeError("Empty key from YubiKey unwrap")
                                self.ok.emit(bytes(mk))
                            except Exception as e:
                                self.err.emit(str(e) or "YubiKey unwrap failed")

                    prog = QProgressDialog(
                        self.tr("Waiting for YubiKey…"),
                        self.tr("Cancel"),
                        0,
                        0,
                        self,
                    )
                    prog.setWindowTitle(self.tr("YubiKey required"))
                    prog.setMinimumDuration(0)
                    prog.setAutoClose(True)
                    prog.setAutoReset(True)

                    worker = _WrapUnwrapWorker(pwk_bytes=bytes(pwk), cfg_dict=dlg_cfg)

                    def _done_ok(mk_bytes: bytes):
                        try:
                            prog.close()
                        except Exception:
                            pass
                        self.core_session_handle = bytes(mk_bytes)
                        try:
                            self._login_requires_yubi_wrap = False
                        except Exception:
                            pass
                        try:
                            self._yk_gate_satisfied = True
                        except Exception:
                            pass
                        # continue to 2FA / success flow
                        try:
                            self.set_status_txt(self.tr("YubiKey verified"))
                        except Exception:
                            pass

                    def _done_err(msg: str):
                        try:
                            prog.close()
                        except Exception:
                            pass
                        low = (msg or "").lower()
                        if "no yubikey" in low or "not detected" in low:
                            QMessageBox.information(
                                self,
                                self.tr("YubiKey required"),
                                self.tr("Insert your YubiKey and try again."),
                            )
                        else:
                            QMessageBox.critical(self, self.tr("YubiKey error"), msg or "YubiKey error")

                    worker.ok.connect(_done_ok)
                    worker.err.connect(_done_err)

                    def _cancel():
                        try:
                            worker.requestInterruption()
                        except Exception:
                            pass
                        try:
                            worker.terminate()
                        except Exception:
                            pass
                        try:
                            worker.wait(200)
                        except Exception:
                            pass

                    prog.canceled.connect(_cancel)

                    worker.start()
                    prog.exec()

                    # If unwrap failed/cancelled, core_session_handle won't be set; stop login.
                    if not (isinstance(getattr(self, "core_session_handle", None), (bytes, bytearray)) and len(self.core_session_handle) >= 16):
                        return
                else:
                    # Fallback: synchronous unwrap (older Qt bindings) - may momentarily freeze.
                    try:
                        mk = unwrap_master_key_with_yubi(b"", password_key=bytes(pwk), cfg=dlg_cfg or {})
                    except YubiKeyError as e:
                        msg = str(e) or "YubiKey error"
                        QMessageBox.information(self, self.tr("YubiKey required"), msg)
                        return
                    if not isinstance(mk, (bytes, bytearray)) or len(mk) < 16:
                        QMessageBox.critical(self, self.tr("Vault locked"), self.tr("YubiKey unwrap returned an empty key."))
                        return
                    self.core_session_handle = bytes(mk)
                    try:
                        self._login_requires_yubi_wrap = False
                    except Exception:
                        pass
                    try:
                        self._yk_gate_satisfied = True
                    except Exception:
                        pass


    self.set_status_txt(self.tr("Checking 2FA Login"))
    try:
        from auth.login.login_handler import is_2fa_enabled as db_is_2fa_enabled
        db_flag = bool(db_is_2fa_enabled(username))
    except Exception:
        db_flag = False

    self.set_login_visible(False)
    self.currentUsername.setText(username)

    # Live identity status (source of truth for TOTP)
    from auth.identity_store import has_totp_quick
    live_has_2fa = bool(has_totp_quick(username))
    # If YubiKey GATE succeeded, treat it as the 2FA method for this login (either/or)

    if mode == "yk_hmac_gate" and self._yk_gate_satisfied == True:
        self._yk_gate_satisfied = False  # one-shot
        self.successful_login()
        return

    # Keep the checkbox in sync with the *live* identity
    if hasattr(self, 'twoFACheckbox'):
        self.twoFACheckbox.blockSignals(True)
        self.twoFACheckbox.setChecked(live_has_2fa)
        self.twoFACheckbox.blockSignals(False)
        self.regen_key_both.setEnabled(live_has_2fa)
        self.regen_key_2fa.setEnabled(live_has_2fa)
        self.regen_key_2fa_2.setEnabled(live_has_2fa)
    log.debug("%s [2FA] status: identity=%s, user_db_flag=%s",
              kql.i('info'), live_has_2fa, db_flag)

    # --- Case A: both say off -> log straight in

    if not live_has_2fa and not db_flag:
        self.totp = None
        self.set_login_visible(False)
        try:
            self.passwordField.clear()
            msg = self.tr("{ok} Successful login no 2FA").format(ok=kql.i("ok"))
            log_event_encrypted(self.currentUsername.text(), self.tr("login"),msg)
            log.debug(str(f"{kql.i('ok')} [2FA] {kql.i('auth')} Successful login no 2FA"))

        except Exception:
            pass

        self.successful_login()
        return

    # --- Case B: identity says ON (this is the normal path) -> prompt for code

    if live_has_2fa:
        from auth.tfa.twofa_dialog import prompt_2fa_for_user
        ok = prompt_2fa_for_user(self, username)
        if ok:
            self.successful_login()
            return
        else:
            try:
                msg = self.tr("{ok} 2FA not completed").format(ok=kql.i("warn"))
                log_event_encrypted(self.currentUsername.text(), self.tr("2FA"), msg)
            except Exception:
                pass
            self.safe_messagebox_warning(self, self.tr("Two-Factor Authentication"),
                                         self.tr("Two-factor authentication was not completed."))
            self.passwordField.clear()
            try: self.current_password = None
            except Exception: pass
            self.show_login_ui()
            if hasattr(self, 'mainTabs'):
                self.mainTabs.setVisible(False)
            return

    # --- Case C: DB says ON but identity says OFF -> repair by re-setup (non-destructive)
    # We *do not* bypass 2FA; ask the user to re-enable now.
    reply = QMessageBox.question(
        self,
        self.tr("2FA Setup Required"),
        (self.tr("Your account is marked as '2FA enabled' but the identity data for TOTP is missing.\n\n"
         "Would you like to set up 2FA now?")),
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.Yes,
    )
    if reply != QMessageBox.Yes:
        # Abort login for safety
        self.safe_messagebox_warning(self, self.tr("Two-Factor Authentication"),
                                     self.tr("2FA is required for this account. Login aborted."))
        self.passwordField.clear()
        self.show_login_ui()
        if hasattr(self, 'mainTabs'):
            self.mainTabs.setVisible(False)
        return

    # Collect password to write identity
    password = self._prompt_account_password(username)
    if not password:
        self.safe_messagebox_warning(self, self.tr("Two-Factor Authentication"),
                                     self.tr("2FA setup was cancelled."))
        self.passwordField.clear()
        self.show_login_ui()
        if hasattr(self, 'mainTabs'):
            self.mainTabs.setVisible(False)
        return

    # Run setup
    try:
        from auth.tfa.twofa_dialog import twofa_setup
        ok2fa = twofa_setup(self, username, pwd=password)
    except Exception as e:
        log.error("%s -> %s [2FA] Setup error during login repair for '%s': %s",
                  kql.i('auth'), kql.i('err'), username, e)
        ok2fa = {"ok": False, "error": str(e)}

    if not (isinstance(ok2fa, dict) and ok2fa.get("ok")):
        self.safe_messagebox_warning(
            self, self.tr("Two-Factor Authentication"),
            self.tr("Could not complete 2FA setup; login aborted.")
        )
        self.passwordField.clear()
        self.show_login_ui()
        if hasattr(self, 'mainTabs'):
            self.mainTabs.setVisible(False)
        return

    # Setup succeeded -> immediately prompt for code to sign in
    if prompt_2fa_for_user(self, username):
        self.successful_login()
        return

    try:
        set_probe_enabled(False)
    except Exception:
        pass

    # If they fail the code right after setup
    self.safe_messagebox_warning(self, self.tr("Two-Factor Authentication"),
                                 self.tr("Two-factor authentication was not completed."))

    self.passwordField.clear()
    self.show_login_ui()
    if hasattr(self, 'mainTabs'):
        self.mainTabs.setVisible(False)

# Main login handler that orchestrates the entire login process.
def attempt_login(self, *args, **kwargs):
    """
    Handle the full user login process.
    - USB binding-aware: resolves username from USB dataset first
    - Read-only until auth succeeds (no mkdir)
    - Validates user + password
    - Lockout + baseline peek (non-blocking)
    - Derives candidate master key
    - YubiKey or TOTP/backup 2FA
    """

    try:
        if hasattr(self, "showPasswordCheckbox"):
            self.showPasswordCheckbox.setChecked(False)
        self.passwordField.setEchoMode(QLineEdit.Password)
    except Exception:
        pass

    # Local imports to avoid circulars
    try:
        from security.secure_audit import (
            is_locked_out as audit_is_locked_out,
            append_audit_log,
            log_event_encrypted,
        )
    except Exception:
        def audit_is_locked_out(_u, _t, *_args): return (False, int(_t or 0), 0)
        def append_audit_log(*a, **k): pass
        def log_event_encrypted(*a, **k): pass

    try:
        from security.baseline_signer import write_audit_baseline
    except Exception:
        write_audit_baseline = None

    # Pre-auth audit logger (audit_v2)
    try:
        from security.audit_v2 import preauth_log_event
        from app.paths import config_dir as _cfgdir
    except Exception:
        def preauth_log_event(*a, **k):
            return None
        def _cfgdir(*a, **k):
            return ""

    try:
        from vault_store.key_utils import derive_key_argon2id
    except Exception:
        return ""
        # Optional: native core wipe helper (safe fallback)
    try:
        from native.native_core import get_core
    except Exception:
        def get_core():
            return None

    log.debug(str(f"{kql.i('auth')} -> {kql.i('info')} [LOGIN] Attempting user login"))

    typed_username = (self.usernameField.text() or "").strip()

    # Capture password once, then clear UI ASAP to reduce lifetime
    pw_str = (self.passwordField.text() or "")
    try:
        self.passwordField.clear()
    except Exception:
        pass

    # Build a single mutable buffer (used for wiping; future: derive directly from this)
    try:
        pw_buf = bytearray(pw_str.encode("utf-8"))
    except Exception:
        pw_buf = bytearray()

    # --- Autofill remembered username on fresh login screen
    try:
        cb_user = getattr(self, "remember_username", None)
        if cb_user and not typed_username:
            remembered = _load_remembered_username()
            if remembered:
                self.usernameField.setText(remembered)
                typed_username = remembered
    except Exception:
        pass

    # ------------------------
    ## Important Updates: 
    # --- DPAPI "Remember this device" quick unlock (Windows)
    # STRICT DLL-only: v4 tokens only. Legacy v2/v3 tokens are deleted (cannot be used).
    # MUST run before any password validation or lockout logic
    # ------------------------
    try:
        from qtpy.QtWidgets import QMessageBox
        remember_on = False
        try:
            cb = (
                getattr(self, "rememberDeviceCheckbox", None)
                or self.findChild(QCheckBox, "rememberDeviceCheckbox")
            )
            remember_on = bool(cb and cb.isChecked())
        except Exception:
            remember_on = False

        if typed_username and (pw_str.strip() == "") and remember_on:
            log.info(f"{kql.i('auth')} -> {kql.i('info')} [LOGIN] dpapi-check user=%s pw_empty=1 remember=1", typed_username)

            # Ensure USB binding / users_root is resolved BEFORE reading user_db for DPAPI
            try:
                _aw('_maybe_install_binding_for', lambda *a, **k: None)(typed_username)
            except Exception:
                pass

            # Resolve canonical username (case-insensitive) BEFORE user_db lookup
            canon = None
            try:
                exists, canon = precheck_username_exists(typed_username)
                if not exists:
                    canon = None
            except Exception:
                canon = None

            lookup_name = (canon or typed_username).strip()

            # Lookup user record (try canonical first, then raw typed)
            from auth.login.login_handler import get_user_record
            rec = {}
            try:
                rec = get_user_record(lookup_name)
            except Exception as e:
                rec = None
            if not rec and lookup_name != typed_username:
                try:
                    rec = get_user_record(typed_username)
                except Exception:
                    rec = None
            if not rec:
                log.warning(f"{kql.i('auth')} -> {kql.i('info')}[LOGIN] dpapi-check no user record typed=%s canon=%s", typed_username, canon or "None")
                return



            # If token is legacy (v2/v3/unknown) in strict mode, purge it so we can't loop forever.
            try:
                du = (rec.get("device_unlock") or {})
                v = int(du.get("v") or 0)
                kind = (du.get("kind") or "").strip().lower()
                if du and (v != 4 or kind != "dpapi_session"):
                    from auth.windows_hello.session import clear_device_unlock
                    rec = clear_device_unlock(rec)
                    set_user_record(lookup_name, rec)
                    try:
                        if cb:
                            cb.setChecked(False)
                    except Exception:
                        pass
                    QMessageBox.information(
                        self,
                        self.tr("Password required"),
                        self.tr("This remembered-device token was created in legacy mode and can’t open a native session in strict DLL-only mode.\n\nPlease sign in once with your password (with 'Remember this device' enabled) to upgrade it."),
                    )
                    return
            except Exception:
                pass

            # v4 (DLL-only): open a native session directly via DLL (no key in Python)
            try:
                from native.native_core import get_core
                from auth.windows_hello.session import try_open_session_from_device_unlock
                core = get_core()
                ok4, sess4, msg4 = try_open_session_from_device_unlock(rec, core=core)
                # If we have a v4 token but it failed, surface a helpful one-time message.
                if (not ok4) and msg4:
                    try:
                        du = rec.get("device_unlock") or {}
                        v = int(du.get("v") or 0)
                        kind = (du.get("kind") or "").strip().lower()
                        if v == 4 and kind == "dpapi_session":
                            QMessageBox.information(
                                self,
                                self.tr("Password required"),
                                self.tr(
                                    "This device unlock token can’t be used right now.\n\n"
                                    "Reason: {msg}\n\n"
                                    "Sign in once with your password (and keep ‘Remember this device’ enabled) to refresh it."
                                ).format(msg=msg4),
                            )
                    except Exception:
                        pass
                if ok4 and isinstance(sess4, int) and sess4 > 0:
                    log.info(f"{kql.i('auth')} -> {kql.i('info')}[LOGIN] dpapi-unlock OK (v4 native session) user=%s handle=%s", lookup_name, sess4)
                    self.core_session_handle = int(sess4)
                    # Mark DPAPI login so post-login code doesn't auto-clear tokens / untick UI.
                    try:
                        self._dpapi_login_active = True
                    except Exception:
                        pass
                    try:
                        if cb:
                            was = cb.blockSignals(True)
                            cb.setEnabled(True)
                            cb.setChecked(True)
                            cb.blockSignals(was)
                    except Exception:
                        pass
                    # Mark that this login used DPAPI fast-path (so later code doesn't clear the token)
                    self._dpapi_login_active = True

                    try:
                        self._login_requires_yubi_wrap = False
                    except Exception:
                        pass

                    # If a WRAP file exists, unwrap to the real vault session (best effort)
                    try:
                        _maybe_unwrap_to_vault_session(self, lookup_name)
                    except Exception:
                        pass

                    # IMPORTANT:
                    # DPAPI "remember device" is passwordless, not factorless.
                    # Must still run the normal factor pipeline (YubiKey gate/wrap, TOTP) before finalizing login.
                    # The factor pipeline will call successful_login() on success.
                    try:
                        # No plaintext password in DPAPI mode
                        self.current_password = ""
                    except Exception:
                        pass
                    log.info(f"{kql.i('auth')} -> {kql.i('info')}[LOGIN] remembered-device login completed (v4 strict)")
                    try:
                        _continue_after_factors(self, lookup_name)
                        return
                    except Exception as e:
                        log.exception(f"{kql.i('auth')} -> {kql.i('err')}[LOGIN] dpapi v4 factor pipeline failed: %s", e)
            except Exception as e:
                log.debug(f"{kql.i('auth')} -> {kql.i('err')}[LOGIN] dpapi-v4 fast path unavailable: %s", e)

            # No usable token => do nothing (user can still type password)
            log.info(f"{kql.i('auth')} -> {kql.i('warn')}[LOGIN] dpapi-unlock not available (v4 missing/failed) user=%s", lookup_name)
    except Exception:
        log.exception(f"{kql.i('auth')} -> {kql.i('warn')}[LOGIN] dpapi-check crashed")

    # ------------------------
    # end DPAPI block
    # ------------------------

    # Shared existence precheck
    try:
        exists, canon = precheck_username_exists(typed_username)
        self._login_user_exists = bool(exists)
    except Exception:
        self._login_user_exists = None

    if not typed_username:
        QMessageBox.information(self, self.tr("No Username"), self.tr("Please enter a username."))
        self.set_status_txt(self.tr("No Username"))
        return

    # ensure salt is defined for the outer scope
    salt: bytes = b""
    _aw('_maybe_install_binding_for', lambda *a, **k: None)(typed_username)

    # ---------- READ-ONLY PHASE ----------
    from app.paths import read_only_paths
    with read_only_paths(True):
        canonical = None

        try:
            from features.portable.portable_user_usb import install_binding_overrides
        except Exception:
            install_binding_overrides = None

        if canonical is None:
            try:
                canonical = _canonical_username_ci(typed_username)
            except Exception as e:
                log.debug(str(f"{kql.i('warn')} [LOGIN] CI resolver failed: {e}"))
                canonical = None

        if canonical is None:
            self.passwordField.clear()
            self.passwordField.setPlaceholderText("Password")
            msg = self.tr("User ") + f"'{typed_username}'" + self.tr(" not found.\n\nWould you like to create a new account?")
            resp = QMessageBox.question(
                self,
                self.tr("Create Account?"), msg,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if resp == QMessageBox.StandardButton.Yes:
                self.create_account()
            return

        username = canonical

        # Master salt (identity-header first, legacy .slt fallback)# Note fallback removed on later Updates 
        try:
            from auth.salt_file import read_master_salt_readonly
            salt = read_master_salt_readonly(username)
            # stash for post-login migration
            try:
                self._login_salt = bytes(salt)
            except Exception:
                self._login_salt = salt
        except Exception as e:
            # Provide actionable paths to the user
            try:
                from app.paths import salt_file
                legacy_path = str(salt_file(username, ensure_parent=False))
            except Exception:
                legacy_path = '(unknown)'
            try:
                from app.paths import identities_file
                id_path = str(identities_file(username, ensure_parent=False))
            except Exception:
                id_path = '(unknown)'

            log.error('[LOGIN] Missing/invalid master salt for user=%s legacy=%s identity=%s err=%r', username, legacy_path, id_path, e)
            self.set_status_txt(self.tr('Missing salt'))
            QMessageBox.critical(
                self,
                self.tr('Account Data Missing'),
                self.tr(
                    "Keyquorum couldn't find your account's master salt, so it can't derive the vault key."
                    f"Checked: • Identity Store header: {id_path} • Legacy salt file: {legacy_path}"
                    "Fix options:"
                    "• Restore the user folder from a backup (recommended), or"
                    "• Delete the user's local folder and create the account again."
                    "If this keeps happening after recreating the account, it usually means the app isn't writing to the expected user storage path."))
            self.passwordField.clear()
            return

        # Sanity check
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
            log.error('[LOGIN] Missing/invalid salt for user=%s (len=%s)', username, (len(salt) if isinstance(salt, (bytes, bytearray)) else 'n/a'))
            self.set_status_txt(self.tr('Missing salt'))
            QMessageBox.critical(
                self,
                self.tr('Account Data Missing'),
                self.tr(
                    "Keyquorum couldn't read a valid master salt for this account."
                    "Fix options:"
                    "• Restore the user folder from a backup (recommended), or"
                    "• Delete the user's local folder and create the account again."))
            self.passwordField.clear()
            return
        # Reload login_handler after possible overrides
        try:
            import importlib
            import auth.login.login_handler as _lh_mod
            lh = importlib.reload(_lh_mod)
            global get_user_setting, validate_login, reset_login_failures
            get_user_setting      = lh.get_user_setting
            validate_login        = lh.validate_login
            reset_login_failures  = lh.reset_login_failures
        except Exception as e:
            log.debug(str(f"{kql.i('warn')} [LOGIN] Could not reload login_handler: {e}"))

        def _int_or(def_val, raw):
            try:
                return int(raw if raw is not None else def_val)
            except Exception:
                return def_val

        threshold     = _int_or(5,  get_user_setting(username, "lockout_threshold", 5))
        window_mins   = _int_or(10, get_user_setting(username, "lockout_window_mins", 10))
        cooldown_mins = _int_or(5,  get_user_setting(username, "lockout_cooldown_mins", 5))

        if threshold > 0:
            locked, attempts_left, mins_left = audit_is_locked_out(username, threshold, window_mins, cooldown_mins)
            if locked:
                msg = ""
                # clear dpapi
                try:
                    rec = get_user_record(username) or {}
                    rec.pop("device_unlock", None)
                    set_user_record(username, rec)
                    msg = ("Windows Hello Removed")
                    log.info(f"{kql.i('auth')} -> {kql.i('warn')} [DPAPI] Windows Hello Removed")
                except Exception as e:
                    log.info(f"{kql.i('auth')} -> {kql.i('warn')} [DPAPI] Windows Hello Error {e}")

                log.info(f"{kql.i('auth')} -> {kql.i('warn')} [LOGIN] Account LOCKED for user: {username} ({mins_left} min left)")
                self.set_status_txt(self.tr("Locked User"))

                msg = self.tr("Too many failed login attempts.\nTry again in about ") + f"{mins_left}" + self.tr(" minute(s).") + msg

                QMessageBox.critical(self, self.tr("Account Locked"), msg)
                try:
                    msg = self.tr("{ok} (vault)  Account Locked ({mins_left1} min left)").format(ok=kql.i("warn"), mins_left1=mins_left)
                    log_event_encrypted(username, self.tr("login"), msg)
                    try:
                        preauth_log_event(str(_cfgdir(username, ensure_parent=False)), username, "login_failed",
                                          {"reason": f"Account locked ({mins_left} min left)"})
                    except Exception:
                        pass
                except Exception:
                    pass
                try:
                    if write_audit_baseline:
                        s = _aw('_load_vault_salt_for', lambda _u: b'')(username)
                        if s:
                            write_audit_baseline(username, s)
                except Exception:
                    pass
                self.passwordField.clear()
                return
            else:
                log.info(f"{kql.i('auth')} -> {kql.i('info')} [LOGIN] Not locked. {attempts_left} attempts left (user: {username})")

        # Password validation (read-only)
        if not validate_login(username, pw_str):
            try:
                append_audit_log(username, "login_attempt", "fail")
            except Exception:
                pass

            locked_after, attempts_left_after, mins_left_after = audit_is_locked_out(
                username, threshold, window_mins, cooldown_mins)

            if locked_after:
                log.info(f"{kql.i('auth')} -> {kql.i('warn')} [LOGIN] Too many failed attempts — account LOCKED (user: {username}; ~{mins_left_after} min left)")
                try:
                    msg = self.tr("{ok} Too many failed login attempts — Account LOCKED").format(ok=kql.i("warn"))
                    log_event_encrypted(username, self.tr("login"), msg)
                    try:
                        preauth_log_event(str(_cfgdir(username, ensure_parent=False)), username, "login_failed",
                                          {"reason": "Too many failed login attempts — Account LOCKED"})
                    except Exception:
                        pass
                except Exception:
                    pass
                self.set_status_txt(self.tr("Locked User"))
                QMessageBox.critical(
                    self, self.tr("Account Locked"),
                    self.tr("Too many failed attempts.\nTry again in about {mins_left_after1} minute(s).").format(mins_left_after1=mins_left_after)
                )
            else:
                log.info(f"{kql.i('auth')} -> {kql.i('warn')} [LOGIN] Invalid credentials (user: {username}); {attempts_left_after} attempts left")
                try:
                    msg = self.tr("{ok} Failed login attempt").format(ok=kql.i("warn"))
                    log_event_encrypted(username, self.tr("login"), msg)
                    try:
                        preauth_log_event(str(_cfgdir(username, ensure_parent=False)), username, "login_failed",
                                          {"reason": "Failed login attempt"})
                    except Exception:
                        pass
                except Exception:
                    pass
                self.set_status_txt(self.tr("Wrong password — {attempts_left_after1} left").format(attempts_left_after1=attempts_left_after))

            try:
                if write_audit_baseline:
                    s = _aw('_load_vault_salt_for', lambda _u: b'')(username)
                    if s:
                        write_audit_baseline(username, s)
            except Exception:
                pass

            self.passwordField.clear()
            self.passwordField.setPlaceholderText(self.tr("Incorrect credentials!"))
            return

    # ---------- WRITE-ALLOWED PHASE ----------
    self.passwordField.setPlaceholderText(self.tr("Password ok Unlocking"))
    self.set_status_txt(self.tr("Password ok"))

    # IMPORTANT: do NOT keep plaintext password around
    self.current_password = None

    try:
        # Derive vault KEK (pw_kek) using the account's authoritative KDF profile.
        # This must match account creation / normal password login / WRAP enable.
        self._pw_kek = _derive_vault_key_for_user(username, pw_buf, salt)

        # Derive identity-store KEK using identity wrapper salt if present
        self._identity_kek = None
        try:
            import base64
            import auth.identity_store as _ids

            salt_b = None
            try:
                _pfn = getattr(_ids, "_user_id_file", None)
                _hfn = getattr(_ids, "_read_header", None)
                if callable(_pfn) and callable(_hfn):
                    _p = _pfn(username, ensure_parent=False)
                    if _p and hasattr(_p, "exists") and _p.exists():
                        _hdr = _hfn(_p) or {}
                        _wr = (_hdr.get("wrappers") or []) if isinstance(_hdr, dict) else []
                        for _w in _wr:
                            if isinstance(_w, dict) and str(_w.get("type") or "").strip().lower() == "password":
                                _sb64 = str(_w.get("salt") or "").strip()
                                if _sb64:
                                    salt_b = base64.b64decode(_sb64 + "===")
                                break
            except Exception:
                salt_b = None

            # NOTE: old: self._identity_kek = derive_key_argon2id(pw_str, salt_b or salt)
            self._identity_kek = derive_key_argon2id_from_buf(pw_buf, salt_b or salt)
        except Exception:
            self._identity_kek = None

        # Keep plaintext password only for this password-login transaction.
        # Do NOT replace it with identity_kek bytes here; that caused type confusion
        # and made the normal password path diverge from account creation.
        self.current_password = pw_str if isinstance(pw_str, str) and pw_str else None

    finally:
        # Keep a short-lived copy for native session open below (will be cleared right after).
        pw_str_session = pw_str
        # Drop plaintext string reference ASAP
        pw_str = None

        # Wipe mutable password buffer
        try:
            core = get_core()
            if core:
                core.secure_wipe(pw_buf)
            else:
                for i in range(len(pw_buf)):
                    pw_buf[i] = 0
        except Exception:
            pass

    # Decide whether this login requires YubiKey WRAP.
    # If WRAP is enabled, we must NOT treat pw_kek as the vault master key.
    _yk_mode = ""
    try:
        _yk_mode, _ = yk_twofactor_enabled(username, password_or_kek=getattr(self, "current_password", None))
        _yk_mode = (_yk_mode or "").strip().lower()
    except Exception:
        _yk_mode = ""

    try:
        self._login_requires_yubi_wrap = (_yk_mode == "yk_hmac_wrap")
    except Exception:
        pass

    # Canonical session-open rule:
    # - Non-WRAP password login must match fresh account creation and open the
    #   native vault session directly from plaintext password + authoritative salt.
    # - WRAP login must stay locked here and wait for the YubiKey/recovery flow
    #   to produce the real master key.
    try:
        from native.native_core import get_core
        core = get_core()

        if not getattr(self, "_login_requires_yubi_wrap", False):
            if not isinstance(locals().get("pw_str_session"), str) or not pw_str_session:
                raise RuntimeError("Password string missing during non-WRAP native session open")

            pw_buf2 = bytearray(pw_str_session.encode("utf-8"))
            try:
                # KDF profile selection (v1 vs v2+) is per-account and stored in user_db.json.
                # v1: core.open_session(password, salt)
                # v2+: core.open_session_ex(password, salt, time_cost, memory_kib, parallelism)
                try:
                    from auth.login.login_handler import get_user_record
                    from vault_store.kdf_utils import normalize_kdf_params
                    _rec = get_user_record(username) or {}
                    _kdf = normalize_kdf_params(_rec.get("kdf"))
                except Exception:
                    _kdf = {"kdf_v": 1}

                try:
                    self._last_kdf = dict(_kdf or {})
                except Exception:
                    pass

                kdf_v = 1
                try:
                    kdf_v = int((_kdf or {}).get("kdf_v", 1))
                except Exception:
                    kdf_v = 1

                if kdf_v >= 2:
                    if not hasattr(core, "open_session_ex"):
                        raise RuntimeError("This account uses KDF v2+, but the native DLL does not support kq_session_open_ex.")
                    self.core_session_handle = int(core.open_session_ex(
                        pw_buf2,
                        salt,
                        time_cost=int((_kdf or {}).get("time_cost", 4)),
                        memory_kib=int((_kdf or {}).get("memory_kib", 512_000)),
                        parallelism=int((_kdf or {}).get("parallelism", 2)),
                    ))
                else:
                    if hasattr(core, "open_session"):
                        self.core_session_handle = int(core.open_session(pw_buf2, salt))
                    else:
                        lib = getattr(core, "lib", None)
                        fn = getattr(lib, "kq_session_open", None) if lib else None
                        if not fn:
                            mod = getattr(type(core), "__module__", "?")
                            raise AttributeError(
                                "Native core wrapper missing open_session() and DLL export kq_session_open not found. "
                                f"core_type={type(core)!r} module={mod!r} lib={lib!r}"
                            )

                        out = c_void_p() #type: ignore 
                        rc = int(fn(_as_ubyte_ptr_copy(bytes(pw_buf2)), len(pw_buf2), _as_ubyte_ptr_copy(bytes(salt)), len(salt), C.byref(out))) #type: ignore 
                        if rc != 0 or not out.value:
                            raise RuntimeError(f"kq_session_open failed rc={rc}")
                        self.core_session_handle = int(out.value)

                log.info("[LOGIN] canonical non-WRAP session opened from password path (handle=%s)", self.core_session_handle)
            finally:
                try:
                    core.secure_wipe(pw_buf2)
                except Exception:
                    for i in range(len(pw_buf2)):
                        pw_buf2[i] = 0

                try:
                    pw_str_session = ""
                except Exception:
                    pass
        else:
            self.core_session_handle = None
            log.info("[LOGIN] WRAP account detected; waiting for YubiKey unwrap before opening vault session")

    except Exception as e:
        self.core_session_handle = None
        log.exception("[LOGIN] Failed to open native session: %s", e)
        try:
            if is_dev:
                QMessageBox.warning(self, self.tr("Login failed"), f"Native session error:\n{repr(e)}")
            else:
                QMessageBox.warning(self, self.tr("Login failed"), self.tr("Native encryption core unavailable."))
        except Exception:
            pass
        return
    try:
        self._yk_completed = False
    except Exception:
        pass

    try:
        log.info(
            "[LOGIN] mode=%s current_password_type=%s pw_kek=%s identity_kek=%s session=%s",
            "wrap" if getattr(self, "_login_requires_yubi_wrap", False) else "plain",
            type(getattr(self, "current_password", None)).__name__,
            isinstance(getattr(self, "_pw_kek", None), (bytes, bytearray)),
            isinstance(getattr(self, "_identity_kek", None), (bytes, bytearray)),
            bool(getattr(self, "core_session_handle", None)),
        )
    except Exception:
        pass

    _continue_after_factors(self, username)
    return

# Centralized post-factor completion handler to finalize login.
def _finish_login(self, username: str, master_key: bytes, yk_record: dict | None = None) -> None:
    """
    Single place to finalize login after all factors (password + YubiKey/recovery) succeed.
    - Preferred: opens a native DLL session from master_key (WRAP DLL-reliant)
    - Backward compatible: falls back to self.core_session_handle bytes if DLL/session unavailable
    - Abort login if vault decrypt fails (never silently show empty vault)
    """
    try:

        # 1) Validate master key
        if not isinstance(master_key, (bytes, bytearray)) or not master_key:
            raise ValueError("Missing/invalid master key after YubiKey step.")

        # 2) Preferred: open DLL session from master key (key stays inside native core)
        self.core_session_handle = None
        used_session = False

        try:
            try:
                from native.native_core import get_core
            except Exception:
                get_core = None

            core = get_core() if callable(get_core) else None

            if core and hasattr(core, "open_session_from_key"):
                mk_ba = bytearray(master_key)
                try:
                    self.core_session_handle = core.open_session_from_key(mk_ba)
                    used_session = bool(self.core_session_handle)
                finally:
                    # Always wipe temp key buffer
                    try:
                        core.secure_wipe(mk_ba)
                    except Exception:
                        for i in range(len(mk_ba)):
                            mk_ba[i] = 0
        except Exception:
            self.core_session_handle = None
            used_session = False

        # 3) Keep the native session handle when DLL login succeeded.
        # Only fall back to raw key bytes on older/non-DLL paths.
        if used_session:
            try:
                if not isinstance(self.core_session_handle, int) or self.core_session_handle <= 0:
                    raise RuntimeError("Native session creation returned an invalid handle.")
            except Exception:
                self.core_session_handle = None
                used_session = False

        if not used_session:
            # Legacy behavior (still works if DLL missing/old)
            self.core_session_handle = bytes(master_key)

        # 4) Audit + lockout reset (best-effort)
        try:
            self.current_username = username
        except Exception:
            pass
        try:
            if hasattr(self, "currentUsername") and self.currentUsername is not None:
                self.currentUsername.setText(username)
        except Exception:
            pass
        try:
            self.vault_unlocked = False
            self._vault_session_ready = False
        except Exception:
            pass
        try:
            self._login_requires_yubi_wrap = False
        except Exception:
            pass
        try:
            reset_login_failures(username)
        except Exception:
            pass
        try:
            log_event_encrypted(username, self.tr("login_success"), {"yk": bool(yk_record), "session": int(bool(used_session))})
        except Exception:
            pass

        # 5) Load (or seed) the user’s vault so UI can render
        # IMPORTANT: abort login if vault decrypt fails (never show empty vault due to wrong key)
            try:
                seed_vault(username)
            except Exception:
                pass

            _maybe_unwrap_to_vault_session(self, username)

            key_or_session = self.core_session_handle or getattr(self, "core_session_handle", None)
            if not key_or_session:
                raise RuntimeError("No vault unlock material available (session/key missing).")

            vault_loaded = load_vault(username, key_or_session)
            if vault_loaded is False:
                raise RuntimeError("Vault loader reported failure.")
            try:
                self.vault_unlocked = True
                self._vault_session_ready = True
            except Exception:
                pass

        except Exception as e:
            # Stop login and keep user on login screen
            self._login_finalized = False

            # Close native session if we created one
            try:
                if self.core_session_handle:
                    try:
                        from native.native_core import get_core
                        core = get_core()
                        if core:
                            core.close_session(self.core_session_handle)
                    except Exception:
                        pass
                self.core_session_handle = None
            except Exception:
                pass

            # Clear any legacy key
            try:
                if hasattr(self, "core_session_handle"):
                    self.core_session_handle = None
            except Exception:
                pass
            try:
                self.vault_unlocked = False
                self._vault_session_ready = False
            except Exception:
                pass

            QMessageBox.critical(
                self,
                self.tr("Vault Decryption Failed"),
                self.tr(
                    "Keyquorum could not decrypt your vault.\n\n"
                    "This usually means:\n"
                    "• The wrong key was used (WRAP/Yubi still required), or\n"
                    "• Your restored vault/salt/identity data does not match, or\n"
                    "• The vault file is corrupted.\n\n"
                    "Login was stopped to protect your data."
                ) + f"\n\n{e}"
            )
            return

        # 6) Update integrity baseline (vault/salt/user_db)
        try:
            update_baseline(username=username, verify_after=False, who="integrity baseline")
        except Exception as e:
            log.error(f"[baseline] update after login failed for {username}: {e}")

        try:
            if hasattr(self, "currentUsername"):
                self.currentUsername.setText(username)
        except Exception:
            pass

        # 7) Switch UI only AFTER vault successfully loads
        try:
            if hasattr(self, "stackedWidget"):
                self.stackedWidget.setCurrentIndex(1)
        except Exception:
            pass
        try:
            if hasattr(self, "mainTabs"):
                self.mainTabs.setCurrentIndex(0)
        except Exception:
            pass

        # 8) Refresh controls that depend on login
        try: self.refresh_recovery_controls()
        except Exception: pass
        try: self._auth_reload()
        except Exception: pass
        try: self._reload_table()
        except Exception: pass

        # 9) Start/Reset session timers, clipboard guards, etc.
        try: self.reset_logout_timer()
        except Exception: pass
        try: install_clipboard_guard(self)
        except Exception: pass

        # 10) Optional one-time clipboard history warning on Windows
        try: maybe_warn_windows_clipboard(self, username, copy=False)
        except Exception: pass

        try:
            self.vault_unlocked = True
            self._vault_session_ready = True
            self.mainTabs.setVisible(True)
            if getattr(self, "widget", None):
                self.widget.hide()
        except Exception:
            pass

        self._login_finalized = True

    except Exception as e:
        self._login_finalized = False
        QMessageBox.critical(self, self.tr("Login failed"), f"{e}")

# The main successful login handler called after all factors complete.
def successful_login(self, *args, **kwargs):
    log.info(f"{kql.i('sign')} ->  [S-LOGIN] successful_login reached ✅")
    
    username = (kwargs.get("username") or getattr(self, "current_username", None) or "").strip()
    if not username:
        try:
            username = (self.currentUsername.text() or "").strip()
        except Exception:
            username = ""

    if username:
        try:
            username = (_canonical_username_ci(username) or username).strip()
        except Exception:
            pass
    else:
        raise ValueError("Login finalized but username is empty (currentUsername widget blank).")

    # Persist session username IMMEDIATELY (auth tab relies on this)
    self.current_username = username
    # WRAP/native-session flows may already have fully finalized login in _finish_login().
    already_finalized = bool(getattr(self, "_login_finalized", False))

    # ================
    # - user checks
    # ================

    # -------
    # Remember this device (Windows DPAPI) - STRICT DLL-only v4 token only
    # - Legacy v2/v3 tokens are never created.
    # - If an existing legacy token is present, it is purged.
    # - Passwordless unlock is only allowed when no identity-backed factors are enabled.
    # -------
    try:
        from qtpy.QtWidgets import QMessageBox

        # Checkbox lives on login UI; if not present, skip silently
        cb = getattr(self, "rememberDeviceCheckbox", None)
        remember = bool(cb and cb.isChecked())

        try:
            log.info("[HELLO] remember-device store start user=%s checked=%s", username, remember)
        except Exception:
            pass

        rec = get_user_record(username) or {}

        # Always purge legacy tokens (v2/v3/unknown), stop looping forever in strict mode.
        try:
            du = rec.get("device_unlock") or {}
            v = int(du.get("v") or 0)
            kind = (du.get("kind") or "").strip().lower()
            if du and (v != 4 or kind != "dpapi_session"):
                rec = clear_device_unlock(rec)
                set_user_record(username, rec)
        except Exception:
            pass

        if remember:
            # Store v4 token from the existing native session handle (no key in Python).
            from native.native_core import get_core
            from device.utils_device import hwfp_sha256
            core = get_core()
            sess = getattr(self, "core_session_handle", None)
            export_fn = (
                getattr(core, "session_export_key_dpapi", None)
                or getattr(core, "session_export_dpapi", None)
            )

            if not (isinstance(sess, int) and sess > 0 and core is not None and callable(export_fn)):
                raise RuntimeError(
                    f"core session export not available (sess={sess!r}, export_fn={bool(callable(export_fn))})"
                )

            # Default TTL policy (do NOT clobber 0 if you ever use it for "never")
            try:
                ttl_days = rec.get("ttl_days", None)
                if ttl_days is None:
                    ttl_days = 30
                else:
                    ttl_days = int(ttl_days)
                    if ttl_days < 0:
                        ttl_days = 30
            except Exception:
                ttl_days = 30

            # Device label (fix Exception typo)
            try:
                fp, data = get_device_fingerprint()
                device_name = (data or {}).get("deviceName", "") or ""
            except Exception:
                device_name = ""

            now = int(time.time())
            hwfp = hwfp_sha256()

            # If we already have a valid token for THIS device, do not mint a new one
            idx, existing = _find_best_device_token_v4(rec, hwfp=hwfp, now=now)

            if existing and not _should_refresh_token(existing, now=now, refresh_window_days=3):
                # Just mark last-used, keep token stable (no new "created_ts" each login)
                try:
                    existing["last_used_ts"] = now
                    toks = rec.get("device_unlock_tokens") or []
                    if isinstance(toks, list) and idx is not None and 0 <= idx < len(toks):
                        toks[idx] = existing
                        rec["device_unlock_tokens"] = toks
                    # Keep back-compat pointer to the selected token
                    rec["device_unlock"] = existing
                except Exception:
                    pass

                log.info("[HELLO] remember-device token already valid for this device; skipping re-mint (v=4)")
            else:
                # Mint a new token (expired/missing/near-expiry)
                rec = save_device_unlock_v4_from_session(
                    rec,
                    core=core,
                    session_handle=int(sess),
                    ttl_days=ttl_days,
                    device_label=device_name,
                )

                # Better log keys for v4
                du = rec.get("device_unlock") or {}
                wrapped = du.get("wrapped_b64") or ""
                log.info(
                    "[HELLO] device_unlock stored v=%s kind=%s len=%s",
                    du.get("v"),
                    du.get("kind"),
                    len(wrapped) if isinstance(wrapped, str) else 0,
                )

            # Persist
            set_user_record(username, rec)

            try:
                update_baseline(username=username, verify_after=False, who=self.tr("Remember device enabled"))
            except Exception as e:
                log.error("[BASELINE] remember-device baseline update failed: %s", e)

        else:
            # Only clear if the user explicitly turned it off during a password login.
            # During DPAPI logins, the UI may not keep the checkbox state, so do NOT auto-clear.
            if getattr(self, "_dpapi_login_active", False):
                log.info("[HELLO] DPAPI login active: preserving existing device token (not clearing).")
          
            # Do not auto-clear during DPAPI logins; checkbox state may reset in the UI.
            if getattr(self, "_dpapi_login_active", False):
                try:
                    log.info("[HELLO] DPAPI login active: preserving device token (not clearing).")
                except Exception:
                    pass
            else:
                rec = clear_device_unlock(rec)
                set_user_record(username, rec)
                try:
                    log.info("[HELLO] remember-device disabled: token cleared.")
                except Exception:
                    pass
                log.info("[HELLO] remember-device disabled: token cleared.")
    except Exception as e:
        # Never fall back to legacy tokens in strict mode.
        try:
            cb = getattr(self, "rememberDeviceCheckbox", None)
            if cb:
                cb.setChecked(False)
        except Exception:
            pass
        try:
            # If DPAPI login is active, do NOT clear the token on store failure.
            if getattr(self, "_dpapi_login_active", False):
                log.info("[HELLO] DPAPI login active: not clearing device token after store failure.")
            else:
                from auth.windows_hello.session import clear_device_unlock
                rec = get_user_record(username) or {}
                rec = clear_device_unlock(rec)
                set_user_record(username, rec)
        except Exception:
            pass
        try:
            log.warning("[HELLO] remember-device v4 store failed: %s", e)
        except Exception:
            pass

    # -------
    # Remember Last Username (Windows) - store/clear in QSettings
    # -------
    try:
        from qtpy.QtCore import QSettings
        cb_user = getattr(self, "remember_username", None)
        s = QSettings("AJHSoftware", "KeyquorumVault")

        if cb_user is not None and cb_user.isChecked():
            s.setValue("login/remembered_username", username)
            log.info("[LOGIN] remember-username saved user=%s", username)
        else:
            s.remove("login/remembered_username")
            log.info("[LOGIN] remember-username cleared")
    except Exception:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Remember Last Username {e}")

    # -------
    # Salt migration: after a successful login, ensure master salt is stored in identity header
    # (best-effort; never break login)
    # -------
    try:
        from auth.salt_file import maybe_migrate_master_salt_to_identity
        _salt = getattr(self, '_login_salt', None)
        if isinstance(_salt, (bytes, bytearray)) and _salt:
            maybe_migrate_master_salt_to_identity(self, username, bytes(_salt))
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Post-login Salt Migration Skipped: {e}")

    _aw('notify_usb_loaded_once', lambda *a, **k: None)(self, username)

    try: # Start watching for USB removal when in portable mode
        self._start_usb_watch_if_needed()

    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN]  Watching For USB Removal Portable Mode")

    try:  # Compute per-session password strength score (used for Security Center)
        from auth.pw.password_utils import estimate_strength_score
        pw = getattr(self, "current_password", "") or ""
        if isinstance(pw, str) and pw:
            self.ps_score = int(estimate_strength_score(pw) or 0)
        else:
            self.ps_score = None
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Failed to compute password strength score: %s", e)
        self.ps_score = None
    
    try:  # Immediately wipe plaintext password from memory
        self.current_password = None
    except Exception:
        pass

    # Note: Sync Not Working remove for now stop show
    self.cloud_widget.show()

    if not already_finalized:
        # WRAP accounts must NOT unlock vault until YubiKey completes
        if getattr(self, "_login_requires_yubi_wrap", False):
            log.info("[LOGIN] WRAP pending — vault locked until YubiKey completes")
            self.current_mk = None
            self.vault_unlocked = False
        else:
            # STRICT DLL-ONLY: vault is unlocked only when we have a native session handle.
            sess = getattr(self, "core_session_handle", None)
            if not isinstance(sess, int) or sess <= 0:
                log.error("[LOGIN] successful_login reached without native session; aborting login")
                try:
                    QMessageBox.warning(
                        self,
                        self.tr("Login failed"),
                        self.tr("Missing encryption session. Please sign in again.")
                    )
                except Exception:
                    pass
                return

            # STRICT MODE:
            # - Keep the native session handle alive for the duration of the app session
            # - Do NOT keep Python master keys
            try:
                self._pw_kek = None
                self._identity_kek = None
            except Exception:
                pass

            self.current_mk = None
            self.vault_unlocked = True

        self.set_status_txt(self.tr("All passed — logging user in"))

        # show main tabs, focus Vault tab, login ui
        self.mainTabs.setVisible(True)
        self.mainTabs.setCurrentWidget(self.findChild(QWidget, "vaultTab"))
    log.info(f" {kql.i('auth')} -> {kql.i('ok')} [2FA] Successful Login")

    try: # set size/geometry after switching UI
        self.set_status_txt(self.tr("Set Size"))
        self._restore_maximized = self.isMaximized()
        QTimer.singleShot(0, self._apply_vault_geometry)
        log.info(f"{kql.i('ok')} -> {kql.i('ui')} [S-LOGIN] Size Set Login")
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] setting size error: {e}")

    try:  # hide login container if present
        if getattr(self, "widget", None):
            self.widget.hide()
            log.info(f"{kql.i('sign')} ->  [S-LOGIN] Hidden Login Ui")
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] hide login widget/container {e}")

    # ================
    # user main login
    # ================

    try: # Reset lockout counter on full success
        reset_login_failures(username)
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Reset Lock Out {e}")

    import app.kq_logging as kqlib

    try:
        kqlib.set_log_user(username)
    except Exception as e:
        log.error(f"LOG FILE NOW {e}")

    try: # switch logs to per-user file  # Note: not working
        _aw('switch_to_user_log' , lambda *a, **k: None)(username)
        log.info(f" {kql.i('auth')} -> {kql.i('ok')} [S-LOGIN] User Logs")
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Switch User Log: {e}")

    try:  # paths debug (unified)
        self.set_status_txt(self.tr("Logging paths"))
        debug_log_paths(username)
        log.info(f"{kql.i('sign')} ->  [S-LOGIN] Log Users Paths")
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] paths debug {e}")

    try:  # Authenticator Store
       
        self.set_status_txt(self.tr("Loading Authenticator"))
        if self.core_session_handle:
            _auth_after_login(self)
            log.info(f"{kql.i('sign')} ->  [S-LOGIN] Authenticator")
            # _auth_set_enabled(self, True)  # already set in _auth_after_login; avoid double-setting which may trigger extra events
        else:
            _auth_set_enabled(self, False)
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Auth Loading Failed, set to False Error: {e}")
        try:
            _auth_set_enabled(self, False)
        except Exception:
            pass

    try:  # Catalog
        self.set_status_txt(self.tr("Setting User Catalog"))
        # IMPORTANT: _load_catalog_effective expects the *username* (it resolves paths internally).
        # Passing a config directory path breaks catalog decryption/creation.
        from catalog_category.catalog_category_ops import _load_catalog_effective
        self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE, self.AUTOFILL_RECIPES, _ = _load_catalog_effective(self, username)
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Catalog error: {e}")

    try:  # Category editor/tab init
        self.init_category_editor_tab(username) 
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Category Error: {e}")

    if is_dev:  # Dev mode load testing 
        try:
            self._init_passkeys_store()
        except Exception as e:
            log.info(f"{kql.i('err')}[S-LOGIN] Passkey Sync: {e}")
        try:
            self._reload_passkeys_for_current_user()
        except Exception as e:
           log.info(f"{kql.i('err')} [S-LOGIN] Reload On Login Failed: {e}")

    try:  # Profile picture (best effort)
        self.set_status_txt(self.tr("Loading Profile Picture"))
        self.load_profile_picture()
        log.info(f"{kql.i('sign')} ->  [S-LOGIN] Loaded Profile Picture")
    except Exception:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] profile picture")

    try:  # Bridge start (UI bus + token)
        log.info(f"{kql.i('sign')} ->  [S-LOGIN] Web Bridge Started")
        self.set_status_txt(self.tr("Starting Web Bridge"))
        if not hasattr(self, "_uibus"):
            self._uibus = _UiBus(self)

        token = ensure_bridge_token(username, new=False)
        httpd = getattr(self, "_bridge_httpd", None)
        if not httpd:
            log.error("%s [S-LOGIN] bridge failed to start", kql.i('err'))
        else:
            port = int(getattr(self, "_bridge_port", 8742))
            t = token or getattr(self, "_bridge_token", "") or ""
            tmask = f"{t[:6]}…{t[-6:]}" if t else "None"
            log.info("✅ [S-LOGIN] bridge online at 127.0.0.1:%s • token=%s", port, tmask)
    except Exception:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Bridge Failed to start")

    # 🔧 Ensure sync engine is ready AFTER login, but DEBUG PATCH: do NOT sync here.
    try:
        from features.sync.sync_ops import _configure_sync_engine

        username = self._active_username()
        log.warning("### DEBUG PATCH auth_flow post-login init username=%r ###", username)
        if username:
            _configure_sync_engine(self, username, "post-login-init")
            log.info("[CLOUD] engine init completed at login (debug patch, no sync)")
    except Exception as e:
        log.debug(f"[CLOUD] engine init failed at login: {e}")

    try:
        log.warning("### DEBUG PATCH auth_flow intentionally skipped login cloud sync ###")
        log.info(f"{kql.i('sign')} ->  [S-LOGIN] Cloud sync skipped (debug patch)")
    except Exception:
        pass
    
    try:  # Windows clipboard risk warning (once)
        maybe_warn_windows_clipboard(self, username)
        log.info(f"{kql.i('sign')} ->  [S-LOGIN] Windows clipboard")
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Windows clipboard {e}")

    try:  # purge trash
        from vault_store.soft_delete_ops import _auto_purge_trash
        _auto_purge_trash(self)
        log.info(f"{kql.i('sign')} ->  [S-LOGIN] Purge Trash")
    except Exception:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Purge Trash")

    try:  # full backup reminder check
        if getattr(self, "full_backup_reminder", None):
            self.full_backup_reminder.maybe_prompt()
            log.info(f"{kql.i('sign')} ->  [S-LOGIN] Backup Reminder")
    except Exception:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Backup Reminder")

    try:  # backup codes check
        check_backup_codes_ok(username, "both")
        log.info(f"{kql.i('sign')} ->  [S-LOGIN] Backup Code Check")
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Backup Code Check {e}")

    try: # reminder check start
        self.start_watchtower_reminder_worker()
        start_reminder_checks(self,)
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Reminder Check {e}")

    try: # Load User Settings
        self.load_setting(first_load=True)
    except Exception as e:
        log.exception(f"{kql.i('sign')} -> {kql.i('err')} [S-LOGIN] Error Loading Settings {e}")

# Lightweight baseline check before full login.
def _prelogin_baseline_peek(self, username: str):
    """
    Lightweight baseline check before full login.

    - Logs status, NEVER blocks login
    - Returns result for the caller to optionally warn the user
    """

    username = (username or "").strip()
    if not username:
        return None

    try:
        from security.baseline_signer import checkbasline
        changed, missing, new_, mac_ok = checkbasline(username)
        log.info(
            "[baseline] prelogin peek: user=%s mac_ok=%s changed=%d missing=%d new=%d",
            username, mac_ok, len(changed), len(missing), len(new_),
        )
        
        def _warn_once(msg: str):
            self._prelogin_baseline_warned = True
            try:
                self._show_login_baseline_warning(msg)
            except Exception:
                try:
                    log.warning(msg)
                except Exception:
                    pass

        # 1) MAC failed = strong warning
        if not mac_ok:
            _warn_once(
                "⚠️ Your baseline signature could not be verified.\n\n"
                "This can happen after app updates, restores, or moving files.\n"
                "It can also indicate tampering.\n\n"
                "If you didn’t expect any changes, restore from a known-good backup "
                "before relying on this device."
            )
            set_remember_checkbox(self, False)
            return

        # 2) No differences = stay quiet on the login screen
        if not changed and not missing and not new_:
            set_remember_checkbox(self, True)
            return

        # 3) Differences present → short, friendly warning
        bullets: list[str] = []
        if changed:
            set_remember_checkbox(self, False)
            bullets.append("• Some protected files have changed since your last trusted baseline.")
        if missing:
            set_remember_checkbox(self, False)
            bullets.append("• One or more expected files are missing (for example a vault or settings file).")
        if new_:
            set_remember_checkbox(self, False)
            bullets.append("• New files were found that were not in your last baseline.")

        msg = (
            "⚠️ Files differ from your trusted baseline.\n\n"
            "If you did not recently update Keyquorum Vault, restore data, or change "
            "security or account settings during your last login, this may indicate "
            "unexpected changes.\n\n"
            "It is strongly recommended that you review the Integrity Details or the "
            "Security Center after logging in (Settings → Pre-Security 🛡️). "
            "It may also help to review the audit log to confirm when settings were last changed. "
            "If anything looks unfamiliar, or if no settings were changed, it is highly "
            "recommended to restore from a recent full backup.\n\n"
            + ("\n".join(bullets) if bullets else "")
            + "\n\n"
            "Important:\n"
            "If login ever fails while your password is correct, your account data may "
            "have been corrupted or tampered with. In that situation, restoring from your "
            "most recent full backup is highly recommended."
        )
        _warn_once(msg)

    except Exception as e:
        log.warning("[baseline] prelogin peek: verify failed user=%s: %s", username, e)
        return None

# Cloud sync preparation before login.
def ensure_cloud_ready_before_login(self, username: str, interactive: bool = True) -> str:
    """
    Prepare the sync engine for this user *without* auto-pulling into an empty vault.
    - Initializes/loads engine state for `username`
    - Detects if a remote vault exists while local is empty
    - Prompts (if interactive) to bootstrap by downloading the remote
    - Never blocks login if anything fails

    Returns one of: "ready", "downloaded", "skipped", "no-engine", "error".
    """
   
    eng = getattr(self, "sync_engine", None)
    if not eng:
        log.info("no sync engine")
        return "no-engine"

    # Small helpers for tolerant engine calls
    def _call(obj, name, *a, **k):
        fn = getattr(obj, name, None)
        if callable(fn):
            return fn(*a, **k)
        return None

    # Pause now; always try to resume in finally
    _call(eng, "pause")

    try:
        # Fresh namespace for the chosen user
        _call(eng, "reset_state")
        _call(eng, "set_user", username)
        _call(eng, "load_local_state")

        # Remote head (truthy if remote exists)
        head = _call(eng, "read_remote_head")
        remote_ok = bool(head)

        # Local hash (truthy if there is local content)
        local_hash = _call(eng, "compute_local_hash")
        local_ok = bool(local_hash)

        # If remote exists but local is empty -> optionally bootstrap
        if remote_ok and not local_ok:
            # Default decision: only download when explicitly confirmed
            want_download = False
            if interactive and QMessageBox is not None:
                resp = QMessageBox.question(
                    self,
                    "Cloud vault found",
                    "A cloud vault exists for this user.\n\n"
                    "Do you want to download it to this device now?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes,
                )
                want_download = (resp == QMessageBox.Yes)

            if want_download:
                # core_session_handle may not be present yet (pre-login); pass empty key safely
                key = getattr(self, "core_session_handle", b"") or b""
                ok = bool(_call(eng, "safe_download_if_nonempty", key))
                if ok:
                    _call(eng, "save_local_state", {"note": "bootstrap download"})
                    _call(eng, "resume_safe") or _call(eng, "resume")
                    return "downloaded"
                # fallthrough: download declined/failed → continue to ready

        # Nothing special to do — engine is primed
        _call(eng, "resume_safe") or _call(eng, "resume")
        log.info("Cloud sync ready")
        return "ready"

    except Exception as e:
        # Don’t block login; surface a gentle status line
        try:
            self.set_status_txt(
                self.tr("Cloud setup skipped: {err}").format(err=e)
            )
        except Exception:
            pass
        return "error"

# ==============================
# = Login screen picture update (live as user types) =
# ==============================

# Note: this is NOT for the profile picture in the main UI header; that is loaded once on login and is not expected to update live.
def update_login_picture(self, *args, **kwargs) -> None:
    """
    Update the login picture as the user types.
    - If the user exists and has a profile image → show it
    - If the user exists but has no image → show default app icon
    - If the user doesn't exist → show 'No Account'
    Does not create any directories.
    """
    try:
        if hasattr(self, "reset_logout_timer"):
            self.reset_logout_timer()

        lbl = getattr(self, "loginPicLabel", None)
        if lbl is None:
            return

        typed = (self.usernameField.text() or "").strip()
        # Keep 'Remember this device' checkbox synced while typing/selecting users
        try:
            _ensure_remember_device_checkbox_hooked(self)
            _sync_remember_device_checkbox_for_username(self, typed)
        except Exception:
            pass
        if not typed:
            lbl.setText(self.tr("No Account"))
            return

        # Handle dev commands first
        try:
            try:
                from app.owner import dev_cmd
            except Exception:
                dev_cmd = None
            if dev_cmd == None:
                log.info(f"[DEV_CMD] Owner File not loaded")
            elif dev_cmd(self, typed):
                return
        except Exception as e:
            log.error(f"[DEV_CMD] ignored error: {e}")

        # Canonicalize username
        try:
            username = _canonical_username_ci(typed) or typed
        except Exception:
            username = typed

        # --- Check if user exists ---
        user_exists = False
        try:
            rec = get_user_record(username) or {}
            user_exists = bool(rec)
        except Exception:
            rec = {}

        #Fallback: check per-user DB file (read-only)
        if not user_exists:
            try:
                from pathlib import Path
                from app.paths import user_db_file
                db_path = Path(user_db_file(username, ensure_parent=False))
                user_exists = db_path.is_file()
            except Exception:
                user_exists = False

        # --- User doesn't exist ---
        if not user_exists:
            lbl.setText(self.tr("No Account"))
            log.info(f"{kql.i('auth')} [LOGIN] No Account")
            return

        # --- Load zoom setting (optional, safe default 1.0) ---
        try:
            zoom = float(get_user_setting(username, "zoom_factor", 1.0) or 1.0)
            log.info(f"{kql.i('auth')} [LOGIN] UserZoom Set {zoom}")
        except Exception:
            zoom = 1.0

        # --- Try user profile image ---
        img_path = None
        try:
            from app.paths import profile_pic
            from pathlib import Path
            p = Path(profile_pic(username))
            if p.exists() and p.is_file():
                img_path = str(p)
        except Exception:
            pass
        log.info(f"{kql.i('auth')} [LOGIN] User Picture Path={img_path}")
        
        # --- If user has an image ---
        if img_path:
            try:
                self.set_rounded_profile_picture(lbl, img_path, zoom_factor=zoom)
                log.info(f"{kql.i('auth')} [LOGIN PIC] User Own Picture Set, zoom={zoom}")
                return
            except Exception as e:
                log.info(f"{kql.i('auth')} [LOGIN PIC] failed to load user image: {e}")

        # --- Otherwise show default app icon ---
        try:
            default_icon_path = icon_file("default_user.png")
            log.info(f"{kql.i('auth')} [LOGIN PIC] Defualt Picture being used {default_icon_path}, zoom={zoom}")
            self.set_rounded_profile_picture(lbl, default_icon_path, zoom_factor=zoom)
        except Exception as e:
            log.error(f"[LOGIN PIC] failed to show default icon: {e}")
            lbl.setText(username)

        # check basline login
        self._prelogin_baseline_peek(username)


    except Exception as e:
        log.error(f"[LOGIN PIC] update failed: {e}")


# Set a profile picture with circular cropping, optional zoom, and a glowing border effect. Caches the last key to avoid redundant redraws.
def set_rounded_profile_picture(self, label: QLabel, image_path: str, zoom_factor: float = 1.0) -> None:
    log.debug(f"[SET_ROUND_PIC] Zoom Set To={zoom_factor}")
    self.reset_logout_timer()   
    pixmap = QPixmap(image_path)
    if pixmap.isNull():
        pixmap = None
        if icon_file("default_user.png"):
            pixmap = QPixmap(icon_file("default_user.png"))
        if pixmap.isNull():
            label.setPixmap(QPixmap())
            label.setText(self.tr("No Image"))
            return
    # self.zoom_factor, 1.0
    size = max(48, min(label.width(), label.height()))
    crop_size = int(min(pixmap.width(), pixmap.height()) / max(zoom_factor, 1.0))  # 
    x = max(0, (pixmap.width() - crop_size) // 2)  #2
    y = max(0, (pixmap.height() - crop_size) // 2)  #2
    cropped = pixmap.copy(x, y, crop_size, crop_size)

    scaled = cropped.scaled(
        size, size,
        Qt.AspectRatioMode.KeepAspectRatioByExpanding,
        Qt.TransformationMode.SmoothTransformation
    )

    rounded = QPixmap(size, size)
    rounded.fill(Qt.GlobalColor.transparent)

    painter = QPainter(rounded)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    path = QPainterPath()
    margin = 1
    path.addEllipse(margin, margin, size - 2*margin, size - 2*margin)
    painter.setClipPath(path)
    painter.drawPixmap(0, 0, scaled)
    painter.end()

    label.setPixmap(rounded)
    label.setText("")

    # optional glow (keep if you like)
    try:
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(50)
        shadow.setOffset(0, 0)
        label.setGraphicsEffect(shadow)
        self.glow_shadow_effect = shadow
        self.glow_colors = [
            QColor(0, 200, 255), QColor(255, 0, 150), QColor(0, 255, 100),
            QColor(255, 255, 0), QColor(255, 80, 0),]

        self.current_glow_index = 0
        self.glow_fade = QVariantAnimation()
        self.glow_fade.setStartValue(50)
        self.glow_fade.setEndValue(200)
        self.glow_fade.setDuration(1000)
        self.glow_fade.setLoopCount(-1)
        self.glow_fade.valueChanged.connect(lambda a: self._update_glow_color(int(a)))
        self.glow_fade.start()

        def cycle_color():
            self.current_glow_index = (self.current_glow_index + 1) % len(self.glow_colors)

        self.color_timer = QTimer()
        self.color_timer.timeout.connect(cycle_color)
        self.color_timer.start(3000)

        def _update_glow_color(alpha):
            base = self.glow_colors[self.current_glow_index]
            self.glow_shadow_effect.setColor(QColor(base.red(), base.green(), base.blue(), alpha))
        self._update_glow_color = _update_glow_color
    except Exception as e:
        log.error(str(f"[DEBUG] Glow effect skipped: {e}"))

# Load the user's profile picture into the UI, with caching and fallback to default. 
# Uses a key based on username, image path, zoom, and label sizes to avoid redundant redraws.
def load_profile_picture(self, *, force: bool = False) -> None:
    log.info("load profile picture")
    try:
        lbl_a = getattr(self, "profilePicLabel", None)
        lbl_b = getattr(self, "profilePicLabel1", None)
        # username
        try:
            raw_user = (self._current_username_text() or "").strip()
        except Exception:
            try:
                raw_user = self._active_username()
            except Exception:
                raw_user = ""

        # zoom
        try:
            zoom = float(get_user_setting(raw_user, "zoom_factor", 1.0) or 1.0)
        except Exception:
            zoom = 1.0

        # canonical username
        if raw_user:
            try:
                username = self._canonical_ci(raw_user)
            except Exception:
                try:
                    username = _canonical_username_ci(raw_user) or raw_user
                except Exception:
                    username = raw_user
        else:
            username = ""

         # --- Try user profile image ---
        img_path = None
        try:
            from app.paths import profile_pic
            from pathlib import Path
            p = Path(profile_pic(username))
            if p.exists() and p.is_file():
                img_path = str(p)
        except Exception:
            pass
        # fallback to default_user.png -> icon.png
        if not img_path:
            try:
                p = icon_file("default_user.png")      # resources/icons/default_user.png
                img_path = str(p if p else "")
            except Exception:
                img_path = ""
            if not img_path or not Path(img_path).exists():
                try:
                    if hasattr(self, "res"):
                        img_path = str(icon_file("default_user.png"))
                except Exception:
                    img_path = "resources/icons/default_user.png"  # last-ditch

        # avoid redundant redraws
        w_a = lbl_a.width() if lbl_a else 0
        h_a = lbl_a.height() if lbl_a else 0
        w_b = lbl_b.width() if lbl_b else 0
        h_b = lbl_b.height() if lbl_b else 0
        key = (username, img_path, zoom, w_a, h_a, w_b, h_b)
        if not force and getattr(self, "_last_profile_pic_key", None) == key:
            return
        self._last_profile_pic_key = key

        if lbl_a:
            self.set_rounded_profile_picture(lbl_a, img_path, zoom)
        if lbl_b:
            QTimer.singleShot(0, lambda p=img_path, l=lbl_b, z=zoom: self.set_rounded_profile_picture(l, p, z))

    except Exception as e:
        log.error(f"[profile-pic] load failed: {e}")


# ==============================
# = Logout warning dialog with countdown and "Stay signed in" option =
# ==============================

# Show a warning dialog that the user will be logged out soon due to inactivity, 
# with a countdown timer and an option to stay signed in. If they choose to stay signed in, reset the logout timer; 
# if they dismiss, do nothing (timers continue counting down).
def _show_logout_warning(self, *args, **kwargs):
    # If already open, don't spawn another
    if getattr(self, "_warning_dialog", None) is not None:
        return

    # Compute seconds remaining
    secs_left = self._seconds_until_logout()
    if secs_left <= 0:
        # Race: just logout
        self.force_logout()
        return

    msg = QMessageBox(self)
    msg.setWindowTitle(self.tr("You’ll be signed out soon"))
    msg.setIcon(QMessageBox.Icon.Warning)
    msg.setStandardButtons(QMessageBox.StandardButton.Ok)
    # Add a custom "Stay signed in" button
    extend_btn = msg.addButton(self.tr("Stay signed in"), QMessageBox.ButtonRole.AcceptRole)
    msg.setDefaultButton(extend_btn)

    # Use a small text that updates every second
    def _update_label():
        s = self._seconds_until_logout()
        if s <= 0:
            try:
                msg.close()
            except Exception:
                pass
            self.force_logout()
            return
        msg.setText(self.tr("Due to inactivity, you will be signed out in ") + f"<b>{s}</b>" + self.tr(" seconds."))
    _update_label()

    # Hook the global 1s ticker to update the label while dialog is visible
    def _maybe_update():
        if getattr(self, "_warning_dialog", None) is msg:
            _update_label()
    try:
        self._warning_update_conn = self._tick.timeout.connect(_maybe_update)  
    except Exception:
        pass

    self._warning_dialog = msg
    res = msg.exec()

    # User clicked something; clear dialog
    self._warning_dialog = None
    try:
        # disconnect temporary updater
        self._tick.timeout.disconnect(_maybe_update)  
    except Exception:
        pass

    # If they clicked "Stay signed in", treat as activity
    if msg.clickedButton() == extend_btn:
        self.reset_logout_timer()
    else:
        # If they dismissed with OK, do nothing (timers continue counting down)
        pass


# ==============================
# --- reminder 
# ==============================
def start_reminder_checks(self):
    self._reminder_timer = QTimer(self)
    self._reminder_timer.timeout.connect(self.run_reminder_checks)
    self._reminder_timer.start(15 * 60 * 1000)  # every 15 mins

    # run once right away
    self.run_reminder_checks()
