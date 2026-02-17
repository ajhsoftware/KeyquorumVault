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
from security.baseline_signer import update_baseline
import sys as _sys
import re as _re
import datetime as dt 
from vault_store.vault_store import _dec_backup_bytes, load_vault, seed_vault
import http.client, json
import app.kq_logging as kql
import logging
log = logging.getLogger("keyquorum")
from auth.identity_store import has_totp_quick, get_yubi_config, get_login_backup_count_quick
from auth.login.login_handler import ( validate_login, _canonical_username_ci, get_user_setting, reset_login_failures, get_user_record,)
import socket
from vault_store.authenticator_store import (add_from_otpauth_uri, add_authenticator, list_authenticators, build_otpauth_uri,)
from features.clipboard.secure_clipboard import install_clipboard_guard
from app.paths import (users_root, debug_log_paths, is_portable_mode, users_root, config_dir, icon_file)
from app.basic import _UiBus
from security.secure_audit import log_event_encrypted
from auth.tfa.twofactor import has_recovery_wrap, get_wrapped_key_path
from ui.ui_flags import maybe_warn_windows_clipboard
from app.basic import is_dev
try:
    import cv2  # OpenCV for QR decoding
except Exception:
    cv2 = None

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

# --- YubiKey config helpers (bytes-safe) -------------------------------------
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


# --- remember/remove remeber ---
from qtpy.QtCore import QSettings

_KQ_SETTINGS_ORG = "AJHSoftware"
_KQ_SETTINGS_APP = "KeyquorumVault"

def _load_remembered_username() -> str:
    s = QSettings(_KQ_SETTINGS_ORG, _KQ_SETTINGS_APP)
    return (s.value("login/remembered_username", "") or "").strip()

def _save_remembered_username(username: str | None):
    s = QSettings(_KQ_SETTINGS_ORG, _KQ_SETTINGS_APP)
    if username:
        s.setValue("login/remembered_username", username)
    else:
        s.remove("login/remembered_username")

# --- Shared pre-login helpers -------
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

def tr(text: str) -> str:
    """Qt translation helper scoped to the Watchtower UI."""
    return QCoreApplication.translate("uiwatchtower", text)

# ==============================
# --- DPAPI "Remember this device" UX helpers ---------------------------------
# ==============================

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

def _sync_remember_device_checkbox_for_username(self, typed_username: str):
    """Auto-reflect per-user DPAPI state in the checkbox while typing/selecting a username.

    - If username is empty or user not found -> disable + untick
    - If user has a saved device_unlock blob -> enable + tick
    - Otherwise -> enable + untick
    """
    cb = getattr(self, "rememberDeviceCheckbox", None)
    if cb is None:
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
    rec = {}
    try:
        rec = get_user_record(lookup_name) or {}
    except Exception:
        rec = {}

    if not rec:
        # Unknown user -> disable
        try:
            self.passwordField.setPlaceholderText("Password")
            self.passwordField.setToolTip(
                "Enable 'Remember this device' to unlock without entering your password on this Windows device."
            )
            self.rememberDeviceCheckbox.setToolTip("Stores an encrypted unlock token on this Windows account (DPAPI). Not portable and not synced.")
            was = cb.blockSignals(True)
            cb.setChecked(False)
            cb.setEnabled(False)
        finally:
            try:
                cb.blockSignals(was)
            except Exception:
                pass
        return

    du = (rec.get("device_unlock") or {})
    enabled = bool(du.get("wrapped_b64") and du.get("entropy_b64")) or bool(du.get("enabled", False))

    # Set UI without triggering toggled handler
    try:
        self.passwordField.setPlaceholderText("Press Enter or click Unlock")
        self.passwordField.setToolTip(
            "This device can unlock the vault without your password. "
            "You can still enter your password if you prefer.")
        self.rememberDeviceCheckbox.setToolTip(
        "Uncheck to disable passwordless unlock on this device.")
        was = cb.blockSignals(True)
        cb.setEnabled(True)
        cb.setChecked(bool(enabled))
    finally:
        try:
            cb.blockSignals(was)
        except Exception:
            pass

# move this to flags 
def _remember_device_security_warning(self, username: str) -> tuple[bool, bool]:
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


# ==============================
# --- attempt login
# ============================== 

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

    log.debug(str(f"{kql.i('auth')} -> {kql.i('info')} [LOGIN] Attempting user login"))

    typed_username = (self.usernameField.text() or "").strip()
    password = (self.passwordField.text() or "")

    # --- Autofill remembered username on fresh login screen
    try:
        cb_user = getattr(self, "rememberUsernameCheckbox", None)
        if cb_user and not typed_username:
            remembered = _load_remembered_username()
            if remembered:
                self.usernameField.setText(remembered)
                typed_username = remembered
    except Exception:
        pass

    # ------------------------
    # --- DPAPI "Remember this device" quick unlock (Windows)
    # MUST run before any password validation or lockout logic
    # ------------------------
    try:
        from auth.windows_hello.session import load_device_unlock

        remember_on = False
        try:
            cb = (
                getattr(self, "rememberDeviceCheckbox", None)
                or self.findChild(QCheckBox, "rememberDeviceCheckbox")
            )
            remember_on = bool(cb and cb.isChecked())
        except Exception:
            remember_on = False

        if typed_username and password.strip() == "" and remember_on:
            log.info("[LOGIN] dpapi-check user=%s pw_empty=1 remember=1", typed_username)

            # Resolve canonical username (case-insensitive) BEFORE user_db lookup
            canon = None
            try:
                exists, canon = precheck_username_exists(typed_username)
                if not exists:
                    canon = None
            except Exception:
                canon = None

            lookup_name = canon or typed_username

            # Lookup user record (try canonical first, then raw typed)
            rec = None
            try:
                rec = get_user_record(lookup_name)
            except Exception:
                rec = None

            if not rec and lookup_name != typed_username:
                try:
                    rec = get_user_record(typed_username)
                except Exception:
                    rec = None

            if not rec:
                log.warning(
                    "[LOGIN] dpapi-check no user record typed=%s canon=%s",
                    typed_username,
                    canon or "None",
                )
            else:
                log.info(
                    "[LOGIN] dpapi-check found user record typed=%s canon=%s",
                    typed_username,
                    lookup_name,
                )

                # Optional: log if blob exists
                try:
                    du = (rec or {}).get("device_unlock") or {}
                    present = bool(du.get("wrapped_b64") and du.get("entropy_b64"))
                    log.info("[LOGIN] dpapi-blob present=%s", int(present))
                except Exception:
                    pass

                # Attempt to unwrap the device-unlock blob.  A non-empty
                # bytes result indicates a v2 record containing the
                # password‑derived KEK (\_pw_kek).  Legacy v1 blobs return
                # ``None`` and are ignored.
                res = load_device_unlock(rec)

                try:
                    log.info(
                        "[LOGIN] dpapi-unlock return_shape=%s",
                        f"tuple[{len(res)}]" if isinstance(res, tuple) else type(res).__name__,
                    )
                except Exception:
                    pass

                
                # Normalize return shape from load_device_unlock(rec)
                ok = False
                data = None
                msg = ""
                if isinstance(res, tuple):
                    try:
                        if len(res) == 3:
                            ok, data, msg = res
                        elif len(res) == 2:
                            ok, data = res
                            msg = ""
                        else:
                            msg = f"unexpected tuple len={len(res)}"
                    except Exception:
                        ok, data, msg = False, None, "bad tuple"
                elif isinstance(res, (bytes, bytearray)):
                    ok = bool(res)
                    data = bytes(res) if res else None
                    msg = ""
                else:
                    ok, data, msg = False, None, f"unexpected return type={type(res).__name__}"

                # -------------------------
                # v3 bundle (vault_kek + identity_kek)
                # -------------------------
                if ok and isinstance(data, dict) and data.get("vault_kek") and data.get("identity_kek"):
                    log.info("[LOGIN] dpapi-unlock OK (bundle) user=%s", lookup_name)

                    self._pw_kek = bytes(data["vault_kek"])          # vault password context
                    self._identity_kek = bytes(data["identity_kek"]) # identity password context

                    # 2FA expects a "password-like" value -> use identity_kek
                    self.current_password = self._identity_kek

                    # Decide YubiKey mode from PUBLIC identity header (no password required)
                    yk_mode = ""
                    try:
                        from auth.identity_store import get_yubi_config_public
                        pub = get_yubi_config_public(lookup_name) or {}
                        yk_mode = (pub.get("mode") or "").strip().lower()
                    except Exception:
                        yk_mode = ""

                    # If WRAP is enabled, DO NOT set the vault master key yet.
                    # The YubiKey factor must unwrap it first.
                    if yk_mode == "yk_hmac_wrap":
                        try:
                            if hasattr(self, "userKey"):
                                delattr(self, "userKey")
                        except Exception:
                            pass
                        try:
                            self._login_requires_yubi_wrap = True
                        except Exception:
                            pass
                        log.info("[LOGIN] dpapi-yubi mode=wrap action=require_yubi")
                    else:
                        # For non-wrap accounts, the vault key can be derived directly from _pw_kek.
                        self.userKey = self._pw_kek
                        try:
                            self._login_requires_yubi_wrap = False
                        except Exception:
                            pass
                        log.info("[LOGIN] dpapi-yubi mode=%s action=set_userKey_pw_kek", yk_mode or "none")

                    try:
                        self._yk_completed = False
                    except Exception:
                        pass
                    self._continue_after_factors(lookup_name)
                    return

                # -------------------------
                # v2 legacy (vault_kek only)
                # -------------------------
                if ok and isinstance(data, (bytes, bytearray)) and data:
                    # v2: only vault password-context is present; 2FA cannot run in passwordless mode.
                    try:
                        # Determine if this account needs extra password-context material.
                        # WRAP requires identity_kek (v3 bundle) for passwordless flows.
                        from auth.identity_store import has_totp_quick, get_yubi_config_public
                        totp_on = bool(has_totp_quick(lookup_name))
                        try:
                            pub = get_yubi_config_public(lookup_name) or {}
                            yk_mode = (pub.get("mode") or "").strip().lower()
                        except Exception:
                            yk_mode = ""
                        wrap_on = (yk_mode == "yk_hmac_wrap")
                    except Exception:
                        totp_on = False
                        wrap_on = False

                    if wrap_on or totp_on:
                        # v2 DPAPI only stores vault_kek; WRAP and TOTP need the extra identity_kek.
                        QMessageBox.information(
                            self,
                            self.tr("Remembered device needs upgrade"),
                            self.tr(
                                "This remembered-device token was created before Keyquorum stored the extra key "
                                "needed for passwordless mode with your enabled security factors.\n\n"
                                "Please sign in with your password once (with 'Remember this device' enabled) to "
                                "upgrade this device token."
                            ),
                        )
                        # Fall through to normal password login.
                    else:
                        log.info("[LOGIN] dpapi-unlock OK (legacy) user=%s", lookup_name)
                        self._pw_kek = bytes(data)
                        # For legacy mode, downstream flows should not assume identity password context.
                        self.current_password = None

                        # v2 legacy gives us vault KEK directly; treat as unlocked master context
                        self.userKey = self._pw_kek
                        try:
                            self._login_requires_yubi_wrap = False
                        except Exception:
                            pass

                        try:
                            self._yk_completed = False
                        except Exception:
                            pass
                        self._continue_after_factors(lookup_name)
                        return

                # Fail / unsupported
                log.warning(
                    "[LOGIN] dpapi-unlock FAIL user=%s err=%s",
                    lookup_name,
                    msg or ("no v2 blob" if not res else "unknown"),
                )
        else:
            # Optional debug to confirm why DPAPI path didn't run
            if typed_username and password.strip() == "":
                log.info(
                    "[LOGIN] dpapi-skip user=%s pw_empty=1 remember=%s",
                    typed_username,
                    int(bool(remember_on)),
                )

    except Exception:
        log.exception("[LOGIN] dpapi-check crashed")

    # ------------------------
    # end DPAPI block
    # ------------------------

    # Shared existence precheck (keeps UI typing checks and login in sync)
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
    _aw('_maybe_install_binding_for', lambda *a, **k: None)(typed_username)  # usb attempt to bind

    # ---------- READ-ONLY PHASE ----------
    from app.paths import read_only_paths
    with read_only_paths(True):
        canonical = None

        # 1) USB binding resolution (case-insensitive), but DO NOT create anything
        try:
            from features.portable.portable_user_usb import install_binding_overrides
        except Exception:
            install_binding_overrides = None

        # 2) Fallback: global CI resolver (respects overrides if installed)
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

        # Load the user's vault salt (required for Argon2id key derivation).
        # NOTE: This must happen BEFORE we derive the password KEK.
        from app.paths import salt_file

        try:
            sp = salt_file(username, ensure_parent=False)
            salt = sp.read_bytes() if sp.exists() else b""
        except Exception:
            salt = b""

        # Argon2 requires a minimum salt length (argon2-cffi enforces this).
        # If the salt is missing/corrupt, fail gracefully with a clear message.
        if not isinstance(salt, (bytes, bytearray)):
            try:
                salt = bytes(salt)
            except Exception:
                salt = b""

        if len(salt) < 8:
            log.error("[LOGIN] Missing/invalid salt for user=%s (len=%s)", username, len(salt))
            self.set_status_txt(self.tr("Missing salt"))
            QMessageBox.critical(
                self,
                self.tr("Account Data Missing"),
                self.tr(
                    "Your account's salt file is missing or corrupted, so Keyquorum cannot derive the vault key."
                    "Fix options:"
                    "• Restore the user folder from a backup (recommended), or"
                    "• Delete the user's local folder and create the account again."
                    "If this keeps happening after recreating the account, it usually means the app isn't writing to the expected user storage path."
                ),
            )
            self.passwordField.clear()
            return

        # IMPORTANT: reload login_handler after possible overrides
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

        # Lockout prefs (read-only from user_db)
        def _int_or(def_val, raw):
            try:
                return int(raw if raw is not None else def_val)
            except Exception:
                return def_val

        threshold     = _int_or(5,  get_user_setting(username, "lockout_threshold", 5))
        window_mins   = _int_or(10, get_user_setting(username, "lockout_window_mins", 10))
        cooldown_mins = _int_or(5,  get_user_setting(username, "lockout_cooldown_mins", 5))

        # Gate BEFORE password check
        if threshold > 0:
            locked, attempts_left, mins_left = audit_is_locked_out(username, threshold, window_mins, cooldown_mins)
            if locked:
                log.info(f"{kql.i('auth')} -> {kql.i('warn')} [LOGIN] Account LOCKED for user: {username} ({mins_left} min left)")
                self.set_status_txt(self.tr("Locked User"))
                msg = self.tr("Too many failed login attempts.\nTry again in about ") + f"{mins_left}" + self.tr(" minute(s).")
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
        if not validate_login(username, password):
            try:
                append_audit_log(username, "login_attempt", "fail")
            except Exception:
                pass

            locked_after, attempts_left_after, mins_left_after = audit_is_locked_out(
                username, threshold, window_mins, cooldown_mins
            )

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
    self.set_status_txt(self.tr("Password ok"))

    # Keep password briefly (some identity flows still need it)
    self.current_password = password

    # Derive password KEK
    self._pw_kek = derive_key_argon2id(password, salt)

    # Derive identity-store password context KEK (needed for DPAPI v3 bundle and WRAP flows)
    # IMPORTANT: Identity Store uses its own per-file password wrapper salt (stored in the identity header),
    # which is different from the vault salt. If we derive with the wrong salt, decrypt will fail (InvalidTag).
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
                                # tolerate missing padding
                                salt_b = base64.b64decode(_sb64 + "===")
                            break
        except Exception:
            salt_b = None

        if salt_b:
            self._identity_kek = derive_key_argon2id(password, salt_b)
        else:
            # Fallback: derive using vault salt (legacy / unexpected identity header)
            self._identity_kek = derive_key_argon2id(password, salt)
    except Exception:
        self._identity_kek = None
    self._identity_kek = getattr(self, "_identity_kek", None)

    # For password-only accounts, the derived key IS the master key.
    # Some factor flows (or older builds) call successful_login() assuming self.userKey exists.
    try:
        if not hasattr(self, "userKey") or self.userKey in (None, b"", bytearray()):
            self.userKey = self._pw_kek
    except Exception:
        try:
            self.userKey = self._pw_kek
        except Exception:
            pass

    # Clear plaintext ASAP
    password = None

    # Continue into remaining login factors (YubiKey / TOTP / backup codes)
    try:
        self._yk_completed = False
    except Exception:
        pass

    self._continue_after_factors(username)
    return
    try:
        from security.secure_audit import record_login_success
        record_login_success(username)
    except Exception:
        pass

    from app.paths import is_portable_mode, portable_root, users_root
    log.info(f"[PATHS] portable_mode={is_portable_mode()}")
    log.info(f"[PATHS] portable_root={portable_root()}")
    log.info(f"[PATHS] users_root={users_root()}")

# --- PRELOGIN IDENTITY RESOLVER ---
def _show_pairing_dialog(self, token: str, port: int | None = None):
    
    if not token:
        QMessageBox.information(self, self.tr("Pair Browser Extension"), self.tr("No token available."))
        return

    # Determine live port (uses self._bridge_port if set)
    if port is None:
        try:
            port = int(getattr(self, "_bridge_port", 8742))
        except Exception:
            port = 8742
    url = f"http://127.0.0.1:{port}"

    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Pair Browser Extension"))
    lay = QVBoxLayout(dlg)

    # Instruction
    lay.addWidget(QLabel(self.tr(
        "Paste this token into the Keyquorum extension popup, then click Save.\n"
        "Bridge URL (in the extension):")
    ))

    # Helper to make selectable, monospace labels
    def _mk_label(text: str) -> QLabel:
        lab = QLabel(text)
        try:
            flags = (Qt.TextInteractionFlag.TextSelectableByMouse |
                     Qt.TextInteractionFlag.TextSelectableByKeyboard)
        except AttributeError:  # Qt5 fallback
            flags = Qt.TextSelectableByMouse
        lab.setTextInteractionFlags(flags)
        lab.setStyleSheet(
            "font-family: monospace; font-size: 14px; padding: 6px; "
            "border: 1px solid #888; border-radius: 8px;"
        )
        return lab

    # URL row
    url_lab = _mk_label(url)
    lay.addWidget(url_lab)

    # Token heading + token
    lay.addWidget(QLabel(self.tr("Pairing token:")))
    token_lab = _mk_label(token)
    lay.addWidget(token_lab)

    # Buttons
    row = QHBoxLayout()
    btn_copy_token = QPushButton(self.tr("Copy Token"))
    btn_copy_url = QPushButton(self.tr("Copy URL"))
    btn_open_status = QPushButton(self.tr("Open Status"))
    btn_diagnose = QPushButton(self.tr("Diagnose"))   
    btn_open_orig   = QPushButton(self.tr("Open Origins File"))  
    btn_reload_orig = QPushButton(self.tr("Reload Origins"))   
    btn_add_origin = QPushButton(self.tr("Add Origin…"))
    btn_close       = QPushButton(self.tr("Close"))
    for b in (btn_copy_token, btn_copy_url, btn_open_status, btn_diagnose, btn_open_orig, btn_reload_orig, btn_add_origin, btn_close):
        row.addWidget(b)
    lay.addLayout(row)

    # Actions
    def _copy(text: str, btn: QPushButton, label: str):
        try:
            QApplication.clipboard().setText(text, QClipboard.Mode.Clipboard)
            btn.setText(self.tr("Copied ✓ {label}").format(label))
            log.info("%s [PAIR] %s copied to clipboard", kql.i('ok'), label.lower())
        except Exception:
            log.exception("%s [PAIR] clipboard copy failed (%s)", kql.i('err'), label.lower())

    btn_copy_token.clicked.connect(lambda: _copy(token, btn_copy_token, "Token"))
    btn_copy_url.clicked.connect(lambda: _copy(url, btn_copy_url, "URL"))
    btn_open_status.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(url + "/v1/status")))
    btn_close.clicked.connect(dlg.reject)
    
    # open the JSON in the user's default editor
    def _open_origins_file():
        try:
            # Ensure file exists with current contents
            cur = list(_aw('refresh_allowed_origins', lambda *a, **k: set())(force=True))
            if not _aw('ORIGINS_PATH').exists():
                _aw('save_allowed_origins', lambda *a, **k: None)(set(cur))
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(_aw('ORIGINS_PATH'))))
        except Exception:
            QMessageBox.warning(dlg, dlg.tr("Open Origins"), dlg.tr("Could not open the origins file."))

    # New: reload into memory (no restart required)
    def _reload_origins():
        global ALLOWED_ORIGINS
        ALLOWED_ORIGINS = _aw('refresh_allowed_origins', lambda *a, **k: set())(force=True)
        QMessageBox.information(dlg, dlg.tr("Reload Origins"), dlg.tr("Loaded ") + f"{len(ALLOWED_ORIGINS)}" + dlg.tr(" origin(s)."))

    btn_open_orig.clicked.connect(_open_origins_file)
    btn_reload_orig.clicked.connect(_reload_origins)

    def _add_origin():
        origin, ok = QInputDialog.getText(dlg, dlg.tr("Add Origin"), dlg.tr("chrome-extension://<ID>"))
        if not ok or not origin: 
            return
        origin = origin.strip()
        if not origin.startswith(("chrome-extension://", "moz-extension://")):
            QMessageBox.warning(dlg, dlg.tr("Add Origin"), dlg.tr("Must start with chrome-extension:// or moz-extension://"))
            return
        cur = _aw('refresh_allowed_origins', lambda *a, **k: set())(force=True)
        cur.add(origin)
        _aw('save_allowed_origins', lambda *a, **k: None)(cur)
        QMessageBox.information(dlg, dlg.tr("Add Origin"), dlg.tr("Saved. Click Reload Origins to apply."))

    btn_add_origin.clicked.connect(_add_origin)

    # --- Diagnose button logic (inline quick self-check) ---
    def _diagnose():
        # Reset field styles to base before coloring
        base_style = (
            "font-family: monospace; font-size: 14px; padding: 6px; "
            "border: 1px solid #888; border-radius: 8px;"
        )
        token_lab.setStyleSheet(base_style)
        url_lab.setStyleSheet(base_style)

        lines = []

        # Token checks
        tok_ok = bool(token) and len(token) >= 24 and _re.fullmatch(r"[A-Za-z0-9_\-]+", token or "") is not None
        lines.append(f"Token: {'OK' if tok_ok else 'BAD'}"
                     f" — {'looks good' if tok_ok else 'missing/too short/invalid chars'}")
        if tok_ok:
            token_lab.setStyleSheet(base_style + " border-color: #19a974;")  # green
        else:
            token_lab.setStyleSheet(base_style + " border-color: #e74c3c;")  # red

        # Bridge object present?
        httpd = getattr(self, "_bridge_httpd", None)
        lines.append(f"Bridge object: {'present' if httpd else 'absent'}")

        # TCP probe
        tcp_ok = False
        try:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=0.5):
                tcp_ok = True
        except Exception:
            tcp_ok = False
        lines.append(f"TCP 127.0.0.1:{port}: {'reachable' if tcp_ok else 'no listener'}")
        url_lab.setStyleSheet(base_style + (" border-color: #19a974;" if tcp_ok else " border-color: #e74c3c;"))

        # HTTP /v1/status probe
        http_ok, code, data = False, None, None
        if tcp_ok:
            try:
                c = http.client.HTTPConnection("127.0.0.1", int(port), timeout=0.8)
                c.request("GET", "/v1/status")
                r = c.getresponse()
                code = r.status
                raw = r.read() or b""
                c.close()
                try:
                    data = json.loads(raw.decode("utf-8", "replace")) if raw else None
                except Exception:
                    data = None
                http_ok = code in (200, 401, 403)
            except Exception:
                http_ok = False
        lines.append(f"GET /v1/status: {'OK' if http_ok else 'FAIL'}"
                     f"{'' if code is None else f' (HTTP {code})'}")

        # Advice
        tips = []
        if not tok_ok:
            tips.append(self.tr("Regenerate a new token (Pair → Regenerate) and paste it into the extension."))
        if httpd is None:
            tips.append(self.tr("Start the bridge (click Pair) after unlocking."))
        if not tcp_ok:
            tips.append(self.tr("Check antivirus/firewall or whether another Keyquorum instance is holding the port."))
        if tcp_ok and not http_ok:
            tips.append(self.tr("Handler error — check app log for bridge exceptions."))

        msg = "\n".join(lines)
        if tips:
            msg += "\n\nTips:\n- " + "\n- ".join(tips)

        QMessageBox.information(dlg, self.tr("Bridge diagnostics"), msg)

    btn_diagnose.clicked.connect(_diagnose)
    # --- end diagnose ---

    # Exec (Qt6) with Qt5 fallback
    try:
        dlg.exec()
    except AttributeError:
        dlg.exec_()

# ==============================
# --- dialog open other windows ---
# ==============================

def successful_login(self, *args, **kwargs):
    log.info("[MIGRATE] successful_login reached ✅")
    # ------------------------
    # Username MUST be stable after UI switches pages.
    # Prefer an explicitly provided username or session username, then UI.
    # ------------------------
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

    # -------
    # Remember this device (Windows DPAPI) - store/clear device-bound unlock blob
    # -------
    try:
        from auth.windows_hello.session import save_device_unlock, clear_device_unlock
        from auth.login.login_handler import get_user_record, set_user_record

        # Checkbox lives on login UI; if not present, skip silently
        remember = False
        try:
            remember = bool(getattr(self, "rememberDeviceCheckbox", None) and self.rememberDeviceCheckbox.isChecked())
        except Exception:
            remember = False

        rec = get_user_record(username) or {}

        # Determine whether this user is a YubiKey WRAP account.
        # WRAP accounts MUST only persist a DPAPI v3 "pw context" bundle (vault_kek + identity_kek).
        try:
            yk_mode, _ = yk_twofactor_enabled(username)  # "yk_hmac_gate" | "yk_hmac_wrap" | None
        except Exception:
            yk_mode = None
        is_wrap = bool(yk_mode == "yk_hmac_wrap" or getattr(self, "_login_requires_yubi_wrap", False))

        # For passwordless with security factors (e.g. TOTP / YubiKey Gate), we must persist
        # an identity unlock context (v3) so we can open/verify identity-backed factors.
        needs_pw_ctx = False
        try:
            from auth.identity_store import has_totp_quick
            needs_pw_ctx = bool(has_totp_quick(username))
        except Exception:
            pass
        # Gate mode may also require identity-backed config during passwordless flows.
        if yk_mode == "yk_hmac_gate":
            needs_pw_ctx = True

        # Persist the DPAPI unlock material when enabled.
        device_kek = getattr(self, "_pw_kek", None)         # vault password KEK (Argon2id)
        ident_kek = getattr(self, "_identity_kek", None)    # identity-store KEK/context (derived on pw login)
        mk = getattr(self, "userKey", None)                 # master key (legacy fallback for non-WRAP)

        if remember:
            if is_wrap:
                # WRAP accounts: v3 only (dpapi_pw_ctx). Never downgrade to v2.
                if not (isinstance(device_kek, (bytes, bytearray, memoryview)) and device_kek):
                    raise RuntimeError("WRAP+RememberDevice requires _pw_kek but it is missing.")
                if not (isinstance(ident_kek, (bytes, bytearray, memoryview)) and ident_kek):
                    raise RuntimeError("WRAP+RememberDevice requires _identity_kek but it is missing.")

                bundle = {
                    "v": 3,
                    "kind": "dpapi_pw_ctx",
                    "vault_kek": bytes(device_kek),
                    "identity_kek": bytes(ident_kek),
                }
                rec = save_device_unlock(rec, bundle)
                set_user_record(username, rec)
                try:
                    update_baseline(username=username, verify_after=False, who=self.tr("Remember device enabled"))
                except Exception as e:
                    log.error("[BASELINE] remember-device baseline update failed: %s", e)
            else:
                # Non-WRAP:
                # - If the account uses identity-backed factors (TOTP / YubiKey Gate), we MUST persist v3 (dpapi_pw_ctx)
                #   so passwordless can verify those factors without a plaintext password.
                # - Otherwise keep legacy v2 KEK storage.
                if needs_pw_ctx:
                    # v3 only for factor-enabled accounts; never silently keep/overwrite with v2.
                    if not (isinstance(device_kek, (bytes, bytearray, memoryview)) and device_kek):
                        # Force-disable remembered device so the user must do a full password login once.
                        rec = clear_device_unlock(rec)
                        set_user_record(username, rec)
                        raise RuntimeError("RememberDevice(v3) requires _pw_kek but it is missing.")
                    if not (isinstance(ident_kek, (bytes, bytearray, memoryview)) and ident_kek):
                        rec = clear_device_unlock(rec)
                        set_user_record(username, rec)
                        raise RuntimeError("RememberDevice(v3) requires _identity_kek but it is missing.")
                    bundle = {
                        "v": 3,
                        "kind": "dpapi_pw_ctx",
                        "vault_kek": bytes(device_kek),
                        "identity_kek": bytes(ident_kek),
                    }
                    rec = save_device_unlock(rec, bundle)
                    set_user_record(username, rec)
                    try:
                        update_baseline(username=username, verify_after=False, who=self.tr("Remember device enabled"))
                    except Exception as e:
                        log.error("[BASELINE] remember-device baseline update failed: %s", e)
                else:
                    # Legacy v2: wrap the password-derived KEK; fall back to master key for older scenarios.
                    if isinstance(device_kek, (bytes, bytearray, memoryview)) and device_kek:
                        rec = save_device_unlock(rec, bytes(device_kek))
                        set_user_record(username, rec)
                        try:
                            update_baseline(username=username, verify_after=False, who=self.tr("Remember device enabled"))
                        except Exception as e:
                            log.error("[BASELINE] remember-device baseline update failed: %s", e)
                    elif isinstance(mk, (bytes, bytearray, memoryview)) and mk:
                        rec = save_device_unlock(rec, bytes(mk))
                        set_user_record(username, rec)
                        try:
                            update_baseline(username=username, verify_after=False, who=self.tr("Remember device enabled"))
                        except Exception as e:
                            log.error("[BASELINE] remember-device baseline update failed: %s", e)
        else:
            rec = clear_device_unlock(rec)
            set_user_record(username, rec)

    except Exception as e:
        try:
            log.debug(f"[HELLO] remember-device update skipped: {e}")
        except Exception:
            pass

    # -------
    # One-time migrations after password change / salt rotation / wrap change
    # -------
    log.info("[MIGRATE] login hook reached user=%r prev=%s new=%s",
            username,
            "YES" if getattr(self, "_prev_userKey", None) else "NO",
            "YES" if getattr(self, "userKey", None) else "NO")
    
    try:
        old_key = getattr(self, "_prev_userKey", None)
        new_key = getattr(self, "userKey", None)

        if old_key and new_key and old_key != new_key:
            log.info("[MIGRATE] Detected key change on login for user=%s", username)

            results = []   # list of dicts: {"name": str, "status": "ok|skip|fail", "detail": str}
            any_fail = False
            any_changed = False

            def _add_result(name: str, status: str, detail: str = ""):
                nonlocal any_fail, any_changed
                results.append({"name": name, "status": status, "detail": detail})
                if status == "fail":
                    any_fail = True
                if status == "ok":
                    any_changed = True

            # 1) Authenticator Store
            try:
                from vault_store.authenticator_store import migrate_authenticator_store

                ok, msg, changed, failed = migrate_authenticator_store(username, old_key, new_key)

                if ok and changed:
                    log.info("[AUTH] %s", msg)
                    _add_result("Authenticator store", "ok", msg)
                    if hasattr(self, "_toast"):
                        self._toast(self.tr("Authenticator refreshed"))
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
            try:
                if results:
                    if any_fail:
                        # Build a readable summary
                        lines = []
                        for r in results:
                            if r["status"] == "fail":
                                lines.append(f"• {r['name']}: FAILED — {r['detail']}")
                        # Also include ok/skip lines if you want; keeping it focused on failures is usually best.
                        QMessageBox.warning(
                            self,
                            self.tr("Migration warnings"),
                            self.tr(
                                "Some files could not be updated after your password change.\n\n"
                                "{details}\n\n"
                                "What you can do:\n"
                                "• Log out and log in again.\n"
                                "• If it still fails, restore from your most recent FULL backup."
                            ).format(details="\n".join(lines)),
                        )
                    else:
                        # Everything ok (ok + skip both count as success)
                        QMessageBox.information(
                            self,
                            self.tr("Migration complete"),
                            self.tr("All files have been updated successfully."),
                        )
            except Exception as e:
                log.warning("[MIGRATE] summary popup failed: %s", e)

        # Always destroy the previous key after best-attempt migrations
        if hasattr(self, "_prev_userKey"):
            try:
                delattr(self, "_prev_userKey")
            except Exception:
                pass
    except Exception as e:
        log.warning("[MIGRATE] key-migration wrapper failed: %s", e)
        try:
            if hasattr(self, "_prev_userKey"):
                delattr(self, "_prev_userKey")
        except Exception:
            pass

    _aw('notify_usb_loaded_once', lambda *a, **k: None)(self, username)

    # --- Start watching for USB removal when in portable mode
    try:
        self._start_usb_watch_if_needed()
    except Exception as e:
        try:
            log.debug(f"[USB] failed to start USB watch: {e}")
        except Exception:
            pass

    # passkey dev
    if is_dev:
        try:
            self._reload_passkeys_for_current_user()
        except Exception as e:
            log.debug(f"[PASSKEY] reload on login failed: {e}")

    # --- Compute per-session password strength score ---
    try:
        from auth.pw.password_utils import estimate_strength_score
        pw = getattr(self, "current_password", "") or ""
        if pw:
            self.ps_score = int(estimate_strength_score(pw) or 0)
        else:
            self.ps_score = None
    except Exception as e:
        log.warning("[SEC] Failed to compute password strength score: %s", e)
        self.ps_score = None

    # --- Immediately wipe plaintext password from memory ---
    try:
        self.current_password = None
    except Exception:
        pass

    # Reset lockout counter on full success
    self.set_status_txt(self.tr("All passed — logging user in"))
    try:
        reset_login_failures(username)
    except Exception:
        pass

    # --- mark vault as unlocked ---
    #self.current_mk = self.userKey
    #self.vault_unlocked = bool(self.userKey)
    # WRAP accounts must NOT unlock vault until YubiKey completes
    if getattr(self, "_login_requires_yubi_wrap", False):
        log.info("[LOGIN] WRAP pending — vault locked until YubiKey completes")
        self.current_mk = None
        self.vault_unlocked = False
    else:
        mk = getattr(self, "userKey", None) or getattr(self, "_pw_kek", None)
        if not isinstance(mk, (bytes, bytearray)) or not mk:
            log.error("[LOGIN] successful_login reached without master key; aborting login")
            try:
                QMessageBox.warning(self, self.tr("Login failed"), self.tr("Missing encryption key context. Please sign in again."))
            except Exception:
                pass
            return
        self.userKey = bytes(mk)
        self.current_mk = self.userKey
        self.vault_unlocked = True



    # switch logs to per-user file
    try:
        _aw('switch_to_user_log', lambda *a, **k: None)(username)
    except Exception:
        pass

    # show main tabs, focus Vault tab
    self.mainTabs.setVisible(True)
    self.mainTabs.setCurrentWidget(self.findChild(QWidget, "vaultTab"))
    log.debug(f" {kql.i('auth')} -> {kql.i('ok')} [2FA] Successful Login")

    # passkey store init (best effort)
    try:
        self._init_passkeys_store()
    except Exception as e:
        log.debug(f"{kql.i('err')} [ERROR] Passkey sync: {e}")

    # set size/geometry after switching UI
    try:
        self.set_status_txt(self.tr("Set Size"))
        self._restore_maximized = self.isMaximized()
        QTimer.singleShot(0, self._apply_vault_geometry)
        log.debug(f"{kql.i('ok')} -> {kql.i('ui')} Size Set Login")
    except Exception as e:
        log.debug(f"{kql.i('err')} [ERROR] setting size error: {e}")

    # paths debug (unified)
    try:
        self.set_status_txt(self.tr("Logging paths"))
        debug_log_paths(username)
    except Exception:
        log.exception(f"{kql.i('err')} [S-LOGIN] paths debug")

    # hide login container if present
    try:
        if getattr(self, "widget", None):
            self.widget.hide()
    except Exception:
        log.exception(f"{kql.i('err')} [S-LOGIN] hide login widget/container")

    # ------------------------
    # Authenticator Store (use session username; do NOT call _auth_reload)
    # ------------------------
    try:
        self.set_status_txt(self.tr("Loading Authenticator"))
        if self.userKey:
            if hasattr(self, "_auth_after_login"):
                self._auth_after_login()
            self._auth_set_enabled(True)
        else:
            self._auth_set_enabled(False)
    except Exception:
        log.exception("[auth] post-login init failed")
        try:
            self._auth_set_enabled(False)
        except Exception:
            pass

    # Profile picture (best effort)
    try:
        self.set_status_txt(self.tr("Loading Profile Picture"))
        self.load_profile_picture()
    except Exception:
        log.exception(f"{kql.i('err')} [S-LOGIN] profile picture")

    # Bridge start (UI bus + token)
    try:
        self.set_status_txt(self.tr("Starting Web Bridge"))
        if not hasattr(self, "_uibus"):
            self._uibus = _UiBus(self)

        token = self.ensure_bridge_token(new=False)
        httpd = getattr(self, "_bridge_httpd", None)
        if not httpd:
            log.error("%s [LOGIN] bridge failed to start", kql.i('err'))
        else:
            port = int(getattr(self, "_bridge_port", 8742))
            t = token or getattr(self, "_bridge_token", "") or ""
            tmask = f"{t[:6]}…{t[-6:]}" if t else "None"
            log.info("✅ [LOGIN] bridge online at 127.0.0.1:%s • token=%s", port, tmask)
    except Exception:
        log.exception(f"{kql.i('err')} [S-LOGIN] failed to start")

    # Sync engine (key-aware)
    try:
        res = self._cloud_sync_safe(self.userKey, interactive=True)
        if hasattr(self, "_toast") and res != "noop":
            self._toast(f"Cloud sync: {res}")
    except Exception as e:
        log.error(f"{kql.i('err')} [CLOUD] Cloud sync {e}")

    # Windows clipboard risk warning (once)
    try:
        maybe_warn_windows_clipboard(self, username)
    except Exception:
        pass

    # purge trash
    try:
        self._auto_purge_trash()
    except Exception:
        pass

    # full backup reminder check
    if getattr(self, "full_backup_reminder", None):
        self.full_backup_reminder.maybe_prompt()

    # backup codes check
    self.check_backup_codes_ok(username, "both")
    
    # Category editor/tab init
    self.init_category_editor_tab(username)

    # ---- Catalog (per-user config dir; no user_settings_dir) ----
    try:
        self.set_status_txt(self.tr("Setting User Catalog"))
        user_cfg_root = str(config_dir(username))  # .../Users/<user>/Config
        self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE, self.AUTOFILL_RECIPES, _ = self._load_catalog_effective(user_cfg_root)
    except Exception as e:
        log.error(f"[CATALOG] Error: {e}")

    # Load user settings last (UI may tweak)
    try:
        self.load_setting()
    except Exception:
        pass

    # Rate-me nudger
    try:
        self.rate_nudger.on_app_start()
    except Exception:
        pass

    # -------
    # Remember Last Username (Windows) - store/clear in QSettings
    # -------
    try:
        from qtpy.QtCore import QSettings
        cb_user = getattr(self, "remember_username", None)  # your checkbox objectName
        s = QSettings("AJHSoftware", "KeyquorumVault")

        if cb_user is not None and cb_user.isChecked():
            s.setValue("login/remembered_username", username)
            log.info("[LOGIN] remember-username saved user=%s", username)
        else:
            s.remove("login/remembered_username")
            log.info("[LOGIN] remember-username cleared")
    except Exception:
        pass

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

    username = (self.currentUsername.text() or "").strip()
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
            from app.misc_ops import emg_ask
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

# --- used to disable 2FA in toggle_2fa_setting
def _auth_import_safe(self, *args, **kwargs):
    """
    Import authenticators from a password-encrypted Keyquorum auth backup (.kqa.enc).

    - Always asks for a password and refuses plaintext files.
    - Entries are added via add_from_otpauth_uri (preferred) or add_authenticator.
    """
    if not self._auth_require_login():
        QMessageBox.warning(self, self.tr("Authenticator Import"), self.tr("Please log in first."))
        return

    username = (self.currentUsername.text() or "").strip()
    if not username:
        QMessageBox.warning(self, self.tr("Authenticator Import"), self.tr("No active user."))
        return

    # Pick file
    file_path, _ = QFileDialog.getOpenFileName(
        self,
        self.tr("Select Authenticator Backup"),
        "",
        "Keyquorum Auth Backup (*.kqa.enc *.enc)",
    )
    if not file_path:
        return

    # Password
    pw, ok = QInputDialog.getText(
        self,
        self.tr("Authenticator Import"),
        self.tr("Enter the password used to encrypt this authenticator backup:"),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not pw.strip():
        return
    password = pw

    # Decrypt
    try:
        from pathlib import Path
        raw_enc = Path(file_path).read_bytes()
        raw = _dec_backup_bytes(password, raw_enc)
    except Exception as e:
        QMessageBox.critical(self, self.tr("Authenticator Import"), f"Decryption failed:\n{e}")
        return

    # Parse JSON
    try:
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("format") != "keyquorum.auth.v1":
            QMessageBox.critical(
                self,
                self.tr("Authenticator Import"),
                self.tr("This file does not look like a Keyquorum authenticator backup."),
            )
            return
        entries = payload.get("entries") or []
        if not isinstance(entries, list):
            entries = []
    except Exception as e:
        QMessageBox.critical(self, self.tr("Authenticator Import"), f"Failed to parse backup:\n{e}")
        return

    if not entries:
        QMessageBox.information(self, self.tr("Authenticator Import"), self.tr("No entries found in this backup."))
        return

    # Confirm (these are very sensitive)
    res = QMessageBox.question(
        self,
        self.tr("Import Authenticators"),
        self.tr("This will add authenticator entries (2FA codes) into your account.\n\n"
        "Only proceed if you trust this backup file.\n\nContinue?"),
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No,
    )
    if res != QMessageBox.Yes:
        return

    added = failed = 0
    for it in entries:
        try:
            uri = (it.get("otpauth_uri") or "").strip()
            if uri.startswith("otpauth://"):
                add_from_otpauth_uri(username, self.userKey, uri)
            else:
                # Fallback: construct from fields if secret is ever included in future
                add_authenticator(
                    username,
                    self.userKey,
                    label=it.get("label", ""),
                    account=it.get("account", ""),
                    issuer=it.get("issuer", ""),
                    secret_base32=it.get("secret_base32", ""),
                    digits=int(it.get("digits", 6) or 6),
                    period=int(it.get("period", 30) or 30),
                    algorithm=it.get("algorithm", "SHA1"),
                )
            added += 1
        except Exception as e:
            failed += 1
            try:
                log.error(f"[auth] failed to import authenticator: {e}")
            except Exception:
                pass

    # Refresh UI
    try:
        update_baseline(username=username, verify_after=False, who=self.tr("Authenticator Backup Imported"))
    except Exception:
        pass

    self._auth_reload_table()

    msg = "✅ " + self.tr("Authenticator import complete.\n\n• Added:") + f"{added}"
    if failed:
        msg += f"\n• Failed: {failed}"
    QMessageBox.information(self, self.tr("Authenticator Import"), msg)

# --- usb login
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

# ==============================
# --- breach/porned ----
# ==============================

# --- check if email has been porned (item must be selected in table)
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

# --- decide what the account actually supports
def _auth_export_safe(self, *args, **kwargs):
    """
    Safely export all authenticator entries for the current user.

    - Always encrypted with a user-chosen password (no plaintext option).
    - Format: JSON wrapped in AES-GCM via _enc_backup_bytes.
    - Contains only the data needed to recreate the authenticator entries,
      including an otpauth:// URI for each one.
    """
    from qtpy.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox
    from vault_store.vault_store import _enc_backup_bytes

    if not self._auth_require_login():
        QMessageBox.warning(self, self.tr("Authenticator Export"), self.tr("Please log in first."))
        return

    username = (self.currentUsername.text() or "").strip()
    if not username:
        QMessageBox.warning(self, self.tr("Authenticator Export"), self.tr("No active user."))
        return

    if not self.verify_sensitive_action(username, title="Export Auth Only"):
        return

    try:
        rows = list_authenticators(username, self.userKey) or []
    except Exception as e:
        msg = self.tr("Failed to read authenticators:") + f"\n{e}"
        QMessageBox.critical(self, self.tr("Authenticator Export"), msg)
        return

    if not rows:
        QMessageBox.information(self, self.tr("Authenticator Export"), self.tr("No authenticator entries to export."))
        return

    # --- Ask for password (mandatory, with confirmation) ---
    pw1, ok = QInputDialog.getText(
        self, self.tr("Export Authenticators"),
        self.tr("Set a password to encrypt this authenticator backup") + ":\n\n⚠️ " +
        self.tr("This file contains your 2FA secrets. Keep it safe."),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not pw1.strip():
        return

    pw2, ok = QInputDialog.getText(
        self, self.tr("Confirm Password"),
        self.tr("Re-enter the password:"),
        QLineEdit.EchoMode.Password,
    )
    if not ok or pw1 != pw2:
        QMessageBox.warning(self, self.tr("Authenticator Export"), self.tr("Passwords do not match."))
        return

    password = pw1

    # --- Build export payload ---
    try:
        export_items = []
        for it in rows:
            try:
                uri = build_otpauth_uri(self.userKey, it)
            except Exception:
                uri = None

            export_items.append({
                "label":     it.get("label", ""),
                "account":   it.get("account", ""),
                "issuer":    it.get("issuer", ""),
                "algorithm": it.get("algorithm", "SHA1"),
                "digits":    int(it.get("digits", 6) or 6),
                "period":    int(it.get("period", 30) or 30),
                "otpauth_uri": uri,
            })
        payload = {
            "format": "keyquorum.auth.v1",
            "username_hint": username,
            "created_utc": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "count": len(export_items),
            "entries": export_items,
        }
        raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    except Exception as e:
        QMessageBox.critical(self, self.tr("Authenticator Export"), f"Failed to prepare data:\n{e}")
        return

    # --- Choose file path ---
    default_name = f"{username}_auth_backup.kqa.enc"
    out_path, _ = QFileDialog.getSaveFileName(
        self,
        "Save Authenticator Backup",
        default_name,
        "Keyquorum Auth Backup (*.kqa.enc)",
    )
    if not out_path:
        return

    try:
        enc = _enc_backup_bytes(password, raw)
        from pathlib import Path
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_bytes(enc)
        try:
            os.chmod(out_path, 0o600)
        except Exception:
            pass
        try:
            log_event_encrypted(username, self.tr("auth_backup"), f"{kql.i('ok')} Authenticator backup exported")
        except Exception:
            pass
        msg = "✅" + self.tr(" Authenticator backup saved successfully.") + "\n\n⚠️" + self.tr(" This file contains your 2FA secrets.\n Store it offline in a safe place (e.g., encrypted USB).")
        QMessageBox.information(
            self,
            self.tr("Authenticator Exported"),msg)
    except Exception as e:
        msg = self.tr(f"Failed to save backup:") + f"\n{e}"
        QMessageBox.critical(self, self.tr("Authenticator Export"), msg)

# ---------- in-app profile picture (settings/header) ----------
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
            if dev_cmd(self, typed):
                return
        except Exception as e:
            log.debug(f"[DEV_CMD] ignored error: {e}")

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

def _finish_login(self, username: str, master_key: bytes, yk_record: dict | None = None) -> None:       # - Finalize a successful login (called from _on_yk_login_ok)
    """
    Single place to finalize login after all factors (password + YubiKey/recovery) succeed.
    - Sets self.userKey
    - Resets lockouts
    - Updates integrity baseline
    - Loads/initializes vault UI
    - Switches screens and starts timers
    """
    try:
        # 0) If you already had a legacy finisher, call it instead (keeps old behavior)
        for legacy in ("_finish_login_with_password", "finish_login", "login_success"):
            if hasattr(self, legacy) and callable(getattr(self, legacy)):
                getattr(self, legacy)(username, master_key, yk_record or {})
                return

        # 1) Set live session key
        if not isinstance(master_key, (bytes, bytearray)) or not master_key:
            raise ValueError("Missing/invalid master key after YubiKey step.")
        self.userKey = bytes(master_key)  # keep as bytes

        # 2) Audit + lockout reset (best-effort)
        try:
            reset_login_failures(username)
        except Exception:
            pass
        try:
            
            log_event_encrypted(username, self.tr("login_success"), {"yk": bool(yk_record)})
        except Exception:
            pass

        # 3) Load (or seed) the user’s vault so UI can render
        try:
            # create empty vault if first login
            try:
                seed_vault(username)
            except Exception:
                pass
            _ = load_vault(username, self.userKey)  # keep in memory if you cache it
        except Exception as e:
            QMessageBox.warning(self, self.tr("Vault"), f"Could not load vault:\n{e}")

        # 4) Update integrity baseline (vault/salt/user_db)
        try:
            update_baseline(username=username, verify_after=False, who="integrity baseline")
        except Exception as e:
            log.error(f"[baseline] update after login failed for {username}: {e}")

        try:
            if hasattr(self, "currentUsername"):
                self.currentUsername.setText(username)
        except Exception:
            pass

        # Hide login panel, show main tabs
        try:
            if hasattr(self, "stackedWidget"):
                # index 1 is the main app
                self.stackedWidget.setCurrentIndex(1)
        except Exception:
            pass
        try:
            if hasattr(self, "mainTabs"):
                self.mainTabs.setCurrentIndex(0)
        except Exception:
            pass

        # 6) Refresh controls that depend on login
        try: self.refresh_recovery_controls()
        except Exception: pass
        try: self._auth_reload()
        except Exception: pass
        try: self._reload_table()
        except Exception: pass

        # 7) Start/Reset session timers, clipboard guards, etc.
        try: self.reset_logout_timer()
        except Exception: pass
        try: install_clipboard_guard(self)
        except Exception: pass

        # 8) Optional one-time clipboard history warning on Windows
        try: maybe_warn_windows_clipboard(self, username, copy=False)
        except Exception: pass

        # 9) Mark complete so double-emits are ignored
        self._login_finalized = True

    except Exception as e:
        # Surface any unexpected failure cleanly
        self._login_finalized = False
        QMessageBox.critical(self, self.tr("Login failed"), f"{e}")

# ==============================
# --- Share Packets (unified paths; no CONFIG_DIR/AUTH_DIR) -------------------
# ==============================
# from sharing import ensure_share_keys, make_share_packet, verify_and_decrypt_share_packet
# from vault_store.add_entry_dialog import AddEntryDialog

# --- Risk helpers -------------------

def _auth_add_from_screen(self, *args, **kwargs):
    if not self._auth_require_login():
        QMessageBox.warning(self, self.tr("Authenticator"), self.tr("Please log in first."))
        return
    if cv2 is None:
        QMessageBox.warning(self, self.tr("QR Scan"), self.tr("OpenCV (cv2) is not available. Install 'opencv-python'."))
        return

    # --- confirmation (with 'don't show again') ---
    if not self._confirm_auth_scan():
        return

    try:
        # Hide the window briefly so it isn’t captured
        with self._hide_for_screen_scan(300):
            screens = QGuiApplication.screens() or []
            if not screens:
                QMessageBox.warning(self, self.tr("QR Scan"), self.tr("No screens detected."))
                return

            detector = cv2.QRCodeDetector()
            found = []

            for s in screens:
                pm = s.grabWindow(0)
                img = pm.toImage()
                bgr = self._qimage_to_numpy(img)

                # Preprocess for robustness on screenshots
                gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
                gray = cv2.equalizeHist(gray)
                gray = cv2.medianBlur(gray, 3)

                decoded = []
                try:
                    ok, texts, points, _ = detector.detectAndDecodeMulti(gray)
                    if ok and texts:
                        decoded.extend(texts)
                except Exception:
                    pass
                if not decoded:
                    try:
                        t, _ = detector.detectAndDecode(gray)
                        if t:
                            decoded.append(t)
                    except Exception:
                        pass

                for t in decoded:
                    t = (t or "").strip()
                    if not t:
                        continue
                    if "otpauth" in t.lower() and not t.lower().startswith("otpauth://"):
                        t = "otpauth://" + t.split("otpauth://")[-1]
                    if t.startswith("otpauth://"):
                        found.append((s.name(), t))

        if not found:
            QMessageBox.information(self, self.tr("QR Scan"), self.tr("No otpauth:// QR codes detected on the screens."))
            return

        # If multiple, let user choose
        if len(found) > 1:

            labels = [f"{sn}: {uri[:80]}..." for sn, uri in found]
            choice, ok = QInputDialog.getItem(self, "Multiple QR codes found", "Choose one to import:", labels, 0, False)
            if not ok:
                return
            idx = labels.index(choice)
            _, uri = found[idx]
        else:
            _, uri = found[0]

        from vault_store.authenticator_store import add_from_otpauth_uri
        add_from_otpauth_uri(self.currentUsername.text().strip(), self.userKey, uri)
        update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Auth Store Vault changed")) 
        self._auth_reload_table()
        if hasattr(self, "_toast"):
            self._toast(self.tr("Authenticator added from screen"))

    except Exception as e:
        QMessageBox.critical(
            self,
            self.tr("QR Scan Error"),
            self.tr("Failed to scan screen:\n\n{err}").format(err=e),
        )

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
                # userKey may not be present yet (pre-login); pass empty key safely
                key = getattr(self, "userKey", b"") or b""
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

def _show_login_rescue(self, username: str):

    mode, allow_backup, allow_recovery = self._rescue_caps(username)

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
                    "Enable Recovery Mode and create a Recovery Key."
                ),
            )
            return
        chosen["rk"] = rk_edit.text().strip()
        dlg.accept()

    btn_backup.clicked.connect(_use_backup); btn_rk.clicked.connect(_use_rk); btn_cancel.clicked.connect(dlg.reject)
    return chosen if dlg.exec() == QDialog.DialogCode.Accepted else None

