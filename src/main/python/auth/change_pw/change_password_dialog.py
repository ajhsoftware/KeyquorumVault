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

import logging

from qtpy.QtWidgets import (
    QDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QInputDialog,
    QVBoxLayout,
)

from ui_gen.change_password_dialog_ui import Ui_SecurePasswordChangeDialog
from new_users.account_creator import create_or_update_user
from auth.identity_store import replace_login_backup_codes
from auth.login.login_handler import (
    get_user_record,
    set_user_record,
    is_2fa_enabled,
    verify_2fa_code,
    use_backup_code,
)
from auth.pw.password_utils import validate_password
from security.timestamp_utils import now_utc_iso
from security.baseline_signer import update_baseline
from native.native_core import get_core
from vault_store.kdf_utils import normalize_kdf_params

log = logging.getLogger("keyquorum")
log.debug("[DEBUG] 🔐 Change Password Dialog Loaded")


def _open_native_session_for_user(username: str, password_text: str) -> int:
    
    """Open a strict native session using the user's stored KDF profile."""
    if not username or not password_text:
        raise ValueError("username and password are required")

    from auth.salt_file import read_master_salt_strict
    salt = read_master_salt_strict(username)
    if not salt:
        raise ValueError("User salt not found")

    rec = get_user_record(username) or {}
    kdf = normalize_kdf_params(rec.get("kdf") or {}) if isinstance(rec, dict) else {}

    core = get_core()
    if not core:
        raise RuntimeError("Native core not loaded. DLL is required.")

    pw_buf = bytearray(password_text.encode("utf-8"))
    try:
        if (
            isinstance(kdf, dict)
            and int(kdf.get("kdf_v", 1)) >= 2
            and hasattr(core, "open_session_ex")
            and getattr(core, "has_session_open_ex", lambda: False)()
        ):
            return int(core.open_session_ex(
                pw_buf,
                bytes(salt),
                time_cost=int(kdf.get("time_cost", 3)),
                memory_kib=int(kdf.get("memory_kib", 256000)),
                parallelism=int(kdf.get("parallelism", 2)),
            ))
        return int(core.open_session(pw_buf, bytes(salt)))
    finally:
        try:
            core.secure_wipe(pw_buf)
        except Exception:
            for i in range(len(pw_buf)):
                pw_buf[i] = 0

def _close_native_session_safe(session_handle) -> None:
    try:
        if isinstance(session_handle, int) and session_handle > 0:
            get_core().close_session(int(session_handle))
    except Exception:
        pass

def _norm(s: str) -> str:
    return (s or "").strip()


def show_message(self):
    # Recommend a full backup before any password / key changes
    reply = QMessageBox.warning(
        self,
        self.tr("Security Warning"),
        self.tr(
            "Changing your password, rotating the salt, or enabling/disabling wrap "
            "(e.g. YubiKey) will re-encrypt all protected parts of your vault.\n\n"

            "This includes:\n"
            "• Authenticator store\n"
            "• Password history\n"
            "• Soft delete (trash)\n"
            "• Catalog data\n\n"

            "Any issue during this process could make this data inaccessible.\n"
            "For your safety, it is strongly recommended to create a FULL encrypted backup first.\n\n"

            "Do you want to create a backup before continuing?"
        ),
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.Yes,
    )
    return reply



def _persist_backup_codes(canonical_username: str, codes_plain: list[str], *, password_for_identity: str) -> None:
    """Persist *login* backup codes via the Identity Store (single source of truth).

    Backup codes are returned plaintext so the UI can show them once, but we only
    store hashed forms inside the encrypted Identity Store.
    """
    replace_login_backup_codes(canonical_username, password_for_identity, codes_plain)

class ChangePasswordDialog(QDialog, Ui_SecurePasswordChangeDialog):
    def __init__(self, username: str, user_key: bytes, parent=None):
        super().__init__(parent)
        try:
            self.username = _norm(username)
            self.user_key = user_key

            self.setWindowTitle(self.tr("Change Password"))
            self.setupUi(self)

            self.ok.clicked.connect(self.try_change_password)
            self.cancel.clicked.connect(self.reject)

            if hasattr(self.parent(), "reset_logout_timer"):
                self.parent().reset_logout_timer()

            acct = get_user_record(self.username) or {}
            recovery_mode = bool(acct.get("recovery_mode", False))
            is_max_security = not recovery_mode

            # Max-security: do not allow generating recovery-mode
            if is_max_security:
                self.updateBackupCodesCheckbox.setChecked(False)
                self.updateBackupCodesCheckbox.setEnabled(False)
                self.updateRecoveryKeyCheckbox.setChecked(False)
                self.updateRecoveryKeyCheckbox.setEnabled(False)

            log.debug("[DEBUG] 🔐 Change Password Dialog initialized")
        except Exception as e:
            log.error(f"[ERROR] 🔐 Change Password Dialog initialization failed: {e}")
            QMessageBox.critical(
                self,
                self.tr("Initialization Error"),
                self.tr("Failed to initialize dialog") + f":\n\n{e}",
            )

    # --- Optional 2FA gate before changing password -------------------------
    def _prompt_2fa_if_enabled(self, canonical_username: str) -> bool:
        try:
            if not is_2fa_enabled(canonical_username):
                return True
        except Exception:
            return True

        for _attempt in range(3):
            if hasattr(self.parent(), "reset_logout_timer"):
                self.parent().reset_logout_timer()

            code, ok = QInputDialog.getText(
                self,
                self.tr("Two-Factor Authentication"),
                self.tr("Enter your 6-digit code (or a backup code):"),
            )
            if not ok:
                return False

            code = _norm(code).replace(" ", "")
            try:
                if verify_2fa_code(canonical_username, code) or use_backup_code(canonical_username, code):
                    return True
            except Exception:
                pass

            QMessageBox.warning(self, self.tr("Incorrect Code"), self.tr("That code didn’t work. Please try again."))

        return False

    # --- Main handler -------------
    def try_change_password(self):
        try:
            parent = self.parent()
            if hasattr(parent, "reset_logout_timer"):
                parent.reset_logout_timer()

            old_pw = _norm(self.oldPasswordField.text())
            new_pw = _norm(self.newPasswordField.text())
            confirm_pw = _norm(self.confirmPasswordField.text())

            update_backup = self.updateBackupCodesCheckbox.isChecked()
            update_recovery_key = self.updateRecoveryKeyCheckbox.isChecked()
            rotate_salt = self.rotateSaltCheckbox.isChecked()

            # Basic validation
            if not old_pw or not new_pw or not confirm_pw:
                QMessageBox.warning(self, self.tr("Input Error"), self.tr("Please fill in all password fields."))
                return

            if new_pw != confirm_pw:
                QMessageBox.warning(self, self.tr("Input Error"), self.tr("New password and confirmation do not match."))
                return

            # Policy + strength check (shared with account creation)
            verdict = validate_password(new_pw)
            if not verdict.get("valid"):
                reason = verdict.get("reason", self.tr("Does not meet the password policy."))
                QMessageBox.warning(
                    self,
                    self.tr("Weak Password"),
                    reason
                    + "\n\n"
                    + self.tr("For best security, use a long, unique passphrase and store it somewhere offline."),
                )
                return

            canonical = self.username
            acct = get_user_record(canonical) or {}
            recovery_mode = bool(acct.get("recovery_mode", False))
            is_max_security = not recovery_mode

            if is_max_security and (update_backup or update_recovery_key):
                QMessageBox.warning(
                    self,
                    self.tr("Not Allowed"),
                    self.tr("This is a Maximum-Security account. Backup codes and recovery key cannot be regenerated."),
                )
                update_backup = False
                update_recovery_key = False

            if not self._prompt_2fa_if_enabled(canonical):
                QMessageBox.warning(self, self.tr("Two-Factor Authentication"), self.tr("2FA verification was not completed."))
                return

            # Preserve only the CURRENT native session handle for any later login-time
            # migration. No fall back to raw bytes
            old_session_handle = None
            try:
                if parent is not None:
                    sess = getattr(parent, "core_session_handle", None)
                    if isinstance(sess, int) and sess > 0:
                        old_session_handle = int(sess)
                        parent._prev_core_session_handle = int(sess)
            except Exception:
                old_session_handle = None

            # Update user record + crypto materials
            result = create_or_update_user(
                username=canonical,
                password=new_pw,
                confirm=confirm_pw,
                recovery_mode=recovery_mode,
                update_mode=True,
                regenerate_keys=(update_backup and recovery_mode),
                regenerate_recovery_key=(update_recovery_key and recovery_mode),
                old_password=old_pw,
                rotate_salt=rotate_salt,
            )

            if not isinstance(result, dict):
                log.error(
                    "[CHANGE-PW] create_or_update_user returned invalid result: %r",
                    result,
                )
                QMessageBox.critical(
                    self,
                    self.tr("Password Update Failed"),
                    self.tr(
                        "Password change did not return a valid result. "
                        "This usually means the update path failed before backup codes could be generated."
                    ),
                )
                return

            ok_flag = (result.get("status") == "SUCCESS") or (result.get("success") is True)
            if not ok_flag:
                QMessageBox.critical(
                    self,
                    self.tr("Password Update Failed"),
                    f"❌ {result.get('message', 'Unknown error')}",
                )
                return

            # --- IMPORTANT: rewrap identity store to the NEW password ---
            try:
                from auth.identity_store import rewrap_identity_password

                ok_id, err_id = rewrap_identity_password(canonical, old_pw, new_pw)
                if not ok_id:
                    log.error("[SEC] Identity password wrapper was not updated for %s: %s", canonical, err_id)
                    try:
                        from auth.identity_store import create_or_open_with_password
                        create_or_open_with_password(canonical, new_pw)
                        log.warning("[SEC] Identity wrapper rebuilt under new password for %s", canonical)
                    except Exception as e2:
                        log.error("[SEC] Identity rebuild failed for %s: %r", canonical, e2)
                        QMessageBox.warning(
                            self,
                            self.tr("Warning"),
                            self.tr(
                                "Your password was changed, but the Identity Store could not be repaired.\n\n"
                                "This may affect 2FA / YubiKey features.\n"
                                "You can fix this by changing your password again or restoring a backup."
                            ),
                        )
                        return

            except Exception as e:
                log.error("[SEC] Identity rewrap call failed for %s: %r", canonical, e)

            # Backup codes + Recovery Key from account_creator
            new_codes = result.get("backup_codes") or result.get("backup_codes_plain") or []
            new_recovery_key = result.get("recovery_key")

            # IMPORTANT:
            # Login backup codes depend on the Identity Store password wrapper.
            # During password change, the identity wrapper is still on the OLD password
            # until rewrap_identity_password(...) succeeds above. So regenerate the
            # login backup codes only AFTER identity rewrap, using the NEW password.
            if update_backup and recovery_mode:
                try:
                    from auth.identity_store import gen_backup_codes

                    log.debug("[SEC] Regenerating backup codes AFTER identity rewrap for %s", canonical)
                    new_codes = gen_backup_codes(
                        canonical,
                        b_type="login",
                        n=10,
                        L=12,
                        password_for_identity=new_pw,
                    )
                except Exception as e:
                    log.error(
                        "[SEC] Backup code regeneration failed AFTER identity rewrap for %s: %r",
                        canonical,
                        e,
                        exc_info=True,
                    )
                    QMessageBox.warning(
                        self,
                        self.tr("Backup Codes"),
                        self.tr(
                            "Your password was changed, but new backup codes could not be generated.\n\n"
                            "Please log in again and regenerate them from Settings."
                        ),
                    )
                    new_codes = []

            # If Recovery Key rotation was requested, ensure we actually got a new key.
            # (If not, the old Emergency Kit key will correctly fail Forgot Password.)
            if (update_recovery_key and recovery_mode) and not new_recovery_key:
                QMessageBox.critical(
                    self,
                    self.tr("Password Update Failed"),
                    self.tr(
                        "Recovery Key rotation was requested, but a new Recovery Key was not generated. "
                        "Please try again."
                    ),
                )
                return

            # IMPORTANT: if we rotated the Recovery Key, re-bind the identity 'recovery' wrapper
            # AFTER the identity password wrapper has been updated, using the NEW password.
            if (update_recovery_key and recovery_mode) and new_recovery_key:
                try:
                    from auth.pw.utils_recovery import recovery_key_to_mk
                    from auth.identity_store import bind_recovery_wrapper

                    mk = recovery_key_to_mk(new_recovery_key)
                    bind_recovery_wrapper(canonical, new_pw, mk)
                    log.info("[SEC] Identity recovery wrapper re-bound for %s", canonical)
                except Exception as e:
                    log.warning("[SEC] Could not re-bind identity recovery wrapper for %s: %r", canonical, e)

            # Persist backup codes (Identity Store; hash-only)
            if new_codes:
                try:
                    _persist_backup_codes(canonical, new_codes, password_for_identity=new_pw)
                except Exception:
                    log.warning("[SEC] Failed to persist new backup codes for %s", canonical)

            # Immediately migrate session-encrypted side stores while the OLD native session is
            # still alive. This is more reliable than waiting for the next login.
            migration_warnings = []
            new_session_handle = None
            try:
                if isinstance(old_session_handle, int) and old_session_handle > 0:
                    new_session_handle = _open_native_session_for_user(canonical, new_pw)

                    try:
                        from features.security_center.vault_security_update_ops import migrate_post_rekey_side_stores

                        mig_ok, mig_warnings = migrate_post_rekey_side_stores(
                            w=parent,
                            username=canonical,
                            old_session_handle=old_session_handle,
                            new_session_handle=new_session_handle,
                            refresh_device_unlock=True,
                        )

                        if mig_warnings:
                            migration_warnings.extend(
                                self.tr("• {msg}").format(msg=str(m)) for m in mig_warnings
                            )

                        try:
                            from features.systemtray.systemtry_ops import notify_other
                            notify_other(self, "Password Update", "Security stores refreshed")
                        except Exception:
                            pass

                    except Exception as e:
                        migration_warnings.append(
                            self.tr("• Side-store migration: FAILED — {msg}").format(msg=str(e))
                        )
            finally:
                _close_native_session_safe(new_session_handle)
            
            if migration_warnings:
                title =  self.tr("Migration warnings")
                msg = self.tr(
                        "Some files could not be updated after your password change.\n\n"
                        "{details}\n\n"
                        "What you can do:\n"
                        "• Log out and log in again.\n"
                        "• If it still fails, restore from your most recent FULL backup."
                    ).format(details="\n".join(migration_warnings))

                QMessageBox.warning(
                    self,
                    title,
                    msg)

                try:
                    from features.systemtray.systemtry_ops import notify_other
                    notify_other(self, title, msg)
                except Exception:
                    pass
            
            # We handled side-store migration already. Avoid a second login-time run
            # against a stale/closed old session.
            try:
                if parent is not None and hasattr(parent, "_prev_core_session_handle"):
                    delattr(parent, "_prev_core_session_handle")
            except Exception:
                pass

            # If we have any new secrets, offer to build/update the Emergency Kit
            try:
                if parent is not None and hasattr(parent, "emg_ask") and (new_codes or new_recovery_key):
                    parent.emg_ask(
                        canonical,
                        one_time_recovery_key=new_recovery_key,
                        recovery_backup_codes=new_codes or None,
                        twofa_backup_codes=None,
                        totp_secret_plain=None,
                        totp_uri=None,
                        totp_qr_png=None,
                    )
                else:
                    # Fallback: simple popups if emg_ask is not available
                    if new_codes:
                        popup = QDialog(self)
                        popup.setWindowTitle(self.tr("New Backup Codes"))
                        lay = QVBoxLayout(popup)
                        lay.addWidget(
                            QLabel(
                                self.tr("Store these backup codes securely. They will only be shown once:")
                                + "\n\n"
                                + "\n".join(new_codes)
                            )
                        )
                        okbtn = QPushButton(self.tr("I have stored them securely"))
                        okbtn.clicked.connect(popup.accept)
                        lay.addWidget(okbtn)
                        popup.exec()

                    if new_recovery_key:
                        rk_popup = QDialog(self)
                        rk_popup.setWindowTitle(self.tr("New Recovery Key"))
                        lay = QVBoxLayout(rk_popup)
                        lay.addWidget(
                            QLabel(
                                self.tr(
                                    "A new Recovery Key has been generated for your account.\n\n"
                                    "Write this down and store it somewhere safe and offline. "
                                    "This key can be used to recover your vault if you forget your password.\n\n"
                                    "It will only be shown once:\n\n"
                                )
                                + f"{new_recovery_key}"
                            )
                        )
                        okbtn = QPushButton(self.tr("I have stored it safely"))
                        okbtn.clicked.connect(rk_popup.accept)
                        lay.addWidget(okbtn)
                        rk_popup.exec()
            except Exception as e:
                log.warning("[KIT] Emergency Kit flow after password change failed: %s", e)

            # Record timestamps
            try:
                rec = get_user_record(canonical) or {}
                ts = now_utc_iso()
                rec["last_password_change"] = ts
                if rotate_salt:
                    rec["last_salt_rotation"] = ts
                set_user_record(canonical, rec)
            except Exception as e:
                log.warning("[SEC] Could not persist last_password_change timestamp for %s: %s", canonical, e)

            # Baseline
            try:
                update_baseline(canonical, verify_after=False, who=self.tr("Password Updated"))
            except Exception as e:
                log.warning("[BASELINE] update_baseline failed: %s", e)
            title = self.tr("Password Updated")
            msg = self.tr(
                "Your password has been updated successfully.\n\n"
                "Keyquorum now needs a quick re-login to refresh your encryption keys.\n\n"
                "If you use cloud sync, it is recommended to run a manual Push once you log back in.\n\n"
                "Click OK, then log in again using your new password."
            )
            # Single, clear message (no double popups)
            QMessageBox.information(
                self,
                title,
                msg,
            )
            
            try:
                from features.systemtray.systemtry_ops import notify_other
                notify_other(self, title, msg)
            except Exception:
                pass

            # Force logout (parent will return to login screen)
            try:
                if parent is not None and hasattr(parent, "logout_user"):
                    parent.logout_user()
            except Exception as e:
                log.error("Logout error after password change: %s", e)

            self.accept()

        except Exception as e:
            log.error(f"[ERROR] 🔐 Change Password failed: {e}")
            try:
                if hasattr(self.parent(), "reset_logout_timer"):
                    self.parent().reset_logout_timer()
            except Exception:
                pass
            QMessageBox.critical(
                self,
                self.tr("Error"),
                self.tr("An error occurred while changing the password") + f":\n\n{e}",
            )
