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

log = logging.getLogger("keyquorum")
log.debug("[DEBUG] 🔐 Change Password Dialog Loaded")

def _norm(s: str) -> str:
    return (s or "").strip()

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

            # Max-security: do not allow generating recovery-mode secrets here
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

            # Keep the current session key so the app can run a post-login rewrap
            # (e.g., Authenticator Store secrets) after the user logs back in.
            try:
                if parent is not None:
                    parent._prev_userKey = getattr(parent, "userKey", None) or self.user_key
            except Exception:
                pass

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

            # Single, clear message (no double popups)
            QMessageBox.information(
                self,
                self.tr("Password Updated"),
                self.tr(
                    "Your password has been updated successfully.\n\n"
                    "Keyquorum now needs a quick re-login to refresh your encryption keys "
                    "and keep features like the Authenticator working.\n\n"
                    "Please don’t close the app.\n"
                    "Click OK, then log in again using your new password."
                ),
            )

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
