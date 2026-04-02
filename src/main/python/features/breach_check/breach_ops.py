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
from features.url.main_url import SITE_HELP, PRIVACY_POLICY
from auth.login.login_handler import get_user_setting, set_user_setting
from urllib.parse import quote
from features.url.main_url import pnwed_url
from features.breach_check.breach_check_dialog import BreachCheckDialog


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
        username = self._active_username()
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
        accepted, dont_ask = _show_email_check_modal(self)
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
