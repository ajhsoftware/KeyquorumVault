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


def show_message_user_login(self, who=""):
    QMessageBox.warning(
        self,
        who,
        self.tr("Please login first."),
    )


# =====================
# password / username
# =====================

def show_message_vault_change(self):
    # Recommend a full backup before any password / key changes
    reply = QMessageBox.warning(
        self,
        self.tr("Vault Warning"),
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
    return reply == QMessageBox.Yes


def message_disable_passwordless(self):
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
        QMessageBox.No,)
    return confirm == QMessageBox.Yes


def message_disable_passwordless(self):
    QMessageBox.information(
        self,
        self.tr("Passwordless unlock cleared"),
        self.tr("Passwordless unlock has been disabled for this device."),)


def message_clear_username(self):
    resp = QMessageBox.question(
        self,
        self.tr("Clear remembered username"),
        self.tr("Remove the remembered username from this device?"),
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No,
    )
    return resp == QMessageBox.Yes


def message_update_vault_ask_pw(self, who="", msg=""):
    pw, ok = QInputDialog.getText(
        self,
        who,
        f"{msg}, please confirm your password:",
        QLineEdit.Password,
    )
    if not ok or not pw:
        return "", False
    return pw, ok


# ======================
# sec center
# ======================

def message_already_updated(self):
    QMessageBox.information(
        self,
        "Security Update",
        "Your vault is already on the newer KDF profile (v2).",
    )


def message_update_vault(self):
    QMessageBox.information(
        self,
        "Security Update",
        "Done! Your vault has been upgraded to the stronger KDF profile (v2).\n\n"
        "Tip: If you use ‘Remember this device’, sign in once again with it enabled so the token can be refreshed."
        "Keyquorum now needs a quick re-login to refresh your encryption keys "
        "and keep features like the Authenticator working.\n\n"
        "Please don’t close the app.\n"
        "Click OK, then log in again using your new password.")


# ======================
# backup
# ======================


def message_no_password(self, who):
    QMessageBox.information(
        self,
        who,
        "Please Enter a Password")

# ======================
# error
# ======================


def message_backup_error(self, e):
     QMessageBox.warning(
        self,
        self.tr("Backup Error"),
        (
            self.tr("Keyquorum tried to create a full backup but an error occurred:\n\n"
            "{e}\n\n"
            "strongly recommended to resolve this backup issue before continue.").format(e)
        ),
    )


def message_salt_error(self, who):
    QMessageBox.warning(
        self,
        who,
        "Your vault salt is missing or invalid. Please restore from backup.",
    )


def message_vault_missing(self, who, vpath):
    QMessageBox.warning(self, who, f"Vault file not found:\n{vpath} \n Please restore from backup")


def message_read_decrypt_vault(self, who, e):
    QMessageBox.warning(self, who, f"Could not read/decrypt your vault:\n{e}")







