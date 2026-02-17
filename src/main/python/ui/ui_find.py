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
UI widget discovery (findChild)

This section is responsible ONLY for locating widgets created by the .ui file
and storing references on the MainWindow instance.

Responsibilities:
- Use findChild / findChildren to locate widgets by objectName
- Cache widget references onto the MainWindow (w.*)
- Perform defensive lookup (widgets may not exist in all builds)
- Perform NO signal wiring
- Perform NO business logic

Rules:
- Never overwrite the `w` object
- Never connect signals here
- Never assume a widget exists
- Always allow missing widgets without crashing

If something breaks here:
- Check the .ui objectName
- Check the widget type (QLineEdit vs QComboBox, etc.)
"""

# - pysider
from qtpy.QtWidgets import (
    QLabel, QToolButton, QLineEdit, QPushButton, QTableWidget,
    QFormLayout, QWidget, QComboBox, QCheckBox
)
# - import Logging
import app.kq_logging as kql
import logging
log = logging.getLogger("keyquorum")


def find_all(w):
    find_login(w)
    init_find_child(w)
    find_authenticator(w)
    find_watchtower(w)


def find_login(w):
    w.loginTitle = w.findChild(QLabel, "loginTitle")
    w.usernameField = w.findChild(QLineEdit, "usernameField")
    w.passwordField = w.findChild(QLineEdit, "passwordField")
    w.loginButton = w.findChild(QPushButton, "loginButton")
    w.currentUsername = w.findChild(QLabel, "currentUsername")
    w.newPasswordField = w.findChild(QLineEdit, "newPasswordField")
    w.changePasswordButton = w.findChild(QPushButton, "changePasswordButton")
    w.loginPanel = w.findChild(QWidget, "loginPanel")

    # - 2FA tab
    w.codeField = w.findChild(QLineEdit, "codeField")
    w.verifyCodeButton = w.findChild(QPushButton, "verifyCodeButton")
    w.codeStatusLabel = w.findChild(QLabel, "codeStatusLabel")


def init_find_child(w):
    # - category
    w.categorySelector_2 = w.findChild(QComboBox, "categorySelector_2")
    if w.categorySelector_2 and not w.categorySelector_2.objectName():
        w.categorySelector_2.setObjectName("categorySelector_2")
    w.editAddCategoryTab = w.findChild(QWidget, "editAddCategoryTab")
    # other
    w.w_test_ = getattr(w, "w_test_", None) or w.findChild(QPushButton, "w_test_")
    w.tuchmode_ = w.findChild(QCheckBox, "tuchmode_")
    w.tuchmode_2 = w.findChild(QCheckBox, "tuchmode_2")
    w.vaultTable = w.findChild(QTableWidget, "vaultTable")
    w.profile_layout = w.findChild(QFormLayout, "profileLayout")
    w.themeSelector = w.findChild(QComboBox, "themeSelector")
    w.auditTable = w.findChild(QTableWidget, "auditTable")
    # ---------------------------
    # language combo
    # ---------------------------
    w.language_combo = None
    try:
        # Try a few likely objectNames first
        for _name in ("languageSelector", "appLanguageCombo", "languageCombo"):
            cb = None
            try:
                cb = w.findChild(QComboBox, _name)
            except Exception:
                cb = None
            if cb is not None:
                w.language_combo = cb
                break

        # Fallback: any QComboBox whose objectName mentions "language"
        if w.language_combo is None:
            try:
                for cb2 in w.findChildren(QComboBox):
                    nm = (cb2.objectName() or "").lower()
                    if "language" in nm:
                        w.language_combo = cb2
                        break
            except Exception:
                pass

        if w.language_combo is not None:
            log.info("%s [LANG] language combo found: %r", kql.i("ok"), w.language_combo.objectName())
            if hasattr(w, "_init_language_selector"):
                try:
                    w._init_language_selector()
                except Exception as e:
                    log.warning("%s [LANG] _init_language_selector failed: %s", kql.i("warn"), e)
        else:
            log.warning("%s [LANG] language combo NOT found; App language selector disabled", kql.i("warn"))

    except Exception as e:
        log.warning("%s [LANG] language combo init crashed: %s", kql.i("warn"), e)

    log.debug("%s [UI] Find Child OK", kql.i("ok"))


def find_authenticator(w):
    """Find Authenticator (TOTP) tab widgets."""
    from qtpy.QtWidgets import QWidget, QTableWidget, QPushButton, QToolButton

    w.authTab = w.findChild(QWidget, "authenticator")
    w.authTable = w.findChild(QTableWidget, "authTable")

    w.btnAuthAdd = w.findChild(QPushButton, "btnAuthAdd")
    w.btnAuthAddQR = w.findChild(QPushButton, "btnAuthAddQR")
    w.btnAuthAddScreen = w.findChild(QPushButton, "btnAuthAddScreen")
    w.btnAuthEdit = w.findChild(QPushButton, "btnAuthEdit")
    w.btnAuthDelete = w.findChild(QPushButton, "btnAuthDelete")
    w.btnAuthCopy = w.findChild(QPushButton, "btnAuthCopy")
    w.btnAuthSafeExport = w.findChild(QPushButton, "btnAuthSafeExport")
    w.btnAuthSafeImport = w.findChild(QPushButton, "btnAuthSafeImport")
    w.btnAuthAddCam = w.findChild(QPushButton, "btnAuthAddCam")
    w.auth_qr_ = w.findChild(QPushButton, "auth_qr_")


def find_watchtower(w):
    from qtpy.QtWidgets import QCheckBox, QLabel, QPushButton, QProgressBar, QTableWidget

    # - buttons
    w.scan_btn      = w.findChild(QPushButton, "scan_btn")
    w.preflight_btn = w.findChild(QPushButton, "preflight_btn")
    w.export_btn    = w.findChild(QPushButton, "export_btn")

    # - filters
    w.chk_weak         = w.findChild(QCheckBox, "chk_weak")
    w.chk_reused       = w.findChild(QCheckBox, "chk_reused")
    w.chk_http         = w.findChild(QCheckBox, "chk_http")
    w.chk_missing_user = w.findChild(QCheckBox, "chk_missing_user")
    w.chk_missing_url  = w.findChild(QCheckBox, "chk_missing_url")
    w.chk_2fa          = w.findChild(QCheckBox, "chk_2fa")
    w.chk_cards        = w.findChild(QCheckBox, "chk_cards")

    # - summary labels
    w.lbl_reused       = w.findChild(QLabel, "lbl_reused")
    w.lbl_weak         = w.findChild(QLabel, "lbl_weak")
    w.lbl_old          = w.findChild(QLabel, "lbl_old")
    w.lbl_breach       = w.findChild(QLabel, "lbl_breach")
    w.lbl_http         = w.findChild(QLabel, "lbl_http")
    w.lbl_missing_user = w.findChild(QLabel, "lbl_missing_user")
    w.lbl_missing_url  = w.findChild(QLabel, "lbl_missing_url")
    w.lbl_2fa          = w.findChild(QLabel, "lbl_2fa")
    w.lbl_cards        = w.findChild(QLabel, "lbl_cards")  # make sure you added this in Designer

    # - progress + tables
    w.progress  = w.findChild(QProgressBar, "progress")
    w.score_lbl = w.findChild(QLabel, "score_lbl")
    w.tbl       = w.findChild(QTableWidget, "tbl")
    w.tbl_ignored = w.findChild(QTableWidget, "tbl_ignored")
