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

# NOTE:
# relogin after logout, like same as remember device but don't show login screen auto load.
# This was the original of remember-device on login and might be safe to remove.

from __future__ import annotations
import logging
from qtpy.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton, QGroupBox, QFrame,
    QMessageBox, QDialogButtonBox, QCheckBox, QGridLayout
)
from qtpy.QtCore import Qt
log = logging.getLogger("keyquorum")

class DeviceUnlockDialog(QDialog):
    """
    Windows Hello (only) device unlock settings dialog.

    IMPORTANT:
    - This dialog is intended to be opened AFTER login.
    - It uses:
        - self.app.userKey (master key in memory)
        - auth.login_handler.get_user_record / set_user_record (persistent record)
    - It does NOT require self.app.user_record
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.app = parent

        # More accurate naming than "Windows Hello" alone
        self.setWindowTitle("Device Unlock (Windows quick unlock)")
        self.setMinimumWidth(560)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(14)

        # Clear explanation (RichText so it reads nicely)
        self.lblHeader = QLabel(
                "<b>Windows quick unlock (Windows secure storage)</b><br>"
                "This feature stores an <b>OS-protected</b> wrapped vault key tied to your current Windows user profile.<br><br>"
                "<b>Important:</b><br>"
                "• You may <b>not</b> see a Windows Hello prompt (face/PIN) if you are already logged into Windows — this is normal.<br>"
                "• If someone can access your <b>unlocked</b> Windows session, they may be able to unlock the vault.<br>"
                "• This does <b>not</b> keep the vault unlocked after restart — you must log into Windows again.<br><br>"
                "<b>Security policy:</b><br>"
                "• This option <b>cannot be enabled</b> on <b>Maximum-Security</b> accounts by design.<br><br>"
                "<span style='color:#c77'><b>Tip:</b></span> Keyquorum will lock automatically when Windows locks, sleeps, or logs out."
            )

        self.lblHeader.setWordWrap(True)
        self.lblHeader.setTextFormat(Qt.TextFormat.RichText)
        self.lblHeader.setStyleSheet("color:#bbb;")
        root.addWidget(self.lblHeader)

        # Acknowledgement checkbox (prevents “I didn’t know” support tickets)
        self.cbAcknowledge = QCheckBox(
            "I understand Windows may not prompt for face/PIN if already logged in."
        )
        self.cbAcknowledge.setChecked(False)
        root.addWidget(self.cbAcknowledge)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        root.addWidget(sep)

        # More accurate group name
        g_hello = QGroupBox("Windows quick unlock")
        v_hello = QVBoxLayout(g_hello)
        v_hello.setContentsMargins(10, 8, 10, 12)
        v_hello.setSpacing(8)

        self.lblStatus = QLabel("Status: -")
        self.lblStatus.setWordWrap(True)
        self.lblStatus.setStyleSheet("color:#888;")
        v_hello.addWidget(self.lblStatus)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(10)

        # Button labels updated to match the new wording
        self.btnEnable = QPushButton("Enable quick unlock")
        self.btnDisable = QPushButton("Disable quick unlock")
        self.btnTest = QPushButton("Test unwrap (no prompt expected)")

        grid.addWidget(self.btnEnable, 0, 0)
        grid.addWidget(self.btnDisable, 0, 1)
        grid.addWidget(self.btnTest, 1, 0, 1, 2)

        v_hello.addLayout(grid)
        root.addWidget(g_hello)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.button(QDialogButtonBox.StandardButton.Close).clicked.connect(self.reject)
        root.addWidget(btns)

        self.btnEnable.clicked.connect(self._on_enable_hello)
        self.btnDisable.clicked.connect(self._on_disable_hello)
        self.btnTest.clicked.connect(self._on_test_hello)

        self.refresh_state()

    # ---------------- helpers ----------------

    def _on_enable_hello(self):
        if hasattr(self, "cbAcknowledge") and not self.cbAcknowledge.isChecked():
            self._err("Please tick the acknowledgement box before enabling quick unlock.")
            return

    def _username(self) -> str:
        try:
            return (self.app.currentUsername.text() or "").strip()
        except Exception:
            return ""

    def _mk(self) -> bytes:
        # Your app stores the master key as self.userKey (bytes) after login
        k = getattr(self.app, "userKey", None)
        if isinstance(k, (bytes, bytearray)) and k:
            return bytes(k)
        raise RuntimeError("Vault key not in memory (open this dialog after login).")

    def _load_record(self) -> dict:
        u = self._username()
        if not u:
            raise RuntimeError("No username available (open this dialog after login).")
        from auth.login_handler import get_user_record
        rec = get_user_record(u) or {}
        if not isinstance(rec, dict) or not rec:
            raise RuntimeError("User record not found.")
        return rec

    def _save_record(self, rec: dict) -> None:
        u = self._username()
        if not u:
            raise RuntimeError("No username available (open this dialog after login).")
        from auth.login_handler import set_user_record
        set_user_record(u, rec)

    def _hello_on(self, rec: dict) -> bool:
        wh = rec.get("windows_hello") or {}
        return bool(wh.get("enabled"))

    def _info(self, msg: str):
        QMessageBox.information(self, "Windows Hello", msg)

    def _err(self, msg: str):
        QMessageBox.critical(self, "Windows Hello", msg)

    # ---------------- state ----------------

    def refresh_state(self):
        try:
            rec = self._load_record()
            on = self._hello_on(rec)

            # Import here to avoid top-level coupling
            from security.security_features import is_max_security
            maxsec = is_max_security(rec)

            self.lblStatus.setText(
                f"Status: {'On' if on else 'Off'}\n"
                f"Account mode: {'Maximum-Security' if maxsec else 'Recovery-Mode'}"
            )

            if maxsec:
                # Hard policy: quick unlock is NOT allowed
                self.btnEnable.setEnabled(False)
                self.btnDisable.setEnabled(False)
                self.btnTest.setEnabled(False)

                # explain why (no popup)
                self.btnEnable.setToolTip(
                    "Unavailable for Maximum-Security accounts.\n"
                    "This is a deliberate security restriction."
                )
            else:
                # Recovery-mode behaviour
                self.btnEnable.setEnabled(not on)
                self.btnDisable.setEnabled(on)
                self.btnTest.setEnabled(True)

        except Exception as e:
            # Something is wrong (not logged in, record missing, etc.)
            self.lblStatus.setText(f"Status: Unavailable\n{e}")
            self.btnEnable.setEnabled(False)
            self.btnDisable.setEnabled(False)
            self.btnTest.setEnabled(False)

    # ---------------- actions ----------------

    def _on_enable_hello(self):
        try:
            from security.security_features import enable_windows_hello
            rec = self._load_record()
            rec = enable_windows_hello(rec, self._mk())
            self._save_record(rec)
            self._info("Windows Hello enabled.")
        except Exception as e:
            log.error("[Hello] enable failed: %s", e)
            self._err(f"Failed to enable Windows Hello:\n{e}")
        self.refresh_state()

    def _on_disable_hello(self):
        try:
            from security.security_features import disable_windows_hello
            rec = self._load_record()
            rec = disable_windows_hello(rec)
            self._save_record(rec)
            self._info("Windows Hello disabled.")
        except Exception as e:
            log.error("[Hello] disable failed: %s", e)
            self._err(f"Failed to disable Windows Hello:\n{e}")
        self.refresh_state()

    def _on_test_hello(self):
        try:
            from security.security_features import try_unlock_with_windows_hello
            rec = self._load_record()
            mk = try_unlock_with_windows_hello(rec)
            if mk:
                self._info("Hello unwrap succeeded (master key recovered).")
            else:
                self._err("Hello is not enabled for this user.")
        except Exception as e:
            log.error("[Hello] test failed: %s", e)
            self._err(f"Hello test failed:\n{e}")
        self.refresh_state()
