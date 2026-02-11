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

"""Module for breach check functionality."""

import logging
import hashlib
from qtpy.QtWidgets import (
    QDialog, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox
)
from qtpy.QtCore import Qt, QThread, Signal

log = logging.getLogger("keyquorum")


class BreachCheckWorker(QThread):
    """
    Background worker that checks a password with the HIBP 'range' API (k-anonymity).
    Emits:
      resultReady(int): -1 on error, or the number of breaches (0+).
    """
    resultReady = Signal(int)

    def __init__(self, password: str, timeout: float = 8.0, parent=None):
        super().__init__(parent)
        self._pwd = password or ""
        self._timeout = float(timeout)

    def _http_get_text(self, url: str, headers: dict) -> str:
        """Attempt HTTP GET (requests first, urllib fallback for frozen builds)."""
        try:
            import requests  
            r = requests.get(url, headers=headers, timeout=self._timeout)
            r.raise_for_status()
            return r.text
        except Exception:
            import urllib.request
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")

    def run(self):
        from features.url.main_url import PWNEDPASSWORD, SITE_MAIN
        """Perform the actual breach check in background thread."""
        try:
            if not self._pwd:
                self.resultReady.emit(0)
                return

            sha1 = hashlib.sha1(self._pwd.encode("utf-8")).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            url = f"{PWNEDPASSWORD}{prefix}"
            headers = {
                "User-Agent": f"KeyquorumVault ({SITE_MAIN})",
                "Add-Padding": "true",  # reduce info leakage
            }
            text = self._http_get_text(url, headers)

            count = 0
            for line in text.splitlines():
                if ":" not in line:
                    continue
                suf, cnt = line.split(":", 1)
                if suf.strip().upper() == suffix:
                    try:
                        count = int(cnt.strip())
                    except ValueError:
                        count = 0
                    break

            log.debug("[BREACH] password match count=%d", count)
            self.resultReady.emit(count)

        except Exception as e:
            log.warning("[BREACH] error: %s", e)
            self.resultReady.emit(-1)


class BreachCheckDialog(QDialog):
    """UI dialog for checking password breaches using HIBP API."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Check Password Breach"))
        self.setMinimumWidth(420)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)

        layout = QVBoxLayout(self)
        self.info_label = QLabel(self.tr("Enter a password to check if it has appeared in known breaches:"))
        self.input_field = QLineEdit()
        self.input_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_field.setPlaceholderText(self.tr("Enter password"))
        self.check_button = QPushButton(self.tr("Check"))
        self.check_button.clicked.connect(self.check_password_breach)

        layout.addWidget(self.info_label)
        layout.addWidget(self.input_field)
        layout.addWidget(self.check_button)

        self._worker = None

    # ---------------------------------------------------------------------

    def _tick_idle_timer(self):
        """Reset idle timer in parent (if implemented)."""
        p = self.parent()
        if p and hasattr(p, "reset_logout_timer"):
            try:
                p.reset_logout_timer()
            except Exception:
                pass

    # ---------------------------------------------------------------------

    def check_password_breach(self):
        """Start background check."""
        self._tick_idle_timer()
        password = self.input_field.text().strip()
        if not password:
            QMessageBox.warning(self, self.tr("Missing"), self.tr("Please enter a password to check."))
            return

        self.check_button.setEnabled(False)
        self.info_label.setText(self.tr("Checking…"))

        self._worker = BreachCheckWorker(password, parent=self)
        self._worker.resultReady.connect(self._on_breach_result)
        self._worker.finished.connect(
            lambda: (self.check_button.setEnabled(True), setattr(self, "_worker", None))
        )
        self._worker.start()

    # ---------------------------------------------------------------------

    def _on_breach_result(self, count: int):
        """Handle result from background worker."""
        self._tick_idle_timer()
        if count == -1:
            QMessageBox.warning(self, self.tr("Error"), self.tr("Could not connect to breach API."))
        elif count > 0:
            QMessageBox.critical(
                self,
                self.tr("Password Breached"),
                "⚠️ " + self.tr("This password has appeared in ") + f"{count:,}" + self.tr(" known breaches!\n\nAvoid using it."),
            )
        else:
            QMessageBox.information(
                self, self.tr("Safe"), "✅ " + self.tr("This password was not found in known breaches.")
            )

        self.info_label.setText(self.tr("Enter a password to check if it has appeared in known breaches:"))
        self.input_field.clear()
