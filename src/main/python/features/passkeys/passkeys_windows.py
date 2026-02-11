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
from qtpy.QtWidgets import QMessageBox
import features.passkeys.capabilities as cap

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("passkeys_windows", text)

def provider_status_text() -> str:
    if cap.is_portable_mode():
        return _tr("Disabled (Portable build)")
    if not cap.is_windows11_23h2_plus():
        return _tr("Unavailable (Windows 11 23H2+ required)")
    if not cap.is_passkey_provider_registered():
        return _tr("Not enabled (open Windows Settings to enable)")
    return _tr("Enabled (system-wide)")

def ensure_enabled_ui(parent=None) -> None:
    """
    Called when the user clicks 'Enable Keyquorum as passkey provider'.
    Opens Settings; user must enable it there.
    """
    if cap.is_portable_mode():
        QMessageBox.information(parent, "Passkeys", "Passkeys are disabled in Portable mode.")
        return
    if not cap.is_windows11_23h2_plus():
        QMessageBox.warning(parent, "Passkeys", "Requires Windows 11 (23H2+) to appear in browsers/apps.")
        return
    cap.open_windows_passkey_settings()
