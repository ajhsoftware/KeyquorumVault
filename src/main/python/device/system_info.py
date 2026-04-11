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
import platform

# winreg is only available on Windows
try:
    import winreg
except Exception:  # pragma: no cover (non-Windows)
    winreg = None  

log = logging.getLogger("keyquorum")

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("system_info", text)


# ---------------------------------
# Small helpers
# ---------------------------------
def _is_windows() -> bool:
    try:
        return platform.system().lower().startswith("win")
    except Exception:
        return False

# ---------------------------------
# Windows Clipboard History / Cloud Clipboard
# ---------------------------------

def get_clipboard_history_state() -> tuple[str, bool]:
    """
    Returns (description, is_enabled) for Windows Clipboard History.

    - On non-Windows: returns a neutral description and False.
    - On Windows: reads the per-user setting and (if present) GPO policy.
    """
    from typing import Optional as _Optional  # local alias to avoid confusion

    if not _is_windows() or winreg is None:
        return (_tr("Clipboard history is only available on Windows 10/11."), False)

    history_on = False
    cloud_on = False
    history_policy: _Optional[bool] = None
    cloud_policy: _Optional[bool] = None

    # --- Per-user settings (HKCU\Software\Microsoft\Clipboard) ---
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Clipboard"
        ) as k:

            def _flag(name: str) -> bool:
                try:
                    val, _ = winreg.QueryValueEx(k, name)
                    return int(val) != 0
                except Exception:
                    return False

            # Different Windows builds have slightly different names
            history_on = _flag("EnableClipboardHistory") or _flag("EnableHistory")
            cloud_on = _flag("EnableCloudClipboard") or _flag("EnableCloudSync")
    except Exception:
        # If this fails, we'll just fall back to policy if present
        pass

    # --- Policy overrides (HKLM/HKCU\Software\Policies\Microsoft\Windows\System) ---
    def _policy(root, name: str) -> _Optional[bool]:
        path = r"Software\Policies\Microsoft\Windows\System"
        try:
            with winreg.OpenKey(root, path) as k:
                val, _ = winreg.QueryValueEx(k, name)
                v = int(val)
                if v == 1:
                    return True
                if v == 0:
                    return False
        except Exception:
            return None
        return None

    if winreg is not None:
        history_policy = _policy(winreg.HKEY_LOCAL_MACHINE, "AllowClipboardHistory")
        if history_policy is None:
            history_policy = _policy(winreg.HKEY_CURRENT_USER, "AllowClipboardHistory")

        cloud_policy = _policy(winreg.HKEY_LOCAL_MACHINE, "AllowCrossDeviceClipboard")
        if cloud_policy is None:
            cloud_policy = _policy(winreg.HKEY_CURRENT_USER, "AllowCrossDeviceClipboard")

    # Policy can explicitly force history off
    if history_policy is False:
        history_on = False

    # Build a human-readable description
    parts: list[str] = []
    if history_on:
        parts.append(_tr("Windows Clipboard History is ON."))
    else:
        parts.append(_tr("Windows Clipboard History is OFF."))

    if cloud_on:
        parts.append(_tr("Cloud clipboard sync is ON (clipboard items may leave this device)."))

    if history_policy is False:
        parts.append(_tr("Policy: Clipboard history is forced OFF by system policy."))
    elif history_policy is True:
        parts.append(_tr("Policy: Clipboard history is forced ON by system policy."))

    if cloud_policy is False:
        parts.append(_tr("Policy: Cross-device clipboard is disabled by system policy."))
    elif cloud_policy is True:
        parts.append("Policy: Cross-device clipboard is forced ON by system policy.")

    desc = " ".join(parts) if parts else "Clipboard history status unknown."
    return (desc, bool(history_on))
