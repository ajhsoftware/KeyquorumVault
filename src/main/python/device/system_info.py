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

import json, sys
import logging
import platform
import shutil
import subprocess
from datetime import datetime
from typing import Any, Dict, Optional

# winreg is only available on Windows
try:
    import winreg
except Exception:  # pragma: no cover (non-Windows)
    winreg = None  

log = logging.getLogger("keyquorum")

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("system_info", text)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _is_windows() -> bool:
    try:
        return platform.system().lower().startswith("win")
    except Exception:
        return False


def _creationflags_no_window() -> int:
    """
    Best-effort flag to avoid popping a console window when we invoke
    PowerShell / tools on Windows.
    """
    try:
        return getattr(subprocess, "CREATE_NO_WINDOW", 0)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Basic system info
# ---------------------------------------------------------------------------

def get_basic_system_info() -> Dict[str, Any]:
    """
    Lightweight, read-only system summary suitable for the Security Center.

    Returns keys like:
      {
        "os_name": "Windows",
        "os_release": "11",
        "os_version": "10.0.22631",
        "arch": "AMD64",
        "bits": 64,
        "hostname": "DESKTOP-ABC",
        "pretty": "Windows 11 (10.0.22631) 64-bit",
      }
    """
    info: Dict[str, Any] = {}

    try:
        info["os_name"]    = platform.system()
        info["os_release"] = platform.release()
        info["os_version"] = platform.version()
        info["arch"]       = platform.machine() or platform.processor() or ""
        info["hostname"]   = platform.node()

        # crude 32/64 bit
        try:
            info["bits"] = 64 if "64" in platform.architecture()[0] else 32
        except Exception:
            info["bits"] = None

        # pretty string for UI
        parts = []
        if info.get("os_name"):
            parts.append(str(info["os_name"]))
        if info.get("os_release"):
            parts.append(str(info["os_release"]))
        ver = info.get("os_version") or ""
        if ver:
            parts.append(f"({ver})")
        if info.get("bits"):
            parts.append(f"{info['bits']}-bit")
        info["pretty"] = " ".join(str(p) for p in parts if p)
    except Exception as e:
        log.warning("[system_info] basic system info failed: %s", e)

    # Windows 11 23H2+ detection from your capabilities helper
    try:
        import features.passkeys.capabilities as cap
        info["is_win11_23h2_plus"] = bool(cap.is_windows11_23h2_plus())
    except Exception:
        info.setdefault("is_win11_23h2_plus", None)

    return info


# ---------------------------------------------------------------------------
# Windows Update status
# ---------------------------------------------------------------------------

def _powershell_available() -> bool:
    """
    Return True if PowerShell is found on PATH.
    """
    try:
        return shutil.which("powershell") is not None
    except Exception:
        return False


def _parse_hotfix_date(raw: str) -> Optional[datetime]:
    """
    Try to parse the 'InstalledOn' field from Get-HotFix.
    Formats seen in the wild:
      - 01/06/2024
      - 01/06/2024 00:00:00
      - 6/1/2024 12:00:00 AM   (US)
    We normalise to a datetime (UTC-naive).
    """
    if not raw:
        return None

    raw = str(raw).strip()
    # Drop time zone words if present
    raw = raw.replace("AM", "").replace("PM", "").strip()

    # Only care about the date portion
    date_part = raw.split()[0]

    for fmt in ("%d/%m/%Y", "%m/%d/%Y"):
        try:
            return datetime.strptime(date_part, fmt)
        except Exception:
            continue
    return None

def get_windows_update_status(max_stale_days: int = 90) -> Dict[str, Any]:
    """
    Best-effort Windows Update status using Get-HotFix.
    Does NOT depend on _ps or winreg.
    """
    result: Dict[str, Any] = {
        "supported": _is_windows(),
        "ok": True,
        "status_text": "",
        "last_update_date": None,
        "days_since_update": None,
        "last_update_label": None,
        "error": None,
    }

    if not _is_windows():
        result["status_text"] = _tr("Windows Update status is only available on Windows.")
        return result

    if not _powershell_available():
        msg = _tr("PowerShell was not found on PATH; cannot query Windows Update.")
        log.info("[system_info] %s", msg)
        result["ok"] = False
        result["status_text"] = _tr("Windows Update status unavailable (PowerShell missing).")
        result["error"] = msg
        return result

    try:
        ps_cmd = (
            "Get-HotFix | Sort-Object InstalledOn | "
            "Select-Object -Last 1 | ConvertTo-Json -Compress"
        )
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="ignore",
            timeout=10,
            creationflags=_creationflags_no_window(),
        )
        out = (completed.stdout or "").strip()
        if completed.returncode != 0 or not out:
            msg = completed.stderr.strip() or "Get-HotFix returned no data"
            raise RuntimeError(msg)

        obj = json.loads(out)
        hotfix_id = (obj.get("HotFixID") or obj.get("hotfixid") or "").strip()
        desc = (obj.get("Description") or obj.get("description") or "").strip()
        installed_raw = obj.get("InstalledOn") or obj.get("installedon") or ""

        dt_installed = _parse_hotfix_date(installed_raw)
        days_since: Optional[int] = None
        if dt_installed:
            today = datetime.utcnow().date()
            days_since = (today - dt_installed.date()).days

        label_parts = []
        if hotfix_id:
            label_parts.append(hotfix_id)
        if desc:
            label_parts.append(f"({desc})")
        label = " ".join(label_parts) if label_parts else ""

        if dt_installed:
            pretty_date = dt_installed.date().isoformat()
            approx = f"~{days_since} days ago" if days_since is not None else "date unknown"
            status_text = _tr("Last Windows update") + f" {label or ''} " + _tr(" on ") + f"{pretty_date} ({approx})."
        else:
            status_text = _tr("Last update") + f" {label or ''} " + _tr("(install date unavailable).")

        ok = True
        if days_since is not None and days_since > max_stale_days:
            ok = False

        result.update(
            {
                "ok": ok,
                "status_text": status_text,
                "last_update_date": dt_installed.date().isoformat() if dt_installed else None,
                "days_since_update": days_since,
                "last_update_label": label or None,
            }
        )
        return result

    except Exception as e:
        msg = _tr("Windows Update status check failed:") + f" {e}"
        log.warning("[system_info] %s", msg)
        result["ok"] = False
        result["status_text"] = _tr("Windows Update status unavailable.")
        result["error"] = msg
        return result

# ---------------------------------------------------------------------------
# Windows Clipboard History / Cloud Clipboard
# ---------------------------------------------------------------------------

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
