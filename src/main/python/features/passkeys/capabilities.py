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
import os, platform, subprocess, sys
from pathlib import Path

def is_windows() -> bool:
    return platform.system().lower() == "windows"

def is_portable_mode() -> bool:
    """
    Heuristics you already use for portable builds.
    - Presence of a 'portable.flag' file next to the EXE, or
    - Running from a USB path, or
    - No installer registry keys (see below).
    Tweak as needed.
    """
    # 1) explicit flag
    if Path("portable.flag").exists():
        return True
    # 2) frozen path on removable drive
    exe = Path(sys.executable)
    try:
        if exe.drive and exe.drive.upper().startswith(tuple([f"{d}:" for d in "DEFGHIJKLMNOPQRSTUVWXYZ"])):
            # crude: treat non-C:/ non-system drives as portable
            pass
    except Exception:
        pass
    # 3) registry (installed provider writes this)
    if is_windows() and not _has_installed_flag():
        return True
    return False

def _has_installed_flag() -> bool:
    if not is_windows():
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Keyquorum\Install", 0, winreg.KEY_READ) as k:
            v, _ = winreg.QueryValueEx(k, "Installed")
            return str(v).lower() in ("1", "true", "yes")
    except Exception:
        return False

def windows_build_number() -> int:
    if not is_windows(): return 0
    try:
        # On Windows, hide the console when calling wmic
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        startupinfo = None
        if os.name == "nt":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            startupinfo = si
        out = subprocess.check_output(
            ["wmic", "os", "get", "BuildNumber"],
            text=True,
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
        nums = [ln.strip() for ln in out.splitlines() if ln.strip().isdigit()]
        return int(nums[-1]) if nums else 0
    except Exception:
        return 0

def is_windows11_23h2_plus() -> bool:
    # 22631≈23H2, 26100≈24H2
    return is_windows() and windows_build_number() >= 22631

def is_passkey_provider_registered() -> bool:
    """
    The installer for the installed build should write this key.
    Your Windows provider component can also set it after successful registration.
    """
    if not is_windows(): return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Keyquorum\PasskeyProvider", 0, winreg.KEY_READ) as k:
            v, _ = winreg.QueryValueEx(k, "Registered")
            return str(v).lower() in ("1", "true", "yes")
    except Exception:
        return False

def passkeys_available_systemwide() -> bool:
    return (
        is_windows11_23h2_plus()
        and not is_portable_mode()
        and is_passkey_provider_registered()
    )

def open_windows_passkey_settings() -> None:
    """
    Launch the Windows Settings page for Passkeys without flashing a console window.
    Uses os.startfile on modern Windows builds and falls back to a hidden cmd invocation.
    """
    if not is_windows():
        return
    try:
        # Modern approach: open the URI directly (no console)
        os.startfile("ms-settings:accounts")
        return
    except Exception:
        pass
    try:
        # Fallback: launch via cmd but hide the console window
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        startupinfo = None
        if os.name == "nt":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            startupinfo = si
        subprocess.Popen(
            ["cmd", "/c", "start", "", "ms-settings:accounts"],
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
    except Exception:
        # Last resort: attempt os.system (console may briefly appear)
        try:
            os.system("start ms-settings:accounts")
        except Exception:
            pass
