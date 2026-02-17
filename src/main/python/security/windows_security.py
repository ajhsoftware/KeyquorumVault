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

import json
import sys
import platform
import subprocess
import logging

log = logging.getLogger("keyquorum")
log_file = "[SYSTEM INFO]"

# --- winreg (Windows only) ---------
try:
    import winreg  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover (non-Windows)
    winreg = None 


def run_ps_hidden(cmd: str, timeout: int = 5) -> subprocess.CompletedProcess:
    """
    Run a PowerShell command silently without flashing a CMD/PS window.
    Returns CompletedProcess (stdout/stderr).
    """

    # Windows-only flags
    creationflags = 0
    startupinfo = None

    if sys.platform == "win32":
        creationflags = 0x08000000  # CREATE_NO_WINDOW

        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        startupinfo = si

    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=creationflags,
        startupinfo=startupinfo,
    )

# --- Registry helper ---------------
def gettinginfo(hkeyc: int, keypath: str, key: str):
    """
    Simple registry reader.
      hkeyc: 1 = HKLM, 2 = HKCU
      keypath: subkey path
      key: value name

    Returns the raw value, or None if missing.
    """
    if winreg is None:
        return None

    if hkeyc == 1:
        hive = winreg.HKEY_LOCAL_MACHINE
    elif hkeyc == 2:
        hive = winreg.HKEY_CURRENT_USER
    else:
        return None

    try:
        hkey = winreg.OpenKey(hive, keypath)
        value, _ = winreg.QueryValueEx(hkey, key)
        return value
    except FileNotFoundError:
        return None
    except OSError:
        return None


# --- Command helper ----------------
def calling_command(command: str) -> str:
    """
    Run a shell command and return stdout as text.
    On Windows, hide the console window during execution.
    On error, returns an empty string.
    """
    try:
        creationflags = 0
        startupinfo = None
        if sys.platform == "win32":
            creationflags = 0x08000000  # CREATE_NO_WINDOW
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            startupinfo = si
        result = subprocess.check_output(
            command,
            shell=True,
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
        return result.decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        log.warning("%s command failed: %s", log_file, e)
        return ""

def _is_windows() -> bool:
    try:
        return platform.system().lower().startswith("win")
    except Exception:
        return False

# ---------------------------------
# TPM
# ---------------------------------
def tpm_status():
    """
    Returns (text, good) for TPM presence/enablement.
    """
    try:
        # PowerShell method
        cp = run_ps_hidden("(Get-Tpm).TpmPresent")
        msg = (cp.stdout or "").strip().lower()

        if msg in ("true", "false"):
            present = (msg == "true")
            if present:
                return ("TPM: Present", True)
            else:
                return ("TPM: Not Present", False)
    except Exception as e:
        log.warning("[SYSTEM INFO] TPM PS check failed: %s", e)

    # WMIC fallback
    try:
        cp = subprocess.run(
            ["wmic", "cpu", "get", "Name"],
            capture_output=True,
            text=True,
            creationflags=0x08000000,
        )
        msg = (cp.stdout or "").strip().lower()
        if "tpm" in msg:
            return ("TPM: Present", True)
    except Exception as e:
        log.warning("[SYSTEM INFO] TPM WMIC fallback failed: %s", e)

    return ("TPM: Unknown", False)

# ---------------------------------
# Secure Boot
# ---------------------------------
def secure_boot_status() -> tuple[str, bool]:
    """
    Return (label, good_flag) for Secure Boot.
    Tries PowerShell first, then registry if available.
    """
    if not _is_windows():
        return ("Unsupported", False)

    # 1) PowerShell cmdlet (works on most Win11 machines with UEFI)
    out = run_ps_hidden("Confirm-SecureBootUEFI 2>$null")
    log.info("%s secure boot PS: %r", log_file, out)
    low = (out.stdout or "").strip().lower()
    if low == "true":
        return ("Enabled", True)
    if low == "false":
        return ("Disabled", False)

    # 2) Registry: UEFISecureBootEnabled
    scboot = gettinginfo(
        1, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled"
    )
    if isinstance(scboot, int):
        log.info("%s secure boot reg: %r", log_file, scboot)
        if scboot == 1:
            return ("Enabled", True)
        if scboot == 0:
            return ("Disabled", False)

    return ("Unknown", False)

# ---------------------------------
# Kernel DMA Protection
# ---------------------------------
def kernel_dma_protection() -> tuple[str, bool]:
    """Return (label, good_flag) for Kernel DMA Protection."""
    if not _is_windows() or winreg is None:
        return ("Unknown", False)

    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DmaSecurity",
        )
        val, _ = winreg.QueryValueEx(key, "DmaProtected")
        log.info("%s kernel dma winreg: %r", log_file, val)
        if val == 1:
            return ("Enabled", True)
        return ("Disabled", False)
    except Exception as e:
        log.warning("%s kernel dma reg error: %s", log_file, e)
        return ("Unknown", False)

# ---------------------------------
# Windows activation
# ---------------------------------
def windows_activation_status() -> tuple[str, bool]:
    """Return (label, good_flag) for Windows activation."""
    if not _is_windows():
        return ("Unsupported", False)

    # 1) Primary: SoftwareLicensingProduct CIM query
    try:
        cp = run_ps_hidden(
            "Get-CimInstance -ClassName SoftwareLicensingProduct | "
            "Where-Object { $_.PartialProductKey } | "
            "Select-Object -First 1 | ConvertTo-Json -Compress"
        )
        stdout = (cp.stdout or "").strip()
        log.info("%s Windows Activation PS: %r", log_file, cp.stdout)

        if stdout:
            try:
                obj = json.loads(stdout)
                status = obj.get("LicenseStatus")
                # 1 = Licensed
                if status == 1:
                    return ("Activated", True)
                if status in (0, 2, 3):
                    return ("Not Activated", False)
            except json.JSONDecodeError as e:
                log.warning("%s activation JSON parse error: %s", log_file, e)
    except Exception as e:
        log.warning("%s activation CIM error: %s", log_file, e)

    # 2) Fallback: slmgr.vbs /xpr
    cp = run_ps_hidden(
        '"$env:windir\\system32\\cscript.exe" //Nologo '
        '"$env:windir\\system32\\slmgr.vbs" /xpr',
        timeout=10,
    )
    stdout = (cp.stdout or "").strip().lower()
    log.info("%s Windows Activation slmgr: %r", log_file, cp.stdout)

    if "permanent" in stdout or "permanently activated" in stdout:
        return ("Activated", True)
    if "not activated" in stdout or "expiration" in stdout:
        return ("Not Activated", False)

    return ("Unknown", False)
