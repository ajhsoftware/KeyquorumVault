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

import platform, hashlib, json, subprocess, os
try:
    import winreg  # type: ignore  # Windows only
except Exception:
    winreg = None

def _get_machine_guid():
    if not winreg: return ""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        val, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return str(val or "")
    except Exception:
        return ""

def _get_smbios_uuid():
    # Best effort, non-fatal. Works when WMI/CIM accessible.
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "(Get-CimInstance Win32_ComputerSystemProduct).UUID"],
            text=True, stderr=subprocess.STDOUT, timeout=3
        ).strip()
        return out if out and out != "00000000-0000-0000-0000-000000000000" else ""
    except Exception:
        return ""

def get_device_fingerprint():
    data = {
        "deviceName": platform.node() or "",
        "machineGuid": _get_machine_guid(),
        "smbiosUuid": _get_smbios_uuid(),
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "arch": platform.machine(),
    }
    # canonicalize & hash
    canon = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fp = hashlib.sha256(canon).hexdigest()
    return fp, data  # return both: hashed id + context (you can log only hashed id)
