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

Windows Hello (DPAPI) helpers for Recovery-mode convenience unlock.

Design goals:
- No "stay logged in after reboot" behaviour.
- Hello is allowed only when recovery_mode == True.
- If DPAPI import fails, show the REAL reason (don't silently return False).
"""
from __future__ import annotations
from typing import Dict, Optional
import sys


POLICY_CONVENIENCE = "convenience"


def is_max_security(user_record: Dict) -> bool:
    # recovery_mode=True => recovery accounts
    # recovery_mode=False => maximum-security accounts
    return not bool((user_record or {}).get("recovery_mode", True))


# ---- DPAPI backend (must exist on Windows) ----
_dpapi_import_error: str | None = None

try:
    from auth.windows_hello.windows_hello_dpapi import dpapi_available, dpapi_wrap_mk, dpapi_unwrap_mk
except Exception as e:
    _dpapi_import_error = f"{type(e).__name__}: {e}"

    def dpapi_available() -> bool:
        return False

    def dpapi_wrap_mk(_: bytes):
        raise RuntimeError(f"DPAPI unavailable (import failed: {_dpapi_import_error})")

    def dpapi_unwrap_mk(_: str, __: str):
        raise RuntimeError(f"DPAPI unavailable (import failed: {_dpapi_import_error})")


def enable_windows_hello(user_record: Dict, master_key: bytes, policy: str = POLICY_CONVENIENCE) -> Dict:
    if is_max_security(user_record):
        raise PermissionError("Windows Hello not allowed for Maximum-Security accounts.")

    if not sys.platform.startswith("win"):
        raise RuntimeError("Windows Hello/DPAPI is Windows-only.")

    if not dpapi_available():
        # IMPORTANT: show WHY (missing file / wrong path / missing __init__.py etc.)
        extra = f" ({_dpapi_import_error})" if _dpapi_import_error else ""
        raise RuntimeError("Windows Hello/DPAPI is not available on this system/build" + extra)

    wrapped_b64, entropy_b64 = dpapi_wrap_mk(master_key)

    ur = dict(user_record or {})
    ur["windows_hello"] = {
        "enabled": True,
        "wrapped_mk": wrapped_b64,
        "entropy": entropy_b64,
        "policy": policy,
    }
    return ur


def disable_windows_hello(user_record: Dict) -> Dict:
    ur = dict(user_record or {})
    ur.pop("windows_hello", None)
    return ur


def try_unlock_with_windows_hello(user_record: Dict) -> Optional[bytes]:
    wh = (user_record or {}).get("windows_hello") or {}
    if not wh.get("enabled"):
        return None
    return dpapi_unwrap_mk(wh["wrapped_mk"], wh.get("entropy", ""))
