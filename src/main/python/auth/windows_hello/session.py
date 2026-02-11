"""Keyquorum Vault
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

# Keyquorum Vault – Windows Hello / DPAPI device-unlock session helpers.

# This module manages the 'Remember this device' DPAPI-bound unlock blob.

# Option B+ (v3):
#  - Stores a small JSON bundle containing:
#      - vault_kek     (used for Yubi wrap / vault password context)
#     - identity_kek  (used to open identity store for TOTP / backup codes)
# - The bundle is wrapped by DPAPI (device-bound).

# Legacy handling:
#  - v1: ignored
#  - v2: single secret only (treated as legacy; requires password once to upgrade for 2FA)


from dataclasses import dataclass
from typing import Optional, Tuple, Union
import time
import json
import base64


def _dpapi():
    # Lazy import avoids circular import issues at startup
    from auth.windows_hello.windows_hello_dpapi import (
        dpapi_available,
        dpapi_wrap_mk,
        dpapi_unwrap_mk,
    )
    return dpapi_available, dpapi_wrap_mk, dpapi_unwrap_mk


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@dataclass
class DeviceUnlockBlob:
    wrapped_b64: str
    entropy_b64: str
    created_ts: int
    v: int = 3
    kind: str = "dpapi_pw_ctx"


def has_device_unlock(rec: dict) -> bool:
    blob = (rec or {}).get("device_unlock") or {}
    return bool(blob.get("wrapped_b64") and blob.get("entropy_b64"))


def save_device_unlock(rec: dict, payload: Union[bytes, dict]) -> dict:
    """
    Save DPAPI device unlock blob.

    Preferred payload (v3):
      payload = {"vault_kek": <bytes>, "identity_kek": <bytes>}

    Legacy payload (v2):
      payload = <bytes>
    """
    if not isinstance(rec, dict):
        rec = {}

    dpapi_available, dpapi_wrap_mk, _ = _dpapi()
    if not dpapi_available():
        rec.pop("device_unlock", None)
        return rec

    secret_bytes: bytes
    version = 3
    kind = "dpapi_pw_ctx"

    if isinstance(payload, dict):
        vk = payload.get("vault_kek")
        ik = payload.get("identity_kek")
        if not (isinstance(vk, (bytes, bytearray, memoryview)) and bytes(vk)):
            raise ValueError("vault_kek must be non-empty bytes")
        if not (isinstance(ik, (bytes, bytearray, memoryview)) and bytes(ik)):
            raise ValueError("identity_kek must be non-empty bytes")
        bundle = {
            "vault_kek_b64": _b64e(bytes(vk)),
            "identity_kek_b64": _b64e(bytes(ik)),
        }
        secret_bytes = json.dumps(bundle, separators=(",", ":")).encode("utf-8")
    elif isinstance(payload, (bytes, bytearray, memoryview)):
        # Legacy single-secret store
        secret_bytes = bytes(payload)
        if not secret_bytes:
            raise ValueError("secret must be non-empty bytes")
        version = 2
        kind = "dpapi_pw_kek"
    else:
        raise TypeError("payload must be bytes or dict")

    wrapped_b64, entropy_b64 = dpapi_wrap_mk(secret_bytes)
    rec["device_unlock"] = {
        "v": int(version),
        "kind": kind,
        "wrapped_b64": wrapped_b64,
        "entropy_b64": entropy_b64,
        "created_ts": int(time.time()),
    }
    return rec


def clear_device_unlock(rec: dict) -> dict:
    if not isinstance(rec, dict):
        return {}
    rec.pop("device_unlock", None)
    return rec


def load_device_unlock(rec: dict) -> Tuple[bool, Optional[object], str]:
    """
    Returns (ok, data, msg)

    data can be:
      - dict {"vault_kek": bytes, "identity_kek": bytes} for v3
      - bytes for v2 (legacy)
    """
    if not isinstance(rec, dict) or not rec:
        return False, None, "no record"

    blob = rec.get("device_unlock") or {}
    wrapped_b64 = (blob.get("wrapped_b64") or "").strip()
    entropy_b64 = (blob.get("entropy_b64") or "").strip()
    if not (wrapped_b64 and entropy_b64):
        return False, None, "no blob"

    try:
        v = int(blob.get("v") or 0)
    except Exception:
        v = 0
    kind = (blob.get("kind") or "").strip().lower()

    if v < 2:
        return False, None, "legacy remembered-device blob (v1). Sign in with password once to upgrade."

    dpapi_available, _, dpapi_unwrap_mk = _dpapi()
    if not dpapi_available():
        return False, None, "dpapi not available"

    try:
        raw = dpapi_unwrap_mk(wrapped_b64, entropy_b64)
        if not raw:
            return False, None, "empty secret"
    except Exception as e:
        return False, None, f"dpapi unwrap failed: {e}"

    # v3 bundle
    if v >= 3 and kind == "dpapi_pw_ctx":
        try:
            bundle = json.loads(raw.decode("utf-8"))
            vk = _b64d(bundle.get("vault_kek_b64") or "")
            ik = _b64d(bundle.get("identity_kek_b64") or "")
            if not (vk and ik):
                return False, None, "invalid dpapi bundle"
            return True, {"vault_kek": vk, "identity_kek": ik}, ""
        except Exception as e:
            return False, None, f"invalid dpapi bundle: {e}"

    return True, raw, ""
