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
#
# v4 (STRICT DLL-ONLY):
#   - stores a DPAPI-protected blob that contains the 32-byte vault key
#   - blob is produced by the DLL from an already-open native session
#   - passwordless unlock opens a native session via DLL (key never returned to Python)
#
# v3 (legacy Python DPAPI):
#   - stores dpapi_pw_ctx bundle {vault_kek, identity_kek}
#   - used when identity-backed factors (TOTP / Yubi) require an identity context
#
# v2 (legacy Python DPAPI):
#   - stores a single secret (vault_kek)

from dataclasses import dataclass
from typing import Optional, Tuple
import time
import json
import base64
import os
from device.utils_device import hwfp_sha256
import uuid
import logging
log = logging.getLogger("keyquorum")

def _dpapi():
    # Legacy python DPAPI wrapper (kept for v2/v3 compatibility)
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
    v: int = 4
    kind: str = "dpapi_session"


def has_device_unlock(rec: dict) -> bool:
    rec = rec or {}
    blob = rec.get("device_unlock") or {}
    if isinstance(blob, dict) and blob.get("wrapped_b64") and blob.get("entropy_b64"):
        return True
    # Also allow token-list records
    toks = rec.get("device_unlock_tokens")
    if isinstance(toks, list) and toks:
        for t in reversed(toks):
            if isinstance(t, dict) and t.get("wrapped_b64") and t.get("entropy_b64"):
                return True
    return False


# -----------------------------
# Token List
# -----------------------------

def _token_list(rec: dict) -> list:
    # New field supports multiple tokens. Back-compat: migrate single device_unlock into list.
    if not isinstance(rec, dict):
        return []
    if isinstance(rec.get("device_unlock_tokens"), list):
        return rec["device_unlock_tokens"]

    # Back-compat: convert old single token -> list once
    du = rec.get("device_unlock")
    if isinstance(du, dict) and du.get("wrapped_b64") and du.get("entropy_b64"):
        rec["device_unlock_tokens"] = [du]
        rec.pop("device_unlock", None)
        return rec["device_unlock_tokens"]

    rec["device_unlock_tokens"] = []
    rec.pop("device_unlock", None)
    return rec["device_unlock_tokens"]

def list_device_unlock_tokens(rec: dict) -> list[dict]:
    toks = _token_list(rec)
    # return shallow copies for UI
    return [dict(t) for t in toks if isinstance(t, dict)]

def revoke_device_unlock_token(rec: dict, device_id: str) -> dict:
    toks = _token_list(rec)
    rec["device_unlock_tokens"] = [t for t in toks if isinstance(t, dict) and t.get("device_id") != device_id]
    return rec

# -----------------------------
# v4 (DLL-only) helpers
# -----------------------------

def save_device_unlock_v4_from_session(
    rec: dict, *, core, session_handle: int, ttl_days: int | None = None, device_label: str | None = None
) -> dict:
    """Persist a v4 device unlock token using ONLY the DLL.
    - entropy is generated in Python (non-secret)
    - DPAPI wrapping is performed by the DLL using session_export_key_dpapi
    - Stores token in device_unlock_tokens (+ latest copy in device_unlock for back-compat)
    """
    if not isinstance(rec, dict):
        rec = {}
    if not session_handle:
        raise ValueError("session_handle missing")
    if not core:
        raise ValueError("core missing")

    entropy = os.urandom(32)

    export_fn = getattr(core, "session_export_key_dpapi", None) or getattr(core, "session_export_dpapi", None)
    if not callable(export_fn):
        raise RuntimeError("core session export DPAPI function not available")

    wrapped_blob = export_fn(int(session_handle), entropy)
    if not wrapped_blob:
        raise RuntimeError("session_export_key_dpapi returned empty")

    now = int(time.time())
    expires_ts = 0
    if isinstance(ttl_days, int) and ttl_days > 0:
        expires_ts = now + (ttl_days * 86400)

    token = {
        "v": 4,
        "kind": "dpapi_session",
        "device_id": str(uuid.uuid4()),
        "hwfp_sha256": hwfp_sha256(),
        "device_label": (device_label or "").strip(),
        "wrapped_b64": _b64e(wrapped_blob),
        "entropy_b64": _b64e(entropy),
        "created_ts": now,
        "ttl_days": int(ttl_days) if (isinstance(ttl_days, int) and ttl_days > 0) else 0,
        "expires_ts": int(expires_ts) if expires_ts else 0,
    }

    # Only set ttl_days if the key is missing or None
    if "ttl_days" not in rec or rec["ttl_days"] is None:
        log.info("No ttl_days saved in record, setting default=%s", ttl_days)
        rec["ttl_days"] = int(ttl_days) if ttl_days is not None else 0

    toks = _token_list(rec)
    toks.append(token)
    rec["device_unlock_tokens"] = toks
    rec["device_unlock"] = token
    log.info("Saved v4 device-unlock token: device_id=%s tokens_total=%d", token["device_id"], len(toks))
    return rec

def try_open_session_from_device_unlock(rec: dict, *, core) -> Tuple[bool, Optional[int], str]:
    if not isinstance(rec, dict) or not rec:
        return False, None, "no record"
    if not core:
        return False, None, "core missing"

    candidates = []
    blob = rec.get("device_unlock")
    if isinstance(blob, dict):
        candidates.append(blob)

    toks = rec.get("device_unlock_tokens")
    if isinstance(toks, list):
        for t in toks:
            if isinstance(t, dict):
                candidates.append(t)

    if not candidates:
        return False, None, "no token"

    now = int(time.time())
    for blob in candidates:
        try:
            idnow = hwfp_sha256().strip().lower()
            stored = (blob.get("hwfp_sha256") or "").strip().lower()
            if stored and stored != idnow:
                # Token belongs to a different device/user profile; try next candidate.
                continue

            v = int(blob.get("v") or 0)
            kind = (blob.get("kind") or "").strip().lower()
            if v != 4 or kind != "dpapi_session":
                continue

            exp = int(blob.get("expires_ts") or 0)
            if exp and now > exp:
                continue

            wrapped_b64 = (blob.get("wrapped_b64") or "").strip()
            entropy_b64 = (blob.get("entropy_b64") or "").strip()
            if not (wrapped_b64 and entropy_b64):
                continue

            wrapped = _b64d(wrapped_b64)
            entropy = _b64d(entropy_b64)
            h = int(core.dpapi_unprotect_to_session(wrapped, entropy))
            if h:
                return True, h, ""
        except Exception:
            continue

    return False, None, "no usable token"

# -----------------------------
# Legacy v2/v3 helpers (Python DPAPI)
# -----------------------------

def clear_device_unlock(rec: dict) -> dict:
    if not isinstance(rec, dict):
        return {}
    rec.pop("device_unlock", None)
    return rec


def load_device_unlock(rec: dict) -> Tuple[bool, Optional[object], str]:
    """Legacy loader (Python DPAPI). Returns (ok, data, msg)."""
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

    # v4 is handled by try_open_session_from_device_unlock()
    if v == 4 and kind == "dpapi_session":
        return False, None, "v4 token requires DLL session open"

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


__all__ = [
    "has_device_unlock",
    "save_device_unlock",
    "save_device_unlock_v4_from_session",
    "try_open_session_from_device_unlock",
    "load_device_unlock",
    "clear_device_unlock",
]
