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

import base64
import ctypes
import os
import sys
from ctypes import wintypes


# ---------------------------------------------------------------------
# Platform check
# ---------------------------------------------------------------------

def dpapi_available() -> bool:
    return sys.platform.startswith("win")


# ---------------------------------------------------------------------
# Windows DPAPI bindings (Windows only)
# ---------------------------------------------------------------------

class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _blob_from_bytes(data: bytes) -> DATA_BLOB:
    if not data:
        return DATA_BLOB(0, None)
    buf = (ctypes.c_byte * len(data))(*data)
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))


def _bytes_from_blob(blob: DATA_BLOB) -> bytes:
    if not blob.pbData or blob.cbData == 0:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


if dpapi_available():
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    CryptProtectData = crypt32.CryptProtectData
    CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    CryptProtectData.restype = wintypes.BOOL

    CryptUnprotectData = crypt32.CryptUnprotectData
    CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    CryptUnprotectData.restype = wintypes.BOOL

    LocalFree = kernel32.LocalFree
    LocalFree.argtypes = [wintypes.HLOCAL]
    LocalFree.restype = wintypes.HLOCAL


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

def dpapi_wrap_mk(secret: bytes) -> tuple[str, str]:
    """
    Protect secret bytes using Windows DPAPI.
    Returns (wrapped_b64, entropy_b64).
    """
    if not dpapi_available():
        raise RuntimeError("DPAPI not available (non-Windows).")
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        raise ValueError("secret must be non-empty bytes")

    entropy = os.urandom(16)

    in_blob = _blob_from_bytes(bytes(secret))
    ent_blob = _blob_from_bytes(entropy)
    out_blob = DATA_BLOB()

    ok = CryptProtectData(
        ctypes.byref(in_blob),
        "Keyquorum DPAPI Secret",
        ctypes.byref(ent_blob),
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise RuntimeError(f"CryptProtectData failed (winerr={ctypes.get_last_error()})")

    try:
        wrapped = _bytes_from_blob(out_blob)
        return (
            base64.b64encode(wrapped).decode("ascii"),
            base64.b64encode(entropy).decode("ascii"),
        )
    finally:
        if out_blob.pbData:
            LocalFree(out_blob.pbData)

def dpapi_unwrap_mk(wrapped_b64: str, entropy_b64: str) -> bytes:
    """
    Unwrap secret bytes using Windows DPAPI.
    """
    if not dpapi_available():
        raise RuntimeError("DPAPI not available (non-Windows).")

    wrapped = base64.b64decode(wrapped_b64)
    entropy = base64.b64decode(entropy_b64) if entropy_b64 else b""

    in_blob = _blob_from_bytes(wrapped)
    ent_blob = _blob_from_bytes(entropy)
    out_blob = DATA_BLOB()
    desc = wintypes.LPWSTR()

    ok = CryptUnprotectData(
        ctypes.byref(in_blob),
        ctypes.byref(desc),
        ctypes.byref(ent_blob),
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise RuntimeError(f"CryptUnprotectData failed (winerr={ctypes.get_last_error()})")

    try:
        return _bytes_from_blob(out_blob)
    finally:
        if out_blob.pbData:
            LocalFree(out_blob.pbData)
        if desc:
            LocalFree(desc)
