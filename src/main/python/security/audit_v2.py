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

"""
Experimental audit logging with separate pre-auth and post-auth logs.

This module provides two types of logging:
  • Pre-auth logs: minimal events such as failed login attempts or lockout notices,
    written in a tamper-evident JSONL format. A secret is stored on disk and used
    to HMAC the chain; on Windows, this secret is DPAPI-protected. The pre-auth
    logs do not require a user password to write or read (though they do not
    reveal sensitive content).
  • Post-auth logs: events occurring after successful login, encrypted using
    a Fernet key derived from the user's master key (user_key). These logs are
    useless to an offline attacker without the user's password or YubiKey.

Use preauth_log_event() before the user has successfully authenticated.
Use postauth_log_event() and postauth_read_events() after you have user_key.

You can merge pre- and post-auth logs for display via merge_audit_events() below.
"""

import base64
import json
import os
import time
from hashlib import sha256
import hmac
from typing import Any, Optional

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def _now_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))

def _uname_tag(username: str) -> str:
    """Return a stable per-machine hash of the username to avoid logging raw names."""
    machine = os.uname().nodename if hasattr(os, "uname") else "machine"
    h = sha256((machine + "|" + (username or "")).encode("utf-8")).hexdigest()
    return h[:16]

def _load_or_create_preauth_secret(config_dir: str) -> bytes:
    """
    Load or create a secret used for HMAC chaining in pre-auth logs.
    On Windows, the secret is protected with DPAPI; on other platforms it is stored as-is.
    """
    path = os.path.join(config_dir, "preauth_audit.key")
    # Try to load existing
    if os.path.exists(path):
        raw = open(path, "rb").read()
        dec = None
        if os.name == "nt":
            # Use DPAPI on Windows to decrypt
            try:
                import ctypes
                from ctypes import wintypes
                class DATA_BLOB(ctypes.Structure):
                    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]
                crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                CryptUnprotectData = crypt32.CryptUnprotectData
                CryptUnprotectData.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wintypes.LPWSTR),
                                               ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
                                               ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.POINTER(DATA_BLOB)]
                CryptUnprotectData.restype = wintypes.BOOL
                LocalFree = kernel32.LocalFree
                LocalFree.argtypes = [ctypes.c_void_p]
                LocalFree.restype = ctypes.c_void_p
                in_blob = DATA_BLOB(len(raw), (ctypes.c_byte * len(raw)).from_buffer_copy(raw))
                out_blob = DATA_BLOB()
                if CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
                    try:
                        dec = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                    finally:
                        LocalFree(out_blob.pbData)
            except Exception:
                dec = None
        return dec or raw
    # Generate new secret
    secret = os.urandom(32)
    to_store = secret
    if os.name == "nt":
        # Protect with DPAPI
        try:
            import ctypes
            from ctypes import wintypes
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]
            crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            CryptProtectData = crypt32.CryptProtectData
            CryptProtectData.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR,
                                         ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
                                         ctypes.c_void_p, wintypes.DWORD,
                                         ctypes.POINTER(DATA_BLOB)]
            CryptProtectData.restype = wintypes.BOOL
            LocalFree = kernel32.LocalFree
            LocalFree.argtypes = [ctypes.c_void_p]
            LocalFree.restype = ctypes.c_void_p
            in_blob = DATA_BLOB(len(secret), (ctypes.c_byte * len(secret)).from_buffer_copy(secret))
            out_blob = DATA_BLOB()
            if CryptProtectData(ctypes.byref(in_blob), "KeyquorumVault preauth log", None, None, None, 0, ctypes.byref(out_blob)):
                try:
                    to_store = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                finally:
                    LocalFree(out_blob.pbData)
        except Exception:
            to_store = secret
    # Save with 600 perms if possible
    _ensure_dir(config_dir)
    with open(path, "wb") as f:
        f.write(to_store)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return secret

def preauth_log_event(config_dir: str, username: str, event: str, details: Optional[dict[str, Any]] = None) -> None:
    """
    Append a pre-auth event to the JSONL log located under config_dir.

    The log is tamper-evident via an HMAC chain; minimal information is stored.
    Does not create directories if config_dir does not exist.
    """
    try:
        # Only proceed if config_dir exists; do not create during read-only phase
        if not os.path.exists(config_dir):
            return
        secret = _load_or_create_preauth_secret(config_dir)
        log_path = os.path.join(config_dir, "preauth_audit.jsonl")
        # Read last MAC in chain
        last_mac = None
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as fp:
                lines = fp.read().splitlines()
            for line in reversed(lines):
                if line.strip():
                    try:
                        obj = json.loads(line)
                        last_mac = obj.get("mac")
                        break
                    except Exception:
                        break
        payload = {
            "ts": _now_iso(),
            "u": _uname_tag(username),
            "event": str(event),
            "d": details or {},
            "prev": last_mac,
        }
        msg = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        mac = hmac.new(secret, msg, sha256).hexdigest()
        payload["mac"] = mac
        with open(log_path, "a", encoding="utf-8") as fp:
            fp.write(json.dumps(payload, ensure_ascii=False))
            fp.write("\n")
    except Exception:
        # Audit must never crash login flows
        pass

def _derive_fernet(user_key: bytes, context: bytes) -> Fernet:
    """
    Derive a Fernet key from user_key for a specific context (salt).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"KeyquorumVault|" + context,
    )
    key = hkdf.derive(user_key)
    return Fernet(base64.urlsafe_b64encode(key))

def postauth_log_event(user_audit_dir: str, user_key: bytes, event: str, details: Optional[dict[str, Any]] = None) -> None:
    """
    Append a post-auth event encrypted with a Fernet key derived from user_key.
    Creates the directory if needed.
    """
    try:
        _ensure_dir(user_audit_dir)
        f = _derive_fernet(user_key, b"audit-v2")
        payload = {
            "ts": _now_iso(),
            "event": str(event),
            "d": details or {},
        }
        token = f.encrypt(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        path = os.path.join(user_audit_dir, "audit.enc.jsonl")
        with open(path, "a", encoding="utf-8") as fp:
            fp.write(_b64e(token))
            fp.write("\n")
    except Exception:
        pass

def postauth_read_events(user_audit_dir: str, user_key: bytes, limit: int = 200) -> list[dict[str, Any]]:
    """
    Decrypt and return up to `limit` post-auth events.
    """
    out: list[dict[str, Any]] = []
    path = os.path.join(user_audit_dir, "audit.enc.jsonl")
    if not os.path.exists(path):
        return out
    f = _derive_fernet(user_key, b"audit-v2")
    with open(path, "r", encoding="utf-8") as fp:
        lines = fp.read().splitlines()
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            token = _b64d(line)
            dec = f.decrypt(token)
            out.append(json.loads(dec.decode("utf-8")))
        except Exception:
            continue
    return out

def merge_audit_events(preauth: list[dict[str, Any]], postauth: list[dict[str, Any]], preauth_chain_ok: bool) -> list[dict[str, Any]]:
    """
    Merge pre-auth and post-auth events into a unified list sorted by timestamp.

    Each returned dict has keys:
      • ts: ISO timestamp
      • ts_epoch: seconds since epoch
      • source: "pre-auth" or "post-auth"
      • event: event name
      • details: dict of details
      • integrity: "OK" / "WARN" / "Encrypted"
    """
    from datetime import datetime
    def _parse(ts: str) -> float:
        try:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").timestamp()
        except Exception:
            return 0.0
    out = []
    # Pre-auth
    for e in preauth:
        out.append({
            "ts": e.get("ts", ""),
            "ts_epoch": _parse(e.get("ts", "")),
            "source": "pre-auth",
            "event": e.get("event", ""),
            "details": e.get("d", {}),
            "integrity": "OK" if preauth_chain_ok else "WARN",
        })
    # Post-auth
    for e in postauth:
        out.append({
            "ts": e.get("ts", ""),
            "ts_epoch": _parse(e.get("ts", "")),
            "source": "post-auth",
            "event": e.get("event", ""),
            "details": e.get("d", {}),
            "integrity": "Encrypted",
        })
    out.sort(key=lambda x: x.get("ts_epoch", 0), reverse=True)
    return out
