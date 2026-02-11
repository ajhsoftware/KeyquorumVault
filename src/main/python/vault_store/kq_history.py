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

# Module for vault store functionality (kept as a comment so __future__ import stays valid).

# Lightweight, zero-plaintext password history for Keyquorum Vault
# Stores only HMAC-SHA256 fingerprints + timestamps.

from __future__ import annotations
import hmac, hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Iterable

HIST_INFO = b"kq.password_history.v1"
MAX_DEFAULT = 10

import logging
log = logging.getLogger("keyquorum")
log.debug("[DEBUG] 🔐 Password history module loaded")


# ---- time helpers ----
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def days_since_iso(ts_iso: str | None) -> int:
    if not ts_iso:
        return 9999
    try:
        dt = datetime.fromisoformat(ts_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return max(0, int((datetime.now(timezone.utc) - dt).days))
    except Exception:
        return 9999

# ---- key + fingerprint ----
def derive_hist_key(vault_key: bytes) -> bytes:
    return hmac.new(vault_key, HIST_INFO, hashlib.sha256).digest()

def pw_fingerprint(hist_key: bytes, pw_bytes: bytes) -> str:
    return hmac.new(hist_key, pw_bytes, hashlib.sha256).hexdigest()

# ---- structure helpers ----
def ensure_pw_hist(entry: Dict[str, Any]) -> None:
    if "pw_hist" not in entry or not isinstance(entry.get("pw_hist"), list):
        entry["pw_hist"] = []

def cap_history(entry: Dict[str, Any], max_hist: int = MAX_DEFAULT) -> None:
    ensure_pw_hist(entry)
    if len(entry["pw_hist"]) > max_hist:
        entry["pw_hist"] = entry["pw_hist"][-max_hist:]

# ---- core operations ----
def compute_current_fp(entry: Dict[str, Any], hist_key: bytes, get_plaintext_password) -> str:
    cur_pw = get_plaintext_password(entry)
    return pw_fingerprint(hist_key, cur_pw)

def would_reuse_old(entry: Dict[str, Any], new_pw_bytes: bytes, hist_key: bytes) -> bool:
    ensure_pw_hist(entry)
    new_fp = pw_fingerprint(hist_key, new_pw_bytes)
    for h in entry["pw_hist"]:
        if hmac.compare_digest(h.get("fp", ""), new_fp):
            return True
    return False

def is_same_as_current(entry: Dict[str, Any], new_pw_bytes: bytes, hist_key: bytes, get_plaintext_password) -> bool:
    cur_fp = compute_current_fp(entry, hist_key, get_plaintext_password)
    new_fp = pw_fingerprint(hist_key, new_pw_bytes)
    return hmac.compare_digest(cur_fp, new_fp)

def record_rotation(entry: Dict[str, Any], hist_key: bytes, get_plaintext_password, note: str = "rotate") -> None:
    ensure_pw_hist(entry)
    cur_fp = compute_current_fp(entry, hist_key, get_plaintext_password)
    entry["pw_hist"].append({"ts": utc_now_iso(), "fp": cur_fp, "note": note})

def mark_changed_now(entry: Dict[str, Any]) -> None:
    entry["last_changed"] = utc_now_iso()

def changed_days(entry: Dict[str, Any]) -> int:
    return days_since_iso(entry.get("last_changed"))

# ---- cross-entry reuse ----
def is_reused_now(entry: Dict[str, Any], all_entries: Iterable[Dict[str, Any]], hist_key: bytes, get_plaintext_password) -> bool:
    cur_fp = compute_current_fp(entry, hist_key, get_plaintext_password)
    for e in all_entries:
        if e is entry:
            continue
        try:
            other_fp = compute_current_fp(e, hist_key, get_plaintext_password)
        except Exception:
            continue
        if hmac.compare_digest(cur_fp, other_fp):
            return True
    return False

# ---- migration ----
def migrate_entry_defaults(entry: Dict[str, Any]) -> bool:
    mutated = False
    if "pw_hist" not in entry:
        entry["pw_hist"] = []
        mutated = True
    if not entry.get("last_changed"):
        lc = entry.get("created_at") or entry.get("created") or utc_now_iso()
        entry["last_changed"] = lc
        mutated = True
    return mutated
