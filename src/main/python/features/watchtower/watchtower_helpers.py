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

import datetime as dt
import hashlib
from datetime import timedelta
from urllib.parse import urlparse

# --- import 
from vault_store.vault_store import load_vault, update_vault_entry
from auth.login.login_handler import get_user_setting



def hash_pw(pw: str) -> str:
    try:
        return hashlib.sha256((pw or "").encode("utf-8")).hexdigest()
    except Exception:
        return ""


def persist_entry_with_history(w, username: str, key: bytes, index: int, new_entry: dict, *, max_hist: int = 10) -> bool:
    """
    Edit-save with password history.
    If password changed:
        - push OLD hash (+ timestamp) into password_history
        - stamp pw_changed_at for the new password
        - store the OLD plaintext as the single "last password" (encrypted),
        so we can one-click restore.
        """

    def _pw_val(d: dict) -> str:
        for k in ("Password", "password", "pwd", "pass", "secret", "Secret"):
            v = d.get(k)
            if isinstance(v, str) and v != "":
                return v
        return ""

    _sha = lambda s: hashlib.sha256((s or "").encode("utf-8")).hexdigest()

    # Load stored entry to compare
    try:
        entries = load_vault(username, key) or []
        prev = dict(entries[index]) if 0 <= index < len(entries) else {}
    except Exception:
        prev = {}

    old_pw = _pw_val(prev)
    new_pw = _pw_val(new_entry) or old_pw
    old_h = _sha(old_pw)
    new_h = _sha(new_pw)

    # Carry forward existing history (normalized)
    hist = []
    raw_hist = prev.get("password_history") or []
    if isinstance(raw_hist, list):
        for h in raw_hist:
            if isinstance(h, dict) and ("hash" in h or "fp" in h):
                hist.append(
                    {
                        "hash": str(h.get("hash") or h.get("fp")),
                        "ts": str(h.get("ts") or h.get("time") or ""),
                    }
                )

    # If changed → append OLD hash; stamp new pw_changed_at; store last plaintext
    if new_h and new_h != old_h:
        try:
            if bool(get_user_setting(username, "secure_restore_cache", True)) and old_pw:
                entry_id = str(prev.get("id") or prev.get("_id") or prev.get("row_id") or index)
                w._pwlast_put(username, key, entry_id, old_pw)
        except Exception:
            pass

        ts_prev = (
            prev.get("pw_changed_at")
            or prev.get("updated_at")
            or prev.get("Date")
            or dt.datetime.now().isoformat(timespec="seconds")
        )
        if old_h:
            hist.append({"hash": old_h, "ts": ts_prev})
        hist = hist[-max_hist:]
        new_entry["pw_changed_at"] = dt.datetime.now().isoformat(timespec="seconds")

    # Keep only last 90 days in history (plus count cap)
    cut = dt.datetime.now() - timedelta(days=90)

    def _parse_iso(ts: str):
        if not ts:
            return None
        s = ts.replace("Z", "")
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return dt.datetime.strptime(s, fmt)
            except Exception:
                pass
        try:
            return dt.datetime.fromisoformat(s)
        except Exception:
            return None

    trimmed = []
    for h in hist:
        t = _parse_iso(h.get("ts") or "")
        if not t or t >= cut:
            trimmed.append(h)
    hist = trimmed[-max_hist:]

    # Always carry bounded history + human Date
    new_entry["password_history"] = hist
    new_entry["Date"] = dt.datetime.now().strftime("%Y-%m-%d")

    # Persist
    ok = False
    try:
        update_vault_entry(username, key, index, new_entry)
        w._on_any_entry_changed()
        ok = True
    except TypeError:
        update_vault_entry(username, key, index, new_entry)
        w._on_any_entry_changed()
        ok = True

    # Refresh UI (best-effort) — keep exactly as-is, but call through w
    try:
        from security.baseline_signer import update_baseline
        update_baseline(username=username, verify_after=False, who="Watchtower -> entry update")
    except Exception:
        pass
    try:
        w.load_vault_table()
    except Exception:
        pass
    try:
        
        watchtower_rescan(w)
    except Exception:
        pass

    return ok


def find_entry_index_by_id(w, entry_id: str) -> int:
    """
    Locate a vault entry index for Watchtower Fix/Ignore.

    IMPORTANT:
    - Watchtower scans the *decrypted vault on disk* (not the visible table).
    - We therefore resolve ids against `load_vault(...)` only.
    - Preferred id is "idx:<n>" (index in decrypted vault list).
    """
    want = str(entry_id or "").strip()

    # Fast-path: idx:<n>
    if want.startswith("idx:"):
        try:
            i = int(want.split(":", 1)[1])
            return i if i >= 0 else -1
        except Exception:
            return -1

    # Load decrypted vault
    try:
        username = w.currentUsername.text()
    except Exception:
        username = ""
    try:
        key = getattr(w, "core_session_handle", None)
    except Exception:
        key = None

    try:
        all_entries = load_vault(username, key) or []
    except Exception:
        all_entries = []

    # Direct id fields
    for i, e in enumerate(all_entries):
        rid = str(e.get("id") or e.get("_id") or e.get("row_id") or "")
        if rid and rid == want:
            return i

    # Fallback: stable id (sha1) derived from non-secret key fields
    try:
        from features.watchtower.watchtower_scan import stable_id_for_entry
    except Exception:
        stable_id_for_entry = None

    if stable_id_for_entry is not None:
        for i, e in enumerate(all_entries):
            try:
                if stable_id_for_entry(e) == want:
                    return i
            except Exception:
                continue

    return -1


def watchtower_rescan(w):
    """Rescan the Watchtower panel (safe if not present)."""
    try:
        if hasattr(w, "watchtower") and w.watchtower:
            w.watchtower.start_scan()
    except Exception:
        pass

