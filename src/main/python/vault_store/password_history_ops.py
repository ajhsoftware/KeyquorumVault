"""
Keyquorum Vault
Copyright (C) 2025-2026 Anthony Hatton (AJH Software)

Password history save helpers.

Why this file exists:
- Password history is part of normal vault edit/save flows.
- The secure one-step restore cache still lives in soft_delete_ops.py.
- Watchtower should only scan/report; it should not own the core save path.

STRICT SECURITY:
- DLL session handle only.
- No Python crypto fallback.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from datetime import timedelta

from vault_store.vault_store import load_vault, update_vault_entry
from auth.login.login_handler import get_user_setting


def hash_pw(pw: str) -> str:
    try:
        return hashlib.sha256((pw or "").encode("utf-8")).hexdigest()
    except Exception:
        return ""


def persist_entry_with_history(w, username: str, session_handle: int, index: int, new_entry: dict, *, max_hist: int = 10) -> bool:
    """
    Edit-save with password history.

    If password changed:
    - push OLD hash (+ timestamp) into password_history
    - stamp pw_changed_at for the new password
    - store the OLD plaintext as the single 'last password' secure restore cache

    STRICT DLL-ONLY:
    - session_handle must be the active native DLL session handle (int)
    - no Python crypto fallback is allowed here
    """

    def _pw_val(d: dict) -> str:
        for k in ("Password", "password", "pwd", "pass", "secret", "Secret"):
            v = d.get(k)
            if isinstance(v, str) and v != "":
                return v
        return ""

    _sha = lambda s: hashlib.sha256((s or "").encode("utf-8")).hexdigest()

    if not isinstance(session_handle, int) or session_handle <= 0:
        raise RuntimeError("persist_entry_with_history requires a native DLL session handle (int)")

    # Load stored entry to compare
    try:
        entries = load_vault(username, session_handle) or []
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

    # If changed -> append OLD hash; stamp new pw_changed_at; store last plaintext
    if new_h and new_h != old_h:
        try:
            if bool(get_user_setting(username, "secure_restore_cache", True)) and old_pw:
                entry_id = str(prev.get("id") or prev.get("_id") or prev.get("row_id") or index)
                from vault_store.soft_delete_ops import _pwlast_put as _pwlast_put_module
                _pwlast_put_module(username, session_handle, entry_id, old_pw)
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
        update_vault_entry(username, session_handle, index, new_entry)
        w._on_any_entry_changed()
        ok = True
    except TypeError:
        update_vault_entry(username, session_handle, index, new_entry)
        w._on_any_entry_changed()
        ok = True

    # Refresh UI / baseline / watchtower (best effort)
    try:
        from security.baseline_signer import update_baseline
        update_baseline(username=username, verify_after=False, who="Password history -> entry update")
    except Exception:
        pass
    try:
        w.load_vault_table()
    except Exception:
        pass
    return ok
