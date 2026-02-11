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
Watchtower per-user settings wrappers.
Moved from main.py (mechanical) to shrink main without changing behaviour.
"""

from typing import Optional

from auth.login.login_handler import get_user_setting, set_user_setting


def wt_active_username(w) -> Optional[str]:
    try:
        u = (w.currentUsername.text() or "").strip()
        return u or None
    except Exception:
        return None


def wt_get_rules(w) -> dict:
    u = wt_active_username(w)
    if not u:
        return {}
    try:
        val = get_user_setting(u, "watchtower_rules", {}) or {}
        return val if isinstance(val, dict) else {}
    except Exception:
        return {}


def wt_set_rules(w, rules: dict):
    u = wt_active_username(w)
    if not u:
        return
    try:
        set_user_setting(u, "watchtower_rules", dict(rules or {}))
    except Exception:
        pass


def wt_get_ignored(w) -> list:
    u = wt_active_username(w)
    if not u:
        return []
    try:
        val = get_user_setting(u, "ignored_watchtower", []) or []
        return val if isinstance(val, list) else []
    except Exception:
        return []


def wt_set_ignored(w, lst: list):
    u = wt_active_username(w)
    if not u:
        return
    try:
        set_user_setting(u, "ignored_watchtower", list(lst or []))
    except Exception:
        pass


def wt_get_global_flags(w) -> dict:
    """Currently: whether this account has 2FA enabled."""
    u = wt_active_username(w)
    has_2fa = True
    if not u:
        return {"account_has_2fa": True}
    try:
        has_2fa = bool(get_user_setting(u, "has_totp", False))
    except Exception:
        has_2fa = True
    return {"account_has_2fa": has_2fa}
