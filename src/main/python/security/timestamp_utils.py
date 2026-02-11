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

from datetime import datetime, timezone
from typing import Optional


def now_utc_iso() -> str:
    """
    Current UTC time as an ISO8601 string without microseconds, e.g.
    '2025-12-01T21:43:00Z'
    """
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def format_timestamp_for_display(ts: Optional[str]) -> str:
    """
    Best-effort friendly formatter for timestamps stored in user_db / identity.
    Accepts:
      - ISO8601 strings (with/without 'Z')
      - Anything else → returned as-is.

    Returns short 'YYYY-MM-DD HH:MM' in *local* time where possible.
    """
    if not ts:
        return "(unknown)"

    s = str(ts).strip()
    if not s:
        return "(unknown)"

    # Try a few common formats used in the app
    candidates = [s]
    if s.endswith("Z"):
        candidates.append(s[:-1])

    dt_obj = None
    for cand in candidates:
        try:
            dt_obj = datetime.fromisoformat(cand)
            break
        except Exception:
            continue

    if not dt_obj:
        # If we can't parse it, just show the raw string
        return s

    # If the datetime is naive, treat as UTC and convert to local
    if not dt_obj.tzinfo:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)

    local = dt_obj.astimezone()  # convert to local time
    return local.strftime("%Y-%m-%d %H:%M")
