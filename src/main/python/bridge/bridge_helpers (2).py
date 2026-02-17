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

# -----------------------------------------------------------------------------
# Standalone helpers to build autofill entries from your QTableWidget
# -----------------------------------------------------------------------------

from __future__ import annotations
from typing import Callable, Optional, Dict
from urllib.parse import urlparse

from qtpy.QtCore import Qt
from qtpy.QtWidgets import QTableWidget, QTableWidgetItem

# ---- Roles (aligned with how load_vault_table stores sensitive values) ----
ENTRY_ID_ROLE = int(Qt.ItemDataRole.UserRole) + 101
HAS_TOTP_ROLE = int(Qt.ItemDataRole.UserRole) + 102
SECRET_ROLE   = int(Qt.ItemDataRole.UserRole)          # clear sensitive value is stored here
URL_ROLE      = int(Qt.ItemDataRole.UserRole) + 104    # optional canonical URL (if you ever set it)

# ---- Header label synonyms (lowercased) ----
URL_LABELS   = {"website", "url", "site", "login url", "web site"}
USER_LABELS  = {"email", "username", "user", "login", "account", "email address"}
PASS_LABELS  = {"password", "passcode", "pwd", "secret"}
TOTP_LABELS  = {"2fa", "totp", "otp", "two-factor"}
TITLE_LABELS = {"title", "name", "label"}

BULLETS = set("•●▪▮∙∗*◦ ")

WEBFILL_COL = {
    "HONORIFIC": "Name Title",
    "FORENAME": "First name",
    "MIDDLENAME": "Middle name",
    "SURNAME": "Surname",
    "EMAIL": "Email",
    "PHONE": "Phone number",
    "ADDR1": "address line 1",
    "ADDR2": "address line 2",
    "CITY": "City / Town",
    "REGION": "State / Province / Region",
    "POSTAL": "Postal code / ZIP",
    "COUNTRY": "Country",
}

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def _headers_lower(table: QTableWidget) -> list[str]:
    out: list[str] = []
    try:
        for c in range(table.columnCount()):
            it = table.horizontalHeaderItem(c)
            t = (it.text() if it else "").strip().lower()
            out.append(t)
    except Exception:
        pass
    return out

def _find_col(table: QTableWidget, wanted: set[str]) -> int:
    """Return column index matching any of the given lowercased labels, or -1 if not found."""
    headers = _headers_lower(table)
    for idx, t in enumerate(headers):
        if not t or t == "👁" or t == "password expired":
            continue
        if t in wanted or any(t.startswith(lbl) for lbl in wanted):
            return idx
    return -1

def _not_bullets(s: str) -> bool:
    return bool(s) and not set(s) <= BULLETS

def _get_text(item: Optional[QTableWidgetItem]) -> str:
    return (item.text() if item else "") or ""

def _get_role_str(item: Optional[QTableWidgetItem], role: int) -> str:
    if not item:
        return ""
    try:
        v = item.data(role)
        if isinstance(v, str) and v.strip():
            return v
    except Exception:
        pass
    return ""

# -----------------------------------------------------------------------------
# Extractors
# -----------------------------------------------------------------------------

def extract_url(table: QTableWidget, row: int) -> str:
    """Return URL/Website for the row; prefers URL_ROLE if present."""
    try:
        if not hasattr(table, "_kq_url_col"):
            table._kq_url_col = _find_col(table, URL_LABELS)
        col = getattr(table, "_kq_url_col", -1)
        if col < 0:
            return ""
        it = table.item(row, col)
        if not it:
            return ""
        v = _get_role_str(it, URL_ROLE)
        if v:
            return v
        txt = _get_text(it).strip()
        if txt.startswith("www."):
            return "http://" + txt
        return txt
    except Exception:
        return ""

def extract_username(table: QTableWidget, row: int) -> str:
    try:
        if not hasattr(table, "_kq_user_col"):
            table._kq_user_col = _find_col(table, USER_LABELS)
        col = getattr(table, "_kq_user_col", -1)
        if col < 0:
            return ""
        it = table.item(row, col)
        return _get_text(it)
    except Exception:
        return ""

def extract_password(table: QTableWidget, row: int) -> str:
    """Return decrypted password from SECRET_ROLE (fallback to visible text if not bullets)."""
    try:
        if not hasattr(table, "_kq_pass_col"):
            table._kq_pass_col = _find_col(table, PASS_LABELS)
        col = getattr(table, "_kq_pass_col", -1)

        if col < 0:
            # no specific password column—scan the row for a secret in UserRole
            for c in range(table.columnCount()):
                it = table.item(row, c)
                v = _get_role_str(it, SECRET_ROLE)
                if v:
                    return v
            return ""

        it = table.item(row, col)
        if it:
            v = _get_role_str(it, SECRET_ROLE)
            if v:
                return v
            txt = _get_text(it).strip()
            if _not_bullets(txt):
                return txt
    except Exception:
        pass
    return ""

def extract_title(table: QTableWidget, row: int) -> str:
    """Return a human-friendly title if your table has one; else fallback to URL host."""
    try:
        if not hasattr(table, "_kq_title_col"):
            table._kq_title_col = _find_col(table, TITLE_LABELS)
        col = getattr(table, "_kq_title_col", -1)
        if col >= 0:
            it = table.item(row, col)
            t = _get_text(it).strip()
            if t:
                return t
    except Exception:
        pass
    # fallback to url host
    u = extract_url(table, row)
    try:
        p = urlparse(u if "://" in u else "https://" + u)
        host = (p.netloc or p.path).split(":")[0]
        return host or u or "login"
    except Exception:
        return u or "login"

def extract_entry_id(table: QTableWidget, row: int) -> str:
    try:
        it = table.item(row, 0)
        v = _get_role_str(it, ENTRY_ID_ROLE)
        if v:
            return v
    except Exception:
        pass
    return f"row-{row}"

def extract_has_totp(table: QTableWidget, row: int) -> bool:
    try:
        if not hasattr(table, "_kq_totp_col"):
            table._kq_totp_col = _find_col(table, TOTP_LABELS)
        col = getattr(table, "_kq_totp_col", -1)
        if col >= 0:
            it = table.item(row, col)
            txt = _get_text(it).strip().lower()
            if txt in {"true","yes","1","y"}:
                return True
            if txt in {"false","no","0","n"}:
                return False
        # role hint on first cell
        it0 = table.item(row, 0)
        if it0 is not None:
            mark = it0.data(HAS_TOTP_ROLE)
            if mark is not None:
                return bool(mark)
    except Exception:
        pass
    return False

# -----------------------------------------------------------------------------
# Domain matching
# -----------------------------------------------------------------------------

def _host(s: str) -> str:
    p = urlparse(s if "://" in s else f"https://{s}")
    net = (p.netloc or p.path).lower().split(":")[0]
    return net.removeprefix("www.")

def match_domain(url: str, domain: str) -> bool:
    """
    True if `url` belongs to `domain` (origin http://host[:port], bare host, or eTLD+1).
    Local/IP compare by host; domains match by exact host or subdomain-of-host.
    """
    try:
        if not url or not domain:
            return False
        a = _host(url)
        b = _host(domain)
        if a in {"localhost","127.0.0.1","::1"} or b in {"localhost","127.0.0.1","::1"}:
            return a == b
        return a == b or a.endswith("." + b)
    except Exception:
        return False

# -----------------------------------------------------------------------------
# Public entry builder
# -----------------------------------------------------------------------------

def entries_for_origin(table: QTableWidget,
                       origin: str,
                       model_getter: Optional[Callable[[int], Dict]] = None,
                       limit: int = 10,
                       logger=None) -> list[Dict]:
    """
    Scan the table and return [{id,title,username,password,has_totp,url}] for rows
    whose Website/URL matches `origin` (host/port safe). If you have an in-memory
    model, pass model_getter(row)->dict to prefer that data.
    """
    out: list[Dict] = []
    try:
        rows = table.rowCount() if table else 0
        if logger: logger.debug("[BRIDGE] scanning %s rows for origin=%s", rows, origin)
        for r in range(rows):
            # allow in-memory override
            if callable(model_getter):
                try:
                    e = model_getter(r) or {}
                except Exception:
                    e = {}
            else:
                e = {}

            url = e.get("url") or e.get("website") or extract_url(table, r)
            if not match_domain(url, origin):
                continue

            username = e.get("username") or e.get("email") or extract_username(table, r)
            password = e.get("password") or extract_password(table, r)
            title    = e.get("title") or extract_title(table, r)
            has_totp = bool(e.get("has_totp")) if "has_totp" in e else extract_has_totp(table, r)
            entry_id = e.get("id") or extract_entry_id(table, r)

            out.append({
                "id": entry_id,
                "title": title or "",
                "username": username or "",
                "password": password or "",
                "has_totp": bool(has_totp),
                "url": url or ""
            })

            if len(out) >= max(1, int(limit)):
                break
        if logger: logger.debug("[BRIDGE] found %s entries", len(out))
    except Exception:
        # never raise into the HTTP handler
        if logger:
            try: logger.exception("[BRIDGE] entries_for_origin failed")
            except Exception: pass
    return out
