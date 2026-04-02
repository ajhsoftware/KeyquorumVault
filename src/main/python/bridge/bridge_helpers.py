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

# -----------------------------------
# Standalone helpers to build autofill entries
# -----------------------------------

from __future__ import annotations
from typing import Callable, Optional, Dict
from urllib.parse import urlparse
from bridge.bridge_values import *
import re
import secrets
from pathlib import Path
from qtpy.QtCore import Qt
from qtpy.QtWidgets import QTableWidget, QTableWidgetItem
import logging
log = logging.getLogger("keyquorum")
from bridge.bridge_ops import *

# NOTE: Your table headers sometimes include emojis or extra words (e.g. '🔒 Password').
# We normalise headers so column matching stays reliable across UI tweaks.
_HEADER_CLEAN_RE = re.compile(r"[^a-z0-9]+")

def _norm_header(s: str) -> str:
    s = (s or "").strip().lower()
    s = _HEADER_CLEAN_RE.sub(" ", s)
    return " ".join(s.split())

def _headers_lower(table: QTableWidget) -> list[str]:
    out: list[str] = []
    try:
        for c in range(table.columnCount()):
            it = table.horizontalHeaderItem(c)
            t = _norm_header(it.text() if it else "")
            out.append(t)
    except Exception:
        pass
    return out

def _find_col(table: QTableWidget, wanted: set[str]) -> int:
    """Return column index matching any of the given labels (normalised), or -1 if not found."""
    headers = _headers_lower(table)
    wanted_norm = {_norm_header(x) for x in wanted if _norm_header(x)}
    for idx, t in enumerate(headers):
        if not t or t in {"👁", "password expired"}:
            continue

        # Exact match, startswith, or contains (handles: "password (hidden)", "🔒 password", etc.)
        for nl in wanted_norm:
            if t == nl or t.startswith(nl) or (nl in t):
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

# -----------------------------------
# Extractors
# -----------------------------------

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
        # ---- 1) Try Username column ----
        if not hasattr(table, "_kq_user_col"):
            table._kq_user_col = _find_col(table, USER_LABELS)

        user_col = getattr(table, "_kq_user_col", -1)
        if user_col >= 0:
            it = table.item(row, user_col)
            val = _get_text(it).strip()
            if val:
                return val

        # ---- 2) Fallback to Email column ----
        if not hasattr(table, "_kq_email_col"):
            table._kq_email_col = _find_col(table, {"email", "e-mail", "email address"})


        email_col = getattr(table, "_kq_email_col", -1)
        if email_col >= 0:
            it = table.item(row, email_col)
            val = _get_text(it).strip()
            if val:
                return val

    except Exception:
        pass

    return ""

def extract_password(table: QTableWidget, row: int) -> str:
    """Return decrypted password from SECRET_ROLE (fallback to visible text if not bullets)."""
    try:
        if not hasattr(table, "_kq_pass_col"):
            table._kq_pass_col = _find_col(table, PASS_LABELS)
        col = getattr(table, "_kq_pass_col", -1)

        if col < 0:
            # No specific password column. Scan the row for a SECRET_ROLE value,
            # but avoid "email/username" columns so we don't accidentally fill the
            # password box with the email address when headers don't match.
            headers = _headers_lower(table)
            for c in range(table.columnCount()):
                h = headers[c] if c < len(headers) else ""
                if any(k in h for k in ("email", "user", "username", "login", "account", "url", "website", "site", "totp", "otp", "2fa")):
                    continue
                it = table.item(row, c)
                v = _get_role_str(it, SECRET_ROLE)
                if v:
                    return v
            # final fallback: return first SECRET_ROLE we can find
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

# -----------------------------------
# Domain matching
# -----------------------------------

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

# -----------------------------------
# Public entry builder
# -----------------------------------

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


# ========================
# Token persistence
# ========================

def check_bridge_token_headless(self, presented: str) -> bool:
    # compare with store as the current token / auth mode
    expected = (self.bridgeToken.text() or "").strip()
    mode = (self.authMode.currentText() or "Authorization").lower()
    if mode in ("none", "disabled"):
        return True
    return bool(presented) and presented == expected


# For simplicity, we store a single token per user in a file. 
# The token is a random string that the app generates and shares with the extension for authentication. The file is stored in a user-specific directory determined by the app's paths module. This approach avoids complex databases and allows easy reset by deleting the file.
def _bridge_token_path_for(username: str) -> Path:
    from app.paths import bridge_token_dir
    u = (username or "").strip()
    if not u:
        raise ValueError("username is required for bridge token persistence")
    return Path(bridge_token_dir(u))


# Load the token for this user, or return empty string if not found/invalid.
def load_bridge_token(username: str) -> str:
    try:
        tok = _bridge_token_path_for(username).read_text(encoding="utf-8").strip()
        return tok if len(tok) >= 24 else ""
    except Exception:
        return ""


# Save a token for this user (overwrites existing). If token is empty, it effectively clears it.
def save_bridge_token(username: str, token: str) -> None:
    try:
        p = _bridge_token_path_for(username)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text((token or "").strip(), encoding="utf-8")
        tmp.replace(p)
    except Exception:
        pass


# For security, we want to allow token reset (e.g. if a user suspects compromise or just wants to force re-pairing).
# This is a simple helper to clear the token; the app can call ensure_bridge_token() again to create a new one.
def clear_bridge_token(username: str) -> None:
    save_bridge_token(username, "")


# Get or create a token for this user. If `new` is True, always create a new token and persist it; otherwise, return existing or create if missing.
def ensure_bridge_token(username: str, *, new: bool = False) -> str:
    """Return a token for this user (create & persist if missing)."""
    if new:
        tok = secrets.token_urlsafe(32)
        save_bridge_token(username, tok)
        return tok

    tok = load_bridge_token(username)
    if tok:
        return tok

    tok = secrets.token_urlsafe(32)
    save_bridge_token(username, tok)
    return tok


