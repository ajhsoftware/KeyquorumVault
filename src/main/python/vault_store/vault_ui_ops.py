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
"""Vault table rendering, CRUD actions, and vault UI helpers extracted from the main window.

This file is part of the Keyquorum Vault codebase.
"""

# This module contains methods extracted from main.py to reduce file size.
# Intentionally "inherit" main module globals so the moved code can run unchanged.
import sys as _sys
from http.server import BaseHTTPRequestHandler
import base64, json, threading, traceback, os, subprocess, secrets
from urllib.parse import urlparse, quote
from pathlib import Path
from app.paths import config_dir
from app.platform_utils import open_path
from auth.login.login_handler import (get_user_setting, _canonical_username_ci, set_user_setting, set_user_cloud, get_user_cloud)
from vault_store.vault_store import (
    add_vault_entry, load_vault, save_vault, import_full_backup,
    delete_vault_entry,)
from security.secure_audit import log_event_encrypted
from vault_store.add_entry_dialog import AddEntryDialog
import datetime as dt
import re as _re
from features.watchtower.watchtower_helpers import persist_entry_with_history
from security.baseline_signer import update_baseline
from datetime import timedelta
from shutil import copy2
import time as _t
from qtpy import QtWidgets
from app.paths import vault_file
# --- QtCore Pysider Backend ---
from qtpy.QtCore import QCoreApplication, QDate, QTime, QDateTime
from qtpy.QtGui import (QColor, QBrush, QDesktopServices,) 
from qtpy.QtWidgets import (
    QApplication, QListView, QDialog, QLabel, QLineEdit, QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QMessageBox, QDialogButtonBox, QProgressDialog, QFileDialog, QVBoxLayout, QTextEdit,
    QFrame, QHeaderView, QMenu, QInputDialog, QHBoxLayout, QCheckBox, QToolButton, QSizePolicy,
    QSpinBox, QDateEdit, QPlainTextEdit, QDateTimeEdit, QTimeEdit, QDoubleSpinBox,)    
from qtpy.QtCore import Qt, QUrl
from qtpy.QtGui import QDesktopServices
from ui.restore_options_dialog import RestoreOptionsDialog
# --- log ---
import logging
log = logging.getLogger("keyquorum")


# ---------------------------------------------------------------------------
# UI-string handling helpers
# ---------------------------------------------------------------------------
def _kq_strip_ws(s: str) -> str:
    """Strip leading/trailing whitespace with a single pass over indices.

    This still returns a Python `str` (Qt/PySide gives us str), but avoids
    chaining `.strip().lower()` etc. in hot paths which can create extra
    intermediate strings.
    """
    if not s:
        return ""
    i = 0
    j = len(s)
    while i < j and s[i].isspace():
        i += 1
    while j > i and s[j - 1].isspace():
        j -= 1
    return s[i:j]


def _kq_norm_header(s: str) -> str:
    """Normalise header/candidate text for comparisons: strip + lowercase.

    Implemented to avoid `.strip().lower()` chaining (two allocations) where possible.
    """
    s = _kq_strip_ws(s)
    if not s:
        return ""
    # Fast-path ASCII lowercasing without creating multiple intermediate strings.
    out_chars = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:  # A-Z
            out_chars.append(chr(o + 32))
        else:
            # For non-ASCII, fall back to per-char lower()
            out_chars.append(ch.lower())
    return "".join(out_chars)
import app.kq_logging as kql


# ==============================
# --- Bridge / Allowed Origins (unified paths) ---
# ==============================

# Default allowed origins (e.g., browser extensions)
_DEFAULT_ORIGINS = {
    # Store ID
    "chrome-extension://jcblpckopkkhokdjdojlblknikfahbgb",
    # Dev ID (found by loading dev extension locally)
    "chrome-extension://lciebglepcghjjlaldlejfiehibemgef",
}

# Use unified config_dir() instead of CONFIG_DIR
ORIGINS_PATH = Path(config_dir()) / "allowed_origins.json"

_origin_cache = {"set": set(_DEFAULT_ORIGINS), "mtime": 0.0}
_origin_lock = threading.Lock()

def _read_file() -> tuple[set[str], float]:
    """Read the JSON file and return (set, mtime). Returns (empty, 0.0) on error/missing."""
    if not ORIGINS_PATH.exists():
        return set(), 0.0
    try:
        mtime = ORIGINS_PATH.stat().st_mtime
        data = json.loads(ORIGINS_PATH.read_text(encoding="utf-8"))
        if isinstance(data, list):
            cleaned = {str(x).strip() for x in data if str(x).strip()}
            return cleaned, mtime
    except Exception:
        pass
    return set(), 0.0

def refresh_allowed_origins(force: bool = False) -> set[str]:
    """Refresh cache from disk (merged with defaults)."""
    with _origin_lock:
        file_set, mtime = _read_file()
        if force or mtime != _origin_cache["mtime"] or not _origin_cache["set"]:
            merged = set(_DEFAULT_ORIGINS) | file_set
            _origin_cache["set"] = merged
            _origin_cache["mtime"] = mtime
        return set(_origin_cache["set"])

def load_allowed_origins() -> set[str]:
    """Public loader: just refresh and return."""
    return refresh_allowed_origins(force=False)

def save_allowed_origins(new_set: set[str]) -> None:
    """Persist a set to disk (without losing defaults), update cache, keep dirs safe."""
    normalized = {str(x).strip() for x in new_set if str(x).strip()}
    # Always preserve defaults when saving
    out = sorted(set(_DEFAULT_ORIGINS) | normalized)
    ORIGINS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ORIGINS_PATH.write_text(json.dumps(out, indent=2), encoding="utf-8")
    # Update cache immediately
    with _origin_lock:
        _origin_cache["set"] = set(out)
        try:
            _origin_cache["mtime"] = ORIGINS_PATH.stat().st_mtime
        except Exception:
            pass

def is_origin_allowed(origin: str) -> bool:
    """Check if a given origin string is allowed."""
    return str(origin).strip() in load_allowed_origins()

def add_allowed_origin(origin: str) -> set[str]:
    """Add a single origin and persist."""
    cur = load_allowed_origins()
    cur.add(str(origin).strip())
    save_allowed_origins(cur)
    return load_allowed_origins()

def remove_allowed_origin(origin: str) -> set[str]:
    """Remove a single origin and persist (defaults are retained automatically)."""
    cur = load_allowed_origins()
    cur.discard(str(origin).strip())
    save_allowed_origins(cur)
    return load_allowed_origins()


# ==============================
# --- Browser  Extensions  ---
# ==============================

# --- Local Server Set
appref = None  # set start_bridge_server
LOCAL_TEST_HOSTS = {"127.0.0.1", "localhost"}  # allow manual testing pages (Replace With Test Site GitHub)

# Global snapshot (optional). Recompute after any change if you rely on it.
ALLOWED_ORIGINS = refresh_allowed_origins(force=True)

# --- Allow Only
_ALLOW_METHODS = "GET, POST, OPTIONS"
_ALLOW_HEADERS = "Content-Type, Authorization, X-Auth-Token, X-KQ-Token"
# --- http/https (note: make option in setting to allow/block http sites)

try:
    from app.basic import is_dev
    if is_dev:
        ALLOW_LOCAL_HTTP  = True  # True in dev HTTP Mode
    else:
        ALLOW_LOCAL_HTTP = False
except Exception:
    ALLOW_LOCAL_HTTP = False


_MAIN = (
    _sys.modules.get("__main__")
    or _sys.modules.get("main")
    or _sys.modules.get("app.app_window")
    or _sys.modules.get("app_window")
)
if _MAIN is not None:
    globals().update(_MAIN.__dict__)

# Safety net: ensure Qt symbols exist even when __main__ differs (e.g., frozen builds)
try:
    from app.qt_imports import *  # noqa: F401,F403
except Exception:
    pass
def _tr(text: str) -> str:
    """Qt translation helper scoped to the Watchtower UI."""
    return QCoreApplication.translate("uiwatchtower", text)


def on_vault_diagButton_clicked(self, *args, **kwargs):
    """
    Self-checks:
      - token presence/format,
      - server object present,
      - TCP accept,
      - /v1/status HTTP,
    and shows a concise report + tips.
    """
    host = "127.0.0.1"
    port = int(getattr(self, "_bridge_port", 8742))
    httpd = getattr(self, "_bridge_httpd", None)
    token = getattr(self, "_bridge_token", "") or ""



    def _tok_ok(t: str) -> tuple[bool, str]:
        import re
        # Use self.tr() so these short reasons can be translated
        if not t:
            return False, self.tr("no token")
        if len(t) < 24:
            return False, self.tr("short token ({length})").format(length=len(t))
        if not re.fullmatch(r"[A-Za-z0-9_\-]+", t):
            return False, self.tr("invalid characters")
        return True, self.tr("looks good")

    lines: list[str] = []

    # Token
    ok_tok, why_tok = _tok_ok(token)
    state_tok = self.tr("OK") if ok_tok else self.tr("BAD")
    lines.append(
        self.tr("Token: {state} — {reason}").format(
            state=state_tok,
            reason=why_tok,
        )
    )

    # Server object
    state_bridge = self.tr("present") if httpd else self.tr("absent")
    lines.append(
        self.tr("Bridge object: {state}").format(state=state_bridge)
    )

    # TCP
    tcp_ok = self._tcp_ready(host, port)
    state_tcp = self.tr("reachable") if tcp_ok else self.tr("no listener")
    lines.append(
        self.tr("TCP {host}:{port}: {state}").format(
            host=host,
            port=port,
            state=state_tcp,
        )
    )

    # HTTP /v1/status
    http_ok, data, code = self._bridge_status_json(host, port)
    if http_ok:
        locked = None
        try:
            if isinstance(data, dict) and "locked" in data:
                locked = bool(data["locked"])
        except Exception:
            pass

        if locked is not None:
            # We keep true/false literal; you *could* localise these too if you want.
            locked_txt = "true" if locked else "false"
            extra = self.tr(", locked={state}").format(state=locked_txt)
        else:
            extra = ""

        lines.append(
            self.tr("GET /v1/status: HTTP {code}{extra}").format(
                code=code,
                extra=extra,
            )
        )
    else:
        lines.append(self.tr("GET /v1/status: failed"))

    # Advice
    advice: list[str] = []
    if not ok_tok:
        advice.append(
            self.tr(
                "Generate a new pairing token (Pair → Regenerate) and paste it into the extension."
            )
        )
    if httpd is None:
        advice.append(
            self.tr("Start the bridge (Pair button) after unlocking.")
        )
    if not tcp_ok:
        advice.append(
            self.tr(
                "Check antivirus/firewall or if another Keyquorum instance is holding the port."
            )
        )
    if http_ok and code not in (200, 401, 403):
        advice.append(
            self.tr(
                "Unexpected HTTP status — check logs for bridge handler errors."
            )
        )

    msg = "\n".join(lines)
    if advice:
        msg += "\n\n" + self.tr("Tips:") + "\n- " + "\n- ".join(advice)

    QMessageBox.information(
        self,
        self.tr("Bridge diagnostics"),
        msg,
    )


# 5) ---------- minimal HTTPS bridge with CORS ----------

# ---- Single, definitive bridge handler ----
class _BridgeHandler(BaseHTTPRequestHandler):

    # --- Passkeys bridge endpoints ----

    def _b64url_decode(self, s: str) -> bytes:
        s = (s or "").strip()
        s += "=" * (-len(s) % 4)                # proper padding
        return base64.urlsafe_b64decode(s)

    def _require_unlocked(self, app) -> bool:
        """
        Determine whether the vault is unlocked without triggering any UI.

        The bridge runs on a background thread and must not display message boxes.
        Instead, it inspects the provided ``app`` for an ``is_vault_unlocked()``
        method (modern API) or falls back to checking for a truthy ``userKey``
        attribute on the app instance.  If neither is available or an exception
        occurs the vault is considered locked.

        :param app: the application instance from the UI thread
        :return: True if the vault is unlocked, else False
        """
        try:
            if not app:
                return False
            # Preferred: call app.is_vault_unlocked() if available
            if hasattr(app, "is_vault_unlocked") and callable(app.is_vault_unlocked):
                return bool(app.is_vault_unlocked())
            # Fallback: older builds may store userKey on the app
            return bool(getattr(app, "userKey", None))
        except Exception:
            return False

    def _json_error(self, msg, code=400):
        return {"ok": False, "error": msg}, code

    def handle_passkeys_create(self, app, body):
        # was: chk, code = self._require_unlocked(app); if code != 200: return chk, code
        if not self._require_unlocked(app):
            return {"ok": False, "error": "vault_locked"}, 423

        # decode inputs (use _b64url_decode helpers)
        rp_id     = (body.get("rpId") or "").strip().lower()
        user_id_b = self._b64url_decode(body.get("userId", ""))
        challenge = self._b64url_decode(body.get("challenge", ""))
        alg       = int(body.get("alg", -8))
        rk        = bool(body.get("residentKey", True))
        uv        = str(body.get("userVerification", "preferred"))

        from features.passkeys.passkeys_store import create_credential
        cred = create_credential(
            rp_id=rp_id,
            user_id=user_id_b,
            alg=alg,
            resident_key=rk,
            require_uv=(uv == "required"),
            display_name=body.get("userDisplayName") or body.get("userName") or ""
        )
        try:
            self._run_on_ui(app, lambda: getattr(app, "passkeysPanel", None) and app.passkeysPanel.reload(), timeout=5.0)
        except Exception:
            pass

        return {"ok": True, "credential": cred}, 200

    def handle_passkeys_get(self, app, body):
        if not self._require_unlocked(app):
            return {"ok": False, "error": "vault_locked"}, 423

        rp_id     = (body.get("rpId") or "").strip().lower()
        challenge = self._b64url_decode(body.get("challenge", ""))
        allow_ids = body.get("allowCredentialIds") or []
        uv        = str(body.get("userVerification", "preferred"))

        from features.passkeys.passkeys_store import get_assertion
        assertion = get_assertion(
            rp_id=rp_id,
            challenge=challenge,
            allow_credential_ids=allow_ids,
            require_uv=(uv == "required")
        )
        return {"ok": True, "assertion": assertion}, 200

    def log_message(self, fmt, *args):  # quiet default spam
        try:
            pass
            #log.debug("HTTP %s - " + fmt, self.command, *args)
        except Exception:
            pass

    def handle_passkeys_list(self, app, body):
        if not self._require_unlocked(app):
            return {"ok": False, "error": "vault_locked"}, 423

        from features.passkeys.passkeys_store import list_entries

        items = []
        for e in list_entries():
            items.append({
                "kid": e.id,
                "rpId": e.rp_id,
                "displayName": e.display_name,
                "alg": e.alg,
                "rk": e.rk,
                "uv": e.uv,
                "created": e.created,
                "updated": e.updated,
                "signCount": e.sign_count,
            })

        return {"ok": True, "items": items}, 200

    def handle_passkeys_delete(self, app, body):
        if not self._require_unlocked(app):
            return {"ok": False, "error": "vault_locked"}, 423

        kid = (body or {}).get("kid")
        if not kid:
            return {"ok": False, "error": "missing_kid"}, 400

        from features.passkeys.passkeys_store import delete_by_id
        delete_by_id(kid)

        try:
            self._run_on_ui(
                app,
                lambda: getattr(app, "passkeysPanel", None) and app.passkeysPanel.reload(),
                timeout=5.0
            )
        except Exception:
            pass

        return {"ok": True, "deleted": True}, 200

    # --- https only lockdown
    def is_https_allowed(self, origin: str) -> bool:
        try:
            u = urlparse(origin or "")
        except Exception:
            return False
        if u.scheme == "https":
            return True
        if ALLOW_LOCAL_HTTP and u.scheme == "http" and (u.hostname in {"127.0.0.1", "localhost"}):
            return True
        return False

    # --- small helpers ---
    def _cors(self):
        origin = self.headers.get("Origin", "")
        self.send_header(
            "Access-Control-Allow-Origin",
            origin if (origin and self._origin_allowed(origin)) else "null"
        )
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", _ALLOW_METHODS)
        self.send_header("Access-Control-Allow-Headers", _ALLOW_HEADERS)
        self.send_header("Access-Control-Max-Age", "86400")

    def _safe_write(self, b: bytes):
        try:
            self.wfile.write(b)
            try: self.wfile.flush()
            except Exception: pass
        except (BrokenPipeError, ConnectionResetError, OSError):
            # client went away — nothing to do
            return


    def _collect_webfill_rows_ui(self, app, synonyms, max_rows=100):
        table = getattr(app, "vaultTable", None)
        if not table or table.rowCount() <= 0:
            return []
        # header texts (lowercased)
        headers = []
        try:
            hh = table.horizontalHeader()
            for i in range(table.columnCount()):
                item = table.horizontalHeaderItem(i)
                headers.append(_kq_norm_header(item.text() if item else ""))
        except Exception:
            for i in range(table.columnCount()):
                headers.append("")

        # map canonical -> column index using synonyms
        col_map = {}
        for canon, alts in (synonyms or {}).items():
            idx = -1
            for candidate in [canon, *alts]:
                c = _kq_norm_header(candidate or "")
                for i, h in enumerate(headers):
                    if h == c:
                        idx = i
                        break
                if idx >= 0:
                    break
            col_map[canon] = idx

        def get_text(r, c):
            try:
                item = table.item(r, c)
                return _kq_strip_ws(item.text() if item else "")
            except Exception:
                return ""

        out = []
        rows = min(table.rowCount(), max_rows)
        for r in range(rows):
            P = {
                "title":   get_text(r, col_map.get("honorific", -1)) or get_text(r, col_map.get("name title", -1)),
                "forename":get_text(r, col_map.get("forename", -1)) or get_text(r, col_map.get("first name", -1)),
                "middle":  get_text(r, col_map.get("middle", -1)) or get_text(r, col_map.get("middle name", -1)),
                "surname": get_text(r, col_map.get("surname", -1)) or get_text(r, col_map.get("last name", -1)),
                "email":   get_text(r, col_map.get("email", -1)) or get_text(r, col_map.get("email address", -1)),
                "phone":   get_text(r, col_map.get("phone", -1)) or get_text(r, col_map.get("phone number", -1)),
                "address1":get_text(r, col_map.get("address1", -1)) or get_text(r, col_map.get("address line 1", -1)),
                "address2":get_text(r, col_map.get("address2", -1)) or get_text(r, col_map.get("address line 2", -1)),
                "city":    get_text(r, col_map.get("city", -1)) or get_text(r, col_map.get("city / town", -1)),
                "region":  get_text(r, col_map.get("region", -1)) or get_text(r, col_map.get("state / province / region", -1)),
                "postal":  get_text(r, col_map.get("postal", -1)) or get_text(r, col_map.get("postal code / zip", -1)),
                "country": get_text(r, col_map.get("country", -1)),
            }
            # Make a friendly label for the list
            P["label"] = (P.get("forename","") + " " + P.get("surname","")).strip() or P.get("email") or "Profile"
            out.append(P)
        return out


    def _send_json(self, obj, code=200):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self._safe_write(payload)
       
    def _get_token(self) -> str:
        h = self.headers
        auth = (h.get("Authorization") or "").strip()
        if auth.startswith("Bearer "): return auth[7:].strip()
        if auth.startswith("Token "):  return auth[6:].strip()
        return h.get("X-Auth-Token") or h.get("X-KQ-Token") or ""

    def _send_plain(self, text: str, code=404):
        body = (text or "").encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self._safe_write(body)

    
    def _send_html(self, html: str, code=200):
        """
        Send a small HTML page to the client. This helper mirrors
        ``_send_plain`` and ``_send_json`` by adding the appropriate CORS
        headers and connection headers, but sets a text/html content type.
        ``html`` may be an empty string; it will be encoded as UTF-8.
        """
        body = (html or "").encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self._safe_write(body)

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            n = 0
        try:
            raw = self.rfile.read(n) if n > 0 else b"{}"
        except Exception:
            raw = b"{}"
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}

    # marshal work to UI thread via app._uibus
    def _run_on_ui(self, app, fn, timeout=10.0):
        evt = threading.Event()
        out = {"ok": False, "value": None}
        def wrapper():
            try:
                out["value"] = fn()
                out["ok"] = True
            except Exception:
                out["ok"] = False
            finally:
                evt.set()
        bus = getattr(app, "_uibus", None)
        if bus is None:
            # last-resort fallback (avoid crashes if called very early)
            wrapper()
            return out
        bus.call.emit(wrapper)
        evt.wait(timeout)
        return out

    # --- HTTP verbs ---
    def _json(self, obj, code=200):
        """Back-compat alias some routes call; just use _send_json."""
        self._send_json(obj, code)

    def do_OPTIONS(self):
        self.send_response(204)              # No Content
        self._cors()                         # adds Allow-Origin/Methods/Headers/Max-Age
        self.send_header("Connection", "close")  # optional
        self.end_headers()

    def do_GET(self):
        try:
            app  = type(self).appref() if (type(self).appref and callable(type(self).appref)) else None
            path = self.path.split("?", 1)[0]

            # ---------- PUBLIC ENDPOINTS ----------

            # /v1/status — always public; minimal info; never touches UI directly
            if path.startswith("/v1/status"):
                try:
                    locked = False
                    if app is not None:
                        if hasattr(app, "_vault_locked"):
                            locked = bool(getattr(app, "_vault_locked"))
                        else:
                            fn = getattr(app, "is_vault_unlocked", None)
                            if callable(fn):
                                locked = not bool(fn())

                    # token hint for pairing UX (does not grant access)
                    token_hdr = self._get_token()
                    app_tok   = (getattr(app, "_bridge_token", "") or getattr(app, "bridge_token", "")) if app else ""
                    status = _tr("ok") if (app_tok and token_hdr and token_hdr == app_tok) else _tr("not match")

                    self._send_json({"locked": bool(locked), "status": status}, 200)
                except Exception as e:
                    log.exception("status handler crashed: %s", e)
                    self._send_json({"locked": True, "status": "error"}, 200)
                return

            # /v1/test -> /test (back-compat)
            if path.startswith("/v1/test"):
                self.send_response(302)
                self._cors()
                self.send_header("Location", "/test")
                self.end_headers()
                return

            # Built-in HTML test pages (public)
            if path.startswith("/test"):
                def _page(title: str, body_html: str) -> str:
                    return f"""<!doctype html>
    <html><head><meta charset='utf-8'><title>{title}</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <style>
    body {{ font-family: system-ui, sans-serif; margin: 24px; line-height: 1.45; }}
    form {{ max-width: 640px; padding: 16px; border: 1px solid #ddd; border-radius: 8px; }}
    label {{ display:block; margin-top: 10px; font-weight:600; }}
    input, select, textarea {{ width: 100%; padding: 8px; margin-top: 6px; }}
    small {{ color:#666 }}
    </style></head><body>
    <h2>{title}</h2>
    {body_html}
    <p><small>Keyquorum Bridge Test • <a href='/test'>Index</a></small></p>
    </body></html>"""

                if path in ("/test", "/test/"):
                    body = """<ul>
    <li><a href='/test/login'>Login form</a></li>
    <li><a href='/test/webfill'>Address / contact form</a></li>
    <li><a href='/test/card'>Credit card form</a></li>
    <li><a href='/v1/status'>/v1/status (JSON)</a></li>
    <li><a href='/v1/webfill'>/v1/webfill (JSON; token required)</a></li>
    <li><a href='/v1/card'>/v1/card (JSON; token required)</a></li>
    <li><a href='/v1/selftest'>/v1/selftest (JSON; token required)</a></li>
    </ul>"""
                    self._send_html(_page("Bridge Test Index", body), 200)
                    return

                if path.startswith("/test/login"):
                    body = """<form>
    <label for='email'>Email</label>
    <input id='email' name='email' type='email' placeholder='you@example.com' autocomplete='username'>
    <label for='password'>Password</label>
    <input id='password' name='password' type='password' placeholder='••••••••' autocomplete='current-password'>
    <button type='submit' style='margin-top:12px'>Sign in</button>
    <div style='color:#666;font-size:12px;margin-top:6px'>Fields fill only when empty. Clear to re-trigger.</div>
    </form>"""
                    self._send_html(_page("Login form", body), 200)
                    return

                if path.startswith("/test/webfill"):
                    body = """<form>
    <label for='forename'>Forename</label>
    <input id='forename' name='forename' placeholder='Alex' autocomplete='given-name'>
    <label for='surname'>Surname</label>
    <input id='surname' name='surname' placeholder='Smith' autocomplete='family-name'>
    <label for='email'>Email address</label>
    <input id='email' name='email' type='email' placeholder='alex@example.com' autocomplete='email'>
    <label for='phone'>Phone number</label>
    <input id='phone' name='phone' type='tel' placeholder='+44 7…' autocomplete='tel'>
    <label for='address1'>Address line 1</label>
    <input id='address1' name='address1' autocomplete='address-line1' placeholder='10 Down Street'>
    <label for='address2'>Address line 2</label>
    <input id='address2' name='address2' autocomplete='address-line2' placeholder='Flat 2B'>
    <label for='city'>City / Town</label>
    <input id='city' name='city' autocomplete='address-level2' placeholder='London'>
    <label for='region'>County / State / Region</label>
    <input id='region' name='region' autocomplete='address-level1' placeholder='Greater London'>
    <label for='postal'>Postal code / ZIP</label>
    <input id='postal' name='postal' autocomplete='postal-code' placeholder='SW1A 2AA'>
    <label for='country'>Country</label>
    <input id='country' name='country' autocomplete='country-name' placeholder='United Kingdom'>
    <button type='submit' style='margin-top:12px'>Submit</button>
    </form>"""
                    self._send_html(_page("Address / contact form", body), 200)
                    return

                if path.startswith("/test/card"):
                    body = """<form>
    <label for='cc-name'>Name on card</label>
    <input id='cc-name' name='cc-name' placeholder='Alex Smith' autocomplete='cc-name'>
    <label for='cc-number'>Card number</label>
    <input id='cc-number' name='cc-number' inputmode='numeric' placeholder='4111 1111 1111 1111' autocomplete='cc-number'>
    <label for='cc-exp'>Expiry (MM/YY)</label>
    <input id='cc-exp' name='cc-exp' placeholder='08/27' autocomplete='cc-exp'>
    <label for='cc-cvc'>CVC</label>
    <input id='cc-cvc' name='cc-cvc' inputmode='numeric' placeholder='123' autocomplete='cc-csc'>
    <button type='submit' style='margin-top:12px'>Pay now</button>
    </form>"""
                    self._send_html(_page("Credit card form", body), 200)
                    return

                # Unknown /test path
                self._send_plain("Not found", 404)
                return

            # ---------- TOKEN-PROTECTED ENDPOINTS ----------

            # 1) CORS allow-list (blocks other extensions/web pages in the browser)
            origin = self.headers.get("Origin", "")
            if origin and not self._origin_allowed(origin):
                self._send_json({"error": "forbidden"}, 403)
                return

            # 2) Token check (header-only for GET)
            token_hdr = self._get_token()
            app_tok   = (getattr(app, "_bridge_token", "") or getattr(app, "bridge_token", "")) if app else ""
            if not app_tok or token_hdr != app_tok:
                self._send_json({"error": "unauthorized"}, 401)
                return

            # /v1/webfill — profiles + synonyms (if unlocked)
            if path.startswith("/v1/webfill"):
                synonyms, profiles, locked = {}, [], True
                if app:
                    try:
                        synonyms = app.webfill_synonyms()
                    except Exception:
                        synonyms = {}
                    try:
                        locked = not app.is_vault_unlocked()
                    except Exception:
                        locked = True
                    if not locked:
                        try:
                            res = self._run_on_ui(app, lambda: self._collect_webfill_rows_ui(app, synonyms), timeout=10.0)
                            profiles = res.get("value") or []
                        except Exception:
                            profiles = []
                self._send_json({"locked": bool(locked), "profiles": profiles, "synonyms": synonyms}, 200)
                return

            # /v1/card or /v1/cards — cards + synonyms (if unlocked)
            if path.startswith("/v1/card"):
                synonyms, cards, locked = {}, [], True
                if app:
                    try:
                        synonyms = app.card_synonyms()
                    except Exception:
                        synonyms = {}
                    try:
                        locked = not app.is_vault_unlocked()
                    except Exception:
                        locked = True
                    if not locked:
                        try:
                            res = self._run_on_ui(app, lambda: app.get_credit_cards(), timeout=10.0)
                            cards = res.get("value") or []
                        except Exception:
                            cards = []
                self._send_json({"locked": bool(locked), "cards": cards, "synonyms": synonyms}, 200)
                return

            # /v1/selftest — small diagnostics (no secrets)
            if path.startswith("/v1/selftest"):
                info = {
                    "app_ok": bool(app),
                    "locked": True,
                    "webfill_synonyms": {},
                    "card_synonyms": {},
                    "card_count": None,
                }
                try:
                    if app:
                        try:
                            info["locked"] = not app.is_vault_unlocked()
                        except Exception:
                            info["locked"] = True
                        try:
                            info["webfill_synonyms"] = app.webfill_synonyms()
                        except Exception:
                            pass
                        try:
                            info["card_synonyms"] = app.card_synonyms()
                        except Exception:
                            pass
                        if not info["locked"]:
                            try:
                                res = self._run_on_ui(app, lambda: app.get_credit_cards(), timeout=10.0)
                                info["card_count"] = len(res.get("value") or [])
                            except Exception:
                                info["card_count"] = -1
                except Exception:
                    pass
                self._send_json(info, 200)
                return

            # /v1/passkeys/list — list stored passkeys (if unlocked)
            if path.startswith("/v1/passkeys/list"):
                data, code = self.handle_passkeys_list(app, {})
                self._send_json(data, code)
                return

            # Unknown path
            self._send_plain("Not found", 404)
            return

        except Exception as e:
            log.exception("do_GET crashed: %s", e)
            try:
                self._send_json({"error": "internal"}, 500)
            except Exception:
                pass

    # post 
    def do_POST(self):
        try:
            app  = type(self).appref() if (type(self).appref and callable(type(self).appref)) else None
            body = self._read_json()
            if not isinstance(body, dict):
                body = {}

            # --- CORS allow-list (browser context) ---
            origin = self.headers.get("Origin", "")
            if origin and not self._origin_allowed(origin):
                self._send_json({"error": "forbidden"}, 403)
                return

            # --- Token required for ALL POST endpoints ---
            token_hdr = self._get_token()
            app_tok   = (getattr(app, "_bridge_token", "") or getattr(app, "bridge_token", "")) if app else ""
            if not app_tok or token_hdr != app_tok:
                self._send_json({"error": "unauthorized"}, 401)
                return

            # --- Routes ---

            # inside do_POST (after token check)
            if self.path == "/v1/passkeys/create":
                data, code = self.handle_passkeys_create(app, body)
                self._send_json(data, code); return

            if self.path == "/v1/passkeys/get":
                data, code = self.handle_passkeys_get(app, body)
                self._send_json(data, code); return

            # Password generator (show UI)
            if self.path.startswith("/v1/password-generator/show"):
                shown = False
                if app:
                    res = self._run_on_ui(app, lambda: app.show_password_generator_from_bridge(), timeout=30.0)
                    shown = bool(res.get("value"))
                self._send_json({"shown": shown}, 200)
                return

            # Password generator (headless generate)
            if self.path.startswith("/v1/password-generator/generate"):
                pw = ""
                if app:
                    opts = body.get("options") or {}
                    res = self._run_on_ui(app, lambda: app.generate_password_headless(opts), timeout=10.0)
                    pw = res.get("value") or ""
                self._send_json({"password": pw}, 200)
                return

            # Query entries for an origin (strict: https or local override)
            if self.path.startswith("/v1/query"):
                origin_url = body.get("origin") or body.get("host") or body.get("url") or ""
                if not self.is_https_allowed(origin_url):
                    self._send_json({"error": "origin-not-allowed"}, 403)
                    return

                entries = []
                if app:
                    res = self._run_on_ui(app, lambda: app.get_entries_for_origin(origin_url), timeout=5.0)
                    entries = res.get("value") or []
                self._send_json({"matches": entries}, 200)
                return

            # Save credential (may present UI)
            if self.path.startswith("/v1/save"):
                saved = False
                if app:
                    res = self._run_on_ui(app, lambda: app.save_credential_ui(body), timeout=30.0)
                    saved = bool(res.get("value"))
                self._send_json({"saved": saved}, 200)
                return

            # Save contact/profile (run on UI thread for safety)
            if self.path.startswith("/v1/webfill"):
                ok = False
                if app:
                    res = self._run_on_ui(app, lambda: app.save_profile_from_bridge(body), timeout=30.0)
                    ok = bool(res.get("value"))
                self._send_json({"ok": ok}, 200)
                return

            # Save card (run on UI thread for safety)
            if self.path.startswith("/v1/card"):
                ok = False
                if app:
                    res = self._run_on_ui(app, lambda: app.save_card_from_bridge(body), timeout=30.0)
                    ok = bool(res.get("value"))
                self._send_json({"ok": ok}, 200)
                return

            if self.path == "/v1/passkeys/delete":
                data, code = self.handle_passkeys_delete(app, body)
                self._send_json(data, code)
                return

            # Unknown
            self._send_plain("Not found", 404)
            return

        except Exception as e:
            tb = traceback.format_exc()
            log.error("do_POST crashed: %s\n%s", e, tb)
            try:
                self._send_json({"error": "internal", "detail": str(e), "traceback": tb}, 500)
            except Exception:
                pass

    def _check_token(self):
        # ask the app for validation, but DO NOT show any UI here
        try:
            return self.appref().check_bridge_token_headless(self._get_token())
        except Exception:
            return False

    # --- allow list
    def _origin_allowed(self, origin: str) -> bool:
        if not origin:
            return False
        if origin in ALLOWED_ORIGINS:
            return True
        # allow manual testing from localhost if enabled
        try:
            u = urlparse(origin)
        except Exception:
            return False
        return (
            ALLOW_LOCAL_HTTP
            and u.scheme in ("http", "https")
            and u.hostname in LOCAL_TEST_HOSTS
        )

    def do_HEAD(self):
        "curl -I http://127.0.0.1:8742/v1/status"
        "You should see HTTP/1.0 200 OK and zero-length body."

        try:
            path = self.path.split("?", 1)[0]

            # Public: allow simple health checks
            if path.startswith("/v1/status") or path.startswith("/test"):
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type",
                                 "application/json" if path.startswith("/v1/status")
                                 else "text/html; charset=utf-8")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            # Protected: enforce Origin + token like in GET
            origin = self.headers.get("Origin", "")
            if origin and not self._origin_allowed(origin):
                self.send_response(403); self._cors()
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            tok = self._get_token()
            app = type(self).appref() if (type(self).appref and callable(type(self).appref)) else None
            app_tok = (getattr(app, "_bridge_token", "") or getattr(app, "bridge_token", "")) if app else ""
            if not app_tok or tok != app_tok:
                self.send_response(401); self._cors()
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            # OK for protected resources
            self.send_response(200); self._cors()
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        except Exception:
            # Minimal 500 on error
            try:
                self.send_response(500); self._cors()
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
            except Exception:
                pass

def show_entry_context_menu(self, pos) -> None:
    """
    Right-click context menu:
      • Copy (auto-clears) — per field + Copy All
      • Open Website
      • Check Email Breach (HIBP)
      • Show QR (URL/Wi-Fi) — Pro only
      • Install / Open (Games) — uses 'Install Link' or first URL/platform
      • Software actions — Run Executable / Open Executable Folder / Open Key Path
    """
    self.reset_logout_timer()
    if not getattr(self, "vaultTable", None):
        return

    def select_row_under_cursor() -> int:
        try:
            idx = self.vaultTable.indexAt(pos)
            if idx.isValid():
                self.vaultTable.selectRow(idx.row())
                return idx.row()
        except Exception:
            pass
        try:
            sel = self.vaultTable.selectionModel().selectedRows()
            if sel:
                return sel[0].row()
        except Exception:
            pass
        return -1

    def _read_item_value(item):
        if not item:
            return ""
        try:
            base = int(Qt.ItemDataRole.UserRole)
            for role in (base, base+1, base+2, base+3,
                         int(Qt.ItemDataRole.DisplayRole),
                         int(Qt.ItemDataRole.EditRole)):
                v = item.data(role)
                if v not in (None, ""):
                    return str(v)
        except Exception:
            pass
        try:
            return item.text() or ""
        except Exception:
            return ""

    def get_row_entry_with_headers(row: int) -> dict:
        entry = {}
        try:
            for col in range(self.vaultTable.columnCount()):
                header_item = self.vaultTable.horizontalHeaderItem(col)
                header_label = _kq_strip_ws(header_item.text() if header_item else f"Column {col}")
                item = self.vaultTable.item(row, col)
                entry[header_label] = _kq_strip_ws(_read_item_value(item))
        except Exception:
            pass
        return entry

    def first_url_in_entry(entry: dict) -> str:
        preferred = ("Install Link", "Website", "Site", "Profile URL", "Platform", "Login URL", "URL", "Link")
        for key in preferred:
            v = entry.get(key, "")
            if v:
                return str(v).strip()
        for key, val in entry.items():
            vv = str(val or "").strip()
            if not vv:
                continue
            if any(tok in key.lower() for tok in ("website", "url", "link", "site", "platform")) or vv.startswith(("http://", "https://", "steam://", "epic://", "origin://", "uplay://")):
                return vv
        return ""

    def make_wifi_qr_payload(entry: dict):
        keys = list(entry.keys())
        ssid_keys = [k for k in keys if "ssid" in k.lower()] \
                    or [k for k in keys if "wifi" in k.lower() and "name" in k.lower()] \
                    or [k for k in keys if k.lower() in ("network", "network name")]
        ssid = entry.get(ssid_keys[0], "").strip() if ssid_keys else ""
        if not ssid:
            return None
        auth_keys = [k for k in keys if any(s in k.lower() for s in ("auth", "security", "type", "enc", "cipher"))]
        pass_keys = [k for k in keys if any(s in k.lower() for s in ("pass", "password", "key", "pwd"))]
        hidn_keys = [k for k in keys if "hidden" in k.lower()]
        auth = entry.get(auth_keys[0], "").strip() if auth_keys else ""
        pwd  = entry.get(pass_keys[0], "").strip() if pass_keys else ""
        hidden_raw = (entry.get(hidn_keys[0], "") if hidn_keys else "").strip().lower()
        hidden = hidden_raw in ("1", "true", "yes", "y")
        t = (auth or "").upper()
        if t not in ("WPA", "WEP", "NOPASS"):
            t = "WPA" if pwd else "NOPASS"
        parts = [f"WIFI:T:{t};S:{ssid};"]
        if pwd and t != "NOPASS":
            parts.append(f"P:{pwd};")
        if hidden:
            parts.append("H:true;")
        parts.append(";")
        return ("Wi-Fi: " + ssid, "".join(parts))

    def confirm(title, text) -> bool:
        mb = QMessageBox(self)
        mb.setIcon(QMessageBox.Warning)
        mb.setWindowTitle(title)
        mb.setText(text)
        mb.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        mb.setDefaultButton(QMessageBox.No)
        return mb.exec() == QMessageBox.Yes

    # ---------- Software helpers ----------
    software_root = getattr(self, "software_root", None) or self._init_software_root()

    def _expand_path(p: str) -> str:
        if not p:
            return ""
        p2 = os.path.expandvars(os.path.expanduser(p.strip()))

        # If it's relative, normalize against software_root
        if not os.path.isabs(p2) and software_root:
            # Avoid ".../software/software/..." if user already typed "software\..."
            norm = p2.replace("/", "\\")
            if norm.lower().startswith("software\\"):
                norm = norm[9:]  # strip "software\\"
            p2 = os.path.join(software_root, norm)

        return os.path.normpath(p2)

    def _is_executable_path(p: str) -> bool:
        if not p:
            return False
        p = _expand_path(p)
        # Accept exe-ish things and simple launchers
        ext = os.path.splitext(p)[1].lower()
        return os.path.exists(p) and ext in (".exe", ".lnk", ".bat", ".cmd", ".msi")

    def _reveal_in_explorer(p: str):
        try:
            p = _expand_path(p)
            if os.path.isdir(p):
                subprocess.Popen(["explorer", p])
            elif os.path.isfile(p):
                subprocess.Popen(["explorer", "/select,", p])
        except Exception as e:
            log.info(f"[WARN] reveal failed: {e}")

    def _run_exec(p: str) -> bool:
        try:
            p = _expand_path(p)
            if not _is_executable_path(p):
                return False
            open_path(p)  # user-triggered
            return True
        except Exception as e:
            log.info(f"[WARN] run exec failed: {e}")
            return False

    # ---------- main flow ----------
    row = select_row_under_cursor()
    if row < 0:
        return
    entry = get_row_entry_with_headers(row)

    menu = QMenu(self)

    # Copy submenu
    copy_menu = menu.addMenu("Copy (auto-clears)")
    for label, value in entry.items():
        act = copy_menu.addAction(label)
        from features.clipboard.secure_clipboard import secure_copy
        act.triggered.connect(lambda _=False, v=value: secure_copy(v, self.clipboard_timeout, self.currentUsername.text()))

    def _copy_all():
        lines = [f"{k}: {v}" for k, v in entry.items() if v not in (None, "")]
        from features.clipboard.secure_clipboard import secure_copy
        secure_copy("\n".join(lines), self.clipboard_timeout, self.currentUsername.text())
        if hasattr(self, "_toast"): self._toast("Code copied")

    copy_menu.addAction("Copy All").triggered.connect(lambda _=False: _copy_all())

    # Open Website
    url = first_url_in_entry(entry)
    if url:
        act_open = menu.addAction(self.tr("Open Website"))
        act_open.triggered.connect(
            lambda _=False, raw=url: self.open_url_with_warnings(raw)
        )

    # Determine current category
    try:
        cat2 = getattr(self, "categorySelector_2", None)
        cat1 = getattr(self, "categorySelector", None)
        current_category = ((cat2.currentText() if cat2 else "") or
                            (cat1.currentText() if cat1 else "") or "")
        current_category = str(current_category).strip()
    except Exception:
        current_category = ""

    # Install / Open (Games)
    # Install / Open (Games)
    if current_category.lower() == "games":
        platform_hint = (entry.get("Platform") or current_category or "")
        platform_hint = str(platform_hint).strip().lower()
        install_link = (entry.get("Install Link") or url or "")
        install_link = str(install_link).strip()

        label = "🎮 Install / Open"
        act_install = menu.addAction(label)

        has_target = bool(install_link or platform_hint)


        if not has_target:
            act_install.setEnabled(False)
            act_install.setToolTip(self.tr("No Install Link/URL or Platform found"))
        else:
            safe_link = install_link
            safe_platform = platform_hint
            act_install.setStatusTip("Install or open the selected game")
            act_install.triggered.connect(
                lambda _=False, lk=safe_link, plat=safe_platform: self.launch_or_download(lk, plat)
            )

  
    # ▶ Software actions
    if current_category.lower() == "software":
        # --- resolve software root for relative paths ---
        from app.paths import software_dir as software_root

        def _expand_path(p: str) -> str:
            if not p:
                return ""
            p2 = os.path.expandvars(os.path.expanduser(p))
            if not os.path.isabs(p2) and software_root:
                p2 = os.path.normpath(os.path.join(software_root, p2))
            return os.path.normpath(p2)

        def _is_executable_path(p: str) -> bool:
            if not p:
                return False
            p = _expand_path(p)
            return os.path.exists(p) and os.path.splitext(p)[1].lower() in (".exe", ".lnk", ".bat", ".cmd")

        def _reveal_in_explorer(p: str):
            try:
                p = _expand_path(p)
                if os.path.isdir(p):
                    subprocess.Popen(["explorer", p])
                elif os.path.isfile(p):
                    subprocess.Popen(["explorer", "/select,", p])
            except Exception as e:
                log.info(f"[WARN] reveal failed: {e}")

        def _run_exec(p: str) -> bool:
            try:
                p = _expand_path(p)
                if not _is_executable_path(p):
                    return False
                open_path(p)  # user-triggered
                return True
            except Exception as e:
                log.info(f"[WARN] run exec failed: {e}")
                return False

        # --- pull values by fuzzy header match (handles 'Executable Path', etc.) ---
        def _pick(entry: dict, want: str) -> str:
            wl = want.lower()
            # exacts first
            if wl == "exec":
                for k in entry.keys():
                    if k.strip().lower() in ("executable path", "executable", "exe", "path"):
                        v = (entry.get(k) or "").strip()
                        if v:
                            return v
            if wl == "key":
                for k in entry.keys():
                    if k.strip().lower() in ("key path", "license", "key", "license key"):
                        v = (entry.get(k) or "").strip()
                        if v:
                            return v
            # fuzzy contains
            for k in entry.keys():
                kl = k.lower()
                if wl == "exec" and ("exec" in kl or kl.endswith("path")):
                    v = (entry.get(k) or "").strip()
                    if v:
                        return v
                if wl == "key" and ("key" in kl or "license" in kl):
                    v = (entry.get(k) or "").strip()
                    if v:
                        return v
            return ""

        exec_path = _pick(entry, "exec")
        key_path  = _pick(entry, "key")
        act_run = menu.addAction("▶ Run Executable")
        act_open_folder = menu.addAction("🗂 Open Executable Folder")
        act_open_key = menu.addAction("🔑 Open Key Path")

        # enable/disable
        if not exec_path:
            act_run.setEnabled(False); act_open_folder.setEnabled(False)
            act_run.setToolTip(self.tr("No Executable path set"))
            act_open_folder.setToolTip(self.tr("No Executable path set"))
        if not key_path:
            act_open_key.setEnabled(False); act_open_key.setToolTip(self.tr("No Key Path set"))

        # wire actions (capture now)
        ep = exec_path
        kp = key_path
        act_run.triggered.connect(
            lambda _=False, raw=ep: (
                _run_exec(raw) or
                QMessageBox.warning(self, "Run",
                    f"Invalid Executable path.\n\nResolved to:\n{_expand_path(raw)}")
            )
        )
        
        act_open_folder.triggered.connect(lambda _=False, p=ep: _reveal_in_explorer(p))
        act_open_key.triggered.connect(
            lambda _=False, p=kp: (
                subprocess.Popen(["explorer", _expand_path(p)]) if os.path.isdir(_expand_path(p)) else
                (open_path(_expand_path(p)) if os.path.isfile(_expand_path(p))
                    else QMessageBox.warning(self, self.tr("Key"), self.tr("Key Path not found.")))
            )
        )


    # Check Email Breach
    for key, val in entry.items():
        if "email" in key.lower():
            email = (val or "").strip()
            if email:
                menu.addAction("🔍 Check Email Breach").triggered.connect(
                    lambda _=False, e=email: QDesktopServices.openUrl(QUrl(f"https://haveibeenpwned.com/account/{quote(e)}"))
                )
            break

    # Show QR (URL / Wi-Fi) — Pro only
    act_qr = menu.addAction("Show QR (URL / Wi-Fi)")
    try:
        self.enforce_pro_feature(act_qr, "QR Code Preview")
    except Exception:
        pass
   
    
    wifi_pair = make_wifi_qr_payload(entry)
    if wifi_pair is not None:
        title, payload = wifi_pair
    else:
        url_payload = first_url_in_entry(entry)
        if url_payload and not url_payload.lower().startswith(("http://", "https://")):
            url_payload = "https://" + url_payload
        title, payload = ("Open URL", url_payload) if url_payload else (None, None)
    if not payload:
        act_qr.setEnabled(False)
    else:
        from features.qr.qr_tools import QRPreviewDialog
        act_qr.triggered.connect(lambda _=False, t=title, p=payload: QRPreviewDialog(t, p, self).exec())

    # Show menu at cursor
    global_pos = self.vaultTable.viewport().mapToGlobal(pos)
    menu.exec(global_pos)

# ==============================
# --- get current column index clicked


def _move_row_to_category_full(self, row: int, new_type: str) -> str:
    """
    Open AddEntryDialog for the target category, prefill from the source row,
    and persist via update_vault_entry(...).

    Returns: 'success' | 'cancelled' | 'failed'
    """
    try:
        log.debug(str(f"{kql.i('update')} [MOVE] Requested move for row={row}, target='{new_type}'"))

        # guards
        if not getattr(self, "vaultTable", None):
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} vaultTable is missing"))
            return "failed"
        if row is None or row < 0 or row >= self.vaultTable.rowCount():
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} Row index out of range: {row}"))
            return "failed"

        # refuse if target/source are protected
        if self._is_blocked_target(new_type):
            log.debug("[MOVE] target category blocked")
            return "failed"
        try:
            if self._is_blocked_source(self._category_for_row(row)):
                log.debug("[MOVE] source category blocked")
                return "failed"
        except Exception:
            pass

        # load source entry + global index
        try:
            entries = load_vault(self.currentUsername.text(), getattr(self, 'core_session_handle', None) or self.userKey)
            try:
                global_index = self.current_entries_indices[row]
            except Exception:
                global_index = row
            src_entry = entries[global_index]
        except Exception as e:
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} Could not load entry for row {row}: {e}"))
            return "failed"

        # create dialog for target category
        try:
            dlg = AddEntryDialog(self, new_type, self.enable_breach_checker, pro=None,
            user=self.currentUsername.text(),is_dev=is_dev)
            dlg.setWindowTitle(self.tr("Move Entry: {row1} → {new}").format(row1=self._category_for_row(row), new=new_type))
        except Exception as e:
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} Could not Move AddEntryDialog: {e}"))
            return "failed"

        # force dialog to build the UI for the TARGET category
        def _force_dialog_category(dlg_obj, cat: str):
            try:
                if hasattr(dlg_obj, "categoryCombo"):
                    dlg_obj.categoryCombo.setCurrentText(cat)
                    for name in ("on_category_changed", "_on_category_changed", "category_changed"):
                        if hasattr(dlg_obj, name):
                            try:
                                getattr(dlg_obj, name)()
                            except Exception:
                                pass
                elif hasattr(dlg_obj, "set_category"):
                    dlg_obj.set_category(cat)
                elif hasattr(dlg_obj, "category"):
                    dlg_obj.category = cat
                    for name in ("build_form", "_build_form", "rebuild_form"):
                        if hasattr(dlg_obj, name):
                            try:
                                getattr(dlg_obj, name)()
                            except Exception:
                                pass
            except Exception as e:
                try:
                    log.debug(str(f"{kql.i('update')} [MOVE] category force warn: {e}"))
                except Exception:
                    pass

        _force_dialog_category(dlg, new_type)

        # if the dialog can build fields from meta, feed it the user's schema
        if hasattr(dlg, "set_fields_from_meta") and callable(dlg.set_fields_from_meta):
            try:
                dlg.set_fields_from_meta(self.user_field_meta_for_category(new_type))
                for name in ("build_form", "_build_form", "rebuild_form"):
                    if hasattr(dlg, name):
                        try:
                            getattr(dlg, name)()
                        except Exception:
                            pass
            except Exception:
                pass

        # robust prefill (bias to user's labels)
        def _norm(s: str) -> str:
            s = (s or "").strip().lower()
            return "".join(ch for ch in s if ch.isalnum())

        _syn = {
            "username": {"user", "login", "account", "accountname", "userid"},
            "email": {"mail", "emailaddress"},
            "password": {"pass", "passwd"},
            "website": {"url", "link", "domain"},
            "phone": {"phonenumber", "mobile", "tel", "telephone"},
            "2faenabled": {"twofactor", "mfa", "2fa"},
            "platform": {"store", "launcher", "service"},
            "gamename": {"title", "name"},
        }

        target_labels = self._user_schema_field_labels(new_type)
        _target_lc = {"".join(ch for ch in (lbl or "").lower() if ch.isalnum()): lbl
                      for lbl in target_labels}

        def _as_bool(v) -> bool:
            s = str(v).strip().lower()
            return s in ("1", "true", "yes", "on", "y", "t")

        def _set_widget_value(w, v):
            try:
                if isinstance(w, QLineEdit):
                    w.setText("" if v is None else str(v))
                    return True
                if isinstance(w, QPlainTextEdit):
                    w.setPlainText("" if v is None else str(v))
                    return True
                if isinstance(w, QTextEdit):
                    w.setPlainText("" if v is None else str(v))
                    return True
                if isinstance(w, QComboBox):
                    txt = "" if v is None else str(v)
                    i = w.findText(txt)
                    if i >= 0:
                        w.setCurrentIndex(i)
                    elif w.isEditable():
                        w.setEditText(txt)
                    return True
                if isinstance(w, QCheckBox):
                    w.setChecked(_as_bool(v))
                    return True
                if isinstance(w, QSpinBox):
                    try:
                        w.setValue(int(float(v)))
                    except Exception:
                        pass
                    return True
                if isinstance(w, QDoubleSpinBox):
                    try:
                        w.setValue(float(v))
                    except Exception:
                        pass
                    return True
                if isinstance(w, QDateEdit):
                    try:
                        s = str(v)
                        d = (QDate.fromString(s, "yyyy-MM-dd")
                             if "-" in s else QDate.fromString(s, "dd/MM/yyyy"))
                        if d.isValid():
                            w.setDate(d)
                    except Exception:
                        pass
                    return True
                if isinstance(w, QTimeEdit):
                    try:
                        t = QTime.fromString(str(v), "HH:mm:ss")
                        if not t.isValid():
                            t = QTime.fromString(str(v), "HH:mm")
                        if t.isValid():
                            w.setTime(t)
                    except Exception:
                        pass
                    return True
                if isinstance(w, QDateTimeEdit):
                    try:
                        dtv = QDateTime.fromString(str(v), "yyyy-MM-dd HH:mm:ss")
                        if not dtv.isValid():
                            dtv = QDateTime.fromString(str(v), "yyyy-MM-ddTHH:mm:ss")
                        if dtv.isValid():
                            w.setDateTime(dtv)
                    except Exception:
                        pass
                    return True
            except Exception:
                pass
            return False

        def _prefill_dialog(dlg_obj, src: dict) -> bool:
            any_set = False
            # normalize src keys + synonyms
            src_norm = {}
            for k, v in (src or {}).items():
                if not isinstance(k, str):
                    continue
                nk = _norm(k)
                src_norm[nk] = v
                for canon, alts in _syn.items():
                    if nk == canon or nk in alts:
                        src_norm[canon] = v
                        for a in alts:
                            src_norm[a] = v

            # 1) preferred: labeled fields mapping
            fields_map = getattr(dlg_obj, "fields", None)
            if isinstance(fields_map, dict) and fields_map:
                for label, widget in fields_map.items():
                    k = _norm(label)
                    # normalize common aliases
                    if k in ("gamenametitle", "name"):
                        k = "gamename"
                    if k in ("user", "login", "account", "accountname", "userid"):
                        k = "username"
                    if k in ("url", "domain", "link"):
                        k = "website"
                    if k in ("phonenumber", "mobile", "tel", "telephone"):
                        k = "phone"
                    if k in ("twofactor", "mfa", "2fa"):
                        k = "2faenabled"

                    # prefer exact normalized match in user's labels
                    if k in _target_lc:
                        val = src_norm.get(k)
                    else:
                        val = src_norm.get(k)

                    if val is not None and _set_widget_value(widget, val):
                        any_set = True

            # 2) common attribute names
            for attr, key in (
                ("websiteInput", "website"), ("emailInput", "email"), ("passwordInput", "password"),
                ("usernameInput", "username"), ("gameNameInput", "gamename"), ("platformInput", "platform"),
                ("phoneInput", "phone"), ("backupCodeInput", "backupcode"), ("notesInput", "notes"),
            ):
                if hasattr(dlg_obj, attr) and src_norm.get(key) is not None:
                    if _set_widget_value(getattr(dlg_obj, attr), src_norm.get(key)):
                        any_set = True



            # 3) last resort: objectName / accessibleName  (PySide6-safe)
            def _all_form_widgets(root):
                classes = (
                    QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QCheckBox,
                    QSpinBox, QDoubleSpinBox, QDateEdit, QTimeEdit, QDateTimeEdit,
                )
                widgets = []
                for cls in classes:
                    widgets.extend(root.findChildren(cls))  # PySide6: must call per-type
                return widgets

            for w in _all_form_widgets(dlg_obj):
                try:
                    nm = _norm(
                        (w.objectName() if hasattr(w, "objectName") else "") or
                        (w.accessibleName() if hasattr(w, "accessibleName") else "")
                    )
                except Exception:
                    nm = ""
                if not nm:
                    continue

                alias = {
                    "url": "website", "link": "website", "domain": "website",
                    "user": "username", "login": "username", "account": "username", "accountname": "username",
                    "gamename": "gamename", "platform": "platform", "phone": "phone", "phonenumber": "phone",
                    "backupcode": "backupcode", "notes": "notes", "email": "email", "password": "password",
                }.get(nm, nm)

                val = src_norm.get(alias)
                if val is not None and _set_widget_value(w, val):
                    any_set = True

            # 4) unmatched → Notes
            notes_widget = None
            fm = getattr(dlg_obj, "fields", None)
            if isinstance(fm, dict):
                notes_widget = fm.get("Notes") or fm.get("notes")
            if not notes_widget:
                for guess in ("notesInput", "notes", "txtNotes"):
                    if hasattr(dlg_obj, guess):
                        notes_widget = getattr(dlg_obj, guess)
                        break
            if notes_widget:
                known = {"username", "email", "password", "website", "phone", "backupcode", "notes",
                         "2faenabled", "platform", "gamename"}
                extras = {k: v for k, v in (src or {}).items()
                          if isinstance(k, str) and _norm(k) not in known and v not in (None, "")}
                if extras:
                    try:
                        existing = (notes_widget.toPlainText()
                                    if isinstance(notes_widget, (QPlainTextEdit, QTextEdit))
                                    else notes_widget.text())
                    except Exception:
                        existing = ""
                    block = "[Unmatched Fields]\n" + "\n".join(f"{k}: {v}" for k, v in extras.items())
                    text = (existing + ("\n\n" if existing else "") + block).strip()
                    _set_widget_value(notes_widget, text)
                    any_set = True

            try:
                log.debug(str(f"{kql.i('update')} [MOVE] {'✅' if any_set else '⚠️'} Prefill {'applied' if any_set else 'not applied'}"))
            except Exception:
                pass
            return any_set

        _prefill_dialog(dlg, src_entry)

        # run dialog (exec() returns int)
        result = dlg.exec()
        if int(result) != int(QDialog.Accepted):
            log.debug(str(f"{kql.i('update')} [MOVE] Cancelled by user (result={result})"))
            return "cancelled"

        # gather & force category/type/date
        try:
            new_entry = dlg.get_entry_data() or {}
            new_entry["category"] = new_type
            new_entry["Type"] = new_type
            new_entry["Date"] = dt.datetime.now().strftime("%Y-%m-%d")
        except Exception as e:
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} get_entry_data failed: {e}"))
            return "failed"

        # persist via canonical API (with signature fallback)
        
        persist_entry_with_history(self, self.currentUsername.text(), self.userKey, global_index, new_entry)

        try:
            update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Moved Entry In Vault"))
        except Exception:
            pass
        try:
            self.load_vault_table()
        except Exception:
            pass
        log.debug(str(f"{kql.i('backup')} [MOVE] {kql.i('ok')} Persisted via update_vault_entry (idx={global_index})"))
        return "success"

    except Exception as e:
        log.error(str(f"{kql.i('update')} [ERROR] {kql.i('warn')} Unexpected error: {e}"))
        return "failed"



def show_trash_manager(self):                                                                           # - show trash dialog
    self.set_status_txt(self.tr("Opening Trash"))
    """
    Open a modal dialog that lists soft-deleted items (Trash).
    Users can Restore, Delete Permanently, or Empty Trash.
    Requires: _trash_load/_trash_save, restore_from_trash, restore_from_trash_index, purge_trash
    _toast, _watchtower_rescan
    """

    username = self.currentUsername.text()
    key=(getattr(self, 'core_session_handle', None) or self.userKey)

    # --- helpers -----------

    def _selected_uid():
        r = tbl.currentRow()
        if r < 0:
            return None
        it = tbl.item(r, 5)  # hidden column
        return it.data(int(Qt.ItemDataRole.UserRole)) if it else None

    def _trash_entry_by_uid(uid: str):
        trash = self._trash_load(username, key) or []
        for e in trash:
            if str(e.get("_trash_uid") or "") == str(uid):
                return e
        return None

    def on_preview():
        uid = _selected_uid()
        if not uid:
            QMessageBox.information(self, self.tr("Preview"), self.tr("Select an item to preview."))
            return

        rec = _trash_entry_by_uid(uid)
        if not rec:
            QMessageBox.warning(dlg, self.tr("Preview"), self.tr("Couldn’t load this item from Trash."))
            return

        pv   = rec.get("_preview") or {}
        safe = self._redact_for_preview(rec) if hasattr(self, "_redact_for_preview") else rec

        v = QDialog(self)
        v.setWindowTitle(self.tr("Trash Item — Preview"))
        v.resize(640, 480)
        layv = QVBoxLayout(v)

        hdr  = (pv.get("kind") or "item").capitalize()
        title = pv.get("title") or "(untitled)"
        lbl = QtWidgets.QLabel(f"<b>{hdr}</b> — {title}")
        layv.addWidget(lbl)

        txt = QtWidgets.QPlainTextEdit(v)
        txt.setReadOnly(True)
        txt.setPlainText(json.dumps(safe, indent=2, ensure_ascii=False))
        layv.addWidget(txt)

        row = QHBoxLayout()
        btnClose = QPushButton(self.tr("Close"))
        row.addStretch(1)
        row.addWidget(btnClose)
        layv.addLayout(row)
        btnClose.clicked.connect(v.accept)

        v.exec()

    def _parse_iso(ts: str):
        if not ts:
            return None
        s = ts.strip().replace("Z", "")
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return dt.datetime.strptime(s, fmt)
            except Exception:
                pass
        try:
            return dt.datetime.fromisoformat(s)
        except Exception:
            return None

    def _load_rows():
        trash = self._trash_load(username, key) or []
        # newest first
        try:
            trash.sort(key=lambda e: _parse_iso(e.get("_deleted_at") or "") or dt.datetime.min, reverse=True)
        except Exception:
            pass
        return trash

    # --- dialog ------------
    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Trash (kept up to 30 days)"))
    dlg.resize(820, 420)

    lay = QVBoxLayout(dlg)

    tbl = QTableWidget(0, 6, dlg)
    tbl.setHorizontalHeaderLabels(["Deleted At", "Kind", "Title", "Username", "URL", "ID"])
    tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    tbl.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    tbl.setAlternatingRowColors(True)
    tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    lay.addWidget(tbl)

    # Single, final version of refresh:
    def _refresh_table():
        rows = _load_rows()
        tbl.setRowCount(len(rows))
        for r, e in enumerate(rows):
            pv    = e.get("_preview") or {}
            title = pv.get("title") or (e.get("title") or e.get("site") or e.get("name") or "(untitled)")
            user  = pv.get("username") or (e.get("username") or e.get("user") or e.get("email") or "")
            url   = pv.get("url") or (e.get("url") or e.get("origin") or "")
            kind  = pv.get("kind") or "login"
            when  = e.get("_deleted_at") or ""
            rid   = str(e.get("id") or e.get("_id") or e.get("row_id") or "")
            uid = str(e.get("_trash_uid") or "")

            it_when  = QTableWidgetItem(when)
            it_kind  = QTableWidgetItem(kind)
            it_title = QTableWidgetItem(title)
            it_user  = QTableWidgetItem(user)
            it_url   = QTableWidgetItem(url)

            tip = (
                f"Deleted: {when}\n"
                f"Kind: {kind}\n"
                f"Title: {title}\n"
                f"Username: {user or '(none)'}\n"
                f"URL: {url or '(none)'}"
            )
            for it in (it_when, it_kind, it_title, it_user, it_url):
                it.setToolTip(tip)

            tbl.setItem(r, 0, it_when)
            tbl.setItem(r, 1, it_kind)
            tbl.setItem(r, 2, it_title)
            tbl.setItem(r, 3, it_user)
            tbl.setItem(r, 4, it_url)

            id_item = QTableWidgetItem(uid or rid)  # show something if you ever unhide
            id_item.setData(int(Qt.ItemDataRole.UserRole), uid)          # <<< primary: uid
            id_item.setData(int(Qt.ItemDataRole.UserRole)+1, rid)        # optional: legacy id
            tbl.setItem(r, 5, id_item) 

        tbl.setColumnHidden(5, True)
        try:
            tbl.resizeColumnsToContents()
            tbl.horizontalHeader().setStretchLastSection(True)
        except Exception:
            pass
        if rows:
            try: tbl.selectRow(0)
            except Exception: pass

    # actions

    def _selected_ref():
        r = tbl.currentRow()
        if r < 0:
            return None
        it = tbl.item(r, 5)  # hidden id column
        uid = it.data(int(Qt.ItemDataRole.UserRole)) if it else None
        return uid

    def on_restore():
        uid = _selected_ref()
        if not uid:
            QMessageBox.information(dlg, dlg.tr("Restore"), dlg.tr("Select an item to restore."))
            return

        ok = bool(self.restore_from_trash_uid(username, key, uid))
        if ok:
            try: self._toast("Restored from Trash.")
            except Exception: pass
            try: 
                update_baseline(username=username, verify_after=False, who="Trash Vault changed")
            except Exception: pass
            try: self.load_vault_table()
            except Exception: pass
            try:
                if hasattr(self, "_watchtower_rescan"):
                    self._watchtower_rescan()
            except Exception: pass
            _refresh_table()
        else:
            
            QMessageBox.warning(self, self.tr("Restore"), self.tr("Failed to restore the entry."))

    def on_delete_perm():
        r = tbl.currentRow()
        if r < 0:
            QMessageBox.information(self, self.tr("Delete"), self.tr("Select an item to delete permanently."))
            return
        if QMessageBox.question(
            self, self.tr("Delete Permanently"),
            self.tr("This will remove the item from Trash forever. Continue?")
        ) != QMessageBox.StandardButton.Yes:
            return

        uid = _selected_ref()
        idx = tbl.currentRow()
        trash = self._trash_load(username, key) or []

        removed = False

        # Primary: delete by the Trash UID we store in UserRole
        if uid:
            new_trash = []
            for e in trash:
                if not removed and str(e.get("_trash_uid") or "") == str(uid):
                    removed = True
                    continue
                new_trash.append(e)
            trash = new_trash

        # Fallback: delete by index (row in the current sorted view)
        if not removed and idx is not None:
            try:
                idx = int(idx)
                if 0 <= idx < len(trash):
                    trash.pop(idx)
                    removed = True
            except Exception:
                pass

        if removed:
            self._trash_save(username, key, trash)
            try:
                txt = self.tr("Deleted from Trash.")
                self._toast(txt)
                self.set_status_txt(txt)
            except Exception: pass
            _refresh_table()
        else:
            QMessageBox.warning(self, self.tr("Delete"), self.tr("Could not delete this item."))

    def on_empty_trash():
        if QMessageBox.question(
            self, self.tr("Empty Trash"), self.tr("Delete all items in Trash permanently?")
        ) != QMessageBox.StandardButton.Yes:
            return
        self._trash_save(username, key, [])
        try: 
            txt = self.tr("Trash emptied.")
            self._toast(txt)
            self.set_status_txt(txt)
        except Exception: pass
        _refresh_table()

    # buttons
    btns = QHBoxLayout()
    btnRestore = QPushButton(self.tr("Restore"))
    btnDelete  = QPushButton(self.tr("Delete Permanently"))
    btnEmpty   = QPushButton(self.tr("Empty Trash"))
    btnClose   = QPushButton(self.tr("Close"))
    btnPreview = QPushButton(self.tr("Preview…"))
    btns.addWidget(btnRestore)
    btns.addWidget(btnDelete)
    btns.addStretch(1)
    btns.addWidget(btnEmpty)
    btns.addWidget(btnClose)
    btns.addWidget(btnPreview)
    lay.addLayout(btns)

    btnRestore.clicked.connect(on_restore)
    btnDelete.clicked.connect(on_delete_perm)
    btnEmpty.clicked.connect(on_empty_trash)
    btnClose.clicked.connect(dlg.accept)
    btnPreview.clicked.connect(on_preview)

    # initial load + opportunistic purge of old items (>30 days)
    try:
        purged = self.purge_trash(username, key, max_age_days=30)
        if purged:
            try: 
                txt = self.tr("Purged ") + f"{purged}" + self.tr(" expired item(s).")
                self._toast(txt)
                self.set_status_txt(txt)
            except Exception: pass
    except Exception:
        pass

    _refresh_table()
    dlg.exec()



def _preview_full_entry(self, entry: dict, sequential: bool = False) -> bool:
    """
    Display a JSON preview + category picker.
    When the user clicks “Add to Category…”, either:
      - sequential=False (default): open AddEntryDialog modeless (current behavior).
      - sequential=True: open AddEntryDialog MODAL and wait; return True if saved.
    Returns True if the preview dialog closed via OK/Add flow; False on Cancel.
    """
    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Share Packet — Full Contents"))
    dlg.setModal(True)

    v = QVBoxLayout(dlg)
    v.setContentsMargins(12, 12, 12, 12)
    v.setSpacing(10)

    cat_detected = str(entry.get("category") or entry.get("Category") or "(unknown)")
    lbl = QLabel(self.tr("Detected category in packet: <b>{cat_detected}</b>").format(cat_detected))
    lbl.setTextFormat(Qt.TextFormat.RichText)
    v.addWidget(lbl)

    txt = QTextEdit()
    txt.setReadOnly(True)
    txt.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
    try:
        txt.setPlainText(json.dumps(entry, ensure_ascii=False, indent=2))
    except Exception:
        txt.setPlainText(str(entry))
    txt.setMinimumSize(700, 420)
    v.addWidget(txt, 1)

    h = QHBoxLayout()
    h.setSpacing(10)
    lbl_cat = QLabel(self.tr("Category:"))
    cmb_cat = QComboBox()
    cmb_cat.setMinimumWidth(220)
    try:
        if getattr(self, 'categorySelector_2', None) and self.categorySelector_2.count() > 0:
            for i in range(self.categorySelector_2.count()):
                cmb_cat.addItem(self.categorySelector_2.itemText(i))
        else:
            for c in ["Email Accounts", "Web Logins", "Software Licenses", "Secure Notes"]:
                cmb_cat.addItem(c)
    except Exception:
        for c in ["Email Accounts", "Web Logins", "Software Licenses", "Secure Notes"]:
            cmb_cat.addItem(c)

    i = cmb_cat.findText(cat_detected)
    if i >= 0:
        cmb_cat.setCurrentIndex(i)

    btn_add = QPushButton(self.tr("Add to Category…"))
    btns = QDialogButtonBox()
    btn_cancel = btns.addButton(QDialogButtonBox.StandardButton.Cancel)
    h.addWidget(lbl_cat)
    h.addWidget(cmb_cat, 1)
    h.addWidget(btn_add)
    h.addWidget(btns)
    v.addLayout(h)

    accepted_flag = {"ok": False}

    def do_add_to_category() -> None:
        target = cmb_cat.currentText().strip()
        if not target:
            QMessageBox.information(self, self.tr("Import Share"), self.tr("Please choose a category first."))
            return
        if self._is_blocked_target(target):
            msg = self.tr("Import into ") + f"“{target}”" + self.tr(" is blocked by your safety setting.")
            QMessageBox.warning(self, self.tr("Import Share"), msg)
            return

        username = self._active_username() or ""
        mapped = self._map_for_dialog(entry)

        # Close preview before launching the editor
        try: dlg.accept()
        except Exception: pass

        ref_win = None
        try:
            editor = AddEntryDialog(
                self, target,
                getattr(self, "enable_breach_checker", False),
                existing_entry=None,
                user=self.currentUsername.text(),
                is_dev=is_dev,
            )
            if hasattr(editor, "category"):
                editor.category = target

            for name in ("build_form", "_build_form", "rebuild_form", "on_category_changed"):
                if hasattr(editor, name):
                    try: getattr(editor, name)()
                    except Exception: pass

            if hasattr(self, "user_field_meta_for_category") and hasattr(editor, "set_fields_from_meta"):
                try:
                    editor.set_fields_from_meta(self.user_field_meta_for_category(target))
                    for name in ("build_form", "_build_form", "rebuild_form"):
                        if hasattr(editor, name):
                            try: getattr(editor, name)()
                            except Exception: pass
                except Exception:
                    pass

            def run_prefill() -> None:
                try: self._prefill_dialog_for_entry(editor, mapped)
                except Exception: pass

            if sequential:
                # modal path — prefill now and block until user finishes
                run_prefill()
                res = editor.exec()
                if res == int(editor.DialogCode.Accepted):
                    new_entry = editor.get_entry_data() or {}
                    new_entry["category"] = target
                    new_entry["Type"] = target
                    new_entry["Date"] = dt.datetime.now().strftime("%Y-%m-%d")

                    try:
                        entries = load_vault(username, getattr(self, 'core_session_handle', None) or self.userKey) or []
                    except TypeError:
                        entries = load_vault(username) or []

                    fp = (
                        (new_entry.get("title") or new_entry.get("Name") or ""),
                        (new_entry.get("username") or new_entry.get("User") or ""),
                        (new_entry.get("url") or new_entry.get("URL") or ""),
                    )
                    exists = any(
                        (
                            (e.get("title", "") or e.get("Name", "")),
                            (e.get("username", "") or e.get("User", "")),
                            (e.get("url", "") or e.get("URL", "")),
                        ) == fp for e in entries
                    )
                    if exists:
                        nk = next((k for k in ("Notes", "notes") if k in new_entry), "Notes")
                        new_entry[nk] = (str(new_entry.get(nk, "")) + "\n[imported from features.share]").strip()

                    entries.append(new_entry)
                    try:
                        save_vault(username, getattr(self, 'core_session_handle', None) or self.userKey, entries)
                    except TypeError:
                        save_vault(username, entries)

                    self._on_any_entry_changed()
                    try: self.load_vault_table()
                    except Exception: pass
                    try:
                        update_baseline(username=username, verify_after=False, who="Vault Entry")
                    except Exception:
                        pass

                    accepted_flag["ok"] = True
                return

            # modeless path (original behavior)
            QTimer.singleShot(0, run_prefill)

            nonlocal_ref = {"ref": None}
            ref_win = self._open_reference_window(mapped, title=self.tr("Reference — Mapped Values"), on_autofill=run_prefill)
            nonlocal_ref["ref"] = ref_win

            editor.setWindowModality(Qt.WindowModality.NonModal)
            editor.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)

            def _on_finished(code: int) -> None:
                try:
                    if nonlocal_ref["ref"]:
                        nonlocal_ref["ref"].close()
                except Exception:
                    pass
                if code != int(editor.DialogCode.Accepted):
                    return
                new_entry = editor.get_entry_data() or {}
                new_entry["category"] = target
                new_entry["Type"] = target
                new_entry["Date"] = dt.datetime.now().strftime("%Y-%m-%d")

                try:
                    entries = load_vault(username, getattr(self, 'core_session_handle', None) or self.userKey) or []
                except TypeError:
                    entries = load_vault(username) or []

                fp = (
                    (new_entry.get("title") or new_entry.get("Name") or ""),
                    (new_entry.get("username") or new_entry.get("User") or ""),
                    (new_entry.get("url") or new_entry.get("URL") or ""),
                )
                exists = any(
                    (
                        (e.get("title", "") or e.get("Name", "")),
                        (e.get("username", "") or e.get("User", "")),
                        (e.get("url", "") or e.get("URL", "")),
                    ) == fp for e in entries
                )
                if exists:
                    nk = next((k for k in ("Notes", "notes") if k in new_entry), "Notes")
                    new_entry[nk] = (str(new_entry.get(nk, "")) + "\n[imported from features.share]").strip()

                entries.append(new_entry)
                try:
                    save_vault(username, getattr(self, 'core_session_handle', None) or self.userKey, entries)
                except TypeError:
                    save_vault(username, entries)

                self._on_any_entry_changed()
                try: self.load_vault_table()
                except Exception: pass
                try:
                    update_baseline(username=username, verify_after=False, who="Category Vault Changed")
                except Exception:
                    pass

            editor.finished.connect(_on_finished)
            editor.show()
            editor.raise_()
            editor.activateWindow()

        except Exception as e:
            msg = self.tr("Could not open the edit form:\n{e}").format(e)
            QMessageBox.critical(self, self.tr("Import Share"), msg)
            try:
                if ref_win:
                    ref_win.close()
            except Exception:
                pass
            return

    btn_add.clicked.connect(do_add_to_category)
    btn_cancel.clicked.connect(dlg.reject)

    return dlg.exec() == QDialog.DialogCode.Accepted or bool(accepted_flag["ok"])

# --- compat wrapper: normalize args + support both 2-arg / 3-arg signatures


def open_add_entry_dialog(self, *args, **kwargs):
    """Open Add Entry dialog, persist on Accept, refresh table/baseline."""
    if not self._require_unlocked(): 
        return
    def _safe_dirname(name: str) -> str:
        return "".join(c for c in (name or "item").strip() if c not in '<>:"/\\|?*')

    def _expand(p: str) -> str:
        return os.path.expandvars(os.path.expanduser(p or ""))

    def _under_root(path: str, root: str) -> bool:
        try:
            return os.path.abspath(path).lower().startswith(os.path.abspath(root).lower() + os.sep)
        except Exception:
            return False

    def _rel_to_root(path: str, root: str) -> str:
        try:
            return os.path.relpath(path, start=root)
        except Exception:
            return path

    self.set_status_txt(self.tr("Adding to Vault"))
    log.debug("%s Trying Open Add Entry", kql.i('ui'))
    self.reset_logout_timer()

    # must be signed in
    username = (self.currentUsername.text() or "").strip()
    if not username or not getattr(self, "userKey", None):
        QMessageBox.warning(self, self.tr("Add Entry"), self.tr("Unlock your vault first."))
        return

    # free-limit gate (keep existing policy)
    try:
        current = load_vault(username, getattr(self, 'core_session_handle', None) or self.userKey) or []
        if not self.can_add_entry():
            return
    except Exception:
        pass

    # pick category from UI
    category = self.categorySelector_2.currentText()
    dlg = AddEntryDialog(
        self,
        category,
        self.enable_breach_checker,
        user=username,is_dev=is_dev,
    )
    self._track_window(dlg)

    if dlg.exec() != QDialog.DialogCode.Accepted:
        return

    # re-check limit post-dialog (if needed)
    try:
        if not self.can_add_entry():
            return
    except Exception:
        pass

    # payload from dialog
    try:
        entry = dlg.get_entry_data() or {}
    except Exception:
        log.exception("[UI ADD] could not read dialog entry")
        return

    # ---- Software attachment handling (safe; failures don’t block saving) ----
    try:
        if (entry.get("category", "").strip().lower() == "software"):

            # per-user software root (under %APPDATA%/Keyquorum/Users/<user>/Software)
            try:
                from app.paths import soft_user_dir
                software_root = soft_user_dir(username, ensure_dir=True)  # returns Path
                software_root = str(software_root)
                os.makedirs(software_root, exist_ok=True)
            except Exception:
                software_root = None

            if software_root:
                name = (entry.get("Name", "").strip() or "software")
                dest_dir = os.path.join(software_root, _safe_dirname(name))
                os.makedirs(dest_dir, exist_ok=True)

                # Executable Path
                exe_path_raw = (entry.get("Executable Path") or entry.get("Executable") or entry.get("Exe") or "").strip()
                exe_src = _expand(exe_path_raw)
                if exe_src and not os.path.isabs(exe_src) and exe_src.lower().startswith(("software\\", "software/")):
                    exe_src = _expand(exe_src[9:])
                if exe_src and os.path.exists(exe_src):
                    if _under_root(exe_src, software_root):
                        entry["Executable Path"] = _rel_to_root(exe_src, software_root)
                    else:
                        ext = os.path.splitext(exe_src)[1].lower()
                        if ext in (".exe", ".msi", ".lnk", ".bat", ".cmd"):
                            dest_file = os.path.join(dest_dir, os.path.basename(exe_src))
                            do_copy = True
                            if os.path.exists(dest_file):
                                try:
                                    s1, s2 = os.stat(exe_src), os.stat(dest_file)
                                    if s1.st_size == s2.st_size and abs(s1.st_mtime - s2.st_mtime) < 1.0:
                                        do_copy = False
                                except Exception:
                                    pass
                            if do_copy:
                                try:
                                    copy2(exe_src, dest_file)
                                except Exception as e:
                                    self.safe_messagebox_warning(
                                        self,
                                        self.tr("Executable Copy"),
                                        self.tr(
                                            "Failed to copy executable:\n{exe_src}\n→ {dest_file}\n\n{e}\n\n"
                                            "Entry will keep the original path."
                                        ).format(exe_src=exe_src, dest_file=dest_file, e=e),
                                    )
                                    entry["Executable Path"] = exe_src
                                else:
                                    entry["Executable Path"] = _rel_to_root(dest_file, software_root)
                            else:
                                entry["Executable Path"] = _rel_to_root(dest_file, software_root)
                        else:
                            entry["Executable Path"] = exe_src
                elif exe_path_raw:
                    self.safe_messagebox_warning(
                        self,
                        self.tr("Executable Path"),
                        self.tr("Source not found:\n{exe_path_raw}").format(exe_path_raw=exe_path_raw),
                    )
                    entry["Executable Path"] = exe_path_raw

                # Key Path (optional single file)
                key_path_raw = (entry.get("Key Path") or entry.get("License") or entry.get("Key") or "").strip()
                if key_path_raw:
                    key_src = _expand(key_path_raw)
                    if not os.path.isabs(key_src) and key_src.lower().startswith(("software\\", "software/")):
                        key_src = _expand(key_src[9:])
                    if key_src and os.path.exists(key_src):
                        if _under_root(key_src, software_root):
                            entry["Key Path"] = _rel_to_root(key_src, software_root)
                        else:
                            if os.path.isfile(key_src):
                                dest_key = os.path.join(dest_dir, os.path.basename(key_src))
                                do_copy = True
                                if os.path.exists(dest_key):
                                    try:
                                        s1, s2 = os.stat(key_src), os.stat(dest_key)
                                        if s1.st_size == s2.st_size and abs(s1.st_mtime - s2.st_mtime) < 1.0:
                                            do_copy = False
                                    except Exception:
                                        pass
                                if do_copy:
                                    try:
                                        copy2(key_src, dest_key)
                                    except Exception as e:
                                        self.safe_messagebox_warning(
                                        self,
                                        self.tr("Key Copy"),
                                        self.tr(
                                            "Failed to copy key file:\n{key_src}\n→ {dest_key}\n\n{e}\n\n"
                                            "Entry will keep the original path."
                                        ).format(key_src=key_src, dest_key=dest_key, e=e),)

                                        entry["Key Path"] = key_src
                                    else:
                                        entry["Key Path"] = _rel_to_root(dest_key, software_root)
                                else:
                                    entry["Key Path"] = _rel_to_root(dest_key, software_root)
                            else:
                                entry["Key Path"] = key_src
                    else:
                        self.safe_messagebox_warning(
                            self,
                            self.tr("Key Path"),
                            self.tr("Path not found:\n{key_path_raw}").format(key_path_raw=key_path_raw),
                        )
                        entry["Key Path"] = key_path_raw

    except Exception:
        # don’t block saving if attachment logic fails
        log.exception("[UI ADD] software attachment handling failed")

    # ---- Persist (ALWAYS runs on accept) ---------------------------------------
    try:
        add_vault_entry(username, self.userKey, entry)
        log.debug("%s [UI OPEN] Added entry to vault", kql.i('ui'))
    except Exception:
        log.exception("[UI ADD] Persist failed")
        QMessageBox.critical(self, self.tr("Vault"), self.tr("Could not save the entry."))
        return

    # ---- Post-save UI / baseline / refresh ------------------------------------
    try:
        self._on_any_entry_changed()
    except Exception:
        pass

    try:
        update_baseline(username=username, verify_after=False, who=f"Added Entry To Vault")
    except Exception:
        pass

    try:
        if "category" in entry:
            self.categorySelector_2.setCurrentText(entry.get("category", "Passwords"))
    except Exception:
        pass

    try:
        # some builds require username param
        if self.load_vault_table.__code__.co_argcount >= 2:
            self.load_vault_table(username)
        else:
            self.load_vault_table()
    except Exception as e:
        log.error("%s [ERROR] Failed to refresh vault table: %s", kql.i('ui'), e)

    try:
        QtWidgets.QMessageBox.information(self, self.tr("Vault"), self.tr("Entry added successfully."))
    except Exception:
        pass

    self.set_status_txt(self.tr("Done"))

# --- open security prefs window (allows add or remove programes)


def user_field_meta_for_category(self, category: str) -> list[dict]:
    """
    Return normalized field metadata for the given category.  The lookup
    order is:

    1. Active user's schema (``category_schema`` in user_db) – use field
       definitions for the matching category.
    2. Built-in defaults from ``auth.category_fields`` (if available).
    3. Application-specific defaults via ``_default_fields_for_category``.
    4. Minimal fallback with a small set of generic fields.

    This ensures that meta is never empty, preventing the vault table from
    returning early when encountering new or unknown categories.
    """
    # Normalize category name
    cat_norm = (category or "").strip().lower()

    # 1) Per-user schema
    try:
        uname = ""
        if hasattr(self, "currentUsername") and self.currentUsername:
            uname = (self.currentUsername.text() or "").strip()
        uname = (self.currentUsername.text() or "").strip()
        if uname:
            schema = get_user_setting(uname, "category_schema") or {}
            cats = schema.get("categories") or []
            for c in cats:
                if not isinstance(c, dict):
                    continue
                name = (c.get("name") or "").strip()
                if name.lower() != cat_norm:
                    continue
                fields = c.get("fields") or []
                out: list[dict] = []
                for f in fields:
                    if isinstance(f, str):
                        label = f.strip()
                        if not label:
                            continue
                        low = label.lower()
                        out.append({
                            "label": label,
                            "sensitive": low in {"password","pin","cvv","secret","key"},
                            "hide": False,
                            "url": low in {"url","website","site"},
                            "file_load": False,
                        })
                    elif isinstance(f, dict):
                        label = (f.get("label") or f.get("name") or "").strip()
                        if not label:
                            continue
                        out.append({
                            "label": label,
                            "sensitive": bool(f.get("sensitive") or f.get("hide")),
                            "hide": bool(f.get("hide")),
                            "url": bool(f.get("url")),
                            "file_load": bool(f.get("file_load")),
                        })
                if out:
                    return out
    except Exception as e:
        # Log and continue to fallback
        try:
            log.error(str(f"[DEBUG] user_field_meta_for_category user_db path failed: {e}"))
        except Exception:
            pass

    # 2) Built-in category definitions (legacy)
    try:
        from catalog_category.category_fields import get_fields_for, preferred_url_fields  
        fields = get_fields_for(category)
        urls = {s.lower() for s in preferred_url_fields(category)}
        out: list[dict] = []
        for lbl in fields:
            low = lbl.lower()
            out.append({
                "label": lbl,
                "sensitive": low in {"password","pin","cvv","secret","key"},
                "hide": False,
                "url": low in urls or low in {"url","website","site"},
                "file_load": False,
            })
        if out:
            return out
    except Exception:
        # Ignore and continue to next fallback
        pass

    # 3) Global category definitions from category_editor
    try:
        # Some categories may be defined in a shared schema via category_editor;
        # use those field definitions if available.  Note: we avoid
        # importing heavy UI modules unless necessary.
        from catalog_category.category_editor import load_schema as _load_global_schema
        schema = _load_global_schema()
        for c in (schema.get("categories") or []):
            if not isinstance(c, dict):
                continue
            name = (c.get("name") or "").strip().lower()
            if name != cat_norm:
                continue
            fields = c.get("fields") or []
            out: list[dict] = []
            for f in fields:
                if isinstance(f, str):
                    label = f.strip()
                    if not label:
                        continue
                    low = label.lower()
                    out.append({
                        "label": label,
                        "sensitive": low in {"password","pin","cvv","secret","key"},
                        "hide": False,
                        "url": low in {"url","website","site"},
                        "file_load": False,
                    })
                elif isinstance(f, dict):
                    label = (f.get("label") or f.get("name") or "").strip()
                    if not label:
                        continue
                    low = label.lower()
                    out.append({
                        "label": label,
                        "sensitive": bool(f.get("sensitive") or f.get("hide")),
                        "hide": bool(f.get("hide")),
                        "url": bool(f.get("url")) or low in {"url","website","site"},
                        "file_load": bool(f.get("file_load")),
                    })
            if out:
                return out
    except Exception:
        pass

    # 4) Application-specific defaults via _default_fields_for_category
    try:
        if hasattr(self, "_default_fields_for_category"):
            fields = self._default_fields_for_category(category) or []
            out: list[dict] = []
            for f in fields:
                if isinstance(f, str):
                    label = f
                elif isinstance(f, dict):
                    label = f.get("label") or f.get("name") or ""
                else:
                    label = ""
                label = label.strip()
                if not label:
                    continue
                low = label.lower()
                out.append({
                    "label": label,
                    "sensitive": low in {"password","pin","cvv","secret","key"},
                    "hide": False,
                    "url": low in {"url","website","site"},
                    "file_load": False,
                })
            if out:
                return out
    except Exception:
        pass

    # 5) Final minimal fallback: use a small generic field set
    default_fields = ["Title", "Username", "Password", "URL", "Notes"]
    out: list[dict] = []
    for lbl in default_fields:
        low = lbl.lower()
        out.append({
            "label": lbl,
            "sensitive": low in {"password","pin","cvv","secret","key"},
            "hide": False,
            "url": low in {"url","website","site"},
            "file_load": False,
        })
    return out
   

# ==============================
# --- on double item click edit that item 



def _get_selected_entry(self, *args, **kwargs) -> dict | None:
    """
    Return a dict for the selected vault row.

    Guaranteed keys:
      - title, username, email, password, category, _row

    Extra:
      - merges all column values from the row (e.g. Platform, Install Link,
        Game Name, URL, etc.) so features like auto-launch can use them.
    """
    tbl = getattr(self, "vaultTable", None)
    if tbl is None:
        return None

    sel = tbl.selectionModel().selectedRows() if tbl.selectionModel() else []
    if not sel:
        idx = tbl.currentIndex()
        if idx and idx.isValid():
            sel = [idx.sibling(idx.row(), 0)]
        else:
            return None

    row = sel[0].row()

    # ---------- Helper: detect masked-looking values ----------
    def _looks_masked(s: str | None) -> bool:
        if not s:
            return False
        # handle *, •, ● etc.
        mask_chars = {"*", "•", "●"}
        return all(ch in mask_chars for ch in s) and len(s) >= 4

    def _canonical_header_role(text: str | None) -> str | None:
        from app.app_translation_fields import (
            USERNAME_HEADER_LABELS,
            EMAIL_LABELS,
            PRIMARY_PASSWORD_LABELS,
        )
        t = (text or "").strip().lower()
        if not t:
            return None
        if t in USERNAME_HEADER_LABELS:
            return "username"
        if t in EMAIL_LABELS:
            return "email"
        if t in PRIMARY_PASSWORD_LABELS or "pass" in t:
            return "password"
        # Fallback heuristics – English-ish
        if "user" in t and "id" not in t and "guid" not in t:
            return "username"
        if "mail" in t:
            return "email"
        if "pwd" in t:
            return "password"
        return None

    def _is_password_header(text: str | None) -> bool:
        return _canonical_header_role(text) == "password"

    # ---------- Try to read a full dict from any column's UserRole ----------
    for c in range(tbl.columnCount()):
        item = tbl.item(row, c) if hasattr(tbl, "item") else None
        data = None
        if item is not None:
            data = item.data(Qt.UserRole)
        else:
            model = getattr(tbl, "model", lambda: None)()
            if model:
                data = model.data(model.index(row, c), Qt.UserRole)

        if isinstance(data, dict) and data:
            # ensure _row is present
            d = dict(data)
            d.setdefault("_row", row)
            return d

    # ---------- Otherwise, build it from headers / cell text ----------
    title = ""
    username = ""
    email = ""
    password = ""

    try:
        # First pass: pick up obvious username/email/password by header role
        pw_col = None
        for col in range(tbl.columnCount()):
            header = tbl.horizontalHeaderItem(col)
            header_txt = header.text() if header else ""
            role = _canonical_header_role(header_txt)

            item = tbl.item(row, col)
            cell_txt = item.text() if item else ""

            if role == "username" and not username:
                username = (cell_txt or "").strip()
            elif role == "email" and not email:
                email = (cell_txt or "").strip()
            elif role == "password":
                pw_col = col

        # Second pass: title/name heuristics
        for col in range(tbl.columnCount()):
            header = tbl.horizontalHeaderItem(col)
            htxt = (header.text() if header else "").strip().lower()
            item = tbl.item(row, col)
            cell_txt = (item.text() if item else "").strip()

            if not title and htxt in {"title", "name", "game name", "site", "website"}:
                title = cell_txt

            # If we still don't have username/email, try simple guesses
            if not username and "user" in htxt:
                username = cell_txt
            if not email and ("mail" in htxt or "e-mail" in htxt):
                email = cell_txt

        # Password: prefer Qt.UserRole to avoid masked text
        if pw_col is not None:
            pw_item = tbl.item(row, pw_col)
            pw_data = pw_item.data(Qt.UserRole) if pw_item else None
            if isinstance(pw_data, str) and pw_data:
                password = pw_data
            elif isinstance(pw_data, dict):
                password = (
                    pw_data.get("password")
                    or pw_data.get("_password")
                    or pw_data.get("real_password")
                    or pw_data.get("plain_password")
                    or password
                )
            else:
                cell_txt = pw_item.text() if pw_item else ""
                if not _looks_masked(cell_txt):
                    password = cell_txt.strip()
    except Exception:
        pass

    # Category from UI if available
    category = getattr(self, "currentCategory", None) or getattr(
        self, "categorySelector_2", None
    )
    if hasattr(category, "currentText"):
        category = category.currentText()
    category = (category or "").strip()

    base = {
        "title": title,
        "username": username,
        "email": email,
        "password": password,
        "category": category,
        "_row": row,
    }

    # ---------- Merge full row dict (Platform, Install Link, etc.) ----------
    row_meta = {}
    try:
        if hasattr(self, "_get_row_entry_dict"):
            row_meta = self._get_row_entry_dict(row) or {}
    except Exception:
        row_meta = {}

    if isinstance(row_meta, dict):
        for k, v in row_meta.items():
            # don't overwrite the canonical keys we just computed
            if k not in base and v is not None:
                base[k] = v

    return base



def load_vault_table(self, *args, **kwargs):
    self.set_status_txt(self.tr("loading Vault Table"))
    log.debug(str(f"{kql.i('vault')} [VAULT] Loading vault table..."))
    self.vaultSearchBox.clear()
    self.reset_logout_timer()
    try:
        if not hasattr(self, "userKey") or self.userKey is None:
            log.debug(str(f"{kql.i('vault')} [VAULT] No user key found; cannot load vault table."))
            return

        # Load entries
        all_entries = load_vault(self.currentUsername.text(), getattr(self, 'core_session_handle', None) or self.userKey)

        # Which category are we showing?
        category = self.categorySelector_2.currentText() if hasattr(self, "categorySelector_2") else "Passwords"

        # --- Build headers from schema meta ---
        # meta = field_meta_for_category(category)  old
        meta = self.user_field_meta_for_category(category)
        if not meta:
            log.debug(str(f"{kql.i('vault')} [VAULT] No meta for category {category}"))
            return

        headers = [m["label"] for m in meta if not m.get("hide")]
        if "Date" not in headers:
            headers.append("Date")

        sensitive_set = {m["label"].lower() for m in meta if m.get("sensitive")}
        # (Optional) also respect legacy sensitive keywords
        try:
            from catalog_category.category_fields import sensitive_data_values
            for s in sensitive_data_values():
                sensitive_set.add(s.lower())
        except Exception:
            pass

        # --- Expiration days (read via settings API) ---
        try:
            # Canonicalize (case-insensitive) if helper exists
            raw_name = (self.currentUsername.text() or "").strip()
            if not raw_name:
                raise ValueError("No username specified.")

            try:
                username = _canonical_username_ci(raw_name) or raw_name
            except Exception:
                username = raw_name

            expiration_days = int(get_user_setting(username, "password_expiry_days", 180))
            expiration_threshold = timedelta(days=expiration_days)
            log.debug(
                f"{kql.i('vault')} [VAULT] Loaded expiration days: {expiration_threshold} for user {username}"
            )
        except Exception as e:
            log.error(f"{kql.i('vault')} [ERROR] Failed to load expiry threshold: {e}")
            expiration_days = 180

        # Expand headers: add 👁 after each sensitive field
        expanded_headers = []
        sensitive_fields = []
        for h in headers:
            expanded_headers.append(h)
            if h.lower() in sensitive_set:
                expanded_headers.append("👁")
                sensitive_fields.append(h)
        expanded_headers.append("Password Expired")

        # Prepare table
        self.vaultTable.clear()
        self.vaultTable.setColumnCount(len(expanded_headers))
        self.vaultTable.setHorizontalHeaderLabels(expanded_headers)
        self.vaultTable.setRowCount(0)
        self.vaultTable.setColumnWidth(1, 300)   # Website column  
        self.vaultTable.setColumnWidth(0, 250)    # Title column 
        self.current_entries_indices = []
        row_index = 0
        password_map = {}
        self.reset_logout_timer()
        if all_entries:
            sample = all_entries[0]

        for idx, entry in enumerate(all_entries):
            if entry.get("category", "Passwords").lower() != category.lower():
                continue

            self.vaultTable.insertRow(row_index)
            self.current_entries_indices.append(idx)
            col_offset = 0
            for col, header in enumerate(headers):
                value = entry.get(header, "")
                low_h = header.lower()
                is_sensitive = (low_h in sensitive_set)

                masked_value = "●●●●●●●●" if is_sensitive and value else str(value)
                item = QTableWidgetItem(masked_value)

                if is_sensitive:
                    # store real value in UserRole
                    item.setData(int(Qt.ItemDataRole.UserRole), value)
                    # track reused sensitive values
                    if value:
                        password_map.setdefault(value, []).append((row_index, col + col_offset))

                self.vaultTable.setItem(row_index, col + col_offset, item)

                if is_sensitive:
                    toggle_btn = QPushButton(self.tr("👁"))
                    toggle_btn.setFixedWidth(40)

                    def make_toggle_func(r=row_index, c=col + col_offset):
                        def toggle():
                            it = self.vaultTable.item(r, c)
                            if it:
                                real = it.data(int(Qt.ItemDataRole.UserRole))
                                if not real:
                                    return
                                it.setText(real if it.text().startswith("●") else "●●●●●●●●")
                        return toggle

                    toggle_btn.clicked.connect(make_toggle_func())
                    self.vaultTable.setCellWidget(row_index, col + col_offset + 1, toggle_btn)
                    col_offset += 1

            # Password expiration status (text-only; no row background, no popups)
            if "Date" in entry:
                try:
                    date_obj = dt.datetime.strptime(str(entry["Date"]).strip(), "%Y-%m-%d")
                    age = dt.datetime.now() - date_obj
                    expired = age > expiration_threshold
                    days_left = (expiration_threshold - age).days  # can be negative if already expired

                    expired_item = QTableWidgetItem(self.tr("❌ True") if expired else self.tr("✅ False"))
                    expired_item.setTextAlignment(Qt.AlignCenter)

                    # text-only coloring
                    if expired:
                        expired_item.setForeground(QBrush(QColor(Qt.GlobalColor.red)))
                    elif days_left < 30:
                        expired_item.setForeground(QBrush(QColor(Qt.GlobalColor.darkYellow)))
                    else:
                        expired_item.setForeground(QBrush(QColor(Qt.GlobalColor.green)))

                    # put it in the last column (Password Expired)
                    self.vaultTable.setItem(row_index, self.vaultTable.columnCount() - 1, expired_item)

                except Exception:
                    self.vaultTable.setItem(row_index, self.vaultTable.columnCount() - 1,
                                            QTableWidgetItem("Invalid"))
            else:
                self.vaultTable.setItem(row_index, self.vaultTable.columnCount() - 1,
                                        QTableWidgetItem("Unknown"))
            row_index += 1
            self.reset_logout_timer()

        # Highlight reused sensitive values (e.g., reused passwords)
        for pw, coords in password_map.items():
            if len(coords) > 1:
                for r, c in coords:
                    it = self.vaultTable.item(r, c)
                    if it:
                        it.setForeground(QBrush(QColor(Qt.GlobalColor.red)))

        self.reset_logout_timer()
        log.debug(f"{kql.i('vault')} [VAULT] {kql.i('ok')} Vault Loaded OK")
    except Exception as e:
        log.error(str(f"{kql.i('vault')} [VAULT] loading vault table: {e}"))




def import_vault_with_password(self, *args, **kwargs):
    """
    Import a password-protected .kqbk vault backup into the *current* Keyquorum account.

    What this does:
    - Asks you to pick an encrypted vault backup file (.kqbk).
    - Asks for the password you chose when you created that backup.
    - Replaces ALL existing items in this account with the backup contents
      (this is a full restore, not a merge).

    Important:
    - Vault backups are still cryptographically linked to the account they were
      created from. They can only be restored into that same Keyquorum account.
    - If the backup does not belong to this account (identity mismatch), or if
      the password is wrong or the file is damaged, the import will fail.
    """
    from qtpy.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox
    from vault_store.vault_store import import_vault_with_password as _import_fn

    self.set_status_txt(self.tr("Importing vault backup"))
    self.reset_logout_timer()

    username = (self.currentUsername.text() or "").strip()
    if not username:
        self.safe_messagebox_warning(
            self,
            "Import Vault Backup",
            "Please sign in to your Keyquorum account before importing a vault backup.",
        )
        return

    # Clear, explicit warning about destructive replace
    warn = QMessageBox.warning(
        self,
        "Replace vault with backup?",
        (
            "You are about to restore an encrypted vault backup into this Keyquorum account.\n\n"
            "• All existing items in this account will be replaced by the items from the backup.\n"
            "• If you want to keep your current items as well, export them to CSV first, "
            "then run this import, and finally import the CSV to add them back.\n\n"
            "Note: This backup is still linked to the Keyquorum account it was created from. "
            "It can only be restored into that same account.\n\n"
            "Do you want to continue?"
        ),
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No,
    )
    if warn != QMessageBox.Yes:
        return

    # Re-auth for sensitive action (YubiKey gate or password + 2FA)
    if not self.verify_sensitive_action(username, title="Confirm Import"):
        return

    # Let the user choose the backup file
    file_path, _ = QFileDialog.getOpenFileName(
        self,
        "Select Encrypted Vault Backup",
        "",
        "Encrypted Vault (*.kqbk)",
    )
    if not file_path:
        return

    # Ask for the password that was used when the backup was created
    password, ok = QInputDialog.getText(
        self,
        self.tr("Vault Backup Password"),
        self.tr("Enter the password you used when you created this vault backup:"),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not password:
        return

    # Perform the import
    self.set_status_txt(self.tr("Importing vault backup…"))
    ok = bool(_import_fn(username, password, file_path))
    self.reset_logout_timer()

    if ok:
        # Only log success if the import actually worked
        try:
            update_baseline(username=username, verify_after=False, who=self.tr("Imported Encrypted Vault (.kqbk)"))
        except Exception:
            pass

        QMessageBox.information(
            self,
            self.tr("Import complete"),
            self.tr("Vault backup imported successfully.\nIf you don’t see the updated items or categories straight away, \nplease sign out and sign back in."),)
        try:
            self.refresh_category_selector()
            self.refresh_category_dependent_ui()
            self.load_vault_table()
            self._auth_reload_table()
            self.set_status_txt(self.tr("Vault backup imported"))
        except Exception:
            pass
    else:
        # Clear, user-friendly explanation of what may have gone wrong
        self.set_status_txt(self.tr("Vault import failed"))
        self.safe_messagebox_warning(
            self,
            self.tr("Vault import failed"),
            (self.tr(
                "The encrypted vault backup could not be imported.\n\n"
                "This can happen if:\n"
                "• The vault backup password is incorrect.\n"
                "• The backup file is damaged or incomplete.\n"
                "• The backup was created from a different Keyquorum account and the "
                "account identity does not match this one.\n\n"
                "What you can try:\n"
                "1) Double-check the backup password.\n"
                "2) If you created a FULL backup (ZIP) around the same time as this vault "
                "backup, restore the full backup first and then try this vault-only "
                "backup again.\n"
                "3) Make sure you are signed in to the same Keyquorum account that originally "
                "created this vault backup.")
            ),
        )

# ==============================
# --- export/import software folder only (Not part of full backup) ------------------
# ==============================


def _autofill_split_flow(self, entry, *, hwnd=None, title_re: str = "", pid=None) -> bool:
    """
    Two-stage flow: identifier (email preferred, else username) -> Next -> wait -> password -> submit.
    Returns True on success.
    """
    # Lazy-import pywinauto and keyboard
    try:
        from pywinauto.keyboard import send_keys
        from pywinauto.findwindows import ElementNotFoundError
    except Exception:
        QMessageBox.warning(self, "Auto-fill",
                            "pywinauto is not installed in this build. Please install it to use desktop autofill.")
        return False

    email = (entry.get("email") or "").strip()
    username = (entry.get("username") or "").strip()
    password = (entry.get("password") or "").strip()

    ident_val = email or username
    if not ident_val or not password:
        QMessageBox.warning(self, self.tr("Auto-fill"), self.tr("This entry needs an email/username and a password."))
        return False

    # Connect + focus
    target = self._connect_window(hwnd=hwnd, title_re=title_re, pid=pid)
    try:
        target.set_focus()
    except Exception:
        pass
    _t.sleep(0.05)

    # --- Stage 1: fill identifier (EMAIL first, fallback to USERNAME) ---
    id_edit = None
    if email:
        id_edit = self._find_email_edit(target)  # prefer explicit email control
    if not id_edit:
        id_edit = self._find_username_edit(target)  # generic user/identifier field
    if not id_edit:
        QMessageBox.information(self, self.tr("Auto-fill"), self.tr("Could not locate the email/username field in the target app."))
        return False

    try:
        id_edit.wait("ready", timeout=1)
    except Exception:
        pass
    self._clear_and_type(id_edit, ident_val, is_password=False)

    # Click Next (or Enter)
    pressed_next = False
    btn_next = self._find_next_button(target)
    if btn_next:
        try:
            btn_next.click_input()
            pressed_next = True
        except Exception:
            pass
    if not pressed_next:
        try:
            id_edit.set_focus()
        except Exception:
            pass
        send_keys("{ENTER}", pause=0.002)

    # --- Stage 2: wait for password, then fill ---
    pw_edit = None
    deadline = _t.time() + 8.0
    while _t.time() < deadline:
        try:
            target = self._connect_window(hwnd=hwnd, title_re=title_re, pid=pid)
            pw_edit = self._find_password_edit(target)
            if pw_edit:
                try:
                    pw_edit.wait("ready", timeout=1)
                except Exception:
                    pass
                self._clear_and_type(pw_edit, password, is_password=True)
                break
        except Exception:
            pass
        _t.sleep(0.2)

    if not pw_edit:
        QMessageBox.information(
            self, self.tr("Auto-fill"),
            self.tr("Identifier filled. Waiting for password field timed out—please press Next and try again.")
        )
        return False

    # Submit
    btn_submit = self._find_submit_button(target)
    if btn_submit:
        try:
            btn_submit.click_input()
        except Exception:
            try:
                pw_edit.set_focus()
            except Exception:
                pass
            send_keys("{ENTER}", pause=0.002)
    else:
        try:
            pw_edit.set_focus()
        except Exception:
            pass
        send_keys("{ENTER}", pause=0.002)

    try:
        self._toast("Filled email/username, waited for password, and signed in.")
    except Exception:
        pass
    return True
    
def delete_selected_vault_entry(self, *args, **kwargs):
    self.set_status_txt(self.tr("Delete selected vault entry"))
    log.debug(str(f"{kql.i('vault')} [VAULT] delete selected vault entry"))
    self.reset_logout_timer()

    try:
        tbl = self.vaultTable
        row = tbl.currentRow()
        if row < 0:
            return

        # Map visible row -> real vault index
        try:
            global_index = self.current_entries_indices[row]
        except Exception:
            global_index = row

        # nice name in the prompt
        title_col = self._find_col_by_labels({"title", "site", "website", "name"})
        entry_name = ""
        try:
            if isinstance(title_col, int) and title_col >= 0:
                it = tbl.item(row, title_col)
                entry_name = (it.text() if it else "").strip()
        except Exception:
            pass

        # Build a 3-option dialog: Trash / Delete Permanently / Cancel
        box = QtWidgets.QMessageBox(self)
        box.setIcon(QtWidgets.QMessageBox.Icon.Warning)
        box.setWindowTitle(self.tr("Delete Entry"))
        msg = self.tr("Delete this entry?")
        if entry_name:
            msg = self.tr('Delete "{entry_name}"?').format(entry_name=entry_name)
        box.setText(msg)

        btn_trash = box.addButton(self.tr("Move to Trash (30 days)"), QtWidgets.QMessageBox.ButtonRole.AcceptRole)
        btn_perm  = box.addButton(self.tr("Delete Permanently"), QtWidgets.QMessageBox.ButtonRole.DestructiveRole)
        btn_cancel= box.addButton(self.tr("Cancel"), QtWidgets.QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(btn_trash)
        box.exec()

        clicked = box.clickedButton()
        if clicked is btn_cancel:
            return

        username = self.currentUsername.text()
        key=(getattr(self, 'core_session_handle', None) or self.userKey)

        ok = False
        if clicked is btn_trash:
            # Soft delete → goes to encrypted trash with timestamp
            try:
                ok, err = self.soft_delete_entry(username, key, global_index)
                if not ok:
                    # Show the specific reason (helps debug)
                    try:
                        QtWidgets.QMessageBox.warning(
                            self,
                            self.tr("Move to Trash"),
                            self.tr("Could not move this entry to Trash.") + (f"{err}" if err else ""))
                    except Exception:
                        pass
            except Exception as e:
                log.error(f"[Trash] soft delete failed: {e}")
                ok = False
            if ok:
                try:
                    # purge old trash items now
                    purged = self.purge_trash(username, key, max_age_days=30)
                    if purged:
                        log.debug(f"[Trash] auto-purged {purged} old trashed item(s)")
                except Exception:
                    pass
        else:
            # Permanent delete
            try:
                delete_vault_entry(username, key, global_index)
                self._on_any_entry_changed()
                ok = True
            except TypeError:
                # some versions require extra arg
                delete_vault_entry(username, key, global_index)
                self._on_any_entry_changed()
                ok = True
            except Exception as e:
                log.error(f"[VAULT] hard delete failed: {e}")
                ok = False

        # Refresh UI
        if ok:
            try: 
                update_baseline(username=username, verify_after=False, who=f"Delete Entry From Vault")
            except Exception: pass
            try: self.load_vault_table()
            except Exception: pass
            try:
                if hasattr(self, "_watchtower_rescan"):
                    self._watchtower_rescan()
            except Exception:
                pass

            # Tiny toast
            try:
                if clicked is btn_trash:
                    self._toast(self.tr("Moved to Trash (kept up to 30 days)."))
                else:
                    self._toast(self.tr("Entry deleted permanently."))
            except Exception:
                pass
        else:
            QtWidgets.QMessageBox.critical(self, self.tr("Delete"), self.tr("Could not delete this entry."))
        log.debug(str(f"{kql.i('vault')} [VAULT] Removed from vault (ok={ok})"))
    except Exception as e:
        self.reset_logout_timer()
        log.error(str(f"{kql.i('vault')} [ERROR] {kql.i('err')} deleting vault entry: {e}"))
        QtWidgets.QMessageBox.warning(self, self.tr("Error"), self.tr("Failed to delete the selected entry. Please try again."))

# ------------------------
# --- update tabe when category is changed

def _quick_move_row_to_category(self, row: int, new_type: str) -> bool:
    """Move without opening the edit dialog: auto-map fields, set category, persist."""
    try:
        # refuse if target is protected
        if self._is_blocked_target(new_type):
            log.debug("[MOVE] target category blocked")
            return False
        # refuse if source is protected
        try:
            if self._is_blocked_source(self._category_for_row(row)):
                log.debug("[MOVE] source category blocked")
                return False
        except Exception:
            pass
        
        try:
            entries = load_vault(self.currentUsername.text(), getattr(self, 'core_session_handle', None) or self.userKey)
            try:
                global_index = self.current_entries_indices[row]
            except Exception:
                global_index = row
            src = entries[global_index]
        except Exception as e:
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} load entry failed: {e}"))
            return False

        # --- automap to target schema (user-defined labels) ---
        def norm(s): return "".join(ch for ch in (s or "").lower().strip() if ch.isalnum())
        synonyms = {
            "username": {"user", "login", "account", "accountname", "userid"},
            "email": {"mail", "emailaddress"},
            "password": {"pass", "passwd"},
            "website": {"url", "link", "domain"},
            "phone": {"phonenumber", "mobile", "tel", "telephone"},
            "2faenabled": {"twofactor", "mfa", "2fa"},
            "platform": {"store", "launcher", "service"},
            "gamename": {"title", "name"},
        }

        try:
            tgt_fields = self._user_schema_field_labels(new_type)
        except Exception:
            tgt_fields = []
        tgt_lc = {norm(f): f for f in tgt_fields if isinstance(f, str)}

        # source normalized map (+synonyms)
        src_norm = {}
        for k, v in (src or {}).items():
            if not isinstance(k, str):
                continue
            nk = norm(k)
            src_norm[nk] = v
            for canon, alts in synonyms.items():
                if nk == canon or nk in alts:
                    src_norm[canon] = v
                    for a in alts:
                        src_norm[a] = v

        new_entry = {}
        used = set()
        # fill by target field names first
        for nk, orig in tgt_lc.items():
            if nk in src_norm:
                new_entry[orig] = src_norm[nk]; used.add(nk)
            else:
                # try synonyms for each target name
                for canon, alts in synonyms.items():
                    if nk == canon or nk in alts:
                        for cand in {canon, *alts}:
                            if cand in src_norm:
                                new_entry[orig] = src_norm[cand]
                                used.add(cand)
                                break

        # push any leftover info into Notes
        extras = {k: v for k, v in (src or {}).items()
                  if isinstance(k, str) and norm(k) not in used
                  and norm(k) not in {"notes", "date", "category", "type", "createdat"} and v not in (None, "")}
        note = str(src.get("Notes") or src.get("notes") or "")
        if extras:
            note = (note + ("\n\n" if note else "") +
                    "[Unmatched Fields]\n" + "\n".join(f"{k}: {v}" for k, v in extras.items()))
        if note:
            notes_key = next((f for f in tgt_fields if norm(f) == "notes"), "Notes")
            new_entry[notes_key] = note

        # force category/type/date
        new_entry["category"] = new_type
        new_entry["Type"] = new_type
        new_entry["Date"] = dt.datetime.now().strftime("%Y-%m-%d")
        from features.watchtower.watchtower_helpers import persist_entry_with_history
        persist_entry_with_history(self, self.currentUsername.text(), self.userKey, global_index, new_entry)

        # refresh UI
        try:
            
            update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Moved Entry In Vault"))
        except Exception:
            pass
        try:
            self.load_vault_table()
        except Exception:
            pass
        return True
    except Exception as e:
        log.error(str(f"{kql.i('update')} [ERROR] {kql.i('warn')} quick move failed: {e}"))
        return False



def _watch_local_vault(self, *args, **kwargs):
    """
    Call after successful login. Watches the vault file AND its parent dir so we
    survive atomic replaces. Re-adds the file path when Qt drops it.
    Uses _schedule_auto_sync() for debounced auto-sync, and avoids loops by
    honoring self._sync_guard (set during our own push/pull).
    """
    try:
        import os
        from qtpy.QtCore import QFileSystemWatcher

        username = self._active_username()
        if not username:
            return

        vault_path = str(vault_file(username, ensure_parent=True))
        parent_dir = os.path.dirname(vault_path) or "."

        # --- (Re)create watcher cleanly ---
        old = getattr(self, "_vault_watcher", None)
        if old is not None:
            try:
                # Best-effort detach old paths
                files = []
                try:
                    files = list(old.files())
                except Exception:
                    pass
                for p in files:
                    try:
                        old.removePath(p)
                    except Exception:
                        pass
                try:
                    old.deleteLater()
                except Exception:
                    pass
            except Exception:
                pass

        self._vault_watcher = QFileSystemWatcher(self)

        # Add parent dir first (to detect replaces/renames/creates)
        if os.path.isdir(parent_dir):
            try:
                self._vault_watcher.addPath(parent_dir)
            except Exception:
                pass

        # Add file if it exists now; if not, the dir watch will catch its creation
        if os.path.exists(vault_path):
            try:
                self._vault_watcher.addPath(vault_path)
            except Exception:
                pass

        def _ensure_paths():
            """Re-add file if Qt dropped it after a replace; keep dir watched."""
            try:
                # Re-add parent dir if needed
                try:
                    if parent_dir and (parent_dir not in self._vault_watcher.directories()):
                        self._vault_watcher.addPath(parent_dir)
                except Exception:
                    pass

                # Re-add file if it exists but isn't being watched
                try:
                    if os.path.exists(vault_path) and (vault_path not in self._vault_watcher.files()):
                        self._vault_watcher.addPath(vault_path)
                except Exception:
                    pass
            except Exception:
                pass

        def _on_file_changed(_path):
            # Avoid loops from our own writes
            if getattr(self, "_sync_guard", False):
                return
            _ensure_paths()
            self._schedule_auto_sync()

        def _on_dir_changed(_path):
            # Parent changed; ensure file is (re)watched and schedule sync if relevant
            _ensure_paths()
            # Only schedule if we’re logged in & have key; _schedule_auto_sync() already checks.
            self._schedule_auto_sync()

        # Connect signals
        self._vault_watcher.fileChanged.connect(_on_file_changed)
        self._vault_watcher.directoryChanged.connect(_on_dir_changed)

    except Exception as e:
        try:
            import logging
            logging.getLogger(__name__).warning(f"[WATCH] setup failed: {e}")
        except Exception:
            pass



def on_copy_vault_to_cloud(self, *args, **kwargs):
    # Provide a literal message so Qt translator can pick it up
    self.set_status_txt(self.tr("Copying vault to user cloud"))
    """
    Copy the local vault to a cloud-synced folder the user selects.
    - Shows a one-time security warning about cloud risk.
    - Offers to enable extra cloud wrapping (recommended) if it's off.
    - Persists the cloud target and reconfigures the sync engine.
    """
    self.reset_logout_timer()

    username = self._active_username() if hasattr(self, "_logged_in_username") else None
    if not username:
        QMessageBox.warning(self, self.tr("Copy to Cloud"), self.tr("Please log in first."))
        return

    # Load current cloud profile (for wrap status)
    try:
        prof = get_user_cloud(username) or {}
    except Exception:
        prof = {}
    wrap = bool(prof.get("cloud_wrap"))

    # One-time cloud risk acknowledgement
    cloud_ack = False
    try:
        cloud_ack = bool(get_user_setting(username, "cloud_risk_ack"))
    except Exception:
        cloud_ack = False

    if not cloud_ack:
        accepted, dont_ask, want_wrap = self._show_cloud_risk_modal(current_wrap=wrap)
        if not accepted:
            return
        if dont_ask:
            try:
                set_user_setting(username, "cloud_risk_ack", True)
            except Exception as e:
                log.debug(f"[WARN] Could not persist cloud_risk_ack: {e}")
        if want_wrap and not wrap:
            wrap = True

    # Let user pick the destination folder (cloud-synced)
    sel = QFileDialog.getExistingDirectory(self, "Select your cloud vault folder")
    if not sel:
        return
    folder = sel.replace("\\", "/")

    # Resolve source file
    try:
        local_file = str(vault_file(username, ensure_parent=True))
    except Exception:
        local_file = ""
    if not local_file or not os.path.isfile(local_file):
        QMessageBox.critical(self, self.tr("Copy to Cloud"), self.tr("Local vault file not found."))
        return

    dest_file = os.path.join(folder, os.path.basename(local_file)).replace("\\", "/")

    # Confirm overwrite if target exists
    try:
        if os.path.exists(dest_file):
            ans = QMessageBox.question(
                self, "Overwrite?",
                f"A vault already exists at:\n{dest_file}\n\nOverwrite it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

        # Perform the copy
        os.makedirs(folder, exist_ok=True)
        copy2(local_file, dest_file)
    except Exception as e:
        QMessageBox.critical(self, self.tr("Copy to Cloud"), f"Failed:\n{e}")
        return

    # Persist cloud target + wrap preference
    try:
        set_user_cloud(username, enable=True, provider="localpath", path=dest_file, wrap=wrap)
    except Exception as e:
        QMessageBox.warning(self, self.tr("Copy to Cloud"), f"Failed to set cloud target:\n{e}")
        return

    # Reconfigure engine if present
    try:
        self._configure_sync_engine(username)
    except Exception:
        pass
    update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("OnCloud Extra Wrap Settings Changed")) 
    extra = "\n\nExtra cloud wrapping: ON (recommended)" if wrap else "\n\nExtra cloud wrapping: OFF"
    msg =  self.tr("Vault has been copied to:") + f"\n{dest_file}\n\n" + self.tr("Reminder: Cloud storage increases exposure. Use a strong password and 2FA.") + f"{extra}\n\n" + self.tr("Cloud sync will use this file.")
    QMessageBox.information(
        self, "Copy to Cloud", msg)
    
    self.set_status_txt(self.tr("Done"))

# Helper (include once; skip if you already added it earlier)


def _trash_preview_for_entry(self, e: dict) -> dict:                                                    # - trash preview
    """
    Make a small, human-friendly snapshot so Trash has something to show.
    Never includes secrets.
    """
    def _norm(s): return (s or "").strip()
    cat = _norm(e.get("category") or e.get("Category"))
    keys = {k.lower() for k in e.keys()}

    cat_l = (cat.lower() if cat else "")
    cat_map = {
        "passwords":        "login",
        "software":         "license",
        "email accounts":   "email",
        "social media":     "login",
        "games":            "login",
        "streaming":        "login",
        "credit cards":     "credit_card",
        "banks":            "bank_account",
        "money":            "finance",
        "personal info":    "identity",
        "webfill":          "webform",
        "windows key":      "license",
        "mac":              "device",
        "app":              "login",
        "pins":             "pin",
        "wifi":             "wifi",
        "encrypted drives": "disk",
        "notes":            "note",
        "other":            "other",
        "temp accounts":    "login",
        "vpn config":       "vpn",
        "recovery codes":   "recovery",
        "ssh config":       "ssh",
        "ssh keys":         "ssh",
        "api keys":         "apikey",
        "crypto":           "crypto",
    }
    kind = cat_map.get(cat_l)

    # Heuristics if category missing/unknown
    if not kind:
        if {"card number","card_number","pan"} & keys:
            kind = "credit_card"
        elif {"iban","account","sort code","routing"} & keys:
            kind = "bank_account"
        elif {"otp","totp","2fa","secret"} & keys:
            kind = "otp"
        elif {"ssid"} & keys:
            kind = "wifi"
        elif {"api key","api_key","token","access_key"} & keys:
            kind = "apikey"
        elif {"ssh_private","ssh_public","private_key","public_key"} & keys:
            kind = "ssh"
        else:
            kind = "login"

    # Title (nice defaults for special kinds)
    title = _norm(e.get("title") or e.get("site") or e.get("name"))
    if not title and kind == "credit_card":
        # show brand + last4
        try:
            pan = e.get("card_number") or e.get("Card Number") or e.get("card") or ""
            if hasattr(self, "_card_brand_last4"):
                brand, last4 = self._card_brand_last4(pan)
            else:
                brand, last4 = "Card", _norm(pan)[-4:]
            title = f"{brand} ••••{last4}" if last4 else brand
        except Exception:
            title = "Card"
    if not title and kind == "wifi":
        title = _norm(e.get("ssid") or "Wi-Fi")
    if not title and kind == "license":
        title = _norm(e.get("product") or e.get("software") or "License")
    if not title and kind == "vpn":
        title = _norm(e.get("provider") or e.get("server") or "VPN")
    if not title:
        title = "(untitled)"

    username = _norm(e.get("username") or e.get("user") or e.get("email"))
    url      = _norm(e.get("url") or e.get("origin") or e.get("website"))

    return {"title": title, "username": username, "url": url, "kind": kind}



def _minimal_share_entry(self, src: dict) -> dict:
    """
    Build a minimal, sanitized entry for sharing.
    - Normalizes common aliases
    - Keeps only human-useful fields
    - Avoids duplications ('URL' vs 'Website')
    """
    if not isinstance(src, dict):
        return {}

    # Allow-list of shareable keys
    ALLOW = {
        "category", "Title", "Name", "Username", "Email", "Password",
        "Website", "URL", "Notes", "2FA Enabled", "TOTP", "TOTP Secret",
        "Phone Number", "Backup Code", "IMAP Server", "SMTP Server"
    }
    # Drop noisy/internal keys
    DROP = {
        "Date", "created_at", "updated_at", "_id", "_uid", "__version__", "__meta__",
        "last_viewed", "last_rotated", "history", "history_hashes",
        "Type",  # UI-only
    }

    def _norm(v):
        if v is None:
            return ""
        if isinstance(v, (list, tuple)):
            return ", ".join(_norm(x) for x in v)
        return str(v)

    out = {}
    # First pass: alias mapping to canonical keys
    for k, v in src.items():
        if k in DROP:
            continue
        kl = str(k or "").strip().lower()

        if kl in ("title",):
            out["Title"] = _norm(v)
        elif kl in ("name",):
            out["Name"] = _norm(v)
        elif kl in ("user", "login", "username", "account", "accountname", "userid"):
            out["Username"] = _norm(v)
        elif kl in ("email", "mail", "emailaddress"):
            out["Email"] = _norm(v)
        elif kl in ("password", "pass", "passwd", "secret", "key"):
            out["Password"] = _norm(v)
        elif kl in ("website",):
            out["Website"] = _norm(v)
        elif kl in ("url", "link", "domain", "site"):
            out["URL"] = _norm(v)
        elif kl in ("phone", "phonenumber", "mobile", "tel", "telephone"):
            out["Phone Number"] = _norm(v)
        elif kl in ("backupcode", "backup codes", "backupcodes", "recoverycodes", "recoverycode"):
            out["Backup Code"] = _norm(v)
        elif kl in ("totp", "totpkey", "totpsecret", "2fasecret", "mfa secret", "authsecret"):
            out["TOTP Secret"] = _norm(v)
        elif kl in ("imap", "imapserver"):
            out["IMAP Server"] = _norm(v)
        elif kl in ("smtp", "smtpserver"):
            out["SMTP Server"] = _norm(v)
        elif kl == "notes":
            out["Notes"] = _norm(v)
        elif kl == "category":
            out["category"] = _norm(v)
        else:
            # Preserve any already canonical allow-listed keys
            if k in ALLOW:
                out[k] = _norm(v)

    # De-duplicate URL/Website if they’re identical
    if "Website" in out and "URL" in out and out["Website"].strip() == out["URL"].strip():
        out.pop("URL", None)

    # If neither Title nor Name present, try to derive something readable
    if not out.get("Title") and not out.get("Name"):
        candidate = out.get("Website") or out.get("URL") or out.get("Email") or out.get("Username")
        if candidate:
            out["Title"] = candidate

    return out



def on_move_category_clicked(self, *args):
   
    table = getattr(self, "vaultTable", None)
    if table is None or table.selectionModel() is None:
        QMessageBox.warning(self, self.tr("Move"), self.tr("Table not available."))
        return

    sel = table.selectionModel().selectedRows()
    if not sel:
        QMessageBox.information(self, self.tr("Move"), self.tr("Select a row to move first."))
        return
    row = sel[0].row()

    # current category of the selected row
    try:
        current_cat = self._category_for_row(row)
    except Exception:
        current_cat = ""

    # block: source category
    if self._is_blocked_source(current_cat):
        QMessageBox.information(self, self.tr("Move"), self.tr("Entries in 'Bank' or 'Credit Cards' cannot be moved."))
        return

    # build options ONCE, filtered against blocked targets
    options = [c for c in self._schema_category_names() if not self._is_blocked_target(c)]
    if not options:
        QMessageBox.information(self, self.tr("Move"), self.tr("No available target categories."))
        return

    default_idx = options.index(current_cat) if current_cat in options else 0

    # let the user choose the destination
    target, ok = QInputDialog.getItem(
        self, "Move to category", "Choose the new category/type:",
        options, default_idx, False
    )
    if not ok or not target:
        return
    target = target.strip()

    # safety: re-check chosen target
    if self._is_blocked_target(target):
        QMessageBox.information(self, self.tr("Move"), self.tr("You can’t move entries into that category."))
        return

    # Modifiers: Ctrl = Quick Move, Shift = Edit First
    mods = QApplication.keyboardModifiers()
    force_quick = bool(mods & Qt.ControlModifier)
    force_edit  = bool(mods & Qt.ShiftModifier)

    if force_quick:
        ok = self._quick_move_row_to_category(row, target)
        QMessageBox.information(self, self.tr("Move"), self.tr("Entry moved.") if ok else self.tr("Move failed."))
        return

    if not force_edit:
        choice = QMessageBox.question(
            self, "Move",
            "Quick move without editing?\n\n"
            "Yes = Move now (auto-map fields)\nNo = Open form to review before saving",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.No
        )
        if choice == QMessageBox.StandardButton.Cancel:
            QMessageBox.information(self, self.tr("Move"), self.tr("Move cancelled."))
            return
        if choice == QMessageBox.StandardButton.Yes:
            ok = self._quick_move_row_to_category(row, target)
            QMessageBox.information(self, self.tr("Move"), self.tr("Entry moved.") if ok else "Move failed.")
            return
        # else fall through to Edit First

    status = self._move_row_to_category_full(row, target)
    if status == "success":
        QMessageBox.information(self, self.tr("Move"), self.tr("Entry moved."))
    elif status == "cancelled":
        QMessageBox.information(self, self.tr("Move"), self.tr("Move cancelled."))
    else:
        QMessageBox.information(self, self.tr("Move"), self.tr("Move failed."))

# move 


def import_vault_custom(self, *args, **kwargs):
    self.set_status_txt(self.tr("Importing Vault"))
    """
    Advanced restore: user picks which items to restore and how to handle the user record.
    """
    self.reset_logout_timer()

    # Choose backup file
    in_path_str, _ = QFileDialog.getOpenFileName(
        self, self.tr("Select Full Backup"), "", "KQV Full Backup (*.zip *.zip.enc)"
    )
    if not in_path_str:
        return

    in_path = Path(in_path_str)
    base = in_path.name
    is_encrypted = base.endswith(".zip.enc")

    # Guess/collect username
    m = _re.match(r"^(?P<user>.+?)_full_backup_\d{8}-\d{6}\.zip(\.enc)?$", base)
    guessed_user = m.group("user") if m else None
    cur_u = (self.currentUsername.text() if hasattr(self, "currentUsername") else "")
    cur_u = _kq_strip_ws(cur_u)
    username = (cur_u if cur_u else (guessed_user or ""))
    if not username:
        username, ok = QInputDialog.getText(self, self.tr("Restore Username"), self.tr("Restore into username:"))
        if not ok or not username.strip():
            return
        username = username.strip()

    # Password if needed
    pw = ""
    if is_encrypted:
        pw, ok = QInputDialog.getText(
            self, self.tr("Confirm Password"),
            self.tr("Enter your account password (used to decrypt the backup):"),
            QLineEdit.EchoMode.Password
        )
        if not ok or not pw:
            return

    # Show options
    dlg = RestoreOptionsDialog(self, default_userdb_mode="replace")
    if dlg.exec() != QDialog.DialogCode.Accepted:
        return
    components, userdb_mode = dlg.result_values()
    if not components:
        QMessageBox.information(self, self.tr("Restore"), self.tr("No components selected."))
        return

    # Run restore
    try:
        self._ensure_user_dirs(username)

        self.reset_logout_timer()
        if is_encrypted:
            import_full_backup(username, pw, str(in_path),
                               components=components, userdb_mode=userdb_mode)
        else:
            import_full_backup(username, str(in_path),
                               components=components, userdb_mode=userdb_mode)

        # baseline + refresh
        update_baseline(username=username, verify_after=False, who=self.tr("Selective restore OK"))
       
        msg = self.tr("{ok}Restore completed\n{in_p}").format(ok=kql.i('ok'), in_p=in_path)
        QMessageBox.information(self, self.tr("Import"), msg)

        try:
            if hasattr(self, "currentUsername"):
                self.currentUsername.setText(username)
            self.load_vault_table()
        except Exception:
            pass

    except Exception as e:
        msg = self.tr("{ok} Restore completed\n{err}").format(ok=kql.i('err'), err=e)
        QMessageBox.critical(self, self.tr("Import Failed"), msg)

# ==============================
# --- Auto-categorize & normalize CSV ---



def _ensure_category_exists_from_import(self, category: str) -> bool:
    """
    Ensure `category` exists in the active user's category_schema (user_db.json).
    Returns:
      True  -> category already existed
      False -> category was newly created and persisted
    """
    try:
        name = (category or "").strip()
        if not name:
            return True  # nothing to do

        # Resolve active user (canonical id)
        uname = ""
        if hasattr(self, "currentUsername") and self.currentUsername:
            uname = (self.currentUsername.text() or "").strip()
        canonical = (self.currentUsername.text() or "").strip()
        if not canonical:
            return True  # no active user yet

        # Load existing per-user schema
        schema = get_user_setting(canonical, "category_schema")
        if not isinstance(schema, dict):
            schema = {}
        cats = list(schema.get("categories") or [])

        # Case-insensitive existence check
        lname = name.lower()
        for c in cats:
            if not isinstance(c, dict):
                continue
            if (c.get("name") or "").strip().lower() == lname:
                # already exists
                try:
                    if hasattr(self, "refresh_category_dependent_ui"):
                        self.refresh_category_dependent_ui()
                except Exception:
                    pass
                return True

        # Build default fields for a new category
        fields = None
        try:
            fields = self._default_fields_for_category(name)
        except Exception:
            fields = None

        # Fallback minimal set
        if not fields:
            fields = [
                {"label": "Title"},
                {"label": "Username"},
                {"label": "Password"},
                {"label": "URL"},
                {"label": "Notes"},
            ]

        # Append and persist
        cats.append({"name": name, "fields": fields})
        schema["categories"] = cats
        set_user_setting(canonical, "category_schema", schema)

        # Refresh UI so selectors pick up the new category immediately
        try:
            if hasattr(self, "refresh_category_dependent_ui"):
                self.refresh_category_dependent_ui()
            elif hasattr(self, "refresh_category_selector"):
                self.refresh_category_selector()
        except Exception:
            pass

        return False  # newly created

    except Exception as e:
        try:
            log.error(f"[DEBUG] _ensure_category_exists_from_import failed: {e}")
        except Exception:
            pass
        # Fail-safe: don't block import if persistence failed; treat as existed.
        return True



def on_vault_search_committed(self, *args, **kwargs):
    q = (self.vaultSearchBox.text() or "").strip()
    if not q:
        try: self.filter_vault_table("")
        except Exception: pass
        return

    use_global = bool(self.search_all_ and self.search_all_.isChecked())
    log.debug(f"[SEARCH] committed. use_global={use_global} query={q!r}")

    if not use_global:
        try: self.filter_vault_table(q)
        except Exception as e:
            log.debug(f"[SEARCH] filter_vault_table failed: {e}")
        return

    if getattr(self, "_search_busy", False):
        log.debug("[SEARCH] already running; ignoring new request")
        return
    self._search_busy = True

    # snapshot primitives on GUI thread
    try:
        username = (self.currentUsername.text() or "").strip()
    except Exception:
        username = ""
    user_key = getattr(self, "userKey", None)

    # Indeterminate progress (range 0,0) -> no repaint recursion
    dlg = QProgressDialog("Searching entire vault…", "Cancel", 0, 0, self)
    dlg.setWindowTitle(self.tr("Keyquorum – Search"))
    dlg.setWindowModality(Qt.NonModal)
    dlg.setMinimumWidth(360)
    dlg.setAutoReset(False)
    dlg.setAutoClose(False)
    dlg.show()
    QApplication.processEvents(QEventLoop.AllEvents, 30)

    from workers.search_worker import VaultSearchWorker

    # Thread + worker
    thread = QThread()  # no parent: avoids parent-owned deletion races
    worker = VaultSearchWorker(username, user_key, q, 500)
    worker.moveToThread(thread)

    # store context so we don't capture deleted objects in lambdas
    self._search_ctx = {
        "dlg": dlg,
        "thread": thread,
        "worker": worker,
        "results": None,
        "error": None,
    }

    # --- Lifecycle wiring ---
    # 1) start work
    thread.started.connect(worker.run, type=Qt.QueuedConnection)

    # 2) worker outcome -> quit thread + self-delete worker; collect result/error
    worker.finished.connect(thread.quit, type=Qt.QueuedConnection)
    worker.finished.connect(worker.deleteLater, type=Qt.QueuedConnection)
    worker.finished.connect(self._on_search_finished_collect, type=Qt.QueuedConnection)

    worker.error.connect(lambda msg: setattr(self._search_ctx, "error", msg) if False else None, type=Qt.QueuedConnection)
    # The lambda above is a no-op placeholder to keep signature. We'll store error in a slot:
    worker.error.connect(self._on_search_error_collect, type=Qt.QueuedConnection)
    worker.error.connect(thread.quit, type=Qt.QueuedConnection)
    worker.error.connect(worker.deleteLater, type=Qt.QueuedConnection)

    # 3) after the thread actually stops, delete the thread object and only then touch GUI
    thread.finished.connect(self._on_search_thread_finished, type=Qt.QueuedConnection)
    thread.finished.connect(thread.deleteLater, type=Qt.QueuedConnection)

    # 4) cancel button
    dlg.canceled.connect(worker.cancel, type=Qt.QueuedConnection)

    # go
    log.debug("[SEARCH] starting worker thread")
    thread.start()



def _search_vault_all(self, query: str, *, max_results: int = 200,
                  progress_cb=None, should_cancel=lambda: False) -> list[dict]:
    """
    Full-vault search (all categories). Optionally reports progress and can be canceled.
    progress_cb: callable(done:int, total:int) | None
    should_cancel: callable() -> bool
    """
    q = (query or "").strip().lower()
    if not q:
        return []

    try:
        entries = self.vault_store.get_all_entries()
    except Exception:
        entries = load_vault(self.currentUsername.text(), getattr(self, 'core_session_handle', None) or self.userKey) or []

    from catalog_category.category_fields import get_fields_for

    common_keys = [
        "Title", "Name", "Username", "User", "Email",
        "URL", "Site", "Website", "Login URL", "Address",
        "Notes", "Note", "Description", "Label",
    ]
    weight = {
        "Title": 4, "Name": 4, "Username": 3, "Email": 3,
        "URL": 3, "Site": 3, "Website": 3, "Login URL": 3,
        "Notes": 1, "Description": 1, "Label": 2,
    }

    hits: list[dict] = []
    q_re = _re.escape(q)
    total = len(entries)

    for i, e in enumerate(entries, 1):
        if should_cancel and should_cancel():
            log.debug("[SEARCH] cancelled by user")
            break

        cat = (e.get("category") or e.get("Category") or "").strip()
        try:
            cat_fields = get_fields_for(cat) or []
        except Exception:
            cat_fields = []

        fields_to_scan = list(dict.fromkeys([*cat_fields, *common_keys]))  # dedupe keep order
        score = 0.0
        matched = set()

        for key in fields_to_scan:
            val = e.get(key)
            if not isinstance(val, str) or not val:
                continue
            s = val.lower()
            if q in s:
                matched.add(key)
                base = weight.get(key, 1)
                pos_bonus = max(0, 1.0 - (s.find(q) / max(1, len(s))))
                score += base * (1.0 + 0.25 * pos_bonus)
            elif _re.search(rf"\b{q_re}", s):
                matched.add(key)
                score += weight.get(key, 1) * 0.9

        if score > 0:
            hits.append({"index": i-1, "category": cat, "entry": e, "score": score, "matched": matched})

        if progress_cb and (i % 25 == 0 or i == total):
            try:
                progress_cb(i, total)
            except Exception:
                pass

    hits.sort(key=lambda h: (-h["score"], h["category"], h["entry"].get("Title") or h["entry"].get("Name") or ""))
    return hits[:max_results]

# ---  new



def on_select_cloud_vault(self, *args, **kwargs):
    """
    Let the user pick a vault file in a cloud-synced folder (e.g., OneDrive/Google Drive).
    On first use, show a one-time security warning. Optionally enable extra cloud wrapping.
    """

    self.reset_logout_timer()
    # Show instruction using a literal string so lupdate can extract it
    self.set_status_txt(self.tr("Please select your cloud file"))
    # Pick file inside the user's cloud folder (OneDrive/Google Drive)
    fn, _ = QFileDialog.getOpenFileName(
        self,
        "Select your vault file in OneDrive/Google Drive",
        "",
        "Keyquorum Vault (*.dat);;All files (*.*)"
    )
    if not fn:
        return

    username = self._active_username() if hasattr(self, "_logged_in_username") else None
    if not username:
        QMessageBox.warning(self, self.tr("Cloud sync"), self.tr("Please log in first."))
        return

    # Current cloud profile
    try:
        prof = get_user_cloud(username) or {}
    except Exception:
        prof = {}

    wrap = bool(prof.get("cloud_wrap"))

    # Read one-time risk acknowledgement
    try:
        cloud_ack = bool(get_user_setting(username, "cloud_risk_ack"))
    except Exception:
        cloud_ack = False

    # If not acknowledged, show the consent dialog
    if not cloud_ack:
        accepted, dont_ask, want_wrap = self._show_cloud_risk_modal(current_wrap=wrap)
        if not accepted:
            # User cancelled – do nothing
            return
        # Persist "don't ask again"
        if dont_ask:
            try:
                set_user_setting(username, "cloud_risk_ack", True)
            except Exception as e:
                log.debug(f"[WARN] Could not persist cloud_risk_ack: {e}")
        # If they opted into wrapping and it wasn't enabled, flip it
        if want_wrap and not wrap:
            wrap = True

    # Persist the FILE path (required by LocalPathProvider)
    remote_file = fn.replace("\\", "/")
    try:
        set_user_cloud(username, enable=True, provider="localpath", path=remote_file, wrap=wrap)
    except Exception as e:
        QMessageBox.warning(self, self.tr("Cloud sync"), f"Failed to set cloud target:\n{e}")
        return

    # notify the sync engine
    try:
        if getattr(self, "sync_engine", None):
            self.sync_engine.set_localpath(remote_file)
    except Exception:
        pass
    update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("OnCloud Sync Settings Changed"))
    # Success message
    extra = self.tr("\n\nExtra cloud wrapping: ON (recommended)") if wrap else self.tr("\n\nExtra cloud wrapping: OFF")
    msg =self.tr("Cloud target set: ") + f"\n{remote_file}\n\n" + self.tr("Note: Cloud storage increases exposure. Use strong passwords and 2FA.") + f"{extra}\n\n" + self.tr("We will auto-sync after login.")
    QMessageBox.information(self, self.tr("Cloud sync"), msg)



def _enforce_category_compact(self, *args, **kwargs):
    combo: QComboBox = getattr(self, "categorySelector_2", None)
    if not isinstance(combo, QComboBox):
        return

    # ----- closed box (compact but readable) -----
    if not combo.objectName():
        combo.setObjectName("categorySelector_2")

    fm = combo.fontMetrics()
    h = max(fm.height() + 8, 28)                 # a touch larger so it feels deliberate
    combo.setMinimumHeight(h)
    combo.setMaximumHeight(h)
    combo.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

    # keep this widget’s style local
    combo.setStyleSheet(
        f"""
        QComboBox#categorySelector_2 {{
            combobox-popup: 0;                   /* ensure Qt uses stylable popup */
            min-height: {h}px;
            max-height: {h}px;
            padding: 4px 8px;
            margin: 0;
        }}
        QComboBox#categorySelector_2::drop-down {{ width: 16px; }}
        /* popup list (remove frame/margins that create the black bands) */
        QComboBox#categorySelector_2 QAbstractItemView {{
            padding: 0;
            margin: 0;
            border: 0;
            background: palette(Base);
            max-height: 260px;
        }}
        QComboBox#categorySelector_2 QAbstractItemView::item {{
            padding: 2px 8px;                    /* tidy row padding */
        }}
        """
    )

    # ----- popup view: own view so we fully control it -----
    view = getattr(combo, "_kq_view", None)
    if view is None:
        view = QListView(combo)
        combo._kq_view = view
        combo.setView(view)

    # remove the frame + any internal margins that draw black bars
    view.setFrameShape(QFrame.NoFrame)
    view.setFrameShadow(QFrame.Plain)
    view.setContentsMargins(0, 0, 0, 0)
    if view.viewport():
        view.viewport().setContentsMargins(0, 0, 0, 0)

    view.setUniformItemSizes(True)
    view.setVerticalScrollMode(QListView.ScrollPerPixel)
    view.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)  # keep bar visible
    view.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)

    # cap popup height so it must scroll (prevents it from filling and leaving empty bands)
    view.setMinimumHeight(180)
    view.setMaximumHeight(260)
    combo.setMaxVisibleItems(10)

    # make popup at least as wide as the combo + scrollbar
    try:
        sbw = view.verticalScrollBar().sizeHint().width()
    except Exception:
        sbw = 14
    view.setMinimumWidth(max(combo.width(), 220) + sbw)

    combo.update()



def import_vault(self, *args, **kwargs):
    self.reset_logout_timer()

    # Pick the backup file produced by export_full_backup(..., out_dir)
    in_path_str, _ = QFileDialog.getOpenFileName(
        self,
        self.tr("Select Full Backup"),
        "",
        "KQV Full Backup (*.zip *.zip.enc)"
    )
    if not in_path_str:
        return

    in_path = Path(in_path_str)
    base = in_path.name

    # Guess username from "<user>_full_backup_YYYYmmdd-HHMMSS.zip[.enc]"
    m = _re.match(r"^(?P<user>.+?)_full_backup_\d{8}-\d{6}\.zip(\.enc)?$", base)
    guessed_user = m.group("user") if m else None

    cur_u = (self.currentUsername.text() if hasattr(self, "currentUsername") else "")
    cur_u = _kq_strip_ws(cur_u)
    username = (cur_u if cur_u else (guessed_user or ""))

    if not username:
        username, ok = QInputDialog.getText(self, self.tr("Restore Username"),
                                            self.tr("Enter the account username to restore into:"))
        if not ok or not username.strip():
            return
        username = username.strip()

    # Encrypted if it ends with ".zip.enc" (your importer checks Path.suffix == ".enc")
    is_encrypted = base.endswith(".zip.enc")

    pw = ""
    if is_encrypted:
        pw, ok = QInputDialog.getText(
            self, self.tr("Confirm Password"),
            self.tr("Enter your account password (used to decrypt the backup):"),
            QLineEdit.EchoMode.Password
        )
        if not ok or not pw:
            return

    try:
        self._ensure_user_dirs(username)  
        self.reset_logout_timer()
        if is_encrypted:
            import_full_backup(username, pw, str(in_path))
        else:
            import_full_backup(username, str(in_path))

        msg = self.tr("{ok} Full Backup OK").format(ok=kql.i('ok'))
        log_event_encrypted(self.currentUsername.text(), self.tr(""), msg)
        update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Full restore OK"))
        msg = self.tr("{ok} Full restore completed\n{in_p}").format(ok=kql.i('ok'), in_p=in_path)
        QMessageBox.information(self, self.tr("Import"), msg)
        try:
            if hasattr(self, "currentUsername"):
                self.currentUsername.setText(username)
            self.load_vault_table()
        except Exception:
            pass

    except Exception as e:
        QMessageBox.critical(self, self.tr("Import Failed"), f"❌ Import failed:\n{e}")



def export_vault_with_password(self, skip_ask: bool = True):
    """
    Export the current user's encrypted vault wrapped in a password-protected envelope (.kqbk).
    Lets the user choose the destination and filename.
    """
    from qtpy.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox
    from vault_store.vault_store import export_vault_with_password as _export_fn
    if not self._require_unlocked():
        return
    self.set_status_txt(self.tr("Exporting Vault"))
    self.reset_logout_timer()

    username = (self.currentUsername.text() or "").strip()
    if not username:
        self.safe_messagebox_warning(self, "Export Vault", "Please log in first.")
        return

    if not skip_ask:
        if not self.verify_sensitive_action(username, title="Export Vault/Auth"):
            return

    # Prompt for an export password
    password, ok = QInputDialog.getText(
        self, self.tr("Set Export Password"),
        self.tr("Choose a password to encrypt your exported vault. Keep it safe — it’s required to restore your data."),
        QLineEdit.EchoMode.Password
    )
    if not ok or not password:
        return

    # Choose destination
    suggested = f"{username}_vault_backup.kqbk"
    out_path, _ = QFileDialog.getSaveFileName(self, self.tr("Save Encrypted Vault"), suggested, self.tr("Encrypted Vault") + "(*.kqbk)")
    if not out_path:
        return

    # Do the export to a temp, then move to chosen path (so partial writes don't clobber)
    tmp_path = _export_fn(username, password)
    if not tmp_path:
        self.safe_messagebox_warning(self, self.tr("Export Failed"), self.tr("Something went wrong during export."))
        return

    try:
        import shutil, os
        # ensure target dir exists
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        shutil.copy2(tmp_path, out_path)
    except Exception as e:
        msg = self.tr("Could not save to chosen location:\n{err}").format(err=e)
        QMessageBox.critical(self, self.tr("Export Failed"), msg)
        return

    try:
        msg = self.tr("{ok} Vault exported → {out_p}").format(ok=kql.i('ok'), out_p=out_path)
        log_event_encrypted(username, self.tr("vault"), msg)
    except Exception:
        pass

    try:
        self._update_backup_timestamp(username, "last_vault_backup")
    except Exception:
        pass
    msg = self.tr("Vault exported to:\n{out_p}\n\nStore it securely (e.g., offline USB)").format(out_p=out_path)
    QMessageBox.information(self, self.tr("Export Complete"), msg)



def edit_selected_vault_entry(self, row, _column):

    log.debug(str(f"{kql.i('vault')} [VAULT] edit selected vault entry called"))
    self.reset_logout_timer()
    try:
        entries = load_vault(self.currentUsername.text(), getattr(self, 'core_session_handle', None) or self.userKey) or []
        try:
            global_index = self.current_entries_indices[row]
        except Exception:
            global_index = row

        if not (0 <= global_index < len(entries)):
            QtWidgets.QMessageBox.warning(self, self.tr("Edit Entry"), self.tr("Could not locate selected entry."))
            return

        entry = dict(entries[global_index])

                # pick category from UI
        category = self.categorySelector_2.currentText()

        dialog = AddEntryDialog(
            self,
            category,
            self.enable_breach_checker,
            existing_entry=entry,
            user=self.currentUsername.text(),
        )

        dialog._vault_index = global_index    # ✅ and the exact index

        self.reset_logout_timer()
        for label, widget in dialog.fields.items():
            if label == "2FA Enabled":
                (dialog.radio_yes if entry.get(label) == "True" else dialog.radio_no).setChecked(True)
            elif hasattr(widget, 'setText') and not callable(widget):
                widget.setText(entry.get(label, ""))

        if hasattr(dialog, "notesInput") and "Notes" in entry:
            dialog.notesInput.setPlainText(entry.get("Notes", ""))

        self.reset_logout_timer()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            updated = dialog.result_entry() or dialog.get_entry_data()
            # Keep Date fresh + ensure category survives
            updated["Date"] = dt.datetime.now().strftime("%Y-%m-%d")
            if "category" not in updated:
                updated["category"] = entry.get("category", "Passwords")              
            if "password" in updated and "Password" not in updated:
                updated["Password"] = updated["password"]
            # Save with history
            from features.watchtower.watchtower_helpers import persist_entry_with_history
            persist_entry_with_history(self,
                self.currentUsername.text(), self.userKey, global_index, updated, max_hist=10
            )
            update_baseline(username=self.currentUsername.text(), verify_after=False, who=f"Edit Entry From Vault")
            self.load_vault_table()
            self._on_any_entry_changed()
        self.reset_logout_timer()
    except Exception as e:
        self.reset_logout_timer()
        log.error(str(f"{kql.i('vault')} [ERROR] {kql.i('err')} editing vault entry: {e}"))
        QtWidgets.QMessageBox.warning(self, self.tr("Error"), self.tr("Failed to edit the selected entry. Please try again."))

# --- edit button clicked


def _schema_category_names(self, *args, **kwargs) -> list[str]:
    """
    Category names for the active user, using the same logic
    as the Category Editor (find_user + load_schema_for).
    Falls back to built-in defaults. Never returns an empty list.

    NOTE: internal categories like 'Authenticator' are hidden from the
    main vault category dropdown.
    """
    names: list[str] = []

    # categories we never want shown in the vault dropdown
    HIDDEN = {"authenticator"}

    try:
        # Work out current username as shown in the UI
        raw_name = ""
        if hasattr(self, "currentUsername") and hasattr(self.currentUsername, "text"):
            raw_name = (self.currentUsername.text() or "").strip()

        canonical = ""
        if raw_name:
            try:
                canonical = _canonical_username_ci(raw_name) or raw_name
            except Exception:
                canonical = raw_name

        # Load the same schema the Category Editor uses
        if canonical:
            try:
                from catalog_category.category_editor import load_schema_for
                schema = load_schema_for(canonical) or {}
            except Exception:
                schema = {}
        else:
            schema = {}

        # Extract names from schema, skipping hidden ones
        for c in schema.get("categories", []):
            if not isinstance(c, dict):
                continue
            nm = (c.get("name") or "").strip()
            if nm and nm.strip().lower() not in HIDDEN:
                names.append(nm)

    except Exception as e:
        try:
            log.debug(f"[DEBUG] _schema_category_names failed: {e}")
        except Exception:
            pass

    # Fallback if we got nothing
    if not names:
        try:
            from catalog_category.category_fields import get_categories
            names = [
                n for n in get_categories()
                if isinstance(n, str) and n.strip().lower() not in HIDDEN
            ]
        except Exception:
            names = ["Passwords"]

    return names



def soft_delete_entry(self, username: str, user_key: bytes, index: int) -> tuple[bool, str]:            # - soft delete entry
    log.debug("[TRASH] soft_delete_entry start index=%s", index)

    # 1) Load vault & pick record
    try:
        
        rows = load_vault(username, user_key) or []
        if not (0 <= index < len(rows)):
            return False, self.tr("index out of range (index=") + f"{index}, " + self.tr("rows=") + f"{len(rows)})"
        entry = dict(rows[index])
    except Exception as e:
        log.exception("[TRASH] load_vault failed")
        return False, self.tr("load_vault error: ") + f"{e}"

    # 2) Build preview (title, username, url, kind)
    try:
        preview = self._trash_preview_for_entry(entry)
    except Exception as e:
        log.debug("[TRASH] preview build failed: %s", e)
        preview = {
            "title": (entry.get("title") or entry.get("site") or entry.get("name") or "(untitled)"),
            "username": (entry.get("username") or entry.get("user") or entry.get("email") or ""),
            "url": (entry.get("url") or entry.get("origin") or ""),
            "kind": "login",
        }

    # 3) Append to encrypted trash
    try:
        trash = self._trash_load(username, user_key) or []
        rec = dict(entry)
        rec["_deleted_at"] = dt.datetime.now().isoformat(timespec="seconds")
        rec["_preview"] = preview
        rec["_trash_uid"]  = secrets.token_hex(8)   # - add id to item for restore
        trash.append(rec)
        self._trash_save(username, user_key, trash)
        log.debug("[TRASH] saved to trash (count=%s)", len(trash))
    except Exception as e:
        log.exception("[TRASH] _trash_save failed")
        return False, self.tr("_trash_save error:") + f" {e}"

    # 4) Remove from vault
    try:
        delete_vault_entry(username, user_key, index)
        log.debug("[TRASH] delete_vault_entry ok index=%s", index)
        self._on_any_entry_changed()
    except TypeError:
        # Some versions require force=True
        from vault_store.vault_store import delete_vault_entry as _del
        try:
            _del(username, user_key, index, True)
            self._on_any_entry_changed()
            log.debug("[TRASH] delete_vault_entry(force) ok index=%s", index)
        except Exception as e:
            log.exception("[TRASH] delete_vault_entry(force) failed")
            return False, self.tr("delete_vault_entry error:") + f" {e}"
    except Exception as e:
        log.exception("[TRASH] delete_vault_entry failed")
        return False, self.tr("delete_vault_entry error:") + f" {e}"

    return True, ""



def _do_vault_schema_refresh(self, *args, **kwargs):
    """
    Called (via schedule_vault_schema_refresh) whenever the category schema
    changes – e.g. Category Editor save/autosave, CSV import, etc.
    We:
    - clean up orphan categories
    - reload vault table
    - rebuild the category filter
    - refresh the add/edit category combo (categorySelector_2)
    """
    if getattr(self, "_vault_loading", False):
        return

    self._vault_loading = True
    try:
        # 1) cleanup orphans quietly
        try:
            self.cleanup_orphan_categories()
        except Exception as e:
            try:
                log.debug(f"[CAT] cleanup_orphan_categories failed in schema refresh: {e}")
            except Exception:
                pass

        # 2) Reload table once
        try:
            self.set_status_txt(self.tr("Refreshing vault (category schema changed)"))
            self.load_vault_table()
        except Exception as e:
            try:
                log.error(f"[CAT] _do_vault_schema_refresh: load_vault_table failed: {e}")
            except Exception:
                pass

        # 3) Rebuild category filter once
        try:
            self.rebuild_category_filter(show_empty=False)
        except Exception as e:
            try:
                log.debug(f"[CAT] _do_vault_schema_refresh: rebuild_category_filter failed: {e}")
            except Exception:
                pass

        # 4) NEW: refresh the add/edit category dropdown
        try:
            if hasattr(self, "refresh_category_selector"):
                log.info("[CAT] _do_vault_schema_refresh: calling refresh_category_selector()")
                self.refresh_category_selector()
        except Exception as e:
            try:
                log.debug(f"[CAT] _do_vault_schema_refresh: refresh_category_selector failed: {e}")
            except Exception:
                pass

    finally:
        self._vault_loading = False

    
# ==============================
# --- edit current item entry


def _normalize_fields_from_browser(self, row: dict) -> dict:
    """Map common browser CSV headers to Title/URL/Username/Password/Notes."""
    e = { (k or "").strip(): (v or "").strip() for k, v in row.items() if k is not None }
    alias = {
        # Title
        "name": "Title", "title": "Title", "label": "Title",
        # Website/URL synonyms – map to Website. We'll replicate later to URL.
        "url": "Website", "website": "Website", "site": "Website", "origin": "Website",
        # Username synonyms
        "username": "Username", "user": "Username", "login": "Username", "user name": "Username", "user-name": "Username",
        # Password synonyms
        "password": "Password", "pass": "Password", "pwd": "Password",
        # Notes synonyms
        "note": "Notes", "notes": "Notes", "comment": "Notes",
        # Email synonyms
        "email": "Email", "e-mail": "Email", "mail": "Email",
        # Phone
        "phone number": "Phone Number", "phone": "Phone Number", "mobile": "Phone Number",
        # Backup code
        "backup code": "Backup Code", "backup codes": "Backup Code", "recovery code": "Backup Code",
        # 2FA enabled
        "2fa": "2FA Enabled", "2fa enabled": "2FA Enabled", "two factor": "2FA Enabled",
    }
    for k in list(e.keys()):
        lk = k.lower()
        dst = alias.get(lk)
        if dst:
            if dst not in e:
                e[dst] = e.get(k, "")
    # Replicate URL/Website synonyms to both keys
    url_val = e.get("URL") or e.get("Website")
    if url_val:
        if "URL" not in e:
            e["URL"] = url_val
        if "Website" not in e:
            e["Website"] = url_val
    # Replicate Username synonyms (Username vs UserName)
    uname_val = e.get("Username") or e.get("UserName")
    if uname_val:
        if "Username" not in e:
            e["Username"] = uname_val
        if "UserName" not in e:
            e["UserName"] = uname_val
    # Ensure Email exists if provided under synonyms
    email_val = e.get("Email") or e.get("email")
    if email_val:
        if "Email" not in e:
            e["Email"] = email_val
    # Ensure Phone Number exists
    phone_val = e.get("Phone Number") or e.get("phone")
    if phone_val:
        if "Phone Number" not in e:
            e["Phone Number"] = phone_val
    # Ensure Notes exists
    notes_val = e.get("Notes") or e.get("notes")
    if notes_val:
        if "Notes" not in e:
            e["Notes"] = notes_val
    return e


