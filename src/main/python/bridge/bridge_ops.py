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
import http.client
import json
import logging
import secrets
import socket
import threading
from pathlib import Path
from tkinter import E
from typing import Set
import sys, os
import weakref
import time as _t
import datetime as dt
import re as _re
import base64
import hashlib
import hmac
from app.paths import config_dir
from urllib.parse import urlparse
from vault_store.vault_store import add_vault_entry
from app.qt_imports import *
from security.baseline_signer import update_baseline
from features.url.main_url import open_url
from vault_store.vault_store import load_vault, update_vault_entry
from bridge.bridge_helpers import (
    ensure_bridge_token,
    load_bridge_token,
    save_bridge_token,)

import app.kq_logging as kql
from bridge.bridge_values import _DEFAULT_ORIGINS
from auth.login.login_handler import set_user_setting

log = logging.getLogger("keyquorum")
bridge_ops = sys.modules[__name__]
CONFIG_DIR = str(config_dir())

def _aw(name: str, default=None):
    return getattr(bridge_ops, name, default)


# Qt translation helper scoped to the Watchtower UI. 
def _tr(text: str) -> str:
    """Qt translation helper scoped to the Watchtower UI."""
    return QCoreApplication.translate("uiwatchtower", text)

# -----------------------------
# Origins (extensions)
# -----------------------------
from bridge.bridge_values import *
# Allowed origins file (one origin per line, or JSON array). 
# This is used by both the bridge server and the extension (via shared config) to allow dev/unpacked extensions 
# to connect without needing to modify the packed extension's code.
ORIGINS_PATH = Path(config_dir()) / "allowed_origins.json"

# In-memory cache of allowed origins with a simple mtime check to avoid reading the file on every request.
_origin_cache = {"set": set(_DEFAULT_ORIGINS), "mtime": 0.0}

# Lock to synchronize access to the allowed origins cache and file.
_origin_lock = threading.Lock()

# Signed-request auth (nonce + timestamp + HMAC over request metadata/body hash)
_AUTH_WINDOW_SECS = 20
_SENSITIVE_APPROVAL_CACHE: dict[tuple[str, str], float] = {}
_AUTH_NONCE_LOCK = threading.Lock()
_AUTH_NONCE_SEEN: dict[str, int] = {}

def _auth_prune_nonces(now_ts: int | None = None) -> None:
    try:
        now = int(now_ts or _t.time())
        stale_before = now - (_AUTH_WINDOW_SECS * 2)
        dead = [k for k, v in list(_AUTH_NONCE_SEEN.items()) if int(v) < stale_before]
        for k in dead:
            _AUTH_NONCE_SEEN.pop(k, None)
    except Exception:
        pass


# =============================
# Allowed origins persistence
# =============================

def _show_pairing_dialog(self, token: str, port: int | None = None):
    """
    show pairing dialog (called from bridge start on login, with token and port)
    """
    if not token:
        QMessageBox.information(self, self.tr("Pair Browser Extension"), self.tr("No token available."))
        return

    # Determine live port (uses self._bridge_port if set)
    if port is None:
        try:
            port = int(getattr(self, "_bridge_port", 8742))
        except Exception:
            port = 8742
    url = f"http://127.0.0.1:{port}"

    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Pair Browser Extension"))
    lay = QVBoxLayout(dlg)

    # Instruction
    lay.addWidget(QLabel(self.tr(
        "Paste this token into the Keyquorum extension popup, then click Save.\n"
        "Bridge URL (in the extension):")
    ))

    # Helper to make selectable, monospace labels
    def _mk_label(text: str) -> QLabel:
        lab = QLabel(text)
        try:
            flags = (Qt.TextInteractionFlag.TextSelectableByMouse |
                     Qt.TextInteractionFlag.TextSelectableByKeyboard)
        except AttributeError:  # Qt5 fallback
            flags = Qt.TextSelectableByMouse
        lab.setTextInteractionFlags(flags)
        lab.setStyleSheet(
            "font-family: monospace; font-size: 14px; padding: 6px; "
            "border: 1px solid #888; border-radius: 8px;"
        )
        return lab

    # URL row
    url_lab = _mk_label(url)
    lay.addWidget(url_lab)

    # Token heading + token
    lay.addWidget(QLabel(self.tr("Pairing token:")))
    current_token = [token]
    token_lab = _mk_label(current_token[0])
    lay.addWidget(token_lab)
    lay.addWidget(QLabel(self.tr("Auth mode: signed requests required (origin checked separately).")))

    # Buttons
    row = QHBoxLayout()
    btn_copy_token = QPushButton(self.tr("Copy Token"))
    btn_reset_token = QPushButton(self.tr("Reset Token"))
    btn_copy_url = QPushButton(self.tr("Copy URL"))
    btn_open_status = QPushButton(self.tr("Open Status"))
    btn_diagnose = QPushButton(self.tr("Diagnose"))   
    btn_open_orig   = QPushButton(self.tr("Open Origins File"))  
    btn_reload_orig = QPushButton(self.tr("Reload Origins"))   
    btn_add_origin = QPushButton(self.tr("Add Origin…"))
    btn_close       = QPushButton(self.tr("Close"))
    for b in (btn_copy_token, btn_reset_token, btn_copy_url, btn_open_status, btn_diagnose, btn_open_orig, btn_reload_orig, btn_add_origin, btn_close):
        row.addWidget(b)
    lay.addLayout(row)

    # Actions
    def _copy(text: str, btn: QPushButton, label: str):
        try:
            QApplication.clipboard().setText(text, QClipboard.Mode.Clipboard)
            btn.setText(self.tr("Copied ✓ {label}").format(label))
            log.info("%s [PAIR] %s copied to clipboard", kql.i('ok'), label.lower())
        except Exception:
            log.exception("%s [PAIR] clipboard copy failed (%s)", kql.i('err'), label.lower())

    btn_copy_token.clicked.connect(lambda: _copy(current_token[0], btn_copy_token, "Token"))
    btn_copy_url.clicked.connect(lambda: _copy(url, btn_copy_url, "URL"))
    btn_open_status.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(url + "/v1/status")))
    btn_close.clicked.connect(dlg.reject)

    def _reset_token():
        try:
            resp = QMessageBox.question(
                dlg,
                dlg.tr("Reset Pairing Token"),
                dlg.tr(
                    "This will generate a new pairing token and the browser extension will need to be paired again. Continue?"
                ),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if resp != QMessageBox.Yes:
                return

            _rotate_bridge_token(self)
            new_tok = (getattr(self, "_bridge_token", "") or getattr(self, "bridge_token", "") or "").strip()
            if not new_tok:
                raise RuntimeError("Token reset returned an empty token")

            current_token[0] = new_tok
            token_lab.setText(new_tok)
            btn_copy_token.setText(self.tr("Copy Token"))
            token_lab.setToolTip(dlg.tr("New token generated. Paste this into the extension and save again."))
            QMessageBox.information(
                dlg,
                dlg.tr("Reset Pairing Token"),
                dlg.tr("A new pairing token has been generated. Paste the new token into the extension and save again."),
            )
            log.info("%s [PAIR] pairing token reset from dialog", kql.i('ok'))
        except Exception:
            log.exception("%s [PAIR] failed to reset pairing token", kql.i('err'))
            QMessageBox.warning(dlg, dlg.tr("Reset Pairing Token"), dlg.tr("Could not reset the pairing token."))

    btn_reset_token.clicked.connect(_reset_token)
    
    # open the JSON in the user's default editor
    def _open_origins_file():
        try:
            # Ensure file exists with current contents
            cur = list(_aw('refresh_allowed_origins', lambda *a, **k: set())(force=True))
            if not _aw('ORIGINS_PATH').exists():
                _aw('save_allowed_origins', lambda *a, **k: None)(set(cur))
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(_aw('ORIGINS_PATH'))))
        except Exception:
            QMessageBox.warning(dlg, dlg.tr("Open Origins"), dlg.tr("Could not open the origins file."))

    # New: reload into memory (no restart required)
    def _reload_origins():
        global ALLOWED_ORIGINS
        ALLOWED_ORIGINS = _aw('refresh_allowed_origins', lambda *a, **k: set())(force=True)
        QMessageBox.information(dlg, dlg.tr("Reload Origins"), dlg.tr("Loaded ") + f"{len(ALLOWED_ORIGINS)}" + dlg.tr(" origin(s)."))

    btn_open_orig.clicked.connect(_open_origins_file)
    btn_reload_orig.clicked.connect(_reload_origins)

    def _add_origin():
        origin, ok = QInputDialog.getText(dlg, dlg.tr("Add Origin"), dlg.tr("chrome-extension://<ID>"))
        if not ok or not origin: 
            return
        origin = origin.strip()
        if not origin.startswith(("chrome-extension://", "moz-extension://")):
            QMessageBox.warning(dlg, dlg.tr("Add Origin"), dlg.tr("Must start with chrome-extension:// or moz-extension://"))
            return
        cur = _aw('refresh_allowed_origins', lambda *a, **k: set())(force=True)
        cur.add(origin)
        _aw('save_allowed_origins', lambda *a, **k: None)(cur)
        QMessageBox.information(dlg, dlg.tr("Add Origin"), dlg.tr("Saved. Click Reload Origins to apply."))

    btn_add_origin.clicked.connect(_add_origin)

    # --- Diagnose button logic (inline quick self-check) ---
    def _diagnose():
        # Reset field styles to base before coloring
        base_style = (
            "font-family: monospace; font-size: 14px; padding: 6px; "
            "border: 1px solid #888; border-radius: 8px;"
        )
        token_lab.setStyleSheet(base_style)
        url_lab.setStyleSheet(base_style)

        lines = []

        # Token checks
        tok_now = current_token[0]
        tok_ok = bool(tok_now) and len(tok_now) >= 24 and _re.fullmatch(r"[A-Za-z0-9_\-]+", tok_now or "") is not None
        lines.append(f"Token: {'OK' if tok_ok else 'BAD'}"
                     f" — {'looks good' if tok_ok else 'missing/too short/invalid chars'}")
        if tok_ok:
            token_lab.setStyleSheet(base_style + " border-color: #19a974;")  # green
        else:
            token_lab.setStyleSheet(base_style + " border-color: #e74c3c;")  # red

        # Bridge object present?
        httpd = getattr(self, "_bridge_httpd", None)
        lines.append(f"Bridge object: {'present' if httpd else 'absent'}")

        # TCP probe
        tcp_ok = False
        try:
            import  socket
            with socket.create_connection(("127.0.0.1", int(port)), timeout=0.5):
                tcp_ok = True
        except Exception:
            tcp_ok = False
        lines.append(f"TCP 127.0.0.1:{port}: {'reachable' if tcp_ok else 'no listener'}")
        url_lab.setStyleSheet(base_style + (" border-color: #19a974;" if tcp_ok else " border-color: #e74c3c;"))

        # HTTP /v1/status probe
        http_ok, code, data = False, None, None
        if tcp_ok:
            try:
                c = http.client.HTTPConnection("127.0.0.1", int(port), timeout=0.8)
                c.request("GET", "/v1/status")
                r = c.getresponse()
                code = r.status
                raw = r.read() or b""
                c.close()
                try:
                    data = json.loads(raw.decode("utf-8", "replace")) if raw else None
                except Exception:
                    data = None
                http_ok = code in (200, 401, 403)
            except Exception:
                http_ok = False
        lines.append(f"GET /v1/status: {'OK' if http_ok else 'FAIL'}"
                     f"{'' if code is None else f' (HTTP {code})'}")

        lines.append("Auth modes supported: signed only (origin checked separately)")

        # Advice
        tips = []
        if not tok_ok:
            tips.append(self.tr("Regenerate a new token (Pair → Regenerate) and paste it into the extension."))
        if httpd is None:
            tips.append(self.tr("Start the bridge (click Pair) after unlocking."))
        if not tcp_ok:
            tips.append(self.tr("Check antivirus/firewall or whether another Keyquorum instance is holding the port."))
        if tcp_ok and not http_ok:
            tips.append(self.tr("Handler error — check app log for bridge exceptions."))

        msg = "\n".join(lines)
        if tips:
            msg += "\n\nTips:\n- " + "\n- ".join(tips)

        QMessageBox.information(dlg, self.tr("Bridge diagnostics"), msg)

    btn_diagnose.clicked.connect(_diagnose)
    # --- end diagnose ---

    # Exec (Qt6) with Qt5 fallback
    try:
        dlg.exec()
    except AttributeError:
        dlg.exec_()



# Read the allowed origins from disk, returning a set and the file's last modified time. 
# If the file doesn't exist or is invalid, return an empty set and zero. This function is used internally to refresh the cache when needed.
def _read_file() -> tuple[Set[str], float]:
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


# Load the allowed origins set (merged with defaults) from cache or disk. 
# This is the main function used by the request handler to check if an origin is allowed. It relies on the cache for performance, 
# but will refresh from disk if the file has changed since last load.
def load_allowed_origins() -> Set[str]:
    return refresh_allowed_origins(force=False)

# Save a new set of allowed origins to disk. The input set is normalized (strings, stripped, non-empty) 
# and merged with defaults before saving. After writing, the cache is updated immediately to reflect the change without waiting 
# for next read. The file write is done safely by writing to a temp file and renaming it, which minimizes risk of corruption.
def save_allowed_origins(new_set: set[str]) -> None:
    """Persist allowed origins safely (keeps defaults) and refresh the cache."""
    normalized = {str(x).strip() for x in (new_set or set()) if str(x).strip()}
    out = sorted(set(_DEFAULT_ORIGINS) | normalized)
    ORIGINS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = ORIGINS_PATH.with_suffix(ORIGINS_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(out, indent=2), encoding="utf-8")
    tmp.replace(ORIGINS_PATH)
    with _origin_lock:
        _origin_cache["set"] = set(out)
        try:
            _origin_cache["mtime"] = ORIGINS_PATH.stat().st_mtime
        except Exception:
            _origin_cache["mtime"] = 0.0

# A more robust version of save that minimizes risk of file corruption by writing to a temp file and renaming it. 
# This is safer because it avoids leaving a partially written file if the process crashes during write. 
# The cache is still updated immediately after the rename to reflect the new data.
def save_allowed_origins_2(new_set: Set[str]) -> None:
    """Back-compat wrapper for older callers."""
    save_allowed_origins(set(new_set or set()))

# Add an origin (e.g. if user wants to allow a new site) and persist. 
# Returns the updated set of allowed origins after the change.
def add_allowed_origin(origin: str) -> set[str]:
    """Add a single origin and persist."""
    cur = load_allowed_origins()
    cur.add(str(origin).strip())
    save_allowed_origins(cur)
    return load_allowed_origins()

# Remove an origin (e.g. if user wants to revoke access) and persist. 
# Defaults cannot be removed, so if the origin is a default, it will still be retained in the merged set.
def remove_allowed_origin(origin: str) -> set[str]:
    """Remove a single origin and persist (defaults are retained automatically)."""
    cur = load_allowed_origins()
    cur.discard(str(origin).strip())
    save_allowed_origins(cur)
    return load_allowed_origins()


# Check if an origin is allowed (after normalizing). This is used in the request handler to enforce CORS policies.
def is_origin_allowed(origin: str) -> bool:
    """Check if a given origin string is allowed."""
    return str(origin).strip() in load_allowed_origins()

# Default allowed origins (always included, cannot be removed)
def ensure_origins_file() -> None:
    """Ensure allowed_origins.json exists so the UI can open/edit it."""
    try:
        ORIGINS_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not ORIGINS_PATH.exists():
            ORIGINS_PATH.write_text(
                json.dumps(sorted(_DEFAULT_ORIGINS), indent=2), encoding="utf-8"
            )
            with _origin_lock:
                _origin_cache["set"] = set(_DEFAULT_ORIGINS)
                _origin_cache["mtime"] = ORIGINS_PATH.stat().st_mtime
    except Exception:
        # don't crash app startup
        pass


# Load allowed origins from cache or disk, merging with defaults. 
# This is the main function used by the request handler to check if an origin is allowed. It relies on the cache for performance, 
# but will refresh from disk if the file has changed since last load.
def refresh_allowed_origins(force: bool = False) -> Set[str]:
    ensure_origins_file()
    with _origin_lock:
        file_set, mtime = _read_file()
        if force or mtime != _origin_cache["mtime"] or not _origin_cache["set"]:
            merged = set(_DEFAULT_ORIGINS) | file_set
            _origin_cache["set"] = merged
            _origin_cache["mtime"] = mtime
        return set(_origin_cache["set"])

# Global snapshot (optional). Recompute after any change if you rely on it.
ALLOWED_ORIGINS = refresh_allowed_origins(force=True)

# For security, the bridge server only allows CORS requests from origins in the allowed list, and only allows certain methods and headers.
_ALLOW_METHODS = "GET, POST, OPTIONS"
_ALLOW_HEADERS = "Content-Type, Authorization, X-Auth-Token, X-KQ-Token, X-KQ-Ts, X-KQ-Nonce, X-KQ-Signature"


try:
    from app.dev import dev_ops
    is_dev = dev_ops.dev_set

    if is_dev:
        # In dev mode, allow local HTTP origins for testing with unpacked extensions and local tools.
        ALLOW_LOCAL_HTTP  = True 
    else:
        ALLOW_LOCAL_HTTP = False
except Exception:
    ALLOW_LOCAL_HTTP = False


from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# The core HTTP request handler for the bridge server. 
# This class is designed to be used in both the local HTTP server and in-process modes, and it implements 
# the main endpoints for passkeys operations as well as some diagnostics and test pages. 
# It also includes helper methods for CORS handling, JSON parsing, and marshaling work to the UI thread.
class _BridgeHandler(BaseHTTPRequestHandler):

    def _b64url_decode(self, s: str) -> bytes:
        s = (s or "").strip()
        s += "=" * (-len(s) % 4)                # proper padding
        return base64.urlsafe_b64decode(s)

    def _require_unlocked(self, app) -> bool:
        """
        Determine whether the vault is unlocked without triggering any UI.

        The bridge runs on a background thread and must not display message boxes.
        Instead, it inspects the provided ``app`` for an ``is_vault_unlocked()``
        method (modern API) or falls back to checking for a truthy ``core_session_handle``
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
            # Fallback: older builds may store core_session_handle on the app
            return bool(getattr(app, "core_session_handle", None))
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            return False

    def _json_error(self, msg, code=400):
        return {"ok": False, "error": msg}, code

    def handle_passkeys_create(self, app, body):
        try:
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

        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")

    def handle_passkeys_get(self, app, body):
        try:
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
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")

    def log_message(self, msg, *args): 
        pass
        #log.info(f"[BRIDGE] Message{msg} {args}")


    # List credentials for the extension's UI (e.g., management panel). This is not used by the WebAuthn API directly, 
    # but provides a way for the extension to display existing passkeys and their metadata.
    def handle_passkeys_list(self, app, body):
        try:
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
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")

    # Delete a passkey credential by its ID (kid). 
    # This is used by the extension's UI to allow users to remove credentials they no longer want. 
    # It requires the vault to be unlocked and will trigger a UI reload on success.
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

    # For security, the bridge server only allows CORS requests from origins in the allowed list, and only allows certain methods and headers.
    def is_https_allowed(self, origin: str) -> bool:
        try:
            u = urlparse(origin or "")
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            return False
        if u.scheme == "https":
            return True
        # In dev mode, allow local HTTP origins for testing with unpacked extensions and local tools. This is disabled in production for security.
        if ALLOW_LOCAL_HTTP and u.scheme == "http" and (u.hostname in {"127.0.0.1", "localhost"}):
            return True
        return False

    # Check if the given origin is allowed based on the in-memory cache and the allowed origins file. 
    # This is used to enforce CORS policies for incoming requests.
    def _cors(self):
        try:
            origin = self.headers.get("Origin", "")
            self.send_header(
                "Access-Control-Allow-Origin",
                origin if (origin and self._origin_allowed(origin)) else "null"
            )
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", _ALLOW_METHODS)
            self.send_header("Access-Control-Allow-Headers", _ALLOW_HEADERS)
            self.send_header("Access-Control-Max-Age", "86400")

        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
    # Check if the given origin is in the allowed origins list. 
    # This is used by the CORS handling to determine whether to allow requests from that origin.
    def _safe_write(self, b: bytes):
        try:
            self.wfile.write(b)
            try: self.wfile.flush()
            except Exception: pass
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            # client went away — nothing to do
            log.error(f"[BRIDGE] Error {e}")
            return

    # Normalize header text for matching (lowercase, strip whitespace, remove common punctuation). 
    # This is used to match column headers in the webfill UI to known field names.
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
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            for i in range(table.columnCount()):
                headers.append("")
        try:
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
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")

        def get_text(r, c):
            try:
                item = table.item(r, c)
                return _kq_strip_ws(item.text() if item else "")
            except Exception as e:
                log.error(f"[BRIDGE] Error {e}")
                return ""
        try:
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
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")


    # Check if the given origin is in the allowed origins list. 
    # This is used by the CORS handling to determine whether to allow requests from that origin.
    def _send_json(self, obj, code=200):
        try:
            payload = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self._safe_write(payload)
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")

    # Extract the token from the request headers. The bridge supports multiple header formats for flexibility:
    def _get_token(self) -> str:
        try:
            h = self.headers
            auth = (h.get("Authorization") or "").strip()
            if auth.startswith("Bearer "):
                return auth[7:].strip()
            if auth.startswith("Token "):
                return auth[6:].strip()
            return h.get("X-Auth-Token") or h.get("X-KQ-Token") or ""
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            return ""

    def _read_body_bytes(self) -> bytes:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            n = 0
        try:
            return self.rfile.read(n) if n > 0 else b""
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            return b""

    def _parse_json_bytes(self, raw: bytes):
        try:
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            return {}

    def _request_path_only(self) -> str:
        try:
            return (self.path or "").split("?", 1)[0]
        except Exception:
            return self.path or ""

    def _has_signed_auth_headers(self) -> bool:
        try:
            h = self.headers
            return bool((h.get("X-KQ-Ts") or "").strip() and (h.get("X-KQ-Nonce") or "").strip() and (h.get("X-KQ-Signature") or "").strip())
        except Exception:
            return False

    def _verify_signed_request(self, secret: str, method: str, path: str, origin: str, raw_body: bytes = b"") -> bool:
        try:
            if not secret:
                return False
            h = self.headers
            ts_s = (h.get("X-KQ-Ts") or "").strip()
            nonce = (h.get("X-KQ-Nonce") or "").strip()
            sig = (h.get("X-KQ-Signature") or "").strip().lower()
            if not ts_s or not nonce or not sig:
                return False

            now = int(_t.time())
            ts_i = int(ts_s)
            if abs(now - ts_i) > _AUTH_WINDOW_SECS:
                return False

            body_hash = hashlib.sha256(raw_body or b"").hexdigest()
            # Signed auth intentionally does not bind the Origin into the HMAC.
            # Browsers control the real Origin header, and extension/service-worker
            # fetches may not preserve any script-supplied Origin value consistently.
            # The bridge still enforces the allow-list separately via CORS/origin checks.
            msg = "\n".join([
                (method or "").upper(),
                path or "",
                ts_s,
                nonce,
                body_hash,
            ]).encode("utf-8")
            expect = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest().lower()
            if not hmac.compare_digest(expect, sig):
                return False

            with _AUTH_NONCE_LOCK:
                _auth_prune_nonces(now)
                if nonce in _AUTH_NONCE_SEEN:
                    return False
                _AUTH_NONCE_SEEN[nonce] = ts_i
            return True
        except Exception as e:
            log.error(f"[BRIDGE] signed auth failed: {e}")
            return False

    def _auth_mode(self, app, method: str, path: str, origin: str, raw_body: bytes = b"") -> str:
        try:
            app_tok = (getattr(app, "_bridge_token", "") or getattr(app, "bridge_token", "")) if app else ""
            if not app_tok:
                return "none"

            # Prefer signed requests from the patched extension.
            if self._has_signed_auth_headers():
                return "signed" if self._verify_signed_request(app_tok, method, path, origin, raw_body) else "none"

            return "none"
        except Exception as e:
            log.error(f"[BRIDGE] auth check failed: {e}")
            return "none"

    def _auth_ok(self, app, method: str, path: str, origin: str, raw_body: bytes = b"") -> bool:
        return self._auth_mode(app, method, path, origin, raw_body) != "none"

    # Check if the given origin is in the allowed origins list.
 
    # This is used by the CORS handling to determine whether to allow requests from that origin.
    def _send_plain(self, text: str, code=404):
        try:
            body = (text or "").encode("utf-8")
            self.send_response(code)
            self._cors()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self._safe_write(body)
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")

    # Check if the given origin is in the allowed origins list.
    def _send_html(self, html: str, code=200):
        """
        Send a small HTML page to the client. This helper mirrors
        ``_send_plain`` and ``_send_json`` by adding the appropriate CORS
        headers and connection headers, but sets a text/html content type.
        ``html`` may be an empty string; it will be encoded as UTF-8.
        """
        try:
            body = (html or "").encode("utf-8")
            self.send_response(code)
            self._cors()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self._safe_write(body)
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")

    # Check if the given origin is in the allowed origins list.
    def _read_json(self):
        return self._parse_json_bytes(self._read_body_bytes())

    # marshal work to UI thread via app._uibus
    # The bridge server runs on a background thread and must not directly manipulate the UI. Instead, 
    # it uses the app's _uibus signal bus to marshal calls to the UI thread. This helper method wraps a 
    # function call in an event and waits for it to complete, 
    # returning the result. It includes a timeout to avoid hanging if the UI is unresponsive.
    def _run_on_ui(self, app, fn, timeout=10.0):
        try:
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
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")


    # For security, the bridge server only allows CORS requests from origins in the allowed list, and only allows certain methods and headers.
    def _json(self, obj, code=200):
        try:
            """Back-compat alias some routes call; just use _send_json."""
            self._send_json(obj, code)
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
    # Handle CORS preflight requests. The browser sends an OPTIONS request before certain cross-origin requests to check if they are allowed. 
    # This method responds with the appropriate CORS headers to indicate that the request is allowed, without processing any body or performing any actions.
    def do_OPTIONS(self):
        try:
            self.send_response(204)              # No Content
            self._cors()                         # adds Allow-Origin/Methods/Headers/Max-Age
            self.send_header("Connection", "close")  # optional
            self.end_headers()
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
    # Handle GET requests. This method implements several endpoints for diagnostics and testing, as well as some public information endpoints. 
    # It also includes CORS handling to allow cross-origin requests from allowed origins.
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

                    # pairing hint for UX: signed auth required
                    origin = self.headers.get("Origin", "")
                    auth_mode = self._auth_mode(app, "GET", path, origin, b"")
                    status = _tr("ok") if auth_mode == "signed" else _tr("not match")

                    self._send_json({"locked": bool(locked), "status": status, "auth_mode": auth_mode}, 200)
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

            # ---------- HEALTH / STATUS ----------

            # /v1/health — extension-facing connection summary.
            # Keep this minimal and never return secrets or entry data.
            if path.startswith("/v1/health"):
                origin = self.headers.get("Origin", "")
                if origin and not self._origin_allowed(origin):
                    self._send_json({"error": "forbidden"}, 403)
                    return

                auth_mode = "none"
                token_valid = False
                signed_auth = False
                vault_unlocked = False
                session_ok = False
                app_vault_unlocked = False

                try:
                    auth_mode = self._auth_mode(app, "GET", path, origin, b"")
                except Exception:
                    auth_mode = "none"

                token_valid = auth_mode == "signed"
                signed_auth = auth_mode == "signed"

                if app is not None:
                    try:
                        session_ok = bool(getattr(app, "core_session_handle", None))
                    except Exception:
                        session_ok = False

                    try:
                        if hasattr(app, "is_vault_unlocked") and callable(getattr(app, "is_vault_unlocked")):
                            app_vault_unlocked = bool(app.is_vault_unlocked())
                        elif hasattr(app, "_vault_locked"):
                            app_vault_unlocked = not bool(getattr(app, "_vault_locked"))
                        else:
                            app_vault_unlocked = bool(getattr(app, "vault_unlocked", False))
                    except Exception:
                        app_vault_unlocked = False

                # Only advertise vault access to the browser when auth passed.
                vault_unlocked = bool(token_valid and session_ok and app_vault_unlocked)
                autofill_ready = bool(vault_unlocked)
                self._send_json({
                    "bridge": True,
                    "auth_mode": auth_mode,
                    "token_valid": bool(token_valid),
                    "signed_auth": bool(signed_auth),
                    "session": bool(session_ok),
                    "app_vault_unlocked": bool(app_vault_unlocked),
                    "vault_unlocked": bool(vault_unlocked),
                    "autofill_ready": bool(autofill_ready),
                }, 200)
                return

            # ---------- TOKEN-PROTECTED ENDPOINTS ----------

            # 1) CORS allow-list (blocks other extensions/web pages in the browser)
            origin = self.headers.get("Origin", "")
            if origin and not self._origin_allowed(origin):
                self._send_json({"error": "forbidden"}, 403)
                return

            # 2) Auth check (signed request required)
            if not self._auth_ok(app, "GET", path, origin, b""):
                self._send_json({"error": "unauthorized"}, 401)
                return

            # /v1/webfill — global profiles + synonyms (if unlocked)
            if path.startswith("/v1/webfill"):
                synonyms, profiles, locked = {}, [], True
                if app:
                    try:
                        synonyms = app.webfill_synonyms()
                    except Exception:
                        synonyms = {}
                    try:
                        locked = not self._require_unlocked(app)
                    except Exception:
                        locked = True
                    if not locked:
                        # Webfill is intentionally global: do not require any site/origin match.
                        # Prefer the dedicated profile extractor if available, then fall back to the
                        # older UI-table collector for compatibility with older builds.
                        try:
                            # Prefer the bridge-local extractor first. It can temporarily switch
                            # the vault view to the Webfill category and restore it afterwards,
                            # which avoids returning whichever rows happen to be visible right now.
                            res = self._run_on_ui(app, lambda: get_webfill_profiles(app), timeout=10.0)
                            profiles = res.get("value") or []
                        except Exception:
                            try:
                                if hasattr(app, "get_webfill_profiles"):
                                    res = self._run_on_ui(app, lambda: app.get_webfill_profiles(), timeout=10.0)
                                    profiles = res.get("value") or []
                                else:
                                    raise AttributeError("missing get_webfill_profiles")
                            except Exception:
                                try:
                                    res = self._run_on_ui(app, lambda: self._collect_webfill_rows_ui(app, synonyms), timeout=10.0)
                                    profiles = res.get("value") or []
                                except Exception:
                                    profiles = []
                self._send_json({"ok": True, "locked": bool(locked), "profiles": profiles, "entries": profiles, "synonyms": synonyms}, 200)
                return

            # /v1/card or /v1/cards — global cards + synonyms (if unlocked)
            if path.startswith("/v1/card"):
                synonyms, cards, locked = {}, [], True
                if app:
                    try:
                        synonyms = app.card_synonyms()
                    except Exception:
                        synonyms = {}
                    try:
                        locked = not self._require_unlocked(app)
                    except Exception:
                        locked = True
                    if not locked:
                        # Cards are intentionally global: do not require any site/origin match.
                        try:
                            # Prefer the bridge-local extractor first so we can read the Credit Cards
                            # category even when the UI is currently showing a different category.
                            res = self._run_on_ui(app, lambda: get_credit_cards(app), timeout=10.0)
                            cards = res.get("value") or []
                        except Exception:
                            try:
                                if hasattr(app, "get_credit_cards"):
                                    res = self._run_on_ui(app, lambda: app.get_credit_cards(), timeout=10.0)
                                    cards = res.get("value") or []
                                else:
                                    raise AttributeError("missing get_credit_cards")
                            except Exception:
                                cards = []
                self._send_json({"ok": True, "locked": bool(locked), "cards": cards, "entries": cards, "synonyms": synonyms}, 200)
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
                            info["locked"] = not self._require_unlocked(app)
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
            log.error(f"[BRIDGE] Error {e}")
            try:
                self._send_json({"error": "internal"}, 500)
            except Exception:
                pass

    # Handle POST requests. This method implements the main endpoints for passkeys operations (create, get, delete) as well as 
    # some operations that may trigger UI interactions (e.g., showing the password generator, saving credentials). 
    # It includes CORS handling and token checks to ensure that only authorized clients can access these operations.
    def do_POST(self):

        try:
            app  = type(self).appref() if (type(self).appref and callable(type(self).appref)) else None
            raw_body = self._read_body_bytes()
            body = self._parse_json_bytes(raw_body)
            if not isinstance(body, dict):
                body = {}

            # --- CORS allow-list (browser context) ---
            origin = self.headers.get("Origin", "")
            if origin and not self._origin_allowed(origin):
                self._send_json({"error": "forbidden"}, 403)
                return

            # --- Signed auth required for protected POST endpoints ---
            path = self._request_path_only()
            if not self._auth_ok(app, "POST", path, origin, raw_body):
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


            # Sensitive approval gate for CVV / other high-risk fills
            if self.path.startswith("/v1/sensitive-approve"):
                kind = (body.get("kind") or body.get("type") or "sensitive").strip().lower()
                origin_url = body.get("origin") or body.get("host") or body.get("url") or ""
                detail = body.get("detail") or body.get("label") or ""
                if kind in {"cvv", "cvc", "card_cvv", "payment_cvv"} and origin_url and not self.is_https_allowed(origin_url):
                    self._send_json({"ok": False, "approved": False, "error": "origin-not-allowed"}, 403)
                    return
                result = self._request_sensitive_approval(app, kind=kind, origin=origin_url, detail=detail)
                code = 200 if result.get("approved") else 403
                self._send_json(result, code)
                return

            # Query entries for an origin (strict: https or local override)
            if self.path.startswith("/v1/query"):
                origin_url = body.get("origin") or body.get("host") or body.get("url") or ""
                if not self.is_https_allowed(origin_url):
                    self._send_json({"error": "origin-not-allowed"}, 403)
                    return

                entries = []
                if app:
                    username = ""
                    try:
                        if hasattr(app, "_active_username"):
                            username = (app._active_username() or "").strip()
                    except Exception:
                        username = ""

                    if not username:
                        try:
                            w = getattr(app, "currentUsername", None)
                            username = (w.text() or "").strip() if w else ""
                        except Exception:
                            username = ""

                    if username and getattr(app, "core_session_handle", None):
                        res = self._run_on_ui(
                            app,
                            lambda: get_entries_for_origin(app, origin_url),
                            timeout=5.0
                        )
                        entries = res.get("value") or []

                auth_mode = self._auth_mode(app, "POST", path, origin, raw_body)
                self._send_json({"matches": entries, "entries": entries, "auth_mode": auth_mode}, 200)
                return

            # Save credential (may present UI)
            if self.path.startswith("/v1/save"):
                saved = False
                if app:
                    res = self._run_on_ui(app, lambda: save_credential_ui(app, body), timeout=30.0)
                    saved = bool(res.get("value"))
                self._send_json({"saved": saved}, 200)
                return

            # Save contact/profile (run on UI thread for safety)
            if self.path.startswith("/v1/webfill"):
                ok = False
                if app:
                    res = self._run_on_ui(app, lambda: save_profile_from_bridge(app, body), timeout=30.0)
                    ok = bool(res.get("value"))
                self._send_json({"ok": ok}, 200)
                return

            # Save credit card (run on UI thread for safety)
            if self.path.startswith("/v1/card"):
                ok = False
                if app:
                    def _save_card_call():
                        if hasattr(app, 'save_card_from_bridge'):
                            try:
                                return app.save_card_from_bridge(body)
                            except TypeError:
                                pass
                        return save_card_from_bridge(app, body)
                    res = self._run_on_ui(app, _save_card_call, timeout=30.0)
                    ok = bool(res.get("value"))
                self._send_json({"ok": ok}, 200)
                return

            if self.path == "/v1/passkeys/delete":
                data, code = self.handle_passkeys_delete(app, body)
                self._send_json(data, code)
                return
            # Unknown path
            self._send_plain("Not found", 404)
            return

        except Exception as e:
            tb = traceback.format_exc()
            log.error(f"[BRIDGE] Error {e} {tb}")
            try:
                self._send_json({"error": "internal", "detail": str(e), "traceback": tb}, 500)
            except Exception:
                pass

    # Check the provided token against the app's token without triggering any UI. 
    # This is used for GET requests where we want to enforce token access but cannot risk showing any prompts. 
    # The function retrieves the token from the request headers and compares it to the app's token, returning True if they match and False otherwise. 
    # Any exceptions during this process are caught and treated as a failed check (returning False).
    def _check_token(self):
        try:
            from bridge.bridge_helpers import check_bridge_token_headless
            return self.appref().check_bridge_token_headless(self._get_token())
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            return False


    # Check if the given origin is allowed based on the allow-list and local testing rules. 
    # This is used to enforce CORS policies for browser-based requests. 
    # The function first checks if the origin is in the allow-list, and if not, 
    # it checks if it's a localhost URL (if local testing is enabled). If neither condition is met, the origin is not allowed.
    def _origin_allowed(self, origin: str) -> bool:
        if not origin:
            return False
        if origin in ALLOWED_ORIGINS:
            return True
        # Local testing override: allow http://localhost and http://
        try:
            u = urlparse(origin)
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            return False
        return (
            ALLOW_LOCAL_HTTP
            and u.scheme in ("http", "https")
            and u.hostname in LOCAL_TEST_HOSTS
        )

    # Handle HEAD requests for health checks. This endpoint is public and does not require a token, 
    # but still enforces the CORS allow-list to prevent abuse from unauthorized web pages. 
    # The response is minimal (200 OK with no body) to allow simple health checks without exposing any information.
    def do_HEAD(self):
        "curl -I http://127.0.0.1:8742/v1/status"
        "You should see HTTP/1.0 200 OK and zero-length body."
        try:
            path = self.path.split("?", 1)[0]

            # This is a HEAD endpoint that mirrors /v1/status but does not require a token. 
            # It still enforces the CORS allow-list to prevent abuse from unauthorized web pages, but it allows any origin that is allowed for GET requests. 
            # The response is minimal (200 OK with no body) to allow simple health checks without exposing any information.
            if path.startswith("/v1/status") or path.startswith("/v1/health") or path.startswith("/test"):
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type",
                                 "application/json" if (path.startswith("/v1/status") or path.startswith("/v1/health"))
                                 else "text/html; charset=utf-8")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            
            origin = self.headers.get("Origin", "")

            # 1) CORS allow-list (blocks other extensions/web pages in the browser)
            if origin and not self._origin_allowed(origin):
                self.send_response(403); self._cors()
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            # 2) Token check (header-only for HEAD)
            tok = self._get_token()
            app = type(self).appref() if (type(self).appref and callable(type(self).appref)) else None
            app_tok = (getattr(app, "_bridge_token", "") or getattr(app, "bridge_token", "")) if app else ""
            if not app_tok or tok != app_tok:
                self.send_response(401); self._cors()
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            # For valid requests, respond with 200 OK and no body
            self.send_response(200); self._cors()
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        except Exception as e:
            # In case of any unexpected error, respond with 500 Internal Server Error and no body.
            log.error(f"[BRIDGE] Error {e}")
            try:
                self.send_response(500); self._cors()
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
            except Exception:
                pass




# -----------------------------
# Lightweight network probes
# -----------------------------

# Simple TCP connect to check if something is listening (not HTTP-specific, just a port check).
def tcp_ready(host: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        return False

# Returns (http_ok: bool, http_status: int|None)
def bridge_status_json(host: str, port: int, timeout: float = 0.7):
    """GET /v1/status. Returns (ok: bool, json: dict|None, http_status: int|None)."""
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=timeout)
        c.request("GET", "/v1/status")
        r = c.getresponse()
        body = r.read() or b""
        c.close()

        data = None
        try:
            data = json.loads(body.decode("utf-8", "replace")) if body else None
        except Exception:
            data = None
        return True, data, r.status
    except Exception as e:  
        log.error(f"[BRIDGE] Error {e}")
        return False, None, None

# =================
# Server lifecycle helper
# =================

# This is a method on the main app class, but it could be called from anywhere with a reference to the app instance.
def start_bridge_server(self, host="127.0.0.1", port=8742, strict: bool | None = None):

    try:
        u = (getattr(self, "_active_username", lambda: "")() or "").strip()
    except Exception:
        log.error(f"[BRIDGE] Error No ACTIVE USER")
        u = ""
    if u:
        tok = ensure_bridge_token(u, new=False)
        try:
            self._bridge_token = tok
            self.bridge_token = tok
        except Exception:
            pass

    if strict is None:
        strict = not getattr(sys, "frozen", False)
        # Allow override via env (KQ_BRIDGE_STRICT=0/1)
        v = os.environ.get("KQ_BRIDGE_STRICT")
        if v is not None:
            strict = (str(v).strip() not in ("0", "false", "False", "no"))

    try:       
        try:
            Handler = _BridgeHandler  # type: ignore
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            Handler = None

        if Handler is None:
            log.error("❌ [BRIDGE] handler class not found; cannot start bridge")
            return

        Handler.appref = weakref.ref(self)
        from http.server import ThreadingHTTPServer
        class _HTTPD(ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

        def _serve_loop(srv):
            log.debug("[BRIDGE] entering serve_forever (pid=%s)", os.getpid())
            try:
                srv.serve_forever()
            except Exception:
                log.exception("❌ [BRIDGE] serve_forever crashed")
            finally:
                try: srv.server_close()
                except Exception: pass
                log.debug("[BRIDGE] serve_forever exited; server closed")

        def _bind(p):
            srv = _HTTPD((host, p), Handler)
            t = threading.Thread(target=_serve_loop, args=(srv,), name="kq-bridge", daemon=True)
            t.start()
            return srv

        def _tcp_ready(p, timeout=0.35) -> bool:
            try:
                with socket.create_connection((host, int(p)), timeout=timeout):
                    return True
            except Exception as e:
                log.error(f"[BRIDGE] Error {e}")
                return False

        def _http_ready(p, timeout=0.8) -> tuple[bool,int|None]:
            try:
                c = http.client.HTTPConnection(host, int(p), timeout=timeout)
                c.request("GET", "/v1/status")
                r = c.getresponse()
                code = r.status
                r.read()
                c.close()
                return (code in (200, 401, 403)), code
            except Exception as e:
                log.error(f"[BRIDGE] Error {e}")
                return (False, None)

        def _wait_until_ready(p, total_ms=3000):
            deadline = _t.time() + (total_ms/1000.0)   # kill time
            tcp_ok = http_ok = False
            http_code = None
            while _t.time() < deadline and not tcp_ok:
                tcp_ok = _tcp_ready(p)
                if not tcp_ok: _t.sleep(0.08)
            while _t.time() < deadline and tcp_ok and not http_ok:
                http_ok, http_code = _http_ready(p)
                if not http_ok: _t.sleep(0.08)
            return tcp_ok, http_ok, http_code

        # --- try primary
        srv = None
        try:
            srv = _bind(port)
            tcp_ok, http_ok, http_code = _wait_until_ready(port)
            
            log.debug("[BRIDGE] verify :%s tcp=%s http=%s code=%s", port, tcp_ok, http_ok, http_code)
            if tcp_ok and http_ok:
                self._bridge_httpd = srv
                self._bridge_port = port
                log.info("✅ [BRIDGE] online at http://%s:%s", host, port)
                return
        except OSError as e:
            log.error(f"[BRIDGE] Error {e}")
            srv = None

        # If verify failed on primary, close it
        try:
            if srv: srv.shutdown(); srv.server_close()
        except Exception:
            pass

        # --- try fallback
        fb = port + 1
        srv2 = _bind(fb)
        tcp_ok, http_ok, http_code = _wait_until_ready(fb)
        log.debug("[BRIDGE] verify :%s tcp=%s http=%s code=%s", fb, tcp_ok, http_ok, http_code)

        if tcp_ok and http_ok:
            self._bridge_httpd = srv2
            self._bridge_port = fb
            log.info("✅ [BRIDGE] online at http://%s:%s", host, fb)
            return

        if strict:
            try: srv2.shutdown(); srv2.server_close()
            except Exception: pass
            self._bridge_httpd = None
            log.error("❌ [BRIDGE] failed verify on %s and %s", port, fb)
            return

        # Non-strict: keep running on primary even though verify failed,
        self._bridge_httpd = srv2
        self._bridge_port = fb
        log.warning("⚠️  [BRIDGE] started without verification on :%s (strict=0)", fb)

    except Exception as e:
        log.exception(f"❌ [BRIDGE] failed to start {e}")

# Shutdown helper (can be called multiple times safely)
def stop_bridge_server_obj(httpd) -> None:
    """Shutdown a http.server instance safely."""
    try:
        if httpd is not None:
            httpd.shutdown()
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        pass


def stop_bridge_server(self):
    srv = getattr(self, "_bridge_httpd", None)
    if srv:
        try: srv.shutdown()
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            pass
        self._bridge_httpd = None

# =================
#  Save/get Data from/to bridge 
# =================

def card_synonyms(self) -> dict[str, list[str]]:
    """Synonym patterns the extension can use to map webfill fields. 
     These keys correspond to canonical profile properties used by the browser extension. 
     Each list contains lowercased substrings to match against name/id/label/placeholder attributes."""
    return {
        # Name on card / cardholder
        "name": ["name","cardholder","card holder","holder","cardholder name","name on card","cc-name"],
        # Primary card number
        "number": ["number","card number","card no","card no.","cardno","cc number","cc-number","ccnum"],
        # Expiry date (combined MM/YY or similar)
        # Expiry date (combined MM/YY or similar). Include explicit "expiry date"
        "expiry": [
            "exp",
            "expiry",
            "expiration",
            "expires",
            "exp date",
            "expiration date",
            "expiry date",
            "expdate",
            "mm/yy",
            "mm yy",
            "mm-yy",
        ],
        # Separate month of expiry
        "month": ["month","mm","exp-month","cc-exp-month","exp month","expire month"],
        # Separate year of expiry
        "year": ["year","yy","yyyy","exp-year","cc-exp-year","exp year","expire year"],
        # Card verification code
        "cvc": ["cvc","cvv","security code","cvn","cvc2","cvv2","cid","csc","cvc/cvv"],
    }


# The following functions are meant to be called on the UI thread of the app, and may interact with the vault table or show confirmation dialogs.
from bridge.bridge_values import WEBFILL_COL

# Get credit cards from vault table, using flexible header matching and category filtering
def get_credit_cards(self, *args, **kwargs) -> list[dict]:
    """
    Return credit-card rows from the FULL unlocked vault so the browser
    extension does not depend on the currently selected category in the app.

    Falls back to the visible-table/category-switch approach if full-vault
    loading is unavailable.
    """
    cards: list[dict] = []
    try:
        from vault_store.vault_store import load_vault

        username = ""
        try:
            if hasattr(self, "_active_username"):
                username = (self._active_username() or "").strip()
        except Exception:
            username = ""
        if not username and hasattr(self, "currentUsername") and hasattr(self.currentUsername, "text"):
            try:
                username = (self.currentUsername.text() or "").strip()
            except Exception:
                username = ""

        session = getattr(self, "core_session_handle", None)
        entries = load_vault(username, session) if username and session else []
        entries = entries or []

        def _pick(src: dict, *keys: str) -> str:
            for key in keys:
                try:
                    val = src.get(key)
                except Exception:
                    val = None
                if val not in (None, ""):
                    return str(val).strip()
            return ""

        for ent in entries:
            if not isinstance(ent, dict):
                continue
            cat = _kq_norm_header(_pick(ent, "category", "Category"))
            if cat and ("credit card" not in cat and cat not in {"cards", "card", "payment cards", "payment card"}):
                continue

            number_val = _pick(ent, "Card Number", "card number", "number", "card_number", "cc_number")
            name_val = _pick(ent, "Cardholder Name", "Name on Card", "name", "cardholder", "cardholder_name", "name_on_card")
            exp_val = _pick(ent, "Expiry Date", "expiry", "expiry_date", "exp")
            month_val = _pick(ent, "month", "exp_month")
            year_val = _pick(ent, "year", "exp_year")
            cvc_val = _pick(ent, "CVV", "CVC", "CVC/CVV", "cvc", "cvv", "security_code", "csc")
            title_val = _pick(ent, "Title", "title", "Name", "name", "Label", "label")

            if not (number_val or exp_val or name_val or title_val):
                continue

            if exp_val and (not month_val or not year_val):
                for sep in ("/", "-", " "):
                    if sep in exp_val:
                        parts = [part.strip() for part in exp_val.split(sep) if part.strip()]
                        if len(parts) >= 2:
                            month_val = month_val or parts[0]
                            year_val = year_val or parts[1]
                            break
                if (not month_val or not year_val):
                    raw = "".join(ch for ch in exp_val if ch.isdigit())
                    if len(raw) >= 4:
                        month_val = month_val or raw[:2]
                        year_val = year_val or raw[2:]

            title = title_val or name_val or ((number_val[-4:] and f"Card …{number_val[-4:]}") if number_val else "Card")
            cards.append({
                "title": title,
                "name": name_val,
                "number": number_val,
                "exp": exp_val,
                "month": month_val,
                "year": year_val,
                "cvc": cvc_val,
            })

        if cards:
            return cards
    except Exception:
        try:
            log.exception("[BRIDGE] get_credit_cards(full vault) failed")
        except Exception:
            pass

    # Legacy fallback: use the currently visible table, switching category if possible.
    cards = []
    table = getattr(self, "vaultTable", None)
    if not table:
        return cards

    selector = getattr(self, "categorySelector_2", None)
    load_fn = getattr(self, "load_vault_table", None)
    previous_text = ""
    switched = False

    def _selector_text(sel) -> str:
        try:
            return (sel.currentText() or "").strip()
        except Exception:
            return ""

    def _set_selector_to_any(sel, candidates: list[str]) -> bool:
        if not sel:
            return False
        try:
            for cand in candidates:
                try:
                    sel.setCurrentText(cand)
                    if (sel.currentText() or "").strip().lower() == cand.strip().lower():
                        return True
                except Exception:
                    pass
            return False
        except Exception:
            return False

    try:
        if selector is not None:
            previous_text = _selector_text(selector)
            low = previous_text.lower()
            if "credit card" not in low and low not in {"cards", "card"}:
                switched = _set_selector_to_any(selector, ["Credit Cards", "Credit Card", "Cards", "Card"])
                if switched and callable(load_fn):
                    try:
                        load_fn()
                    except Exception:
                        pass

        table = getattr(self, "vaultTable", None)
        if not table:
            return cards

        def norm(s: str) -> str:
            return _kq_norm_header(s or "")

        headers = []
        try:
            for c in range(table.columnCount()):
                it = table.horizontalHeaderItem(c)
                headers.append(norm(it.text() if it else ""))
        except Exception:
            headers = [""] * int(table.columnCount() or 0)

        def find_col(labels: set[str]) -> int:
            wanted = {norm(x) for x in labels if norm(x)}
            for idx, h in enumerate(headers):
                if not h:
                    continue
                for w in wanted:
                    if h == w or h.startswith(w) or w in h:
                        return idx
            return -1

        cat_col = find_col({"category"})
        title_col = find_col({"title", "name", "label"})
        name_col = find_col({"name on card", "name", "cardholder", "card holder", "cardholder name"})
        number_col = find_col({"card number", "number", "card no", "card no.", "cardno", "cc number"})
        expiry_col = find_col({"expiry", "exp", "exp.", "expires", "expiration", "exp date", "expiration date", "expiry date"})
        cvc_col = find_col({"cvv", "cvc", "security code", "cvn", "cvc2", "cvv2", "cid", "csc"})

        def cell(r: int, c: int) -> str:
            if c < 0:
                return ""
            try:
                it = table.item(r, c)
                if it is None:
                    return ""
                secret = it.data(int(Qt.ItemDataRole.UserRole))
                if isinstance(secret, str) and secret.strip():
                    return secret.strip()
                return _kq_strip_ws(it.text() if it else "")
            except Exception:
                return ""

        nrows = int(table.rowCount() or 0)
        for r in range(nrows):
            if cat_col >= 0:
                cat = norm(cell(r, cat_col))
                if cat and ("credit card" not in cat and cat not in {"cards", "card", "payment cards", "payment card"}):
                    continue

            title_val = cell(r, title_col)
            name_val = cell(r, name_col)
            number_val = cell(r, number_col)
            exp_val = cell(r, expiry_col)
            cvc_val = cell(r, cvc_col)

            if not (number_val or exp_val or name_val or title_val):
                continue

            month_val = ""
            year_val = ""
            if exp_val:
                for sep in ("/", "-", " "):
                    if sep in exp_val:
                        parts = [p.strip() for p in exp_val.split(sep) if p.strip()]
                        if len(parts) >= 2:
                            month_val, year_val = parts[0], parts[1]
                            break
                if not month_val and not year_val:
                    raw = "".join(ch for ch in exp_val if ch.isdigit())
                    if len(raw) >= 4:
                        month_val, year_val = raw[:2], raw[2:]

            title = title_val or name_val or ((number_val[-4:] and f"Card …{number_val[-4:]}") if number_val else "Card")
            cards.append({
                "title": title,
                "name": name_val,
                "number": number_val,
                "exp": exp_val,
                "month": month_val,
                "year": year_val,
                "cvc": cvc_val,
            })
        return cards
    finally:
        if selector is not None and switched:
            try:
                selector.setCurrentText(previous_text)
                if callable(load_fn):
                    load_fn()
            except Exception:
                pass

# Save from site(bridge) To Vault 
def save_credential_ui(self, payload: dict) -> bool:
    """
    Confirm with the user and persist credentials into the vault.
    Handles: update-existing, add-new, and basic validation.
    """
    try:
        if not self._require_unlocked(): 
            return
        # --- Normalize incoming fields
        url  = (payload.get("url") or payload.get("origin") or "").strip()
        user = (payload.get("username") or "").strip()
        pwd  = (payload.get("password") or "").strip()

        # --- Basic validation
        if not url or not pwd:
            QMessageBox.warning(self, self.tr("Save Login"), self.tr("Missing website URL or password."))
            return False

        # --- Normalize host
        try:
            host = urlparse(url if "://" in url else f"https://{url}").netloc or url
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            host = url

        # --- Build entry: write lower-case (canonical) AND Title-case (table-friendly) keys
        now_iso = dt.datetime.utcnow().isoformat(timespec="seconds")
        today   = dt.datetime.now().strftime("%Y-%m-%d")
        title   = host or url

        new_entry = {
            # canonical
            "category": "Passwords",
            "title": title,
            "website": url,
            "url": url,
            "email": user,
            "password": pwd,
            "phone": "",
            "backup_code": "",
            "twofa_enabled": False,
            "notes": "Added With Browser",
            "created_at": now_iso,
            "updated_at": now_iso,
            "Date": today, 

            # Title-case compatibility for existing table/loaders
            "Website": url,
            "Email": user,
            "Password": pwd,
            "Phone Number": "",
            "Backup Code": "",
            "2FA Enabled": False,
            "Notes": "Added With Browser",
        }

        # --- Load current user's entries
        try:
            current_user_name = self.currentUsername.text() if hasattr(self, "currentUsername") else ""
        except Exception as e:
            log.error(f"[BRIDGE] Error No ACTIVE USER")
            current_user_name = ""
        try:
            entries = load_vault(current_user_name, self.core_session_handle) or []
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            entries = []

    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")

    # --- Helpers
    def _strip_www(h: str) -> str:
        try:
            if not h:
                return ""
            h = h.strip().lower()
            while h.startswith("www."):
                h = h[4:]
            return h
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            return ""
    try:
        target_host = _strip_www((host.split(":")[0]) if host else "")

        # --- Find host matches across multiple possible URL fields
        same_host_indices = []
        for idx, ent in enumerate(entries):
            e_url = (ent.get("url") or ent.get("URL") or ent.get("website")
                     or ent.get("site") or ent.get("Website") or "").strip()
            try:
                e_host = urlparse(e_url if "://" in e_url else f"https://{e_url}").netloc or e_url
            except Exception:
                e_host = e_url
            e_host_norm = _strip_www(e_host.split(":")[0])
            if e_host_norm == target_host or e_host_norm.endswith("." + target_host) or target_host.endswith("." + e_host_norm):
                same_host_indices.append(idx)

        # --- Partition by username (check both 'email' and 'Email')
        same_user_indices, diff_user_indices = [], []
        for idx in same_host_indices:
            ent_user = (ent := entries[idx]).get("email") or ent.get("Email") or ""
            ent_user = ent_user.strip()
            (same_user_indices if ent_user == user else diff_user_indices).append(idx)

        # --- Same user exists → propose update (password compare checks both cases)
        if same_user_indices:
            for i in same_user_indices:
                existing_pwd = (entries[i].get("password")
                                or entries[i].get("Password") or "")
                if existing_pwd == pwd:
                    QMessageBox.information(self, self.tr("Already Saved"), self.tr("These credentials already exist in your vault."))
                    return True

            msg = self.tr("Credentials for this site and username already exist:\n\nWebsite: ") + f"{host}" + self.tr("\nUsername:") + f"{user or self.tr('(empty)')}\n\n" + self.tr("Would you like to update the existing entry?")
            resp = QMessageBox.question(
                self, self.tr("Update Login"),
                msg,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if resp != QMessageBox.StandardButton.Yes:
                return False

            upd_idx = same_user_indices[0]
            # keep title if present in old entry
            if not new_entry["title"]:
                prev_title = (entries[upd_idx].get("title")
                              or entries[upd_idx].get("Website")
                              or host)
                new_entry["title"] = prev_title
            new_entry["updated_at"] = now_iso

            try:
                update_vault_entry(current_user_name, self.core_session_handle, upd_idx, new_entry)
                self._on_any_entry_changed()
            except Exception:
                try:
                    update_vault_entry(current_user_name, self.core_session_handle, upd_idx, new_entry)
                    self._on_any_entry_changed()
                except Exception:
                    QMessageBox.critical(self, self.tr("Update Failed"), self.tr("Failed to update the existing entry."))
                    return False

            # Reload from source of truth
            try:            
                update_baseline(username=current_user_name, verify_after=False, who=f"Trash Vault changed")
            except Exception as e:
                log.error(f"[BRIDGE] Error {e}")
                pass
            try: self.load_vault_table()
            except Exception as e:
                log.error(f"[BRIDGE] Error {e}")
                pass
            QMessageBox.information(self, self.tr("Updated"), self.tr("Login updated in your vault."))
            return True

        # --- Different users for same host → confirm add
        if diff_user_indices:
            msg = (self.tr("Existing credentials were found for this site, but with different usernames.\n\n"
                   "Website: {host1}\nUsername: {username1}\n\n"
                   "Would you like to add this as a new entry?")).format(host1=host, username1={user or self.tr('(empty)')})
            resp = QMessageBox.question(
                self, self.tr("Add New Login"),
                msg,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if resp != QMessageBox.StandardButton.Yes:
                return False
     
        # --- Persist new entry
        try:
            # --- Persist new entry
            add_vault_entry(current_user_name, self.core_session_handle, new_entry)
            self._on_any_entry_changed()
            update_baseline(username=self.currentUsername.text(), verify_after=False, who=f"Vault Added")
            QMessageBox.information(self, self.tr("Save Login"), self.tr("Added successfully"))
            self.categorySelector_2.setCurrentText(self.tr("Passwords"))
            self.reset_logout_timer()
            self.load_vault_table()
            return True 

        except Exception as e:
                log.error(f"{kql.i('err')} [ERROR] Vault Add URL Error: {e}")
                QMessageBox.warning(self, self.tr("Save Login"), self.tr("Could not save to vault."))
                return False

    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")

def _header_texts_lower(self):
    try:
        out = []
        for c in range(self.vaultTable.columnCount()):
            hi = self.vaultTable.horizontalHeaderItem(c)
            out.append(hi.text().strip().lower() if hi else "")
        return out
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")


def _get_password_from_table(self, row: int) -> str:
    try:
        """Return the real secret stored in the table's UserRole for this row."""
        tbl = getattr(self, "vaultTable", None)
        if not tbl or row < 0 or row >= tbl.rowCount():
            return ""

        roles = [
            int(Qt.ItemDataRole.UserRole),
            int(Qt.ItemDataRole.UserRole) + 1,
            int(Qt.ItemDataRole.UserRole) + 42,
        ]

        def _secret_from_item(it) -> str:
            if not it:
                return ""
            for role in roles:
                val = it.data(role)
                if isinstance(val, bytes) and val:
                    try:
                        return val.decode("utf-8", "ignore")
                    except Exception:
                        continue
                if isinstance(val, str) and val.strip():
                    return val
            return ""

        if not hasattr(self, "_kq_pw_col"):
            labels = {
                "password", "pass", "passcode", "pwd", "secret",
                "backup code", "backup", "recovery code", "2fa code", "otp", "code",
            }
            self._kq_pw_col = self._find_col_by_labels(labels)

        if isinstance(self, object) and isinstance(self._kq_pw_col, int) and self._kq_pw_col >= 0:
            v = _secret_from_item(tbl.item(row, self._kq_pw_col))
            if v:
                return v

        for c in range(tbl.columnCount()):
            v = _secret_from_item(tbl.item(row, c))
            if v:
                return v

        cache = getattr(self, "_pw_cache_by_row", None)
        if isinstance(cache, dict) and cache.get(row):
            return cache[row]

        return ""
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")

# get entrys for origin (called by bridge on UI thread)
def get_entries_for_origin_old(self, origin: str):
    """
    Return [{title, username, password, url}] for the page origin.
    Reads from the currently loaded vault table.
    Always returns a list.
    """
    try:
        from urllib.parse import urlparse
        from qtpy.QtCore import Qt

        table = getattr(self, "vaultTable", None)
        if table is None:
            return []

        try:
            netloc = urlparse(origin if "://" in origin else f"https://{origin}").netloc
            target = (netloc.split(":")[0] or "").strip().lower()
        except Exception:
            target = (origin or "").strip().lower()

        if not target:
            return []

        def header_texts_lower():
            out = []
            for c in range(table.columnCount()):
                it = table.horizontalHeaderItem(c)
                out.append((it.text().strip().lower() if it and it.text() else ""))
            return out

        def find_col_by_labels(labels):
            wanted = {str(x).strip().lower() for x in labels}
            headers = header_texts_lower()
            for i, h in enumerate(headers):
                if h in wanted:
                    return i
            return -1

        def get_text(row, col):
            if col is None or col < 0:
                return ""
            it = table.item(row, col)
            if not it:
                return ""
            try:
                return (it.text() or "").strip()
            except Exception:
                return ""

        def get_password_from_cell(row, col):
            if col is None or col < 0:
                return ""
            it = table.item(row, col)
            if not it:
                return ""
            try:
                raw = it.data(Qt.UserRole)
                if isinstance(raw, str) and raw:
                    return raw
            except Exception:
                pass
            try:
                return (it.text() or "").strip()
            except Exception:
                return ""

        headers = header_texts_lower()

        url_col = find_col_by_labels({"website", "url", "login url", "site", "web site", "domain"})
        user_col = find_col_by_labels({"email", "username", "user name", "login", "email address", "user"})
        pass_col = find_col_by_labels({"password", "pass", "secret"})
        title_col = find_col_by_labels({"title", "name", "label", "service"})

        if title_col < 0:
            title_col = url_col if url_col >= 0 else 0

        if url_col < 0:
            log.warning("[BRIDGE] get_entries_for_origin: no URL column found; headers=%r", headers)
            return []

        def strip_www(h: str) -> str:
            h = (h or "").strip().lower()
            while h.startswith("www."):
                h = h[4:]
            return h

        def host_ok(u: str) -> bool:
            try:
                net = urlparse(u if "://" in u else f"https://{u}").netloc.lower()
                host = (net.split(":")[0] or "").strip().lower()

                h0 = strip_www(host)
                t0 = strip_www(target)

                if host == target or h0 == t0:
                    return True

                if host.endswith("." + target) or target.endswith("." + host):
                    return True

                if h0.endswith("." + t0) or t0.endswith("." + h0):
                    return True

                return False
            except Exception:
                return False

        out = []
        for r in range(table.rowCount()):
            try:
                url = get_text(r, url_col)
                if not url or not host_ok(url):
                    continue

                username = get_text(r, user_col) if user_col >= 0 else ""
                password = get_password_from_cell(r, pass_col) if pass_col >= 0 else ""
                title = get_text(r, title_col) if title_col >= 0 else ""
                title = title or url or target

                out.append({
                    "title": title,
                    "username": username,
                    "email": username,
                    "password": password,
                    "url": url,
                })
            except Exception as row_err:
                log.error("[BRIDGE] row %s lookup failed: %s", r, row_err)

        return out

    except Exception:
        log.exception("[BRIDGE] get_entries_for_origin failed")
        return []


def get_entries_for_origin(self, origin: str):
    """
    Return bridge autofill matches from the FULL unlocked vault,
    not just the currently visible table/category.

    Output:
      [{title, username, email, password, url}]

    Notes:
      - Prefer the DLL/native full-vault load.
      - If that returns no usable rows for the current schema, fall back to the
        older table-based matcher that previously worked in the app. This keeps
        signed auth changes separate from match extraction changes.
    """
    try:
        from urllib.parse import urlparse
        from vault_store.vault_store import load_vault

        username = ""
        try:
            if hasattr(self, "_active_username"):
                username = (self._active_username() or "").strip()
        except Exception:
            username = ""

        if not username and hasattr(self, "currentUsername") and hasattr(self.currentUsername, "text"):
            try:
                username = (self.currentUsername.text() or "").strip()
            except Exception:
                username = ""

        session = getattr(self, "core_session_handle", None)
        if not username or not session:
            try:
                return get_entries_for_origin_old(self, origin)
            except Exception:
                return []

        # FULL VAULT LOAD (native session handle, DLL-backed)
        entries = load_vault(username, session) or []
        
        if not isinstance(entries, list):
            entries = []

        try:
            netloc = urlparse(origin if "://" in origin else f"https://{origin}").netloc
            target = (netloc.split(":")[0] or "").strip().lower()
        except Exception:
            target = (origin or "").strip().lower()

        if not target:
            return []

        def _norm_host(value: str) -> str:
            try:
                net = urlparse(value if "://" in value else f"https://{value}").netloc
                host = (net.split(":")[0] or "").strip().lower()
                while host.startswith("www."):
                    host = host[4:]
                return host
            except Exception:
                host = (value or "").strip().lower()
                while host.startswith("www."):
                    host = host[4:]
                return host

        def _host_matches(candidate: str) -> bool:
            h = _norm_host(candidate)
            t = _norm_host(target)
            if not h or not t:
                return False
            if h == t:
                return True
            if h.endswith("." + t) or t.endswith("." + h):
                return True
            return False

        def _pick(entry: dict, *names: str) -> str:
            for name in names:
                try:
                    v = entry.get(name)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
                    if isinstance(v, (list, tuple)):
                        for item in v:
                            if isinstance(item, str) and item.strip():
                                return item.strip()
                    if v not in (None, False, ""):
                        return str(v).strip()
                except Exception:
                    pass
            return ""

        out = []
        for e in entries:
            if not isinstance(e, dict):
                continue

            # skip authenticator-like rows
            etype = (_pick(e, "_type", "type")).lower()
            cat = (_pick(e, "category", "Category")).lower()
            if (
                etype in ("authenticator", "totp", "otp", "2fa")
                or cat == "authenticator"
                or "secret_enc_b64" in e
            ):
                continue

            url = _pick(
                e,
                "website", "Website",
                "url", "URL",
                "login url", "Login URL",
                "login_url", "loginUrl",
                "site", "Site",
                "web site", "Web Site",
                "domain", "Domain",
                "uri", "URI",
                "website_url", "websiteUrl",
                "urls", "URLs",
            )

            if not url:
                continue
            if not _host_matches(url):
                continue

            username_val = _pick(
                e,
                "username", "Username",
                "user", "User",
                "email", "Email",
                "login", "Login",
                "email address", "Email Address",
            )

            password_val = _pick(
                e,
                "password", "Password",
                "pass", "Pass",
                "secret", "Secret",
                "secret_text", "secretText",
            )

            title_val = _pick(
                e,
                "title", "Title",
                "name", "Name",
                "label", "Label",
                "service", "Service",
                "website", "Website",
            ) or url

            out.append({
                "title": title_val,
                "username": username_val,
                "email": _pick(e, "email", "Email") or username_val,
                "password": password_val,
                "url": url,
            })

        # Fallback: if the full-vault schema produced no matches, use the older
        # table scanner that previously worked with the visible vault model.
        if not out:
            try:
                legacy_out = get_entries_for_origin_old(self, origin)
                if legacy_out:
                    return legacy_out
            except Exception:
                pass

        return out

    except Exception:
        try:
            log.exception("[BRIDGE] get_entries_for_origin(full vault) failed")
        except Exception:
            pass
        try:
            return get_entries_for_origin_old(self, origin)
        except Exception:
            return []

# get Webfill profiles (called by bridge on UI thread)
def get_webfill_profiles(self, *args, **kwargs) -> list[dict]:
    """
    Return Webfill rows from the FULL unlocked vault so the browser extension
    does not depend on the currently selected category in the desktop UI.

    Falls back to the visible table/category switch approach if the full vault
    load is unavailable for any reason.
    """
    out: list[dict] = []
    try:
        from vault_store.vault_store import load_vault

        username = ""
        try:
            if hasattr(self, "_active_username"):
                username = (self._active_username() or "").strip()
        except Exception:
            username = ""
        if not username and hasattr(self, "currentUsername") and hasattr(self.currentUsername, "text"):
            try:
                username = (self.currentUsername.text() or "").strip()
            except Exception:
                username = ""

        session = getattr(self, "core_session_handle", None)
        entries = load_vault(username, session) if username and session else []
        entries = entries or []

        def _pick(src: dict, *keys: str) -> str:
            for key in keys:
                try:
                    val = src.get(key)
                except Exception:
                    val = None
                if val not in (None, ""):
                    return str(val).strip()
            return ""

        for idx, ent in enumerate(entries):
            if not isinstance(ent, dict):
                continue
            cat = _kq_norm_header(_pick(ent, "category", "Category"))
            if cat and cat != "webfill":
                continue

            prof = {
                "honorific": _pick(ent, WEBFILL_COL["HONORIFIC"], "honorific", "Honorific", "name title", "Name Title", "salutation", "prefix"),
                "forename": _pick(ent, WEBFILL_COL["FORENAME"], "forename", "Forename", "first", "First", "first name", "First Name", "given name"),
                "middle": _pick(ent, WEBFILL_COL["MIDDLENAME"], "middle", "Middle", "middle name", "Middle Name"),
                "surname": _pick(ent, WEBFILL_COL["SURNAME"], "surname", "Surname", "last", "Last", "last name", "Last Name", "family name"),
                "email": _pick(ent, WEBFILL_COL["EMAIL"], "email", "Email", "email address", "Email Address"),
                "phone": _pick(ent, WEBFILL_COL["PHONE"], "phone", "Phone", "phone number", "Phone Number", "tel", "telephone"),
                "address1": _pick(ent, WEBFILL_COL["ADDR1"], "address1", "Address 1", "address line 1", "Address Line 1", "street", "street address"),
                "address2": _pick(ent, WEBFILL_COL["ADDR2"], "address2", "Address 2", "address line 2", "Address Line 2", "suite", "unit"),
                "city": _pick(ent, WEBFILL_COL["CITY"], "city", "City", "town", "City / Town"),
                "region": _pick(ent, WEBFILL_COL["REGION"], "region", "Region", "state", "county", "province", "State / Province / Region"),
                "postal": _pick(ent, WEBFILL_COL["POSTAL"], "postal", "Postal", "postcode", "zip", "Postal code / ZIP"),
                "country": _pick(ent, WEBFILL_COL["COUNTRY"], "country", "Country"),
            }
            if not any(v for v in prof.values()):
                continue

            title = (
                _pick(ent, "Title", "title", "Name", "name", "Label", "label")
                or " ".join(x for x in [prof["forename"], prof["surname"]] if x).strip()
                or prof["email"]
                or "Profile"
            )
            out.append({
                "id": idx,
                "title": title,
                "subtitle": " ".join(x for x in [prof["forename"], prof["surname"]] if x).strip(),
                "profile": prof,
            })

        if out:
            return out
    except Exception:
        try:
            log.exception("[BRIDGE] get_webfill_profiles(full vault) failed")
        except Exception:
            pass

    # Legacy fallback: read from the currently visible table, switching to
    # the Webfill category if possible.
    out = []
    table = getattr(self, "vaultTable", None)
    if not table:
        return out

    selector = getattr(self, "categorySelector_2", None)
    load_fn = getattr(self, "load_vault_table", None)
    previous_text = ""
    switched = False

    def _selector_text(sel) -> str:
        try:
            return (sel.currentText() or "").strip()
        except Exception:
            return ""

    try:
        if selector is not None:
            previous_text = _selector_text(selector)
            if previous_text.lower() != "webfill":
                try:
                    selector.setCurrentText("Webfill")
                    switched = (selector.currentText() or "").strip().lower() == "webfill"
                except Exception:
                    switched = False
                if switched and callable(load_fn):
                    try:
                        load_fn()
                    except Exception:
                        pass

        table = getattr(self, "vaultTable", None)
        if not table:
            return out

        headers = []
        try:
            for i in range(table.columnCount()):
                it = table.horizontalHeaderItem(i)
                headers.append(_kq_norm_header(it.text() if it else ""))
        except Exception:
            headers = [""] * int(table.columnCount() or 0)

        def find_col(labels: set[str]) -> int:
            wanted = {_kq_norm_header(x) for x in labels if _kq_norm_header(x)}
            for idx, h in enumerate(headers):
                if not h:
                    continue
                for w in wanted:
                    if h == w or h.startswith(w) or w in h:
                        return idx
            return -1

        idx = {
            "cat": find_col({"category"}),
            "title": find_col({"title", "name", "label"}),
            "honorific": find_col({WEBFILL_COL["HONORIFIC"], "name title", "title", "honorific", "salutation", "prefix"}),
            "first": find_col({WEBFILL_COL["FORENAME"], "first", "first name", "forename", "given name"}),
            "middle": find_col({WEBFILL_COL["MIDDLENAME"], "middle", "middle name"}),
            "surname": find_col({WEBFILL_COL["SURNAME"], "last", "last name", "surname", "family name"}),
            "email": find_col({WEBFILL_COL["EMAIL"], "email", "email address"}),
            "phone": find_col({WEBFILL_COL["PHONE"], "phone", "phone number", "tel", "telephone"}),
            "addr1": find_col({WEBFILL_COL["ADDR1"], "address1", "address line 1", "street", "street address"}),
            "addr2": find_col({WEBFILL_COL["ADDR2"], "address2", "address line 2", "apartment", "suite", "unit"}),
            "city": find_col({WEBFILL_COL["CITY"], "city", "town", "city / town"}),
            "region": find_col({WEBFILL_COL["REGION"], "region", "state", "county", "province"}),
            "postal": find_col({WEBFILL_COL["POSTAL"], "postal", "postcode", "zip", "postal code / zip"}),
            "country": find_col({WEBFILL_COL["COUNTRY"], "country"}),
        }

        def cell(r: int, c: int) -> str:
            if c < 0:
                return ""
            try:
                w = table.item(r, c)
                return _kq_strip_ws(w.text() if w else "")
            except Exception:
                return ""

        nrows = int(table.rowCount() or 0)
        for r in range(nrows):
            if idx["cat"] >= 0:
                cat = _kq_norm_header(cell(r, idx["cat"]))
                if cat and cat != "webfill":
                    continue
            prof = {
                "honorific": cell(r, idx["honorific"]),
                "forename": cell(r, idx["first"]),
                "middle": cell(r, idx["middle"]),
                "surname": cell(r, idx["surname"]),
                "email": cell(r, idx["email"]),
                "phone": cell(r, idx["phone"]),
                "address1": cell(r, idx["addr1"]),
                "address2": cell(r, idx["addr2"]),
                "city": cell(r, idx["city"]),
                "region": cell(r, idx["region"]),
                "postal": cell(r, idx["postal"]),
                "country": cell(r, idx["country"]),
            }
            if not any(v for v in prof.values()):
                continue
            title = cell(r, idx["title"]) or " ".join(x for x in [prof["forename"], prof["surname"]] if x).strip() or prof["email"] or "Profile"
            out.append({
                "id": r,
                "title": title,
                "subtitle": " ".join(x for x in [prof["forename"], prof["surname"]] if x).strip(),
                "profile": prof,
            })
        return out
    finally:
        if selector is not None and switched:
            try:
                selector.setCurrentText(previous_text)
                if callable(load_fn):
                    load_fn()
            except Exception:
                pass

# Save Webfill profile from bridge (called by bridge on UI thread)
def save_profile_from_bridge(self, payload: dict) -> bool:
    try:
        if not self._require_unlocked(): 
            return
        p = payload or {}

        def pick(*keys):
            for k in keys:
                v = p.get(k)
                if v not in (None, ""):
                    return str(v)
            return ""

        # honorific / title
        honorific   = pick("honorific", "honorificPrefix", "honorific-prefix",
                           "nameTitle", "salutation", "prefix", "courtesyTitle")
        # 
        if honorific and (len(honorific) > 12 or " — " in honorific or " – " in honorific or " " in honorific.strip()):
            # honorifics are usually short tokens (Mr, Ms, Dr, Prof, etc.)
            honorific = honorific.split()[0] if len(honorific.split()) == 1 else ""
    
        # names
        forename    = pick("forename", "firstName", "firstname", "first_name", "givenName", "given_name")
        middlename  = pick("middle", "middleName", "middlename", "additionalName", "additional-name")
        surname     = pick("surname", "lastName", "lastname", "last_name", "familyName", "family_name")
        # contact
        email       = pick("email", "emailAddress", "email_address")
        phone       = pick("phone", "tel", "phoneNumber", "phone_number", "mobile", "mobilePhone")
        # address
        address1    = pick("address1", "addressLine1", "address_line1", "street1", "streetAddress", "address-line1")
        address2    = pick("address2", "addressLine2", "address_line2", "street2", "address-line2")
        city        = pick("city", "locality", "town", "addressLevel2", "address-level2")
        region      = pick("region", "state", "county", "province", "addressRegion", "addressLevel1", "address-level1",
                           "stateProvinceRegion")
        postal      = pick("postal", "postalCode", "postcode", "zip", "zipCode", "postal-code")
        country     = pick("country", "countryName", "addressCountry")

        # Row caption: DO NOT use p["title"] (that’s the honorific).
        record_title = (
            p.get("entryTitle") or p.get("recordTitle")
            or " ".join(x for x in [honorific, forename, middlename, surname] if x)
            or (email or phone or "Profile")
        )

        try:
            new_entry = {
                "category": "Webfill",
                "Title": record_title,
                WEBFILL_COL["HONORIFIC"]:  honorific,
                WEBFILL_COL["FORENAME"]:   forename,
                WEBFILL_COL["MIDDLENAME"]: middlename,
                WEBFILL_COL["SURNAME"]:    surname,
                WEBFILL_COL["EMAIL"]:      email,
                WEBFILL_COL["PHONE"]:      phone,
                WEBFILL_COL["ADDR1"]:      address1,
                WEBFILL_COL["ADDR2"]:      address2,
                WEBFILL_COL["CITY"]:       city,
                WEBFILL_COL["REGION"]:     region,
                WEBFILL_COL["POSTAL"]:     postal,
                WEBFILL_COL["COUNTRY"]:    country,
            }
            add_vault_entry(self.currentUsername.text(), self.core_session_handle, new_entry)
            self._on_any_entry_changed()

            # refresh UI
            try:
                QTimer.singleShot(0, lambda: (self.categorySelector_2.setCurrentText("Webfill"),
                                                     self.load_vault_table()))
                QTimer.singleShot(0, lambda: update_baseline(username=self.currentUsername.text(), verify_after=False, who=f"Save from bridge -> New/Updated"))
            except Exception as e:
                log.error(f"[BRIDGE] Error {e}")
                pass

            return True
        except Exception as e:
            log.error(f"{kql.i('err')} [BRIDGE] save_profile_from_bridge failed:", e)
            return False
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        return False


def save_card_from_bridge(self, payload: dict) -> bool:
    try:
        if not self._require_unlocked():
            return False
        p = payload or {}
        def pick(*keys):
            for k in keys:
                v = p.get(k)
                if v not in (None, ""):
                    return str(v).strip()
            return ""
        title = pick('entryTitle','recordTitle','title')
        name = pick('name','cardholder','cardholder_name','name_on_card','cc_name')
        number = pick('number','card_number','cc_number')
        expiry = pick('expiry','expiry_date','exp')
        month = pick('month','exp_month')
        year = pick('year','exp_year')
        cvc = pick('cvc','cvv','security_code','securityCode','card_cvv','card_cvc','csc','cc_csc')
        if not expiry and (month or year):
            yy = str(year)[-2:] if year else ''
            expiry = (str(month).zfill(2) + '/' + yy).strip('/').strip()
        if not title:
            digits = ''.join(ch for ch in str(number) if ch.isdigit())
            title = f"Card •••• {digits[-4:]}" if digits else (name or 'Payment card')
        new_entry = {
            'category': 'Credit Cards',
            'Category': 'Credit Cards',
            'Title': title,
            'Cardholder Name': name,
            'Name on Card': name,
            'Card Number': number,
            'Expiry Date': expiry,
            'CVV': cvc,
            'CVC': cvc,
            'CVC/CVV': cvc,
        }
        add_vault_entry(self.currentUsername.text(), self.core_session_handle, new_entry)
        self._on_any_entry_changed()
        try:
            QTimer.singleShot(0, lambda: (self.categorySelector_2.setCurrentText('Credit Cards'), self.load_vault_table()))
        except Exception:
            pass
        try:
            update_baseline(username=self.currentUsername.text(), verify_after=False, who='Save from bridge -> Card')
        except Exception:
            pass
        return True
    except Exception as e:
        log.error(f"[BRIDGE] save_card_from_bridge failed: {e}")
        return False
# ==============================
# --- Bridge / Allowed Origins (unified paths) ---
# ==============================

# Diagnostic self-check (called by UI button)
def on_vault_diagButton_clicked(self, *args, **kwargs):
    """
    Self-checks:
      - token presence/format,
      - server object present,
      - TCP accept,
      - /v1/status HTTP,
    and shows a concise report + tips.
    """
    try:
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

        lines.append("Auth modes supported: signed only (origin checked separately)")

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
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")

# Strip leading/trailing whitespace with a single pass over indices (faster than .strip()).
def _kq_strip_ws(s: str) -> str:
    """Strip leading/trailing whitespace with a single pass over indices.
    """
    try:
        if not s:
            return ""
        i = 0
        j = len(s)
        while i < j and s[i].isspace():
            i += 1
        while j > i and s[j - 1].isspace():
            j -= 1
        return s[i:j]
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")

# Normalise header/candidate text for comparisons: strip + lowercase, with a single pass and fast ASCII handling.
def _kq_norm_header(s: str) -> str:
    
    """Normalise header/candidate text for comparisons: strip + lowercase.

    Implemented to avoid `.strip().lower()` chaining (two allocations) where possible.
    """
    try:
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
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")

# Bridge status indicator (small label in vault UI)
def _set_bridge_indicator(self, *, online: bool, locked: bool | None = None, note: str = "") -> None:
    """Update the small status label."""
    try:
        lab = getattr(self, "vault_connected_", None)
        if not lab:
            lab = self.findChild(QLabel, "vault_connected_")
            if not lab:
                return

        if online:
            txt = self.tr("● Bridge: Online")
            if locked is True:
                txt += self.tr(" (vault locked)")
            elif locked is False:
                txt += self.tr(" (vault unlocked)")
            if note:
                txt += self.tr(" — {note1}").format(note1=note)
            lab.setText(txt)
            lab.setStyleSheet("color: #19a974; font-weight: 600;")
        else:
            txt = self.tr("● Bridge: Offline")
            if note:
                txt += self.tr(" — {note1}").format(note1=note)
            lab.setText(txt)
            lab.setStyleSheet("color: #e74c3c; font-weight: 600;")

        # keep switch in sync if present
        try:
            _set_switch_checked(self, bool(online))
        except Exception:
            pass
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")

# Force bridge status to offline (called on stop and on failed start)
def _set_bridge_offline(self):
    """Force the bridge status label to show offline without deleting the persisted per-user token."""
    try:
        try:
            u = (self.currentUsername.text() or "").strip()
        except Exception:
            log.error(f"[BRIDGE] Error No ACTIVE USER")
            u = ""
        if u:
            tok = load_bridge_token(u)
            try:
                self._bridge_token = tok
                self.bridge_token = tok
            except Exception:
                pass

        lab = getattr(self, "vault_connected_", None)
        if lab:
            lab.setText(self.tr("Bridge: Offline — stopped"))
            lab.setStyleSheet("color: #ff5555;")
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        pass

# Start periodic monitoring of the bridge status (called on successful start)
def start_bridge_monitoring(self):
    """Begin periodic status checks (idempotent)."""
    try:
   
        if getattr(self, "_bridge_mon_timer", None):
            return
        self._bridge_mon_timer = QTimer(self)
        self._bridge_mon_timer.setInterval(2500)
        self._bridge_mon_timer.timeout.connect(lambda: poll_bridge_once(self))
        self._bridge_mon_timer.start()
        poll_bridge_once(self)
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")

# Stop periodic monitoring of the bridge status (called on stop)
def stop_bridge_monitoring(self):
    try:
        t = getattr(self, "_bridge_mon_timer", None)
        if t:
            try:
                t.stop()
            except Exception:
                pass
            self._bridge_mon_timer = None
        _set_bridge_indicator(self, online=False, note=self.tr("stopped"))
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")

# Single status check (called by monitor and on successful start) NOTE: use brige values py instead 
def poll_bridge_once(self) -> None:
    try:
        host = "127.0.0.1"
        port = int(getattr(self, "_bridge_port", 8742))
        httpd = getattr(self, "_bridge_httpd", None)

        if httpd is None:
            _set_bridge_indicator(self, online=False, note=self.tr("not running"))
            return

        if not bridge_ops.tcp_ready(host, port):
            _set_bridge_indicator(self, online=False, note=self.tr("no listener on :{port1}").format(port1=port))
            return

        ok, data, code = bridge_ops.bridge_status_json(host, port)
        if not ok or code not in (200, 401, 403):
            _set_bridge_indicator(self, online=False, note=f"HTTP {code or '—'}")
            return

        locked = None
        try:
            if isinstance(data, dict) and "locked" in data:
                locked = bool(data["locked"])
        except Exception:
            pass
        _set_bridge_indicator(self, online=True, locked=locked)
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")

# UI handler for the enable/disable bridge toggle switch
def on_bridge_toggle(self, checked: bool):
    """Enable/disable the local bridge explicitly (connected to UI toggle)."""
    try:
        if checked:
            u = self._active_username()
            # Need an unlocked vault to start
            tok = ensure_bridge_token(u, new=False)
            try:
                self._bridge_token = tok
                self.bridge_token = tok
            except Exception:
                pass
            if not tok:
                QMessageBox.warning(self, self.tr("Enable Bridge"), self.tr("Unlock your vault first."))
                try:
                    _set_switch_checked(self, False)
                except Exception:
                    pass
                return

            try:
                start_bridge_server(self, strict=None)
                start_bridge_monitoring(self)
                try:
                    poll_bridge_once(self)
                except Exception:
                    pass
                try:
                    self._toast(self.tr("Bridge enabled (localhost only)."))
                except Exception:
                    pass
            except Exception as e:
                try:
                    _set_switch_checked(self, False)
                except Exception:
                    pass
                try:
                    self._toast(self.tr("Bridge failed to start: ") + f"{e}")
                except Exception:
                    pass
        else:
            try:
                stop_bridge_monitoring(self)
            except Exception:
                pass
            try:
                stop_bridge_server(self,)
            except Exception:
                pass
            try:
                _set_bridge_offline(self)
            except Exception:
                pass
            try:
                self._toast(self.tr("Bridge disabled."))
            except Exception:
                pass
    except Exception as e:
        try:
            _set_switch_checked(self, False)
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            pass
        log.error(f"[BRIDGE] Error {e}")


def on_install_ext_(self):

    """Handler for "Install Extension" button (called on UI thread)"""
    try:
        msg = QMessageBox(self)
        msg.setWindowTitle(self.tr("Browser Extension Security Info"))
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowFlags(msg.windowFlags() | Qt.WindowStaysOnTopHint)
        msg.setText(
            self.tr(
                "<b>Before installing the extension, please read:</b><br><br>"
                "• Everything happens locally on your PC – nothing is sent to the cloud.<br>"
                "• The bridge only listens on <code>localhost</code> (never leaves your computer).<br>"
                "• Your vault stays encrypted and locked until you unlock it.<br>"
                "• A random token protects the bridge – keep it secret.<br>"
                "• Auto-fill works only on matching, HTTPS-protected sites.<br><br>"
                "<i>Keep your system updated and malware-free – security depends on your device.</i>"
            )
        )
        msg.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        msg.setDefaultButton(QMessageBox.StandardButton.Ok)

        ret = msg.exec()
        if ret != QMessageBox.StandardButton.Ok:
            return
        open_url(url="STORE_URL_CHROME", default_=True)
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")

def on_pair_browser_(self):
    """Start/verify the local bridge and show the pairing token + URL."""
    log.info("%s [PAIR] button clicked", kql.i('ok'))
    try:
        u = self._active_username()
        token = ensure_bridge_token(u, new=False)
        try:
            self._bridge_token = token
            self.bridge_token = token
        except Exception:
            pass
        if not token:
            log.error("%s [BRIDGE] no token (user not logged in?)", kql.i('err'))
            QMessageBox.warning(self, self.tr("Pairing"), self.tr("No token available. Please unlock your vault first."))
            return

        # 2) Start (or verify) the local HTTP bridge (idempotent)
        try:
            start_bridge_server(self, strict=None)
            start_bridge_monitoring(self)
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")


        httpd = getattr(self, "_bridge_httpd", None)
        if httpd is None:
            log.error("%s [BRIDGE] not running", kql.i('err'))
            QMessageBox.warning(
                self, self.tr("Pairing"),
                self.tr("The local bridge isn't running. Check antivirus/firewall and try again.")
            )
            return

        # 3) Use the actual bound port
        port = int(getattr(self, "_bridge_port", 8742))

        # Safer token mask
        def _mask(t: str) -> str:
            return t if len(t) < 12 else f"{t[:6]}…{t[-6:]}"
        log.info("✅ [PAIR] bridge ready on 127.0.0.1:%s • token=%s", port, _mask(token))

        # 4) Show dialog (with live URL)
        _show_pairing_dialog(self, token, port)

    except Exception:
        log.exception("%s [PAIR] failed", kql.i('err'))
        QMessageBox.critical(self, self.tr("Pairing error"), self.tr("Could not start or show pairing. See log for details."))


# Handler for "Open Origins" button (called on UI thread)
def open_origins_file_in_editor(parent) -> None:
    """Used by the pairing dialog (Open Origins button)."""
    try:
        ensure_origins_file()
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(ORIGINS_PATH)))
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        QMessageBox.warning(parent, parent.tr("Open Origins"), parent.tr("Could not open the origins file. "))


def _poll_bridge_once(self) -> None:
    """
    One-shot refresh of the indicator. Safe to call anytime.
    """
    try: 
        host = "127.0.0.1"
        port = int(getattr(self, "_bridge_port", 8742))
        httpd = getattr(self, "_bridge_httpd", None)

        # If our server object isn't present, it's offline for our purposes.
        if httpd is None:
            self._set_bridge_indicator(online=False, note=self.tr("not running"))
            return

        # Fast TCP probe first (accepts + close → 'empty response' still counts as reachable)
        if not self._tcp_ready(host, port):
            self._set_bridge_indicator(online=False, note=self.tr("no listener on :{port1}").format(port1=port))
            return

        ok, data, code = self._bridge_status_json(host, port)
        if not ok or code not in (200, 401, 403):
            self._set_bridge_indicator(online=False, note=f"HTTP {code or '—'}")
            return

        # We’re online. Try to show locked state if the endpoint returns it.
        locked = None
        try:
            if isinstance(data, dict) and "locked" in data:
                locked = bool(data["locked"])
        except Exception:
            pass
        self._set_bridge_indicator(online=True, locked=locked)
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")


def _bridge_status_json(self, host: str, port: int, timeout: float = 0.7):
    """
    GET /v1/status. Returns (ok: bool, json: dict|None, http_status: int|None).
    Does not require token.
    """
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=timeout)
        c.request("GET", "/v1/status")
        r = c.getresponse()
        body = r.read() or b""
        c.close()
        data = None
        try:
            data = json.loads(body.decode("utf-8", "replace")) if body else None
        except Exception:
            data = None
        return True, data, r.status
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        return False, None, None


def _tcp_ready(self, host: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        return False

def _on_bridge_toggle(self, checked: bool):
    self.set_status_txt(self.tr("Bridge toggle Changed"))
    """Enable/disable the local bridge explicitly."""
    try:
        if checked:
            u = self._active_username()
            # Start
            tok = ensure_bridge_token(u, new=False)
            try:
                self._bridge_token = tok
                self.bridge_token = tok
            except Exception:
                pass
            if not tok:
                QMessageBox.warning(self, self.tr("Enable Bridge"), self.tr("Unlock your vault first."))
                _set_switch_checked(self, False)
                return
            try:
                start_bridge_server(self, strict=None)
                start_bridge_monitoring(self)
                # instant refresh
                try: self._poll_bridge_once()
                except Exception: pass
                self._toast(self.tr("Bridge enabled (localhost only)."))
            except Exception as e:
                _set_switch_checked(self, False)
                self._toast(self.tr("Bridge failed to start: ") + f"{e}")
        else:
            # Stop
            try: stop_bridge_monitoring(self)
            except Exception: pass
            try: stop_bridge_server(self)
            except Exception: pass
            try: self._set_bridge_offline()   # from earlier step
            except Exception: pass
            self._toast(self.tr("Bridge disabled."))
    except Exception as e:
        # Revert on error
        _set_switch_checked(self, False)
        log.error(f"[BRIDGE] Error {e}")


def _set_switch_checked(self, on: bool):
    """Set switch state without firing toggled again."""
    w = getattr(self, "bridgeEnableSwitch", None)
    if not w:
        return
    try:
        w.blockSignals(True)
        w.setChecked(bool(on))
    finally:
        try: w.blockSignals(False)
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            pass


def _is_bridge_running(self) -> bool:
    try:
        return getattr(self, "_bridge_httpd", None) is not None
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        return False


def on_toggle_autostart_bridge(self, checked: bool):
    self.set_status_txt(self.tr("Bridge saveing change ") + f"{checked}")
    """Persist user preference for Bridge autostart."""
    try:
        u = self._active_username()
        if not u:
            return
        set_user_setting(u, "autostart_bridge", bool(checked))
        update_baseline(username=u, verify_after=False, who=f"Autostart Bridge Changed={checked}")
        if checked:
            self._toast(self.tr("Bridge will auto-start after login."))
        else:
            self._toast(self.tr("Bridge auto-start disabled."))
        self.set_status_txt(self.tr("Done"))
    except Exception as e:
        log.error(f"[SETTINGS] Failed to save autostart_bridge: {e}")


def _rotate_bridge_token(self):
    self._bridge_token = secrets.token_urlsafe(32)
    try:
        u = (getattr(self, "_active_username", lambda: "")() or "").strip()
        if u:
            save_bridge_token(u, self._bridge_token)
        self.bridge_token = self._bridge_token
        log.debug("%s [BRIDGE] token rotated (%s…%s)",
                    kql.i('ok'), self._bridge_token[:6], self._bridge_token[-6:])
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        pass

def _find_col_by_labels(self, names: set[str]) -> int:
    want = {s.lower() for s in names}
    for i, t in enumerate(_header_texts_lower(self,)):
        if t in want:
            return i
    return -1


def _get_text(self, row: int, col: int) -> str:
    if col < 0:
        return ""
    it = self.vaultTable.item(row, col)
    return (it.text() if it else "") or ""

def _set_pw_cell(self, row: int, col: int, password: str):
    display = "●" * max(8, len(password or ""))
    it = QTableWidgetItem(display)
    it.setData(int(Qt.ItemDataRole.UserRole), password or "")
    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
    self.vaultTable.setItem(row, col, it)


def webfill_synonyms(self) -> dict[str, list[str]]:
    return {
        "honorific": ["honorific-prefix","title","salutation","name title","honorific","prefix"],
        "forename":  ["first","first name","firstname","given","given name","forename","given-name"],
        "middle":    ["middle","middle name","middlename","additional-name","additional name"],
        "surname":   ["surname","last","last name","lastname","family","family name","family-name"],
        "email":     ["email","email address","emailaddress","e-mail","mailaddress"],
        "phone":     ["phone","phone number","phonenumber","tel","telephone","mobile","contact"],
        "address1":  ["address line 1","address-line1","addressline1","address1","street","street address","addr1"],
        "address2":  ["address line 2","address-line2","addressline2","address2","street2","apt","apartment","suite","unit","addr2"],
        "city":      ["city","town","city/town","city or town","locality","address-level2"],
        "region":    ["state / province / region","state/province/region","region","state","county","province","territory","address-level1","addressregion"],
        "postal":    ["postal code / zip","postal-code","postcode","zip","zip code","zipcode","postal"],
        "country":   ["country","country code","countryname","addresscountry"],
    }


def load_webfill_profile(self) -> dict:
    defaults = {
        "honorific": "",
        "forename": "",
        "middle":   "",
        "surname":  "",
        "email":    "",
        "phone":    "",
        "address1": "",
        "address2": "",
        "city":     "",
        "region":   "",
        "postal":   "",
        "country":  "",
    }

    try:
        table = getattr(self, "vaultTable", None)
        if not table or table.rowCount() == 0:
            return defaults

        r = table.currentRow()
        if r is None or r < 0 or r >= table.rowCount():
            r = 0

        def cell(lbl: str, *fallbacks: str) -> str:
            # try new label first, then old ones
            for key in (lbl, *fallbacks):
                try:
                    idx = self._column_index_case_insensitive(key)
                    if idx >= 0:
                        v = self._get_text(r, idx) or ""
                        if v:
                            return v.strip()
                except Exception:
                    pass
            return ""

        out = defaults.copy()
        out["honorific"] = cell(WEBFILL_COL["HONORIFIC"], "Name title", "Name Title")
        out["forename"]  = cell(WEBFILL_COL["FORENAME"],   "Forename", "First")
        out["middle"]    = cell(WEBFILL_COL["MIDDLENAME"], "Middle", "Middle name")
        out["surname"]   = cell(WEBFILL_COL["SURNAME"],    "Surname", "Last")
        out["email"]     = cell(WEBFILL_COL["EMAIL"],      "Email address", "Email")
        out["phone"]     = cell(WEBFILL_COL["PHONE"],      "Phone", "Phone number")
        out["address1"]  = cell(WEBFILL_COL["ADDR1"],      "Address line 1")
        out["address2"]  = cell(WEBFILL_COL["ADDR2"],      "Address line 2")
        out["city"]      = cell(WEBFILL_COL["CITY"],       "City / Town")
        out["region"]    = cell(WEBFILL_COL["REGION"],     "County / State / Region", "Region", "State", "County")
        out["postal"]    = cell(WEBFILL_COL["POSTAL"],     "Postal code / ZIP", "Postcode", "ZIP")
        out["country"]   = cell(WEBFILL_COL["COUNTRY"],    "Country")
        return out
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        return defaults

def _webfill_profile_path(self) -> Path:
    """Where your local Webfill profile (address/contact) lives."""
    try:
        base = Path(CONFIG_DIR)
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        base = Path.home() / ".keyquorum"
    base.mkdir(parents=True, exist_ok=True)
    return base / "Webfill_profile.json"


def save_webfill_profile(self, profile: dict) -> None:
    """
    Optional helper if you later add a UI to edit the profile.
    NOT called by autofill; provided for completeness.
    """
    try:
        p = self._webfill_profile_path(self)
        p.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        pass


def lookup_entries_by_domain(self, domain_or_origin: str):
    try:
        item = get_entries_for_origin(self, domain_or_origin)
        return item
        
    except Exception as e:
        log.error(f"[BRIDGE] Error {e}")
        try:
            return self.get_entries_for_origin(domain_or_origin)
        except Exception:
            return []

def is_vault_unlocked(self) -> bool:
    """Return True if a native vault session is active (strict DLL-only).

    In strict mode the vault unlock state is represented by a native session handle
    (an int / pointer value). Legacy builds used raw key bytes; we keep a tiny
    compatibility check so older state doesn't break UI logic.
    """
    uk = getattr(self, 'core_session_handle', None)
    if isinstance(uk, int):
        return uk > 0
    if isinstance(uk, (bytes, bytearray)):
        return bool(uk)
    return False


def _bridge_token_path(self) -> Path:
    from app.paths import bridge_token_dir
    username = (getattr(self, 'current_username', None) or '').strip()
    if not username:
        try:
            username = (self.currentUsername.text() or '').strip()
        except Exception as e:
            log.error(f"[BRIDGE] Error {e}")
            username = ''
    return bridge_token_dir(username)


