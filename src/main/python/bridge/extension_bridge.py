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
Hardened localhost bridge for the Keyquorum browser extension.
- Binds to 127.0.0.1 only.
- Random bearer token (X-KQ-Token) that rotates per app session.
- Small request size limits and explicit JSON parsing.
- CORS preflight only; actual data requires the token.
- Does NOT attempt eTLD+1 unless tldextract is installed; falls back to full host for safety.
"""

import json, secrets, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from typing import Any, Dict, list, Optional

TOKEN_HEADER = "X-KQ-Token"
DEFAULT_PORT = 8742

def _now() -> float: return time.monotonic()

# -----------------------------------
# CORS origin validation
# -----------------------------------
def _is_allowed_origin(origin: str) -> bool:
    """
    Return True if the provided Origin header value is permitted to access the bridge.

    Only allows chrome-extension:// or moz-extension:// scheme origins. Any other origin
    will cause the request to be rejected before sending any response.
    """
    o = (origin or "").strip().lower()
    return o.startswith("chrome-extension://") or o.startswith("moz-extension://")

def _safe_json_loads(b: bytes, limit: int = 16_384) -> Dict[str, Any]:
    if len(b) > limit: raise ValueError("payload too large")
    try:
        return json.loads(b.decode("utf-8", "strict"))
    except Exception as e:
        raise ValueError("invalid json") from e

def _host_from_origin(origin: str) -> str:
    try:
        u = urlparse(origin)
        host = (u.hostname or "").lower()
        # if tldextract is present, reduce to registrable domain
        try:
            import tldextract  
            ext = tldextract.extract(host)
            if ext.registered_domain:
                return ext.registered_domain
        except Exception:
            pass
        return host
    except Exception:
        return ""

class ExtensionBridge:
    def __init__(self, app, host: str = "127.0.0.1", port: int = DEFAULT_PORT, token_ttl_sec: int = 24*3600):
        """
        app must provide:
          - is_vault_unlocked() -> bool
          - get_entries_for_origin(host: str) -> list[Dict[str, str]]
          - get_totp_for_origin(host: str) -> Optional[str]   (optional)
        """
        self.app = app
        self.host, self.port = host, port
        self._token = secrets.token_urlsafe(32)
        self._token_issued = _now()
        self._token_ttl = token_ttl_sec
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # ---- lifecycle ----

    @property
    def token(self) -> str:
        return self._token

    def rotate_token(self) -> str:
        self._token = secrets.token_urlsafe(32)
        self._token_issued = _now()
        return self._token

    def start(self) -> str:
        Handler = self._make_handler()
        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self._token

    def stop(self) -> None:
        try:
            if self._server: self._server.shutdown()
        except Exception:
            pass
        self._server = None
        self._thread = None

    # ---- internals ----

    def _valid_token(self, tok: str) -> bool:
        if not tok or tok != self._token:
            return False
        if self._token_ttl and (_now() - self._token_issued) > self._token_ttl:
            return False
        return True

    def _make_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "KQBridge/0.2"

            def log_message(self, fmt, *args):
                return

            # CORS preflight
            def do_OPTIONS(self):
                self._write_cors(200)

            def do_GET(self):
                if self.path == "/v1/status":
                    body = {
                        "status": "ok",
                        "locked": not _call_bool(outer.app, ("is_vault_unlocked", "is_unlocked", "vault_unlocked"))
                    }
                    self._write_json(200, body)
                else:
                    self._write_json(404, {"error": "not found"})

            def do_POST(self):
                # Authenticate
                tok = self.headers.get(TOKEN_HEADER, "")
                if not outer._valid_token(tok):
                    self._write_json(401, {"error": "unauthorized"})
                    return

                length = int(self.headers.get("Content-Length") or 0)
                payload = self.rfile.read(min(length, 16_384))
                try:
                    data = _safe_json_loads(payload)
                except Exception:
                    self._write_json(400, {"error": "bad json"})
                    return

                if self.path == "/v1/query":
                    origin = str(data.get("origin") or "")
                    host = _host_from_origin(origin)
                    if not origin or not host:
                        self._write_json(400, {"error": "invalid origin"})
                        return

                    if not _call_bool(outer.app, ("is_vault_unlocked", "is_unlocked", "vault_unlocked")):
                        self._write_json(423, {"error": "locked"})
                        return

                    entries = _call_entries(outer.app, host) or []
                    # Only return fields the extension needs
                    out = []
                    for e in entries[:10]:  # cap for safety
                        out.append({
                            "title": e.get("title") or e.get("name") or host,
                            "username": e.get("username") or e.get("user") or "",
                            "password": e.get("password") or e.get("pass") or ""
                        })
                    self._write_json(200, { "entries": out })

                elif self.path == "/v1/otp":
                    origin = str(data.get("origin") or "")
                    host = _host_from_origin(origin)
                    if not origin or not host:
                        self._write_json(400, {"error": "invalid origin"})
                        return

                    code = _call_otp(outer.app, host)
                    if code is None:
                        self._write_json(404, {"error": "no totp"})
                    else:
                        self._write_json(200, { "code": str(code) })

                else:
                    self._write_json(404, {"error": "not found"})

            # ---- helpers ----
            def _write_cors(self, code: int):
                """
                Write CORS headers after validating the Origin header.

                Only allow origins that begin with chrome-extension:// or moz-extension://.
                Reject any other origins with 403 before sending the status line.
                """
                origin = (self.headers.get("Origin") or "").strip()
                # Validate origin before sending any headers
                if origin and not _is_allowed_origin(origin):
                    self.send_error(403, "Origin not allowed")
                    return
                self.send_response(code)
                if origin:
                    # Reflect back the allowed origin and vary on origin
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-KQ-Token")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.end_headers()

            def _write_json(self, code: int, obj: Dict[str, Any]):
                """
                Write a JSON response with strict CORS checks.

                Validates Origin before sending headers, then reflects it.
                """
                origin = (self.headers.get("Origin") or "").strip()
                # Validate before sending status; on invalid, refuse the request
                if origin and not _is_allowed_origin(origin):
                    self.send_error(403, "Origin not allowed")
                    return
                s = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(s)))
                self.send_header("Cache-Control", "no-store")
                if origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
                self.end_headers()
                self.wfile.write(s)

        return Handler

# --- small app integration helpers ---

def _call_bool(app, names) -> bool:
    for n in names:
        f = getattr(app, n, None)
        if callable(f):
            try:
                return bool(f())
            except Exception:
                return False
    return False

def _call_entries(app, host: str) -> Optional[list[Dict[str, str]]]:
    for n in ("get_entries_for_origin", "query_entries_for_origin", "query_vault_for_origin"):
        f = getattr(app, n, None)
        if callable(f):
            try:
                return f(host)
            except Exception:
                return []
    return []

def _call_otp(app, host: str) -> Optional[str]:
    for n in ("get_totp_for_origin", "get_otp_for_origin"):
        f = getattr(app, n, None)
        if callable(f):
            try:
                return f(host)
            except Exception:
                return None
    return None
