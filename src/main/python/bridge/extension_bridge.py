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
Signed-only localhost bridge for the Keyquorum browser extension.

This module used to implement a legacy X-KQ-Token transport. That causes
signed-only pairings to fail whenever the application accidentally starts this
bridge class instead of the newer bridge_ops handler.

This version aligns the auth contract with the MV3 extension:
- CORS allow-list based on chrome-extension:// / moz-extension:// origins.
- Signed requests only: X-KQ-Ts, X-KQ-Nonce, X-KQ-Signature.
- HMAC SHA256 payload: METHOD + PATH + TS + NONCE + SHA256(BODY), joined with \n.
- No legacy token fallback.
"""

import json
import secrets
import threading
import time
import re
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from typing import Any, Dict, Optional

from bridge.bridge_ops import ensure_origins_file, is_origin_allowed
from bridge.bridge_values import DEFAULT_IP, DEFAULT_PORT


def _now_monotonic() -> float:
    return time.monotonic()


def _now_wall() -> int:
    return int(time.time())


def _is_allowed_origin(origin: str) -> bool:
    o = (origin or "").strip().lower()
    return o.startswith("chrome-extension://") or o.startswith("moz-extension://")


def _safe_json_loads(b: bytes, limit: int = 16_384) -> Dict[str, Any]:
    if len(b) > limit:
        raise ValueError("payload too large")
    try:
        return json.loads(b.decode("utf-8", "strict"))
    except Exception as e:
        raise ValueError("invalid json") from e


def _is_ip_like(host: str) -> bool:
    h = (host or "").strip().lower()
    if not h:
        return False
    if h == "localhost":
        return True
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", h):
        return True
    if ":" in h and re.fullmatch(r"[0-9a-f:]+", h):
        return True
    return False


def _registrable_domain(host: str) -> str:
    from bridge.bridge_values import _TWO_LEVEL_SUFFIXES

    h = (host or "").strip().lower().strip(".")
    if not h or _is_ip_like(h):
        return h
    for pref in ("www.", "m.", "mobile."):
        if h.startswith(pref):
            h = h[len(pref):]
            break
    try:
        import tldextract
        ext = tldextract.extract(h)
        if ext.registered_domain:
            return ext.registered_domain
    except Exception:
        pass
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return h
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in _TWO_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    if last3 in _TWO_LEVEL_SUFFIXES and len(parts) >= 4:
        return ".".join(parts[-4:])
    return last2


def _host_variants_from_origin(origin: str) -> list[str]:
    try:
        u = urlparse(origin or "")
        host = (u.hostname or "").strip().lower().strip(".")
    except Exception:
        host = ""
    if not host:
        return []
    if _is_ip_like(host):
        return [host]
    variants: list[str] = []

    def _add(h: str) -> None:
        hh = (h or "").strip().lower().strip(".")
        if hh and hh not in variants:
            variants.append(hh)

    _add(host)
    if host.startswith("www."):
        _add(host[4:])
    if host.startswith("m."):
        _add(host[2:])
    if host.startswith("mobile."):
        _add(host[len("mobile."):])

    reg = _registrable_domain(host)
    _add(reg)

    parts = [p for p in host.split(".") if p]
    if len(parts) > 2:
        _add(".".join(parts[-3:]))
        _add(".".join(parts[-2:]))
    return variants


_AUTH_WINDOW_SECS = 20
_AUTH_NONCE_LOCK = threading.Lock()
_AUTH_NONCE_SEEN: dict[str, int] = {}


def _auth_prune_nonces(now_ts: int | None = None) -> None:
    now = int(now_ts or _now_wall())
    stale_before = now - (_AUTH_WINDOW_SECS * 2)
    dead = [k for k, v in list(_AUTH_NONCE_SEEN.items()) if int(v) < stale_before]
    for k in dead:
        _AUTH_NONCE_SEEN.pop(k, None)


class ExtensionBridge:
    def __init__(self, app, host: str = DEFAULT_IP, port: int = DEFAULT_PORT, token_ttl_sec: int = 24 * 3600):
        self.app = app
        self.host, self.port = host, port
        self._token = secrets.token_urlsafe(32)
        self._token_issued = _now_monotonic()
        self._token_ttl = token_ttl_sec
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._last_auth_debug: Dict[str, Any] = {}
        ensure_origins_file()

    @property
    def token(self) -> str:
        return self._token

    def rotate_token(self) -> str:
        self._token = secrets.token_urlsafe(32)
        self._token_issued = _now_monotonic()
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
            if self._server:
                self._server.shutdown()
        except Exception:
            pass
        self._server = None
        self._thread = None

    def _token_live(self) -> bool:
        return not self._token_ttl or ((_now_monotonic() - self._token_issued) <= self._token_ttl)

    def _make_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "KQBridge/1.0"

            def log_message(self, fmt, *args):
                return

            def _request_path_only(self) -> str:
                return (self.path or "").split("?", 1)[0]

            def _auth_debug(self, ok: bool, reason: str, **extra: Any) -> None:
                outer._last_auth_debug = {
                    "ok": bool(ok),
                    "reason": reason,
                    **extra,
                    "ts": _now_wall(),
                }

            def _has_signed_auth_headers(self) -> bool:
                h = self.headers
                return bool((h.get("X-KQ-Ts") or "").strip() and (h.get("X-KQ-Nonce") or "").strip() and (h.get("X-KQ-Signature") or "").strip())

            def _verify_signed_request(self, method: str, path: str, raw_body: bytes = b"") -> bool:
                secret = outer._token
                if not secret:
                    self._auth_debug(False, "missing-secret")
                    return False
                if not outer._token_live():
                    self._auth_debug(False, "token-expired")
                    return False
                h = self.headers
                ts_s = (h.get("X-KQ-Ts") or "").strip()
                nonce = (h.get("X-KQ-Nonce") or "").strip()
                sig = (h.get("X-KQ-Signature") or "").strip().lower()
                if not ts_s or not nonce or not sig:
                    self._auth_debug(False, "missing-signed-headers")
                    return False
                try:
                    ts_i = int(ts_s)
                except Exception:
                    self._auth_debug(False, "bad-ts", ts=ts_s)
                    return False
                now = _now_wall()
                if abs(now - ts_i) > _AUTH_WINDOW_SECS:
                    self._auth_debug(False, "ts-window", now=now, ts=ts_i, window=_AUTH_WINDOW_SECS)
                    return False
                body_hash = hashlib.sha256(raw_body or b"").hexdigest()
                msg = "\n".join([
                    (method or "").upper(),
                    path or "",
                    ts_s,
                    nonce,
                    body_hash,
                ]).encode("utf-8")
                expect = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest().lower()
                if not hmac.compare_digest(expect, sig):
                    self._auth_debug(False, "bad-signature", method=(method or "").upper(), path=path or "", body_hash=body_hash, expected=expect[:16], got=sig[:16])
                    return False
                with _AUTH_NONCE_LOCK:
                    _auth_prune_nonces(now)
                    if nonce in _AUTH_NONCE_SEEN:
                        self._auth_debug(False, "replayed-nonce", nonce=nonce[:16])
                        return False
                    _AUTH_NONCE_SEEN[nonce] = ts_i
                self._auth_debug(True, "signed")
                return True

            def _auth_mode(self, method: str, path: str, raw_body: bytes = b"") -> str:
                if self._has_signed_auth_headers() and self._verify_signed_request(method, path, raw_body):
                    return "signed"
                return "none"

            def _origin_ok(self) -> bool:
                origin = (self.headers.get("Origin") or "").strip()
                if origin and not (_is_allowed_origin(origin) and is_origin_allowed(origin)):
                    return False
                return True

            def _write_cors(self, code: int) -> bool:
                origin = (self.headers.get("Origin") or "").strip()
                if origin and not self._origin_ok():
                    self.send_error(403, "Origin not allowed")
                    return False
                self.send_response(code)
                if origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-KQ-Ts, X-KQ-Nonce, X-KQ-Signature")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Max-Age", "86400")
                return True

            def _write_json(self, code: int, obj: Dict[str, Any]):
                origin = (self.headers.get("Origin") or "").strip()
                if origin and not self._origin_ok():
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

            def _read_json(self) -> tuple[Dict[str, Any], bytes]:
                length = int(self.headers.get("Content-Length") or 0)
                payload = self.rfile.read(min(length, 16_384))
                return _safe_json_loads(payload), payload

            def do_OPTIONS(self):
                if not self._write_cors(200):
                    return
                self.end_headers()

            def do_GET(self):
                path = self._request_path_only()
                if path == "/v1/status":
                    auth_mode = self._auth_mode("GET", path, b"")
                    body = {
                        "status": "ok" if auth_mode == "signed" else "not match",
                        "auth_mode": auth_mode,
                        "locked": not _call_bool(outer.app, ("is_vault_unlocked", "is_unlocked", "vault_unlocked")),
                    }
                    self._write_json(200, body)
                    return
                if path == "/v1/health":
                    auth_mode = self._auth_mode("GET", path, b"")
                    app_unlocked = _call_bool(outer.app, ("is_vault_unlocked", "is_unlocked", "vault_unlocked"))
                    vault_unlocked = bool(auth_mode == "signed" and app_unlocked)
                    dbg = dict(outer._last_auth_debug or {})
                    if "expected" in dbg:
                        dbg["expected_prefix"] = dbg.pop("expected")
                    if "got" in dbg:
                        dbg["got_prefix"] = dbg.pop("got")
                    body = {
                        "bridge": True,
                        "auth_mode": auth_mode,
                        "token_valid": auth_mode == "signed",
                        "signed_auth": auth_mode == "signed",
                        "session": bool(app_unlocked),
                        "app_vault_unlocked": bool(app_unlocked),
                        "vault_unlocked": vault_unlocked,
                        "autofill_ready": vault_unlocked,
                        "debug": dbg,
                    }
                    self._write_json(200, body)
                    return
                self._write_json(404, {"error": "not found"})

            def do_POST(self):
                path = self._request_path_only()
                if not self._origin_ok():
                    self._write_json(403, {"error": "forbidden"})
                    return
                try:
                    data, payload = self._read_json()
                except Exception:
                    self._write_json(400, {"error": "bad json"})
                    return
                auth_mode = self._auth_mode("POST", path, payload)
                if auth_mode != "signed":
                    self._write_json(401, {"error": "unauthorized", "auth_mode": auth_mode, "debug": outer._last_auth_debug})
                    return

                if path == "/v1/query":
                    origin = str(data.get("origin") or "")
                    hosts = _host_variants_from_origin(origin)
                    if not origin or not hosts:
                        self._write_json(400, {"error": "invalid origin", "auth_mode": auth_mode})
                        return
                    if not _call_bool(outer.app, ("is_vault_unlocked", "is_unlocked", "vault_unlocked")):
                        self._write_json(423, {"error": "locked", "auth_mode": auth_mode})
                        return
                    entries = []
                    seen = set()
                    for hk in hosts:
                        for e in (_call_entries(outer.app, hk) or []):
                            key = (e.get("id") or "", e.get("title") or "", e.get("username") or e.get("user") or "", e.get("password") or e.get("pass") or "")
                            if key in seen:
                                continue
                            seen.add(key)
                            entries.append(e)
                    out = []
                    for e in entries[:10]:
                        out.append({
                            "title": e.get("title") or e.get("name") or (hosts[0] if hosts else "login"),
                            "username": e.get("username") or e.get("user") or "",
                            "password": e.get("password") or e.get("pass") or "",
                        })
                    self._write_json(200, {"entries": out, "auth_mode": auth_mode})
                    return

                if path == "/v1/otp":
                    origin = str(data.get("origin") or "")
                    hosts = _host_variants_from_origin(origin)
                    if not origin or not hosts:
                        self._write_json(400, {"error": "invalid origin", "auth_mode": auth_mode})
                        return
                    code = None
                    for hk in hosts:
                        code = _call_otp(outer.app, hk)
                        if code is not None:
                            break
                    if code is None:
                        self._write_json(404, {"error": "no totp", "auth_mode": auth_mode})
                    else:
                        self._write_json(200, {"code": str(code), "auth_mode": auth_mode})
                    return

                self._write_json(404, {"error": "not found", "auth_mode": auth_mode})

        return Handler


def _call_bool(app, names) -> bool:
    for n in names:
        fn = getattr(app, n, None)
        if callable(fn):
            try:
                return bool(fn())
            except Exception:
                pass
    return False


def _call_entries(app, host: str):
    for n in ("get_entries_for_origin", "query_entries_for_origin", "query_vault_for_origin"):
        fn = getattr(app, n, None)
        if callable(fn):
            try:
                return fn(host)
            except Exception:
                pass
    return []


def _call_otp(app, host: str):
    for n in ("get_totp_for_origin", "query_totp_for_origin", "get_otp_for_origin"):
        fn = getattr(app, n, None)
        if callable(fn):
            try:
                return fn(host)
            except Exception:
                pass
    return None
