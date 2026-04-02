"""
Keyquorum Vault
Copyright (C) 2025-2026 Anthony Hatton (AJH Software)

User catalog storage (clients/aliases/platform guide/autofill recipes).

STRICT DLL-only mode:
- Catalog is encrypted/decrypted using the native session (AES-256-GCM).
- No raw vault key bytes are ever used in Python.
- Integrity is provided by AES-GCM tags (no separate HMAC seal).

On-disk format: JSON with base64 fields {"iv","tag","data"}.
"""

from __future__ import annotations

import os, json, base64
from typing import Any
import logging
log = logging.getLogger("keyquorum")

from app.paths import catalog_file
from native.native_core import get_core


def _build_default_catalog(b_clients, b_aliases, b_guide, b_recipes=None) -> dict:
    return {
        "CLIENTS": b_clients,
        "ALIASES": b_aliases,
        "PLATFORM_GUIDE": b_guide,
        "AUTOFILL_RECIPES": b_recipes or {},
        "version": 1,
    }


def _encrypt_json_native(obj: dict, session_handle: int) -> bytes:
    core = get_core()
    iv = os.urandom(12)
    pt = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    ct_ba, tag_ba = core.session_encrypt(session_handle, iv, pt)
    payload = {
        "iv": base64.b64encode(iv).decode("ascii"),
        "tag": base64.b64encode(bytes(tag_ba)).decode("ascii"),
        "data": base64.b64encode(bytes(ct_ba)).decode("ascii"),
        "ver": 1,
    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _decrypt_json_native(blob: bytes, session_handle: int) -> dict:
    """Decrypt an encrypted JSON container using native session.

    Supports:
      A) JSON envelope (utf-8 JSON with base64 fields)
      B) Binary: iv(12)||tag(16)||ct
      C) Binary: iv(12)||ct||tag(16)
    """
    if not blob:
        return {}
    if not isinstance(session_handle, int) or not session_handle:
        raise RuntimeError("native session missing/invalid")

    core = get_core()

    def _dec(iv: bytes, ct: bytes, tag: bytes) -> dict:
        pt_ba = core.session_decrypt(int(session_handle), iv, ct, tag)
        try:
            return json.loads(bytes(pt_ba).decode("utf-8"))
        finally:
            try:
                core.secure_wipe(pt_ba)
            except Exception:
                pass

    # JSON envelope
    if blob[:1] in (b"{", b"["):
        try:
            obj = json.loads(blob.decode("utf-8"))
            # allow plaintext json dict
            if isinstance(obj, dict) and ("iv" not in obj or ("data" not in obj and "vault_data" not in obj)):
                return obj
            iv = base64.b64decode(obj["iv"])
            tag = base64.b64decode(obj["tag"])
            ct = base64.b64decode(obj.get("data") or obj.get("vault_data"))
            return _dec(iv, ct, tag)
        except Exception:
            pass

    # binary
    if len(blob) < 12 + 16:
        raise RuntimeError("Encrypted blob too small/invalid format")

    iv = blob[:12]
    rest = blob[12:]

    # iv||tag||ct
    if len(rest) >= 16:
        tag1 = rest[:16]
        ct1 = rest[16:]
        try:
            return _dec(iv, ct1, tag1)
        except Exception:
            pass

    # iv||ct||tag
    tag2 = rest[-16:]
    ct2 = rest[:-16]
    return _dec(iv, ct2, tag2)


def ensure_user_catalog_created(username: str, b_clients, b_aliases, b_guide, b_recipes=None, session_handle: int | None = None):
    """Ensure the encrypted catalog file exists for `username`.

    In strict mode, `session_handle` is required to create the file.
    """
    enc_path = catalog_file(username, ensure_parent=True)
    if os.path.exists(enc_path):
        return enc_path

    if not isinstance(session_handle, int) or not session_handle:
        raise RuntimeError("Native session handle required to create catalog")

    catalog = _build_default_catalog(b_clients, b_aliases, b_guide, b_recipes)
    blob = _encrypt_json_native(catalog, session_handle)
    with open(enc_path, "wb") as f:
        f.write(blob)
    return enc_path


def load_user_catalog_raw(username: str, session_handle: int | None) -> dict:
    enc_path = catalog_file(username)
    if not os.path.exists(enc_path):
        log.debug("[CATALOG] no catalog file; returning empty overlay")
        return {}
    if not isinstance(session_handle, int) or not session_handle:
        log.debug("[CATALOG] session missing; cannot decrypt")
        return {}

    try:
        blob = open(enc_path, "rb").read()
        # if it looks like plaintext JSON overlay (dev leftovers), accept it
        try:
            o = json.loads(blob.decode("utf-8"))
            if isinstance(o, dict) and ("iv" not in o or "data" not in o):
                return o
        except Exception:
            pass
        return _decrypt_json_native(blob, session_handle) or {}
    except Exception as e:
        log.error("[CATALOG] decrypt failed: %s", e)
        return {}


def save_user_catalog(username: str, overlay: dict, *, session_handle: int):
    if not isinstance(session_handle, int) or not session_handle:
        raise RuntimeError("Native session handle required")
    enc_path = catalog_file(username, ensure_parent=True)
    blob = _encrypt_json_native(overlay or {}, session_handle)
    with open(enc_path, "wb") as f:
        f.write(blob)


def merge_catalogs(b_clients, b_aliases, b_guide, b_recipes, overlay: dict) -> dict:
    base = _build_default_catalog(b_clients, b_aliases, b_guide, b_recipes)
    if not isinstance(overlay, dict):
        return base
    for k in ("CLIENTS", "ALIASES", "PLATFORM_GUIDE", "AUTOFILL_RECIPES"):
        if isinstance(overlay.get(k), dict):
            base[k].update(overlay.get(k) or {})
    return base


def load_effective_catalogs_from_user(username: str, b_clients, b_aliases, b_guide, b_recipes=None, *, session_handle: int, user_overlay: dict | None = None):
    overlay = user_overlay if isinstance(user_overlay, dict) else load_user_catalog_raw(username, session_handle)
    eff = merge_catalogs(b_clients, b_aliases, b_guide, b_recipes or {}, overlay)
    return eff.get("CLIENTS", {}), eff.get("ALIASES", {}), eff.get("PLATFORM_GUIDE", {}), eff.get("AUTOFILL_RECIPES", {}), overlay


def debug_catalog_status(username: str) -> dict:
    enc_path = catalog_file(username)
    return {
        "path": enc_path,
        "exists": os.path.exists(enc_path),
        "size": os.path.getsize(enc_path) if os.path.exists(enc_path) else 0,
    }


def migrate_user_catalog_overlay(username: str, old_session_handle: int, new_session_handle: int):
    """
    Migrate the encrypted user catalog overlay from old DLL session -> new DLL session.

    DLL-only:
    - read/decrypt with old_session_handle
    - save/encrypt with new_session_handle
    - no Python crypto fallback

    Backward-compatible behavior:
    - if the file is still plaintext JSON, re-encrypt it with new_session_handle
    """
    enc_path = catalog_file(username)
    if not os.path.exists(enc_path):
        return True, "No catalog overlay file found."

    try:
        old_sess = int(old_session_handle) if old_session_handle else 0
        new_sess = int(new_session_handle) if new_session_handle else 0
    except Exception:
        return False, "Invalid session handle(s)."

    if old_sess <= 0 or new_sess <= 0:
        return False, "Missing old/new session handle."

    if old_sess == new_sess:
        return True, "Catalog migration skipped (same session)."

    try:
        # 1) Normal case: load current overlay using OLD session
        data = load_user_catalog_raw(username, old_sess)

        if isinstance(data, dict) and data:
            save_user_catalog(username, data, session_handle=new_sess)
            return True, f"Migrated catalog overlay ({len(data)} top-level item(s))."

        # 2) If empty dict came back, check whether the file is legacy plaintext JSON
        blob = open(enc_path, "rb").read()
        try:
            o = json.loads(blob.decode("utf-8"))
        except Exception:
            return False, "Catalog overlay could not be loaded with old session and is not plaintext JSON."

        if not isinstance(o, dict):
            return False, "Catalog overlay plaintext format is invalid."

        # If it already looks like encrypted wrapper JSON, then old-session decrypt failed
        if "iv" in o and "data" in o:
            return False, "Catalog overlay appears encrypted but could not be loaded with old session."

        save_user_catalog(username, o, session_handle=new_sess)
        return True, f"Upgraded plaintext catalog overlay ({len(o)} top-level item(s))."

    except Exception as e:
        return False, f"Catalog migration failed: {e}"
