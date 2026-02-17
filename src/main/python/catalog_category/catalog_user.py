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


import os, json, hmac, hashlib
from typing import Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.paths import catalog_file, catalog_seal_file
import logging
log = logging.getLogger("keyquorum")


# ==============================
# --- Crypto helpers (AES-GCM + HMAC integrity)
# ==============================
def _hkdf_subkey(user_key: bytes, info: bytes) -> bytes:
    salt = b"\x00" * 32
    prk = hmac.new(salt, user_key, hashlib.sha256).digest()
    t = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t  # 32 bytes


def encrypt_json(plain: dict, user_key: bytes) -> bytes:
    key = _hkdf_subkey(user_key, b"catalog:aesgcm-32")
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(plain, ensure_ascii=False).encode("utf-8"), None)
    return nonce + ct


def decrypt_json(blob: bytes, user_key: bytes) -> dict:
    if not blob:
        return {}
    key = _hkdf_subkey(user_key, b"catalog:aesgcm-32")
    nonce, ct = blob[:12], blob[12:]
    pt = AESGCM(key).decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))



def write_hmac_seal(username: str, obj: dict, user_key: bytes) -> None:
    msg = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    mac = hmac.new(_hkdf_subkey(user_key, b"catalog:hmac-32"), msg, hashlib.sha256).hexdigest()
    f = catalog_seal_file(username, ensure_dir=True)
    with open(f, "w", encoding="utf-8") as f:
        f.write(mac)


def verify_hmac_seal(username: str, obj: dict, user_key: bytes) -> bool:
    try:
        f = catalog_seal_file(username, ensure_dir=True)
        with open(f, "r", encoding="utf-8") as f:
            want = f.read().strip()
    except Exception:
        return False
    msg = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    mac = hmac.new(_hkdf_subkey(user_key, b"catalog:hmac-32"), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, mac)


# ==============================
# --- Catalog load / save
# ==============================
def _build_default_catalog(b_clients, b_aliases, b_guide, b_recipes=None) -> dict:
    return {
        "CLIENTS": b_clients,
        "ALIASES": b_aliases,
        "PLATFORM_GUIDE": b_guide,
        "AUTOFILL_RECIPES": b_recipes or {},
        "version": 1,
    }


def ensure_user_catalog_created(username: str, b_clients, b_aliases, b_guide, b_recipes=None, user_key: bytes | None = None):
    enc_path = catalog_file(username, ensure_parent=True)
    if os.path.exists(enc_path):
        return enc_path
    catalog = _build_default_catalog(b_clients, b_aliases, b_guide, b_recipes)
    if user_key:
        blob = encrypt_json(catalog, user_key)
        with open(enc_path, "wb") as f:
            f.write(blob)
        write_hmac_seal(username, catalog, user_key)
    else:
        with open(enc_path, "w", encoding="utf-8") as f:
            json.dump(catalog, f, indent=2, ensure_ascii=False)
    return enc_path

def load_user_catalog_raw(username: str, user_key: bytes | None) -> dict:
    enc_path = catalog_file(username)
    if not os.path.exists(enc_path):
        log.debug("[CATALOG] no encrypted catalog file – returning empty overlay – returning empty overlay")
        return {}
    try:
        if not user_key:
            log.debug("[CATALOG] WARNING: user_key missing; cannot decrypt catalog.enc")
            return {}
        with open(enc_path, "rb") as f:
            return decrypt_json(f.read(), user_key)
    except Exception as e:
        log.debug("[CATALOG] decrypt failed:", e)
        return {}


def save_user_catalog(username: str, data: dict, user_key: bytes | None = None):
    enc_path = catalog_file(username, ensure_parent=True)
    if user_key:
        blob = encrypt_json(data, user_key)
        with open(enc_path, "wb") as f:
            f.write(blob)
        write_hmac_seal(username, data, user_key)
    else:
        with open(enc_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


# ==============================
# --- Merge logic (respects __deleted__)
# ==============================

def merge_catalogs(builtins: dict, user_overlay: dict) -> dict:
    """
    Merge built-ins and user overlay for the catalog.

    Rules:
    - Start from built-ins.
    - Apply per-user overrides for any fields present in user CLIENTS.
    - Add any user-only CLIENTS that don't exist in built-ins.
    - Respect __deleted__ so users can hide built-in entries.
    - ALIASES and PLATFORM_GUIDE: user values override built-ins key-by-key.
    """
    b = builtins or {}
    u = user_overlay or {}

    deleted = set(u.get("__deleted__", []))

    base_clients = b.get("CLIENTS", {}) or {}
    user_clients = u.get("CLIENTS", {}) or {}

    res_clients: dict = {}

    # 1) Built-in clients, unless deleted
    for k, v in base_clients.items():
        if k in deleted:
            # User explicitly “deleted” this built-in client
            continue

        # Start from built-in definition
        merged = dict(v)

        # If user has overrides for this client, apply them
        u_client = user_clients.get(k)
        if isinstance(u_client, dict):
            # Overlay fields completely override built-in ones:
            # protocols, domains, exe_paths, installer, page, emails, etc.
            merged.update(u_client)

        res_clients[k] = merged

    # 2) User-only clients (not in built-ins at all)
    for k, v in user_clients.items():
        if k in base_clients:
            # Already handled above as an override
            continue
        if k in deleted:
            # If user somehow marked a non-built-in as deleted, skip
            continue
        if isinstance(v, dict):
            res_clients[k] = dict(v)

    # 3) Aliases – user overlay overrides built-ins per key
    base_aliases = b.get("ALIASES", {}) or {}
    user_aliases = u.get("ALIASES", {}) or {}
    res_aliases = dict(base_aliases)
    res_aliases.update(user_aliases)

    # 4) Platform guide – same pattern
    base_guide = b.get("PLATFORM_GUIDE", {}) or {}
    user_guide = u.get("PLATFORM_GUIDE", {}) or {}
    res_guide = dict(base_guide)
    res_guide.update(user_guide)

    base_recipes = b.get("AUTOFILL_RECIPES", {}) or {}
    user_recipes = u.get("AUTOFILL_RECIPES", {}) or {}
    res_recipes = dict(base_recipes)
    # user overlay wins key-by-key; allow per-client dict overrides
    for rk, rv in user_recipes.items():
        if isinstance(rv, dict) and isinstance(res_recipes.get(rk), dict):
            merged_r = dict(res_recipes.get(rk) or {})
            merged_r.update(rv)
            res_recipes[rk] = merged_r
        else:
            res_recipes[rk] = rv

    return {
        "CLIENTS": res_clients,
        "ALIASES": res_aliases,
        "PLATFORM_GUIDE": res_guide,
        "AUTOFILL_RECIPES": res_recipes,
        "__deleted__": sorted(deleted),
        "version": u.get("version", 1),
    }


def load_effective_catalogs_from_user(
    username: str,
    CLIENTS: dict,
    ALIASES: dict,
    PLATFORM_GUIDE: dict,
    AUTOFILL_RECIPES: dict | None = None,
    user_key: bytes | None = None,
    user_overlay: dict | None = None,
) -> Tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict]:
    overlay = user_overlay if user_overlay is not None else load_user_catalog_raw(username, user_key)
    merged = merge_catalogs(
        {"CLIENTS": CLIENTS, "ALIASES": ALIASES, "PLATFORM_GUIDE": PLATFORM_GUIDE, "AUTOFILL_RECIPES": (AUTOFILL_RECIPES or {})},
        overlay or {}
    )
    return merged["CLIENTS"], merged["ALIASES"], merged["PLATFORM_GUIDE"], merged.get("AUTOFILL_RECIPES", {}) or {}, merged


# --- Diagnostics -------------------

def debug_catalog_status(username: str, user_key: bytes | None):
    """Prints catalog file existence, overlay stats, and HMAC result."""
    try:
        enc = catalog_file(username, ensure_parent=True)
        log.debug(f"[CATALOG] path: {enc}")
        log.debug(f"[CATALOG] exists: {os.path.exists(enc)} size={os.path.getsize(enc) if os.path.exists(enc) else 0}")

        overlay = load_user_catalog_raw(username, user_key)
        log.debug(f"[CATALOG] overlay keys: {list(overlay.keys())}")
        dels = set(overlay.get("__deleted__", [])) if isinstance(overlay, dict) else set()
        log.debug(f"[CATALOG] __deleted__ count: {len(dels)} ({sorted(list(dels))[:5]}{'...' if len(dels)>5 else ''})")

        ok = False
        if user_key:
            try:
                ok = verify_hmac_seal(username, overlay or {}, user_key)
            except Exception as e:
                log.debug("[CATALOG] HMAC verify error:", e)
        log.debug(f"[CATALOG] HMAC ok: {ok}")

        return overlay, ok
    except Exception as e:
        log.debug("[CATALOG] debug_catalog_status failed:", e)
        return {}, False

# ==============================
# --- password change
# ==============================
def migrate_user_catalog_overlay(username: str, old_key: bytes, new_key: bytes):
    """
    Re-encrypt the user's catalog overlay (catalog.enc) from old_key -> new_key.
    Returns (ok: bool, msg: str)
    """
    if not username:
        return False, "No username"
    if not old_key or not new_key or old_key == new_key:
        return True, "No key change"

    try:
        overlay = load_user_catalog_raw(username, old_key) or {}
        if not overlay:
            return True, "No overlay to migrate"

        # Save overlay under new key
        save_user_catalog(username, overlay, new_key)

        # Re-seal under new key
        try:
            write_hmac_seal(username, overlay, new_key)
        except TypeError:
            write_hmac_seal(username, new_key)

        return True, "Catalog overlay migrated"
    except Exception as e:
        return False, f"Catalog migrate failed: {e}"
