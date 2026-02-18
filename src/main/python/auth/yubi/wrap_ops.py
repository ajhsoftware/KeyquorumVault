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

# -*- coding: utf-8 -*-
# Legacy note (kept as comment so __future__ import stays valid):
# This project is currently distributed as freeware. A source-available / open-source
# release may follow in the future.

from __future__ import annotations

from auth.login.auth_flow_ops import update_baseline
import hmac
import hashlib
import os

def rekey_vault(username: str, old_key: bytes, new_key: bytes) -> None:
    """
    Load the user's vault with old_key and immediately re-save it with new_key.

    SECURITY NOTE:
      - This is a destructive re-encryption step. Callers should ensure a verified
        backup exists before migrating keys.
    """
    from vault_store.vault_store import load_vault, save_vault
    if not isinstance(old_key, (bytes, bytearray)) or not isinstance(new_key, (bytes, bytearray)):
        raise TypeError("rekey_vault: keys must be bytes")
    data = load_vault(username, bytes(old_key)) # raises if wrong key
    save_vault(username, bytes(new_key), data)  

def bytes_equal(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to reduce timing side-channels."""
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        return False
    return hmac.compare_digest(bytes(a), bytes(b))

def hkdf_subkey(user_key: bytes, info: bytes) -> bytes:
    """Tiny HKDF-SHA256-ish (HMAC-based) 32B subkey, matching app_window._hkdf_subkey."""
    if not isinstance(info, (bytes, bytearray)):
        raise TypeError("hkdf_subkey: info must be bytes")

    # SECURITY NOTE:
    # SHA-256 used for salted one-time backup codes.
    # Not used for password hashing.

    salt = b"\x00" * 32
    prk = hmac.new(salt, bytes(user_key), hashlib.sha256).digest()
    t = hmac.new(prk, bytes(info) + b"\x01", hashlib.sha256).digest()
    return t

def rekey_user_stores(username: str, old_key: bytes, new_key: bytes) -> dict:
    """Re-encrypt all key-dependent user stores after a master-key change.

    Guarantees:
      • Main vault is re-encrypted old_key -> new_key (raises if old_key wrong).
      • Authenticator secrets stored inside vault entries are rewrapped (best-effort).
      • Password history fingerprints are cleared (they become invalid after key change).

    Best-effort:
      • Sidecar encrypted stores in the same vault directory (trash/soft-delete/passkeys/etc).
        We only touch files we can decrypt with old_key, and re-save with new_key.

    Returns a small summary dict for logging/UI.
    """
    summary = {
        "vault_reencrypted": False,
        "authstore_migrated": False,
        "pw_hist_cleared": False,
        "sidecars_migrated": 0,
        "sidecars_skipped": 0,
        "errors": [],
    }

    if not isinstance(old_key, (bytes, bytearray)) or not isinstance(new_key, (bytes, bytearray)):
        raise TypeError("rekey_user_stores: keys must be bytes")

    # 1) Load + mutate vault -------
    try:
        from vault_store.vault_store import load_vault, save_vault
        data = load_vault(username, bytes(old_key))
    except Exception as e:
        summary["errors"].append(f"vault_load:{e!r}")
        raise

    # Extract entries list for migrations
    entries = None
    try:
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            for k in ("entries", "items", "vault", "rows", "data"):
                v = data.get(k)
                if isinsta
























































































































                nce(v, list):
                    entries = v
                    break
    except Exception:
        entries = None

    # Authenticator store migration (inside entries)
    try:
        if entries is not None:
            from vault_store.authenticator_store import rewrap_authenticator_entries
            ok, msg, changed, failed = rewrap_authenticator_entries(entries, bytes(old_key), bytes(new_key))
            summary["authstore_migrated"] = bool(ok)
    except Exception as e:
        summary["errors"].append(f"authstore:{e!r}")

    # Password history: clear pw_hist because hist_key depends on vault key
    try:
        if entries is not None:
            cleared_any = False
            for it in entries:
                if isinstance(it, dict) and isinstance(it.get("pw_hist"), list) and it.get("pw_hist"):
                    it["pw_hist"] = []
                    cleared_any = True
            summary["pw_hist_cleared"] = cleared_any
    except Exception as e:
        summary["errors"].append(f"pw_hist:{e!r}")

    # Save vault under new key
    try:
        save_vault(username, bytes(new_key), data)
        summary["vault_reencrypted"] = True
    except Exception as e:
        summary["errors"].append(f"vault_save:{e!r}")
        raise

    # 1b) Explicit migration of known encrypted JSON stores -------------------
    # These are key-derived stores that are NOT guaranteed to be compatible with
    # the generic "sidecar" heuristics (they use HKDF subkeys).
    try:
        from app.paths import trash_path, pw_cache_file
        from sync.engine import decrypt_json_file, encrypt_json_file

        # pwcache (password history)
        try:
            p_pw = str(pw_cache_file(username))
            if os.path.exists(p_pw):
                info = f"pwcache:{username}".encode("utf-8")
                obj = decrypt_json_file(p_pw, hkdf_subkey(bytes(old_key), info)) or {}
                encrypt_json_file(p_pw, hkdf_subkey(bytes(new_key), info), obj)
                summary["pw_hist_cleared"] = True
            else:
                pass
        except Exception as e:
            summary["errors"].append(f"pwcache_migrate:{e!r}")

        # Trash / soft delete
        try:
            p_tr = str(trash_path(username))
            if os.path.exists(p_tr):
                rows = decrypt_json_file(p_tr, hkdf_subkey(bytes(old_key), b"trash")) or []
                encrypt_json_file(p_tr, hkdf_subkey(bytes(new_key), b"trash"), rows)
                # count as sidecar migrated for summary
                summary["sidecars_migrated"] += 1
            else:
                pass
        except Exception as e:
            summary["errors"].append(f"trash_migrate:{e!r}")

        # User catalog overlay (+ seal)
        try:
            from catalog_category.catalog_user import migrate_user_catalog_overlay
            ok, msg = migrate_user_catalog_overlay(username, bytes(old_key), bytes(new_key))
            if not ok:
                summary["errors"].append(f"catalog_migrate:{msg}")
        except Exception as e:
            summary["errors"].append(f"catalog_migrate:{e!r}")

    except Exception as e:
        summary["errors"].append(f"explicit_store_migrate:{e!r}")
        # 2) Best-effort sidecar migration --------------------------------------
        try:
            from pathlib import Path as _Path
            from vault_store.vault_store import get_vault_path, load_encrypted, save_encrypted
            vpath = _Path(get_vault_path(username))
            base_dir = vpath.parent if vpath else None
            if base_dir and base_dir.exists():
                candidates = []
                candidates += list(base_dir.glob("*trash*"))
                candidates += list(base_dir.glob("*soft*"))
                candidates += list(base_dir.glob("*deleted*"))
                candidates += list(base_dir.glob("passkeys_store.*"))
                candidates += list(base_dir.glob("passkeys*"))
                # De-duplicate
                seen=set()
                for p in candidates:
                    if p.is_file():
                        s=str(p.resolve())
                        if s not in seen:
                            seen.add(s)

                for s in sorted(seen):
                    p = _Path(s)
                    try:
                        blob = load_encrypted(str(p), bytes(old_key))
                        save_encrypted(blob, str(p), bytes(new_key))
                        summary["sidecars_migrated"] += 1
                    except Exception:
                        summary["sidecars_skipped"] += 1    
        except Exception:
            # If helpers don't exist in this build, skip silently (do not break WRAP enable)
            pass

        update_baseline(username,verify_after=False, who="Yubi Key Wrap")
        return summary
