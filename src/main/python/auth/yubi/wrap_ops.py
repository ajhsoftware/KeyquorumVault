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

def rekey_user_stores(
    username: str,
    old_key: bytes | None = None,
    new_key: bytes | None = None,
    *,
    old_vault_session: int | None = None,
    new_vault_session: int | None = None,
) -> dict:
    """Re-encrypt all key-dependent user stores after a master-key change.

    Backward compatible call styles:
      - rekey_user_stores(username, old_key_bytes, new_key_bytes)
      - rekey_user_stores(username, old_key_bytes, new_key_bytes,
                          old_vault_session=..., new_vault_session=...)

    The main vault may require native session handles in strict DLL mode, so
    supplied session handles are preferred for vault load/save when present.
    Sidecar stores still use old_key/new_key bytes because they derive HKDF
    subkeys from the vault key material.
    """
    summary = {
        "vault_reencrypted": False,
        "authstore_migrated": False,
        "pw_hist_cleared": False,
        "sidecars_migrated": 0,
        "sidecars_skipped": 0,
        "errors": [],
    }

    old_has_bytes = isinstance(old_key, (bytes, bytearray))
    new_has_bytes = isinstance(new_key, (bytes, bytearray))
    old_has_session = isinstance(old_vault_session, int) and old_vault_session > 0
    new_has_session = isinstance(new_vault_session, int) and new_vault_session > 0

    if not old_has_bytes and not old_has_session:
        raise TypeError("rekey_user_stores: need old_key bytes or old_vault_session")

    if not new_has_bytes and not new_has_session:
        raise TypeError("rekey_user_stores: need new_key bytes or new_vault_session")

    old_key_b = bytes(old_key) if old_has_bytes else None
    new_key_b = bytes(new_key) if new_has_bytes else None

    old_handle = old_vault_session if old_has_session else old_key_b
    new_handle = new_vault_session if new_has_session else new_key_b

    # 1) Load vault using session handle when available
    try:
        from vault_store.vault_store import load_vault, save_vault
        data = load_vault(username, old_handle)
    except Exception as e:
        summary["errors"].append(f"vault_load:{e!r}")
        raise

    entries = None
    try:
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            for k in ("entries", "items", "vault", "rows", "data"):
                v = data.get(k)
                if isinstance(v, list):
                    entries = v
                    break
    except Exception:
        entries = None

    # Authenticator store migration (inside entries) requires raw key bytes
    try:
        if entries is not None and old_key_b is not None and new_key_b is not None:
            try:
                from vault_store.authenticator_store import rewrap_authenticator_entries
            except Exception:
                from features.auth_store.authenticator_store import rewrap_authenticator_entries
            ok, msg, changed, failed = rewrap_authenticator_entries(entries, old_key_b, new_key_b)
            summary["authstore_migrated"] = bool(ok)
            if not ok and msg:
                summary["errors"].append(f"authstore:{msg}")
        elif entries is not None:
            summary["errors"].append("authstore_skipped:no_raw_key_material")
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

    # Save vault using session handle when available. In strict DLL-only mode,
    # save_vault(username, session_handle, data) requires a native session handle
    # for the *new* key; raw bytes are not accepted there.
    created_new_session = None
    try:
        if not (isinstance(new_handle, int) and new_handle > 0):
            core = None
            try:
                from vault_store.vault_store import get_core
                core = get_core()
            except Exception:
                try:
                    from auth.login.auth_flow_ops import get_core
                    core = get_core()
                except Exception:
                    core = None
            if core is None or not hasattr(core, "open_session_from_key"):
                raise RuntimeError("Vault encryption requires native session handle (int).")
            created_new_session = int(core.open_session_from_key(bytearray(new_key_b)))
            new_handle = created_new_session

        # Correct save_vault signature in this project is (username, key_or_session, data)
        save_vault(username, new_handle, data)
        summary["vault_reencrypted"] = True
    except Exception as e:
        summary["errors"].append(f"vault_save:{e!r}")
        raise
    finally:
        if created_new_session:
            try:
                core.close_session(created_new_session)
            except Exception:
                pass

    # Byte-dependent sidecar migrations
    if old_key_b is not None and new_key_b is not None:
        try:
            import os
            from app.paths import trash_path, pw_cache_file
            from features.sync.engine import decrypt_json_file, encrypt_json_file

            try:
                p_pw = str(pw_cache_file(username))
                if os.path.exists(p_pw):
                    info = f"pwcache:{username}".encode("utf-8")
                    obj = decrypt_json_file(p_pw, hkdf_subkey(old_key_b, info)) or {}
                    encrypt_json_file(p_pw, hkdf_subkey(new_key_b, info), obj)
                    summary["pw_hist_cleared"] = True
            except Exception as e:
                summary["errors"].append(f"pwcache_migrate:{e!r}")

            try:
                p_tr = str(trash_path(username))
                if os.path.exists(p_tr):
                    rows = decrypt_json_file(p_tr, hkdf_subkey(old_key_b, b"trash")) or []
                    encrypt_json_file(p_tr, hkdf_subkey(new_key_b, b"trash"), rows)
                    summary["sidecars_migrated"] += 1
            except Exception as e:
                summary["errors"].append(f"trash_migrate:{e!r}")

            try:
                from catalog_category.catalog_user import migrate_user_catalog_overlay
                ok, msg = migrate_user_catalog_overlay(username, old_key_b, new_key_b)
                if not ok:
                    summary["errors"].append(f"catalog_migrate:{msg}")
            except Exception as e:
                summary["errors"].append(f"catalog_migrate:{e!r}")
        except Exception as e:
            summary["errors"].append(f"explicit_store_migrate:{e!r}")

        # Best-effort sidecar migration
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

                seen = set()
                for p in candidates:
                    if p.is_file():
                        seen.add(str(p.resolve()))

                for s in sorted(seen):
                    p = _Path(s)
                    try:
                        blob = load_encrypted(str(p), old_key_b)
                        save_encrypted(blob, str(p), new_key_b)
                        summary["sidecars_migrated"] += 1
                    except Exception:
                        summary["sidecars_skipped"] += 1
        except Exception:
            pass
    else:
        summary["errors"].append("sidecar_migration_skipped:no_raw_key_material")

    update_baseline(username, verify_after=False, who="Yubi Key Wrap")
    return summary
