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
import os, json, base64, logging, getpass, platform
from pathlib import Path
from typing import Any, Dict
import datetime as dt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None  # we'll guard for this below

from app.dev import dev_ops
is_dev = dev_ops.dev_set

# --- Native core (REQUIRED: strict DLL-only mode for vault crypto) ---
from native.native_core import get_core  # type: ignore


log = logging.getLogger("keyquorum")
# --- single source of truth (Phase 2 paths) ---
from app.paths import (
    ensure_dirs,
    vault_file,
    salt_file,
    user_db_file,
    vault_wrapped_file,
    identities_file,
)

from pathlib import Path
from os import urandom
import base64, hashlib

# --- baseline (best effort) ---
try:
    from security.baseline_signer import write_baseline
except Exception:
    def write_baseline(*a, **k):  
        pass

# --- optional KDF helper for export/import password envelope ---
try:
    from vault_store.kdf_utils import derive_key_argon2id
except Exception:
    derive_key_argon2id = None  

# --- KDF helper for export/import password envelope ---
try:
    from vault_store.kdf_utils import derive_key_argon2id
except Exception:
    derive_key_argon2id = None  

def _derive_key_export(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from password+salt for export/import using Argon2id.
    """
    if not derive_key_argon2id:
        raise RuntimeError("Argon2id support is required for backup/export key derivation.")
    return derive_key_argon2id(password, salt)

_KQBK_MAGIC = b"KQBK1"
_MAGIC = b"KQFB"
_VER   = 1
_SALT_LEN  = 16
_NONCE_LEN = 12

# ==============================
# Core path helpers expected by account_creator / main
# ==============================

def get_vault_path(username: str, ensure_parent:bool = False) -> str:
    """Absolute path to the encrypted vault file, ensuring parent dir exists."""
    return str(vault_file(username, ensure_parent=ensure_parent))

def get_salt_path(username: str, ensure_parent:bool = False) -> str:
    """Absolute path to the primary salt file, ensuring parent dir exists."""
    return str(salt_file(username, ensure_parent=ensure_parent, name_only=False))

def get_wrapped_key_path(username: str, ensure_parent:bool = False) -> str:
    """Absolute path to the wrapped-key file (recovery), ensuring parent dir exists."""
    return str(vault_wrapped_file(username, ensure_parent=ensure_parent, name_only=False))

def load_user_salt(username: str) -> bytes:
    p = Path(get_salt_path(username))
    return p.read_bytes()

def save_user_salt(username: str, salt_bytes: bytes) -> None:
    if not isinstance(salt_bytes, (bytes, bytearray)):
        raise TypeError("salt_bytes must be bytes")
    p = Path(get_salt_path(username))
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(bytes(salt_bytes))
        try:
            f.flush(); os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp, p)
    try: os.chmod(p, 0o600)
    except Exception: pass

# --- tiny AES-GCM helpers used for wrapping the vault key with the DMK -----

def _aes_enc(key: bytes,
             aad: bytes,
             plaintext: bytes,
             *,
             custom_nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Encrypt small blobs (vault key) with AES-GCM.
    Returns (nonce, ciphertext+tag).
    """
    if AESGCM is None:
        raise RuntimeError("AESGCM not available (cryptography missing)")
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("key must be 32 bytes (AES-256)")

    nonce = custom_nonce or os.urandom(12)
    aead = AESGCM(key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return nonce, ct

def _aes_dec(key: bytes,
             aad: bytes,
             nonce: bytes,
             ct: bytes) -> bytes:
    """
    Decrypt counterpart for _aes_enc.
    """
    if AESGCM is None:
        raise RuntimeError("AESGCM not available (cryptography missing)")
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("key must be 32 bytes (AES-256)")

    aead = AESGCM(key)
    return aead.decrypt(nonce, ct, aad)

# ==============================
# --- Vault unwrap/rewrap 
# ==============================

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def unwrap_old_vault_key(username: str, password: str) -> bytes:
    wrapped_path = Path(get_wrapped_key_path(username))
    data = wrapped_path.read_bytes()

    salt  = data[:16]
    nonce = data[16:28]
    ct    = data[28:]  # should be ciphertext+tag

    from vault_store.kdf_utils import derive_key_argon2id
    kek = derive_key_argon2id(password, salt)

    try:
        return _aes_dec(kek, b"KQID-VK-PW", nonce, ct)
    except InvalidTag:
        raise ValueError("Decryption failed")
    except Exception as e:
        log.error(f"Unexpected decryption error: {e}")
        raise

def rewrap_vault_key(username: str, old_password: str, new_password: str) -> bool:
    try:
        vk = unwrap_old_vault_key(username, old_password)

        salt  = os.urandom(16)
        nonce = os.urandom(12)

        from vault_store.kdf_utils import derive_key_argon2id
        kek_new = derive_key_argon2id(new_password, salt)

        # AESGCM encrypt returns ciphertext+tag
        _, ct = _aes_enc(kek_new, b"KQID-VK-PW", vk, custom_nonce=nonce)

        out = salt + nonce + ct
        wrapped_path = Path(get_wrapped_key_path(username))
        wrapped_path.parent.mkdir(parents=True, exist_ok=True)
        wrapped_path.write_bytes(out)
        return True
    except Exception as e:
        log.error(f"[VaultKey] rewrap failed: {e}")
        return False

def wrap_vault_key_dmk(username: str, dmk: bytes, vk: bytes) -> None:
    """
    Wrap vault key (VK) using the DMK instead of password.
    """
    path = Path(get_wrapped_key_path(username))
    path.parent.mkdir(parents=True, exist_ok=True)

    nonce = os.urandom(12)
    n, ct = _aes_enc(dmk, b"KQID-VK", vk, custom_nonce=nonce)
    # Format: nonce | ct
    path.write_bytes(n + ct)

def unwrap_vault_key_dmk(username: str, dmk: bytes) -> bytes:
    """
    Unwrap vault key from DMK wrapper.
    """
    path = Path(get_wrapped_key_path(username))
    data = path.read_bytes()
    nonce = data[:12]
    ct    = data[12:]
    vk = _aes_dec(dmk, b"KQID-VK", nonce, ct)
    return vk

# ==============================
# AES-GCM envelope (vault content)
# ==============================

def save_encrypted(plaintext_obj: Any, path: str, key_or_session) -> None:
    """Encrypt and write vault JSON (STRICT: native session handle only).

    key_or_session MUST be an int native session handle.
    This prevents any Python-based crypto fallback for vault encryption.
    """
    data = json.dumps(plaintext_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    iv = os.urandom(12)

    if not isinstance(key_or_session, int):
        raise RuntimeError("Vault encryption requires native session handle (int).")

    core = get_core()
    ct_ba, tag_ba = core.session_encrypt(key_or_session, iv, data)

    ct = bytes(ct_ba)
    tag = bytes(tag_ba)

    try:
        core.secure_wipe(ct_ba)
        core.secure_wipe(tag_ba)
    except Exception:
        pass

    obj: Dict[str, str] = {
        "iv":         base64.b64encode(iv).decode(),
        "tag":        base64.b64encode(tag).decode(),
        "vault_data": base64.b64encode(ct).decode(),
        "kdf":        "argon2id",   # informational
    }
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def load_encrypted(path: str, key_or_session):
    """Load and decrypt a vault JSON payload.

    STRICT DLL-only mode: requires a native session handle (int).

    Supports both formats automatically:
      A) JSON envelope: {"iv","tag","vault_data"} base64 (text or bytes)
      B) Binary blob: iv(12) || tag(16) || ct
      C) Binary blob: iv(12) || ct || tag(16)
    """
    from pathlib import Path
    import json, base64

    if not isinstance(key_or_session, int) or not key_or_session:
        raise RuntimeError("Vault decryption requires native session handle (int).")

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Vault file not found: {path}")

    blob = p.read_bytes()
    core = get_core()

    def _decrypt(iv: bytes, ct: bytes, tag: bytes):
        if is_dev:
            log.debug("[VAULT] decrypt using session=%s iv=%s ct=%s tag=%s",
                  key_or_session,
                  len(iv) if iv else 0,
                  len(ct) if ct else 0,
                  len(tag) if tag else 0)

            pt_buf = core.session_decrypt(int(key_or_session), iv, ct, tag)
            try:
                return json.loads(pt_buf)
            finally:
                try:
                    # Best-effort wipe of temporary decrypted buffer.
                    core.secure_wipe(pt_buf)
                except Exception as e:
                    log.warning("secure_wipe failed in load_encrypted: %r", e)

    # ---- A) JSON envelope
    if blob[:1] in (b"{", b"["):
        try:
            obj = json.loads(blob.decode("utf-8"))
            # allow plaintext JSON (dev/recovery)
            if isinstance(obj, (list, dict)) and ("iv" not in obj or ("vault_data" not in obj and "data" not in obj)):
                return obj

            iv = base64.b64decode(obj["iv"])
            tag = base64.b64decode(obj["tag"])
            ct  = base64.b64decode(obj.get("vault_data") or obj.get("data"))
            return _decrypt(iv, ct, tag)
        except Exception:
            pass  # fall through to binary

    # ---- B/C) binary
    if len(blob) < 12 + 16:
        raise RuntimeError("Encrypted file too small / invalid format")

    iv = blob[:12]
    rest = blob[12:]

    # B: iv || tag || ct
    if len(rest) >= 16:
        tag1 = rest[:16]
        ct1  = rest[16:]
        try:
            return _decrypt(iv, ct1, tag1)
        except Exception:
            pass

    # C: iv || ct || tag
    tag2 = rest[-16:]
    ct2  = rest[:-16]
    return _decrypt(iv, ct2, tag2)


def _verify_vault_owner(vault_path: str, username: str, auto_claim=True) -> bool:
    """
    Ensure the vault belongs to this user (simple .owner sidecar).
    """
    try:
        if not vault_path or not username:
            return False
        owner_path = os.path.splitext(vault_path)[0] + ".owner"
        if not os.path.exists(owner_path):
            if not auto_claim:
                return False
            meta = {
                "user": username,
                "created": dt.datetime.utcnow().isoformat() + "Z",
                "device": platform.node(),
                "created_by": getpass.getuser(),
                "verified": True,
            }
            os.makedirs(os.path.dirname(owner_path), exist_ok=True)
            with open(owner_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
            return True
        meta = json.loads(Path(owner_path).read_text(encoding="utf-8")) or {}
        owner = (meta.get("user", "") or "").strip().casefold()
        return owner == (username or "").strip().casefold()
    except Exception as e:
        log.error(f"[vault_store] owner check failed: {e}")
        return False

def verify_vault_owner(vault_path: str, username: str, *, auto_claim: bool = True) -> bool:
    """
    Public wrapper for ownership check. Kept for external callers (sync, etc.).
    """
    return _verify_vault_owner(vault_path, username, auto_claim=auto_claim)

def load_vault(username: str, key_or_session):
    try:
        raw = load_encrypted(get_vault_path(username), key_or_session)
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            return [raw] if raw else []
        if isinstance(raw, (str, bytes, bytearray)):
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return [parsed] if parsed else []
            return parsed if isinstance(parsed, list) else []
        return []
    except Exception as e:
        vp = get_vault_path(username)
        log.error("[VAULT] load_vault failed user=%s path=%s handle=%r err=%r", username, vp, key_or_session, e)
        # return None so UI knows vault isn't ready yet
        return None


def save_vault(username: str, key_or_session, entries: list) -> bool:
    """
    Encrypt and write the vault; then refresh the per-user baseline (best effort).
    """
    ensure_dirs()

    vp = get_vault_path(username)
    if not _verify_vault_owner(vp, username):
        raise PermissionError(f"Vault ownership mismatch for {username}")

    save_encrypted(entries, vp, key_or_session)

    # best-effort baseline refresh
    try:
        salt = load_user_salt(username)
        write_baseline(
            username,
            salt,
            [
                vp,
                get_salt_path(username),
                str(user_db_file(username)),   # per-user DB file
            ],
        )
    except Exception:
        pass
    return True

def add_vault_entry(username: str, key: bytes, entry: dict) -> None:
    entries = load_vault(username, key)
    entry["created_at"] = dt.datetime.now().isoformat()
    entries.append(entry)
    save_vault(username, key, entries)

def update_vault_entry(username: str, key: bytes, index: int, updated_data: dict) -> None:
    entries = load_vault(username, key)
    if 0 <= index < len(entries):
        entries[index].update(updated_data)
        entries[index]["updated_at"] = dt.datetime.now().isoformat()
        save_vault(username, key, entries)

def delete_vault_entry(username: str, key: bytes, index: int) -> None:
    entries = load_vault(username, key)
    if 0 <= index < len(entries):
        del entries[index]
        save_vault(username, key, entries)

def seed_vault(username: str, vault_path: str, key: bytes):
    """
    Initialize a new, empty vault file for the user.
    """
    empty_vault = []  # start with empty list of entries
    save_encrypted(empty_vault, vault_path, key)
    return True

def _dec_backup_bytes(password: str, blob: bytes) -> bytes:
    """
    Expects bytes: MAGIC | salt(16) | nonce(12) | AESGCM(ciphertext+tag)
    Raises ValueError on malformed header or wrong password.
    """
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < len(_KQBK_MAGIC) + _SALT_LEN + _NONCE_LEN + 16:
        raise ValueError("Backup file is too short or corrupted")

    blob = bytes(blob)  # normalize

    off = 0
    magic = blob[off:off + len(_KQBK_MAGIC)]
    off += len(_KQBK_MAGIC)

    if magic != _KQBK_MAGIC:
        raise ValueError("Not a Keyquorum backup or unknown format")

    salt = blob[off:off + _SALT_LEN]
    off += _SALT_LEN

    nonce = blob[off:off + _NONCE_LEN]
    off += _NONCE_LEN

    ct = blob[off:]
    key = _kdf_key(password, salt)
    aead = AESGCM(key)

    try:
        return aead.decrypt(nonce, ct, _KQBK_MAGIC)  # AAD = magic
    except Exception:
        raise ValueError("Backup decryption failed (wrong password or corrupted file)")

def _identity_fingerprint(username: str) -> str | None:
    """
    Returns a stable fingerprint for this account's identity file, or None
    if it cannot be read.

    We hash the raw identity bytes so we can later tell whether a backup
    belongs to the same account or not.
    """
    try:
        import hashlib
        identity_path = Path(identities_file(username, ensure_parent=True))
        if not identity_path.exists():
            return None
        raw = identity_path.read_bytes()
        h = hashlib.sha256(raw).digest()
        return base64.b64encode(h).decode("ascii")
    except Exception:
        return None

# ==============================
# --- simple password-wrapped export/import for the vault blob # --- vault only 
# ==============================

def export_vault_with_password(
    username: str,
    password: str,
    out_path: str | os.PathLike | None = None,
) -> str | None:
    """
    Wrap the existing *encrypted* vault blob in a password-protected envelope (AES-GCM).
    If out_path is provided, save there; otherwise use a sensible per-user default.
    Returns the absolute path on success, or None on failure.

    Security model:
    - The inner vault is STILL encrypted with this account's master key (MK).
      The export password just protects the backup file on disk/in transit.
    - We also embed:
        • identity_fingerprint: to ensure restore only goes back into the same account
        • category_schema: so category layout is restored along with the vault data
    """
    try:
        if not username or not password:
            log.error("[vault_store] export: missing username or password")
            return None

        vp = Path(get_vault_path(username))
        if not vp.exists():
            log.error("[vault_store] export: vault file not found: %s", vp)
            return None

        # --- fingerprint the account identity (for later account-match check) ---
        ident_fp = _identity_fingerprint(username)

        # --- snapshot category schema from user settings, if present ---
        category_schema: dict | None = None
        try:
            from auth.login.login_handler import get_user_setting  

            schema = get_user_setting(username, "category_schema", None)
            if isinstance(schema, dict) and isinstance(schema.get("categories"), list):
                category_schema = schema
        except Exception:
            category_schema = None

        # --- derive wrapping key from export password (Argon2id) ---
        salt = os.urandom(16)
        iv   = os.urandom(12)
        key  = _derive_key_export(password, salt)

        enc = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        ciphertext = enc.update(vp.read_bytes()) + enc.finalize()

        payload: dict[str, Any] = {
            "format": "keyquorum.v1",
            "username_hint": username,  # informational only
            "salt": base64.b64encode(salt).decode("ascii"),
            "iv":   base64.b64encode(iv).decode("ascii"),
            "tag":  base64.b64encode(enc.tag).decode("ascii"),
            "vault_data": base64.b64encode(ciphertext).decode("ascii"),
            "timestamp": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }

        # Attach identity fingerprint and category schema if available
        if ident_fp:
            payload["identity_fingerprint"] = ident_fp
        if category_schema:
            payload["category_schema"] = category_schema

        # Decide output path
        if out_path is None:
            default_dir = user_db_file(username, ensure_parent=True).parent
            default_name = f"{username}_vault_backup.kqbk"
            out_file = default_dir / default_name
        else:
            out_file = Path(out_path)

        out_file.parent.mkdir(parents=True, exist_ok=True)

        # Write atomically
        tmp = out_file.with_suffix(out_file.suffix + ".part")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(out_file)

        try:
            os.chmod(out_file, 0o600)
        except Exception:
            pass

        log.info("[vault_store] export: wrote %s", out_file)
        return str(out_file.resolve())

    except Exception as e:
        log.exception("[vault_store] export failed: %s", e)
        return None

def import_vault_with_password(username: str, password: str, vault_export_path: str | os.PathLike) -> bool:
    """
    Decrypt a .kqbk file created by export_vault_with_password and write it as the
    *current* user's vault file (overwriting existing).

    Important:
    - This does NOT make the vault account-agnostic. The inner vault blob is still
      encrypted with the original account's master key (MK).
    - We check an embedded identity fingerprint (if present) against this account's
      identity file to detect "wrong account" restores. On mismatch we abort.
    - If a category_schema is embedded in the backup, we restore it to the current
      account via set_user_setting, so categories come back with the vault.
    """
    try:
        src = Path(vault_export_path)
        if not src.exists():
            log.error("[vault_store] import: file not found: %s", src)
            return False

        data = json.loads(src.read_text(encoding="utf-8"))
        data = json.loads(src.read_text(encoding="utf-8"))

        # --- identity linkage check (if backup contains fingerprint) ---
        try:
            backup_fp = data.get("identity_fingerprint") or ""
            if backup_fp:
                current_fp = _identity_fingerprint(username) or ""
                if not current_fp:
                    log.error(
                        "[vault_store] import: backup has identity_fingerprint but "
                        "current account %r has no identity file; refusing import.",
                        username,
                    )
                    return False

                if backup_fp != current_fp:
                    log.error(
                        "[vault_store] import: identity mismatch for %r (backup != current). "
                        "This backup does not belong to this account.",
                        username,
                    )
                    return False
        except Exception as e:
            log.error("[vault_store] import: identity check failed: %s", e)
            return False

        # --- pull any embedded category schema (we apply after vault restore) ---
        backup_schema = data.get("category_schema", None)

        # --- decrypt AES-GCM envelope with EXPORT password ---
        salt_b = base64.b64decode(data["salt"])
        iv_b   = base64.b64decode(data["iv"])
        tag_b  = base64.b64decode(data["tag"])
        ct_b   = base64.b64decode(data["vault_data"])

        # Must match export: use _derive_key_export (Argon2id)
        key = _derive_key_export(password, salt_b)
        dec = Cipher(algorithms.AES(key), modes.GCM(iv_b, tag_b), backend=default_backend()).decryptor()
        plaintext = dec.update(ct_b) + dec.finalize()

        # --- overwrite current user's vault file ---
        dst = Path(vault_file(username, ensure_parent=True))
        dst.write_bytes(plaintext)
        try:
            os.chmod(dst, 0o600)
        except Exception:
            pass

        log.info("[vault_store] import: wrote vault for %s -> %s", username, dst)

        # --- restore category schema into user settings, if present ---
        try:
            if isinstance(backup_schema, dict) and isinstance(backup_schema.get("categories"), list):
                from auth.login.login_handler import set_user_setting  

                set_user_setting(username, "category_schema", backup_schema)
                log.info(
                    "[vault_store] import: restored category_schema for account %r "
                    "from vault backup",
                    username,
                )
        except Exception as e:
            log.warning(
                "[vault_store] import: failed to restore category_schema for %r: %s",
                username,
                e,
            )

        return True

    except Exception as e:
        log.exception("[vault_store] import failed: %s", e)
        return False

# --- Full-backup AES-GCM helpers (password-based) ------------------------------
# File format: b"KQBK1" + salt(16) + nonce(12) + ciphertext (incl. tag)

def _kdf_key(password: str, salt: bytes) -> bytes:
    """
    Derive a backup key from password+salt using the main Argon2id KDF.
    """
    return _derive_key_export(password, salt)

def _enc_backup_bytes(password: str, plain: bytes) -> bytes:
    """
    Returns bytes: MAGIC | salt(16) | nonce(12) | AESGCM(ciphertext+tag)
    """
    if not isinstance(plain, (bytes, bytearray)):
        raise TypeError("plain must be bytes")
    salt  = urandom(_SALT_LEN)
    key   = _kdf_key(password, salt)
    nonce = urandom(_NONCE_LEN)
    aead  = AESGCM(key)
    ct    = aead.encrypt(nonce, plain, _KQBK_MAGIC)   # AAD = magic
    return _KQBK_MAGIC + salt + nonce + ct


def export_full_backup(username: str, *args) -> str:
    """
    export_full_backup(username, password, out_dir)  # .zip.enc
    export_full_backup(username, out_dir)            # .zip (DEV ONLY)
    """
    import json, os, datetime as dt
    from io import BytesIO
    from zipfile import ZipFile
    from pathlib import Path
    # Phase-2 single source of truth
    from app.paths import (
        vault_file, salt_file, vault_wrapped_file, shared_key_file,
        identities_file, user_db_file, ensure_dirs,
    )

    # args
    if len(args) == 2:
        password, out_dir = args
    elif len(args) == 1:
        password, out_dir = None, args[0]
    else:
        raise ValueError("usage: export_full_backup(username, [password], out_dir)")

    ensure_dirs()
    out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)

    # Canonical Phase-2 file locations
    vault_path     = Path(vault_file(username, ensure_parent=True))
    wrapped_path   = Path(vault_wrapped_file(username, ensure_parent=True, name_only=False))
    salt_path      = Path(salt_file(username, ensure_parent=True, name_only=False))
    sharekeys_path = Path(shared_key_file(username, ensure_parent=True, name_only=False))
    identity_path  = Path(identities_file(username, ensure_parent=True))  # <Users>/<u>/identities/<u>.data

    to_add = []
    if vault_path.exists():     to_add.append((vault_path,     f"data/vaults/{vault_path.name}"))
    if wrapped_path.exists():   to_add.append((wrapped_path,   f"data/vaults/{wrapped_path.name}"))
    if salt_path.exists():      to_add.append((salt_path,      f"config/auth/{salt_path.name}"))
    if sharekeys_path.exists(): to_add.append((sharekeys_path, f"config/auth/{sharekeys_path.name}"))
    if identity_path.exists():  to_add.append((identity_path,  f"config/auth/identities/{identity_path.name}"))

    # --- Load per-user DB (Phase-2 per-user file)
    db_path = Path(user_db_file(username, ensure_parent=True))
    try:
        user_rec = json.loads(db_path.read_text(encoding="utf-8"))
        if not isinstance(user_rec, dict):
            user_rec = {}
    except Exception:
        user_rec = {}

    # Extract any embedded category schema, keep the rest as user record
    def _extract_schema_from_record(rec: dict) -> tuple[dict, dict|None]:
        if not isinstance(rec, dict): return {}, None
        rec = dict(rec)
        schema = None
        if isinstance(rec.get("category_schema"), dict):
            schema = rec.pop("category_schema")
        st = rec.get("settings")
        if isinstance(st, dict) and isinstance(st.get("category_schema"), dict):
            schema = schema or st["category_schema"]
            st = dict(st); st.pop("category_schema", None)
            rec["settings"] = st
        return rec, schema

    user_rec, embedded_schema = _extract_schema_from_record(user_rec)

    # Build a mini DB in the *legacy* shape for compatibility with restores
    mini_db = {username: user_rec}
    if isinstance(embedded_schema, dict):
        mini_db["category_schema"] = embedded_schema

    # Zip
    buf = BytesIO()
    with ZipFile(buf, "w") as z:
        for src, arc in to_add:
            z.write(src, arcname=arc)
        # Keep same arcname for compatibility
        z.writestr("config/auth/user_db.json", json.dumps(mini_db, ensure_ascii=False, indent=2))

    plain_zip = buf.getvalue()
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_fp = out_dir / (f"{username}_full_backup_{ts}.zip.enc" if password else f"{username}_full_backup_{ts}.zip")
    if password:
        enc = _enc_backup_bytes(password, plain_zip)
        out_fp.write_bytes(enc)
    else:
        out_fp.write_bytes(plain_zip)
    return str(out_fp)

def import_full_backup(username: str, *args, **kwargs) -> bool:
    """
    import_full_backup(username, password, file_path, **opts)
    import_full_backup(username, file_path, **opts)

    Optional kwargs:
      - components: {"vault","wrapped","salt","sharekeys","identity","userdb"} (default: all)
      - userdb_mode: "replace" | "merge"  (default: "replace")
    """
    import json, os
    from io import BytesIO
    from zipfile import ZipFile
    from pathlib import Path
    from app.paths import (
        vault_file, salt_file, vault_wrapped_file, shared_key_file,
        identities_file, user_db_file,
    )

    # args
    if len(args) == 2:
        password, file_path = args
    elif len(args) == 1:
        password, file_path = None, args[0]
    else:
        raise ValueError("usage: import_full_backup(username, [password], file_path)")

    components = kwargs.get("components") or {"vault","wrapped","salt","sharekeys","identity","userdb"}
    userdb_mode = (kwargs.get("userdb_mode") or "replace").lower()
    if userdb_mode not in ("replace","merge"): userdb_mode = "replace"

    p = Path(file_path)
    if not p.exists():
        return False

    # Open zip (encrypted or plain)
    if p.suffix == ".enc":
        if not password:
            raise ValueError("password required for encrypted backup (.enc)")
        plain_zip = _dec_backup_bytes(password, p.read_bytes())  # existing helper
        zf = ZipFile(BytesIO(plain_zip), "r")
    else:
        if password:
            raise ValueError("backup is not encrypted (.zip); do not supply a password")
        zf = ZipFile(p, "r")

    # Canonical destinations
    vault_dst      = Path(vault_file(username, ensure_parent=True))
    wrapped_dst    = Path(vault_wrapped_file(username, ensure_parent=True, name_only=False))
    salt_dst       = Path(salt_file(username, ensure_parent=True, name_only=False))
    sharekeys_dst  = Path(shared_key_file(username, ensure_parent=True, name_only=False))
    identity_dst   = Path(identities_file(username, ensure_parent=True))
    db_dst         = Path(user_db_file(username, ensure_parent=True))

    # Canonical names (for lookup inside the archive)
    vault_name     = vault_dst.name
    wrapped_name   = wrapped_dst.name
    salt_name      = salt_dst.name
    sharekeys_name = sharekeys_dst.name
    identity_name  = identity_dst.name

    def _extract(arc_candidates, dest: Path) -> bool:
        for arc in arc_candidates:
            try:
                info = zf.getinfo(arc)
            except KeyError:
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            zf.extract(info, dest.parent)
            (dest.parent / arc).replace(dest)
            try: os.chmod(dest, 0o600)
            except Exception: pass
            return True
        return False

    # Per-user DB helpers (Phase-2: single per-user file)
    def _load_user_db() -> dict:
        if db_dst.exists():
            try: return json.loads(db_dst.read_text(encoding="utf-8"))
            except Exception: return {}
        return {}

    def _save_user_db(d: dict) -> None:
        tmp = db_dst.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(db_dst)
        try: os.chmod(db_dst, 0o600)
        except Exception: pass

    def _deep_merge(dst: dict, src: dict) -> dict:
        out = dict(dst or {})
        for k, v in (src or {}).items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = _deep_merge(out[k], v)
            else:
                out[k] = v
        return out

    def _merge_user_from_zip() -> bool:
        # Accept both legacy arcname and a flat file
        payload = None
        for arc in ("config/auth/user_db.json", db_dst.name):
            try:
                with zf.open(arc) as f:
                    payload = json.loads(f.read().decode("utf-8")); break
            except KeyError:
                continue
            except Exception:
                payload = None; break
        if not isinstance(payload, dict):
            return False

        # Legacy payload may be {username: {...}, category_schema: {...}}
        if username in payload:
            incoming_user = payload.get(username) or {}
            # schema may be top-level
            incoming_schema = payload.get("category_schema")
            if isinstance(incoming_schema, dict):
                # promote into user record for Phase-2 single-file model
                iu = dict(incoming_user)
                st = iu.get("settings") or {}
                if isinstance(st, dict):
                    st = dict(st)
                    st["category_schema"] = incoming_schema
                    iu["settings"] = st
                else:
                    iu["settings"] = {"category_schema": incoming_schema}
                incoming_user = iu
        else:
            # Or the payload may already be the per-user record (Phase-2)
            incoming_user = payload

        existing = _load_user_db()
        if userdb_mode == "merge" and isinstance(existing, dict):
            merged = _deep_merge(existing, incoming_user if isinstance(incoming_user, dict) else {})
            _save_user_db(merged)
        else:
            _save_user_db(incoming_user if isinstance(incoming_user, dict) else {})
        return True

    try:
        if "salt" in components:      _extract([f"config/auth/{salt_name}",      salt_name],      salt_dst)
        if "vault" in components:     _extract([f"data/vaults/{vault_name}",     vault_name],     vault_dst)
        if "wrapped" in components:   _extract([f"data/vaults/{wrapped_name}",   wrapped_name],   wrapped_dst)
        if "sharekeys" in components: _extract([f"config/auth/{sharekeys_name}", sharekeys_name], sharekeys_dst)
        if "identity" in components:  _extract([f"config/auth/identities/{identity_name}", identity_name], identity_dst)
        if "userdb" in components:    _merge_user_from_zip()
        return True
    finally:
        try: zf.close()
        except Exception: pass

# --- export to password csv

def export_vault_csv(
    username: str,
    vault_data: list[dict],
    out_path: str,
    password: str | None = None,
    target_format: str = "Keyquorum (App-native)"
) -> str:
    """
    Export vault entries as CSV in one of:
      - "Keyquorum (App-native)"  -> category-aware, rich fields for re-import (adds KQ_FORMAT=1 + optional KQ_SCHEMA)
      - "Google Chrome"           -> name,url,username,password
      - "Microsoft Edge"          -> same as Chrome
      - "Samsung Pass"            -> title,username,password,url,notes

    If 'password' is provided, the CSV is AES-GCM encrypted via _enc_backup_bytes and
    the file name will end with '.enc'.

    For Keyquorum (App-native):
    - Includes a metadata row with KQ_SCHEMA containing a base64-encoded category_schema
      from user_db (if available), so categories can be recreated on import.
    """
    import io, csv
    from pathlib import Path

    tf = (target_format or "").strip().lower()

    def _collect_union_headers(data: list[dict]) -> list[str]:
        if not data:
            return []
        keys = set()
        for e in data:
            if isinstance(e, dict):
                keys.update(e.keys())
        preferred_first = [
            "category", "Title", "Name", "Username", "Password",
            "URL", "Website", "Notes", "Date", "created_at"
        ]
        return [k for k in preferred_first if k in keys] + sorted(
            k for k in keys if k not in preferred_first
        )

    def _norm_username(e: dict) -> str:
        for k in ("Username", "UserName", "User", "Login", "Account", "Email", "ID"):
            v = (e.get(k) if isinstance(e, dict) else None)
            if v:
                v = str(v).strip()
                if v:
                    return v
        return ""

    def _norm_title(e: dict) -> str:
        for k in ("Title", "Name", "label", "category"):
            v = (e.get(k) if isinstance(e, dict) else None)
            if v:
                v = str(v).strip()
                if v:
                    return v
        return ""

    buf = io.StringIO()

    # -------------------------------
    # Keyquorum (App-native) – embed category schema
    # -------------------------------
    if tf.startswith("keyquorum"):
        # App-native, category-aware (best for round-trips). Include marker + optional schema.
        headers = _collect_union_headers(vault_data)

        # Try to pull category_schema from user_db settings
        schema_b64 = ""
        try:
            from auth.login.login_handler import get_user_setting  

            schema = get_user_setting(username, "category_schema", None)
            if isinstance(schema, dict) and isinstance(schema.get("categories"), list):
                schema_json = json.dumps(
                    schema,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                schema_b64 = base64.b64encode(schema_json.encode("utf-8")).decode("ascii")
        except Exception:
            schema_b64 = ""

        # Ensure marker and common fields exist
        base = ["KQ_FORMAT"]
        # If we have a schema, ensure KQ_SCHEMA header exists (right after marker)
        if schema_b64 and "KQ_SCHEMA" not in headers:
            headers.insert(0, "KQ_SCHEMA")

        for h in ("category", "Title", "Username", "Password", "URL", "Notes", "Date", "created_at"):
            if h not in headers:
                headers.append(h)

        # Final header order: marker + (optional schema) + everything else
        headers = base + headers

        w = csv.DictWriter(buf, fieldnames=headers, extrasaction="ignore")
        w.writeheader()

        # If we have a schema, write a single metadata row first
        if schema_b64:
            meta = {
                "KQ_FORMAT": "1",
                "KQ_SCHEMA": schema_b64,
            }
            w.writerow({k: meta.get(k, "") for k in headers})

        # Then write the actual entries
        for e in vault_data:
            row = dict(e) if isinstance(e, dict) else {}
            row.setdefault("KQ_FORMAT", "1")
            if schema_b64:
                # We only want the schema on the metadata row, not every entry
                row.setdefault("KQ_SCHEMA", "")
            w.writerow({k: row.get(k, "") for k in headers})

    # -------------------------------
    # Other formats unchanged
    # -------------------------------
    elif tf in ("google chrome", "microsoft edge", "google", "chrome", "edge"):
        headers = ["name", "url", "username", "password"]
        w = csv.DictWriter(buf, fieldnames=headers)
        w.writeheader()
        for e in vault_data:
            url = (e.get("URL") or e.get("Website") or "").strip() if isinstance(e, dict) else ""
            if not url:
                continue
            w.writerow({
                "name": _norm_title(e),
                "url": url,
                "username": _norm_username(e),
                "password": (e.get("Password") or "").strip(),
            })

    elif tf in ("samsung pass", "samsung"):
        headers = ["title", "username", "password", "url", "notes"]
        w = csv.DictWriter(buf, fieldnames=headers)
        w.writeheader()
        for e in vault_data:
            w.writerow({
                "title": _norm_title(e),
                "username": _norm_username(e),
                "password": (e.get("Password") or "").strip(),
                "url": (e.get("URL") or e.get("Website") or "").strip(),
                "notes": (e.get("Notes") or "").strip(),
            })

    else:
        # Fallback to App-native without schema
        headers = _collect_union_headers(vault_data)
        if "KQ_FORMAT" not in headers:
            headers = ["KQ_FORMAT"] + headers
        if not headers:
            headers = ["KQ_FORMAT", "category", "Title", "Username", "Password", "URL", "Notes", "Date", "created_at"]
        w = csv.DictWriter(buf, fieldnames=headers, extrasaction="ignore")
        w.writeheader()
        for e in vault_data:
            row = dict(e) if isinstance(e, dict) else {}
            row.setdefault("KQ_FORMAT", "1")
            w.writerow({k: row.get(k, "") for k in headers})

    csv_bytes = buf.getvalue().encode("utf-8-sig")  # BOM helps Excel

    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    if password:
        enc = _enc_backup_bytes(password, csv_bytes)
        if not out_file.name.endswith(".enc"):
            out_file = out_file.with_name(out_file.name + ".enc")
        out_file.write_bytes(enc)
    else:
        out_file.write_bytes(csv_bytes)

    return str(out_file)
