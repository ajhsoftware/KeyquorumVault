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

import base64, hashlib, os, logging, re
from typing import Optional
# --- AES-GCM for wrapping/unwrapping vault keys ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from vault_store.kdf_utils import derive_key_argon2id
log = logging.getLogger("keyquorum")
# key_utils.py — consolidated: password hashing + key wrap/unwrap + recovery KDF

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("key_utils", text)

NONCE_LEN = 12
FORMAT_TAG = "kqwrap:v1"  # version tag for future changes

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))

def _assert_len(name: str, b: bytes, expect: int | tuple[int, ...]) -> None:
    if isinstance(expect, int):
        ok = len(b) == expect
    else:
        ok = len(b) in expect
    if not ok:
        raise ValueError(f"{name} " + _tr("must be length ") + "{expect}, " + _tr("got") + f" {len(b)}")

# --- Argon2id KDF (for recovery key -> wrapping key) ---
from vault_store.kdf_utils import derive_key_argon2id_safe as _derive_key_argon2id_safe  # preferred (auto memory fallback)
from vault_store.kdf_utils import derive_key_argon2id       as _derive_key_argon2id       # strict

def derive_wrapping_key_from_recovery_key(recovery_key: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derive a 256-bit wrapping key from a human recovery key + per-user salt.
    Uses Argon2id with a safe memory fallback.
    """
    if not isinstance(recovery_key, str) or not recovery_key:
        raise ValueError(_tr("recovery_key required"))
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError(_tr("salt must be >= 8 bytes"))
    return _derive_key_argon2id_safe(recovery_key, salt, length=length)

# --- Key wrapping / unwrapping (AES-GCM) ---
def encrypt_key(raw_key: bytes, wrapping_key: bytes, *, aad: Optional[bytes] = None) -> str:
    """
    Wrap a raw key with AES-GCM.
    Returns token: 'kqwrap:v1.<b64nonce>.<b64ct>'
    """
    if not isinstance(raw_key, (bytes, bytearray)) or len(raw_key) == 0:
        raise ValueError(_tr("raw_key required"))
    if not isinstance(wrapping_key, (bytes, bytearray)):
        raise ValueError(_tr("wrapping_key required"))
    _assert_len("wrapping_key", wrapping_key, (16, 24, 32))  # AES key sizes

    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(wrapping_key).encrypt(nonce, bytes(raw_key), aad)
    token = f"{FORMAT_TAG}.{_b64e(nonce)}.{_b64e(ct)}"
    return token

def decrypt_key(wrapped: str, wrapping_key: bytes, *, aad: Optional[bytes] = None) -> bytes:
    """
    Unwrap a key produced by encrypt_key(). Also supports legacy base64(nonce||ct) form.
    """
    if not isinstance(wrapped, str) or not wrapped:
        raise ValueError(_tr("wrapped token required"))
    _assert_len("wrapping_key", wrapping_key, (16, 24, 32))

    try:
        if wrapped.startswith(FORMAT_TAG + "."):
            # New format: kqwrap:v1.<nonce>.<ct>
            _, b64_nonce, b64_ct = wrapped.split(".", 2)
            nonce = _b64d(b64_nonce)
            ct = _b64d(b64_ct)
            _assert_len("nonce", nonce, NONCE_LEN)
            return AESGCM(wrapping_key).decrypt(nonce, ct, aad)
        else:
            # Legacy format: base64(nonce||ct)
            blob = base64.b64decode(wrapped)
            nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
            _assert_len("nonce", nonce, NONCE_LEN)
            return AESGCM(wrapping_key).decrypt(nonce, ct, aad)
    except Exception as e:
        # Do NOT log secrets; keep message generic
        raise ValueError(_tr("Failed to decrypt wrapped key")) from e

# --- Password hashing (Argon2id) — moved from key_utils.py ---
from argon2 import PasswordHasher, exceptions as argon2_exceptions
try:
    import bcrypt # type: ignore
except Exception:  # pragma: no cover
    bcrypt = None  # type: ignore

ARGON2 = PasswordHasher(
    time_cost=3,          # iterations
    memory_cost=256_000,  # KiB (≈256 MiB)
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

_BCRYPT_PREFIX = re.compile(r"^\$(2[aby])$")
_BCRYPT_ROUNDS_TARGET = 12  # only relevant if you still store bcrypt

def is_bcrypt_hash(stored: str | bytes) -> bool:
    s = stored.decode("utf-8", "ignore") if isinstance(stored, (bytes, bytearray)) else str(stored or "")
    return bool(_BCRYPT_PREFIX.match(s))

def hash_password(password: str) -> str:
    """Create a new Argon2id password hash."""
    return ARGON2.hash(password)

def verify_password(stored_hash: str | bytes, password: str) -> bool:
    """
    Verify password against either Argon2id (current) or legacy bcrypt.
    Returns True/False. Does not persist upgrades—use maybe_upgrade_hash().
    """
    s = stored_hash.decode("utf-8", "ignore") if isinstance(stored_hash, (bytes, bytearray)) else str(stored_hash or "")
    # Argon2id fast path
    if s.startswith("$argon2"):
        try:
            return ARGON2.verify(s, password)
        except argon2_exceptions.VerifyMismatchError:
            return False
        except Exception:
            return False

    # Legacy bcrypt (if present)
    if is_bcrypt_hash(s) and bcrypt:
        try:
            return bcrypt.checkpw(password.encode("utf-8"), s.encode("utf-8"))
        except Exception:
            return False

    # Unknown format
    return False

def needs_rehash(stored_hash: str | bytes) -> bool:
    """True if the hash should be upgraded (new Argon2 params or legacy bcrypt)."""
    s = stored_hash.decode("utf-8", "ignore") if isinstance(stored_hash, (bytes, bytearray)) else str(stored_hash or "")
    if s.startswith("$argon2"):
        try:
            return ARGON2.check_needs_rehash(s)
        except Exception:
            return True
    # Anything else (including bcrypt) should be rehashed to Argon2
    return True

def maybe_upgrade_hash(stored_hash: str | bytes, password: str) -> str | None:
    """
    If verify succeeds and the hash needs an upgrade, return a **new Argon2id hash**.
    Caller is responsible for persisting it (e.g., update users DB).
    Returns None if no upgrade is needed or verify fails.
    """
    if not verify_password(stored_hash, password):
        return None
    if not needs_rehash(stored_hash):
        return None
    try:
        new_hash = hash_password(password)
        log.info("[auth] password hash upgraded → Argon2id")
        return new_hash
    except Exception:
        return None
