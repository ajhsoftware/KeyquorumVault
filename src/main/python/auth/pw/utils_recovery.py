"""

DEPRECATED: Backup code generation should use auth.identity_store.gen_backup_codes() as the single source of truth.
Keyquorum Vault
Copyright (C) 2025-2026 Anthony Hatton (AJH Software)

This file is part of Keyquorum Vault.

Keyquorum Vault is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Keyquorum Vault is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."""

import base64
import hashlib
import textwrap
import re
import hmac

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("utils_recovery", text)

# ==============================
# --- Recovery Key (single source of truth)  
# ==============================


def mk_to_recovery_key(mk: bytes) -> str:
    """
    Pretty-print a 32-byte Master Key as a Recovery Key string.

    Format:
      - Base32-encoded mk (no padding)
      - grouped in chunks of 5 with '-'
      - final '-XXXXXX' is a 6-char checksum (SHA256 hex prefix)
    """
    if not isinstance(mk, (bytes, bytearray)):
        raise TypeError(_tr("mk must be bytes"))
    if len(mk) != 32:
        raise ValueError(_tr("mk must be 32 bytes"))

    b32 = base64.b32encode(bytes(mk)).decode("ascii").rstrip("=")
    grouped = "-".join(textwrap.wrap(b32, 5))
    chk = hashlib.sha256(bytes(mk)).hexdigest()[:6].upper()
    return f"{grouped}-{chk}"


def recovery_key_to_mk(rk: str) -> bytes:
    """
    Decode a Recovery Key into the 32-byte Master Key.

    Accepts:
      • New format (with or without dashes):
          ABCDE-ABCDE-ABCDE-ABCDE-123456
          ABCDEABCDEABCDEABCDE123456

      • Legacy urlsafe base64 format:
          X6xMXcjgA80IrpSmSssogL6975dT0vU2cYgVIV2_88k

    Returns 32-byte MK or raises ValueError.
    """
    s_raw = (rk or "").strip()
    if not s_raw:
        raise ValueError(_tr("Recovery Key is empty"))

    # -------
    # 1) New format (base32 body + 6-char checksum)
    #    Accept dashed or dashless input
    # -------
    s = s_raw.upper()
    s_alnum = re.sub(r"[^A-Z0-9]", "", s)

    if len(s_alnum) > 6 and re.fullmatch(r"[0-9A-F]{6}", s_alnum[-6:]):
        body = s_alnum[:-6]
        chk = s_alnum[-6:]

        if re.fullmatch(r"[A-Z2-7]+", body):
            pad = (-len(body)) % 8
            try:
                mk = base64.b32decode(body + ("=" * pad), casefold=True)
            except Exception as e:
                raise ValueError(_tr("Recovery Key base32 decode failed")) from e

            if len(mk) != 32:
                raise ValueError(_tr("Recovery Key decoded to wrong length"))

            if hashlib.sha256(mk).hexdigest()[:6].upper() != chk:
                raise ValueError(_tr("Recovery Key checksum mismatch"))

            return mk

    # -------
    # 2) Legacy urlsafe base64 (32 bytes, no checksum)
    # -------
    s_b64 = s_raw.replace(" ", "")
    pad = (-len(s_b64)) % 4
    try:
        mk = base64.urlsafe_b64decode(s_b64 + ("=" * pad))
    except Exception as e:
        raise ValueError(_tr("Recovery Key format invalid")) from e

    if len(mk) != 32:
        raise ValueError(_tr("Recovery Key length invalid"))

    return mk


def _verify_recovery_key_local(*args) -> bool:
    """
    Local (offline) verification for a Recovery Key.

    Supports:
      - _verify_recovery_key_local(username, recovery_key)
      - _verify_recovery_key_local(None, username, recovery_key)

    Returns True if the Recovery Key decodes to an MK whose mk_hash_b64
    matches the identity header.
    """
    try:
        if len(args) == 2:
            username, recovery_key = args
        elif len(args) == 3:
            _, username, recovery_key = args
        else:
            return False

        from auth.identity_store import get_public_header, mk_hash_b64

        mk = recovery_key_to_mk(recovery_key)

        hdr = get_public_header(username) or {}
        want = ((hdr.get("meta") or {}).get("mk_hash_b64") or "").strip()
        if not want:
            return False

        have = mk_hash_b64(mk)

        if isinstance(have, (bytes, bytearray)):
            have = have.decode("utf-8", "ignore")
        if isinstance(want, (bytes, bytearray)):
            want = want.decode("utf-8", "ignore")

        return hmac.compare_digest(
            (have or "").strip().rstrip("="),
            (want or "").strip().rstrip("="),
        )
    except Exception:
        return False


# ==============================
# --- Backup Codes (single source of truth)
# ==============================

import secrets
import string
import hashlib
import hmac
from typing import Tuple, List


def normalize_backup_code(code: str) -> str:
    """Normalize user input (case, spaces, hyphens)."""
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def generate_backup_codes(
    count: int = 10,
    length: int = 12,
    *,
    salt: bytes,
) -> Tuple[List[str], List[str]]:
    """
    Generate one-time backup codes and their salted hashes.

    Returns (plaintext_codes, hashed_codes).
    """
    alphabet = string.ascii_uppercase + string.digits
    plaintext: List[str] = [
        "".join(secrets.choice(alphabet) for _ in range(length))
        for _ in range(count)
    ]

    hashes: List[str] = []
    for code in plaintext:
        norm = normalize_backup_code(code).encode("utf-8")
        h = hashlib.sha256(salt + norm).hexdigest()
        hashes.append(h)

    return plaintext, hashes


def verify_and_consume_backup_code(
    provided_code: str,
    stored_hashes: list[str],
    *,
    salt: bytes,
) -> tuple[bool, list[str]]:
    want = backup_code_hash_b64(provided_code, salt=salt)

    new_hashes = []
    used = False

    for h in stored_hashes:
        if not used and hmac.compare_digest(h, want):
            used = True
            continue
        new_hashes.append(h)

    return used, new_hashes


def backup_code_hash_b64(code: str, *, salt: bytes) -> str:
    import base64, hashlib
    norm = normalize_backup_code(code).encode("utf-8")
    h = hashlib.sha256(salt + norm).digest()
    return base64.b64encode(h).decode("ascii")
