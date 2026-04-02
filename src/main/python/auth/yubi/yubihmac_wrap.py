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
from security.baseline_signer import update_baseline
from typing import Optional, Callable
import base64, binascii, hashlib, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class YubiKeyError(RuntimeError):
    pass

AAD_WRAP_V1 = b"KQ-WRAP-V1"  # additional authenticated data (binds ciphertext context)

def _b64d(s: Optional[str]) -> bytes:
    if not s:
        return b""
    return base64.b64decode(s)

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def unwrap_master_key_with_yubi(master_key: bytes, *, password_key: Optional[bytes], cfg: dict) -> bytes:
    """
    WRAP mode:
      - cfg contains {salt_b64, nonce_b64, wrapped_b64, slot, serial, ykman_path, mk_hash_b64?}
      - device_key_32 = SHA256( YK_HMAC( wrap_salt ) )
      - kek = SHA256( password_key || device_key_32 )
      - MK = AESGCM(kek).decrypt(nonce, wrapped, AAD_WRAP_V1)

    Returns the unwrapped master key (MK).
    """
    if password_key is None or len(password_key) == 0:
        raise RuntimeError("unwrap_master_key_with_yubi: password_key is required")

    if (cfg.get("mode") or "").strip().lower() != "yk_hmac_wrap":
        # not wrap → return unchanged
        return master_key

    salt      = _b64d(cfg.get("salt_b64"))
    nonce     = _b64d(cfg.get("nonce_b64"))
    wrapped   = _b64d(cfg.get("wrapped_b64"))
    slot      = int(cfg.get("slot", 2) or 2)
    serial    = (cfg.get("serial") or "").strip() or None
    ykmanpath = (cfg.get("ykman_path") or "").strip() or None

    if not salt or not nonce or not wrapped:
        raise RuntimeError("unwrap_master_key_with_yubi: missing wrap artifacts (salt/nonce/wrapped).")

    # lazy import to avoid circulars
    try:
        from auth.yubi.yk_backend import YKBackend
    except Exception:
        from yk_backend import YKBackend

    # Ask YubiKey to HMAC the wrap salt
    challenge_hex = binascii.hexlify(salt).decode("ascii")
    yk = YKBackend(ykmanpath)
    resp_hex = yk.calculate_hmac(slot, challenge_hex, serial)
    if not resp_hex:
        raise YubiKeyError("No response from YubiKey during unwrap")

    try:
        resp_bytes = binascii.unhexlify(resp_hex)
    except Exception as e:
        raise RuntimeError(f"Bad YubiKey HMAC hex: {e}")

    # SECURITY NOTE:
    # SHA-256 used for salted one-time backup codes.
    # Not used for password hashing.

    device_key_32 = hashlib.sha256(resp_bytes).digest()
    kek = hashlib.sha256(bytes(password_key) + device_key_32).digest()

    try:
        mk = AESGCM(kek).decrypt(nonce, wrapped, AAD_WRAP_V1)
    except Exception as e:
        # Keep error message user-safe (no oracle)
        raise RuntimeError("YubiKey unwrap failed (wrong key or corrupted data).") from e

    # Optional verification against stored MK fingerprint
    expected = (cfg.get("mk_hash_b64") or "").strip()
    if expected:
        actual = base64.b64encode(hashlib.sha256(mk).digest()).decode("ascii")
        if actual != expected:
            raise RuntimeError("YubiKey unwrap produced an unexpected master key (verification failed).")

    return mk

def enable_wrap_and_rotate_vault(
    *,
    username: str,
    current_mk: bytes,                 # current vault master key (session)
    password_key: bytes,               # Argon2id(password, user_salt) → 32B
    slot: int,
    serial: str | None,
    ykman_path: str | None,
    get_cfg: Callable[[], dict],        # () -> dict  (load identity config)
    set_cfg: Callable[[dict], None],    # (dict) -> None  (persist identity config)
) -> dict:
    """
    Enable WRAP for a user and ensure the vault is no longer decryptable by password alone.

    Steps:
      1) Generate wrap_salt and request YubiKey HMAC(wrap_salt)
      2) device_key_32 = SHA256(yk_hmac)
      3) kek = SHA256(password_key || device_key_32)
      4) If current_mk == password_key (password-only vault), rotate vault to a new random MK
      5) Wrap MK with AES-GCM(kek) using AAD_WRAP_V1
      6) Save wrap artifacts + mk_hash_b64 into identity config

    Returns updated config dict.
    """
    from auth.yubi.wrap_ops import rekey_user_stores, bytes_equal

    if not isinstance(current_mk, (bytes, bytearray)) or len(current_mk) == 0:
        raise RuntimeError("enable_wrap_and_rotate_vault: current_mk is required")
    if not isinstance(password_key, (bytes, bytearray)) or len(password_key) == 0:
        raise RuntimeError("enable_wrap_and_rotate_vault: password_key is required")

    # 1) YubiKey HMAC over a fresh wrap salt
    wrap_salt = os.urandom(16)
    challenge_hex = binascii.hexlify(wrap_salt).decode("ascii")

    try:
        from auth.yubi.yk_backend import YKBackend
    except Exception:
        from yk_backend import YKBackend

    yk = YKBackend(ykman_path or None)
    yk_hex = yk.calculate_hmac(int(slot or 2), challenge_hex, (serial or "").strip() or None)
    if not yk_hex:
        raise RuntimeError("No YubiKey response during WRAP enable")
    try:
        yk_bytes = binascii.unhexlify(yk_hex)
    except Exception as e:
        raise RuntimeError(f"Bad YubiKey HMAC hex at enable: {e}")

    # 2) KEK = SHA256(password_key || SHA256(yk_hmac))
    device_key_32 = hashlib.sha256(yk_bytes).digest()
    kek = hashlib.sha256(bytes(password_key) + device_key_32).digest()

    # 3) If vault is password-only (mk == password_key), rotate to random MK
    mk = bytes(current_mk)
    if bytes_equal(mk, password_key):
        mk_new = os.urandom(32)
        rekey_user_stores(username, mk, mk_new)
        mk = mk_new

    # 4) Wrap MK with AES-GCM
    nonce = os.urandom(12)
    wrapped = AESGCM(kek).encrypt(nonce, mk, AAD_WRAP_V1)
    mk_hash_b64 = base64.b64encode(hashlib.sha256(mk).digest()).decode("ascii")

    cfg = (get_cfg() or {}).copy()
    cfg.update({
        "mode": "yk_hmac_wrap",
        "slot": int(slot or 2),
        "serial": (serial or "").strip() or None,
        "ykman_path": (ykman_path or "").strip() or None,
        "salt_b64": _b64e(wrap_salt),
        "nonce_b64": _b64e(nonce),
        "wrapped_b64": _b64e(wrapped),
        "mk_hash_b64": mk_hash_b64,
    })
    set_cfg(cfg)
    return cfg

def test_yk_unwrap(*, username: str, password: str) -> bool:
    """UI-facing WRAP test: unwrap the MK using password + YubiKey touch."""
    try:
        try:
            from auth.identity_store import get_yubi_config
        except Exception:
            from identity_store import get_yubi_config

        cfg = get_yubi_config((username or "").strip(), password or "") or {}
        if (cfg.get("mode") or "").strip().lower() != "yk_hmac_wrap":
            return False

        # Derive password_key from user salt (identity header first, fallback legacy .slt)
        try:
            from auth.salt_file import read_master_salt_readonly
            user_salt = read_master_salt_readonly(username)
        except Exception:
            from app.paths import salt_file
            user_salt = salt_file(username, ensure_parent=False).read_bytes()

        from vault_store.kdf_utils import derive_key_argon2id
        password_key = derive_key_argon2id(password or "", user_salt)

        mk = unwrap_master_key_with_yubi(b"", password_key=password_key, cfg=cfg)
        return bool(mk and len(mk) in (32, 64))
    except Exception:
        return False
