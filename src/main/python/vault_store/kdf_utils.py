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

import os
from typing import Dict, Any

# STRICT DLL-ONLY MODE:
# - No Python Argon2 implementation is kept here.
# - If the native core (DLL) isn't loaded, key derivation MUST fail.

from native.native_core import get_core

# Legacy profile (v1) is compiled into older DLL builds.
# These values are NOT used by the DLL unless it exposes a parameterized API.
ARGON2_KEY_LEN      = 32
ARGON2_TIME_COST    = 3
ARGON2_MEMORY_KIB   = 256_000
ARGON2_PARALLELISM  = 2


def recommended_argon2_params() -> Dict[str, int]:
    """
    Default KDF profile for NEW accounts (KDF v2).

    Note:
      These parameters only take effect if the native DLL supports the *_ex APIs
      (kq_session_open_ex / derive_vault_key_ex). Otherwise, accounts fall back
      to legacy profile v1 (fixed params compiled into the DLL).
    """
    cpu = os.cpu_count() or 2
    return {
        "algo": "argon2id",
        "kdf_v": 2,
        "time_cost": 4,
        "memory_kib": 512_000,
        "parallelism": 2 if cpu < 4 else 4,
        "hash_len": ARGON2_KEY_LEN,
    }


def normalize_kdf_params(kdf: Dict[str, Any] | None) -> Dict[str, Any]:
    """
    Ensure a KDF dict is complete + well-typed.
    """
    kdf = dict(kdf or {})
    kdf.setdefault("algo", "argon2id")
    kdf.setdefault("kdf_v", 1)
    kdf.setdefault("time_cost", ARGON2_TIME_COST)
    kdf.setdefault("memory_kib", ARGON2_MEMORY_KIB)
    kdf.setdefault("parallelism", ARGON2_PARALLELISM)
    kdf.setdefault("hash_len", ARGON2_KEY_LEN)

    # Coerce ints
    for k in ("kdf_v", "time_cost", "memory_kib", "parallelism", "hash_len"):
        try:
            kdf[k] = int(kdf[k])
        except Exception:
            kdf[k] = int(ARGON2_TIME_COST) if k == "time_cost" else int(kdf.get(k, 0) or 0)

    # Floors (avoid accidental 0/negative)
    kdf["time_cost"] = max(1, int(kdf["time_cost"]))
    kdf["memory_kib"] = max(8_192, int(kdf["memory_kib"]))  # 8MB floor (sanity)
    kdf["parallelism"] = max(1, int(kdf["parallelism"]))
    kdf["hash_len"] = max(16, int(kdf["hash_len"]))

    return kdf


def derive_key_argon2id_from_buf(password_buf: bytearray, salt: bytes) -> bytes:
    """
    Derive using the legacy fixed-params DLL API.
    """
    core = get_core()
    if not core:
        raise RuntimeError("Native core not loaded (DLL required).")

    key = core.derive_vault_key(password_buf, salt)
    return bytes(key)


def derive_key_argon2id_ex_from_buf(
    password_buf: bytearray,
    salt: bytes,
    *,
    time_cost: int,
    memory_kib: int,
    parallelism: int,
    hash_len: int = ARGON2_KEY_LEN,
) -> bytes:
    """
    Derive using the parameterized DLL API (if supported).
    """
    core = get_core()
    if not core:
        raise RuntimeError("Native core not loaded (DLL required).")

    if not hasattr(core, "derive_vault_key_ex"):
        raise RuntimeError("Native DLL does not support derive_vault_key_ex. Please upgrade the DLL.")

    key = core.derive_vault_key_ex(
        password_buf,
        salt,
        int(time_cost),
        int(memory_kib),
        int(parallelism),
        int(hash_len),
    )
    return bytes(key)


def derive_key_argon2id(password: str, salt: bytes) -> bytes:
    """
    Convenience wrapper for key derivation (DLL-only).
    Uses the legacy fixed-params DLL derivation.
    """
    core = get_core()
    if not core:
        raise RuntimeError("Native core not loaded (DLL required).")

    pw_buf = bytearray(password.encode("utf-8"))
    try:
        return derive_key_argon2id_from_buf(pw_buf, salt)
    finally:
        try:
            core.secure_wipe(pw_buf)
        except Exception:
            for i in range(len(pw_buf)):
                pw_buf[i] = 0


def derive_key_argon2id_safe(
    password: str,
    salt: bytes,
    *,
    min_memory_kib: int = 64_000,
) -> bytes:
    """
    Kept for API compatibility, but in strict DLL-only mode this is the same as derive_key_argon2id().
    (The "safe memory downshift" behaviour only existed for the old Python fallback.)
    """
    _ = min_memory_kib
    return derive_key_argon2id(password, salt)
