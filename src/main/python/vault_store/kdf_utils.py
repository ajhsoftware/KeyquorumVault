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
"""Module for vault store functionality.

This file is part of the Keyquorum Vault codebase.
"""

from argon2.low_level import Type, hash_secret_raw

"""
Argon2id parameters — defaults for desktop/laptop users.
These match your PasswordHasher in crypto_utils.py:
  time_cost    = 3
  memory_cost  = 256_000 KiB  (≈256 MB)
  parallelism  = 2
  hash_len     = 32 bytes
"""

ARGON2_TIME_COST   = 3
ARGON2_MEMORY_KIB  = 256_000   # ~256 MB
ARGON2_PARALLELISM = 2
ARGON2_KEY_LEN     = 32


def _derive_key_argon2id_python(
    password: str,
    salt: bytes,
    length: int = ARGON2_KEY_LEN,
    time_cost: int = ARGON2_TIME_COST,
    memory_kib: int = ARGON2_MEMORY_KIB,
    parallelism: int = ARGON2_PARALLELISM,
) -> bytes:
    if not isinstance(password, (bytes, bytearray)):
        password = password.encode("utf-8")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    if len(salt) < 8:
        raise ValueError("argon2 salt is too short (need >= 8 bytes)")
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=length,
        type=Type.ID,
    )

from native.native_core import get_core



def _derive_key_argon2id_python_bytes(
    password_bytes: bytes,
    salt: bytes,
    length: int = ARGON2_KEY_LEN,
    time_cost: int = ARGON2_TIME_COST,
    memory_kib: int = ARGON2_MEMORY_KIB,
    parallelism: int = ARGON2_PARALLELISM,
) -> bytes:
    """Python fallback Argon2id that accepts bytes (avoids creating a str copy)."""
    return hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=length,
        type=Type.ID,
    )

def derive_key_argon2id(password: str, salt: bytes) -> bytes:
    """
    Fast path: use native core if available, else Python Argon2id.
    """
    core = get_core()
    if core:
        pw_buf = bytearray(password, "utf-8")
        try:
            key = core.derive_vault_key(pw_buf, salt)
        finally:
            core.secure_wipe(pw_buf)
        return bytes(key)

    # Fallback to Python Argon2
    return _derive_key_argon2id_python(password, salt)


def derive_key_argon2id_safe(
    password: str,
    salt: bytes,
    *,
    min_memory_kib: int = 64_000,  # ~64 MB floor
) -> bytes:
    """
    Safe mode: try native first (fast). If native isn't available, use Python Argon2id.
    If Python runs out of memory, automatically reduce Argon2 memory_cost until it succeeds.

    NOTE: The native DLL uses fixed Argon2 parameters compiled into the DLL,
    so we cannot reduce memory on the native path without changing the DLL API.
    """
    core = get_core()
    if core:
        # Native path (fixed memory params in DLL)
        pw_buf = bytearray(password, "utf-8")
        try:
            key = core.derive_vault_key(pw_buf, salt)
        finally:
            core.secure_wipe(pw_buf)
        return bytes(key)

    # Python adaptive path
    mkib = int(ARGON2_MEMORY_KIB)
    while True:
        try:
            return _derive_key_argon2id_python(
                password=password,
                salt=salt,
                length=ARGON2_KEY_LEN,
                time_cost=ARGON2_TIME_COST,
                memory_kib=mkib,
                parallelism=ARGON2_PARALLELISM,
            )
        except MemoryError:
            mkib //= 2
            if mkib < int(min_memory_kib):
                # last attempt at floor; if it still fails, let it raise
                return _derive_key_argon2id_python(
                    password=password,
                    salt=salt,
                    length=ARGON2_KEY_LEN,
                    time_cost=ARGON2_TIME_COST,
                    memory_kib=int(min_memory_kib),
                    parallelism=ARGON2_PARALLELISM,
                )


#  attempt_login doesn’t need pw_str
def derive_key_argon2id_from_buf(pw_buf: bytearray, salt: bytes) -> bytes:
    core = get_core()
    if core:
        key = core.derive_vault_key(pw_buf, salt)
        return bytes(key)
    # fallback (creates one unavoidable copy)
    return _derive_key_argon2id_python_bytes(bytes(pw_buf), salt)
