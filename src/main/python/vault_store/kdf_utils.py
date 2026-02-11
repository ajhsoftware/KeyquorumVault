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

def derive_key_argon2id(
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

def derive_key_argon2id_safe(
    password: str,
    salt: bytes,
    length: int = ARGON2_KEY_LEN,
    time_cost: int = ARGON2_TIME_COST,
    memory_kib: int = ARGON2_MEMORY_KIB,
    parallelism: int = ARGON2_PARALLELISM,
    min_memory_kib: int = 64_000,  # ~64 MB floor
) -> bytes:
    """
    Same as derive_key_argon2id, but if the machine can't allocate the requested
    memory, it automatically falls back by halving memory until it succeeds.
    """
    mkib = int(memory_kib)
    while True:
        try:
            return derive_key_argon2id(password, salt, length, time_cost, mkib, parallelism)
        except MemoryError:
            mkib //= 2
            if mkib < min_memory_kib:
                # last attempt with the floor; if it still fails, raise
                return derive_key_argon2id(password, salt, length, time_cost, min_memory_kib, parallelism)


