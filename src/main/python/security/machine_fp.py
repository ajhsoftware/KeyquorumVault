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

"""
Generate a stable, privacy-safe machine fingerprint.
This helper returns a fingerprint derived from generic system information.
It avoids logging any raw serial numbers or MAC addresses, and produces a
consistent SHA-256 hash per machine.  On failure, returns "unknown".
"""

import hashlib
import platform
import uuid
import os


def get_machine_fingerprint() -> str:
    """
    Compute a stable machine fingerprint string.

    The fingerprint is derived from:
      - OS name, release, and machine type
      - Obfuscated MAC address via uuid.getnode()
      - The root path (drive letter) on disk

    It does not include raw serial numbers or unique identifiers.
    Returns "unknown" on failure.
    """
    try:
        parts: list[str] = []
        parts.append(platform.system())
        parts.append(platform.release())
        parts.append(platform.machine())
        # uuid.getnode() already returns an integer derived from the MAC
        parts.append(hex(uuid.getnode()))
        # Include the root path on Windows (e.g. "C:\\") for extra variation
        try:
            root = os.path.abspath(os.sep)
            parts.append(root)
        except Exception:
            pass
        raw = "|".join(parts).encode("utf-8", errors="ignore")
        return hashlib.sha256(raw).hexdigest()
    except Exception:
        return "unknown"
