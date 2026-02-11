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

from typing import Optional, TypedDict

class ParsedKit(TypedDict, total=False):
    has_payload: bool
    payload_version: int
    username: Optional[str]
    recovery_key_present: bool
    recovery_key_fingerprint: Optional[str]
    recovery_backup_codes: list[str]
    twofa_backup_codes: list[str]
    totp_secret_hint: Optional[str]
    raw_payload: Optional[str]


class AccountSnapshot(TypedDict, total=False):
    """
    Minimal snapshot of the account's current state, used only for merging.
    Your DB layer can adapt/extend this.
    """
    recovery_backup_codes: list[str]
    used_recovery_codes: list[str]
    twofa_backup_codes: list[str]
    used_twofa_codes: list[str]
    totp_secret_hint: Optional[str]
