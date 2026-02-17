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

import logging
import re
from typing import Tuple, Dict
log = logging.getLogger("keyquorum")

try:
    from qtpy.QtWidgets import QLineEdit
except Exception:
    QLineEdit = None

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("password_utils", text)

def estimate_strength_score(password: str) -> int:
    """Return a 0..100 score. No external deps; fast and deterministic."""
    p = password or ""
    if len(p) < 8:
        return 0

    # Base for length (caps at 40 points)
    score = min(40, len(p) * 2)

    # Character classes
    score += 15 if any(c.islower() for c in p) else 0
    score += 15 if any(c.isupper() for c in p) else 0
    score += 15 if any(c.isdigit() for c in p) else 0
    score += 15 if any(c in SYMBOLS for c in p) else 0

    # Variety bonus / repetition penalty
    low = p.lower()
    if len(set(low)) <= 3:
        score -= 10
    if len(p) >= 6 and (len(set(p)) == 1 or p == (p[:2] * (len(p) // 2) + p[:2][:len(p) % 2])):
        score -= 10

    # Common/keyboard patterns
    common = {"123456","12345678","123456789","1234567890","password","qwerty",
              "letmein","welcome","admin","iloveyou","abc123","111111","000000",
              "passw0rd","qwertyuiop","monkey"}
    if low in common or low in {"qwertyuiop","asdfghjkl","zxcvbnm","1q2w3e4r","qazwsx","123qwe"}:
        score = min(score, 35)

    return max(0, min(100, int(score)))

# -----------------------------------
# Policy & symbols
# -----------------------------------
# Keep symbols aligned with generator; allow a few extras + £ for UK users.
SYMBOLS = '!@#$%^&*()-_=+[]{}|:;\'",.<>/?`~\\£'

# Build a safe character class for regex
_SYMBOLS_CLASS = re.escape(SYMBOLS)

# At least 1 lower, 1 upper, 1 digit, 1 symbol from our set; min length 8.
# Only letters/digits/our symbols are allowed (no whitespace).
POLICY_RE = re.compile(
    rf'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[{_SYMBOLS_CLASS}])[A-Za-z\d{_SYMBOLS_CLASS}]{{8,}}$'
)


# --- Password strength ---
def evaluate_password_strength2(password: str) -> str:
    length = len(password or "")
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()-_=+[{]}|;:'\",<.>/?`~" for c in password)
    score = sum([has_upper, has_lower, has_digit, has_special])
    if length >= 12 and score == 4:
        return "Strong"
    elif length >= 8 and score >= 3:
        return "Medium"
    return "Weak"


# --- hash password ---
def _store_password_hash(h: str | bytes) -> str:
    if isinstance(h, (bytes, bytearray)):
        try:
            return h.decode("utf-8")
        except Exception:
            return h.hex()
    return str(h)

# -----------------------------------
# Core validators
# -----------------------------------
def validate_password_policy(password: str) -> bool:
    """
    Return True if `password` satisfies:
      - ≥ 8 chars
      - contains lowercase, uppercase, digit, and a symbol from SYMBOLS
      - contains only letters/digits/SYMBOLS (no spaces)
    """
    try:
        return POLICY_RE.match(password or "") is not None
    except Exception:
        # Extremely defensive fallback (should never happen)
        return False


def get_password_strength(password: str) -> Tuple[int, str, str]:
    """
    Returns (score, level, info):
      - score: 0..4
      - level: 'Too Short' | 'Weak' | 'Medium' | 'Strong' | 'Excellent'
      - info : human-friendly guidance
    """
    pwd = password or ""
    length = len(pwd)

    # Quick length gate
    if length < 8:
        return (0, "Too Short", _tr("Password must be at least 8 characters long."))

    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_sym   = any(c in SYMBOLS for c in pwd)
    score     = int(has_upper) + int(has_lower) + int(has_digit) + int(has_sym)

    if score == 4:
        if length >= 14:
            return (4, "Excellent", _tr("Strong, long, and complex."))
        if length >= 10:
            return (3, "Strong", _tr("Great password. Consider enabling 2FA."))
        return (2, "Medium", _tr("Good structure—add more length for even better security."))
    if score == 3:
        return (2, "Medium", _tr("Acceptable, but can be improved with more variety or length."))
    if score == 2:
        return (1, "Weak", _tr("Add uppercase, numbers, symbols, and length."))
    return (1, "Weak", _tr("Add uppercase, lowercase, numbers, and symbols."))


def validate_password(password: str) -> Dict[str, object]:
    """
    Validate password against policy and return a structured verdict:
      {
        "valid": bool,
        "reason": str,
        "strength": str
      }
    """
    if not password:
        return {"valid": False, "reason": _tr("Password cannot be empty."), "strength": "Invalid"}

    strength_score, strength_level, _ = get_password_strength(password)
    policy_ok = validate_password_policy(password)

    if policy_ok:
        return {"valid": True, "reason": _tr("Meets password policy."), "strength": strength_level}

    # If not policy-ok, give clear guidance
    if strength_score == 0:
        reason = _tr("Password must be at least 8 characters long.")
    else:
        reason = (_tr(
            "Must include uppercase, lowercase, number, and symbol; "
            "use only letters, digits, and standard symbols (no spaces).")
        )

    return {"valid": False, "reason": reason, "strength": strength_level}


# -----------------------------------
# UI helper (optional)
# -----------------------------------
def toggle_password_visibility(field) -> None:
    """
    Toggle a QLineEdit between Password/Normal echo modes.
    Safe no-op if PyQt5 isn't available or widget is not a QLineEdit.
    """
    try:
        if QLineEdit is None or not isinstance(field, QLineEdit):
            return
        field.setEchoMode(
            QLineEdit.EchoMode.Normal
            if field.echoMode() == QLineEdit.EchoMode.Password
            else QLineEdit.EchoMode.Password
        )
    except Exception:
        pass


__all__ = [
    "SYMBOLS",
    "estimate_strength_score",
    "validate_password_policy",
    "get_password_strength",
    "validate_password",
    "toggle_password_visibility",
]


