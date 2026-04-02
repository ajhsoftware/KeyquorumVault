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
log = logging.getLogger("keyquorum")
import app.kq_logging as kql
import traceback
from security.preflight import run_preflight_checks


# ==============================
# --- prefligh safe ---
# ==============================
def safe_preflight() -> tuple[bool, str]:
    """
    Call run_preflight_checks() safely.
    Works whether it returns a bool or (ok, reason).
    Returns: (ok, reason)
    """
    try:
        result = run_preflight_checks()
        if isinstance(result, tuple) and len(result) >= 1:
            ok = bool(result[0])
            reason = str(result[1]) if len(result) >= 2 else ""
            return ok, reason
        return bool(result), ""
    except Exception as e:
        # capture full traceback for debug.log
        tb = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        log.error(str(f"{kql.i('err')} [ERROR] 🛑 Preflight checks crashed:\n{tb}"))
        return False, f"Preflight crashed: {e}"



