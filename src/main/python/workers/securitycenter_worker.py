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

from qtpy.QtCore import Signal, QThread
from pathlib import Path
import os
from app.paths import vault_file
from features.clipboard.secure_clipboard import _win_clipboard_risk_state
from auth.login.login_handler import _load_vault_salt_for, get_user_record
from security.baseline_signer import _baseline_tracked_files, verify_baseline
from security.integrity_manifest import verify_manifest_auto


# ==============================
# --- SecurityCenterWorker
#==============================================================================
class SecurityCenterWorker(QThread):
    progress = Signal(str)
    finished = Signal(object, object)   # (data, error)

    def __init__(self, username: str):
        super().__init__()
        self.username = username
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            results = {}

            def step(label, fn):
                if self._stop:
                    return
                self.progress.emit(label)
                try:
                    results[label] = fn()
                except Exception as e:
                    results[label] = {"error": str(e)}

            # --- CLIPBOARD RISK ---
            step("clipboard", lambda: _win_clipboard_risk_state())

            # --- VAULT ---
            step("vault", lambda: self._check_vault())

            # --- BASELINE ---
            step("baseline", lambda: self._check_baseline())

            # --- MANIFEST ---
            step("manifest", lambda: self._check_manifest())

            # --- BACKUPS ---
            step("backups", lambda: self._check_backups())

            self.finished.emit(results, None)

        except Exception as e:
            self.finished.emit({}, str(e))

    # ---------------- INTERNAL CHECKS ---------------------

    def _check_vault(self):
        try:
            p = vault_file(self.username)
            return {
                "exists": Path(p).exists(),
                "size": os.path.getsize(p) if Path(p).exists() else 0,
            }
        except Exception as e:
            return {"error": str(e)}

    def _check_baseline(self):
        try:
            salt = _load_vault_salt_for(self.username)
            files = _baseline_tracked_files(self.username)
            changed, missing, new, mac_ok = verify_baseline(self.username, salt, files)
            return {
                "ok": mac_ok,
                "changed": changed,
                "missing": missing,
                "new": new,
            }
        except Exception as e:
            return {"error": str(e)}


    def _check_manifest(self):
        try:
            ok, msg = verify_manifest_auto()
            return {"ok": ok, "msg": msg}
        except Exception as e:
            return {"error": str(e)}

    def _check_backups(self):
        try:
            rec = get_user_record(self.username)
            last = rec.get("last_backup_time")
            return {
                "has_recent_backup": last is not None,
                "last_backup": last,
            }
        except Exception as e:
            return {"error": str(e)}
