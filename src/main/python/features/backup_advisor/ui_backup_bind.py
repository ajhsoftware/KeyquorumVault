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

# --- pysider
from qtpy.QtCore import QSettings
from qtpy.QtWidgets import QMessageBox

# --- import Logging
import logging
import app.kq_logging as kql
log = logging.getLogger("keyquorum")

# --- helpers ---
from features.backup_advisor.backup_advisor import BackupAdvisor


# ==============================
# --- Backup Advisor
# ==============================

def init__backup_avisor(w):
    qs = QSettings("AJH Software", "Keyquorum Vault")

    # --- ensure advisor exists ---
    if not getattr(w, "backupAdvisor", None):
        # use the actual backup function you have
        w.backupAdvisor = BackupAdvisor(w, do_backup_callable=w.export_vault_with_password)

    # --- read prefs (with sane defaults) ---
    mode = str(qs.value("backup/remindMode", "both")).lower()
    if mode not in ("off", "changes", "logout", "both"):
        mode = "both"
    w._backup_remind_mode = mode

    try:
        thr = int(qs.value("backup/changesThreshold", 5) or 5)
    except Exception:
        thr = 5
    w.backupAdvisor.threshold = max(1, int(thr))

    # --- find widgets if they exist (run headless-safe) ---
    mode_combo = getattr(w, "backupModeCombo", None)
    thr_spin   = getattr(w, "backupThresholdSpin", None)
    reset_btn  = getattr(w, "resetBackupCounterBtn", None)

    # if there is no UI yet, we're done (advisor still works)
    if not mode_combo or not thr_spin:
        return

    # only wire once
    if getattr(w, "_wired_backup_ui", False):
        # still refresh values in case prefs changed
        idx_map = {"off":0, "changes":1, "logout":2, "both":3}
        mode_combo.setCurrentIndex(idx_map.get(mode, 3))
        thr_spin.setValue(int(thr))
        thr_spin.setEnabled(mode_combo.currentIndex() in (1, 3))
        return

    # --- populate & set current values ---
    if mode_combo.count() == 0:
        mode_combo.addItems(["Off", "After N changes", "On logout", "After N + logout"])
    idx_map = {"off":0, "changes":1, "logout":2, "both":3}
    mode_combo.setCurrentIndex(idx_map.get(mode, 3))

    thr_spin.setRange(1, 999)
    thr_spin.setValue(int(thr))
    thr_spin.setEnabled(mode_combo.currentIndex() in (1, 3))

    # --- handlers (save immediately on change) ---
    def on_mode_changed(ix: int):
        rev = {0:"off", 1:"changes", 2:"logout", 3:"both"}[ix]
        w._backup_remind_mode = rev
        qs.setValue("backup/remindMode", rev)
        # enable/disable threshold when needed
        thr_spin.setEnabled(ix in (1, 3))

    def on_thr_changed(v: int):
        v = max(1, int(v))
        w.backupAdvisor.threshold = v
        qs.setValue("backup/changesThreshold", v)

    # clean old connections (if any)
    try: mode_combo.currentIndexChanged.disconnect()
    except Exception: pass
    try: thr_spin.valueChanged.disconnect()
    except Exception: pass

    mode_combo.currentIndexChanged.connect(on_mode_changed)
    thr_spin.valueChanged.connect(on_thr_changed)

    # --- reset counter button (optional) ---
    if reset_btn:
        try: reset_btn.clicked.disconnect()
        except Exception: pass

        def on_reset_counter():
            if QMessageBox.question(
                w, "Reset backup counter",
                "Reset the pending change counter (and clear any snooze)?"
            ) == QMessageBox.Yes:
                if getattr(w, "backupAdvisor", None):
                    w.backupAdvisor.reset_change_counter(clear_snooze=True, clear_session_suppress=False)

        reset_btn.clicked.connect(on_reset_counter)

    w._wired_backup_ui = True

# --- pick a working backup function dynamically ---

def resolve_backup_callable(w):
    """
    Try likely method names on w; return a callable or a stub that warns and returns False.
    """
    candidates = [
        "export_evault_with_password",  # your newer name (if present)
        "export_vault_with_password",
        "export_vault_secure",
        "export_vault",                 # older plain export
        "backup_now",                   # any custom alias you might have
    ]
    for name in candidates:
        fn = getattr(w, name, None)
        if callable(fn):
            return fn

    # final fallback: a stub that informs the user
    def _no_backup_stub():
        QMessageBox.warning(
            w,
            "Backup",
            "No backup function is available in this build. "
            "Please add/enable an export/backup function."
        )
        return False
    return _no_backup_stub
   
def cleanup_on_logout(w):
    w.set_status_txt(w.tr("cleaning up on logout"))
    # 1) Last-chance prompt (only if mode includes logout)
    try:
        if getattr(w, "_backup_remind_mode", "both") in ("logout", "both"):
            adv = getattr(w, "backupAdvisor", None)
            w.set_status_txt(w.tr("Last Changes backup"))
            if adv:
                changes   = int(adv.pending_changes())
                    
                threshold = max(1, int(getattr(adv, "threshold", 5) or 5))
                # On logout we prompt if either:
                #  - mode includes logout AND changes >= threshold (same rule as in-session), OR
                #  - you prefer: always prompt on logout when mode includes logout (uncomment next line)
                # changes = max(changes, threshold)  # <- forces prompt once on logout
                if changes >= threshold:
                    adv.prompt_to_backup_now(force=True)
    except Exception:
        pass

    # 2) Stop timer (if you add scheduler later)
    try:
        w.set_status_txt(w.tr("Stoping Timers"))
        if getattr(w, "backupScheduler", None) and hasattr(w.backupScheduler, "timer"):
            w.backupScheduler.timer.stop()
    except Exception:
        pass

    # 3) Clear refs
    w.set_status_txt(w.tr("Backup Clean"))
    w.backupAdvisor = None
    w.backupScheduler = None
