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
# - pysider
from qtpy.QtCore import QTimer, QDateTime, Qt, QSettings, QCoreApplication
from qtpy.QtWidgets import QCheckBox, QApplication, QMessageBox
# - import Logging
import logging
log = logging.getLogger("keyquorum")


# --- lang
def _tr(text: str) -> str:
    # context name can be anything stable, e.g. "MainWindow" or "Keyquorum"
    return QCoreApplication.translate("main", text)


# ==============================
# --- BackupAdvisor: prompt user to back up after N changes ---
# ==============================
class BackupAdvisor:
    """
    Tracks vault changes and politely prompts for a backup after N changes.
    - Persists counters in QSettings (per user)
    - "Don't show again until restart" supported (session-only)
    - Can be snoozed for a number of minutes (optional parameter)
    """

    def __init__(self, parent, do_backup_callable, *, settings_org="AJH Software", settings_app="Keyquorum Vault"):
        self.parent = parent
        self._do_backup = do_backup_callable  # callable -> bool/None
        self.settings = QSettings(settings_org, settings_app)

        self.threshold = int(self.settings.value("backup/n_changes_threshold", 5))  # show after 5 changes by default
        self.session_suppressed = False  # "don't show until restart"
        self._debounce_ms = 500  # coalesce rapid bursts of edits

        # counters
        self.change_count = int(self.settings.value("backup/change_count", 0))
        self.last_prompt_ts = int(self.settings.value("backup/last_prompt_ts", 0))  # epoch seconds
        self.snooze_until_ts = int(self.settings.value("backup/snooze_until_ts", 0))

        self._debounce_timer = QTimer(self.parent)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.timeout.connect(self._maybe_prompt_now)

    # Call this after you add/update/delete an entry
    def note_change(self, how_many: int = 1):
        self.change_count += max(1, int(how_many))
        self.settings.setValue("backup/change_count", self.change_count)
        # debounce to avoid spamming on batch imports/edits
        if not self._debounce_timer.isActive():
            self._debounce_timer.start(self._debounce_ms)

    # --- in BackupAdvisor ---

    def pending_changes(self) -> int:
        return int(self.change_count)

    def prompt_to_backup_now(self, force: bool = False):
        """Show the same prompt immediately. If force=True, ignore suppression & threshold."""
        self._maybe_prompt_now(force=force)

    def _maybe_prompt_now(self, force: bool = False):
        # Respect "don't show until restart" only if not forced
        if self.session_suppressed and not force:
            return

        now = int(QDateTime.currentSecsSinceEpoch())

        # Snooze check unless forced
        if not force and self.snooze_until_ts and now < self.snooze_until_ts:
            return

        # Threshold check unless forced
        if not force and int(self.change_count) < max(1, int(self.threshold)):
            return

        # ---- build & show dialog (unchanged) ----
        plural = "changes" if self.change_count != 1 else "change"
        msg = _tr("You have ") + f"{self.change_count} {plural} " + _tr("since your last backup") + ".\n\n" + _tr("Would you like to create a backup now?")
        box = QMessageBox(self.parent)
        box.setWindowTitle(_tr("Create Backup?"))
        box.setIcon(QMessageBox.Question)
        box.setText(msg)
        backup_btn = box.addButton(_tr("Back up now"), QMessageBox.AcceptRole)
        later_btn  = box.addButton(_tr("Later"), QMessageBox.RejectRole)
        chk = QCheckBox(_tr("Don’t show again until restart"))
        box.setCheckBox(chk)

        snooze_minutes = int(self.settings.value("backup/snooze_minutes_on_later", 30))

        box.exec()
        if box.clickedButton() is backup_btn:
            try:
                QApplication.setOverrideCursor(Qt.WaitCursor)
            except Exception:
                pass
            try:
                ok = self._do_backup()
                if ok is True or ok is None:
                    self.change_count = 0
                    self.settings.setValue("backup/change_count", self.change_count)
                    # clear snooze when a successful backup happens
                    self.snooze_until_ts = 0
                    self.settings.setValue("backup/snooze_until_ts", 0)
            finally:
                try:
                    QApplication.restoreOverrideCursor()
                except Exception:
                    pass
        else:
            if snooze_minutes > 0 and not force:  # don't snooze when we forced the prompt
                self.snooze_until_ts = now + snooze_minutes * 60
                self.settings.setValue("backup/snooze_until_ts", self.snooze_until_ts)

        self.session_suppressed = chk.isChecked() if not force else False
        self.settings.setValue("backup/last_prompt_ts", int(QDateTime.currentSecsSinceEpoch()))

    # in BackupAdvisor
    def reset_change_counter(self, *, clear_snooze: bool = True, clear_session_suppress: bool = True):
        """Reset the pending-changes counter (and optionally snooze/session flags)."""
        try:
            self.change_count = 0
            self.settings.setValue("backup/change_count", 0)
            if clear_snooze:
                self.snooze_until_ts = 0
                self.settings.setValue("backup/snooze_until_ts", 0)
            if clear_session_suppress:
                self.session_suppressed = False
            # optional: update last_prompt_ts so we don't immediately re-prompt
            self.last_prompt_ts = int(QDateTime.currentSecsSinceEpoch())
            self.settings.setValue("backup/last_prompt_ts", self.last_prompt_ts)
        except Exception:
            pass

class FullBackupReminder:
    """
    Time-based reminder for full (account/vault/settings) backups.

    - Stores last full backup timestamp in QSettings.
    - Prompts only if overdue by a configurable number of days.
    - Can be snoozed for N days or skipped until next session.
    """

    def __init__(
        self,
        parent,
        do_full_backup_callable,
        *,
        settings_org="AJH Software",
        settings_app="Keyquorum Vault",
    ):
        self.parent = parent
        self._do_full_backup = do_full_backup_callable  # callable -> bool/None
        self.settings = QSettings(settings_org, settings_app)

        # Default: remind every 60 days (you can change to 90, 180, etc.)
        self.interval_days = int(self.settings.value("full_backup/interval_days", 60))
        self.session_suppressed = False  # "don't remind again until restart"

    def note_full_backup_done(self):
        """Call this after a successful full backup."""
        now = int(QDateTime.currentSecsSinceEpoch())
        self.settings.setValue("full_backup/last_ts", now)
        # Clear any snooze when user actually does a full backup
        self.settings.setValue("full_backup/snooze_until_ts", 0)

    def maybe_prompt(self, force: bool = False):
        """
        Check if a reminder is due and, if so, show a gentle prompt.
        Call this at login or app start.
        """
        if self.session_suppressed and not force:
            return

        now = int(QDateTime.currentSecsSinceEpoch())
        last_ts = int(self.settings.value("full_backup/last_ts", 0))
        snooze_until_ts = int(self.settings.value("full_backup/snooze_until_ts", 0))

        # Snooze check
        if not force and snooze_until_ts and now < snooze_until_ts:
            return

        # Interval check
        if not force and last_ts > 0:
            days_since = (now - last_ts) / (24 * 3600)
            if days_since < max(1, self.interval_days):
                return

        # If never backed up, we can optionally still prompt (or only after X days of use)
        # For now, treat last_ts == 0 as "overdue" as well.
        plural_days = self.parent.tr("days") if self.interval_days != 1 else self.parent.tr("day")
        msg = (
            self.parent.tr("It has been a while since your last FULL Keyquorum backup") + ".\n\n" +
            self.parent.tr("A full backup protects your account identity, security keys, categories, ") +
            self.parent.tr("and all vault data in one encrypted package") + ".\n\n" +
            self.parent.tr("Recommended: create a full backup at least every ") + f"{self.interval_days} {plural_days}.")

        box = QMessageBox(self.parent)
        box.setWindowTitle(self.parent.tr("Full Backup Recommended"))
        box.setIcon(QMessageBox.Information)
        box.setText(msg)

        backup_btn = box.addButton(self.parent.tr("Create full backup now"), QMessageBox.AcceptRole)
        later_btn  = box.addButton(self.parent.tr("Remind me later"), QMessageBox.RejectRole)
        never_btn  = box.addButton(self.parent.tr("Not now"), QMessageBox.DestructiveRole)

        chk = QCheckBox(self.parent.tr("Don’t remind again until next session"))
        box.setCheckBox(chk)

        # How long to snooze “Remind me later” (in days)
        snooze_days = int(self.settings.value("full_backup/snooze_days_on_later", 7))

        box.exec()
        clicked = box.clickedButton()

        if clicked is backup_btn:
            try:
                QApplication.setOverrideCursor(Qt.WaitCursor)
            except Exception:
                pass
            try:
                ok = self._do_full_backup()
                if ok is True or ok is None:
                    self.note_full_backup_done()
            finally:
                try:
                    QApplication.restoreOverrideCursor()
                except Exception:
                    pass

        elif clicked is later_btn and snooze_days > 0 and not force:
            snooze_until = now + snooze_days * 24 * 3600
            self.settings.setValue("full_backup/snooze_until_ts", snooze_until)

        # "Not now" just respects the checkbox
        self.session_suppressed = chk.isChecked() if not force else False
