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
In-app Reminders panel for Keyquorum Vault.

This is intentionally self-contained and "soft" integrated:
- Reads reminders from vault entries (best-effort key lookup).
- Lets the user open the related entry, snooze, or clear the reminder.
- Does NOT require Windows notifications to function.

Reminder storage (current):
- Uses dedicated category-added fields when present:
- We look for one of these keys on a vault entry:
    "Reminder", "reminder", "reminder_date", "due_date", "due"
  with a value like "YYYY-MM-DD" or ISO datetime.
- Optionally we read repeat from:
    "reminder_repeat", "repeat"
"""

import datetime as dt
import logging
from typing import Any

from qtpy.QtCore import Qt
from qtpy.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QAbstractItemView,
)

log = logging.getLogger("keyquorum")


def _now_date() -> dt.date:
    return dt.datetime.now().date()


def _parse_date(s: str) -> dt.date | None:
    if not s:
        return None
    s = str(s).strip()
    if not s:
        return None

    # ISO date/time
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "")).date()
    except Exception:
        pass

    # Common formats
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d"):
        try:
            return dt.datetime.strptime(s, fmt).date()
        except Exception:
            pass

    return None


def _fmt_date(d: dt.date | None) -> str:
    return d.isoformat() if d else ""


def _status_for(due: dt.date | None) -> str:
    if not due:
        return "—"
    today = _now_date()
    if due < today:
        return "Overdue"
    if due == today:
        return "Due today"
    # soon
    if (due - today).days <= 7:
        return "Upcoming"
    return "Scheduled"



def _best_entry_label(entry: dict, note: str = "") -> str:
    """Return a user-friendly label for a reminder row."""
    note = (note or "").strip()
    if note:
        return note

    # Common title-like keys
    for k in ("Title", "title", "Name", "name", "Service", "service", "Platform", "platform"):
        v = entry.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()

    # Fallback: first non-empty string-ish field value that isn't metadata
    skip_keys = {
        "category", "Category",
        "Reminder Date", "Reminder Note", "reminder_date", "reminder_note",
        "Reminder", "reminder", "due_date", "due",
        "Notes", "notes",
        "created", "created_at", "updated", "updated_at",
        "id", "uuid",
        "hash", "entry_hash",
    }
    for k, v in entry.items():
        if k in skip_keys:
            continue
        if isinstance(v, str) and v.strip():
            return v.strip()

    # Last resort
    return "—"


class RemindersDialog(QDialog):
    def __init__(self, parent=None, username: str = "", user_key: bytes | None = None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Reminders"))
        self.setMinimumWidth(820)

        self._username = (username or "").strip()
        self._user_key = user_key
        self._rows: list[dict[str, Any]] = []  # table row metadata

        root = QVBoxLayout(self)

        title = QLabel(self.tr("🔔 Reminders"))
        title.setStyleSheet("font-size: 18px; font-weight: 600;")
        root.addWidget(title)

        self.info = QLabel(self.tr("Shows reminders found in your vault entries."))
        self.info.setWordWrap(True)
        root.addWidget(self.info)

        self.table = QTableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            self.tr("Due"),
            self.tr("Status"),
            self.tr("Reminder"),
            self.tr("Category"),
            self.tr("Repeat"),
            self.tr("Notes"),
        ])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        root.addWidget(self.table, 1)

        btns = QHBoxLayout()
        self.refreshBtn = QPushButton(self.tr("Refresh"))
        self.openBtn = QPushButton(self.tr("Open item"))
        self.snooze1Btn = QPushButton(self.tr("Snooze 1 day"))
        self.snooze7Btn = QPushButton(self.tr("Snooze 7 days"))
        self.clearBtn = QPushButton(self.tr("Clear reminder"))
        self.closeBtn = QPushButton(self.tr("Close"))

        for b in (self.refreshBtn, self.openBtn, self.snooze1Btn, self.snooze7Btn, self.clearBtn):
            btns.addWidget(b)
        btns.addStretch(1)
        btns.addWidget(self.closeBtn)
        root.addLayout(btns)

        self.refreshBtn.clicked.connect(self._reload)
        self.openBtn.clicked.connect(self._open_selected)
        self.snooze1Btn.clicked.connect(lambda: self._snooze_selected(days=1))
        self.snooze7Btn.clicked.connect(lambda: self._snooze_selected(days=7))
        self.clearBtn.clicked.connect(self._clear_selected)
        self.closeBtn.clicked.connect(self.accept)

        self._reload()

    # ------------------------ data plumbing ------------------------

    def _load_vault_entries(self) -> list[dict]:
        try:
            from vault_store.vault_store import load_vault
        except Exception:
            return []

        if not self._username or not self._user_key:
            return []

        try:
            return list(load_vault(self._username, self._user_key) or [])
        except Exception as e:
            log.error("[REMINDERS] load_vault failed: %s", e)
            return []

    def _save_vault_entries(self, entries: list[dict]) -> bool:
        try:
            from vault_store.vault_store import save_vault
        except Exception:
            return False

        if not self._username or not self._user_key:
            return False

        try:
            save_vault(self._username, self._user_key, entries)
            return True
        except Exception as e:
            log.error("[REMINDERS] save_vault failed: %s", e)
            return False

    
    def _extract_reminder(self, entry: dict) -> tuple[dt.date | None, str, str]:
        # Prefer dedicated reminder fields added by category editor
        due_raw = (
            entry.get("Reminder Date")
            or entry.get("reminder_date")
            or entry.get("Reminder")
            or entry.get("reminder")
            or entry.get("due_date")
            or entry.get("due")
            or ""
        )
        due = _parse_date(str(due_raw)) if due_raw else None

        note = (
            entry.get("Reminder Note")
            or entry.get("reminder_note")
            or entry.get("Notes")
            or entry.get("notes")
            or ""
        )
        note = str(note).strip()

        # repeat (optional, future)
        repeat = (
            entry.get("reminder_repeat")
            or entry.get("repeat")
            or ""
        )
        repeat = (str(repeat).strip() if repeat is not None else "")

        return due, repeat, note


    def _set_reminder(self, entry: dict, due: dt.date | None, repeat: str = "") -> None:
        # Store in a predictable key. Keep legacy keys cleaned up.
        for k in ("Reminder", "reminder", "reminder_date", "due_date", "due"):
            if k in entry:
                try:
                    del entry[k]
                except Exception:
                    pass
        if due:
            entry["Reminder"] = _fmt_date(due)
        if repeat:
            entry["reminder_repeat"] = repeat
        else:
            entry.pop("reminder_repeat", None)

    def _clear_reminder(self, entry: dict) -> None:
        for k in ("Reminder Date", "Reminder Note", "reminder_note", "Reminder", "reminder", "reminder_date", "due_date", "due", "reminder_repeat", "repeat"):
            if k in entry:
                try:
                    del entry[k]
                except Exception:
                    pass

    # ------------------------ UI actions ------------------------

    def _reload(self):
        entries = self._load_vault_entries()

        rows: list[dict[str, Any]] = []
        for idx, e in enumerate(entries):
            if not isinstance(e, dict):
                continue
            due, repeat, note = self._extract_reminder(e)
            if not due:
                continue
            cat = str(e.get("category") or e.get("Category") or "")
            title = _best_entry_label(e, note=note)
            notes = note  # keep note visible in Notes column too
            rows.append({
                "vault_index": idx,
                "due": due,
                "repeat": repeat,
                "title": title,
                "category": cat,
                "notes": notes,
            })

        # Sort: overdue first, then soonest
        today = _now_date()
        rows.sort(key=lambda r: ((r["due"] >= today), r["due"]))

        self._rows = rows
        self.table.setRowCount(len(rows))

        for r, rec in enumerate(rows):
            due = rec["due"]
            status = _status_for(due)

            items = [
                QTableWidgetItem(_fmt_date(due)),
                QTableWidgetItem(self.tr(status)),
                QTableWidgetItem(rec["title"]),
                QTableWidgetItem(rec["category"]),
                QTableWidgetItem(rec["repeat"]),
                QTableWidgetItem(rec["notes"]),
            ]
            for c, it in enumerate(items):
                it.setFlags(it.flags() & ~Qt.ItemIsEditable)
                self.table.setItem(r, c, it)

        if rows:
            self.table.selectRow(0)
            self.info.setText(self.tr("Found {n} reminder(s).").format(n=len(rows)))
        else:
            self.info.setText(self.tr("No reminders found yet."))

    def _selected_meta(self) -> dict[str, Any] | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._rows):
            return None
        return self._rows[row]

    def _open_selected(self):
        meta = self._selected_meta()
        if not meta:
            return
        par = self.parent()
        if not par:
            return
        idx = int(meta.get("vault_index", -1))
        if idx < 0:
            return
        try:
            tbl = getattr(par, "vaultTable", None)
            if tbl:
                tbl.selectRow(idx)
                tbl.setFocus()
        except Exception:
            pass

        # If an edit helper exists, open it (optional)
        try:
            if hasattr(par, "edit_selected_vault_entry") and callable(par.edit_selected_vault_entry):
                par.edit_selected_vault_entry()
        except Exception:
            pass

    def _snooze_selected(self, days: int = 1):
        meta = self._selected_meta()
        if not meta:
            return
        idx = int(meta.get("vault_index", -1))
        if idx < 0:
            return

        entries = self._load_vault_entries()
        if not (0 <= idx < len(entries)):
            return

        due, repeat, note = self._extract_reminder(entries[idx])
        if not due:
            return

        new_due = due + dt.timedelta(days=int(days))
        self._set_reminder(entries[idx], new_due, repeat=repeat)

        if not self._save_vault_entries(entries):
            QMessageBox.warning(self, self.tr("Reminders"), self.tr("Could not save changes."))
            return

        self._reload()

    def _clear_selected(self):
        meta = self._selected_meta()
        if not meta:
            return
        idx = int(meta.get("vault_index", -1))
        if idx < 0:
            return

        if QMessageBox.question(
            self,
            self.tr("Clear reminder"),
            self.tr("Remove this reminder from the item?"),
        ) != QMessageBox.Yes:
            return

        entries = self._load_vault_entries()
        if not (0 <= idx < len(entries)):
            return

        self._clear_reminder(entries[idx])
        if not self._save_vault_entries(entries):
            QMessageBox.warning(self, self.tr("Reminders"), self.tr("Could not save changes."))
            return

        self._reload()
