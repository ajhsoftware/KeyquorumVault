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
- All file locations resolved via paths.security_prefs_file (single source of truth)
- No hardcoded %APPDATA% or subfolders
- Duplicate helpers removed; atomic writes retained
- UI: two lists (Blocked tools, Allowlist), with Add/Delete and keyboard shortcuts
"""

import json, os, logging
from pathlib import Path
from typing import List, Optional

from qtpy.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QTabWidget,
    QTableWidget, QTableWidgetItem, QWidget, QMessageBox, QAbstractItemView,
    QHeaderView, QShortcut
)
from qtpy.QtGui import QKeySequence
from qtpy.QtCore import Qt

# Single source of truth for the prefs file path
from app.paths import security_prefs_file

log = logging.getLogger("keyquorum")

# --------------------------------- #
# Defaults
# --------------------------------- #

DEFAULTS = {
    "suspect_process_names": [
        "x64dbg", "ida", "ollydbg", "gdb", "lldb", "cheatengine",
        "wireshark", "fiddler", "procmon", "processhacker", "tcpdump",
        "keylogger", "hookdll",
    ],
    "allowlist": [],

    # Optional per-tool explanations shown in the preflight warning dialog.
    # Key: process name (e.g. "wireshark" or "wireshark.exe")
    # Value: {title, risk, why, recommended}
    "process_notes": {
        "x64dbg": {
            "title": "x64dbg",
            "risk": "Debugger / process inspection",
            "why": "Debuggers can attach to processes and inspect or modify memory.",
            "recommended": "Close before unlocking the vault.",
        },
        "ida": {
            "title": "IDA",
            "risk": "Reverse engineering tool",
            "why": "May be used to analyze binaries and security mechanisms.",
            "recommended": "Close before unlocking the vault.",
        },
        "ollydbg": {
            "title": "OllyDbg",
            "risk": "Debugger / process inspection",
            "why": "Can attach to processes and inspect or modify memory.",
            "recommended": "Close before unlocking the vault.",
        },
        "gdb": {
            "title": "GDB",
            "risk": "Debugger / process inspection",
            "why": "Can attach to processes and inspect or modify memory.",
            "recommended": "Close before unlocking the vault.",
        },
        "lldb": {
            "title": "LLDB",
            "risk": "Debugger / process inspection",
            "why": "Can attach to processes and inspect or modify memory.",
            "recommended": "Close before unlocking the vault.",
        },
        "cheatengine": {
            "title": "Cheat Engine",
            "risk": "Memory scanning / modification",
            "why": "May inspect or change memory contents (including secrets).",
            "recommended": "Close before unlocking the vault.",
        },
        "wireshark": {
            "title": "Wireshark",
            "risk": "Network packet capture",
            "why": "Can capture network traffic on the local system.",
            "recommended": "Avoid running during login/unlock on untrusted networks.",
        },
        "fiddler": {
            "title": "Fiddler",
            "risk": "HTTP(S) proxy / traffic inspection",
            "why": "Can intercept and inspect network traffic.",
            "recommended": "Close before unlocking the vault if not required.",
        },
        "procmon": {
            "title": "Process Monitor",
            "risk": "System monitoring",
            "why": "Can observe file/registry/process activity.",
            "recommended": "Close before unlocking the vault.",
        },
        "processhacker": {
            "title": "Process Hacker",
            "risk": "Process inspection / memory access",
            "why": "Can inspect or manipulate running processes.",
            "recommended": "Close before unlocking the vault.",
        },
        "tcpdump": {
            "title": "tcpdump",
            "risk": "Network packet capture",
            "why": "Can capture network traffic on the local system.",
            "recommended": "Avoid running during login/unlock on untrusted networks.",
        },
        "keylogger": {
            "title": "Keylogger",
            "risk": "Keystroke capture",
            "why": "May capture typed credentials or sensitive data.",
            "recommended": "Remove/close before unlocking the vault.",
        },
        "hookdll": {
            "title": "Hook DLL",
            "risk": "Input/memory hooking",
            "why": "May hook keyboard/mouse or process memory.",
            "recommended": "Close before unlocking the vault.",
        },
    },
}

# --------------------------------- #
# File I/O helpers
# --------------------------------- #

def _atomic_write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    txt = json.dumps(obj, indent=2, ensure_ascii=False)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(txt)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp, path)

def _read_json_safe(p: Path) -> dict:
    try:
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception as e:
        log.error(f"[prefs] read failed {p}: {e}")
    return {}

# --------------------------------- #
# Normalisation helpers
# --------------------------------- #

def _strip_exe_lower(s: str) -> str:
    s = (s or "").strip()
    if s.lower().endswith(".exe"):
        s = s[:-4]
    return s.lower()

def _unique_ci(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for it in items:
        it = (it or "").strip()
        if not it:
            continue
        key = _strip_exe_lower(it)
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out

def _norm_key(x: str) -> str:
    return (x or "").strip().lower()

def _norm_username(u: Optional[str]) -> str:
    if isinstance(u, str):
        u = u.strip()
        return u or "default"
    if hasattr(u, "username") and isinstance(getattr(u, "username"), str):
        v = getattr(u, "username").strip()
        return v or "default"
    return "default"

# --------------------------------- #
# Per-user prefs load/save (via paths.security_prefs_file)
# --------------------------------- #

def _prefs_path(username: str) -> Path:
    # name_only=False to get the full file path; ensure_parent=True to create dirs
    return Path(security_prefs_file(username, ensure_parent=True, name_only=False))

def load_prefs(username: Optional[str]) -> dict:
    """
    Load per-user security prefs (merged with defaults, lists normalised).
    """
    user = _norm_username(username)
    p = _prefs_path(user)

    base = _read_json_safe(p)
    data = dict(base)  # preserve unknown keys

    # Ensure present
    data.setdefault("suspect_process_names", list(DEFAULTS["suspect_process_names"]))
    data.setdefault("allowlist", list(DEFAULTS["allowlist"]))
    data.setdefault("process_notes", dict(DEFAULTS["process_notes"]))

    # Normalise lists (strip empties/whitespace)
    for k in ("suspect_process_names", "allowlist"):
        v = data.get(k)
        v = [str(x).strip() for x in v] if isinstance(v, list) else []
        data[k] = [x for x in v if x]

    # Normalise notes
    notes = data.get("process_notes")
    if not isinstance(notes, dict):
        notes = {}
    norm_notes: dict = {}
    for k, v in notes.items():
        if not isinstance(k, str) or not isinstance(v, dict):
            continue
        kk = _strip_exe_lower(k)  # store canonical key without .exe
        if not kk:
            continue
        norm_notes[kk] = {
            "title": str(v.get("title", "")).strip(),
            "risk": str(v.get("risk", "")).strip(),
            "why": str(v.get("why", "")).strip(),
            "recommended": str(v.get("recommended", "")).strip(),
        }
    data["process_notes"] = norm_notes

    return data

def save_prefs(update: dict, username: Optional[str]) -> None:
    """
    Update only known list fields while preserving any other keys on disk.
    """
    user = _norm_username(username)
    p = _prefs_path(user)

    existing = _read_json_safe(p)
    out = dict(existing)  # preserve unknown keys

    out["suspect_process_names"] = list(update.get("suspect_process_names", []))
    out["allowlist"] = list(update.get("allowlist", []))
    out["process_notes"] = dict(update.get("process_notes", {}))

    _atomic_write_json(p, out)

# --------------------------------- #
# Widgets
# --------------------------------- #

class _ListEditor(QWidget):
    """Reusable one-column editor with Add/Delete (Enter to add, Delete to remove)."""
    def __init__(self, header: str, initial_items: List[str], parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Entry row
        row = QHBoxLayout()
        self.input = QLineEdit(self)
        self.input.setPlaceholderText(self.tr("Enter process name (e.g., wireshark)"))
        self.btn_add = QPushButton(self.tr("Add"))
        row.addWidget(self.input)
        row.addWidget(self.btn_add)
        layout.addLayout(row)

        # Table
        self.table = QTableWidget(0, 1, self)
        self.table.setHorizontalHeaderLabels([header])
        try:
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        except Exception:
            self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked |
            QAbstractItemView.EditTrigger.SelectedClicked
        )
        layout.addWidget(self.table)

        # Delete row
        del_row = QHBoxLayout()
        self.btn_delete = QPushButton(self.tr("Delete Selected"))
        del_row.addStretch(1)
        del_row.addWidget(self.btn_delete)
        layout.addLayout(del_row)

        # Actions
        self.btn_add.clicked.connect(self._on_add)
        self.btn_delete.clicked.connect(self._on_delete)
        self.input.returnPressed.connect(self._on_add)
        QShortcut(QKeySequence(Qt.Key.Key_Delete), self, activated=self._on_delete)

        # Populate
        for it in initial_items or []:
            self._append(it)

    def _poke_parent_idle(self):
        p = self.parent()
        if p is not None and hasattr(p, "reset_logout_timer"):
            try:
                p.reset_logout_timer()
            except Exception:
                pass

    def _append(self, text: str) -> None:
        text = (text or "").strip()
        if not text:
            return
        existing = [
            _strip_exe_lower(self.table.item(r, 0).text())
            for r in range(self.table.rowCount())
            if self.table.item(r, 0)
        ]
        if _strip_exe_lower(text) in existing:
            return
        self._poke_parent_idle()
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(text))

    def _on_add(self) -> None:
        text = self.input.text().strip()
        if not text:
            return
        self._append(text)
        self.input.clear()

    def _on_delete(self) -> None:
        r = self.table.currentRow()
        if r >= 0:
            self.table.removeRow(r)
            self._poke_parent_idle()

    def items(self) -> List[str]:
        vals = [
            self.table.item(r, 0).text().strip()
            for r in range(self.table.rowCount())
            if self.table.item(r, 0)
        ]
        return _unique_ci(vals)


class _ToolNoteDialog(QDialog):
    """Add/Edit dialog for a single process note."""

    def __init__(self, parent=None, *, initial: Optional[dict] = None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Tool Details"))
        self.resize(520, 320)

        initial = initial or {}

        from qtpy.QtWidgets import QFormLayout, QTextEdit

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.ed_proc = QLineEdit(self)
        self.ed_proc.setPlaceholderText(self.tr("Process name (e.g., wireshark or wireshark.exe)"))
        self.ed_title = QLineEdit(self)
        self.ed_title.setPlaceholderText(self.tr("Display name (optional)"))
        self.ed_risk = QLineEdit(self)
        self.ed_risk.setPlaceholderText(self.tr("Risk summary (optional)"))

        self.ed_why = QTextEdit(self)
        self.ed_why.setPlaceholderText(self.tr("Why it matters (optional)"))
        self.ed_rec = QTextEdit(self)
        self.ed_rec.setPlaceholderText(self.tr("Recommended action (optional)"))

        self.ed_proc.setText(str(initial.get("proc", "") or ""))
        self.ed_title.setText(str(initial.get("title", "") or ""))
        self.ed_risk.setText(str(initial.get("risk", "") or ""))
        self.ed_why.setPlainText(str(initial.get("why", "") or ""))
        self.ed_rec.setPlainText(str(initial.get("recommended", "") or ""))

        form.addRow(self.tr("Process"), self.ed_proc)
        form.addRow(self.tr("Title"), self.ed_title)
        form.addRow(self.tr("Risk"), self.ed_risk)
        form.addRow(self.tr("Why"), self.ed_why)
        form.addRow(self.tr("Recommended"), self.ed_rec)
        layout.addLayout(form)

        btns = QHBoxLayout()
        self.btn_cancel = QPushButton(self.tr("Cancel"))
        self.btn_ok = QPushButton(self.tr("OK"))
        btns.addStretch(1)
        btns.addWidget(self.btn_cancel)
        btns.addWidget(self.btn_ok)
        layout.addLayout(btns)

        self.btn_cancel.clicked.connect(self.reject)
        self.btn_ok.clicked.connect(self.accept)

    def get_value(self) -> dict:
        proc = (self.ed_proc.text() or "").strip()
        return {
            "proc": proc,
            "title": (self.ed_title.text() or "").strip(),
            "risk": (self.ed_risk.text() or "").strip(),
            "why": (self.ed_why.toPlainText() or "").strip(),
            "recommended": (self.ed_rec.toPlainText() or "").strip(),
        }


class _ToolNotesEditor(QWidget):
    """Multi-column editor for per-tool/process notes."""

    COLS = ["Process", "Title", "Risk", "Why", "Recommended"]

    def __init__(self, notes: dict, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        self.table = QTableWidget(0, len(self.COLS), self)
        self.table.setHorizontalHeaderLabels([self.tr(c) for c in self.COLS])
        try:
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        except Exception:
            self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        row = QHBoxLayout()
        self.btn_add = QPushButton(self.tr("Add"))
        self.btn_edit = QPushButton(self.tr("Edit"))
        self.btn_delete = QPushButton(self.tr("Delete"))
        self.btn_reset = QPushButton(self.tr("Reset Defaults"))
        row.addWidget(self.btn_add)
        row.addWidget(self.btn_edit)
        row.addWidget(self.btn_delete)
        row.addStretch(1)
        row.addWidget(self.btn_reset)
        layout.addLayout(row)

        self.btn_add.clicked.connect(self._on_add)
        self.btn_edit.clicked.connect(self._on_edit)
        self.btn_delete.clicked.connect(self._on_delete)
        self.btn_reset.clicked.connect(self._on_reset)

        QShortcut(QKeySequence(Qt.Key.Key_Delete), self, activated=self._on_delete)

        self.set_notes(notes or {})

    def _poke_parent_idle(self):
        p = self.parent()
        if p is not None and hasattr(p, "reset_logout_timer"):
            try:
                p.reset_logout_timer()
            except Exception:
                pass

    def set_notes(self, notes: dict):
        self.table.setRowCount(0)
        if not isinstance(notes, dict):
            notes = {}
        for proc_key in sorted(notes.keys()):
            info = notes.get(proc_key) or {}
            self._append_row(proc_key, info)

    def _append_row(self, proc_key: str, info: dict):
        r = self.table.rowCount()
        self.table.insertRow(r)
        vals = [
            proc_key,
            str(info.get("title", "") or ""),
            str(info.get("risk", "") or ""),
            str(info.get("why", "") or ""),
            str(info.get("recommended", "") or ""),
        ]
        for c, v in enumerate(vals):
            it = QTableWidgetItem(v)
            if c == 0:
                it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, c, it)

    def _current_proc(self) -> Optional[str]:
        r = self.table.currentRow()
        if r < 0:
            return None
        it = self.table.item(r, 0)
        return it.text().strip() if it else None

    def _on_add(self):
        dlg = _ToolNoteDialog(self)
        if (dlg.exec_() if hasattr(dlg, "exec_") else dlg.exec()) != QDialog.DialogCode.Accepted:
            return
        val = dlg.get_value()
        proc = _strip_exe_lower(val.get("proc", ""))
        if not proc:
            QMessageBox.information(self, self.tr("Tool Details"), self.tr("Process name is required."))
            return

        # Upsert
        existing = self.items_dict()
        existing[proc] = {
            "title": val.get("title", ""),
            "risk": val.get("risk", ""),
            "why": val.get("why", ""),
            "recommended": val.get("recommended", ""),
        }
        self.set_notes(existing)
        self._poke_parent_idle()

    def _on_edit(self):
        proc = self._current_proc()
        if not proc:
            return
        existing = self.items_dict()
        info = existing.get(proc, {})
        dlg = _ToolNoteDialog(self, initial={
            "proc": proc,
            "title": info.get("title", ""),
            "risk": info.get("risk", ""),
            "why": info.get("why", ""),
            "recommended": info.get("recommended", ""),
        })
        if (dlg.exec_() if hasattr(dlg, "exec_") else dlg.exec()) != QDialog.DialogCode.Accepted:
            return
        val = dlg.get_value()
        # proc key is not editable in edit (we keep it stable)
        existing[proc] = {
            "title": val.get("title", ""),
            "risk": val.get("risk", ""),
            "why": val.get("why", ""),
            "recommended": val.get("recommended", ""),
        }
        self.set_notes(existing)
        self._poke_parent_idle()

    def _on_delete(self):
        proc = self._current_proc()
        if not proc:
            return
        existing = self.items_dict()
        if proc in existing:
            existing.pop(proc, None)
        self.set_notes(existing)
        self._poke_parent_idle()

    def _on_reset(self):
        # Reset to shipped defaults
        self.set_notes(dict(DEFAULTS.get("process_notes", {})))
        self._poke_parent_idle()

    def items_dict(self) -> dict:
        out: dict = {}
        for r in range(self.table.rowCount()):
            proc = (self.table.item(r, 0).text() if self.table.item(r, 0) else "").strip()
            if not proc:
                continue
            out[_strip_exe_lower(proc)] = {
                "title": (self.table.item(r, 1).text() if self.table.item(r, 1) else "").strip(),
                "risk": (self.table.item(r, 2).text() if self.table.item(r, 2) else "").strip(),
                "why": (self.table.item(r, 3).text() if self.table.item(r, 3) else "").strip(),
                "recommended": (self.table.item(r, 4).text() if self.table.item(r, 4) else "").strip(),
            }
        return out


# --------------------------------- #
# Dialog
# --------------------------------- #

class SecurityPrefsDialog(QDialog):
    def __init__(self, username: str, parent=None):
        super().__init__(parent)
        self.username = _norm_username(username)

        self.setWindowTitle(self.tr("Security Preferences") + f" — {self.username}")
        self.resize(560, 440)

        # Load current prefs
        self.prefs = load_prefs(self.username)

        # UI
        layout = QVBoxLayout(self)
        tabs = QTabWidget(self)

        self.tab_blocked = _ListEditor(
            self.tr("Blocked tool/process names"),
            self.prefs.get("suspect_process_names", DEFAULTS["suspect_process_names"]),
            self,
        )
        self.tab_allow = _ListEditor(
            self.tr("Allowlist (always ignore)"),
            self.prefs.get("allowlist", DEFAULTS["allowlist"]),
            self,
        )

        # Per-tool explanations shown in the preflight warning dialog
        self.tab_notes = _ToolNotesEditor(
            self.prefs.get("process_notes", DEFAULTS.get("process_notes", {})),
            self,
        )
        tabs.addTab(self.tab_blocked, self.tr("Blocked Tools"))
        tabs.addTab(self.tab_allow, self.tr("Allowlist"))
        tabs.addTab(self.tab_notes, self.tr("Tool Details"))
        layout.addWidget(tabs)

        btn_row = QHBoxLayout()
        self.btn_save = QPushButton(self.tr("Save"))
        self.btn_cancel = QPushButton(self.tr("Cancel"))
        btn_row.addStretch(1)
        btn_row.addWidget(self.btn_cancel)
        btn_row.addWidget(self.btn_save)
        layout.addLayout(btn_row)

        self.btn_cancel.clicked.connect(self.reject)
        self.btn_save.clicked.connect(self._save_and_close)

        # Shortcuts
        QShortcut(QKeySequence(self.tr("Ctrl+S")), self, activated=self._save_and_close)
        QShortcut(QKeySequence(self.tr("Esc")), self, activated=self.reject)

    # Optional external update
    def setUsername(self, username: str):
        self.username = _norm_username(username)
        self.setWindowTitle(self.tr("Security Preferences") + f" — {self.username}")
        self.prefs = load_prefs(self.username)
        # Repopulate tabs from new prefs
        self._reload_tabs()

    def _reload_tabs(self):
        # Clear tables and repopulate from self.prefs
        def _reseed(table: _ListEditor, items: List[str]):
            table.table.setRowCount(0)
            for it in items or []:
                table._append(it)

        _reseed(self.tab_blocked, self.prefs.get("suspect_process_names", []))
        _reseed(self.tab_allow,   self.prefs.get("allowlist", []))
        try:
            self.tab_notes.set_notes(self.prefs.get("process_notes", {}))
        except Exception:
            pass

    def _save_and_close(self) -> None:
        # Collect lists from tabs
        blocked = list(self.tab_blocked.items())
        allow   = list(self.tab_allow.items())

        # Allowlist wins: remove overlaps from blocked (case-insensitive)
        allow_keys = {_norm_key(a) for a in allow}
        blocked = [b for b in blocked if _norm_key(b) not in allow_keys]

        # Build new prefs (preserve unknown keys)
        new_prefs = dict(self.prefs)
        new_prefs["suspect_process_names"] = blocked
        new_prefs["allowlist"] = allow
        try:
            new_prefs["process_notes"] = dict(self.tab_notes.items_dict())
        except Exception:
            new_prefs["process_notes"] = dict(self.prefs.get("process_notes", {}))
        try:
            new_prefs["process_notes"] = dict(self.tab_notes.items_dict())
        except Exception:
            new_prefs["process_notes"] = dict(self.prefs.get("process_notes", {}))

        # Persist
        try:
            save_prefs(new_prefs, self.username)
        except Exception as e:
            log.error(f"[prefs] save failed for {self.username}: {e}")
            try:
                QMessageBox.critical(self, self.tr("Save Failed"), self.tr("Could not save preferences") + f":\n{e}")
            except Exception:
                pass
            return

        try:
            QMessageBox.information(self, self.tr("Saved"), self.tr("Security preferences updated."))
            from security.baseline_signer import update_baseline
            update_baseline(self.username, verify_after=False, who="Preflight Config")
        except Exception:
            pass

        self.accept()
