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

from typing import Optional
import re, ctypes
from ctypes import wintypes
import psutil
from PySide6.QtCore import Qt, QSortFilterProxyModel, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QTableView, QLabel, QMessageBox
)

from features.autofill.desktop_autofill import list_top_windows, TargetWindow
from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("window_picker", text)

try:
    # On Windows bind to user32; this attribute doesn't exist on other platforms.
    user32 = ctypes.windll.user32  
except Exception:
    user32 = None

# Safely bind user32 functions only when available; else set to no‑ops.
if user32:
    EnumWindows              = user32.EnumWindows  
    EnumWindowsProc          = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    IsWindowVisible          = user32.IsWindowVisible  
    GetWindowTextW           = user32.GetWindowTextW  
    GetWindowTextLengthW     = user32.GetWindowTextLengthW  
    GetWindowThreadProcessId = user32.GetWindowThreadProcessId  
    GetWindowRect            = user32.GetWindowRect  
    GetForegroundWindow      = user32.GetForegroundWindow  
else:
    EnumWindows              = lambda *args, **kwargs: 0  
    EnumWindowsProc          = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    IsWindowVisible          = lambda *args, **kwargs: False  
    GetWindowTextW           = lambda *args, **kwargs: 0  
    GetWindowTextLengthW     = lambda *args, **kwargs: 0  
    GetWindowThreadProcessId = lambda *args, **kwargs: None  
    GetWindowRect            = lambda *args, **kwargs: 0  
    GetForegroundWindow      = lambda *args, **kwargs: 0  

class RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

def _get_title(hwnd: int) -> str:
    try:
        n = GetWindowTextLengthW(hwnd)
        if n <= 0:
            return ""
        buf = ctypes.create_unicode_buffer(n + 1)
        GetWindowTextW(hwnd, buf, n + 1)
        return (buf.value or "").strip()
    except Exception:
        return ""

def _fallback_list_top_windows() -> list[TargetWindow]:
    """Enumerate top‑level windows using Win32 APIs as a fallback.

    On non‑Windows platforms this returns an empty list immediately to avoid
    calling into unavailable ctypes functions.
    """
    if user32 is None:
        return []
    rows: list[TargetWindow] = []
    def _cb(hwnd, _):
        try:
            if not IsWindowVisible(hwnd):
                return True
            rc = RECT()
            if GetWindowRect(hwnd, ctypes.byref(rc)) == 0:
                return True
            if (rc.right - rc.left) <= 0 or (rc.bottom - rc.top) <= 0:
                return True
            title = _get_title(hwnd)
            if not title:
                return True
            pid = wintypes.DWORD()
            if GetWindowThreadProcessId:
                GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pid_val = int(pid.value or 0)
            pname = ""
            try:
                if pid_val:
                    pname = psutil.Process(pid_val).name()
            except Exception:
                pass
            rows.append(TargetWindow(title=title, process=pname, pid=pid_val, handle=int(hwnd)))
        except Exception:
            pass
        return True
    EnumWindows(EnumWindowsProc(_cb), 0)
    uniq = {}
    for r in rows:
        uniq[(r.title, r.pid)] = r
    return list(uniq.values())

class _WindowsTable(QAbstractTableModel):
    headers = [_tr("Title"), _tr("Process"), _tr("PID"), _tr("Handle")]
    def __init__(self, rows: list[TargetWindow]):
        super().__init__()
        self._rows = rows
    def rowCount(self, parent=None): return len(self._rows)
    def columnCount(self, parent=None): return 4
    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid() or role not in (Qt.DisplayRole, Qt.ToolTipRole):
            return None
        r = self._rows[index.row()]; c = index.column()
        return [r.title, r.process or "", str(r.pid), hex(r.handle)][c]
    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None
    def row(self, i: int) -> TargetWindow: return self._rows[i]
    def set_rows(self, rows: list[TargetWindow]):
        self.beginResetModel(); self._rows = rows; self.endResetModel()

class WindowPickerDialog(QDialog):
    """
    Exposes:
      - selected_title_regex(): forgiving '(?i).*Title.*' regex
      - selected_pid(): PID or None
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Pick target window"))
        self.setMinimumWidth(760)
        layout = QVBoxLayout(self)

        self.search = QLineEdit(self); self.search.setPlaceholderText(self.tr("Filter by title or process…"))
        layout.addWidget(self.search)

        base = list_top_windows() or _fallback_list_top_windows()
        self.model = _WindowsTable(base)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setSourceModel(self.model)

        self.table = QTableView(self)
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.AscendingOrder)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        row = QHBoxLayout()
        self.useActiveBtn = QPushButton(self.tr("Use Active Window"))
        self.refreshBtn   = QPushButton(self.tr("Refresh"))
        self.okBtn        = QPushButton(self.tr("Select"))
        self.cancelBtn    = QPushButton(self.tr("Cancel"))
        row.addWidget(QLabel(self.tr("Tip: run Keyquorum with the same elevation as the target app.")))
        row.addStretch(1)
        row.addWidget(self.useActiveBtn); row.addWidget(self.refreshBtn)
        row.addWidget(self.okBtn); row.addWidget(self.cancelBtn)
        layout.addLayout(row)

        self.search.textChanged.connect(self._on_filter)
        self.refreshBtn.clicked.connect(self._refresh)
        self.okBtn.clicked.connect(self.accept)
        self.cancelBtn.clicked.connect(self.reject)
        self.useActiveBtn.clicked.connect(self._use_active)
        self.table.doubleClicked.connect(lambda *_: self.accept())

        self._selected_regex: Optional[str] = None
        self._selected_pid: Optional[int] = None

    def selected_handle(self) -> int | None:
        tw = self._selected_row()
        return int(tw.handle) if tw else None

    # --- API ---
    def selected_title_regex(self) -> Optional[str]:
        if self._selected_regex:
            return self._selected_regex
        tw = self._selected_row()
        if not tw:
            return None
        esc = re.escape(tw.title)
        return rf"(?i).*{esc}.*"

    def selected_pid(self) -> Optional[int]:
        if self._selected_pid is not None:
            return int(self._selected_pid)
        tw = self._selected_row()
        return int(tw.pid) if (tw and tw.pid) else None

    # --- internals ---
    def _selected_row(self) -> Optional[TargetWindow]:
        sel = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not sel:
            return None
        idx = sel[0]
        try:
            src = self.proxy.mapToSource(idx)
        except Exception:
            src = idx
        try:
            return self.model.row(src.row())
        except Exception:
            return None

    def _on_filter(self, text: str): self.proxy.setFilterFixedString(text or "")

    def _refresh(self):
        rows = list_top_windows() or _fallback_list_top_windows()
        self.model.set_rows(rows)

    def _use_active(self):
        """Populate the dialog with the currently active window on Windows."""
        if user32 is None:
            QMessageBox.information(self, self.tr("Use Active Window"),
                                    self.tr("Use Active Window is only available on Windows."))
            return

        hwnd = GetForegroundWindow() if GetForegroundWindow else 0
        if not hwnd:
            QMessageBox.information(self, self.tr("Use Active Window"), self.tr("No active window detected."))
            return
        title = _get_title(hwnd)
        if not title:
            QMessageBox.information(self, self.tr("Use Active Window"), self.tr("Active window has no title."))
            return
        pid_dw = wintypes.DWORD()
        if GetWindowThreadProcessId:
            GetWindowThreadProcessId(hwnd, ctypes.byref(pid_dw))
        self._selected_pid = int(pid_dw.value or 0)
        esc = re.escape(title)
        self._selected_regex = rf"(?i).*{esc}.*"
        self.accept()
