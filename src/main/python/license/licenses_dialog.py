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

# Simple dialog that shows THIRD_PARTY_LICENSES.txt
from __future__ import annotations
from pathlib import Path
from qtpy.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout

def _resolve_licenses_path() -> str:
    # Prefer new LEGAL pack
    for p in (
        Path(__file__).resolve().parent / "licenses" / "THIRD_PARTY_NOTICES.md",
        Path.cwd() / "licenses" / "THIRD_PARTY_NOTICES.md",):
        if p.exists():
            return str(p)
    # Fallback to old FBS resource
    try:
        from fbs_runtime.application_context.PySide6 import ApplicationContext
        appctxt = ApplicationContext()
        return appctxt.get_resource("licenses/THIRD_PARTY_LICENSES.txt")
    except Exception:
        pass
    return ""
 
class LicensesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Third‑Party Licenses"))
        self.setMinimumSize(700, 500)
        lay = QVBoxLayout(self)
        self.view = QTextEdit(self)
        self.view.setReadOnly(True)
        lay.addWidget(self.view)
        btn_row = QHBoxLayout()
        btn_close = QPushButton(self.tr("Close"), self)
        btn_close.clicked.connect(self.accept)
        btn_row.addStretch(1)
        btn_row.addWidget(btn_close)
        lay.addLayout(btn_row)
        path = _resolve_licenses_path()
        if path:
            try:
                self.view.setPlainText(Path(path).read_text(encoding="utf-8"))
            except Exception as e:
                self.view.setPlainText(self.tr("Could not read licenses file at") + f":\n{path}\n\n{e}")
        else:
            self.view.setPlainText("Licenses file not found. Make sure it is bundled at:\n"
                                   "src/main/resources/base/licenses/THIRD_PARTY_LICENSES.txt")

def open_licenses_dialog(parent=None):
    dlg = LicensesDialog(parent)
    dlg.exec()

