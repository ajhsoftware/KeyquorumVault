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
from qtpy.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, QInputDialog, QMessageBox
import passkeys_store as pk

class PasskeysPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.table = QTableWidget(0, 5, self)
        self.table.setHorizontalHeaderLabels(["RP ID", "Label", "Username", "CredID…", "Last used"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.btnRefresh = QPushButton(self.tr("Refresh"))
        self.btnRename  = QPushButton(self.tr("Rename"))
        self.btnDelete  = QPushButton(self.tr("Delete"))
        row = QHBoxLayout()
        row.addWidget(self.btnRefresh); row.addWidget(self.btnRename); row.addWidget(self.btnDelete)
        lay = QVBoxLayout(self)
        lay.addWidget(self.table); lay.addLayout(row)

        self.btnRefresh.clicked.connect(self.reload)
        self.btnRename.clicked.connect(self.rename_selected)
        self.btnDelete.clicked.connect(self.delete_selected)
        self.reload()

    def reload(self):
        creds = pk.list_all()
        self.table.setRowCount(len(creds))
        for i, c in enumerate(sorted(creds, key=lambda x: (x.rpId, -(x.lastUsed or 0)))):
            self.table.setItem(i, 0, QTableWidgetItem(c.rpId))
            self.table.setItem(i, 1, QTableWidgetItem(c.label or ""))
            self.table.setItem(i, 2, QTableWidgetItem(c.userName or ""))
            self.table.setItem(i, 3, QTableWidgetItem((c.credId_b64[:8] + "…") if c.credId_b64 else ""))
            self.table.setItem(i, 4, QTableWidgetItem(self._fmt_time(c.lastUsed)))

    def _fmt_time(self, ts: float) -> str:
        if not ts: return "—"
        from datetime import datetime
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

    def _selected_cred_id(self) -> str | None:
        r = self.table.currentRow()
        if r < 0: return None
        cred_short = self.table.item(r, 3).text().replace("…","")
        # Map short to full id
        for c in pk.list_all():
            if c.credId_b64.startswith(cred_short):
                return c.credId_b64
        return None

    def rename_selected(self):
        cred = self._selected_cred_id()
        if not cred: return
        name, ok = QInputDialog.getText(self, self.tr("Rename"), self.tr("New label:"))
        if not ok: return
        allc = pk.list_all()
        for c in allc:
            if c.credId_b64 == cred:
                c.label = name.strip()
                break
        pk.save_all(pk.PasskeyVault(version=1, creds=allc))
        self.reload()

    def delete_selected(self):
        cred = self._selected_cred_id()
        if not cred: return
        if QMessageBox.question(self, self.tr("Delete Passkey"), self.tr("Delete this passkey? This cannot be undone.")) != QMessageBox.Yes:
            return
        pk.delete_by_cred_id(cred)
        self.reload()
