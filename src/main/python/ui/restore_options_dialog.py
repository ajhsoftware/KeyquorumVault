"""Keyquorum Vault
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

from qtpy.QtWidgets import (QGroupBox,QDialog, QLabel, QDialogButtonBox, QVBoxLayout, QCheckBox,QRadioButton)    

# ==============================
# --- (UI) restore options show ---
# ==============================
class RestoreOptionsDialog(QDialog):
    """
    Lets the user choose which parts to restore and how to handle the user_db record.
    Returns (components_set, userdb_mode) on accept.
    """
    def __init__(self, parent=None, *, default_components=None, default_userdb_mode="replace"):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Restore Options"))

        # Components
        self.chkVault     = QCheckBox(self.tr("Vault file"))
        self.chkWrapped   = QCheckBox(self.tr("Wrapped key"))
        self.chkSalt      = QCheckBox(self.tr("Salt"))
        self.chkShare     = QCheckBox(self.tr("Share keys"))
        self.chkIdentity  = QCheckBox(self.tr("Identity blob"))
        self.chkUserDB    = QCheckBox(self.tr("User record (user_db)"))

        for cb in (self.chkVault, self.chkWrapped, self.chkSalt, self.chkShare, self.chkIdentity, self.chkUserDB):
            cb.setChecked(True)

        if isinstance(default_components, set):
            # set defaults if provided
            all_keys = {
                "vault": self.chkVault,
                "wrapped": self.chkWrapped,
                "salt": self.chkSalt,
                "sharekeys": self.chkShare,
                "identity": self.chkIdentity,
                "userdb": self.chkUserDB,
            }
            # clear all then enable those passed
            for cb in all_keys.values():
                cb.setChecked(False)
            for key in default_components:
                if key in all_keys:
                    all_keys[key].setChecked(True)

        comps_box = QGroupBox("Components to restore")
        v_comps = QVBoxLayout(comps_box)
        v_comps.addWidget(self.chkVault)
        v_comps.addWidget(self.chkWrapped)
        v_comps.addWidget(self.chkSalt)
        v_comps.addWidget(self.chkShare)
        v_comps.addWidget(self.chkIdentity)
        v_comps.addWidget(self.chkUserDB)

        # User DB mode
        self.rbReplace = QRadioButton(self.tr("Replace user record"))
        self.rbMerge   = QRadioButton(self.tr("Merge into existing record"))
        if str(default_userdb_mode).lower() == "merge":
            self.rbMerge.setChecked(True)
        else:
            self.rbReplace.setChecked(True)

        mode_box = QGroupBox("User record mode")
        v_mode = QVBoxLayout(mode_box)
        v_mode.addWidget(self.rbReplace)
        v_mode.addWidget(self.rbMerge)

        # Hint
        hint = QLabel(self.tr("Tip: to restore only your user record, untick everything except “User record (user_db)”."))
        hint.setWordWrap(True)

        # Buttons
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        # Layout
        root = QVBoxLayout(self)
        root.addWidget(hint)
        root.addWidget(comps_box)
        root.addWidget(mode_box)
        root.addWidget(btns)

    def result_values(self):
        components = set()
        if self.chkVault.isChecked():    components.add("vault")
        if self.chkWrapped.isChecked():  components.add("wrapped")
        if self.chkSalt.isChecked():     components.add("salt")
        if self.chkShare.isChecked():    components.add("sharekeys")
        if self.chkIdentity.isChecked(): components.add("identity")
        if self.chkUserDB.isChecked():   components.add("userdb")
        mode = "merge" if self.rbMerge.isChecked() else "replace"
        return components, mode

