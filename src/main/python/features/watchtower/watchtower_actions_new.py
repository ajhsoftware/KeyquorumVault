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
Refactored Watchtower action handlers.

This module consolidates the UI‑level actions for the Watchtower feature.  It
provides functions for generating a strong replacement password for an entry
and for routing the user to the appropriate location to resolve Watchtower
issues.  The logic here mirrors and extends the behaviour that previously
lived in `main.py` and the original `watchtower_actions.py`.  In
particular, `_watchtower_fix_entry` now handles the special
`"__GLOBAL_2FA__"` identifier to prompt the user to enable two‑factor
authentication in the Settings → Security tab.  All user interactions
(prompts, warnings, information dialogs) are performed via the provided
main window `w`, which must implement `tr()` and have the expected
Watchtower UI widgets.

Functions:

* `_watchtower_generate_new_password_for(w, entry_id: str)`
    Generate a strong new password for a vault entry, persist it with
    history, and notify the user.

* `_watchtower_fix_entry(w, entry_id: str)`
    Route the user to fix an issue: either enabling 2FA or opening the
    appropriate entry in the editor.  If the entry cannot be located,
    a warning or information message is shown.
"""

from qtpy.QtWidgets import QMessageBox
from vault_store.vault_store import load_vault
from auth.pw.password_generator import generate_strong_password
from features.watchtower.watchtower_helpers import (
    persist_entry_with_history as _persist_entry_with_history,
    find_entry_index_by_id as _find_entry_index_by_id,
)

from features.watchtower.watchtower_scan import stable_id_for_entry
import string
import secrets


def _watchtower_generate_new_password_for(w, entry_id: str) -> None:
    """
    Generate a strong new password for the given vault entry and update it.

    A confirmation dialog is presented to the user.  If the operation
    succeeds, an informational message is shown.  Otherwise, an error
    message is displayed.  The `w` argument should be the main window
    instance with access to the current username and vault key, and with
    a `tr()` method for translations.
    """
    # Locate the entry index in the vault
    try:
        idx = _find_entry_index_by_id(w, entry_id)
    except Exception:
        idx = -1
    if idx < 0:
        try:
            QMessageBox.warning(
                w,
                w.tr("Watchtower"),
                w.tr("Couldn't locate that entry in the vault."),
            )
        except Exception:
            pass
        return

    # Load the existing entry for display purposes
    try:
        entries = load_vault(w.currentUsername.text(), w.userKey)
        entry = dict(entries[idx]) if 0 <= idx < len(entries) else {}
    except Exception:
        entry = {}

    # Ask the user to confirm the password replacement
    try:
        name = entry.get("title") or entry.get("site") or entry.get("name") or "(untitled)"
        resp = QMessageBox.question(
            w,
            w.tr("Generate New Password"),
            w.tr(
                'Generate a new strong password for "{name}" and update this entry?\n\n'
                "You'll need to update it on the website/app next."
            ).format(name=name),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if resp != QMessageBox.StandardButton.Yes:
            return
    except Exception:
        pass

    # Generate a new strong password; fall back to a random string on failure
    new_pw: str | None = None
    if callable(generate_strong_password):
        try:
            new_pw = generate_strong_password(length=20)
        except Exception:
            new_pw = None
    if not new_pw:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,./?"
        new_pw = "".join(secrets.choice(alphabet) for _ in range(24))

    # Update the entry and persist with history (max 5 previous passwords)
    entry["password"] = new_pw
    ok = _persist_entry_with_history(
        w,
        w.currentUsername.text(),
        w.userKey,
        idx,
        entry,
        max_hist=5,
    )
    try:
        if ok:
            QMessageBox.information(
                w,
                w.tr("Password Updated"),
                w.tr(
                    "New password generated and saved to the vault.\n"
                    "Remember to change it on the actual site/app."
                ),
            )
        else:
            QMessageBox.critical(
                w,
                w.tr("Update Failed"),
                w.tr("Could not save the updated entry."),
            )
    except Exception:
        pass


def _watchtower_fix_entry(w, entry_id: str) -> None:
    """
    Handle a Watchtower 'Fix' action.

    If `entry_id` equals the special ``"__GLOBAL_2FA__"`` token then the user
    is directed to enable two‑factor authentication in the settings.  For
    regular entries the function attempts to switch to the correct category,
    locate the corresponding row in the vault table and open the entry
    editor.  Should the entry be missing or the editor fail to open, the
    user is notified accordingly.
    """
    # Special-case: prompt to enable 2FA and switch to the Settings/Security tab
    if str(entry_id) == "__GLOBAL_2FA__":
        try:
            tabs = getattr(w, "mainTabs", None)
            if tabs is not None:
                target_idx = -1
                for i in range(tabs.count()):
                    txt = (tabs.tabText(i) or "").strip().lower()
                    if "setting" in txt or "security" in txt:
                        target_idx = i
                        break
                if target_idx >= 0:
                    tabs.setCurrentIndex(target_idx)
            QMessageBox.information(
                w,
                w.tr("Enable Two-Factor Authentication"),
                w.tr(
                    "To fix this warning, enable 2FA (TOTP) for your account in the "
                    "Settings / Security section.\n\n"
                    "Once enabled, run Watchtower again and this warning will disappear."
                ),
            )
        except Exception:
            pass
        return

    # Locate the entry index using fingerprint or ID
    try:
        idx = _find_entry_index_by_id(w, entry_id)
    except Exception:
        idx = -1
    if idx < 0:
        try:
            QMessageBox.warning(
                w,
                w.tr("Watchtower"),
                w.tr("Couldn't locate that entry in the vault."),
            )
        except Exception:
            pass
        return

    # Load entries to retrieve the category for switching
    try:
        try:
            all_entries = load_vault(w.currentUsername.text(), w.userKey) or []
        except TypeError:
            all_entries = load_vault(w.currentUsername.text()) or []
    except Exception:
        all_entries = []
    # If the direct-id lookup failed, try matching by stable content id.
    if idx < 0 and all_entries:
        try:
            for j, e in enumerate(all_entries):
                try:
                    if stable_id_for_entry(e) == str(entry_id):
                        idx = j
                        break
                except Exception:
                    continue
        except Exception:
            pass
    if not (0 <= idx < len(all_entries)):
        try:
            QMessageBox.warning(
                w,
                w.tr("Watchtower"),
                w.tr("The vault entry for this issue could not be found."),
            )
        except Exception:
            pass
        return

    entry = dict(all_entries[idx])
    category = (entry.get("category") or "Passwords").strip()

    # Attempt to switch the UI to the correct category (if available)
    cat_sel = getattr(w, "categorySelector_2", None)
    if cat_sel is not None:
        try:
            target_index = -1
            want = category.lower()
            for i in range(cat_sel.count()):
                try:
                    txt = cat_sel.itemText(i)
                except Exception:
                    txt = ""
                if (txt or "").strip().lower() == want:
                    target_index = i
                    break
            if target_index >= 0 and cat_sel.currentIndex() != target_index:
                cat_sel.setCurrentIndex(target_index)
                # Force table reload in case the signal isn't wired
                if hasattr(w, "load_vault_table"):
                    w.load_vault_table()
        except Exception:
            pass
    else:
        try:
            if hasattr(w, "load_vault_table"):
                w.load_vault_table()
        except Exception:
            pass

    # Map the global index back to a row in the visible table
    tbl = getattr(w, "vaultTable", None)
    idx_map = getattr(w, "current_entries_indices", None)
    row = -1
    if isinstance(idx_map, list):
        try:
            for r, gi in enumerate(idx_map):
                if gi == idx:
                    row = r
                    break
        except Exception:
            row = -1

    # Open the entry in the editor if we found a row
    if tbl is not None and 0 <= row < getattr(tbl, "rowCount", lambda: 0)():
        try:
            tbl.selectRow(row)
        except Exception:
            pass
        try:
            w.edit_selected_vault_entry(row, 0)
            return
        except Exception:
            pass

    # Final fallback: could not open automatically
    try:
        QMessageBox.information(
            w,
            w.tr("Watchtower"),
            w.tr(
                "Could not open this entry automatically.\n"
                "Use the search box or filters to locate it manually."
            ),
        )
    except Exception:
        pass

