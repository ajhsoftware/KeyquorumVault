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
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."""

"""
This module implements all backup and restore functionality for
Keyquorum Vault.  It was extracted from the original ``main.py`` to
isolate the business logic related to exporting and importing vaults
and associated user data.  Each function here accepts an instance
of the main window (``w``) as its first argument.  The logic
originally lived as methods on the main application class; by
passing the window instance explicitly these helpers can live in
their own module without depending on global state.

The high‑level flows provided are:

``export_vault_with_password``
    Export the current user's encrypted vault wrapped in a password‑
    protected envelope (.kqbk).  Prompts for an export password and
    location, then writes the backup and updates the audit log.

``import_vault_with_password``
    Restore a password‑protected ``.kqbk`` vault backup into the
    current Keyquorum account.  Prompts for the backup file and
    decryption password and replaces the existing vault contents.

``backup_software_folder`` and ``restore_software_folder``
    Convenience helpers to backup and restore the ``app/software``
    folder as a separate ZIP file.  These are not part of the full
    backup flow but are exposed to users via the UI.

``export_vault``
    Create a full backup of the user's vault and configuration as a
    ``.zip.enc`` file encrypted with the account password.  This is
    the recommended way to take a complete snapshot of your data.

``import_vault`` and ``import_vault_custom``
    Restore a full backup.  The former restores everything as it was
    saved; the latter allows the user to choose which components to
    restore and how to handle the per‑user database.

``_ensure_user_dirs``
    Helper to make sure all per‑user directories exist before
    performing an import.  This mirrors the helper that used to
    exist on the main window class.

``RestoreOptionsDialog``
    A standalone dialog used by ``import_vault_custom`` to let the
    user choose which components to restore and whether to replace or
    merge the per‑user database.  This class was copied verbatim
    from the original ``main.py`` to avoid circular imports.

The functions here are designed to be imported and called from
``main.py``.  They do not depend on any GUI wiring and focus solely
on the business logic required for backups.  Translating these into
a separate module avoids circular dependencies and makes testing
easier.
"""

from __future__ import annotations

import os
import re as _re
import datetime as dt
from pathlib import Path
from zipfile import ZipFile
from shutil import rmtree
from typing import Optional, Set, Tuple
try:
    from app.qt_imports import *  # noqa: F401,F403
except Exception:
    pass

from auth.logout.logout_flow import reset_logout_timer
from auth.login.login_handler import validate_login
from vault_store.vault_store import (
    export_vault_with_password as _export_pw_fn,
    import_vault_with_password as _import_pw_fn,
    export_full_backup,
    import_full_backup,)
from security.baseline_signer import update_baseline
from security.audit_v2 import log_event_encrypted
import app.kq_logging as kql


class RestoreOptionsDialog(QDialog):
    """Dialog allowing the user to choose which components to restore.

    This class mirrors the implementation that was originally located
    in ``main.py``.  It is intentionally self‑contained so it can be
    imported without pulling in the entire main module.  When
    accepted, call :meth:`result_values` to retrieve the chosen
    components and user database handling mode.
    """

    def __init__(
        self,
        parent: Optional[object] = None,
        *,
        default_components: Optional[Set[str]] = None,
        default_userdb_mode: str = "replace",
    ) -> None:
        super().__init__(parent)
        # Use translation context identical to main window
        self.setWindowTitle(self.tr("Restore Options"))

        # Components checkboxes
        self.chkVault = QCheckBox(self.tr("Vault file"))
        self.chkWrapped = QCheckBox(self.tr("Wrapped key"))
        self.chkSalt = QCheckBox(self.tr("Salt"))
        self.chkShare = QCheckBox(self.tr("Share keys"))
        self.chkIdentity = QCheckBox(self.tr("Identity blob"))
        self.chkUserDB = QCheckBox(self.tr("User record (user_db)"))

        # Default: all on
        for cb in (
            self.chkVault,
            self.chkWrapped,
            self.chkSalt,
            self.chkShare,
            self.chkIdentity,
            self.chkUserDB,
        ):
            cb.setChecked(True)

        # Apply provided defaults
        if isinstance(default_components, set):
            all_keys = {
                "vault": self.chkVault,
                "wrapped": self.chkWrapped,
                "salt": self.chkSalt,
                "sharekeys": self.chkShare,
                "identity": self.chkIdentity,
                "userdb": self.chkUserDB,
            }
            for cb in all_keys.values():
                cb.setChecked(False)
            for key in default_components:
                if key in all_keys:
                    all_keys[key].setChecked(True)

        # Components box
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
        self.rbMerge = QRadioButton(self.tr("Merge into existing record"))
        if str(default_userdb_mode).lower() == "merge":
            self.rbMerge.setChecked(True)
        else:
            self.rbReplace.setChecked(True)

        mode_box = QGroupBox("User record mode")
        v_mode = QVBoxLayout(mode_box)
        v_mode.addWidget(self.rbReplace)
        v_mode.addWidget(self.rbMerge)

        # Hint
        hint = QLabel(
            self.tr(
                "Tip: to restore only your user record, untick everything except “User record (user_db)”."))

        hint.setWordWrap(True)

        # Buttons
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        # Layout
        root = QVBoxLayout(self)
        root.addWidget(hint)
        root.addWidget(comps_box)
        root.addWidget(mode_box)
        root.addWidget(btns)

    def result_values(self) -> Tuple[Set[str], str]:
        """Return the selected components and user_db mode."""
        components: Set[str] = set()
        if self.chkVault.isChecked():
            components.add("vault")
        if self.chkWrapped.isChecked():
            components.add("wrapped")
        if self.chkSalt.isChecked():
            components.add("salt")
        if self.chkShare.isChecked():
            components.add("sharekeys")
        if self.chkIdentity.isChecked():
            components.add("identity")
        if self.chkUserDB.isChecked():
            components.add("userdb")
        mode = "merge" if self.rbMerge.isChecked() else "replace"
        return components, mode


def export_vault_with_password(w, *, skip_ask: bool = True) -> None:
    """Export the current user's encrypted vault to a .kqbk file.

    This function prompts for an export password and destination and
    writes the backup.  It performs the same logic as the original
    ``MainWindow.export_vault_with_password`` method but operates on a
    window instance passed in explicitly.

    Parameters
    ----------
    w: The main window instance to operate on.
    skip_ask: If ``True``, bypasses the confirmation prompt for
        sensitive actions.  The UI uses this when triggered from a
        button that already verified the action.
    """
    # Ensure vault is unlocked
    if not w._require_unlocked():
        return
    w.set_status_txt(w.tr("Exporting Vault"))
    reset_logout_timer(w)

    username = (w.currentUsername.text() or "").strip()
    if not username:
        w.safe_messagebox_warning(w, "Export Vault", "Please log in first.")
        return

    if not skip_ask:
        if not w.verify_sensitive_action(username, title="Export Vault/Auth"):
            return

    # Prompt for an export password
    password, ok = QInputDialog.getText(
        w,
        w.tr("Set Export Password"),
        w.tr(
            "Choose a password to encrypt your exported vault. Keep it safe — it’s required to restore your data."
        ),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not password:
        return

    # Choose destination
    suggested = f"{username}_vault_backup.kqbk"
    out_path, _ = QFileDialog.getSaveFileName(
        w,
        w.tr("Save Encrypted Vault"),
        suggested,
        w.tr("Encrypted Vault") + "(*.kqbk)",
    )
    if not out_path:
        return

    # Perform the export
    tmp_path = _export_pw_fn(username, password)
    if not tmp_path:
        w.safe_messagebox_warning(
            w, w.tr("Export Failed"), w.tr("Something went wrong during export."),
        )
        return
    try:
        # Copy to chosen location
        import shutil

        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        shutil.copy2(tmp_path, out_path)
    except Exception as e:
        msg = w.tr("Could not save to chosen location:\n{err}").format(err=e)
        QMessageBox.critical(w, w.tr("Export Failed"), msg)
        return

    # Log success
    try:
        msg = w.tr("{ok} Vault exported → {out_p}").format(ok=kql.i("ok"), out_p=out_path)
        log_event_encrypted(username, w.tr("vault"), msg)
    except Exception:
        pass

    # Update backup timestamp
    try:
        w._update_backup_timestamp(username, "last_vault_backup")
    except Exception:
        pass

    # Notify user
    msg = w.tr(
        "Vault exported to:\n{out_p}\n\nStore it securely (e.g., offline USB)"
    ).format(out_p=out_path)
    QMessageBox.information(w, w.tr("Export Complete"), msg)


def import_vault_with_password(w) -> None:
    """Import a password‑protected ``.kqbk`` vault backup into the current account."""
    w.set_status_txt(w.tr("Importing vault backup"))
    reset_logout_timer(w)

    username = (w.currentUsername.text() or "").strip()
    if not username:
        w.safe_messagebox_warning(
            w,
            "Import Vault Backup",
            "Please sign in to your Keyquorum account before importing a vault backup.",
        )
        return

    # Confirm destructive action
    warn = QMessageBox.warning(
        w,
        "Replace vault with backup?",
        (
            "You are about to restore an encrypted vault backup into this Keyquorum account.\n\n"
            "• All existing items in this account will be replaced by the items from the backup.\n"
            "• If you want to keep your current items as well, export them to CSV first, "
            "then run this import, and finally import the CSV to add them back.\n\n"
            "Note: This backup is still linked to the Keyquorum account it was created from. "
            "It can only be restored into that same account.\n\n"
            "Do you want to continue?"
        ),
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No,
    )
    if warn != QMessageBox.Yes:
        return

    # Re‑authenticate user for sensitive action
    if not w.verify_sensitive_action(username, title="Confirm Import"):
        return

    # Choose the backup file
    file_path, _ = QFileDialog.getOpenFileName(
        w,
        "Select Encrypted Vault Backup",
        "",
        "Encrypted Vault (*.kqbk)",
    )
    if not file_path:
        return

    # Ask for the export password
    password, ok = QInputDialog.getText(
        w,
        w.tr("Vault Backup Password"),
        w.tr("Enter the password you used when you created this vault backup:"),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not password:
        return

    # Perform the import
    w.set_status_txt(w.tr("Importing vault backup…"))
    ok_import = bool(_import_pw_fn(username, password, file_path))
    reset_logout_timer(w)

    if ok_import:
        # Log success
        try:
            update_baseline(username=username, verify_after=False, who=w.tr("Imported Encrypted Vault (.kqbk)"))
        except Exception:
            pass
        QMessageBox.information(
            w,
            w.tr("Import complete"),
            w.tr(
                "Vault backup imported successfully.\nIf you don’t see the updated items or categories straight away, \nplease sign out and sign back in."
            ),
        )
        try:
            from features.auth_store.auth_ops import _auth_reload_table
            w.refresh_category_selector()
            w.refresh_category_dependent_ui()
            w.load_vault_table()
            _auth_reload_table(w)
            w.set_status_txt(w.tr("Vault backup imported"))
        except Exception:
            pass
    else:
        # Explain failure
        w.set_status_txt(w.tr("Vault import failed"))
        w.safe_messagebox_warning(
            w,
            w.tr("Vault import failed"),
            (
                w.tr(
                    "The encrypted vault backup could not be imported.\n\n"
                    "This can happen if:\n"
                    "• The vault backup password is incorrect.\n"
                    "• The backup file is damaged or incomplete.\n"
                    "• The backup was created from a different Keyquorum account and the "
                    "account identity does not match this one.\n\n"
                    "What you can try:\n"
                    "1) Double‑check the backup password.\n"
                    "2) If you created a FULL backup (ZIP) around the same time as this vault "
                    "backup, restore the full backup first and then try this vault‑only "
                    "backup again.\n"
                    "3) Make sure you are signed in to the same Keyquorum account that originally "
                    "created this vault backup."
                )
            ),
        )


def backup_software_folder(w) -> None:
    """Backup the ``app/software`` folder to a timestamped ZIP archive."""
    reset_logout_timer(w)
    source_dir = os.path.join("app", "software")
    if not os.path.exists(source_dir):
        QMessageBox.information(
            w,
            w.tr("Software Backup"),
            w.tr("No software folder found to back up."),
        )
        return
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join("software_backups")
    os.makedirs(backup_dir, exist_ok=True)
    zip_path = os.path.join(backup_dir, f"software_backup_{timestamp}.zip")

    with ZipFile(zip_path, "w") as zipf:
        for root, _, files in os.walk(source_dir):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, start=source_dir)
                zipf.write(full_path, arcname=arcname)
    msg = w.tr("{ok} Software folder backedup").format(ok=kql.i("ok"))
    log_event_encrypted(w.currentUsername.text(), w.tr("soft backed up"), msg)
    msg = w.tr("{ok} Software folder backed up to:\n{zip_p}").format(
        ok=kql.i("ok"), zip_p=zip_path
    )
    QMessageBox.information(w, w.tr("Software Backup"), msg)


def restore_software_folder(w) -> None:
    """Restore the ``app/software`` folder from a ZIP archive."""
    reset_logout_timer(w)
    zip_path, _ = QFileDialog.getOpenFileName(
        w,
        w.tr("Select Software Backup"),
        "",
        "ZIP Files (*.zip)",
    )
    if not zip_path:
        return
    restore_dir = os.path.join("app", "software")
    os.makedirs(restore_dir, exist_ok=True)

    # Confirm overwrite
    confirm = QMessageBox.question(
        w,
        w.tr("Restore Software Folder"),
        w.tr("This will overwrite existing files. Continue?"),
    )
    if confirm != QMessageBox.StandardButton.Yes:
        return
    reset_logout_timer(w)
    rmtree(restore_dir)
    os.makedirs(restore_dir, exist_ok=True)

    with ZipFile(zip_path, "r") as zipf:
        zipf.extractall(restore_dir)
    update_baseline(
        username=w.currentUsername.text(), verify_after=False, who=w.tr("Soft Restored")
    )
    QMessageBox.information(
        w,
        w.tr("Software Restore"),
        w.tr("✅ Software folder restored successfully."),
    )


def export_vault(w) -> None:
    """Export a full backup (vault + salt + user_db + wrapped key) encrypted with the account password."""
    w.set_status_txt(w.tr("Exporting Vault"))
    reset_logout_timer(w)
    username = w.currentUsername.text().strip()
    if not username:
        w.safe_messagebox_warning(w, "Export", "Please log in before exporting.")
        return

    # Ask for account password to encrypt the backup
    pw, ok = QInputDialog.getText(
        w,
        w.tr("Confirm Password"),
        w.tr("Enter your account password:"),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not pw:
        return

    if not validate_login(username, pw):
        # Wrong password
        msg = "❌" + w.tr(" Wrong Password")
        QMessageBox.information(w, w.tr("Full Backup"), msg)
        msg = w.tr("{ok} Wrong Password").format(ok=kql.i("warn"))
        log_event_encrypted(w.currentUsername.text(), w.tr("Full Backup"), msg)
        return
    msg = w.tr("{ok} Password OK").format(ok=kql.i("ok"))
    log_event_encrypted(w.currentUsername.text(), w.tr("Full Backup"), msg)

    # Choose destination directory
    out_dir = QFileDialog.getExistingDirectory(
        w,
        w.tr("Choose folder for backup"),
    )
    if not out_dir:
        return

    reset_logout_timer(w)
    try:
        # export_full_backup returns the path to the created file
        written = export_full_backup(username, pw, out_dir)
        msg = w.tr("{ok} Full Backup OK").format(ok=kql.i("ok"))
        log_event_encrypted(w.currentUsername.text(), w.tr("Full Backup"), msg)
        # Note full backup completion
        try:
            w.full_backup_reminder.note_full_backup_done()
        except Exception:
            pass
        # Record timestamp for security center
        try:
            w._update_backup_timestamp(username, "last_full_backup")
        except Exception:
            pass
        msg = w.tr("{ok} Full backup saved:\n{writ}").format(
            ok=kql.i("ok"), writ=written
        )
        QMessageBox.information(w, w.tr("Export"), msg)
    except Exception as e:
        msg = w.tr("{ok} Export failed:\n{err}").format(ok=kql.i("err"), err=e)
        QMessageBox.critical(w, w.tr("Export Failed"), msg)


def _ensure_user_dirs(w, username: str) -> None:
    """Ensure all per‑user directories exist so imports can write files safely."""
    from app.paths import (
        ensure_dirs,
        vault_file,
        salt_file,
        vault_wrapped_file,
        shared_key_file,
        identities_file,
        user_db_file,
    )
    try:
        ensure_dirs()
    except Exception:
        pass
    targets = [
        Path(vault_file(username, ensure_parent=True)),
        Path(vault_wrapped_file(username, ensure_parent=True, name_only=False)),
        Path(salt_file(username, ensure_parent=True, name_only=False)),
        Path(shared_key_file(username, ensure_parent=True, name_only=False)),
        Path(identities_file(username, ensure_parent=True)),
        Path(user_db_file(username, ensure_parent=True)),
    ]
    for p in targets:
        p.parent.mkdir(parents=True, exist_ok=True)


def import_vault(w) -> None:
    """Import a full backup created by ``export_full_backup`` (everything is restored)."""
    reset_logout_timer(w)
    # Pick backup file produced by export_full_backup
    in_path_str, _ = QFileDialog.getOpenFileName(
        w,
        w.tr("Select Full Backup"),
        "",
        "KQV Full Backup (*.zip *.zip.enc)",
    )
    if not in_path_str:
        return
    in_path = Path(in_path_str)
    base = in_path.name
    # Guess username from filename
    m = _re.match(r"^(?P<user>.+?)_full_backup_\d{8}-\d{6}\.zip(\.enc)?$", base)
    guessed_user = m.group("user") if m else None
    # Determine username
    username = (
        w.currentUsername.text().strip()
        if hasattr(w, "currentUsername") and w.currentUsername.text().strip()
        else (guessed_user or "")
    )
    if not username:
        username, ok = QInputDialog.getText(
            w,
            w.tr("Restore Username"),
            w.tr("Enter the account username to restore into:"),
        )
        if not ok or not username.strip():
            return
        username = username.strip()
    # Determine encryption
    is_encrypted = base.endswith(".zip.enc")
    pw = ""
    if is_encrypted:
        pw, ok = QInputDialog.getText(
            w,
            w.tr("Confirm Password"),
            w.tr("Enter your account password (used to decrypt the backup):"),
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pw:
            return
    try:
        _ensure_user_dirs(w, username)
        reset_logout_timer(w)
        if is_encrypted:
            import_full_backup(username, pw, str(in_path))
        else:
            import_full_backup(username, str(in_path))
        msg = w.tr("{ok} Full Backup OK").format(ok=kql.i("ok"))
        log_event_encrypted(w.currentUsername.text(), w.tr(""), msg)
        update_baseline(username=w.currentUsername.text(), verify_after=False, who=w.tr("Full restore OK"))
        msg = w.tr("{ok} Full restore completed\n{in_p}").format(ok=kql.i("ok"), in_p=in_path)
        QMessageBox.information(w, w.tr("Import"), msg)
        try:
            if hasattr(w, "currentUsername"):
                w.currentUsername.setText(username)
            w.load_vault_table()
        except Exception:
            pass
    except Exception as e:
        QMessageBox.critical(
            w,
            w.tr("Import Failed"),
            f"❌ Import failed:\n{e}",
        )


def import_vault_custom(w) -> None:
    """Import a full backup with user‑selected components and user_db merge/replace options."""
    w.set_status_txt(w.tr("Importing Vault"))
    reset_logout_timer(w)
    # Choose backup file
    in_path_str, _ = QFileDialog.getOpenFileName(
        w,
        w.tr("Select Full Backup"),
        "",
        "KQV Full Backup (*.zip *.zip.enc)",
    )
    if not in_path_str:
        return
    in_path = Path(in_path_str)
    base = in_path.name
    is_encrypted = base.endswith(".zip.enc")
    # Guess username
    m = _re.match(r"^(?P<user>.+?)_full_backup_\d{8}-\d{6}\.zip(\.enc)?$", base)
    guessed_user = m.group("user") if m else None
    username = (
        w.currentUsername.text().strip()
        if hasattr(w, "currentUsername") and w.currentUsername.text().strip()
        else (guessed_user or "")
    )
    if not username:
        username, ok = QInputDialog.getText(
            w,
            w.tr("Restore Username"),
            w.tr("Restore into username:"),
        )
        if not ok or not username.strip():
            return
        username = username.strip()
    # Password if needed
    pw = ""
    if is_encrypted:
        pw, ok = QInputDialog.getText(
            w,
            w.tr("Confirm Password"),
            w.tr("Enter your account password (used to decrypt the backup):"),
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pw:
            return
    # Show options dialog
    dlg = RestoreOptionsDialog(w, default_userdb_mode="replace")
    if dlg.exec() != QDialog.DialogCode.Accepted:
        return
    components, userdb_mode = dlg.result_values()
    if not components:
        QMessageBox.information(w, w.tr("Restore"), w.tr("No components selected."))
        return
    # Perform restore
    try:
        _ensure_user_dirs(w, username)
        reset_logout_timer(w)
        if is_encrypted:
            import_full_backup(
                username,
                pw,
                str(in_path),
                components=components,
                userdb_mode=userdb_mode,
            )
        else:
            import_full_backup(
                username,
                str(in_path),
                components=components,
                userdb_mode=userdb_mode,
            )
        # Baseline and refresh
        update_baseline(username=username, verify_after=False, who=w.tr("Selective restore OK"))
        msg = w.tr("{ok}Restore completed\n{in_p}").format(ok=kql.i("ok"), in_p=in_path)
        QMessageBox.information(w, w.tr("Import"), msg)
        w.logout_user()
    except Exception as e:
        msg = w.tr("{ok} Restore completed\n{err}").format(ok=kql.i("err"), err=e)
        QMessageBox.critical(w, w.tr("Import Failed"), msg)
