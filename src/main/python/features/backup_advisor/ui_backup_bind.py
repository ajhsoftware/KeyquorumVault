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
import sys as _sys
from auth.login.login_handler import validate_login
from security.secure_audit import log_event_encrypted
from vault_store.vault_store import export_full_backup, import_full_backup
import datetime as dt 
from vault_store.vault_store import export_vault_csv, save_vault, _dec_backup_bytes, load_vault
from zipfile import ZipFile
import re as _re
from security.baseline_signer import update_baseline
from bridge.bridge_ops import _kq_strip_ws
from auth.login.login_handler import get_user_setting, set_user_setting
from ui.restore_options_dialog import RestoreOptionsDialog
from shutil import rmtree
from app.paths import vault_file, shared_key_file, salt_file, identities_file, vault_wrapped_file, user_db_file



_MAIN = (
    _sys.modules.get("__main__")
    or _sys.modules.get("main")
    or _sys.modules.get("app.app_window")
    or _sys.modules.get("app_window")
)

if _MAIN is not None:
    globals().update(_MAIN.__dict__)

from app.qt_imports import *


# --- import Logging
import logging
import app.kq_logging as kql
log = logging.getLogger("keyquorum")

# --- helpers ---
from features.backup_advisor.backup_advisor import BackupAdvisor


def _backup_user_name(w) -> str:
    try:
        return (w._active_username() or "").strip().lower()
    except Exception:
        return ""


def _backup_user_prefix(w) -> str:
    return f"users/{_backup_user_name(w) or '_global'}/"


# ==============================
# --- CSV Import ---
# ==============================

# Fast path for CSV import: ensures `category` exists in the active user's category_schema (user_db.json).
def _ensure_category_exists_from_import(self, category: str) -> bool:
    """Fast path for CSV import.

    Ensures `category` exists in the active user's category_schema (user_db.json).

    Returns:
      True  -> category already existed (or treated as existed)
      False -> category was newly created (and persisted)
    """
    try:
        name = (category or "").strip()
        if not name:
            return True

        # Active user (canonical id)
        canonical = ""
        try:
            if hasattr(self, "currentUsername") and self.currentUsername:
                canonical = self._active_username()
        except Exception:
            canonical = ""
        if not canonical:
            return True

        lname = name.lower()

        # ---- In-memory cache to avoid re-reading user_db.json for every row ----
        cache_key = "_import_category_seen"
        seen = getattr(self, cache_key, None)
        if not isinstance(seen, set):
            # First call in this import session: load schema once and seed cache
            schema = get_user_setting(canonical, "category_schema")
            if not isinstance(schema, dict):
                schema = {}
            cats = list(schema.get("categories") or [])
            seen = set()
            for c in cats:
                if isinstance(c, dict):
                    seen.add((c.get("name") or "").strip().lower())
            setattr(self, cache_key, seen)

        # If we already know it exists, return instantly.
        # IMPORTANT: do NOT refresh UI here (10k calls would repaint 10k times)
        if lname in seen:
            return True

        # Build default fields for a new category
        try:
            fields = self._default_fields_for_category(name)
        except Exception:
            fields = None

        if not fields:
            fields = [
                {"label": "Title"},
                {"label": "Username"},
                {"label": "Password"},
                {"label": "URL"},
                {"label": "Notes"},
            ]

        # Persist new category (rare compared to CSV rows)
        schema = get_user_setting(canonical, "category_schema")
        if not isinstance(schema, dict):
            schema = {}
        cats = list(schema.get("categories") or [])

        # Double-check existence against persisted data (case-insensitive)
        for c in cats:
            if isinstance(c, dict) and (c.get("name") or "").strip().lower() == lname:
                seen.add(lname)
                return True

        cats.append({"name": name, "fields": fields})
        schema["categories"] = cats
        set_user_setting(canonical, "category_schema", schema)

        # Update cache
        seen.add(lname)

        # Refresh category UI ONLY if we're not in a bulk import.
        # Bulk imports should refresh once at the end.
        if not bool(getattr(self, "_bulk_import_in_progress", False)):
            try:
                if hasattr(self, "refresh_category_dependent_ui"):
                    self.refresh_category_dependent_ui()
                elif hasattr(self, "refresh_category_selector"):
                    self.refresh_category_selector()
            except Exception:
                pass

        return False

    except Exception as e:
        try:
            log.error(f"[DEBUG] _ensure_category_exists_from_import failed: {e}")
        except Exception:
            pass
        return True

# When importing from a browser CSV export, we want to be flexible in mapping common column headers to our internal schema. 
# This function takes a raw CSV row (as a dict) and normalizes keys like "name" -> "Title", "url" -> "Website"/"URL", "user" -> "Username", etc., 
# while also trimming whitespace and ensuring we have consistent keys for downstream processing.
def _normalize_fields_from_browser(self, row: dict) -> dict:
    """Map common browser CSV headers to Title/URL/Username/Password/Notes."""
    e = { (k or "").strip(): (v or "").strip() for k, v in row.items() if k is not None }
    alias = {
        # Title
        "name": "Title", "title": "Title", "label": "Title",
        # Website/URL synonyms – map to Website. We'll replicate later to URL.
        "url": "Website", "website": "Website", "site": "Website", "origin": "Website",
        # Username synonyms
        "username": "Username", "user": "Username", "login": "Username", "user name": "Username", "user-name": "Username",
        # Password synonyms
        "password": "Password", "pass": "Password", "pwd": "Password",
        # Notes synonyms
        "note": "Notes", "notes": "Notes", "comment": "Notes",
        # Email synonyms
        "email": "Email", "e-mail": "Email", "mail": "Email",
        # Phone
        "phone number": "Phone Number", "phone": "Phone Number", "mobile": "Phone Number",
        # Backup code
        "backup code": "Backup Code", "backup codes": "Backup Code", "recovery code": "Backup Code",
        # 2FA enabled
        "2fa": "2FA Enabled", "2fa enabled": "2FA Enabled", "two factor": "2FA Enabled",
    }
    for k in list(e.keys()):
        lk = k.lower()
        dst = alias.get(lk)
        if dst:
            if dst not in e:
                e[dst] = e.get(k, "")
    # Replicate URL/Website synonyms to both keys
    url_val = e.get("URL") or e.get("Website")
    if url_val:
        if "URL" not in e:
            e["URL"] = url_val
        if "Website" not in e:
            e["Website"] = url_val
    # Replicate Username synonyms (Username vs UserName)
    uname_val = e.get("Username") or e.get("UserName")
    if uname_val:
        if "Username" not in e:
            e["Username"] = uname_val
        if "UserName" not in e:
            e["UserName"] = uname_val
    # Ensure Email exists if provided under synonyms
    email_val = e.get("Email") or e.get("email")
    if email_val:
        if "Email" not in e:
            e["Email"] = email_val
    # Ensure Phone Number exists
    phone_val = e.get("Phone Number") or e.get("phone")
    if phone_val:
        if "Phone Number" not in e:
            e["Phone Number"] = phone_val
    # Ensure Notes exists
    notes_val = e.get("Notes") or e.get("notes")
    if notes_val:
        if "Notes" not in e:
            e["Notes"] = notes_val
    return e

# should we find duplicates, show this dialog to let the user choose how to resolve each one (update existing, keep both, skip).
class DedupeResolverDialog(QDialog):
    """
    Shows all duplicate collisions in one table.
    Each row: Category, Title/Name, Username, URL, Existing (summary), Incoming (summary), Action.
    Actions: Skip / Update existing / Keep both.
    """
    def __init__(self, parent, collisions: list[tuple[tuple, dict, dict]]):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Resolve Duplicate Entries"))
        self.resize(980, 520)
        self._collisions = collisions
        self.result_actions: list[str] = []  # "skip" | "update" | "keep"
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)

        help_lbl = QLabel(self.tr("Duplicates were found. Choose how to resolve each row:"))
        help_lbl.setWordWrap(True)
        layout.addWidget(help_lbl)

        self.table = QTableWidget(self)
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Category", "Title/Name", "Username", "URL",
            "Existing (summary)", "Incoming (summary)", "Action"
        ])
        self.table.setRowCount(len(self._collisions))
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        def get(o: dict, *keys):
            for k in keys:
                v = o.get(k)
                if v:
                    return v
            return ""

        def summarize(d: dict) -> str:
            keys = ["Title","Name","Username","URL","Email","Notes","Date","created_at"]
            parts = []
            for k in keys:
                v = d.get(k)
                if v:
                    v = v if len(v) <= 120 else (v[:117] + "…")
                    parts.append(f"{k}: {v}")
            extras = [k for k in d.keys() if k not in keys and k not in ("category",)]
            for k in sorted(extras)[:5]:
                v = d.get(k)
                if v:
                    v = v if len(v) <= 120 else (v[:117] + "…")
                    parts.append(f"{k}: {v}")
            return "\n".join(parts) if parts else "(empty)"

        for r, (key, existing, incoming) in enumerate(self._collisions):
            cat = (existing.get("category") or incoming.get("category") or "")
            title = get(existing, "Title", "Name", "label") or get(incoming, "Title", "Name", "label")
            user  = get(existing, "Username", "User") or get(incoming, "Username", "User")
            url   = get(existing, "URL", "Site") or get(incoming, "URL", "Site")

            self.table.setItem(r, 0, QTableWidgetItem(cat))
            self.table.setItem(r, 1, QTableWidgetItem(title))
            self.table.setItem(r, 2, QTableWidgetItem(user))
            self.table.setItem(r, 3, QTableWidgetItem(url))

            it_exist = QTableWidgetItem(summarize(existing))
            it_exist.setFlags(it_exist.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(r, 4, it_exist)

            it_in = QTableWidgetItem(summarize(incoming))
            it_in.setFlags(it_in.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(r, 5, it_in)

            combo = QComboBox(self.table)
            combo.addItems([self.tr("Update existing"), self.tr("Keep both"), self.tr("Skip")])
            combo.setCurrentIndex(0)
            self.table.setCellWidget(r, 6, combo)

        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        # Bulk action buttons
        btn_row = QHBoxLayout()
        btn_set_update = QPushButton(self.tr("All → Update"))
        btn_set_keep   = QPushButton(self.tr("All → Keep both"))
        btn_set_skip   = QPushButton(self.tr("All → Skip"))
        btn_row.addWidget(btn_set_update)
        btn_row.addWidget(btn_set_keep)
        btn_row.addWidget(btn_set_skip)
        btn_row.addStretch(1)
        layout.addLayout(btn_row)

        def set_all(idx: int):
            for r in range(self.table.rowCount()):
                w = self.table.cellWidget(r, 6)
                if isinstance(w, QComboBox):
                    w.setCurrentIndex(idx)

        btn_set_update.clicked.connect(lambda: set_all(0))
        btn_set_keep.clicked.connect(lambda: set_all(1))
        btn_set_skip.clicked.connect(lambda: set_all(2))

        # OK/Cancel
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        btn_ok = QPushButton(self.tr("Apply"))
        btn_cancel = QPushButton(self.tr("Cancel"))
        bottom.addWidget(btn_ok)
        bottom.addWidget(btn_cancel)
        layout.addLayout(bottom)

        btn_ok.clicked.connect(self._accept)
        btn_cancel.clicked.connect(self.reject)

    def _accept(self):
        mapping = {0: "update", 1: "keep", 2: "skip"}
        self.result_actions = []
        for r in range(self.table.rowCount()):
            w = self.table.cellWidget(r, 6)
            idx = w.currentIndex() if isinstance(w, QComboBox) else 0
            self.result_actions.append(mapping.get(idx, "update"))
        self.accept()


# ==============================
# --- Backup Advisor
# ==============================
def init_backup_avisor(w):
    qs = QSettings("AJH Software", "Keyquorum Vault")
    username = _backup_user_name(w)
    user_prefix = _backup_user_prefix(w)

    # --- ensure advisor exists and is switched to active user ---
    if not getattr(w, "backupAdvisor", None):
        w.backupAdvisor = BackupAdvisor(w, do_backup_callable=w.export_vault_with_password, username=username)
        w._backup_advisor_user = username
    else:
        old_user = getattr(w, "_backup_advisor_user", "")
        if old_user != username:
            try:
                w.backupAdvisor.switch_user(username)
            except Exception:
                w.backupAdvisor = BackupAdvisor(w, do_backup_callable=w.export_vault_with_password, username=username)
            w._backup_advisor_user = username

    # --- read prefs (with sane defaults) ---
    mode = str(qs.value(user_prefix + "backup/remindMode", "both")).lower()
    if mode not in ("off", "changes", "logout", "both"):
        mode = "both"
    w._backup_remind_mode = mode

    try:
        thr = int(qs.value(user_prefix + "backup/changesThreshold", 5) or 5)
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

    # refresh values first
    idx_map = {"off":0, "changes":1, "logout":2, "both":3}
    if mode_combo.count() == 0:
        mode_combo.addItems(["Off", "After N changes", "On logout", "After N + logout"])
    try:
        blocker = QSignalBlocker(mode_combo)
        mode_combo.setCurrentIndex(idx_map.get(mode, 3))
    except Exception:
        mode_combo.setCurrentIndex(idx_map.get(mode, 3))
    try:
        blocker2 = QSignalBlocker(thr_spin)
        thr_spin.setRange(1, 999)
        thr_spin.setValue(int(thr))
    except Exception:
        thr_spin.setRange(1, 999)
        thr_spin.setValue(int(thr))
    thr_spin.setEnabled(mode_combo.currentIndex() in (1, 3))

    # only wire once
    if getattr(w, "_wired_backup_ui", False):
        return

    # --- handlers (save immediately on change) ---
    def on_mode_changed(ix: int):
        rev = {0:"off", 1:"changes", 2:"logout", 3:"both"}[ix]
        w._backup_remind_mode = rev
        qs.setValue(_backup_user_prefix(w) + "backup/remindMode", rev)
        thr_spin.setEnabled(ix in (1, 3))

    def on_thr_changed(v: int):
        v = max(1, int(v))
        if getattr(w, "backupAdvisor", None):
            w.backupAdvisor.threshold = v
            try:
                w.backupAdvisor.settings.setValue(w.backupAdvisor._key("backup/n_changes_threshold"), v)
            except Exception:
                pass
        qs.setValue(_backup_user_prefix(w) + "backup/changesThreshold", v)

    try:
        mode_combo.currentIndexChanged.disconnect()
    except Exception:
        pass
    try:
        thr_spin.valueChanged.disconnect()
    except Exception:
        pass

    mode_combo.currentIndexChanged.connect(on_mode_changed)
    thr_spin.valueChanged.connect(on_thr_changed)

    if reset_btn:
        try:
            reset_btn.clicked.disconnect()
        except Exception:
            pass

        def on_reset_counter():
            if QMessageBox.question(
                w, "Reset backup counter",
                "Reset the pending change counter (and clear any snooze)?"
            ) == QMessageBox.Yes:
                if getattr(w, "backupAdvisor", None):
                    w.backupAdvisor.reset_change_counter(clear_snooze=True, clear_session_suppress=False)

        reset_btn.clicked.connect(on_reset_counter)

    w._wired_backup_ui = True


def backup_advisor_reset_for_logout(w):
    try:
        w._backup_advisor_user = ""
    except Exception:
        pass
    try:
        if getattr(w, "backupAdvisor", None):
            w.backupAdvisor.session_suppressed = False
    except Exception:
        pass

# This function tries to find the most appropriate backup/export function on the main window (self) by checking a list of likely method names. 
# If it finds a callable method, it returns it. If not, it returns a stub function that shows a warning message when called, 
# informing the user that no backup function is available and they should add or enable one.
def resolve_backup_callable(self): # old remove
    """
    Try likely method names on self; return a callable or a stub that warns and returns False.
    """
    candidates = [
        "export_evault_with_password", 
        "export_vault_with_password",
        "export_vault_secure",
        "export_vault",                
        "backup_now",                   
    ]
    for name in candidates:
        fn = getattr(self, name, None)
        if callable(fn):
            return fn

    # final fallback: a stub that informs the user
    def _no_backup_stub():
        QMessageBox.warning(
            self,
            "Backup",
            "No backup function is available in this build. "
            "Please add/enable an export/backup function."
        )
        return False
    return _no_backup_stub

# ==============================
# --- Export
# ==============================

# full -> Note: this is a more basic export that creates a .zip.enc file using the existing export_full_backup function.
def export_vault(self):
    self.set_status_txt(self.tr("Exporting Vault"))
    """
    UI wrapper around auth.vault_store.export_full_backup.
    Exports a .zip.enc (encrypted with the account password) into a chosen folder.
    """
    self.reset_logout_timer()
    username = self.currentUsername.text().strip()
    if not username:
        self.safe_messagebox_warning(self, "Export", "Please log in before exporting.")
        return

    # Ask for account password to encrypt the backup
    pw, ok = QInputDialog.getText(
        self, self.tr("Confirm Password"),
        self.tr("Enter your account password:"),
        QLineEdit.EchoMode.Password
    )
    if not ok or not pw:
        return

    if not validate_login(username, pw):
        msg = "❌" + self.tr(" Wrong Password")
        QMessageBox.information(self, self.tr("Full Backup"), msg)
        msg = self.tr("{ok} Wrong Password").format(ok=kql.i('warn'))
        log_event_encrypted(self.currentUsername.text(), self.tr("Full Backup"), msg)
        return
    msg = self.tr("{ok} Password OK").format(ok=kql.i('ok'))
    log_event_encrypted(self.currentUsername.text(), self.tr("Full Backup"), msg)

    # Let the user choose a destination folder (export function expects a directory)
    out_dir = QFileDialog.getExistingDirectory(self, self.tr("Choose folder for backup"))
    if not out_dir:
        return

    self.reset_logout_timer()
    try:
        # NOTE: export_full_backup(username, [password], out_dir)
        written = export_full_backup(username, pw, out_dir)  # returns str path to the created file
        msg = self.tr("{ok} Full Backup OK").format(ok=kql.i('ok'))
        log_event_encrypted(self.currentUsername.text(), self.tr("Full Backup"), msg)
        self.full_backup_reminder.note_full_backup_done()

            # Record when this full backup was done (for Security Center)
        try:
            self._update_backup_timestamp(username, "last_full_backup")
        except Exception:
            pass
        msg = self.tr("{ok} Full backup saved:\n{writ}").format(ok=kql.i('ok'),writ=written)
        QMessageBox.information(self, self.tr("Export"), msg)
    except Exception as e:
        msg = self.tr("{ok} Export failed:\n{err}").format(ok=kql.i('err'), err=e)
        QMessageBox.critical(self, self.tr("Export Failed"), msg)

# vault only -> This export creates a .kqbk file that contains only the encrypted vault (no attachments, no catalog), 
# wrapped in a password-protected envelope.
def export_vault_with_password(self, skip_ask: bool = True):
    """
    Export the current user's encrypted vault wrapped in a password-protected envelope (.kqbk).
    Lets the user choose the destination and filename.
    """

    from ui.message_ops import message_no_password, show_message_user_login
    from vault_store.vault_store import export_vault_with_password as _export_fn
    if not self._require_unlocked():
        return
    self.set_status_txt(self.tr("Exporting Vault"))
    self.reset_logout_timer()

    who = "Export Vault"

    username = self._active_username()
    if not username:
        show_message_user_login(self, who)
        return

    if not skip_ask:
        if not self.verify_sensitive_action(username, title="Export Vault/Auth"):
            return

    # Prompt for an export password
    password, ok = QInputDialog.getText(
        self, self.tr("Set Export Password"),
        self.tr("Choose a password to encrypt your exported vault. Keep it safe — it’s required to restore your data."),
        QLineEdit.EchoMode.Password
    )
    if not ok or not password:
        message_no_password(self, who)
        return

    # Choose destination
    suggested = f"{username}_vault_backup.kqbk"
    out_path, _ = QFileDialog.getSaveFileName(self, self.tr("Save Encrypted Vault"), suggested, self.tr("Encrypted Vault") + "(*.kqbk)")
    if not out_path:
        return

    # Do the export to a temp, then move to chosen path (so partial writes don't clobber)
    tmp_path = _export_fn(username, password)
    if not tmp_path:
        self.safe_messagebox_warning(self, self.tr("Export Failed"), self.tr("Something went wrong during export."))
        return

    try:
        import shutil, os
        # ensure target dir exists
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        shutil.copy2(tmp_path, out_path)
    except Exception as e:
        msg = self.tr("Could not save to chosen location:\n{err}").format(err=e)
        QMessageBox.critical(self, self.tr("Export Failed"), msg)
        return

    try:
        msg = self.tr("{ok} Vault exported → {out_p}").format(ok=kql.i('ok'), out_p=out_path)
        log_event_encrypted(username, self.tr("vault"), msg)
    except Exception:
        pass

    try:
        self._update_backup_timestamp(username, "last_vault_backup")
    except Exception:
        pass
    msg = self.tr("Vault exported to:\n{out_p}\n\nStore it securely (e.g., offline USB)").format(out_p=out_path)
    QMessageBox.information(self, self.tr("Export Complete"), msg)

# catalog -> This export creates a .kqc.enc file that contains only the user's catalog overlay (no vault, no attachments),
def export_user_catalog_encrypted(self, user_root: str) -> None:
    """
    Export this user's catalog overlay to an encrypted file
    protected with a user-chosen password.

    Called from CatalogEditorUserDialog._on_export_encrypted().
    """
    from qtpy.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox
    from vault_store.vault_store import _enc_backup_bytes

    username = self._active_username()
    if not username:
        QMessageBox.warning(
            self,
            self.tr("Catalog Export"),
            self.tr("Please log in first."),
        )
        return

    # your existing “are you sure?” check, if you have one
    try:
        if hasattr(self, "verify_sensitive_action"):
            if not self.verify_sensitive_action(username, title=self.tr("Export Catalog")):
                return
    except Exception:
        pass

    # Load ONLY the user overlay (not built-in catalog)
    try:
        from catalog_category.catalog_user import load_user_catalog_raw
        try:
            overlay = load_user_catalog_raw(user_root, self.core_session_handle) or {}
        except TypeError:
            overlay = load_user_catalog_raw(Path(user_root), self.core_session_handle) or {}
    except Exception as e:
        QMessageBox.critical(
            self,
            self.tr("Catalog Export"),
            self.tr("Could not read your catalog:\n{err}").format(err=e),
        )
        return

    if not isinstance(overlay, dict):
        overlay = {}

    # Ask for password (twice)
    pw1, ok = QInputDialog.getText(
        self,
        self.tr("Export Catalog"),
        self.tr(
            "Set a password to encrypt this catalog backup.\n\n"
            "Tip: This file may contain email suggestions and app info, "
            "so keep it safe."
        ),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not pw1.strip():
        return

    pw2, ok = QInputDialog.getText(
        self,
        self.tr("Export Catalog"),
        self.tr("Re-enter the password:"),
        QLineEdit.EchoMode.Password,
    )
    if not ok:
        return

    if pw1 != pw2:
        QMessageBox.warning(
            self,
            self.tr("Catalog Export"),
            self.tr("Passwords do not match."),
        )
        return

    password = pw1

    # Wrap overlay in a small header so we can sanity-check on import
    payload = {
        "format": "keyquorum.catalog.v1",
        "username_hint": username,
        "created_utc": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "data": overlay,
    }

    try:
        raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    except Exception as e:
        QMessageBox.critical(
            self,
            self.tr("Catalog Export"),
            self.tr("Failed to prepare catalog data:\n{err}").format(err=e),
        )
        return

    default_name = f"{username}_catalog.kqc.enc"
    out_path, _ = QFileDialog.getSaveFileName(
        self,
        self.tr("Save Catalog Backup"),
        default_name,
        self.tr("Keyquorum Catalog Backup (*.kqc.enc)"),
    )
    if not out_path:
        return

    try:
        enc = _enc_backup_bytes(password, raw)
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_bytes(enc)
    except Exception as e:
        QMessageBox.critical(
            self,
            self.tr("Catalog Export"),
            self.tr("Failed to write catalog backup:\n{err}").format(err=e),
        )
        return

    QMessageBox.information(
        self,
        self.tr("Catalog Export"),
        self.tr("Encrypted catalog backup saved successfully."),
    )

# csv -> This export creates a .csv or .csv.enc file containing the user's entries in a format that can be imported by browsers or other password managers.
def export_csv(self):
    self.set_status_txt(self.tr("CSV Export"))

    username = self.currentUsername.text()
    if not self.verify_sensitive_action(username, title="Export Full Account"):
            return

    entries = self._collect_entries_for_csv()
    if not entries:
        QMessageBox.warning(self, self.tr("Export CSV"), self.tr("No entries to export (log in and/or add entries)."))
        return

    # Scope: All vs Current category
    scope_box = QMessageBox(self)
    scope_box.setWindowTitle(self.tr("CSV Export Scope"))
    scope_box.setText(self.tr("What would you like to export?"))
    btn_all = scope_box.addButton(self.tr("All entries"), QMessageBox.ButtonRole.AcceptRole)
    btn_current = scope_box.addButton(self.tr("Current category"), QMessageBox.ButtonRole.ActionRole)
    scope_box.addButton(QMessageBox.StandardButton.Cancel)
    scope_box.exec()
    if scope_box.clickedButton() is None:
        return
    use_all = (scope_box.clickedButton() == btn_all)

    category_name = ""
    if not use_all:
        try:
            category_name = self.categorySelector_2.currentText().strip()
        except Exception:
            category_name = ""
        if category_name:
            filtered = [e for e in entries if (e.get("category") or "").strip() == category_name]
            if not filtered:
                msg = self.tr("No entries in category ") + f" '{category_name}'."
                QMessageBox.information(self, self.tr("Export CSV"), msg)
                return
            entries = filtered
        else:
            QMessageBox.information(self, self.tr("Export CSV"), self.tr("No category selected."))
            return

    # NEW: choose format
    from qtpy.QtWidgets import QInputDialog
    formats = [
        "Keyquorum (App-native)",   # category-aware
        "Google Chrome",
        "Microsoft Edge",
        "Samsung Pass",
    ]
    fmt, ok = QInputDialog.getItem(
        self, "CSV Format",
        "Choose CSV format:",
        formats, 0, False
    )
    if not ok or not fmt:
        return

    # Optional encryption
    pw, ok = QInputDialog.getText(
        self, self.tr("CSV Export"),
        self.tr("Enter a password to encrypt the CSV (leave blank for plain CSV):"),
        QLineEdit.EchoMode.Password
    )
    if not ok:
        return
    password = (pw or "").strip() or None

    # Filename
    username = self.currentUsername.text().strip() if hasattr(self, "currentUsername") else ""
    scope_slug = "all" if use_all else (category_name.replace(" ", "_") or "current")
    fmt_slug = fmt.split("(")[0].strip().replace(" ", "_").lower()  # "keyquorum", "google", "microsoft", "samsung"
    default_name = (f"{username}_" if username else "") + f"vault_export_{scope_slug}_{fmt_slug}.csv"
    if password:
        default_name += ".enc"

    out_path, _ = QFileDialog.getSaveFileName(
        self, self.tr("Save Vault CSV"), default_name,
        "CSV Files (*.csv *.csv.enc)"
    )
    if not out_path:
        return

    try:
        # pass the chosen format through
        written = export_vault_csv(username, entries, out_path, password, fmt)
        log_event_encrypted(self.currentUsername.text(), "Export CSV", f"{kql.i('ok')} CSV export saved:\n{written}")
        msg = "✅" + self.tr(" CSV export saved:") + f"\n{written}\n\n⚠️ " + self.tr("CSV is plaintext. Store it securely.")
        QMessageBox.information(self, self.tr("Export CSV"), msg)
    except Exception as e:
        msg = "❌" + self.tr(" Failed:") + f"\n{e}"
        QMessageBox.critical(self, self.tr("Export CSV"), msg)

# software folder -> This export creates a .zip file containing the contents of the "software" folder in the app directory.
def backup_software_folder(self):
    self.reset_logout_timer()
    source_dir = os.path.join("app", "software")
    if not os.path.exists(source_dir):
        QMessageBox.information(self, self.tr("Software Backup"), self.tr("No software folder found to back up."))
        return

    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join("software_backups")
    os.makedirs(backup_dir, exist_ok=True)
    zip_path = os.path.join(backup_dir, f"software_backup_{timestamp}.zip")

    with ZipFile(zip_path, 'w') as zipf:
        for root, _, files in os.walk(source_dir):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, start=source_dir)
                zipf.write(full_path, arcname=arcname)
    msg = self.tr("{ok} Software folder backedup").format(ok=kql.i('ok'))
    log_event_encrypted(self.currentUsername.text(), self.tr("soft backed up"), msg)
    msg = self.tr("{ok} Software folder backed up to:\n{zip_p}").format(ok=kql.i('ok'), zip_p=zip_path)
    QMessageBox.information(self, self.tr("Software Backup"), msg)


# ==============================
# --- Import
# ==============================


# full -> This import expects a .zip.enc file produced by export_full_backup. 
# It prompts for the account username (with a guess based on the filename) and password, then imports the vault, attachments, and catalog, 
# replacing existing data. It also logs the event and updates the baseline.
def import_vault(self):
    self.reset_logout_timer()

    # Pick the backup file produced by export_full_backup(..., out_dir)
    in_path_str, _ = QFileDialog.getOpenFileName(
        self,
        self.tr("Select Full Backup"),
        "",
        "KQV Full Backup (*.zip *.zip.enc)"
    )
    if not in_path_str:
        return

    in_path = Path(in_path_str)
    base = in_path.name

    # Guess username from "<user>_full_backup_YYYYmmdd-HHMMSS.zip[.enc]"
    m = _re.match(r"^(?P<user>.+?)_full_backup_\d{8}-\d{6}\.zip(\.enc)?$", base)
    guessed_user = m.group("user") if m else None

    cur_u = (self.currentUsername.text() if hasattr(self, "currentUsername") else "")
    cur_u = _kq_strip_ws(cur_u)
    username = (cur_u if cur_u else (guessed_user or ""))

    if not username:
        username, ok = QInputDialog.getText(self, self.tr("Restore Username"),
                                            self.tr("Enter the account username to restore into:"))
        if not ok or not username.strip():
            return
        username = username.strip()

    # Encrypted if it ends with ".zip.enc" (your importer checks Path.suffix == ".enc")
    is_encrypted = base.endswith(".zip.enc")

    pw = ""
    if is_encrypted:
        pw, ok = QInputDialog.getText(
            self, self.tr("Confirm Password"),
            self.tr("Enter your account password (used to decrypt the backup):"),
            QLineEdit.EchoMode.Password
        )
        if not ok or not pw:
            return

    try:
        self._ensure_user_dirs(username)  
        self.reset_logout_timer()
        if is_encrypted:
            import_full_backup(username, pw, str(in_path))
        else:
            import_full_backup(username, str(in_path))

        msg = self.tr("{ok} Full Backup OK").format(ok=kql.i('ok'))
        log_event_encrypted(self.currentUsername.text(), self.tr(""), msg)
        update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Full restore OK"))
        msg = self.tr("{ok} Full restore completed\n{in_p}").format(ok=kql.i('ok'), in_p=in_path)
        QMessageBox.information(self, self.tr("Import"), msg)
        try:
            if hasattr(self, "currentUsername"):
                self.currentUsername.setText(username)
            self.load_vault_table()
        except Exception:
            pass

    except Exception as e:
        QMessageBox.critical(self, self.tr("Import Failed"), f"❌ Import failed:\n{e}")


# custom (part of full) -> This is a more advanced restore flow that lets the user pick which components to restore (vault, catalog, user_db) 
# and how to handle the user record (replace, merge, etc.). It still expects the same .zip.enc file from export_full_backup, but gives more control over the restore process. It also includes better error handling and logging.
def import_vault_custom(self):
    self.set_status_txt(self.tr("Importing Vault"))
    """
    Advanced restore: user picks which items to restore and how to handle the user record.
    """
    self.reset_logout_timer()

    # Choose backup file
    in_path_str, _ = QFileDialog.getOpenFileName(
        self, self.tr("Select Full Backup"), "", "KQV Full Backup (*.zip *.zip.enc)"
    )
    if not in_path_str:
        return

    in_path = Path(in_path_str)
    base = in_path.name
    is_encrypted = base.endswith(".zip.enc")

    # Guess/collect username
    m = _re.match(r"^(?P<user>.+?)_full_backup_\d{8}-\d{6}\.zip(\.enc)?$", base)
    guessed_user = m.group("user") if m else None
    cur_u = (self.currentUsername.text() if hasattr(self, "currentUsername") else "")
    cur_u = _kq_strip_ws(cur_u)
    username = (cur_u if cur_u else (guessed_user or ""))
    if not username:
        username, ok = QInputDialog.getText(self, self.tr("Restore Username"), self.tr("Restore into username:"))
        if not ok or not username.strip():
            return
        username = username.strip()

    # Password if needed
    pw = ""
    if is_encrypted:
        pw, ok = QInputDialog.getText(
            self, self.tr("Confirm Password"),
            self.tr("Enter your account password (used to decrypt the backup):"),
            QLineEdit.EchoMode.Password
        )
        if not ok or not pw:
            return

    # Show options
    dlg = RestoreOptionsDialog(self, default_userdb_mode="replace")
    if dlg.exec() != QDialog.DialogCode.Accepted:
        return
    components, userdb_mode = dlg.result_values()
    if not components:
        QMessageBox.information(self, self.tr("Restore"), self.tr("No components selected."))
        return

    # Run restore
    try:
        self._ensure_user_dirs(username)
        self.reset_logout_timer()
        if is_encrypted:
            import_full_backup(username, pw, str(in_path),
                               components=components, userdb_mode=userdb_mode)
        else:
            import_full_backup(username, str(in_path),
                               components=components, userdb_mode=userdb_mode)

        # baseline + refresh
        update_baseline(username=username, verify_after=False, who=self.tr("Selective restore OK"))
        msg = self.tr("{ok}Restore completed\n{in_p}").format(ok=kql.i('ok'), in_p=in_path)
        QMessageBox.information(self, self.tr("Import"), msg)

        self.logout_user()

    except Exception as e:
        msg = self.tr("{ok} Restore completed\n{err}").format(ok=kql.i('err'), err=e)
        QMessageBox.critical(self, self.tr("Import Failed"), msg)


# vault only -> This import expects a .kqbk file produced by export_vault_with_password. 
# It prompts for the password, then imports the vault contents, replacing existing vault items. 
# It also includes detailed error handling and user-friendly messages about what may have gone wrong if the import fails.
def import_vault_with_password(self):
    """
    Import a password-protected .kqbk vault backup into the *current* Keyquorum account.

    What this does:
    - Asks you to pick an encrypted vault backup file (.kqbk).
    - Asks for the password you chose when you created that backup.
    - Replaces ALL existing items in this account with the backup contents
      (this is a full restore, not a merge).

    Important:
    - Vault backups are still cryptographically linked to the account they were
      created from. They can only be restored into that same Keyquorum account.
    - If the backup does not belong to this account (identity mismatch), or if
      the password is wrong or the file is damaged, the import will fail.
    """
    from vault_store.vault_store import import_vault_with_password as _import_fn

    self.set_status_txt(self.tr("Importing vault backup"))
    self.reset_logout_timer()

    username = self._active_username()
    if not username:
        self.safe_messagebox_warning(
            self,
            "Import Vault Backup",
            "Please sign in to your Keyquorum account before importing a vault backup.",
        )
        return

    # Clear, explicit warning about destructive replace
    warn = QMessageBox.warning(
        self,
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

    # Re-auth for sensitive action (YubiKey gate or password + 2FA)
    if not self.verify_sensitive_action(username, title="Confirm Import"):
        return

    # Let the user choose the backup file
    file_path, _ = QFileDialog.getOpenFileName(
        self,
        "Select Encrypted Vault Backup",
        "",
        "Encrypted Vault (*.kqbk)",
    )
    if not file_path:
        return

    # Ask for the password that was used when the backup was created
    password, ok = QInputDialog.getText(
        self,
        self.tr("Vault Backup Password"),
        self.tr("Enter the password you used when you created this vault backup:"),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not password:
        return

    # Perform the import
    self.set_status_txt(self.tr("Importing vault backup…"))
    ok = bool(_import_fn(username, password, file_path))
    self.reset_logout_timer()

    if ok:
        # Only log success if the import actually worked
        try:
            update_baseline(username=username, verify_after=False, who=self.tr("Imported Encrypted Vault (.kqbk)"))
        except Exception:
            pass

        QMessageBox.information(
            self,
            self.tr("Import complete"),
            self.tr("Vault backup imported successfully.\nIf you don’t see the updated items or categories straight away, \nplease sign out and sign back in."),)
        try:
            from features.auth_store.auth_ops import _auth_reload_table
            self.refresh_category_selector()
            self.refresh_category_dependent_ui()
            self.load_vault_table()
            _auth_reload_table(self)
            self.set_status_txt(self.tr("Vault backup imported"))
        except Exception:
            pass
    else:
        # Clear, user-friendly explanation of what may have gone wrong
        self.set_status_txt(self.tr("Vault import failed"))
        self.safe_messagebox_warning(
            self,
            self.tr("Vault import failed"),
            (self.tr(
                "The encrypted vault backup could not be imported.\n\n"
                "This can happen if:\n"
                "• The vault backup password is incorrect.\n"
                "• The backup file is damaged or incomplete.\n"
                "• The backup was created from a different Keyquorum account and the "
                "account identity does not match this one.\n\n"
                "What you can try:\n"
                "1) Double-check the backup password.\n"
                "2) If you created a FULL backup (ZIP) around the same time as this vault "
                "backup, restore the full backup first and then try this vault-only "
                "backup again.\n"
                "3) Make sure you are signed in to the same Keyquorum account that originally "
                "created this vault backup.")
            ),
        )


# csv -> This import lets the user pick a CSV or encrypted CSV file, choose which category to import into (or all), and then imports the entries.
def import_csv_entries(self):
    self.set_status_txt(self.tr("CSV Import"))
    """
    Import entries from CSV (.csv) or encrypted CSV (.csv.enc).
    Optimized for large files:
      - Bulk-create missing categories once (single user_db read/write)
      - Avoid per-row category schema persistence/UI refresh
      - Throttle progress/UI event pumping
    """
    from qtpy.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox, QProgressDialog, QApplication
    from qtpy.QtCore import Qt
    from pathlib import Path
    import io, csv, json, hashlib
    import datetime as dt

    log.debug("[DEBUG] starting import csv entries")
    try:
        self.reset_logout_timer()
    except Exception:
        pass

    # ---- helpers (scoped to function) ----
    def _stable_fingerprint(entry: dict) -> str:
        ignore = {"Date", "created_at"}
        items = [(k, entry.get(k, "")) for k in sorted(entry.keys()) if k not in ignore]
        return hashlib.sha256(
            json.dumps(items, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def _key_of(e: dict) -> tuple:
        cat = (e.get("category") or "").strip().lower()
        title = (e.get("Title") or e.get("Name") or e.get("label") or "").strip().lower()
        user  = (e.get("Username") or e.get("User") or "").strip().lower()
        url   = (e.get("URL") or e.get("Site") or "").strip().lower()
        strong = [x for x in (title, user, url) if x]
        if len(strong) >= 2:
            return (cat, title, user, url)
        return (cat, _stable_fingerprint(e))

    def _merge_update(existing: dict, incoming: dict) -> bool:
        changed = False
        for k, v in incoming.items():
            if v != "" and existing.get(k) != v:
                existing[k] = v
                changed = True
        return changed

    def _ensure_categories_bulk(category_names: set[str]) -> None:
        """
        Ensure all categories exist in the per-user category_schema with ONE read/write.
        Also refresh category UI once at the end.
        """
        try:
            canonical = self._active_username()
        except Exception:
            canonical = ""
        if not canonical:
            return

        if not category_names:
            return

        # Load schema once
        schema = get_user_setting(canonical, "category_schema")
        if not isinstance(schema, dict):
            schema = {}
        cats = list(schema.get("categories") or [])

        existing = set()
        for c in cats:
            if isinstance(c, dict):
                existing.add((c.get("name") or "").strip().lower())

        added_any = False
        for name in sorted({(x or "").strip() for x in category_names if (x or "").strip()}):
            lname = name.lower()
            if lname in existing:
                continue

            # default fields
            fields = None
            try:
                fields = self._default_fields_for_category(name)
            except Exception:
                fields = None

            if not fields:
                fields = [
                    {"label": "Title"},
                    {"label": "Username"},
                    {"label": "Password"},
                    {"label": "URL"},
                    {"label": "Notes"},
                ]

            cats.append({"name": name, "fields": fields})
            existing.add(lname)
            added_any = True

        if added_any:
            schema["categories"] = cats
            set_user_setting(canonical, "category_schema", schema)

        # Refresh UI once
        try:
            if hasattr(self, "refresh_category_dependent_ui"):
                self.refresh_category_dependent_ui()
            elif hasattr(self, "refresh_category_selector"):
                self.refresh_category_selector()
        except Exception:
            pass

        # Ensure dropdown includes them (once)
        try:
            if hasattr(self, "categorySelector_2") and self.categorySelector_2 is not None:
                ui_items = {self.categorySelector_2.itemText(i).strip() for i in range(self.categorySelector_2.count())}
                for nm in sorted({(x or "").strip() for x in category_names if (x or "").strip()}):
                    if nm not in ui_items:
                        self.categorySelector_2.addItem(nm)
        except Exception:
            pass

    # ---- choose file ----
    file_path_str, _ = QFileDialog.getOpenFileName(
        self, "Select CSV or Encrypted CSV", "", "CSV Files (*.csv *.csv.enc)"
    )
    if not file_path_str:
        return

    p = Path(file_path_str)
    is_encrypted = p.name.endswith(".csv.enc")

    # ---- open/decrypt ----
    try:
        raw = p.read_bytes()
        if is_encrypted:
            pw, ok = QInputDialog.getText(
                self, self.tr("CSV Password"),
                self.tr("Enter the password used to encrypt the CSV:"),
                QLineEdit.EchoMode.Password
            )
            if not ok or not pw:
                return
            try:
                csv_bytes = _dec_backup_bytes(pw, raw)
            except Exception:
                QMessageBox.critical(
                    self, self.tr("CSV Import"),
                    self.tr("Could not decrypt the CSV.\n\n"
                            "• Ensure it's a .csv.enc created by this app\n"
                            "• Verify the password\n"
                            "• If it's a full backup (.zip.enc), use Import Full Backup")
                )
                return
        else:
            csv_bytes = raw
    except Exception as e:
        log.error(f"[DEBUG] Failed to open/decrypt CSV: {e}")
        QMessageBox.critical(self, self.tr("Import Failed"), f"Failed to open/decrypt CSV:\n{e}")
        return

    if b"\x00" in csv_bytes[:1024]:
        QMessageBox.critical(
            self, self.tr("CSV Import"),
            self.tr("Decrypted file does not look like a CSV (binary data found). "
                    "Did you select a full backup instead of a CSV export?")
        )
        return

    # ---- decode ----
    try:
        text = csv_bytes.decode("utf-8-sig")
    except Exception as e:
        log.error(f"[DEBUG] CSV decode error: {e}")
        QMessageBox.critical(self, self.tr("Import Failed"), f"CSV decode error:\n{e}")
        return

    # ---- sniff dialect & header ----
    try:
        sample = text[:4096]
        if sample.startswith("\ufeff"):
            sample = sample.lstrip("\ufeff")
            text = text.lstrip("\ufeff")

        try:
            sniffed = csv.Sniffer().sniff(sample)
        except Exception:
            sniffed = csv.excel

        first_line = (sample.splitlines()[0] if sample.splitlines() else "").strip().lower()
        chrome_like = "name,url,username,password" in first_line or "url,username,password" in first_line
        if chrome_like:
            has_header = True
        else:
            try:
                has_header = csv.Sniffer().has_header(sample)
            except Exception:
                has_header = True
    except Exception:
        sniffed = csv.excel
        has_header = True

    sio = io.StringIO(text, newline="")
    reader = csv.DictReader(sio, dialect=sniffed) if has_header else None
    if reader is None or not reader.fieldnames:
        self.safe_messagebox_warning(self, self.tr("CSV Error"), self.tr("No headers found in CSV."))
        return

    reader.fieldnames = [h.strip() if isinstance(h, str) else h for h in reader.fieldnames]

    # ---- load current vault ----
    try:
        entries = load_vault(self.currentUsername.text(), self.core_session_handle)
    except Exception as e:
        log.error(f"[DEBUG] Failed to load vault before CSV import: {e}")
        QMessageBox.critical(self, self.tr("Import Failed"), f"Vault open error:\n{e}")
        return

    existing_keys = {_key_of(e) for e in entries}
    index_by_key = {_key_of(e): e for e in entries}

    default_category = self.categorySelector_2.currentText().strip() if hasattr(self, "categorySelector_2") else ""

    added = updated = unchanged = 0
    now_iso = dt.datetime.now().isoformat(timespec="seconds")
    today = dt.datetime.now().strftime("%Y-%m-%d")
    collisions: list[tuple[tuple, dict, dict]] = []

    # Bulk import flag: suppress per-row category UI refresh in vault_ui_ops
    self._bulk_import_in_progress = True
    try:
        if hasattr(self, "_import_category_seen"):
            delattr(self, "_import_category_seen")
    except Exception:
        pass

    try:
        source_hint = self._detect_source_hint(str(p), reader.fieldnames or [])

        # ---------- Phase 1: normalize & categorize ----------
        rows: list[dict] = []
        suggested_cats: set[str] = set()

        row_idx = 0
        for raw_row in reader:
            row_idx += 1
            try:
                norm = self._normalize_csv_row(raw_row, source_hint=source_hint, default_category=default_category)
            except Exception:
                norm = dict(raw_row or {})

            # Determine category
            cat = (norm.get("category") or "").strip()
            fallback_cat = default_category or "Web Logins"
            cat = cat or fallback_cat
            norm["category"] = cat

            if "KQ_FORMAT" in norm:
                norm.pop("KQ_FORMAT", None)

            rows.append(norm)
            suggested_cats.add(cat)

            if row_idx % 500 == 0:
                QApplication.processEvents()

        # Optional rename pass
        rename_map = self._prompt_category_renames(suggested_cats) if suggested_cats else {}
        final_cats = {rename_map.get(c, c).strip() for c in suggested_cats if (rename_map.get(c, c) or "").strip()}

        # ✅ BULK ensure categories once (big speedup)
        _ensure_categories_bulk(final_cats)

        # ---------- Phase 2: import (with progress) ----------
        total = len(rows)
        cancelled = False
        progress = None

        if total > 0:
            progress = QProgressDialog("Importing entries…", "Cancel", 0, total, self)
            progress.setWindowTitle(self.tr("CSV Import"))
            progress.setWindowModality(Qt.WindowModal)
            progress.setAutoClose(True)
            progress.setAutoReset(True)
            progress.setMinimumDuration(500)

        try:
            for idx, norm in enumerate(rows, start=1):
                # throttle progress updates to reduce repaint overhead
                if progress and (idx == 1 or idx % 50 == 0 or idx == total):
                    progress.setValue(idx)
                    self.set_status_txt(self.tr("CSV Import: ") + f"{idx}/{total}")
                    QApplication.processEvents()
                    if progress.wasCanceled():
                        cancelled = True
                        break

                category = rename_map.get(norm.get("category", ""), norm.get("category", "")).strip()
                if not category:
                    continue

                entry = {k: v for k, v in norm.items() if v != "" and k.lower() != "category"}
                entry["category"] = category
                entry.setdefault("Date", today)
                entry.setdefault("created_at", now_iso)

                # ---- fill blank core fields from fallbacks ----
                lower_to_key = {k.lower(): k for k in entry.keys()}

                def _val_for(*candidates: str) -> str:
                    for c in candidates:
                        k_real = lower_to_key.get(c.lower())
                        if k_real:
                            v = entry.get(k_real)
                            if v:
                                return v
                    return ""

                if not entry.get("Title"):
                    entry["Title"] = _val_for("title", "name", "account name", "full name",
                                              "app / title", "app name", "windows name", "game name", "site")

                if not entry.get("Username"):
                    entry["Username"] = _val_for("username", "user name", "user", "username / email", "email")

                if not entry.get("URL"):
                    url_val = _val_for("url", "website", "site", "origin / domain")
                    if url_val:
                        entry["URL"] = url_val
                        entry.setdefault("Website", url_val)

                k = _key_of(entry)
                if k in existing_keys:
                    existing = index_by_key.get(k, {})
                    collisions.append((k, existing, entry))
                else:
                    entries.append(entry)
                    existing_keys.add(k)
                    index_by_key[k] = entry
                    added += 1
        finally:
            if progress:
                progress.close()
                QApplication.processEvents()

        if cancelled:
            QMessageBox.information(
                self, self.tr("CSV Import"),
                self.tr("Import cancelled. No changes were saved to your vault.")
            )
            self.set_status_txt(self.tr("CSV import cancelled"))
            return

        # Resolve duplicates
        if collisions:
            dlg = DedupeResolverDialog(self, collisions)
            if dlg.exec() and getattr(dlg, "result_actions", None):
                for (k, existing, incoming), action in zip(collisions, dlg.result_actions):
                    if action == "skip":
                        continue
                    elif action == "update" and existing:
                        if _merge_update(existing, incoming):
                            updated += 1
                        else:
                            unchanged += 1
                    elif action == "keep":
                        entries.append(incoming)
                        kk = _key_of(incoming)
                        existing_keys.add(kk)
                        index_by_key[kk] = incoming
                        added += 1

        msg = self.tr("{ok} OK").format(ok=kql.i('ok'))
        log_event_encrypted(self.currentUsername.text(), self.tr("Import CSV"), msg)
        msg = self.tr("{ok} (vault) -> Encrypted Vault changed").format(ok=kql.i('ok'))
        log_event_encrypted(self.currentUsername.text(), self.tr("baseline"), msg)

        if added > 0 or updated > 0 or unchanged > 0:
            try:
                self.reset_logout_timer()
            except Exception:
                pass

            save_vault(self.currentUsername.text(), self.core_session_handle, entries)

            msg = self.tr("{ok} Import complete\n• New: {add}\n• Updated: {update}\n• Unchanged: {unchange}").format(
                ok=kql.i('ok'), add=added, update=updated, unchange=unchanged
            )
            QMessageBox.information(self, self.tr("Import Successful"), msg)

            try:
                self.load_vault_table()
            except Exception:
                pass
        else:
            QMessageBox.information(self, self.tr("Nothing Imported"), self.tr("No new or updated entries were imported."))

        update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("CSV import"))
        try:
            self._reconcile_category_schema_with_entries()
        except Exception:
            pass
        self.set_status_txt(self.tr("CSV import finished"))

    except Exception as e:
        log.error(f"[DEBUG] CSV Import Failed: {e}")
        QMessageBox.critical(self, self.tr("Import Failed"), str(e))
        self.set_status_txt(self.tr("CSV import failed"))


# catalog -> This import expects an encrypted catalog backup file (.kqc.enc) created by the app's export feature. 
def import_user_catalog_encrypted(self, user_root: str) -> None:
    """
    Import an encrypted catalog overlay file (.kqc.enc) using
    a user-supplied password, then reseal and reload.

    Called from CatalogEditorUserDialog._on_import_encrypted().
    """
    from qtpy.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox
    from vault_store.vault_store import _dec_backup_bytes

    username = self._active_username()
    if not username:
        QMessageBox.warning(
            self,
            self.tr("Catalog Import"),
            self.tr("Please log in first."),
        )
        return

    try:
        if hasattr(self, "verify_sensitive_action"):
            if not self.verify_sensitive_action(username, title=self.tr("Import Catalog")):
                return
    except Exception:
        pass

    in_path, _ = QFileDialog.getOpenFileName(
        self,
        self.tr("Open Catalog Backup"),
        "",
        self.tr("Keyquorum Catalog Backup (*.kqc.enc);;All Files (*.*)"),
    )
    if not in_path:
        return

    pw, ok = QInputDialog.getText(
        self,
        self.tr("Catalog Import"),
        self.tr("Enter the password used to encrypt this backup:"),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not pw.strip():
        return

    try:
        blob = Path(in_path).read_bytes()
        dec = _dec_backup_bytes(pw, blob)
        payload = json.loads(dec.decode("utf-8"))
    except Exception as e:
        QMessageBox.critical(
            self,
            self.tr("Catalog Import"),
            self.tr("Could not decrypt or read this catalog backup:\n{err}").format(err=e),
        )
        return

    if not isinstance(payload, dict) or payload.get("format") != "keyquorum.catalog.v1":
        QMessageBox.critical(
            self,
            self.tr("Catalog Import"),
            self.tr("This file does not look like a Keyquorum catalog backup."),
        )
        return

    overlay = payload.get("data") or {}
    if not isinstance(overlay, dict):
        overlay = {}

    try:
        from catalog_category.catalog_user import save_user_catalog
        save_user_catalog(user_root, overlay, session_handle=self.core_session_handle)
    except Exception as e:
        QMessageBox.critical(
            self,
            self.tr("Catalog Import"),
            self.tr("Could not import catalog:\n{err}").format(err=e),
        )
        return

    # Re-seal + reload + baseline via existing helpers
    try:
        self._on_catalog_saved(user_root)
    except Exception as e:
        try:
            log.error("[CATALOG] post-import hook failed: %s", e)
        except Exception:
            pass

    QMessageBox.information(
        self,
        self.tr("Catalog Import"),
        self.tr("Catalog imported and applied successfully."),
    )


# software folder -> This restore expects a .zip file created by backup_software_folder. It prompts the user to confirm overwriting existing files, then extracts the zip contents into the "software" folder in the app directory, replacing existing files.
def restore_software_folder(self):
    self.reset_logout_timer()
    zip_path, _ = QFileDialog.getOpenFileName(self, self.tr("Select Software Backup"), "", "ZIP Files (*.zip)")
    if not zip_path:
        return

    restore_dir = os.path.join("app", "software")
    os.makedirs(restore_dir, exist_ok=True)

    # Optionally clear existing files
    confirm = QMessageBox.question(self, self.tr("Restore Software Folder"), self.tr("This will overwrite existing files. Continue?"))
    if confirm != QMessageBox.StandardButton.Yes:
        return
    self.reset_logout_timer()
    rmtree(restore_dir)
    os.makedirs(restore_dir, exist_ok=True)

    with ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(restore_dir)
    update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Soft Restored"))
    QMessageBox.information(self, self.tr("Software Restore"), self.tr("✅ Software folder restored successfully."))

# ==============================
# --- Helpers
# ==============================

def _ensure_user_dirs(self, username: str) -> None:
    """
    Make sure the per-user folder tree exists so imports can write files safely.
    """
      
    try:
        from app.paths import ensure_dirs
        ensure_dirs()
    except Exception:
        pass

    targets = [
        Path(vault_file(username, ensure_parent=True)),
        Path(vault_wrapped_file(username, ensure_parent=True, name_only=False)),
        Path(salt_file(username, ensure_parent=True, name_only=False)),
        Path(shared_key_file(username, ensure_parent=True, name_only=False)),
        Path(identities_file(username, ensure_parent=True)),  # …/Users/<u>/identities/<u>.data
        Path(user_db_file(username, ensure_parent=True)),     # per-user JSON
    ]
    for p in targets:
        p.parent.mkdir(parents=True, exist_ok=True)


