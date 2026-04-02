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

import json, logging, datetime as dt
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

from qtpy.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QListWidget, QListWidgetItem, QTableWidget, QTableWidgetItem,
    QPushButton, QHeaderView, QMessageBox, QAbstractItemView, QLabel, QInputDialog, QFileDialog,
    QTabWidget, QStackedWidget, QCheckBox
)
from qtpy.QtCore import Qt, Signal, QObject, QRunnable, QThreadPool, QSettings, QTimer
from qtpy.QtGui import QGuiApplication

# ---- app logging ----
log = logging.getLogger("keyquorum")


from catalog_category.category_fields import PROTECTED_CATEGORIES, AUTH_CATEGORY_NAME, _SENSITIVE_DATA, default_category_schema

# ---- settings API (optional; safe fallbacks below) ----
try:
    from auth.login.login_handler import get_user_setting, set_user_setting, find_user  # type: ignore
except Exception:
    def get_user_setting(_u, _k, default=None): return default
    def set_user_setting(_u, _k, _v): return None
    def find_user(u): return u


from qtpy.QtCore import QCoreApplication


from app.paths import user_db_file
# ==============================
# Per-user schema persistence (user_db.json under ...\Users\<user>\)
# ==============================

def _read_user_db_for(uname: str) -> dict:
    p = user_db_file(uname)
    if not p.exists():
        return {}
    try:
        txt = p.read_text(encoding="utf-8") or "{}"
        db = json.loads(txt)
        return db if isinstance(db, dict) else {}
    except Exception as e:
        log.error("[CAT] read %s failed: %s", p, e)
        return {}

def _write_user_db_for(uname: str, data: dict) -> None:
    p = user_db_file(uname)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        log.debug("[CAT] wrote %s", p)
    except Exception as e:
        log.error(f"❌ [CAT] write failed: {e}")

def _extract_schema_from_db(db: dict, uname: str) -> dict | None:
    """
    Prefer per-user path; tolerate legacy shapes so we can migrate them.
    """
    # 1) preferred
    x = db.get(uname, {}).get("settings", {}).get("category_schema")
    if isinstance(x, dict) and isinstance(x.get("categories"), list):
        return x
    # 2) tolerated legacy shapes
    x = db.get("users", {}).get(uname, {}).get("settings", {}).get("category_schema")
    if isinstance(x, dict) and isinstance(x.get("categories"), list):
        return x
    x = db.get("user", {}).get("settings", {}).get("category_schema")
    if isinstance(x, dict) and isinstance(x.get("categories"), list):
        return x
    x = db.get("settings", {}).get("category_schema")
    if isinstance(x, dict) and isinstance(x.get("categories"), list):
        return x
    x = db.get("category_schema")
    if isinstance(x, dict) and isinstance(x.get("categories"), list):
        return x
    return None

def _place_schema_into_db(db: dict, uname: str, schema: dict) -> dict:
    """
    Ensure the schema lives ONLY at db[uname]['settings']['category_schema'].
    Also scrub any legacy copies.
    """
    db = dict(db or {})
    db.setdefault(uname, {}).setdefault("settings", {})["category_schema"] = schema

    # Scrub legacy containers to prevent duplicates on next read
    if "user" in db and isinstance(db["user"], dict):
        us = db["user"].get("settings", {})
        if "category_schema" in us:
            del us["category_schema"]
        if us == {}:
            db["user"].pop("settings", None)
        if db["user"] == {}:
            db.pop("user", None)

    if "settings" in db and isinstance(db["settings"], dict):
        if "category_schema" in db["settings"]:
            del db["settings"]["category_schema"]
        if db["settings"] == {}:
            db.pop("settings", None)

    if "category_schema" in db:
        db.pop("category_schema", None)

    return db

def _normalize_schema_inplace(data: dict) -> None:
    # strip legacy field key, keep system category hidden
    for c in data.get("categories", []):
        for f in c.get("fields", []):
            if isinstance(f, dict):
                f.pop("hide", None)
    # ensure the system OTP category exists and is hidden/system
    names = [c.get("name") for c in data.get("categories", [])]
    if AUTH_CATEGORY_NAME not in names:
        base = default_category_schema()
        for cat in base.get("categories", []):
            if cat.get("name") == AUTH_CATEGORY_NAME:
                data.setdefault("categories", []).append(cat)
                break
    else:
        for c in data.get("categories", []):
            if c.get("name") == AUTH_CATEGORY_NAME:
                c["hidden"] = True
                c["system"] = True
                break

def _migrate_legacy_blocks(db: dict, uname: str) -> dict:
    """
    If legacy schema blocks exist, move them into db[uname]['settings']['category_schema']
    and remove the old copies.
    """
    db = dict(db or {})
    legacy = None

    # Collect a valid legacy schema
    for candidate in (
        db.get("user", {}).get("settings", {}).get("category_schema"),
        db.get("settings", {}).get("category_schema"),
        db.get("category_schema"),
    ):
        if isinstance(candidate, dict) and isinstance(candidate.get("categories"), list):
            legacy = candidate
            break

    # Migrate it under the username-scoped path
    if legacy:
        db.setdefault(uname, {}).setdefault("settings", {})["category_schema"] = legacy

        # Clean up old containers
        if "user" in db and isinstance(db["user"], dict):
            us = db["user"].get("settings", {})
            if "category_schema" in us:
                del us["category_schema"]
            if us == {}:
                db["user"].pop("settings", None)
            if db["user"] == {}:
                db.pop("user", None)

        if "settings" in db and isinstance(db["settings"], dict):
            if "category_schema" in db["settings"]:
                del db["settings"]["category_schema"]
            if db["settings"] == {}:
                db.pop("settings", None)

        if "category_schema" in db:
            db.pop("category_schema", None)

    return db

def save_full_schema_dict_for(uname: str, data: dict) -> None:
    try:
        data = dict(data or {})
        _normalize_schema_inplace(data)

        # mirror to settings (fast path)
        try:
            set_user_setting(uname, "category_schema", data)
        except Exception:
            pass

        # authoritative: per-user file, username-scoped
        db = _read_user_db_for(uname)
        db = _migrate_legacy_blocks(db, uname)
        db = _place_schema_into_db(db, uname, data)
        _write_user_db_for(uname, db)
    except Exception as e:
        log.error("[CAT] save_full_schema_dict_for failed: %s", e)

def load_schema_for(uname: str) -> dict:
    # A) fast path: settings API
    try:
        s = get_user_setting(uname, "category_schema", None)
        if isinstance(s, dict) and isinstance(s.get("categories"), list):
            _normalize_schema_inplace(s)
            db = _read_user_db_for(uname)
            db = _migrate_legacy_blocks(db, uname)
            db = _place_schema_into_db(db, uname, s)
            _write_user_db_for(uname, db)
            return s
    except Exception:
        pass

    # B) file path
    db = _read_user_db_for(uname)
    db = _migrate_legacy_blocks(db, uname)
    s = _extract_schema_from_db(db, uname)
    if isinstance(s, dict):
        _normalize_schema_inplace(s)
        try:
            set_user_setting(uname, "category_schema", s)
        except Exception:
            pass
        db = _place_schema_into_db(db, uname, s)
        _write_user_db_for(uname, db)
        return s

    # C) defaults fallback
    s = default_category_schema()
    _normalize_schema_inplace(s)
    try:
        set_user_setting(uname, "category_schema", s)
    except Exception:
        pass
    db = _place_schema_into_db(db, uname, s)
    _write_user_db_for(uname, db)
    return s

# ==============================
# Defaults builder (delegates to category_fields for single source of truth)
# ==============================

def _heuristic_sensitive(label: str) -> bool:
    lab = (label or "").lower()
    for k in _SENSITIVE_DATA:
        if k in lab:
            return True
    return False

def _build_schema_from_defaults() -> dict:
    # keep code path for callers that expect this helper
    return default_category_schema()

# ==============================
# Background save infra
# ==============================

class _SaveSignals(QObject):
    started = Signal()
    finished = Signal(bool, str) 

class _SaveJob(QRunnable):
    def __init__(self, do_save_callable):
        super().__init__()
        self.signals = _SaveSignals()
        self._do_save = do_save_callable

    def run(self):
        self.signals.started.emit()
        ok = False
        msg = ""
        try:
            ok, msg = self._do_save()
        except Exception as e:
            ok, msg = False, str(e)
        self.signals.finished.emit(ok, msg)

# ==============================
# Category Editor (pass uname from main)
# ==============================

class CategoryEditor(QWidget):
    # ---------- category reminders (safe stub + logic) ----------

    def _on_category_reminders_toggled(self, enabled: bool):
        """
        Category-level reminder toggle.
        Adds or removes dedicated 'Reminder Date' and 'Reminder Note' fields.
        """
        try:
            cat, idx = self._current_cat()
        except Exception:
            return
        if not cat or idx < 0:
            return

        # Protected categories cannot be modified
        protected = ((cat.get("name") or "").strip().lower() in PROTECTED_CATEGORIES)
        if protected:
            try:
                self.catReminderChk.blockSignals(True)
                self.catReminderChk.setChecked(False)
            finally:
                self.catReminderChk.blockSignals(False)
            return

        cat["allow_reminders"] = bool(enabled)
        fields = cat.setdefault("fields", [])

        def _is_reminder_date_field(f):
            if not isinstance(f, dict):
                return False
            if f.get("is_reminder_field") or f.get("is_reminder_date"):
                return True
            lab = (f.get("label") or "").strip().lower()
            return lab in ("reminder date", "reminder_date", "reminder")

        def _is_reminder_note_field(f):
            if not isinstance(f, dict):
                return False
            if f.get("is_reminder_note") or f.get("is_reminder_note_field"):
                return True
            lab = (f.get("label") or "").strip().lower()
            return lab in ("reminder note", "reminder_note", "note (reminder)", "reminder notes")

        if enabled:
            # Ensure reminder date field exists
            if not any(_is_reminder_date_field(f) for f in fields):
                fields.append({
                    "label": "Reminder Date",
                    "sensitive": False,
                    "url": False,
                    "file_load": False,
                    "required": False,
                    "is_reminder_field": True,   # legacy flag (kept for compatibility)
                    "is_reminder_date": True,    # preferred flag
                })
            # Ensure reminder note field exists
            if not any(_is_reminder_note_field(f) for f in fields):
                fields.append({
                    "label": "Reminder Note",
                    "sensitive": False,
                    "url": False,
                    "file_load": False,
                    "required": False,
                    "is_reminder_note": True,
                })
        else:
            # Remove both reminder fields if present
            fields[:] = [f for f in fields if not (_is_reminder_date_field(f) or _is_reminder_note_field(f))]

        self.mark_dirty()
        try:
            self._load_fields_for_selected(self.catList.currentRow())
        except Exception:
            pass

        """
        Category-level reminder toggle.
        Adds or removes dedicated 'Reminder Date' and 'Reminder Note' fields.
        """
        try:
            cat, idx = self._current_cat()
        except Exception:
            return
        if not cat or idx < 0:
            return

        # Protected categories cannot be modified
        protected = ((cat.get("name") or "").strip().lower() in PROTECTED_CATEGORIES)
        if protected:
            try:
                self.catReminderChk.blockSignals(True)
                self.catReminderChk.setChecked(False)
            finally:
                self.catReminderChk.blockSignals(False)
            return

        cat["allow_reminders"] = bool(enabled)
        fields = cat.setdefault("fields", [])

        def _is_reminder_field(f):
            if not isinstance(f, dict):
                return False
            if f.get("is_reminder_field"):
                return True
            lab = (f.get("label") or "").strip().lower()
            return lab in ("reminder", "reminder date", "reminder_date")

        if enabled:
            if not any(_is_reminder_field(f) for f in fields):
                fields.append({
                    "label": "Reminder Date",
                    "sensitive": False,
                    "url": False,
                    "file_load": False,
                    "required": False,
                    "is_reminder_field": True,
                })
        else:
            fields[:] = [f for f in fields if not _is_reminder_field(f)]

        self.mark_dirty()
        try:
            self._load_fields_for_selected(self.catList.currentRow())
        except Exception:
            pass

    """
    Manage categories and per-field flags for a specific user.
    - Pass `uname` from MainWindow so we always read/write the correct user.
    - All changes persist into per-user user_db.json under <uname>.settings.category_schema
    - Also mirrored via get/set_user_setting for faster access.
    """

    def __init__(self, parent=None, uname: str = "", on_schema_saved=None, get_category_usage=None):
        super().__init__(parent)
        self._dirty = False
        self._parent = parent
        self._threadpool = QThreadPool.globalInstance()
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(600)
        self._debounce.timeout.connect(self._autosave_fire)

        self._on_schema_saved = on_schema_saved
        self.get_category_usage = get_category_usage
        self._uname = find_user(uname) or (uname or "")

        if not self._uname:
            log.warning("[CAT] CategoryEditor created without uname; using defaults in-memory.")
            self.schema = _build_schema_from_defaults()
        else:
            try:
                self.schema = load_schema_for(self._uname)
            except Exception as e:
                log.error("[CAT] load_schema_for failed for %s: %s", self._uname, e)
                self.schema = _build_schema_from_defaults()

        # UI
        self._build_ui()

        # controls row
        bar = QHBoxLayout()
        self.autoSaveChk = QCheckBox(self.tr("Auto-save"))
        self.autoSaveChk.setChecked(_read_auto_save_default())
        self.saveBtn = QPushButton(self.tr("Save"))
        self.saveBtn.setEnabled(False)
        self.statusLbl = QLabel("")
        self.autoSaveChk.toggled.connect(lambda v: _write_auto_save_default(v))
        self.saveBtn.clicked.connect(self._save_now_clicked)
        bar.addWidget(self.autoSaveChk)
        bar.addWidget(self.saveBtn)
        bar.addStretch(1)
        bar.addWidget(self.statusLbl)

        self._leftControlsHost.addLayout(bar)

        # lists
        self._refresh_lists()

    # ---------- prefs ----------
    def mark_dirty(self):
        if not self._dirty:
            self._dirty = True
            self.saveBtn.setEnabled(True)
        if self.autoSaveChk.isChecked():
            self._debounce.start()
        else:
            self.statusLbl.setText(self.tr("Unsaved changes"))

    def _save_now_clicked(self):
        self._debounce.stop()
        self._run_save_job()

    def _autosave_fire(self):
        if self._dirty:
            self._run_save_job()

    def _run_save_job(self):
        job = _SaveJob(self._do_save_impl)
        job.signals.started.connect(self._on_save_started)
        job.signals.finished.connect(self._on_save_finished)
        self._threadpool.start(job)

    def _on_save_started(self):
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        self.statusLbl.setText(self.tr("Saving…"))
        self.saveBtn.setEnabled(False)


    def _on_save_finished(self, ok: bool, msg: str):
        QGuiApplication.restoreOverrideCursor()
        if ok:
            self._dirty = False
            self.statusLbl.setText(self.tr("Saved at") + f" { _fmt_now() }")

            # 1) Refresh any vault UI that depends on the schema
            host = self._find_host_with("schedule_vault_schema_refresh", "updatebaseline")
            if host:
                # Refresh schema-dependent UI (existing behaviour)
                try:
                    host.schedule_vault_schema_refresh()
                except Exception:
                    pass

                # 2) Update baseline for user_db.json after category save
                try:
                    canonical = (self._uname or "").strip()
                    if canonical:
                        host.updatebaseline(
                            canonical,
                            verify_after=False,
                            who=self.tr("Category Save"),
                        )
                except Exception as e:
                    log.error("[CAT] updatebaseline after category save failed: %s", e)

            # Any extra callback wired in from MainWindow
            cb = getattr(self, "_on_schema_saved", None)
            if callable(cb):
                try:
                    cb()
                except Exception:
                    pass
        else:
            self.saveBtn.setEnabled(True)
            self.statusLbl.setText(self.tr("Save failed") + f": {msg}")


    def _do_save_impl(self):
        try:
            if not self._uname:
                return False, self.tr("No active user")
            save_full_schema_dict_for(self._uname, self.schema)
            return True, self.tr("OK")
        except Exception as e:
            return False, str(e)

    # ------------------------
    # UI build
    def _build_ui(self):
        root = QHBoxLayout(self)

        # LEFT
        left = QVBoxLayout()
        left.addWidget(QLabel(self.tr("Categories")))
        self.catList = QListWidget()
        self.catList.currentRowChanged.connect(self._on_selection_changed)
        left.addWidget(self.catList)

        # --- Category buttons ---

        # Row 1: Add / Remove / Rename
        self.btnAddCat = QPushButton(self.tr("Add Category"))
        self.btnDelCat = QPushButton(self.tr("Remove Category"))
        self.btnRenCat = QPushButton(self.tr("Rename Category"))

        self.btnAddCat.clicked.connect(self._add_category)
        self.btnDelCat.clicked.connect(self._remove_category)
        self.btnRenCat.clicked.connect(self._rename_category)

        row_cat1 = QHBoxLayout()
        row_cat1.addWidget(self.btnAddCat)
        row_cat1.addWidget(self.btnDelCat)
        row_cat1.addWidget(self.btnRenCat)
        left.addLayout(row_cat1)

        # Row 2: Move Up / Move Down
        self.btnUpCat   = QPushButton("↑ " + self.tr("Move Up"))
        self.btnDownCat = QPushButton("↓ " + self.tr("Move Down"))

        self.btnUpCat.clicked.connect(self._move_up_category)
        self.btnDownCat.clicked.connect(self._move_down_category)

        row_cat2 = QHBoxLayout()
        row_cat2.addWidget(self.btnUpCat)
        row_cat2.addWidget(self.btnDownCat)
        left.addLayout(row_cat2)

        # --- Maintenance (backup/restore/default/repair) ---

        # Row 3: Backup / Restore
        self.btnBackup   = QPushButton(self.tr("Backup Schema"))
        self.btnRestore  = QPushButton(self.tr("Import Schema"))
        self.btnBackup.clicked.connect(self.backup_schema)
        self.btnRestore.clicked.connect(self.restore_schema)

        row_maint1 = QHBoxLayout()
        row_maint1.addWidget(self.btnBackup)
        row_maint1.addWidget(self.btnRestore)
        left.addLayout(row_maint1)

        # Row 4: Reset defaults (own row)
        self.btnDefaults = QPushButton(self.tr("Reset Defaults"))
        self.btnDefaults.clicked.connect(self.reset_defaults)
        left.addWidget(self.btnDefaults)

        # Row 5: Repair schema / find missing data (own row)
        self.btnRepair = QPushButton(self.tr("Find Missing Data / Repair Schema"))
        self.btnRepair.clicked.connect(self.repair_category_schema)
        left.addWidget(self.btnRepair)

        # Extra host for any future controls
        self._leftControlsHost = QVBoxLayout()
        left.addLayout(self._leftControlsHost)


        # RIGHT
        right = QVBoxLayout()
        right.addWidget(QLabel(self.tr("Fields")))

        # Category-level reminders (adds/removes a dedicated Reminder Date field)
        self.catReminderChk = QCheckBox(self.tr("Enable reminders for this category"))
        self.catReminderChk.setToolTip(self.tr("Adds 'Reminder Date' and 'Reminder Note' fields. The date field shows a calendar button when adding entries."))
        self.catReminderChk.toggled.connect(self._on_category_reminders_toggled)
        right.addWidget(self.catReminderChk)

        self.fields = QTableWidget(0, 5)
        # note: add box remineder that once vault opens alarts will be made (shuld be data box)
        self.fields.setHorizontalHeaderLabels([self.tr("Label"), self.tr("Sensitive"), self.tr("URL"), self.tr("File Load"), self.tr("Required")])  
        self.fields.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.fields.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked |
            QAbstractItemView.EditTrigger.SelectedClicked
        )
        right.addWidget(self.fields, 1)
        self.fields.itemChanged.connect(self._on_field_item_changed)



        rowBtns = QHBoxLayout()
        self.btnAddField   = QPushButton(self.tr("Add Field"))
        self.btnRenField   = QPushButton(self.tr("Rename Field"))
        self.btnDelField   = QPushButton(self.tr("Remove Field"))
        self.btnFieldUp    = QPushButton("↑ " + self.tr("Field Up"))
        self.btnFieldDown  = QPushButton("↓ " + self.tr("Field Down"))

        self.btnAddField.clicked.connect(self._add_field)
        self.btnRenField.clicked.connect(self._rename_field)
        self.btnDelField.clicked.connect(self._remove_field)
        self.btnFieldUp.clicked.connect(self._move_field_up)
        self.btnFieldDown.clicked.connect(self._move_field_down)

        rowBtns.addWidget(self.btnAddField)
        rowBtns.addWidget(self.btnRenField)
        rowBtns.addWidget(self.btnDelField)
        rowBtns.addWidget(self.btnFieldUp)
        rowBtns.addWidget(self.btnFieldDown)
        right.addLayout(rowBtns)

        root.addLayout(left, 1)
        root.addLayout(right, 2)


    # ---------- list/table population ----------
    def _refresh_lists(self):
        self.catList.blockSignals(True)
        try:
            self.catList.clear()
            for c in self.schema.get("categories", []):
                label = c["name"]
                if c.get("hidden"):
                    label = f"{label}  (system)"
                it = QListWidgetItem(label)
                it.setData(Qt.ItemDataRole.UserRole, c["name"])
                it.setFlags(it.flags() | Qt.ItemIsEditable)
                self.catList.addItem(it)
            if self.catList.count() > 0 and self.catList.currentRow() < 0:
                self.catList.setCurrentRow(0)
        finally:
            self.catList.blockSignals(False)

        self.catList.itemChanged.connect(self._on_cat_item_changed)
        self._load_fields_for_selected(self.catList.currentRow())

    def _on_selection_changed(self, _row: int):
        self._load_fields_for_selected(_row)
        cat, _ = self._current_cat()
        protected = ((cat.get("name") if cat else "") or "").strip().lower() in PROTECTED_CATEGORIES
        self.btnRenCat.setEnabled(not protected and cat is not None)
        self.btnDelCat.setEnabled(not protected and cat is not None)

        # Sync reminder category toggle
        if hasattr(self, "catReminderChk"):
            self.catReminderChk.blockSignals(True)
            self.catReminderChk.setChecked(bool(cat.get("allow_reminders", False)) if cat else False)
            self.catReminderChk.setEnabled((cat is not None) and (not protected))
            self.catReminderChk.blockSignals(False)
        has_sel = cat is not None
        self.btnUpCat.setEnabled(has_sel)
        self.btnDownCat.setEnabled(has_sel)
        it = self.catList.item(self.catList.currentRow())
        if it:
            flags = it.flags()
            it.setFlags((flags & ~Qt.ItemIsEditable) if protected else (flags | Qt.ItemIsEditable))

    def _apply_protection_ui_state(self, locked: bool):
        self.fields.setDisabled(locked)
        for b in (self.btnAddField, self.btnRenField, self.btnDelField, self.btnFieldUp, self.btnFieldDown):
            b.setDisabled(locked)
        triggers = (QAbstractItemView.EditTrigger.NoEditTriggers if locked else
                    QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.SelectedClicked)
        self.fields.setEditTriggers(triggers)

    def _load_fields_for_selected(self, _row: int):
        cat, _ = self._current_cat()
        self.fields.blockSignals(True)
        locked = ((cat.get("name") if cat else "") or "").strip().lower() in PROTECTED_CATEGORIES
        self._apply_protection_ui_state(locked)
        try:
            self.fields.setRowCount(0)
            if not cat:
                return
            for f in cat.get("fields", []):
                r = self.fields.rowCount()
                self.fields.insertRow(r)

                self.fields.setItem(r, 0, QTableWidgetItem(f.get("label", "")))

                sens_item = QTableWidgetItem()
                sens_item.setFlags((sens_item.flags() | Qt.ItemIsUserCheckable) & (~Qt.ItemIsEnabled if locked else ~Qt.ItemFlag(0)))
                sens_item.setCheckState(Qt.Checked if f.get("sensitive") else Qt.Unchecked)
                self.fields.setItem(r, 1, sens_item)

                url_item = QTableWidgetItem()
                url_item.setFlags((url_item.flags() | Qt.ItemIsUserCheckable) & (~Qt.ItemIsEnabled if locked else ~Qt.ItemFlag(0)))
                url_item.setCheckState(Qt.Checked if f.get("url") else Qt.Unchecked)
                self.fields.setItem(r, 2, url_item)

                file_item = QTableWidgetItem()
                file_item.setFlags((file_item.flags() | Qt.ItemIsUserCheckable) & (~Qt.ItemIsEnabled if locked else ~Qt.ItemFlag(0)))
                file_item.setCheckState(Qt.Checked if f.get("file_load") else Qt.Unchecked)
                self.fields.setItem(r, 3, file_item)

                req_item = QTableWidgetItem()
                req_item.setFlags((req_item.flags() | Qt.ItemIsUserCheckable) & (~Qt.ItemIsEnabled if locked else ~Qt.ItemFlag(0)))
                req_item.setCheckState(Qt.Checked if f.get("required") else Qt.Unchecked)
                self.fields.setItem(r, 4, req_item)

        finally:
            self.fields.blockSignals(False)

    def _on_cat_item_changed(self, item: QListWidgetItem):
        row = self.catList.row(item)
        if row < 0:
            return
        cat = self.schema["categories"][row]
        true_name = item.data(Qt.ItemDataRole.UserRole) or cat.get("name", "")
        if (true_name or "").strip().lower() in PROTECTED_CATEGORIES:
            # revert any change
            self.catList.blockSignals(True)
            try:
                label = f"{true_name}  (system)"
                item.setText(label)
            finally:
                self.catList.blockSignals(False)
            return

        new_name = (item.text() or "").strip()
        if not new_name:
            item.setText(self.schema["categories"][row]["name"])
            return
        names_lower = {c["name"].lower() for i, c in enumerate(self.schema["categories"]) if i != row}
        if new_name.lower() in names_lower:
            QMessageBox.warning(self, self.tr("Name exists"), self.tr("Another category already has that name."))
            item.setText(self.schema["categories"][row]["name"])
            return
        if new_name.lower() == AUTH_CATEGORY_NAME.lower():
            QMessageBox.warning(self, self.tr("Protected"), f"“{AUTH_CATEGORY_NAME}” " + self.tr("is a system category."))
            item.setText(self.schema["categories"][row]["name"])
            return

        self.schema["categories"][row]["name"] = new_name
        item.setData(Qt.ItemDataRole.UserRole, new_name)
        self.mark_dirty()

    def _on_field_item_changed(self, item: QTableWidgetItem):
        try:
            cat, idx = self._current_cat()
            if idx < 0 or item is None:
                return
            if ((cat.get("name") if cat else "") or "").strip().lower() in PROTECTED_CATEGORIES:
                return
            row, col = item.row(), item.column()
            fields = self.schema["categories"][idx].setdefault("fields", [])
            while row >= len(fields):
                fields.append({"label": f"Field {row+1}", "sensitive": False, "url": False, "file_load": False, "required": False})

            if col == 0:
                new_label = (item.text() or "").strip()
                if not new_label:
                    prev = fields[row].get("label", "")
                    if prev:
                        self.fields.blockSignals(True)
                        item.setText(prev)
                        self.fields.blockSignals(False)
                        return
                fields[row]["label"] = new_label
            else:
                key_map = {1: "sensitive", 2: "url", 3: "file_load", 4: "required"}
                key = key_map.get(col)
                if key:
                    checked = (item.checkState() == Qt.Checked)
                    fields[row][key] = checked


            self.mark_dirty()
        except Exception as e:
            log.error("[CAT] _on_field_item_changed failed: %s", e)

    # ---------- category ops ----------
    def _add_category(self):
        base = "New Category"; name = base; i = 1
        existing = {c["name"].lower() for c in self.schema["categories"]}
        while name.lower() in existing:
            i += 1; name = f"{base} {i}"
        typed, ok = QInputDialog.getText(self, self.tr("Add Category"), self.tr("Category name:"), text=name)
        if not ok or not (typed := typed.strip()):
            return
        if typed.lower() == AUTH_CATEGORY_NAME.lower():
            QMessageBox.information(self, self.tr("Protected"), f"“{AUTH_CATEGORY_NAME}” " + self.tr("is a system category and cannot be created."))
            return
        if typed.lower() in existing:
            QMessageBox.warning(self, self.tr("Exists"), self.tr("That category already exists."))
            return
        self.schema["categories"].append({"name": typed, "fields": []})
        self.mark_dirty(); self._refresh_lists()
        cb = getattr(self, "_on_schema_saved", None)
        if callable(cb): 
            try: cb()
            except Exception: pass

    def _remove_category(self):
        cat, idx = self._current_cat()
        if idx < 0: return
        lower = (cat.get("name") or "").strip().lower()
        if lower in PROTECTED_CATEGORIES:
            QMessageBox.information(self, self.tr("Protected"), self.tr("This category cannot be removed."))
            return

        in_use = 0
        if callable(self.get_category_usage):
            try:
                usage = self.get_category_usage() or {}
                in_use = int(usage.get(cat["name"], 0))
            except Exception:
                in_use = 0

        if in_use > 0:
            schema_names = [c["name"] for c in self.schema.get("categories", []) if c["name"] != cat["name"]]
            choices = list(schema_names) + ["<Create new category...>", "<Auto -> Uncategorized>"]
            tgt, ok = QInputDialog.getItem(self, self.tr("Category In Use"),
                                            f"'{cat['name']}' " + self.tr("has ") + f"{in_use} " + self.tr("entr") + (self.tr("y") if in_use==1 else self.tr("ies")) + self.tr(". Move them to:"),
                                            choices, 0, False)
            if not ok or not tgt:
                return
            if tgt == "<Create new category...>":
                new_name, ok2 = QInputDialog.getText(self, self.tr("New Category"), self.tr("New category name:"))
                if not ok2: return
                tgt = (new_name or "").strip()
                if not tgt:
                    QMessageBox.warning(self, self.tr("New Category"), self.tr("Name cannot be empty.")); return
                if tgt.lower() in [n.lower() for n in schema_names]:
                    QMessageBox.warning(self, self.tr("New Category"), self.tr("That category already exists.")); return
                self.schema["categories"].append({"name": tgt, "fields": []})
                self.mark_dirty()
            elif tgt == "<Auto -> Uncategorized>":
                if "Uncategorized" not in [c["name"] for c in self.schema["categories"]]:
                    self.schema["categories"].append({"name":"Uncategorized","fields":[]})
                    self.mark_dirty()
                tgt = "Uncategorized"

            host = self._find_host_with("migrate_entries", "refresh_category_dependent_ui")
            if host:
                try:
                    moved = host.migrate_entries(cat["name"], tgt)
                    log.debug("[CAT] Migrated %s entries from '%s' to '%s'.", moved, cat["name"], tgt)
                except Exception as e:
                    log.error("[CAT] migrate_entries failed: %s", e)

        try:
            self.schema["categories"].pop(idx)
        except Exception:
            pass
        self.mark_dirty(); self._refresh_lists()
        cb = getattr(self, "_on_schema_saved", None)
        if callable(cb): 
            try: cb()
            except Exception: pass

    def _rename_category(self):
        cat, idx = self._current_cat()
        if idx < 0: return
        lower = (cat.get("name") or "").strip().lower()
        if lower in PROTECTED_CATEGORIES:
            QMessageBox.information(self, self.tr("Protected"), self.tr("This category cannot be renamed."))
            return
        new_name, ok = QInputDialog.getText(self, self.tr("Rename Category"), self.tr("New name:"), text=cat["name"])
        if not ok: return
        new_name = new_name.strip()
        if not new_name: return
        if any(c["name"].lower()==new_name.lower() for c in self.schema["categories"] if c is not cat):
            QMessageBox.warning(self, self.tr("Name exists"), self.tr("Another category already has that name.")); return
        if new_name.lower() == AUTH_CATEGORY_NAME.lower():
            QMessageBox.warning(self, self.tr("Protected"), f"“{AUTH_CATEGORY_NAME}” " + self.tr("is a system category."))
            return
        cat["name"] = new_name
        self.mark_dirty(); self._refresh_lists()
        cb = getattr(self, "_on_schema_saved", None)
        if callable(cb): 
            try: cb()
            except Exception: pass

    def _move_category(self, delta: int):
        cat, idx = self._current_cat()
        if idx is None or idx < 0:
            return
        new_idx = idx + delta
        if not (0 <= new_idx < len(self.schema["categories"])):
            return

        cats = self.schema["categories"]
        cats[idx], cats[new_idx] = cats[new_idx], cats[idx]

        self.catList.blockSignals(True)
        try:
            it = self.catList.takeItem(idx)
            self.catList.insertItem(new_idx, it)
            self.catList.setCurrentRow(new_idx)
        finally:
            self.catList.blockSignals(False)

        self.mark_dirty()
        self._load_fields_for_selected(new_idx)

    def _move_up_category(self): self._move_category(-1)
    def _move_down_category(self): self._move_category(+1)

    # ---------- field ops ----------
    def _add_field(self):
        cat, idx = self._current_cat()
        lower = ((cat.get("name") if cat else "") or "").strip().lower()
        if lower in PROTECTED_CATEGORIES:
            QMessageBox.information(self, self.tr("Protected"), self.tr("Fields in this category are locked."))
            return
        if idx < 0:
            QMessageBox.warning(self, self.tr("No Category"), self.tr("Select a category first.")); return
        name, ok = QInputDialog.getText(self, self.tr("Add Field"), self.tr("Field name:"))
        if not ok or not name.strip(): return
        self.schema["categories"][idx]["fields"].append(
            {"label": name.strip(), "sensitive": False, "url": False, "file_load": False, "required": False}
        )
        self.mark_dirty(); self._load_fields_for_selected(idx)
        cb = getattr(self, "_on_schema_saved", None)
        if callable(cb): 
            try: cb()
            except Exception: pass

    def _remove_field(self):
        cat, idx = self._current_cat()
        lower = ((cat.get("name") if cat else "") or "").strip().lower()
        if lower in PROTECTED_CATEGORIES:
            QMessageBox.information(self, self.tr("Protected"), self.tr("Fields in this category are locked."))
            return
        if idx < 0: return
        r = self.fields.currentRow()
        if r < 0:
            QMessageBox.warning(self, self.tr("No Field"), self.tr("Select a field to remove.")); return
        try:
            self.schema["categories"][idx]["fields"].pop(r)
        except Exception:
            pass
        self.mark_dirty(); self._load_fields_for_selected(idx)
        cb = getattr(self, "_on_schema_saved", None)
        if callable(cb): 
            try: cb()
            except Exception: pass

    def _rename_field(self):
        cat, idx = self._current_cat()
        lower = ((cat.get("name") if cat else "") or "").strip().lower()
        if lower in PROTECTED_CATEGORIES:
            QMessageBox.information(self, self.tr("Protected"), self.tr("Fields in this category are locked."))
            return
        if idx < 0: return
        r = self.fields.currentRow()
        if r < 0:
            QMessageBox.warning(self, self.tr("No Field"), self.tr("Select a field to rename.")); return
        old = self.fields.item(r, 0).text() if self.fields.item(r, 0) else ""
        new, ok = QInputDialog.getText(self, self.tr("Rename Field"), self.tr("New name:"), text=old)
        if not ok or not new.strip(): return
        self.schema["categories"][idx]["fields"][r]["label"] = new.strip()
        self.mark_dirty(); self._load_fields_for_selected(idx)
        cb = getattr(self, "_on_schema_saved", None)
        if callable(cb): 
            try: cb()
            except Exception: pass

    def _move_field_up(self): self._move_field(-1)
    def _move_field_down(self): self._move_field(1)

    def _move_field(self, delta: int):
        cat, idx = self._current_cat()
        if idx < 0: return
        r = self.fields.currentRow()
        if r < 0: return
        fields = self.schema["categories"][idx]["fields"]
        new_idx = r + delta
        if 0 <= new_idx < len(fields):
            fields.insert(new_idx, fields.pop(r))
            self.mark_dirty(); self._load_fields_for_selected(idx)
            self.fields.selectRow(new_idx)
            cb = getattr(self, "_on_schema_saved", None)
            if callable(cb): 
                try: cb()
                except Exception: pass

    # -------- schema maintenance --------
    def reset_defaults(self):
        try:
            self.schema = _build_schema_from_defaults()
            self.mark_dirty(); self._refresh_lists()
            cb = getattr(self, "_on_schema_saved", None)
            if callable(cb): 
                try: cb()
                except Exception: pass
            QMessageBox.information(self, self.tr("Defaults Restored"), self.tr("Category schema has been reset to defaults."))
        except Exception as e:
            QMessageBox.critical(self, self.tr("Reset Failed"), self.tr("Could not reset defaults") + f":\n{e}")

    def backup_schema(self):
        try:
            ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        except Exception:
            ts = "backup"
        default_name = f"category_schema.{ts}.json"
        path, _ = QFileDialog.getSaveFileName(self, self.tr("Save Category Schema Backup"), default_name, self.tr("JSON Files (*.json);;All Files (*)"))
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.schema, f, indent=2)
            QMessageBox.information(self, self.tr("Backup Saved"), self.tr("Saved schema backup to") + f":\n{path}")
        except Exception as e:
            QMessageBox.critical(self, self.tr("Backup Failed"), self.tr("Could not save schema backup") + f":\n{e}")


    def restore_schema(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            self.tr("Restore Category Schema"),
            "",
            self.tr("JSON Files (*.json);;All Files (*)"),
        )
        if not path:
            return

        # --- Warn the user before actually restoring ------------------------------
        warn_text = self.tr(
            "Restoring a category schema will change how your vault entries are "
            "interpreted.\n\n"
            "• If a field name in the new schema does not match the old name, the "
            "existing data for that field will not be shown in the table. It is NOT "
            "deleted – it will reappear if you restore a schema that uses the original "
            "field name.\n"
            "• If you are restoring a schema mainly to change the language, it is "
            "strongly recommended to do this on an empty vault. Otherwise many fields "
            "may not match and large parts of your data may appear hidden.\n\n"
            "Do you want to continue and restore the schema from this file?"
        )

        choice = QMessageBox.warning(
            self,
            self.tr("Confirm Schema Restore"),
            warn_text,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if choice != QMessageBox.Yes:
            return

        # --- Perform the restore ---------
        try:
            # utf-8-sig handles files with or without a BOM
            with open(path, "r", encoding="utf-8-sig") as f:
                data = json.load(f)

            if not isinstance(data, dict) or not isinstance(data.get("categories"), list):
                raise ValueError(
                    self.tr("Selected file does not look like a Keyquorum category schema JSON.")
                )

            _normalize_schema_inplace(data)
            self.schema = data
            self.mark_dirty()
            self._refresh_lists()

            cb = getattr(self, "_on_schema_saved", None)
            if callable(cb):
                try:
                    cb()
                except Exception:
                    pass

            QMessageBox.information(
                self,
                self.tr("Schema Restored"),
                self.tr("Category schema has been restored from backup."),
            )

        except Exception as e:
            QMessageBox.critical(
                self,
                self.tr("Restore Failed"),
                self.tr("Could not restore schema") + f":\n{e}",
            )


    # ---------- misc helpers ----------
    def _find_host_with(self, *attrs):
        w = self.parent()
        try:
            while w is not None:
                if all(hasattr(w, a) for a in attrs):
                    return w
                w = w.parent()
        except Exception:
            return None
        return None

    def _current_cat(self) -> Tuple[Optional[Dict[str, Any]], int]:
        idx = self.catList.currentRow()
        if idx is None or idx < 0 or idx >= len(self.schema.get("categories", [])):
            return None, -1
        return self.schema["categories"][idx], idx

    def repair_category_schema(self):
        """
        Scan the vault for ALL fields used across entries.
        Compare to the user's category schema.
        Add any missing fields to the correct categories.
        """
        try:
            from vault_store.vault_store import load_vault
            canonical = (self._uname or "").strip()
            if not canonical:
                QMessageBox.information(self, self.tr("No User"), self.tr("No active user to repair schema for."))
                return

            # --- FIX: vault key from parent ---
            # Correct method: find the real MainWindow that has core_session_handle
            host = self._find_host_with("core_session_handle")
            if host is None:
                QMessageBox.critical(self, self.tr("Error"), self.tr("Cannot find vault host."))
                return

            key = getattr(host, "core_session_handle", None)
            if not key:
                QMessageBox.critical(self, self.tr("Error"), self.tr("No vault key available. Please ensure vault is loaded."))
                return


            if not key:
                QMessageBox.critical(self, self.tr("Error"), self.tr("No vault key available. Please ensure vault is loaded."))
                return

            vault = load_vault(canonical, key) or []

            schema = load_schema_for(canonical)
            #vault = load_vault(canonical) or []
            if not isinstance(schema, dict):
                return

            changed = False

            # Build quick lookup
            cat_map = {}
            for c in schema.get("categories", []):
                cat_map[c["name"]] = c

            # Scan every entry
            for entry in vault:
                cat = (entry.get("Category") or "").strip()
                if not cat:
                    continue

                if cat not in cat_map:
                    # category exists in vault but not in schema
                    schema.setdefault("categories", []).append({
                        "name": cat,
                        "fields": [],
                    })
                    cat_map[cat] = schema["categories"][-1]
                    changed = True

                # Now check fields
                sc_fields = {f["label"] for f in cat_map[cat].get("fields", [])}

                for k in entry.keys():
                    if k in ("Category", "Trash", "Deleted", "uuid"):  # ignore system keys
                        continue

                    if k not in sc_fields:
                        # Add missing field
                        cat_map[cat].setdefault("fields", []).append({
                            "label": k,
                            "sensitive": False,
                            "url": False,
                            "file_load": False,   # <-- use file_load, not "file"
                            "required": False,
                        })
                        changed = True

            if changed:
                save_full_schema_dict_for(canonical, schema)
                QMessageBox.information(
                    self,
                    self.tr("Schema Updated"),
                    self.tr("Missing fields were added back from your vault.")
                )
            else:
                QMessageBox.information(
                    self,
                    self.tr("No Issues Found"),
                    self.tr("Schema already matches all vault entries.")
                )

        except Exception as e:
            log.error(f"[RepairSchema] failed: {e}")
            QMessageBox.critical(self, self.tr("Error"), self.tr("Repair failed") + f":\n{e}")

# ==============================
# External helpers used by MainWindow (unchanged signatures)
# ==============================

def _fmt_now():
    from datetime import datetime
    return datetime.now().strftime("%H:%M:%S")

def _read_auto_save_default():
    s = QSettings("AJHSoftware", "Keyquorum")
    return s.value("categoryEditor/autoSave", True, type=bool)

def _write_auto_save_default(val: bool):
    s = QSettings("AJHSoftware", "Keyquorum")
    s.setValue("categoryEditor/autoSave", bool(val))

def table_category_counts(self, cat_col_name: str = "Category", cat_col_index: int | None = None) -> dict:
    counts = {}
    try:
        table = getattr(self, "vaultTable", None)
        if table is None: return counts
        if cat_col_index is None:
            headers = [(table.horizontalHeaderItem(c).text() if table.horizontalHeaderItem(c) else "") for c in range(table.columnCount())]
            if cat_col_name not in headers:
                return counts
            cat_idx = headers.index(cat_col_name)
        else:
            cat_idx = int(cat_col_index)
        for r in range(table.rowCount()):
            it = table.item(r, cat_idx)
            cat = it.text().strip() if it else ""
            if cat:
                counts[cat] = counts.get(cat, 0) + 1
    except Exception as e:
        log.error(f"[CAT] table_category_counts failed: {e}")
    return counts

def rebuild_category_filter(self, show_empty: bool = False) -> None:
    """
    Rebuild the category filter dropdown for the active user.
    """
    try:
        canonical = ""
        uname = ""
        if hasattr(self, "currentUsername") and hasattr(self.currentUsername, "text"):
            uname = (self.currentUsername.text() or "").strip()
        if uname:
            canonical = find_user(uname) or uname

        if canonical:
            data = get_user_setting(canonical, "category_schema")
            if not (isinstance(data, dict) and isinstance(data.get("categories"), list)):
                data = load_schema_for(canonical)
        else:
            data = default_category_schema()

        schema_cats: List[str] = []
        for c in data.get("categories", []):
            nm = (c.get("name") or "").strip()
            if not nm or c.get("hidden"):
                continue
            schema_cats.append(nm)
    except Exception:
        schema_cats = []  # type: ignore

    counts = table_category_counts(self)
    ordered = list(schema_cats)
    if not show_empty:
        ordered = [c for c in ordered if counts.get(c, 0) > 0]

    combo = getattr(self, "categoryFilterCombo", None) or getattr(self, "categoryFilter", None)
    if not combo:
        return
    combo.blockSignals(True)
    try:
        combo.clear()
        combo.addItem("All")
        for c in ordered:
            combo.addItem(c)
    finally:
        combo.blockSignals(False)

def cleanup_orphan_categories(self, fallback: str = "Uncategorized") -> int:
    """
    Move entries whose category is no longer in the user's schema into `fallback`.
    """
    changed = 0
    try:
        canonical = ""
        if hasattr(self, "currentUsername") and hasattr(self.currentUsername, "text"):
            uname = (self.currentUsername.text() or "").strip()
            if uname:
                canonical = find_user(uname) or uname

        schema: dict = load_schema_for(canonical) if canonical else default_category_schema()
        schema_names = {c.get("name") for c in schema.get("categories", [])}
        table = getattr(self, "vaultTable", None)
        if table is None:
            return 0
        # Ensure fallback exists
        if fallback not in schema_names:
            schema.setdefault("categories", []).append({"name": fallback, "fields": []})
            if canonical:
                save_full_schema_dict_for(canonical, schema)
            schema_names.add(fallback)

        # Identify category column
        headers = [(table.horizontalHeaderItem(c).text() if table.horizontalHeaderItem(c) else "") for c in range(table.columnCount())]
        if "Category" not in headers:
            return 0
        cat_idx = headers.index("Category")

        # Move rows
        for r in range(table.rowCount()):
            it = table.item(r, cat_idx)
            if not it:
                continue
            cur = (it.text() or "").strip()
            if cur and cur not in schema_names:
                it.setText(fallback)
                changed += 1

        # Persist table modifications
        for meth in ("save_vault", "save_vault_table", "persist_table_to_vault", "save_current_vault"):
            if hasattr(self, meth):
                try:
                    getattr(self, meth)()
                    break
                except Exception as e:
                    log.error(f"[CAT] {meth} failed after orphan cleanup: {e}")
    except Exception as e:
        log.error(f"[CAT] cleanup_orphan_categories failed: {e}")
    return changed

def refresh_category_dependent_ui(self) -> None:
    """
    Rebuild views that depend on the active user's category schema.
    """
    try:
        if hasattr(self, "load_vault_table"):
            self.load_vault_table()
    except Exception as e:
        log.error(f"[CAT] load_vault_table during refresh failed: {e}")

    try:
        rebuild_category_filter(self, show_empty=False)
    except Exception as e:
        log.error(f"[CAT] rebuild_category_filter failed: {e}")

    try:
        if hasattr(self, "refresh_add_entry_categories"):
            self.refresh_add_entry_categories()
    except Exception as e:
        log.error(f"[CAT] refresh_add_entry_categories failed: {e}")

def migrate_entries(self, source: str, target: str) -> int:
    changed = 0
    try:
        table = getattr(self, "vaultTable", None)
        if table is None: return 0
        headers = [(table.horizontalHeaderItem(c).text() if table.horizontalHeaderItem(c) else "") for c in range(table.columnCount())]
        if "Category" not in headers:
            log.debug("[CAT] migrate_entries: no 'Category' column; skipping.")
            return 0
        cat_idx = headers.index("Category")
        for r in range(table.rowCount()):
            it = table.item(r, cat_idx)
            if it and it.text().strip() == source:
                it.setText(target); changed += 1
        for meth in ("save_vault", "save_vault_table", "persist_table_to_vault", "save_current_vault"):
            if hasattr(self, meth):
                try: getattr(self, meth)(); break
                except Exception as e: log.error(f"[CAT] {meth} failed after migration: {e}")
        if hasattr(self, "load_vault_table"):
            try: self.load_vault_table()
            except Exception as e: log.error(f"[CAT] reload after migrate failed: {e}")
    except Exception as e:
        log.error(f"[CAT] migrate_entries failed: {e}")
    return changed

def _resolve_edit_tab(self) -> QWidget | None:
    try:
        sw = getattr(self, "stackedWidget", None)
        if isinstance(sw, QStackedWidget):
            named = sw.findChild(QWidget, "categoryEditorPage")
            if named is not None:
                return named
            if sw.count() > 6:
                return sw.widget(6)
    except Exception:
        pass

    tab = getattr(self, "editAddCategoryTab", None)
    if tab:
        return tab

    try:
        tabs: QTabWidget | None = getattr(self, "mainTabs", None)
        if tabs and tabs.count() > 0:
            for i in range(tabs.count()):
                if "category" in (tabs.tabText(i) or "").lower():
                    return tabs.widget(i)
        if tabs:
            return tabs.currentWidget()
    except Exception:
        pass
    return None

def show_category_editor(self, uname: str):
    """
    Ensure the editor exists and navigate to it. Pass uname from MainWindow.
    """
    self.init_category_editor_tab(uname)

    try:
        from qtpy.QtWidgets import QStackedWidget
        sw = getattr(self, "stackedWidget", None)
        host = getattr(self, "categoryEditor", None)
        if isinstance(sw, QStackedWidget) and host is not None:
            page = host.parentWidget()
            if page is not None:
                idx = sw.indexOf(page)
                if idx >= 0:
                    sw.setCurrentIndex(idx)
    except Exception:
        pass

def patch_mainwindow_class(MainWindowCls):
    """
    Attach helpers to your MainWindow class. Call once at app start.
    """
    if getattr(MainWindowCls, "__categories_patched__", False):
        return
    setattr(MainWindowCls, "__categories_patched__", True)

    MainWindowCls.table_category_counts = table_category_counts
    MainWindowCls.rebuild_category_filter = rebuild_category_filter
    MainWindowCls.refresh_category_dependent_ui = refresh_category_dependent_ui
    MainWindowCls.migrate_entries = migrate_entries
    MainWindowCls.cleanup_orphan_categories = cleanup_orphan_categories
    MainWindowCls.show_category_editor = show_category_editor

    def _init_category_editor_tab(self, uname: str):
        tab = _resolve_edit_tab(self)
        if tab is None:
            log.debug("[CAT] init_category_editor_tab: could not resolve editor tab")
            return

        layout = tab.layout()
        if layout is None:
            layout = QVBoxLayout(tab)
            tab.setLayout(layout)

        try:
            while layout.count():
                item = layout.takeAt(0)
                w = item.widget()
                if w is not None:
                    w.setParent(None)
        except Exception as e:
            log.error(f"[CAT] clearing placeholder widgets failed: {e}")

        if getattr(self, "categoryEditor", None) is None:
            self.categoryEditor = CategoryEditor(
                tab,
                uname=uname,
                on_schema_saved=self._on_editor_schema_saved if hasattr(self, "_on_editor_schema_saved") else None,
                get_category_usage=getattr(self, "table_category_counts", None),
            )
        layout.addWidget(self.categoryEditor)

        try:
            if hasattr(self, "_on_editor_schema_saved"):
                self._on_editor_schema_saved()
        except Exception as e:
            log.error(f"[CAT] post editor init refresh failed: {e}")

        try:
            self.refresh_category_dependent_ui()
        except Exception:
            pass

    MainWindowCls.init_category_editor_tab = _init_category_editor_tab

mount_category_editor_tab = patch_mainwindow_class
