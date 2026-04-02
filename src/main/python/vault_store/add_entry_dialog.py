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

"""Module for vault store functionality.

This file is part of the Keyquorum Vault codebase.
"""

import logging
log = logging.getLogger("keyquorum")

from qtpy.QtWidgets import (
    QDialog, QLabel, QLineEdit, QFileDialog, QVBoxLayout, QHBoxLayout,
    QPushButton, QRadioButton, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QCompleter)

from qtpy.QtCore import Qt
from qtpy.QtCore import QStringListModel
import json, hashlib, os, re
import datetime as dt
import sys

# --- optional QR decoder (OpenCV) ---
try:
    import cv2  
except Exception:
    cv2 = None  

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("add_entry_dialog", text)

# translat helpers
from app.app_translation_fields import PLATFORM_LABELS, INSTALL_LINK_LABELS, EMAIL_LABELS, PRIMARY_PASSWORD_LABELS

# Fallback defaults only (used if parent doesn't provide a user-edited guide)
from catalog_category.my_catalog_builtin import PLATFORM_GUIDE as DEFAULT_PLATFORM_GUIDE

PLATFORM_GUIDE = (_tr(
    "Select the platform, launcher, or utility this entry belongs to.\n\n"
    "For example:\n"
    "• Steam, Epic Games, EA App, Ubisoft Connect, Battle.net\n"
    "• Xbox / Microsoft Store, GOG, Riot Client, Itch.io\n"
    "• Or PC utilities like NVIDIA App, AMD Auto-Detect, Intel DSA\n\n"
    "Keyquorum can detect or open supported apps directly.\n"
    "If a launcher isn’t installed, the 'Install' link will open the official download page.")
)

def _effective_platform_guide(parent) -> dict:
    try:
        guide = getattr(parent, "PLATFORM_GUIDE", None)
        if isinstance(guide, dict) and guide:
            return guide  # ← user-edited (file) version
    except Exception:
        pass
    return dict(DEFAULT_PLATFORM_GUIDE)  # fallback to built-ins

def _effective_aliases(parent) -> dict:
    try:
        aliases = getattr(parent, "ALIASES", None)
        if isinstance(aliases, dict) and aliases:
            return aliases
    except Exception:
        pass
    try:
        from catalog_category.my_catalog_builtin import ALIASES as DEFAULT_ALIASES
        return dict(DEFAULT_ALIASES)
    except Exception:
        return {}

# -------------------- Optional integrations (soft imports) --------------------
try:
    # Async breach worker; expected to emit a signal or expose .result
    from features.breach_check.breach_checker import BreachCheckWorker  
except Exception:
    BreachCheckWorker = None  

try:
    # User/category schema helpers (optional); we provide fallbacks below
    #   remove fall back and add to user database from create account
    from catalog_category.category_fields import (
        get_field_meta_for,
        get_fields_for,
        preferred_url_fields,
        sensitive_data_values,
        file_load_values,
        hide_values,
        showprefiled,
        required_fields,
    )  
except Exception:
    get_field_meta_for = None  
    def get_fields_for(category): return ["Title", "Username", "Password", "Website", "Phone Number", "2FA Enabled", "TOTP Secret", "Notes"]
    def preferred_url_fields(category): return ["Website"]
    def sensitive_data_values(): return ["Password", "TOTP Secret", "Recovery Codes", "Private Key", "Secret"]
    def file_load_values(): return ["Recovery Codes"]
    def hide_values(): return ["TOTP Secret", "Private Key", "Secret"]
    def showprefiled(): return ["games", "app", "software", "social media"]

# ------------------------- Breach cache utilities -----------------------------
from app.paths import breach_cache, config_dir

def _cache_path(username) -> str:
    return breach_cache(username, ensure_dir=True)

def load_breach_cache(username) -> dict:
    try:
        p = _cache_path(username)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        log.info(f"[BCACHE] Error {e}")
        pass
    return {}

def save_breach_cache(username, cache: dict):
    try:
        with open(_cache_path(username), "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        log.error(' '.join(map(str, ("[BCACHE] [⚠️] Failed to save breach cache:", e))))

def sha1_password(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

# --------------------------- Schema meta helpers ------------------------------
def _normalize_field_dict(d: dict) -> dict:
    label = (d.get("label") or d.get("name") or "").strip()
    if not label:
        return {}
    return {
        "label": label,
        "sensitive": bool(d.get("sensitive") or d.get("hide")),
        "file_load": bool(d.get("file_load")),
        "hide": bool(d.get("hide")),
        "url": bool(d.get("url")),
        "required": bool(d.get("required")),   # <-- PRESERVE REQUIRED
        "is_reminder_field": bool(d.get("is_reminder_field")),
        "placeholder": d.get("placeholder", ""),
    }

def _user_schema_meta(parent, category: str, uname: str):
    """Read a per-user category schema stored in user_db (if available)."""
    try:
        from auth.login.login_handler import get_user_setting  
    except Exception as e:
        log.debug(str(f"[UI ADD] [⚠️]  User schema unavailable: {e}"))
        return []

    canonical = uname
    schema = get_user_setting(canonical, "category_schema", None)
    if not isinstance(schema, dict):
        return []

    target = None
    for c in schema.get("categories", []):
        try:
            if isinstance(c, dict) and str(c.get("name","")).strip().lower() == category.strip().lower():
                target = c; break
        except Exception:
            continue
    if not target:
        return []

    out = []
    for f in target.get("fields", []):
        if isinstance(f, dict):
            nf = _normalize_field_dict(f)
            if nf: out.append(nf)
        elif isinstance(f, str):
            out.append({"label": f.strip(), "sensitive": False, "file_load": False,
                        "hide": False, "url": False, "required": False, "is_reminder_field": False, "placeholder": ""})
    return out

def _module_schema_meta(category: str):
    try:
        if callable(get_field_meta_for):  
            raw = get_field_meta_for(category) or []
            out = []
            for f in raw:
                if isinstance(f, dict):
                    nf = _normalize_field_dict(f)
                    if nf: out.append(nf)
            return out
    except Exception:
        pass
    return []

def resolve_field_meta(parent, category: str, user: str):
    meta = _user_schema_meta(parent, category, user)
    if meta: return meta

    meta = _module_schema_meta(category)
    if meta: return meta

    # --- Fallback: build from simple lists
    sens = {s.lower() for s in sensitive_data_values()}
    files = {s.lower() for s in file_load_values()}
    hidden = {s.lower() for s in hide_values()}
    urls = {s.lower() for s in preferred_url_fields(category)}  # your existing URL prefs

    out = []
    for label in get_fields_for(category):
        low = label.lower()
        is_url = (low in urls)
        out.append({
            "label": label,
            "sensitive": (low in sens) or any(k in low for k in ("password","key","cvv","account number","private","recovery","secret")),
            "file_load": low in files,
            "hide": low in hidden,
            "url": is_url,
            "required": is_url,   # <-- fallback: treat URL-pref fields as required by default
            "is_reminder_field": False,
            "placeholder": "",
        })
    return out

# ------------------------- Password history dialog ----------------------------
class PasswordHistoryDialog(QDialog):
    def __init__(self, history_list, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Password History"))
        self.setMinimumWidth(480)

        # keep raw history so we can fetch the full hash on restore
        self._history = self._normalize(history_list)

        layout = QVBoxLayout(self)

        # table
        self.table = QTableWidget(len(self._history), 3, self)
        self.table.setHorizontalHeaderLabels(["When", "Days ago", "Hash (first 10)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._fill_table()

        layout.addWidget(self.table)

        # buttons row
        buttons = QHBoxLayout()
        self.btnRestore = QPushButton(self.tr("Restore"))
        self.btnRestore.clicked.connect(self._restore_selected)
        btnClose = QPushButton(self.tr("Close"))
        btnClose.clicked.connect(self.accept)
        buttons.addStretch(1)
        buttons.addWidget(self.btnRestore)
        buttons.addWidget(btnClose)
        layout.addLayout(buttons)

    # ---- internals -------

    def _parse_iso(self, ts: str):
        if not ts:
            return None
        try:
            return dt.datetime.fromisoformat(ts.replace("Z", ""))
        except Exception:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    return dt.datetime.strptime(ts, fmt)
                except Exception:
                    pass
        return None

    def _normalize(self, history_list):
        """Return list of dicts with keys: ts, hash (keep full), days, entry_id."""
        out = []
        now = dt.datetime.now()
        for h in (history_list or []):
            if not isinstance(h, dict):
                continue
            ts = str(h.get("ts") or h.get("time") or "")
            full_hash = str(h.get("hash") or h.get("fp") or "")
            entry_id = str(h.get("entry_id") or h.get("id") or h.get("_id") or h.get("row_id") or "")
            d = self._parse_iso(ts)
            days = (now - d).days if d else ""
            out.append({"ts": ts, "hash": full_hash, "days": days, "entry_id": entry_id})
        # newest first
        try:
            out.sort(key=lambda r: self._parse_iso(r["ts"]) or dt.datetime.min, reverse=True)
        except Exception:
            pass
        return out

    def _fill_table(self):
        for r, rec in enumerate(self._history):
            ts = rec["ts"]
            days = rec["days"]
            h10 = rec["hash"][:10]
            self.table.setItem(r, 0, QTableWidgetItem(ts))
            self.table.setItem(r, 1, QTableWidgetItem("" if days == "" else str(days)))
            self.table.setItem(r, 2, QTableWidgetItem(h10))
        if self._history:
            self.table.selectRow(0)

    def _restore_selected(self):
        try:
            row = self.table.currentRow()
            if row < 0 or row >= len(self._history):
                return

            rec = dict(self._history[row] or {})
            # Hand off to the parent dialog (AddEntryDialog) to perform the restore.
            # Pass the full record so the parent can use the entry_id that was stored
            # alongside the visible hash/timestamp row.
            par = self.parent()
            if par and hasattr(par, "_restore_password_from_history"):
                par._restore_password_from_history(rec)
                self.accept()
            else:
                QMessageBox.information(
                    self, self.tr("Restore"),
                    self.tr("Restore handler not available in parent dialog.")
                )
        except Exception as e:
            log.error(f"[PW] Error On Restore {e}")

# ------------------------------- Dialog class --------------------------------
class AddEntryDialog(QDialog):
    """
    Fresh, self-contained Add Entry dialog.
    Compatible with calls like:
        AddEntryDialog(self, category, self.enable_breach_checker)
        AddEntryDialog(self, entry.get("category", "..."))
        AddEntryDialog(self, category=current_category)
    """
    def __init__(self, parent=None, category=None, enable_breach_checker=True, existing_entry=None, user=None, is_dev=False, *args, **kwargs):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Add Entry"))
        self.setMinimumWidth(460)
        self.user = user
        self.is_dev = is_dev
        # Positional compatibility
        # If caller passed (self, category, enable_breach_checker) positionally, map them.
        if "category" in kwargs and isinstance(kwargs["category"], str):
            category = kwargs["category"]
        # Handle the case AddEntryDialog(self, entry.get("category", ...)) where 3rd arg is missing
        if len(args) >= 1 and isinstance(args[0], str):
            category = args[0]
        if len(args) >= 2 and isinstance(args[1], bool):
            enable_breach_checker = args[1]

        self.category = category 
        self._guide   = _effective_platform_guide(parent)
        self._aliases = _effective_aliases(parent)
        self.enable_breach_checker = bool(enable_breach_checker)
        self.existing_entry = existing_entry if isinstance(existing_entry, dict) else None

        self.fields: dict[str, QLineEdit | QRadioButton] = {}
        self.passwordField: QLineEdit | None = None
        self._meta = []        # resolved field meta
        self._breachWorker = None
        self._pending_entry = None
        self._last_entry = None

        layout = QVBoxLayout(self)

        # Build dynamic fields from schema meta
        meta = resolve_field_meta(parent, self.category, self.user)
        self._meta = meta or []

        def add_line(label, placeholder="", password=False, file_select=False, preset="", is_reminder_field=False):
            """
            Renders a single input row.
            - If password==True AND this is the *primary* Password field, show:
                👁 toggle + 🔐 generator + 📜 history + Strength meter
            - For other sensitive fields (e.g., Backup Code, TOTP Secret), show only 👁 toggle.
            - If category == 'Games' AND label == 'Platform': add autocomplete + help button.
            """
            row = QHBoxLayout()
            layout.addWidget(QLabel(label))

            edit = QLineEdit()

            def _set_date_via_prompt(target_edit: QLineEdit):
                # Lightweight date picker (YYYY-MM-DD) to avoid heavy UI changes.
                # (We can swap to QCalendarWidget later if you want.)
                from qtpy.QtWidgets import QInputDialog
                cur = (target_edit.text() or "").strip()
                default = cur if cur else dt.datetime.now().strftime("%Y-%m-%d")
                val, ok = QInputDialog.getText(
                    self,
                    self.tr("Reminder Date"),
                    self.tr("Enter date (YYYY-MM-DD):"),
                    text=default
                )
                if not ok:
                    return
                v = (val or "").strip()
                if not v:
                    target_edit.setText("")
                    return
                try:
                    dt.datetime.strptime(v, "%Y-%m-%d")
                except Exception:
                    QMessageBox.warning(
                        self,
                        self.tr("Invalid Date"),
                        self.tr("Please enter a valid date in the format YYYY-MM-DD.")
                    )
                    return
                target_edit.setText(v)

            if placeholder:
                edit.setPlaceholderText(placeholder)
            if preset:
                edit.setText(preset)

            # Context for Games, app, software -> Platform enhancements
            #is_games = str(self.category).strip().lower() in showprefiled
            prefs = set(x.strip().lower() for x in showprefiled() or [])
            is_games = (str(self.category or "").strip().lower() in prefs)
            lab = label.strip().lower()
            is_platform_label = lab in PLATFORM_LABELS
            is_install_link = lab in INSTALL_LINK_LABELS            
            is_primary_password = password and (label.strip().lower() in PRIMARY_PASSWORD_LABELS)
            is_primary_password = password and (label.strip().lower() == "password")

            if password:
                # Always allow show/hide
                edit.setEchoMode(QLineEdit.EchoMode.Password)
                toggle_btn = QPushButton("👁")
                toggle_btn.setFixedWidth(60)

                def toggle_echo():
                    if edit.echoMode() == QLineEdit.EchoMode.Password:
                        edit.setEchoMode(QLineEdit.EchoMode.Normal)
                        toggle_btn.setText("🙈")
                    else:
                        edit.setEchoMode(QLineEdit.EchoMode.Password)
                        toggle_btn.setText("👁")

                toggle_btn.clicked.connect(toggle_echo)

                # Row always contains the edit and the toggle
                row.addWidget(edit)
                row.addWidget(toggle_btn)

                if is_primary_password:
                    # Only for the real Password field:
                    gen_btn = QPushButton("🔐")
                    gen_btn.setStyleSheet("")  # note
                    gen_btn.setFixedWidth(60)

                    def open_generator():
                        try:
                            from auth.pw.password_generator import show_password_generator_dialog  
                            return show_password_generator_dialog(target_field=edit, confirm_field=None)
                        except Exception:
                            import secrets, string
                            alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,./?"
                            pw = "".join(secrets.choice(alphabet) for _ in range(20))
                            edit.setText(pw)

                    gen_btn.clicked.connect(open_generator)

                    hist_btn = QPushButton("📜")
                    hist_btn.setFixedWidth(60)
                    hist_btn.setStyleSheet("")  # note
                    hist_btn.setToolTip(self.tr("View password history for this entry"))
                    hist_btn.clicked.connect(self._on_show_history)

                    row.addWidget(gen_btn)
                    row.addWidget(hist_btn)
                    layout.addLayout(row)

                    # Strength meter only for main Password
                    try:
                        strength = QLabel(self.tr("Strength: "))
                        layout.addWidget(strength)

                        def on_pw_changed(text):
                            try:
                                from auth.pw.password_utils import get_password_strength  
                                score, _, info = get_password_strength(text)
                                strength.setText(self.tr("Strength: {info}").format(info=info))
                                color = ("green" if score >= 4 else
                                         "darkorange" if score == 3 else
                                         "orange" if score == 2 else
                                         "red" if score == 1 else
                                         "darkred")
                                strength.setStyleSheet(f"color: {color}; font-weight: bold;")
                            except Exception:
                                pass

                        edit.textChanged.connect(on_pw_changed)
                    except Exception:
                        pass
                else:
                    # For sensitive non-Password fields (Backup Code, TOTP Secret, etc.)
                    # No generator, no history, no strength meter.
                    layout.addLayout(row)

            elif file_select:
                browse_btn = QPushButton("📁")
                browse_btn.setFixedWidth(60)

                def choose_file():
                    path, _ = QFileDialog.getOpenFileName(self, self.tr("Select ") + f"{label}", "", self.tr("All Files (*)"))
                    if path:
                        edit.setText(path)

                browse_btn.clicked.connect(choose_file)
                row.addWidget(edit)
                row.addWidget(browse_btn)
                layout.addLayout(row)

            else:
                # Normal (non-password, non-file) field
                #if is_games and is_platform_label:
                if is_platform_label:
                    # Provide autocomplete + inline help for platform keywords
                    guide = self._guide

                    # Helpful placeholder if one not already provided
                    if not placeholder:
                        edit.setPlaceholderText(self.tr("e.g. steam, epic, uplay... (Install / Open / AutoFill)"))

                    try:
                        from qtpy.QtWidgets import QCompleter
                        keys = sorted(set(list(guide.keys()) + list(self._aliases.keys())))
                        comp = QCompleter(keys); comp.setCaseSensitivity(Qt.CaseInsensitive)
                        edit.setCompleter(comp)
                    except Exception:
                        pass

                    # Help button
                    help_btn = QPushButton("❓")
                    help_btn.setFixedWidth(60)
                    help_btn.setToolTip(self.tr("Show supported platform names"))

                    def _show_platform_help():
                        msg = "\n".join(f"{k} — {v}" for k, v in self._guide.items())
                        try:
                            QMessageBox.information(
                                self, self.tr("Game Platform Keywords"),
                                self.tr("Use one of the following values in the Platform field for Install / Open:\n\n") + f"{msg}"
                            )
                        except Exception:
                            log.info("[Game Platforms] Keywords: %s", msg)

                    # Prefer a richer handler if the class has one
                    if hasattr(self, "on_platform_help_clicked"):
                        help_btn.clicked.connect(self.on_platform_help_clicked)
                    else:
                        help_btn.clicked.connect(_show_platform_help)

                    row.addWidget(edit)
                    row.addWidget(help_btn)
                    layout.addLayout(row)
                

                
                else:
                    # NEW: clarify "Install Link" as a fallback
                    if is_install_link:
                        edit.setPlaceholderText(
                            self.tr("Optional direct installer/site URL — used if Catalog Install/Open is missing or fails")
                        )
                        edit.setToolTip(self.tr(
                            "Fallback link. If your Catalog entry doesn't have an installer/exe "
                            "or launching fails, Keyquorum will open this URL to help you install.")
                        )
                    # If this field is marked as a reminder field, show a date-picker button
                    if is_reminder_field or (label or '').strip().lower() in ('reminder', 'reminder date', 'reminder_date'):
                        cal_btn = QPushButton("📅")
                        cal_btn.setFixedWidth(60)
                        cal_btn.setToolTip(self.tr("Set reminder date"))
                        cal_btn.clicked.connect(lambda _=None, e=edit: _set_date_via_prompt(e))
                        row.addWidget(edit)
                        row.addWidget(cal_btn)
                        layout.addLayout(row)
                    else:
                        layout.addWidget(edit)

            self.fields[label] = edit
            if label.lower() == "password":
                self.passwordField = edit

        # Render fields from meta (treat 'hide' as sensitive)
        for f in self._meta:
            label = f.get("label", "").strip() or "Field"
            is_sensitive = bool(f.get("sensitive") or f.get("hide"))
            if label.lower() == "2fa enabled":
                layout.addWidget(QLabel(self.tr("2FA Enabled")))
                radio_row = QHBoxLayout()
                self.radio_yes = QRadioButton(self.tr("Yes"))
                self.radio_no = QRadioButton(self.tr("No"))
                self.radio_no.setChecked(True)
                radio_row.addWidget(self.radio_yes)
                radio_row.addWidget(self.radio_no)
                layout.addLayout(radio_row)
                self.fields["2FA Enabled"] = self.radio_yes
                continue

            preset = ""
            if isinstance(self.existing_entry, dict):
                preset = str(self.existing_entry.get(label, ""))

            add_line(
                label,
                placeholder=f.get("placeholder", ""),
                password=is_sensitive,
                file_select=bool(f.get("file_load")),
                preset=preset,
                is_reminder_field=bool(f.get("is_reminder_field")),
            )

        # --- attach encrypted email suggestions to ALL Email fields ---
        self._setup_email_completers_for_all()

        # Buttons
        btns = QHBoxLayout()
        self.save_btn = QPushButton(self.tr("Save"))
        scan_btn = QPushButton(self.tr("Scan QR"))  # NEW
        scan_btn.hide()
        cancel_btn = QPushButton(self.tr("Cancel"))
        btns.addWidget(self.save_btn)
        btns.addWidget(scan_btn)           # NEW
        btns.addWidget(cancel_btn)
        layout.addLayout(btns)

        # Dev testing helper (optional) # add if dev ?
        if self.is_dev:
            def fill_test_data():
                try:
                    from random import randint
                    for label, field in self.fields.items():
                        if isinstance(field, QRadioButton):
                            continue
                        low = label.lower()
                        if "email" in low:
                            field.setText(f"user{randint(100,999)}@example.com")
                        elif "website" in low or "site" in low or "url" in low:
                            field.setText("https://example.com")
                        elif "username" in low:
                            field.setText(f"testuser{randint(1,999)}")
                        elif "password" in low:
                            field.setText(f"P@ss{randint(1000,9999)}word!")
                        elif "key" in low:
                            field.setText(f"KEY-{randint(100000,999999)}")
                        elif "cvv" in low:
                            field.setText(f"{randint(100,999)}")
                        elif "account number" in low:
                            field.setText(f"{randint(10000000,99999999)}")
                        elif "sort code" in low:
                            field.setText("112233")
                        elif "card number" in low:
                            field.setText("4111111111111111")
                        elif "mac" in low:
                            field.setText("AA:BB:CC:DD:EE:FF")
                        elif "ip address" in low:
                            field.setText("192.168.0.1")
                        elif "ipv6" in low:
                            field.setText("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
                        elif "iban" in low:
                            field.setText("GB29NWBK60161331926819")
                        elif "bic" in low:
                            field.setText("NWBKGB2L")
                        elif "title" in low:
                            field.setText("Test Note")
                        elif "content" in low or "notes" in low:
                            field.setText("This is a test entry.")
                        else:
                            field.setText(f"Test {label}")
                except Exception as e:
                    log.debug(str(f"[UI ADD DEV True] fill test data failed: {e}"))
            test_btn = QPushButton("🧪 Fill Test Data")
            test_btn.setToolTip("Auto-fill fields with test data for debugging")
            test_btn.clicked.connect(fill_test_data)
            layout.addWidget(test_btn)

        # Wire buttons
        self.save_btn.clicked.connect(lambda: self._on_save_clicked(self.user))
        scan_btn.clicked.connect(self.quick_fill_from_qr)
        cancel_btn.clicked.connect(self.reject)

    
        # --------------------------- QUICK SCAN (QR) HELPERS ---------------------------
    
    def _map_share_like_dict(self, data: dict) -> dict:
        """
        Normalize a 'share-like' dict (Title/Name, Username/Email, Password, Website/URL, Notes, etc.)
        into a simple label->value map matching dialog field labels (case-insensitive).
        Only returns keys we can plausibly show here.
        """
        if not isinstance(data, dict):
            return {}
        def norm(v):
            if v is None: return ""
            if isinstance(v, (list, tuple)): return ", ".join(norm(x) for x in v)
            return str(v)

        out = {}
        # canonical keys
        if "Title" in data or "title" in data or "Name" in data or "name" in data:
            out["Title"] = norm(data.get("Title") or data.get("title") or data.get("Name") or data.get("name"))
        if "Username" in data or "username" in data or "Email" in data or "email" in data or "User" in data:
            out["Username"] = norm(data.get("Username") or data.get("username") or data.get("Email") or data.get("email") or data.get("User"))
        if "Password" in data or "password" in data or "pass" in data:
            out["Password"] = norm(data.get("Password") or data.get("password") or data.get("pass"))
        if "Website" in data or "website" in data or "URL" in data or "url" in data or "link" in data or "domain" in data:
            # de-dup website/url if same
            web = norm(data.get("Website") or data.get("website") or "")
            url = norm(data.get("URL") or data.get("url") or data.get("link") or data.get("domain") or "")
            out["Website"] = web or url
        if "Notes" in data or "notes" in data or "Description" in data or "description" in data:
            out["Notes"] = norm(data.get("Notes") or data.get("notes") or data.get("Description") or data.get("description"))

        # common extras (best-effort)
        for k in ("Phone Number","TOTP Secret","Backup Code","IMAP Server","SMTP Server"):
            for alias in (k, k.lower(), k.replace(" ", "").lower()):
                for src in (k, alias):
                    if src in data:
                        out[k] = norm(data.get(src))
                        break

        return out

    def _decode_qr_json_from_image(self, path: str) -> dict | None:
        """
        Read a QR code from an image file and parse JSON payload.
        Returns dict or None. Works only if OpenCV is available.
        """
        try:
            if cv2 is None:  # soft dependency
                return None
            img = cv2.imread(path)
            if img is None:
                return None
            det = cv2.QRCodeDetector()
            data, points, _ = det.detectAndDecode(img)
            if not data:
                return None
            obj = json.loads(data)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None

    def _extract_single_entry_from_share_obj(self, obj: dict) -> dict | None:
        """
        Accepts either:
            - plain single: {"kq_share":1, "entry": {...}}
            - plain raw entry: {"Title": "...", ...}
        (Encrypted or multi-entry QR are not handled here; use main Import for those.)
        """
        if not isinstance(obj, dict):
            return None
        # plain single packet
        if obj.get("kq_share") in (1, "1") and isinstance(obj.get("entry"), dict):
            return obj["entry"]
        # plain raw entry
        likely_keys = {"title","Title","name","Name","username","Username","email","Email","password","Password","website","Website","url","URL"}
        if any(k in obj for k in likely_keys):
            return obj
        return None

    def quick_fill_from_qr(self):
        """
        User picks an image with a QR code containing a single 'share-like' entry JSON.
        We map it to the dialog's fields and prefill empty ones. Multi/Encrypted are refused.
        """
        try:
            from qtpy.QtWidgets import QFileDialog, QMessageBox, QInputDialog
        except Exception:
            return

        # choose image
        img_path, _ = QFileDialog.getOpenFileName(self, self.tr("Scan QR (image)"), "", self.tr("Images (*.png *.jpg *.jpeg *.bmp)"))
        if not img_path:
            return

        obj = self._decode_qr_json_from_image(img_path)
        if not obj:
            QMessageBox.information(
                self,
                self.tr("Quick Scan"),
                self.tr("No QR found or invalid QR content.")
            )
            return

        entry = self._extract_single_entry_from_share_obj(obj)
        if not isinstance(entry, dict):
            QMessageBox.information(
                self,
                self.tr("Quick Scan"),
                self.tr("This QR isn’t a single share item. Use Import Share instead.")
            )
            return

        mapped = self._map_share_like_dict(entry)
        if not mapped:
            QMessageBox.information(
                self,
                self.tr("Quick Scan"),
                self.tr("Nothing to prefill from this QR.")
            )
            return

        try:
            self.prefill_from_dict(mapped)
        except Exception:
            # fallback: best-effort assignment
            for k, v in mapped.items():
                for label, w in (self.fields or {}).items():
                    if isinstance(w, QLineEdit) and label.strip().lower() == k.strip().lower():
                        if not w.text().strip():
                            w.setText(str(v))

        QMessageBox.information(
            self,
            self.tr("Quick Scan"),
            self.tr("Fields prefilled from QR (where they were empty).")
        )

    def load_emails(self) -> dict:
        from catalog_category.catalog_user import load_effective_catalogs_from_user

        par = self.parent()
        username = (getattr(par, "username", "") or par.currentUsername.text() or "").strip()
        if not username:
            return {}

        session_handle = getattr(par, "core_session_handle", None)
        if not isinstance(session_handle, int) or not session_handle:
            # Strict DLL-only: no session => no decrypted catalog access
            return {}

        # Prefer built-ins if available on the parent (main app keeps these)
        CLIENTS = getattr(par, "CLIENTS", None)
        ALIASES = getattr(par, "ALIASES", None)
        PLATFORM_GUIDE = getattr(par, "PLATFORM_GUIDE", None)
        AUTOFILL_RECIPES = getattr(par, "AUTOFILL_RECIPES", None) or getattr(self, "_BUILTIN_AUTOFILL_RECIPES", None)

        # Make sure merge bases are dicts (never None)
        if not isinstance(CLIENTS, dict): CLIENTS = {}
        if not isinstance(ALIASES, dict): ALIASES = {}
        if not isinstance(PLATFORM_GUIDE, dict): PLATFORM_GUIDE = {}
        if not isinstance(AUTOFILL_RECIPES, dict): AUTOFILL_RECIPES = {}

        ret = load_effective_catalogs_from_user(
            str(config_dir(username)),
            CLIENTS, ALIASES, PLATFORM_GUIDE,
            AUTOFILL_RECIPES,
            session_handle=session_handle,
        )

        # Support both return shapes (4 or 5)
        if isinstance(ret, tuple) and len(ret) >= 1:
            clients = ret[0]
        else:
            clients = None

        return clients if isinstance(clients, dict) else {}

    # --------------------------- UNIVERSAL EMAIL COMPLETERS -------------------
   
    def _setup_email_completers_for_all(self):
        """Attach encrypted email suggestions to all Email fields in every category."""
        try:
            clients = self.load_emails() or {}
            if not isinstance(clients, dict):
                # Show hint on all email fields
                for label, w in getattr(self, "fields", {}).items():
                    lab_lower = str(label).strip().lower()
                    if isinstance(w, QLineEdit) and (lab_lower in EMAIL_LABELS or "email" in lab_lower):
                        w.setPlaceholderText(self.tr("Config emails in Catalog for suggestions"))
                return

            all_emails = []
            for v in clients.values():
                if not isinstance(v, dict):
                    continue
                emails = v.get("emails", [])
                if isinstance(emails, list):
                    all_emails.extend(
                        e.strip() for e in emails
                        if isinstance(e, str) and e.strip()
                    )

            # dedupe + sort
            all_emails = sorted(dict.fromkeys(all_emails), key=str.lower)

            if not all_emails:
                # still hint the user
                for label, w in getattr(self, "fields", {}).items():
                    lab_lower = str(label).strip().lower()
                    if isinstance(w, QLineEdit) and (lab_lower in EMAIL_LABELS or "email" in lab_lower):
                        w.setPlaceholderText(self.tr("No catalog emails found — add them in Settings → Catalog → Emails"))
                return

            model = QStringListModel(all_emails, self)
            comp = QCompleter(model, self)
            comp.setCaseSensitivity(Qt.CaseInsensitive)
            try:
                comp.setFilterMode(Qt.MatchContains)
            except Exception:
                pass

            applied = 0
            for label, w in getattr(self, "fields", {}).items():
                lab_lower = str(label).strip().lower()
                if isinstance(w, QLineEdit) and (lab_lower in EMAIL_LABELS or "email" in lab_lower):
                    w.setCompleter(comp)
                    w.setPlaceholderText(self.tr("Start typing… (suggestions from your catalog)"))
                    w.setToolTip(self.tr("Suggestions are from your encrypted catalog emails list."))
                    applied += 1
                    log.debug("[EMAIL] Completer applied to %s field(s); %s known emails.", applied, len(all_emails))

        except Exception as e:
            log.warning("[EMAIL] Failed to attach completers: %s", e)

    # --------------------------- History helpers ---------------------------

    def on_platform_help_clicked(self):
        """
        Show platform keyword help — only when category is 'Games'.
        """
        try:
            from qtpy.QtWidgets import QMessageBox
            if str(self.category).strip().lower() != "games":
                QMessageBox.information(
                    self, self.tr("Platform Help"),
                    self.tr("Platform help is only available for the 'Games' category.")
                )
                return
            msg = "\n".join(f"{k} — {v}" for k, v in PLATFORM_GUIDE.items())
            QMessageBox.information(
                self,
                self.tr("Game Platform Keywords"),
                self.tr("Use one of the following values in the Platform field:\n\n{msg}").format(msg=msg))
        except Exception as e:
            log.warning("on_platform_help_clicked failed: %s", e)


    def _history_entry_id(self) -> str:
        """Resolve the restore-cache key for this edited entry.

        Strict DLL-only restore cache is keyed by entry id (or exact vault index as a
        last resort), not by password hash.
        """
        try:
            if isinstance(getattr(self, "existing_entry", None), dict):
                e = self.existing_entry
                entry_id = str(e.get("id") or e.get("_id") or e.get("row_id") or "").strip()
                if entry_id:
                    return entry_id
        except Exception:
            pass

        try:
            if hasattr(self, "_vault_index"):
                i = int(getattr(self, "_vault_index"))
                if i >= 0:
                    return str(i)
        except Exception:
            pass

        return ""

    def _restore_password_from_history(self, history_rec=None):
        """
        One-click restore: pull the last plaintext from the encrypted cache.

        Strict DLL-only path:
        - use the active native DLL session handle from the parent window
        - resolve the restore-cache entry by entry_id / vault index
        - do not derive or use any Python-side key fallback
        """
        par = self.parent()
        if not par:
            return

        entry_id = ""
        try:
            if isinstance(history_rec, dict):
                entry_id = str(
                    history_rec.get("entry_id")
                    or history_rec.get("id")
                    or history_rec.get("_id")
                    or history_rec.get("row_id")
                    or ""
                ).strip()
        except Exception:
            entry_id = ""

        if not entry_id:
            entry_id = self._history_entry_id()

        if not entry_id:
            QMessageBox.information(
                self,
                self.tr("Restore"),
                self.tr("This entry does not have a restore-cache id yet, so the previous password cannot be restored.")
            )
            return

        session_handle = getattr(par, "core_session_handle", None)
        if not isinstance(session_handle, int) or session_handle <= 0:
            QMessageBox.information(
                self,
                self.tr("Restore"),
                self.tr("Unlock your vault first before restoring a previous password.")
            )
            return

        try:
            from vault_store.soft_delete_ops import _pwlast_get
            username = par.currentUsername.text() if hasattr(par, "currentUsername") else ""
            pw = _pwlast_get(username, session_handle, entry_id, max_age_days=90)
            log.debug("[PW] restore lookup entry_id=%s found=%s", entry_id, bool(pw))
            if pw:
                try:
                    self.passwordField.setText(pw)
                    self.passwordField.setFocus()
                    self.passwordField.selectAll()
                except Exception as e:
                    log.error(f"[PW] Error {e}")
            else:
                QMessageBox.information(
                    self,
                    self.tr("Restore"),
                    self.tr("No recent password found to restore (older than 90 days or not cached yet).")
                )
        except Exception as e:
            log.error(f"[PW] Error {e}")

    def _pw_text(self) -> str:
        # Prefer bound password widget; fall back to fields dict
        try:
            if getattr(self, "passwordField", None):
                t = self.passwordField.text()
                if isinstance(t, str):
                    return t
        except Exception as e:
            log.error(f"[PW] Error {e}")
            pass

        f = getattr(self, "fields", {}) or {}
        for k in ("Password", "password", "pwd", "pass", "secret", "Secret"):
            w = f.get(k)
            if w and hasattr(w, "text"):
                return (w.text() or "").strip()
        return ""

    def _sha(self, s: str) -> str:
        import hashlib
        return hashlib.sha256((s or "").encode("utf-8")).hexdigest()

    def _fp_optional(self, s: str) -> str | None:
        """If parent exposes a keyed hist_key, compute HMAC fingerprint to match 'fp' entries."""
        try:
            import hmac, hashlib
            hk = getattr(self.parent(), "hist_key", None)
            if hk:
                return hmac.new(hk, (s or "").encode("utf-8"), hashlib.sha256).hexdigest()
        except Exception:
            pass
        return None

    def _days_since(self, ts: str) -> int | None:
        
        if not ts:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                t = dt.datetime.strptime(ts, fmt)
                return (dt.datetime.now() - t).days
            except Exception:
                pass
        try:
            # Python 3.11+ often has fromisoformat with 'Z' etc.
            t = dt.datetime.fromisoformat(ts.replace("Z",""))
            return (dt.datetime.now() - t).days
        except Exception:
            return None

    def _reused_info_for_this_item(self, candidate_pw: str) -> tuple[bool, int | None]:
        """
        Return (is_reuse, days_since_last_use).
        Matches against this entry's password_history by 'hash' (legacy) and 'fp' (if available).
        """
        hist = []
        try:
            # Fast paths: use index/entry if provided by the editor
            par = self.parent()
            if hasattr(self, "_vault_index"):
                from vault_store.vault_store import load_vault  
                uname = par.currentUsername.text() if (par and hasattr(par, "currentUsername") and hasattr(par.currentUsername, "text")) else ""
                key = getattr(par, "core_session_handle", None)
                entries = load_vault(uname, key) if uname and key else []
                if 0 <= self._vault_index < len(entries):
                    hist = list(entries[self._vault_index].get("password_history") or [])
            elif hasattr(self, "existing_entry") and isinstance(self.existing_entry, dict):
                hist = list(self.existing_entry.get("password_history") or [])
            else:
                if hasattr(self, "_resolve_existing_history"):
                    hist = list(self._resolve_existing_history() or [])
        except Exception as e:
            log.error(f"[PW] Check usage Error: {e}")
            pass

        if not hist:
            return (False, None)

        cand_h = self._sha(candidate_pw)
        cand_fp = self._fp_optional(candidate_pw)

        newest_ts = None
        for h in hist:
            if not isinstance(h, dict):
                continue
            prev_h  = str(h.get("hash") or "")
            prev_fp = str(h.get("fp")   or "")
            if (prev_h and prev_h == cand_h) or (cand_fp and prev_fp and prev_fp == cand_fp):
                ts = str(h.get("ts") or h.get("time") or "")
                # keep the most recent matching timestamp (if multiple rotations matched)
                if ts and (newest_ts is None or self._days_since(ts) is not None and (self._days_since(ts) <= (self._days_since(newest_ts) or 10**9))):
                    newest_ts = ts

        if newest_ts:
            return (True, self._days_since(newest_ts))
        return (False, None)

    def _resolve_existing_history(self):
        """Attempt to fetch password_history for this entry from the vault or parent."""
        # ---- Fast paths: index or existing_entry ----
        try:
            par = self.parent()
            # If the edit dialog told us the exact vault index, use it
            if hasattr(self, "_vault_index"):
                try:
                    from vault_store.vault_store import load_vault
                    uname = par.currentUsername.text() if (par and hasattr(par, "currentUsername") and hasattr(par.currentUsername, "text")) else ""
                    key = getattr(par, "core_session_handle", None)
                    entries = load_vault(uname, key) if uname and key else []
                    if 0 <= self._vault_index < len(entries):
                        return list(entries[self._vault_index].get("password_history") or [])
                except Exception as e:
                    log.error(f"[PWH] Error {e}")
                    pass

            # Or, if the caller gave us the entry dict, use it directly
            if hasattr(self, "existing_entry") and isinstance(self.existing_entry, dict):
                return list(self.existing_entry.get("password_history") or [])
        except Exception:
            log.error(f"[PW] fetch Error: {e}")
            pass

    def _on_show_history(self):
        """Open the password history dialog (read-only; last 90 days)."""
        hist = self._resolve_existing_history() or []
        # normalize + 90-day filter + newest-first
        def _parse_iso(ts: str):
            if not ts:
                return None
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    return dt.datetime.strptime(ts.replace("Z",""), fmt)
                except Exception:
                    pass
            try:
                return dt.datetime.fromisoformat(ts.replace("Z",""))
            except Exception:
                return None

        cutoff = dt.datetime.now() - dt.timedelta(days=90)
        norm = []
        entry_id = self._history_entry_id()
        try:
            for h in hist:
                if not isinstance(h, dict):
                    continue
                hv = h.get("hash") or h.get("fp")
                ts = str(h.get("ts") or h.get("time") or "")
                # only keep records with a hash/fp; ts optional but preferred
                if not hv:
                    continue
                t = _parse_iso(ts)
                if t and t < cutoff:
                    continue
                norm.append({"hash": hv, "ts": ts, "entry_id": entry_id})
        except Exception as e:
            log.error(f"[PW] Error {e}")
            QMessageBox.information(
                self,
                self.tr("Password History"),
                self.tr(f"Error on password history {e}")
            )
            return

        if not norm:
            QMessageBox.information(
                self,
                self.tr("Password History"),
                self.tr("No history in the last 90 days for this entry.")
            )
            return

        # newest first (unknown timestamps sink to bottom)
        try:
            norm.sort(key=lambda r: _parse_iso(r["ts"]) or dt.datetime.min, reverse=True)
        except Exception:
            pass

        dlg = PasswordHistoryDialog(norm, parent=self)
        dlg.exec()

    # --------------------------- Save orchestration ------------------------
    def _on_save_clicked(self, username):
        entry = self.get_entry_data(validate=True)
        if not entry:
            return

        # --- per-entry reuse warning -----------------------------------
        pw = entry.get("Password") or entry.get("password") or self._pw_text()
        if pw:
            was_reused, days = self._reused_info_for_this_item(pw)
            if was_reused:
                msg = self.tr("You’ve used this password for this item before.")
                if isinstance(days, int):
                    msg += (self.tr("\n(Last used ~")
                        + f"{days} "
                        + self.tr("day")
                        + (self.tr("s") if days != 1 else "")
                        + self.tr(" ago.)"))

                msg += self.tr("\n\nContinue anyway?")
                res = QMessageBox.question(
                    self, self.tr("Password Reuse Detected"),
                    msg,
                    QMessageBox.StandardButton.No | QMessageBox.StandardButton.Yes,
                    QMessageBox.StandardButton.No
                )
                if res != QMessageBox.StandardButton.Yes:
                    # Let user change it
                    try:
                        if self.passwordField:
                            self.passwordField.setFocus()
                            self.passwordField.selectAll()
                    except Exception:
                        pass
                    return

        password = entry.get("Password")



        if password and self.enable_breach_checker and BreachCheckWorker:
            self._pending_entry = entry
            self._run_breach_check_async(password)
            return

        self._finalize_save(entry)

    def _run_breach_check_async(self, password: str):
        try:
            # Cache first
            hashed = sha1_password(password)
            cache = load_breach_cache(self.user)
            if hashed in cache:
                count = cache[hashed]
                log.debug(str(f"[UI ADD] breach cache hit for {hashed[:6]}… -> {count}"))
                self._on_breach_result(password, count)
                return

            self._breachWorker = BreachCheckWorker(password, self)  
            if hasattr(self._breachWorker, "resultReady"):
                self._breachWorker.resultReady.connect(
                    lambda count: self._on_breach_result_with_cache(password, count, self.user)
                )
            else:
                def _done():
                    count = getattr(self._breachWorker, "result", -1)
                    self._on_breach_result_with_cache(password, count, self.user)
                self._breachWorker.finished.connect(_done)
            self._breachWorker.start()
        except Exception as e:
            log.error(str(f"[UI ADD] breach worker failed: {e}"))
            QMessageBox.warning(self, self.tr("Breach Check"), self.tr("Couldn't run breach check. Saving without check."))
            self._finalize_save(self._pending_entry or {})

    def _on_breach_result_with_cache(self, password: str, count: int, user:str):
        try:
            cache = load_breach_cache(user)
            cache[sha1_password(password)] = count
            save_breach_cache(user, cache)
        except Exception as e:
            log.debug(str(f"[UI ADD] breach cache save failed: {e}"))
        self._on_breach_result(password, count)

    def _on_breach_result(self, password: str, count: int):
        if count > 0:
            res = QMessageBox.question(
                self, self.tr("Password Found in Breach"),
                self.tr("⚠️ This password has appeared in {count} known data breaches.\n\n"
                "Do you still want to use it?").format(count=count),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if res != QMessageBox.StandardButton.Yes:
                if self.passwordField and self.passwordField.text() == password:
                    self.passwordField.clear()
                self._pending_entry = None
                return
        self._finalize_save(self._pending_entry or {})
        self._pending_entry = None

    def _finalize_save(self, entry: dict):
        self._last_entry = entry
        try:
            # give parent a chance to reset logout timer
            if hasattr(self.parent(), "reset_logout_timer"):
                self.parent().reset_logout_timer()
        except Exception:
            pass
        self.accept()

    # --------------------------- Data collection ---------------------------
    def get_entry_data(self, validate=False):
        entry = {}
        try:
            now = dt.datetime.now()
            entry = {
                "created_at": now.isoformat(),
                "Date": now.strftime("%Y-%m-%d"),
                "category": self.category,
            }
            invalid_fields = []

            def highlight(widget, ok=True):
                try:
                    widget.setStyleSheet("" if ok else "border: 2px solid red;")
                except Exception:
                    pass

            # -------------------- collect values + basic format checks --------------------
            for label, widget in self.fields.items():
                if isinstance(widget, QRadioButton) and label == self.tr("2FA Enabled"):
                    entry[label] = self.tr("True") if widget.isChecked() else self.tr("False")
                    continue

                if isinstance(widget, QLineEdit):
                    text = widget.text().strip()
                    entry[label] = text

                    # Basic format validation for certain field types
                    ok = True
                    low = label.lower()
                    if self.tr("card number") in low:
                        ok = bool(re.fullmatch(r"\d{13,19}", text)) or (text == "")
                    elif self.tr("cvv") in low:
                        ok = bool(re.fullmatch(r"\d{3,4}", text)) or (text == "")
                    elif self.tr("mac") in low:
                        ok = bool(re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", text)) or (text == "")
                    elif self.tr("ip address") in low or self.tr("ipv4") in low:
                        ok = bool(re.fullmatch(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)) or (text == "")
                    elif self.tr("ipv6") in low:
                        ok = bool(re.fullmatch(r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}", text)) or (text == "")
                    elif self.tr("account number") in low:
                        ok = bool(re.fullmatch(r"\d{6,12}", text)) or (text == "")
                    elif self.tr("sort code") in low:
                        ok = bool(re.fullmatch(r"\d{6}", text)) or (text == "")

                    highlight(widget, ok)
                    if not ok:
                        invalid_fields.append(label)

            if invalid_fields:
                QMessageBox.warning(
                    self, self.tr("Invalid Fields"),
                    self.tr("The following fields have invalid formats:\n\n") + "\n".join(invalid_fields)
                )
                return {}

            # -------------------- required fields (schema > quick lookup > url prefs) -------------
            required: set[str] = set()

            # 1) Respect explicit "required" flags from the current schema
            if isinstance(self._meta, list):
                for f in self._meta:
                    try:
                        if not isinstance(f, dict):
                            continue
                        if f.get("required"):
                            lbl = (f.get("label") or "").strip()
                            if lbl:
                                required.add(lbl.lower())
                    except Exception:
                        pass

            # 2) Fallback: per-category quick lookup (from category_fields.py)
            if not required:
                try:
                    req_list = required_fields(self.category) or []
                    required.update((str(x).strip().lower() for x in req_list if str(x).strip()))
                except Exception:
                    pass

            # 3) Final fallback: URL-ish fields we *really* want filled in
            if not required:
                try:
                    required.update(
                        str(s).strip().lower()
                        for s in preferred_url_fields(self.category) or []
                        if str(s).strip()
                    )
                except Exception:
                    pass

            if validate and required:
                for w in self.fields.values():
                    highlight(w, True)

                missing = []
                for key, val in entry.items():
                    if key.lower() in required and not val:
                        missing.append(key)
                        w = self.fields.get(key)
                        if w:
                            highlight(w, False)

                if missing:
                    QMessageBox.warning(
                        self, self.tr("Missing Field"),
                        self.tr("The following fields are required:\n\n- ") + "\n- ".join(missing)
                    )
                    return {}

            # -------------------- soft URL safety warnings (do not block) --------------------
            # Use meta "url" flag to decide which fields are URL-like
            url_labels = []
            if isinstance(self._meta, list):
                for f in self._meta:
                    try:
                        if not isinstance(f, dict):
                            continue
                        if f.get("url"):
                            lbl = (f.get("label") or "").strip()
                            if lbl:
                                url_labels.append(lbl)
                    except Exception:
                        pass
            if url_labels:
                missing_scheme = []
                insecure_http = []

                for lbl in url_labels:
                    val = (entry.get(lbl) or "").strip()
                    if not val:
                        continue  # empty allowed unless 'required' flagged earlier
                    low = val.lower()
                    if not (low.startswith(self.tr("http://")) or low.startswith(self.tr("https://"))):
                        missing_scheme.append((lbl, val))
                    elif low.startswith(self.tr("http://")):
                        insecure_http.append((lbl, val))

                if missing_scheme or insecure_http:
                    msg_parts = []
                    if missing_scheme:
                        msg_parts.append(
                            self.tr("These fields do not start with http:// or https://:\n") +
                            "\n".join(f"• {l}: {v}" for l, v in missing_scheme)
                        )
                    if insecure_http:
                        msg_parts.append(
                            self.tr("These sites use http:// (not secure — HTTPS is recommended):\n") +
                            "\n".join(f"• {l}: {v}" for l, v in insecure_http)
                        )
                    msg = "\n\n".join(msg_parts) + self.tr("\n\nSave anyway?")
                    res = QMessageBox.warning(
                        self, self.tr("URL Safety Warning"), msg,
                        QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                    )
                    if res == QMessageBox.No:
                        return {}

            return entry

        except Exception as e:
            log.error(str(f"[UI ADD] get_entry_data failed: {e}"))
            QMessageBox.critical(self, self.tr("Error"), self.tr("An error occurred while getting entry data:") + f"\n{e}")
            return {}

    # --------------------------- Convenience accessor for callers ---------------------------
    def result_entry(self) -> dict | None:
        return self._last_entry

    # -------------
    # Prefill helpers
    # -------------
    def prefill_from_dict(self, data: dict[str, object] | None) -> None:
        """
        Prefill the dynamic entry fields from a plain mapping.

        This helper iterates over the resolved field labels (as shown in the UI)
        and attempts to match each against keys in the provided mapping. The
        comparison is case-insensitive and ignores whitespace. When a match
        is found, the corresponding widget is updated with the value. Radio
        buttons (e.g. "2FA Enabled") are toggled based on common truthy
        strings ("true", "1", "yes", "on"). Missing keys are ignored.

        Note that callers should supply keys that correspond to the field
        labels used in your category schema (e.g. "Title", "Username",
        "Password", etc.). Values will be converted to strings when
        assigning to line edits. If the provided data is not a mapping,
        this method silently returns.
        """
        if not isinstance(data, dict):
            return

        # Build a lookup dict keyed by lower-case labels for quick access
        # Also include original casing to preserve common synonyms (e.g. Name vs name)
        norm_map = {}
        for k, v in data.items():
            try:
                key = str(k).strip()
            except Exception:
                continue
            if not key:
                continue
            norm_map[key.lower()] = v

        for label, widget in self.fields.items():
            try:
                target_key = str(label).strip().lower()
            except Exception:
                continue
            if not target_key:
                continue
            if target_key not in norm_map:
                continue
            val = norm_map[target_key]
            # Skip empty values
            if val is None:
                continue
            # Convert to string for widgets
            sval = str(val)
            # Update widget based on type
            if isinstance(widget, QRadioButton):
                # Interpret various truthy values
                sval_lower = sval.strip().lower()
                widget.setChecked(sval_lower in {"true", "1", "yes", "on"})
            elif isinstance(widget, QLineEdit):
                # Avoid overwriting if already populated
                if not widget.text().strip():
                    widget.setText(sval)
            else:
                try:
                    # Generic fallback: attempt to set text property
                    if hasattr(widget, "setPlainText"):
                        # e.g. QTextEdit/QPlainTextEdit
                        if not widget.toPlainText().strip():
                            widget.setPlainText(sval)
                    elif hasattr(widget, "setText"):
                        if not widget.text().strip():
                            widget.setText(sval)
                except Exception:
                    pass
