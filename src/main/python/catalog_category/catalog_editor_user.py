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


from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget, QWidget, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QLabel,
    QMessageBox, QHeaderView, QTextBrowser, QLineEdit
)
from PySide6.QtCore import Signal
from catalog_category.catalog_user import (
    load_effective_catalogs_from_user,
    save_user_catalog,
)

# ---- app logging ----
import logging
log = logging.getLogger("keyquorum")

# pull emails from the user's vault (Email Accounts category)
# Support both historical layouts:
#   - vault_store.py at project root:    from vault_store import load_vault
#   - vault_store/vault_store.py module: from vault_store.vault_store import load_vault
try:
    from vault_store.vault_store import load_vault as _load_vault
except Exception:
    try:
        from vault_store import load_vault as _load_vault
    except Exception:
        _load_vault = None

class CatalogEditorUserDialog(QDialog):
    saved = Signal()

    def __init__(
        self,
        user_cfg_dir,
        CLIENTS,
        ALIASES,
        PLATFORM_GUIDE,
        *args,
        parent=None,
        user_key=None,
        username=None,
        AUTOFILL_RECIPES=None,
        **kwargs,
    ):
        super().__init__(parent)

        # ---- Backward/forward compatible args handling ----
        # Accept calls:
        #   CatalogEditorUserDialog(user_cfg_dir, CLIENTS, ALIASES, PLATFORM_GUIDE, parent=..., user_key=...)
        #   CatalogEditorUserDialog(user_cfg_dir, CLIENTS, ALIASES, PLATFORM_GUIDE, AUTOFILL_RECIPES, parent=..., user_key=...)
        if AUTOFILL_RECIPES is None:
            AUTOFILL_RECIPES = kwargs.get("AUTOFILL_RECIPES", None)

        # Determine parent/user_key if accidentally passed positionally
        if args:
            first = args[0]
            try:
                from PySide6.QtWidgets import QWidget
                from PySide6.QtCore import QObject
                is_widget = isinstance(first, (QWidget, QObject))
            except Exception:
                is_widget = False

            if isinstance(first, dict) and AUTOFILL_RECIPES is None:
                AUTOFILL_RECIPES = first
            elif isinstance(first, (bytes, bytearray)) and user_key is None:
                user_key = first
            elif is_widget and parent is None:
                parent = first

        if parent is None:
            parent = kwargs.get("parent", None)
        if user_key is None:
            user_key = kwargs.get("user_key", None)

        # Canonical naming in Keyquorum is userKey; keep snake_case alias for safety.
        self.userKey = user_key
        self.user_key = self.userKey
        self.user_cfg_dir = user_cfg_dir
        self.AUTOFILL_RECIPES = AUTOFILL_RECIPES or {}
        self._BUILTIN_AUTOFILL_RECIPES = dict(self.AUTOFILL_RECIPES)
        self.setWindowTitle(self.tr("Catalog Editor"))
        self.setMinimumSize(950, 620)

        # Prefer explicit username, then host-provided username, then a best-effort guess.
        self.username = (username or kwargs.get("username") or "").strip()
        if not self.username:
            try:
                host = self.parent()
                while host is not None and not hasattr(host, "username"):
                    host = host.parent()
                if host is not None:
                    self.username = (getattr(host, "username", "") or "").strip()
            except Exception:
                pass
        if not self.username:
            try:
                from pathlib import Path as _Path
                p = _Path(str(user_cfg_dir))
                # If user_cfg_dir is .../users/<name>/config, use parent folder.
                if p.name.lower() in ("config", "cfg", "settings") and p.parent is not None:
                    self.username = p.parent.name
                else:
                    self.username = p.name
            except Exception:
                self.username = ""
        self.CLIENTS = CLIENTS
        self.ALIASES = ALIASES
        self.PLATFORM_GUIDE = PLATFORM_GUIDE
        # Tabs
        self.tabs = QTabWidget(self)
        self.clientsTab = QWidget()
        self.aliasesTab = QWidget()
        self.platformGuideTab = QWidget()
        self.autofillTab = QWidget()
        self.emailsTab = QWidget()
        self.helpTab = QWidget()

        self.tabs.addTab(self.clientsTab, self.tr("Clients"))
        self.tabs.addTab(self.aliasesTab, self.tr("Aliases"))
        self.tabs.addTab(self.platformGuideTab, self.tr("Platform Guide"))
        self.tabs.addTab(self.autofillTab, self.tr("Autofill"))
        self.tabs.addTab(self.emailsTab, self.tr("Emails"))
        self.tabs.addTab(self.helpTab, self.tr("Help / Guide"))

        # Bottom buttons
        self.btnExport = QPushButton(self.tr("Export (Encrypted)"))
        self.btnImport = QPushButton(self.tr("Import (Encrypted)"))
        self.btnSave   = QPushButton(self.tr("Save"))
        self.btnReset  = QPushButton(self.tr("Reset to Defaults"))
        self.btnClose  = QPushButton(self.tr("Close"))

        self.btnExport.clicked.connect(self._on_export_encrypted)
        self.btnImport.clicked.connect(self._on_import_encrypted)
        self.btnSave.clicked.connect(self._save)
        self.btnReset.clicked.connect(self._reset_to_defaults)
        self.btnClose.clicked.connect(self.close)

        # Layout scaffold
        root = QVBoxLayout(self)
        root.addWidget(self.tabs)
        btnrow = QHBoxLayout()
        btnrow.addStretch(1)
        # Export/Import on the left side of the action group
        btnrow.addWidget(self.btnExport)
        btnrow.addWidget(self.btnImport)
        btnrow.addSpacing(24)
        btnrow.addWidget(self.btnSave)
        btnrow.addWidget(self.btnReset)
        btnrow.addWidget(self.btnClose)
        root.addLayout(btnrow)


        # Init tabs
        self._init_clients_tab()
        self._init_aliases_tab()
        self._init_platform_guide_tab()
        self._init_autofill_tab()
        self._init_emails_tab()
        self._init_help_tab()

        # Populate
        self._load_into_ui()


    # -----------------------------------------------------------------------
    # Host lookup (walk parent chain to find MainWindow)
    # -----------------------------------------------------------------------
    def _find_host_with(self, *attrs):
        """
        Walk up the parent chain to find a host object that has all of the
        given attributes (e.g. updatebaseline, export/import helpers).
        """
        host = self.parent()
        while host is not None:
            if all(hasattr(host, a) for a in attrs):
                return host
            host = host.parent()
        return None

    # -----------------------------------------------------------------------
    # Encrypted export/import actions
    # -----------------------------------------------------------------------
    def _on_export_encrypted(self):
        """
        Ask the host (MainWindow) to export this user's catalog using the
        standard encrypted export mechanism.
        """
        host = self._find_host_with("export_user_catalog_encrypted")
        if not host:
            QMessageBox.information(
                self,
                self.tr("Export (Encrypted)"),
                self.tr("Encrypted export is not available in this build.")
            )
            return

        try:
            # MainWindow should handle file dialog + password UI + crypto.
            host.export_user_catalog_encrypted(self.username)
        except Exception as e:
            QMessageBox.critical(
                self,
                self.tr("Export (Encrypted)"),
                self.tr("Failed to export catalog") + f":\n{e}"
            )

    def _on_import_encrypted(self):
        """
        Ask the host (MainWindow) to import an encrypted catalog for this user.
        """
        host = self._find_host_with("import_user_catalog_encrypted")
        if not host:
            QMessageBox.information(
                self,
                self.tr("Import (Encrypted)"),
                self.tr("Encrypted import is not available in this build.")
            )
            return

        try:
            if host.import_user_catalog_encrypted(self.username):
                # If import succeeded, reload UI so the new catalog is visible.
                self._load_into_ui()
                QMessageBox.information(
                    self,
                    self.tr("Import (Encrypted)"),
                    self.tr("Catalog imported successfully.")
                )
                self.saved.emit()
        except Exception as e:
            QMessageBox.critical(
                self,
                self.tr("Import (Encrypted)"),
                self.tr("Failed to import catalog") + f":\n{e}"
            )

    # -----------------------------------------------------------------------
    # Tabs
    # -----------------------------------------------------------------------
    
    def _init_clients_tab(self):
        lay = QVBoxLayout(self.clientsTab)

        # Search bar
        top = QHBoxLayout()
        lbl = QLabel(self.tr("Search:"))
        self.clientSearch = QLineEdit()
        self.clientSearch.setPlaceholderText(self.tr("Key, protocol, domain, exe path, installer, page…"))
        self.clientSearch.textChanged.connect(self._filter_clients_table)
        top.addWidget(lbl)
        top.addWidget(self.clientSearch, 1)
        lay.addLayout(top)

        # Table
        self.clientsTable = QTableWidget(0, 6)
        self.clientsTable.setHorizontalHeaderLabels(
            ["Key", "Protocols", "Domains", "Exe Paths", "Installer", "Page"]
        )
        self.clientsTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.clientsTable)

        # Buttons
        btns = QHBoxLayout()
        self.btnAddClient = QPushButton(self.tr("Add Row"))
        self.btnDelClient = QPushButton(self.tr("Delete Selected"))
        self.btnRestoreSelected = QPushButton(self.tr("Restore from Defaults (Selected)"))
        self.btnAddClient.clicked.connect(self._on_add_client_row)
        self.btnDelClient.clicked.connect(self._on_delete_client_row)
        self.btnRestoreSelected.clicked.connect(self._restore_selected_from_defaults)
        btns.addWidget(self.btnAddClient)
        btns.addWidget(self.btnDelClient)
        btns.addWidget(self.btnRestoreSelected)
        btns.addStretch(1)
        lay.addLayout(btns)

    def _init_aliases_tab(self):
        lay = QVBoxLayout(self.aliasesTab)
        self.aliasTable = QTableWidget(0, 2)
        self.aliasTable.setHorizontalHeaderLabels([self.tr("Alias"), self.tr("Target")])
        self.aliasTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.aliasTable)

        btns = QHBoxLayout()
        self.btnAddAlias = QPushButton(self.tr("Add Row"))
        self.btnDelAlias = QPushButton(self.tr("Delete Selected"))
        self.btnAddAlias.clicked.connect(self._on_add_alias_row)
        self.btnDelAlias.clicked.connect(self._on_delete_alias_row)
        btns.addWidget(self.btnAddAlias)
        btns.addWidget(self.btnDelAlias)
        btns.addStretch(1)
        lay.addLayout(btns)

    def _init_platform_guide_tab(self):
        lay = QVBoxLayout(self.platformGuideTab)
        self.platformGuideTable = QTableWidget(0, 2)
        self.platformGuideTable.setHorizontalHeaderLabels([self.tr("Platform"), self.tr("Description / Notes")])
        self.platformGuideTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.platformGuideTable)

        btns = QHBoxLayout()
        self.btnAddGuide = QPushButton(self.tr("Add Row"))
        self.btnDelGuide = QPushButton(self.tr("Delete Selected"))
        self.btnAddGuide.clicked.connect(self._on_add_platform_row)
        self.btnDelGuide.clicked.connect(self._on_delete_platform_row)
        btns.addWidget(self.btnAddGuide)
        btns.addWidget(self.btnDelGuide)
        btns.addStretch(1)
        lay.addLayout(btns)

    def _init_autofill_tab(self):
        layout = QVBoxLayout(self.autofillTab)
        layout.addWidget(QLabel(self.tr("Autofill recipes (per-app UI selectors).")))

        self.autofillTable = QTableWidget(0, 6)
        self.autofillTable.setHorizontalHeaderLabels([
            self.tr("Key"),
            self.tr("Window Title (regex)"),
            self.tr("Username title_re"),
            self.tr("Password title_re"),
            self.tr("Submit title_re"),
            self.tr("Flags (comma)"),
        ])
        self.autofillTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.autofillTable)

        btnRow = QHBoxLayout()
        self.btnAddRecipe = QPushButton(self.tr("Add Recipe"))
        self.btnDelRecipe = QPushButton(self.tr("Delete Recipe"))
        btnRow.addWidget(self.btnAddRecipe)
        btnRow.addWidget(self.btnDelRecipe)
        btnRow.addStretch(1)
        layout.addLayout(btnRow)

        self.btnAddRecipe.clicked.connect(lambda: self.autofillTable.insertRow(self.autofillTable.rowCount()))
        self.btnDelRecipe.clicked.connect(self._delete_selected_autofill_rows)

        self._load_autofill_table(self.AUTOFILL_RECIPES)

    def _delete_selected_autofill_rows(self):
        try:
            rows = sorted({i.row() for i in self.autofillTable.selectedIndexes()}, reverse=True)
            for r in rows:
                self.autofillTable.removeRow(r)
        except Exception:
            pass

    def _load_autofill_table(self, recipes: dict):
        self.autofillTable.setSortingEnabled(False)
        try:
            self.autofillTable.setRowCount(0)
            for key, rec in (recipes or {}).items():
                r = self.autofillTable.rowCount()
                self.autofillTable.insertRow(r)
                window_re = str(rec.get("window_title_re", "") or "")
                u_re = str(((rec.get("username") or {}).get("title_re")) or "")
                p_re = str(((rec.get("password") or {}).get("title_re")) or "")
                s_re = str(((rec.get("submit") or {}).get("title_re")) or "")
                flags = []
                if (rec.get("password") or {}).get("prefer_password"):
                    flags.append("prefer_password")
                self.autofillTable.setItem(r, 0, QTableWidgetItem(str(key)))
                self.autofillTable.setItem(r, 1, QTableWidgetItem(window_re))
                self.autofillTable.setItem(r, 2, QTableWidgetItem(u_re))
                self.autofillTable.setItem(r, 3, QTableWidgetItem(p_re))
                self.autofillTable.setItem(r, 4, QTableWidgetItem(s_re))
                self.autofillTable.setItem(r, 5, QTableWidgetItem(", ".join(flags)))
        finally:
            self.autofillTable.setSortingEnabled(True)

    def _collect_autofill_recipes_from_table(self) -> dict:
        recipes = {}
        for r in range(self.autofillTable.rowCount()):
            if self._row_is_all_blank(self.autofillTable, r):
                continue
            key = self._cell_text(self.autofillTable, r, 0)
            if not key:
                continue
            window_re = self._cell_text(self.autofillTable, r, 1)
            u_re = self._cell_text(self.autofillTable, r, 2)
            p_re = self._cell_text(self.autofillTable, r, 3)
            s_re = self._cell_text(self.autofillTable, r, 4)
            flags = self._cell_text(self.autofillTable, r, 5)

            prefer_password = any(f.strip().lower() == "prefer_password" for f in (flags or "").split(","))

            rec = {}
            if window_re:
                rec["window_title_re"] = window_re
            rec["username"] = {"control_type": "Edit", "title_re": u_re or "(Email|Username|Account)"}
            rec["password"] = {"control_type": "Edit", "title_re": p_re or "(Password)", "prefer_password": bool(prefer_password)}
            rec["submit"]   = {"control_type": "Button", "title_re": s_re or "(Sign in|Log in|Continue)"}
            recipes[key] = rec
        return recipes



    def _init_emails_tab(self):
        lay = QVBoxLayout(self.emailsTab)
        desc = QLabel(self.tr(
            "<b>Emails:</b> Optional per-platform email suggestions used when adding a vault entry."
            "<br>Format: comma-separated emails (e.g. <code>alice@work.com, bob@example.com</code>)."))
        desc.setWordWrap(True)
        lay.addWidget(desc)

        self.emailsTable = QTableWidget(0, 2)
        self.emailsTable.setHorizontalHeaderLabels([self.tr("Key"), self.tr("Emails")])
        self.emailsTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.emailsTable.setToolTip(self.tr(
            "Per-platform email suggestions used in the Add Entry dialog. "
            "Comma-separated list. Stored encrypted in your catalog."
        ))
        lay.addWidget(self.emailsTable)

        btns = QHBoxLayout()
        self.btnAddEmail = QPushButton(self.tr("Add Row"))
        self.btnDelEmail = QPushButton(self.tr("Delete Selected"))
        self.btnImportEmails = QPushButton(self.tr("Import From Vault (Email Accounts)"))
        self.btnAddEmail.clicked.connect(self._on_add_email_row)
        self.btnDelEmail.clicked.connect(self._on_delete_email_row)
        self.btnImportEmails.clicked.connect(self._on_import_emails_from_vault)
        btns.addWidget(self.btnAddEmail)
        btns.addWidget(self.btnDelEmail)
        btns.addWidget(self.btnImportEmails)
        btns.addStretch(1)
        lay.addLayout(btns)

    def _on_import_emails_from_vault(self):
        """Import ONLY email addresses from vault Email Accounts into this table.

        - Never imports passwords/notes.
        - Adds one email per row.
        """
        if _load_vault is None:
            QMessageBox.information(
                self,
                self.tr("Import Emails"),
                self.tr("Vault integration is not available in this build."),
            )
            return

        username = (getattr(self, "username", "") or "").strip()
        user_key = getattr(self, "userKey", None) or getattr(self, "user_key", None)
        if not username or not user_key:
            QMessageBox.information(
                self,
                self.tr("Import Emails"),
                self.tr("You must be logged in (username + vault key) to import emails."),
            )
            return

        try:
            entries = _load_vault(username, user_key) or []
        except Exception as e:
            QMessageBox.critical(
                self,
                self.tr("Import Emails"),
                self.tr("Failed to read vault") + f":\n{e}",
            )
            return

        import re
        email_re = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)

        def extract_emails(d: dict) -> set:
            allowed = {
                "Email", "email", "E-mail", "e-mail",
                "Username", "UserName", "username",
                "Login", "login", "Account", "account",
                "User", "user", "ID", "id",
            }
            found = set()
            for k in allowed:
                v = d.get(k)
                if isinstance(v, str) and v.strip():
                    for m in email_re.findall(v):
                        found.add(m.strip())
            for k in ("Title", "Name", "label"):
                v = d.get(k)
                if isinstance(v, str) and v.strip():
                    for m in email_re.findall(v):
                        found.add(m.strip())
            return found

        emails_found = set()
        for e in entries:
            if not isinstance(e, dict):
                continue
            cat = (e.get("category") or e.get("Category") or "").strip().casefold()
            if cat not in ("email accounts", "email account", "emails"):
                continue
            emails_found |= extract_emails(e)

        if not emails_found:
            QMessageBox.information(
                self,
                self.tr("Import Emails"),
                self.tr("No email addresses were found in the 'Email Accounts' category."),
            )
            return

        existing = set()
        for r in range(self.emailsTable.rowCount()):
            k = self._cell_text(self.emailsTable, r, 0)
            if k:
                existing.add(k.strip().lower())

        added = 0
        for em in sorted(emails_found, key=str.lower):
            if em.strip().lower() in existing:
                continue
            r = self.emailsTable.rowCount()
            self.emailsTable.insertRow(r)
            self.emailsTable.setItem(r, 0, QTableWidgetItem(em))
            self.emailsTable.setItem(r, 1, QTableWidgetItem(em))
            added += 1

        QMessageBox.information(
            self,
            self.tr("Import Emails"),
            self.tr("Imported emails from vault.") + f"\n\n{self.tr('New rows')}: {added}",
        )

    def _init_help_tab(self):
        layout = QVBoxLayout(self.helpTab)
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        browser.setHtml(self.tr("""
        <h2>📘 Catalog Editor Guide</h2>
        <p>This catalog tells Keyquorum how to recognise, match and launch apps or websites when you use
        AutoFill or quick launch features.</p>

        <h3>🧩 Fields Explained</h3>
        <ul>
          <li><b>Key</b> — Unique name for the app or platform (e.g. <code>steam</code>, <code>battle.net</code>).</li>
          <li><b>Protocols</b> — URL schemes that can launch or identify the app (e.g. <code>steam://</code>).</li>
          <li><b>Domains</b> — Website hostnames for this app (e.g. <code>steampowered.com</code>).</li>
          <li><b>Exe Paths</b> — Likely Windows install locations for the app’s executable.</li>
          <li><b>Installer</b> — Download/store page for the app (vendor page recommended).</li>
          <li><b>Page</b> — Main home or account page.</li>
          <li><b>Emails</b> — Optional suggestions shown in “Add Entry”.</li>
        </ul>

        <h3>⚙️ How It Works</h3>
        <ul>
          <li>Desktop AutoFill: match running window or known <b>exe path</b>.</li>
          <li>Web AutoFill: match by <b>domain</b> to pick the right client.</li>
          <li>If not installed: we open the <b>Installer</b> vendor page.</li>
          <li><b>Aliases</b>: map alternative names to the same client key.</li>
          <li><b>Platform Guide</b>: human-readable notes shown in the UI.</li>
        </ul>

        <h3>💡 Tips</h3>
        <ul>
          <li>Add multiple domains if the platform uses several.</li>
          <li>Include per-user and global exe paths for reliability.</li>
          <li>Prefer vendor web pages over direct EXE links.</li>
          <li>Save to keep changes, Reset to restore built-ins.</li>
        </ul>
        """))
        layout.addWidget(browser)

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _is_email_only_client(self, data: dict) -> bool:
        """Return True if this client entry only contains email suggestions (no launch metadata)."""
        if not isinstance(data, dict):
            return False
        # Only emails key present (or emails + empty values elsewhere)
        email_keys = {"emails"}
        if set(data.keys()) == email_keys:
            return True
        # If it has emails, but none of the launch metadata fields are present, treat as email-only.
        has_emails = bool(data.get("emails"))
        has_launch = any(
            bool(data.get(k)) for k in ("exe_paths", "protocols", "domains", "installer", "page")
        )
        return has_emails and (not has_launch)

    def _cell_text(self, table, r: int, c: int) -> str:
        item = table.item(r, c)
        return (item.text() if item else "").strip()

    def _row_is_all_blank(self, table, r: int) -> bool:
        for c in range(table.columnCount()):
            if table.item(r, c) and table.item(r, c).text().strip():
                return False
        return True
    # -----------------------------------------------------------------------
    # Search filter
    # -----------------------------------------------------------------------
    def _filter_clients_table(self, text: str):
        query = (text or "").strip().lower()
        row_count = self.clientsTable.rowCount()
        if not query:
            for r in range(row_count):
                self.clientsTable.setRowHidden(r, False)
            return
        tokens = [t for t in query.split() if t]
        for r in range(row_count):
            hay = []
            for c in range(self.clientsTable.columnCount()):
                item = self.clientsTable.item(r, c)
                if item:
                    hay.append(item.text().lower())
            blob = " ".join(hay)
            show = all(t in blob for t in tokens)
            self.clientsTable.setRowHidden(r, not show)

    def _reapply_clients_filter(self):
        if hasattr(self, "clientSearch"):
            self._filter_clients_table(self.clientSearch.text())

    # -----------------------------------------------------------------------
    # Load + Save
    # -----------------------------------------------------------------------
    def _load_into_ui(self):
        sort_on = self.clientsTable.isSortingEnabled()
        self.clientsTable.setSortingEnabled(False)
        try:
            clients, aliases, guide, recipes, _merged = load_effective_catalogs_from_user(
                self.username,
                self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE,
                getattr(self, '_BUILTIN_AUTOFILL_RECIPES', None),
                user_key=self.user_key
            )
        except Exception as e:
            log.debug(f"[CATALOG] ⚠️ load failed: {e}")
            clients, aliases, guide = self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE
            recipes = dict(getattr(self, '_BUILTIN_AUTOFILL_RECIPES', {}) or {})
        # Clients
        self.clientsTable.setRowCount(0)
        for k, v in (clients or {}).items():
            if self._is_email_only_client(v):
                continue
            r = self.clientsTable.rowCount()
            self.clientsTable.insertRow(r)
            self.clientsTable.setItem(r, 0, QTableWidgetItem(k))
            self.clientsTable.setItem(r, 1, QTableWidgetItem(", ".join(v.get("protocols", []))))
            self.clientsTable.setItem(r, 2, QTableWidgetItem(", ".join(v.get("domains", []))))
            self.clientsTable.setItem(r, 3, QTableWidgetItem(", ".join(v.get("exe_paths", []))))
            self.clientsTable.setItem(r, 4, QTableWidgetItem(v.get("installer", "")))
            self.clientsTable.setItem(r, 5, QTableWidgetItem(v.get("page", "")))

        # Aliases
        self.aliasTable.setRowCount(0)
        for a, t in (aliases or {}).items():
            r = self.aliasTable.rowCount()
            self.aliasTable.insertRow(r)
            self.aliasTable.setItem(r, 0, QTableWidgetItem(a))
            self.aliasTable.setItem(r, 1, QTableWidgetItem(t))

        # Platform guide
        self.platformGuideTable.setRowCount(0)
        for k, v in (guide or {}).items():
            r = self.platformGuideTable.rowCount()
            self.platformGuideTable.insertRow(r)
            self.platformGuideTable.setItem(r, 0, QTableWidgetItem(k))
            self.platformGuideTable.setItem(r, 1, QTableWidgetItem(v))

        # Emails from clients
        self._populate_emails(clients)

        # Autofill recipes (loaded)
        try:
            self.AUTOFILL_RECIPES = recipes or {}
            self._load_autofill_table(self.AUTOFILL_RECIPES)
        except Exception:
            pass


        self._reapply_clients_filter()
        self.clientsTable.setSortingEnabled(sort_on)
        self.clientsTable.scrollToTop()

    def _save(self):
        try:
            clients, aliases, guide = {}, {}, {}

            # --- clients (skip truly blank rows) ---
            for r in range(self.clientsTable.rowCount()):
                if self._row_is_all_blank(self.clientsTable, r):
                    continue

                key = self._cell_text(self.clientsTable, r, 0)
                if not key:
                    continue

                protocols = [s.strip() for s in self._cell_text(self.clientsTable, r, 1).split(",") if s.strip()]
                domains   = [s.strip() for s in self._cell_text(self.clientsTable, r, 2).split(",") if s.strip()]
                exe_paths = [s.strip() for s in self._cell_text(self.clientsTable, r, 3).split(",") if s.strip()]
                installer = self._cell_text(self.clientsTable, r, 4)
                page      = self._cell_text(self.clientsTable, r, 5)

                clients[key] = {
                    "protocols": protocols,
                    "domains": domains,
                    "exe_paths": exe_paths,
                    "installer": installer,
                    "page": page,
                }

            # --- platform guide ---
            for r in range(self.platformGuideTable.rowCount()):
                if self._row_is_all_blank(self.platformGuideTable, r):
                    continue
                k = self._cell_text(self.platformGuideTable, r, 0)
                v = self._cell_text(self.platformGuideTable, r, 1)
                if k:
                    guide[k] = v

            # --- aliases ---
            for r in range(self.aliasTable.rowCount()):
                if self._row_is_all_blank(self.aliasTable, r):
                    continue
                a = self._cell_text(self.aliasTable, r, 0)
                t = self._cell_text(self.aliasTable, r, 1)
                if a:
                    aliases[a] = t

            # --- emails (only include non-empty) ---
            emails_map = self._emails_map_from_table()
            for k, emails in emails_map.items():
                if k not in clients:
                    clients[k] = {}
                if emails:
                    clients[k]["emails"] = emails

            payload = {
                "CLIENTS": clients,
                "ALIASES": aliases,
                "PLATFORM_GUIDE": guide,
                "AUTOFILL_RECIPES": self._collect_autofill_recipes_from_table(),
                "version": 1,
            }
            save_user_catalog(self.username, payload, user_key=self.user_key)

            # ---- Baseline update (per-user, for integrity system) ----
            host = self._find_host_with("updatebaseline")
            if host:
                try:
                    host.updatebaseline(
                        self.username,
                        verify_after=False,
                        who=self.tr("Catalog Save"),
                    )
                except Exception as e:
                    # Don't block save on baseline errors.
                    log.debug(f"[CATALOG] ⚠️ updatebaseline after save failed: {e}")

            QMessageBox.information(self, self.tr("Saved"), self.tr("Catalog saved successfully."))
            self.saved.emit()

        except Exception as e:
            QMessageBox.critical(self, self.tr("Error"), self.tr("Failed to save catalog") + f":\n{e}")


    # -----------------------------------------------------------------------
    # Reset + restore
    # -----------------------------------------------------------------------
    def _reset_to_defaults(self):
        try:
            # overwrite user catalog with built-ins and reload
            payload = {
                "CLIENTS": self.CLIENTS,
                "ALIASES": self.ALIASES,
                "PLATFORM_GUIDE": self.PLATFORM_GUIDE,
                "version": 1,
            }
            save_user_catalog(self.username, payload, user_key=self.user_key)
            self._load_into_ui()
            self._reapply_clients_filter()

            # Baseline update for reset as well
            host = self._find_host_with("updatebaseline")
            if host:
                try:
                    host.updatebaseline(
                        self.username,
                        verify_after=False,
                        who=self.tr("Catalog Reset"),
                    )
                except Exception as e:
                    log.debug(f"[CATALOG] ⚠️ updatebaseline after reset failed: {e}")

            QMessageBox.information(self, self.tr("Reset"), self.tr("Catalog reset to defaults."))
            self.saved.emit()
        except Exception as e:
            QMessageBox.critical(self, self.tr("Error"), self.tr("Failed to reset catalog") + f":\n{e}")

    def _restore_selected_from_defaults(self):
        r = self.clientsTable.currentRow()
        if r < 0:
            QMessageBox.information(self, self.tr("Restore"), self.tr("Select a row (or create an empty row) first."))
            return
        key_item = self.clientsTable.item(r, 0)
        key = (key_item.text() if key_item else "").strip()
        if not key:
            QMessageBox.information(self, self.tr("Restore"), self.tr("Enter a Key in column 0, then click Restore."))
            return

        src = self.CLIENTS.get(key)
        if not src:
            QMessageBox.information(self, self.tr("Restore"), self.tr("No built-in defaults found for") + f" '{key}'.")
            return

        def setc(col, text):
            if not self.clientsTable.item(r, col):
                self.clientsTable.setItem(r, col, QTableWidgetItem(""))
            self.clientsTable.item(r, col).setText(text)

        setc(1, ", ".join(src.get("protocols", [])))
        setc(2, ", ".join(src.get("domains", [])))
        setc(3, ", ".join(src.get("exe_paths", [])))
        setc(4, src.get("installer", "") or "")
        setc(5, src.get("page", "") or "")

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------
    def _populate_emails(self, clients: dict):
        self.emailsTable.setRowCount(0)
        for k, v in (clients or {}).items():
            emails = v.get("emails", [])
            if not emails:
                continue
            r = self.emailsTable.rowCount()
            self.emailsTable.insertRow(r)
            self.emailsTable.setItem(r, 0, QTableWidgetItem(k))
            self.emailsTable.setItem(r, 1, QTableWidgetItem(", ".join(emails)))

    def _emails_map_from_table(self):
        out = {}
        for r in range(self.emailsTable.rowCount()):
            k = self._cell_text(self.emailsTable, r, 0)
            v = self._cell_text(self.emailsTable, r, 1)
            if not k or not v:
                continue
            emails = [e.strip() for e in v.split(",") if e.strip()]
            if emails:
                out[k] = emails
        return out

    # Row ops
    def _on_add_client_row(self):
        self.clientsTable.insertRow(self.clientsTable.rowCount())

    def _on_delete_client_row(self):
        r = self.clientsTable.currentRow()
        if r < 0:
            return
        key = self.clientsTable.item(r, 0).text() if self.clientsTable.item(r, 0) else ""
        if QMessageBox.question(self, self.tr("Delete"), self.tr("Delete") + f" '{key or self.tr('this row')}' " + self.tr(" permanently?")) != QMessageBox.Yes:
            return
        self.clientsTable.removeRow(r)

    def _on_add_alias_row(self):
        self.aliasTable.insertRow(self.aliasTable.rowCount())

    def _on_delete_alias_row(self):
        r = self.aliasTable.currentRow()
        if r >= 0:
            self.aliasTable.removeRow(r)

    def _on_add_platform_row(self):
        self.platformGuideTable.insertRow(self.platformGuideTable.rowCount())

    def _on_delete_platform_row(self):
        r = self.platformGuideTable.currentRow()
        if r >= 0:
            self.platformGuideTable.removeRow(r)

    def _on_add_email_row(self):
        self.emailsTable.insertRow(self.emailsTable.rowCount())

    def _on_delete_email_row(self):
        r = self.emailsTable.currentRow()
        if r >= 0:
            self.emailsTable.removeRow(r)
