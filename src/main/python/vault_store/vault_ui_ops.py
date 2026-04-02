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
import json, os, subprocess, secrets
from urllib.parse import quote
from app.platform_utils import open_path
from auth.login.login_handler import (get_user_setting, _canonical_username_ci, set_user_cloud, get_user_cloud)
from vault_store.vault_store import (add_vault_entry, load_vault, delete_vault_entry,)
from vault_store.add_entry_dialog import AddEntryDialog
import datetime as dt
from features.qr.qr_tools import QRPreviewDialog
import re as _re
# Use the canonical password-history helper from vault_store.password_history_ops.
# The old import from features.watchtower.watchtower_helpers depended on Watchtower being present,
# which is not required for password history. Importing from vault_store.password_history_ops
# avoids bringing in Watchtower at all and ensures we call the DLL-based persist helper.
from vault_store.password_history_ops import persist_entry_with_history
from security.baseline_signer import update_baseline
from shutil import copy2
import time as _t
from qtpy import QtWidgets
from bridge.bridge_ops import _kq_strip_ws
from app.qt_imports import *  # noqa: F401,F403


# ---------------------------------------------------------------------------
# UI-string handling helpers
# ---------------------------------------------------------------------------

_MAIN = (
    _sys.modules.get("__main__")
    or _sys.modules.get("main")
    or _sys.modules.get("app.app_window")
    or _sys.modules.get("app_window")
)
if _MAIN is not None:
    globals().update(_MAIN.__dict__)

# Safety net: ensure Qt symbols exist even when __main__ differs (e.g., frozen builds)
try:
    from app.qt_imports import *  # noqa: F401,F403
except Exception:
    pass


# ====================================
# = GET TABLE HELPERS ==
# ===================================

def _header_texts_lower(self):
        out = []
        for c in range(self.vaultTable.columnCount()):
            hi = self.vaultTable.horizontalHeaderItem(c)
            out.append(hi.text().strip().lower() if hi else "")
        return out

def _find_col_by_labels2(self, names: set[str]) -> int:
    want = {s.lower() for s in names}
    for i, t in enumerate(_header_texts_lower(self,)):
        if t in want:
            return i
    return -1


# ====================================
# = VAULT ENTRY CONTEXT MENU + ADD ENTRY DIALOG ==
# ===================================

def show_entry_context_menu(self, pos) -> None:
    """
    main context menu for vault entries (triggered by right-clicking a row in the vault table)
    Right-click context menu:
      • Copy (auto-clears) — per field + Copy All
      • Open Website
      • Check Email Breach (HIBP)
      • Show QR (URL/Wi-Fi) — Pro only
      • Install / Open (Games) — uses 'Install Link' or first URL/platform
      • Software actions — Run Executable / Open Executable Folder / Open Key Path
    """
    self.reset_logout_timer()
    if not getattr(self, "vaultTable", None):
        return

    def select_row_under_cursor() -> int:
        try:
            idx = self.vaultTable.indexAt(pos)
            if idx.isValid():
                self.vaultTable.selectRow(idx.row())
                return idx.row()
        except Exception:
            pass
        try:
            sel = self.vaultTable.selectionModel().selectedRows()
            if sel:
                return sel[0].row()
        except Exception:
            pass
        return -1

    def _read_item_value(item):
        if not item:
            return ""
        try:
            base = int(Qt.ItemDataRole.UserRole)
            for role in (base, base+1, base+2, base+3,
                         int(Qt.ItemDataRole.DisplayRole),
                         int(Qt.ItemDataRole.EditRole)):
                v = item.data(role)
                if v not in (None, ""):
                    return str(v)
        except Exception:
            pass
        try:
            return item.text() or ""
        except Exception:
            return ""

    def get_row_entry_with_headers(row: int) -> dict:
        entry = {}
        try:
            for col in range(self.vaultTable.columnCount()):
                header_item = self.vaultTable.horizontalHeaderItem(col)
                header_label = _kq_strip_ws(header_item.text() if header_item else f"Column {col}")
                item = self.vaultTable.item(row, col)
                entry[header_label] = _kq_strip_ws(_read_item_value(item))
        except Exception:
            pass
        return entry

    def first_url_in_entry(entry: dict) -> str:
        preferred = ("Install Link", "Website", "Site", "Profile URL", "Platform", "Login URL", "URL", "Link")
        for key in preferred:
            v = entry.get(key, "")
            if v:
                return str(v).strip()
        for key, val in entry.items():
            vv = str(val or "").strip()
            if not vv:
                continue
            if any(tok in key.lower() for tok in ("website", "url", "link", "site", "platform")) or vv.startswith(("http://", "https://", "steam://", "epic://", "origin://", "uplay://")):
                return vv
        return ""

    def make_wifi_qr_payload(entry: dict):
        keys = list(entry.keys())
        ssid_keys = [k for k in keys if "ssid" in k.lower()] \
                    or [k for k in keys if "wifi" in k.lower() and "name" in k.lower()] \
                    or [k for k in keys if k.lower() in ("network", "network name")]
        ssid = entry.get(ssid_keys[0], "").strip() if ssid_keys else ""
        if not ssid:
            return None
        auth_keys = [k for k in keys if any(s in k.lower() for s in ("auth", "security", "type", "enc", "cipher"))]
        pass_keys = [k for k in keys if any(s in k.lower() for s in ("pass", "password", "key", "pwd"))]
        hidn_keys = [k for k in keys if "hidden" in k.lower()]
        auth = entry.get(auth_keys[0], "").strip() if auth_keys else ""
        pwd  = entry.get(pass_keys[0], "").strip() if pass_keys else ""
        hidden_raw = (entry.get(hidn_keys[0], "") if hidn_keys else "").strip().lower()
        hidden = hidden_raw in ("1", "true", "yes", "y")
        t = (auth or "").upper()
        if t not in ("WPA", "WEP", "NOPASS"):
            t = "WPA" if pwd else "NOPASS"
        parts = [f"WIFI:T:{t};S:{ssid};"]
        if pwd and t != "NOPASS":
            parts.append(f"P:{pwd};")
        if hidden:
            parts.append("H:true;")
        parts.append(";")
        return ("Wi-Fi: " + ssid, "".join(parts))

    def confirm(title, text) -> bool:
        mb = QMessageBox(self)
        mb.setIcon(QMessageBox.Warning)
        mb.setWindowTitle(title)
        mb.setText(text)
        mb.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        mb.setDefaultButton(QMessageBox.No)
        return mb.exec() == QMessageBox.Yes

    # ---------- Software helpers ----------
    software_root = getattr(self, "software_root", None) or self._init_software_root()

    def _expand_path(p: str) -> str:
        if not p:
            return ""
        p2 = os.path.expandvars(os.path.expanduser(p.strip()))

        # If it's relative, normalize against software_root
        if not os.path.isabs(p2) and software_root:
            # Avoid ".../software/software/..." if user already typed "software\..."
            norm = p2.replace("/", "\\")
            if norm.lower().startswith("software\\"):
                norm = norm[9:]  # strip "software\\"
            p2 = os.path.join(software_root, norm)

        return os.path.normpath(p2)

    def _is_executable_path(p: str) -> bool:
        if not p:
            return False
        p = _expand_path(p)
        # Accept exe-ish things and simple launchers
        ext = os.path.splitext(p)[1].lower()
        return os.path.exists(p) and ext in (".exe", ".lnk", ".bat", ".cmd", ".msi")

    def _reveal_in_explorer(p: str):
        try:
            p = _expand_path(p)
            if os.path.isdir(p):
                subprocess.Popen(["explorer", p])
            elif os.path.isfile(p):
                subprocess.Popen(["explorer", "/select,", p])
        except Exception as e:
            log.info(f"[WARN] reveal failed: {e}")

    def _run_exec(p: str) -> bool:
        try:
            p = _expand_path(p)
            if not _is_executable_path(p):
                return False
            open_path(p)  # user-triggered
            return True
        except Exception as e:
            log.info(f"[WARN] run exec failed: {e}")
            return False

    # ---------- main flow ----------
    row = select_row_under_cursor()
    if row < 0:
        return
    entry = get_row_entry_with_headers(row)

    menu = QMenu(self)

    # Copy submenu
    copy_menu = menu.addMenu("Copy (auto-clears)")
    for label, value in entry.items():
        act = copy_menu.addAction(label)
        from features.clipboard.secure_clipboard import secure_copy
        act.triggered.connect(lambda _=False, v=value: secure_copy(v, self.clipboard_timeout, self.currentUsername.text()))

    def _copy_all():
        lines = [f"{k}: {v}" for k, v in entry.items() if v not in (None, "")]
        from features.clipboard.secure_clipboard import secure_copy
        secure_copy("\n".join(lines), self.clipboard_timeout, self.currentUsername.text())
        if hasattr(self, "_toast"): self._toast("Code copied")

    copy_menu.addAction("Copy All").triggered.connect(lambda _=False: _copy_all())

    # Open Website
    url = first_url_in_entry(entry)
    if url:
        act_open = menu.addAction(self.tr("Open Website"))
        act_open.triggered.connect(
            lambda _=False, raw=url: self.open_url_with_warnings(raw)
        )

    # Determine current category
    try:
        cat2 = getattr(self, "categorySelector_2", None)
        cat1 = getattr(self, "categorySelector", None)
        current_category = ((cat2.currentText() if cat2 else "") or
                            (cat1.currentText() if cat1 else "") or "")
        current_category = str(current_category).strip()
    except Exception:
        current_category = ""

    # Install / Open (Games)
    # Install / Open (Games)
    if current_category.lower() == "games":
        platform_hint = (entry.get("Platform") or current_category or "")
        platform_hint = str(platform_hint).strip().lower()
        install_link = (entry.get("Install Link") or url or "")
        install_link = str(install_link).strip()

        label = "🎮 Install / Open"
        act_install = menu.addAction(label)

        has_target = bool(install_link or platform_hint)


        if not has_target:
            act_install.setEnabled(False)
            act_install.setToolTip(self.tr("No Install Link/URL or Platform found"))
        else:
            safe_link = install_link
            safe_platform = platform_hint
            act_install.setStatusTip("Install or open the selected game")
            act_install.triggered.connect(
                lambda _=False, lk=safe_link, plat=safe_platform: self.launch_or_download(lk, plat)
            )

  
    # ▶ Software actions
    if current_category.lower() == "software":
        # --- resolve software root for relative paths ---
        from app.paths import software_dir as software_root

        def _expand_path(p: str) -> str:
            if not p:
                return ""
            p2 = os.path.expandvars(os.path.expanduser(p))
            if not os.path.isabs(p2) and software_root:
                p2 = os.path.normpath(os.path.join(software_root, p2))
            return os.path.normpath(p2)

        def _is_executable_path(p: str) -> bool:
            if not p:
                return False
            p = _expand_path(p)
            return os.path.exists(p) and os.path.splitext(p)[1].lower() in (".exe", ".lnk", ".bat", ".cmd")

        def _reveal_in_explorer(p: str):
            try:
                p = _expand_path(p)
                if os.path.isdir(p):
                    subprocess.Popen(["explorer", p])
                elif os.path.isfile(p):
                    subprocess.Popen(["explorer", "/select,", p])
            except Exception as e:
                log.info(f"[WARN] reveal failed: {e}")

        def _run_exec(p: str) -> bool:
            try:
                p = _expand_path(p)
                if not _is_executable_path(p):
                    return False
                open_path(p)  # user-triggered
                return True
            except Exception as e:
                log.info(f"[WARN] run exec failed: {e}")
                return False

        # --- pull values by fuzzy header match (handles 'Executable Path', etc.) ---
        def _pick(entry: dict, want: str) -> str:
            wl = want.lower()
            # exacts first
            if wl == "exec":
                for k in entry.keys():
                    if k.strip().lower() in ("executable path", "executable", "exe", "path"):
                        v = (entry.get(k) or "").strip()
                        if v:
                            return v
            if wl == "key":
                for k in entry.keys():
                    if k.strip().lower() in ("key path", "license", "key", "license key"):
                        v = (entry.get(k) or "").strip()
                        if v:
                            return v
            # fuzzy contains
            for k in entry.keys():
                kl = k.lower()
                if wl == "exec" and ("exec" in kl or kl.endswith("path")):
                    v = (entry.get(k) or "").strip()
                    if v:
                        return v
                if wl == "key" and ("key" in kl or "license" in kl):
                    v = (entry.get(k) or "").strip()
                    if v:
                        return v
            return ""

        exec_path = _pick(entry, "exec")
        key_path  = _pick(entry, "key")
        act_run = menu.addAction("▶ Run Executable")
        act_open_folder = menu.addAction("🗂 Open Executable Folder")
        act_open_key = menu.addAction("🔑 Open Key Path")

        # enable/disable
        if not exec_path:
            act_run.setEnabled(False); act_open_folder.setEnabled(False)
            act_run.setToolTip(self.tr("No Executable path set"))
            act_open_folder.setToolTip(self.tr("No Executable path set"))
        if not key_path:
            act_open_key.setEnabled(False); act_open_key.setToolTip(self.tr("No Key Path set"))

        # wire actions (capture now)
        ep = exec_path
        kp = key_path
        act_run.triggered.connect(
            lambda _=False, raw=ep: (
                _run_exec(raw) or
                QMessageBox.warning(self, "Run",
                    f"Invalid Executable path.\n\nResolved to:\n{_expand_path(raw)}")
            )
        )
        
        act_open_folder.triggered.connect(lambda _=False, p=ep: _reveal_in_explorer(p))
        act_open_key.triggered.connect(
            lambda _=False, p=kp: (
                subprocess.Popen(["explorer", _expand_path(p)]) if os.path.isdir(_expand_path(p)) else
                (open_path(_expand_path(p)) if os.path.isfile(_expand_path(p))
                    else QMessageBox.warning(self, self.tr("Key"), self.tr("Key Path not found.")))
            )
        )


    # Check Email Breach
    for key, val in entry.items():
        if "email" in key.lower():
            email = (val or "").strip()
            if email:
                menu.addAction("🔍 Check Email Breach").triggered.connect(
                    lambda _=False, e=email: QDesktopServices.openUrl(QUrl(f"https://haveibeenpwned.com/account/{quote(e)}"))
                )
            break

    # Show QR (URL / Wi-Fi) — Pro only
    act_qr = menu.addAction("Show QR (URL / Wi-Fi)")
    try:
        self.enforce_pro_feature(act_qr, "QR Code Preview")
    except Exception:
        pass
   
    
    wifi_pair = make_wifi_qr_payload(entry)
    if wifi_pair is not None:
        title, payload = wifi_pair
    else:
        url_payload = first_url_in_entry(entry)
        if url_payload and not url_payload.lower().startswith(("http://", "https://")):
            url_payload = "https://" + url_payload
        title, payload = ("Open URL", url_payload) if url_payload else (None, None)
    if not payload:
        act_qr.setEnabled(False)
    else:
        from features.qr.qr_tools import QRPreviewDialog
        act_qr.triggered.connect(lambda _=False, t=title, p=payload: QRPreviewDialog(t, p, self).exec())

    # Show menu at cursor
    global_pos = self.vaultTable.viewport().mapToGlobal(pos)
    menu.exec(global_pos)

def open_add_entry_dialog(self, *args, **kwargs):
    """Open "Add Entry" flow (accessed via main menu and category-specific "Add" buttons) — opens AddEntryDialog, saves on Accept, refreshes table"""
    if not self._require_unlocked(): 
        return
    def _safe_dirname(name: str) -> str:
        return "".join(c for c in (name or "item").strip() if c not in '<>:"/\\|?*')

    def _expand(p: str) -> str:
        return os.path.expandvars(os.path.expanduser(p or ""))

    def _under_root(path: str, root: str) -> bool:
        try:
            return os.path.abspath(path).lower().startswith(os.path.abspath(root).lower() + os.sep)
        except Exception:
            return False

    def _rel_to_root(path: str, root: str) -> str:
        try:
            return os.path.relpath(path, start=root)
        except Exception:
            return path

    self.set_status_txt(self.tr("Adding to Vault"))
    log.debug("%s Trying Open Add Entry", kql.i('ui'))
    self.reset_logout_timer()

    # must be signed in
    username = self._active_username()
    if not username or not getattr(self, "core_session_handle", None):
        QMessageBox.warning(self, self.tr("Add Entry"), self.tr("Unlock your vault first."))
        return

    # free-limit gate (keep existing policy)
    try:
        current = load_vault(username, getattr(self, 'core_session_handle', None) or self.core_session_handle) or []
        if not self.can_add_entry():
            return
    except Exception:
        pass
    from app.dev import dev_ops
    is_dev = dev_ops.dev_set
    # pick category from UI
    category = self.categorySelector_2.currentText()
    dlg = AddEntryDialog(
        self,
        category,
        self.enable_breach_checker,
        user=username,is_dev=is_dev,
    )
    self._track_window(dlg)

    if dlg.exec() != QDialog.DialogCode.Accepted:
        return

    # re-check limit post-dialog (if needed)
    try:
        if not self.can_add_entry():
            return
    except Exception:
        pass

    # payload from dialog
    try:
        entry = dlg.get_entry_data() or {}
    except Exception:
        log.exception("[UI ADD] could not read dialog entry")
        return

    # ---- Software attachment handling (safe; failures don’t block saving) ----
    try:
        if (entry.get("category", "").strip().lower() == "software"):

            # per-user software root (under %APPDATA%/Keyquorum/Users/<user>/Software)
            try:
                from app.paths import soft_user_dir
                software_root = soft_user_dir(username, ensure_dir=True)  # returns Path
                software_root = str(software_root)
                os.makedirs(software_root, exist_ok=True)
            except Exception:
                software_root = None

            if software_root:
                name = (entry.get("Name", "").strip() or "software")
                dest_dir = os.path.join(software_root, _safe_dirname(name))
                os.makedirs(dest_dir, exist_ok=True)

                # Executable Path
                exe_path_raw = (entry.get("Executable Path") or entry.get("Executable") or entry.get("Exe") or "").strip()
                exe_src = _expand(exe_path_raw)
                if exe_src and not os.path.isabs(exe_src) and exe_src.lower().startswith(("software\\", "software/")):
                    exe_src = _expand(exe_src[9:])
                if exe_src and os.path.exists(exe_src):
                    if _under_root(exe_src, software_root):
                        entry["Executable Path"] = _rel_to_root(exe_src, software_root)
                    else:
                        ext = os.path.splitext(exe_src)[1].lower()
                        if ext in (".exe", ".msi", ".lnk", ".bat", ".cmd"):
                            dest_file = os.path.join(dest_dir, os.path.basename(exe_src))
                            do_copy = True
                            if os.path.exists(dest_file):
                                try:
                                    s1, s2 = os.stat(exe_src), os.stat(dest_file)
                                    if s1.st_size == s2.st_size and abs(s1.st_mtime - s2.st_mtime) < 1.0:
                                        do_copy = False
                                except Exception:
                                    pass
                            if do_copy:
                                try:
                                    copy2(exe_src, dest_file)
                                except Exception as e:
                                    self.safe_messagebox_warning(
                                        self,
                                        self.tr("Executable Copy"),
                                        self.tr(
                                            "Failed to copy executable:\n{exe_src}\n→ {dest_file}\n\n{e}\n\n"
                                            "Entry will keep the original path."
                                        ).format(exe_src=exe_src, dest_file=dest_file, e=e),
                                    )
                                    entry["Executable Path"] = exe_src
                                else:
                                    entry["Executable Path"] = _rel_to_root(dest_file, software_root)
                            else:
                                entry["Executable Path"] = _rel_to_root(dest_file, software_root)
                        else:
                            entry["Executable Path"] = exe_src
                elif exe_path_raw:
                    self.safe_messagebox_warning(
                        self,
                        self.tr("Executable Path"),
                        self.tr("Source not found:\n{exe_path_raw}").format(exe_path_raw=exe_path_raw),
                    )
                    entry["Executable Path"] = exe_path_raw

                # Key Path (optional single file)
                key_path_raw = (entry.get("Key Path") or entry.get("License") or entry.get("Key") or "").strip()
                if key_path_raw:
                    key_src = _expand(key_path_raw)
                    if not os.path.isabs(key_src) and key_src.lower().startswith(("software\\", "software/")):
                        key_src = _expand(key_src[9:])
                    if key_src and os.path.exists(key_src):
                        if _under_root(key_src, software_root):
                            entry["Key Path"] = _rel_to_root(key_src, software_root)
                        else:
                            if os.path.isfile(key_src):
                                dest_key = os.path.join(dest_dir, os.path.basename(key_src))
                                do_copy = True
                                if os.path.exists(dest_key):
                                    try:
                                        s1, s2 = os.stat(key_src), os.stat(dest_key)
                                        if s1.st_size == s2.st_size and abs(s1.st_mtime - s2.st_mtime) < 1.0:
                                            do_copy = False
                                    except Exception:
                                        pass
                                if do_copy:
                                    try:
                                        copy2(key_src, dest_key)
                                    except Exception as e:
                                        self.safe_messagebox_warning(
                                        self,
                                        self.tr("Key Copy"),
                                        self.tr(
                                            "Failed to copy key file:\n{key_src}\n→ {dest_key}\n\n{e}\n\n"
                                            "Entry will keep the original path."
                                        ).format(key_src=key_src, dest_key=dest_key, e=e),)

                                        entry["Key Path"] = key_src
                                    else:
                                        entry["Key Path"] = _rel_to_root(dest_key, software_root)
                                else:
                                    entry["Key Path"] = _rel_to_root(dest_key, software_root)
                            else:
                                entry["Key Path"] = key_src
                    else:
                        self.safe_messagebox_warning(
                            self,
                            self.tr("Key Path"),
                            self.tr("Path not found:\n{key_path_raw}").format(key_path_raw=key_path_raw),
                        )
                        entry["Key Path"] = key_path_raw

    except Exception:
        # don’t block saving if attachment logic fails
        log.exception("[UI ADD] software attachment handling failed")

    # ---- Persist (ALWAYS runs on accept) ---------------------------------------
    try:
        add_vault_entry(username, self.core_session_handle, entry)
        log.debug("%s [UI OPEN] Added entry to vault", kql.i('ui'))
    except Exception:
        log.exception("[UI ADD] Persist failed")
        QMessageBox.critical(self, self.tr("Vault"), self.tr("Could not save the entry."))
        return

    # ---- Post-save UI / baseline / refresh ------------------------------------
    try:
        self._on_any_entry_changed()
    except Exception:
        pass

    try:
        update_baseline(username=username, verify_after=False, who=f"Added Entry To Vault")
    except Exception:
        pass

    try:
        if "category" in entry:
            self.categorySelector_2.setCurrentText(entry.get("category", "Passwords"))
    except Exception:
        pass

    try:
        # some builds require username param
        if self.load_vault_table.__code__.co_argcount >= 2:
            self.load_vault_table(username)
        else:
            self.load_vault_table()
    except Exception as e:
        log.error("%s [ERROR] Failed to refresh vault table: %s", kql.i('ui'), e)

    try:
        QtWidgets.QMessageBox.information(self, self.tr("Vault"), self.tr("Entry added successfully."))
    except Exception:
        pass

    self.set_status_txt(self.tr("Done"))

def _get_selected_entry(self, *args, **kwargs) -> dict | None:
    """
    Get selected vault entry as a dict, with guaranteed keys and heuristics to fill in missing values.
    Return a dict for the selected vault row.

    Guaranteed keys:
      - title, username, email, password, category, _row

    Extra:
      - merges all column values from the row (e.g. Platform, Install Link,
        Game Name, URL, etc.) so features like auto-launch can use them.
    """
    tbl = getattr(self, "vaultTable", None)
    if tbl is None:
        return None

    sel = tbl.selectionModel().selectedRows() if tbl.selectionModel() else []
    if not sel:
        idx = tbl.currentIndex()
        if idx and idx.isValid():
            sel = [idx.sibling(idx.row(), 0)]
        else:
            return None

    row = sel[0].row()

    # ---------- Helper: detect masked-looking values ----------
    def _looks_masked(s: str | None) -> bool:
        if not s:
            return False
        # handle *, •, ● etc.
        mask_chars = {"*", "•", "●"}
        return all(ch in mask_chars for ch in s) and len(s) >= 4

    def _canonical_header_role(text: str | None) -> str | None:
        from app.app_translation_fields import (
            USERNAME_HEADER_LABELS,
            EMAIL_LABELS,
            PRIMARY_PASSWORD_LABELS,
        )
        t = (text or "").strip().lower()
        if not t:
            return None
        if t in USERNAME_HEADER_LABELS:
            return "username"
        if t in EMAIL_LABELS:
            return "email"
        if t in PRIMARY_PASSWORD_LABELS or "pass" in t:
            return "password"
        # Fallback heuristics – English-ish
        if "user" in t and "id" not in t and "guid" not in t:
            return "username"
        if "mail" in t:
            return "email"
        if "pwd" in t:
            return "password"
        return None

    def _is_password_header(text: str | None) -> bool:
        return _canonical_header_role(text) == "password"

    # ---------- Try to read a full dict from any column's UserRole ----------
    for c in range(tbl.columnCount()):
        item = tbl.item(row, c) if hasattr(tbl, "item") else None
        data = None
        if item is not None:
            data = item.data(Qt.UserRole)
        else:
            model = getattr(tbl, "model", lambda: None)()
            if model:
                data = model.data(model.index(row, c), Qt.UserRole)

        if isinstance(data, dict) and data:
            # ensure _row is present
            d = dict(data)
            d.setdefault("_row", row)
            return d

    # ---------- Otherwise, build it from headers / cell text ----------
    title = ""
    username = ""
    email = ""
    password = ""

    try:
        # First pass: pick up obvious username/email/password by header role
        pw_col = None
        for col in range(tbl.columnCount()):
            header = tbl.horizontalHeaderItem(col)
            header_txt = header.text() if header else ""
            role = _canonical_header_role(header_txt)

            item = tbl.item(row, col)
            cell_txt = item.text() if item else ""

            if role == "username" and not username:
                username = (cell_txt or "").strip()
            elif role == "email" and not email:
                email = (cell_txt or "").strip()
            elif role == "password":
                pw_col = col

        # Second pass: title/name heuristics
        for col in range(tbl.columnCount()):
            header = tbl.horizontalHeaderItem(col)
            htxt = (header.text() if header else "").strip().lower()
            item = tbl.item(row, col)
            cell_txt = (item.text() if item else "").strip()

            if not title and htxt in {"title", "name", "game name", "site", "website"}:
                title = cell_txt

            # If we still don't have username/email, try simple guesses
            if not username and "user" in htxt:
                username = cell_txt
            if not email and ("mail" in htxt or "e-mail" in htxt):
                email = cell_txt

        # Password: prefer Qt.UserRole to avoid masked text
        if pw_col is not None:
            pw_item = tbl.item(row, pw_col)
            pw_data = pw_item.data(Qt.UserRole) if pw_item else None
            if isinstance(pw_data, str) and pw_data:
                password = pw_data
            elif isinstance(pw_data, dict):
                password = (
                    pw_data.get("password")
                    or pw_data.get("_password")
                    or pw_data.get("real_password")
                    or pw_data.get("plain_password")
                    or password
                )
            else:
                cell_txt = pw_item.text() if pw_item else ""
                if not _looks_masked(cell_txt):
                    password = cell_txt.strip()
    except Exception:
        pass

    # Category from UI if available
    category = getattr(self, "currentCategory", None) or getattr(
        self, "categorySelector_2", None
    )
    if hasattr(category, "currentText"):
        category = category.currentText()
    category = (category or "").strip()

    base = {
        "title": title,
        "username": username,
        "email": email,
        "password": password,
        "category": category,
        "_row": row,
    }

    # ---------- Merge full row dict (Platform, Install Link, etc.) ----------
    row_meta = {}
    try:
        if hasattr(self, "_get_row_entry_dict"):
            row_meta = self._get_row_entry_dict(row) or {}
    except Exception:
        row_meta = {}

    if isinstance(row_meta, dict):
        for k, v in row_meta.items():
            # don't overwrite the canonical keys we just computed
            if k not in base and v is not None:
                base[k] = v

    return base

def load_vault_table(self, *args, **kwargs):
    """Load vault entries for the active user and display in the table, with support for category filtering,
    dynamic headers based on category schema, sensitive field masking with toggle, and expiration highlighting.
    """

    from qtpy.QtCore import Qt, QSignalBlocker, QTimer, QElapsedTimer
    from qtpy.QtGui import QColor, QBrush
    from qtpy.QtWidgets import QTableWidgetItem, QHeaderView

    self.set_status_txt(self.tr("loading Vault Table"))
    self.vaultSearchBox.clear()

    if not getattr(self, "core_session_handle", None) and not getattr(self, "core_session_handle", None):
        return

    t_all = QElapsedTimer()
    t_all.start()

    username = self._active_username()
    key_or_session = getattr(self, "core_session_handle", None) or self.core_session_handle

    # ---- Load vault (cached in vault_store.py already)
    t_dec = QElapsedTimer()
    t_dec.start()
    all_entries = load_vault(username, key_or_session) or []
    dec_ms = t_dec.elapsed()

    # ---- Category filter
    category = self.categorySelector_2.currentText() if hasattr(self, "categorySelector_2") else "Passwords"
    cat_lc = category.lower()

    # ---- Build headers from schema meta
    meta = self.user_field_meta_for_category(category) or []
    if not meta:
        return

    headers = [m["label"] for m in meta if not m.get("hide")]
    if "Date" not in headers:
        headers.append("Date")

    sensitive_set = {m["label"].lower() for m in meta if m.get("sensitive")}
    try:
        from catalog_category.category_fields import sensitive_data_values
        for s in sensitive_data_values():
            sensitive_set.add(str(s).lower())
    except Exception:
        pass

    # ---- Expiration config
    try:
        raw_name = (username or "").strip()
        try:
            username_ci = _canonical_username_ci(raw_name) or raw_name
        except Exception:
            username_ci = raw_name
        expiration_days = int(get_user_setting(username_ci, "password_expiry_days", 180))
    except Exception:
        expiration_days = 180

    import datetime as dt
    from datetime import timedelta
    expiration_threshold = timedelta(days=int(expiration_days))

    # ---- Expand headers: add "👁" column AFTER each sensitive field
    expanded_headers = []
    eye_to_data_col = {}   # eye_col_index -> data_col_index
    data_col = 0
    for h in headers:
        expanded_headers.append(h)
        if h.lower() in sensitive_set:
            expanded_headers.append("👁")
            # eye column will be (current expanded_headers index - 1), data col is (index - 2)
            eye_to_data_col[len(expanded_headers) - 1] = len(expanded_headers) - 2
        data_col += 1
    expanded_headers.append("Password Expired")

    # ---- Filter entries once (and keep index map for edit/delete)
    filtered = []
    idx_map = []
    for idx, entry in enumerate(all_entries):
        try:
            if str(entry.get("category", "Passwords")).lower() != cat_lc:
                continue
        except Exception:
            continue
        filtered.append(entry)
        idx_map.append(idx)

    self.current_entries_indices = idx_map

    table = self.vaultTable

    # ---- One-time click handler for 👁 toggle (disconnect old safely)
    try:
        table.cellClicked.disconnect()
    except Exception:
        pass

    def _toggle_sensitive_at(row: int, col: int):
        # Toggle if user clicked on an 👁 column OR clicked the sensitive cell itself
        target_col = None
        if col in eye_to_data_col:
            target_col = eye_to_data_col[col]
        # Optional: allow clicking the masked cell to toggle too
        elif col + 1 in eye_to_data_col and eye_to_data_col[col + 1] == col:
            target_col = col

        if target_col is None:
            return

        it = table.item(row, target_col)
        if not it:
            return
        real = it.data(int(Qt.ItemDataRole.UserRole))
        if not real:
            return

        cur = it.text() or ""
        if cur.startswith("●"):
            it.setText(str(real))
        else:
            it.setText("●●●●●●●●")

    table.cellClicked.connect(_toggle_sensitive_at)

    # ---- Fast table prep
    blocker = QSignalBlocker(table)
    table.setSortingEnabled(False)
    table.setUpdatesEnabled(False)
    table.clear()
    table.setColumnCount(len(expanded_headers))
    table.setHorizontalHeaderLabels(expanded_headers)
    table.setRowCount(len(filtered))
    try:
        table.setUniformRowHeights(True)
    except Exception:
        pass

    # Avoid expensive "auto fit" on huge tables
    header = table.horizontalHeader()
    try:
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
    except Exception:
        pass

    try:
        table.setColumnWidth(0, 250)
        if table.columnCount() > 1:
            table.setColumnWidth(1, 300)
    except Exception:
        pass

    # ---- Precompute reused sensitive values (count only, cheap)
    reuse_count = {}
    for e in filtered:
        for h in headers:
            if h.lower() not in sensitive_set:
                continue
            v = e.get(h, "")
            if v:
                reuse_count[v] = reuse_count.get(v, 0) + 1

    # ---- Batched fill so UI stays responsive (prevents “Python not responding”)
    BATCH = 250  # tune if needed
    state = {
        "row": 0,
        "filtered": filtered,
        "headers": headers,
        "sensitive_set": sensitive_set,
        "reuse_count": reuse_count,
        "expiration_threshold": expiration_threshold,
        "start_ms": t_all.elapsed(),
        "token": getattr(self, "_vault_fill_token", 0) + 1,
    }
    self._vault_fill_token = state["token"]

    def _fill_batch():
        # cancel if a new load started (category changed etc.)
        if getattr(self, "_vault_fill_token", 0) != state["token"]:
            return

        row = state["row"]
        filtered_local = state["filtered"]
        headers_local = state["headers"]
        sensitive_local = state["sensitive_set"]
        reuse_local = state["reuse_count"]

        end = min(row + BATCH, len(filtered_local))
        for r in range(row, end):
            entry = filtered_local[r]
            col_offset = 0

            for col, h in enumerate(headers_local):
                value = entry.get(h, "")
                low_h = h.lower()
                is_sensitive = (low_h in sensitive_local)

                masked = "●●●●●●●●" if is_sensitive and value else str(value)
                item = QTableWidgetItem(masked)

                if is_sensitive:
                    item.setData(int(Qt.ItemDataRole.UserRole), value)
                    if value and reuse_local.get(value, 0) > 1:
                        item.setForeground(QBrush(QColor(Qt.GlobalColor.red)))

                table.setItem(r, col + col_offset, item)

                if is_sensitive:
                    # Put an eye item in the next column (NO QWidget)
                    eye_item = QTableWidgetItem(self.tr("👁"))
                    eye_item.setTextAlignment(Qt.AlignCenter)
                    eye_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                    table.setItem(r, col + col_offset + 1, eye_item)
                    col_offset += 1

            # Expired column (last)
            last_col = table.columnCount() - 1
            date_val = entry.get("Date", "")
            try:
                if date_val:
                    d = dt.datetime.strptime(str(date_val).strip(), "%Y-%m-%d")
                    age = dt.datetime.now() - d
                    expired = age > state["expiration_threshold"]
                    days_left = (state["expiration_threshold"] - age).days
                    itx = QTableWidgetItem(self.tr("❌ True") if expired else self.tr("✅ False"))
                    itx.setTextAlignment(Qt.AlignCenter)
                    if expired:
                        itx.setForeground(QBrush(QColor(Qt.GlobalColor.red)))
                    elif days_left < 30:
                        itx.setForeground(QBrush(QColor(Qt.GlobalColor.darkYellow)))
                    else:
                        itx.setForeground(QBrush(QColor(Qt.GlobalColor.green)))
                else:
                    itx = QTableWidgetItem(self.tr("Unknown"))
            except Exception:
                itx = QTableWidgetItem(self.tr("Invalid"))
            table.setItem(r, last_col, itx)

        state["row"] = end

        # keep session alive without doing it 10k times
        try:
            self.reset_logout_timer()
        except Exception:
            pass

        if end < len(filtered_local):
            self.set_status_txt(self.tr(f"Loading… {end}/{len(filtered_local)}"))
            QTimer.singleShot(0, _fill_batch)
        else:
            # Done
            table.setUpdatesEnabled(True)
            self.set_status_txt(self.tr("Vault loaded"))
            total_ms = t_all.elapsed()
            try:
                log.debug(f"[PERF] decrypt={dec_ms}ms table={total_ms - dec_ms}ms total={total_ms}ms rows={len(filtered_local)}")
            except Exception:
                pass

    QTimer.singleShot(0, _fill_batch)

def _move_row_to_category_full(self, row: int, new_type: str) -> str:
    """
    move entry to another category (triggered by "Move to {Category}" action in the category submenu of the row context menu)
    Open AddEntryDialog for the target category, prefill from the source row,
    and persist via update_vault_entry(...).

    Returns: 'success' | 'cancelled' | 'failed'
    """
    try:
        log.debug(str(f"{kql.i('update')} [MOVE] Requested move for row={row}, target='{new_type}'"))

        # guards
        if not getattr(self, "vaultTable", None):
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} vaultTable is missing"))
            return "failed"
        if row is None or row < 0 or row >= self.vaultTable.rowCount():
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} Row index out of range: {row}"))
            return "failed"

        # refuse if target/source are protected
        if self._is_blocked_target(new_type):
            log.debug("[MOVE] target category blocked")
            return "failed"
        try:
            if self._is_blocked_source(self._category_for_row(row)):
                log.debug("[MOVE] source category blocked")
                return "failed"
        except Exception:
            pass

        # load source entry + global index
        try:
            entries = load_vault(self.currentUsername.text(), getattr(self, 'core_session_handle', None) or self.core_session_handle)
            try:
                global_index = self.current_entries_indices[row]
            except Exception:
                global_index = row
            src_entry = entries[global_index]
        except Exception as e:
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} Could not load entry for row {row}: {e}"))
            return "failed"

        # create dialog for target category
        try:
            dlg = AddEntryDialog(self, new_type, self.enable_breach_checker, pro=None,
            user=self.currentUsername.text(),is_dev=is_dev)
            dlg.setWindowTitle(self.tr("Move Entry: {row1} → {new}").format(row1=self._category_for_row(row), new=new_type))
        except Exception as e:
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} Could not Move AddEntryDialog: {e}"))
            return "failed"

        # force dialog to build the UI for the TARGET category
        def _force_dialog_category(dlg_obj, cat: str):
            try:
                if hasattr(dlg_obj, "categoryCombo"):
                    dlg_obj.categoryCombo.setCurrentText(cat)
                    for name in ("on_category_changed", "_on_category_changed", "category_changed"):
                        if hasattr(dlg_obj, name):
                            try:
                                getattr(dlg_obj, name)()
                            except Exception:
                                pass
                elif hasattr(dlg_obj, "set_category"):
                    dlg_obj.set_category(cat)
                elif hasattr(dlg_obj, "category"):
                    dlg_obj.category = cat
                    for name in ("build_form", "_build_form", "rebuild_form"):
                        if hasattr(dlg_obj, name):
                            try:
                                getattr(dlg_obj, name)()
                            except Exception:
                                pass
            except Exception as e:
                try:
                    log.debug(str(f"{kql.i('update')} [MOVE] category force warn: {e}"))
                except Exception:
                    pass

        _force_dialog_category(dlg, new_type)

        # if the dialog can build fields from meta, feed it the user's schema
        if hasattr(dlg, "set_fields_from_meta") and callable(dlg.set_fields_from_meta):
            try:
                dlg.set_fields_from_meta(self.user_field_meta_for_category(new_type))
                for name in ("build_form", "_build_form", "rebuild_form"):
                    if hasattr(dlg, name):
                        try:
                            getattr(dlg, name)()
                        except Exception:
                            pass
            except Exception:
                pass

        # robust prefill (bias to user's labels)
        def _norm(s: str) -> str:
            s = (s or "").strip().lower()
            return "".join(ch for ch in s if ch.isalnum())

        _syn = {
            "username": {"user", "login", "account", "accountname", "userid"},
            "email": {"mail", "emailaddress"},
            "password": {"pass", "passwd"},
            "website": {"url", "link", "domain"},
            "phone": {"phonenumber", "mobile", "tel", "telephone"},
            "2faenabled": {"twofactor", "mfa", "2fa"},
            "platform": {"store", "launcher", "service"},
            "gamename": {"title", "name"},
        }

        target_labels = self._user_schema_field_labels(new_type)
        _target_lc = {"".join(ch for ch in (lbl or "").lower() if ch.isalnum()): lbl
                      for lbl in target_labels}

        def _as_bool(v) -> bool:
            s = str(v).strip().lower()
            return s in ("1", "true", "yes", "on", "y", "t")

        def _set_widget_value(w, v):
            try:
                if isinstance(w, QLineEdit):
                    w.setText("" if v is None else str(v))
                    return True
                if isinstance(w, QPlainTextEdit):
                    w.setPlainText("" if v is None else str(v))
                    return True
                if isinstance(w, QTextEdit):
                    w.setPlainText("" if v is None else str(v))
                    return True
                if isinstance(w, QComboBox):
                    txt = "" if v is None else str(v)
                    i = w.findText(txt)
                    if i >= 0:
                        w.setCurrentIndex(i)
                    elif w.isEditable():
                        w.setEditText(txt)
                    return True
                if isinstance(w, QCheckBox):
                    w.setChecked(_as_bool(v))
                    return True
                if isinstance(w, QSpinBox):
                    try:
                        w.setValue(int(float(v)))
                    except Exception:
                        pass
                    return True
                if isinstance(w, QDoubleSpinBox):
                    try:
                        w.setValue(float(v))
                    except Exception:
                        pass
                    return True
                if isinstance(w, QDateEdit):
                    try:
                        s = str(v)
                        d = (QDate.fromString(s, "yyyy-MM-dd")
                             if "-" in s else QDate.fromString(s, "dd/MM/yyyy"))
                        if d.isValid():
                            w.setDate(d)
                    except Exception:
                        pass
                    return True
                if isinstance(w, QTimeEdit):
                    try:
                        t = QTime.fromString(str(v), "HH:mm:ss")
                        if not t.isValid():
                            t = QTime.fromString(str(v), "HH:mm")
                        if t.isValid():
                            w.setTime(t)
                    except Exception:
                        pass
                    return True
                if isinstance(w, QDateTimeEdit):
                    try:
                        dtv = QDateTime.fromString(str(v), "yyyy-MM-dd HH:mm:ss")
                        if not dtv.isValid():
                            dtv = QDateTime.fromString(str(v), "yyyy-MM-ddTHH:mm:ss")
                        if dtv.isValid():
                            w.setDateTime(dtv)
                    except Exception:
                        pass
                    return True
            except Exception:
                pass
            return False

        def _prefill_dialog(dlg_obj, src: dict) -> bool:
            any_set = False
            # normalize src keys + synonyms
            src_norm = {}
            for k, v in (src or {}).items():
                if not isinstance(k, str):
                    continue
                nk = _norm(k)
                src_norm[nk] = v
                for canon, alts in _syn.items():
                    if nk == canon or nk in alts:
                        src_norm[canon] = v
                        for a in alts:
                            src_norm[a] = v

            # 1) preferred: labeled fields mapping
            fields_map = getattr(dlg_obj, "fields", None)
            if isinstance(fields_map, dict) and fields_map:
                for label, widget in fields_map.items():
                    k = _norm(label)
                    # normalize common aliases
                    if k in ("gamenametitle", "name"):
                        k = "gamename"
                    if k in ("user", "login", "account", "accountname", "userid"):
                        k = "username"
                    if k in ("url", "domain", "link"):
                        k = "website"
                    if k in ("phonenumber", "mobile", "tel", "telephone"):
                        k = "phone"
                    if k in ("twofactor", "mfa", "2fa"):
                        k = "2faenabled"

                    # prefer exact normalized match in user's labels
                    if k in _target_lc:
                        val = src_norm.get(k)
                    else:
                        val = src_norm.get(k)

                    if val is not None and _set_widget_value(widget, val):
                        any_set = True

            # 2) common attribute names
            for attr, key in (
                ("websiteInput", "website"), ("emailInput", "email"), ("passwordInput", "password"),
                ("usernameInput", "username"), ("gameNameInput", "gamename"), ("platformInput", "platform"),
                ("phoneInput", "phone"), ("backupCodeInput", "backupcode"), ("notesInput", "notes"),
            ):
                if hasattr(dlg_obj, attr) and src_norm.get(key) is not None:
                    if _set_widget_value(getattr(dlg_obj, attr), src_norm.get(key)):
                        any_set = True



            # 3) last resort: objectName / accessibleName  (PySide6-safe)
            def _all_form_widgets(root):
                classes = (
                    QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QCheckBox,
                    QSpinBox, QDoubleSpinBox, QDateEdit, QTimeEdit, QDateTimeEdit,
                )
                widgets = []
                for cls in classes:
                    widgets.extend(root.findChildren(cls))  # PySide6: must call per-type
                return widgets

            for w in _all_form_widgets(dlg_obj):
                try:
                    nm = _norm(
                        (w.objectName() if hasattr(w, "objectName") else "") or
                        (w.accessibleName() if hasattr(w, "accessibleName") else "")
                    )
                except Exception:
                    nm = ""
                if not nm:
                    continue

                alias = {
                    "url": "website", "link": "website", "domain": "website",
                    "user": "username", "login": "username", "account": "username", "accountname": "username",
                    "gamename": "gamename", "platform": "platform", "phone": "phone", "phonenumber": "phone",
                    "backupcode": "backupcode", "notes": "notes", "email": "email", "password": "password",
                }.get(nm, nm)

                val = src_norm.get(alias)
                if val is not None and _set_widget_value(w, val):
                    any_set = True

            # 4) unmatched → Notes
            notes_widget = None
            fm = getattr(dlg_obj, "fields", None)
            if isinstance(fm, dict):
                notes_widget = fm.get("Notes") or fm.get("notes")
            if not notes_widget:
                for guess in ("notesInput", "notes", "txtNotes"):
                    if hasattr(dlg_obj, guess):
                        notes_widget = getattr(dlg_obj, guess)
                        break
            if notes_widget:
                known = {"username", "email", "password", "website", "phone", "backupcode", "notes",
                         "2faenabled", "platform", "gamename"}
                extras = {k: v for k, v in (src or {}).items()
                          if isinstance(k, str) and _norm(k) not in known and v not in (None, "")}
                if extras:
                    try:
                        existing = (notes_widget.toPlainText()
                                    if isinstance(notes_widget, (QPlainTextEdit, QTextEdit))
                                    else notes_widget.text())
                    except Exception:
                        existing = ""
                    block = "[Unmatched Fields]\n" + "\n".join(f"{k}: {v}" for k, v in extras.items())
                    text = (existing + ("\n\n" if existing else "") + block).strip()
                    _set_widget_value(notes_widget, text)
                    any_set = True

            try:
                log.debug(str(f"{kql.i('update')} [MOVE] {'✅' if any_set else '⚠️'} Prefill {'applied' if any_set else 'not applied'}"))
            except Exception:
                pass
            return any_set

        _prefill_dialog(dlg, src_entry)

        # run dialog (exec() returns int)
        result = dlg.exec()
        if int(result) != int(QDialog.Accepted):
            log.debug(str(f"{kql.i('update')} [MOVE] Cancelled by user (result={result})"))
            return "cancelled"

        # gather & force category/type/date
        try:
            new_entry = dlg.get_entry_data() or {}
            new_entry["category"] = new_type
            new_entry["Type"] = new_type
            new_entry["Date"] = dt.datetime.now().strftime("%Y-%m-%d")
        except Exception as e:
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} get_entry_data failed: {e}"))
            return "failed"

        # persist via canonical API (with signature fallback)
        
        persist_entry_with_history(self, self.currentUsername.text(), self.core_session_handle, global_index, new_entry)

        try:
            update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Moved Entry In Vault"))
        except Exception:
            pass
        try:
            self.load_vault_table()
        except Exception:
            pass
        log.debug(str(f"{kql.i('backup')} [MOVE] {kql.i('ok')} Persisted via update_vault_entry (idx={global_index})"))
        return "success"

    except Exception as e:
        log.error(str(f"{kql.i('update')} [ERROR] {kql.i('warn')} Unexpected error: {e}"))
        return "failed"

def on_move_category_clicked(self, *args):
    """
    Move Category Flow (accessed via right-click on a vault entry) — prompts for new category,
    offers quick move vs edit dialog, persists change, refreshes table/baseline
    """
    table = getattr(self, "vaultTable", None)
    if table is None or table.selectionModel() is None:
        QMessageBox.warning(self, self.tr("Move"), self.tr("Table not available."))
        return

    sel = table.selectionModel().selectedRows()
    if not sel:
        QMessageBox.information(self, self.tr("Move"), self.tr("Select a row to move first."))
        return
    row = sel[0].row()

    # current category of the selected row
    try:
        current_cat = self._category_for_row(row)
    except Exception:
        current_cat = ""

    # block: source category
    if self._is_blocked_source(current_cat):
        QMessageBox.information(self, self.tr("Move"), self.tr("Entries in 'Bank' or 'Credit Cards' cannot be moved."))
        return

    # build options ONCE, filtered against blocked targets
    options = [c for c in self._schema_category_names() if not self._is_blocked_target(c)]
    if not options:
        QMessageBox.information(self, self.tr("Move"), self.tr("No available target categories."))
        return

    default_idx = options.index(current_cat) if current_cat in options else 0

    # let the user choose the destination
    target, ok = QInputDialog.getItem(
        self, "Move to category", "Choose the new category/type:",
        options, default_idx, False
    )
    if not ok or not target:
        return
    target = target.strip()

    # safety: re-check chosen target
    if self._is_blocked_target(target):
        QMessageBox.information(self, self.tr("Move"), self.tr("You can’t move entries into that category."))
        return

    # Modifiers: Ctrl = Quick Move, Shift = Edit First
    mods = QApplication.keyboardModifiers()
    force_quick = bool(mods & Qt.ControlModifier)
    force_edit  = bool(mods & Qt.ShiftModifier)

    if force_quick:
        ok = self._quick_move_row_to_category(row, target)
        QMessageBox.information(self, self.tr("Move"), self.tr("Entry moved.") if ok else self.tr("Move failed."))
        return

    if not force_edit:
        choice = QMessageBox.question(
            self, "Move",
            "Quick move without editing?\n\n"
            "Yes = Move now (auto-map fields)\nNo = Open form to review before saving",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.No
        )
        if choice == QMessageBox.StandardButton.Cancel:
            QMessageBox.information(self, self.tr("Move"), self.tr("Move cancelled."))
            return
        if choice == QMessageBox.StandardButton.Yes:
            ok = self._quick_move_row_to_category(row, target)
            QMessageBox.information(self, self.tr("Move"), self.tr("Entry moved.") if ok else "Move failed.")
            return
        # else fall through to Edit First

    status = self._move_row_to_category_full(row, target)
    if status == "success":
        QMessageBox.information(self, self.tr("Move"), self.tr("Entry moved."))
    elif status == "cancelled":
        QMessageBox.information(self, self.tr("Move"), self.tr("Move cancelled."))
    else:
        QMessageBox.information(self, self.tr("Move"), self.tr("Move failed."))

def edit_selected_vault_entry(self, row, _column):
    """Edit Entry Flow (double-click on a vault entry) — opens AddEntryDialog prefilled with entry data,"""
    log.debug(str(f"{kql.i('vault')} [VAULT] edit selected vault entry called"))
    self.reset_logout_timer()
    try:
        entries = load_vault(self.currentUsername.text(), getattr(self, 'core_session_handle', None) or self.core_session_handle) or []
        try:
            global_index = self.current_entries_indices[row]
        except Exception:
            global_index = row

        if not (0 <= global_index < len(entries)):
            QtWidgets.QMessageBox.warning(self, self.tr("Edit Entry"), self.tr("Could not locate selected entry."))
            return

        entry = dict(entries[global_index])

                # pick category from UI
        category = self.categorySelector_2.currentText()

        dialog = AddEntryDialog(
            self,
            category,
            self.enable_breach_checker,
            existing_entry=entry,
            user=self.currentUsername.text(),
        )

        dialog._vault_index = global_index    # ✅ and the exact index

        self.reset_logout_timer()
        for label, widget in dialog.fields.items():
            if label == "2FA Enabled":
                (dialog.radio_yes if entry.get(label) == "True" else dialog.radio_no).setChecked(True)
            elif hasattr(widget, 'setText') and not callable(widget):
                widget.setText(entry.get(label, ""))

        if hasattr(dialog, "notesInput") and "Notes" in entry:
            dialog.notesInput.setPlainText(entry.get("Notes", ""))

        self.reset_logout_timer()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            updated = dialog.result_entry() or dialog.get_entry_data()
            # Keep Date fresh + ensure category survives
            updated["Date"] = dt.datetime.now().strftime("%Y-%m-%d")
            if "category" not in updated:
                updated["category"] = entry.get("category", "Passwords")              
            if "password" in updated and "Password" not in updated:
                updated["Password"] = updated["password"]
            # Save with history
            # Persist using the dedicated password history helper. Avoid importing Watchtower here.
            from vault_store.password_history_ops import persist_entry_with_history
            persist_entry_with_history(
                self,
                self.currentUsername.text(),
                self.core_session_handle,
                global_index,
                updated,
                max_hist=10,
            )
            update_baseline(username=self.currentUsername.text(), verify_after=False, who=f"Edit Entry From Vault")
            self.load_vault_table()
            self._on_any_entry_changed()
        self.reset_logout_timer()
    except Exception as e:
        self.reset_logout_timer()
        log.error(str(f"{kql.i('vault')} [ERROR] {kql.i('err')} editing vault entry: {e}"))
        QtWidgets.QMessageBox.warning(self, self.tr("Error"), self.tr("Failed to edit the selected entry. Please try again."))

def _do_vault_schema_refresh(self, *args, **kwargs):
    """
    Vault Schema Refresh (called after category schema changes) — cleans orphans, reloads vault, rebuilds filter, refreshes add/edit dropdown
    Called (via schedule_vault_schema_refresh) whenever the category schema
    changes – e.g. Category Editor save/autosave, CSV import, etc.
    We:
    - clean up orphan categories
    - reload vault table
    - rebuild the category filter
    - refresh the add/edit category combo (categorySelector_2)
    """
    if getattr(self, "_vault_loading", False):
        return

    self._vault_loading = True
    try:
        # 1) cleanup orphans quietly
        try:
            self.cleanup_orphan_categories()
        except Exception as e:
            try:
                log.debug(f"[CAT] cleanup_orphan_categories failed in schema refresh: {e}")
            except Exception:
                pass

        # 2) Reload table once
        try:
            self.set_status_txt(self.tr("Refreshing vault (category schema changed)"))
            self.load_vault_table()
        except Exception as e:
            try:
                log.error(f"[CAT] _do_vault_schema_refresh: load_vault_table failed: {e}")
            except Exception:
                pass

        # 3) Rebuild category filter once
        try:
            self.rebuild_category_filter(show_empty=False)
        except Exception as e:
            try:
                log.debug(f"[CAT] _do_vault_schema_refresh: rebuild_category_filter failed: {e}")
            except Exception:
                pass

        # 4) NEW: refresh the add/edit category dropdown
        try:
            if hasattr(self, "refresh_category_selector"):
                log.info("[CAT] _do_vault_schema_refresh: calling refresh_category_selector()")
                self.refresh_category_selector()
        except Exception as e:
            try:
                log.debug(f"[CAT] _do_vault_schema_refresh: refresh_category_selector failed: {e}")
            except Exception:
                pass

    finally:
        self._vault_loading = False

def _quick_move_row_to_category(self, row: int, new_type: str) -> bool:
    """Quick move: if user drags an entry to a different category, we can try to auto-map fields and move it without making them go through the edit dialog.
    This is a bit complex but provides a much smoother UX.
    """
    try:
        # refuse if target is protected
        if self._is_blocked_target(new_type):
            log.debug("[MOVE] target category blocked")
            return False
        # refuse if source is protected
        try:
            if self._is_blocked_source(self._category_for_row(row)):
                log.debug("[MOVE] source category blocked")
                return False
        except Exception:
            pass
        
        try:
            entries = load_vault(self.currentUsername.text(), getattr(self, 'core_session_handle', None) or self.core_session_handle)
            try:
                global_index = self.current_entries_indices[row]
            except Exception:
                global_index = row
            src = entries[global_index]
        except Exception as e:
            log.error(str(f"{kql.i('update')} [ERROR] {kql.i('err')} load entry failed: {e}"))
            return False

        # --- automap to target schema (user-defined labels) ---
        def norm(s): return "".join(ch for ch in (s or "").lower().strip() if ch.isalnum())
        synonyms = {
            "username": {"user", "login", "account", "accountname", "userid"},
            "email": {"mail", "emailaddress"},
            "password": {"pass", "passwd"},
            "website": {"url", "link", "domain"},
            "phone": {"phonenumber", "mobile", "tel", "telephone"},
            "2faenabled": {"twofactor", "mfa", "2fa"},
            "platform": {"store", "launcher", "service"},
            "gamename": {"title", "name"},
        }

        try:
            tgt_fields = self._user_schema_field_labels(new_type)
        except Exception:
            tgt_fields = []
        tgt_lc = {norm(f): f for f in tgt_fields if isinstance(f, str)}

        # source normalized map (+synonyms)
        src_norm = {}
        for k, v in (src or {}).items():
            if not isinstance(k, str):
                continue
            nk = norm(k)
            src_norm[nk] = v
            for canon, alts in synonyms.items():
                if nk == canon or nk in alts:
                    src_norm[canon] = v
                    for a in alts:
                        src_norm[a] = v

        new_entry = {}
        used = set()
        # fill by target field names first
        for nk, orig in tgt_lc.items():
            if nk in src_norm:
                new_entry[orig] = src_norm[nk]; used.add(nk)
            else:
                # try synonyms for each target name
                for canon, alts in synonyms.items():
                    if nk == canon or nk in alts:
                        for cand in {canon, *alts}:
                            if cand in src_norm:
                                new_entry[orig] = src_norm[cand]
                                used.add(cand)
                                break

        # push any leftover info into Notes
        extras = {k: v for k, v in (src or {}).items()
                  if isinstance(k, str) and norm(k) not in used
                  and norm(k) not in {"notes", "date", "category", "type", "createdat"} and v not in (None, "")}
        note = str(src.get("Notes") or src.get("notes") or "")
        if extras:
            note = (note + ("\n\n" if note else "") +
                    "[Unmatched Fields]\n" + "\n".join(f"{k}: {v}" for k, v in extras.items()))
        if note:
            notes_key = next((f for f in tgt_fields if norm(f) == "notes"), "Notes")
            new_entry[notes_key] = note

        # force category/type/date
        new_entry["category"] = new_type
        new_entry["Type"] = new_type
        new_entry["Date"] = dt.datetime.now().strftime("%Y-%m-%d")
        # Persist using the dedicated password history helper. Avoid importing Watchtower here.
        from vault_store.password_history_ops import persist_entry_with_history
        persist_entry_with_history(
            self,
            self.currentUsername.text(),
            self.core_session_handle,
            global_index,
            new_entry,
        )

        # refresh UI
        try:
            
            update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Moved Entry In Vault"))
        except Exception:
            pass
        try:
            self.load_vault_table()
        except Exception:
            pass
        return True
    except Exception as e:
        log.error(str(f"{kql.i('update')} [ERROR] {kql.i('warn')} quick move failed: {e}"))
        return False

def show_qr_for_selected(self, *args, **kwargs):
    self.set_status_txt(self.tr("Show Qr Code"))
    """Show a QR code for the best value in the currently selected row.
       - If category looks like Wi-Fi (or row has SSID), show a Wi-Fi QR.
       - Else pick a sensible field (OTP secret, Password, URL, License Key, etc.).
    """
    self.reset_logout_timer()
    if not getattr(self, "vaultTable", None):
        return
    row = self.vaultTable.currentRow()
    if row < 0:
        self.safe_messagebox_warning(self, "QR", "Select a row first.")
        return

    # Pull row data using existing helpers
    entry = self._get_row_entry_dict(row)       # header->value map (unmasks where possible)
    category = (self._category_for_row(row) or "").strip().lower()

    # 1) Wi-Fi detection (by category or by presence of SSID)
    is_wifi = ("wifi" in category) or any(k in entry for k in ("ssid", "wi-fi ssid", "network name"))
    if is_wifi:
        ssid = entry.get("ssid") or entry.get("wi-fi ssid") or entry.get("network name") or ""
        password = entry.get("password") or entry.get("pass") or entry.get("key") or ""
        encryption = entry.get("encryption") or entry.get("security") or "WPA"
        hidden = str(entry.get("hidden") or "").strip().lower() in ("1", "true", "yes", "y")
        payload = self._make_wifi_qr_payload(ssid, password, encryption=encryption, hidden=hidden)
        title = f"Wi-Fi: {ssid or 'Network'}"
        QRPreviewDialog(title, payload, self).exec()
        return

    # 2) Non-Wi-Fi: pick the “best” field to encode
    #    Priority: OTP secret/URI -> password -> URL -> license key -> username/email -> notes/other
    candidates_order = [
        ("otp", "OTP"),
        ("totp", "OTP"),
        ("otpauth", "OTP"),
        ("secret", "Secret"),
        ("password", "Password"),
        ("pass", "Password"),
        ("url", "URL"),
        ("website", "URL"),
        ("link", "URL"),
        ("license key", "License Key"),
        ("serial", "License Key"),
        ("product key", "License Key"),
        ("username", "Username"),
        ("email", "Email"),
        ("note", "Note"),
        ("notes", "Note"),
        ("value", "Value"),
    ]

    # If the user has an active cell, prefer that column if it has text
    try:
        col = self.vaultTable.currentColumn()
        if col >= 0:
            header_item = self.vaultTable.horizontalHeaderItem(col)
            if header_item:
                active_header = (header_item.text() or "").strip().lower()
                active_val = entry.get(active_header)
                if active_val:
                    QRPreviewDialog(f"QR: {header_item.text()}", str(active_val), self).exec()
                    return
    except Exception:
        pass

    # Otherwise scan by priority
    for key, label in candidates_order:
        val = entry.get(key)
        if val:
            QRPreviewDialog(f"QR: {label}", str(val), self).exec()
            return

    self.safe_messagebox_warning(self, "QR", "No suitable field found in this row to convert to QR.")


# =============================
# = vault search (local + full) with background thread, progress dialog, and cancellation =
# =============================

def on_vault_search_committed(self, *args, **kwargs):
    """
    Full-vault search flow: if "Search entire vault" is checked, run a full search in a background thread with progress dialog and cancellation.
    """

    q = (self.vaultSearchBox.text() or "").strip()
    if not q:
        try: self.filter_vault_table("")
        except Exception: pass
        return

    use_global = bool(self.search_all_ and self.search_all_.isChecked())
    log.debug(f"[SEARCH] committed. use_global={use_global} query={q!r}")

    if not use_global:
        try: self.filter_vault_table(q)
        except Exception as e:
            log.debug(f"[SEARCH] filter_vault_table failed: {e}")
        return

    if getattr(self, "_search_busy", False):
        log.debug("[SEARCH] already running; ignoring new request")
        return
    self._search_busy = True

    # snapshot primitives on GUI thread
    try:
        username = self._active_username()
    except Exception:
        username = ""
    user_key = getattr(self, "core_session_handle", None)

    # Indeterminate progress (range 0,0) -> no repaint recursion
    dlg = QProgressDialog("Searching entire vault…", "Cancel", 0, 0, self)
    dlg.setWindowTitle(self.tr("Keyquorum – Search"))
    dlg.setWindowModality(Qt.NonModal)
    dlg.setMinimumWidth(360)
    dlg.setAutoReset(False)
    dlg.setAutoClose(False)
    dlg.show()
    QApplication.processEvents(QEventLoop.AllEvents, 30)

    from workers.search_worker import VaultSearchWorker

    # Thread + worker
    thread = QThread()  # no parent: avoids parent-owned deletion races
    worker = VaultSearchWorker(username, user_key, q, 500)
    worker.moveToThread(thread)

    # store context so we don't capture deleted objects in lambdas
    self._search_ctx = {
        "dlg": dlg,
        "thread": thread,
        "worker": worker,
        "results": None,
        "error": None,
    }

    # --- Lifecycle wiring ---
    # 1) start work
    thread.started.connect(worker.run, type=Qt.QueuedConnection)

    # 2) worker outcome -> quit thread + self-delete worker; collect result/error
    worker.finished.connect(thread.quit, type=Qt.QueuedConnection)
    worker.finished.connect(worker.deleteLater, type=Qt.QueuedConnection)
    worker.finished.connect(self._on_search_finished_collect, type=Qt.QueuedConnection)

    worker.error.connect(lambda msg: setattr(self._search_ctx, "error", msg) if False else None, type=Qt.QueuedConnection)
    # The lambda above is a no-op placeholder to keep signature. We'll store error in a slot:
    worker.error.connect(self._on_search_error_collect, type=Qt.QueuedConnection)
    worker.error.connect(thread.quit, type=Qt.QueuedConnection)
    worker.error.connect(worker.deleteLater, type=Qt.QueuedConnection)

    # 3) after the thread actually stops, delete the thread object and only then touch GUI
    thread.finished.connect(self._on_search_thread_finished, type=Qt.QueuedConnection)
    thread.finished.connect(thread.deleteLater, type=Qt.QueuedConnection)

    # 4) cancel button
    dlg.canceled.connect(worker.cancel, type=Qt.QueuedConnection)

    # go
    log.debug("[SEARCH] starting worker thread")
    thread.start()

def _search_vault_all(self, query: str, *, max_results: int = 200,
                  progress_cb=None, should_cancel=lambda: False) -> list[dict]:
    """
    The actual search function, which runs in the worker thread. It loads all entries and scores them based on the 
    presence and position of the query in common fields, with category-specific boosts.
    Full-vault search (all categories). 
    progress_cb: callable(done:int, total:int) | None
    should_cancel: callable() -> bool
    """
    q = (query or "").strip().lower()
    if not q:
        return []

    try:
        entries = self.vault_store.get_all_entries()
    except Exception:
        entries = load_vault(self.currentUsername.text(), getattr(self, 'core_session_handle', None) or self.core_session_handle) or []

    from catalog_category.category_fields import get_fields_for

    common_keys = [
        "Title", "Name", "Username", "User", "Email",
        "URL", "Site", "Website", "Login URL", "Address",
        "Notes", "Note", "Description", "Label",
    ]
    weight = {
        "Title": 4, "Name": 4, "Username": 3, "Email": 3,
        "URL": 3, "Site": 3, "Website": 3, "Login URL": 3,
        "Notes": 1, "Description": 1, "Label": 2,
    }

    hits: list[dict] = []
    q_re = _re.escape(q)
    total = len(entries)

    for i, e in enumerate(entries, 1):
        if should_cancel and should_cancel():
            log.debug("[SEARCH] cancelled by user")
            break

        cat = (e.get("category") or e.get("Category") or "").strip()
        try:
            cat_fields = get_fields_for(cat) or []
        except Exception:
            cat_fields = []

        fields_to_scan = list(dict.fromkeys([*cat_fields, *common_keys]))  # dedupe keep order
        score = 0.0
        matched = set()

        for key in fields_to_scan:
            val = e.get(key)
            if not isinstance(val, str) or not val:
                continue
            s = val.lower()
            if q in s:
                matched.add(key)
                base = weight.get(key, 1)
                pos_bonus = max(0, 1.0 - (s.find(q) / max(1, len(s))))
                score += base * (1.0 + 0.25 * pos_bonus)
            elif _re.search(rf"\b{q_re}", s):
                matched.add(key)
                score += weight.get(key, 1) * 0.9

        if score > 0:
            hits.append({"index": i-1, "category": cat, "entry": e, "score": score, "matched": matched})

        if progress_cb and (i % 25 == 0 or i == total):
            try:
                progress_cb(i, total)
            except Exception:
                pass

    hits.sort(key=lambda h: (-h["score"], h["category"], h["entry"].get("Title") or h["entry"].get("Name") or ""))
    return hits[:max_results]

# =============================
# = Desktop Auto-fill Flow ==
# =============================

def _autofill_split_flow(self, entry, *, hwnd=None, title_re: str = "", pid=None) -> bool:
    """
    Two-stage flow: identifier (email preferred, else username) -> Next -> wait -> password -> submit.
    Returns True on success.
    """
    # Lazy-import pywinauto and keyboard
    try:
        from pywinauto.keyboard import send_keys
        from pywinauto.findwindows import ElementNotFoundError
    except Exception:
        QMessageBox.warning(self, "Auto-fill",
                            "pywinauto is not installed in this build. Please install it to use desktop autofill.")
        return False

    email = (entry.get("email") or "").strip()
    username = (entry.get("username") or "").strip()
    password = (entry.get("password") or "").strip()

    ident_val = email or username
    if not ident_val or not password:
        QMessageBox.warning(self, self.tr("Auto-fill"), self.tr("This entry needs an email/username and a password."))
        return False

    # Connect + focus
    target = self._connect_window(hwnd=hwnd, title_re=title_re, pid=pid)
    try:
        target.set_focus()
    except Exception:
        pass
    _t.sleep(0.05)

    # --- Stage 1: fill identifier (EMAIL first, fallback to USERNAME) ---
    id_edit = None
    if email:
        id_edit = self._find_email_edit(target)  # prefer explicit email control
    if not id_edit:
        id_edit = self._find_username_edit(target)  # generic user/identifier field
    if not id_edit:
        QMessageBox.information(self, self.tr("Auto-fill"), self.tr("Could not locate the email/username field in the target app."))
        return False

    try:
        id_edit.wait("ready", timeout=1)
    except Exception:
        pass
    self._clear_and_type(id_edit, ident_val, is_password=False)

    # Click Next (or Enter)
    pressed_next = False
    btn_next = self._find_next_button(target)
    if btn_next:
        try:
            btn_next.click_input()
            pressed_next = True
        except Exception:
            pass
    if not pressed_next:
        try:
            id_edit.set_focus()
        except Exception:
            pass
        send_keys("{ENTER}", pause=0.002)

    # --- Stage 2: wait for password, then fill ---
    pw_edit = None
    deadline = _t.time() + 8.0
    while _t.time() < deadline:
        try:
            target = self._connect_window(hwnd=hwnd, title_re=title_re, pid=pid)
            pw_edit = self._find_password_edit(target)
            if pw_edit:
                try:
                    pw_edit.wait("ready", timeout=1)
                except Exception:
                    pass
                self._clear_and_type(pw_edit, password, is_password=True)
                break
        except Exception:
            pass
        _t.sleep(0.2)

    if not pw_edit:
        QMessageBox.information(
            self, self.tr("Auto-fill"),
            self.tr("Identifier filled. Waiting for password field timed out—please press Next and try again.")
        )
        return False

    # Submit
    btn_submit = self._find_submit_button(target)
    if btn_submit:
        try:
            btn_submit.click_input()
        except Exception:
            try:
                pw_edit.set_focus()
            except Exception:
                pass
            send_keys("{ENTER}", pause=0.002)
    else:
        try:
            pw_edit.set_focus()
        except Exception:
            pass
        send_keys("{ENTER}", pause=0.002)

    try:
        self._toast("Filled email/username, waited for password, and signed in.")
    except Exception:
        pass
    return True

