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
from features.qr.qr_tools import show_qr_for_object, QRPreviewDialog
import datetime as dt
from ui_gen.emergency_kit_dialog import EmergencyKitDialog
from app.basic import get_app_version
from auth.identity_store import get_login_backup_count_quick
import json, csv, hashlib, socket, threading, ctypes, base64, http.client
import re as _re
from urllib.parse import urlparse
from shutil import copy2
import logging
from auth.login.login_handler import (get_user_setting, _canonical_username_ci, set_user_setting, set_user_cloud, get_user_cloud)
from app.paths import (vault_file, tamper_log_file,audit_file, audit_mirror_file, icon_file,
                       config_dir, user_lock_flag_path,)
log = logging.getLogger("keyquorum")
from pathlib import Path
from app.paths import user_lock_flag_path, LICENSES_DIR, SPDX_DIR
from vault_store.vault_store import (
    export_vault_csv, _dec_backup_bytes, add_vault_entry, load_vault, save_vault, update_vault_entry,  export_full_backup,)
import app.kq_logging as kql
from security.secure_audit import log_event_encrypted, read_audit_log, get_audit_file_path
from security.preflight import (
    load_security_prefs, run_preflight_for_user, scan_for_suspicious_processes, _any_av_present,)
from app.paths import tamper_log_file
from auth.login.login_handler import validate_login
from security.baseline_signer import update_baseline
import time as _t
from features.share.zk_share import verify_and_decrypt_share_packet
from typing import Union
import weakref
try:
    from auth.yubi.yk_backend import set_probe_enabled
except Exception:
    def set_probe_enabled(val: bool):
        pass

from bridge.bridge_helpers import WEBFILL_COL
from features.share.share_keys import ensure_share_keys
from app.basic import is_dev

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
def import_csv_entries(self, *args, **kwargs):
    self.set_status_txt(self.tr("CSV Import"))
    """
    Import entries from CSV (.csv) or encrypted CSV (.csv.enc).
    - Encrypted files use AES-GCM via vault_store._dec_backup_bytes.
    - App-native CSV (marked with KQ_FORMAT=1) preserves/creates categories.
    - Browser CSVs are bucketed (Google/Edge/Chrome/Samsung Pass).
    - Auto-creates categories in schema & UI.
    - Batch duplicate resolution.
    - Shows a progress dialog during the import phase so users can see it's working.
    """
    from qtpy.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox, QProgressDialog, QApplication
    from qtpy.QtCore import Qt


    log.debug("[DEBUG] starting import csv entries")
    self.reset_logout_timer()

    # ---- helpers (scoped to function) ----
    def _ensure_category_exists_in_ui(category: str) -> bool:
        if not category:
            return True
        cat = category.strip()
        existed = False
        try:
            if hasattr(self, "categorySelector_2") and self.categorySelector_2 is not None:
                items = [self.categorySelector_2.itemText(i).strip()
                         for i in range(self.categorySelector_2.count())]
                if cat in items:
                    existed = True
                else:
                    self.categorySelector_2.addItem(cat)
                    existed = False
                    for name in ("save_categories", "save_category_config",
                                 "_save_categories", "_persist_categories", "persist_categories"):
                        saver = getattr(self, name, None)
                        if callable(saver):
                            try:
                                saver()
                            except Exception:
                                pass
                            break
        except Exception:
            pass
        return existed

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
                # detect full backup confusion
                try:
                    probe = _dec_backup_bytes(pw, raw)
                    if len(probe) >= 2 and probe[:2] == b"PK":
                        QMessageBox.critical(
                            self, self.tr("Wrong Import Type"),
                            self.tr("This is a FULL BACKUP (.zip.enc), not a CSV export.\n\n"
                            "Use: Settings → Import Full Backup.")
                        )
                        return
                except Exception:
                    pass
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

    # ---- sniff dialect & header (more robust; friendly to Chrome/Edge BOM) ----
    try:
        sample = text[:4096]
        # strip BOM if present
        if sample.startswith("\ufeff"):
            sample = sample.lstrip("\ufeff")
            text = text.lstrip("\ufeff")

        try:
            sniffed = csv.Sniffer().sniff(sample)
        except Exception:
            sniffed = csv.excel

        # Chrome/Edge style: always treat first row as header
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

    import io
    sio = io.StringIO(text, newline="")
    reader = csv.DictReader(sio, dialect=sniffed) if has_header else None
    if reader is None or not reader.fieldnames:
        self.safe_messagebox_warning(self, self.tr("CSV Error"), self.tr("No headers found in CSV."))
        return

    # normalize headers (strip)
    reader.fieldnames = [h.strip() if isinstance(h, str) else h for h in reader.fieldnames]

    # ---- load current vault ----
    try:
        entries = load_vault(self.currentUsername.text(), self.userKey)
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

    try:
        # Source detection (class helper recognizes KQ_FORMAT marker)
        source_hint = self._detect_source_hint(str(p), reader.fieldnames or [])

        # ---------- Phase 1: normalize & categorize ----------
        rows: list[dict] = []
        suggested_cats: set[str] = set()

        for row_idx, row in enumerate(reader, start=1):
            self.reset_logout_timer()
            if not isinstance(row, dict):
                continue

            clean = {(k or "").strip(): (v or "").strip() for k, v in row.items() if k is not None}

            # Prefer CSV Category, else UI default
            csv_cat = ""
            for k in list(clean.keys()):
                if (k or "").lower() == "category":
                    csv_cat = clean.get(k, "") or ""
                    break
            fallback_cat = (csv_cat or default_category or "").strip()

            cat, norm = self._categorize_entry(clean, source_hint)
            # If class helper returned a bucket, prefer it; else fallback_cat
            cat = cat or fallback_cat or "Web Logins"
            norm["category"] = cat

            # Remove marker if present
            if "KQ_FORMAT" in norm:
                norm.pop("KQ_FORMAT", None)

            rows.append(norm)
            suggested_cats.add(cat)

            # keep UI responsive even on big files
            if row_idx % 200 == 0:
                QApplication.processEvents()

        # Optional rename pass
        rename_map = self._prompt_category_renames(suggested_cats) if suggested_cats else {}

        # ---------- Phase 2: persist categories + import (with progress) ----------
        total = len(rows)
        cancelled = False
        progress = None

        if total > 0:
            progress = QProgressDialog("Importing entries…", "Cancel", 0, total, self)
            progress.setWindowTitle(self.tr("CSV Import"))
            progress.setWindowModality(Qt.WindowModal)
            progress.setAutoClose(True)
            progress.setAutoReset(True)
            progress.setMinimumDuration(500)  # show after 0.5s

        try:
            for idx, norm in enumerate(rows, start=1):
                if progress:
                    progress.setValue(idx)
                    self.set_status_txt(self.tr("CSV Import: ") + f"{idx}/{total}")
                    QApplication.processEvents()
                    if progress.wasCanceled():
                        cancelled = True
                        break

                category = rename_map.get(norm.get("category", ""), norm.get("category", "")).strip()
                if not category:
                    continue

                # ensure category exists (schema + UI)
                existed_before = False
                try:
                    existed_before = self._ensure_category_exists_from_import(category)
                except Exception:
                    existed_before = False
                try:
                    _ensure_category_exists_in_ui(category)
                except Exception:
                    pass

                # minimal validation for existing categories
                try:
                    from catalog_category.category_fields import preferred_url_fields
                    req = preferred_url_fields(category) if existed_before else []
                except Exception:
                    req = []
                if any(not (norm.get(field) or "").strip() for field in req):
                    continue

                entry = {k: v for k, v in norm.items() if v != "" and k.lower() != "category"}
                entry["category"] = category
                entry.setdefault("Date", today)
                entry.setdefault("created_at", now_iso)

                # ---- fill blank core fields from fallbacks ----
                lower_to_key = {k.lower(): k for k in entry.keys()}

                def _val_for(*candidates: str) -> str:
                    """Return first non-empty value from any of the candidate keys (case-insensitive)."""
                    for c in candidates:
                        k_real = lower_to_key.get(c.lower())
                        if k_real:
                            v = entry.get(k_real)
                            if v:
                                return v
                    return ""

                # Title
                if not entry.get("Title"):
                    entry["Title"] = _val_for(
                        "title", "name", "account name", "full name",
                        "app / title", "app name", "windows name", "game name", "site"
                    )

                # Username
                if not entry.get("Username"):
                    entry["Username"] = _val_for(
                        "username", "user name", "user", "username / email", "email"
                    )

                # URL
                if not entry.get("URL"):
                    url_val = _val_for("url", "website", "site", "origin / domain")
                    if url_val:
                        entry["URL"] = url_val
                        entry.setdefault("Website", url_val)
                # ---- end NEW block ----

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
            from app_window import DedupeResolverDialog
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
            self.reset_logout_timer()
            save_vault(self.currentUsername.text(), self.userKey, entries)
            msg = self.tr("{ok} Import complete\n• New: {add}\n• Updated: {update}\n• Unchanged: {unchange}").format(ok=kql.i('ok'), add=added, update=updated,unchange=unchanged)
            QMessageBox.information(
                self, self.tr("Import Successful"),
                msg)
            try:
                self.load_vault_table()
            except Exception:
                pass
        else:
            QMessageBox.information(self, self.tr("Nothing Imported"), self.tr("No new or updated entries were imported."))

        
        update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("CSV import"))
        self._reconcile_category_schema_with_entries()
        self.set_status_txt(self.tr("CSV import finished"))

    except Exception as e:
        log.error(f"[DEBUG] CSV Import Failed: {e}")
        QMessageBox.critical(self, self.tr("Import Failed"), str(e))
        self.set_status_txt(self.tr("CSV import failed"))

def emg_ask(
    self,
    username,
    one_time_recovery_key=None,
    recovery_backup_codes=None,   # list[str] | str | None
    twofa_backup_codes=None,      # list[str] | str | None
    totp_secret_plain=None,
    totp_uri=None,
    totp_qr_png=None,
):
    """
    Show Emergency Kit dialog, allowing:
      - Use current data only
      - Load / merge from an existing Emergency Kit PDF
      - Manual entry / edits

    No secrets are persisted here — only used for building the PDF
    and showing the on-screen emergency info.
    """
    from auth.emergency_kit.emergency_kit import (
        parse_emergency_kit_pdf,
        merge_kit_into_account_snapshot,
    )

    def _normalize_codes(val):
        """
        Accepts list[str] | str | None and returns list[str] (unique, trimmed).
        Splits strings by newline, commas, spaces.
        """
        if val is None:
            return []
        if isinstance(val, list):
            items = val
        else:
            # split on newlines, commas, semicolons, or whitespace runs
            items = _re.split(r"[,\s;]+", str(val))
        # trim, drop empties, dedupe preserving order
        seen, out = set(), []
        for x in (s.strip() for s in items):
            if x and x not in seen:
                seen.add(x); out.append(x)
        return out

    # --- Start from provided values (do NOT overwrite with "N/A") ---
    rec_key = one_time_recovery_key or None
    rec_codes = _normalize_codes(recovery_backup_codes)
    tfa_codes = _normalize_codes(twofa_backup_codes)
    totp_secret = totp_secret_plain or None   
    totp = totp_uri or None
    qr_png = totp_qr_png

    # --- Ask how to build the Emergency Kit data ---
    mode_box = QMessageBox(self)
    mode_box.setWindowTitle(self.tr("Emergency Kit"))
    mode_box.setText(self.tr(
        "How do you want to build your Emergency Kit?\n\n"
        "• Use current data only\n"
        "• Load & merge from an existing Emergency Kit PDF\n"
        "• Add or edit details manually")
    )
    btn_current = mode_box.addButton(self.tr("Use current only"), QMessageBox.AcceptRole)
    btn_import = mode_box.addButton(self.tr("Load from PDF"), QMessageBox.ActionRole)
    btn_manual = mode_box.addButton(self.tr("Add / edit manually"), QMessageBox.DestructiveRole)
    mode_box.setDefaultButton(btn_current)
    mode_box.exec()

    clicked = mode_box.clickedButton()
    mode = "current"
    if clicked is btn_import:
        mode = "import"
    elif clicked is btn_manual:
        mode = "manual"

    # --- If user chose "Load from PDF", merge in old kit data (add-only) ---
    if mode == "import":
        pdf_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select existing Emergency Kit PDF to merge",
            "",
            "PDF files (*.pdf)",
        )
        if pdf_path:
            try:
                parsed = parse_emergency_kit_pdf(pdf_path)

                # Build a lightweight "snapshot" from what we have in memory.
                # We don't track used_* codes here, so we pass empty lists.
                snapshot = {
                    "recovery_backup_codes": rec_codes,
                    "used_recovery_codes": [],
                    "twofa_backup_codes": tfa_codes,
                    "used_twofa_codes": [],
                    "totp_secret_hint": totp_secret,
                }

                merged = merge_kit_into_account_snapshot(snapshot, parsed)

                rec_codes = merged.get("recovery_backup_codes", rec_codes)
                tfa_codes = merged.get("twofa_backup_codes", tfa_codes)
                # merged["totp_secret_hint"] is just a hint string, safe to use
                if merged.get("totp_secret_hint") and not totp_secret:
                    totp_secret = merged["totp_secret_hint"]

                QMessageBox.information(
                    self,
                    self.tr("Emergency Kit"),
                    self.tr("Existing Emergency Kit data was merged successfully.\n\n"
                    "New codes were added where available. Your current data was not overwritten."))
            except Exception as e:
                QMessageBox.critical(
                    self,
                    self.tr("Emergency Kit"),
                    self.tr("Could not read or merge the selected Emergency Kit PDF:" + f"\n\n{e}"))

        # If user cancels file selection, just fall back to current data + optional manual below.

    # --- If user chose "manual", open manual-entry dialog ---
    if mode == "manual":
        manual = self.prompt_manual_kit_entries(
            defaults={
                "recovery_key": rec_key,
                "recovery_backup_codes": rec_codes,
                "twofa_backup_codes": tfa_codes,
                "totp_secret": totp_secret,
                "totp_uri": totp,
            }
        ) or {}
        if manual.get("ok"):
            if manual.get("recovery_key"):
                rec_key = str(manual["recovery_key"]).strip() or None

            rbc = manual.get("recovery_backup_codes")
            if rbc is not None:
                rec_codes = _normalize_codes(rbc)

            tfa = manual.get("twofa_backup_codes")
            if tfa is not None:
                tfa_codes = _normalize_codes(tfa)

            if manual.get("totp_uri"):
                totp = str(manual["totp_uri"]).strip() or None
                # If URI exists, we can ignore raw secret unless you want to keep both
                totp_secret = None
            elif manual.get("totp_secret"):
                totp_secret = str(manual["totp_secret"]).strip() or None

    # --- Only show if we have *real* content ---
    show_kit = any([
        bool(rec_key),
        bool(rec_codes),
        bool(tfa_codes),
        bool(totp),
        bool(qr_png),
        bool(totp_secret),
    ])

    app_version = get_app_version()

    if show_kit:
        try:
            dlg = EmergencyKitDialog(
                self,
                username=username,
                app_version=app_version,
                recovery_key=rec_key,
                recovery_backup_codes=rec_codes,    # list[str]
                twofa_backup_codes=tfa_codes,        # list[str]
                totp_uri=totp,
                totp_secret_hint=totp_secret,
                totp_qr_png=qr_png,
            )
            dlg.exec()
        except Exception as e:
            log.warning("%s [KIT] EmergencyKitDialog unavailable, fallback text: %s", kql.i('warn'), e)

            # --- Minimal fallback popup ---
            recovery_popup = QDialog(self)
            recovery_popup.setWindowTitle(self.tr("Your Emergency Kit"))
            recovery_popup.setMinimumSize(560, 480)

            layout = QVBoxLayout(recovery_popup)
            instructions = QTextEdit(); instructions.setReadOnly(True)

            def _fmt_list(lst):
                return "<br>".join(map(lambda s: Qt.escape(str(s)), lst)) if lst else "<i>None</i>"

            rk_html = f"<code style='font-size: 16px;'>{Qt.escape(str(rec_key))}</code>" if rec_key else "<i>No recovery key</i>"
            instructions.setHtml(
                "<b>📢 Emergency Kit</b><br><br>"
                f"<b>Recovery Key</b><br>{rk_html}<br><br>"
                "<b>Recovery Backup Codes</b><br>"
                f"<pre style='font-size: 14px;'>{_fmt_list(rec_codes)}</pre><br>"
                "<b>2FA Backup Codes</b><br>"
                f"<pre style='font-size: 14px;'>{_fmt_list(tfa_codes)}</pre><br>"
                + ("<i>TOTP QR/URI included.</i>" if (totp or qr_png or totp_secret) else "")
            )
            layout.addWidget(instructions)
            close_btn = QPushButton(self.tr("I have stored these safely"))
            close_btn.clicked.connect(recovery_popup.accept)
            layout.addWidget(close_btn)
            recovery_popup.exec()

    # --- Cleanup: wipe secrets in memory as best we can ---
    try:
        # Overwrite lists in place
        for i in range(len(rec_codes)): rec_codes[i] = ""
        for i in range(len(tfa_codes)): tfa_codes[i] = ""
        # Overwrite and drop refs
        totp_secret = None
        totp = None
        qr_png = None
    except Exception:
        pass

    return True

def maybe_show_quick_tour(self, which: str = "core"):
    """"core": core_steps,
        "authenticator": authenticator_steps,
        "audit": audit_steps,
        "profile": profile_steps,
        "settings": settings_steps,
        "portable": portable_steps,
        "backup": backup_steps,
        "category": category_steps,
        "watchtower": watchtower_steps,"""

    core_steps = [
            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "vaultTable",
             "title": "Items table", "text": "Everything you add appears here. Select a row to view or act on it.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "categorySelector_2",
             "title": "Category", "text": "Switch categories. The table updates to show items in the selected category.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "widget_2",
             "title": "Add / Edit / Delete", "text": "Add new items, edit the selected one, or remove it. Tip: choose the category first.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "vaultSearchBox",
             "title": "Search", "text": "Find items instantly in the current category. Filters are supported.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "password_generator",
             "title": "Password generator", "text": "Create strong passwords with customizable length and characters.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "bowser_btn",
             "title": "Browser extension", "text": "Install and pair the Token to enable on-site autofill and saving. Remove the Token to disconnect. A fresh token is created each login.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "breach_check_",
             "title": "Breach check", "text": "Email: open Have I Been Pwned for the selected address. Password: check a password against known breach data (we don’t store what you type).", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "share_",
             "title": "Share", "text": "Securely share with other Keyquorum users. Enter their Share ID to send an encrypted packet only they can open. Use ‘Import packet’ to add one you’ve received.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "softdelete_",
             "title": "Soft delete", "text": "A safety net for deletions: items stay here for 30 days for easy restore, then are removed permanently.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "move_category_",
             "title": "Move to category", "text": "Move the selected item to a different category. Unmapped fields are preserved in Notes.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "qrshow_",
             "title": "Create QR", "text": "Make a QR for the selected item. Most categories encode only the website URL; Wi-Fi encodes full credentials so scanning can join the network.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "logoutButton",
             "title": "Log out", "text": "Securely sign out. Clears sensitive data and resets the session. Works here, on app close, or after idle timeout.", "padding": 10},
        ]

    authenticator_steps = [
            {"tab": {"widget": "mainTabs", "title": "Authenticator"}, "target": "widget_27",
             "title": "Authenticator", "text": "Add, edit, and delete authenticator entries. Add manually or quickly via camera/image. Important: don’t add your vault’s own 2FA here to avoid lockouts.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Authenticator"}, "target": "authTable",
             "title": "Codes table", "text": "Your authenticators are listed here. Codes refresh every ~30 seconds by default.", "padding": 10},
        ]

    audit_steps = [
            {"tab": {"widget": "mainTabs", "title": "Audit Logs"}, "target": "auditTable",
             "title": "Audit logs", "text": "Review recent account activity, including failed login attempts.", "padding": 10, "dim": 110},
        ]

    profile_steps = [
            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "Profile",
             "title": "Profile", "text": "Update your account profile and preferences.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "twoFACheckbox",
             "title": "Two-Factor Authentication", "text": "Enable or disable 2FA for login. This secures account sign-in (vault protection is configured separately).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "btnDeviceUnlock",
             "title": "YubiKey", "text": "Enable a genuine, modern YubiKey for stronger login and vault protection.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "regenerateBackupCodesButton",
             "title": "Regenerate backup codes", "text": "Create new account backup codes if you’ve lost the old ones. Not available in ‘no-recovery’ mode.", "padding": 10, "dim": 110},
        ]

    settings_steps = [
            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "enablePreflightCheckbox_",
             "title": "Preflight checks", "text": "Scan running processes at startup and warn about risky ones (defaults or your allow/block list).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "vault_safety_btn",
             "title": "Preflight lists", "text": "Manage your allow/deny lists for process scanning.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "runPreflightNowButton",
             "title": "Run preflight now", "text": "Run the process check on demand. If Windows Defender is available, you can kick off a quick scan.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "enableWinDefCheckbox_",
             "title": "Antivirus check", "text": "On startup/login, check whether antivirus is present and alert on issues.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "DefenderQuickScan_",
             "title": "Quick scan prompt", "text": "Offer a Windows Defender quick scan at app start.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "vault_safety_btn_2",
             "title": "Integrity baseline", "text": "Update file-integrity baseline for key files.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "clipboard_clear_timeout_",
             "title": "Clipboard safety", "text": "Auto-clear copied secrets after a delay.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "auto_logout_timeout_",
             "title": "Auto-logout", "text": "Automatically log out after inactivity.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "lockoutSpinBox",
             "title": "Lockout", "text": "Lock the account after too many failed login or 2FA attempts.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "password_expiry_days",
             "title": "Password expiry", "text": "Set how long passwords can live before reminders nudge you to rotate them.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "enable_breach_checker_",
             "title": "Breach checker", "text": "Check (hashed) passwords against known breach databases when saving items.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "ontop_",
             "title": "Always on top", "text": "Keep the app window above others.", "padding": 10, "dim": 110},

        ]

    backup_steps = [
            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "BackUp/Restore",
             "title": "Backups", "text": "Regular backups are essential. Create and store them safely.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_28",
             "title": "Cloud sync", "text": "keep a copy of your data in a cloud folder you control.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "select_cloud",
             "title": "Choose cloud folder", "text": "Pick a signed-in, accessible folder for backups.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "extra_cloud_wrap",
             "title": "Cloud safety", "text": "Add extra protection for data stored in the cloud copy.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "autosync_",
             "title": "Auto-sync", "text": "Automatically sync to cloud when data changes.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_16",
             "title": "Full backup / restore", "text": "Create a full backup of vault + account, or import one (also available on the login screen).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_29",
             "title": "Vault-only backup", "text": "Back up just the vault (restorable to the same account).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_30",
             "title": "CSV import / export", "text": "Import from other managers’ CSV, or export your vault to CSV (optionally password-protected).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_31",
             "title": "Software folder backup", "text": "back up the software folder separately if it’s large.", "padding": 10, "dim": 110},
        ]

    category_steps = [
            {"tab": {"widget": "mainTabs", "title": "Edit/Add Category"}, "target": "Edit/Add Category",
             "title": "Customize categories", "text": "Create and edit categories to fit your workflow.", "padding": 10, "dim": 110},
        ]

    watchtower_steps = [
            {"tab": {"widget": "mainTabs", "title": "Watchtower"}, "target": "Watchtower",
             "title": "Watchtower", "text": "Spot weak, reused, or unsafe items at a glance and fix them quickly.", "padding": 10, "dim": 110},
        ]
    
    # ---- choose steps by key
    steps_by_type = {
        "core": core_steps,
        "authenticator": authenticator_steps,
        "audit": audit_steps,
        "profile": profile_steps,
        "settings": settings_steps,
        "backup": backup_steps,
        "category": category_steps,
        "watchtower": watchtower_steps,
    }
    steps = steps_by_type.get(which)
    if not steps:
        return

    # ---- finish any running tour
    try:
        if getattr(self, "_tour", None):
            self._tour.finish()
    except Exception:
        pass

    # ---- start new tour; keep a ref so it doesn't get GC’d
    default_dim = 120 if which in ("core",) else 110
    from new_users.tour import GuidedTour
    tour = GuidedTour(self, steps, default_dim=default_dim)
    tour.start()

# ==============================
# --- size -------
# ============================== 

def save_credential_ui(self, payload: dict) -> bool:
    """
    Confirm with the user and persist credentials into the vault.
    Handles: update-existing, add-new, and basic validation.
    """
    if not self._require_unlocked(): 
        return
    # --- Normalize incoming fields
    url  = (payload.get("url") or payload.get("origin") or "").strip()
    user = (payload.get("username") or "").strip()
    pwd  = (payload.get("password") or "").strip()

    # --- Basic validation
    if not url or not pwd:
        QMessageBox.warning(self, self.tr("Save Login"), self.tr("Missing website URL or password."))
        return False

    # --- Normalize host
    try:
        host = urlparse(url if "://" in url else f"https://{url}").netloc or url
    except Exception:
        host = url

    # --- Build entry: write lower-case (canonical) AND Title-case (table-friendly) keys
    now_iso = dt.datetime.utcnow().isoformat(timespec="seconds")
    today   = dt.datetime.now().strftime("%Y-%m-%d")
    title   = host or url

    new_entry = {
        # canonical
        "category": "Passwords",
        "title": title,
        "website": url,
        "url": url,
        "email": user,
        "password": pwd,
        "phone": "",
        "backup_code": "",
        "twofa_enabled": False,
        "notes": "Added With Browser",
        "created_at": now_iso,
        "updated_at": now_iso,
        "Date": today, 

        # Title-case compatibility for existing table/loaders
        "Website": url,
        "Email": user,
        "Password": pwd,
        "Phone Number": "",
        "Backup Code": "",
        "2FA Enabled": False,
        "Notes": "Added With Browser",
    }

    # --- Load current user's entries
    try:
        current_user_name = self.currentUsername.text() if hasattr(self, "currentUsername") else ""
    except Exception:
        current_user_name = ""
    try:
        entries = load_vault(current_user_name, self.userKey) or []
    except Exception:
        entries = []

    # --- Helpers
    def _strip_www(h: str) -> str:
        if not h:
            return ""
        h = h.strip().lower()
        while h.startswith("www."):
            h = h[4:]
        return h

    target_host = _strip_www((host.split(":")[0]) if host else "")

    # --- Find host matches across multiple possible URL fields
    same_host_indices = []
    for idx, ent in enumerate(entries):
        e_url = (ent.get("url") or ent.get("URL") or ent.get("website")
                 or ent.get("site") or ent.get("Website") or "").strip()
        try:
            e_host = urlparse(e_url if "://" in e_url else f"https://{e_url}").netloc or e_url
        except Exception:
            e_host = e_url
        e_host_norm = _strip_www(e_host.split(":")[0])
        if e_host_norm == target_host or e_host_norm.endswith("." + target_host) or target_host.endswith("." + e_host_norm):
            same_host_indices.append(idx)

    # --- Partition by username (check both 'email' and 'Email')
    same_user_indices, diff_user_indices = [], []
    for idx in same_host_indices:
        ent_user = (ent := entries[idx]).get("email") or ent.get("Email") or ""
        ent_user = ent_user.strip()
        (same_user_indices if ent_user == user else diff_user_indices).append(idx)

    # --- Same user exists → propose update (password compare checks both cases)
    if same_user_indices:
        for i in same_user_indices:
            existing_pwd = (entries[i].get("password")
                            or entries[i].get("Password") or "")
            if existing_pwd == pwd:
                QMessageBox.information(self, self.tr("Already Saved"), self.tr("These credentials already exist in your vault."))
                return True

        msg = self.tr("Credentials for this site and username already exist:\n\nWebsite: ") + f"{host}" + self.tr("\nUsername:") + f"{user or self.tr('(empty)')}\n\n" + self.tr("Would you like to update the existing entry?")
        resp = QMessageBox.question(
            self, self.tr("Update Login"),
            msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if resp != QMessageBox.StandardButton.Yes:
            return False

        upd_idx = same_user_indices[0]
        # keep title if present in old entry
        if not new_entry["title"]:
            prev_title = (entries[upd_idx].get("title")
                          or entries[upd_idx].get("Website")
                          or host)
            new_entry["title"] = prev_title
        new_entry["updated_at"] = now_iso

        try:
            update_vault_entry(current_user_name, self.userKey, upd_idx, new_entry)
            self._on_any_entry_changed()
        except Exception:
            try:
                update_vault_entry(current_user_name, self.userKey, upd_idx, new_entry)
                self._on_any_entry_changed()
            except Exception:
                QMessageBox.critical(self, self.tr("Update Failed"), self.tr("Failed to update the existing entry."))
                return False

        # Reload from source of truth
        try:            
            update_baseline(username=current_user_name, verify_after=False, who=f"Trash Vault changed")
        except Exception: pass
        try: self.load_vault_table()
        except Exception: pass
        QMessageBox.information(self, self.tr("Updated"), self.tr("Login updated in your vault."))
        return True

    # --- Different users for same host → confirm add
    if diff_user_indices:
        msg = (self.tr("Existing credentials were found for this site, but with different usernames.\n\n"
               "Website: {host1}\nUsername: {username1}\n\n"
               "Would you like to add this as a new entry?")).format(host1=host, username1={user or self.tr('(empty)')})
        resp = QMessageBox.question(
            self, self.tr("Add New Login"),
            msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if resp != QMessageBox.StandardButton.Yes:
            return False
     
    # --- Persist new entry
    try:
        # --- Persist new entry
        add_vault_entry(current_user_name, self.userKey, new_entry)
        self._on_any_entry_changed()
        update_baseline(username=self.currentUsername.text(), verify_after=False, who=f"Vault Added")
        QMessageBox.information(self, self.tr("Save Login"), self.tr("Added successfully"))
        self.categorySelector_2.setCurrentText(self.tr("Passwords"))
        self.reset_logout_timer()
        self.load_vault_table()
        return True   # <-- was just `return`

    except Exception as e:
            log.error(f"{kql.i('err')} [ERROR] Vault Add URL Error: {e}")
            QMessageBox.warning(self, self.tr("Save Login"), self.tr("Could not save to vault."))
            return False

# --- Password generator helpers ----------------------------------   

def check_backup_codes_ok(self, username: str, b_type: str | None = "both") -> None:
    """
    Ensure the user has sufficient backup codes for the requested type.
    If only 0–1 left, offer to regenerate and show the Emergency Kit dialog.
    Supports a per-type 'Don't show again' preference.

    b_type:
      - "yubi"  -> YubiKey Gate/Wrap backup codes (only if yubi enabled)
      - "2fa"   -> TOTP/2FA backup codes (only if 2FA enabled)
      - None / "" / "both" / "all" / "auto" -> check all relevant types
    """
    try:
        log.debug("[B-CODE] Backup Check")
        username = (username or "").strip()
        if not username:
            return

        b_in = (b_type or "").strip().lower()

        # Auto / both: check 2FA then Yubi (but each worker will skip if not enabled)
        if b_type is None or b_in in ("", "both", "all", "auto"):
            try:
                _check_backup_codes_ok_one(self, username, "2fa")
            except Exception as e:
                log.debug("[B-CODE] 2fa check failed: %s", e)
            try:
                _check_backup_codes_ok_one(self, username, "yubi")
            except Exception as e:
                log.debug("[B-CODE] yubi check failed: %s", e)
            return
        _check_backup_codes_ok_one(self, username, b_in)

    except Exception as e:
        log.error("check_backup_codes_ok failed: %s", e)

def _check_backup_codes_ok_one(self, username: str, b_type: str) -> None:
    """Internal worker: checks exactly one type ('yubi' or '2fa')."""
    from auth.identity_store import (
        get_login_backup_count_quick,
        get_2fa_backup_count_quick,
        get_yubi_config_public,
    )

    try:
        from auth.login.login_handler import is_2fa_enabled as _is_2fa_enabled
    except Exception:
        _is_2fa_enabled = None

    # --- normalise type ---
    b = (b_type or "yubi").strip().lower()
    if b not in ("yubi", "2fa"):
        b = "yubi"

    try:
        self.set_status_txt(self.tr("Checking Backup Codes"))
    except Exception:
        pass

    # -------
    # Skip irrelevant checks (only warn if factor enabled)
    # -------
    if b == "yubi":
        try:
            # ✅ best: reads header.meta.yubi_enabled / yubi_mode
            from auth.identity_store import get_yubi_meta_quick
            yubi_enabled, yubi_mode = get_yubi_meta_quick(username)
            # treat having a mode as enabled too (defensive)
            yubi_enabled = bool(yubi_enabled or yubi_mode)
        except Exception:
            yubi_enabled = False
        if not yubi_enabled:
            log.debug("[B-CODE] yubi check skipped (not enabled) user=%s", username)
            return

    if b == "2fa":
        try:
            # quick proxy: if any 2fa backup codes exist, it's enabled;
            # stronger: also check TOTP enabled if helper exists
            cnt = int(get_2fa_backup_count_quick(username) or 0)
            twofa_enabled = bool(cnt > 0)
            if _is_2fa_enabled is not None:
                twofa_enabled = bool(twofa_enabled or _is_2fa_enabled(username))
        except Exception:
            twofa_enabled = False

        if not twofa_enabled:
            log.debug("[B-CODE] 2fa check skipped (not enabled) user=%s", username)
            return

    # -------
    # Now compute remaining + per-type UI strings/settings
    # -------
    if b == "2fa":
        human = "2FA"
        suppress_key = "suppress_backup_warning_2fa"
        emg_field = "twofa_backup_codes"
        remaining = int(get_2fa_backup_count_quick(username) or 0)
        log.debug("[B-CODE] 2fa remaining user=%s left=%s", username, remaining)
    else:
        human = "YubiKey"
        suppress_key = "suppress_backup_warning_login"
        emg_field = "recovery_backup_codes"
        remaining = int(get_login_backup_count_quick(username) or 0)
        log.info("[B-CODE] yubi remaining user=%s left=%s", username, remaining)

    # Respect per-type suppression
    try:
        suppressed = bool(get_user_setting(username, suppress_key, False))
    except Exception:
        suppressed = False

    log.debug(
        "Backup-codes check: user=%s type=%s remaining=%s suppressed=%s",
        username, b, remaining, suppressed
    )

    if suppressed:
        return

    # Enough codes? bail
    if remaining >= 2:
        return

    # Title/body per count
    if remaining == 1:
        title = f"{human} " + self.tr("Backup Codes Low")
        text = (
            self.tr("You have only 1") + f" {human.lower()} " + self.tr("backup code left.\n\n")
            + self.tr(
                "If this last code is used or lost and your primary login method is unavailable, "
                "you may be unable to access your account."
            )
            + "\n\n"
            + self.tr(
                "To reduce the risk of lockout, it is strongly recommended that you "
                "generate a new set of backup codes now."
            )
            + "\n\n"
            + self.tr("Old codes will be permanently invalidated.")
            + "\n\n"
            + self.tr("You can also regenerate them later from Settings → Profile.")
        )
    else:
        title = self.tr("No ") + f"{human}" + self.tr(" Backup Codes Left")
        text = (
            self.tr("You have no ") + f"{human.lower()}" + self.tr(" backup codes left.\n\n")
            + self.tr(
                "If your primary login method becomes unavailable, "
                "you may be unable to access your account."
            )
            + "\n\n"
            + self.tr(
                "To avoid the risk of lockout, it is strongly recommended that you "
                "generate a new set of backup codes now."
            )
            + "\n\n"
            + self.tr("Old codes will be permanently invalidated.")
            + "\n\n"
            + self.tr("You can also regenerate them later from Settings → Profile.")
        )

    # Custom QMessageBox so we can add a checkbox
    msg = QMessageBox(self)
    msg.setWindowTitle(title)
    msg.setText(text)
    msg.setIcon(QMessageBox.Warning)
    yes_btn = msg.addButton(self.tr("Regenerate Now"), QMessageBox.YesRole)
    msg.addButton(self.tr("Later"), QMessageBox.NoRole)

    dont_show = QCheckBox(self.tr("Don't show again for this warning"))
    msg.setCheckBox(dont_show)

    msg.exec()
    reply = msg.clickedButton()

    # Persist suppression per type if checked
    if dont_show.isChecked():
        try:
            set_user_setting(username, suppress_key, True)
        except Exception:
            pass

    # Regenerate on Yes
    if reply != yes_btn:
        return

    # ---- Collect password (needed to write identity payload) ----
    pwd = getattr(self, "current_password", None)

    if not pwd:
        # Use existing confirmation flow (handles yubi/2fa policies)
        try:
            pw = self._confirm_sensitive_action(
                username=username,
                title=self.tr("Confirm Password"),
                require_password=True,
                twofa_check=False,
                yubi_check=False,
                return_pw=True,
            )
            if isinstance(pw, str) and pw:
                pwd = pw
        except Exception:
            pwd = None

    if not pwd:
        msg_txt = (
            self.tr("Enter password for ") + f"'{username}'"
            + self.tr(" to generate new ") + f"{human} " + self.tr("backup codes:")
        )
        pwd, ok = QInputDialog.getText(self, self.tr("Confirm Password"), msg_txt, QLineEdit.Password)
        if not ok or not pwd:
            QMessageBox.information(self, self.tr("Cancelled"), self.tr("Backup code regeneration cancelled."))
            return

    # ---- Generate + persist; we expect plaintext codes returned (show once) ----
    new_codes = None
    try:
        new_codes = self.on_generate_recovery_key_clicked(b, password_for_identity=pwd)
    except TypeError:
        # Backward-compat if function signature doesn't accept password_for_identity
        new_codes = self.on_generate_recovery_key_clicked(b)

    if not new_codes or not isinstance(new_codes, list):
        # If  handler shows its own UI and doesn't return codes,
        # we can’t show Emergency Kit reliably.
        QMessageBox.information(
            self,
            self.tr("Backup Codes Updated"),
            self.tr("Backup codes were updated."),
        )
        return

    # Show in Emergency Kit with the correct field
    try:
        if emg_field == "recovery_backup_codes":
            self.emg_ask(
                username=username,
                recovery_backup_codes=new_codes,
                twofa_backup_codes=None,
                totp_secret_plain=None,
                totp_uri=None,
                totp_qr_png=None,
            )
        else:
            self.emg_ask(
                username=username,
                recovery_backup_codes=None,
                twofa_backup_codes=new_codes,
                totp_secret_plain=None,
                totp_uri=None,
                totp_qr_png=None,
            )
    except Exception:
        # fallback
        QMessageBox.information(
            self,
            f"{human}" + self.tr(" Backup Codes Updated"),
            self.tr("Generated ") + f"{len(new_codes)} {human} " + self.tr(" backup codes.\nPlease store them safely."),
        )

    # Re-check remaining
    try:
        if b == "yubi":
            remaining_after = int(get_login_backup_count_quick(username) or 0)
        else:
            remaining_after = int(get_2fa_backup_count_quick(username) or 0)
        log.info("[B-CODE] refreshed user=%s type=%s remaining_after=%s", username, b, remaining_after)
    except Exception as e:
        log.debug("[B-CODE] quick recheck failed: %s", e)

# --- login\logout ------------------------------------------

def _continue_after_factors(self, username: str) -> None:
    # ------------------------
    # YubiKey mode detection
    # - Prefer PUBLIC header (works for passwordless / DPAPI)
    # - Fall back to private identity payload only if we have context
    # ------------------------
    mode = None
    cfg = None

    try:
        from auth.identity_store import get_yubi_config_public
        pub = get_yubi_config_public(username) or {}
        mode = (pub.get("mode") or "").strip().lower() or None
    except Exception:
        mode = None

    # If we still don't know, try private config (requires password or bytes-KEK)
    if not mode:
        try:
            from auth.identity_store import get_yubi_config
            cfg = get_yubi_config(username, getattr(self, "current_password", "") or "") or {}
            mode = (cfg.get("mode") or "").strip().lower() or None
        except Exception:
            cfg = None
            mode = None

    # ------------------------
    # Enforce YubiKey factors BEFORE any 2FA dialog / successful_login
    # ------------------------
    # IMPORTANT: Use the existing threaded YubiKey login dialog so we:
    # - don't freeze the UI
    # - keep the original UX (Insert → Touch, plus Backup/Recovery fallbacks)

    if mode in ("yk_hmac_gate", "yk_hmac_wrap"):
        # Build the most complete config we can.
        # - Public header is always safe (works for DPAPI/passwordless).
        # - Private config requires either the plaintext password OR identity_kek (DPAPI v3).
        cfg_seed = None
        try:
            cfg_seed = pub if isinstance(pub, dict) else None
        except Exception:
            cfg_seed = None

        # Password for identity operations (backup-code consumption).
        # Password/identity context used for consuming backup codes.
        # NOTE: This may be a plaintext password (normal login) OR an identity_kek bytes value
        # (DPAPI v3 passwordless). identity_store supports both for existing identities.
        pw_for_identity = getattr(self, "current_password", "") or ""
        if isinstance(pw_for_identity, memoryview):
            pw_for_identity = bytes(pw_for_identity)


        # Always try to load the PRIVATE YubiKey config when we have a plaintext password,
        # even if the mode came from the public header. The original worker/dialog often
        # relies on private fields (slot/serial/etc).
        if not (isinstance(cfg, dict) and cfg):
            if pw_for_identity:
                try:
                    from auth.identity_store import get_yubi_config
                    cfg = get_yubi_config(username, pw_for_identity) or {}
                except Exception:
                    cfg = cfg if isinstance(cfg, dict) else None

        # For WRAP we MUST have the wrapped MK payload.
        if mode == "yk_hmac_wrap":
            if not (isinstance(cfg, dict) and cfg.get("wrapped_b64")):
                try:
                    from auth.identity_store import get_yubi_config
                    ik = getattr(self, "_identity_kek", None)
                    if isinstance(ik, (bytes, bytearray, memoryview)) and bytes(ik):
                        cfg = get_yubi_config(username, bytes(ik)) or {}
                    elif pw_for_identity:
                        cfg = get_yubi_config(username, pw_for_identity) or {}
                except Exception:
                    cfg = cfg if isinstance(cfg, dict) else None

            if not (isinstance(cfg, dict) and cfg.get("wrapped_b64")):
                QMessageBox.information(
                    self,
                    self.tr("Remembered device needs upgrade"),
                    self.tr(
                        "Keyquorum could not load the YubiKey WRAP data needed to unlock this vault."
                        "If you are using a remembered-device token, sign in once with your password (and tick "
                        "'Remember this device') to upgrade the token to v3."
                    ),
                )
                return

        # Compose final cfg for the dialog (must include the mode).
        dlg_cfg = {}
        try:
            if isinstance(cfg_seed, dict):
                dlg_cfg.update(cfg_seed)
        except Exception:
            pass
        try:
            if isinstance(cfg, dict):
                dlg_cfg.update(cfg)
        except Exception:
            pass
        dlg_cfg["mode"] = mode

        # Gate/Wrap should always run BEFORE 2FA prompt.
        try:
            # Prefer the original dialog implementation inside app_window.py
            from app.app_window import YubiKeyLoginGateDialog
        except Exception:
            try:
                from app_window import YubiKeyLoginGateDialog
            except Exception:
                YubiKeyLoginGateDialog = None

        if not YubiKeyLoginGateDialog:
            QMessageBox.critical(
                self,
                self.tr("YubiKey required"),
                self.tr("YubiKey login dialog is missing from this build."),
            )
            return

        pwk = getattr(self, "_pw_kek", None)
        import secrets as _secrets
        dlg = YubiKeyLoginGateDialog(
            username=username,
            password=pw_for_identity,
            cfg=dlg_cfg,
            challenge_hex=_secrets.token_hex(16),
            parent=self,
            password_key=(bytes(pwk) if (mode == "yk_hmac_wrap" and isinstance(pwk, (bytes, bytearray, memoryview))) else None),
        )

        try:
            ok_dialog = bool(dlg.exec())
        except Exception:
            ok_dialog = False
        if not ok_dialog:
            return

        # If they used the fallback paths:
        mk_from_dialog = getattr(dlg, "result_mk", None)
        result_mode = (getattr(dlg, "result_mode", "") or "").strip().lower()

        if mode == "yk_hmac_gate":
            # Gate is satisfied either by hardware touch or backup-code bypass.
            self._yk_gate_satisfied = True
            # Continue to 2FA logic below (it will short-circuit for gate).
            pass


        if mode == "yk_hmac_wrap":
            mk_from_dialog = getattr(dlg, "result_mk", None)
            if isinstance(mk_from_dialog, (bytes, bytearray)) and len(mk_from_dialog) >= 16:
                self.userKey = bytes(mk_from_dialog)
                try:
                    self._login_requires_yubi_wrap = False
                except Exception:
                    pass
                try:
                    self._yk_gate_satisfied = True
                except Exception:
                    pass
            else:
                QMessageBox.critical(
                    self,
                    self.tr("Vault locked"),
                    self.tr("YubiKey WRAP was not completed."),
                )
                return

        if False and mode == "yk_hmac_wrap":
            # WRAP: dialog may have returned an MK (recovery+backup path).
            if isinstance(mk_from_dialog, (bytes, bytearray)) and len(mk_from_dialog) >= 16:
                self.userKey = bytes(mk_from_dialog)
                try:
                    self._login_requires_yubi_wrap = False
                except Exception:
                    pass
                try:
                    self._yk_gate_satisfied = True
                except Exception:
                    pass
            else:
                # Hardware path: unwrap MK using YubiKey + password-context (pw_kek).
                pwk = getattr(self, "_pw_kek", None)
                if not isinstance(pwk, (bytes, bytearray, memoryview)) or len(bytes(pwk)) < 16:
                    QMessageBox.critical(
                        self,
                        self.tr("Vault locked"),
                        self.tr("Missing password context required for YubiKey WRAP."),
                    )
                    return

                try:
                    from qtpy.QtCore import QThread, Signal
                    from qtpy.QtWidgets import QProgressDialog
                except Exception:
                    QThread = None
                    Signal = None
                    QProgressDialog = None

                try:
                    try:
                        from yubi.yubihmac_wrap import unwrap_master_key_with_yubi
                    except Exception:
                        from auth.yubi.yubihmac_wrap import unwrap_master_key_with_yubi
                except Exception as e:
                    QMessageBox.critical(self, self.tr("Vault locked"), self.tr("Missing WRAP module: {e}").format(e=e))
                    return

                # Friendly error type (optional)
                try:
                    from auth.yubi.yk_backend import YubiKeyError
                except Exception:
                    YubiKeyError = Exception

                # Run unwrap off the UI thread to avoid freezes.
                if QThread and Signal and QProgressDialog:

                    class _WrapUnwrapWorker(QThread):
                        ok = Signal(bytes)
                        err = Signal(str)

                        def __init__(self, *, pwk_bytes: bytes, cfg_dict: dict):
                            super().__init__()
                            self._pwk = pwk_bytes
                            self._cfg = cfg_dict

                        def run(self):
                            try:
                                mk = unwrap_master_key_with_yubi(b"", password_key=self._pwk, cfg=self._cfg or {})
                                if not isinstance(mk, (bytes, bytearray)) or len(mk) < 16:
                                    raise RuntimeError("Empty key from YubiKey unwrap")
                                self.ok.emit(bytes(mk))
                            except Exception as e:
                                self.err.emit(str(e) or "YubiKey unwrap failed")

                    prog = QProgressDialog(
                        self.tr("Waiting for YubiKey…"),
                        self.tr("Cancel"),
                        0,
                        0,
                        self,
                    )
                    prog.setWindowTitle(self.tr("YubiKey required"))
                    prog.setMinimumDuration(0)
                    prog.setAutoClose(True)
                    prog.setAutoReset(True)

                    worker = _WrapUnwrapWorker(pwk_bytes=bytes(pwk), cfg_dict=dlg_cfg)

                    def _done_ok(mk_bytes: bytes):
                        try:
                            prog.close()
                        except Exception:
                            pass
                        self.userKey = bytes(mk_bytes)
                        try:
                            self._login_requires_yubi_wrap = False
                        except Exception:
                            pass
                        try:
                            self._yk_gate_satisfied = True
                        except Exception:
                            pass
                        # continue to 2FA / success flow
                        try:
                            self.set_status_txt(self.tr("YubiKey verified"))
                        except Exception:
                            pass

                    def _done_err(msg: str):
                        try:
                            prog.close()
                        except Exception:
                            pass
                        low = (msg or "").lower()
                        if "no yubikey" in low or "not detected" in low:
                            QMessageBox.information(
                                self,
                                self.tr("YubiKey required"),
                                self.tr("Insert your YubiKey and try again."),
                            )
                        else:
                            QMessageBox.critical(self, self.tr("YubiKey error"), msg or "YubiKey error")

                    worker.ok.connect(_done_ok)
                    worker.err.connect(_done_err)

                    def _cancel():
                        try:
                            worker.requestInterruption()
                        except Exception:
                            pass
                        try:
                            worker.terminate()
                        except Exception:
                            pass
                        try:
                            worker.wait(200)
                        except Exception:
                            pass

                    prog.canceled.connect(_cancel)

                    worker.start()
                    prog.exec()

                    # If unwrap failed/cancelled, userKey won't be set; stop login.
                    if not (isinstance(getattr(self, "userKey", None), (bytes, bytearray)) and len(self.userKey) >= 16):
                        return
                else:
                    # Fallback: synchronous unwrap (older Qt bindings) - may momentarily freeze.
                    try:
                        mk = unwrap_master_key_with_yubi(b"", password_key=bytes(pwk), cfg=dlg_cfg or {})
                    except YubiKeyError as e:
                        msg = str(e) or "YubiKey error"
                        QMessageBox.information(self, self.tr("YubiKey required"), msg)
                        return
                    if not isinstance(mk, (bytes, bytearray)) or len(mk) < 16:
                        QMessageBox.critical(self, self.tr("Vault locked"), self.tr("YubiKey unwrap returned an empty key."))
                        return
                    self.userKey = bytes(mk)
                    try:
                        self._login_requires_yubi_wrap = False
                    except Exception:
                        pass
                    try:
                        self._yk_gate_satisfied = True
                    except Exception:
                        pass


    self.set_status_txt(self.tr("Checking 2FA Login"))
    try:
        from auth.login.login_handler import is_2fa_enabled as db_is_2fa_enabled
        db_flag = bool(db_is_2fa_enabled(username))
    except Exception:
        db_flag = False

    self.set_login_visible(False)
    self.currentUsername.setText(username)

    # Live identity status (source of truth for TOTP)
    from auth.identity_store import has_totp_quick
    live_has_2fa = bool(has_totp_quick(username))
    # If YubiKey GATE succeeded, treat it as the 2FA method for this login (either/or)

    if mode == "yk_hmac_gate" and self._yk_gate_satisfied == True:
        self._yk_gate_satisfied = False  # one-shot
        self.successful_login()
        return

    # Keep the checkbox in sync with the *live* identity
    if hasattr(self, 'twoFACheckbox'):
        self.twoFACheckbox.blockSignals(True)
        self.twoFACheckbox.setChecked(live_has_2fa)
        self.twoFACheckbox.blockSignals(False)
        self.regen_key_both.setEnabled(live_has_2fa)
        self.regen_key_2fa.setEnabled(live_has_2fa)
        self.regen_key_2fa_2.setEnabled(live_has_2fa)
    log.debug("%s [2FA] status: identity=%s, user_db_flag=%s",
              kql.i('info'), live_has_2fa, db_flag)

    # --- Case A: both say off -> log straight in

    if not live_has_2fa and not db_flag:
        self.totp = None
        self.set_login_visible(False)
        try:
            self.passwordField.clear()
            msg = self.tr("{ok} Successful login no 2FA").format(ok=kql.i("ok"))
            log_event_encrypted(self.currentUsername.text(), self.tr("login"),msg)
            log.debug(str(f"{kql.i('ok')} [2FA] {kql.i('auth')} Successful login no 2FA"))

        except Exception:
            pass

        self.successful_login()
        return

    # --- Case B: identity says ON (this is the normal path) -> prompt for code

    if live_has_2fa:
        from auth.tfa.twofa_dialog import prompt_2fa_for_user
        ok = prompt_2fa_for_user(self, username)
        if ok:
            self.successful_login()
            return
        else:
            try:
                msg = self.tr("{ok} 2FA not completed").format(ok=kql.i("warn"))
                log_event_encrypted(self.currentUsername.text(), self.tr("2FA"), msg)
            except Exception:
                pass
            self.safe_messagebox_warning(self, self.tr("Two-Factor Authentication"),
                                         self.tr("Two-factor authentication was not completed."))
            self.passwordField.clear()
            try: self.current_password = None
            except Exception: pass
            self.show_login_ui()
            if hasattr(self, 'mainTabs'):
                self.mainTabs.setVisible(False)
            return

    # --- Case C: DB says ON but identity says OFF -> repair by re-setup (non-destructive)
    # We *do not* bypass 2FA; ask the user to re-enable now.
    reply = QMessageBox.question(
        self,
        self.tr("2FA Setup Required"),
        (self.tr("Your account is marked as '2FA enabled' but the identity data for TOTP is missing.\n\n"
         "Would you like to set up 2FA now?")),
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.Yes,
    )
    if reply != QMessageBox.Yes:
        # Abort login for safety
        self.safe_messagebox_warning(self, self.tr("Two-Factor Authentication"),
                                     self.tr("2FA is required for this account. Login aborted."))
        self.passwordField.clear()
        self.show_login_ui()
        if hasattr(self, 'mainTabs'):
            self.mainTabs.setVisible(False)
        return

    # Collect password to write identity
    password = self._prompt_account_password(username)
    if not password:
        self.safe_messagebox_warning(self, self.tr("Two-Factor Authentication"),
                                     self.tr("2FA setup was cancelled."))
        self.passwordField.clear()
        self.show_login_ui()
        if hasattr(self, 'mainTabs'):
            self.mainTabs.setVisible(False)
        return

    # Run setup
    try:
        from auth.tfa.twofa_dialog import twofa_setup
        ok2fa = twofa_setup(self, username, pwd=password)
    except Exception as e:
        log.error("%s -> %s [2FA] Setup error during login repair for '%s': %s",
                  kql.i('auth'), kql.i('err'), username, e)
        ok2fa = {"ok": False, "error": str(e)}

    if not (isinstance(ok2fa, dict) and ok2fa.get("ok")):
        self.safe_messagebox_warning(
            self, self.tr("Two-Factor Authentication"),
            self.tr("Could not complete 2FA setup; login aborted.")
        )
        self.passwordField.clear()
        self.show_login_ui()
        if hasattr(self, 'mainTabs'):
            self.mainTabs.setVisible(False)
        return

    # Setup succeeded -> immediately prompt for code to sign in
    if prompt_2fa_for_user(self, username):
        self.successful_login()
        return

    try:
        set_probe_enabled(False)
    except Exception:
        pass

    # If they fail the code right after setup
    self.safe_messagebox_warning(self, self.tr("Two-Factor Authentication"),
                                 self.tr("Two-factor authentication was not completed."))

    self.passwordField.clear()
    self.show_login_ui()
    if hasattr(self, 'mainTabs'):
        self.mainTabs.setVisible(False)


def _maybe_show_release_notes(self, *args, **kwargs):
    from ui.ui_flags import _maybe_show_release_notes as __maybe_show_release_notes
    return __maybe_show_release_notes(self)


# ==============================
# ---  get selected entry ------
# ==============================


def __init__default_values(self, *args, **kwargs):
    """
    Reset per-session variables to sensible defaults.  This should be
    called once during application construction and again after each
    logout.  Its purpose is to avoid carrying over timers, watchers
    or counters between user sessions.  Many of these attributes are
    created lazily; setting them to None here ensures a clean slate.
    """
    # Reset cloud sync state and auto-sync timers
    try:
        # Stop and release the auto-sync timer if present
        t = getattr(self, "_auto_sync_timer", None)
        if t:
            try:
                t.stop()
            except Exception:
                pass
            try:
                t.deleteLater()
            except Exception:
                pass
        self._auto_sync_timer = None
    except Exception:
        pass
    # Release the vault file watcher
    try:
        w = getattr(self, "_vault_watcher", None)
        if w:
            try:
                w.deleteLater()
            except Exception:
                pass
        self._vault_watcher = None
    except Exception:
        pass
    # Clear the sync engine and bound user
    try:
        self.sync_engine = None
    except Exception:
        pass
    try:
        self._sync_user = None
    except Exception:
        pass
    # Guard flags for sync recursion
    try:
        self._sync_guard = False
    except Exception:
        pass
    # Drop debouncer timers (baseline/vault reload)
    try:
        br = getattr(self, "_baseline_timer", None)
        if br:
            try:
                br.stop()
            except Exception:
                pass
            try:
                br.deleteLater()
            except Exception:
                pass
        self._baseline_timer = None
    except Exception:
        pass
    try:
        vr = getattr(self, "_vault_reload_timer", None)
        if vr:
            try:
                vr.stop()
            except Exception:
                pass
            try:
                vr.deleteLater()
            except Exception:
                pass
        self._vault_reload_timer = None
    except Exception:
        pass
    # Reset the backup advisor and scheduler; clear counters in QSettings
    try:
        adv = getattr(self, "backupAdvisor", None)
        if adv:
            try:
                adv.reset_change_counter(clear_snooze=True, clear_session_suppress=True)
            except Exception:
                pass
    except Exception:
        pass
    try:
        self.backupAdvisor = None
    except Exception:
        pass
    try:
        self.backupScheduler = None
    except Exception:
        pass
    # Backup reminder mode default
    try:
        self._backup_remind_mode = "both"
    except Exception:
        pass
    # Reset session flags
    try:
        self._is_logging_out = False
    except Exception:
        pass

    # 4) Reset backup counter and session state on logout.  Without this, change
    # counters can spill over when switching accounts, causing stale
    # "X changes" prompts for a newly logged-in user.  We also clear
    # auto-sync timers, file watchers and any per-session sync state.
    try:
        adv = getattr(self, "backupAdvisor", None)
        if adv:
            # Clear pending changes and suppression flags
            adv.reset_change_counter(clear_snooze=True, clear_session_suppress=True)
    except Exception:
        pass
    # Use the helper to tear down auto-sync and sync engine and reinitialise
    try:
        if hasattr(self, "__init__default_values"):
            self.__init__default_values()
    except Exception:
        pass


def _bulk_preview_entries(self, entries: list[dict]) -> bool:
    """
    Show a list of entries with checkboxes + single category picker.
    For each selected item we open the AddEntryDialog prefilled, one by one.
    """
    if not entries:
        return False

    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Share Packet ") + f"— {len(entries)}" + self.tr(" Items"))
    dlg.setModal(True)
    v = QVBoxLayout(dlg); v.setContentsMargins(12,12,12,12); v.setSpacing(10)

    lab = QLabel(self.tr("Select items to import and choose a target category."))
    v.addWidget(lab)

    # list with checkboxes
    lst = QListWidget()
    lst.setMinimumSize(720, 360)
    for e in entries:
        title = (e.get("Title") or e.get("Name") or e.get("Email") or e.get("Username") or e.get("Website") or e.get("URL") or "Untitled")
        item = QListWidgetItem(str(title))
        item.setCheckState(Qt.CheckState.Checked)
        item.setData(Qt.ItemDataRole.UserRole, e)
        lst.addItem(item)
    v.addWidget(lst, 1)

    # Category picker
    h = QHBoxLayout()
    h.addWidget(QLabel(self.tr("Category:")))
    cmb = QComboBox(); cmb.setMinimumWidth(220)
    try:
        if getattr(self, 'categorySelector_2', None) and self.categorySelector_2.count() > 0:
            for i in range(self.categorySelector_2.count()):
                cmb.addItem(self.categorySelector_2.itemText(i))
        else:
            for c in ["Email Accounts", "Web Logins", "Software Licenses", "Secure Notes"]:
                cmb.addItem(c)
    except Exception:
        for c in ["Email Accounts", "Web Logins", "Software Licenses", "Secure Notes"]:
            cmb.addItem(c)
    h.addWidget(cmb, 1)
    v.addLayout(h)

    btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    v.addWidget(btns)

    chosen = {"ok": False}
    def _accept():
        target = cmb.currentText().strip()
        if not target:
            QMessageBox.information(dlg, dlg.tr("Import Share"), dlg.tr("Please choose a category first."))
            return
        if self._is_blocked_target(target):
            msg = dlg.tr("Import into ") + f"“{target}”" + dlg.tr(" is blocked by your safety setting.")
            QMessageBox.warning(dlg, dlg.tr("Import Share"), msg)
            return

        username = self._active_username() or ""
        try:
            from vault_store.add_entry_dialog import AddEntryDialog
        except Exception:
            QMessageBox.critical(dlg, dlg.tr("Import Share"), dlg.tr("AddEntryDialog not found."))
            return

        # Iterate selected items and open editor for each
        for i in range(lst.count()):
            item = lst.item(i)
            if item.checkState() != Qt.CheckState.Checked:
                continue
            entry = item.data(Qt.ItemDataRole.UserRole) or {}
            mapped = self._map_for_dialog(entry)


            editor = AddEntryDialog(self, target, getattr(self, "enable_breach_checker", False),
                                    existing_entry=None, pro=None, user=self.currentUsername.text(), is_dev=is_dev)
            if hasattr(editor, "category"):
                editor.category = target
            for name in ("build_form", "_build_form", "rebuild_form", "on_category_changed"):
                if hasattr(editor, name):
                    try: getattr(editor, name)()
                    except Exception: pass
            try:
                self._prefill_dialog_for_entry(editor, mapped)
            except Exception:
                pass

            # Run editor modally (sequential bulk)
            if editor.exec() == int(editor.DialogCode.Accepted):
                new_entry = editor.get_entry_data() or {}
                new_entry["category"] = target
                new_entry["Type"] = target
                new_entry["Date"] = dt.datetime.now().strftime("%Y-%m-%d")

                try:
                    entries_cur = load_vault(username, self.userKey) or []
                except TypeError:
                    entries_cur = load_vault(username) or []

                entries_cur.append(new_entry)
                try:
                    save_vault(username, self.userKey, entries_cur)
                except TypeError:
                    save_vault(username, entries_cur)

        try:
            self._on_any_entry_changed()
            self.load_vault_table()
            update_baseline(username=username, verify_after=False, who="Category Vault Changed")
        except Exception:
            pass

        chosen["ok"] = True
        dlg.accept()

    btns.accepted.connect(_accept)
    btns.rejected.connect(dlg.reject)

    return dlg.exec() == QDialog.DialogCode.Accepted and chosen["ok"]


# ==============================
# --- Password/Vault history ----------------
# ==============================

# ---- Passkey store I/O used by passkeys_store.py ----


def export_user_catalog_encrypted(self, user_root: str) -> None:
    """
    Export this user's catalog overlay to an encrypted file
    protected with a user-chosen password.

    Called from CatalogEditorUserDialog._on_export_encrypted().
    """
    from qtpy.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox
    from vault_store.vault_store import _enc_backup_bytes

    username = (self.currentUsername.text() or "").strip()
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
            overlay = load_user_catalog_raw(user_root, self.userKey) or {}
        except TypeError:
            overlay = load_user_catalog_raw(Path(user_root), self.userKey) or {}
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


def start_bridge_server(self, host="127.0.0.1", port=8742, strict: bool | None = None):
    

    # Default: strict in dev, non-strict when frozen (EXE)
    if strict is None:
        strict = not getattr(sys, "frozen", False)
        # Allow override via env (KQ_BRIDGE_STRICT=0/1)
        v = os.environ.get("KQ_BRIDGE_STRICT")
        if v is not None:
            strict = (str(v).strip() not in ("0", "false", "False", "no"))

    try:
        # Bridge handler may live in a different module after the split
        Handler = globals().get("_BridgeHandler") or getattr(type(self), "_BridgeHandler", None)

        if Handler is None:
            try:
                # definitive handler location in the split build
                from vault_store.vault_ui_ops import _BridgeHandler as Handler  # type: ignore
            except Exception:
                Handler = None

        if Handler is None:
            log.error("❌ [BRIDGE] handler class not found; cannot start bridge")
            return

        Handler.appref = weakref.ref(self)
        from http.server import ThreadingHTTPServer
        class _HTTPD(ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

        def _serve_loop(srv):
            log.debug("[BRIDGE] entering serve_forever (pid=%s)", os.getpid())
            try:
                srv.serve_forever()
            except Exception:
                log.exception("❌ [BRIDGE] serve_forever crashed")
            finally:
                try: srv.server_close()
                except Exception: pass
                log.debug("[BRIDGE] serve_forever exited; server closed")

        def _bind(p):
            srv = _HTTPD((host, p), Handler)
            t = threading.Thread(target=_serve_loop, args=(srv,), name="kq-bridge", daemon=True)
            t.start()
            return srv

        def _tcp_ready(p, timeout=0.35) -> bool:
            try:
                with socket.create_connection((host, int(p)), timeout=timeout):
                    return True
            except Exception:
                return False

        def _http_ready(p, timeout=0.8) -> tuple[bool,int|None]:
            try:
                c = http.client.HTTPConnection(host, int(p), timeout=timeout)
                c.request("GET", "/v1/status")
                r = c.getresponse()
                code = r.status
                r.read()
                c.close()
                return (code in (200, 401, 403)), code
            except Exception:
                return (False, None)

        def _wait_until_ready(p, total_ms=3000):
            deadline = _t.time() + (total_ms/1000.0)   # kill time
            tcp_ok = http_ok = False
            http_code = None
            while _t.time() < deadline and not tcp_ok:
                tcp_ok = _tcp_ready(p)
                if not tcp_ok: _t.sleep(0.08)
            while _t.time() < deadline and tcp_ok and not http_ok:
                http_ok, http_code = _http_ready(p)
                if not http_ok: _t.sleep(0.08)
            return tcp_ok, http_ok, http_code

        # --- try primary
        srv = None
        try:
            srv = _bind(port)
            tcp_ok, http_ok, http_code = _wait_until_ready(port)
            
            log.debug("[BRIDGE] verify :%s tcp=%s http=%s code=%s", port, tcp_ok, http_ok, http_code)
            if tcp_ok and http_ok:
                self._bridge_httpd = srv
                self._bridge_port = port
                log.info("✅ [BRIDGE] online at http://%s:%s", host, port)
                return
        except OSError:
            srv = None

        # If verify failed on primary, close it
        try:
            if srv: srv.shutdown(); srv.server_close()
        except Exception:
            pass

        # --- try fallback
        fb = port + 1
        srv2 = _bind(fb)
        tcp_ok, http_ok, http_code = _wait_until_ready(fb)
        log.debug("[BRIDGE] verify :%s tcp=%s http=%s code=%s", fb, tcp_ok, http_ok, http_code)
        if tcp_ok and http_ok:
            self._bridge_httpd = srv2
            self._bridge_port = fb
            log.info("✅ [BRIDGE] online at http://%s:%s", host, fb)
            return

        # Fallback also failed
        if strict:
            try: srv2.shutdown(); srv2.server_close()
            except Exception: pass
            self._bridge_httpd = None
            log.error("❌ [BRIDGE] failed verify on %s and %s", port, fb)
            return

        # Non-strict: keep running on primary even though verify failed,
        # so you can test with netstat/browser and see what AV is doing.
        self._bridge_httpd = srv2
        self._bridge_port = fb
        log.warning("⚠️  [BRIDGE] started without verification on :%s (strict=0)", fb)

    except Exception:
        log.exception("❌ [BRIDGE] failed to start")


def on_generate_recovery_key_clicked(self, b_type: str = "login") -> None:
    self.set_status_txt(self.tr("Generating recovery Key for ") + f"{b_type}")
    # Normalize type
    b = (b_type or "login").strip().lower()
    if b not in ("login", "2fa", "both"):
        b = "login"

    # Target user
    username = (self.currentUsername.text() or "").strip()
    if not username:
        QMessageBox.warning(self, self.tr("Backup Codes"), self.tr("No user selected."))
        return

    # Get password context (prompt if missing)
    pwd = getattr(self, "current_password", None) or getattr(self, "currentPassword", None)
    if not pwd:
        msg = self.tr("Enter password for ") + f"'{username}'" + self.tr(" to generate new backup codes:")
        pwd, ok = QInputDialog.getText(
            self, self.tr("Confirm Password"), msg,
            QLineEdit.Password
        )
        if not ok or not pwd:
            QMessageBox.information(self, self.tr("Cancelled"), self.tr("Backup code regeneration cancelled."))
            return

    # Generate and persist (identity store)
    login_codes: list[str] | None = None
    twofa_codes: list[str] | None = None
    try:
        from auth.tfa.twofactor import gen_backup_codes, yk_twofactor_enabled
        if b == "login":
            login_codes = gen_backup_codes(username, "login", password_for_identity=pwd)
        elif b == "2fa":
            twofa_codes = gen_backup_codes(username, "2fa", password_for_identity=pwd)
        else:  # both (and recovery mode allowed)
            login_codes = gen_backup_codes(username, "login", password_for_identity=pwd)
            twofa_codes = gen_backup_codes(username, "2fa",  password_for_identity=pwd)
    except Exception as e:
        # Most common cause: wrong password for identity store
        QMessageBox.critical(
            self, self.tr("Backup Codes"),
            self.tr("Could not generate backup codes.\n\n"
            "{err}\n\nIf this was a password error, please try again.").format(err=e)
        )
        return

    # Baseline/audit (best effort)
    try:
        update_baseline(username=username, verify_after=False, who=self.tr("Backup Code -> Updated")) 
    except Exception:
        pass
    try:
        msg = self.tr("{ok} (userdb) -> Regenerate Backup codes").format(ok=kql.i('ok'))
        log_event_encrypted(username, self.tr("USER"), msg)
    except Exception:
        pass

    # Helper to stringify lists
    def _fmt_codes(codes: list[str] | None) -> str:
        if not codes:
            return "(none)"
        try:
            return "\n".join(str(x).strip() for x in codes if str(x).strip())
        except Exception:
            return str(codes)

    # Try Emergency Kit dialog first
    try:
        if b == "login":
            if not self.emg_ask(username=username, recovery_backup_codes=login_codes):
                raise RuntimeError("EmergencyKitDialog declined/failed")
        elif b == "2fa":
            if not self.emg_ask(username=username, twofa_backup_codes=twofa_codes):
                raise RuntimeError("EmergencyKitDialog declined/failed")
        else:  # both
            if not self.emg_ask(
                username=username,
                recovery_backup_codes=login_codes,
                twofa_backup_codes=twofa_codes
            ):
                raise RuntimeError("EmergencyKitDialog declined/failed")
        return
    except Exception as e:
        # Fallback: copy to clipboard and show once
        try:
            log.error(f"Emg Error = {e}")
            clip = QApplication.clipboard()
            if b == "login":
                clip.setText(_fmt_codes(login_codes))
            elif b == "2fa":
                clip.setText(_fmt_codes(twofa_codes))
            else:
                clip.setText(
                    f"Login backup codes:\n{_fmt_codes(login_codes)}\n\n"
                    f"2FA backup codes:\n{_fmt_codes(twofa_codes)}"
                )
        except Exception:
            pass

        if b == "login":
            QMessageBox.information(
                self, self.tr("Backup Codes (Shown Once)"),
                self.tr("Save these Login backup codes in a safe offline place.\n\n")
                + _fmt_codes(login_codes)
            )
        elif b == "2fa":
            QMessageBox.information(
                self, self.tr("Backup Codes (Shown Once)"),
                self.tr("Save these 2FA backup codes in a safe offline place.\n\n")
                + _fmt_codes(twofa_codes)
            )
        else:
            QMessageBox.information(
                self, self.tr("Backup Codes (Shown Once)"),
                self.tr("Save these backup codes in a safe offline place.\n\nLogin backup codes:") + 
                f"\n{_fmt_codes(login_codes)}\n\n" + 
                self.tr("2FA backup codes:") + 
                f"\n{_fmt_codes(twofa_codes)}"
            )



def _enable_touch_mode(self, *, force: bool | None = None):
    log.info(f"{kql.i('ui')} -> {kql.i('ok')} [UI] enable touch mode: force={force}")
    # Provide template and format for dynamic value
    self.set_status_txt(self.tr("Applying Touch mode {state}").format(state=force))
    # - state slots
    if not hasattr(self, "_touch_mode_active"):
        self._touch_mode_active = False
    if not hasattr(self, "_orig_row_height"):
        self._orig_row_height = None

    if force is None:  # --- auto-detect ---
        def _qt_has_touch() -> bool:
            try:
                from PySide6.QtGui import QTouchDevice
                return bool(QTouchDevice.devices())
            except Exception:
                 return False

        def _win_has_touch() -> bool:
            try:
                SM_MAXIMUMTOUCHES = 95
                return ctypes.windll.user32.GetSystemMetrics(SM_MAXIMUMTOUCHES) > 0
            except Exception:
                return False

        has_touch = _qt_has_touch() or _win_has_touch()
        target = bool(has_touch)
    else:          # --- explicit override via checkbox ---
        target = bool(force)

    if target == self._touch_mode_active:                                # - no-op if already applied
        try:                                                             # - keep checkbox in sync if present
            self.tuchmode_.blockSignals(True)
            self.tuchmode_.setChecked(target)
            self.tuchmode_2.setChecked(target)
            self.tuchmode_.blockSignals(False)
        except Exception:
            pass
        return

    if QScroller is not None:                                            # - kinetic scrolling on common scrollables
        try:
            # robust gesture constant (varies across Qt bindings)
            try:
                gesture = QScroller.ScrollerGestureType.TouchGesture
            except Exception:
                gesture = getattr(QScroller, "TouchGesture",
                          getattr(QScroller, "LeftMouseButtonGesture", None))

            def _apply_scroller(w):
                try:
                    vw = w.viewport() if hasattr(w, "viewport") else w
                    if target and gesture is not None:
                        QScroller.grabGesture(vw, gesture)
                    else:
                        QScroller.ungrabGesture(vw)
                except Exception:
                    pass

            for w in self.findChildren(QAbstractScrollArea):
                _apply_scroller(w)
            for c in self.findChildren(QComboBox):
                try:
                    v = c.view()
                    if v:
                        _apply_scroller(v)
                except Exception:
                    pass

            # optional tuning (ignore failures)
            try:
                sc = QScroller.scroller(self)
                sp = sc.scrollerProperties()
                sp.setScrollMetric(sp.DecelerationFactor, 0.10)
                sp.setScrollMetric(sp.OvershootScrollDistanceFactor, 0.20)
                sp.setScrollMetric(sp.OvershootDragDistanceFactor, 0.10)
                sc.setScrollerProperties(sp)
            except Exception:
                pass
        except Exception:
            pass

    try:                                                                 # - row height & per-table padding
        if getattr(self, "vaultTable", None):
            vh = self.vaultTable.verticalHeader()
            if target:
                if vh and self._orig_row_height is None:
                    self._orig_row_height = vh.defaultSectionSize()
                if vh:
                    vh.setDefaultSectionSize(max((self._orig_row_height or 24), 40))
                self.vaultTable.setStyleSheet("QTableWidget::item{ padding:6px 8px; }")
            else:
                if vh and self._orig_row_height is not None:
                    vh.setDefaultSectionSize(self._orig_row_height)
                self.vaultTable.setStyleSheet("")
    except Exception:
        pass

    try:                                                                 # - accept/unaccept touch events
        self.setAttribute(Qt.WA_AcceptTouchEvents, bool(target))
    except Exception:
        pass

    # - commit state and (re)apply combined stylesheet
    self._touch_mode_active = bool(target)                                                       
    self._refresh_stylesheet()                                         

    try:                                                                # - sync checkbox without loops
        self.tuchmode_.blockSignals(True)
        self.tuchmode_.setChecked(self._touch_mode_active)
        self.tuchmode_2.setChecked(self._touch_mode_active)
        self.tuchmode_.blockSignals(False)
    except Exception:
        pass


def make_share_packet(self, *args, **kwargs):
    """Create a .kqshare (single) or .kqshareb (bundle) and SAVE TO FILE only (no QR preview)."""
    try:
        username = (self.currentUsername.text() if hasattr(self, "currentUsername") else "").strip()
        if not isinstance(self.userKey, (bytes, bytearray)) or len(self.userKey) != 32 or not username:
            QMessageBox.critical(self, self.tr("Share"), self.tr("Please log in first. (Missing 32-byte key or username)"))
            return

        table = getattr(self, "vaultTable", None)
        if table is None:
            QMessageBox.information(self, self.tr("Share"), self.tr("Vault table not available."))
            return

        sel_model = table.selectionModel()
        rows = sorted({ix.row() for ix in sel_model.selectedRows()}) if sel_model else []
        if not rows:
            if table.currentRow() >= 0:
                rows = [table.currentRow()]
            else:
                QMessageBox.information(self, self.tr("Share"), self.tr("Select one or more entries first."))
                return

        # Load vault + map selection
        try:
            try:
                all_entries = load_vault(username, self.userKey) or []
            except TypeError:
                all_entries = load_vault(username) or []
            idx_map = getattr(self, "current_entries_indices", None)
            to_global = lambda i: idx_map[i] if isinstance(idx_map, list) and 0 <= i < len(idx_map) else i
            selected = [dict(all_entries[to_global(r)]) for r in rows]
        except Exception:
            QMessageBox.critical(self, self.tr("Share"), self.tr("Could not read the selected entry/entries."))
            return

        # Safety: risky categories?
        allow_risky = bool(getattr(self, "user_remove_risk", True))
        for src in selected:
            cat = (src.get("category") or src.get("Category") or "").strip()
            if (not allow_risky) and self._is_risky_category(cat):
                msg = self.tr("Entries in category ") + f"“{cat or self.tr('Unknown')}”" + self.tr(" are blocked by your safety setting.")
                QMessageBox.warning(self, self.tr("Share blocked"), msg)
                return

        # Recipient Share ID (file-based)
        rid_path, _ = QFileDialog.getOpenFileName(
            self, self.tr("Open Recipient Share ID"), str(config_dir()), "Share ID (*.kqshareid *.json)"
        )
        if not rid_path:
            self.set_status_txt(self.tr("Share cancelled"))
            return

        recipient = json.loads(Path(rid_path).read_text(encoding="utf-8"))
        recipient_pub_x = recipient["pub_x25519"]
        recipient_id = recipient.get("id", "recipient")

        # Sender share keys — new API (username, user_key)
        pub_bundle, priv_x, priv_ed = ensure_share_keys(username, bytes(self.userKey))  # :contentReference[oaicite:2]{index=2}

        # Build encrypted envelopes
        envelopes = []
        for src in selected:
            entry = self._minimal_share_entry(src)
            pkt = make_share_packet(
                entry_json=entry,
                sender_priv_x25519=priv_x,
                sender_priv_ed25519=priv_ed,
                sender_pub_bundle=pub_bundle,
                recipient_pub_x25519_b64=recipient_pub_x,
                recipient_id=recipient_id,
                scope="entry",
                policy={"read_only": True, "import_as": "entry", "expires_at": None},
            )  # :contentReference[oaicite:3]{index=3}
            envelopes.append(pkt)

        # Save: single → .kqshare ; multi → .kqshareb (NO QR)
        if len(envelopes) == 1:
            e0 = selected[0]
            suggested = Path(config_dir()) / f"{(e0.get('Title') or e0.get('Name') or 'entry')[:80]}.kqshare"
            out_path, _ = QFileDialog.getSaveFileName(self, self.tr("Save Share Packet"), str(suggested), "Keyquorum Share (*.kqshare)")
            if not out_path:
                self.set_status_txt(self.tr("Share cancelled"))
                return
            Path(out_path).write_text(json.dumps(envelopes[0], indent=2), encoding="utf-8")
            self.set_status_txt(self.tr("Share: packet saved"))
            return

        bundle = {"kq_share_bundle": 1, "recipient_id": recipient_id, "entries": envelopes}
        suggested = Path(config_dir()) / f"bundle_{len(envelopes)}_items.kqshareb"
        out_path, _ = QFileDialog.getSaveFileName(self, self.tr("Save Share Bundle"), str(suggested), "Keyquorum Share Bundle (*.kqshareb)")
        if not out_path:
            self.set_status_txt(self.tr("Share cancelled"))
            return

        Path(out_path).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        self.set_status_txt(self.tr("Share: bundle with ") + f"{len(envelopes)}" + self.tr(" items saved"))

    except Exception as e:
        log.error(f"[SHARE] make_share_packet failed: {e}")
        msg = self.tr("Failed to make share packet:\n") + f"{e}"
        QMessageBox.critical(self, self.tr("Share"), msg)


def verify_sensitive_action(
    self,
    username: str,
    *,
    title: str = None,
    return_pw: bool = False,
    require_password: bool = False,   # <--- NEW
    twofa_check: bool = True,
    yubi_check: bool = True,
) -> Union[bool, str]:
    """
    Sensitive-action gate.

    If require_password=True:
        Always prompt + verify password (YubiKey can be extra).
        If return_pw=True -> returns the password on success.

    If require_password=False:
        May allow YubiKey-only success when available (fast confirm).
    """
    try:
        from qtpy.QtWidgets import QMessageBox
    except Exception:
        return False

    if title is None:
        title = self.tr("Confirm Action")

    username = (username or "").strip()
    if not username:
        return False

    # --- 0) TOTP enabled? ---
    totp_enabled = False
    try:
        from auth.tfa.twofactor import has_totp_enabled
        totp_enabled = bool(has_totp_enabled(username))
    except Exception:
        totp_enabled = False

    # --- 1) YubiKey quick gate (only allowed to short-circuit when password is NOT required) ---
    if yubi_check and hasattr(self, "_yk_quick_gate"):
        try:
            msg = self.tr(
                "For the security of this account '{user}',\n\n"
                "please touch your YubiKey to confirm this action."
            ).format(user=username)
            QMessageBox.information(self, title, msg)

            ok_yk = bool(self._yk_quick_gate(username))
            if not ok_yk:
                QMessageBox.warning(self, title, self.tr("YubiKey confirmation failed or was cancelled."))
                return False

            if not require_password:
                # YubiKey-only is acceptable for this action
                return "" if return_pw else True
            # else: continue (YubiKey becomes an extra layer)
        except Exception:
            # Fall back to password/2FA
            pass

    # --- 2) Password (REQUIRED for actions like enabling 2FA) ---
    pwd = self._prompt_account_password(username)
    if not pwd:
        return False

    try:
        if not validate_login(username, pwd):
            QMessageBox.critical(self, title, self.tr("Incorrect password."))
            return False
    except Exception:
        QMessageBox.critical(self, title, self.tr("Password verification is unavailable."))
        return False

    # --- 3) Optional 2FA check (if enabled) ---
    if twofa_check and totp_enabled:
        try:
            from auth.tfa.twofa_dialog import prompt_2fa_for_user
            msg = self.tr(
                "For the security of this account '{user}',\n\n"
                "please enter your 2FA verification code."
            ).format(user=username)

            QMessageBox.information(self, self.tr("Two-Factor Authentication"), msg)

            if not prompt_2fa_for_user(self, username):
                QMessageBox.warning(self, title, self.tr("Two-factor authentication was not completed."))
                return False
        except Exception:
            QMessageBox.critical(self, title, self.tr("Two-factor verification is unavailable."))
            return False

    return pwd if return_pw else True

# ==============================
# --- bridge - extension bridge callbacks expected by ExtensionBridge ---------
# ==============================


def import_share_packet(self, *args, **kwargs):
    """Open .kqshare / .kqshareb / .json; validate/decrypt, preview each, then modeless Add dialog(s)."""
    try:
        if not isinstance(self.userKey, (bytes, bytearray)) or len(self.userKey) != 32 or not self.currentUsername.text().strip():
            QMessageBox.warning(self, self.tr("Import Share"), self.tr("Please log in first. (Missing 32-byte key or username)"))
            return

        pkt_path, _ = QFileDialog.getOpenFileName(
            self, "Open Share Packet", str(config_dir()), "Keyquorum Share (*.kqshare *.kqshareb *.json)"
        )
        if not pkt_path:
            return

        try:
            packet = json.loads(Path(pkt_path).read_text(encoding="utf-8"))
        except Exception as e:
            QMessageBox.critical(self, self.tr("Import Share"), f"Invalid file (not JSON):\n{e}")
            return

        username = self._active_username() or ""
        pub_bundle, priv_x, _priv_ed = ensure_share_keys(username, bytes(self.userKey))  # :contentReference[oaicite:6]{index=6}

        def _mode(p):
            if isinstance(p, dict):
                if all(k in p for k in ("ver","sender","recipient","payload","wrapped_key")):
                    return "encrypted"
                if "kq_share_bundle" in p:
                    return "bundle"
                if "kq_share" in p and "entry" in p:
                    return "plain"
            return None

        mode = _mode(packet)

        # Bundle
        if mode == "bundle":
            entries = []
            for env in (packet.get("entries") or []):
                m = _mode(env)
                if m == "encrypted":
                    try:
                        e = verify_and_decrypt_share_packet(
                            {k: env[k] for k in ("ver","sender","recipient","payload","wrapped_key") if k in env},
                            priv_x
                        )
                        entries.append(e)
                    except Exception:
                        continue
                elif m == "plain":
                    ent = env.get("entry")
                    if isinstance(ent, dict):
                        entries.append(ent)

            if not entries:
                QMessageBox.information(self, self.tr("Import Share"), self.tr("No valid entries found in the bundle."))
                return

            imported = 0
            for e in entries:
                # SEQUENTIAL: pass sequential=True so the Add dialog is modal and blocking
                if self._preview_full_entry(e, sequential=True):
                    imported += 1
            msg = self.tr("Bundle processed. Imported ") + f"{imported}" + self.tr(" of ") + f"{len(entries)}" + self.tr(" item(s).")
            QMessageBox.information(self, self.tr("Import Share"), msg)
            return

        # Encrypted single
        if mode == "encrypted":
            try:
                env = {k: packet[k] for k in ("ver","sender","recipient","payload","wrapped_key") if k in packet}
                entry = verify_and_decrypt_share_packet(env, priv_x)  # :contentReference[oaicite:8]{index=8}
            except Exception as e:
                msg = self.tr("Could not decrypt this packet:\n") + f"{e}"
                QMessageBox.critical(self, self.tr("Import Share"), msg)
                return
            self._preview_full_entry(entry)
            return

        # Plain single
        if mode == "plain":
            entry = packet.get("entry")
            if not isinstance(entry, dict) or not entry:
                QMessageBox.critical(self, self.tr("Import Share"), self.tr("Packet had no valid 'entry' object."))
                return
            self._preview_full_entry(entry)
            return

        # Unknown
        QMessageBox.critical(self, self.tr("Import Share"), self.tr("Unrecognized share format."))
        return

    except Exception as e:
        log.error(f"[SHARE] import_share_packet failed: {e}")
        msg = self.tr("Import failed:\n") + f"{e}"
        QMessageBox.critical(self, self.tr("Import Share"), msg)


def export_csv(self, *args, **kwargs):
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


# ==============================
# --- auth export/import ----
# ==============================


def import_user_catalog_encrypted(self, user_root: str) -> None:
    """
    Import an encrypted catalog overlay file (.kqc.enc) using
    a user-supplied password, then reseal and reload.

    Called from CatalogEditorUserDialog._on_import_encrypted().
    """
    from qtpy.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox
    from vault_store.vault_store import _dec_backup_bytes

    username = (self.currentUsername.text() or "").strip()
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
        save_user_catalog(user_root, overlay, user_key=self.userKey)
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


def _show_cloud_risk_modal(self, current_wrap: bool) -> tuple[bool, bool, bool]:
    """
    One-time consent explaining cloud risks.
    Returns (accepted: bool, dont_ask_again: bool, enable_wrap: bool).
    """
    from features.url.main_url import SITE_HELP, PRIVACY_POLICY
    help_url = getattr(self, "SITE_HELP", SITE_HELP)
    privacy_url = PRIVACY_POLICY

    # Figure out YubiKey state for the active user (best-effort)
    uname = None
    try:
        uname = self._active_username()
    except Exception:
        try:
            uname = (self.currentUsername.text() or "").strip()
        except Exception:
            uname = None

    yk = {"enabled": False, "mode": "", "available": None}
    if uname:
        try:
            yk = self._yubi_wrap_status(uname)
        except Exception:
            pass

    # Normalize YubiKey state (defensive)
    yk_enabled = bool(yk.get("enabled", False))
    yk_available = (yk.get("available", None) is True)
    yk_mode = (yk.get("mode", "") or "").lower()

    # Build YubiKey hint line (accurate threat-model wording)
    if yk_enabled and ("wrap" in yk_mode or "key-wrap" in yk_mode):
        yubi_hint = (
            "• <b>YubiKey (Wrap mode): ON</b> — decrypting a your vault file would also require "
            "your physical YubiKey.<br>"
        )
    elif yk_enabled:
        yubi_hint = (
            "• <b>YubiKey:</b> enabled for app access. Note: this does <i>not</i> protect a "
            "stolen vault file from offline password-guessing unless Wrap mode is enabled.<br>"
        )
    elif yk_available:
        yubi_hint = (
            "• <b>YubiKey (Wrap mode, optional):</b> enable this in Settings to require your "
            "YubiKey to decrypt a stolen vault file.<br>"
        )
    else:
        yubi_hint = ""

    msg = QMessageBox(self)
    msg.setIcon(QMessageBox.Warning)
    msg.setWindowTitle(self.tr("Cloud storage — security warning"))
    msg.setTextFormat(Qt.RichText)
    msg.setTextInteractionFlags(Qt.TextBrowserInteraction)
    msg.setOpenExternalLinks(True)
    msg.setText(
        self.tr(
            "<b>Cloud storage increases security risk</b><br>"
            "This app is designed for local security. Storing your vault in a cloud-synced folder "
            "increases exposure. If an attacker obtains the file from your cloud, they can attempt "
            "offline password-guessing against it.<br><br>"
            "<b>Recommendations:</b><br>"
            "• <b>Secure your cloud account</b> (Microsoft/Google/Dropbox): use a strong, unique "
            "password and <b>enable 2FA</b> with your cloud provider.<br>"
            "• <b>Use a strong master password</b> for the vault. In-app 2FA protects access to the "
            "app, but it <i>does not</i> protect a leaked file from offline guessing.<br>"
            "{yubi_hint}"
            "• Consider enabling <b>extra cloud wrapping</b> for an additional encryption layer "
            "if you use cloud sync.<br><br>"
            "<a href='{help_url}'>Learn more</a> · "
            "<a href='{privacy_url}'>Privacy Policy</a>"
        ).format(
            yubi_hint=yubi_hint,
            help_url=help_url,
            privacy_url=privacy_url,
        )
    )

    # Remember flag
    dont_ask_box = QCheckBox(self.tr("Don't ask me again"))
    msg.setCheckBox(dont_ask_box)

    # Buttons
    proceed_btn = msg.addButton(self.tr("Proceed"), QMessageBox.AcceptRole)
    msg.addButton(self.tr("Cancel"), QMessageBox.RejectRole)

    msg.exec_() if hasattr(msg, "exec_") else msg.exec()
    accepted = (msg.clickedButton() is proceed_btn)

    if not accepted:
        return False, False, False

    # If extra cloud wrapping already ON, we're done
    if current_wrap:
        return True, bool(dont_ask_box.isChecked()), False

    # Ask to enable extra cloud wrapping now
    wrap_q = QMessageBox(self)
    wrap_q.setIcon(QMessageBox.Question)
    wrap_q.setWindowTitle(self.tr("Enable extra cloud wrapping?"))
    wrap_q.setText(
        self.tr(
            "Enable extra encryption wrapping for cloud storage?\n\n"
            "This adds an additional encryption layer specifically for cloud sync targets."
        )
    )

    wrap_yes = wrap_q.addButton(self.tr("Enable wrapping"), QMessageBox.AcceptRole)
    wrap_q.addButton(self.tr("Not now"), QMessageBox.RejectRole)

    wrap_q.exec_() if hasattr(wrap_q, "exec_") else wrap_q.exec()
    enable_wrap = (wrap_q.clickedButton() is wrap_yes)

    return True, bool(dont_ask_box.isChecked()), bool(enable_wrap)


def __init__backup_avisor(self, *args, **kwargs):
    from features.backup_advisor.ui_backup_bind import init__backup_avisor as _init__backup_avisor
    _init__backup_avisor(self)
    return 
    qs = QSettings("AJH Software", "Keyquorum Vault")

    # --- ensure advisor exists ---
    if not getattr(self, "backupAdvisor", None):
        # use the actual backup function you have
        self.backupAdvisor = BackupAdvisor(self, do_backup_callable=self.export_vault_with_password)

    # --- read prefs (with sane defaults) ---
    mode = str(qs.value("backup/remindMode", "both")).lower()
    if mode not in ("off", "changes", "logout", "both"):
        mode = "both"
    self._backup_remind_mode = mode

    try:
        thr = int(qs.value("backup/changesThreshold", 5) or 5)
    except Exception:
        thr = 5
    self.backupAdvisor.threshold = max(1, int(thr))

    # --- find widgets if they exist (run headless-safe) ---
    mode_combo = getattr(self, "backupModeCombo", None)
    thr_spin   = getattr(self, "backupThresholdSpin", None)
    reset_btn  = getattr(self, "resetBackupCounterBtn", None)

    # if there is no UI yet, we're done (advisor still works)
    if not mode_combo or not thr_spin:
        return

    # only wire once
    if getattr(self, "_wired_backup_ui", False):
        # still refresh values in case prefs changed
        idx_map = {"off":0, "changes":1, "logout":2, "both":3}
        mode_combo.setCurrentIndex(idx_map.get(mode, 3))
        thr_spin.setValue(int(thr))
        thr_spin.setEnabled(mode_combo.currentIndex() in (1, 3))
        return

    # --- populate & set current values ---
    if mode_combo.count() == 0:
        mode_combo.addItems(["Off", "After N changes", "On logout", "After N + logout"])
    idx_map = {"off":0, "changes":1, "logout":2, "both":3}
    mode_combo.setCurrentIndex(idx_map.get(mode, 3))

    thr_spin.setRange(1, 999)
    thr_spin.setValue(int(thr))
    thr_spin.setEnabled(mode_combo.currentIndex() in (1, 3))

    # --- handlers (save immediately on change) ---
    def on_mode_changed(ix: int):
        rev = {0:"off", 1:"changes", 2:"logout", 3:"both"}[ix]
        self._backup_remind_mode = rev
        qs.setValue("backup/remindMode", rev)
        # enable/disable threshold when needed
        thr_spin.setEnabled(ix in (1, 3))

    def on_thr_changed(v: int):
        v = max(1, int(v))
        self.backupAdvisor.threshold = v
        qs.setValue("backup/changesThreshold", v)

    # clean old connections (if any)
    try: mode_combo.currentIndexChanged.disconnect()
    except Exception: pass
    try: thr_spin.valueChanged.disconnect()
    except Exception: pass

    mode_combo.currentIndexChanged.connect(on_mode_changed)
    thr_spin.valueChanged.connect(on_thr_changed)

    # --- reset counter button (optional) ---
    if reset_btn:
        try: reset_btn.clicked.disconnect()
        except Exception: pass

        def on_reset_counter():
            if QMessageBox.question(
                self, "Reset backup counter",
                "Reset the pending change counter (and clear any snooze)?"
            ) == QMessageBox.Yes:
                if getattr(self, "backupAdvisor", None):
                    self.backupAdvisor.reset_change_counter(clear_snooze=True, clear_session_suppress=False)

        reset_btn.clicked.connect(on_reset_counter)

    self._wired_backup_ui = True


# --- pick a working backup function dynamically ---


def delete_audit_logs(self, *args, **kwargs) -> None:
    self.set_status_txt(self.tr("deleting audit"))
    self.reset_logout_timer()
    log.debug("[DEBUG] delete_audit_logs called")

    """
    Delete the current user's Phase-2 audit artifacts:
      - Encrypted primary audit file
      - Encrypted mirror audit file
      - Per-user lockout flag
      - Per-user tamper log
    Then re-initialize the audit with a fresh entry.
    """

    username = (self.currentUsername.text() or "").strip()
    if not username:
        log.debug("[delete_audit_logs] No user is currently logged in.")
        self.safe_messagebox_warning(self, "Delete Audit Logs", "No user is currently logged in.")
        return

    deleted: list[str] = []

    # Phase-2 canonical paths
    try:
        p_primary = Path(audit_file(username, ensure_dir=True))
    except Exception:
        # Fallback via secure_audit helper (string path)
        p_primary = Path(get_audit_file_path(username))

    p_mirror  = Path(audit_mirror_file(username, ensure_dir=True))
    p_lock    = Path(user_lock_flag_path(username, ensure_dir=True))
    p_tamper  = Path(tamper_log_file(username, ensure_parent=True))

    # Delete helper
    def _try_delete(p: Path):
        if p.exists():
            try:
                p.unlink()
                deleted.append(str(p))
            except Exception as e:
                log.error(f"[delete_audit_logs] Failed to delete {p}: {e}")
                self.safe_messagebox_warning(self, "Delete Failed", f"Could not delete {p.name}: {e}")
                raise

    # Remove files (non-fatal if some are missing)
    try:
        _try_delete(p_primary)
        _try_delete(p_mirror)
        _try_delete(p_lock)
        _try_delete(p_tamper)
    except Exception:
        return  # message already shown

    # ✅ Result
    if deleted:
        self.set_status_txt(self.tr("Done"))
        try:
            # Re-initialize audit with a first entry so a fresh file always exists
            msg = self.tr("{ok} Audit log (re)initialized after user deletion action.").format(ok=kql.i('ok'))
            log_event_encrypted(
                username,
                self.tr("audit_init"),
                msg
            )
        except Exception as e:
            # Not fatal, but tell the user the file couldn't be re-created
            msg = self.tr("Audit was deleted, but could not create a fresh log automatically:\n{err}").format(err=e)
            self.safe_messagebox_warning(
                self, self.tr("Audit Recreate"), msg)

        # Refresh the table to show the fresh entry
        try:
            self.load_audit_table()
        except Exception:
            # fallback: keep headers
            self.auditTable.clear()
            self.auditTable.setColumnCount(3)
            self.auditTable.setHorizontalHeaderLabels(["Timestamp", "Event", "Description"])

        msg = "✅ " + self.tr("Deleted files:\n") + "\n".join(deleted) + self.tr("\n\nA fresh audit log has been initialized.")
        QMessageBox.information(
            self,
            self.tr("Audit Logs Deleted"),
            msg
        )
    else:
        msg = self.tr("No audit logs were found for user ") + f"'{username}'."
        QMessageBox.information(
            self, self.tr("No Audit Logs Found"),
            msg
        )


def on_toggle_extra_cloud_wrap(self, *args, **kwargs):
    self.set_status_txt(self.tr("Cloud wrap: applying…"))

    username = self._active_username()
    if not username:
        QMessageBox.warning(self, self.tr("Extra Cloud Wrap"), self.tr("Please log in first."))
        return

    # Need a key and a configured engine/remote
    if not getattr(self, "userKey", None):
        QMessageBox.warning(self, self.tr("Extra Cloud Wrap"), self.tr("Unlock your vault first."))
        return

    prof = get_user_cloud(username) or {}
    if not prof.get("enabled") or not (prof.get("remote_path") or "").strip():
        QMessageBox.information(self, self.tr("Extra Cloud Wrap"), self.tr("Cloud sync is not configured yet."))
        return

    # Compute new state
    new_state = not bool(prof.get("cloud_wrap"))

    # ---- PAUSE automation to avoid races ----
    try:
        if getattr(self, "_auto_sync_timer", None):
            self._auto_sync_timer.stop()
        if getattr(self, "_vault_watcher", None):
            self._vault_watcher.blockSignals(True)
    except Exception:
        pass
    self._sync_guard = True

    try:
        # Bind engine to current user/profile (old wrap state)
        self._configure_sync_engine(username)
        if (self.sync_engine is None) or (not self.sync_engine.configured()):
            QMessageBox.information(self, self.tr("Extra Cloud Wrap"), self.tr("Choose a cloud vault file first."))
            return

        # A) Pull with OLD state so local is up to date
        res0 = str(self._cloud_sync_safe(self.userKey, interactive=True) or "")

        # Flip wrap flag in profile
        set_user_cloud(
            username,
            enable=bool(prof.get("enabled") or prof.get("sync_enable")),
            provider=prof.get("provider") or "localpath",
            path=prof.get("remote_path") or "",
            wrap=new_state,
        )

        # Rebind so engine sees NEW wrap state
        self._configure_sync_engine(username)

        # B) Push once with NEW state to migrate remote
        res1 = str(self._cloud_sync_safe(self.userKey, interactive=True) or "")

        # Refresh baseline if a pull/merge happened during either step
        try:
            def _rb(res: str): 
                s = (res or "").lower()
                return s.startswith("pulled") or ("conflict" in s) or ("download" in s)
            if _rb(res0) or _rb(res1):
                update_baseline(username=username, verify_after=False, who=self.tr("OnCloud Extra Wrap Settings Changed")) 
        except Exception:
            pass
        msg =  f"{self.tr('Enabled') if new_state else self.tr('Disabled')}.\n" + self.tr("Initial sync: ") + f"{res0}\n" + self.tr("Migration sync:") + f"{res1}"
        QMessageBox.information(
            self, self.tr("Extra Cloud Wrap"), msg)

    except Exception as e:
        msg = self.tr("Wrap toggle failed:") + f"\n{e}"
        QMessageBox.critical(self, self.tr("Extra Cloud Wrap"), msg)
    finally:
        # ---- RESUME automation ----
        try:
            if getattr(self, "_vault_watcher", None):
                self._vault_watcher.blockSignals(False)
        except Exception:
            pass
        self._sync_guard = False
        try:
            # Re-arm watcher and (debounced) auto-sync
            self._watch_local_vault()
            self._schedule_auto_sync()
        except Exception:
            pass
        self.set_status_txt(self.tr("Cloud wrap: done"))


# ==============================
# --- cloud login help -------
# ==============================


def get_credit_cards(self, *args, **kwargs) -> list[dict]:
    """
    Return a list of credit card dictionaries extracted from the vault table.
    Each dict contains: title, name (cardholder), number, exp, month, year, cvc.
    Cards are identified either by category 'Credit Cards' or by presence of card-like fields.
    """
    cards = []
    table = getattr(self, "vaultTable", None)
    if not table:
        return cards
    # Determine column indices by header names
    # Category column, if present, helps filter credit card rows
    if not hasattr(self, "_kq_cat_col"):
        self._kq_cat_col = self._find_col_by_labels({"category"})
    cat_col = getattr(self, "_kq_cat_col")
    # Names for card fields
    name_labels = {"name on card","name","cardholder","card holder","cardholder name"}
    number_labels = {"card number","number","card no","card no.","cardno","cc number"}
    # Recognize various labels for expiry date. Include common variations seen in the
    # Credit Cards category, such as "Expiry Date" (with space).  The labels must
    # exactly match the lowercased column header.
    expiry_labels = {
        "expiry",
        "exp",
        "exp.",
        "expires",
        "expiration",
        "exp date",
        "expiration date",
        "expiry date",
    }
    cvc_labels = {"cvv","cvc","security code","cvn","cvc2","cvv2","cid","csc"}
    # find column indexes using header matching
    def find_col(labels: set[str]) -> int:
        return self._find_col_by_labels(labels)
    name_col = find_col(name_labels)
    number_col = find_col(number_labels)
    expiry_col = find_col(expiry_labels)
    cvc_col = find_col(cvc_labels)
    # iterate through rows
    nrows = table.rowCount()
    for r in range(nrows):
        # If category column exists, filter by category
        if isinstance(cat_col, int) and cat_col >= 0:
            cat = self._get_text(r, cat_col).strip().lower()
            # If category not credit cards, skip
            if cat and "credit card" not in cat:
                continue
        # gather fields
        name_val = self._get_text(r, name_col).strip() if isinstance(name_col, int) and name_col >= 0 else ""
        number_val = self._get_text(r, number_col).strip() if isinstance(number_col, int) and number_col >= 0 else ""
        exp_val = self._get_text(r, expiry_col).strip() if isinstance(expiry_col, int) and expiry_col >= 0 else ""
        cvc_val = self._get_text(r, cvc_col).strip() if isinstance(cvc_col, int) and cvc_col >= 0 else ""
        # If we have at least card number or name+exp, consider row as card
        if not (number_val or exp_val or name_val):
            continue
        # Parse expiry into month/year
        month_val = ""
        year_val = ""
        if exp_val:
            # Normalize separators
            seps = ["/","-"," "]
            for sep in seps:
                if sep in exp_val:
                    parts = [p.strip() for p in exp_val.split(sep) if p.strip()]
                    if len(parts) >= 2:
                        month_val, year_val = parts[0], parts[1]
                        break
            # If month/year still empty and expiry string length >=4, attempt to guess
            if not month_val and not year_val:
                s = exp_val.strip()
                if len(s) in (4,6):
                    # assume MMYY or MMYYYY
                    if len(s) == 4:
                        month_val, year_val = s[:2], s[2:]
                    else:
                        month_val, year_val = s[:2], s[2:]
        # Title: prefer name on card if present, else derive from number
        title = name_val or ((number_val[-4:] and f"Card …{number_val[-4:]}") if number_val else "Card")
        cards.append({
            "title": title,
            "name": name_val,
            "number": number_val,
            "exp": exp_val,
            "month": month_val,
            "year": year_val,
            "cvc": cvc_val,
        })
    return cards

# 3) ---------- main API used by the bridge ----------

def load_audit_table(self, *args, **kwargs) -> None:
    self.set_status_txt(self.tr("Loading Audit to Table"))
    log.debug(str("[DEBUG] load_audit_table called"))

    """
    Populate the audit table with the user's audit log history.

    Handles secure audit entries, including detecting tampered entries.
    """
    self.reset_logout_timer()
    username = self.currentUsername.text()
    if not username:
        return
    
    # Read encrypted audit log entries (post-auth)
    events = read_audit_log(username)
    # Attempt to read pre-auth events and merge
    merged = []  # type: list[dict]
    try:
        from security.audit_v2 import preauth_read_events  
        from app.paths import config_dir as _cfgdir  
        pre_events, _ok_chain = preauth_read_events(str(_cfgdir(username, ensure_parent=False)), username)
    except Exception:
        pre_events, _ok_chain = [], True
    # Convert pre-auth events into unified format
    for e in pre_events:
        desc = ""
        details = e.get("d", {})
        if isinstance(details, dict):
            parts = []
            for k, v in details.items():
                # Flatten dict to simple key=value pairs
                try:
                    parts.append(f"{k}={v}")
                except Exception:
                    parts.append(str(v))
            desc = "; ".join(parts)
        else:
            desc = str(details)
        merged.append({
            "timestamp": e.get("ts", ""),
            "event": e.get("event", ""),
            "description": desc,
            "_epoch": e.get("ts", ""),
        })
    # Append encrypted events
    for e in events:
        # unify: read_audit_log returns dicts with timestamp/event/description
        ts = e.get("timestamp", "")
        merged.append({
            "timestamp": ts,
            "event": e.get("event", ""),
            "description": e.get("description", ""),
            "_epoch": ts,
        })
    # Sort by timestamp descending; use string comparison or convert isoformat
    try:
        from datetime import datetime
        for item in merged:
            iso = item["timestamp"]
            try:
                # handle Z suffix
                if iso.endswith("Z"):
                    dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
                else:
                    dt = datetime.fromisoformat(iso)
                item["_t"] = dt.timestamp()
            except Exception:
                item["_t"] = 0.0
        merged.sort(key=lambda x: x.get("_t", 0.0), reverse=True)
    except Exception:
        merged.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    # Populate table
    self.reset_logout_timer()
    self.auditTable.clear()
    self.auditTable.setColumnCount(3)
    self.auditTable.setHorizontalHeaderLabels(["Timestamp", "Event", "Description"])
    self.auditTable.setRowCount(len(merged))
    for row, entry in enumerate(merged):
        self.reset_logout_timer()
        self.auditTable.setItem(row, 0, QTableWidgetItem(entry.get("timestamp", "")))
        self.auditTable.setItem(row, 1, QTableWidgetItem(entry.get("event", "")))
        self.auditTable.setItem(row, 2, QTableWidgetItem(entry.get("description", "")))



def quick_share_qr(self, *args, **kwargs):
    """
    Fileless, encrypted quick share to *my* Share ID.
    - Uses the currently selected entry (single).
    - No file saved; just shows a QR (may be multi-page if large).
    - Adds policy.expires_at = now+5min (soft; future-enforceable).
    """
    try:
        username = (self.currentUsername.text() if hasattr(self, "currentUsername") else "").strip()
        if not isinstance(self.userKey, (bytes, bytearray)) or len(self.userKey) != 32 or not username:
            QMessageBox.warning(self, self.tr("Quick Share"), self.tr("Please log in first. (Missing 32-byte key or username)"))
            return

        # Pick the source entry (single)
        table = getattr(self, "vaultTable", None)
        if table is None or table.currentRow() < 0:
            QMessageBox.information(self, self.tr("Quick Share"), self.tr("Select an entry to share first."))
            return

        # Load vault + map current row
        try:
            try:
                all_entries = load_vault(username, self.userKey) or []
            except TypeError:
                all_entries = load_vault(username) or []
            idx_map = getattr(self, "current_entries_indices", None)
            row = table.currentRow()
            gi = idx_map[row] if isinstance(idx_map, list) and 0 <= row < len(idx_map) else row
            src = dict(all_entries[gi])
        except Exception:
            QMessageBox.critical(self, self.tr("Quick Share"), self.tr("Could not read the selected entry."))
            return

        # Optional safety gate (lightweight): confirm
        if QMessageBox.question(
            self, "Quick Share",
            "Show an encrypted QR for this entry?\nIt will be visible on screen only.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
        ) != QMessageBox.Yes:
            return

        # Block risky categories
        allow_risky = bool(getattr(self, "user_remove_risk", True))
        cat = (src.get("category") or src.get("Category") or "").strip()
        if (not allow_risky) and self._is_risky_category(cat):
            QMessageBox.warning(self, "Quick Share",
                                f"Entries in category “{cat or 'Unknown'}” are blocked by your safety setting.")
            return

        # Build minimal payload to keep QR small
        entry = self._minimal_share_entry(src)

        # Ensure *my* share keys (new API: username + 32-byte key)
        pub_bundle, priv_x, priv_ed = ensure_share_keys(username, bytes(self.userKey))

        # Use *my own* public key as recipient (no selection needed)
        recipient_pub_x = pub_bundle.get("pub_x25519")
        recipient_id = f"{username}@this-device"

        # Soft expiry 5 minutes from now (not enforced yet; future-ready)
        expires_at = (dt.datetime.utcnow() + dt.timedelta(minutes=5)).replace(microsecond=0).isoformat() + "Z"

        packet = make_share_packet(
            entry_json=entry,
            sender_priv_x25519=priv_x,
            sender_priv_ed25519=priv_ed,
            sender_pub_bundle=pub_bundle,
            recipient_pub_x25519_b64=recipient_pub_x,
            recipient_id=recipient_id,
            scope="entry",
            policy={"read_only": True, "import_as": "entry", "expires_at": expires_at},
        )

        # Show *on screen only* (no file saved)
        # (Your QR tool will auto-split to multiple pages if needed.)
        show_qr_for_object(self.tr("Share Packet (scan/close to finish)"), {"type": "kqshare", **packet}, self)

        self.set_status_txt(self.tr("Quick Share shown."))
    except Exception as e:
        try:
            log.error("[SHARE] quick_share_qr failed: %s", e)
        except Exception:
            pass
        QMessageBox.critical(self, self.tr("Quick Share"), f"Failed to show QR:\n{e}")

# --- JSON preview + Category + modeless Add form ----------------------------


def _cloud_sync_safe(self, user_key: bytes, interactive: bool = True) -> str:
    """
    Safely perform a cloud sync if the engine exists and is configured.
    - Never raises on missing engine/config
    - Logs the outcome and updates the status text
    - Returns: 'pushed', 'pulled', 'synced', 'noop', 'blocked-owner', 'no-engine', 'no-user', or 'error'
    """
    def _status(msg: str):
        try:
            self.set_status_txt(self.tr(msg))
        except Exception:
            pass

    try:
        username = None
        if hasattr(self, "_logged_in_username"):
            username = self._active_username()
        # Fallbacks
        if not username and hasattr(self, "currentUsername") and self.currentUsername:
            username = (self.currentUsername.text() or "").strip()
        if not username and getattr(self, "_current_user", None):
            username = str(self._current_user or "").strip()
        if not username and getattr(self, "username", None):
            username = str(self.username or "").strip()

        if not username:
            log.info("[CLOUD] sync skipped — no user")
            _status("Cloud sync: no user")
            return "no-user"

        # Ensure engine is created/bound for this user
        if hasattr(self, "_configure_sync_engine"):
            self._configure_sync_engine(username)

        eng = getattr(self, "sync_engine", None)
        if not eng or not hasattr(eng, "sync_now"):
            log.info(f"[CLOUD] sync skipped — no engine for user {username}")
            _status("Cloud sync: no engine configured")
            return "no-engine"

        # Do the sync
        result = str(eng.sync_now(user_key, interactive=interactive) or "noop")

        # Normalise 'synced' vs 'noop'
        if result == "synced":
            norm = "synced"
        elif result == "noop":
            norm = "noop"
        else:
            norm = result

        # Log + status text (no popups)
        if norm == "pushed":
            log.info("[CLOUD] sync result: pushed")
            _status("Cloud sync: uploaded (pushed)")
        elif norm == "pulled":
            log.info("[CLOUD] sync result: pulled")
            _status("Cloud sync: downloaded (pulled)")
        elif norm in ("synced", "noop"):
            log.info(f"[CLOUD] sync result: {norm}")
            _status("Cloud sync: up to date")
        elif norm == "blocked-owner":
            log.info("[CLOUD] sync result: blocked-owner")
            _status("Cloud sync: blocked (owner mismatch)")
        else:
            # Any custom/engine-specific label falls back here
            log.info(f"[CLOUD] sync result: {norm}")
            _status(f"Cloud sync: {norm}")

        return norm

    except Exception as e:
        log.error(f"[CLOUD] sync error: {e}")
        try:
            self.set_status_txt(
                self.tr("Cloud sync failed: {err}").format(err=e)
            )
        except Exception:
            pass
        return "error"



def quick_import_from_qr(self, *args, **kwargs):
    """Scan a share QR (camera or image, single or multi-page) and open the prefilled Add dialog for a single item."""
    try:
        if not isinstance(self.userKey, (bytes, bytearray)) or len(self.userKey) != 32 or not self.currentUsername.text().strip():
            QMessageBox.warning(self, self.tr("Quick Import"), self.tr("Please log in first. (Missing 32-byte key or username)"))
            return

        # Ask camera or file
        use_camera = False
        camera_available = False
        try:
            import cv2  
            camera_available = cv2 is not None
        except Exception:
            camera_available = False

        if camera_available:
            mb = QMessageBox(self)
            mb.setWindowTitle(self.tr("Quick Import"))
            mb.setText(self.tr("How would you like to scan the QR?"))
            btn_cam  = mb.addButton(self.tr("Use Camera"), QMessageBox.AcceptRole)
            btn_file = mb.addButton(self.tr("Pick Image File"), QMessageBox.ActionRole)
            mb.addButton(QMessageBox.Cancel)
            mb.exec()
            clicked = mb.clickedButton()
            if clicked is None or clicked == mb.button(QMessageBox.Cancel):
                return
            use_camera = (clicked == btn_cam)

        # NEW: scan single or multi-page and auto-assemble
        from features.qr.qr_tools import scan_qr_any
        obj = scan_qr_any(parent=self, use_camera=use_camera)
        if not obj:
            return

        username = self._active_username() or ""
        pub_bundle, priv_x, _priv_ed = ensure_share_keys(username, bytes(self.userKey))

        mode = self._packet_mode(obj)

        # Bundle QR should reconstruct to a full packet here; still guard:
        if mode == "bundle" or (isinstance(obj, dict) and str(obj.get("kq_share")) in ("1", 1) and isinstance(obj.get("entries"), list)):
            QMessageBox.information(self, self.tr("Quick Import"), self.tr("This QR contains multiple items.\nUse “Import Share Packet…” instead."))
            return

        if mode == "encrypted":
            try:
                my_pub_x_b64 = pub_bundle.get("pub_x25519", "")
                pkt_recipient_b64 = str(obj.get("recipient", {}).get("pub_x25519", ""))
                if my_pub_x_b64 and pkt_recipient_b64 and my_pub_x_b64 != pkt_recipient_b64:
                    intended_id = obj.get("recipient", {}).get("id") or "(unknown)"
                    msg = self.tr("This share packet is not addressed to your account.\n\nIntended recipient: ") + f"{intended_id}\n\n" + self.tr("Switch user or ask the sender to re-share to your current Share ID.")
                    QMessageBox.warning(
                        self, self.tr("Wrong recipient"), msg)
                    return
            except Exception:
                pass

            entry = verify_and_decrypt_share_packet(
                {k: obj[k] for k in ("ver","sender","recipient","payload","wrapped_key") if k in obj}, priv_x
            )
        else:
            ok, why = self._validate_share_packet(obj)
            if not ok:
                msg = self.tr("QR data is not a valid share packet:\n") + f"{why}"
                QMessageBox.critical(self, self.tr("Quick Import"), msg)
                return
            entry = obj.get("entry")
            if not isinstance(entry, dict):
                QMessageBox.information(self, self.tr("Quick Import"), self.tr("This QR did not contain a single share item."))
                return

        self._preview_full_entry(entry)

    except Exception as e:
        msg = self.tr("QR import failed:\n") + f"{e}"
        QMessageBox.critical(self, self.tr("Quick Import"), msg)

# ==============================
# --- Make share packet -------------
# ==============================


def _provider_exe_path(self, *args, **kwargs) -> str | None:
    """
    Locate the Keyquorum Passkey helper EXE.

    We look in:
    - The directory of the running EXE (installed build)
    - A 'passkeys' subfolder next to the EXE
    - Portable root and common subfolders (App/bin/Passkeys)
    - The directory of this script (dev mode)
    """
    from pathlib import Path
    import sys

    exe_names = [
        "Keyquorum.PasskeyManager.exe",   # your C# project
        "keyquorum-passkey-provider.exe", # future alt name
    ]

    bases: list[Path] = []

    # 1) Installed / frozen EXE folder
    try:
        exe_dir = Path(sys.executable).resolve().parent
        bases.append(exe_dir)
        bases.append(exe_dir / "passkeys")
    except Exception:
        pass

    # 2) Portable root (if active)
    try:
        import app.paths as _paths
        if _paths.is_portable_mode():
            pr = _paths.portable_root()
            bases.extend([
                pr,
                pr / "App",
                pr / "app",
                pr / "bin",
                pr / "Passkeys",
            ])
    except Exception:
        pass

    # 3) Dev mode – location of main.py
    try:
        here = Path(__file__).resolve().parent
        bases.append(here)
        bases.append(here.parent)
    except Exception:
        pass

    seen: set[str] = set()
    for base in bases:
        try:
            if not base:
                continue
            b = Path(base)
            key = str(b).lower()
            if key in seen:
                continue
            seen.add(key)

            for name in exe_names:
                p = b / name
                if p.is_file():
                    try:
                        log.info(f"[PASSKEY] helper exe found at {p}")
                    except Exception:
                        pass
                    return str(p)
        except Exception:
            continue

    try:
        log.info("[PASSKEY] helper exe not found in any candidate paths")
    except Exception:
        pass
    return None



def on_stop_cloud_sync_keep_local(self, *args, **kwargs):
    # Announce that the sync stop state is being saved (literal for translation)
    self.set_status_txt(self.tr("Saving Cloud sync Stopped"))
    username = self._active_username()
    if not username:
        QMessageBox.information(
            self,
            self.tr("Stop Cloud Sync"),
            self.tr("Please log in first."),
        )
        return

    prof = get_user_cloud(username) or {}
    cloud_path = (prof.get("remote_path") or "").strip()
    if not cloud_path:
        QMessageBox.information(
            self,
            self.tr("Stop Cloud Sync"),
            self.tr("Cloud location not configured."),
        )
        return

    # If profile stores a folder, infer the probable filename to copy
    src_file = None
    if os.path.isdir(cloud_path):
        # use the same filename as local vault
        local = str(vault_file(username, ensure_parent=True))
        src_candidate = os.path.join(cloud_path, os.path.basename(local))
        if os.path.isfile(src_candidate):
            src_file = src_candidate
    elif os.path.isfile(cloud_path):
        src_file = cloud_path

    if not src_file or not os.path.isfile(src_file):
        QMessageBox.information(
            self,
            self.tr("Stop Cloud Sync"),
            self.tr("Cloud file not found in the configured location."),
        )
        return

    # Choose a local destination
    home = os.path.expanduser("~")
    dst, _ = QFileDialog.getSaveFileName(
        self, "Save a local copy of your vault",
        os.path.join(home, os.path.basename(src_file)),
        "Keyquorum Vault (*.kqvault);;All files (*.*)"
    )
    if not dst:
        return

    try:
        #shutil.copy2(src_file, dst)
        #self.currentVaultPath = dst
        tmp_local = str(vault_file(username, ensure_parent=True))
        self._restore_local_from_remote(username, src_file)  # write to working local
        copy2(tmp_local, dst)  # now copy the unwrapped working file to the user's chosen path
        # disable cloud
        set_user_cloud(
            username,
            enable=False,
            provider=prof.get("provider") or "localpath",
            path=prof.get("remote_path") or "",
            wrap=bool(prof.get("cloud_wrap")),
        )
        QMessageBox.information(
            self,
            self.tr("Stop Cloud Sync"),
            self.tr("Cloud sync disabled. You're now using a local copy."),
        )
    except Exception as e:
        QMessageBox.critical(
            self,
            self.tr("Stop Cloud Sync"),
            self.tr("Failed: {err}").format(err=e),
        )
    # Use plain literal for 'Done'
    self.set_status_txt(self.tr("Done"))



def load_profile_picture(self, *, force: bool = False) -> None:
    log.info("load profile picture")
    try:
        lbl_a = getattr(self, "profilePicLabel", None)
        lbl_b = getattr(self, "profilePicLabel1", None)
        # username
        try:
            raw_user = (self._current_username_text() or "").strip()
        except Exception:
            try:
                raw_user = (self.currentUsername.text() or "").strip()
            except Exception:
                raw_user = ""

        # zoom
        try:
            zoom = float(get_user_setting(raw_user, "zoom_factor", 1.0) or 1.0)
        except Exception:
            zoom = 1.0

        # canonical username
        if raw_user:
            try:
                username = self._canonical_ci(raw_user)
            except Exception:
                try:
                    username = _canonical_username_ci(raw_user) or raw_user
                except Exception:
                    username = raw_user
        else:
            username = ""

        # choose image path (user image first)
        img_path = None
        if username:
            try:
                p = self._profile_image_path(username)  # should return a string
                if p and Path(p).exists():
                    img_path = p
            except Exception:
                pass

        # fallback to default_user.png -> icon.png
        if not img_path:
            try:
                p = icon_file("default_user.png")      # resources/icons/default_user.png
                img_path = str(p if p else "")
            except Exception:
                img_path = ""
            if not img_path or not Path(img_path).exists():
                try:
                    if hasattr(self, "res"):
                        img_path = str(icon_file("default_user.png"))
                except Exception:
                    img_path = "resources/icons/default_user.png"  # last-ditch

        # avoid redundant redraws
        w_a = lbl_a.width() if lbl_a else 0
        h_a = lbl_a.height() if lbl_a else 0
        w_b = lbl_b.width() if lbl_b else 0
        h_b = lbl_b.height() if lbl_b else 0
        key = (username, img_path, zoom, w_a, h_a, w_b, h_b)
        if not force and getattr(self, "_last_profile_pic_key", None) == key:
            return
        self._last_profile_pic_key = key

        if lbl_a:
            self.set_rounded_profile_picture(lbl_a, img_path, zoom)
        if lbl_b:
            QTimer.singleShot(0, lambda p=img_path, l=lbl_b, z=zoom: self.set_rounded_profile_picture(l, p, z))

    except Exception as e:
        log.error(f"[profile-pic] load failed: {e}")


def prompt_manual_kit_entries(self, *, defaults: dict | None = None) -> dict:
    """
    Returns:
      {
        "ok": bool,
        "recovery_key": str|None,
        "recovery_backup_codes": list[str],
        "twofa_backup_codes": list[str],
        "totp_secret": str|None,
        "totp_uri": str|None
      }
    Only used for Emergency Kit rendering; does NOT save to disk.
    """
    dfl = defaults or {}
    rec_key_d = dfl.get("recovery_key", "")
    rec_codes_d = "\n".join(dfl.get("recovery_backup_codes", []))
    twofa_codes_d = "\n".join(dfl.get("twofa_backup_codes", []))
    totp_secret_d = dfl.get("totp_secret", "")
    totp_uri_d = dfl.get("totp_uri", "")

    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Add items manually to your Emergency Kit"))
    dlg.setModal(True)
    dlg.setMinimumWidth(520)
    lay = QVBoxLayout(dlg)

    # Recovery key
    lay.addWidget(QLabel(self.tr("Recovery Key (optional):")))
    rec_key = QLineEdit(); rec_key.setText(rec_key_d); lay.addWidget(rec_key)

    # Recovery backup codes (one per line)
    lay.addWidget(QLabel(self.tr("Recovery Backup Codes (one per line):")))
    rec_codes = QTextEdit(); rec_codes.setPlainText(rec_codes_d); lay.addWidget(rec_codes)

    # 2FA backup codes (one per line)
    lay.addWidget(QLabel(self.tr("2FA Backup Codes (one per line):")))
    twofa_codes = QTextEdit(); twofa_codes.setPlainText(twofa_codes_d); lay.addWidget(twofa_codes)

    # TOTP manual
    lay.addWidget(QLabel(self.tr("TOTP Manual Fields (optional — use either):")))
    totp_secret = QLineEdit(); totp_secret.setPlaceholderText(self.tr("BASE32SECRET (e.g., JBSWY3DPEHPK3PXP)"))
    totp_secret.setText(totp_secret_d); lay.addWidget(totp_secret)
    totp_uri = QLineEdit(); totp_uri.setPlaceholderText(self.tr("otpauth://totp/Issuer:User?...")) 
    totp_uri.setText(totp_uri_d); lay.addWidget(totp_uri)

    confirm_cb = QCheckBox(self.tr("I have double-checked the entries above (typos can lock me out)."))
    lay.addWidget(confirm_cb)

    row = QHBoxLayout()
    btn_ok = QPushButton(self.tr("Use These"))
    btn_cancel = QPushButton(self.tr("Cancel"))
    row.addWidget(btn_ok); row.addWidget(btn_cancel)
    lay.addLayout(row)

    def _use():
        if not confirm_cb.isChecked():
            QMessageBox.warning(dlg, self.tr("Please confirm"), self.tr("Tick the checkbox to confirm you've double-checked the entries."))
            return
        dlg.accept()

    btn_ok.clicked.connect(_use)
    btn_cancel.clicked.connect(dlg.reject)

    if dlg.exec() != QDialog.DialogCode.Accepted:
        return {"ok": False, "recovery_key": None, "recovery_backup_codes": [], "twofa_backup_codes": [], "totp_secret": None, "totp_uri": None}

    # Normalize lists (strip empties/spaces)
    def _split_lines(widget: QTextEdit) -> list[str]:
        return [ln.strip() for ln in widget.toPlainText().splitlines() if ln.strip()]
    return {
        "ok": True,
        "recovery_key": rec_key.text().strip() or None,
        "recovery_backup_codes": _split_lines(rec_codes),
        "twofa_backup_codes": _split_lines(twofa_codes),
        "totp_secret": totp_secret.text().strip() or None,
        "totp_uri": totp_uri.text().strip() or None,
    }


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


# ==============================
# --- QR: show for selected row / Wi-Fi helper --------------------------------


def save_profile_from_bridge(self, payload: dict) -> bool:
    if not self._require_unlocked(): 
        return
    p = payload or {}

    def pick(*keys):
        for k in keys:
            v = p.get(k)
            if v not in (None, ""):
                return str(v)
        return ""

    # honorific / title
    honorific   = pick("honorific", "honorificPrefix", "honorific-prefix",
                       "nameTitle", "salutation", "prefix", "courtesyTitle")
    # 
    if honorific and (len(honorific) > 12 or " — " in honorific or " – " in honorific or " " in honorific.strip()):
        # honorifics are usually short tokens (Mr, Ms, Dr, Prof, etc.)
        honorific = honorific.split()[0] if len(honorific.split()) == 1 else ""
    
    # names
    forename    = pick("forename", "firstName", "firstname", "first_name", "givenName", "given_name")
    middlename  = pick("middle", "middleName", "middlename", "additionalName", "additional-name")
    surname     = pick("surname", "lastName", "lastname", "last_name", "familyName", "family_name")
    # contact
    email       = pick("email", "emailAddress", "email_address")
    phone       = pick("phone", "tel", "phoneNumber", "phone_number", "mobile", "mobilePhone")
    # address
    address1    = pick("address1", "addressLine1", "address_line1", "street1", "streetAddress", "address-line1")
    address2    = pick("address2", "addressLine2", "address_line2", "street2", "address-line2")
    city        = pick("city", "locality", "town", "addressLevel2", "address-level2")
    region      = pick("region", "state", "county", "province", "addressRegion", "addressLevel1", "address-level1",
                       "stateProvinceRegion")
    postal      = pick("postal", "postalCode", "postcode", "zip", "zipCode", "postal-code")
    country     = pick("country", "countryName", "addressCountry")

    # Row caption: DO NOT use p["title"] (that’s the honorific).
    record_title = (
        p.get("entryTitle") or p.get("recordTitle")
        or " ".join(x for x in [honorific, forename, middlename, surname] if x)
        or (email or phone or "Profile")
    )

    try:
        new_entry = {
            "category": "Webfill",
            "Title": record_title,
            WEBFILL_COL["HONORIFIC"]:  honorific,
            WEBFILL_COL["FORENAME"]:   forename,
            WEBFILL_COL["MIDDLENAME"]: middlename,
            WEBFILL_COL["SURNAME"]:    surname,
            WEBFILL_COL["EMAIL"]:      email,
            WEBFILL_COL["PHONE"]:      phone,
            WEBFILL_COL["ADDR1"]:      address1,
            WEBFILL_COL["ADDR2"]:      address2,
            WEBFILL_COL["CITY"]:       city,
            WEBFILL_COL["REGION"]:     region,
            WEBFILL_COL["POSTAL"]:     postal,
            WEBFILL_COL["COUNTRY"]:    country,
        }
        add_vault_entry(self.currentUsername.text(), self.userKey, new_entry)
        self._on_any_entry_changed()

        # refresh UI
        try:
            QTimer.singleShot(0, lambda: (self.categorySelector_2.setCurrentText("Webfill"),
                                                 self.load_vault_table()))
            QTimer.singleShot(0, lambda: update_baseline(username=self.currentUsername.text(), verify_after=False, who=f"Save from bridge -> New/Updated"))
        except Exception:
            pass
        return True
    except Exception as e:
        log.error(f"{kql.i('err')} [BRIDGE] save_profile_from_bridge failed:", e)
        return False

# --- save a Credit Card coming from the extension -----------------


def quick_export_scan_only(self, *args, **kwargs):
    """
    Create an encrypted share **for a chosen recipient** and show QR on screen only (no file).
    Use when the other device/app will scan immediately.
    """
    try:
        username = (self.currentUsername.text() if hasattr(self, "currentUsername") else "").strip()
        if not isinstance(self.userKey, (bytes, bytearray)) or len(self.userKey) != 32 or not username:
            QMessageBox.warning(self, self.tr("Quick Export (Scan)"), self.tr("Please log in first. (Missing 32-byte key or username)"))
            return

        table = getattr(self, "vaultTable", None)
        if table is None or table.currentRow() < 0:
            QMessageBox.information(self, self.tr("Quick Export (Scan)"), self.tr("Select an entry to share first."))
            return

        # Only single-item quick QR (keep it small/predictable)
        try:
            try:
                all_entries = load_vault(username, self.userKey) or []
            except TypeError:
                all_entries = load_vault(username) or []
            idx_map = getattr(self, "current_entries_indices", None)
            row = table.currentRow()
            gi = idx_map[row] if isinstance(idx_map, list) and 0 <= row < len(idx_map) else row
            src = dict(all_entries[gi])
        except Exception:
            QMessageBox.critical(self, self.tr("Quick Export (Scan)"), self.tr("Could not read the selected entry."))
            return

        allow_risky = bool(getattr(self, "user_remove_risk", True))
        cat = (src.get("category") or src.get("Category") or "").strip()
        if (not allow_risky) and self._is_risky_category(cat):
            msg = self.tr("Entries in category ") + f"“{cat or self.tr('Unknown')}”" + self.tr(" are blocked by your safety setting.")
            QMessageBox.warning(self, self.tr("Quick Export (Scan)"), msg)
            return

        # Pick Recipient Share ID (the scanning device/user)
        rid_path, _ = QFileDialog.getOpenFileName(
            self, self.tr("Open Recipient Share ID"), str(config_dir()), "Share ID (*.kqshareid *.json)"
        )
        if not rid_path:
            return
        recipient = json.loads(Path(rid_path).read_text(encoding="utf-8"))
        recipient_pub_x = recipient["pub_x25519"]
        recipient_id = recipient.get("id", "recipient")

        # Sender keys
        pub_bundle, priv_x, priv_ed = ensure_share_keys(username, bytes(self.userKey))  # :contentReference[oaicite:4]{index=4}

        # Minimal payload to keep QR size down
        entry = self._minimal_share_entry(src)

        # Optional expiry hint (soft)
        expires_at = None  # keep simple for now

        packet = make_share_packet(
            entry_json=entry,
            sender_priv_x25519=priv_x,
            sender_priv_ed25519=priv_ed,
            sender_pub_bundle=pub_bundle,
            recipient_pub_x25519_b64=recipient_pub_x,
            recipient_id=recipient_id,
            scope="entry",
            policy={"read_only": True, "import_as": "entry", "expires_at": expires_at},
        )  # :contentReference[oaicite:5]{index=5}

        # Show on-screen QR (may paginate if large; that’s OK)
        show_qr_for_object(self.tr("Share Packet (scan to import)"), {"type": "kqshare", **packet}, self)
        self.set_status_txt(self.tr("Quick Export (Scan): QR shown"))

    except Exception as e:
        msg = self.tr("Failed to show QR:\n") + f"{e}"
        QMessageBox.critical(self, self.tr("Quick Export (Scan)"), msg)


def set_rounded_profile_picture(self, label: QLabel, image_path: str, zoom_factor: float = 1.0) -> None:
    log.debug(f"[SET_ROUND_PIC] Zoom Set To={zoom_factor}")
    self.reset_logout_timer()   
    pixmap = QPixmap(image_path)
    if pixmap.isNull():
        pixmap = None
        if icon_file("default_user.png"):
            pixmap = QPixmap(icon_file("default_user.png"))
        if pixmap.isNull():
            label.setPixmap(QPixmap())
            label.setText(self.tr("No Image"))
            return
    # self.zoom_factor, 1.0
    size = max(48, min(label.width(), label.height()))
    crop_size = int(min(pixmap.width(), pixmap.height()) / max(zoom_factor, 1.0))  # 
    x = max(0, (pixmap.width() - crop_size) // 2)  #2
    y = max(0, (pixmap.height() - crop_size) // 2)  #2
    cropped = pixmap.copy(x, y, crop_size, crop_size)

    scaled = cropped.scaled(
        size, size,
        Qt.AspectRatioMode.KeepAspectRatioByExpanding,
        Qt.TransformationMode.SmoothTransformation
    )

    rounded = QPixmap(size, size)
    rounded.fill(Qt.GlobalColor.transparent)

    painter = QPainter(rounded)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    path = QPainterPath()
    margin = 1
    path.addEllipse(margin, margin, size - 2*margin, size - 2*margin)
    painter.setClipPath(path)
    painter.drawPixmap(0, 0, scaled)
    painter.end()

    label.setPixmap(rounded)
    label.setText("")

    # optional glow (keep if you like)
    try:
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(50)
        shadow.setOffset(0, 0)
        label.setGraphicsEffect(shadow)
        self.glow_shadow_effect = shadow
        self.glow_colors = [
            QColor(0, 200, 255), QColor(255, 0, 150), QColor(0, 255, 100),
            QColor(255, 255, 0), QColor(255, 80, 0),]

        self.current_glow_index = 0
        self.glow_fade = QVariantAnimation()
        self.glow_fade.setStartValue(50)
        self.glow_fade.setEndValue(200)
        self.glow_fade.setDuration(1000)
        self.glow_fade.setLoopCount(-1)
        self.glow_fade.valueChanged.connect(lambda a: self._update_glow_color(int(a)))
        self.glow_fade.start()

        def cycle_color():
            self.current_glow_index = (self.current_glow_index + 1) % len(self.glow_colors)

        self.color_timer = QTimer()
        self.color_timer.timeout.connect(cycle_color)
        self.color_timer.start(3000)

        def _update_glow_color(alpha):
            base = self.glow_colors[self.current_glow_index]
            self.glow_shadow_effect.setColor(QColor(base.red(), base.green(), base.blue(), alpha))
        self._update_glow_color = _update_glow_color
    except Exception as e:
        log.error(str(f"[DEBUG] Glow effect skipped: {e}"))

# --- return profile image loc if none return icon loc

def on_run_preflight_now_clicked(self, *args, **kwargs):
    self.set_status_txt(self.tr("Checking Preflight"))
    log.debug(str(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} run preflight now clicked"))

    username = self._active_username()
    if not username:
        QMessageBox.information(self, self.tr("Preflight"), self.tr("Please enter or select a user first."))
        return

    # Gentle heads-up about clipboard etc.
    try:
        if hasattr(self, "maybe_warn_windows_clipboard"):
            self.maybe_warn_windows_clipboard(self, username, False)
    except Exception as e:
        log.error(str(f"{kql.i('tool')} [ERROR] {kql.i('err')} clipboard warn error: {e}"))

    # Per-user security prefs (login mode)
    try:
        prefs = load_security_prefs(username) or {}
    except Exception as e:
        prefs = {}
        log.error(str(f"{kql.i('tool')} [ERROR] {kql.i('err')} load_security_prefs error: {e}"))

    # AV check is now stored in the per-user *.sp file so it can be honored pre-login.
    if "check_av_login" in prefs:
        check_av = bool(prefs.get("check_av_login", False))
    else:
        # Back-compat: older builds stored this in user_db
        try:
            check_av = bool(get_user_setting(username, "WinDefCheckbox"))
            log.debug(str(f"{kql.i('tool')} [TOOLS] {kql.i('info')} get_user_setting: {username}/WinDefCheckbox -> {check_av}"))
        except Exception as e:
            check_av = False
            log.error(str(f"{kql.i('tool')} [ERROR] {kql.i('err')} get_user_setting error: {e}"))

    preflight_enabled = bool(prefs.get("enable_preflight_login", prefs.get("enable_preflight", True)))
    av_present = None
    av_names = []
    av_source = "n/a"
    if check_av:
        try:
            ok_av, names, source = _any_av_present(debug=True)
            av_present, av_names, av_source = ok_av, names, source
        except Exception as e:
            log.error(str(f"{kql.i('tool')} [ERROR] {kql.i('err')} any av present error: {e}"))

    # Suspicious processes (uses per-user prefs list)
    try:
        flagged = scan_for_suspicious_processes(prefs)
    except Exception as e:
        flagged = []
        log.error(str(f"{kql.i('tool')} [ERROR] {kql.i('err')} scan suspicious processes failed: {e}"))

    # Quick status
    lines = [
        f"Preflight enabled (per-user): {preflight_enabled}",
        f"Per-user AV check (WinDefCheckbox): {check_av}",
    ]
    if check_av:
        lines.append(f"AV detected: {av_present} via {av_source} {av_names}")
    lines.append("Suspicious processes: " + (", ".join(flagged) if flagged else "None"))
    QMessageBox.information(self, self.tr("Preflight status"), self.tr("\n").join(lines))

    # Run full preflight for this user
    try:
        ok = run_preflight_for_user(
            username=username,
            user_prefs_loader=self._load_user_preflight_overrides,  # if you have overrides; else lambda u: {}
            is_dev=is_dev,
            parent=self
        )
        log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('info')} run preflight for user returned: {ok}")
    except Exception as e:
        log.error(str(f"{kql.i('tool')} [ERROR] {kql.i('info')} run preflight for user error: {e}"))

# ==============================
# --- auto sync
# ==============================


def get_webfill_profiles(self, *args, **kwargs) -> list[dict]:
    """
    Return all Webfill rows as a list of light-weight dicts
    suitable for the extension UI. Each item includes a 'title'
    and a 'profile' payload with canonical keys.
    """
    out = []
    # ensure table is showing Webfill; if not, we can still read values by headers
    table = getattr(self, "vaultTable", None)
    if not table:
        return out

    # grab lowercase headers once
    headers = [ (self.vaultTable.horizontalHeaderItem(i).text() or "").strip().lower()
                for i in range(self.vaultTable.columnCount()) ]

    def col_idx(lbl: str) -> int:
        try:
            return headers.index((lbl or "").strip().lower())
        except ValueError:
            return -1

    # resolve column indices for our labels
    idx = {
        "title": col_idx("title"),
        "honorific": col_idx(WEBFILL_COL["HONORIFIC"]),
        "first": col_idx(WEBFILL_COL["FORENAME"]),
        "middle": col_idx(WEBFILL_COL["MIDDLENAME"]),
        "surname": col_idx(WEBFILL_COL["SURNAME"]),
        "email": col_idx(WEBFILL_COL["EMAIL"]),
        "phone": col_idx(WEBFILL_COL["PHONE"]),
        "addr1": col_idx(WEBFILL_COL["ADDR1"]),
        "addr2": col_idx(WEBFILL_COL["ADDR2"]),
        "city": col_idx(WEBFILL_COL["CITY"]),
        "region": col_idx(WEBFILL_COL["REGION"]),
        "postal": col_idx(WEBFILL_COL["POSTAL"]),
        "country": col_idx(WEBFILL_COL["COUNTRY"]),
    }

    def cell(r, c) -> str:
        if c < 0: return ""
        try:
            w = self.vaultTable.item(r, c)
            return (w.text() if w else "").strip()
        except Exception:
            return ""

    for r in range(self.vaultTable.rowCount()):
        prof = {
            "honorific": cell(r, idx["honorific"]),
            "forename":  cell(r, idx["first"]),
            "middle":    cell(r, idx["middle"]),
            "surname":   cell(r, idx["surname"]),
            "email":     cell(r, idx["email"]),
            "phone":     cell(r, idx["phone"]),
            "address1":  cell(r, idx["addr1"]),
            "address2":  cell(r, idx["addr2"]),
            "city":      cell(r, idx["city"]),
            "region":    cell(r, idx["region"]),
            "postal":    cell(r, idx["postal"]),
            "country":   cell(r, idx["country"]),
        }
        title = cell(r, idx["title"]) or "Profile"
        out.append({
            "id": r,                     # row index (stable while app open)
            "title": title,
            "subtitle": f'{prof["forename"]} {prof["surname"]}'.strip(),
            "profile": prof,
        })
    return out

# --- indercnated 


def show_licenses_dialog(self, *args, **kwargs):
    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Open-Source Licenses"))

    root = QVBoxLayout(dlg)
    intro = QLabel(
        "This product includes open-source software. "
        "Click a link to open a notice or license file.", dlg
    )
    intro.setWordWrap(True)
    root.addWidget(intro)

    # Quick links to folders + notices
    def add_link(text, path: Path):
        if not path.exists(): 
            return
        url = QUrl.fromLocalFile(str(path))
        lbl = QLabel(f'• <a href="{url.toString()}">{text}</a>', dlg)
        lbl.setTextFormat(Qt.RichText)
        lbl.setTextInteractionFlags(Qt.TextBrowserInteraction)
        lbl.setOpenExternalLinks(True)
        container_layout.addWidget(lbl)

    area = QScrollArea(dlg); area.setWidgetResizable(True)
    container = QWidget(); container_layout = QVBoxLayout(container)

    # Top: important files
    add_link("THIRD_PARTY_NOTICES.txt", LICENSES_DIR / "THIRD_PARTY_NOTICES.txt")
    add_link("components.json",          LICENSES_DIR / "components.json")
    add_link("README.txt",               LICENSES_DIR / "README.txt")

    # Core texts (LGPL + GPL + PyInstaller)
    add_link("SPDX_LICENSES/LGPL-3.0-only.txt", SPDX_DIR / "LGPL-3.0-only.txt")
    add_link("SPDX_LICENSES/GPL-3.0.txt",       SPDX_DIR / "GPL-3.0.txt")
    add_link("SPDX_LICENSES/vendors/pyinstaller/COPYING.txt",
             SPDX_DIR / "vendors" / "pyinstaller" / "COPYING.txt")

    # Show ALL license files recursively (common names/extensions)
    exts = {".txt", ".md", ""}  # include files like COPYING with no extension
    common_names = {"LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE"}
    shown = set()

    for p in sorted(LICENSES_DIR.rglob("*")):
        if p.is_dir():
            continue
        name = p.name
        if p.suffix.lower() in (".txt", ".md"):
            pass
        elif name.upper() in common_names:  # LICENSE, COPYING, etc.
            pass
        else:
            continue
        # avoid duplicates already listed above
        key = str(p.resolve())
        if key in shown:
            continue
        shown.add(key)
        add_link(str(p.relative_to(LICENSES_DIR)).replace("\\", "/"), p)

    container_layout.addStretch(1)
    area.setWidget(container)
    root.addWidget(area, 1)

    # Close
    btn = QPushButton(self.tr("Close"), dlg)
    btn.clicked.connect(dlg.accept)
    root.addWidget(btn)

    dlg.resize(640, 520)
    dlg.exec()


def on_export_audit_clicked(self, *args, **kwargs):
    self.set_status_txt(self.tr("Exporting"))
    """
    Export the user's audit log to a UTF-8 .txt (tab-separated).
    Uses read_audit_log(username) so it exports ALL entries, not just visible rows.
    """
    user = (self.currentUsername.text() or "").strip()
    if not user:
        QMessageBox.warning(self, self.tr("Export Audit"), self.tr("No user is active."))
        return

    # Choose filename
    ts = QDateTime.currentDateTime().toString("yyyyMMdd_HHmmss")
    suggested = f"{user}_audit_{ts}.txt"
    path, _ = QFileDialog.getSaveFileName(self, "Export Audit Log", suggested, "Text files (*.txt);;All files (*.*)")
    if not path:
        return
    if os.path.isdir(path):
        path = os.path.join(path, suggested)
    if not os.path.splitext(path)[1]:
        path += ".txt"

    # Fetch data directly from source
    try:
        events = read_audit_log(user)  # same API you use in load_audit_table
    except Exception as e:
        QMessageBox.critical(self, self.tr("Export Audit"), f"Failed to read audit log:\n{e}")
        return

    def _san(s: str) -> str:
        s = (s or "").replace("\r\n", " ").replace("\n", " ").replace("\t", "  ")
        return s.strip()

    # Write file
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Keyquorum Audit Export\n")
            f.write(f"# user={user} exported={QDateTime.currentDateTime().toString(Qt.ISODate)}\n\n")
            f.write("Timestamp\tEvent\tDescription\n")

            for e in events:
                if "error" in e:
                    # Preserve tamper/invalid row style
                    ts = _san(e.get("timestamp", "")) or "✖"
                    event = "Invalid Entry"
                    desc = _san(e.get("error", ""))
                else:
                    ts = _san(e.get("timestamp", ""))
                    event = _san(e.get("event", ""))
                    desc = _san(e.get("description", ""))
                f.write(f"{ts}\t{event}\t{desc}\n")
        msg = self.tr("Audit exported to:") + f"\n{path}"
        QMessageBox.information(self, self.tr("Export Audit"), msg)
    except Exception as e:
        msg = self.tr("Failed to export:") + f"\n{e}"
        QMessageBox.critical(self, self.tr("Export Audit"), msg)

# ==============================
# --- regenerate vault backup codes
# ==============================


def _show_cloud_risk_modal(self, current_wrap: bool) -> tuple[bool, bool, bool]:
    """
    One-time consent explaining cloud risks.
    Returns (accepted: bool, dont_ask_again: bool, enable_wrap: bool).

    - accepted: user wants to proceed
    - dont_ask_again: remember consent for future operations
    - enable_wrap: user chose to turn on extra cloud wrapping (recommended)
    """
    from features.url.main_url import SITE_HELP, PRIVACY_POLICY
    help_url = getattr(self, "SITE_HELP", SITE_HELP)
    privacy_url = PRIVACY_POLICY

    msg = QMessageBox(self)
    msg.setIcon(QMessageBox.Warning)
    msg.setWindowTitle(self.tr("Cloud storage — security warning"))
    msg.setTextFormat(Qt.RichText)
    msg.setText(self.tr(
        "<b>Cloud storage increases security risk</b><br>"
        "This app is designed for local security. Storing your vault in a cloud-synced folder "
        "increases exposure. If an attacker obtains the file from your cloud, they can attempt "
        "unlimited offline password-guessing against it.<br><br>"
        "Use a strong master password and 2FA. Consider enabling extra cloud wrapping.<br><br>"
        "<a href='{help_url}'>Learn more</a> · <a href='{privacy_url}'>Privacy Policy</a>").format(help_url, privacy_url)
    )

    # Add checkboxes
    dont_ask_box = QCheckBox(self.tr("Don't ask me again"))
    wrap_box = QCheckBox(self.tr("Enable extra cloud wrapping (recommended)"))
    wrap_box.setChecked(not current_wrap)  # suggest enabling if it's currently off

    # Portable way: use setCheckBox for the remember flag only
    msg.setCheckBox(dont_ask_box)

    # Buttons
    proceed_btn = msg.addButton("Proceed", QMessageBox.AcceptRole)
    cancel_btn = msg.addButton(self.tr("Cancel"), QMessageBox.RejectRole)

    # Show small dialog if user proceeds and wrap is off.
    # To keep UX tight, we handle it after click.

    res = msg.exec_() if hasattr(msg, "exec_") else msg.exec()
    accepted = (msg.clickedButton() is proceed_btn)
    if not accepted:
        return False, False, False

    # If wrap is already ON, we're done.
    if current_wrap:
        return True, bool(dont_ask_box.isChecked()), False

    # Ask about enabling wrap now (separate lightweight confirm)
    wrap_q = QMessageBox(self)
    wrap_q.setIcon(QMessageBox.Question)
    wrap_q.setWindowTitle(self.tr("Enable extra cloud wrapping?"))
    wrap_q.setText(self.tr(
        "Enable extra encryption wrapping for cloud storage?\n\n"
        "This adds an additional encryption layer specifically for cloud sync targets.")
    )
    wrap_yes = wrap_q.addButton(self.tr("Enable wrapping"), QMessageBox.AcceptRole)
    wrap_no = wrap_q.addButton(self.tr("Not now"), QMessageBox.RejectRole)
    wrap_q.exec_() if hasattr(wrap_q, "exec_") else wrap_q.exec()
    enable_wrap = (wrap_q.clickedButton() is wrap_yes)

    return True, bool(dont_ask_box.isChecked()), bool(enable_wrap)


def _validate_share_packet(self, packet: dict) -> tuple[bool, str | None]:
    """
    Validate both single and bundle plain packets.
    Returns (ok, why).
    - encrypted envelopes are syntactically validated by _packet_mode and then
      cryptographically verified when decrypting.
    """
    try:
        mode = self._packet_mode(packet)
        if mode is None:
            return False, "Unrecognized share packet."

        if mode == "encrypted":
            # Basic base64 sanity (we’ll rely on decrypt failing for real validation)
            snd, rcp, pld, wky = packet.get("sender"), packet.get("recipient"), packet.get("payload"), packet.get("wrapped_key")
            if not all(isinstance(x, dict) for x in (snd, rcp, pld, wky)):
                return False, "Malformed encrypted envelope."
            for path, val in (
                ("sender.pub_x25519", snd.get("pub_x25519") if isinstance(snd, dict) else None),
                ("payload.nonce",     pld.get("nonce")     if isinstance(pld, dict) else None),
                ("payload.ciphertext",pld.get("ciphertext")if isinstance(pld, dict) else None),
                ("wrapped_key.nonce", wky.get("nonce")     if isinstance(wky, dict) else None),
                ("wrapped_key.ciphertext", wky.get("ciphertext") if isinstance(wky, dict) else None),
            ):
                try:
                    base64.b64decode(str(val or ""), validate=True)
                except Exception:
                    return False, f"Invalid base64 at {path}"
            return True, None

        # --- plain single ---
        if mode == "plain":
            entry = packet.get("entry")
            if not isinstance(entry, dict) or not entry:
                return False, "Packet has no entry data."
            # Size guard
            if len(json.dumps(packet, ensure_ascii=False)) > 256_000:
                return False, "Packet too large."
            packet["entry"] = self._sanitize_share_entry(entry)
            return True, None

        # --- plain bundle ---
        if mode == "bundle":
            items = packet.get("entries") or []
            if not isinstance(items, list) or not items:
                return False, "Empty entries bundle."
            # sanitize each entry
            clean = []
            for it in items:
                if isinstance(it, dict) and it.get("entry"):
                    clean.append(self._sanitize_share_entry(it["entry"]))
                elif isinstance(it, dict):  # allow raw entry dicts
                    clean.append(self._sanitize_share_entry(it))
            if not clean:
                return False, "No valid entries in bundle."
            packet["entries"] = clean
            # light size guard
            if len(json.dumps(packet, ensure_ascii=False)) > 1_500_000:
                return False, "Bundle too large."
            return True, None

        return False, "Unsupported share format."
    except Exception as e:
        return False, f"Packet validation failed: {e}"


def get_entries_for_origin(self, origin: str):
    """
    Return [{title, username, password, url}] for the page origin.
    Reads password from the Password cell's UserRole (unmasked).
    """
    table = getattr(self, "vaultTable", None)
    if not table:
        return []

    try:
        netloc = urlparse(origin if "://" in origin else f"https://{origin}").netloc
        target = netloc.split(":")[0].lower()
    except Exception:
        target = (origin or "").strip().lower()

    headers = self._header_texts_lower()
    if not hasattr(self, "_kq_url_col") or self._kq_url_col is None:
        self._kq_url_col = self._find_col_by_labels({"website", "url", "login url", "site", "web site"})
    if not hasattr(self, "_kq_user_col") or self._kq_user_col is None:
        self._kq_user_col = self._find_col_by_labels({"email", "username", "user name", "login"})
    if not hasattr(self, "_kq_title_col") or self._kq_title_col is None:
        self._kq_title_col = headers.index("website") if "website" in headers else 0

    url_col, user_col, title_col = self._kq_url_col, self._kq_user_col, self._kq_title_col

    def host_ok(u: str) -> bool:
        try:
            net = urlparse(u if "://" in u else f"https://{u}").netloc.lower()
            host = net.split(":")[0]

            def strip_www(h: str) -> str:
                # remove one or more leading 'www.' to be safe
                while h.startswith("www."):
                    h = h[4:]
                return h

            thost = target  # from origin earlier in the function
            h0 = strip_www(host)
            t0 = strip_www(thost)

            # exact or without www
            if host == thost or h0 == t0:
                return True

            # allow either side to be a subdomain of the other
            if host.endswith("." + thost) or thost.endswith("." + host):
                return True
            if h0.endswith("." + t0) or t0.endswith("." + h0):
                return True

            return False
        except Exception:
            return False

    out = []
    for r in range(table.rowCount()):
        url = self._get_text(r, url_col)
        if not host_ok(url):
            continue
        username = self._get_text(r, user_col) if user_col >= 0 else ""
        password = self._get_password_from_table(r)
        title    = self._get_text(r, title_col) or (url or target)
        out.append({"title": title, "username": username, "password": password, "url": url})
    return out


def _set_cloud_cfg(self, remote_path: str, *, enable: bool = True,
                   provider: str = "localpath", wrap: bool | None = None) -> bool:
    # Resolve the canonical username (CI if helper exists)
    try:
        canon = _canonical_username_ci(self.currentUsername.text())
    except Exception:
        canon = None
    username = (canon or (self.currentUsername.text() or "").strip())

    if not username:
        QMessageBox.warning(self, self.tr("Cloud Sync"), self.tr("Please log in first."))
        return False

    remote_path = (remote_path or "").replace("\\", "/")
    if not remote_path:
        QMessageBox.warning(self, self.tr("Cloud Sync"), self.tr("Please choose a cloud location first."))
        return False

    # Ensure parent folder exists (ignore if provider isn't filesystem-based)
    try:
        parent = os.path.dirname(remote_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
    except Exception as e:
        QMessageBox.critical(self, self.tr("Cloud Sync"), f"Cannot use this location:\n{e}")
        return False

    # Read existing profile to inherit wrap if not specified
    try:
        prof = get_user_cloud(username) or {}
        if wrap is None:
            wrap = bool(prof.get("cloud_wrap"))
    except Exception:
        prof = {}
        if wrap is None:
            wrap = False

    # Save settings via per-user API
    try:
        set_user_cloud(
            username,
            enable=bool(enable),
            provider=(provider or "localpath"),
            path=remote_path,
            wrap=bool(wrap),
        )
    except Exception as e:
        log.error(f"[CLOUD] set_user_cloud failed: {e}")
        QMessageBox.critical(self, self.tr("Cloud Sync"), f"Failed to save cloud settings:\n{e}")
        return False

    # Reflect changes in UI (best-effort)
    try:
        if hasattr(self, "cloudSyncCheckbox"):
            self.cloudSyncCheckbox.blockSignals(True)
            self.cloudSyncCheckbox.setChecked(bool(enable))
            self.cloudSyncCheckbox.blockSignals(False)
        if hasattr(self, "cloudPathLabel"):
            self.cloudPathLabel.setText(remote_path)
    except Exception:
        pass

    return True


def _toggle_cloud_wrap(self, enable: bool):
    """
    Atomically switch cloud_wrap on/off without bricking the vault.
    Pauses auto-sync + file watcher, does a controlled migration, then resumes.
    """
    username = self._active_username()
    if not username or not getattr(self, "userKey", None):
        QMessageBox.information(self, self.tr("Cloud sync"), self.tr("Please log in first."))
        return

    # ---- Pause auto mechanisms ----
    try:
        if getattr(self, "_auto_sync_timer", None):
            self._auto_sync_timer.stop()
        if getattr(self, "_vault_watcher", None):
            self._vault_watcher.blockSignals(True)
    except Exception:
        pass
    self._sync_guard = True

    try:
        # Bind engine to this user
        self._configure_sync_engine(username)

        # STEP A: Pull latest with the CURRENT wrap state (whatever it is now)
        _ = self._cloud_sync_safe(self.userKey, interactive=True)

        # STEP B: Flip the setting in your profile (so next push uses the new state)
        prof = get_user_cloud(username) or {}
        set_user_cloud(
            username,
            enable=True,
            provider=prof.get("provider") or "localpath",
            path=prof.get("remote_path") or "",
            wrap=bool(enable),
        )
        # Rebind so engine reads the updated wrap flag
        self._configure_sync_engine(username)

        # STEP C: Push once with the NEW wrap state to migrate the remote
        res = self._cloud_sync_safe(self.userKey, interactive=True)
        self._refresh_baseline_if_pulled(res, username)
        msg = self.tr("Extra wrap ") + f"{self.tr('enabled') if enable else self.tr('disabled')}.\n" + "Sync: " + f"{res}"
        QMessageBox.information(
            self, self.tr("Cloud wrap"), msg)
    except Exception as e:
        msg = self.tr("Wrap toggle failed: ") + f"{e}"
        QMessageBox.warning(self, self.tr("Cloud wrap"), msg)
    finally:
        # ---- Resume auto mechanisms ----
        try:
            if getattr(self, "_vault_watcher", None):
                self._vault_watcher.blockSignals(False)
        except Exception:
            pass
        self._sync_guard = False
        # Kick watcher + auto-sync back on
        try:
            self._watch_local_vault()
            self._schedule_auto_sync()
        except Exception:
            pass


def one_time_mobile_transfer(self, *args, **kwargs):
    """
    Create a password-encrypted transfer package (.zip.enc) with:
    - vault + wrapped vault (if present)
    - salt
    - identities
    - user_db (per-user)
    - shared keys (if any)

    The user chooses their cloud folder (OneDrive/Drive/Dropbox). Android will import it once.
    """
    from qtpy.QtWidgets import QFileDialog, QInputDialog, QMessageBox
    from pathlib import Path
    import datetime as _dt

    self.reset_logout_timer()

    # 0) Pre-checks
    username = (self.currentUsername.text().strip() if hasattr(self, "currentUsername") else "")
    if not username:
        QMessageBox.warning(self, self.tr("Mobile Transfer"), self.tr("Please log in first."))
        return

    # 1) Set strong passphrase for the package
    pw, ok = QInputDialog.getText(
        self, self.tr("Mobile Transfer Password"),
        self.tr("Choose a password to encrypt the transfer package") + ":\n\n• "+
        self.tr("Write it down or store it safely — Android will need it") + ".\n• " +
        self.tr("This is NOT your vault password (it can be different)."),
        QLineEdit.EchoMode.Password
    )
    if not ok or not pw:
        return

    # 2) Pick cloud folder to save the package
    cloud_dir = QFileDialog.getExistingDirectory(
        self, self.tr("Choose your cloud folder (e.g., OneDrive/Drive/Dropbox)")
    )
    if not cloud_dir:
        return

    # 3) Export using full-backup helper (AES-GCM zip.enc)
    try:
        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        # export_full_backup(username, password, out_dir) -> returns path string
        written = export_full_backup(username, pw, cloud_dir)

        # 4) UX: clear instructions
        QMessageBox.information(
            self, self.tr("Transfer Ready"),
            self.tr("✅ Mobile transfer package created:\n"
            "{written1}\n\n"
            "Next steps on Android:\n"
            "1) Open Keyquorum (Android) → Import → Desktop Transfer\n"
            "2) Pick this .zip.enc file from your cloud\n"
            "3) Enter the transfer password\n\n"
            "⚠️ For your security: delete the .zip.enc from your cloud after import.").format(written1=written)
        )
        log_event_encrypted(username, "One-Time Mobile Transfer", f"{kql.i('ok')} package: {written} Time: {ts}")
    except Exception as e:
        QMessageBox.critical(self, self.tr("Mobile Transfer Failed"), f"❌ {e}")


def _on_editor_schema_saved(self, *args, **kwargs):
    """
    Called by CategoryEditor when it has finished saving the new schema.

    We:
    - persist schema into the per-user user_db.json (authoritative)
    - mirror into login_handler settings
    - refresh vault schema + category selector immediately
    """
    log.debug("[CAT] _on_editor_schema_saved: starting")
    try:
        # schema from the editor
        schema = getattr(self, "category_schema", None) or getattr(self, "_category_schema", None)
        if not isinstance(schema, dict):
            log.debug("[CAT] _on_editor_schema_saved: no schema dict on host")
            return

        # target user
        try:
            uname = getattr(self, "_category_editor_user", "") or ""
        except Exception:
            uname = ""
        if not uname:
            try:
                uname = (self.currentUsername.text() or "").strip()
            except Exception:
                uname = ""

        if not uname:
            log.warning("[CAT] _on_editor_schema_saved: no username; schema not saved")
            return

        canonical = uname.strip().lower()

        # 1) Write to per-user user_db.json
        try:
            from catalog_category.category_editor import save_full_schema_dict_for
            save_full_schema_dict_for(canonical, schema)
            log.debug("[CAT] _on_editor_schema_saved: user_db schema saved for %s", canonical)
        except Exception as e:
            log.error("[CAT] _on_editor_schema_saved: save_full_schema_dict_for failed for %s: %s", canonical, e)

        # 2) Mirror into login_handler settings
        try:
            set_user_setting(canonical, "category_schema", schema)
        except Exception as e:
            log.debug("[CAT] _on_editor_schema_saved: set_user_setting(category_schema) failed for %s: %s", canonical, e)

        # 3) Refresh vault + UI now
        try:
            self._do_vault_schema_refresh()
        except Exception as e:
            log.debug("[CAT] _on_editor_schema_saved: _do_vault_schema_refresh failed: %s", e)

    except Exception as e:
        log.error("[CAT] _on_editor_schema_saved outer error: %s", e)


# ==============================
# --- login/App avatar
# ==============================
# --- crop user photo + add shround + renderer (shared by login + app)


def _show_logout_warning(self, *args, **kwargs):
    # If already open, don't spawn another
    if getattr(self, "_warning_dialog", None) is not None:
        return

    # Compute seconds remaining
    secs_left = self._seconds_until_logout()
    if secs_left <= 0:
        # Race: just logout
        self.force_logout()
        return

    msg = QMessageBox(self)
    msg.setWindowTitle(self.tr("You’ll be signed out soon"))
    msg.setIcon(QMessageBox.Icon.Warning)
    msg.setStandardButtons(QMessageBox.StandardButton.Ok)
    # Add a custom "Stay signed in" button
    extend_btn = msg.addButton(self.tr("Stay signed in"), QMessageBox.ButtonRole.AcceptRole)
    msg.setDefaultButton(extend_btn)

    # Use a small text that updates every second
    def _update_label():
        s = self._seconds_until_logout()
        if s <= 0:
            try:
                msg.close()
            except Exception:
                pass
            self.force_logout()
            return
        msg.setText(self.tr("Due to inactivity, you will be signed out in ") + f"<b>{s}</b>" + self.tr(" seconds."))
    _update_label()

    # Hook the global 1s ticker to update the label while dialog is visible
    def _maybe_update():
        if getattr(self, "_warning_dialog", None) is msg:
            _update_label()
    try:
        self._warning_update_conn = self._tick.timeout.connect(_maybe_update)  
    except Exception:
        pass

    self._warning_dialog = msg
    res = msg.exec()

    # User clicked something; clear dialog
    self._warning_dialog = None
    try:
        # disconnect temporary updater
        self._tick.timeout.disconnect(_maybe_update)  
    except Exception:
        pass

    # If they clicked "Stay signed in", treat as activity
    if msg.clickedButton() == extend_btn:
        self.reset_logout_timer()
    else:
        # If they dismissed with OK, do nothing (timers continue counting down)
        pass
