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
from features.share.zk_share import (
    verify_and_decrypt_share_packet,
    make_share_packet as zk_make_share_packet,)
from vault_store.vault_store import load_vault
from app.paths import config_dir
from features.share.share_keys import ensure_share_keys, export_share_id_json
from app.paths import shared_key_file
from features.qr.qr_tools import show_qr_for_object
import datetime as dt 

from app.dev import dev_ops
is_dev = dev_ops.dev_set

from vault_store.vault_store import save_vault
from security.baseline_signer import update_baseline
import base64, json
from vault_store.add_entry_dialog import AddEntryDialog

_MAIN = (
    _sys.modules.get("__main__")
    or _sys.modules.get("main")
    or _sys.modules.get("app.app_window")
    or _sys.modules.get("app_window"))

if _MAIN is not None:
    globals().update(_MAIN.__dict__)


# Safety net: ensure Qt symbols exist even when __main__ differs (e.g., frozen builds)
try:
    from app.qt_imports import *  # noqa: F401,F403
except Exception:
    pass

# ensure compatibility with both old and new signatures of ensure_share_keys (with or without user_key argument)
def _ensure_share_keys_compat(self, key_dir, username, user_key=None):
    kd = str(key_dir) if key_dir is not None else ""
    try:
        return ensure_share_keys(kd, username)            # new signature
    except TypeError:
        return ensure_share_keys(kd, username, user_key)  # old signature

# STRICT NATIVE: share packets require raw asymmetric key material; disable until migrated to native.
def make_share_packet(self):
    """Create a .kqshare (single) or .kqshareb (bundle) and SAVE TO FILE only (no QR preview)."""
    try:
        username = (self.currentUsername.text() if hasattr(self, "currentUsername") else "").strip()
        if not (isinstance(getattr(self, 'core_session_handle', None), int) and getattr(self, 'core_session_handle', 0) > 0) or not username:
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
                all_entries = load_vault(username, self.core_session_handle) or []
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
        pub_bundle, priv_x, priv_ed = ensure_share_keys(username, self.core_session_handle)  # :contentReference[oaicite:2]{index=2}

        # Build encrypted envelopes
        envelopes = []
        for src in selected:
            entry = self._minimal_share_entry(src)
            pkt = zk_make_share_packet(
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

# import from file: open a .kqshare / .kqshareb / .json; validate/decrypt, preview each, then modeless Add dialog(s). 
# For encrypted packets we validate the structure, then attempt decryption; for plain packets we just validate the structure. 
# For bundles we show a checklist preview first, then sequential Add dialogs for each selected item. We handle multiple 
# formats and guard against common errors (e.g., wrong recipient, invalid JSON, missing fields) with user-friendly messages.
def import_share_packet(self):
    # STRICT NATIVE: share packets require raw asymmetric key material; disable until migrated to native.
    """Open .kqshare / .kqshareb / .json; validate/decrypt, preview each, then modeless Add dialog(s)."""
    try:
        if not (isinstance(getattr(self, 'core_session_handle', None), int) and getattr(self, 'core_session_handle', 0) > 0) or not self.currentUsername.text().strip():
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
        pub_bundle, priv_x, _priv_ed = ensure_share_keys(username, self.core_session_handle)  # :contentReference[oaicite:6]{index=6}

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

# export my Share ID (public key + metadata) as JSON file and show QR on screen for easy scanning by the recipient. 
# The Share ID is what others need to share entries.
def export_my_share_id(self):
    try:
        username = (self.currentUsername.text() if hasattr(self, "currentUsername") else "").strip()
        if not getattr(self, 'core_session_handle', None) or not username:
            QMessageBox.warning(self, self.tr("Export Share ID"), self.tr("Please log in first."))
            return
        # Use the unified per-user shared_key_file path
        key_path = shared_key_file(username, ensure_dir=True, name_only=False)
        share_id = export_share_id_json(username, self.core_session_handle)

        try:
            show_qr_for_object(
                "My Share ID (scan to add me)",
                {"type": "kqshareid", **share_id},
                self,
                mode="shareid",
            )
        except Exception:
            pass

        suggested = Path(config_dir()) / f"{username}.kqshareid"
        out_path, _ = QFileDialog.getSaveFileName(
            self,
            self.tr("Save My Share ID"),
            str(suggested),
            "Share ID (*.kqshareid)",
        )
        if not out_path:
            return

        Path(out_path).write_text(json.dumps(share_id, indent=2), encoding="utf-8")
        QMessageBox.information(
            self,
            self.tr("Export Share ID"),
            self.tr(
                "Your Share ID was saved.\nShare it with people who want to send you entries."
            ),
        )

    except Exception as e:
        try:
            log.error("%s [SHARE] export id failed: %s", kql.i("err"), e)
        except Exception:
            pass
        QMessageBox.critical(
            self,
            self.tr("Export Share ID"),
            self.tr("Failed to export Share ID:\n{err}").format(err=e),
        )

# qr scan import (single or multi-page) with on-screen preview and Add dialog(s). For single-item share packets we show the entry preview → 
# Add dialog immediately; for bundles we show a checklist preview first, then sequential Add dialogs for each selected item.
def quick_import_from_qr(self):
    # STRICT NATIVE: share packets require raw asymmetric key material; disable until migrated to native.
    """Scan a share QR (camera or image, single or multi-page) and open the prefilled Add dialog for a single item."""
    try:
        if not (isinstance(getattr(self, 'core_session_handle', None), int) and getattr(self, 'core_session_handle', 0) > 0) or not self.currentUsername.text().strip():
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
        pub_bundle, priv_x, _priv_ed = ensure_share_keys(username, self.core_session_handle)

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

# STRICT NATIVE: share packets require raw asymmetric key material; disable until migrated to native.
def quick_export_scan_only(self):
    """
    Create an encrypted share **for a chosen recipient** and show QR on screen only (no file).
    Use when the other device/app will scan immediately.
    """
    try:
        username = (self.currentUsername.text() if hasattr(self, "currentUsername") else "").strip()
        if not (isinstance(getattr(self, 'core_session_handle', None), int) and getattr(self, 'core_session_handle', 0) > 0) or not username:
            QMessageBox.warning(self, self.tr("Quick Export (Scan)"), self.tr("Please log in first. (Missing 32-byte key or username)"))
            return

        table = getattr(self, "vaultTable", None)
        if table is None or table.currentRow() < 0:
            QMessageBox.information(self, self.tr("Quick Export (Scan)"), self.tr("Select an entry to share first."))
            return

        # Only single-item quick QR (keep it small/predictable)
        try:
            try:
                all_entries = load_vault(username, self.core_session_handle) or []
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
        pub_bundle, priv_x, priv_ed = ensure_share_keys(username, self.core_session_handle)  # :contentReference[oaicite:4]{index=4}

        # Minimal payload to keep QR size down
        entry = self._minimal_share_entry(src)

        # Optional expiry hint (soft)
        expires_at = None  # keep simple for now

        packet = zk_make_share_packet(
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

# validate the structure of a share packet (plain single, plain bundle, or encrypted envelope). 
# Checks for required fields, types, and basic base64 validity for encrypted packets. Returns (ok, why)
#  where ok is a boolean and why is an error message if not ok.
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

# For bundles we show a checklist preview first, then sequential Add dialogs for each selected item. Returns True if at least one item was imported.
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
                    entries_cur = load_vault(username, self.core_session_handle) or []
                except TypeError:
                    entries_cur = load_vault(username) or []

                entries_cur.append(new_entry)
                try:
                    save_vault(username, self.core_session_handle, entries_cur)
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

# When sharing an entry (e.g., via QR code or file export), we want to build a minimal, 
# sanitized version of the entry that normalizes common aliases, keeps only human-useful fields, 
# and avoids duplications (e.g., 'URL' vs 'Website'). This function takes a raw entry dict and produces a cleaned-up version for sharing.
def _minimal_share_entry(self, src: dict) -> dict:
    """
    Build a minimal, sanitized entry for sharing.
    - Normalizes common aliases
    - Keeps only human-useful fields
    - Avoids duplications ('URL' vs 'Website')
    """
    if not isinstance(src, dict):
        return {}

    # Allow-list of shareable keys
    ALLOW = {
        "category", "Title", "Name", "Username", "Email", "Password",
        "Website", "URL", "Notes", "2FA Enabled", "TOTP", "TOTP Secret",
        "Phone Number", "Backup Code", "IMAP Server", "SMTP Server"
    }
    # Drop noisy/internal keys
    DROP = {
        "Date", "created_at", "updated_at", "_id", "_uid", "__version__", "__meta__",
        "last_viewed", "last_rotated", "history", "history_hashes",
        "Type",  # UI-only
    }

    def _norm(v):
        if v is None:
            return ""
        if isinstance(v, (list, tuple)):
            return ", ".join(_norm(x) for x in v)
        return str(v)

    out = {}
    # First pass: alias mapping to canonical keys
    for k, v in src.items():
        if k in DROP:
            continue
        kl = str(k or "").strip().lower()

        if kl in ("title",):
            out["Title"] = _norm(v)
        elif kl in ("name",):
            out["Name"] = _norm(v)
        elif kl in ("user", "login", "username", "account", "accountname", "userid"):
            out["Username"] = _norm(v)
        elif kl in ("email", "mail", "emailaddress"):
            out["Email"] = _norm(v)
        elif kl in ("password", "pass", "passwd", "secret", "key"):
            out["Password"] = _norm(v)
        elif kl in ("website",):
            out["Website"] = _norm(v)
        elif kl in ("url", "link", "domain", "site"):
            out["URL"] = _norm(v)
        elif kl in ("phone", "phonenumber", "mobile", "tel", "telephone"):
            out["Phone Number"] = _norm(v)
        elif kl in ("backupcode", "backup codes", "backupcodes", "recoverycodes", "recoverycode"):
            out["Backup Code"] = _norm(v)
        elif kl in ("totp", "totpkey", "totpsecret", "2fasecret", "mfa secret", "authsecret"):
            out["TOTP Secret"] = _norm(v)
        elif kl in ("imap", "imapserver"):
            out["IMAP Server"] = _norm(v)
        elif kl in ("smtp", "smtpserver"):
            out["SMTP Server"] = _norm(v)
        elif kl == "notes":
            out["Notes"] = _norm(v)
        elif kl == "category":
            out["category"] = _norm(v)
        else:
            # Preserve any already canonical allow-listed keys
            if k in ALLOW:
                out[k] = _norm(v)

    # De-duplicate URL/Website if they’re identical
    if "Website" in out and "URL" in out and out["Website"].strip() == out["URL"].strip():
        out.pop("URL", None)

    # If neither Title nor Name present, try to derive something readable
    if not out.get("Title") and not out.get("Name"):
        candidate = out.get("Website") or out.get("URL") or out.get("Email") or out.get("Username")
        if candidate:
            out["Title"] = candidate

    return out

# shared flow for previewing a full entry + category picker, used by both "Import Share" and "Move to Category" flows
def _preview_full_entry(self, entry: dict, sequential: bool = False) -> bool:
    """
    Display a JSON preview + category picker.
    When the user clicks “Add to Category…”, either:
      - sequential=False (default): open AddEntryDialog modeless (current behavior).
      - sequential=True: open AddEntryDialog MODAL and wait; return True if saved.
    Returns True if the preview dialog closed via OK/Add flow; False on Cancel.
    """
    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Share Packet — Full Contents"))
    dlg.setModal(True)

    v = QVBoxLayout(dlg)
    v.setContentsMargins(12, 12, 12, 12)
    v.setSpacing(10)

    cat_detected = str(entry.get("category") or entry.get("Category") or "(unknown)")
    lbl = QLabel(self.tr("Detected category in packet: <b>{cat_detected}</b>").format(cat_detected=cat_detected))
    lbl.setTextFormat(Qt.TextFormat.RichText)
    v.addWidget(lbl)

    txt = QTextEdit()
    txt.setReadOnly(True)
    txt.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
    try:
        txt.setPlainText(json.dumps(entry, ensure_ascii=False, indent=2))
    except Exception:
        txt.setPlainText(str(entry))
    txt.setMinimumSize(700, 420)
    v.addWidget(txt, 1)

    h = QHBoxLayout()
    h.setSpacing(10)
    lbl_cat = QLabel(self.tr("Category:"))
    cmb_cat = QComboBox()
    cmb_cat.setMinimumWidth(220)
    try:
        if getattr(self, 'categorySelector_2', None) and self.categorySelector_2.count() > 0:
            for i in range(self.categorySelector_2.count()):
                cmb_cat.addItem(self.categorySelector_2.itemText(i))
        else:
            for c in ["Email Accounts", "Web Logins", "Software Licenses", "Secure Notes"]:
                cmb_cat.addItem(c)
    except Exception:
        for c in ["Email Accounts", "Web Logins", "Software Licenses", "Secure Notes"]:
            cmb_cat.addItem(c)

    i = cmb_cat.findText(cat_detected)
    if i >= 0:
        cmb_cat.setCurrentIndex(i)

    btn_add = QPushButton(self.tr("Add to Category…"))
    btns = QDialogButtonBox()
    btn_cancel = btns.addButton(QDialogButtonBox.StandardButton.Cancel)
    h.addWidget(lbl_cat)
    h.addWidget(cmb_cat, 1)
    h.addWidget(btn_add)
    h.addWidget(btns)
    v.addLayout(h)

    accepted_flag = {"ok": False}

    def do_add_to_category() -> None:
        target = cmb_cat.currentText().strip()
        if not target:
            QMessageBox.information(self, self.tr("Import Share"), self.tr("Please choose a category first."))
            return
        if self._is_blocked_target(target):
            msg = self.tr("Import into ") + f"“{target}”" + self.tr(" is blocked by your safety setting.")
            QMessageBox.warning(self, self.tr("Import Share"), msg)
            return

        username = self._active_username() or ""
        mapped = self._map_for_dialog(entry)

        # Close preview before launching the editor
        try: dlg.accept()
        except Exception: pass

        ref_win = None
        try:
            editor = AddEntryDialog(
                self, target,
                getattr(self, "enable_breach_checker", False),
                existing_entry=None,
                user=self.currentUsername.text(),
                is_dev=is_dev,
            )
            if hasattr(editor, "category"):
                editor.category = target

            for name in ("build_form", "_build_form", "rebuild_form", "on_category_changed"):
                if hasattr(editor, name):
                    try: getattr(editor, name)()
                    except Exception: pass

            if hasattr(self, "user_field_meta_for_category") and hasattr(editor, "set_fields_from_meta"):
                try:
                    editor.set_fields_from_meta(self.user_field_meta_for_category(target))
                    for name in ("build_form", "_build_form", "rebuild_form"):
                        if hasattr(editor, name):
                            try: getattr(editor, name)()
                            except Exception: pass
                except Exception:
                    pass

            def run_prefill() -> None:
                try: self._prefill_dialog_for_entry(editor, mapped)
                except Exception: pass

            if sequential:
                # modal path — prefill now and block until user finishes
                run_prefill()
                res = editor.exec()
                if res == int(editor.DialogCode.Accepted):
                    new_entry = editor.get_entry_data() or {}
                    new_entry["category"] = target
                    new_entry["Type"] = target
                    new_entry["Date"] = dt.datetime.now().strftime("%Y-%m-%d")

                    try:
                        entries = load_vault(username, getattr(self, 'core_session_handle', None) or self.core_session_handle) or []
                    except TypeError:
                        entries = load_vault(username) or []

                    fp = (
                        (new_entry.get("title") or new_entry.get("Name") or ""),
                        (new_entry.get("username") or new_entry.get("User") or ""),
                        (new_entry.get("url") or new_entry.get("URL") or ""),
                    )
                    exists = any(
                        (
                            (e.get("title", "") or e.get("Name", "")),
                            (e.get("username", "") or e.get("User", "")),
                            (e.get("url", "") or e.get("URL", "")),
                        ) == fp for e in entries
                    )
                    if exists:
                        nk = next((k for k in ("Notes", "notes") if k in new_entry), "Notes")
                        new_entry[nk] = (str(new_entry.get(nk, "")) + "\n[imported from features.share]").strip()

                    entries.append(new_entry)
                    try:
                        save_vault(username, getattr(self, 'core_session_handle', None) or self.core_session_handle, entries)
                    except TypeError:
                        save_vault(username, entries)

                    self._on_any_entry_changed()
                    try: self.load_vault_table()
                    except Exception: pass
                    try:
                        update_baseline(username=username, verify_after=False, who="Vault Entry")
                    except Exception:
                        pass

                    accepted_flag["ok"] = True
                return

            QTimer.singleShot(0, run_prefill)

            nonlocal_ref = {"ref": None}
            ref_win = self._open_reference_window(mapped, title=self.tr("Reference — Mapped Values"), on_autofill=run_prefill)
            nonlocal_ref["ref"] = ref_win

            editor.setWindowModality(Qt.WindowModality.NonModal)
            editor.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)

            def _on_finished(code: int) -> None:
                try:
                    if nonlocal_ref["ref"]:
                        nonlocal_ref["ref"].close()
                except Exception:
                    pass
                if code != int(editor.DialogCode.Accepted):
                    return
                new_entry = editor.get_entry_data() or {}
                new_entry["category"] = target
                new_entry["Type"] = target
                new_entry["Date"] = dt.datetime.now().strftime("%Y-%m-%d")

                try:
                    entries = load_vault(username, getattr(self, 'core_session_handle', None) or self.core_session_handle) or []
                except TypeError:
                    entries = load_vault(username) or []

                fp = (
                    (new_entry.get("title") or new_entry.get("Name") or ""),
                    (new_entry.get("username") or new_entry.get("User") or ""),
                    (new_entry.get("url") or new_entry.get("URL") or ""),
                )
                exists = any(
                    (
                        (e.get("title", "") or e.get("Name", "")),
                        (e.get("username", "") or e.get("User", "")),
                        (e.get("url", "") or e.get("URL", "")),
                    ) == fp for e in entries
                )
                if exists:
                    nk = next((k for k in ("Notes", "notes") if k in new_entry), "Notes")
                    new_entry[nk] = (str(new_entry.get(nk, "")) + "\n[imported from features.share]").strip()

                entries.append(new_entry)
                try:
                    save_vault(username, getattr(self, 'core_session_handle', None) or self.core_session_handle, entries)
                except TypeError:
                    save_vault(username, entries)

                self._on_any_entry_changed()
                try: self.load_vault_table()
                except Exception: pass
                try:
                    update_baseline(username=username, verify_after=False, who="Category Vault Changed")
                except Exception:
                    pass

            editor.finished.connect(_on_finished)
            editor.show()
            editor.raise_()
            editor.activateWindow()

        except Exception as e:
            msg = self.tr("Could not open the edit form:\n{e}").format(e)
            QMessageBox.critical(self, self.tr("Import Share"), msg)
            try:
                if ref_win:
                    ref_win.close()
            except Exception:
                pass
            return

    btn_add.clicked.connect(do_add_to_category)
    btn_cancel.clicked.connect(dlg.reject)

    return dlg.exec() == QDialog.DialogCode.Accepted or bool(accepted_flag["ok"])


# minimal entry sanitization for plain share packets: remove any fields that are not basic strings or numbers,
# to avoid issues with QR encoding and to keep the payload small. 
# We allow only a flat dict with string keys and string/number values.
def _show_make_share_tip(self):
    if not self._get_hint_flag("show_make_share_tip", True):
        return
    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("How to Share (Zero-Knowledge)"))
    dlg.setModal(True)
    layout = QVBoxLayout(dlg)
    txt = (
        "<b>What this does</b><br>"
        "• Encrypts the selected entry with a one-time key.<br>"
        "• Wraps that key to the recipient’s public key from their Share ID.<br>"
        "• Produces a <code>.kqshare</code> file (and optional QR) that only they can open.<br><br>"
        "<b>How to use</b><br>"
        "1) Ask the recipient to send their <i>Share ID</i> (<code>.kqshareid</code>) first.<br>"
        "2) Click <i>Make Share Packet…</i>, pick their Share ID, then save or show QR.<br>"
        "3) The recipient opens your <code>.kqshare</code> via <i>Import Share Packet…</i> after logging in.<br><br>"
        "<b>Notes</b><br>"
        "• No server can decrypt; only the recipient’s private key works.<br>"
        "• Import will add the entry into their vault (you keep your copy)."
    )
    lbl = QLabel(txt, dlg); lbl.setTextFormat(Qt.TextFormat.RichText); lbl.setWordWrap(True)
    layout.addWidget(lbl)
    chk = QCheckBox(self.tr("Don’t show this tip again"), dlg)
    layout.addWidget(chk)
    btns = QHBoxLayout()
    ok = QPushButton(self.tr("OK"), dlg)
    ok.setDefault(True)
    btns.addStretch(1); btns.addWidget(ok); layout.addLayout(btns)
    ok.clicked.connect(dlg.accept); dlg.exec()
    if chk.isChecked(): self._set_hint_flag("show_make_share_tip", False)

# STRICT NATIVE: share packets require raw asymmetric key material; disable until migrated to native.
def quick_share_qr(self):
    """
    Fileless, encrypted quick share to *my* Share ID.
    - Uses the currently selected entry (single).
    - No file saved; just shows a QR (may be multi-page if large).
    - Adds policy.expires_at = now+5min (soft; future-enforceable).
    """
    try:
        username = (self.currentUsername.text() if hasattr(self, "currentUsername") else "").strip()
        if not (isinstance(getattr(self, 'core_session_handle', None), int) and getattr(self, 'core_session_handle', 0) > 0) or not username:
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
                all_entries = load_vault(username, self.core_session_handle) or []
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
        pub_bundle, priv_x, priv_ed = ensure_share_keys(username, self.core_session_handle)

        # Use *my own* public key as recipient (no selection needed)
        recipient_pub_x = pub_bundle.get("pub_x25519")
        recipient_id = f"{username}@this-device"

        # Soft expiry 5 minutes from now (not enforced yet; future-ready)
        expires_at = (dt.datetime.utcnow() + dt.timedelta(minutes=5)).replace(microsecond=0).isoformat() + "Z"

        packet = zk_make_share_packet(
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

# Backward-compatible alias (older UI code may call this name)
# We can remove this alias once all UI code is updated to call make_share_packet directly.
build_share_packet = make_share_packet
