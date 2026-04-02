from vault_store.vault_store import add_vault_entry, load_vault, save_vault
from app.qt_imports import *
from app.paths import pw_cache_file, trash_path
import datetime as dt 
from security.baseline_signer import update_baseline
import hmac, hashlib
import secrets
from vault_store.vault_store import delete_vault_entry

# --- strict DLL-only JSON stores (encrypted with native session key) -------------------
_KQJ_MAGIC = b"KQJ1"  # Keyquorum JSON v1 (session-encrypted)
_KQJ_IV_LEN = 12
_KQJ_TAG_LEN = 16

# --- Trash Delete
TRASH_KEEP_DAYS_DEFAULT = 30  # can be overridden by env KQ_TRASH_KEEP_DAYS # NOTE: Might add to setting


# ====================================
# = Delete Entry / Trash Management / PW History Helpers 
# ====================================


def _session_json_write(path: str | os.PathLike, session_handle: int, label: bytes, obj: dict | list) -> None:
    """Write an encrypted JSON file using the native DLL session key (no Python crypto)."""
    if not isinstance(session_handle, int) or session_handle <= 0:
        raise TypeError("session_handle must be a valid native session handle (int)")
    if not isinstance(label, (bytes, bytearray)) or not label:
        raise TypeError("label must be non-empty bytes")

    from native.native_core import get_core
    core = get_core()

    p = str(path)
    os.makedirs(os.path.dirname(p), exist_ok=True)

    payload = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    iv = os.urandom(_KQJ_IV_LEN)
    ct_ba, tag_ba = core.session_encrypt(session_handle, iv, payload)

    # Format:
    #   magic(4) | label_len(u16be) | label | iv(12) | tag(16) | ct
    if len(label) > 65535:
        raise ValueError("label too long")
    header = _KQJ_MAGIC + len(label).to_bytes(2, "big") + bytes(label)
    blob = header + iv + bytes(tag_ba) + bytes(ct_ba)

    tmp = p + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
        try:
            f.flush(); os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp, p)
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def _session_json_read(path: str | os.PathLike, session_handle: int, label: bytes) -> dict | list:
    """Read an encrypted JSON file using the native DLL session key (no Python crypto)."""
    if not isinstance(session_handle, int) or session_handle <= 0:
        raise TypeError("session_handle must be a valid native session handle (int)")
    if not isinstance(label, (bytes, bytearray)) or not label:
        raise TypeError("label must be non-empty bytes")

    from native.native_core import get_core
    core = get_core()

    p = str(path)
    if not os.path.exists(p):
        return {}

    data = pathlib.Path(p).read_bytes()
    if not data.startswith(_KQJ_MAGIC) or len(data) < 4 + 2 + _KQJ_IV_LEN + _KQJ_TAG_LEN:
        # Legacy format (Python HKDF/AESGCM). In strict DLL-only mode we do NOT decrypt it.
        # Preserve it for manual recovery / debugging and start fresh.
        try:
            legacy = p + ".legacy"
            if not os.path.exists(legacy):
                os.replace(p, legacy)
        except Exception:
            pass
        return {}

    off = 4
    lab_len = int.from_bytes(data[off:off+2], "big"); off += 2
    if lab_len <= 0 or off + lab_len + _KQJ_IV_LEN + _KQJ_TAG_LEN > len(data):
        return {}
    lab = data[off:off+lab_len]; off += lab_len
    if bytes(lab) != bytes(label):
        return {}

    iv = data[off:off+_KQJ_IV_LEN]; off += _KQJ_IV_LEN
    tag = data[off:off+_KQJ_TAG_LEN]; off += _KQJ_TAG_LEN
    ct  = data[off:]

    pt_ba = core.session_decrypt(session_handle, iv, ct, tag)
    try:
        txt = bytes(pt_ba).decode("utf-8")
        return json.loads(txt)
    finally:
        try:
            core.secure_wipe(pt_ba)
        except Exception:
            pass


# ==============================
# -- PW History (encrypted)
# ==============================
def migrate_pw_cache(
    *,
    username: str,
    old_session_handle: int | None,
    new_session_handle: int | None,
) -> tuple[bool, str]:
    """
    Migrate the password restore cache from old DLL session -> new DLL session.

    DLL-only:
    - reads with old_session_handle
    - writes with new_session_handle
    - no Python crypto fallback
    """
    try:
        old_sess = int(old_session_handle) if old_session_handle else 0
        new_sess = int(new_session_handle) if new_session_handle else 0
    except Exception:
        return False, "Invalid session handle(s)."

    if old_sess <= 0 or new_sess <= 0:
        return False, "Missing old/new session handle."

    if old_sess == new_sess:
        return True, "PW cache migration skipped (same session)."

    try:
        # Read existing cache using OLD session
        data = _pwlast_load(username, old_sess) or {}

        # If nothing there, that's fine
        if not isinstance(data, dict) or not data:
            return True, "PW cache empty; nothing to migrate."

        # Write exact same data using NEW session
        _pwlast_save(username, new_sess, data)
        return True, f"Migrated {len(data)} pw cache item(s)."

    except Exception as e:
        return False, f"PW cache migration failed: {e}"


def _pwcache_path(username: str, ensure_parent=False) -> str:
    # Ensure parent exists and always return a string path
    return str(pw_cache_file(username, ensure_parent=ensure_parent))


def _pwlast_load(username: str, user_key: int) -> dict:
    # Strict DLL-only: user_key is the native session handle.
    label = f"pwcache:{username}".encode("utf-8")
    pw_load = _session_json_read(_pwcache_path(username), int(user_key), label)
    return pw_load or {}


def _pwlast_save(username: str, user_key: int, obj: dict) -> None:
    label = f"pwcache:{username}".encode("utf-8")
    _session_json_write(_pwcache_path(username, True), int(user_key), label, obj or {})


def _pwlast_put(username: str, user_key: int, entry_id: str, old_pw: str):
    """Store exactly ONE previous password for this entry (secure restore cache).

    Strict DLL-only: the cache file is encrypted with the native session key
    via _session_json_write/_session_json_read (AES-GCM in the DLL). We do NOT
    derive subkeys or compute HMACs in Python here.

    This is used only for a single-step restore/undo if a password change breaks
    something.
    """
    try:
        if not (entry_id and old_pw and user_key):
            return
        d = _pwlast_load(username, int(user_key)) or {}
        d[str(entry_id)] = {
            "ts": dt.datetime.now().isoformat(timespec="seconds") + "Z",
            "pw": str(old_pw),
        }
        _pwlast_save(username, int(user_key), d)
    except Exception:
        # Never break save flows because restore-cache failed
        return


def _pwlast_get(username: str, user_key: bytes, entry_id: str, *, max_age_days: int = 90) -> str | None:
    d = _pwlast_load(username, user_key)
    rec = d.get(str(entry_id))
    if not rec:
        return None
    try:
        t = dt.datetime.fromisoformat(rec.get("ts", "").replace("Z", ""))
        if t < dt.datetime.now() - dt.timedelta(days=max_age_days):
            return None
    except Exception:
        pass
    return rec.get("pw") or None


# ==============================
# -- Trash storage (encrypted)
# ==============================

def _header_texts_lower(self):
        out = []
        for c in range(self.vaultTable.columnCount()):
            hi = self.vaultTable.horizontalHeaderItem(c)
            out.append(hi.text().strip().lower() if hi else "")
        return out


def _find_col_by_labels(self, names: set[str]) -> int:
    want = {s.lower() for s in names}
    for i, t in enumerate(_header_texts_lower(self,)):
        if t in want:
            return i
    return -1


def delete_selected_vault_entry(self, *args, **kwargs):
    """
    Delete the selected vault entry, with a confirmation dialog offering 
    "Move to Trash" (soft delete with 30-day retention) vs "Delete Permanently". Refresh the table and baseline after deletion.
    """
    self.set_status_txt(self.tr("Delete selected vault entry"))
    log.debug(str(f"{kql.i('vault')} [VAULT] delete selected vault entry"))
    self.reset_logout_timer()

    try:
        tbl = self.vaultTable
        row = tbl.currentRow()
        if row < 0:
            return

        # Map visible row -> real vault index
        try:
            global_index = self.current_entries_indices[row]
        except Exception:
            global_index = row

        # nice name in the prompt
        title_col = _find_col_by_labels(self, {"title", "site", "website", "name"})
        entry_name = ""
        try:
            if isinstance(title_col, int) and title_col >= 0:
                it = tbl.item(row, title_col)
                entry_name = (it.text() if it else "").strip()
        except Exception:
            pass

        # Build a 3-option dialog: Trash / Delete Permanently / Cancel
        box = QtWidgets.QMessageBox(self)
        box.setIcon(QtWidgets.QMessageBox.Icon.Warning)
        box.setWindowTitle(self.tr("Delete Entry"))
        msg = self.tr("Delete this entry?")
        if entry_name:
            msg = self.tr('Delete "{entry_name}"?').format(entry_name=entry_name)
        box.setText(msg)

        btn_trash = box.addButton(self.tr("Move to Trash (30 days)"), QtWidgets.QMessageBox.ButtonRole.AcceptRole)
        btn_perm  = box.addButton(self.tr("Delete Permanently"), QtWidgets.QMessageBox.ButtonRole.DestructiveRole)
        btn_cancel= box.addButton(self.tr("Cancel"), QtWidgets.QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(btn_trash)
        box.exec()

        clicked = box.clickedButton()
        if clicked is btn_cancel:
            return

        username = self.currentUsername.text()
        key=(getattr(self, 'core_session_handle', None) or self.core_session_handle)

        ok = False
        if clicked is btn_trash:
            # Soft delete → goes to encrypted trash with timestamp
            try:

                ok, err = soft_delete_entry(self, username, key, global_index)
                if not ok:
                    # Show the specific reason (helps debug)
                    try:
                        QtWidgets.QMessageBox.warning(
                            self,
                            self.tr("Move to Trash"),
                            self.tr("Could not move this entry to Trash.") + (f"{err}" if err else ""))
                    except Exception:
                        pass
            except Exception as e:
                log.error(f"[Trash] soft delete failed: {e}")
                ok = False
            if ok:
                try:
                    # purge old trash items now
                    purged = purge_trash(username, key, max_age_days=30)
                    if purged:
                        log.debug(f"[Trash] auto-purged {purged} old trashed item(s)")
                except Exception:
                    pass
        else:
            # Permanent delete
            try:
                delete_vault_entry(username, key, global_index)
                self._on_any_entry_changed()
                ok = True
            except TypeError:
                # some versions require extra arg
                delete_vault_entry(username, key, global_index)
                self._on_any_entry_changed()
                ok = True
            except Exception as e:
                log.error(f"[VAULT] hard delete failed: {e}")
                ok = False

        # Refresh UI
        if ok:
            try: 
                update_baseline(username=username, verify_after=False, who=f"Delete Entry From Vault")
            except Exception: pass
            try: self.load_vault_table()
            except Exception: pass
            try:
                if hasattr(self, "_watchtower_rescan"):
                    self._watchtower_rescan()
            except Exception:
                pass

            # Tiny toast
            try:
                if clicked is btn_trash:
                    self._toast(self.tr("Moved to Trash (kept up to 30 days)."))
                else:
                    self._toast(self.tr("Entry deleted permanently."))
            except Exception:
                pass
        else:
            QtWidgets.QMessageBox.critical(self, self.tr("Delete"), self.tr("Could not delete this entry."))
        log.debug(str(f"{kql.i('vault')} [VAULT] Removed from vault (ok={ok})"))
    except Exception as e:
        self.reset_logout_timer()
        log.error(str(f"{kql.i('vault')} [ERROR] {kql.i('err')} deleting vault entry: {e}"))
        QtWidgets.QMessageBox.warning(self, self.tr("Error"), self.tr("Failed to delete the selected entry. Please try again."))


def show_trash_manager(self):
    """
    Trash Manager (accessed via main menu) — lists soft-deleted items with options to Restore or Permanently Delete
    Open a modal dialog that lists soft-deleted items (Trash).
    Users can Restore, Delete Permanently, or Empty Trash.
    Requires: _trash_load/_trash_save, restore_from_trash, restore_from_trash_index, purge_trash
    _toast, _watchtower_rescan
    """
    self.set_status_txt(self.tr("Opening Trash"))
    username = self.currentUsername.text()
    key=(getattr(self, 'core_session_handle', None) or self.core_session_handle)

    # --- helpers -----------

    def _selected_uid():
        r = tbl.currentRow()
        if r < 0:
            return None
        it = tbl.item(r, 5)  # hidden column
        return it.data(int(Qt.ItemDataRole.UserRole)) if it else None

    def _trash_entry_by_uid(uid: str):
        trash = _trash_load(username, key) or []
        for e in trash:
            if str(e.get("_trash_uid") or "") == str(uid):
                return e
        return None

    def on_preview():
        uid = _selected_uid()
        if not uid:
            QMessageBox.information(self, self.tr("Preview"), self.tr("Select an item to preview."))
            return

        rec = _trash_entry_by_uid(uid)
        if not rec:
            QMessageBox.warning(dlg, self.tr("Preview"), self.tr("Couldn’t load this item from Trash."))
            return

        pv   = rec.get("_preview") or {}
        safe = self._redact_for_preview(rec) if hasattr(self, "_redact_for_preview") else rec

        v = QDialog(self)
        v.setWindowTitle(self.tr("Trash Item — Preview"))
        v.resize(640, 480)
        layv = QVBoxLayout(v)

        hdr  = (pv.get("kind") or "item").capitalize()
        title = pv.get("title") or "(untitled)"
        lbl = QtWidgets.QLabel(f"<b>{hdr}</b> — {title}")
        layv.addWidget(lbl)

        txt = QtWidgets.QPlainTextEdit(v)
        txt.setReadOnly(True)
        txt.setPlainText(json.dumps(safe, indent=2, ensure_ascii=False))
        layv.addWidget(txt)

        row = QHBoxLayout()
        btnClose = QPushButton(self.tr("Close"))
        row.addStretch(1)
        row.addWidget(btnClose)
        layv.addLayout(row)
        btnClose.clicked.connect(v.accept)

        v.exec()

    def _parse_iso(ts: str):
        if not ts:
            return None
        s = ts.strip().replace("Z", "")
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return dt.datetime.strptime(s, fmt)
            except Exception:
                pass
        try:
            return dt.datetime.fromisoformat(s)
        except Exception:
            return None

    def _load_rows():
        trash = _trash_load(username, key) or []
        # newest first
        try:
            trash.sort(key=lambda e: _parse_iso(e.get("_deleted_at") or "") or dt.datetime.min, reverse=True)
        except Exception:
            pass
        return trash

    # --- dialog ------------
    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Trash (kept up to 30 days)"))
    dlg.resize(820, 420)

    lay = QVBoxLayout(dlg)

    tbl = QTableWidget(0, 6, dlg)
    tbl.setHorizontalHeaderLabels(["Deleted At", "Kind", "Title", "Username", "URL", "ID"])
    tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    tbl.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    tbl.setAlternatingRowColors(True)
    tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    lay.addWidget(tbl)

    # Single, final version of refresh:
    def _refresh_table():
        rows = _load_rows()
        tbl.setRowCount(len(rows))
        for r, e in enumerate(rows):
            pv    = e.get("_preview") or {}
            title = pv.get("title") or (e.get("title") or e.get("site") or e.get("name") or "(untitled)")
            user  = pv.get("username") or (e.get("username") or e.get("user") or e.get("email") or "")
            url   = pv.get("url") or (e.get("url") or e.get("origin") or "")
            kind  = pv.get("kind") or "login"
            when  = e.get("_deleted_at") or ""
            rid   = str(e.get("id") or e.get("_id") or e.get("row_id") or "")
            uid = str(e.get("_trash_uid") or "")

            it_when  = QTableWidgetItem(when)
            it_kind  = QTableWidgetItem(kind)
            it_title = QTableWidgetItem(title)
            it_user  = QTableWidgetItem(user)
            it_url   = QTableWidgetItem(url)

            tip = (
                f"Deleted: {when}\n"
                f"Kind: {kind}\n"
                f"Title: {title}\n"
                f"Username: {user or '(none)'}\n"
                f"URL: {url or '(none)'}"
            )
            for it in (it_when, it_kind, it_title, it_user, it_url):
                it.setToolTip(tip)

            tbl.setItem(r, 0, it_when)
            tbl.setItem(r, 1, it_kind)
            tbl.setItem(r, 2, it_title)
            tbl.setItem(r, 3, it_user)
            tbl.setItem(r, 4, it_url)

            id_item = QTableWidgetItem(uid or rid)  # show something if you ever unhide
            id_item.setData(int(Qt.ItemDataRole.UserRole), uid)          # <<< primary: uid
            id_item.setData(int(Qt.ItemDataRole.UserRole)+1, rid)        # optional: legacy id
            tbl.setItem(r, 5, id_item) 

        tbl.setColumnHidden(5, True)
        try:
            tbl.resizeColumnsToContents()
            tbl.horizontalHeader().setStretchLastSection(True)
        except Exception:
            pass
        if rows:
            try: tbl.selectRow(0)
            except Exception: pass

    # actions

    def _selected_ref():
        r = tbl.currentRow()
        if r < 0:
            return None
        it = tbl.item(r, 5)  # hidden id column
        uid = it.data(int(Qt.ItemDataRole.UserRole)) if it else None
        return uid

    def on_restore():
        uid = _selected_ref()
        if not uid:
            QMessageBox.information(dlg, dlg.tr("Restore"), dlg.tr("Select an item to restore."))
            return
        ok = bool(restore_from_trash_uid(self, username, key, uid))
        if ok:
            try: self._toast("Restored from Trash.")
            except Exception: pass
            try: 
                update_baseline(username=username, verify_after=False, who="Trash Vault changed")
            except Exception: pass
            try: self.load_vault_table()
            except Exception: pass
            try:
                if hasattr(self, "_watchtower_rescan"):
                    self._watchtower_rescan()
            except Exception: pass
            _refresh_table()
        else:
            
            QMessageBox.warning(self, self.tr("Restore"), self.tr("Failed to restore the entry."))

    def on_delete_perm():
        r = tbl.currentRow()
        if r < 0:
            QMessageBox.information(self, self.tr("Delete"), self.tr("Select an item to delete permanently."))
            return
        if QMessageBox.question(
            self, self.tr("Delete Permanently"),
            self.tr("This will remove the item from Trash forever. Continue?")
        ) != QMessageBox.StandardButton.Yes:
            return

        uid = _selected_ref()
        idx = tbl.currentRow()
        trash = _trash_load(username, key) or []

        removed = False

        # Primary: delete by the Trash UID we store in UserRole
        if uid:
            new_trash = []
            for e in trash:
                if not removed and str(e.get("_trash_uid") or "") == str(uid):
                    removed = True
                    continue
                new_trash.append(e)
            trash = new_trash

        # Fallback: delete by index (row in the current sorted view)
        if not removed and idx is not None:
            try:
                idx = int(idx)
                if 0 <= idx < len(trash):
                    trash.pop(idx)
                    removed = True
            except Exception:
                pass

        if removed:
            _trash_save(username, key, trash)
            try:
                txt = self.tr("Deleted from Trash.")
                self._toast(txt)
                self.set_status_txt(txt)
            except Exception: pass
            _refresh_table()
        else:
            QMessageBox.warning(self, self.tr("Delete"), self.tr("Could not delete this item."))

    def on_empty_trash():
        if QMessageBox.question(
            self, self.tr("Empty Trash"), self.tr("Delete all items in Trash permanently?")
        ) != QMessageBox.StandardButton.Yes:
            return
        _trash_save(username, key, [])
        try: 
            txt = self.tr("Trash emptied.")
            self._toast(txt)
            self.set_status_txt(txt)
        except Exception: pass
        _refresh_table()

    # buttons
    btns = QHBoxLayout()
    btnRestore = QPushButton(self.tr("Restore"))
    btnDelete  = QPushButton(self.tr("Delete Permanently"))
    btnEmpty   = QPushButton(self.tr("Empty Trash"))
    btnClose   = QPushButton(self.tr("Close"))
    btnPreview = QPushButton(self.tr("Preview…"))
    btns.addWidget(btnRestore)
    btns.addWidget(btnDelete)
    btns.addStretch(1)
    btns.addWidget(btnEmpty)
    btns.addWidget(btnClose)
    btns.addWidget(btnPreview)
    lay.addLayout(btns)

    btnRestore.clicked.connect(on_restore)
    btnDelete.clicked.connect(on_delete_perm)
    btnEmpty.clicked.connect(on_empty_trash)
    btnClose.clicked.connect(dlg.accept)
    btnPreview.clicked.connect(on_preview)

    # initial load + opportunistic purge of old items (>30 days)
    try:
        purged = purge_trash(username, key, max_age_days=30)
        if purged:
            try: 
                txt = self.tr("Purged ") + f"{purged}" + self.tr(" expired item(s).")
                self._toast(txt)
                self.set_status_txt(txt)
            except Exception: pass
    except Exception:
        pass

    _refresh_table()
    dlg.exec()


def _trash_preview_for_entry(self, e: dict) -> dict:
    """
    Generate a small preview dict for an entry, with heuristics to determine kind and title, 
    for display in Trash or similar contexts where we don't want to show secrets but want a human-friendly summary.
    """
    def _norm(s): return (s or "").strip()
    cat = _norm(e.get("category") or e.get("Category"))
    keys = {k.lower() for k in e.keys()}

    cat_l = (cat.lower() if cat else "")
    cat_map = {
        "passwords":        "login",
        "software":         "license",
        "email accounts":   "email",
        "social media":     "login",
        "games":            "login",
        "streaming":        "login",
        "credit cards":     "credit_card",
        "banks":            "bank_account",
        "money":            "finance",
        "personal info":    "identity",
        "webfill":          "webform",
        "windows key":      "license",
        "mac":              "device",
        "app":              "login",
        "pins":             "pin",
        "wifi":             "wifi",
        "encrypted drives": "disk",
        "notes":            "note",
        "other":            "other",
        "temp accounts":    "login",
        "vpn config":       "vpn",
        "recovery codes":   "recovery",
        "ssh config":       "ssh",
        "ssh keys":         "ssh",
        "api keys":         "apikey",
        "crypto":           "crypto",
    }
    kind = cat_map.get(cat_l)

    # Heuristics if category missing/unknown
    if not kind:
        if {"card number","card_number","pan"} & keys:
            kind = "credit_card"
        elif {"iban","account","sort code","routing"} & keys:
            kind = "bank_account"
        elif {"otp","totp","2fa","secret"} & keys:
            kind = "otp"
        elif {"ssid"} & keys:
            kind = "wifi"
        elif {"api key","api_key","token","access_key"} & keys:
            kind = "apikey"
        elif {"ssh_private","ssh_public","private_key","public_key"} & keys:
            kind = "ssh"
        else:
            kind = "login"

    # Title (nice defaults for special kinds)
    title = _norm(e.get("title") or e.get("site") or e.get("name"))
    if not title and kind == "credit_card":
        # show brand + last4
        try:
            pan = e.get("card_number") or e.get("Card Number") or e.get("card") or ""
            if hasattr(self, "_card_brand_last4"):
                brand, last4 = self._card_brand_last4(pan)
            else:
                brand, last4 = "Card", _norm(pan)[-4:]
            title = f"{brand} ••••{last4}" if last4 else brand
        except Exception:
            title = "Card"
    if not title and kind == "wifi":
        title = _norm(e.get("ssid") or "Wi-Fi")
    if not title and kind == "license":
        title = _norm(e.get("product") or e.get("software") or "License")
    if not title and kind == "vpn":
        title = _norm(e.get("provider") or e.get("server") or "VPN")
    if not title:
        title = "(untitled)"

    username = _norm(e.get("username") or e.get("user") or e.get("email"))
    url      = _norm(e.get("url") or e.get("origin") or e.get("website"))

    return {"title": title, "username": username, "url": url, "kind": kind}


def soft_delete_entry(self, username: str, user_key: bytes, index: int) -> tuple[bool, str]:
    """
    Soft delete an entry: move it to the encrypted Trash store with a timestamp, then remove from vault.
    """
    log.debug("[TRASH] soft_delete_entry start index=%s", index)

    # 1) Load vault & pick record
    try:
        
        rows = load_vault(username, user_key) or []
        if not (0 <= index < len(rows)):
            return False, self.tr("index out of range (index=") + f"{index}, " + self.tr("rows=") + f"{len(rows)})"
        entry = dict(rows[index])
    except Exception as e:
        log.exception("[TRASH] load_vault failed")
        return False, self.tr("load_vault error: ") + f"{e}"

    # 2) Build preview (title, username, url, kind)
    try:
        preview = self._trash_preview_for_entry(entry)
    except Exception as e:
        log.debug("[TRASH] preview build failed: %s", e)
        preview = {
            "title": (entry.get("title") or entry.get("site") or entry.get("name") or "(untitled)"),
            "username": (entry.get("username") or entry.get("user") or entry.get("email") or ""),
            "url": (entry.get("url") or entry.get("origin") or ""),
            "kind": "login",
        }

    # 3) Append to encrypted trash
    try:
        trash = _trash_load(username, user_key) or []
        rec = dict(entry)
        rec["_deleted_at"] = dt.datetime.now().isoformat(timespec="seconds")
        rec["_preview"] = preview
        rec["_trash_uid"]  = secrets.token_hex(8)   # - add id to item for restore
        trash.append(rec)
        _trash_save(username, user_key, trash)
        log.debug("[TRASH] saved to trash (count=%s)", len(trash))
    except Exception as e:
        log.exception("[TRASH] _trash_save failed")
        return False, self.tr("_trash_save error:") + f" {e}"

    # 4) Remove from vault
    try:
        delete_vault_entry(username, user_key, index)
        log.debug("[TRASH] delete_vault_entry ok index=%s", index)
        self._on_any_entry_changed()
    except TypeError:
        # Some versions require force=True
        
        try:
            soft_delete_entry(self, username, user_key, index, True)
            self._on_any_entry_changed()
            log.debug("[TRASH] delete_vault_entry(force) ok index=%s", index)
        except Exception as e:
            log.exception("[TRASH] delete_vault_entry(force) failed")
            return False, self.tr("delete_vault_entry error:") + f" {e}"
    except Exception as e:
        log.exception("[TRASH] delete_vault_entry failed")
        return False, self.tr("delete_vault_entry error:") + f" {e}"

    return True, ""


def _trash_path(username: str, ensure_parent=False) -> str:
    return trash_path(username, ensure_parent=ensure_parent)


def _trash_load(username: str, user_key: int) -> list:
    """Load encrypted trash for this user (DLL-only session-encrypted JSON)."""
    try:
        label = b"trash:" + username.encode("utf-8")
        obj = _session_json_read(_trash_path(username), int(user_key), label)
        return obj or []
    except Exception as e:
        log.error(f"[TRASH] load failed for {username}: {e}")
        return []


def _trash_save(username: str, user_key: int, rows: list):
    """Save encrypted trash for this user (DLL-only session-encrypted JSON)."""
    try:
        label = b"trash:" + username.encode("utf-8")
        _session_json_write(_trash_path(username, True), int(user_key), label, rows or [])
    except Exception as e:
        log.error(f"[TRASH] save failed for {username}: {e}")
        raise


def on_move_to_trash_clicked(self):
    row = self.vaultTable.currentRow()
    if row < 0:
        QMessageBox.information(self, self.tr("Delete"), self.tr("Select an item to delete."))
        return

    # Map visible row → real vault index
    try:
        global_index = self.current_entries_indices[row]
    except Exception:
        global_index = row
    log.debug("[TRASH] UI row=%s -> global_index=%s", row, global_index)

    if QtWidgets.QMessageBox.question(
        self, self.tr("Move to Trash"),
        self.tr("This item will be moved to Trash and kept up to 30 days. Continue?")
    ) != QtWidgets.QMessageBox.StandardButton.Yes:
        return

    ok, why = soft_delete_entry(self, self.currentUsername.text(), self.core_session_handle, int(global_index))
    log.debug("[TRASH] soft_delete result ok=%s why='%s'", ok, why)

    if ok:
        try: self._toast(self.tr("Moved to Trash (kept up to 30 days)."))
        except Exception: pass
        try: 
            update_baseline(username=self.currentUsername.text(), verify_after=False, who="Trash Vault changed")
        except Exception: pass
        try: self.load_vault_table()
        except Exception: pass
        try:
            self._watchtower_rescan(self)
        except Exception: pass
    else:
        msg = self.tr("Could not delete this entry.\n\n") + f"{why}"
        QtWidgets.QMessageBox.critical(self, self.tr("Delete"), msg)


def restore_from_trash_uid(self, username: str, key: bytes, uid: str) -> bool:       # - restore from trash using uid
    if not self._require_unlocked():
        return False
    try:
        trash = _trash_load(username, key) or []
        picked_i = -1
        for i, e in enumerate(trash):
            if str(e.get("_trash_uid") or "") == str(uid):
                picked_i = i
                break
        if picked_i < 0:
            return False

        picked = trash.pop(picked_i)
        _trash_save(username, key, trash)

        picked.pop("_deleted_at", None)
        picked.pop("_trash_uid", None)
        try:

            add_vault_entry(username, key, picked)
            self._on_any_entry_changed()
        except Exception:
            rows = load_vault(username, key) or []
            rows.append(picked)
            save_vault(username, key, rows)
            self._on_any_entry_changed()
        return True
    except Exception:
        return False


def restore_from_trash_index(self, username: str, key: bytes, index_in_trash: int) -> bool:             # - restore from trash using index  remove
    """
    Restore a trashed item by its index within the trash list.
    Useful when the trashed item has no persistent id.
    """
    if not self._require_unlocked():
        return False
    try:
        trash = _trash_load(username, key) or []
        if not (0 <= int(index_in_trash) < len(trash)):
            return False
        # remove from trash
        picked = trash.pop(int(index_in_trash))
        _trash_save(username, key, trash)

        # add back to vault
        picked.pop("_deleted_at", None)
        try:
            add_vault_entry(username, key, picked)
            self._on_any_entry_changed()
        except Exception:
            # fallback if add_vault_entry not available
            rows = load_vault(username, key) or []
            rows.append(picked)
            save_vault(username, key, rows)
            self._on_any_entry_changed()
        return True
    except Exception as e:
        log.error(f"[Trash] restore_from_trash_index failed: {e}")
        return False


def restore_from_trash(self, username: str, key: bytes, match_id: str) -> bool:    # - find item to restore id 
    """
    Restore a trashed item by persistent id (id/_id/row_id) or fingerprint ('fp:...').
    """
    if not self._require_unlocked():
        return False
    try:
        trash = _trash_load(username, key) or []
        picked = None
        picked_i = -1

        # exact id match
        def _rid(e):
            return str(e.get("id") or e.get("_id") or e.get("row_id") or "")

        for i, e in enumerate(trash):
            if _rid(e) and _rid(e) == str(match_id):
                picked = e; picked_i = i
                break

        # fingerprint fallback
        if picked is None and str(match_id).startswith("fp:"):
            def _norm(s): 
                return (s or "").strip().lower()

            for i, e in enumerate(trash):
                t = _norm(e.get("title") or e.get("site") or e.get("name"))
                u = _norm(e.get("username") or e.get("user"))
                url = _norm(e.get("url") or e.get("origin"))
                pw = e.get("password") or e.get("Password") or ""

                # SECURITY NOTE:
                # Use keyed HMAC fingerprint instead of raw SHA256 hashing.
                # This is for deterministic restore matching, not password hashing.
                msg = f"{t}|{u}|{url}|{pw}".encode("utf-8")

                fp = "fp:" + hmac.new(
                    key,
                    msg,
                    hashlib.sha256
                ).hexdigest()

                if hmac.compare_digest(fp, str(match_id)):
                    picked = e
                    picked_i = i
                    break

        if picked is None:
            return False

        # remove from trash
        trash.pop(picked_i)
        _trash_save(username, key, trash)

        # add back to vault
        picked.pop("_deleted_at", None)
        try:
            add_vault_entry(username, key, picked)
            self._on_any_entry_changed()
        except Exception:
            rows = load_vault(username, key) or []
            rows.append(picked)
            save_vault(username, key, rows)
            self._on_any_entry_changed()
        return True
    except Exception as e:
        log.error(f"[Trash] restore_from_trash failed: {e}")
        return False


# NOTE add option to change this on updates (in settings add option to change days)
def _auto_purge_trash(self) -> int:  # - delete after 30 days
    """Purge trashed items older than TRASH_KEEP_DAYS; quiet if anything is missing."""
    try:
        username = self._active_username()
        if not username:
            return 0
        self.set_status_txt(self.tr("KQ TRASH: Time to delete? "))
        keep_days = int(os.getenv("KQ_TRASH_KEEP_DAYS", TRASH_KEEP_DAYS_DEFAULT))
        cutoff = dt.datetime.utcnow() - dt.timedelta(days=keep_days)
        trash = _trash_load(username) or []      # expects list of dicts
        keep, purge = [], []
        for it in trash:
            ts_str = (it.get("deleted_at") or it.get("ts") or it.get("deleted") or "")
            try:
                ts = dt.datetime.fromisoformat(ts_str.replace("Z",""))
            except Exception:
                # If no timestamp, treat as old → purge
                ts = dt.datetime(1970,1,1)
            (purge if ts < cutoff else keep).append(it)
        if len(purge) == 0:
            return 0
        # Save trimmed trash
        _trash_save(username, keep)
        # log & rescan
        try:
            for it in purge:
                try:
                    log_event_encrypted(username, self.tr("trash_purge"), {"id": it.get("id") or it.get("uuid")})
                except Exception:
                    pass
                self._watchtower_rescan(self)
        except Exception:
            pass
        # quick heads-up
        try:
            if getattr(self, "_toast", None):
                txt = self.tr("Purged ") + f"{len(purge)}" + self.tr(" old item(s) from Trash.")
                self._toast(txt)
                self.set_status_txt(txt)
        except Exception:
            pass
        return len(purge)
    except Exception as e:
        log.error(f"[PURGED] Error emptying trash {e}")
        return 0


def _auto_purge_trash(self) -> int:
    """Purge old trash items using the current native session handle."""
    try:
        username = self._active_username()
        if not username:
            return 0

        key = getattr(self, "core_session_handle", None)
        if not isinstance(key, int) or key <= 0:
            return 0

        keep_days = int(os.getenv("KQ_TRASH_KEEP_DAYS", TRASH_KEEP_DAYS_DEFAULT))
        purged = purge_trash(username, key, max_age_days=keep_days)

        if purged:
            try:
                txt = self.tr("Purged ") + f"{purged}" + self.tr(" old item(s) from Trash.")
                if getattr(self, "_toast", None):
                    self._toast(txt)
                self.set_status_txt(txt)
            except Exception:
                pass

            try:
                if hasattr(self, "_watchtower_rescan"):
                    self._watchtower_rescan()
            except Exception:
                pass

        return purged

    except Exception as e:
        log.error(f"[PURGED] Error emptying trash {e}")
        return 0


def purge_trash(username: str, key: bytes, max_age_days: int = 30) -> int:   # - delete after 30 days
    """
    Remove soft-deleted items older than max_age_days from the encrypted trash.
    Return the number of items purged.
    """
    # After login/unlock
    trash = _trash_load(username, key)
    if not trash:
        return 0

    cutoff = dt.datetime.now() - dt.timedelta(days=max_age_days)

    def _parse_iso(ts: str):
        """Best-effort parse for ISO-like timestamps (no dateutil)."""
        if not ts:
            return None
        s = ts.strip().replace("Z", "")
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return dt.datetime.strptime(s, fmt)
            except Exception:
                pass
        try:
            return dt.datetime.fromisoformat(s)
        except Exception:
            return None

    def _deleted_at(entry) -> dt.datetime | None:
        return _parse_iso(entry.get("_deleted_at") or "")

    kept = [e for e in trash if (t := _deleted_at(e)) is None or t >= cutoff]
    purged = len(trash) - len(kept)
    if purged:
        _trash_save(username, key, kept)
    return purged


def _trash_preview_for_entry(self, *args, **kwargs):
    from vault_store.vault_ui_ops import _trash_preview_for_entry as _impl
    return _impl(self, *args, **kwargs)


def _redact_for_preview(entry: dict) -> dict: # - trash preview
    """
    Return a shallow copy with common secret fields masked.
    """
    secretish = {
        "password","Password","pwd","secret","otp","totp",
        "api_key","api key","token","access_key","private_key","ssh_private",
        "card_number","Card Number","cvv","cvc","pin","recovery key","recovery_key"
    }
    red = {}
    for k, v in (entry or {}).items():
        if isinstance(v, str) and k.lower() in secretish:
            red[k] = "••••••••"
        else:
            red[k] = v
    return red

