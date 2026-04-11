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
from app.qt_imports import *
from auth.login.login_handler import get_user_setting
from security.secure_audit import (get_audit_file_path, audit_file, audit_mirror_file, user_lock_flag_path,
                                   log_event_encrypted, tamper_log_file, read_audit_log,)

# ================
# = audit log management: load and delete =
# ================

# Delete all Phase-2 audit logs for the current user, including encrypted files, lockout flag, and tamper log. Then re-initialize with a fresh entry.
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

    username = self._active_username()
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

# Load the audit log entries for the current user and populate the audit table. This includes merging pre-auth and post-auth events, handling secure entries, and detecting tampering.
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

# Export the user's audit log to a UTF-8 .txt file, with a simple tab-separated format.
#  Reads directly from the source to include all entries.
def on_export_audit_clicked(self, *args, **kwargs):
    self.set_status_txt(self.tr("Exporting"))
    """
    Export the user's audit log to a UTF-8 .txt (tab-separated).
    Uses read_audit_log(username) so it exports ALL entries, not just visible rows.
    """
    user = self._active_username()
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
