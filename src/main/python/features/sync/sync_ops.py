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
from shutil import copy2
from auth.login.login_handler import _canonical_username_ci, set_user_cloud, get_user_cloud
from app.paths import (
    vault_file,
    user_db_file,
    identities_file,
    catalog_file,
    vault_wrapped_file,
    trash_path,
    pw_cache_file,
    breach_cache,
    audit_file,
    audit_file_salt,
    audit_mirror_file,
    baseline_file)

import os, hashlib
from vault_store.vault_store import export_full_backup
from security.secure_audit import log_event_encrypted
from qtpy.QtWidgets import QFileDialog, QMessageBox, QLineEdit
from pathlib import Path
from auth.login.login_handler import get_user_setting, set_user_setting, stop_user_cloud
from security.baseline_signer import update_baseline
from qtpy.QtCore import QTimer
from qtpy.QtCore import QSettings
from pathlib import Path
from features.sync.engine import SyncEngine
from app.qt_imports import *


# ==============================
# Cloud Sync UI helpers
# ==============================

# These functions are used by the cloud sync UI (buttons, labels) to get/set user cloud profiles and sync state.
def _cloud_profile(username: str) -> dict:
    try:
        return get_user_cloud(username) or {}
    except Exception:
        return {}

# Sync state is kept separate from the user_db.json profile (which is baseline-tracked) to avoid polluting the baseline with frequently changing timestamps and hashes. Instead, we use QSettings for device-local sync state persistence.
def _kq_sync_state_get(username: str) -> dict:
    """Device-local sync timestamps/state (kept OUT of baseline-tracked user_db)."""
    try:
        u = (username or "").strip()
        qs = QSettings("AJH Software", "Keyquorum Vault")
        base = f"sync/{u}/"
        return {
            "last_sync_ts": int(qs.value(base + "last_sync_ts", 0) or 0),
            "last_pulled_ts": int(qs.value(base + "last_pulled_ts", 0) or 0),
            "last_pushed_ts": int(qs.value(base + "last_pushed_ts", 0) or 0),
            "last_local_sha256": str(qs.value(base + "last_local_sha256", "") or ""),
            "last_remote_sha256": str(qs.value(base + "last_remote_sha256", "") or ""),
            "last_remote_version": str(qs.value(base + "last_remote_version", "") or ""),
            "files_in_cloud": str(qs.value(base + "files_in_cloud", "") or ""),
        }
    except Exception:
        return {
            "last_sync_ts": 0,
            "last_pulled_ts": 0,
            "last_pushed_ts": 0,
            "last_local_sha256": "",
            "last_remote_sha256": "",
            "last_remote_version": "",
            "files_in_cloud": "",
        }

# Only set values that are not None to avoid accidentally wiping state with partial updates. (E.g., if the caller only has a new local hash, we don't want to wipe the remote hash or timestamps.)
def _kq_sync_state_set(username: str, **kwargs) -> None:
    try:
        u = (username or "").strip()
        qs = QSettings("AJH Software", "Keyquorum Vault")
        base = f"sync/{u}/"
        for k, v in kwargs.items():
            if v is None:
                continue
            qs.setValue(base + k, v)
    except Exception:
        pass

# Helper to format timestamps for display in the UI, with error handling to avoid crashes if the timestamp is invalid.
def _fmt_ts(ts: int) -> str:
    try:
        if not ts:
            return "Never"
        from datetime import datetime
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Never"

# Helper to configure the sync engine for a given user, with error handling and user feedback.
def on_toggle_extra_cloud_wrap(self, *args, **kwargs):
    self.set_status_txt(self.tr("Cloud wrap: applying…"))

    username = self._active_username()
    if not username:
        QMessageBox.warning(self, self.tr("Extra Cloud Wrap"), self.tr("Please log in first."))
        return

    if not getattr(self, "core_session_handle", None):
        QMessageBox.warning(self, self.tr("Extra Cloud Wrap"), self.tr("Unlock your vault first."))
        return

    prof = get_user_cloud(username) or {}
    if not prof.get("enabled") or not (prof.get("remote_path") or "").strip():
        QMessageBox.information(self, self.tr("Extra Cloud Wrap"), self.tr("Cloud sync is not configured yet."))
        return

    new_state = not bool(prof.get("cloud_wrap"))

    try:
        if getattr(self, "_auto_sync_timer", None):
            self._auto_sync_timer.stop()
        if getattr(self, "_vault_watcher", None):
            self._vault_watcher.blockSignals(True)
    except Exception:
        pass
    self._sync_guard = True

    tmp_upload = None
    try:
        _configure_sync_engine(self, username, "on_toggle_extra_cloud_wrap")
        eng = getattr(self, "sync_engine", None)
        if eng is None:
            QMessageBox.information(self, self.tr("Extra Cloud Wrap"), self.tr("Choose a cloud vault file first."))
            return

        cfg, provider = eng.configured()
        sc = cfg.get("sync") or {}
        local_vault_path = str(vault_file(username, ensure_parent=True))

        # Always keep cloud sync on a dedicated .kqsync bundle path.
        rp = (sc.get("remote_path") or "").strip()
        if rp and not rp.lower().endswith((".kqsync", ".kqbndl", ".kqbundle")):
            rp = os.path.join(os.path.dirname(rp), f"{username}.kqsync").replace("\\", "/")
            sc["remote_path"] = rp
            sc["bundle"] = True
            cfg["sync"] = sc
            try:
                eng._save(cfg)
            except Exception:
                set_user_cloud(username, path=rp, bundle=True)
            _configure_sync_engine(self,username, "on_toggle_extra_cloud_wrap")
            eng = getattr(self, "sync_engine", None)
            cfg, provider = eng.configured()
            sc = cfg.get("sync") or {}

        local_path = local_vault_path
        if eng._is_bundle_mode(sc):
            local_path = eng._build_bundle(sc, local_vault_path)
            try:
                sc["files_in_cloud"] = ",".join(sorted(eng._get_bundle_map(sc, local_vault_path).keys()))
            except Exception:
                pass
        else:
            sc["files_in_cloud"] = "vault"

        upload_path = local_path
        if new_state:
            from features.sync.engine import wrap_encrypt
            import tempfile
            plain = Path(local_path).read_bytes()
            fd, tmp_upload = tempfile.mkstemp(prefix="kq_cloud_wrap_", suffix=".bin")
            os.close(fd)
            Path(tmp_upload).write_bytes(wrap_encrypt(self.core_session_handle, plain))
            upload_path = tmp_upload

        provider.upload_from(sc, upload_path)

        # Persist the NEW wrap state after the remote has been rewritten.
        set_user_cloud(
            username,
            enable=bool(sc.get("enabled") or sc.get("sync_enable")),
            provider=sc.get("provider") or "localpath",
            path=sc.get("remote_path") or "",
            wrap=new_state,
            bundle=bool(sc.get("bundle", True)),
            sync_enable=bool(sc.get("sync_enable", sc.get("enabled", False))),
        )

        # Reset local pairing state so the next sync compares against the rewritten remote cleanly.
        try:
            _kq_sync_state_set(
                username,
                last_local_sha256="",
                last_remote_sha256="",
                last_remote_version="",
                files_in_cloud=sc.get("files_in_cloud") or ("vault" if not eng._is_bundle_mode(sc) else ""),
            )
        except Exception:
            pass

        _configure_sync_engine(self, username, "on_toggle_extra_cloud_wrap")
        verify_res = str(_cloud_sync_safe(self, self.core_session_handle, interactive=True) or "synced")
        _update_cloudsync_label(self, username, last_result=verify_res)

        QMessageBox.information(
            self,
            self.tr("Extra Cloud Wrap"),
            (self.tr("Enabled") if new_state else self.tr("Disabled")) + ".\n" +
            self.tr("Remote bundle rewritten successfully.") + "\n" +
            self.tr("Verification sync:") + f" {verify_res}"
        )
    except Exception as e:
        msg = self.tr("Wrap toggle failed:") + f"\n{e}"
        log.info(f"Extra Cloud Wrap: {e}")
        QMessageBox.critical(self, self.tr("Extra Cloud Wrap"), msg)
    finally:
        try:
            if tmp_upload and os.path.exists(tmp_upload):
                os.remove(tmp_upload)
        except Exception:
            pass
        try:
            if getattr(self, "_vault_watcher", None):
                self._vault_watcher.blockSignals(False)
        except Exception:
            pass
        self._sync_guard = False
        try:
            _watch_local_vault(self,)
            _schedule_auto_sync(self,)
        except Exception:
            pass

        update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Cloud Wrap")) 
        self.set_status_txt(self.tr("Cloud wrap: done"))

# This is the "One-Time Mobile Transfer" feature that creates a password-protected transfer package for securely moving vault data to Android. It includes pre-checks, password input, cloud folder selection, and uses the export_full_backup helper to create an encrypted .zip.enc file. Clear instructions are shown to the user after creation.
def one_time_mobile_transfer(self):
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

# Helper to update the Cloud Sync info label in the UI with the latest sync state and profile info. This is called after sync operations to reflect the current status, timestamps, and any results. It reads from both the user cloud profile and the local sync state stored in QSettings.
def _update_cloudsync_label(self, username: str, *, last_result: str | None = None) -> None:
    """Update the Cloud Sync info label (QLabel objectName='cloudsync') if present."""
    try:
        prof = _cloud_profile(username)
        provider = (prof.get("provider") or "localpath")
        remote_path = (prof.get("remote_path") or "").strip()
        wrap = bool(prof.get("cloud_wrap", False))
        sync_enable = bool(
            prof.get("sync_enabled",
            prof.get("sync_enable",
            prof.get("enabled", False))))

        if last_result:
            try:
                import time as _time
                _now = int(_time.time())
                _lr = str(last_result or "").lower()
                updates = {"last_sync_ts": _now}
                if "pull" in _lr:
                    updates["last_pulled_ts"] = _now
                if "push" in _lr:
                    updates["last_pushed_ts"] = _now
                _kq_sync_state_set(username, **updates)
            except Exception:
                pass

        st = _kq_sync_state_get(username)
        last_ts = int(st.get("last_sync_ts", 0) or 0)
        last_pull = int(st.get("last_pulled_ts", 0) or 0)
        last_push = int(st.get("last_pushed_ts", 0) or 0)
        last_local = (str(st.get("last_local_sha256", "")) or "")[:8]
        last_remote = (str(st.get("last_remote_sha256", "")) or "")[:8]

        files_in_cloud = (str(st.get("files_in_cloud", "")) or (prof.get("files_in_cloud") or "")).strip()
        if not files_in_cloud:
            files_in_cloud = "(unknown)"

        self.provid.setText(f"Provider: {provider}")
        self.selectfolder.setText(f"Selected Cloud: {remote_path or '(not set)'}")
        self.extrawrap.setText(f"Cloud Wrap: {'True' if wrap else 'False'}")
        self.auto_syncset.setText(f"Sync Enable: {'True' if sync_enable else 'False'}")
        self.file_in_cloud.setText(f"Files In Cloud: {files_in_cloud}")
        self.pushed_on.setText(f"Pushed On: {_fmt_ts(last_push)}")
        self.pulled_on.setText(f"Pulled On: {_fmt_ts(last_pull)}")
        self.synced_on.setText(f"Last Sync: {_fmt_ts(last_ts)}")
        self.statusloc.setText(f"State: local={last_local or '-'}")
        self.statusremote.setText(f"remote={last_remote or '-'}")

        lr = (str(last_result or "").strip() or "-")
        self.cloudsync.setText(
            f"Pushed: {_fmt_ts(last_push)}   "
            f"Pulled: {_fmt_ts(last_pull)}   "
            f"Last Sync: {_fmt_ts(last_ts)}   "
            f"Result: {lr}"
        )
    except Exception:
        pass

# Helper to enable/disable the cloud sync buttons in the UI based on whether cloud sync is active. This is called after enabling/disabling cloud sync to reflect the current state in the UI and prevent invalid actions.
def enable_buttons(self):
    """Enable cloud buttons"""
    self.autosync_.setChecked(True)
    self.autosync_.setEnabled(True)
    self.move_vault_to_cloud.setEnabled(False)
    self.extra_cloud_wrap.setEnabled(True)
    self.select_cloud.setEnabled(False)
    self.stop_cloud_sync.setEnabled(True)
    self.on_sync_now.setEnabled(True)  

# Helper to disable the cloud sync buttons in the UI when cloud sync is turned off. This prevents the user from trying to sync or configure cloud settings when cloud sync is not active.
def disable_buttons(self):
    """Disable cloud buttons"""
    self.autosync_.setChecked(False)
    self.autosync_.setEnabled(False)
    self.move_vault_to_cloud.setEnabled(True)
    self.extra_cloud_wrap.setEnabled(False)
    self.select_cloud.setEnabled(True)
    self.stop_cloud_sync.setEnabled(False)
    self.on_sync_now.setEnabled(False)

# Event handler for when the user toggles the "Auto Sync" checkbox in the UI. This function updates the user's cloud profile with the new sync enable state, configures the sync engine accordingly, and optionally triggers an immediate sync if auto sync is turned on. It also updates the UI and baseline after making changes.
def on_autosync_clicked(self, checked: bool) -> None:
    self.set_status_txt(self.tr("Auto Sync to users Cloud"))
    username = self._active_username()
    if not username:
        return

    prof = get_user_cloud(username) or {}

    # Store user preference (recommended)
    try:
        set_user_setting(username, "auto_sync", bool(checked))
    except Exception:
        pass

    # Mirror to cloud profile
    set_user_cloud(
        username=username,
        enable=bool(prof.get("enabled")), 
        provider=(prof.get("provider") or "localpath"),
        path=(prof.get("remote_path") or ""),
        wrap=bool(prof.get("cloud_wrap")),
        sync_enable=bool(checked),
    )

    # Keep checkbox in sync without re-triggering
    try:
        self.autosync_.blockSignals(True)
        self.autosync_.setChecked(bool(checked))
        self.autosync_.blockSignals(False)
    except Exception:
        pass

    # Ensure engine exists & configured, then optionally kick a silent sync
    try:
        if not hasattr(self, "sync_engine") or self.sync_engine is None:
            _configure_sync_engine(self, username, "on_autosync_clicked")
        if self.sync_engine and self.sync_engine.configured() and checked:
            self.sync_engine.sync_now(self.core_session_handle, interactive=False)
            _watch_local_vault(self,)

        elif not checked and hasattr(self, "_vault_watcher") and self._vault_watcher:
            self._vault_watcher.deleteLater()
            self._vault_watcher = None
        update_baseline(username=username, verify_after=False, who=self.tr("Cloud Sync Settings Changed"))

    except Exception as e:
        if "Sync not configured" in str(e):
            QMessageBox.information(
                    self, self.tr("Sync"),
                    self.tr("Cloud Sync not enabled goto Backup/Restore -> Move To Cloud to Enable"))
            self.autosync_.setChecked(False)
        else:
            log.debug(f"[AUTO-SYNC] setup failed: {e}")
    self.set_status_txt(self.tr("Done"))

# Event handler for when the user clicks the "Sync Now" button in the UI. This function performs a manual sync operation with the cloud, providing user feedback on the sync status and result. It checks that the user is logged in, that cloud sync is enabled, and that the sync engine is configured before attempting to sync. After syncing, it updates the UI with the result and refreshes the integrity baseline if needed.
def on_button_sync_cloud(self):
    try:
        self.set_status_txt(self.tr("Cloud: syncing…"))

        username = self._active_username()
        if not username:
            QMessageBox.information(self, self.tr("Cloud sync"), self.tr("Please log in first."))
            return

        prof = _cloud_profile(username)
        _cloud_on_from_profile = prof.get("enabled", False)
        if not _cloud_on_from_profile:
            QMessageBox.information(self, self.tr("Cloud sync"), self.tr("Cloud Sync is not enabled."))
            _update_cloudsync_label(self, username, last_result="disabled")
            return

        if not username:
            QMessageBox.information(self, self.tr("Cloud sync"), self.tr("Please log in first."))
            return

        # Always (re)build the engine so its closures bind to THIS username
        _configure_sync_engine(self, username, "on_button_sync_cloud")

        eng = getattr(self, 'sync_engine', None)

        if (eng is None) or (not eng.configured()):
            QMessageBox.information(
                self, self.tr("Cloud sync"),
                self.tr("Sync engine is not configured. Choose a cloud vault file first."))
            return

        key = getattr(self, 'core_session_handle', None)
        if not key:
            QMessageBox.information(self, self.tr("Cloud sync"), self.tr("Please log in first."))
            return

        res = str(self.sync_engine.sync_now(key, interactive=True) or "")
        _update_cloudsync_label(self, username, last_result=res)

        self.set_status_txt(self.tr("Cloud: done"))

        # If the result indicates a pull/merge, refresh integrity baseline
        _r = res.lower()
        if _r.startswith("pulled") or ("conflict" in _r) or ("download" in _r):
            try:
                update_baseline(username=username, verify_after=False, who=self.tr("OnCloud Sync Settings Changed")) 
            except Exception:
                pass  # keep UX smooth even if baseline refresh throws
        msg = self.tr("Result: ") + f"{res}"
        QMessageBox.information(self, self.tr("Cloud sync"), msg)

    except Exception as e:
        log.error(f"[CLOUD] Manual Sync Error: {e}")
        try:
            import logging
            logging.getLogger(__name__).exception("Cloud sync failed")
        except Exception:
            pass
        self.set_status_txt(self.tr("Cloud: failed"))
        QMessageBox.warning(self, self.tr("Cloud sync"), f"Error: {e}")

# Event handler for when the user clicks the "Stop Cloud Sync (Keep Local)" button in the UI. This function disables cloud sync for the user while keeping their local vault file intact. It checks that the user is logged in and that a cloud file is configured, then prompts the user to save a local copy of their vault before disabling cloud sync. After disabling, it updates the UI and baseline accordingly.
def on_stop_cloud_sync_keep_local(self, *args, **kwargs):
    # Announce that the sync stop state is being saved
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

    src_file = None
    if os.path.isdir(cloud_path):
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

    home = os.path.expanduser("~")
    dst, _ = QFileDialog.getSaveFileName(
        self, "Save a local copy of your vault",
        os.path.join(home, os.path.basename(src_file)),
        "Keyquorum Vault (*.kqvault);;All files (*.*)"
    )
    if not dst:
        return

    try:

        tmp_local = str(vault_file(username, ensure_parent=True))
        _restore_local_from_remote(username, src_file)
        copy2(tmp_local, dst)  # now copy the unwrapped working file to the user's chosen path
        # disable cloud
        ok = stop_user_cloud(username)
        if not ok:
            QMessageBox.critical(
                self,
                self.tr("Stop Cloud Sync"),
                self.tr("Failed: {ok}").format(ok=ok),
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
    disable_buttons(self)
    update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Cloud Disable")) 
    self.set_status_txt(self.tr("Done"))

# Helper to get the cloud vault file path for the current user, if configured. This checks the user's cloud profile for the remote path and returns it as a Path object if it exists, or None if not configured. This is used by various sync operations to determine where the cloud-synced vault file is located.
def cloud_vault_file(self, username: str) -> Path | None:
    """
    Return the FILE path configured for cloud sync for this user,
    or None if not configured. (Engine is file-based.)
    """
    try:
        username = self._active_username()
        prof = get_user_cloud(username) or {}
        rp = (prof.get("remote_path") or "").strip()
        return Path(rp) if rp else None
    except Exception:
        return None

# Helper to compute the SHA256 hash of a file, used for integrity verification during sync operations. This reads the file in chunks to avoid memory issues with large files. Note that this is strictly for integrity checks and should not be used for password hashing or other security-sensitive purposes.
def _sha256_file(path):
    """
    Compute SHA256 of a file for integrity verification.

    SECURITY NOTE:
    Used strictly for file integrity checks (not password hashing).
    """
    hasher = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

# Event handler for when the user clicks the "Copy Vault to Cloud" button in the UI. This function guides the user through the process of copying their local vault file to a cloud-synced folder. It includes a one-time security warning about cloud risks, an option to enable extra cloud wrapping, and then allows the user to select a destination folder. After copying, it configures the sync engine and performs an initial sync to set up the cloud vault properly. Finally, it updates the UI and baseline with the new cloud sync status.
def on_copy_vault_to_cloud(self):
    self.set_status_txt(self.tr("Copying vault to user cloud"))
    """
    Copy the local vault to a cloud-synced folder the user selects.
    - Shows a one-time security warning about cloud risk.
    - Offers to enable extra cloud wrapping (recommended) if it's off.
    - Persists the cloud target and reconfigures the sync engine.
    """
    self.reset_logout_timer()

    username = self._active_username()

    if not username:
        QMessageBox.warning(self, self.tr("Copy to Cloud"), self.tr("Please log in first."))
        return

    try:
        prof = get_user_cloud(username) or {}
    except Exception:
        prof = {}
    wrap = bool(prof.get("cloud_wrap"))

    cloud_ack = False
    try:
        cloud_ack = bool(get_user_setting(username, "cloud_risk_ack"))
    except Exception:
        cloud_ack = False

    if not cloud_ack:
        accepted, dont_ask, want_wrap = _show_cloud_risk_modal(self, current_wrap=wrap)
        if not accepted:
            return
        if dont_ask:
            try:
                set_user_setting(username, "cloud_risk_ack", True)
            except Exception as e:
                log.debug(f"[WARN] Could not persist cloud_risk_ack: {e}")
        if want_wrap and not wrap:
            wrap = True

    # Let user pick the destination folder (cloud-synced)
    sel = QFileDialog.getExistingDirectory(self, "Select your cloud vault folder")
    if not sel:
        return
    folder = sel.replace("\\", "/")

    try:
        local_file = str(vault_file(username, ensure_parent=True))
    except Exception:
        local_file = ""
    if not local_file or not os.path.isfile(local_file):
        QMessageBox.critical(self, self.tr("Copy to Cloud"), self.tr("Local vault file not found."))
        return

    # Cloud sync uses a dedicated bundle target, not the raw local .kq_user file.
    dest_file = os.path.join(folder, f"{username}.kqsync").replace("\\", "/")

    # Confirm overwrite if target exists
    try:
        if os.path.exists(dest_file):
            ans = QMessageBox.question(
                self, "Overwrite?",
                f"A sync bundle already exists at:\n{dest_file}\n\nOverwrite it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

        os.makedirs(folder, exist_ok=True)
    except Exception as e:
        QMessageBox.critical(self, self.tr("Copy to Cloud"), f"Failed:\n{e}")
        return

    # Persist cloud target + wrap preference
    try:
        set_user_cloud(username, enable=True, provider="localpath", path=dest_file, wrap=wrap, bundle=True)
    except Exception as e:
        QMessageBox.warning(self, self.tr("Copy to Cloud"), f"Failed to set cloud target:\n{e}")
        return

    # Reconfigure engine + do an initial sync so the remote is created in the correct format.
    try:
        _configure_sync_engine(self, username, "on_copy_vault_to_cloud")
        initial = str(_cloud_sync_safe(self, self.core_session_handle, interactive=True) or "synced")
    except Exception as e:
        QMessageBox.critical(self, self.tr("Copy to Cloud"), f"Initial cloud sync failed:\n{e}")
        return

    enable_buttons(self)
    update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Cloud Enable")) 
    extra = "\n\nExtra cloud wrapping: ON (recommended)" if wrap else "\n\nExtra cloud wrapping: OFF"
    msg =  self.tr("Vault will sync to:") + f"\n{dest_file}\n\n" + self.tr("Reminder: Cloud storage increases exposure. Use a strong password and 2FA.") + f"{extra}\n\n" + self.tr("Initial sync result:") + f" {initial}"
    QMessageBox.information(
        self, "Copy to Cloud", msg)
    
    self.set_status_txt(self.tr("Done"))

# Helper to (re)configure the sync engine for a given user. This is called whenever we need to ensure that the sync engine is set up and bound to the current user's cloud profile. It defines the necessary callbacks for loading/saving config, getting local vault paths, and determining which files are part of the sync bundle. It also handles binding the remote file path from the user's profile to the engine.
def _configure_sync_engine(self, username=None, who="None"):
    """Bind / (re)create the sync engine for the given user."""

    username = (username or "").strip()
    if not username:
        return

    def load_cfg():
        prof = get_user_cloud(username) or {}
        return {"sync": prof}

    def save_cfg(cfg: dict):
        sc = (cfg or {}).get("sync") or {}
        set_user_cloud(
            username,
            enable=bool(sc.get("enabled", sc.get("sync_enable", False))),
            provider=(sc.get("provider") or "localpath"),
            path=(sc.get("remote_path") or ""),
            wrap=bool(sc.get("cloud_wrap")),
            bundle=bool(sc.get("bundle", True)),
            sync_enable=bool(sc.get("sync_enable", sc.get("enabled", False))),
        )

    def get_local_vault_path():
        return str(vault_file(username, ensure_parent=True))


    def get_bundle_files() -> dict:
        """
        Files that count as real synced account content.

        Core files are always listed.
        Optional/lazy-created files are only included if they already exist,
        so bundle creation does not fail on fresh accounts.
        """

        core_files = {
            "vault": str(vault_file(username, ensure_parent=True)),
            "user_db": str(user_db_file(username, ensure_parent=True)),
            "identity": str(identities_file(username, ensure_parent=True)),
            "catalog.enc": str(catalog_file(username, ensure_parent=True)),
        }

        optional_files = {
            "audit.kqad": str(audit_file(username, ensure_parent=True)),
            "audit_slt.kqslt": str(audit_file_salt(username, ensure_parent=True)),
            "audit_mir.kqadmr": str(audit_mirror_file(username, ensure_parent=True)),
            "baseline.bsln": str(baseline_file(username, ensure_parent=True)),
            "vault_wrap": str(vault_wrapped_file(username, ensure_parent=True)),
            "trash.bin": str(trash_path(username, ensure_parent=True)),
            "pw_last.bin": str(pw_cache_file(username, ensure_parent=True)),
            "breach_cache.json": str(breach_cache(username, ensure_parent=True)),
        }

        files = dict(core_files)

        for logical, path in optional_files.items():
            try:
                if path and os.path.exists(path):
                    files[logical] = path
            except Exception:
                pass

        return files

    # Recreate engine if user changed
    if getattr(self, "_sync_user", None) != username:
        self.sync_engine = SyncEngine(load_cfg, save_cfg, get_local_vault_path, get_bundle_files=get_bundle_files)
        try:
            self.sync_engine.username = username
            self.sync_engine._current_user = username
        except Exception:
            pass
        self._sync_user = username
    try:
        if getattr(self, "sync_engine", None) is not None:
            self.sync_engine.username = username
            self.sync_engine._current_user = username
    except Exception:
        pass

    # Bind remote file path from profile
    try:
        prof = get_user_cloud(username) or {}
        rp = (prof.get("remote_path") or "").strip()
        if rp:
            try:
                self.sync_engine.set_remote_file(rp)
            except Exception:
                try:
                    self.sync_engine.set_localpath(rp)
                except Exception:
                    pass
    except Exception:
        pass

# Helper to perform a cloud sync operation safely, with comprehensive checks and user feedback. This is used by various sync triggers (manual sync, auto sync, wrap toggle) to ensure that the sync operation only proceeds if the user is logged in, cloud sync is enabled, and the engine is properly configured. It also logs the outcome and updates the status text accordingly.
def _cloud_sync_safe(self, *args, **kwargs) -> str:
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
        interactive = bool(kwargs.get("interactive", False))
        username = self._active_username()

        if not username:
            log.info("[CLOUD] sync skipped — no user")
            _status("Cloud sync: no user")
            return "no-user"

        # Ensure engine is created/bound for this user
        if hasattr(self, "_configure_sync_engine"):
            _configure_sync_engine(self, username, "_cloud_sync_safe")

        eng = getattr(self, "sync_engine", None)
        if not eng or not hasattr(eng, "sync_now"):
            log.info(f"[CLOUD] sync skipped — no engine for user {username}")
            _status("Cloud sync: no engine configured")
            return "no-engine"

        # Do the sync (requires a native session handle for Extra Wrap)
        session_handle = getattr(self, "core_session_handle", None)
        if not isinstance(session_handle, int) or not session_handle:
            log.info(f"[CLOUD] sync skipped — no native session for user {username}")
            _status("Cloud sync: please unlock vault first")
            return "no-session"

        result = str(eng.sync_now(session_handle, interactive=interactive) or "noop")

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

# Helper to determine the YubiKey Wrap/Gate status for a given user, including whether the necessary tooling is available on this machine. This is used to inform the user about their YubiKey 2FA configuration and whether they can enable extra cloud wrapping for enhanced security.
def _yubi_wrap_status(username) -> dict:
    """
    Return {'enabled': bool, 'mode': 'WRAP'|'GATE'|'' , 'available': bool|None}

    - 'mode' is derived from the current twofactor record (new) or legacy flags (old).
    - 'enabled' is True if mode is WRAP or GATE.
    - 'available' is True if YubiKey tooling is available on this machine,
        False if we can tell it isn't, or None if we can't determine.
    """
    mode = ""
    enabled = False
    available_flag = None

    # --- Read settings (prefer new, fall back to legacy) ---
    try:
        tf = get_user_setting(username, "twofactor") or {}
        m = (tf.get("mode") or "").lower()
        if m == "yk_hmac_wrap":
            mode = "WRAP"
        elif m == "yk_hmac_gate":
            mode = "GATE"
        else:
            # Legacy compatibility
            legacy = (get_user_setting(username, "yubi_2of2_mode") or "").upper()
            if legacy in ("WRAP", "GATE"):
                mode = legacy
            elif get_user_setting(username, "yubi_wrap_enabled"):
                mode = "WRAP"
        enabled = mode in ("WRAP", "GATE")
    except Exception:
        pass

    # --- Check YubiKey tooling availability (no console popups) ---
    YKBackend = None
    try:
        from auth.yubi.yk_backend import YKBackend  # packaged layout
    except Exception:
        try:
            from auth.yubi.yk_backend import YKBackend  # flat layout
        except Exception:
            YKBackend = None

    if YKBackend is None:
        available_flag = None  # unknown
    else:
        try:
            # If ykman (python or exe) is present/working, this succeeds.
            YKBackend().yk_version()
            available_flag = True
        except Exception:
            available_flag = False

    return {"enabled": bool(enabled), "mode": mode, "available": available_flag}

# Helper to show a one-time modal dialog explaining the risks of cloud storage and offering to enable extra cloud wrapping for enhanced security. This is triggered when the user attempts to use cloud sync features for the first time, and it provides clear information about the risks and recommendations for secure cloud usage. The user's choices are returned as a tuple indicating whether they accepted the risks, whether they want to be reminded again, and whether they want to enable extra cloud wrapping.
def _show_cloud_risk_modal(self, current_wrap: bool = False) -> tuple[bool, bool, bool]:
    """
    One-time consent explaining cloud risks.
    Returns (accepted: bool, dont_ask_again: bool, enable_wrap: bool).
    """
    from features.url.main_url import SITE_HELP, PRIVACY_POLICY
    current_wrap = bool(current_wrap)
    help_url = getattr(self, "SITE_HELP", SITE_HELP)
    privacy_url = PRIVACY_POLICY

    # Figure out YubiKey state for the active user (best-effort)
    uname = None
    try:
        uname = self._active_username()
    except Exception:
        try:
            uname = self._active_username()
        except Exception:
            uname = None

    yk = {"enabled": False, "mode": "", "available": None}
    if uname:
        try:
            yk = _yubi_wrap_status(uname)
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
    msg.setTextFormat(Qt.RichText)
    msg.setTextInteractionFlags(Qt.TextBrowserInteraction)
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

# Event handler for when the user clicks the "Cleanup Transfer Packages" button in the UI. This function allows the user to select a folder (typically their cloud sync folder) and offers to delete any leftover *.zip.enc transfer packages that may be present from previous Android imports or sync operations. It provides a confirmation dialog listing the found packages and handles the deletion while reporting any errors.
def cleanup_transfer_packages(self, *args, **kwargs):
    """
    Offers to delete *.zip.enc transfer packages from a chosen folder.
    Handy after the Android import is done.
    """
    from qtpy.QtWidgets import QFileDialog, QMessageBox
    from pathlib import Path

    folder = QFileDialog.getExistingDirectory(self, "Select folder to clean (cloud)")
    if not folder:
        return
    p = Path(folder)
    candidates = sorted([x for x in p.glob("*.zip.enc") if x.is_file()])

    if not candidates:
        QMessageBox.information(self, self.tr("Cleanup"), self.tr("No .zip.enc packages found here."))
        return

    names = "\n".join(str(x.name) for x in candidates[:20])
    more = "" if len(candidates) <= 20 else self.tr("\n… and ") + f" {len(candidates)-20} " + self.tr("more")
    msg =  self.tr("Found ") + f"{len(candidates)}" + self.tr(" package(s):") + f"\n{names}{more}\n\n" + self.tr(" Delete them now?"),
    resp = QMessageBox.question(
        self, self.tr("Delete transfer packages?"), msg,
        QMessageBox.Yes | QMessageBox.No, QMessageBox.No
    )
    if resp != QMessageBox.Yes:
        return

    errors = 0
    for x in candidates:
        try:
            x.unlink()
        except Exception:
            errors += 1
    if errors:
        msg = self.tr("Deleted with ") + f"{errors}" + self.tr(" error(s).")
        QMessageBox.warning(self, self.tr("Cleanup"), msg)
    else:
        msg = "✅ " + self.tr("All packages deleted.")
        QMessageBox.information(self, self.tr("Cleanup"), msg)

# ==============================
# --- cloud encrypted wrap ---
# ==============================

# The sync engine expects certain helper methods to be available on the main window for reading/writing files and performing cloud wrapping. These are defined here and bound to the main window instance if they don't already exist. This allows the sync engine to call these methods for its operations without worrying about where they are defined.
def _bind_sync_helpers(self) -> None:
    """
    sync_ops historically expected helper methods to exist on the main window
    """
    try:
        if not hasattr(self, "_read_bytes"):
            self._read_bytes = lambda path: _read_bytes(path)
        if not hasattr(self, "_write_bytes"):
            self._write_bytes = lambda path, data: _write_bytes(path, data)
        if not hasattr(self, "_cloud_wrap_encrypt"):
            self._cloud_wrap_encrypt = lambda data, username=None: _cloud_wrap_encrypt(self, data, username)
        if not hasattr(self, "_cloud_wrap_decrypt"):
            self._cloud_wrap_decrypt = lambda data, username=None: _cloud_wrap_decrypt(self, data, username)
    except Exception:
        pass

# Helper methods for the sync engine to read/write files and perform optional cloud wrapping. These are bound to the main window instance if not already present, allowing the sync engine to use them for its operations. The cloud wrapping methods attempt to import and use the wrap_encrypt/wrap_decrypt functions from the sync engine, but fall back to no-op if they aren't available (e.g., in older versions or if the import fails).
def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

# Helper to write bytes to a file, ensuring the parent directory exists. This is used by the sync engine when it needs to write files during sync operations, and it abstracts away the file writing logic while ensuring that directories are created as needed.
def _write_bytes(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

# Optional extra encryption layer for cloud storage. The sync engine calls this method to wrap data before uploading to the cloud if the user has enabled extra cloud wrapping. If the wrap_encrypt function isn't available (e.g., in older versions of the engine), it simply returns the original data, allowing cloud sync to work without wrapping.
def _cloud_wrap_encrypt(self, data: bytes, username: str | None = None) -> bytes:
    """
    Optional extra layer for cloud storage only.
    If wrap_encrypt isn't available, returns plaintext bytes.
    """
    try:
        from features.sync.engine import wrap_encrypt
        return wrap_encrypt(self.core_session_handle, data)
    except Exception:
        return data

# Optional decryption for cloud storage. The sync engine calls this method to unwrap data after downloading from the cloud if the user has enabled extra cloud wrapping. If the wrap_decrypt function isn't available (e.g., in older versions of the engine), it simply returns the original data, allowing cloud sync to work without unwrapping.
def _cloud_wrap_decrypt(self, data: bytes, username: str | None = None) -> bytes:
    try:
        from features.sync.engine import wrap_decrypt
        return wrap_decrypt(self.core_session_handle, data)
    except Exception:
        return data

# Method to seed the remote cloud file from the local working copy. This is used when setting up cloud sync for the first time or when the user wants to push their local vault to the cloud. It supports different formats of remote files, including legacy raw files, bundle containers, and wrapped bundles. It reads the local vault data, optionally wraps it for cloud storage, and then writes it to the remote location configured in the user's cloud profile.
def _seed_remote_from_local(self, *args, **kwargs):
    """
    Create/update the cloud file from the local working copy.

    Supports:
    - legacy raw remote vault file
    - bundle container (.kqsync / .kqbndl / .kqbundle)
    - wrapped bundle/file (KQW1)
    """
    try:
        username = self._active_username()
    except Exception:
        username = (getattr(self, "current_username", None) or "").strip()
    if not username:
        return

    prof = get_user_cloud(username) or {}
    remote_file = ((prof.get("remote_path") or "").strip() or (prof.get("path") or "").strip())
    if not remote_file:
        return

    _configure_sync_engine(self, username, "_seed_remote_from_local")
    eng = getattr(self, "sync_engine", None)

    local_vault_path = str(vault_file(username, ensure_parent=True))
    upload_path = local_vault_path
    is_bundle = str(remote_file).lower().endswith((".kqsync", ".kqbndl", ".kqbundle"))

    if is_bundle and eng is not None:
        try:
            cfg, _provider = eng.configured()
            sc = cfg.get("sync") or {}
        except Exception:
            sc = {"remote_path": remote_file, "bundle": True}
        upload_path = eng._build_bundle(sc, local_vault_path)

    data = _read_bytes(upload_path)
    try:
        if bool(prof.get("cloud_wrap")):
            data = _cloud_wrap_encrypt(self, data, username)
    except Exception:
        pass

    _write_bytes(remote_file, data)
    try:
        update_baseline(username=username, verify_after=False, who=self.tr("Cloud sync: seed remote"))
    except Exception:
        pass

# Method to restore the local working copy from the remote cloud file. This is used when setting up cloud sync for the first time or when the user wants to pull their vault from the cloud. It supports different formats of remote files, including legacy raw files, bundle containers, and wrapped bundles. It reads the remote data, optionally unwraps it if extra cloud wrapping is enabled, and then writes it to the local vault location.

def _restore_local_from_remote(self, username: str | None = None, remote_file: str | None = None, *args, **kwargs):
    """
    Restore LOCAL working copy from CLOUD file.

    Supports:
    - legacy raw remote vault file
    - bundle container (.kqsync / .kqbndl / .kqbundle)
    - wrapped bundle/file (KQW1)
    """
    import tempfile

    try:
        active_username = (self._active_username() or "").strip()
    except Exception:
        active_username = ""

    current_username = (getattr(self, "current_username", None) or "").strip()

    widget_current = ""
    try:
        widget_current = (self.currentUsername.text() or "").strip() if hasattr(self, "currentUsername") and self.currentUsername else ""
    except Exception:
        widget_current = ""

    login_username = ""
    try:
        login_username = (self.usernameField.text() or "").strip() if hasattr(self, "usernameField") and self.usernameField else ""
    except Exception:
        login_username = ""

    log.info(
        "[CLOUD-RESTORE] enter arg_username=%r active=%r current_username=%r currentUsername=%r usernameField=%r remote_arg=%r",
        username, active_username, current_username, widget_current, login_username, remote_file,
    )

    username = (username or active_username or current_username or widget_current or login_username or "").strip()
    if not username:
        log.warning("[CLOUD-RESTORE] abort: no username resolved")
        raise RuntimeError("No username available for cloud restore.")

    log.info("[CLOUD-RESTORE] resolved username=%r", username)

    # Prefer the directly supplied path first (important for pre-login restore)
    remote_file = (remote_file or "").strip()

    prof = {}
    if not remote_file:
        try:
            prof = get_user_cloud(username) or {}
        except Exception:
            prof = {}

        remote_file = ((prof.get("remote_path") or "").strip() or (prof.get("path") or "").strip())

    if not remote_file:
        log.warning("[CLOUD-RESTORE] abort: no remote path available for username=%r", username)
        raise RuntimeError(f"No cloud file configured for {username}")

    log.info("[CLOUD-RESTORE] profile/arg remote=%r wrap=%r", remote_file, bool((prof or {}).get("cloud_wrap")))

    if not os.path.isfile(remote_file):
        log.warning("[CLOUD-RESTORE] abort: remote file missing path=%r", remote_file)
        raise RuntimeError(f"Cloud file not found: {remote_file}")

    _configure_sync_engine(self, username, "_restore_local_from_remote")
    eng = getattr(self, "sync_engine", None)

    local_vault_path = str(vault_file(username, ensure_parent=True))

    data = _read_bytes(remote_file)
    log.info("[CLOUD-RESTORE] remote exists=%r size=%r", os.path.isfile(remote_file), len(data) if data else 0)

    # unwrap if needed
    try:
        prof = get_user_cloud(username) or {}
    except Exception:
        prof = {}

    try:
        if data[:4] == b"KQW1" or bool(prof.get("cloud_wrap")):
            data = _cloud_wrap_decrypt(self, data, username)
    except Exception as e:
        log.warning("[CLOUD-RESTORE] cloud unwrap skipped/failed err=%r", e)

    is_bundle = str(remote_file).lower().endswith((".kqsync", ".kqbndl", ".kqbundle"))
    log.info("[CLOUD-RESTORE] is_bundle=%r", is_bundle)

    if is_bundle and eng is not None:
        tmp_bundle = None
        try:
            fd, tmp_bundle = tempfile.mkstemp(prefix="kq_restore_", suffix=".kqsync")
            os.close(fd)
            _write_bytes(tmp_bundle, data)

            try:
                cfg, _provider = eng.configured()
                sc = cfg.get("sync") or {}
            except Exception:
                sc = {"remote_path": remote_file, "bundle": True}

            log.info("[CLOUD-RESTORE] sync_engine=%r sync_user=%r", bool(eng), getattr(self, "_sync_user", None))

            try:
                bundle_map = eng._get_bundle_map(sc, local_vault_path)
                log.info("[CLOUD-RESTORE] bundle targets=%r", bundle_map)
            except Exception as e:
                log.error("[CLOUD-RESTORE] bundle map failed: %r", e)
                bundle_map = {}

            eng._apply_bundle(sc, local_vault_path, tmp_bundle)

            for logical, target in (bundle_map or {}).items():
                log.info(
                    "[CLOUD-RESTORE] restored check logical=%r target=%r exists=%r",
                    logical, target, os.path.exists(target)
                )

            return

        finally:
            if tmp_bundle and os.path.exists(tmp_bundle):
                try:
                    os.remove(tmp_bundle)
                except Exception:
                    pass

    # legacy raw single-file fallback
    _write_bytes(local_vault_path, data)
    log.info("[CLOUD-RESTORE] wrote legacy/raw vault path=%r exists=%r", local_vault_path, os.path.exists(local_vault_path))

def _init_auto_sync(self, *args, **kwargs):
    # Ensure helper methods exist on self (read/write/wrap)
    try:
        _bind_sync_helpers(self)
    except Exception:
        pass

    self._auto_sync_timer = QTimer(self)
    self._auto_sync_timer.setSingleShot(True)
    self._auto_sync_timer.setInterval(2500)  # 2.5s debounce
    self._auto_sync_timer.timeout.connect(lambda: _run_auto_sync(self))

    # Guards/state
    self._is_syncing_cloud = False
    self._vault_watcher = None

# Method to schedule an auto-sync operation after a delay. This is triggered by file change events on the local vault, and it ensures that we don't immediately sync on every single file change (which could be noisy), but instead wait for a short period of inactivity before performing the sync. It includes comprehensive checks to ensure that the user is logged in, cloud sync is enabled, and the engine is configured before starting the timer for auto-sync.
def _schedule_auto_sync(self):
    try:
         
        log.info("[AUTO-SYNC] entered")
    except Exception:
        pass

    if getattr(self, "_auto_sync_timer", None) is None:
        try:
             
            log.info("[AUTO-SYNC] init timer")
        except Exception:
            pass
        self._init_auto_sync()

    username = self._active_username()
    try:
         
        log.info(f"[AUTO-SYNC] username={username!r}")
    except Exception:
        pass
    if not username:
         
        log.warning("[AUTO-SYNC] exit: no active username")
        return

    handle = getattr(self, "core_session_handle", None)
    try:
         
        log.info(f"[AUTO-SYNC] core_session_handle={bool(handle)}")
    except Exception:
        pass
    if not handle:
         
        log.warning("[AUTO-SYNC] exit: no core_session_handle")
        return

    try:
        prof = (get_user_cloud(username) or {})
        sync_enabled = bool(prof.get("sync_enable", False))
        if not sync_enabled:
            return
        log.info(f"[AUTO-SYNC] sync_enable={sync_enabled}")
    except Exception as e:
         
        log.error(f"[AUTO-SYNC] exit: get_user_cloud failed: {e}")
        return

    if not sync_enabled:
         
        log.warning("[AUTO-SYNC] exit: sync_enabled is false")
        return

    try:
        _configure_sync_engine(self, username, "_schedule_auto_sync")
         
        log.info("[AUTO-SYNC] configure_sync_engine ok")
    except Exception as e:
         
        log.error(f"[AUTO-SYNC] exit: configure failed: {e}")
        return

    try:
        self.sync_engine.configured()
         
        log.info("[AUTO-SYNC] sync_engine.configured ok")
    except Exception as e:
         
        log.warning(f"[AUTO-SYNC] exit: engine not configured: {e}")
        return

    if getattr(self, "_is_syncing_cloud", False):
         
        log.warning("[AUTO-SYNC] exit: already syncing")
        return

    try:
         
        log.info("[AUTO-SYNC] starting timer")
    except Exception:
        pass

    self._auto_sync_timer.start()

# Method to perform an auto-sync operation, triggered by the timer after a file change is detected. It includes comprehensive checks to ensure that the user is logged in, cloud sync is enabled, and the engine is configured before attempting to sync. It also handles logging the outcome and refreshing the UI if changes were pulled from the cloud.
def _run_auto_sync(self):
    username = self._active_username()
    if not username or not getattr(self, "core_session_handle", None):
        return

    # Respect cloud enabled + autosync setting
    try:
        prof = (get_user_cloud(username) or {})
    except Exception:
        prof = {}

    cloud_on = bool(prof.get("enabled", prof.get("sync_enable", False)))
    if not cloud_on:
        return

    if not bool(get_user_setting(username, "auto_sync", True)):
        return

    if not (hasattr(self, "sync_engine") and self.sync_engine and self.sync_engine.configured()):
        return

    # prevent re-entrant loops when our own pull/write triggers fileChanged
    if getattr(self, "_is_syncing_cloud", False):
        return

    try:
        self._is_syncing_cloud = True
        res = str(self.sync_engine.sync_now(self.core_session_handle, interactive=False) or "")
         
        log.info(f"[AUTO-SYNC] result={res}")
        log.debug(self.tr("[AUTO-SYNC] {result}").format(result=res))

        try:
            _update_cloudsync_label(self, username, last_result=res)
        except Exception as e:
            log.warning(f"[AUTO-SYNC] label refresh failed: {e}")

        # Refresh the Cloud Sync footer / timestamps
        try:
            _update_cloudsync_label(self, username, last_result=res)
        except Exception as e:
             
            log.warning(f"[AUTO-SYNC] label refresh failed: {e}")

        _r = res.lower()
        if _r.startswith("pulled") or ("conflict" in _r) or ("download" in _r):
            try:
                update_baseline(username=username, verify_after=False, who=self.tr("Auto-Sync -> File Change"))
            except Exception:
                pass

            # Refresh UI so changes appear immediately
            try:
                QTimer.singleShot(0, self.load_vault_table)
            except Exception:
                try:
                    self.load_vault_table()
                except Exception:
                    pass

    except Exception as e:
        log.warning(self.tr("[AUTO-SYNC] failed: {err}").format(err=e))
    finally:
        self._is_syncing_cloud = False

# Method to cleanly remove the file watcher on the local vault. This is used when switching users or when the vault file is no longer relevant, ensuring that we don't keep watching old files or directories and that we free up resources associated with the QFileSystemWatcher.
def _unwatch_local_vault(self):
    try:
        w = getattr(self, "_vault_watcher", None)
        if not w:
            return
        # detach paths
        try:
            for p in list(w.files()):
                try: w.removePath(p)
                except Exception: pass
            for d in list(w.directories()):
                try: w.removePath(d)
                except Exception: pass
        except Exception:
            pass
        try:
            w.deleteLater()
        except Exception:
            pass
        self._vault_watcher = None
    except Exception:
        pass


# watch the vault file and parent directory for changes, handling atomic writes and Qt watch quirks, 
# to trigger auto-sync when the vault is modified externally.
def _watch_local_vault(self,):
    """
    Watches the vault file and its parent directory.

    Handles:
    - atomic replace writes
    - Qt dropping file watches
    - avoiding sync loops
    - delayed scheduling so the vault finishes writing
    """

    try:
        import os
        from qtpy.QtCore import QFileSystemWatcher, QTimer

        username = self._active_username()
        if not username:
            return

        vault_path = str(vault_file(username, ensure_parent=True))
        parent_dir = os.path.dirname(vault_path) or "."

        # --- remove old watcher cleanly ---
        old = getattr(self, "_vault_watcher", None)
        if old is not None:
            try:
                for p in list(old.files()) + list(old.directories()):
                    try:
                        old.removePath(p)
                    except Exception:
                        pass
                old.deleteLater()
            except Exception:
                pass

        self._vault_watcher = QFileSystemWatcher(self)

        # watch parent directory (important for atomic replace)
        if os.path.isdir(parent_dir):
            try:
                self._vault_watcher.addPath(parent_dir)
            except Exception:
                pass

        # watch file if present
        if os.path.exists(vault_path):
            try:
                self._vault_watcher.addPath(vault_path)
            except Exception:
                pass

        def _ensure_paths():
            """Re-add paths if Qt drops them"""
            try:
                if parent_dir not in self._vault_watcher.directories():
                    self._vault_watcher.addPath(parent_dir)
            except Exception:
                pass

            try:
                if os.path.exists(vault_path) and vault_path not in self._vault_watcher.files():
                    self._vault_watcher.addPath(vault_path)
            except Exception:
                pass

        def _trigger_sync():
            if getattr(self, "_sync_guard", False):
                return
            try:
                self._schedule_auto_sync()
            except Exception:
                pass

        def _on_file_changed(_):
            if getattr(self, "_sync_guard", False):
                return
            _ensure_paths()
            QTimer.singleShot(600, _trigger_sync)

        def _on_dir_changed(_):
            if getattr(self, "_sync_guard", False):
                return
            _ensure_paths()
            QTimer.singleShot(600, _trigger_sync)

        self._vault_watcher.fileChanged.connect(_on_file_changed)
        self._vault_watcher.directoryChanged.connect(_on_dir_changed)

    except Exception as e:
        try:
            import logging
            logging.getLogger(__name__).warning(f"[WATCH] setup failed: {e}")
        except Exception:
            pass

# Cloud vault selection flow: let the user pick a vault file in a cloud-synced folder 
# (e.g., OneDrive/Google Drive). On first use, show a one-time security warning.

def on_select_cloud_vault(self, *args, **kwargs):
    """
    Let the user select a cloud vault file (.kqsync). If a sync bundle already exists,
    link/restore it to this device. If not, stop and tell the user no bundle was found.
    """
    from features.sync.sync_ops import enable_buttons

    self.reset_logout_timer()
    self.set_status_txt(self.tr("Please select your cloud vault file"))

    active_username = (self._active_username() or "").strip()
    prelogin_mode = False

    if active_username:
        username = active_username
    else:
        try:
            username = (self.usernameField.text() or "").strip()
        except Exception:
            username = ""
        prelogin_mode = True

    log.info(
        "[CLOUD-SELECT] active=%r current_username=%r currentUsername=%r usernameField=%r",
        active_username,
        getattr(self, "current_username", None),
        (self.currentUsername.text() if hasattr(self, "currentUsername") and self.currentUsername else ""),
        (self.usernameField.text() if hasattr(self, "usernameField") and self.usernameField else ""),
    )
    log.info("[CLOUD-SELECT] resolved username=%r prelogin_mode=%r", username, prelogin_mode)

    if not username:
        QMessageBox.warning(
            self,
            self.tr("Cloud sync"),
            self.tr("Enter your username first (or log in).")
        )
        return

    fn, _ = QFileDialog.getOpenFileName(
        self,
        self.tr("Select your cloud vault file"),
        "",
        "Keyquorum Vault (*.kqsync);;All files (*.*)"
    )
    if not fn:
        return

    remote_file = fn.replace("\\", "/")

    try:
        prof = get_user_cloud(username) or {}
    except Exception:
        prof = {}
    wrap = bool(prof.get("cloud_wrap"))

    try:
        cloud_ack = bool(get_user_setting(username, "cloud_risk_ack"))
    except Exception:
        cloud_ack = False

    if (not prelogin_mode) and (not cloud_ack):
        accepted, dont_ask, want_wrap = _show_cloud_risk_modal(self, current_wrap=wrap)
        if not accepted:
            return
        if dont_ask:
            try:
                set_user_setting(username, "cloud_risk_ack", True)
            except Exception as e:
                log.debug(f"[WARN] Could not persist cloud_risk_ack: {e}")
        if want_wrap and not wrap:
            wrap = True

    log.info("[CLOUD-SELECT] remote target candidate username=%r path=%r wrap=%r", username, remote_file, wrap)

    try:
        set_user_cloud(username, enable=True, provider="localpath", path=remote_file, wrap=wrap, bundle=True)
    except Exception as e:
        QMessageBox.warning(self, self.tr("Cloud sync"), f"Failed to set cloud target:\n{e}")
        return

    try:
        _configure_sync_engine(self, username, "on_select_cloud_vault")
        if getattr(self, "sync_engine", None):
            try:
                self.sync_engine.set_localpath(remote_file)
            except Exception:
                pass
    except Exception as e:
        log.error("[CLOUD-SELECT] configure failed username=%r err=%r", username, e)

    existing_remote = os.path.isfile(remote_file)
    log.info("[CLOUD-SELECT] existing_remote=%r path=%r", existing_remote, remote_file)

    if existing_remote:
        try:
            log.info("[CLOUD-SELECT] calling restore username=%r prelogin_mode=%r", username, prelogin_mode)
            _restore_local_from_remote(self, username=username, remote_file=remote_file)

            extra = self.tr("Extra cloud wrapping: ON (recommended)") if wrap else self.tr("Extra cloud wrapping: OFF")
            msg = (
                self.tr("Cloud target linked:\n")
                + f"{remote_file}\n\n"
                + self.tr("Existing sync data was restored to this device.\n\n")
                + extra
            )
            if prelogin_mode:
                msg += "\n\n" + self.tr("Now log in normally.")

            QMessageBox.information(self, self.tr("Cloud sync"), msg)
        except Exception as e:
            log.error("[CLOUD-SELECT] restore failed username=%r path=%r err=%r", username, remote_file, e)
            QMessageBox.warning(self, self.tr("Cloud sync"), self.tr("Cloud restore failed: ") + f"{e}")
            return
    else:
        QMessageBox.information(
            self,
            self.tr("Cloud sync"),
            self.tr("That cloud vault file was not found.")
        )
        return

    try:
        if active_username:
            update_baseline(username=username, verify_after=False, who=self.tr("OnCloud Sync Settings Changed"))
    except Exception:
        pass

    try:
        if active_username:
            enable_buttons(self)
    except Exception:
        pass
