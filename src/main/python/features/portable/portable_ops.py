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
"""Portable/USB mode helpers and UI actions.

This file is part of the Keyquorum Vault codebase.
"""


# This module contains methods extracted from main.py to reduce file size.
# We intentionally "inherit" main module globals so the moved code can run unchanged.
import sys as _sys
from pathlib import Path
import os
import threading
import logging
from qtpy import QtCore
from qtpy.QtCore import Qt, QTimer
from qtpy.QtWidgets import QFileDialog, QMessageBox, QInputDialog, QProgressDialog, QApplication
from features.portable.portable_manager import pick_usb_drive, move_user_data_to_usb, _detect_portable_root, _list_portable_users_verbose
from features.portable.portable_user_usb import ensure_portable_layout, install_binding_overrides, portable_root
from app.paths import vault_file, salt_file, user_db_file, debug_log_paths
from features.portable.portable_binding import set_user_usb_binding


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

def on_select_usb_clicked(self, *args, **kwargs):
    """
    Pick a USB drive, choose a portable user folder, validate it against
    Phase-2 canonical filenames/locations, then bind and install overrides.
    """

    # 1) Pick the USB root
    usb_root = pick_usb_drive(self)
    if not usb_root:
        picked = QFileDialog.getExistingDirectory(self, self.tr("Select your USB (root)"))
        if not picked:
            return
        usb_root = Path(picked)

    # 2) Find user folders on <USB>\KeyquorumPortable\Users
    pr, users_dir = ensure_portable_layout(usb_root)
    try:
        user_dirs = [p for p in users_dir.iterdir() if p.is_dir()]
    except Exception:
        user_dirs = []

    if not user_dirs:
        QMessageBox.warning(
            self, self.tr("Select USB"),
            self.tr("No users found under KeyquorumPortable/Users on this drive.\n\n"
            "Use Settings → Move User To USB first.")
        )
        return

    # 3) Choose the user folder
    names = [p.name for p in user_dirs]
    choice, ok = QInputDialog.getItem(
        self, self.tr("Select USB user"),
        self.tr("Choose the user folder to bind:"), names, 0, False
    )
    if not ok or not choice:
        return

    username = choice.strip()
    user_dir = users_dir / username

    # 4) Validate Phase-2 layout (with legacy fallbacks)
    canon_vault = Path(vault_file(username, name_only=True)).name
    canon_salt  = Path(salt_file(username,  name_only=True)).name
    canon_db    = Path(user_db_file(username, name_only=True)).name

    # canonical locations
    vault_path = user_dir / "Main" / "Vault"   / canon_vault
    salt_path  = user_dir / "KQ_Store"         / canon_salt
    db_path    = user_dir / "Main"             / canon_db

    # fallback candidates (legacy flat layout)
    legacy_vaults = [
        user_dir / "vault.dat",
        user_dir / f"{username}.vault",
        user_dir / canon_vault,  # same name but wrong place
    ]
    legacy_salts = [
        user_dir / "salt.bin",
        user_dir / f"salt_{username}.bin",
        user_dir / canon_salt,   # same name but wrong place
    ]
    legacy_dbs = [
        user_dir / "user_db.json",
        user_dir / canon_db,     # same name but wrong place
    ]

    def _exists_any(paths):
        return any(p.exists() for p in paths)

    vault_ok = vault_path.exists() or _exists_any(legacy_vaults)
    salt_ok  = salt_path.exists()  or _exists_any(legacy_salts)
    db_ok    = db_path.exists()    or _exists_any(legacy_dbs)

    if not (vault_ok and salt_ok and db_ok):
        exp_lines = [
            f"• Main/Vault/{canon_vault} (or vault.dat / {username}.vault)",
            f"• KQ_Store/{canon_salt} (or salt.bin / salt_{username}.bin)",
            f"• Main/{canon_db} (or user_db.json)",
        ]
        QMessageBox.warning(
            self, "Select USB",
            "That folder doesn’t contain a valid Keyquorum dataset.\n\n"
            "Expected files like:\n" + "\n".join(exp_lines)
        )
        return

    # 5) Persist binding and install runtime overrides NOW
    try:
        set_user_usb_binding(username, usb_root=Path(usb_root), user_dir=Path(user_dir))
        install_binding_overrides(username, Path(user_dir))  # redirect paths.* to USB for this process

        # ensure any cached imports pick up the new paths
        import importlib
        import vault_store as vstore  # <-- correct module
        importlib.reload(vstore)
        globals().update({"vstore": vstore})

        # Helpful logs
        try:
            debug_log_paths(username)
        except Exception:
            pass

        # Prefill login username (nice UX)
        try:
            if hasattr(self, "usernameField"):
                self.usernameField.setText(username)
        except Exception:
            pass
        msg = self.tr("Saved. ") + f"{username} " + self.tr("is now bound to this USB.\n You can log in and the app will read from the USB data.")
        QMessageBox.information(
            self, self.tr("USB Selected"), msg)
    except Exception as e:
        QMessageBox.critical(self, self.tr("USB Selection Failed"), str(e))

def action_move_user_from_usb(self, *args, **kwargs):
    """
    Restore a user from a USB stick back to this PC's per-user layout.
    Copies, verifies, then deletes the USB copy automatically.
    """
    import logging
    from pathlib import Path
    from qtpy.QtWidgets import QMessageBox, QInputDialog
    from features.portable.portable_manager import restore_from_usb, pick_usb_drive
    log = logging.getLogger("keyquorum")

    self.set_status_txt(self.tr("Moving User back to System"))

    # --- get username from UI ---
    try:
        username = (self.currentUsername.text() or "").strip()
    except Exception:
        username = ""

    log.info(f"[MOVE_FROM_USB] Initiated — UI username='{username}'")

    # --- choose USB drive ---
    drive = pick_usb_drive(self)
    if not drive:
        log.info("[MOVE_FROM_USB] Cancelled: no drive selected.")
        return

    usb_root = Path(drive)
    pr = _detect_portable_root(usb_root)
    log.info(f"[MOVE_FROM_USB] USB root={usb_root}, detected portable_root={pr}")

    users_dir = pr / "Users"
    if not users_dir.exists():
        QMessageBox.warning(self, "Restore from USB",
                            f"No KeyquorumPortable\\Users folder found on {usb_root}.")
        log.warning(f"[MOVE_FROM_USB] Missing Users dir at {users_dir}")
        return

    # --- scan portable users ---
    users = _list_portable_users_verbose(pr, username_hint=username)
    if not users:
        QMessageBox.warning(self, self.tr("Restore from USB"), self.tr("No valid users found on this USB."))
        log.warning(f"[MOVE_FROM_USB] No valid users found on USB {usb_root}")
        return

    # --- select user (case-insensitive / fuzzy) ---
    # _list_portable_users_verbose returns a list of dicts: {"username": ..., "path": ...}
    usernames = [u.get("username","") for u in users if isinstance(u, dict) and u.get("username")]
    users_ci = {name.casefold(): name for name in usernames}

    selected_username = ""

    if username:
        key = username.casefold()
        if key in users_ci:
            selected_username = users_ci[key]
            log.info(f"[MOVE_FROM_USB] Username matched case-insensitive: {selected_username}")
        else:
            # simple prefix match (case-insensitive)
            pref = [name for name in usernames if name.casefold().startswith(key)]
            if len(pref) == 1:
                selected_username = pref[0]
            else:
                selected_username, ok = QInputDialog.getItem(
                    self, "Select account to restore",
                    "Choose a user to restore to this PC:", usernames, 0, False
                )
                if not ok or not selected_username:
                    log.info("[MOVE_FROM_USB] Cancelled: user not selected.")
                    return
    else:
        selected_username, ok = QInputDialog.getItem(
            self, "Select account to restore",
            "Choose a user to restore to this PC:", usernames, 0, False
        )
        if not ok or not selected_username:
            log.info("[MOVE_FROM_USB] Cancelled: user not selected.")
            return

    username = selected_username  # keep downstream code expecting a string username

    log.info(f"[MOVE_FROM_USB] Proceeding with username='{username}'")

    # --- release any open handles ---
    try:
        if hasattr(self, "_release_local_handles_for_user"):
            self._release_local_handles_for_user(username)
            log.info(f"[MOVE_FROM_USB] Released file handles for {username}")
    except Exception as e:
        log.warning(f"[MOVE_FROM_USB] Failed to release file handles: {e}")

    # --- perform restore ---
    try:
        ok = restore_from_usb(self, usb_root, username)
    except Exception as e:
        log.exception(f"[MOVE_FROM_USB] restore_from_usb failed: {e}")
        QMessageBox.critical(self, self.tr("Restore from USB"), f"Error:\n{e}")
        return

    if not ok:
        log.warning(f"[MOVE_FROM_USB] Restore failed or aborted for {username}")
        return

    # --- clear portable flags ---
    try:
        set_user_setting(username, "portable_enforced", False)
        set_user_setting(username, "portable_root", "")
        log.info(f"[MOVE_FROM_USB] Cleared portable flags for {username}")
    except Exception as e:
        log.warning(f"[MOVE_FROM_USB] Could not clear portable flags: {e}")

    # --- logout to refresh UI ---
    try:
        if hasattr(self, "force_logout") and callable(self.force_logout):
            self.force_logout()
        else:
            self.logout_user()
        log.info(f"[MOVE_FROM_USB] Forced logout after restore for {username}")
    except Exception as e:
        log.warning(f"[MOVE_FROM_USB] Logout step failed: {e}")



def action_move_user_to_usb(self, *args, **kwargs):
    """
    Single button: move ONE user's data to USB (Users/<user>/...), bind the app to read from USB.
    Uses the new portable_manager.move_user_data_to_usb(self, usb_root) which performs the copy+verify+delete
    with detailed logging.
    """
    import logging
    from pathlib import Path
    log = logging.getLogger("keyquorum")

    self.set_status_txt(self.tr("Move User to USB"))
    log.info("[UI] action_move_user_to_usb clicked")

    # --- Resolve username ---
    username = (self.currentUsername.text() or "").strip()
    log.info(f"[UI] Selected username: {username!r}")
    if not username:
        QMessageBox.information(self, self.tr("Move to USB"), self.tr("Please log in or select a user first."))
        return

    # --- Pick USB root (prefer helper from features.portable_manager) ---
    usb_root = None
    try:
        # Prefer the portable_manager helper to keep UX consistent
        from features.portable.portable_manager import pick_usb_drive as _pm_pick_drive  
        usb = _pm_pick_drive(self)
        if not usb:
            log.info("[UI] User cancelled USB drive selection via pick_usb_drive")
            return
        usb_root = Path(usb)
    except Exception as e:
        log.warning(f"[UI] pick_usb_drive not available or failed: {e}; falling back to QFileDialog.")
        # Fallback to a folder picker
        from qtpy.QtWidgets import QFileDialog
        picked = QFileDialog.getExistingDirectory(self, "Select USB Root")
        if not picked:
            log.info("[UI] User cancelled USB folder selection")
            return
        usb_root = Path(picked)

    log.info(f"[UI] Selected USB root: {usb_root}")

    # --- Run the new mover (copy → verify → delete local) ---
    try:
        # binding overrides if available
        try:
            from features.portable.portable_user_usb import install_binding_overrides 
        except Exception:
            install_binding_overrides = None

        # Ensure the portable layout exists on the chosen USB root
        ensure_portable_layout(usb_root)

        log.info("[UI] Starting move_user_data_to_usb(...)")
        ok = move_user_data_to_usb(self, usb_root, username,delete_local=True)
        log.info(f"[UI] move_user_data_to_usb finished with ok={ok}")

        if not ok:
            QMessageBox.critical(self, self.tr("Move to USB"), self.tr("Move failed or was cancelled. See log for details."))
            return

        # Build the destination path for the user
        pr = portable_root(usb_root)
        user_dir = pr / "Users" / username
        app_exists = (pr / "app").exists()

        # Bind installed app to USB paths (best-effort)
        if install_binding_overrides:
            try:
                # NOTE: correct signature is (username, user_dir: Path)
                install_binding_overrides(username, user_dir)

                log.info(f"[UI] install_binding_overrides succeeded for user={username} at {user_dir}")
            except Exception as e:
                log.error(f"[UI] install_binding_overrides failed: {e}")


        if app_exists:
            msg = self.tr("Your data for ") + f"'{username}'" + self.tr(" has been moved to:") + f"\n{user_dir}\n\n" + self.tr("The installed app is now bound to read from USB.\nA portable app was detected on this USB and will read the same data.")
            
        else:
            msg = self.tr("Your data for ") + f"'{username}' " + self.tr(" has been moved to:") + f"\n{user_dir}\n\n" + self.tr("The installed app is now bound to read from USB.\n If you later build a portable app onto this USB, it will use this data automatically.")

        QMessageBox.information(self, self.tr("Move to USB"), msg)
        log.info(f"[UI] Move to USB successful → {user_dir}")

        # force a clean reopen from USB-bound paths
        try:
            if hasattr(self, "force_logout") and callable(self.force_logout):
                self.force_logout()
            else:
                self.logout_user()
        except Exception as e:
            log.warning(f"[UI] Post-move logout failed (continuing): {e}")

    except Exception as e:
        log.exception("[UI] action_move_user_to_usb failed")
        QMessageBox.critical(self, "Move to USB failed", str(e))

from pathlib import Path

def _check_usb_alive(self, *args, **kwargs) -> None:
    """
    Poll whether the portable USB drive is still mounted.
    If not, log out and close the application.
    """
    from pathlib import Path

    try:
        anchor = getattr(self, "_usb_anchor_path", None)
        root = getattr(self, "_usb_root_path", None)
        if not anchor or not root:
            return

        anchor = Path(anchor)
        root = Path(root)

        # Still there? Nothing to do.
        if anchor.exists() and root.exists():
            return
    except Exception as e:
        try:
            log.debug(f"[USB] watch check failed: {e}")
        except Exception:
            pass
        return

    # If we reach here, the drive appears to be gone.
    try:
        t = getattr(self, "_usb_watch_timer", None)
        if t and t.isActive():
            t.stop()
    except Exception:
        pass

    try:
        msg = self.tr(
            "The USB drive used for portable mode appears to have been removed.\n\n"
            "For your security, you will be logged out and the application will now close."
        )
        QMessageBox.warning(self, self.tr("Portable USB Removed"), msg)
    except Exception:
        pass

    try:
        # Skip backup – the drive is already gone
        self.logout_user(skip_backup=True)
    except Exception:
        pass

    try:
        QTimer.singleShot(0, QApplication.instance().quit)
    except Exception:
        try:
            QApplication.quit()
        except Exception:
            os._exit(0)


# =============================================================================
# --- mouse ---
# =============================================================================

# might need to update with reset dont remove this or maybe one below only on needs keeping



def update_portable_actions(self, *args, **kwargs):
    try:
        from features.portable.portable_manager import _is_running_portable
        is_portable = bool(_is_running_portable())
        log.info(f"[USB] Mode: {is_portable}")
    except Exception:
        is_portable = False  # safe default

    # If you use QPushButtons
    def _set_btn(btn, visible, enabled, tip=""):
        if hasattr(self, btn):
            b = getattr(self, btn)
            try:
                b.setVisible(visible)
                b.setEnabled(enabled)
                if tip: b.setToolTip(tip)
            except Exception:
                pass

    # If you use QActions (menu/toolbar)
    def _set_act(act, visible, enabled, tip=""):
        if hasattr(self, act):
            a = getattr(self, act)
            try:
                a.setVisible(visible)
                a.setEnabled(enabled)
                if tip: a.setToolTip(tip)
            except Exception:
                pass
