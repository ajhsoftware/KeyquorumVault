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
import shutil, secrets
from pathlib import Path
from typing import Optional

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QCheckBox, QMessageBox
)
import logging

log = logging.getLogger("keyquorum")
from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("delete_account_dialog", text)


# ---- Single source of truth: paths ---------------------------------------
from app.paths import (
    user_db_file, vault_file, vault_wrapped_file, salt_file, shared_key_file,
    identities_file, audit_file, audit_mirror_file, audit_file_salt, baseline_file,)

# ---- Login / 2FA wrappers (modern) ---------------------------------------
try:
    from auth.login.login_handler import (
        validate_login,
        get_user_setting,
        is_2fa_enabled,
        verify_2fa_code,
        use_backup_code,
    )
except Exception:
    validate_login   = None
    get_user_setting = lambda u,k,d=None: d
    def is_2fa_enabled(u): return False
    def verify_2fa_code(u,c,p=None,**_): return False
    def use_backup_code(u,c,**_): return False

# ---- Audit / Baseline (best effort) --------------------------------------
try:
    from security.secure_audit import append_audit_log, log_event_encrypted, is_locked_out as audit_is_locked_out
except Exception:
    append_audit_log = lambda *a, **k: None
    log_event_encrypted = lambda *a, **k: None
    def audit_is_locked_out(_u, _t, *_): return (False, _t, 0)

try:
    from security.baseline_signer import write_audit_baseline
except Exception:
    write_audit_baseline = None

# ---- USB binding guard -----------------------------------------
try:
    from features.portable.portable_user_usb import get_user_usb_dir
except Exception:
    get_user_usb_dir = None

def _is_usb_bound(username: str) -> bool:
    try:
        if get_user_usb_dir:
            ud = get_user_usb_dir(username)
            return bool(ud and ud.exists())
    except Exception:
        pass
    return False

# ---- Utilities ------------------
def _secure_wipe_file(path: Optional[Path | str]) -> None:
    """Best-effort overwrite (up to 1MB) + delete. SSDs may ignore overwrites; still fine."""
    try:
        if not path:
            return
        p = Path(path)
        if not p.is_file():
            return
        size = p.stat().st_size
        with open(p, "r+b", buffering=0) as f:
            f.seek(0); f.write(secrets.token_bytes(min(size, 1024 * 1024)))
        with open(p, "r+b", buffering=0) as f:
            f.seek(0); f.write(b"\x00" * min(size, 1024 * 1024))
        p.unlink(missing_ok=True)
    except Exception:
        try: Path(path).unlink(missing_ok=True)
        except Exception: pass

def _delete_path_with_verify(pathlike: Optional[Path | str], label: str, logs: list[str]) -> None:
    try:
        if not pathlike:
            logs.append(f"{label}:" + _tr(" no path"))
            return
        p = Path(pathlike)
        if not p.exists():
            logs.append(f"{label}:" + _tr(" not found (ok) — ") + f"{p}")
            return
        _secure_wipe_file(p)
        gone = not p.exists()
        logs.append(f"{label}: {_tr('deleted ✓') if gone else _tr('still present ✗')} — {p}")
    except Exception as e:
        logs.append(f"{label}:" + _tr(" error ✗") + f" — {e}")

def _cloud_delete(self, username: str, logs: list[str]) -> None:
    """Delete remote copy if sync is enabled; best-effort."""
    try:
        eng = getattr(self, "sync_engine", None)
        cloud = {}
        try:
            from auth.login.login_handler import get_user_cloud
            cloud = get_user_cloud(username)
        except Exception:
            pass
        if not eng or not (cloud.get("enabled") or cloud.get("sync_enable")):
            logs.append(_tr("cloud: disabled or no engine (skip)"))
            return
        if hasattr(eng, "delete_remote_user"):
            eng.delete_remote_user(username, cloud)
            logs.append(_tr("cloud: delete_remote_user() invoked ✓"))
        else:
            rp = cloud.get("remote_path") or ""
            if rp and hasattr(eng, "delete_remote_file"):
                eng.delete_remote_file(rp)
                logs.append(_tr("cloud: delete_remote_file") + f"({rp})" + _tr(" invoked ✓"))
            else:
                logs.append(_tr("cloud: no remote_path or delete method (skip)"))
    except Exception as e:
        logs.append(_tr("cloud: error ") + f"✗ — {e}")

# ---- Dialog ---------------------

class DeleteAccountDialog(QDialog):
    def __init__(self, parent, username: str):
        super().__init__(parent)
        self.username = (username or "").strip()

        self.setWindowTitle(
            self.tr("Delete Account – {user}").format(user=self.username)
        )
        self.setModal(True)
        self.resize(480, 300)

        v = QVBoxLayout(self)
        v.addWidget(QLabel("<b>" + self.tr("Delete account:") + f"“{self.username}”</b><br>" + self.tr("This will permanently remove your local vault and user data") + ".<br>" + self.tr("If cloud sync is enabled, we’ll also try to remove the remote copy.")))
        v.addWidget(QLabel(self.tr("Current password")))
        self.edit_pass = QLineEdit(self); self.edit_pass.setEchoMode(QLineEdit.Password)
        v.addWidget(self.edit_pass)

        v.addWidget(QLabel(self.tr("Type") + " <b>" + self.tr("DELETE") + " </b> " + self.tr("to confirm")))
        self.edit_phrase = QLineEdit(self); self.edit_phrase.setPlaceholderText(self.tr("DELETE"))
        v.addWidget(self.edit_phrase)

        self.chk_ack = QCheckBox(self.tr("I understand this will permanently remove my data."))
        v.addWidget(self.chk_ack)

        btns = QHBoxLayout()
        self.btn_cancel = QPushButton(self.tr("Cancel"))
        self.btn_ok = QPushButton(self.tr("Delete")); self.btn_ok.setEnabled(False)
        btns.addStretch(1); btns.addWidget(self.btn_cancel); btns.addWidget(self.btn_ok)
        v.addLayout(btns)

        def _update_ok():
            ok = self.edit_phrase.text().strip().upper() == self.tr("DELETE") and self.chk_ack.isChecked()
            self.btn_ok.setEnabled(ok)
        self.edit_phrase.textChanged.connect(_update_ok)
        self.chk_ack.toggled.connect(_update_ok)
        _update_ok()

        self.btn_cancel.clicked.connect(self.reject)
        self.btn_ok.clicked.connect(self.accept)

# ---- Public entry point ---------
def open_delete_account_dialog(self, username: str):
    """
    Hook this from your Settings/Delete button:
        self.btnDeleteAccount.clicked.connect(lambda: open_delete_account_dialog(self, self.current_user))
    """
    username = (username or "").strip()
    if not username:
        QMessageBox.information(self, self.tr("No user"), self.tr("No signed-in user."))
        return

    dlg = DeleteAccountDialog(self, username=username)
    if dlg.exec() != QDialog.Accepted:
        return

    _handle_delete_account(
        self,
        username=username,
        password=dlg.edit_pass.text().strip(),
        maybe_code="",
        phrase=dlg.edit_phrase.text().strip()
    )

# ---- Core deletion flow ---------

def _handle_delete_account(self, username: str, password: str, maybe_code: str, phrase: str):
    report: list[str] = []

    password_ok = False
    twofa_ok = False

    # Phrase gate
    if (phrase or "").upper() != self.tr("DELETE"):
        QMessageBox.information(self, self.tr("Type DELETE"), self.tr("Please type DELETE to confirm."))
        return

    # Lockout guard
    try:
        th  = int(get_user_setting(username, "lockout_threshold", 5) or 5)
        win = int(get_user_setting(username, "lockout_window_mins", 10) or 10)
        cd  = int(get_user_setting(username, "lockout_cooldown_mins", 5) or 5)
        if th > 0:
            locked, *_ = audit_is_locked_out(username, th, win, cd)
            if locked:
                QMessageBox.critical(self, self.tr("Account Locked"), self.tr("Try again later. Deletion is blocked while locked out."))
                return
    except Exception:
        pass

    # USB guard
    if _is_usb_bound(username):
        QMessageBox.warning(
            self, self.tr("USB-bound Account"),
            self.tr("This account is bound to a USB portable vault.\n\n"
                    "Please manage deletion from the Portable Manager, or unplug the drive and try again.")
        )
        return

    # Password verify
    if not (callable(validate_login) and validate_login(username, password)):
        QMessageBox.warning(self, self.tr("Wrong password"), self.tr("The current password is incorrect."))
        return
    password_ok = True

    # 2FA if enabled
    if is_2fa_enabled(username):
        code = (maybe_code or "").replace(" ", "").strip()
        if code:
            # Try TOTP first, then backup code
            twofa_ok = bool(verify_2fa_code(username, code, password=password)) or bool(
                use_backup_code(username, code, password_for_identity=password)
            )
        if not twofa_ok:
            QMessageBox.warning(self, self.tr("2FA required"), self.tr("Enter a valid 2FA or backup code."))
            return
    else:
        twofa_ok = True  # not required

    # Final confirm
    if QMessageBox.question(
        self,
        self.tr("Confirm deletion"),
        self.tr("This will permanently remove your vault, local user data and cloud copy (if enabled). Continue?"),
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No,
    ) != QMessageBox.Yes:
        return

    # Cloud deletion
    _cloud_delete(self, username, report)

    # Local deletion — specific files first (best-effort wipe), then per-user folders
    targets = [
        vault_file(username),
        vault_wrapped_file(username),
        salt_file(username),
        shared_key_file(username),
        identities_file(username),
        audit_file(username),
        audit_mirror_file(username),
        audit_file_salt(username),
        baseline_file(username),
        user_db_file(username),
    ]
    for label, p in [
        ("vault", targets[0]),
        ("wrapped_key", targets[1]),
        ("salt", targets[2]),
        ("share_keys", targets[3]),
        ("identity", targets[4]),
        ("audit", targets[5]),
        ("audit_mirror", targets[6]),
        ("audit_salt", targets[7]),
        ("baseline", targets[8]),
        ("user_db", targets[9]),
    ]:
        _delete_path_with_verify(p, label, report)

    # Delete all possible per-user roots (Local, Roaming, Portable)
    from app.paths import user_root_local, user_root_roaming, user_root_portable

    for label, root_func in [
        ("user_root_local", user_root_local),
        ("user_root_roaming", user_root_roaming),
        ("user_root_portable", user_root_portable),
    ]:
        try:
            root = root_func(username, ensure=False)
            if root.exists():
                shutil.rmtree(root, ignore_errors=True)
                report.append(f"{label}: {self.tr('deleted')} ✓ — {root}")
            else:
                report.append(f"{label}: {self.tr('not found (ok)')} — {root}")
        except Exception as e:
            report.append(f"{label}: {self.tr('error')} ✗ — {e}")

    # ✅ Replace audit log with a new simple tombstone + also save to Desktop
    _write_account_deleted_audit(self, username, report, password_ok=password_ok, twofa_ok=twofa_ok)
    report.append(self.tr("audit: replaced with deletion record") + " ✓")

    # (Optional) baseline event write (best-effort)
    try:
        if write_audit_baseline:
            write_audit_baseline(username, b"", files=[])
            report.append(self.tr("baseline: wrote event") + " ✓")
    except Exception as e:
        report.append(self.tr("baseline: error ") + f"✗ — {e}")

    # Zeroize in-memory keys & logout
    for attr in ("_session_key", "_master_key", "_vault_key", "_wrap_key"):
        if hasattr(self, attr):
            setattr(self, attr, None)
    try:
        if hasattr(self, "logout_user"):
            self.logout_user()
    except Exception:
        pass

    QMessageBox.information(
        self,
        self.tr("Account deleted"),
        self.tr("Your account has been removed from this device. You’ll now return to the login screen."),
    )

    # Show delete report (and optionally keep a short record elsewhere if you want)
    try:
        details = "\n".join(report)
        QMessageBox.information(self, self.tr("Delete report"), details if details else self.tr("No details."))
    except Exception:
        pass

# --- delete audit ---

def _write_account_deleted_audit(self, username: str, report: list[str], *, password_ok: bool = True, twofa_ok: bool = True):
    """
    Replace audit log with a single tombstone entry after account deletion.
    Also saves a copy to the current OS user's Desktop.

    Accepts flags so the report can honestly say whether password/2FA were verified.
    """
    try:
        # Local import to avoid any circular imports at module load time
        from app.paths import user_root_local, user_root_roaming

        # --- Existing audit paths ---
        af  = audit_file(username)
        afm = audit_mirror_file(username)
        afs = audit_file_salt(username)

        for p in (af, afm, afs):
            try:
                if p.exists():
                    p.unlink(missing_ok=True)
            except Exception:
                pass

        af.parent.mkdir(parents=True, exist_ok=True)

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        local_path   = user_root_local(username, ensure=False)
        roaming_path = user_root_roaming(username, ensure=False)

        msg = (
            f"Keyquorum Account Deletion Record\n"
            f"---------------------------------\n\n"
            f"User account: {username}\n"
            f"Deleted on: {now}\n\n"
            f"Password verified: {'YES' if password_ok else 'NO'}\n"
            f"2FA verified: {'YES' if twofa_ok else 'NO'}\n\n"
            f"Files deleted:\n"
        )

        for line in report:
            msg += f"- {line}\n"

        msg += (
            "\nManual verification recommended:\n"
            f"Local:   {local_path}\n"
            f"Roaming: {roaming_path}\n"
        )

        # --- Write internal audit tombstone ---
        af.write_text(msg, encoding="utf-8")

        # --- ALSO write to Desktop ---
        try:
            desktop = Path.home() / "Desktop"
            if desktop.exists():
                desktop_file = desktop / f"Keyquorum_Account_Deleted_{username}.txt"
                desktop_file.write_text(msg, encoding="utf-8")
        except Exception as e:
            log.warning(f"[DELETE] could not write desktop copy: {e}")

    except Exception as e:
        log.error(f"[DELETE] failed to write deletion audit: {e}")
