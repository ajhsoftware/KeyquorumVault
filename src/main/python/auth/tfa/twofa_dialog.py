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
import io
import logging
from typing import  Dict, Any

import pyotp, qrcode
from qtpy.QtCore import Qt, QRegularExpression, QCoreApplication
from qtpy.QtGui import QPixmap, QRegularExpressionValidator
from qtpy.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QApplication,
    QLineEdit, QPushButton, QMessageBox,
)

from auth.identity_store import (
    gen_backup_codes,
    get_totp_secret,
    has_totp_quick,
    replace_backup_codes,
    set_totp_secret,
)
from auth.login.login_handler import use_backup_code

log = logging.getLogger("keyquorum")

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
SAFE_KEYS = {"event", "username", "mode", "slot", "serial", "ok", "error"}


def _tr(ctx: str, txt: str) -> str:
    return QCoreApplication.translate(ctx, txt)

def _safe_2fa_log(event: str, username: str, **kv):
    safe = {k: v for k, v in kv.items() if k in SAFE_KEYS}
    log.info(f"[2FA] {event} user='{username}' | {safe}")

def _norm_code(s: str) -> str:
    return (s or "").strip().replace(" ", "").upper()

def _make_result(ok: bool, *, error: str | None = None,
                 uri: str | None = None, secret: str | None = None,
                 backup_codes: list[str] | None = None, qr_png: bytes | None = None) -> Dict[str, Any]:
    return {"ok": bool(ok), "error": error, "otpauth_uri": uri, "secret": secret,
            "backup_codes": backup_codes or [], "qr_png": qr_png}

# -----------------------------------------------------------------------------

def twofa_setup(parent, username: str, pwd: str | None = None) -> Dict[str, Any]:
    try:
        username = (username or "").strip()
        if not pwd:
            pwd = getattr(parent, "current_password", None)
        if not pwd:
            QMessageBox.critical(parent, _tr("2FA", "2FA"), _tr("2FA", "Password context is required to enable 2FA."))
            return {"ok": False, "error": "Missing password context"}

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=username, issuer_name="Keyquorum")

        buf = io.BytesIO()
        qrcode.make(uri).save(buf, format="PNG")
        qr_png = buf.getvalue()

        # ---------------- dialog ----------------
        dlg = QDialog(parent)
        dlg.setWindowTitle(_tr("2FA", "Set up Two-Factor Authentication"))

        lay = QVBoxLayout(dlg)

        lbl = QLabel(alignment=Qt.AlignCenter)
        pm = QPixmap()
        pm.loadFromData(qr_png, "PNG")
        lbl.setPixmap(pm.scaledToWidth(240))
        lay.addWidget(lbl)

        # Manual code + copy button
        secret_row = QHBoxLayout()
        secret_label = QLabel(_tr("2FA", "Manual code (Base32): <b>{secret}</b>").format(secret=secret))
        copy_btn = QPushButton(_tr("2FA", "Copy"))
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(secret))
        secret_row.addWidget(secret_label)
        secret_row.addWidget(copy_btn)
        lay.addLayout(secret_row)
        lay.addWidget(QLabel(_tr("2FA", "Enter a 6-digit code to confirm:")))

        code = QLineEdit()
        code.setPlaceholderText(_tr("2FA", "123456"))
        code.setAlignment(Qt.AlignCenter)
        code.setMaxLength(6)
        code.setValidator(QRegularExpressionValidator(QRegularExpression(r"^\d{0,6}$")))
        lay.addWidget(code)

        row = QHBoxLayout()
        okb = QPushButton(_tr("2FA", "Verify & Enable"))
        cab = QPushButton(_tr("2FA", "Cancel"))
        row.addWidget(okb)
        row.addWidget(cab)
        lay.addLayout(row)

        def _verify():
            c = code.text().strip()
            if len(c) != 6 or not c.isdigit():
                QMessageBox.warning(dlg, _tr("2FA", "Invalid Code"), _tr("2FA", "Please enter a 6-digit numeric code."))
                return
            if pyotp.TOTP(secret).verify(c, valid_window=1):
                dlg.accept()
            else:
                QMessageBox.warning(dlg, _tr("2FA", "Incorrect Code"), _tr("2FA", "That code didn’t work. Try again."))
                code.selectAll()
                code.setFocus()

        okb.clicked.connect(_verify)
        cab.clicked.connect(dlg.reject)
        code.returnPressed.connect(_verify)
        if dlg.exec():
            try:                
                set_totp_secret(username, pwd, secret)
                # Single source of truth for backup-code generation + persistence
                backup_codes = gen_backup_codes(
                    username,
                    b_type="2fa",
                    n=5,
                    L=8,
                    password_for_identity=pwd,
                )

                # Show backup codes ONCE (user should store them safely)
                try:
                    codes_dlg = QDialog(parent)
                    codes_dlg.setWindowTitle(_tr("2FA", "Save Your Backup Codes"))
                    v = QVBoxLayout(codes_dlg)
                    v.addWidget(QLabel(_tr("2FA", "⚠️ Store these codes safely. They won’t be shown again.")))

                    txt = QTextEdit()
                    txt.setReadOnly(True)
                    txt.setPlainText("\n".join(backup_codes))
                    v.addWidget(txt)

                    copy_all = QPushButton(_tr("2FA", "Copy All Codes"))
                    copy_all.clicked.connect(lambda: QApplication.clipboard().setText("\n".join(backup_codes)))
                    v.addWidget(copy_all)

                    ok_close = QPushButton(_tr("2FA", "Close"))
                    ok_close.clicked.connect(codes_dlg.accept)
                    v.addWidget(ok_close)

                    codes_dlg.exec()
                except Exception:
                    pass

                return {
                    "ok": True,
                    "secret": secret,
                    "otpauth_uri": uri,
                    "backup_codes": backup_codes,
                    "qr_png": qr_png
                }
            except Exception as e:
                QMessageBox.critical(parent, _tr("2FA", "2FA Error"),
                                     _tr("2FA", "Failed to save 2FA details.\n\n{err}").format(err=e))
                return {"ok": False, "error": str(e)}
        else:
            QMessageBox.information(parent, _tr("2FA", "2FA"),
                                    _tr("2FA", "Two-factor setup was canceled."))
            return {"ok": False, "error": "Setup canceled"}
    except Exception as e:
        log.info(f"2FA Setup Error: {e}")
# -----------------------------------------------------------------------------

class TwoFAPopup(QDialog):
    def __init__(self, verify_callback, parent=None, title="Enter 2FA Code"):
        super().__init__(parent)
        self.verify_callback = verify_callback
        self.setWindowTitle(self.tr(title))
        self.setModal(True)
        self.setMinimumWidth(320)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(self.tr("Enter your 6-digit code or a backup code:")))

        self.code_input = QLineEdit(self)
        self.code_input.setMaxLength(32)
        self.code_input.setPlaceholderText(self.tr("123456   or   ABCD-EF12"))
        self.code_input.returnPressed.connect(self._verify)
        layout.addWidget(self.code_input)

        self.err_label = QLabel("")
        self.err_label.setStyleSheet("color:#c00;")
        layout.addWidget(self.err_label)

        self.verify_btn = QPushButton(self.tr("Verify"), self)
        self.verify_btn.clicked.connect(self._verify)
        layout.addWidget(self.verify_btn)
        self.code_input.setFocus()

    def _verify(self):
        txt = (self.code_input.text() or "").strip()
        if not txt:
            self._show_err(self.tr("Please enter a code."))
            return

        code = txt.replace(" ", "").replace("—", "-").replace("–", "-").upper()
        self.verify_btn.setEnabled(False)
        self.err_label.clear()

        ok = False
        try:
            ok = bool(self.verify_callback(code))
        except Exception as e:
            log.warning("[2FA] popup_verify_error: %s", e)
            ok = False
        finally:
            self.verify_btn.setEnabled(True)

        if ok:
            self.accept()
        else:
            self._show_err(self.tr("That code didn’t work. Try again."))
            self.code_input.selectAll()
            self.code_input.setFocus()

    def _show_err(self, msg: str):
        self.err_label.setText(msg)

# -----------------------------------------------------------------------------

def prompt_2fa_for_user(parent, username: str) -> bool:
    username = (username or "").strip()
    pwd = getattr(parent, "current_password", None)
    if not pwd:
        QMessageBox.critical(parent, _tr("2FA", "2FA"), _tr("2FA", "Missing password context."))
        return False
    try:
        if not has_totp_quick(username):
            QMessageBox.warning(parent, _tr("2FA", "Two-Factor Authentication"),
                                _tr("2FA", "2FA is not set up for this account."))
            return False

        def _verify(code: str) -> bool:
            try:
                # Users often paste with spaces; This keep login tolerant.
                code = (code or "").strip().replace(" ", "")
                if code.isdigit() and 6 <= len(code) <= 8:
                    secret = get_totp_secret(username, pwd)
                    if not secret:
                        return False
                    return bool(pyotp.TOTP(secret).verify(code, valid_window=1))  # allow small clock skew
                return bool(use_backup_code(username, code, "2fa", password_for_identity=pwd))
            except Exception as e:
                # Log full traceback to diagnose DPAPI / identity-store issues.
                log.exception("[2FA] login_verify_error: %r", e)
                return False

        dlg = TwoFAPopup(_verify, parent=parent, title=_tr("2FA", "Enter 2FA code"))
        return dlg.exec() == QDialog.DialogCode.Accepted
    except Exception as e:
            log.exception("twofa_dialog error")
