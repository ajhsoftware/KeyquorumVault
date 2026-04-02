"""Keyquorum Vault
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
from features.auth_store.authenticator_store import ( list_authenticators, add_authenticator, add_from_otpauth_uri, delete_authenticator,
    update_authenticator, get_current_code, import_otpauth_from_qr_image, build_otpauth_uri, export_otpauth_qr_bytes,)

from features.auth_store.authenticator_store import add_from_otpauth_uri
from features.clipboard.secure_clipboard import secure_copy
from security.baseline_signer import update_baseline
import numpy as np
from security.secure_audit import log_event_encrypted
from vault_store.vault_store import _dec_backup_bytes
from auth.login.login_handler import get_user_setting , set_user_setting
from contextlib import contextmanager
import datetime as dt 
import time as _t

try:
    import cv2  # OpenCV for QR decoding
except Exception:
    cv2 = None

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


# ==============================
# --- Camera QR Scanner Dialog
# ==============================
class _QRCameraScannerDialog(QDialog):
    """Minimal webcam QR scanner that returns an otpauth:// URI if found."""
    found_uri = None

    def __init__(self, parent=None, device_index=0):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Scan TOTP QR"))
        self.setModal(True)
        self.setMinimumSize(640, 480)

        self._video = QLabel(self)
        self._video.setAlignment(Qt.AlignCenter)
        self._hint = QLabel(self.tr("Point your camera at the TOTP QR code…"))
        self._hint.setStyleSheet("color: gray;")

        self._cancel = QPushButton(self.tr("Cancel"))
        self._cancel.clicked.connect(self.reject)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn_row.addWidget(self._cancel)

        lay = QVBoxLayout(self)
        lay.addWidget(self._video)
        lay.addWidget(self._hint)
        lay.addLayout(btn_row)

        # OpenCV capture
        try:
            if not cv2 == None:
                self._cv2 = cv2
        except Exception:
            self._cv2 = None
            self._hint.setText(self.tr("OpenCV not available. Install with: pip install opencv-python"))
            return

        self._cap = self._cv2.VideoCapture(device_index, self._cv2.CAP_DSHOW)
        if not self._cap or not self._cap.isOpened():
            self._hint.setText(self.tr("Could not open camera."))
            return

        self._det = self._cv2.QRCodeDetector()

        self._timer = QTimer(self)
        self._timer.setInterval(33)  # ~33 fps
        self._timer.timeout.connect(self._on_tick)
        self._timer.start()

    def _on_tick(self):
        if not self._cv2 or not self._cap:
            return
        ok, frame = self._cap.read()
        if not ok or frame is None:
            return

        # Detect/decode (multi) QR
        try:
            # Newer OpenCV: detectAndDecodeMulti
            retval, decoded_infos, points, _ = self._det.detectAndDecodeMulti(frame)
            payloads = decoded_infos if (retval and decoded_infos) else []
        except Exception:
            # Fallback: single
            payload, pts = self._det.detectAndDecode(frame)
            payloads = [payload] if payload else []
            points = [pts] if pts is not None else None

        # If saw an otpauth URI, accept and close
        for s in payloads:
            if isinstance(s, str) and s.startswith("otpauth://"):
                self.found_uri = s.strip()
                self.accept()
                return

        # Draw boxes
        if points is not None and len(points) > 0:
            try:
                # points: list of arrays Nx1x2 or Nx2
                for p in points:
                    pts = p.reshape(-1, 2).astype(int)
                    for i in range(len(pts)):
                        a = tuple(pts[i]); b = tuple(pts[(i+1) % len(pts)])
                        self._cv2.line(frame, a, b, (0, 255, 0), 2)
            except Exception:
                pass

        rgb = self._cv2.cvtColor(frame, self._cv2.COLOR_BGR2RGB)
        h, w, ch = rgb.shape
        qimg = QImage(rgb.data, w, h, ch * w, QImage.Format.Format_RGB888)
        self._video.setPixmap(QPixmap.fromImage(qimg))

    def reject(self):
        self._cleanup()
        super().reject()

    def accept(self):
        self._cleanup()
        super().accept()

    def _cleanup(self):
        try:
            if hasattr(self, "_timer") and self._timer: self._timer.stop()
        except Exception:
            pass
        try:
            if hasattr(self, "_cap") and self._cap and self._cap.isOpened():
                self._cap.release()
        except Exception:
            pass


def init_authenticator_tab(w):
    tbl = getattr(w, "authTable", None)
    if tbl is None:
        return

    # ensure headers (in case Designer didn’t save them)
    try:
        if tbl.columnCount() < 8:
            tbl.setColumnCount(8)
        tbl.setHorizontalHeaderLabels(
            ["Label", "Code", "Remaining", "Account", "Issuer", "Algorithm", "Digits", "Period"]
        )
        tbl.setEditTriggers(tbl.EditTrigger.NoEditTriggers)
        tbl.setSelectionBehavior(tbl.SelectionBehavior.SelectRows)
    except Exception:
        pass
    # 1-sec timer for rolling codes
    try:
        w._auth_timer = QTimer(w)
        w._auth_timer.setInterval(1000)
        w._auth_timer.timeout.connect(lambda: _auth_refresh_codes(w))
        w._auth_timer.start()
    except Exception:
        pass
    # start locked on login screen
    try:
        _auth_set_enabled(w, False)
    except Exception:
        pass

    log.debug("%s [UI] Authenticator tab (table config + timer)", kql.i("ok"))

def _auth_after_login(self):
    """Enable the Authenticator tab and populate it after a successful login."""
    try:
        log.debug(f"[AUTH] after login active_user={self._active_username()!r}")
        _auth_set_enabled(self, True)
        _auth_reload_table(self)
    except Exception as e:
        log.debug(f"{kql.i('err')} AUTH after_login {e}")
        pass

def _auth_show_qr_selected(self):
    """Show a QR for the selected authenticator so the user can add it to another app."""
    if not _auth_require_login(self):
        QMessageBox.warning(self, self.tr("Authenticator"), self.tr("Please log in first."))
        return

    row = _auth_selected_row(self)
    it = _auth_row_entry(self, row)
    if not it:
        QMessageBox.information(self, self.tr("Show QR"), self.tr("Please select an authenticator entry first."))
        return

    # Safety confirmation
    msg =  self.tr("This will display the QR code for the authenticator secret.\n\nOnly do this on a trusted device.\n\nContinue?")
    res = QMessageBox.question(
        self,
        self.tr("Reveal 2FA QR"), msg,
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No
    )
    if res != QMessageBox.Yes:
        return

    try:
        # Generate QR PNG bytes and URI
        png_bytes = export_otpauth_qr_bytes(self.core_session_handle, it)
        uri = build_otpauth_uri(self.core_session_handle, it)
        dlg = QDialog(self)
        dlg.setWindowTitle(self.tr("Authenticator QR"))
        layout = QVBoxLayout(dlg)

        img = QLabel()
        pix = QPixmap()
        pix.loadFromData(png_bytes, "PNG")
        img.setPixmap(pix)
        img.setAlignment(Qt.AlignCenter)
        layout.addWidget(img)

        btn_copy = QPushButton(self.tr("Copy otpauth:// URI"))
        btn_copy.clicked.connect(lambda: secure_copy(uri, ttl_ms=self.clipboard_timeout, username=self._active_username()))
        if hasattr(self, "_toast"): self._toast("Code copied")
        layout.addWidget(btn_copy)

        dlg.exec()

    except Exception as e:
        QMessageBox.warning(
            self,
            self.tr("QR Error"),
            self.tr("Could not generate QR:\n\n{err}").format(err=e),
        )

def _auth_set_enabled(self, enabled: bool):
    t = getattr(self, "_auth_timer", None)
    if enabled:
        if t is None:
            self._auth_timer = t = QTimer(self)
            t.setInterval(1000)               # 1s tick
            t.timeout.connect(lambda: _auth_tick(self))
        if not t.isActive():
            t.start()
    else:
        if t and t.isActive():
            t.stop()

def _auth_tick(self):
    if not self._auth_entries:
        return
    table = getattr(self, "authTable", None)
    if not table:
        return

    for r, e in enumerate(self._auth_entries):
        try:
            code, rem = get_current_code(self.core_session_handle, e)
        except Exception:
            code, rem = "—", 0

        if table.item(r, 1) is None:
            table.setItem(r, 1, QTableWidgetItem(str(code)))
        else:
            table.item(r, 1).setText(str(code))

        # Remaining column = 2
        if table.item(r, 2) is None:
            table.setItem(r, 2, QTableWidgetItem(str(int(rem))))
        else:
            table.item(r, 2).setText(str(int(rem)))

def _auth_require_login(self) -> bool:
    return bool(isinstance(getattr(self, 'core_session_handle', None), int) and self.core_session_handle and self._active_username())

def _auth_rows(self):
    uname = (self._active_username() or "").strip()
    if not uname:
        return []
    return list_authenticators(uname, self.core_session_handle)

def _auth_reload_table(self):
    if not _auth_require_login(self):
        return

    rows = _auth_rows(self) or []
    self._auth_entries = rows 

    self.authTable.setRowCount(len(rows))
    for i, it in enumerate(rows):
        vals = [
            it.get("label",""),          # 0 Label
            "—",                         # 1 Code
            "—",                         # 2 Remaining
            it.get("account",""),        # 3 Account
            it.get("issuer",""),         # 4 Issuer
            it.get("algorithm","SHA1"),  # 5 Algorithm
            str(it.get("digits",6)),     # 6 Digits
            str(it.get("period",30)),    # 7 Period
        ]
        for c, v in enumerate(vals):
            self.authTable.setItem(i, c, QTableWidgetItem(v))

        self.authTable.item(i, 0).setData(Qt.ItemDataRole.UserRole, it.get("id"))

    _auth_refresh_codes(self)

def _auth_selected_row(self) -> int:
    sel = self.authTable.selectionModel().selectedRows() if self.authTable.selectionModel() else []
    return sel[0].row() if sel else -1

def _auth_row_entry(self, row: int) -> dict | None:
    rows = self._auth_entries or []
    return rows[row] if 0 <= row < len(rows) else None

def _auth_refresh_codes(self):
    if not _auth_require_login(self): return
    rows = _auth_rows(self)
    self._auth_entries = rows
    for i, it in enumerate(rows):
        try:
            code, rem = get_current_code(self.core_session_handle, it)
        except Exception:
            code, rem = ("—", 0)
        if i < self.authTable.rowCount():
            self.authTable.item(i, 1).setText(code)
            self.authTable.item(i, 2).setText(str(rem))

def _auth_add_manual(self):
    if not _auth_require_login(self): 
        QMessageBox.warning(self, self.tr("Authenticator"), self.tr("Please log in first."))
        return

    label, ok = QInputDialog.getText(self, self.tr("Add Authenticator"), self.tr("Label:"))
    if not ok or not label.strip(): return

    account, ok = QInputDialog.getText(self, self.tr("Add Authenticator"), self.tr("Account:"))
    if not ok: return

    issuer, ok = QInputDialog.getText(self, self.tr("Add Authenticator"), self.tr("Issuer:"))
    if not ok: return

    secret, ok = QInputDialog.getText(self, self.tr("Add Authenticator"), self.tr("Secret (BASE32):"))
    if not ok or not secret.strip(): return

    digits, ok = QInputDialog.getInt(self, self.tr("Add"), self.tr("Digits:"), 6, 6, 8, 1)
    if not ok: return

    period, ok = QInputDialog.getInt(self, self.tr("Add"), self.tr("Period (s):"), 30, 15, 90, 1)
    if not ok: return

    algo, ok = QInputDialog.getItem(self, self.tr("Add"), self.tr("Algorithm:"),
                                    ["SHA1","SHA256","SHA512"], 0, False)
    if not ok: return

    add_authenticator(self._active_username(), self.core_session_handle,
                        label=label, account=account, issuer=issuer,
                        secret_base32=secret, digits=digits,
                        period=period, algorithm=algo)
    update_baseline(username=self._active_username(), verify_after=False, who=self.tr("Auth Store Added (Manually)"))
    _auth_reload_table(self)

def _auth_add_from_camera(self):
    if not _auth_require_login(self):
        QMessageBox.warning(self, self.tr("Authenticator"), self.tr("Please log in first."))
        return
    try:
        dlg = self._QRCameraScannerDialog(self) if hasattr(self, "_QRCameraScannerDialog") else _QRCameraScannerDialog(self)
    except NameError:
        dlg = _QRCameraScannerDialog(self)
    if dlg.exec():
        uri = dlg.found_uri
        if uri and uri.startswith("otpauth://"):
            try:
                uname = self._active_username()
                add_from_otpauth_uri(uname, self.core_session_handle, uri)
                update_baseline(username=uname, verify_after=False, who=self.tr("Auth Store Added (On Screen QR)"))
                _auth_reload_table(self)
                if hasattr(self, "_toast"): self._toast("Authenticator added")
            except Exception as e:
                QMessageBox.critical(
                    self,
                    self.tr("Add from Camera"),
                    # Translate failure message with a template
                    self.tr("Failed: {err}").format(err=e),
                )
        else:
            QMessageBox.information(self, self.tr("Add from Camera"), self.tr("No otpauth:// QR detected."))

def _auth_add_from_qr(self):
    if not _auth_require_login(self): 
        QMessageBox.warning(self, self.tr("Authenticator"), self.tr("Please log in first.")); return
    fn, _ = QFileDialog.getOpenFileName(self, self.tr("Select QR Image"), "", "Images (*.png *.jpg *.jpeg *.bmp)")
    if not fn: return
    uri = import_otpauth_from_qr_image(fn)
    if not uri:
        QMessageBox.warning(self, self.tr("Add from QR"), self.tr("Could not read an otpauth:// QR from that image.")); return
    add_from_otpauth_uri(self._active_username(), self.core_session_handle, uri)
    update_baseline(username=self._active_username(), verify_after=False, who=self.tr("Auth Store Added (QR Image)")) 
    _auth_reload_table(self)

def _auth_edit_selected(self):
    if not _auth_require_login(self): return
    row = _auth_selected_row(self); it = _auth_row_entry(self, row)
    if not it: QMessageBox.information(self, self.tr("Edit"), self.tr("Select an entry first.")); return
    label, ok = QInputDialog.getText(self, self.tr("Edit"), self.tr("Label:"), text=it.get("label",""));           
    if not ok: return
    account, ok = QInputDialog.getText(self, self.tr("Edit"), self.tr("Account:"), text=it.get("account",""));     
    if not ok: return
    issuer, ok = QInputDialog.getText(self, self.tr("Edit"), self.tr("Issuer:"), text=it.get("issuer",""));        
    if not ok: return
    algo, ok = QInputDialog.getItem(self, self.tr("Edit"), self.tr("Algorithm:"), ["SHA1","SHA256","SHA512"],
                                    ["SHA1","SHA256","SHA512"].index(it.get("algorithm","SHA1")), False); 
    if not ok: return
    digits, ok = QInputDialog.getInt(self, self.tr("Edit"), self.tr("Digits:"), int(it.get("digits",6)), 6, 8, 1); 
    if not ok: return
    period, ok = QInputDialog.getInt(self, self.tr("Edit"), self.tr("Period:"), int(it.get("period",30)), 15, 90, 1); 
    if not ok: return
    if update_authenticator(
        self._active_username(),
        self.core_session_handle,
        it["id"],
        label=label,
        account=account,
        issuer=issuer,
        algorithm=algo,
        digits=digits,
        period=period,
    ):
        update_baseline(username=self._active_username(), verify_after=False, who=self.tr("Auth Store Edited")) 
        _auth_reload_table(self)

def _auth_delete_selected(self):
    if not _auth_require_login(self): return
    row = _auth_selected_row(self); it = _auth_row_entry(self, row)
    if not it: QMessageBox.information(self, self.tr("Delete"), self.tr("Select an entry first.")); return
    # Ask confirmation using a template to allow translation
    if (
        QMessageBox.question(
            self,
            self.tr("Delete"),
            self.tr("Remove '{label}'?").format(label=it.get("label", "Authenticator")),
        )
        != QMessageBox.StandardButton.Yes
    ):
        return
    if delete_authenticator(self._active_username(), self.core_session_handle, it["id"]):
        _auth_reload_table(self)
    update_baseline(self._active_username(), verify_after=False, who=self.tr("Auth Store Deleted Entry"))
   
def _auth_copy_code(self):
    if not _auth_require_login(self): return
    row = _auth_selected_row(self); it = _auth_row_entry(self, row)
    if not it: QMessageBox.information(self, self.tr("Copy"), self.tr("Select an entry first.")); return
    code, _ = get_current_code(self.core_session_handle, it)
    try:
        uname = self._active_username()
        secure_copy(code, self.clipboard_timeout, uname)
        log_event_encrypted(uname, "Auth Store", "Code Copied")
        if hasattr(self, "_toast"): self._toast(self.tr("Code copied"))
    except Exception:
        QGuiApplication.clipboard().setText(code)
        if hasattr(self, "_toast"): self._toast(self.tr("Code copied"))
    
# --- auth screen scan ---
def _qimage_to_numpy(img: QImage) -> np.ndarray:
    """Convert QImage to an OpenCV BGR ndarray (PySide6-safe)."""
    # Normalize to a known 4-channel format
    img = img.convertToFormat(QImage.Format.Format_RGBA8888)
    w, h = img.width(), img.height()

    # PySide6 returns a memoryview; convert to bytes then to ndarray
    mv = img.constBits()  # or img.bits()
    data = mv.tobytes()   # length == img.sizeInBytes()
    arr = np.frombuffer(data, dtype=np.uint8).reshape((h, w, 4))

    # RGBA -> BGR (OpenCV default)
    bgr = arr[:, :, 2::-1].copy()
    return bgr

def _confirm_auth_scan(self) -> bool:
    """
    Ask the user to make sure the QR code is visible before scanning.
    Includes a 'Don't show again' checkbox persisted in settings.
    Returns True if the user wants to proceed.
    """
    try:
        # Respect saved preference
        suppress = bool(get_user_setting("__global__", "suppress_auth_scan_prompt"))
    except Exception:
        suppress = False

    if suppress:
        return True
    msg = QMessageBox(self)
    msg.setWindowTitle(self.tr("QR Scan"))
    msg.setIcon(QMessageBox.Information)
    msg.setText(self.tr(
        "Make sure the TOTP QR code is visible on your screen.\n\n"
        "When you click OK, Keyquorum will briefly minimize, scan all screens, "
        "and auto-add any authenticator QR it finds.")
    )
    msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
    msg.setDefaultButton(QMessageBox.Ok)

    chk = QCheckBox(self.tr("Don’t show this again"))
    msg.setCheckBox(chk)

    res = msg.exec()
    if res == QMessageBox.Ok:
        # Persist the preference if they checked the box
        try:
            set_user_setting("__global__", "suppress_auth_scan_prompt", bool(chk.isChecked()))
        except Exception:
            pass
        return True
    return False


@contextmanager
def _hide_for_screen_scan(self, delay_ms: int = 250):
    # NOTE: screenshot is only for scanning QR on screen only
    was_visible = False
    prev_opacity = 1.0
    try:
        was_visible = self.isVisible()
        prev_opacity = self.windowOpacity()

        # Hide quickly & flush events so the window is gone before grabbing screen
        self.setWindowOpacity(0.0)
        self.hide()
        QApplication.processEvents()

        _t.sleep(max(0, delay_ms) / 1000.0)

        yield

    except Exception as e:
        log.error(f"[AUTH] Hide Window Error {e}")

    finally:
        try:
            if was_visible:
                self.show()
                self.raise_()
                self.activateWindow()
            self.setWindowOpacity(prev_opacity)
            QApplication.processEvents()
        except Exception:
            pass

def _auth_add_from_screen(self):
    if not _auth_require_login(self):
        QMessageBox.warning(self, self.tr("Authenticator"), self.tr("Please log in first."))
        return
    if cv2 is None:
        QMessageBox.warning(self, self.tr("QR Scan"), self.tr("OpenCV (cv2) is not available. Install 'opencv-python'."))
        return

    # --- confirmation (with 'don't show again') ---
    if not _confirm_auth_scan(self):
        return

    try:
        # Hide the window briefly so it isn’t captured
        with _hide_for_screen_scan(self, 300):
            screens = QGuiApplication.screens() or []
            if not screens:
                QMessageBox.warning(self, self.tr("QR Scan"), self.tr("No screens detected."))
                return

            detector = cv2.QRCodeDetector()
            found = []

            for s in screens:
                pm = s.grabWindow(0)
                img = pm.toImage()
                bgr = _qimage_to_numpy(img)

                # Preprocess for robustness on screenshots
                gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
                gray = cv2.equalizeHist(gray)
                gray = cv2.medianBlur(gray, 3)

                decoded = []
                try:
                    ok, texts, points, _ = detector.detectAndDecodeMulti(gray)
                    if ok and texts:
                        decoded.extend(texts)
                except Exception:
                    pass
                if not decoded:
                    try:
                        t, _ = detector.detectAndDecode(gray)
                        if t:
                            decoded.append(t)
                    except Exception:
                        pass

                for t in decoded:
                    t = (t or "").strip()
                    if not t:
                        continue
                    if "otpauth" in t.lower() and not t.lower().startswith("otpauth://"):
                        t = "otpauth://" + t.split("otpauth://")[-1]
                    if t.startswith("otpauth://"):
                        found.append((s.name(), t))

        if not found:
            QMessageBox.information(self, self.tr("QR Scan"), self.tr("No otpauth:// QR codes detected on the screens."))
            return

        # If multiple, let user choose
        if len(found) > 1:

            labels = [f"{sn}: {uri[:80]}..." for sn, uri in found]
            choice, ok = QInputDialog.getItem(self, "Multiple QR codes found", "Choose one to import:", labels, 0, False)
            if not ok:
                return
            idx = labels.index(choice)
            _, uri = found[idx]
        else:
            _, uri = found[0]

        add_from_otpauth_uri(self.currentUsername.text().strip(), self.core_session_handle, uri)
        update_baseline(username=self.currentUsername.text(), verify_after=False, who=self.tr("Auth Store Vault changed")) 
        _auth_reload_table(self)
        if hasattr(self, "_toast"):
            self._toast(self.tr("Authenticator added from screen"))

    except Exception as e:
        QMessageBox.critical(
            self,
            self.tr("QR Scan Error"),
            self.tr("Failed to scan screen:\n\n{err}").format(err=e))

# ==============================
# --- auth export/import (safe, encrypted) ---
# ==============================

def _auth_export_safe(self):
    """
    Safely export all authenticator entries for the current user.

    - Always encrypted with a user-chosen password (no plaintext option).
    - Format: JSON wrapped in AES-GCM via _enc_backup_bytes.
    - Contains only the data needed to recreate the authenticator entries,
      including an otpauth:// URI for each one.
    """
    from vault_store.vault_store import _enc_backup_bytes

    if not _auth_require_login(self):
        QMessageBox.warning(self, self.tr("Authenticator Export"), self.tr("Please log in first."))
        return

    username = self._active_username()
    if not username:
        QMessageBox.warning(self, self.tr("Authenticator Export"), self.tr("No active user."))
        return

    if not self.verify_sensitive_action(username, title="Export Auth Only"):
        return

    try:
        rows = list_authenticators(username, self.core_session_handle) or []
    except Exception as e:
        msg = self.tr("Failed to read authenticators:") + f"\n{e}"
        QMessageBox.critical(self, self.tr("Authenticator Export"), msg)
        return

    if not rows:
        QMessageBox.information(self, self.tr("Authenticator Export"), self.tr("No authenticator entries to export."))
        return

    # --- Ask for password (mandatory, with confirmation) ---
    pw1, ok = QInputDialog.getText(
        self, self.tr("Export Authenticators"),
        self.tr("Set a password to encrypt this authenticator backup") + ":\n\n⚠️ " +
        self.tr("This file contains your 2FA secrets. Keep it safe."),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not pw1.strip():
        return

    pw2, ok = QInputDialog.getText(
        self, self.tr("Confirm Password"),
        self.tr("Re-enter the password:"),
        QLineEdit.EchoMode.Password,
    )
    if not ok or pw1 != pw2:
        QMessageBox.warning(self, self.tr("Authenticator Export"), self.tr("Passwords do not match."))
        return

    password = pw1

    # --- Build export payload ---
    try:
        export_items = []
        for it in rows:
            try:
                uri = build_otpauth_uri(self.core_session_handle, it)
            except Exception:
                uri = None

            export_items.append({
                "label":     it.get("label", ""),
                "account":   it.get("account", ""),
                "issuer":    it.get("issuer", ""),
                "algorithm": it.get("algorithm", "SHA1"),
                "digits":    int(it.get("digits", 6) or 6),
                "period":    int(it.get("period", 30) or 30),
                "otpauth_uri": uri,
            })
        payload = {
            "format": "keyquorum.auth.v1",
            "username_hint": username,
            "created_utc": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "count": len(export_items),
            "entries": export_items,
        }
        raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    except Exception as e:
        QMessageBox.critical(self, self.tr("Authenticator Export"), f"Failed to prepare data:\n{e}")
        return

    # --- Choose file path ---
    default_name = f"{username}_auth_backup.kqa.enc"
    out_path, _ = QFileDialog.getSaveFileName(
        self,
        "Save Authenticator Backup",
        default_name,
        "Keyquorum Auth Backup (*.kqa.enc)",
    )
    if not out_path:
        return

    try:
        enc = _enc_backup_bytes(password, raw)
        from pathlib import Path
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_bytes(enc)
        try:
            os.chmod(out_path, 0o600)
        except Exception:
            pass
        try:
            log_event_encrypted(username, self.tr("auth_backup"), f"{kql.i('ok')} Authenticator backup exported")
        except Exception:
            pass
        msg = "✅" + self.tr(" Authenticator backup saved successfully.") + "\n\n⚠️" + self.tr(" This file contains your 2FA secrets.\n Store it offline in a safe place (e.g., encrypted USB).")
        QMessageBox.information(
            self,
            self.tr("Authenticator Exported"),msg)
    except Exception as e:
        msg = self.tr(f"Failed to save backup:") + f"\n{e}"
        QMessageBox.critical(self, self.tr("Authenticator Export"), msg)

def _auth_import_safe(self):
    """
    Import authenticators from a password-encrypted Keyquorum auth backup (.kqa.enc).

    - Always asks for a password and refuses plaintext files.
    - Entries are added via add_from_otpauth_uri (preferred) or add_authenticator.
    """
    if not _auth_require_login(self):
        QMessageBox.warning(self, self.tr("Authenticator Import"), self.tr("Please log in first."))
        return

    username = self._active_username()
    if not username:
        QMessageBox.warning(self, self.tr("Authenticator Import"), self.tr("No active user."))
        return

    # Pick file
    file_path, _ = QFileDialog.getOpenFileName(
        self,
        self.tr("Select Authenticator Backup"),
        "",
        "Keyquorum Auth Backup (*.kqa.enc *.enc)",
    )
    if not file_path:
        return

    # Password
    pw, ok = QInputDialog.getText(
        self,
        self.tr("Authenticator Import"),
        self.tr("Enter the password used to encrypt this authenticator backup:"),
        QLineEdit.EchoMode.Password,
    )
    if not ok or not pw.strip():
        return
    password = pw

    # Decrypt
    try:
        from pathlib import Path
        raw_enc = Path(file_path).read_bytes()
        raw = _dec_backup_bytes(password, raw_enc)
    except Exception as e:
        QMessageBox.critical(self, self.tr("Authenticator Import"), f"Decryption failed:\n{e}")
        return

    # Parse JSON
    try:
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("format") != "keyquorum.auth.v1":
            QMessageBox.critical(
                self,
                self.tr("Authenticator Import"),
                self.tr("This file does not look like a Keyquorum authenticator backup."),
            )
            return
        entries = payload.get("entries") or []
        if not isinstance(entries, list):
            entries = []
    except Exception as e:
        QMessageBox.critical(self, self.tr("Authenticator Import"), f"Failed to parse backup:\n{e}")
        return

    if not entries:
        QMessageBox.information(self, self.tr("Authenticator Import"), self.tr("No entries found in this backup."))
        return

    # Confirm (these are very sensitive)
    res = QMessageBox.question(
        self,
        self.tr("Import Authenticators"),
        self.tr("This will add authenticator entries (2FA codes) into your account.\n\n"
        "Only proceed if you trust this backup file.\n\nContinue?"),
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No,
    )
    if res != QMessageBox.Yes:
        return

    added = failed = 0
    for it in entries:
        try:
            uri = (it.get("otpauth_uri") or "").strip()
            if uri.startswith("otpauth://"):
                add_from_otpauth_uri(username, self.core_session_handle, uri)
            else:
                # Fallback: construct from fields
                add_authenticator(
                    username,
                    self.core_session_handle,
                    label=it.get("label", ""),
                    account=it.get("account", ""),
                    issuer=it.get("issuer", ""),
                    secret_base32=it.get("secret_base32", ""),
                    digits=int(it.get("digits", 6) or 6),
                    period=int(it.get("period", 30) or 30),
                    algorithm=it.get("algorithm", "SHA1"),
                )
            added += 1
        except Exception as e:
            failed += 1
            try:
                log.error(f"[auth] failed to import authenticator: {e}")
            except Exception:
                pass

    # Refresh UI
    try:
        update_baseline(username=username, verify_after=False, who=self.tr("Authenticator Backup Imported"))
    except Exception:
        pass

    _auth_reload_table(self)

    msg = "✅ " + self.tr("Authenticator import complete.\n\n• Added:") + f"{added}"
    if failed:
        msg += f"\n• Failed: {failed}"
    QMessageBox.information(self, self.tr("Authenticator Import"), msg)
