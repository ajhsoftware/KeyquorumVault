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

import time as _t
import logging

from qtpy.QtCore import QCoreApplication, QThread, QTimer, Qt, Signal
from qtpy.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStackedLayout,
    QVBoxLayout,
)

from auth.login.login_handler import use_backup_code as _use_backup_code
from auth.pw.utils_recovery import _verify_recovery_key_local, recovery_key_to_mk
from auth.yubi.yk_backend import YKBackend

log = logging.getLogger("keyquorum")

try:
    from auth.yubi.yk_backend import set_probe_enabled
except Exception:
    def set_probe_enabled(val: bool):
        return None


def _tr(text: str) -> str:
    return QCoreApplication.translate("YubiKeyLoginGateDialog", text)


def _verify_and_consume_login_backup_with_pw(username: str, password_for_identity: str, code: str) -> bool:
    """Validate and consume a login backup code stored in the identity file."""
    try:
        return bool(
            _use_backup_code(
                username,
                code,
                "login",
                password_for_identity=password_for_identity or "",
            )
        )
    except Exception:
        return False



def _verify_recovery_key(username: str, recovery_key: str) -> bool:
    return bool(_verify_recovery_key_local(username, recovery_key))


class _YKTouchWorker(QThread):
    ok = Signal()
    err = Signal(str)

    def __init__(
        self,
        *,
        slot: int,
        serial: str | None,
        ykman_path: str | None,
        challenge_hex: str,
        timeout_s: int = 25,
    ):
        super().__init__()
        self.slot = int(slot or 2)
        self.serial = (serial or "").strip() or None
        self.ykman_path = (ykman_path or "").strip() or None
        self.challenge_hex = (challenge_hex or "").strip()
        self.timeout_s = int(max(5, timeout_s))

    def run(self):
        try:
            if self.isInterruptionRequested():
                return

            yk = YKBackend(self.ykman_path)

            try:
                if hasattr(yk, "slot_requires_touch") and not yk.slot_requires_touch(self.slot):
                    raise RuntimeError(
                        "This YubiKey slot is not configured to require touch. "
                        "Reprogram it with touch enabled in Settings → YubiKey."
                    )
            except RuntimeError:
                raise
            except Exception:
                pass

            deadline = _t.monotonic() + float(self.timeout_s)
            while _t.monotonic() < deadline:
                if self.isInterruptionRequested():
                    return

                slice_s = min(3.0, max(0.1, deadline - _t.monotonic()))
                try:
                    _ = yk.calculate_hmac(
                        self.slot,
                        self.challenge_hex,
                        self.serial,
                        timeout=float(slice_s),
                    )
                    if self.isInterruptionRequested():
                        return
                    self.ok.emit()
                    return
                except Exception as e:
                    msg = str(e).lower()
                    if "timed out" in msg or "touch" in msg:
                        continue
                    raise

            raise RuntimeError("Timed out waiting for YubiKey touch.")
        except Exception as e:
            self.err.emit(str(e) or repr(e))


class _YKWrapWorker(QThread):
    ok = Signal(bytes)
    err = Signal(str)

    def __init__(self, *, password_key: bytes, cfg: dict, timeout_s: int = 25):
        super().__init__()
        self.password_key = bytes(password_key or b"")
        self.cfg = dict(cfg or {})
        self.timeout_s = int(max(5, timeout_s))

    def run(self):
        try:
            if self.isInterruptionRequested():
                return

            from auth.yubi.yubihmac_wrap import unwrap_master_key_with_yubi

            mk = unwrap_master_key_with_yubi(
                b"",
                password_key=self.password_key,
                cfg=self.cfg,
            )

            if self.isInterruptionRequested():
                return

            if not isinstance(mk, (bytes, bytearray)) or len(mk) < 16:
                raise RuntimeError("YubiKey unwrap returned an invalid key.")

            self.ok.emit(bytes(mk))
        except Exception as e:
            self.err.emit(str(e) or repr(e))


class _YKPresenceWorker(QThread):
    found = Signal(bool, list)

    def __init__(self, ykman_path: str | None, want_serial: str | None):
        super().__init__()
        self.ykman_path = (ykman_path or "").strip() or None
        self.want_serial = (want_serial or "").strip() or None

    def run(self):
        try:
            if self.isInterruptionRequested():
                return

            yk = YKBackend(self.ykman_path)
            serials = list(yk.list_serials() or [])

            if self.want_serial:
                present = self.want_serial in serials or "(present)" in serials
            else:
                present = bool(serials)

            if not self.isInterruptionRequested():
                self.found.emit(bool(present), serials)
        except Exception:
            if not self.isInterruptionRequested():
                self.found.emit(False, [])


class YubiKeyLoginGateDialog(QDialog):
    """
    Modes:
      - yk_hmac_gate: requires YubiKey presence + touch to continue login
      - yk_hmac_wrap: requires YubiKey touch to unwrap MK and return it

    Fallback:
      - gate -> backup code
      - wrap -> backup code + recovery key
    """

    fallback_success = Signal()

    def __init__(
        self,
        *,
        username: str,
        password: str,
        cfg: dict,
        challenge_hex: str,
        password_key: bytes | None = None,
        insert_poll_ms: int = 1200,
        touch_timeout_s: int = 25,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle(self.tr("YubiKey Required"))
        self.setModal(True)
        self.setMinimumWidth(460)

        self.username = (username or "").strip()
        self.password = password or ""
        self.cfg = dict(cfg or {})
        self.challenge_hex = (challenge_hex or "").strip()
        self.password_key = (
            bytes(password_key)
            if isinstance(password_key, (bytes, bytearray, memoryview))
            else None
        )
        self.insert_poll_ms = int(max(400, insert_poll_ms))
        self.touch_timeout_s = int(max(5, touch_timeout_s))
        self._t0 = _t.monotonic()

        self.slot = int(self.cfg.get("slot", 2) or 2)
        self.serial = (self.cfg.get("serial") or "").strip() or None
        self.ykman_path = (self.cfg.get("ykman_path") or "").strip() or None
        self.mode = (self.cfg.get("mode") or "").strip().lower()

        self.result_mk = None
        self.result_mode = None
        self.last_error = ""

        self._closed = False
        self._presence_inflight = False
        self._touch_inflight = False
        self._presence_worker = None
        self._worker = None

        self.stack = QStackedLayout()

        p0 = QVBoxLayout()
        self.p0_status = QLabel(self.tr("Insert your YubiKey…"))
        self.p0_status.setWordWrap(True)
        p0.addWidget(self.p0_status)

        self.p0_bar = QProgressBar()
        self.p0_bar.setRange(0, 0)
        p0.addWidget(self.p0_bar)

        row0 = QHBoxLayout()
        backup_btn_text = (
            self.tr("Use backup code")
            if self.mode == "yk_hmac_gate"
            else self.tr("Use backup code + Recovery Key")
        )
        self.p0_backup_btn = QPushButton(backup_btn_text)
        self.p0_cancel_btn = QPushButton(self.tr("Cancel"))
        row0.addWidget(self.p0_backup_btn)
        row0.addStretch(1)
        row0.addWidget(self.p0_cancel_btn)
        p0.addLayout(row0)

        w0 = QDialog(self)
        w0.setLayout(p0)
        w0.setWindowFlags(Qt.Widget)
        self.stack.addWidget(w0)

        p1 = QVBoxLayout()
        label = (
            QLabel(self.tr("Enter a login backup code:"))
            if self.mode == "yk_hmac_gate"
            else QLabel(self.tr("Enter a login backup code and your Recovery Key:"))
        )
        p1.addWidget(label)

        self.backup_edit = QLineEdit()
        self.backup_edit.setPlaceholderText(self.tr("Login backup code (single-use)"))
        p1.addWidget(self.backup_edit)

        if self.mode == "yk_hmac_wrap":
            self.recovery_edit = QLineEdit()
            self.recovery_edit.setPlaceholderText(self.tr("Recovery Key"))
            p1.addWidget(self.recovery_edit)
        else:
            self.recovery_edit = None

        row1 = QHBoxLayout()
        self.p1_submit = QPushButton(self.tr("Submit"))
        self.p1_back = QPushButton(self.tr("Back"))
        row1.addWidget(self.p1_submit)
        row1.addStretch(1)
        row1.addWidget(self.p1_back)
        p1.addLayout(row1)

        w1 = QDialog(self)
        w1.setLayout(p1)
        w1.setWindowFlags(Qt.Widget)
        self.stack.addWidget(w1)

        v = QVBoxLayout(self)
        v.addLayout(self.stack)
        self.setLayout(v)
        self.stack.setCurrentIndex(0)

        self.p0_backup_btn.clicked.connect(self._enter_backup_mode)
        self.p0_cancel_btn.clicked.connect(self.reject)
        self.p1_submit.clicked.connect(self._try_backup)
        self.p1_back.clicked.connect(self._back_to_insert)

        self._poll = QTimer(self)
        self._poll.setInterval(self.insert_poll_ms)
        self._poll.timeout.connect(self._tick_insert)
        self._poll.start()

        self._touch_to = QTimer(self)
        self._touch_to.setSingleShot(True)
        self._touch_to.setInterval(self.touch_timeout_s * 1000)
        self._touch_to.timeout.connect(self._fallback_auto)

        try:
            set_probe_enabled(False)
        except Exception:
            pass

    def _set_last_error(self, msg: str) -> None:
        try:
            self.last_error = str(msg or "")
        except Exception:
            self.last_error = ""
        try:
            log.error("[YUBI-DLG] %s", self.last_error)
        except Exception:
            pass

    def reject(self):
        if not getattr(self, "last_error", ""):
            try:
                self.last_error = self.tr("YubiKey login was cancelled or could not be completed.")
            except Exception:
                self.last_error = "YubiKey login was cancelled or could not be completed."
        try:
            log.warning("[YUBI-DLG] reject mode=%s reason=%s", getattr(self, "mode", None), self.last_error)
        except Exception:
            pass
        return super().reject()

    def accept(self):
        try:
            mk = getattr(self, "result_mk", None)
            log.info(
                "[YUBI-DLG] accept mode=%s result_mode=%s mk_len=%s",
                getattr(self, "mode", None),
                getattr(self, "result_mode", None),
                len(mk) if isinstance(mk, (bytes, bytearray)) else 0,
            )
        except Exception:
            pass
        return super().accept()

    def _tick_insert(self):
        if self._closed or self._presence_inflight or self._touch_inflight:
            return
        if self.stack.currentIndex() == 1:
            return

        self._presence_inflight = True
        worker = _YKPresenceWorker(self.ykman_path, self.serial)
        worker.found.connect(self._on_presence_result)
        self._presence_worker = worker
        worker.start()

    def _enter_backup_mode(self):
        if self._closed:
            return
        try:
            if self._poll and self._poll.isActive():
                self._poll.stop()
        except Exception:
            pass
        try:
            if self._touch_to:
                self._touch_to.stop()
        except Exception:
            pass

        pw = self._presence_worker
        if pw is not None:
            try:
                pw.found.disconnect(self._on_presence_result)
            except Exception:
                pass
            self._stop_thread(pw)
            self._presence_worker = None
            self._presence_inflight = False

        # If the user switches to backup/recovery while a touch worker is still
        # running, stop it now so the dialog cannot be destroyed with a live thread.
        tw = self._worker
        if tw is not None:
            try:
                if hasattr(tw, "ok"):
                    try:
                        tw.ok.disconnect(self._touch_ok)
                    except Exception:
                        pass
                    try:
                        tw.ok.disconnect(self._wrap_ok)
                    except Exception:
                        pass
                if hasattr(tw, "err"):
                    try:
                        tw.err.disconnect(self._touch_err)
                    except Exception:
                        pass
                    try:
                        tw.err.disconnect(self._wrap_err)
                    except Exception:
                        pass
            except Exception:
                pass
            self._stop_thread(tw)
            self._worker = None
            self._touch_inflight = False

        self.stack.setCurrentIndex(1)

    def _back_to_insert(self):
        if self._closed:
            return

        self.stack.setCurrentIndex(0)
        self._t0 = _t.monotonic()
        try:
            self.p0_status.setText(self.tr("Insert your YubiKey…"))
        except Exception:
            pass
        try:
            if self._poll:
                self._poll.start()
        except Exception:
            pass

    def _on_presence_result(self, present: bool, serials: list):
        if self._closed:
            return

        self._presence_inflight = False
        self._presence_worker = None

        if not present:
            waited = int(_t.monotonic() - self._t0)
            try:
                self.p0_status.setText(
                    self.tr("Insert your YubiKey… (waiting {waited}s)").format(waited=waited)
                )
            except Exception:
                self.p0_status.setText(self.tr("Insert your YubiKey…"))
            return

        try:
            if self._poll and self._poll.isActive():
                self._poll.stop()
        except Exception:
            pass

        if self.mode == "yk_hmac_wrap":
            self._start_wrap_unwrap()
        else:
            self._start_touch()

    def _start_touch(self):
        if self._closed or self._touch_inflight:
            return

        self._touch_inflight = True
        self.p0_status.setText(self.tr("YubiKey detected. Touch the YubiKey to continue…"))
        try:
            self._touch_to.start()
        except Exception:
            pass

        self._worker = _YKTouchWorker(
            slot=self.slot,
            serial=self.serial,
            ykman_path=self.ykman_path,
            challenge_hex=self.challenge_hex,
            timeout_s=self.touch_timeout_s,
        )
        self._worker.ok.connect(self._touch_ok)
        self._worker.err.connect(self._touch_err)
        self._worker.start()

    def _start_wrap_unwrap(self):
        if self._closed or self._touch_inflight:
            return

        if not (isinstance(self.password_key, (bytes, bytearray)) and len(self.password_key) >= 16):
            msg = self.tr("Missing password context required for YubiKey WRAP.")
            self._set_last_error(msg)
            try:
                log.error("[YUBI-DLG] wrap start aborted: password_key missing/invalid len=%s", len(self.password_key) if isinstance(self.password_key, (bytes, bytearray)) else 0)
            except Exception:
                pass
            QMessageBox.critical(
                self,
                self.tr("Vault locked"),
                msg,
            )
            self.reject()
            return

        self._touch_inflight = True
        self.p0_status.setText(self.tr("YubiKey detected. Touch the YubiKey to continue…"))
        try:
            self._touch_to.start()
        except Exception:
            pass

        self._worker = _YKWrapWorker(
            password_key=bytes(self.password_key),
            cfg=self.cfg,
            timeout_s=self.touch_timeout_s,
        )
        self._worker.ok.connect(self._wrap_ok)
        self._worker.err.connect(self._wrap_err)
        self._worker.start()

    def _wrap_ok(self, mk: bytes):
        if self._closed:
            return
        self._touch_inflight = False
        try:
            self._touch_to.stop()
        except Exception:
            pass
        tw = self._worker
        self._worker = None
        if tw is not None:
            self._stop_thread(tw)
        self.result_mk = bytes(mk)
        self.result_mode = "wrap-hw"
        try:
            log.info("[YUBI-DLG] wrap ok mk_len=%s", len(self.result_mk))
        except Exception:
            pass
        self.accept()

    def _wrap_err(self, msg: str):
        if self._closed:
            return

        self._touch_inflight = False
        self._worker = None
        try:
            self._touch_to.stop()
        except Exception:
            pass

        self._set_last_error(msg or self.tr("YubiKey operation failed."))
        low = (msg or "").lower()
        if "no yubikey" in low or "not detected" in low:
            QMessageBox.information(
                self,
                self.tr("YubiKey required"),
                self.tr("No YubiKey was detected.\n\nInsert your YubiKey and try again."),
            )
        elif "timed out" in low or "touch" in low:
            QMessageBox.information(
                self,
                self.tr("YubiKey required"),
                self.tr("Timed out waiting for YubiKey touch."),
            )
        else:
            QMessageBox.critical(
                self,
                self.tr("YubiKey error"),
                msg or self.tr("YubiKey operation failed."),
            )

        if self.stack.currentIndex() == 0 and self._poll and not self._poll.isActive():
            self._poll.start()

    def _touch_ok(self):
        if self._closed:
            return
        self._touch_inflight = False
        try:
            self._touch_to.stop()
        except Exception:
            pass
        tw = self._worker
        self._worker = None
        if tw is not None:
            self._stop_thread(tw)
        self.result_mk = None
        self.result_mode = "gate-hw"
        try:
            log.info("[YUBI-DLG] gate touch ok")
        except Exception:
            pass
        self.accept()

    def _touch_err(self, msg: str):
        if self._closed:
            return

        self._touch_inflight = False
        self._worker = None
        self._set_last_error(msg or self.tr("YubiKey operation failed."))

        if self.mode == "yk_hmac_gate":
            msg_txt = self.tr("YubiKey error: {msg}\nYou can retry, or use a backup code.")
        else:
            msg_txt = self.tr("YubiKey error: {msg}\nYou can retry, or use a backup code + recovery key.")
        self.p0_status.setText(msg_txt.format(msg=msg))

        if self.stack.currentIndex() == 0 and self._poll and not self._poll.isActive():
            self._poll.start()

    def _fallback_auto(self):
        if self._closed:
            return
        self._enter_backup_mode()

    def _try_backup(self):
        if self._closed:
            return

        code = self.backup_edit.text().strip() if self.backup_edit else ""
        rk = self.recovery_edit.text().strip() if self.recovery_edit else ""
        mode = (self.mode or "").strip().lower()

        def _norm_rk(s: str) -> str:
            return "".join(ch for ch in (s or "") if ch.isalnum()).upper()

        if mode == "yk_hmac_gate":
            if not code:
                self._set_last_error(self.tr("Backup code was not entered."))
                QMessageBox.critical(self, self.tr("Backup Code"), self.tr("Please enter your login backup code."))
                return
            if not _verify_and_consume_login_backup_with_pw(self.username, self.password, code):
                self._set_last_error(self.tr("Backup code was invalid or already used."))
                QMessageBox.critical(self, self.tr("Backup Code"), self.tr("That backup code is invalid or already used."))
                return
            self.result_mk = None
            self.result_mode = "gate-backup"
            try:
                log.info("[YUBI-DLG] gate backup accepted")
            except Exception:
                pass
            self.accept()
            return

        if not code or not rk:
            self._set_last_error(self.tr("Recovery login details were incomplete."))
            QMessageBox.critical(
                self,
                self.tr("Missing details"),
                self.tr("Enter both a Recovery Key and a login backup code."),
            )
            return

        rk_norm = _norm_rk(rk)
        if not _verify_recovery_key(self.username, rk_norm):
            self._set_last_error(self.tr("Recovery Key was not valid for this account."))
            QMessageBox.critical(self, self.tr("Recovery Key"), self.tr("That Recovery Key is not valid for this account."))
            return

        if not _verify_and_consume_login_backup_with_pw(self.username, self.password, code):
            self._set_last_error(self.tr("Backup code was invalid or already used."))
            QMessageBox.critical(self, self.tr("Backup Code"), self.tr("That backup code is invalid or already used."))
            return

        try:
            mk = recovery_key_to_mk(rk_norm)
        except Exception:
            self._set_last_error(self.tr("Recovery Key could not be applied."))
            QMessageBox.critical(self, self.tr("Recovery Key"), self.tr("Could not apply Recovery Key."))
            return

        self.result_mk = bytes(mk)
        self.result_mode = "recovery+backup"
        try:
            log.info("[YUBI-DLG] recovery+backup accepted mk_len=%s", len(self.result_mk))
        except Exception:
            pass
        self.accept()

    def _stop_thread(self, worker_obj):
        if not worker_obj:
            return
        try:
            if isinstance(worker_obj, QThread):
                gui_thread = QCoreApplication.instance().thread() if QCoreApplication.instance() else None
                if worker_obj is gui_thread or worker_obj is QThread.currentThread():
                    return
                try:
                    worker_obj.requestInterruption()
                except Exception:
                    pass
                try:
                    worker_obj.quit()
                except Exception:
                    pass
                try:
                    worker_obj.wait(5000)
                except Exception:
                    pass
                return
        except Exception:
            pass

        try:
            if hasattr(worker_obj, "stop") and callable(worker_obj.stop):
                worker_obj.stop()
        except Exception:
            pass
        try:
            if hasattr(worker_obj, "join") and callable(worker_obj.join):
                worker_obj.join(timeout=1.5)
        except Exception:
            pass

    def _cleanup(self):
        if self._closed:
            return
        self._closed = True

        for tname in ("_poll", "_touch_to"):
            t = getattr(self, tname, None)
            if t is not None:
                try:
                    t.stop()
                except Exception:
                    pass
                try:
                    t.timeout.disconnect()
                except Exception:
                    pass
                setattr(self, tname, None)

        pw = getattr(self, "_presence_worker", None)
        if pw is not None:
            try:
                pw.found.disconnect(self._on_presence_result)
            except Exception:
                pass
            self._stop_thread(pw)
        self._presence_worker = None
        self._presence_inflight = False

        tw = getattr(self, "_worker", None)
        if tw is not None:
            try:
                if hasattr(tw, "ok"):
                    try:
                        tw.ok.disconnect(self._touch_ok)
                    except Exception:
                        pass
                    try:
                        tw.ok.disconnect(self._wrap_ok)
                    except Exception:
                        pass
                if hasattr(tw, "err"):
                    try:
                        tw.err.disconnect(self._touch_err)
                    except Exception:
                        pass
                    try:
                        tw.err.disconnect(self._wrap_err)
                    except Exception:
                        pass
            except Exception:
                pass
            self._stop_thread(tw)
        self._worker = None
        self._touch_inflight = False

        try:
            set_probe_enabled(False)
        except Exception:
            pass

    def accept(self):
        self._cleanup()
        super().accept()

    def reject(self):
        try:
            set_probe_enabled(False)
        except Exception:
            pass
        self._cleanup()
        super().reject()

    def closeEvent(self, e):
        try:
            set_probe_enabled(False)
        except Exception:
            pass
        self._cleanup()
        super().closeEvent(e)
