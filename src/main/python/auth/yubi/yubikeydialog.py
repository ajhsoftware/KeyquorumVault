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

from typing import Optional, Dict, Any
import logging, inspect, binascii, time as _t

from qtpy.QtCore import Qt, QThread, Signal, QTimer
from qtpy.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QRadioButton, QGroupBox, QMessageBox, QProgressBar)

from qtpy.QtCore import Signal as QtSignal

log = logging.getLogger("keyquorum")
L = lambda m: log.debug("[yk-setup] " + m)

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("yubikeydialog", text)

# --- Yubi Backend ---
from auth.yubi.yk_backend import YKBackend
# --- Two-of-two helpers (support both module names) ---
try:
    from auth.tfa.two_of_two import enable_yk_hmac_gate
except Exception:
    enable_yk_hmac_gate = None

# --- Identity store
from auth.identity_store import get_yubi_meta_quick, set_yubi_config, bind_recovery_wrapper, bind_yubi_wrapper, clear_yubi_config

# ==============================
# ---------------- Small modal "Touch" spinner ----------------
# ==============================

class _TouchPrompt(QDialog):
    cancelled = Signal()
    def __init__(self, parent=None, title="YubiKey", message=_tr("Touch your YubiKey to continue…"),  timeout_s=25):
        super().__init__(parent)
        self.setWindowTitle(_tr(title)); self.setModal(True); self.setMinimumWidth(360)
        self.setWindowFlag(Qt.WindowCloseButtonHint, False)
        v = QVBoxLayout(self)
        lab = QLabel(message, self); lab.setWordWrap(True); v.addWidget(lab)
        bar = QProgressBar(self); bar.setRange(0, 0); v.addWidget(bar)
        row = QHBoxLayout(); row.addStretch(1)
        btn = QPushButton(_tr("Cancel"), self); btn.clicked.connect(self._on_cancel); row.addWidget(btn)
        v.addLayout(row)

        self.timeout_s = timeout_s
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._update_countdown)
        self.start_time = _t.monotonic()
        
        self.countdown_label = QLabel(f"{self.timeout_s}s remaining")

        v.addWidget(self.countdown_label)
        
        self.timer.start(500)  # Update twice per second

    def _update_countdown(self):
        elapsed = _t.monotonic() - self.start_time
        remaining = max(0, int(self.timeout_s - elapsed))
        self.countdown_label.setText(f"{remaining}s remaining")

    def _on_cancel(self):
        self.cancelled.emit(); self.reject()

# ---------------- Worker: enable in background ----------------

yubi_warning = _tr("""
🔐 WRAP Mode: Maximum Security

WRAP binds your vault encryption to BOTH:
  • Your Password
  • Your YubiKey

📌 What This Means:
  • A stolen vault file alone is insufficient to decrypt your data
  • Decryption additionally requires your physical YubiKey or a valid Recovery Key
  • TOTP / Authenticator 2FA will NOT work as recovery

⚠️ CRITICAL: Recovery Key Required
  • You will receive a NEW Recovery Key after setup
  • If you lose your YubiKey, you MUST have:
    - Your Password + Recovery Key (+ Backup Login Code if enabled)

✅ Before Proceeding:
  • Create a full encrypted vault backup (File → Export)
  • Store your Recovery Key offline (paper/USB)
  • Test your backup before logging out

Continue with WRAP setup?
""")

# ==============================
# ---------------- Yubi enable worker ----------------
# ==============================

class _YkEnableWorker(QThread):
    status = Signal(str)
    needs_touch = Signal()
    done = Signal(dict)

    def __init__(self, *, mode: str, username: str, master_key: Optional[bytes],
                 serial: Optional[str], slot: int, ykman_path: Optional[str],
                 password: str):
        super().__init__()
        self.mode = mode  # "wrap" or "gate"
        self.username = username
        self.master_key = master_key
        self.serial = serial
        self.slot = int(slot or 2)
        self.ykman_path = ykman_path
        self.password = password

    def _call_helper(self, fn, **kwargs):
        if fn is None: return None
        sig = inspect.signature(fn)
        return fn(**{k: v for k, v in kwargs.items() if k in sig.parameters})

    def run(self):
        try:
            self.status.emit(_tr("Preparing YubiKey backend…"))
            yk = YKBackend(self.ykman_path)

            # show touch spinner once and keep it up
            self.needs_touch.emit()

            # Probe/provision flow:
            def probe(slot: int, tmo: int) -> bool:
                self.status.emit(_tr("Waiting for a YubiKey touch…"))
                try:
                    if hasattr(yk, "probe_chalresp_touch") and yk.probe_chalresp_touch(slot=slot, timeout=tmo):
                        return True
                except Exception as e:
                    L(f"probe slot {slot} error: {e!r}")
                return False

            def provision_touch(slot: int, tmo: int) -> bool:
                self.status.emit(_tr("Configuring slot {sl} for HMAC-SHA1 (requires touch)…").format(sl=slot))
                try:
                    if hasattr(yk, "program_slot_generate_touch"):
                        yk.program_slot_generate_touch(slot, timeout=tmo)
                        return True
                    # legacy helpers:
                    if slot == 2 and hasattr(yk, "program_slot2_generate_touch"):
                        yk.program_slot2_generate_touch(); return True
                    if slot == 1 and hasattr(yk, "program_slot1_generate_touch"):
                        yk.program_slot1_generate_touch(); return True
                except Exception as e:
                    L(f"provision_touch slot {slot} error: {e!r}")
                return False

            selected = int(self.slot)
            alternate = 1 if selected == 2 else 2

            ok = probe(selected, 12) or (provision_touch(selected, 25) and probe(selected, 25))
            if not ok:
                # last resort: try the other slot
                ok = probe(alternate, 12) or (provision_touch(alternate, 25) and probe(alternate, 25))
                if ok:
                    self.slot = alternate

            if not ok:
                raise RuntimeError(_tr("We didn’t receive a challenge-response from the YubiKey.\n\nTips: close YubiKey Manager, unplug/replug the key, ensure \"OTP\" is enabled."))

            # --- Enable in identity ---
            common: Dict[str, Any] = dict(
                username=self.username,
                password=self.password,
                serial=self.serial,
                slot=int(self.slot),
                ykman_path=self.ykman_path,
            )

            if self.mode == "wrap":
                if not self.master_key or not isinstance(self.master_key, (bytes, bytearray)):
                    raise RuntimeError(_tr("Unlock the vault first: WRAP needs the master key."))

                self.status.emit(_tr("Enabling YubiKey WRAP…"))

                # --- Inline wrap creation (matches login unwrap recipe) ---
                import os, base64, hashlib
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                # 1) Derive password_key = Argon2id(password, user_salt)
                from app.paths import salt_file

                try:
                    user_salt = salt_file(self.username, ensure_parent=False).read_bytes()
                except FileNotFoundError:
                    raise RuntimeError(f"User salt file not found for '{self.username}'")

                try:
                    # use Argon2id function
                    from vault_store.kdf_utils import derive_key_argon2id
                except Exception:
                    from vault_store.kdf_utils import derive_key_argon2id 
                password_key = derive_key_argon2id(self.password or "", user_salt)  # 32B

                # 2) Touch YubiKey with a fresh WRAP salt (we will store this salt)
                wrap_salt = os.urandom(16)
                ch_hex = binascii.hexlify(wrap_salt).decode("ascii")
                resp_hex = yk.calculate_hmac(int(self.slot), ch_hex, self.serial, timeout=25.0)
                resp_bytes = binascii.unhexlify(resp_hex)
                device_key_32 = hashlib.sha256(resp_bytes).digest()

                # 3) Final WRAP key = SHA256(password_key || SHA256(YK_HMAC))
                wrap_kek = hashlib.sha256(password_key + device_key_32).digest()  # 32B

                # 4) Choose the Master Key (MK) that will own the vault going forward:
                #    If current MK == password_key (password-only), rotate to random.
                from auth.yubi.wrap_ops import rekey_user_stores, bytes_equal
                mk = bytes(self.master_key)
                if bytes_equal(mk, password_key):
                    new_mk = os.urandom(32)
                    rekey_user_stores(self.username, mk, new_mk)  # vault now requires unwrap to get new_mk
                    mk = new_mk
                    self.master_key = new_mk  # keep session unlocked with the new MK

                # Ensure identity recovery wrapper and yubi wrapper track this MK
                try:
                    # Refresh recovery wrapper
                    bind_recovery_wrapper(self.username, self.password or "", mk)

                    # Refresh yubi wrapper (wrap_kek already computed earlier in flow)
                    bind_yubi_wrapper(self.username, mk, wrap_kek)

                except Exception as e:
                    L(f"[WRAP] wrapper-rebind warning: {e!r}")

                # 5) AES-GCM wrap the MK (ciphertext already includes tag) with AAD
                aes   = AESGCM(wrap_kek)
                nonce = os.urandom(12)
                wrapped = aes.encrypt(nonce, mk, b"KQ-WRAP-V1")  # ct||tag
                mk_hash_b64 = base64.b64encode(hashlib.sha256(bytes(self.master_key)).digest()).decode("ascii")

                # 6) Persist full config to identity
                def _b64(x: bytes) -> str: return base64.b64encode(x).decode("ascii")
                
                set_yubi_config(
                    self.username, self.password or "",
                    mode="yk_hmac_wrap",
                    serial=self.serial,
                    slot=int(self.slot),
                    ykman_path=self.ykman_path,
                    salt_b64=_b64(wrap_salt),
                    nonce_b64=_b64(nonce),
                    wrapped_b64=_b64(wrapped),
                    mk_hash_b64=mk_hash_b64, 
                    ykman_hash=None,
                )
                from auth.identity_store import get_yubi_config_public
                pub = get_yubi_config_public(self.username) or {}
                #L(f"[WRAP] header meta: mode={pub.get('mode')} mk_hash_b64={'yes' if pub.get('mk_hash_b64') else 'no'}")

                # 7) Return a printable Recovery Key for Emergency Kit (shown once)
                from auth.pw.utils_recovery import mk_to_recovery_key
                rk_print = mk_to_recovery_key(mk)

                # Generate fresh Backup Login Codes (stored in Identity Store where supported)
                backup_codes = []
                try:
                    from auth.tfa.twofactor import gen_backup_codes
                    backup_codes = gen_backup_codes(
                        self.username,
                        b_type="login",
                        n=5,
                        L=10,
                        password_for_identity=self.password,
                    ) or []
                except Exception:
                    backup_codes = []

                # update live session key in parent (so UI actions keep working)
                try:
                    if hasattr(self.parent(), "_set_user_key"):
                        self.parent()._set_user_key(mk, reason="wrap-enable")
                except Exception:
                    pass

                self.done.emit({"ok": True, "mode": "wrap", "recovery_key": rk_print, "backup_codes": backup_codes})
                return


            self.status.emit(_tr("Enabling YubiKey GATE…"))
            res = self._call_helper(enable_yk_hmac_gate, **common)
            if res is None:
                #set_yubi_config(self.username, {"mode": "yk_hmac_gate", **common})
                set_yubi_config(
                            self.username, self.password,
                            mode="yk_hmac_gate",
                            serial=self.serial,
                            slot=self.slot,
                            salt_b64=None,
                            nonce_b64=None,
                            wrapped_b64=None,
                            ykman_path=self.ykman_path,
                            ykman_hash=None,
                        )
            self.done.emit({"ok": True, "mode": "gate"})

        except Exception as e:
            self.done.emit({"ok": False, "error": str(e)})

# ==============================
# ---------------- Setup Dialog ----------------
# ==============================

class YubiKeySetupDialog(QDialog):
    """
    Gate — require touch at login (password still required)
    Wrap — encrypt master key under password_key + YubiKey HMAC(salt)
    """
    finished_setup = QtSignal(dict)

    def __init__(self, parent, username: str, current_mk: Optional[bytes],
                 identity_password: Optional[str] = None, current_password: Optional[str] = None, **_):
        super().__init__(parent)
        self.setWindowTitle(self.tr("YubiKey 2-of-2 Setup")); self.setModal(True)

        self.username = (username or "").strip()
        self.current_mk = current_mk
        # store whichever password name the caller used (UI doesn’t need it directly here)
        self._password = current_password or identity_password

        self._yk_worker: Optional[_YkEnableWorker] = None
        self._yk_touch: Optional[_TouchPrompt] = None

        v = QVBoxLayout(self)

        # Device box
        box_dev = QGroupBox(self.tr("Device")); vb = QVBoxLayout(box_dev)
        r1 = QHBoxLayout()
        r1.addWidget(QLabel(self.tr("YubiKey:")))
        self.combo = QComboBox(self); r1.addWidget(self.combo)
        self.btn_refresh = QPushButton(self.tr("Recheck")); r1.addWidget(self.btn_refresh)
        vb.addLayout(r1)

        # Slot box
        rslot = QHBoxLayout()
        rslot.addWidget(QLabel(self.tr("Slot:")))
        self.slot_combo = QComboBox(self)
        self.slot_combo.addItem(self.tr("2 (recommended)"), userData=2)
        self.slot_combo.addItem(self.tr("1"), userData=1)
        rslot.addWidget(self.slot_combo)
        vb.addLayout(rslot)
        v.addWidget(box_dev)

        # Mode box
        box_mode = QGroupBox(self.tr("2-of-2 Mode")); vm = QVBoxLayout(box_mode)
        self.rad_wrap = QRadioButton(self.tr(
            "WRAP (binds vault encryption to Password + YubiKey — Recovery Key needed if YubiKey is lost)"
        ))
        self.rad_gate = QRadioButton(self.tr("GATE (adds a login touch step — does not change vault encryption)"))
        self.rad_gate.setChecked(True)
        vm.addWidget(self.rad_wrap); vm.addWidget(self.rad_gate)
        v.addWidget(box_mode)

        # Buttons row
        row = QHBoxLayout()
        self.enable_btn = QPushButton(self.tr("Enable")); row.addWidget(self.enable_btn)
        self.test_btn   = QPushButton(self.tr("Test"));   row.addWidget(self.test_btn)
        self.disable_btn= QPushButton(self.tr("Disable"));row.addWidget(self.disable_btn)
        row.addStretch(1)
        v.addLayout(row)

        self.status = QLabel(""); v.addWidget(self.status)

        # wire
        self.btn_refresh.clicked.connect(self._refresh_devices)
        self.enable_btn.clicked.connect(self._on_enable)
        self.test_btn.clicked.connect(self._on_test)
        self.disable_btn.clicked.connect(self._on_disable)

        # init
        self._refresh_devices()
        self._reflect_current_mode()

    # --- helpers ---
    def _list_serials_safe(self):
        try:
            yk = YKBackend(None)
            if hasattr(yk, "list_serials"):
                return list(yk.list_serials() or [])
        except Exception as e:
            L(f"list_serials failed: {e!r}")
        return []

    def _refresh_devices(self):
        self.combo.clear()
        serials = self._list_serials_safe()
        if not serials:
            self.combo.addItem(self.tr("— No YubiKey detected —"), userData=None)
            self.status.setText(self.tr("Plug in your YubiKey, then click Recheck."))
            self.enable_btn.setEnabled(False); self.test_btn.setEnabled(False)
            return
        for s in serials:
            self.combo.addItem(str(s), userData=str(s))
        self.enable_btn.setEnabled(True); self.test_btn.setEnabled(True)
        self.status.setText(self.tr("YubiKey detected."))

    def _selected_serial(self) -> Optional[str]:
        i = self.combo.currentIndex()
        return self.combo.itemData(i) if i >= 0 else None

    def _selected_slot(self) -> int:
        i = self.slot_combo.currentIndex()
        slot = self.slot_combo.itemData(i) if i >= 0 else 2
        try: return int(slot)
        except Exception: return 2

    def _ykman_path_guess(self) -> Optional[str]:
        # Let backend resolve; return None here so it uses bundle-first automatically
        return None

    def _reflect_current_mode(self) -> None:
        """
        Update the UI to reflect the current YubiKey mode.

        Rules:
          - If WRAP is enabled  → WRAP radio checked, GATE radio disabled
          - If GATE is enabled  → GATE radio checked, WRAP radio disabled
          - If nothing enabled  → both radios enabled, GATE selected by default
        """
        enabled, mode = get_yubi_meta_quick(self.username)

        # Start with both options enabled; we’ll lock one out if needed.
        self.rad_gate.setEnabled(True)
        self.rad_wrap.setEnabled(True)

        # No active mode → both choices available
        if not enabled or not mode:
            self.rad_gate.setChecked(True)
            self.status.setText("No YubiKey mode enabled yet.")
            return

        if mode == "yk_hmac_wrap":
            # WRAP active → cannot switch directly to GATE
            self.rad_wrap.setChecked(True)
            self.rad_gate.setEnabled(False)
            self.status.setText("Current mode: WRAP is enabled.")
        elif mode == "yk_hmac_gate":
            # GATE active → cannot switch directly to WRAP
            self.rad_gate.setChecked(True)
            self.rad_wrap.setEnabled(False)
            self.status.setText("Current mode: GATE is enabled.")
        else:
            # Unknown / future mode → don’t lock anything, just show text
            self.rad_gate.setChecked(True)
            self.status.setText(f"YubiKey mode: {mode}")

    # --- backup ---
    def _must_backup(self) -> bool:
        parent = self.parent()
        if not parent or not hasattr(parent, "export_vault"):
            return True  # fallback: allow

        ans = QMessageBox.question(
            self,
            "Full Backup Recommended",
            (
                "Before changing YubiKey security settings, Keyquorum can create a full "
                "encrypted backup of your account.\n\n"
                "Do you want to create a backup now?"
            ),
            QMessageBox.Yes | QMessageBox.No
        )

        if ans == QMessageBox.No:
            QMessageBox.information(self, "YubiKey", "Changes cancelled — backup was skipped.")
            return False

        ok = parent.export_vault()
        if ok is False:
            QMessageBox.warning(
                self,
                "Backup Not Completed",
                "Backup did not complete.\nYubiKey changes have been cancelled."
            )
            return False

        return True

    # --- buttons ---
    def _on_enable(self):

        serial = (self._selected_serial() or "").strip()
        if not serial or serial.startswith("("):
            QMessageBox.critical(
                self,
                self.tr("YubiKey"),
                self.tr("No YubiKey detected. Plug it in, then click Recheck."),
            )
            return

        slot = self._selected_slot()
        mode = "wrap" if self.rad_wrap.isChecked() else "gate"

        # ------------------------
        # 🔒 WRAP ONLY: full backup + explicit warning/confirm
        # ------------------------
        if mode == "wrap":
            # 1) Require backup first
            if hasattr(self, "_must_backup"):
                if not self._must_backup():
                    return

            # 2) Show WRAP warning with explicit Continue / Cancel buttons
            warn = QMessageBox(self)
            warn.setIcon(QMessageBox.Warning)
            warn.setWindowTitle("Enable YubiKey WRAP")
            warn.setText(yubi_warning)

            continue_btn = warn.addButton("Continue", QMessageBox.AcceptRole)
            cancel_btn   = warn.addButton("Cancel",   QMessageBox.RejectRole)
            warn.setDefaultButton(continue_btn)

            warn.exec()

            # If user did NOT click Continue → abort
            if warn.clickedButton() is not continue_btn:
                return

        # ------------------------
        # Normal enable flow
        # ------------------------
        if self._yk_touch:
            try:
                self._yk_touch.close()
            except Exception:
                pass

        self._yk_touch = _TouchPrompt(self, "YubiKey", "Touch your YubiKey to continue…")
        self._yk_touch.open()

        self.enable_btn.setEnabled(False)
        self.test_btn.setEnabled(False)
        self.disable_btn.setEnabled(False)
        self.status.setText(f"Enabling YubiKey {mode.upper()}…")

        if self._yk_worker and self._yk_worker.isRunning():  # stopping old workers before new one starts
            self._yk_worker.requestInterruption()
            self._yk_worker.wait(1000)  # Wait up to 1s
            self._yk_worker.deleteLater()

        self._yk_worker = _YkEnableWorker(
            mode=mode,
            username=self.username,
            master_key=self.current_mk,
            serial=serial,
            slot=slot,
            ykman_path=self._ykman_path_guess(),
            password=self._password or "",
        )
        self._yk_worker.status.connect(lambda s: self.status.setText(s or ""))
        self._yk_worker.needs_touch.connect(self._on_needs_touch)
        self._yk_worker.done.connect(self._on_done)
        self._yk_worker.start()

    def _on_needs_touch(self):
        if self._yk_touch: return
        self._yk_touch = _TouchPrompt(self, "YubiKey", "Touch your YubiKey to continue…")
        self._yk_touch.open()

    def _on_done(self, res: dict):
        if self._yk_touch:
            try: self._yk_touch.close()
            except Exception: pass
            self._yk_touch = None

        self.enable_btn.setEnabled(True); self.test_btn.setEnabled(True); self.disable_btn.setEnabled(True)

        if res.get("ok"):
            mode = res.get("mode")

            try:
                self.finished_setup.emit(res)
            except Exception as e:
                L(f"emit finished_setup failed: {e}")

            if mode == "wrap":
                QMessageBox.information(self, "YubiKey", "Enabled: WRAP.\nYour key now unwraps the master key.")
            else:
                QMessageBox.information(self, "YubiKey", "Enabled: GATE.\nPassword + YubiKey required at login.")
            self._reflect_current_mode()
        else:
            QMessageBox.critical(self, "YubiKey", f"Enable failed:\n{res.get('error') or 'Unknown error'}")

    def _on_test(self):
        """
        Fully test the user's YubiKey configuration.

        • GATE → Perform live HMAC challenge and require touch
        • WRAP → Attempt real unwrap of the wrapped master key
        """

        enabled, mode = get_yubi_meta_quick(self.username)
        if not enabled or not mode:
            QMessageBox.information(self, "YubiKey", "No YubiKey mode is enabled for this account yet.")
            return

        # ------------------
        # GATE MODE TEST
        # ------------------
        if mode == "yk_hmac_gate":
            try:
                from auth.yubi.yk_backend import yk_hmac_challenge_gate_test

                # Show touch prompt
                touch = _TouchPrompt(self, "YubiKey Test", "Touch your YubiKey to continue…")
                touch.open()

                ok = yk_hmac_challenge_gate_test(self.username)

                try:
                    touch.close()
                except Exception:
                    pass

                if ok:
                    QMessageBox.information(
                        self,
                        self.tr("YubiKey Test"),
                        self.tr("✔ GATE test passed.\nYour YubiKey responded correctly.")
                    )
                else:
                    QMessageBox.warning(
                        self,
                        self.tr("YubiKey Test Failed"),
                        self.tr("⚠ GATE test failed.\nYour YubiKey did not return a valid signature.\n"
                        "Please reconfigure before logging out.")
                    )
            except Exception as e:
                msg = self.tr("GATE test failed due to an error:\n\n{err}").format(err=e)
                QMessageBox.critical(
                    self,
                    self.tr("YubiKey Error"),
                    msg)
            return

        # ------------------
        # WRAP MODE TEST
        # ------------------
        if mode == "yk_hmac_wrap":
            try:
                from auth.yubi.yk_backend import test_yk_wrap_unwrap

                if not (self._password or '').strip():
                    QMessageBox.warning(
                        self,
                        self.tr("YubiKey Test Failed"),
                        self.tr("Password is required to test WRAP mode.")
                    )
                    return

                # Show touch prompt
                touch = _TouchPrompt(self,  self.tr("YubiKey Test"),  self.tr("Touch your YubiKey to continue…"))
                touch.open()

                ok = test_yk_wrap_unwrap(username=self.username, password=self._password or '')

                try:
                    touch.close()
                except Exception:
                    pass

                if ok:
                    QMessageBox.information(
                        self,
                        self.tr("YubiKey Test"),
                        self.tr("✔ WRAP test passed.\nYour YubiKey successfully unwrapped the master key.")
                    )
                else:
                    QMessageBox.warning(
                        self,
                         self.tr("YubiKey Test Failed"),
                         self.tr("⚠ WRAP test failed.\nYour YubiKey could NOT unwrap the master key.\n"
                        "Fix this BEFORE logging out or you may be locked out.")
                    )
            except Exception as e:
                msg =  self.tr("WRAP test failed due to an error:\n\n{err}").format(err=e)
                QMessageBox.critical(
                    self,
                     self.tr("YubiKey Error"),
                     msg)
            return

        # ------------------
        # Unknown mode fallback
        # ------------------
        QMessageBox.information(self, "YubiKey", f"Unknown YubiKey mode: {mode}")

    def _on_disable(self) -> None:
        """
        Disable YubiKey:

        - GATE: just remove config (no crypto changes)
        - WRAP: only allowed if we can safely migrate the vault back to a password key.
                If migration fails / isn’t possible, show the “export first” message and
                DO NOT touch the WRAP config.
        """
        # What mode are we in?
        try:
            enabled, mode = get_yubi_meta_quick(self.username)
        except Exception as e:
            msg = self.tr("Could not read YubiKey config:\n{err}").format(err=e)
            QMessageBox.critical(self, self.tr("YubiKey"), msg)
            return

        if not enabled or not mode:
            QMessageBox.information(self, self.tr("YubiKey"), self.tr("No YubiKey mode is enabled for this account."))
            return

        # -----------------------
        # 1) GATE: simple disable
        # -----------------------
        if mode == "yk_hmac_gate":
            # Best-effort: clear twofactor record in user_db
            try:
                from auth.tfa.twofactor import disable_yk_2of2  # local import to avoid hard dep at top
            except Exception:
                disable_yk_2of2 = None

            err = None
            try:
                if disable_yk_2of2 is not None:
                    disable_yk_2of2(self.username)
            except Exception as e:
                err = e

            # Also clear identity header copy (no crypto impact)
            try:
                clear_yubi_config(self.username, self._password or "")
            except Exception as e:
                err = err or e

            if err:
                msg = self.tr("Disable failed:\n{e}").format(e=err)
                QMessageBox.critical(self, self.tr("YubiKey"), msg)
            else:
                QMessageBox.information(self, self.tr("YubiKey"), self.tr("YubiKey GATE disabled for this account."))
                from security.baseline_signer import update_baseline
                update_baseline(self.username, verify_after=False, who="Yubi GATE Disabled")
                from security.secure_audit import log_event_encrypted
                log_event_encrypted(self.username, "User", "Yubi GATE Disabled")
                self._reflect_current_mode()
            return

        # -----------------------
        # 2) WRAP: needs migration
        # -----------------------
        if mode == "yk_hmac_wrap":
            # We MUST NOT drop WRAP unless we successfully migrate the vault key.
            # Conditions:
            #   - ask to backup if faile return
            #   - we have the current master key (vault is unlocked)
            #   - we know the account password (to derive password_key)
            #   - rekey_vault succeeds
            if not self._must_backup():
                return

            # Get current master key from parent or our cached copy
            mk: Optional[bytes] = None
            try:
                parent = self.parent()
            except Exception:
                parent = None

            if parent is not None and hasattr(parent, "userKey"):
                try:
                    mk = bytes(getattr(parent, "userKey"))
                except Exception:
                    mk = None

            if mk is None and isinstance(self.current_mk, (bytes, bytearray)):
                mk = bytes(self.current_mk)

            if not mk:
                # We cannot safely re-encrypt the vault key → refuse to disable
                QMessageBox.warning(
                    self,
                    self.tr("YubiKey WRAP"),
                    (
                        self.tr("You cannot disable YubiKey WRAP without a vault backup; "
                        "export your vault first.")
                    ),
                )
                return

            if not (self._password or "").strip():
                # No password, so we can't derive the password_key to migrate to
                QMessageBox.warning(
                    self,
                    self.tr("YubiKey WRAP"),
                    (
                        self.tr("You cannot disable YubiKey WRAP without your account password.\n\n"
                        "Tip: log out and log back in, then open YubiKey settings again.")
                    ),
                )
                return

            # Derive the password_key using the same salt as login
            try:
                from app.paths import salt_file
                user_salt = salt_file(self.username, ensure_parent=False).read_bytes()
            except Exception as e:
                msg = self.tr("Cannot disable WRAP: vault backup required.\n\n"
                              "Create a full encrypted backup first (File → Export Vault).\n\n"
                              "(Error: {err})").format(err=e)
                QMessageBox.warning(
                    self,
                    self.tr("YubiKey WRAP"),
                    msg,
                )
                return

            try:
                try:
                    from vault_store.kdf_utils import derive_key_argon2id
                except Exception:
                    from vault_store.kdf_utils import derive_key_argon2id  # legacy fallback
                password_key = derive_key_argon2id(self._password or "", user_salt)
            except Exception as e:
                msg = self.tr("You cannot disable YubiKey WRAP without a vault backup; "
                                "export your vault first.\n\n"
                                "(KDF error: {err})").format(err=e)
                QMessageBox.warning(
                    self,
                    self.tr("YubiKey WRAP"), msg)
                return

            # Try to re-encrypt the vault from MK → password_key
            try:
                from auth.yubi.wrap_ops import rekey_user_stores
            except Exception as e:
                msg = self.tr("You cannot disable YubiKey WRAP without a vault backup; "
                "export your vault first.\n\n"
                "(Vault rekey helper missing: {err})").format(err=e)
                QMessageBox.warning(
                    self,
                    self.tr("YubiKey WRAP"), msg )
                return

            try:
                rekey_user_stores(self.username, mk, password_key)
            except Exception as e:
                msg = self.tr("You cannot disable YubiKey WRAP without a vault backup; "
                                "export your vault first.\n\n"
                                "(Vault migration failed: {err})").format(err=e)
                # CRITICAL: do NOT touch config on failure, or the vault is stranded
                QMessageBox.warning(
                    self,
                    self.tr("YubiKey WRAP"), msg)
                return

            # Best-effort: refresh recovery wrapper to track the new MK (password_key)
            try:
                bind_recovery_wrapper(self.username, self._password or "", password_key)
            except Exception as e:
                L(f"[disable-wrap] bind_recovery_wrapper warning: {e!r}")

            # Now it is SAFE to drop WRAP config:
            err = None
            try:
                clear_yubi_config(self.username, self._password or "")
            except Exception as e:
                err = e

            # Also clear user_db twofactor record if present
            try:
                from auth.tfa.twofactor import disable_yk_2of2
            except Exception:
                disable_yk_2of2 = None
            try:
                if disable_yk_2of2 is not None:
                    disable_yk_2of2(self.username)
            except Exception as e:
                err = err or e

            if err:
                msg =  self.tr("Vault key was migrated back to your password, but cleanup failed:\n{e}").format(e=err)
                QMessageBox.critical(
                    self,
                     self.tr("YubiKey WRAP"), msg )
            else:
                # We successfully migrated MK back to password_key.
                # For safety, we will log the user out so the next session
                # cleanly uses password-only protection.
                try:
                    if parent is not None and hasattr(parent, "_set_user_key"):
                        parent._set_user_key(password_key, reason="wrap-disable")
                except Exception:
                    pass

                QMessageBox.information(
                    self,
                    self.tr("YubiKey WRAP Disabled"),
                    self.tr(
                        "YubiKey WRAP has been disabled.\n\n"
                        "Your vault is now protected by your password only.\n"
                        "Maximum-security mode remains active.\n\n"
                        "For your security, you will now be logged out.\n"
                        "Please log in again using your account password."
                    ),
                )

                self._reflect_current_mode()

                # 🔐 Force logout on the parent main window, if available
                try:
                    if parent is not None and hasattr(parent, "logout_user"):
                        try:
                            from security.baseline_signer import update_baseline
                            update_baseline(self.username, verify_after=False, who="Yubi Wrap Disabled")
                            from security.secure_audit import log_event_encrypted
                            log_event_encrypted(self.username, "User", "Yubi Wrap Disabled")
                        except Exception:
                            pass
                        parent.logout_user()
                except Exception:
                    pass

                try:
                    self.close()
                except Exception:
                    pass
            return

        # Any unknown mode
        QMessageBox.warning(self, self.tr("YubiKey"), self.tr("Unknown YubiKey mode: {m}").format(m=mode))
