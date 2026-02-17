from __future__ import annotations
from typing import Optional

from qtpy.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGroupBox, QFrame, QMessageBox, QLineEdit, QDialogButtonBox
)
from qtpy.QtCore import Qt

from security.security_features import (
    # Recovery-Mode (convenience) helpers
    enable_windows_hello, disable_windows_hello,
    enable_yubikey_fido2, disable_yubikey_fido2,

    # Max-Security 2-of-2 helpers
    maxsec2of2_enabled, disable_maxsec2of2,
    enable_maxsec2of2_with_fido2, enable_maxsec2of2_with_hello,
    add_second_fido2_key, add_second_hello_key,
)

class DeviceUnlockDialog(QDialog):
    """
    A standalone dialog for managing Windows Hello / YubiKey (FIDO2)
    in both Recovery-Mode (convenience) and Maximum-Security (2-of-2).
    Pass your main app instance so we can access user_record, userKey, etc.
    """
    def __init__(self, app, parent=None):
        super().__init__(parent or app)
        self.app = app
        self.setWindowTitle("Device Unlock (Hello / FIDO2)")
        self.setMinimumWidth(580)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(12)

        # ============================== Recovery-Mode group ===
        g_rec = QGroupBox("Recovery-Mode: Convenience Unlock (Windows Hello & YubiKey)")
        v_rec = QVBoxLayout(g_rec); v_rec.setSpacing(8)
        self.lblRec = QLabel("Status: -"); self.lblRec.setStyleSheet("color:#666")
        v_rec.addWidget(self.lblRec)

        row1 = QHBoxLayout()
        self.btnHelloEnable  = QPushButton("Enable Windows Hello")
        self.btnHelloDisable = QPushButton("Disable Windows Hello")
        row1.addWidget(self.btnHelloEnable); row1.addWidget(self.btnHelloDisable); row1.addStretch(1)
        v_rec.addLayout(row1)

        row2 = QHBoxLayout()
        self.btnYubiEnable  = QPushButton("Register YubiKey")
        self.btnYubiDisable = QPushButton("Disable YubiKey")
        row2.addWidget(self.btnYubiEnable); row2.addWidget(self.btnYubiDisable); row2.addStretch(1)
        v_rec.addLayout(row2)

        # separator
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine); sep.setFrameShadow(QFrame.Shadow.Sunken)
        v_rec.addWidget(sep)

        # ============================== Max-Security group ===
        g_ms = QGroupBox("Maximum-Security: 2-of-2 (Password + Device)")
        v_ms = QVBoxLayout(g_ms); v_ms.setSpacing(8)
        self.lblMs = QLabel("Status: -"); self.lblMs.setStyleSheet("color:#666")
        v_ms.addWidget(self.lblMs)

        row3 = QHBoxLayout()
        self.btnMsEnableFido  = QPushButton("Enable 2-of-2 with FIDO2")
        self.btnMsEnableHello = QPushButton("Enable 2-of-2 with Windows Hello")
        row3.addWidget(self.btnMsEnableFido); row3.addWidget(self.btnMsEnableHello); row3.addStretch(1)
        v_ms.addLayout(row3)

        row4 = QHBoxLayout()
        self.btnMsAddFido   = QPushButton("Add Second Key (FIDO2)")
        self.btnMsAddHello  = QPushButton("Add Second Key (Hello)")
        self.btnMsDisable   = QPushButton("Disable 2-of-2")
        row4.addWidget(self.btnMsAddFido); row4.addWidget(self.btnMsAddHello); row4.addWidget(self.btnMsDisable); row4.addStretch(1)
        v_ms.addLayout(row4)

        root.addWidget(g_rec)
        root.addWidget(g_ms)

        # Close button row
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, parent=self)
        btns.rejected.connect(self.reject)
        btns.accepted.connect(self.accept)
        # map Close to reject so ESC/Close works
        btns.button(QDialogButtonBox.StandardButton.Close).clicked.connect(self.reject)
        root.addWidget(btns)

        # Wire signals
        self.btnHelloEnable.clicked.connect(self._on_enable_hello)
        self.btnHelloDisable.clicked.connect(self._on_disable_hello)
        self.btnYubiEnable.clicked.connect(self._on_enable_yubi)
        self.btnYubiDisable.clicked.connect(self._on_disable_yubi)

        self.btnMsEnableFido.clicked.connect(self._on_ms_enable_fido)
        self.btnMsEnableHello.clicked.connect(self._on_ms_enable_hello)
        self.btnMsAddFido.clicked.connect(self._on_ms_add_fido)
        self.btnMsAddHello.clicked.connect(self._on_ms_add_hello)
        self.btnMsDisable.clicked.connect(self._on_ms_disable)

        self.refresh_state()

    # ----------------- UI helpers -----------------

    def _is_maxsec(self) -> bool:
        ur = getattr(self.app, "user_record", {}) or {}
        return not bool(ur.get("recovery_mode", True))

    def _pwd_prompt(self, title: str) -> Optional[str]:
        """Tiny in-dialog password re-entry prompt (uses app’s if available)."""
        # Note: check _prompt_for_master_password
        if hasattr(self.app, "_prompt_for_master_password"):
            return self.app._prompt_for_master_password(title)

        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        v = QVBoxLayout(dlg)
        v.addWidget(QLabel("Re-enter your master password:"))
        edit = QLineEdit(dlg); edit.setEchoMode(QLineEdit.EchoMode.Password)
        v.addWidget(edit)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, parent=dlg)
        v.addWidget(bb)
        bb.accepted.connect(dlg.accept); bb.rejected.connect(dlg.reject)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            return edit.text() or None
        return None

    def _info(self, msg: str): QMessageBox.information(self, "Keyquorum", msg)
    def _err(self, msg: str):  QMessageBox.critical(self, "Keyquorum", msg)

    def _mk(self) -> bytes:
        # Uses app's in-memory MK
        return self.app._current_master_key_bytes()

    def _save_user_record(self):
        if hasattr(self.app, "_save_user_record"):
            self.app._save_user_record()

    def refresh_state(self):
        ur = getattr(self.app, "user_record", {}) or {}
        is_maxsec = self._is_maxsec()

        # Recovery-Mode state
        hello = ur.get("windows_hello") or {}
        fido  = ur.get("fido2") or {}
        hello_on = bool(hello.get("enabled"))
        fido_on  = bool(fido.get("enabled"))

        if not is_maxsec:
            self.lblRec.setText(f"Status: Hello: {'On' if hello_on else 'Off'}  |  YubiKey: {'On' if fido_on else 'Off'}")
        else:
            self.lblRec.setText("Status: Unavailable on Maximum-Security accounts")

        self.btnHelloEnable.setEnabled((not is_maxsec) and (not hello_on))
        self.btnHelloDisable.setEnabled((not is_maxsec) and hello_on)
        self.btnYubiEnable.setEnabled((not is_maxsec) and (not fido_on))
        self.btnYubiDisable.setEnabled((not is_maxsec) and fido_on)

        # Max-Sec 2-of-2
        node = ur.get("maxsec_2of2") or {}
        ms_enabled = is_maxsec and bool(node.get("enabled"))
        dev = node.get("device") or {}
        keys = len(dev.get("fido2_keys") or [])
        if dev.get("hello_wrapped"): keys += 1

        if is_maxsec:
            if ms_enabled:
                self.lblMs.setText(f"Status: Enabled (keys: {keys}/2)")
            else:
                self.lblMs.setText("Status: Disabled")
        else:
            self.lblMs.setText("Status: Only available for Maximum-Security accounts")

        self.btnMsEnableFido.setEnabled(is_maxsec and not ms_enabled)
        self.btnMsEnableHello.setEnabled(is_maxsec and not ms_enabled)
        can_add = is_maxsec and ms_enabled and (keys < 2)
        self.btnMsAddFido.setEnabled(can_add)
        self.btnMsAddHello.setEnabled(can_add and not bool(dev.get("hello_wrapped")))
        self.btnMsDisable.setEnabled(is_maxsec and ms_enabled)

    # ----------------- Recovery-Mode handlers -----------------

    def _on_enable_hello(self):
        try:
            self.app.user_record = enable_windows_hello(self.app.user_record, self._mk())
            self._save_user_record()
            self._info("Windows Hello enabled.")
        except Exception as e:
            self._err(f"Failed to enable Windows Hello: {e}")
        self.refresh_state()

    def _on_disable_hello(self):
        try:
            self.app.user_record = disable_windows_hello(self.app.user_record)
            self._save_user_record()
            self._info("Windows Hello disabled.")
        except Exception as e:
            self._err(f"Failed to disable Windows Hello: {e}")
        self.refresh_state()

    def _on_enable_yubi(self):
        try:
            self.app.user_record = enable_yubikey_fido2(self.app.user_record, self._mk())
            self._save_user_record()
            self._info("YubiKey registered and enabled.")
        except Exception as e:
            self._err(f"Failed to register YubiKey: {e}")
        self.refresh_state()

    def _on_disable_yubi(self):
        try:
            self.app.user_record = disable_yubikey_fido2(self.app.user_record)
            self._save_user_record()
            self._info("YubiKey disabled.")
        except Exception as e:
            self._err(f"Failed to disable YubiKey: {e}")
        self.refresh_state()

    # ----------------- Max-Security 2-of-2 handlers -----------------

    def _on_ms_enable_fido(self):
        if not self._is_maxsec():
            self._info("2-of-2 is only for Maximum-Security accounts.")
            return
        pwd = self._pwd_prompt("Enable 2-of-2 (FIDO2)")
        if not pwd: return
        try:
            self.app.user_record = enable_maxsec2of2_with_fido2(self.app.user_record, pwd, self._mk())
            self._save_user_record()
            self._info("2-of-2 enabled with FIDO2.")
        except Exception as e:
            self._err(f"Failed to enable 2-of-2 (FIDO2): {e}")
        self.refresh_state()

    def _on_ms_enable_hello(self):
        if not self._is_maxsec():
            self._info("2-of-2 is only for Maximum-Security accounts.")
            return
        pwd = self._pwd_prompt("Enable 2-of-2 (Windows Hello)")
        if not pwd: return
        try:
            self.app.user_record = enable_maxsec2of2_with_hello(self.app.user_record, pwd, self._mk())
            self._save_user_record()
            self._info("2-of-2 enabled with Windows Hello.")
        except Exception as e:
            self._err(f"Failed to enable 2-of-2 (Hello): {e}")
        self.refresh_state()

    def _on_ms_add_fido(self):
        if not self._is_maxsec():
            self._info("2-of-2 is only for Maximum-Security accounts.")
            return
        pwd = self._pwd_prompt("Add Second Device Key (FIDO2)")
        if not pwd: return
        try:
            self.app.user_record = add_second_fido2_key(self.app.user_record, pwd, self._mk())
            self._save_user_record()
            self._info("Second device key added (FIDO2).")
        except Exception as e:
            self._err(f"Failed to add second key (FIDO2): {e}")
        self.refresh_state()

    def _on_ms_add_hello(self):
        if not self._is_maxsec():
            self._info("2-of-2 is only for Maximum-Security accounts.")
            return
        pwd = self._pwd_prompt("Add Second Device Key (Windows Hello)")
        if not pwd: return
        try:
            self.app.user_record = add_second_hello_key(self.app.user_record, pwd, self._mk())
            self._save_user_record()
            self._info("Second device key added (Windows Hello).")
        except Exception as e:
            self._err(f"Failed to add second key (Hello): {e}")
        self.refresh_state()

    def _on_ms_disable(self):
        if not self._is_maxsec():
            self._info("2-of-2 is only for Maximum-Security accounts.")
            return
        try:
            self.app.user_record = disable_maxsec2of2(self.app.user_record)
            self._save_user_record()
            self._info("2-of-2 disabled for this account.")
        except Exception as e:
            self._err(f"Failed to disable 2-of-2: {e}")
        self.refresh_state()
