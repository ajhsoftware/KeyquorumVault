from app.qt_imports import *

class DevPanel(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Developer Panel")
        layout = QVBoxLayout(self)

        # -------------------------
        # Dev Mode Toggle
        # -------------------------
        self.dev_toggle = QCheckBox("Enable Developer Mode")
        self.dev_toggle.setChecked(self._get_dev_enabled())
        self.dev_toggle.stateChanged.connect(self._toggle_dev_mode)

        layout.addWidget(self.dev_toggle)

        layout.addWidget(QLabel("Demo / Video Tools"))

        # -------------------------
        # Demo Buttons
        # -------------------------
        btn_demo_seed = QPushButton("Seed Demo Data")
        btn_demo_seed.clicked.connect(self._demo_seed)

        btn_demo_clear = QPushButton("Clear Demo Data")
        btn_demo_clear.clicked.connect(self._demo_clear)

        btn_demo_reset = QPushButton("Reset Demo Data")
        btn_demo_reset.clicked.connect(self._demo_reset)

        layout.addWidget(btn_demo_seed)
        layout.addWidget(btn_demo_clear)
        layout.addWidget(btn_demo_reset)

        layout.addSpacing(10)

        layout.addWidget(QLabel("Testing"))

        # -------------------------
        # Smoke Tests
        # -------------------------
        btn_smoke = QPushButton("Run Smoke Tests")
        btn_smoke.clicked.connect(self._run_smoke)

        layout.addWidget(btn_smoke)

        layout.addSpacing(10)

        layout.addWidget(QLabel("Debug"))

        # -------------------------
        # Debug Buttons
        # -------------------------
        btn_session = QPushButton("Session Info")
        btn_session.clicked.connect(self._session_info)

        btn_qsettings = QPushButton("QSettings Viewer")
        btn_qsettings.clicked.connect(self._qsettings_view)

        layout.addWidget(btn_session)
        layout.addWidget(btn_qsettings)

        layout.addStretch()

    # -------------------------
    # Dev Mode State
    # -------------------------
    def _get_dev_enabled(self):
        settings = QSettings("AJH Software", "Keyquorum Vault")
        return settings.value("dev_mode", False, type=bool)

    def _toggle_dev_mode(self):
        settings = QSettings("AJH Software", "Keyquorum Vault")
        settings.setValue("dev_mode", self.dev_toggle.isChecked())

        QMessageBox.information(
            self,
            "Dev Mode",
            f"Developer Mode {'Enabled' if self.dev_toggle.isChecked() else 'Disabled'}"
        )

    def _is_dev(self):
        return True # self._get_dev_enabled()

    # -------------------------
    # Demo Actions
    # -------------------------
    def _demo_seed(self):
        if not self._is_dev():
            return

        try:
            from tools.demo_seed import seed_demo_data
            parent = self.parent()

            u = getattr(parent, "_active_username", lambda: "")()
            h = getattr(parent, "core_session_handle", None)

            seed_demo_data(u, h)

            QMessageBox.information(self, "Demo", "Demo data created")

        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _demo_clear(self):
        if not self._is_dev():
            return

        try:
            from tools.demo_seed import clear_demo_data
            parent = self.parent()

            u = getattr(parent, "_active_username", lambda: "")()
            h = getattr(parent, "core_session_handle", None)

            clear_demo_data(u, h)

            QMessageBox.information(self, "Demo", "Demo data cleared")

        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _demo_reset(self):
        if not self._is_dev():
            return

        try:
            from tools.demo_seed import seed_demo_data, clear_demo_data
            parent = self.parent()

            u = getattr(parent, "_active_username", lambda: "")()
            h = getattr(parent, "core_session_handle", None)

            clear_demo_data(u, h)
            seed_demo_data(u, h)

            QMessageBox.information(self, "Demo", "Demo reset complete")

        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    # -------------------------
    # Smoke
    # -------------------------
    def _run_smoke(self):
        if not self._is_dev():
            return

        try:
            from tools.kv_auto_tests_pro import run_suite
            run_suite()
            QMessageBox.information(self, "Smoke", "Smoke tests complete")

        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    # -------------------------
    # Debug
    # -------------------------
    def _session_info(self):
        parent = self.parent()
        h = getattr(parent, "core_session_handle", None)

        QMessageBox.information(
            self,
            "Session Info",
            f"Session Handle: {h}"
        )

    def _qsettings_view(self):
        try:
            from tools.qsettings_viewer import QSettingsInspector
            dlg = QSettingsInspector(self)
            dlg.exec()
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))
