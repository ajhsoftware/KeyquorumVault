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

import logging
log = logging.getLogger("keyquorum")
import app.kq_logging as kql
from qtpy.QtCore import QObject, Qt
from qtpy.QtWidgets import QApplication
from qtpy.QtCore import Signal as pyqtSignal, Slot as pyqtSlot
import os, sys
from auth.logout.logout_flow import logout_user


# ==============================
# --- brighe ui ---
# ============================== 
# UI bus: run callables on the GUI thread (queued connection).
class _UiBus(QObject):
    call = pyqtSignal(object)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.call.connect(self._run, Qt.ConnectionType.QueuedConnection)
    @pyqtSlot(object)
    def _run(self, fn):
        try: fn()
        except Exception: pass

# ==============================
# --- App Helpers ---
# ==============================
def get_app_version():
    try:
        from fbs_runtime.application_context.qtpy import ApplicationContext # type: ignore
        APP_VERSION = ApplicationContext().build_settings.get('version', 'dev')
        log.debug(f"{kql.i('build')} [APP] VERSION {APP_VERSION}")
        return APP_VERSION
    except Exception:
        APP_VERSION = "1.9.0"
        log.debug(f"{kql.i('build')} [APP] VERSION {APP_VERSION}")
        return APP_VERSION

# ==============================
# --- Restart App ---
# ==============================
def _restart_application(w):
    """
    Attempt to restart the application in-place.
    Works for both dev (python main.py) and frozen .exe.
    """
    try:
        log.info("%s [LANG] attempting to logout user", kql.i("build"))
        logout_user(w)
        log.info("%s [LANG] attempting app restart after language change", kql.i("build"))
        python = sys.executable
        os.execl(python, python, *sys.argv)
    except Exception as e:
        log.error("%s [LANG] restart failed, quitting instead: %s", kql.i("err"), e)
        app = QApplication.instance()
        if app is not None:
            app.quit()


