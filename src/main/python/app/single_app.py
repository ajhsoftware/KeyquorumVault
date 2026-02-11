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
from qtpy.QtWidgets import QApplication
import sys, traceback, types
import logging
log = logging.getLogger("keyquorum")

_DEV_BLOCK_QUIT = True  # flip to False for production

class DevApp(QApplication):
    def quit(self):  # instance method
        if _DEV_BLOCK_QUIT:
# dev print removed (use logs instead)

            traceback.print_stack(limit=40)
            return
        return super().quit()

    def exit(self, code: int = 0):
        if _DEV_BLOCK_QUIT:
# dev print removed (use logs instead)

            traceback.print_stack(limit=40)
            return
        return super().exit(code)

def get_app(argv=None) -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = DevApp(sys.argv if argv is None else argv)  # <-- use DevApp
    return app

