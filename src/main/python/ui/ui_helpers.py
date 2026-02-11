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
# --- Pysider6 backend QtWidgets ---
from qtpy.QtWidgets import QApplication


def center_on_screen(w):
    """keep ui center of screen"""
    scr = w.screen() or QApplication.primaryScreen()
    geo = scr.availableGeometry() if scr else QApplication.desktop().availableGeometry(w)
    w.resize(w.size())  # keep current size, but ensure frameGeometry is valid
    w.move(
        geo.x() + (geo.width()  - w.frameGeometry().width())  // 2,
        geo.y() + (geo.height() - w.frameGeometry().height()) // 2,
    )

