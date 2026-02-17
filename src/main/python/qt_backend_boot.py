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

# Forces QtPy to select the PySide6 backend (LGPL) for closed‑source distribution.
#
# Usage (top of main.py, before any Qt import):
#   import qt_backend_boot  # noqa: F401
#
# qt_backend_boot.py — import FIRST in main.py to force QtPy→PySide6
import os
os.environ.setdefault("QT_API", "pyside6")

# Correct way to verify the chosen backend with QtPy
from qtpy import API_NAME, PYSIDE6

if not PYSIDE6:
    raise RuntimeError(f"QtPy backend is {API_NAME!r}, expected 'pyside6'")
