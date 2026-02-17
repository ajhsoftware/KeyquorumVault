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

"""Central import bridge for legacy ops modules.

Keyquorum historically relied on copying __main__ globals into ops modules
(globals().update(...)). After refactors and frozen builds, __main__ may not
contain expected symbols, causing NameError at runtime (Qt, logging, stdlib).

This module is a **temporary compatibility layer** so the split codebase keeps
working while you gradually add explicit imports where it makes sense.

Ops modules can do: `from app.qt_imports import *` as a safety net.
"""

# --- stdlib commonly relied on by legacy ops modules --------------------------
import sys
import os
import json
import csv
import re
import time
import traceback
import importlib
from pathlib import Path
import logging

# Stable logger name used across Keyquorum
log = logging.getLogger("keyquorum")

# Keyquorum icon/label logger helper
try:
    import app.kq_logging as kql  # noqa: F401
except Exception:
    kql = None  # type: ignore

# --- Qt imports ---------------------
from PySide6.QtCore import *  # noqa: F401,F403
from PySide6.QtGui import *  # noqa: F401,F403
from PySide6.QtWidgets import *  # noqa: F401,F403

# Some legacy code uses the QtCore namespace (QtCore.Qt.*)
from PySide6 import QtCore  # noqa: F401
