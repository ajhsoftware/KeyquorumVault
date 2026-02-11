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

# Background tasks and worker-thread helpers for the Qt app.
# File: python/workers/usb_workers.py

from __future__ import annotations

import os
from shutil import copy2
from qtpy.QtCore import QObject, Signal

class USBMigrator(QObject):
    finished = Signal(str)
    error = Signal(str)
    file_copied = Signal(str)

    def __init__(self, source: str, target: str):
        super().__init__()
        self.source = source
        self.target = target

    def run(self):
        try:
            for root, _, files in os.walk(self.source):
                rel_path = os.path.relpath(root, self.source)
                dest_dir = os.path.join(self.target, rel_path)
                os.makedirs(dest_dir, exist_ok=True)

                for file in files:
                    src_file = os.path.join(root, file)
                    dest_file = os.path.join(dest_dir, file)
                    copy2(src_file, dest_file)
                    self.file_copied.emit(file)

            self.finished.emit(f"✅ Migration complete at:\n{self.target}")
        except Exception as e:
            self.error.emit(f"❌ Migration failed:\n{str(e)}")
