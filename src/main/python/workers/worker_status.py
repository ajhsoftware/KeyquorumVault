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

"""Project module.

This file is part of the Keyquorum Vault codebase.
"""
from PySide6.QtCore import QObject, Signal, Slot

class Worker(QObject):
    status = Signal(str)
    finished = Signal()
    error = Signal(str)

    @Slot()
    def run(self):
        try:
            self.status.emit("Starting…")
            # ... do work ...
            self.status.emit("Halfway…")
            # ... more work ...
            self.status.emit("Done")
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished.emit()
