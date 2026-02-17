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

"""Module for portable functionality.

This file is part of the Keyquorum Vault codebase.
"""

import os
import zipfile

def safe_extract_zip(zf: zipfile.ZipFile, dest_dir: str) -> None:
    """
    Extract a zip file into dest_dir while preventing directory traversal and symlink abuse.

    Ensures that all extracted paths are within dest_dir and not absolute, and rejects
    any symlink entries. Raises ValueError on invalid entries.
    """
    dest_dir = os.path.abspath(str(dest_dir))
    for m in zf.infolist():
        name = m.filename
        # Disallow absolute paths
        if os.path.isabs(name):
            raise ValueError(f"Unsafe zip path (absolute): {name}")
        # Resolve final target
        target = os.path.abspath(os.path.join(dest_dir, name))
        # Prevent directory traversal
        if not target.startswith(dest_dir + os.sep) and target != dest_dir:
            raise ValueError(f"Unsafe zip path (traversal): {name}")
        # Disallow symlinks (zip may encode symlinks via unix mode bits)
        is_symlink = ((m.external_attr >> 16) & 0o170000) == 0o120000
        if is_symlink:
            raise ValueError(f"Unsafe zip entry (symlink): {name}")
    # All checks passed; perform extraction
    zf.extractall(dest_dir)
