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
import sys as _sys
import ctypes
from urllib.parse import urlparse
import logging
from auth.login.login_handler import (get_user_setting, _canonical_username_ci)

log = logging.getLogger("keyquorum")
from pathlib import Path
from app.paths import user_lock_flag_path, LICENSES_DIR, SPDX_DIR
from vault_store.vault_store import (
      add_vault_entry, load_vault, save_vault, update_vault_entry,)

from auth.login.login_handler import validate_login
from security.baseline_signer import update_baseline

try:
    from auth.yubi.yk_backend import set_probe_enabled
except Exception:
    def set_probe_enabled(val: bool):
        pass

_MAIN = (
    _sys.modules.get("__main__")
    or _sys.modules.get("main")
    or _sys.modules.get("app.app_window")
    or _sys.modules.get("app_window")
)
if _MAIN is not None:
    globals().update(_MAIN.__dict__)

# Safety net: ensure Qt symbols exist even when __main__ differs (e.g., frozen builds)
try:
    from app.qt_imports import *  # noqa: F401,F403
except Exception:
    pass





# provider_exe_path: Locate the Keyquorum Passkey helper EXE by checking multiple candidate directories, including the running EXE's folder, 
# a 'passkeys' subfolder, portable mode locations, and the script's directory. Returns the path if found, or None if not found. 
def _provider_exe_path(self, *args, **kwargs) -> str | None:
    """
    Locate the Keyquorum Passkey helper EXE.

    We look in:
    - The directory of the running EXE (installed build)
    - A 'passkeys' subfolder next to the EXE
    - Portable root and common subfolders (App/bin/Passkeys)
    - The directory of this script (dev mode)
    """
    from pathlib import Path
    import sys

    exe_names = [
        "Keyquorum.PasskeyManager.exe",   # your C# project
        "keyquorum-passkey-provider.exe", # future alt name
    ]

    bases: list[Path] = []

    # 1) Installed / frozen EXE folder
    try:
        exe_dir = Path(sys.executable).resolve().parent
        bases.append(exe_dir)
        bases.append(exe_dir / "passkeys")
    except Exception:
        pass

    # 2) Portable root (if active)
    try:
        import app.paths as _paths
        if _paths.is_portable_mode():
            pr = _paths.portable_root()
            bases.extend([
                pr,
                pr / "App",
                pr / "app",
                pr / "bin",
                pr / "Passkeys",
            ])
    except Exception:
        pass

    # 3) Dev mode – location of main.py
    try:
        here = Path(__file__).resolve().parent
        bases.append(here)
        bases.append(here.parent)
    except Exception:
        pass

    seen: set[str] = set()
    for base in bases:
        try:
            if not base:
                continue
            b = Path(base)
            key = str(b).lower()
            if key in seen:
                continue
            seen.add(key)

            for name in exe_names:
                p = b / name
                if p.is_file():
                    try:
                        log.info(f"[PASSKEY] helper exe found at {p}")
                    except Exception:
                        pass
                    return str(p)
        except Exception:
            continue

    try:
        log.info("[PASSKEY] helper exe not found in any candidate paths")
    except Exception:
        pass
    return None




# Show a dialog listing all open-source licenses included with the product, 
# with quick links to important files and a scrollable list of all license texts. Uses the LICENSES_DIR and SPDX_DIR for content.
def show_licenses_dialog(self, *args, **kwargs):
    dlg = QDialog(self)
    dlg.setWindowTitle(self.tr("Open-Source Licenses"))

    root = QVBoxLayout(dlg)
    intro = QLabel(
        "This product includes open-source software. "
        "Click a link to open a notice or license file.", dlg
    )
    intro.setWordWrap(True)
    root.addWidget(intro)

    # Quick links to folders + notices
    def add_link(text, path: Path):
        if not path.exists(): 
            return
        url = QUrl.fromLocalFile(str(path))
        lbl = QLabel(f'• <a href="{url.toString()}">{text}</a>', dlg)
        lbl.setTextFormat(Qt.RichText)
        lbl.setTextInteractionFlags(Qt.TextBrowserInteraction)
        lbl.setOpenExternalLinks(True)
        container_layout.addWidget(lbl)

    area = QScrollArea(dlg); area.setWidgetResizable(True)
    container = QWidget(); container_layout = QVBoxLayout(container)

    # Top: important files
    add_link("THIRD_PARTY_NOTICES.txt", LICENSES_DIR / "THIRD_PARTY_NOTICES.txt")
    add_link("components.json",          LICENSES_DIR / "components.json")
    add_link("README.txt",               LICENSES_DIR / "README.txt")

    # Core texts (LGPL + GPL + PyInstaller)
    add_link("SPDX_LICENSES/LGPL-3.0-only.txt", SPDX_DIR / "LGPL-3.0-only.txt")
    add_link("SPDX_LICENSES/GPL-3.0.txt",       SPDX_DIR / "GPL-3.0.txt")
    add_link("SPDX_LICENSES/vendors/pyinstaller/COPYING.txt",
             SPDX_DIR / "vendors" / "pyinstaller" / "COPYING.txt")

    # Show ALL license files recursively (common names/extensions)
    exts = {".txt", ".md", ""}  # include files like COPYING with no extension
    common_names = {"LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE"}
    shown = set()

    for p in sorted(LICENSES_DIR.rglob("*")):
        if p.is_dir():
            continue
        name = p.name
        if p.suffix.lower() in (".txt", ".md"):
            pass
        elif name.upper() in common_names:  # LICENSE, COPYING, etc.
            pass
        else:
            continue
        # avoid duplicates already listed above
        key = str(p.resolve())
        if key in shown:
            continue
        shown.add(key)
        add_link(str(p.relative_to(LICENSES_DIR)).replace("\\", "/"), p)

    container_layout.addStretch(1)
    area.setWidget(container)
    root.addWidget(area, 1)

    # Close
    btn = QPushButton(self.tr("Close"), dlg)
    btn.clicked.connect(dlg.accept)
    root.addWidget(btn)

    dlg.resize(640, 520)
    dlg.exec()

