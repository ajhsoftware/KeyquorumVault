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
import os
import sys
import subprocess
import webbrowser
from pathlib import Path
from typing import Optional, Sequence
# --- log
import logging 
log = logging.getLogger("keyquorum")


IS_WINDOWS: bool = sys.platform.startswith("win")
IS_MAC: bool = sys.platform == "darwin"
IS_LINUX: bool = sys.platform.startswith("linux")

def _as_path(p: str | os.PathLike) -> Path:
    return p if isinstance(p, Path) else Path(p)

def reveal_in_file_manager(path: str | os.PathLike) -> bool:
    """Reveal a file/folder in the system file manager."""
    p = _as_path(path).expanduser().resolve()
    try:
        if IS_WINDOWS:
            # Explorer can select files with /select,
            args = ["explorer.exe", "/select,", str(p)]
            return _popen_detached(args, no_console=True)
        if IS_MAC:
            return _popen_detached(["open", "-R", str(p)])
        if IS_LINUX:
            # Best-effort: try common file managers; fallback to xdg-open on parent
            parent = str(p.parent)
            for fm in ("nautilus", "dolphin", "nemo", "thunar", "pcmanfm"):
                if shutil_which(fm):
                    return _popen_detached([fm, parent])
            return _popen_detached(["xdg-open", parent])
        return False
    except Exception:
        return False

def open_path(path: str | os.PathLike) -> bool:
    """Open a file/folder with the default associated application.

    If a URL (http/https/ms-windows-store) is passed by mistake, open it in the default browser
    instead of treating it as a local filesystem path.
    """
    raw = str(path) if path is not None else ""
    raw = raw.strip()

    # --- URL guard (prevents Path('https:\...') becoming a bogus local path) ---
    if raw.lower().startswith(("http://", "https://", "ms-windows-store://")) or ("://" in raw and " " not in raw):
        log.debug(f"Open URL via open_path guard: {raw}")
        # Prefer Qt if available, else webbrowser
        try:
            from qtpy.QtGui import QDesktopServices
            from qtpy.QtCore import QUrl
            return bool(QDesktopServices.openUrl(QUrl(raw)))
        except Exception:
            try:
                return bool(webbrowser.open(raw, new=2))
            except Exception:
                return False

    # --- Normal filesystem path open ---
    try:
        p = _as_path(raw).expanduser().resolve()
    except Exception:
        # If resolution fails, fall back to raw string
        p = raw

    log.debug(f"Open Path call: {p}")
    try:
        if IS_WINDOWS:
            os.startfile(str(p))  # type: ignore[attr-defined]
            return True
        if IS_MAC:
            return _popen_detached(["open", str(p)])
        if IS_LINUX:
            return _popen_detached(["xdg-open", str(p)])
        return False
    except Exception:
        return False

def shutil_which(cmd: str) -> Optional[str]:
    """Minimal 'which' to avoid importing shutil everywhere."""
    for base in os.getenv("PATH", "").split(os.pathsep):
        c = Path(base) / cmd
        if IS_WINDOWS:
            for ext in (".exe", ".cmd", ".bat", ""):
                if (Path(str(c) + ext)).is_file():
                    return str(Path(str(c) + ext))
        else:
            if c.is_file() and os.access(str(c), os.X_OK):
                return str(c)
    return None

def _popen_detached(argv: Sequence[str], *, no_console: bool = False) -> bool:
    """Start a process without blocking; suppress console on Windows when requested."""
    try:
        kwargs = {}
        if IS_WINDOWS:
            # CREATE_NO_WINDOW avoids black console flashes
            if no_console:
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            kwargs["close_fds"] = True
        else:
            kwargs["start_new_session"] = True
            kwargs["close_fds"] = True
        subprocess.Popen(list(argv), **kwargs)  # noqa: S603,S607 (user-controlled not expected here)
        return True
    except Exception:
        return False
