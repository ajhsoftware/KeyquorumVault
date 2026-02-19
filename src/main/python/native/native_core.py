from __future__ import annotations

from pathlib import Path
import sys

import logging
log = logging.getLogger("keyquorum")

from native.keyquorum_core_ctypes import KeyquorumCore

_core: KeyquorumCore | None = None


def _default_dll_path() -> str:
    """Locate keyquorum_core.dll for both dev and frozen builds."""
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    else:
        base = Path(__file__).resolve().parent
    return str(base / "bin" / "keyquorum_core.dll")


def get_core() -> KeyquorumCore | None:
    """Return a cached native core instance, or None if unavailable."""
    global _core
    if _core is not None:
        return _core
    try:
        _core = KeyquorumCore(_default_dll_path())
        print("[NativeCore] Loaded DLL OK:", _default_dll_path())
        log.info("[NativeCore] Loaded DLL OK: %s", _default_dll_path())
    except Exception:
        _core = None
    return _core
