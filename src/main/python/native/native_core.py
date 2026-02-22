from __future__ import annotations

from pathlib import Path
import logging

log = logging.getLogger("keyquorum")

from native.keyquorum_core_ctypes import KeyquorumCore

_core: KeyquorumCore | None = None


def get_core() -> KeyquorumCore | None:
    """Return a cached native core instance, or None if unavailable."""
    global _core
    if _core is not None:
        return _core

    try:
        from app.paths import dll_file

        resolved = dll_file()  # <-- CALL IT
        dll_path = resolved if isinstance(resolved, Path) else Path(resolved)

        log.info("[NativeCore] Resolved DLL path: %s (exists=%s)", dll_path, dll_path.exists())

        if not dll_path.exists():
            raise FileNotFoundError(f"Native DLL not found at: {dll_path}")

        dep_dir = dll_path.parent
        for dep in ("libcrypto-3-x64.dll", "argon2.dll"):
            dp = dep_dir / dep
            log.info("[NativeCore] dep %s near DLL: %s (exists=%s)", dep, dp, dp.exists())

        _core = KeyquorumCore(str(dll_path))

        log.info("[NativeCore] Loaded DLL OK: %s", dll_path)
        print("[NativeCore] Loaded DLL OK:", dll_path)
        return _core

    except Exception as e:
        log.exception("[NativeCore] FAILED to load native core: %s", e)
        print("[NativeCore] FAILED to load native core:", repr(e))
        _core = None
        return None
