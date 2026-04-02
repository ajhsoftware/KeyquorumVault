from __future__ import annotations

from pathlib import Path
import logging

log = logging.getLogger("keyquorum")

from native.keyquorum_core_ctypes import KeyquorumCore

_core: KeyquorumCore | None = None


# Fail-closed: do not allow Python crypto fallback for vault operations.

from app.dev.dev_ops import STRICT_NATIVE_CORE

def get_core() -> KeyquorumCore:
    """Return a cached native core instance (STRICT mode: never returns None).

    In STRICT_NATIVE_CORE mode, failure to load the DLL is a fatal error. This prevents
    any accidental downgrade to Python-based crypto paths.
    """
    global _core
    if _core is not None:
        return _core

    try:
        from app.paths import dll_file

        resolved = dll_file()  # <-- CALL DLL
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
        return _core

    except Exception as e:
        log.exception("[NativeCore] FAILED to load native core: %s", e)
        _core = None
        if STRICT_NATIVE_CORE:
            raise RuntimeError(
                "Native core (keyquorum_core.dll) is required. "
                "Keyquorum Vault cannot run securely without it."
            ) from e
        # Non-strict (dev/test) mode: allow callers to handle None.
        return None  # type: ignore[return-value]

