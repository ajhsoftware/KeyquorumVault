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


import os, sys, logging, inspect
from pathlib import Path
from typing import Optional
from functools import lru_cache

import app.kq_logging as kql

log = logging.getLogger("keyquorum")
APP_NAME = "Keyquorum"
PORTABLE_MARKER = "portable.marker"
PORTABLE_OVERRIDES = "portable.json"

# --- global read-only switch (default: False) ---
_READ_ONLY_PATHS = False

# ==============================
# --- URL --- 
# ==============================
APP_ROOT            = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
LICENSES_DIR        = APP_ROOT / "licenses"        
LICENSE_CACHE_DIR   = APP_ROOT / "license_cache"
SPDX_DIR            = LICENSES_DIR / "SPDX_LICENSES"
VENDORS_DIR         = SPDX_DIR / "vendors"
PYI_DIR             = VENDORS_DIR / "pyinstaller"

# ==============================
# --- Resource lookup (unified; no RES_DIR / APP_ROOT) ---
# ==============================

class read_only_paths:
    """Context manager to suppress any auto-mkdir during sensitive code paths (e.g., login)."""
    def __init__(self, on: bool = True):
        self._on = on
        self._prev = None
    def __enter__(self):
        global _READ_ONLY_PATHS
        self._prev = _READ_ONLY_PATHS
        _READ_ONLY_PATHS = bool(self._on)
        return self
    def __exit__(self, exc_type, exc, tb):
        global _READ_ONLY_PATHS
        _READ_ONLY_PATHS = self._prev

def _paths_ro() -> bool:
    """True when read_only_paths(True) is active."""
    try:
        from app.paths import _READ_ONLY_PATHS
        return bool(_READ_ONLY_PATHS)
    except Exception:
        return False

def _maybe_mkdir(p: Path, *, note: str, caller: str, ensure: bool):
    """
    Create dir only if ensure=True and global read-only is OFF.
    """
    from pathlib import Path as _Path
    try:
        if ensure and not _READ_ONLY_PATHS:
            p.mkdir(parents=True, exist_ok=True)
            try:
                log.debug(f"📁 [PATHS] mkdir -> {p}  note={note}  caller={caller}")
            except Exception:
                pass
    except Exception:
        pass
    return p

# ==============================
# --- Resources (single source of truth) ---
# ==============================

from functools import lru_cache
from pathlib import Path
import os, sys

def _bundle_root() -> Path:
    """
    Root folder for bundled assets.
    - Frozen (PyInstaller/FBS): sys._MEIPASS
    - Source: folder containing this file (or your repo layout)
    """
    if getattr(sys, "frozen", False):
        mp = getattr(sys, "_MEIPASS", None)
        if mp:
            return Path(mp)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

def _resource_roots() -> list[Path]:
    """
    Ordered search roots. First match wins.
    """
    roots: list[Path] = []

    # 0) Optional env override (dev/tests)
    env = os.getenv("KEYQUORUM_RES_DIR")
    if env:
        roots.append(Path(env).resolve())

    base = _bundle_root()

    # 1) Preferred: bundle has /resources at root
    roots.append((base / "resources").resolve())

    # 2) Common PyInstaller/FBS layouts
    roots.append((base / "_internal" / "resources").resolve())
    roots.append((base / "base" / "resources").resolve())
    roots.append((base / "resources" / "base" / "resources").resolve())

    # 3) Dev fallback: repo-style resources next to this module
    roots.append((Path(__file__).resolve().parent / "resources").resolve())

    # 4) Last resort: cwd/resources
    roots.append((Path.cwd() / "resources").resolve())

    # Deduplicate while preserving order
    seen = set()
    out = []
    for r in roots:
        if str(r) not in seen:
            out.append(r)
            seen.add(str(r))
    return out

@lru_cache(maxsize=1024)
def res_path(relpath: str | Path, *, must_exist: bool = False) -> Path:
    """
    Single, canonical resolver for ALL resources (source + frozen).
    Use like:
      res_path("ui/login.ui")
      res_path("i18n/en_GB.qm")
      res_path("icons/icon.png")
    """
    rp = Path(relpath)

    tried: list[str] = []
    for root in _resource_roots():
        p = (root / rp)
        tried.append(str(p))
        try:
            if p.exists():
                return p
        except Exception:
            continue

    if must_exist:
        raise FileNotFoundError(
            f"Resource not found: {rp}\nTried:\n- " + "\n- ".join(tried)
        )

    # Best-guess (predictable): first root + rp
    return _resource_roots()[0] / rp

# Back-compat: old call sites use res("...") returning a string sometimes
def res(relpath: str | Path) -> str:
    return str(res_path(relpath))


# -----------------------------------
# Mode & overrides
# -----------------------------------
_PORTABLE_ROOT_OVERRIDE: Optional[Path] = None
_USERS_DIR_OVERRIDE: Optional[Path] = None  # legacy/compat

def set_portable_root(root: Optional[Path | str]) -> None:
    """Force portable mode under <root>/KeyquorumPortable (or <root> if already that)."""
    global _PORTABLE_ROOT_OVERRIDE, _USERS_DIR_OVERRIDE
    if root is None:
        _PORTABLE_ROOT_OVERRIDE = None
        _USERS_DIR_OVERRIDE = None
        log.info("🧭 [PATHS] portable root override cleared (installed split mode).")
        return
    r = Path(root)
    if (r / "KeyquorumPortable").exists():
        r = r / "KeyquorumPortable"
    _PORTABLE_ROOT_OVERRIDE = r.resolve()
    _USERS_DIR_OVERRIDE = None
    log.info(f"🧭 [PATHS] portable root override → {str(_PORTABLE_ROOT_OVERRIDE)}")

def set_users_dir_override(users_dir: Optional[Path | str]) -> None:
    """Directly force the Users directory (compat)."""
    global _USERS_DIR_OVERRIDE
    _USERS_DIR_OVERRIDE = None if users_dir is None else Path(users_dir).resolve()
    log.info(f"🧭 [PATHS] USERS_DIR override → {str(_USERS_DIR_OVERRIDE) if _USERS_DIR_OVERRIDE else 'cleared'}")

def is_frozen() -> bool:
    return getattr(sys, "frozen", False)

def _exe_dir() -> Path:
    return Path(sys.executable if is_frozen() else __file__).resolve().parent

def _env_local() -> Path:
    """Best-effort OS-appropriate 'local data' base directory."""
    # Windows: LOCALAPPDATA (fallback: ~/AppData/Local)
    if sys.platform.startswith("win"):
        return Path(os.getenv("LOCALAPPDATA", "") or (Path.home() / "AppData" / "Local"))
    # macOS: ~/Library/Application Support
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support"
    # Linux / other: XDG_DATA_HOME (fallback: ~/.local/share)
    return Path(os.getenv("XDG_DATA_HOME", "") or (Path.home() / ".local" / "share"))

def _env_roaming() -> Path:
    """Best-effort OS-appropriate 'config/roaming' base directory."""
    # Windows: APPDATA (fallback: ~/AppData/Roaming)
    if sys.platform.startswith("win"):
        return Path(os.getenv("APPDATA", "") or (Path.home() / "AppData" / "Roaming"))
    # macOS: keep configs alongside app support (works well for desktop apps)
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support"
    # Linux / other: XDG_CONFIG_HOME (fallback: ~/.config)
    return Path(os.getenv("XDG_CONFIG_HOME", "") or (Path.home() / ".config"))

def is_portable_mode() -> bool:
    if _PORTABLE_ROOT_OVERRIDE:
        return True
    d = _exe_dir()
    for _ in range(8):
        if (d / "KeyquorumPortable").exists() or (d / "KeyquorumPortable.marker").exists():
            return True
        d = d.parent
    return False

def portable_root() -> Path:
    if _PORTABLE_ROOT_OVERRIDE:
        return _PORTABLE_ROOT_OVERRIDE
    if is_portable_mode():
        d = _exe_dir()
        for _ in range(8):
            if (d / "KeyquorumPortable").exists():
                return (d / "KeyquorumPortable").resolve()
            d = d.parent
    # fallback: installed local app root
    return (_env_local() / "Keyquorum").resolve()

# -----------------------------------
# App roots (global)
# -----------------------------------
def app_root_local() -> Path:
    return (_env_local() / "Keyquorum").resolve()

def app_root_roaming() -> Path:
    return (_env_roaming() / "Keyquorum").resolve()

def data_dir(*, ensure: bool = False) -> Path:
    d = app_root_local()
    _ensure_dir_logged(d, ensure, note="data_dir")
    return d

def docs_dir(*, ensure: bool = False) -> Path:
    d = Path.home() / "Documents" / "Keyquorum"
    _ensure_dir_logged(d, ensure, note="docs_dir")
    return d

def log_dir(*, ensure: bool = False) -> Path:
    d = app_root_local() / "logs"
    _ensure_dir_logged(d, ensure, note="log_dir")
    return d

def _backup_dir(username: str):
    """
    Read-only path for user backups under the new layout.
    Do NOT create directories from here.
    """
    return (user_root(username, ensure=False) / "Backups")


BACKUP_DIR = _backup_dir
# -----------------------------------
# mkdir instrumentation
# -----------------------------------
def _ensure_dir_logged(path: Path, make: bool, note: str = "") -> None:
    """Create directory only if make=True AND global read-only is OFF; log who asked."""
    try:
        # Same module, but this try keeps things safe if moved.
        from app.paths import _READ_ONLY_PATHS  # noqa: F401
    except Exception:
        _READ_ONLY_PATHS = False  

    if (not make) or _READ_ONLY_PATHS:
        return

    try:
        import inspect  # local import OK
        frm = inspect.stack()[1]  # immediate caller
        caller = f"{frm.function}@{Path(frm.filename).name}:{frm.lineno}"
    except Exception:
        caller = "unknown"

    try:
        path.mkdir(parents=True, exist_ok=True)
        log.debug(f"📁 [PATHS] mkdir -> {path}  note={note}  caller={caller}")
    except Exception as e:
        log.error(f"❌ [PATHS] mkdir failed -> {path}: {e}  note={note}  caller={caller}")

# -----------------------------------
# Users roots — split (installed) vs unified (portable)
# -----------------------------------

def users_root_local(*, ensure: bool = False) -> Path:
    p = app_root_local() / "Users"
    _ensure_dir_logged(p, ensure, note="users_root_local")
    return p.resolve()

def users_root_roaming(*, ensure: bool = False) -> Path:
    p = app_root_roaming() / "Users"
    _ensure_dir_logged(p, ensure, note="users_root_roaming")
    return p.resolve()

def users_root_portable(*, ensure: bool = False) -> Path:
    p = portable_root() / "Users"
    _ensure_dir_logged(p, ensure, note="users_root_portable")
    return p.resolve()

def users_root(*, ensure: bool = False) -> Path:
    """General 'Users' root: portable if portable, else Local."""
    if _USERS_DIR_OVERRIDE:
        d = _USERS_DIR_OVERRIDE
    else:
        # IMPORTANT: never allow inner mkdirs here
        d = users_root_portable(ensure=False) if is_portable_mode() else users_root_local(ensure=False)

    # Only create when explicitly asked *and* not in read-only mode
    try:
        from app.paths import _READ_ONLY_PATHS  # same module
    except Exception:
        _READ_ONLY_PATHS = False

    if ensure and not _READ_ONLY_PATHS:
        _ensure_dir_logged(d, True, note="users_root")

    return d

# NOTE: Per-user roots MUST NOT create by default. Pass ensure=True only when writing.
def user_root_local(username: str, *, ensure: bool = False) -> Path:
    u = (username or "user").strip()
    container = users_root_local(ensure=False)  # never create here
    # create container only if we are explicitly ensuring (and not in RO)
    _ensure_dir_logged(container, ensure, note="users_root_local(parent)")
    p = container / u
    _ensure_dir_logged(p, ensure, note="user_root_local")
    return p.resolve()

def user_root_roaming(username: str, *, ensure: bool = False) -> Path:
    u = (username or "user").strip()
    container = users_root_roaming(ensure=False)
    _ensure_dir_logged(container, ensure, note="users_root_roaming(parent)")
    p = container / u
    _ensure_dir_logged(p, ensure, note="user_root_roaming")
    return p.resolve()

def user_root_portable(username: str, *, ensure: bool = False) -> Path:
    u = (username or "user").strip()
    container = users_root_portable(ensure=False)
    _ensure_dir_logged(container, ensure, note="users_root_portable(parent)")
    p = container / u
    _ensure_dir_logged(p, ensure, note="user_root_portable")
    return p.resolve()

def user_root(username: str, *, ensure: bool = False) -> Path:
    return user_root_portable(username, ensure=ensure) if is_portable_mode() \
           else user_root_local(username, ensure=ensure)
# -----------------------------------
# Per-user subdirs (helpers)
# -----------------------------------
def _user_local_dir(username: str, *parts: str, ensure_dir: bool = False) -> Path:
    base = users_root_local(ensure=False) / username
    if parts:
        base = base / Path(*parts)
    # Never mkdir in read-only
    _ensure_dir_logged(base, ensure_dir and not _paths_ro(), note="_user_local_dir")
    return base.resolve()

def _user_roaming_dir(username: str, *parts: str, ensure_dir: bool = False) -> Path:
    p = user_root_roaming(username, ensure=False)
    for part in parts:
        p = p / part
    _ensure_dir_logged(p, ensure_dir, note="_user_roaming_dir")
    return p

def _user_portable_dir(username: str, *parts: str, ensure_dir: bool = False) -> Path:
    base = users_root_portable(ensure=False) / username
    if parts:
        base = base / Path(*parts)
    _ensure_dir_logged(base, ensure_dir and not _paths_ro(), note="_user_portable_dir")
    return base.resolve()
# -----------------------------------
# VAULT (Local/Main/<u>.kq_user OR Portable/Main/<u>.kq_user)
# -----------------------------------
def vault_dir(username: str, *, ensure_parent: bool = False) -> Path:
    base = (user_root_portable(username, ensure=False) / "Main") if is_portable_mode() \
           else (user_root_local(username, ensure=False) / "Main")
    p = base / "Vault"
    _ensure_dir_logged(p, bool(ensure_parent), note="vault_dir")
    return p

def vault_file(username: str, *, ensure_parent: bool = False, name_only: bool = False) -> Path:
    name = f"{username}.kq_user"
    return Path(name) if name_only else vault_dir(username, ensure_parent=ensure_parent) / name

def pw_cache_file(username: str, *, ensure_parent: bool = False, name_only: bool = False) -> Path:
    name = f"{username}pw_last.bin"
    return Path(name) if name_only else vault_dir(username, ensure_parent=ensure_parent) / name

def trash_path(username: str, *, ensure_parent: bool = False, name_only: bool = False) -> Path:
    name = f"{username}_trash.bin"
    return Path(name) if name_only else vault_dir(username, ensure_parent=ensure_parent) / name

# Wrapped key next to vault
def vault_wrapped_file(username: str, *, ensure_parent: bool = False, name_only: bool = False) -> Path:
    name = f"{username}.kq_wrap"
    return Path(name) if name_only else vault_dir(username, ensure_parent=ensure_parent) / name

# -----------------------------------
# SALT (Roaming/KQ_Store OR Portable/KQ_Store)
# -----------------------------------
def salt_dir(username: str, *, ensure_parent: bool = False) -> Path:
    """Return the per-user salt directory.

    Portable:  <USB>\KeyquorumPortable\\Users\<user>\KQ_Store
    Installed: %APPDATA%\Keyquorum\\Users\<user>\KQ_Store  (roaming)
    """
    base = user_root_portable(username, ensure=False) if is_portable_mode() else user_root_roaming(username, ensure=False)
    p = base / "KQ_Store"
    _ensure_dir_logged(p, bool(ensure_parent) and not _paths_ro(), note="salt_dir")
    return p

def salt_file(username: str, *, ensure_parent: bool = False, name_only: bool = False) -> Path:
    name = f"kq_user_{username}.slt"
    return Path(name) if name_only else salt_dir(username, ensure_parent=ensure_parent) / name

# -----------------------------------
# CONFIG (global or per-user)
# -----------------------------------
def profile_pic(username):
    return config_dir(username, ensure_parent=True) / "Profile" / f"{username}.png"

def config_dir(username: Optional[str] = None, *, ensure_parent: bool = False) -> Path:
    """
    Return configuration directory.
    - If username is given: per-user config under that user root.
    - If username is None: global config (portable root or Local).
    """
    if username:
        # --- Per-user config ---
        u = username.strip()
        if is_portable_mode():
            base = user_root_portable(u, ensure=False)
        else:
            base = user_root_local(u, ensure=False)
        p = base / "Config"
        _ensure_dir_logged(p, bool(ensure_parent), note=f"config_dir(user={u})")
        return p.resolve()

    # --- Global config (no username) ---
    if is_portable_mode():
        p = portable_root() / "Config"
    else:
        p = app_root_local() / "Config"

    _ensure_dir_logged(p, bool(ensure_parent), note="config_dir(global)")
    return p.resolve()

# -----------------------------------
# LOGS (per-user)
# -----------------------------------
def user_logs_dir(username: str, *, ensure_parent: bool = False) -> Path:
    want = bool(ensure_parent)
    base = _user_portable_dir(username, ensure_dir=want) if is_portable_mode() \
        else _user_roaming_dir(username, ensure_dir=want)
    p = base / f"{username}_log"
    _ensure_dir_logged(p, want, note="user_logs_dir")
    return p

def tamper_log_file(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"{username}ms_tamper.log"
    return Path(name) if name_only else user_logs_dir(username, ensure_parent=ensure_parent) / name

def user_log_file(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"{username}.log"
    return Path(name) if name_only else user_logs_dir(username, ensure_parent=ensure_parent) / name

# -----------------------------------
# USER DB (Roaming/Main OR Portable/Main)
# -----------------------------------
def per_user_db_dir(username: str, *, ensure_parent: bool = False) -> Path:
    want = bool(ensure_parent)
    p = _user_portable_dir(username, "Main", ensure_dir=want) if is_portable_mode() \
        else _user_roaming_dir(username, "Main", ensure_dir=want)
    _ensure_dir_logged(p, want, note="per_user_db_dir")
    return p

def user_db_file(username: str, *, ensure_parent: bool = False, name_only: bool = False) -> Path:
    name = f"{username}_KQ.kq"
    return Path(name) if name_only else per_user_db_dir(username, ensure_parent=ensure_parent) / name

# -----------------------------------
# IDENTITIES (per-user Config)
# -----------------------------------
def identities_file(username: str, *, ensure_parent: bool = False, name_only: bool = False) -> Path:
    """
    Canonical identity store (TOTP, backup codes, header flags).
    Installed:  %APPDATA%\Keyquorum\\Users\<user>\Main\<user>.kq_id
    Portable:   <USB>\KeyquorumPortable\\Users\<user>\Main\<user>.kq_id
    """
    u = (username or "user").strip()
    name = f"{u}.kq_id"
    # keep it next to other roaming 'Main' files so baselining / backups see it
    base = user_root_portable(u, ensure=False) / "Main" if is_portable_mode() \
           else user_root_roaming(u, ensure=False) / "Main"
    if name_only:
        return Path(name)
    p = base / name
    _ensure_dir_logged(base, ensure_parent, note="identities_parent")
    return p

# -----------------------------------
# AUDIT (per-user Config)
# -----------------------------------
def audit_file_salt(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"AD_{username}.kqslt"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

def audit_file(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"{username}.kqad"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

def audit_mirror_file(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"{username}.kqadmr"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

def user_lock_flag_path(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"{username}.kquslk"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

def audit_tamper(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"{username}tamper.kqtp"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

def audit_dir_for_user(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = "audit.enc.jsonl"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

# -----------------------------------
# LICENSES (global or per-user Config)
# -----------------------------------
def licenses_dir(username: str | None = None, *, ensure_parent: bool = False) -> Path:
    if is_portable_mode():
        p = (_user_portable_dir(username, "Config", ensure_dir=ensure_parent) / "LICENSES") if username \
            else (users_root_portable() / "LICENSES")
    else:
        p = (_user_roaming_dir(username, "Config", ensure_dir=ensure_parent) / "LICENSES") if username \
            else (app_root_local() / "LICENSES")
    _ensure_dir_logged(p, ensure_parent, note="licenses_dir")
    return p

def licenses_file(username: str | None = None, *, ensure_parent: bool = False, name_only: bool = False, use_type: str = "lemon", ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = "lemon_instance.json" if use_type == "lemon" else "license_cache.json"
    return Path(name) if name_only else licenses_dir(username, ensure_parent=ensure_parent) / name

def licenses_key_file(username: str | None = None, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = "license_key.key"
    return Path(name) if name_only else licenses_dir(username, ensure_parent=ensure_parent) / name

# -----------------------------------
# BASELINE, SETTINGS, SECURITY PREFS, SOFTWARE
# -----------------------------------
def baseline_file(username: str, *, ensure_parent: bool = False, name_only: bool = False) -> Path:
    name = f"{username}_bline.bsln"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

def _settings_dir_canonical(username: str) -> Path:
    base = user_root_portable(username, ensure=False) if is_portable_mode() else user_root_roaming(username, ensure=False)
    lower = base / "settings"
    upper = base / "Settings"
    if upper.exists() and not lower.exists():
        return upper
    return lower

def settings_dir(username: str, *, ensure_parent: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    p = _settings_dir_canonical(username)
    _ensure_dir_logged(p, ensure_parent, note="settings_dir")
    return p

def security_prefs_file(username: str, *, ensure_parent: bool = False, name_only: bool = True) -> Path:
    name = f"{username}_prefs.sp"
    return name if name_only else (config_dir(username, ensure_parent=ensure_parent) / name)

def software_dir(username: str, *, ensure_parent: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    p = _user_portable_dir(username, "Software", ensure_dir=ensure_parent) if is_portable_mode() \
        else _user_roaming_dir(username, "Software", ensure_dir=ensure_parent)
    _ensure_dir_logged(p, ensure_parent, note="software_dir")
    return p

# -----------------------------------
# Shared & schema/caches
# -----------------------------------
def shared_key_file(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"{username}.sharekeys.json"
    base = config_dir(username, ensure_parent=ensure_parent) / "ShareKey"
    _ensure_dir_logged(base, ensure_parent, note="shared_key_file(base)")
    return Path(name) if name_only else base / name

def category_schema_file(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"{username}.schema.json"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

def catalog_file(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"{username}.enc"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

def catalog_seal_file(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"{username}.hmac"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

def breach_cache(username: str, *, ensure_parent: bool = False, name_only: bool = False, ensure_dir: bool = None) -> Path:
    if ensure_dir is not None:
        ensure_parent = bool(ensure_parent or ensure_dir)
    name = f"{username}_breach_cache.json"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

def dev_file(username: str, *, ensure_parent: bool = False, name_only: bool = False) -> Path:
    name = "dev_entitlements.json"
    return Path(name) if name_only else config_dir(username, ensure_parent=ensure_parent) / name

def _hints_path() -> Path:
    return Path(config_dir()) / "hints.json"

def ui_file(name: str = "keyquorum_ui", *, must_exist: bool = False) -> Path:
    return res_path(Path("ui") / f"{name}.ui", must_exist=must_exist)

def lang_dir(*, must_exist: bool = False) -> Path:
    # example: resources/i18n/...
    return res_path(Path("i18n"), must_exist=must_exist)

def icon_file(name: str) -> Path:
    return res_path(f"icons/{name}")

def lang(name: str) -> Path:
    return res_path(Path("i18n") / name)

CONFIG_DIR: Path = app_root_local()
DATA_DIR:   Path = data_dir()
DOCS_DIR:   Path = docs_dir()
LOG_DIR:    Path = log_dir()
LANG_DIR:    Path = lang_dir()
UI_DIR:     Path = ui_file()

# -----------------------------------
# Back-compat alias/registry (optional)
# -----------------------------------
USERS_DIR: Path = users_root()
_KQ_ORIG_FUNCS = {
    "user_db_file": user_db_file,
    "per_user_db_file": user_db_file,
    "vault_file": vault_file,
    "salt_file": salt_file,
    "soft_user_dir": software_dir,
    "settings_dir": settings_dir,
    "security_prefs_file": security_prefs_file,
    "audit_dir": config_dir,
    "identities_file": identities_file,
}

# -----------------------------------
# Import-time summary
# -----------------------------------
try:
    mode = "portable" if is_portable_mode() else "installed"
    log.info(f"🧭 [PATHS] mode={mode}")
    log.info(f"🧭 [PATHS] DATA_DIR={str(DATA_DIR)}")
    log.info(f"🧭 [PATHS] DOCS_DIR={str(DOCS_DIR)}")
    log.info(f"🧭 [PATHS] LOG_DIR={str(LOG_DIR)}")
except Exception:
    pass

# ==============================
# --- Unified ensure_dirs (modern)
# ==============================
def ensure_dirs(username: str | None = None) -> None:
    """
    Ensure required app and (optionally) per-user directories exist.
    Only call from flows that intend to write (create account, imports, etc.).
    """
    try:
        Path(app_root_local()).mkdir(parents=True, exist_ok=True)
        Path(users_root()).mkdir(parents=True, exist_ok=True)
        if username:
            Path(user_root(username, ensure=True)).mkdir(parents=True, exist_ok=True)
            Path(config_dir(username, ensure_parent=True)).mkdir(parents=True, exist_ok=True)
            Path(vault_dir(username, ensure_parent=True)).mkdir(parents=True, exist_ok=True)
            try:
                Path(trash_path(username, ensure_parent=True)).parent.mkdir(parents=True, exist_ok=True)
            except TypeError:
                pass
        log.debug(f"✅ [PATHS] ensured base{' + user' if username else ''} dirs ok")
    except Exception as e:
        log.error(f"❌ [PATHS] ensure_dirs failed: {e}")

# -----------------------------------
# Bridge token file location helper
# -----------------------------------
def bridge_token_dir(username: str | None = None, ensure_parent: bool = True) -> Path:
    return config_dir(username, ensure_parent=ensure_parent) / "BTOK.txt"


def find_passkey_manager_exe(base_dir: str) -> str | None:
    cands = []

    # 1) Bundled (prefer)
    cands += [
        os.path.join(base_dir, "_internal", "resources", "bin", "Keyquorum.PasskeyManager.exe"),
        os.path.join(base_dir, "resources", "bin", "Keyquorum.PasskeyManager.exe"),
    ]

    # (optional) also allow a shorter name if you ship it that way
    cands += [
        os.path.join(base_dir, "_internal", "resources", "bin", "PasskeyManager.exe"),
        os.path.join(base_dir, "resources", "bin", "PasskeyManager.exe"),
    ]

    for p in cands:
        try:
            if p and os.path.isfile(p):
                return p
        except Exception:
            pass

    return None

def debug_log_paths(username: str | None = None) -> None:
    try:
        mode = "portable" if is_portable_mode() else "installed"

        dod   = docs_dir()
        ur    = users_root()
        ld    =  log_dir()
        glp   = LANG_DIR

        RES_ROOT = res_path("")    
        I18N_DIR = res_path("i18n")      
        PROF_PNG = icon_file("default_user.png")    # res_path("icons/icon.png")   
        ICON_PNG = icon_file("icon.png")            

        try: 
            from app.kq_logging import get_logfile_path
            lgd   = get_logfile_path()
        except Exception as e:
            lgd = ""

        CONFIG_DIR: Path = app_root_local()
        LOG_DIR:    Path = log_dir()
        log.info(f"{kql.i('build')} [MODE] mode={mode}")
        log.info(f"{kql.i('path')} [DF_PATHS] DATA_DIR={DATA_DIR} (exists={DATA_DIR.exists()})")
        log.info(f"{kql.i('path')} [DF_PATHS] DOCS_DIR={DOCS_DIR} (exists={DOCS_DIR.exists()})")
        log.info(f"{kql.i('path')} [DF_PATHS] USERS_ROOT={ur} (exists={ur.exists()})")
        log.info(f"{kql.i('path')} [DF_PATHS] LOG_DIR={LOG_DIR} (exists={LOG_DIR.exists()})")
        log.info(f"{kql.i('path')} [LOG] LANG_DIR={lgd}")
        log.info(f"{kql.i('path')} [RES] RES_ROOT={RES_ROOT} (exists={RES_ROOT.exists()})")
        log.info(f"{kql.i('path')} [RES] I18N_DIR={I18N_DIR} (exists={I18N_DIR.exists()})")
        log.info(f"{kql.i('path')} [RES] PROF_PNG={PROF_PNG} (exists={PROF_PNG.exists()})")
        log.info(f"{kql.i('path')} [RES] ICON_PNG={ICON_PNG} (exists={ICON_PNG.exists()})")

    except Exception as e:
        try:
            log.error(f"{kql.i('path')} [DF_PATHS] Error: {e}")
        except Exception:
            pass

def user_log_paths(username: str | None = None) -> None:

    spf = security_prefs_file(username, ensure_parent=False, name_only=False)
    csf = category_schema_file(username, ensure_parent=False)
    cf = catalog_file(username, ensure_parent=False)
    casf = catalog_seal_file(username, ensure_parent=False)
    skf = shared_key_file(username, ensure_parent=False)
    bcf = breach_cache(username, ensure_parent=False)
    pif = profile_pic(username)
    tf = trash_path(username, ensure_parent=False)
    phf = pw_cache_file(username, ensure_parent=False)
    vw = vault_wrapped_file(username, ensure_parent=False)
    vf = vault_file(username, ensure_parent=False)
    sf = salt_file(username, ensure_parent=False)
    idf = identities_file(username, ensure_parent=False)
    udb = user_db_file(username, ensure_parent=False)
    sft = software_dir(username, ensure_parent=False)
    afs = audit_file_salt(username, ensure_parent=False)
    adf = audit_file(username, ensure_parent=False)
    amf = audit_mirror_file(username, ensure_parent=False)
    at = audit_tamper(username, ensure_parent=False)
    adfu = audit_dir_for_user(username, ensure_parent=False)
    ulf = user_lock_flag_path(username, ensure_parent=False)
    cf = config_dir(username, ensure_parent=False)
    bk = _backup_dir(username)
    # -----------------------
    log.info(f"{kql.i('path')} [US_PATHS] {spf} exists={spf.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {csf} exists={csf.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {cf} exists={cf.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {casf} exists={casf.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {skf} exists={skf.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {bcf} exists={bcf.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {pif} exists={pif.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {tf} exists={tf.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {phf} exists={phf.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {vw} exists={vw.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {vf} exists={vf.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {sf} exists={sf.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {idf} exists={idf.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {udb} exists={udb.exists()}")
    log.info(f"{kql.i('path')} [US_PATHS] {sft} exists={sft.exists()}")
