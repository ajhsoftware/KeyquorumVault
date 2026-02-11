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

import logging, json, os, time
from pathlib import Path
from typing import Any, Dict
log = logging.getLogger("keyquorum")
from app.paths import USER_DB

_LOCK_PATH: Path = Path(USER_DB).with_suffix(".lock")
_BACKUP_DIR: Path = Path(USER_DB).parent / "_backups"


# --- Compatibility aliases (so other modules can import settings helpers) ---
def get_user_setting(username: str, key: str, default=None):
    return get_user_pref(username, key, default)

def set_user_setting(username: str, key: str, value) -> None:
    set_user_pref(username, key, value)

def find_user(name: str):
    """
    Case-insensitive username resolver. Returns the canonical username from the DB or None.
    """
    try:
        db = _load_users()
    except Exception:
        return None
    if name in db:
        return name
    name_l = (name or "").strip().lower()
    for u in db.keys():
        if u.lower() == name_l:
            return u
    return None

# ---------- tiny file lock (best-effort, no extra deps) ----------
def _acquire_lock(timeout: float = 2.5, poll: float = 0.05) -> bool:
    """
    Try to create an exclusive lock file. Returns True on lock, False on timeout.
    Best-effort; wont catch all races, but greatly reduces them.
    """
    deadline = time.time() + max(0.0, timeout)
    _LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    while time.time() < deadline:
        try:
            # O_EXCL fails if file exists
            fd = os.open(str(_LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, str(os.getpid()).encode("ascii", "ignore"))
            finally:
                os.close(fd)
            return True
        except FileExistsError:
            time.sleep(poll)
        except Exception as e:
            log.debug(f"[prefs] lock error: {e}")
            break
    return False

def _release_lock() -> None:
    try:
        if _LOCK_PATH.exists():
            _LOCK_PATH.unlink()
    except Exception:
        pass

# ---------- IO helpers ----------
def _atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    data = json.dumps(obj, indent=2, ensure_ascii=False)
    with tmp.open("w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def _safe_backup_bad_json(path: Path, raw_text: str) -> None:
    try:
        _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        bkp = _BACKUP_DIR / f"{path.name}.corrupt_{ts}.bak"
        bkp.write_text(raw_text, encoding="utf-8")
        log.warning(f"[prefs] Backed up corrupt {path} -> {bkp}")
    except Exception:
        pass

# ---------- DB load/save ----------
def _load_users() -> Dict[str, Any]:
    if not USER_DB.exists():
        return {}
    try:
        txt = USER_DB.read_text(encoding="utf-8")
        return json.loads(txt) if txt.strip() else {}
    except json.JSONDecodeError as e:
        # backup and start fresh
        try:
            txt = USER_DB.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            txt = ""
        _safe_backup_bad_json(USER_DB, txt)
        log.error(f"[prefs] Corrupt JSON in {USER_DB}: {e}")
        return {}
    except Exception as e:
        log.error(f"[prefs] Failed reading {USER_DB}: {e}")
        return {}

def _save_users(d: Dict[str, Any]) -> None:
    if not _acquire_lock():
        # As a fallback, write anyway (reduces total failure)
        log.warning("[prefs] Could not acquire lock; proceeding without it.")
        _atomic_write_json(USER_DB, d)
        return
    try:
        _atomic_write_json(USER_DB, d)
    finally:
        _release_lock()

# ---------- public API ----------
def get_user_prefs(username: str) -> Dict[str, Any]:
    """
    Returns a (shallow) copy of the users prefs dict (never None).
    Note: modifying this return value wont persist; call set_user_prefs().
    """
    db = _load_users()
    prefs = dict(db.get(username, {}).get("prefs", {}) or {})
    return prefs

def set_user_prefs(username: str, prefs: Dict[str, Any]) -> None:
    """
    Merge-and-save prefs for user (only top-level keys in `prefs` are updated).
    """
    if not isinstance(prefs, dict):
        raise TypeError("prefs must be a dict")
    db = _load_users()
    user = db.setdefault(username, {})
    p = user.setdefault("prefs", {})
    if not isinstance(p, dict):
        user["prefs"] = p = {}
    p.update(prefs)
    _save_users(db)

def get_user_pref(username: str, key: str, default: Any = None) -> Any:
    """
    Convenience getter for one key with a default.
    """
    return get_user_prefs(username).get(key, default)

def set_user_pref(username: str, key: str, value: Any) -> None:
    """
    Convenience setter for one key.
    """
    set_user_prefs(username, {key: value})

def delete_user_pref(username: str, key: str) -> None:
    """
    Remove one pref key if present.
    """
    db = _load_users()
    user = db.get(username) or {}
    prefs = user.get("prefs")
    if isinstance(prefs, dict) and key in prefs:
        prefs.pop(key, None)
        _save_users(db)

def delete_user_prefs(username: str) -> None:
    """
    Remove the entire prefs object for a user (does not delete the user entry).
    """
    db = _load_users()
    user = db.get(username) or {}
    if "prefs" in user:
        user["prefs"] = {}
        _save_users(db)
