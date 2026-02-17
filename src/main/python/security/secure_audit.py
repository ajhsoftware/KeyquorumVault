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
"""
Public API:
- append_audit_log(username, event_type, description="")
- read_audit_log(username)
- log_event(username, event, desc="")
- log_event_encrypted(username, label, value="", *, extra=None, anchor_store_cb=None)
- write_audit(event, username, vault_salt, anchor_store_cb)
- verify_audit(vault_salt, expected_anchor, username)
- is_locked_out(username, threshold, window_mins=10, cooldown_mins=5)
- clear_lockout(username)
- audit_health(username)
- get_audit_file_path(username)
"""

import base64, hashlib, hmac, json, logging, os, time, datetime as dt
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

from cryptography.fernet import Fernet

log = logging.getLogger("keyquorum")

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("secure_audit", text)
# -----------------------------------
# Centralized paths
# -----------------------------------
from app.paths import (
    audit_file,
    audit_mirror_file,
    user_lock_flag_path,
    tamper_log_file,
)

# -----------------------------------
# Constants / helpers
# -----------------------------------

#
# The previous implementation stored a static application key (`APP_KEY`) and HMAC
# label (`AUDIT_KEY_LABEL`) directly in source.  Those values were used as
# cryptographic inputs which meant anybody with access to the source could
# reconstruct a user's audit key.  With the introduction of audit_v2 this is
# unnecessary and potentially dangerous.  Replace the static values with
# context strings to make it explicit that these bytes are *not* secrets.
# They are only used as labels when deriving keys via HMAC or HKDF.  See
# `audit_v2.py` for the current recommended implementation.

# Label used when deriving the HMAC key from a user’s vault salt.  This is a
AUDIT_HMAC_CONTEXT = b"KeyquorumVault|AUDIT|HMAC"

def _get_user_salt(username: str) -> bytes:
    """Return a per-user random salt used to derive the audit encryption key.

    This helper creates a salt file alongside the audit log if one does not
    already exist.  Using a unique salt per user avoids deriving all audit
    keys from a single constant.  The salt is stored on disk with
    restrictive permissions (0o600) where supported.
    """
    try:
        # Compute a path next to the primary audit file for storing the salt.
        base_path = audit_file(username)
        # The salt file uses the same stem with a `.salt` suffix to avoid
        # clashing with existing files.
        salt_path = base_path.with_suffix(base_path.suffix + ".salt")
        # Return the existing salt if present
        if salt_path.exists():
            return salt_path.read_bytes()
        # Generate a new 32‑byte salt
        salt = os.urandom(32)
        # Ensure the parent directory exists
        salt_path.parent.mkdir(parents=True, exist_ok=True)
        with open(salt_path, "wb") as f:
            f.write(salt)
        try:
            os.chmod(salt_path, 0o600)
        except Exception:
            pass
        return salt
    except Exception:
        # Fall back to a random salt if any I/O fails
        return os.urandom(32)

def _chmod_600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _chmod_600(path)

def _fernet_for_user(username: str) -> Fernet:
    """Derive a per-user Fernet key using a unique per-user salt.

    Historically this function concatenated a global `APP_KEY` constant with the
    username and hashed the result to derive a key.  That design meant all
    users shared the same secret, which is unsuitable for an encrypted audit
    log.  This revised implementation uses a random salt stored alongside
    the audit file.  The salt is persisted on disk so that the same key is
    derived across sessions without hard‑coding any secret in the source.
    """
    # Retrieve (or create) a 32‑byte salt for this user
    salt = _get_user_salt(username)
    # Combine the salt with the username to derive the key material
    u = (username or "").encode("utf-8", "ignore")
    digest = hashlib.sha256(salt + u).digest()
    return Fernet(base64.urlsafe_b64encode(digest))

# -----------------------------------
# Tamper logs
# -----------------------------------
def log_manifest_tamper(reason: str, username: str | None = None) -> None:
    """Append a tamper-notice line to tamper_log_file(username)."""
    try:
        path = tamper_log_file(username, ensure_parent=True)
        stamp = dt.datetime.now().isoformat(timespec="seconds")
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[{stamp}] [MANIFEST FAILURE] {reason}\n")
    except Exception as e:
        log.warning(f"[manifest] log failure: {e}")

# -----------------------------------
# Encrypted per-user audit log
# -----------------------------------
def get_audit_file_path(username: str) -> str:
    return str(audit_file(username))

def append_audit_log(username: str, event_type: str, description: str = "") -> None:
    """Append one encrypted JSON entry to the per-user audit log."""
    path = audit_file(username, ensure_dir=True)
    fernet = _fernet_for_user(username)

    entries: list[dict[str, Any]] = []
    if path.exists():
        try:
            decrypted = fernet.decrypt(path.read_bytes())
            entries = json.loads(decrypted.decode("utf-8"))
            if not isinstance(entries, list):
                entries = []
        except Exception as e:
            log.error(f"[secure_audit] read error for {username}: {e}")

    entries.append({
        "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
        "event": event_type,
        "description": description or "",
    })

    try:
        blob = fernet.encrypt(json.dumps(entries, ensure_ascii=False).encode("utf-8"))
        _atomic_write_bytes(path, blob)
        _atomic_write_bytes(audit_mirror_file(username, ensure_dir=True), blob)
    except Exception as e:
        log.error(f"[secure_audit] save error for {username}: {e}")

def read_audit_log(username: str) -> list[dict[str, Any]]:
    path = audit_file(username)
    if not path.exists():
        return []
    fernet = _fernet_for_user(username)
    try:
        data = fernet.decrypt(path.read_bytes())
        return json.loads(data.decode("utf-8"))
    except Exception as e:
        log.error(f"[secure_audit] decrypt failed for {username}: {e}")
        return [{
            "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
            "event": _tr("⚠️ unreadable"),
            "description": _tr("Audit may be corrupted or tampered."),
        }]

def log_event(username: str, event: str, desc: str = "") -> None:
    append_audit_log(username, event, desc)

# -----------------------------------
# Tamper-evident chained ledger
# -----------------------------------
def _tail_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 8192))
            for line in reversed(f.read().decode("utf-8", "ignore").splitlines()):
                if line.strip():
                    return json.loads(line)
    except Exception:
        return None
    return None

try:
    # Prefer the packaged machine fingerprint helper
    from security.machine_fp import get_machine_fingerprint  
except Exception:
    # Fallback: return a placeholder when the helper is unavailable
    def get_machine_fingerprint() -> str: 
        return "unknown"

def _hmac_key_from_salt(vault_salt: bytes) -> bytes:
    """Derive an HMAC key from the provided vault salt.

    The previous implementation used a global `AUDIT_KEY_LABEL` constant.  The
    name has been changed to `AUDIT_HMAC_CONTEXT` to make it clear that this
    value is a context string and not a secret.  The function now derives the
    key using HMAC with the vault salt and this context.  If you need
    stronger key separation, consider passing an explicit info/context
    parameter instead of relying on a module constant.
    """
    return hmac.new(vault_salt, AUDIT_HMAC_CONTEXT, hashlib.sha256).digest()

def write_audit(event: str, username: str, vault_salt: bytes,
                anchor_store_cb: Callable[[str], None] | None):
    """Append JSONL line: {ts,event,user,machine,prev,head,mac}"""
    prev = _tail_json(audit_file(username)) or _tail_json(audit_mirror_file(username)) or {}
    prev_head = prev.get("head", "")

    rec = {
        "ts": int(time.time()),
        "event": event,
        "user": username,
        "machine": get_machine_fingerprint(),
        "prev": prev_head,
    }
    head_bytes = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode("utf-8")
    head = hashlib.sha256(head_bytes).hexdigest()

    key = _hmac_key_from_salt(vault_salt)
    mac = hmac.new(key, (head + prev_head).encode("utf-8"), hashlib.sha256).hexdigest()

    rec.update({"head": head, "mac": mac})
    line = json.dumps(rec, separators=(",", ":")) + "\n"

    for target in (audit_file(username), audit_mirror_file(username)):
        try:
            tmp = target.with_suffix(target.suffix + ".tmp")
            with open(tmp, "a", encoding="utf-8") as f:
                f.write(line)
            os.replace(tmp, target)
            _chmod_600(target)
        except Exception:
            try:
                with open(target, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                pass

    if anchor_store_cb:
        try: anchor_store_cb(head)
        except Exception: pass

def verify_audit(vault_salt: bytes, expected_anchor: str, username: str) -> bool:
    """Return True if the current audit chain matches expected_anchor."""
    last = _tail_json(audit_file(username)) or _tail_json(audit_mirror_file(username))
    if not last:
        return expected_anchor == ""
    head, prev, mac = last.get("head", ""), last.get("prev", ""), last.get("mac", "")
    key = _hmac_key_from_salt(vault_salt)
    good = hmac.new(key, (head + prev).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, good) and (expected_anchor in ("", head) or head == expected_anchor)

# -----------------------------------
# Combined convenience
# -----------------------------------
def log_event_encrypted(username: str, label: str, value: str = "",
                        *, extra=None, anchor_store_cb=None):
    """Write encrypted event + optional ledger anchor."""
    try:
        desc = label + (f": {value}" if value else "")
        if extra:
            try: desc += " | extra=" + json.dumps(extra, separators=(",", ":"), sort_keys=True)
            except Exception: pass
        append_audit_log(username, label, desc)
    except Exception:
        pass
    if anchor_store_cb:
        try: anchor_store_cb(label)
        except Exception: pass

# -----------------------------------
# Health / lockout
# -----------------------------------
def audit_health(username: str) -> tuple[bool, str]:
    p, m = audit_file(username), audit_mirror_file(username)
    if not p.exists():
        return False, _tr("Primary audit missing.")
    try: _ = read_audit_log(username)
    except Exception as e:
        return False, _tr("Decrypt failed") + f": {e}"
    return True, _tr("OK") if m.exists() else _tr("Mirror missing (non-blocking).")

def _last_success(events):
    latest = None
    for e in events:
        try:
            if e.get("event") in ("login_attempt", "2FA") and "success" in e.get("description","").lower():
                t = dt.datetime.fromisoformat(e["timestamp"])
                if not latest or t > latest: latest = t
        except Exception: pass
    return latest

def _fails_after(events, since, window_mins):
    now = dt.datetime.now()
    fails = []
    for e in events:
        try:
            if e.get("event") in ("login_attempt","2FA") and "fail" in e.get("description","").lower():
                t = dt.datetime.fromisoformat(e["timestamp"])
                if since and t <= since: continue
                if now - t <= timedelta(minutes=window_mins): fails.append(t)
        except Exception: pass
    return fails

def is_locked_out(username: str, threshold: int,
                  window_mins: int = 10, cooldown_mins: int = 5) -> tuple[bool,int,int]:
    """Return (locked, attempts_left, mins_left)."""
    threshold = int(threshold or 0)
    events = read_audit_log(username)
    last_ok = _last_success(events)
    fails = _fails_after(events, last_ok, window_mins)
    flag = user_lock_flag_path(username, ensure_dir=True)
    now = dt.datetime.now()

    if len(fails) >= threshold > 0:
        last_fail = max(fails)
        if now - last_fail < timedelta(minutes=cooldown_mins):
            if not flag.exists():
                append_audit_log(username, _tr("lockout"), _tr("Too many failed attempts."))
                flag.touch(); _chmod_600(flag)
            mins_left = max(0, cooldown_mins - int((now - last_fail).total_seconds()//60))
            return True, 0, mins_left
        if flag.exists():
            try: flag.unlink()
            except Exception: pass
        return False, threshold - len(fails), 0

    if flag.exists():
        try: flag.unlink()
        except Exception: pass
    return False, threshold - len(fails), 0

def clear_lockout(username: str) -> None:
    p = user_lock_flag_path(username)
    try:
        if p.exists(): p.unlink()
    except Exception: pass

def record_login_success(username: str) -> None:
    try: append_audit_log(username, _tr("login_attempt"), _tr("success"))
    except Exception: pass
    clear_lockout(username)
