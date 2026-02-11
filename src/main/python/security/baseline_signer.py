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
Tamper-evident per-user baseline manifest with HMAC using the user's salt.
Public API expected by main.py and friends:
- write_baseline(username: str, salt: bytes, files: list[str|Path]) -> dict
- verify_baseline(username: str, salt: bytes, files: list[str|Path]) -> tuple[list[str], list[str], list[str], bool]
- peek_verify_baseline(username: str, salt: bytes, files: list[str|Path]) -> tuple[list[str], list[str], list[str], bool]
- write_audit_baseline(username: str, salt: bytes, files: list[str|Path]) -> dict
"""

import hashlib, hmac, json, os, time, logging
from pathlib import Path
from typing import Iterable, Tuple, Dict, Any

# --- log
log = logging.getLogger("keyquorum")
import app.kq_logging as kql

# --- helpers ---
# Single source of truth for where the baseline lives
from app.paths import baseline_file
from auth.login.login_handler import _load_vault_salt_for

from app.paths import security_prefs_file
# --- Pathsfrom app.paths ---
from app.paths import ( profile_pic,  
    vault_file, shared_key_file, catalog_file, salt_file, identities_file, breach_cache,
    catalog_seal_file, category_schema_file, trash_path, pw_cache_file, vault_wrapped_file,
    user_db_file,)
from security.secure_audit import log_event_encrypted
from auth.identity_store import verify_recovery_key


# Optional secure_audit hook
try:
    from security.secure_audit import write_audit
except Exception:  # fallback no-op
    def write_audit(event: str, username: str, vault_salt: bytes, anchor_store_cb):
        pass


# ------------------------------ Helpers --------------------------------------

HMAC_INFO = b"KQ_BASELINE_V1"

def _now_iso() -> str:
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    except Exception:
        return "1970-01-01T00:00:00Z"

def _as_path_list(files: Iterable[Any]) -> list[Path]:
    out: list[Path] = []
    for f in (files or []):
        try:
            p = Path(f)
            out.append(p)
        except Exception:
            # Guard against accidental ints/None etc.
            continue
    return out

def _norm_existing(files: Iterable[Any]) -> list[Path]:
    out: list[Path] = []
    for p in _as_path_list(files):
        try:
            rp = p if p.is_absolute() else p.resolve()
        except Exception:
            rp = p
        try:
            if rp.exists() and rp.is_file():
                out.append(rp)
        except Exception:
            continue
    return out

def _sha256_file(p: Path, buf: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(buf), b""):
            h.update(chunk)
    return h.hexdigest()

def _hmac(salt: bytes, data: bytes) -> str:
    return hmac.new(salt or b"\x00" * 16, data, hashlib.sha256).hexdigest()

def _manifest_path(username: str) -> Path:
    # ensure_parent=True so directory exists
    return Path(baseline_file(username, ensure_parent=True, name_only=False))

def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp, path)

def _build_payload(files: list[Path]) -> Dict[str, Any]:
    items: Dict[str, str] = {}
    for p in files:
        try:
            digest = _sha256_file(p)
            items[str(p)] = digest
            log.debug(f"[baseline] hashed {p} -> {digest[:12]}…")
        except Exception as e:
            log.warning(f"[baseline] failed to hash {p}: {e}")
            continue
    return {"files": items}

def _mac_for_payload(salt: bytes, payload: Dict[str, Any]) -> str:
    # Canonicalize JSON for MAC
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _hmac(salt, HMAC_INFO + blob)

def _load_manifest(username: str) -> Dict[str, Any] | None:
    path = _manifest_path(username)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "payload" in data and "mac" in data:
            return data
    except Exception as e:
        log.error(f"[baseline] read error: {e}")
    return None

# ------------------------------ Writers --------------------------------------

def write_baseline(username: str, salt: bytes, files: Iterable[Any]) -> Dict[str, Any]:
    """
    Create/overwrite the user's baseline manifest with HMAC.
    Returns the manifest dict written.
    """
    username = (username or "").strip()
    plist = _norm_existing(files)
    payload = {
        "version": 1,
        "created": _now_iso(),
        "payload": _build_payload(plist),
    }
    payload["mac"] = _mac_for_payload(salt or b"", payload["payload"])
    try:
        _atomic_write_text(_manifest_path(username), json.dumps(payload, indent=2, ensure_ascii=False))
    except Exception as e:
        log.error(f"[baseline] write failed for {username}: {e}")
    return payload

def write_audit_baseline(username: str, salt: bytes, files: Iterable[Any]) -> Dict[str, Any]:
    """
    Write baseline and also append an audit ledger entry (best effort).
    """
    manifest = write_baseline(username, salt, files)
    try:
        write_audit("baseline_update", username, salt, anchor_store_cb=None)
    except Exception:
        pass
    return manifest

def ensure_baseline(username: str, salt: bytes, files: Iterable[Any]) -> Dict[str, Any]:
    """
    Backwards-compatible wrapper used by main.py.

    For now this simply calls write_baseline() and overwrites the manifest
    for the given user + file set. This is exactly what we want when the user
    clicks 'Update Baseline' in the integrity warning.
    """
    return write_baseline(username, salt, files)

# ------------------------------ Verifier --------------------------------------

def verify_baseline(username: str, salt: bytes, files: Iterable[Any]) -> Tuple[list[str], list[str], list[str], bool]:
    """
    Compare current file set against stored baseline.

    Returns (changed, missing, new, mac_ok):
      - changed: files present in both sets but whose digest changed
      - missing: files present in baseline but missing now
      - new:     files present now but absent in baseline
      - mac_ok:  True if stored baseline MAC verifies with provided salt
    """
    username = (username or "").strip()
    want = _as_path_list(files)              # Accept anything, even non-existent → used for 'new'
    have = _norm_existing(files)             # Subset that exists → used for hashing

    manifest = _load_manifest(username)
    if not manifest:
        # No baseline: everything is "new", MAC cannot be checked
        return ([str(p) for p in have], [], [str(p) for p in want], False)

    payload = manifest.get("payload") or {}
    stored_mac = str(manifest.get("mac") or "")
    calc_mac = _mac_for_payload(salt or b"", payload)

    mac_ok = hmac.compare_digest(stored_mac, calc_mac)

    # Baseline map
    base_map: Dict[str, str] = {}
    files_section = payload.get("files") or {}
    if isinstance(files_section, dict):
        for k, v in files_section.items():
            base_map[str(k)] = str(v)

    # Current map (for existing files)
    now_map: Dict[str, str] = {}
    for p in have:
        try:
            now_map[str(p)] = _sha256_file(p)
        except Exception:
            # unreadable now → treat as "changed"
            now_map[str(p)] = "__UNREADABLE__"

    base_set = set(base_map.keys())
    want_set = set(str(p) for p in want)     # what caller cares about now (even if missing)
    now_set  = set(now_map.keys())           # existing & hashed

    missing = sorted(list(base_set - now_set))
    # changed = in both maps but digests differ
    changed = sorted([k for k in (base_set & now_set) if base_map.get(k) != now_map.get(k)])
    # new = in desired set but not in baseline
    new = sorted(list(want_set - base_set))

    return (changed, missing, new, mac_ok)

def peek_verify_baseline(username: str, salt: bytes, files: Iterable[Any]) -> Tuple[list[str], list[str], list[str], bool]:
    """
    Non-mutating verifier. Alias to verify_baseline; kept for clarity with pre-login 'peek'.
    """
    return verify_baseline(username, salt, files)

def default_user_file_set(username: str) -> list[Path]:
    """
    Standard per-user files for baseline checking.

    This helper defines the **mandatory** set of files that uniquely
    identify a user's vault and login state. These files are required
    for both pre‑login baseline peeks and post‑login integrity checks.

    We track at minimum:

      • the encrypted vault file
      • the per‑user salt file
      • the per‑user user_db.kq file (modern per‑user database)
      • the per‑user identity file (.kq_id)

    Additional optional files (settings, category schema, etc.) are
    appended by callers who need a more comprehensive integrity check.

    Returns a list of ``Path`` objects; any missing files are omitted.
    """
    username = (username or "").strip()
    if not username:
        return []

    try:
        from app.paths import vault_file, salt_file, user_db_file, identities_file
    except Exception:
        # If paths can't be imported here, just return empty so callers
        # will treat baseline as 'not available'.
        return []

    out: list[Path] = []

    # Vault file
    try:
        p = Path(vault_file(username))
        out.append(p)
    except Exception:
        pass

    # Salt file
    try:
        p = Path(salt_file(username))
        out.append(p)
    except Exception:
        pass

    # Per-user user_db file
    try:
        p = Path(user_db_file(username))
        out.append(p)
    except Exception:
        pass

    # Identity file (.kq_id)
    try:
        p = Path(identities_file(username))
        out.append(p)
    except Exception:
        pass

    return out

# =============================================================================
# --- ui usage call Split Main
# =============================================================================

def update_baseline(
    username: str,
    *,
    verify_after: bool = True,
    who: str = "Unknown",
    show_message: bool = False,
    parent=None
) -> bool:
    username = (username or "").strip()
    if not username:
        log.error("[baseline] (In Settings) update_baseline called with empty username")
        return False

    try:
        # 1) Load salt
        try:
            salt = _load_vault_salt_for(username)
        except Exception as e:
            log.error(f"{kql.i('err')} [baseline] (In Settings) failed to load salt for {username}: {e}")
            salt = b""

        # 2) Build tracked files
        files = _baseline_tracked_files(username)
        log.info(f"[baseline] files to update: {files}")
        log.info(f"{kql.i('info')} [baseline] (In Settings) updating for user={username}")

        # 3) Write baseline
        ensure_baseline(username, salt, files)
        log.info(f"{kql.i('ok')} [baseline] (In Settings) wrote baseline (files={len(files)})")

        # 4) Audit log
        audit_msg = f"Who: {who}"
        log_event_encrypted(username, "📜 [Baseline Update]", audit_msg)
        log.info(f"📜 [Baseline Update] {audit_msg} -> verify_after={verify_after}")

        # 5) Optional post-verify
        if verify_after:
            changed, missing, new, mac_ok = verify_baseline(username, salt, files)
            log.info(
                f"{kql.i('check')} [baseline] (In Settings) post-verify: mac_ok={mac_ok} "
                f"changed={len(changed)} missing={len(missing)} new={len(new)}"
            )
            if changed:
                log.debug(f"{kql.i('warn')} [baseline] (In Settings) changed: {changed}")
            if missing:
                log.debug(f"{kql.i('warn')} [baseline] (In Settings) missing: {missing}")
            if new:
                log.debug(f"{kql.i('ok')} [baseline] (In Settings) new: {new}")

        if show_message:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.information(parent, "Baseline updated", "Baseline updated OK")

        return True

    except Exception as e:
        log.error(f"{kql.i('err')} [baseline] (In Settings) update failed for {username}: {e}")
        if show_message:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.critical(parent, "Baseline update failed", f"Baseline did NOT update:\n\n{e}")
        return False

def _baseline_tracked_files(username: str) -> list[str]:

    """
    Build the list of files used for per-user integrity checks.

    For now we deliberately *exclude* the per-user catalog/user_db file
    (KQ_Dev_KQ.kq), because it is touched frequently by the category editor
    and causes constant 'CHANGED' noise. We still protect the critical
    crypto state: vault, salt, identity, and prefs.
    """
    username = (username or "").strip()
    files: list[str] = []

    # --- MANDATORY FILES (crypto-critical) ---
    mandatory_paths: list[Path] = [
        vault_file(username, ensure_parent=False),
        salt_file(username, ensure_parent=False),
        identities_file(username, ensure_parent=False),
        user_db_file(username, ensure_parent=False),
    ]

    for p in mandatory_paths:
        log.debug(f"🧭 [baseline tracked files]: vault file:{str(p)}")
        files.append(str(p))   # always tracked, even if currently missing

    # --- OPTIONAL FILES (only if present) ---
    optional_paths: list[Path] = [
        security_prefs_file(username, ensure_parent=False, name_only=False),
        category_schema_file(username, ensure_parent=False),  # can add later if stable
        catalog_file(username, ensure_parent=False),          # KQ_Dev_KQ.kq; excluded for now
        catalog_seal_file(username, ensure_parent=False),
        shared_key_file(username, ensure_parent=False),
        breach_cache(username, ensure_parent=False),
        profile_pic(username),
        trash_path(username, ensure_parent=False),
        pw_cache_file(username, ensure_parent=False),
        vault_wrapped_file(username, ensure_parent=False),
    ]

    for p in optional_paths:
        if p and isinstance(p, Path) and p.exists():
            log.debug(f"🧭 [baseline tracked files]: vault file:{str(p)}")
            files.append(str(p))
    return files

def checkbasline(username: str) -> None:
    username = (username or "").strip()
    if not username:
        return None

    try:
        salt_for_baseline = _load_vault_salt_for(username)
        files = [str(p) for p in _baseline_tracked_files(username)]
    except Exception as e:
        log.warning("[baseline] prelogin peek: could not build file list user=%s: %s", username, e)
        return None

    try:
        changed, missing, new_, mac_ok = verify_baseline(username, salt_for_baseline, files)
    except Exception as e:
        log.error(f"[ERROR] Basline check error {e}")
        return None

    return changed, missing, new_, mac_ok 
