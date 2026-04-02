"""
    Centralised salt loading + one-time migration into the identity-store *public header*.

    Why:
    - Current layout can split salt (Roaming) and vault (Local), which is easy to break
      across portable/installed/dev profiles.
    - Salt is NOT secret, so it is safe to store in the identity header (which is already plaintext).
    - With STRICT native mode, we want a single reliable source of truth for the salt.

    Design:
    - Read-only phase (login pre-check): read header if present, else read legacy .slt.
    - Post-login (after password validated): if header missing, write salt into header,
      create a backup of the legacy file, then (optionally) delete it.

NOTE: this module intentionally does NOT do any Python crypto fallback.

must check or replace, forgot passord salt regen, creacte account, 
"""


from __future__ import annotations

import base64
import os
import time
import logging
from pathlib import Path

log = logging.getLogger("keyquorum")

EXPECTED_SALT_LEN = 16  # keep aligned with DLL expectations


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _legacy_salt_path(username: str) -> Path:
    from app.paths import salt_file
    return Path(salt_file(username, ensure_parent=False))


def _header_get_salt(username: str) -> bytes | None:
    """Return salt from identity public header if present."""
    try:
        from auth.identity_store import get_public_header
        hdr = get_public_header(username) or {}
        meta = hdr.get("meta") or {}
        b64 = (meta.get("master_salt_b64") or "").strip()
        if not b64:
            return None
        salt = _b64d(b64)
        return salt
    except Exception:
        return None


def _header_set_salt(username: str, salt: bytes) -> None:
    """Write salt into identity public header (best-effort)."""
    from auth.identity_store import get_public_header, _write_public_header  # intentional internal use
    hdr = get_public_header(username) or {}
    meta = hdr.setdefault("meta", {})
    meta["master_salt_b64"] = _b64e(salt)
    meta["master_salt_len"] = int(len(salt))
    meta["master_salt_v"] = 1
    _write_public_header(username, hdr)




def write_master_salt_to_identity(username: str, salt: bytes) -> None:
    """Public helper: ensure master salt is stored in the identity header.

    Use this during account creation so new accounts are 'native' from day 0.
    Salt is not secret; storing it in the identity *public header* improves reliability
    across installed/portable profiles.
    """
    if not salt or len(salt) != EXPECTED_SALT_LEN:
        raise ValueError(f"invalid salt length: {0 if not salt else len(salt)}")
    _header_set_salt(username, salt)
def read_master_salt_readonly(username: str) -> bytes:
    """Read master salt without writing anything (safe for read_only_paths).

    Order:
    1) identity public header
    2) legacy .slt
    """
    salt = _header_get_salt(username)
    if salt:
        if len(salt) != EXPECTED_SALT_LEN:
            raise ValueError(f"Invalid master salt length in identity header: {len(salt)} (expected {EXPECTED_SALT_LEN})")
        return salt

    sp = _legacy_salt_path(username)
    if not sp.exists():
        raise FileNotFoundError(f"Master salt not found (header missing and legacy missing): {sp}")
    salt = sp.read_bytes()
    if len(salt) != EXPECTED_SALT_LEN:
        raise ValueError(f"Invalid legacy salt length: {len(salt)} (expected {EXPECTED_SALT_LEN}) path={sp}")
    return salt


def maybe_migrate_master_salt_to_identity(parent_ui, username: str, salt: bytes, *, delete_legacy: bool = True) -> None:
    """After a successful login, ensure salt exists in identity header.

    - If header already has salt: do nothing.
    - If missing: write it, backup legacy .slt, then delete legacy .slt.

    This function is UI-safe:
    - It logs failures and does not raise unless something very unexpected happens.
    - It shows a one-time info popup when a migration occurs.
    """
    try:
        if not salt or len(salt) != EXPECTED_SALT_LEN:
            return

        already = _header_get_salt(username)
        if already:
            return

        # Write to header
        _header_set_salt(username, salt)
        log.info("[SALT] Migrated master salt into identity header for user=%s", username)

        # Backup (+ optional delete) legacy salt (only if it exists)
        sp = _legacy_salt_path(username)
        if sp.exists():
            ts = time.strftime("%Y%m%d_%H%M%S")
            bak = sp.with_suffix(sp.suffix + f".bak_{ts}")
            try:
                bak.write_bytes(sp.read_bytes())
                log.info("[SALT] Legacy salt backup created: %s", bak)
            except Exception as e:
                log.warning("[SALT] Could not create legacy salt backup (%s): %r", bak, e)

            if delete_legacy:
                try:
                    sp.unlink()
                    log.info("[SALT] Legacy salt deleted after migration: %s", sp)
                except Exception as e:
                    log.warning("[SALT] Could not delete legacy salt (%s): %r", sp, e)

        # Warn the user (best-effort)
        try:
            from qtpy.QtWidgets import QMessageBox
            QMessageBox.information(
                parent_ui,
                parent_ui.tr("Account update"),
                parent_ui.tr(
                    "We updated your account storage to improve reliability."
                    "Your master salt was migrated into your Identity Store header so unlock works consistently "
                    "across installed/portable profiles."
                    "A backup of the old salt file was created before cleanup (if it existed)."
                ),
            )
        except Exception:
            pass

    except Exception as e:
        log.debug("[SALT] migration skipped/failed for %s: %r", username, e)
        return