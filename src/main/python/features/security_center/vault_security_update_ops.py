"""Vault Security Update (KDF upgrade)

This module powers the **vault_security_update** button in Security Center.

Goal (long-term stable design):
  - Keep legacy KDF (v1) working forever.
  - Allow upgrading a specific vault/user to a stronger KDF profile (v2)
    without breaking backwards compatibility.

Strict DLL-only:
  - Requires native core exports kq_session_open_ex / derive_vault_key_ex.
  - Vault re-encryption is done using native session handles only.
"""

from __future__ import annotations

from doctest import Example
import logging
from pathlib import Path
from tkinter import E

from qtpy.QtWidgets import QMessageBox, QInputDialog, QLineEdit

log = logging.getLogger("keyquorum")

def migrate_post_rekey_side_stores(*, w, username: str, old_session_handle=None, new_session_handle=None, refresh_device_unlock: bool = True):
    """Shared post-rekey migration helper.

    Important for this codebase:
    - authenticator migration is KEY-based in features/auth_store/authenticator_store.py
    - pw history / trash / catalog overlay are SESSION-based in the current DLL-only path
    - remember-device refresh is SESSION-based
    """
    warnings = []
    ok = True
    log.info("in Migrate_post_rekey_side_stores")

    try:
        def _warn(msg: str):
            nonlocal ok
            ok = False
            warnings.append(msg)
            try:
                log.warning("[REKEY-MIGRATE] %s", msg)
            except Exception:
                pass

        old_session = int(old_session_handle) if isinstance(old_session_handle, int) and old_session_handle > 0 else None
        new_session = int(new_session_handle) if isinstance(new_session_handle, int) and new_session_handle > 0 else None

        if old_session is not None and new_session is not None and old_session != new_session:
            # 1) Authenticator store is SESSION-BASED in strict DLL-only mode.
            try:
                log.info("Step 1 - 5 Authenticator")
                from features.auth_store.authenticator_store import migrate_authenticator_store_with_sessions
                res = migrate_authenticator_store_with_sessions(username, old_session, new_session)

                if isinstance(res, tuple):
                    mig_ok = bool(res[0])
                    mig_msg = str(res[1]) if len(res) > 1 else ""
                else:
                    mig_ok = bool(res)
                    mig_msg = ""
                if not mig_ok:
                    _warn(f"Authenticator store migration failed: {mig_msg or 'unknown error'}")
                log.info(f"Authenticator Done {res}")
            except Exception as e:
                _warn(f"Authenticator store migration failed: {e}")

            # 2) Attempt Password history cache (SESSION-based).
            try:
                log.info("Step 2 - 5 Password history cache")
                from vault_store.soft_delete_ops import _pwlast_load, _pwlast_save
                d = _pwlast_load(username, old_session) or {}
                log.info(f"[REKEY-MIGRATE][PASSWORD] Password history cache")
                if d:
                    _pwlast_save(username, new_session, d)
                    verify = _pwlast_load(username, new_session) or {}
            except Exception as e:
                _warn(f"Password history migration failed: {e}")

            # 3) Attempt Trash / soft delete is SESSION-based.
            try:
                log.info("Step 3 - 5 Trash / soft delete")
                from vault_store.soft_delete_ops import _trash_load, _trash_save
                rows = _trash_load(username, old_session) or []
                if isinstance(rows, list) and rows:
                    _trash_save(username, new_session, rows)
                    verify = _trash_load(username, new_session) or []
                    log.info(
                        f"[REKEY-MIGRATE][TRASH] verify "
                        f"type={type(verify).__name__} "
                        f"len={len(verify) if hasattr(verify, '__len__') else 'n/a'}"
                    )
                else:
                    log.info("[REKEY-MIGRATE][TRASH] nothing to migrate")

            except Exception as e:
                _warn(f"Trash migration failed: {e}")

            # 4) Attempt Encrypted user catalog overlay is SESSION-based.
            try:
                log.info("Step 4 - 5 user catalog")
                from catalog_category.catalog_user import migrate_user_catalog_overlay
                res = migrate_user_catalog_overlay(username, old_session, new_session)
                log.info(f"[REKEY-MIGRATE][CATALOG] result={res}")

                if isinstance(res, tuple):
                    cok = bool(res[0])
                    cmsg = str(res[1]) if len(res) > 1 else ""
                    if not cok:
                        _warn(f"User catalog overlay migration failed: {cmsg or 'unknown error'}")
                elif res is False:
                    _warn("User catalog overlay migration failed")

            except Exception as e:
                _warn(f"User catalog overlay migration failed: {e}")


            # 5) Refresh Remember Device token against the new live session.
            try:
                log.info("Step 5 - 5 Clear Remember Device token")
                if refresh_device_unlock and w is not None:
                    from auth.login.auth_flow_ops import clear_passwordless_unlock_on_this_device
                    clear_passwordless_unlock_on_this_device(w, False)   # clear passwordless
                else:
                    log.info("[REKEY-MIGRATE] skipping Remember Device refresh (no UI context)")
            except Exception as e:
                _warn(f"Remember Device refresh failed: {e}")

            return ok, warnings
    except Exception as e:
        log.error(f"migrate post rekey side stores error: {e}")

def run_vault_security_update(w) -> None:
    """Upgrade the active user's vault KDF profile to v2 (stronger Argon2id).
    Flow:
      1) Require unlocked vault (we need the current session to decrypt).
      2) Ask the user to confirm their password (needed to open the new session).
      3) Decrypt vault with current session handle.
      4) Open a new native session using kq_session_open_ex + recommended params.
      5) Re-encrypt vault using the new session.
      6) Swap session handles and persist params to user_db.json.
    """
    from ui.message_ops import (show_message_user_login, message_already_updated,
                                show_message_vault_change, message_backup_error,
                                message_update_vault_ask_pw, message_salt_error,
                                message_read_decrypt_vault, message_vault_missing,
                                message_update_vault)

    try:
        if hasattr(w, "_require_unlocked") and callable(getattr(w, "_require_unlocked")):
            if not w._require_unlocked():
                return
    except Exception:
        # fall back to minimal checks
        if not getattr(w, "core_session_handle", None) or not getattr(w, "current_username", None):
            show_message_user_login(w, "Vault Security Update")
            return

    username = (getattr(w, "current_username", "") or "").strip()
    if not username:
        try:
            username = (w.currentUsername.text() or "").strip()
        except Exception:
            username = ""
    if not username:
        show_message_user_login(w, "Vault Security Update")
        return

    from auth.login.login_handler import get_user_record, set_user_record
    from auth.salt_file import read_master_salt_readonly
    from vault_store.kdf_utils import recommended_argon2_params, normalize_kdf_params
    from app.paths import vault_file
    from vault_store.vault_store import load_encrypted, save_encrypted
    from native.native_core import get_core

    rec = get_user_record(username) or {}
    kdf = normalize_kdf_params(rec.get("kdf"))
    if int(kdf.get("kdf_v", 1)) >= 2:
        message_already_updated(w)
        return

    # Make Full Backup Before Continuing
    try:
        if show_message_vault_change(w):
            try:
                w.export_vault()
            except Exception as e:
                message_backup_error(w, e)
    except Exception as e:
        log.error(f"[UPDATE VAULT] Change password  error {e}")


    # Ask for password confirmation (must open a new session for the upgraded KDF)
    msg = "To upgrade your vault security"
    who = "Vault Security Update"
    pw, ok = message_update_vault_ask_pw(w, who=who, msg=msg)
    if not ok:
        return

    # Load vault salt + path
    salt = read_master_salt_readonly(username)
    if not salt or len(salt) < 8:
        message_salt_error(w, who=who)
        return

    vpath = Path(vault_file(username, ensure_parent=False))
    if not vpath.exists():
        message_vault_missing(w, who, vpath)
        return

    # Decrypt current vault using the current native session
    try:
        plaintext_obj = load_encrypted(str(vpath), int(getattr(w, "core_session_handle")))
    except Exception as e:
        log.exception("[SecurityUpdate] decrypt failed: %s", e)
        message_read_decrypt_vault(w, who, e)
        return

    # Open upgraded session + re-encrypt
    core = get_core()
    new_params = recommended_argon2_params()
    pw_buf = bytearray(pw.encode("utf-8"))
    new_session = None
    try:
        if not hasattr(core, "open_session_ex"):
            raise RuntimeError("Native DLL does not support kq_session_open_ex. Please upgrade the DLL.")

        new_session = int(core.open_session_ex(
            pw_buf,
            salt,
            time_cost=int(new_params.get("time_cost")),
            memory_kib=int(new_params.get("memory_kib")),
            parallelism=int(new_params.get("parallelism")),
        ))
    except Exception as e:
        log.exception("[SecurityUpdate] open_session_ex failed: %s", e)
        QMessageBox.warning(w, who, f"Could not open upgraded session:\n{e}")
        return
    finally:
        try:
            core.secure_wipe(pw_buf)
        except Exception:
            for i in range(len(pw_buf)):
                pw_buf[i] = 0

    try:
        save_encrypted(plaintext_obj, str(vpath), int(new_session))
    except Exception as e:
        log.exception("[SecurityUpdate] re-encrypt failed: %s", e)
        # Close new session (best effort)
        try:
            core.close_session(int(new_session))
        except Exception:
            pass
        QMessageBox.warning(w, who, f"Could not write upgraded vault:\n{e}")
        return


    old_session = 0
    try:
        old_session = int(getattr(w, "core_session_handle", 0) or 0)
        if w is not None:
            w._prev_core_session_handle = old_session
    except Exception as e:
        log.error("[SecurityUpdate] failed to capture old session: %s", e)
        old_session = 0

    # Migrate side stores against the new live session before any session swap.
    mig_ok, mig_warnings = migrate_post_rekey_side_stores(
        w=w,
        username=username,
        old_session_handle=(old_session if old_session > 0 else None),
        new_session_handle=int(new_session),
        refresh_device_unlock=True,
    )
    try:
        log.info("[SecurityUpdate] side-store migration ok=%s warnings=%s", mig_ok, mig_warnings)
    except Exception:
        pass

    # Swap session handles: close old, keep new
    try:
        try:
            core.close_session(old_session)
        except Exception:
            pass
        w.core_session_handle = int(new_session)
        w.vault_unlocked = True
    except Exception:
        pass

    # Persist params into user_db.json
    rec["kdf"] = {
        "algo": "argon2id",
        "kdf_v": int(new_params.get("kdf_v", 2)),
        "time_cost": int(new_params.get("time_cost")),
        "memory_kib": int(new_params.get("memory_kib")),
        "parallelism": int(new_params.get("parallelism")),
        "hash_len": int(new_params.get("hash_len", 32)),
    }
    try:
        set_user_record(username, rec)
    except Exception:
        pass

    # Refresh Security Center vault section if available
    try:
        if hasattr(w, "_update_security_vault_section"):
            w._update_security_vault_section(username)
    except Exception:
        pass

    message_update_vault(w)

    # Force logout (parent will return to login screen)
    try:
        if w is not None and hasattr(w, "logout_user"):
            w.logout_user()
    except Exception as e:
        log.error("Logout error after password change: %s", e)

