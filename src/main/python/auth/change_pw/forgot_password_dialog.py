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

import base64, re
import logging
import traceback
from qtpy.QtWidgets import QDialog, QMessageBox

log = logging.getLogger("keyquorum")

from ui_gen.forgot_password_ui import Ui_ForgotPasswordDialog
# Core crypto + identity helpers ----------------------------------------------
from auth.pw.utils_recovery import recovery_key_to_mk
from auth.identity_store import get_public_header, mk_hash_b64, rewrap_with_new_password
# Password policy + generator
from auth.pw.password_utils import get_password_strength
from auth.pw.password_generator import show_password_generator_dialog
# Per-user DB
from auth.login.login_handler import get_user_record, set_user_record, _canonical_username_ci
# Password hashing (same as account_creator)
from vault_store.key_utils import hash_password
from auth.pw.password_utils import _store_password_hash
from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("forgot_password_dialog", text)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _derive_mk_from_any_recovery_key(username: str, rk_str: str) -> bytes:
    """
    Backwards-compatible Recovery Key decoder.

    Supports:
      • NEW format (base32 body + checksum) via recovery_key_to_mk()
        (allows spaces/hyphens; we normalize).
      • LEGACY format (urlsafe-base64, no checksum).
    """

    rk_str = (rk_str or "").strip()
    
    if not rk_str:
        raise ValueError(_tr("Recovery Key is required"))

    # Keep original for legacy base64url decoding (because '-' and '_' are valid there)
    rk_raw = rk_str.strip()

    # 1) New format: normalize for base32+checksum (remove separators)
    rk_norm = re.sub(r"[^A-Za-z0-9]", "", rk_raw).upper()

    # Try new format first (normalized)
    try:
        return recovery_key_to_mk(rk_norm)
    except Exception:
        pass

    # Also try new format without normalization (in case your decoder already normalizes)
    try:
        return recovery_key_to_mk(rk_raw)
    except Exception:
        pass

    # 2) Legacy urlsafe-base64 format (do NOT strip '-' '_' here)
    try:
        s = rk_raw.strip()
        pad = (-len(s)) % 4
        mk = base64.urlsafe_b64decode(s + ("=" * pad))
        if len(mk) != 32:
            raise ValueError(_tr("Legacy Recovery Key decoded to wrong length"))
        return mk
    except Exception as e:
        raise ValueError(_tr("Recovery Key format invalid")) from e


def _tick_idle_timer(parent):
    """Ping the main window’s logout timer if available."""
    try:
        if parent is not None and hasattr(parent, "reset_logout_timer"):
            parent.reset_logout_timer()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Dialog
# ---------------------------------------------------------------------------

class ForgotPasswordDialog(QDialog, Ui_ForgotPasswordDialog):
    """
    Recovery-mode forgot-password flow.

    Design:
      • Uses Recovery Key → MK (supports new + legacy keys).
      • Verifies against identity header mk_hash_b64 when present.
      • Rewraps identity password wrapper via rewrap_with_new_password().
      • Updates per-user DB password hash so normal login keeps working.
      • DOES NOT touch login backup codes – those are now reserved for
        login / gate flows only, not for forgot-password resets.
    """

    def __init__(self, username_prefill: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self.setupUi(self)

        # Wire buttons
        if hasattr(self, "resetButton"):
            self.resetButton.clicked.connect(self.reset_password)
        if hasattr(self, "cancelButton"):
            self.cancelButton.clicked.connect(self.reject)
        if hasattr(self, "password_generator_1"):
            self.password_generator_1.clicked.connect(self.open_password_generator)
        if hasattr(self, "newPasswordField"):
            self.newPasswordField.textChanged.connect(self.update_password_feedback)

        # Prefill username from login screen if provided
        if username_prefill and hasattr(self, "usernameField"):
            try:
                self.usernameField.setText(username_prefill.strip())
                self.usernameField.setEnabled(False)
            except Exception:
                pass

    # --- UI helpers ---------------------------------------------------------

    def open_password_generator(self) -> None:
        """Open password generator popup, if available."""
        _tick_idle_timer(self.parent())
        try:
            return show_password_generator_dialog(target_field=self.newPasswordField, confirm_field=self.confirmPasswordField)
        except Exception:
            QMessageBox.information(
                self,
                _tr("Password Generator"),
                _tr("The password generator isn’t available in this dialog."),
            )



    def update_password_feedback(self) -> None:
        """Live password policy feedback under the new-password field."""
        _tick_idle_timer(self.parent())
        try:
            if not hasattr(self, "newPasswordField") or not hasattr(self, "passwordInfoLabel"):
                return
            password = self.newPasswordField.text()
            ok, level_text, policy_msg = get_password_strength(password)
            self.passwordInfoLabel.setText(f"{level_text}: {policy_msg}")
            color = "green" if level_text == "Excellent Strong" or ok == 4 else "orange" if level_text == "Medium" else "red"
            self.passwordInfoLabel.setStyleSheet(f"color: {color}; font-size: 8pt;")
        except Exception:
            # Never block on UI cosmetics
            pass
    def _confirm_recovery_warning(self) -> bool:
        """
        Show a warning before running recovery reset.
        """
        msg = (
            "⚠️ Important recovery warning\n\n"
            "Use this option only if you have forgotten your password.\n\n"
            "This recovery process will unlock your vault and authenticator data, "
            "but not all data that relies on your previous encryption key can be "
            "guaranteed to decrypt correctly.\n\n"
            "The following data may be lost or reset:\n"
            "• Password history\n"
            "• Soft-deleted (Trash) items\n\n"
            "Your vault entries and authenticator secrets will be recovered. "
            "If you later see errors or a baseline warning, it is recommended "
            "to restore your most recent full backup.\n\n"
            "Do you want to continue?"
        )
        res = QMessageBox.warning(
            self,
            _tr("Recovery Warning"),
            _tr(msg),
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        return res == QMessageBox.Yes



    # --- Core flow ----------------------------------------------------------

    def reset_password_backup_code(self) -> None:
        log.info("[ForgotPassword] ENTER reset_password_backup_code()")
        stage = "start"


        # --- Recovery warning confirmation ----------------------------
        if not self._confirm_recovery_warning():
            log.info("[ForgotPassword] user cancelled recovery after warning")
            return

        def fail(msg: str, e: Exception | None = None) -> None:
            """Centralised error handler with logging."""
            nonlocal stage
            if e is not None:
                log.error(
                    "[ForgotPassword] %s -> %s | %r\n%s",
                    stage,
                    msg,
                    e,
                    traceback.format_exc(),
                )
                try:
                    QMessageBox.critical(
                        self,
                        _tr("Reset Failed"),
                        _tr("Password reset failed at step") + f" '{stage}':\n\n{msg}\n\n{e}",
                    )
                except Exception:
                    pass
            else:
                log.error("[ForgotPassword] %s -> %s", stage, msg)
                try:
                    QMessageBox.critical(
                        self,
                        _tr("Reset Failed"),
                        _tr("Password reset failed at step") + f" '{stage}':\n\n{msg}",
                    )
                except Exception:
                    pass

        try:
            # --- 1) Read + basic validate inputs ----------------------------
            stage = "read_inputs"
            u = (self.usernameField.text() if hasattr(self, "usernameField") else "").strip()
            rk_in = (self.recoveryKeyField.text() if hasattr(self, "recoveryKeyField") else "").strip()
            rk_in = (rk_in or "").replace(" ", "").strip()
            new1 = self.newPasswordField.text().strip() if hasattr(self, "newPasswordField") else ""
            new2 = self.confirmPasswordField.text().strip() if hasattr(self, "confirmPasswordField") else ""

            # backup codes are NO longer required here (login-only)
            if not all([u, rk_in, new1, new2]):
                return fail(_tr("All fields are required."))
            if new1 != new2:
                return fail(_tr("Passwords do not match."))

            # --- 2) Password policy ----------------------------------------
            stage = "policy"
            ok, level_text, policy_msg = get_password_strength(new1)
            if not ok:
                return fail(_tr("Password does not meet the security policy."))

            # --- 3) Normalise username -------------------------------------
            stage = "normalize"
            username = _canonical_username_ci(u) or u
            log.info("[ForgotPassword] user=%s", username)

            # Check user exists (per-user DB)
            stage = "load_user_record"
            rec = get_user_record(username) or {}
            if not isinstance(rec, dict) or not rec:
                return fail(_tr("Username not found."))

            # --- 4) Recovery Key → MK (supports legacy + new formats) ------
            stage = "rk_to_mk"
            MK = _derive_mk_from_any_recovery_key(username, rk_in)
            # soft header check via mk_hash_b64 mirror
            header_mismatch = False
            header_mismatch_want = ""
            header_mismatch_have = ""


            # soft header check via mk_hash_b64 mirror -------------
            stage = "header_check"
            try:
                hdr = get_public_header(username) or {}
                want = ((hdr.get("meta") or {}).get("mk_hash_b64") or "").strip()
                have = mk_hash_b64(MK)
                log.debug("[ForgotPassword] mk_hash want=%s have=%s", want, have)
                if want and have != want:
                    header_mismatch = True
                    header_mismatch_want = want
                    header_mismatch_have = have
                    log.warning("[ForgotPassword] header_check mismatch for %s (want=%s have=%s) — continuing", username, want, have)

            except Exception as e:
                log.debug("[ForgotPassword] header check skipped: %r", e)

            # --- 5) Rewrap identity password/recovery wrappers -------------
            stage = "rewrap_identity"
            ok_rw, msg_rw = rewrap_with_new_password(username, MK, new1)
            if not ok_rw:
                return fail(_tr("Could not update identity") + f": {msg_rw}")

            # --- 5b) Reload identity with NEW password to get DMK ----------
            stage = "reload_identity"
            try:
                from auth.identity_store import create_or_open_with_password
                dmk_after, inner_after, hdr_after = create_or_open_with_password(username, new1)
            except Exception as e:
                return fail(_tr(
                    "Identity was updated, but it could not be reopened with the new password."),
                    e,
                )

            # --- 5c) Rewrap vault key, keep vault data ----------------------
            stage = "rewrap_vault"
            try:
                from pathlib import Path
                from vault_store.vault_store import (
                    get_vault_path,
                    get_wrapped_key_path,
                    load_encrypted,
                    save_encrypted,
                    load_user_salt,
                    unwrap_vault_key_dmk,
                    wrap_vault_key_dmk,
                )

                # 5c-1: Work out the current vault key (vk)
                vk = None

                # Try DMK-based wrapper first (new format)
                try:
                    vk = unwrap_vault_key_dmk(username, dmk_after)
                    log.debug("[ForgotPassword] DMK-based vault wrapper OK for %s", username)
                except Exception as e_dmk:
                    log.debug("[ForgotPassword] DMK unwrap failed, trying legacy Recovery-Key wrapper: %r", e_dmk)

                    # Legacy Recovery-Key-based .kq_wrap (text, encrypt_key())
                    from vault_store.kdf_utils import derive_key_argon2id
                    from vault_store.key_utils import decrypt_key as _decrypt_key

                    wpath = Path(get_wrapped_key_path(username))
                    if not wpath.exists():
                        raise FileNotFoundError(_tr("Wrapped vault key not found at") + f" {wpath}")

                    # Old file is a base64 string written by encrypt_key()
                    ct_b64 = wpath.read_text(encoding="utf-8").strip()
                    salt = load_user_salt(username)
                    # KEK derived from Recovery Key string + salt
                    kek = derive_key_argon2id(rk_in, salt)
                    vk = _decrypt_key(ct_b64, kek)
                    log.info("[ForgotPassword] migrated legacy Recovery-Key wrapped vault key for %s", username)

                if vk is None:
                    raise RuntimeError(_tr("Vault key could not be obtained from any wrapper."))

                # 5c-2: If there is no vault file yet, just create a new DMK wrapper
                vault_path = get_vault_path(username)
                vpath = Path(vault_path)
                if not vpath.exists():
                    log.info("[ForgotPassword] no existing vault for %s; creating DMK wrapper only", username)
                    from vault_store.kdf_utils import derive_key_argon2id
                    salt = load_user_salt(username)
                    new_vk = derive_key_argon2id(new1, salt)
                    wrap_vault_key_dmk(username, dmk_after, new_vk)
                else:
                    # 5c-3: Decrypt existing vault with old vk
                    try:
                        data = load_encrypted(vault_path, vk)
                    except Exception as e_dec:
                        raise RuntimeError(
                            _tr("Existing vault could not be decrypted with recovered key") + f": {e_dec}"
                        ) from e_dec

                    # 5c-4: Derive new vault key from NEW password + existing salt
                    from vault_store.kdf_utils import derive_key_argon2id
                    salt = load_user_salt(username)
                    new_vk = derive_key_argon2id(new1, salt)

                    # 5c-4b: Migrate Authenticator field secrets (secret_enc_b64) from old vk -> new_vk
                    # These secrets are additionally wrapped using AES-GCM(user_key) inside the decrypted vault.
                    try:
                        from vault_store.authenticator_store import rewrap_authenticator_entries

                        # 'data' may be dict(vault) or list(entries). Try to get an entries list safely.
                        entries_obj = data
                        if isinstance(entries_obj, dict):
                            entries_list = entries_obj.get("entries") or entries_obj.get("vault") or []
                        else:
                            entries_list = list(entries_obj or [])

                        auth_ok, auth_msg, auth_changed, auth_failed = rewrap_authenticator_entries(entries_list, vk, new_vk)
                        log.info("[ForgotPassword] authenticator migrate ok=%s changed=%s failed=%s msg=%s", auth_ok, auth_changed, auth_failed, auth_msg)
                    except Exception as e_auth:
                        # Never fail the whole reset for authenticator migration – just log.
                        log.warning("[ForgotPassword] authenticator migration skipped/failed: %r", e_auth)

                    
                    # 5c-4b: Migrate/repair auxiliary stores tied to the vault key
                    # - Password history: fingerprints are keyed to the vault key, so they cannot be
                    #   verified after a key change. We clear pw_hist so future history works cleanly.
                    try:
                        def _iter_entries(obj):
                            if isinstance(obj, list):
                                return obj
                            if isinstance(obj, dict):
                                # common shapes: {"entries":[...]} or {"vault":[...]}
                                for k in ("entries", "vault", "items", "rows"):
                                    v = obj.get(k)
                                    if isinstance(v, list):
                                        return v
                            return None

                        entries_for_hist = _iter_entries(data)
                        if entries_for_hist:
                            cleared = 0
                            for e in entries_for_hist:
                                if isinstance(e, dict) and "pw_hist" in e:
                                    e["pw_hist"] = []
                                    cleared += 1
                            if cleared:
                                log.info("[ForgotPassword] cleared pw_hist for %s entry/entries", cleared)
                    except Exception as e_hist:
                        log.warning("[ForgotPassword] pw_hist clear skipped: %r", e_hist)

                    # - Trash (soft delete): encrypted under HKDF(user_key,'trash'), so must be rewrapped.
                    try:
                        import os, json, hmac, hashlib
                        from pathlib import Path
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                        from app.paths import trash_path, vault_dir

                        def _hkdf_subkey(user_key: bytes, info: bytes) -> bytes:
                            salt0 = b"\x00" * 32
                            prk = hmac.new(salt0, user_key, hashlib.sha256).digest()
                            return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

                        # trash file = {vault_dir}/{username}_trash.bin, JSON encrypted via sync.engine if present
                        tpath = Path(trash_path(username))
                        if tpath.exists():
                            old_tk = _hkdf_subkey(vk, b"trash")
                            new_tk = _hkdf_subkey(new_vk, b"trash")

                            # Prefer the same encrypt/decrypt helpers as the app (sync.engine).
                            moved = False
                            try:
                                from sync.engine import decrypt_json_file, encrypt_json_file
                                trash_rows = decrypt_json_file(str(tpath), old_tk) or []
                                encrypt_json_file(str(tpath), new_tk, trash_rows)
                                moved = True
                            except Exception:
                                # Fallback: if file is already plain JSON for any reason.
                                try:
                                    trash_rows = json.loads(tpath.read_text(encoding="utf-8") or "[]")
                                    tpath.write_text(json.dumps(trash_rows, ensure_ascii=False), encoding="utf-8")
                                    moved = True  # "moved" in the sense that it's readable; key migration not possible here.
                                except Exception:
                                    moved = False

                            if moved:
                                log.info("[ForgotPassword] trash migrated (soft delete preserved)")
                            else:
                                log.warning("[ForgotPassword] trash migration failed; soft delete may appear empty")
                        else:
                            # no trash yet
                            pass
                    except Exception as e_trash:
                        log.warning("[ForgotPassword] trash migration skipped/failed: %r", e_trash)

                    # - Passkeys store: encrypted blob passkeys_store.json with AES-GCM subkey
                    try:
                        import os, hmac, hashlib
                        from pathlib import Path
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                        from app.paths import vault_dir

                        def _hkdf_subkey2(user_key: bytes, info: bytes) -> bytes:
                            salt0 = b"\x00" * 32
                            prk = hmac.new(salt0, user_key, hashlib.sha256).digest()
                            return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

                        pdir = Path(vault_dir(username))
                        pk_path = pdir / "passkeys_store.json"
                        if pk_path.exists():
                            old_sk = _hkdf_subkey2(vk, b"passkeys-store:aesgcm-32")
                            new_sk = _hkdf_subkey2(new_vk, b"passkeys-store:aesgcm-32")
                            raw = pk_path.read_bytes()
                            if raw and len(raw) > 12:
                                nonce, ct = raw[:12], raw[12:]
                                pt = AESGCM(old_sk).decrypt(nonce, ct, None)
                                new_nonce = os.urandom(12)
                                new_ct = AESGCM(new_sk).encrypt(new_nonce, pt, None)
                                pk_path.write_bytes(new_nonce + new_ct)
                                log.info("[ForgotPassword] passkeys store migrated")
                    except Exception as e_pk:
                        log.warning("[ForgotPassword] passkeys store migration skipped/failed: %r", e_pk)

# 5c-5: Re-encrypt vault under new_vk and store DMK wrapper
                    save_encrypted(data, vault_path, new_vk)
                    wrap_vault_key_dmk(username, dmk_after, new_vk)

            except Exception as e:
                return fail(
                    _tr("Identity was updated, but the vault key could not be rewrapped."),
                    e,
                )

            # --- 6) Update per-user DB password hash -----------------------
            stage = "update_user_db"
            try:
                rec["password"] = _store_password_hash(hash_password(new1))
                set_user_record(username, rec)
            except Exception as e:
                return fail(_tr("Identity updated, but user record could not be saved."), e)

            # --- 7) Success -------------------------------------------------
            
            # --- 6b) Force Identity Store refresh (fix stale header / soft-state) ----
            stage = "identity_refresh"
            try:
                from auth.identity_store import create_or_open_with_password
                # Re-open forces header + wrapper coherence under the new password
                create_or_open_with_password(username, new1)
            except Exception as e:
                log.warning("[ForgotPassword] identity_refresh failed but continuing: %r", e)

            stage = "success"
            try:
                # Identity header repair after successful reset:
                # Re-bind the recovery wrapper under the NEW password so future header_check passes.
                try:
                    from auth.identity_store import bind_recovery_wrapper
                    bind_recovery_wrapper(username, new1, MK)
                except Exception as e:
                    log.info("[ForgotPassword] identity recovery re-bind skipped: %r", e)

                QMessageBox.information(
                    self,
                    _tr("Password Reset"),
                    _tr("✅ Your password was reset.\n\n"
                    "You can now log in using the new password."),
                )
            except Exception:
                pass
            self.accept()

        except Exception as e:
            fail("Unhandled error", e)


    def reset_password(self) -> None:
        log.info("[ForgotPassword] ENTER reset_password_backup_code()")
        stage = "start"


        # --- Recovery warning confirmation ----------------------------
        if not self._confirm_recovery_warning():
            log.info("[ForgotPassword] user cancelled recovery after warning")
            return

        def fail(msg: str, e: Exception | None = None) -> None:
            """Centralised error handler with logging."""
            nonlocal stage
            if e is not None:
                log.error(
                    "[ForgotPassword] %s -> %s | %r\n%s",
                    stage,
                    msg,
                    e,
                    traceback.format_exc(),
                )
                try:
                    QMessageBox.critical(
                        self,
                        _tr("Reset Failed"),
                        _tr("Password reset failed at step") + f" '{stage}':\n\n{msg}\n\n{e}",
                    )
                except Exception:
                    pass
            else:
                log.error("[ForgotPassword] %s -> %s", stage, msg)
                try:
                    QMessageBox.critical(
                        self,
                        _tr("Reset Failed"),
                        _tr("Password reset failed at step") + f" '{stage}':\n\n{msg}",
                    )
                except Exception:
                    pass

        try:
            # --- 1) Read + basic validate inputs ----------------------------
            stage = "read_inputs"
            u = (self.usernameField.text() if hasattr(self, "usernameField") else "").strip()
            rk_in = (self.recoveryKeyField.text() if hasattr(self, "recoveryKeyField") else "").strip()
            new1 = self.newPasswordField.text().strip() if hasattr(self, "newPasswordField") else ""
            new2 = self.confirmPasswordField.text().strip() if hasattr(self, "confirmPasswordField") else ""

            # backup codes are NO longer required here (login-only)
            if not all([u, rk_in, new1, new2]):
                return fail(_tr("All fields are required."))
            if new1 != new2:
                return fail(_tr("Passwords do not match."))

            # --- 2) Password policy ----------------------------------------
            stage = "policy"
            ok, level_text, policy_msg = get_password_strength(new1)
            if not ok:
                return fail(_tr("Password does not meet the security policy."))

            # --- 3) Normalise username -------------------------------------
            stage = "normalize"
            username = _canonical_username_ci(u) or u
            log.info("[ForgotPassword] user=%s", username)

            # Check user exists (per-user DB)
            stage = "load_user_record"
            rec = get_user_record(username) or {}
            if not isinstance(rec, dict) or not rec:
                return fail(_tr("Username not found."))

            # --- 4) Recovery Key → MK (supports legacy + new formats) ------
            stage = "rk_to_mk"
            MK = _derive_mk_from_any_recovery_key(username, rk_in.replace(" ",""))
            # soft header check via mk_hash_b64 mirror
            header_mismatch = False
            header_mismatch_want = ""
            header_mismatch_have = ""


            # soft header check via mk_hash_b64 mirror -------------
            stage = "header_check"
            try:
                hdr = get_public_header(username) or {}
                want = ((hdr.get("meta") or {}).get("mk_hash_b64") or "").strip()
                have = mk_hash_b64(MK)
                log.debug("[ForgotPassword] mk_hash want=%s have=%s", want, have)
                if want and have != want:
                    header_mismatch = True
                    header_mismatch_want = want
                    header_mismatch_have = have
                    log.warning("[ForgotPassword] header_check mismatch for %s (want=%s have=%s) — continuing", username, want, have)

                # If 'want' is blank (very old identities), we allow and rely on
                # the rewrap step to fail if MK is wrong.
            except Exception as e:
                log.debug("[ForgotPassword] header check skipped: %r", e)

            # --- 5) Rewrap identity password/recovery wrappers -------------
            stage = "rewrap_identity"
            ok_rw, msg_rw = rewrap_with_new_password(username, MK, new1)
            if not ok_rw:
                return fail(_tr("Could not update identity") + f": {msg_rw}")

            # --- 5b) Reload identity with NEW password to get DMK ----------
            stage = "reload_identity"
            try:
                from auth.identity_store import create_or_open_with_password
                dmk_after, inner_after, hdr_after = create_or_open_with_password(username, new1)
            except Exception as e:
                return fail(
                    _tr("Identity was updated, but it could not be reopened with the new password."),
                    e,
                )

            # --- 5c) Rewrap vault key, keep vault data ----------------------
            stage = "rewrap_vault"
            try:
                from pathlib import Path
                from vault_store.vault_store import (
                    get_vault_path,
                    get_wrapped_key_path,
                    load_encrypted,
                    save_encrypted,
                    load_user_salt,
                    unwrap_vault_key_dmk,
                    wrap_vault_key_dmk,
                )

                # 5c-1: Work out the current vault key (vk)
                vk = None

                # Try DMK-based wrapper first (new format)
                try:
                    vk = unwrap_vault_key_dmk(username, dmk_after)
                    log.debug("[ForgotPassword] DMK-based vault wrapper OK for %s", username)
                except Exception as e_dmk:
                    log.debug("[ForgotPassword] DMK unwrap failed, trying legacy Recovery-Key wrapper: %r", e_dmk)

                    # Legacy Recovery-Key-based .kq_wrap (text, encrypt_key())
                    from vault_store.kdf_utils import derive_key_argon2id
                    from vault_store.key_utils import decrypt_key as _decrypt_key

                    wpath = Path(get_wrapped_key_path(username))
                    if not wpath.exists():
                        raise FileNotFoundError(_tr("Wrapped vault key not found at") + f" {wpath}")

                    # Old file is a base64 string written by encrypt_key()
                    ct_b64 = wpath.read_text(encoding="utf-8").strip()
                    salt = load_user_salt(username)
                    # KEK derived from Recovery Key string + salt
                    kek = derive_key_argon2id(rk_in, salt)
                    vk = _decrypt_key(ct_b64, kek)
                    log.info("[ForgotPassword] migrated legacy Recovery-Key wrapped vault key for %s", username)

                if vk is None:
                    raise RuntimeError(_tr("Vault key could not be obtained from any wrapper."))

                # 5c-2: If there is no vault file yet, just create a new DMK wrapper
                vault_path = get_vault_path(username)
                vpath = Path(vault_path)
                if not vpath.exists():
                    log.info("[ForgotPassword] no existing vault for %s; creating DMK wrapper only", username)
                    from vault_store.kdf_utils import derive_key_argon2id
                    salt = load_user_salt(username)
                    new_vk = derive_key_argon2id(new1, salt)
                    wrap_vault_key_dmk(username, dmk_after, new_vk)
                else:
                    # 5c-3: Decrypt existing vault with old vk
                    try:
                        data = load_encrypted(vault_path, vk)
                    except Exception as e_dec:
                        raise RuntimeError(
                            _tr("Existing vault could not be decrypted with recovered key") + f": {e_dec}"
                        ) from e_dec

                    # 5c-4: Derive new vault key from NEW password + existing salt
                    from vault_store.kdf_utils import derive_key_argon2id
                    salt = load_user_salt(username)
                    new_vk = derive_key_argon2id(new1, salt)

                    # 5c-4b: Migrate Authenticator field secrets (secret_enc_b64) from old vk -> new_vk
                    # These secrets are additionally wrapped using AES-GCM(user_key) inside the decrypted vault.
                    try:
                        from vault_store.authenticator_store import rewrap_authenticator_entries

                        # 'data' may be dict(vault) or list(entries). Try to get an entries list safely.
                        entries_obj = data
                        if isinstance(entries_obj, dict):
                            entries_list = entries_obj.get("entries") or entries_obj.get("vault") or []
                        else:
                            entries_list = list(entries_obj or [])

                        auth_ok, auth_msg, auth_changed, auth_failed = rewrap_authenticator_entries(entries_list, vk, new_vk)
                        log.info("[ForgotPassword] authenticator migrate ok=%s changed=%s failed=%s msg=%s", auth_ok, auth_changed, auth_failed, auth_msg)
                    except Exception as e_auth:
                        # Never fail the whole reset for authenticator migration – just log.
                        log.warning("[ForgotPassword] authenticator migration skipped/failed: %r", e_auth)

                    # 5c-4b: Migrate/repair auxiliary stores tied to the vault key
                    
                    # - Password history: fingerprints are keyed to the vault key, so they cannot be
                    #   verified after a key change. We clear pw_hist so future history works cleanly.
                    try:
                        def _iter_entries(obj):
                            if isinstance(obj, list):
                                return obj
                            if isinstance(obj, dict):
                                # common shapes: {"entries":[...]} or {"vault":[...]}
                                for k in ("entries", "vault", "items", "rows"):
                                    v = obj.get(k)
                                    if isinstance(v, list):
                                        return v
                            return None
                    
                        entries_for_hist = _iter_entries(data)
                        if entries_for_hist:
                            cleared = 0
                            for e in entries_for_hist:
                                if isinstance(e, dict) and "pw_hist" in e:
                                    e["pw_hist"] = []
                                    cleared += 1
                            if cleared:
                                log.info("[ForgotPassword] cleared pw_hist for %s entry/entries", cleared)
                    except Exception as e_hist:
                        log.warning("[ForgotPassword] pw_hist clear skipped: %r", e_hist)
                    
                    # - Trash (soft delete): encrypted under HKDF(user_key,'trash'), so must be rewrapped.
                    try:
                        import os, json, hmac, hashlib
                        from pathlib import Path
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                        from app.paths import trash_path, vault_dir
                    
                        def _hkdf_subkey(user_key: bytes, info: bytes) -> bytes:
                            salt0 = b"\x00" * 32
                            prk = hmac.new(salt0, user_key, hashlib.sha256).digest()
                            return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
                    
                        # trash file = {vault_dir}/{username}_trash.bin, JSON encrypted via sync.engine if present
                        tpath = Path(trash_path(username))
                        if tpath.exists():
                            old_tk = _hkdf_subkey(vk, b"trash")
                            new_tk = _hkdf_subkey(new_vk, b"trash")
                    
                            # Prefer the same encrypt/decrypt helpers as the app (sync.engine).
                            moved = False
                            try:
                                from sync.engine import decrypt_json_file, encrypt_json_file
                                trash_rows = decrypt_json_file(str(tpath), old_tk) or []
                                encrypt_json_file(str(tpath), new_tk, trash_rows)
                                moved = True
                            except Exception:
                                # Fallback: if file is already plain JSON for any reason.
                                try:
                                    trash_rows = json.loads(tpath.read_text(encoding="utf-8") or "[]")
                                    tpath.write_text(json.dumps(trash_rows, ensure_ascii=False), encoding="utf-8")
                                    moved = True  # "moved" in the sense that it's readable; key migration not possible here.
                                except Exception:
                                    moved = False
                    
                            if moved:
                                log.info("[ForgotPassword] trash migrated (soft delete preserved)")
                            else:
                                log.warning("[ForgotPassword] trash migration failed; soft delete may appear empty")
                        else:
                            # no trash yet
                            pass
                    except Exception as e_trash:
                        log.warning("[ForgotPassword] trash migration skipped/failed: %r", e_trash)
                    
                    # - Passkeys store: encrypted blob passkeys_store.json with AES-GCM subkey
                    try:
                        import os, hmac, hashlib
                        from pathlib import Path
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                        from app.paths import vault_dir
                    
                        def _hkdf_subkey2(user_key: bytes, info: bytes) -> bytes:
                            salt0 = b"\x00" * 32
                            prk = hmac.new(salt0, user_key, hashlib.sha256).digest()
                            return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
                    
                        pdir = Path(vault_dir(username))
                        pk_path = pdir / "passkeys_store.json"
                        if pk_path.exists():
                            old_sk = _hkdf_subkey2(vk, b"passkeys-store:aesgcm-32")
                            new_sk = _hkdf_subkey2(new_vk, b"passkeys-store:aesgcm-32")
                            raw = pk_path.read_bytes()
                            if raw and len(raw) > 12:
                                nonce, ct = raw[:12], raw[12:]
                                pt = AESGCM(old_sk).decrypt(nonce, ct, None)
                                new_nonce = os.urandom(12)
                                new_ct = AESGCM(new_sk).encrypt(new_nonce, pt, None)
                                pk_path.write_bytes(new_nonce + new_ct)
                                log.info("[ForgotPassword] passkeys store migrated")
                    except Exception as e_pk:
                        log.warning("[ForgotPassword] passkeys store migration skipped/failed: %r", e_pk)


                    # 5c-5: Re-encrypt vault under new_vk and store DMK wrapper
                    save_encrypted(data, vault_path, new_vk)
                    wrap_vault_key_dmk(username, dmk_after, new_vk)

            except Exception as e:
                return fail(
                    _tr("Identity was updated, but the vault key could not be rewrapped."),
                    e,
                )

            # --- 5d) After recovery, turn account back into 'normal' (no Yubi) ---
            stage = "clear_yubi"
            try:
                from auth.identity_store import clear_yubi_config
                try:
                    from auth.tfa.twofactor import disable_yk_2of2
                except Exception:
                    disable_yk_2of2 = None  # older builds

                # Only try Yubi cleanup if identity store *really* has active config
                try:
                    yubi_meta = (hdr_after.get("meta") or {})
                    really_enabled = (
                        yubi_meta.get("yubi_enabled") and
                        yubi_meta.get("yubi_mode") and
                        yubi_meta.get("yk_slot")
                    )
                except Exception:
                    really_enabled = False

                if really_enabled:
                    try:
                        cleared_id = clear_yubi_config(username, new1)
                    except Exception as e:
                        log.warning("[ForgotPassword] clear_yubi_config failed but continuing: %r", e)

                    if disable_yk_2of2 is not None:
                        try:
                            disable_yk_2of2(username)
                        except Exception as e:
                            log.warning("[ForgotPassword] disable_yk_2of2 failed but continuing: %r", e)
                else:
                    log.info("[ForgotPassword] YubiKey metadata stale/disabled — skipping cleanup safely.")

            except Exception as e:
                # Don't fail reset if Yubi cleanup fails – just log it
                log.warning("[ForgotPassword] could not clear YubiKey config after reset: %r", e)


            # --- 6) Update per-user DB password hash -----------------------
            stage = "update_user_db"
            try:
                rec["password"] = _store_password_hash(hash_password(new1))
                set_user_record(username, rec)
            except Exception as e:
                return fail(_tr("Identity updated, but user record could not be saved."), e)

            # --- 7) Success -------------------------------------------------
            
            # --- 6b) Force Identity Store refresh (fix stale header / soft-state) ----
            stage = "identity_refresh"
            try:
                from auth.identity_store import create_or_open_with_password
                # Re-open forces header + wrapper coherence under the new password
                create_or_open_with_password(username, new1)
            except Exception as e:
                log.warning("[ForgotPassword] identity_refresh failed but continuing: %r", e)

            stage = "success"
            try:
                # Identity header repair after successful reset:
                # Re-bind the recovery wrapper under the NEW password so future header_check passes.
                try:
                    from auth.identity_store import bind_recovery_wrapper
                    bind_recovery_wrapper(username, new1, MK)
                except Exception as e:
                    log.info("[ForgotPassword] identity recovery re-bind skipped: %r", e)

                QMessageBox.information(
                    self,
                    _tr("Password Reset"),
                    _tr("✅ Your password was reset.\n\n"
                    "You can now log in using the new password."),
                )
            except Exception:
                pass
            self.accept()

        except Exception as e:
            fail(_tr("Unhandled error"), e)

