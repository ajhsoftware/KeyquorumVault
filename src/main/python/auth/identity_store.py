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

import base64
import hashlib
import json
import logging
import os
import secrets
import shutil
from pathlib import Path
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from vault_store.key_utils import derive_key_argon2id
from security.secure_audit import log_event_encrypted

log = logging.getLogger("keyquorum")
log.debug("[DEBUG] 🔐 Identity Store")

# ==============================
# Dynamic path resolution (USB binding-aware)
# ==============================

import base64, hashlib, json
from pathlib import Path
from typing import Dict
from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("identity_store", text)

# ==============================
# --- forgot password rewrap: bind recovery wrapper
# ==============================

def bind_recovery_wrapper(username: str, password: str, master_key: bytes) -> None:
    """
    After account creation: open identity with password and ensure it has
    a 'recovery' wrapper bound to master_key, plus mk_hash_b64 in meta.

    In this model:
      • DMK (Data Master Key) is what protects the identity payload.
      • We treat DMK as the "CEK" for the recovery wrapper.
    """
    # Open (or create) the identity using the normal password path
    p = _user_id_file(username, ensure_parent=True)
    dmk, inner, hdr = create_or_open_with_password(username, password)

    wrappers = hdr.setdefault("wrappers", [])
    pw = next((w for w in wrappers if (w.get("type") or "").lower() == "password"), None)
    if not pw:
        raise ValueError(_tr("identity has no password wrapper"))

    # In our model, the "CEK" for the recovery wrapper is just the DMK
    cek = dmk

    # Build / update 'recovery' wrapper using master_key and a random salt
    recw = next((w for w in wrappers if (w.get("type") or "").lower() == "recovery"), None)
    if not recw:
        recw = {"type": "recovery"}
        wrappers.append(recw)

    rec_salt = os.urandom(16)
    kek_rec  = _kek_from_mk(master_key, rec_salt)
    nr, ctr  = _aes_enc(kek_rec, b"KQID-CEK-REC", cek)
    recw.update(
        {
            "salt":  _b64e(rec_salt),
            "nonce": _b64e(nr),
            "ct":    _b64e(ctr),
        }
    )

    # Mirror mk_hash_b64 into header.meta for soft verification
    ensure_mk_hash_in_header(username, master_key)

    # Re-encrypt the payload with the same DMK, but updated header
    n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
    _write_all(p, hdr, n2, ct2)

# ==============================
# --- forgot password rewrap (strict, no identity reset)
# ==============================

def bind_yubi_wrapper(username: str, master_key: bytes, wrap_kek: bytes) -> None:
    """
    Rebind the YubiKey wrapper after identity has been rewrapped.

    • master_key = the new MK after password reset (CEK/DMK-derived)
    • wrap_kek   = AES-GCM KEK derived from YubiKey slot challenge-response

    This replaces the 'yubi' wrapper in the identity header with one using
    the new MK. Without this, YubiKey unwrap returns the old MK and fails.
    """
    from pathlib import Path
    import base64, os, json
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from app.paths import identities_file

    uid_path = Path(identities_file(username, ensure_dir=False))
    if not uid_path.exists():
        raise FileNotFoundError("Identity file not found for YubiKey rebind")

    # Load identity JSON
    ident = json.loads(uid_path.read_text("utf-8"))

    wrappers = ident.get("wrappers") or []
    wrappers = [w for w in wrappers if w.get("type") != "yk"]

    aes = AESGCM(wrap_kek)
    nonce = os.urandom(12)
    wrapped = aes.encrypt(nonce, master_key, b"KQ-WRAP-V1")

    wrappers.append({
        "type": "yk",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct":    base64.b64encode(wrapped).decode("ascii"),
    })

    ident["wrappers"] = wrappers

    # Write back safely
    tmp = uid_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(ident, indent=2), encoding="utf-8")
    tmp.replace(uid_path)

def rewrap_with_new_password(username: str, master_key: bytes, new_password: str) -> tuple[bool, str]:
    """
    Re-wrap the identity with a NEW account password, using the Recovery Master Key (MK).

    Strict behaviour:

      • Requires an existing identity file with a 'recovery' wrapper.
      • Uses the Recovery Key–derived MK to decrypt the CEK.
      • On ANY failure, returns (False, reason) and DOES NOT touch the file.
      • On success, rewrites:
           - 'password' wrapper (new password)
           - 'recovery' wrapper (same MK)
        and keeps the payload (Yubi, 2FA, backup codes) intact.

    Returns:
        (True, "") on success
        (False, "reason") on failure
    """
    from app.paths import identities_file

    username = (username or "").strip()
    if not username or not new_password or not isinstance(master_key, (bytes, bytearray)):
        return False, _tr("invalid arguments to rewrap_with_new_password")

    p = Path(identities_file(username, ensure_parent=True))

    # 1) Load identity
    try:
        hdr, n2, ct2 = _read_header_nonce_ct(p)
    except FileNotFoundError:
        log.warning(
            "[identity] rewrap_with_new_password: identity file missing for %s",
            username,
        )
        return False, _tr("identity file not found for this account")
    except Exception as e:
        log.error(
            "[identity] rewrap_with_new_password: failed to read identity for %s: %r",
            username,
            e,
        )
        return False, _tr("could not read identity: {e}")

    # 2) Get recovery wrapper + salt
    try:
        recw = _find_wrapper(hdr, "recovery")
        rec_salt_b64 = (recw.get("salt") or "").strip()
        if not rec_salt_b64:
            log.error(
                "[identity] rewrap_with_new_password: recovery wrapper missing salt for %s",
                username,
            )
            return False, _tr("identity is missing recovery metadata")
        rec_salt = _b64d(rec_salt_b64)
    except KeyError:
        log.warning(
            "[identity] rewrap_with_new_password: no 'recovery' wrapper for %s",
            username,
        )
        return False, _tr("this account is not configured for Recovery-Key resets")
    except Exception as e:
        log.error(
            "[identity] rewrap_with_new_password: error inspecting recovery wrapper for %s: %r",
            username,
            e,
        )
        return False, _tr("identity structure is invalid") + f": {e}"

    # 3) Decrypt CEK with Recovery MK
    try:
        cek = _unwrap_cek_with_recovery(hdr, master_key, rec_salt)
    except Exception as e:
        log.error(
            "[identity] rewrap_with_new_password: CEK unwrap with recovery MK failed for %s: %r",
            username,
            e,
        )
        return False, _tr("Recovery Key could not decrypt the identity (wrong Recovery Key?)")

    # 4) Rewrite password wrapper with NEW password
    try:
        wrappers = hdr.setdefault("wrappers", [])
        pw = next((w for w in wrappers if (w.get("type") or "").lower() == "password"), None)
        if not pw:
            pw = {"type": "password"}
            wrappers.append(pw)

        pw_salt = _b64d(pw["salt"]) if pw.get("salt") else os.urandom(16)
        kek_pw  = derive_key_argon2id(new_password, pw_salt)

        # IMPORTANT: keep this aligned with create_or_open_with_password
        # so login can still decrypt the DMK from the password wrapper.
        n1, ct1 = _aes_enc(kek_pw, b"KQID-DMK", cek)   # 'cek' is actually DMK here

        pw.update(
            {
                "salt":  _b64e(pw_salt),
                "nonce": _b64e(n1),
                "ct":    _b64e(ct1),
            }
        )


        # 5) Refresh recovery wrapper with same MK (in case we want to rotate salt)
        if recw is None:
            recw = {"type": "recovery"}
            wrappers.append(recw)

        kek_rec = _kek_from_mk(master_key, rec_salt)
        nr, ctr = _aes_enc(kek_rec, b"KQID-CEK-REC", cek)
        recw.update({
            "salt":  _b64e(rec_salt),
            "nonce": _b64e(nr),
            "ct":    _b64e(ctr),
        })

        # 6) Write back header + existing payload
        _write_all(p, hdr, n2, ct2)

        # mirror mk_hash_b64 into header.meta for future soft checks
        try:
            ensure_mk_hash_in_header(username, master_key)
        except Exception:
            pass

        log.info("[identity] rewrap_with_new_password: updated wrappers for %s", username)
        return True, ""

    except Exception as e:
        log.error(
            "[identity] rewrap_with_new_password: failed to rewrite wrappers for %s: %r",
            username,
            e,
        )
        return False, _tr("could not update identity wrappers") + f": {e}"

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def _kek_from_mk(master_key: bytes, salt: bytes) -> bytes:
    # Derive a KEK deterministically from MK (does not weaken MK; HKDF isolates usage)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"kq/identity/recovery")
    return hkdf.derive(master_key)

def _unwrap_cek_with_recovery(hdr: dict, master_key: bytes, salt: bytes) -> bytes:
    """
    Unwrap the CEK/DMK from the 'recovery' wrapper using the Recovery MK.

    The recovery wrapper was created by bind_recovery_wrapper using:
        nonce, ct = _aes_enc(kek_rec, b"KQID-CEK-REC", cek)

    So we must undo that with _aes_dec and the same AEAD header.
    """
    w = _find_wrapper(hdr, "recovery")

    nonce_b64 = (w.get("nonce") or "").strip()
    ct_b64    = (w.get("ct") or "").strip()
    if not nonce_b64 or not ct_b64:
        raise ValueError(_tr("recovery wrapper missing nonce/ct"))

    nonce = _b64d(nonce_b64)
    ct    = _b64d(ct_b64)

    kek = _kek_from_mk(master_key, salt)
    # This returns the DMK (we call it CEK logically)
    return _aes_dec(kek, b"KQID-CEK-REC", nonce, ct)

def _find_wrapper(hdr: dict, typ: str) -> dict:
    for w in (hdr.get("wrappers") or []):
        if (w.get("type") or "").lower() == typ:
            return w
    raise KeyError(f"wrapper '{typ}' not found")

# ==============================
# --- helpers

def mk_hash_b64(mk: bytes) -> str:
    return base64.b64encode(hashlib.sha256(mk).digest()).decode("ascii")

def get_public_header(username: str) -> dict | None:
    """
    Read only the public header of the identity file (no password needed).
    Safe to call even if the file is missing.
    """
    try:
        # IMPORTANT: don't create dirs here – just read if present
        p = _user_id_file(username, ensure_parent=False)
        if not p.exists():
            return None
        hdr = _read_header(p)
        return hdr or {}
    except Exception as e:
        log.debug("[identity] get_public_header failed for %s: %r", username, e)
        return None

def _write_public_header(username: str, header: Dict) -> None:
    """
    Update only the header of an existing identity file while preserving the
    encrypted payload, using the new KQID1 binary format.
    """
    from app.paths import identities_file
    p = Path(identities_file(username, ensure_parent=True))

    try:
        # Read existing payload (nonce + ciphertext) so we don't touch it
        _, payload_nonce, payload_ct = _read_header_nonce_ct(p)
    except Exception:
        # No valid identity yet → create minimal empty payload
        dmk = secrets.token_bytes(32)
        inner = {"twofa": {}, "recovery": {}, "meta": header.get("meta", {})}
        payload_nonce, payload_ct = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))

    # Now write header + existing (or freshly created) payload in the new format
    _write_all(p, header, payload_nonce, payload_ct)

def ensure_mk_hash_in_header(username: str, mk: bytes) -> None:
    """Back-fill meta.mk_hash_b64 if missing/blank, without touching payload."""
    try:
        hdr = get_public_header(username) or {}
        meta = hdr.setdefault("meta", {})
        if not (meta.get("mk_hash_b64") or "").strip():
            meta["mk_hash_b64"] = mk_hash_b64(mk)
            _write_public_header(username, hdr)
    except Exception:
        # best-effort; never break login
        pass

# ==============================
# Dynamic path resolution (USB binding-aware)
# ==============================

from app.paths import (
    identities_file,
    users_root,
    user_root_local,
    user_root_roaming,
    user_root_portable,
)

# Back-compat shim used internally in this module
def _user_id_file(username: str, ensure_parent: bool = False) -> Path:
    # canonical identity path:
    #  - Installed:  %APPDATA%\Keyquorum\Users\<user>\Main\<user>.kq_id
    #  - Portable:   <USB>\KeyquorumPortable\Users\<user>\Main\<user>.kq_id
    return identities_file(username, ensure_parent=ensure_parent)

def debug_identity_paths(username: str) -> None:
    """Log canonical identity location for a user."""
    p = _user_id_file(username, ensure_parent=False)
    log.info("[IDENTITY_STORE] canonical=%s (exists=%s)", p, p.exists())

def ensure_identity_ready(typed_username: str) -> Tuple[str, str, bool]:
    """
    Make sure the identity blob is in the canonical place.
    Returns: (id_path_str, canonical_username, exists_now)
    - Looks for legacy locations and migrates the newest one to identities_file(...).
    - Does NOT create anything when absent.
    """
    username = (typed_username or "").strip()
    if not username:
        return ("", typed_username, False)

    # canonical target (READ-ONLY here)
    target = _user_id_file(username, ensure_parent=False)

    # If target already exists, we're done.
    if target.exists():
        return (str(target), username, True)

    # Gather legacy candidates (most-recent wins)
    candidates: list[Path] = []

    # 1) Old Config location(s)
    try:
        candidates.append(user_root_local(username, ensure=False) / "Config" / f"{username}.kq_id")
    except Exception:
        pass
    try:
        candidates.append(user_root_roaming(username, ensure=False) / "Config" / f"{username}.kq_id")
    except Exception:
        pass

    # 2) Very old identity layout, if ever used
    try:
        candidates.append(user_root_local(username, ensure=False) / "identities" / f"{username}.data")
    except Exception:
        pass

    # 3) Portable legacy (old portable Config)
    try:
        candidates.append(user_root_portable(username, ensure=False) / "Config" / f"{username}.kq_id")
    except Exception:
        pass

    existing = [p for p in candidates if p.exists()]

    priority = {
        "portable": 3,
        "roaming": 2,
        "local": 1,
    }

    def _rank(p: Path) -> tuple[int, float]:
        rank = 0
        if "portable" in str(p).lower(): rank = 3
        elif "roaming" in str(p).lower(): rank = 2
        else: rank = 1
        return (rank, p.stat().st_mtime)

    newest = max(existing, key=_rank, default=None)
    # newest = max(existing, key=lambda p: p.stat().st_mtime, default=None)



    # If there is a legacy file, migrate it (WRITE allowed here because it's a one-off repair)
    if newest:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(newest, target)
            log.info("[IDENTITY_STORE] migrated legacy identity → %s", target)
            return (str(target), username, True)
        except Exception as e:
            log.error("[IDENTITY_STORE] migrate failed: %s", e)

    # Nothing found; target still doesn't exist
    return (str(target), username, target.exists())


# ==============================
# File format
# ==============================

MAGIC = b"KQID1"

def _b64e(b: bytes) -> str: return base64.b64encode(b).decode()
def _b64d(s: str) -> bytes: return base64.b64decode(s)
def _canon(obj: dict) -> bytes: return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _aes_enc(key: bytes, ad: bytes, pt: bytes) -> Tuple[bytes, bytes]:
    aes = AESGCM(key); nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, pt, ad)
    return nonce, ct

def _aes_dec(key: bytes, ad: bytes, nonce: bytes, ct: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, ad)

def _read_raw(path: Path) -> bytes:
    return path.read_bytes()

def _read_header(path: Path) -> dict:
    b = _read_raw(path)
    if b[:5] != MAGIC:
        raise ValueError("bad magic")
    hdr_len = int.from_bytes(b[5:9], "big")
    return json.loads(b[9:9 + hdr_len])

def _read_header_nonce_ct(path: Path) -> tuple[dict, bytes, bytes]:
    b = _read_raw(path)
    if b[:5] != MAGIC:
        raise ValueError("bad magic")
    hdr_len = int.from_bytes(b[5:9], "big")
    hdr = json.loads(b[9:9 + hdr_len])
    n2 = b[9 + hdr_len:9 + hdr_len + 12]
    ct2 = b[9 + hdr_len + 12:]
    return hdr, n2, ct2

def _write_all(path: Path, header: dict, payload_nonce: bytes, payload_ct: bytes) -> None:
    # ✅ ensure parent exists before atomic write
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = MAGIC + len(_canon(header)).to_bytes(4, "big") + _canon(header) + payload_nonce + payload_ct
    tmp = path.with_suffix(path.suffix + ".tmp")  # keep original suffix and add .tmp
    tmp.write_bytes(blob)
    os.replace(tmp, path)

# ==============================
# Public API
# ==============================

def create_or_open_with_password(username: str, password: str | bytes) -> tuple[bytes, dict, dict]:
    """
    Open identity file for user. Creates a new identity if missing.
    Returns (dmk, inner, header).
    """
    p = _user_id_file(username, ensure_parent=True)
    if not p.exists():
        # new identity
        # Require a textual password to derive the initial KEK.  This path
        # intentionally rejects bytes-like passwords to avoid accidentally
        # binding an identity to a derived key without a corresponding
        # memorable passphrase.  DPAPI‑bound logins never create new
        # identities.
        if not isinstance(password, str):
            raise TypeError("password must be a string when creating a new identity")

        salt = secrets.token_bytes(16)
        kek  = derive_key_argon2id(password, salt)  # 32 bytes
        dmk  = secrets.token_bytes(32)
        n1, ct1 = _aes_enc(kek, b"KQID-DMK", dmk)

        header = {
            "wrappers": [
                {"type": "password", "salt": _b64e(salt), "nonce": _b64e(n1), "ct": _b64e(ct1)}
            ],
            "alg": "aesgcm-256",
            "meta": {
                # small, non-sensitive flags for fast UI
                "twofa_backup_count": 0,
                "login_backup_count": 0,
                "has_totp": False,
            },
        }

        inner = {
            "twofa": {
                "enabled": False,
                "salt": _b64e(secrets.token_bytes(16)),   # used to hash codes
                "totp": {"nonce": None, "ct": None},      # AES-GCM of base32 secret
                "backup_code_hashes": [],
            },
            "recovery": {
                "login_backup_code_hashes": []
            },
            "meta": {"version": 1}
        }

        n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
        _write_all(p, header, n2, ct2)
        return dmk, inner, header

    # open existing
    hdr, n2, ct2 = _read_header_nonce_ct(p)
    pw = next((w for w in hdr.get("wrappers", []) if w.get("type") == "password"), None)
    if not pw:
        raise ValueError("no password wrapper")
    salt = _b64d(pw["salt"]); n1 = _b64d(pw["nonce"]); ct1 = _b64d(pw["ct"])
    # Accept either a textual password (str) or a pre‑derived KEK (bytes).
    # When a bytes‑like value is provided (e.g. via DPAPI passwordless login),
    # it is used directly as the key encryption key (KEK).  Otherwise the
    # KEK is derived from the provided password and stored salt.
    if isinstance(password, (bytes, bytearray)):
        # Use the provided key directly.  Copy into bytes to avoid
        # inadvertently using a mutable memoryview or subclass.
        kek = bytes(password)
    else:
        kek = derive_key_argon2id(password, salt)
    dmk  = _aes_dec(kek, b"KQID-DMK", n1, ct1)
    inner = json.loads(_aes_dec(dmk, b"KQID-PAYLOAD", n2, ct2).decode("utf-8"))
    return dmk, inner, hdr

def update_inner(username: str, dmk: bytes, inner: dict) -> None:
    p = _user_id_file(username, ensure_parent=True)
    hdr, _, _ = _read_header_nonce_ct(p)
    n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
    _write_all(p, hdr, n2, ct2)

# -------- TOTP secret --------

def set_totp_secret(username: str, password: str, secret_b32: str) -> None:
    try:
        dmk, inner, hdr = create_or_open_with_password(username, password)
        n, ct = _aes_enc(dmk, b"KQID-TOTP", secret_b32.encode("ascii"))
        inner["twofa"]["enabled"] = True
        inner["twofa"]["totp"] = {"nonce": _b64e(n), "ct": _b64e(ct)}

        meta = hdr.setdefault("meta", {})
        meta["has_totp"] = True

        n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
        _write_all(_user_id_file(username, ensure_parent=True), hdr, n2, ct2)
    except Exception as e:
        log.info(f"Error setting secert: {e}")

def get_totp_secret(username: str, password: str) -> Optional[str]:
    dmk, inner, _ = create_or_open_with_password(username, password)
    t = inner["twofa"]["totp"]
    if not (t and t.get("nonce") and t.get("ct")):
        return None
    sec = _aes_dec(dmk, b"KQID-TOTP", _b64d(t["nonce"]), _b64d(t["ct"]))
    return sec.decode("ascii")

# -------- 2FA backup codes (TOTP usage) --------

def replace_backup_codes(username: str, password: str, codes_plain: list[str]) -> list[str]:
    """
    Replace the list of 2FA backup codes in the identity store.  Each
    provided code is normalised, hashed with a memory‑hard KDF (Argon2id)
    using the per‑user salt, and stored as a base64 string.  Legacy
    codes hashed with SHA‑256 will continue to validate via
    `consume_backup_code()` for backwards compatibility.
    """
    p = _user_id_file(username, ensure_parent=True)
    dmk, inner, hdr = create_or_open_with_password(username, password)

    salt = base64.b64decode(inner["twofa"]["salt"])
    hashes: list[str] = []
    for c in (codes_plain or []):
        c = (c or "").strip()
        if not c:
            continue
        try:
            # derive a 32‑byte hash using Argon2id; fall back to SHA‑256 if
            # Argon2 fails for any reason (e.g. out of memory).  This
            # increases the cost of offline brute forcing of backup codes.
            from vault_store.kdf_utils import derive_key_argon2id_safe
            h_bytes = derive_key_argon2id_safe(c, salt, length=32)
        except Exception:
            h_bytes = hashlib.sha256(salt + c.encode("utf-8")).digest()
        hashes.append(_b64e(h_bytes))
    inner["twofa"]["backup_code_hashes"] = hashes

    meta = hdr.setdefault("meta", {})
    meta["twofa_backup_count"] = len(hashes)

    n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
    _write_all(p, hdr, n2, ct2)
    return codes_plain

def consume_backup_code(username: str, password: str, code_plain: str) -> bool:
    """
    Validate and consume a 2FA backup code.  Supports both legacy
    SHA‑256 hashes and the newer Argon2id hashes.  Returns True on
    successful consumption, False otherwise.
    """
    p = _user_id_file(username)
    dmk, inner, hdr = create_or_open_with_password(username, password)

    salt = base64.b64decode(inner["twofa"]["salt"])
    code_norm = (code_plain or "").strip()
    # do quick basline check before change, if shows error then no baseline update will be done
    from security.baseline_signer import checkbasline
    changed, missing, new_, mac_ok = checkbasline(username)
    # Compute candidate hashes for both Argon2id and legacy SHA‑256
    hash_candidates: list[str] = []
    try:
        from vault_store.kdf_utils import derive_key_argon2id_safe
        h_argon = derive_key_argon2id_safe(code_norm, salt, length=32)
        hash_candidates.append(_b64e(h_argon))
    except Exception:
        pass
    # Always include the legacy SHA‑256 hash
    h_sha = hashlib.sha256(salt + code_norm.encode("utf-8")).digest()
    hash_candidates.append(_b64e(h_sha))

    lst = inner["twofa"].get("backup_code_hashes") or []
    # Find a matching hash
    match: Optional[str] = None
    for candidate in hash_candidates:
        if candidate in lst:
            match = candidate
            break
    if not match:
        return False
    # Remove the matched hash
    lst.remove(match)
    inner["twofa"]["backup_code_hashes"] = lst

    meta = hdr.setdefault("meta", {})
    meta["twofa_backup_count"] = len(lst)

    n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
    _write_all(p, hdr, n2, ct2)
    try:
        log_event_encrypted(username, "CODE", "2FA Backup Code Used")
        if not changed and not missing and not new_:
            from security.baseline_signer import update_baseline
            update_baseline(username, verify_after=False, who="2FA Backup Code Used")
        else:
            log_event_encrypted(username, "CODE", "2FA Code used But basline not ok before use")
    except Exception as e:
        log.error(f"[ERROR] 2FA Backup Code log error: {e}")
        pass

    return True

def get_2fa_backup_count_quick(username: str) -> int:
    p = _user_id_file(username)
    if not p.exists():
        return 0
    try:
        hdr = _read_header(p)
        return int(hdr.get("meta", {}).get("twofa_backup_count", 0))
    except Exception:
        return 0

# -------- LOGIN backup codes (forgot-password / Yubi) --------


def gen_backup_codes(username: str, b_type: str = "login", n: int = 10, L: int = 12, *, password_for_identity: str) -> list[str]:
    """Generate backup codes and persist them to the encrypted identity store.

    - Returns plaintext codes (show once).
    - Persists *hashed* codes (identity_store handles the hashing + backwards compatibility).

    b_type:
      - "login": recovery/login backup codes (default length L)
      - "2fa": authenticator backup codes (fixed length 8)
    """
    SAFE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    if b_type not in ("login", "2fa"):
        raise ValueError("b_type must be 'login' or '2fa'")

    length = 8 if b_type == "2fa" else int(L)
    import secrets
    codes_plain = ["".join(secrets.choice(SAFE_ALPHABET) for _ in range(int(length))) for _ in range(int(n))]

    # Persist via the existing, single source-of-truth writers
    if b_type == "login":
        replace_login_backup_codes(username, password_for_identity, codes_plain)
    else:
        replace_backup_codes(username, password_for_identity, codes_plain)

    return codes_plain

def replace_login_backup_codes(username: str, password: str, codes_plain: list[str]) -> list[str]:
    """
    Replace the list of login backup codes (forgot‑password / Yubi) in the
    identity store.  Codes are hashed using a memory‑hard KDF (Argon2id)
    with the per‑user salt.  Legacy SHA‑256 hashes remain valid for
    backwards compatibility.
    """
    p = _user_id_file(username, ensure_parent=True)
    dmk, inner, hdr = create_or_open_with_password(username, password)

    salt = base64.b64decode(inner["twofa"]["salt"])
    hashes: list[str] = []
    for c in (codes_plain or []):
        c = (c or "").strip()
        if not c:
            continue
        try:
            from vault_store.kdf_utils import derive_key_argon2id_safe
            h_bytes = derive_key_argon2id_safe(c, salt, length=32)
        except Exception:
            h_bytes = hashlib.sha256(salt + c.encode("utf-8")).digest()
        hashes.append(_b64e(h_bytes))

    rec = inner.setdefault("recovery", {})
    rec["login_backup_code_hashes"] = hashes

    meta = hdr.setdefault("meta", {})
    meta["login_backup_count"] = len(hashes)

    n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
    _write_all(p, hdr, n2, ct2)
    return codes_plain

def consume_login_backup_code(username: str, password: str, code_plain: str) -> bool:
    """
    Validate and consume a login backup code.  Supports both legacy
    SHA‑256 and Argon2id hashes for backwards compatibility.  Returns
    True if the code was found and removed.
    """
    p = _user_id_file(username, ensure_parent=True)
    dmk, inner, hdr = create_or_open_with_password(username, password)

    salt = base64.b64decode(inner["twofa"]["salt"])
    
    # do quick basline check before change, if shows error then no baseline update will be done
    from security.baseline_signer import checkbasline
    changed, missing, new_, mac_ok = checkbasline(username)

    code_norm = (code_plain or "").strip()
    hash_candidates: list[str] = []
    try:
        from vault_store.kdf_utils import derive_key_argon2id_safe
        h_argon = derive_key_argon2id_safe(code_norm, salt, length=32)
        hash_candidates.append(_b64e(h_argon))
    except Exception:
        pass
    h_sha = hashlib.sha256(salt + code_norm.encode("utf-8")).digest()
    hash_candidates.append(_b64e(h_sha))

    rec = inner.setdefault("recovery", {})
    lst = rec.get("login_backup_code_hashes") or []
    match: Optional[str] = None
    for candidate in hash_candidates:
        if candidate in lst:
            match = candidate
            break
    log.debug(f"[2FA] code candidate match: {match is not None}")
    if not match:
        return False
    lst.remove(match)
    rec["login_backup_code_hashes"] = lst
    meta = hdr.setdefault("meta", {})
    meta["login_backup_count"] = len(lst)
    n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
    _write_all(p, hdr, n2, ct2)
    try:
        log_event_encrypted(username, "CODE", "Yubi Key Backup Code Used")
        if not changed and not missing and not new_:
            from security.baseline_signer import update_baseline
            update_baseline(username, verify_after=False, who="Yubi Backup Code Used")
        else:
            log_event_encrypted(username, "CODE", "Yubi Code used But basline not ok before use")
    except Exception as e:
        log.error(f"[ERROR] Yubi Backup Code log error: {e}")
        pass
    
    return True

def get_login_backup_count_quick(username: str) -> int:
    p = _user_id_file(username)
    if not p.exists():
        return 0
    try:
        hdr = _read_header(p)
        return int(hdr.get("meta", {}).get("login_backup_count", 0))
    except Exception:
        return 0

# -------- Quick TOTP header flag --------

def mark_totp_header(username: str, password: str | None, enabled: bool) -> bool:
    """
    Set header.meta.has_totp = enabled.
    Tries header-only write first; falls back to full open with password.
    """
    p = _user_id_file(username)
    try:
        hdr, n2, ct2 = _read_header_nonce_ct(p)  # header-only
        meta = hdr.setdefault("meta", {})
        meta["has_totp"] = bool(enabled)
        _write_all(p, hdr, n2, ct2)
        return True
    except Exception:
        pass

    if not password:
        return False

    try:
        dmk, inner, hdr = create_or_open_with_password(username, password)
        meta = hdr.setdefault("meta", {})
        meta["has_totp"] = bool(enabled)
        n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
        _write_all(p, hdr, n2, ct2)
        return True
    except Exception:
        return False

def has_totp_quick(username: str) -> bool:
    """
    Fast, no-password check. Reads header.meta.has_totp from the identity file.
    """
    p = _user_id_file(username)
    if not p.exists():
        return False
    try:
        hdr = _read_header(p)
        return bool(hdr.get("meta", {}).get("has_totp", False))
    except Exception:
        return False


def derive_identity_kek(username: str, password: str) -> bytes:
    """Derive the *identity-store* KEK from the password wrapper salt.

    This is distinct from the vault/Yubi password context salt.
    It is required to open the identity store (TOTP/backup codes) during
    DPAPI passwordless login (DPAPI v3 bundle).
    """
    if not password:
        raise ValueError("password required")

    p = _user_id_file(username)
    if not p.exists():
        raise FileNotFoundError("identity file not found")

    hdr = _read_header(p)
    pw = None
    for w in (hdr.get("wrappers") or []):
        if isinstance(w, dict) and w.get("type") == "password":
            pw = w
            break
    if not pw:
        raise RuntimeError("identity has no password wrapper")

    salt = _b64d(pw["salt"])
    return derive_key_argon2id(password, salt)

# -------- YubiKey config --------

def set_yubi_config(
    username: str,
    password: str,
    *,
    mode: str,                # "yk_hmac_wrap" | "yk_hmac_gate"
    serial: str | None,
    slot: int | None,
    salt_b64: str | None = None,
    nonce_b64: str | None = None,
    wrapped_b64: str | None = None,
    ykman_path: str | None = None,
    mk_hash_b64: str | None = None, 
    ykman_hash: str | None = None,
) -> None:
    p = _user_id_file(username, ensure_parent=True)
    dmk, inner, hdr = create_or_open_with_password(username, password)

    yubi = inner.setdefault("yubi", {})
    yubi["mode"] = mode
    if serial is not None:     yubi["serial"] = str(serial)
    if slot is not None:       yubi["slot"] = int(slot)
    if salt_b64 is not None:   yubi["salt_b64"] = salt_b64
    if nonce_b64 is not None:  yubi["nonce_b64"] = nonce_b64
    if wrapped_b64 is not None:yubi["wrapped_b64"] = wrapped_b64
    if ykman_path is not None: yubi["ykman_path"] = ykman_path
    if mk_hash_b64 is not None:yubi["mk_hash_b64"] = mk_hash_b64
    if ykman_hash is not None: yubi["ykman_hash"] = ykman_hash

    meta = hdr.setdefault("meta", {})
    meta["yubi_enabled"] = True
    meta["yubi_mode"] = mode
    if mk_hash_b64 is not None:
        meta["mk_hash_b64"] = mk_hash_b64     # ← mirror hash into header for passwordless verify

    n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
    _write_all(p, hdr, n2, ct2)

def get_yubi_config_public(username: str) -> dict | None:
    """
    Read only the public header meta (no password required).
    Returns a dict with yubi_mode and mk_hash_b64 if present.
    """
    p = _user_id_file(username, ensure_parent=False)
    if not p.exists():
        return None
    hdr = _read_header(p)
    meta = hdr.get("meta", {}) if isinstance(hdr, dict) else {}
    out = {
        "mode": meta.get("yubi_mode"),
        "mk_hash_b64": meta.get("mk_hash_b64"),
    }
    # Only return if at least mode present
    return out if out.get("mode") else None

def verify_recovery_key(username: str, recovery_key: str) -> bool:
    """
    Passwordless verification of a Recovery Key.
    Compares sha256(MK) with mk_hash_b64 mirrored in the identity header.
    Falls back to private get_yubi_config with blank password if header is missing.
    """
    try:
        pub = get_yubi_config_public(username) or {}
        mkh = (pub or {}).get("mk_hash_b64")
        if mkh:
            from auth.pw.utils_recovery import recovery_key_to_mk
            import base64, hashlib
            mk = recovery_key_to_mk(recovery_key)
            return hashlib.sha256(mk).digest() == base64.b64decode(mkh)
    except Exception:
        pass

    return False

def get_yubi_config(username: str, password: str) -> dict | None:
    _, inner, _ = create_or_open_with_password(username, password)
    return inner.get("yubi")

def set_ykman_trusted_hash(username: str, password: str, ykman_hash: str) -> None:
    dmk, inner, hdr = create_or_open_with_password(username, password)
    yubi = inner.setdefault("yubi", {})
    yubi["ykman_hash"] = ykman_hash
    n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
    _write_all(_user_id_file(username, ensure_parent=True), hdr, n2, ct2)

def get_ykman_trusted_hash(username: str, password: str) -> str | None:
    _, inner, _ = create_or_open_with_password(username, password)
    yubi = inner.get("yubi") or {}
    return yubi.get("ykman_hash")

def get_yubi_meta_quick(username: str) -> tuple[bool, str | None]:
    """
    Quick, no-password check for UI: (enabled?, mode) from header meta.
    """
    p = _user_id_file(username)
    if not p.exists():
        return (False, None)
    try:
        hdr = _read_header(p)
        meta = hdr.get("meta", {})
        return (bool(meta.get("yubi_enabled", False)), meta.get("yubi_mode"))
    except Exception:
        return (False, None)

def clear_yubi_config(username: str, password: str) -> None:
    """
    Remove YubiKey config and mark headers accordingly.
    """
    p = identities_file(username, ensure_parent=True)
    dmk, inner, hdr = create_or_open_with_password(username, password)
    inner["yubi"] = {}
    meta = hdr.setdefault("meta", {})
    meta["yubi_enabled"] = False
    meta["yubi_mode"] = None
    # rewrite payload + keep updated header.meta
    n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
    _write_all(p, hdr, n2, ct2)

# -------- user changed password --------
def rewrap_identity_password(username: str, old_password: str, new_password: str) -> tuple[bool, str]:
    """
    Change-password path (not forgot-password):
    Rewrap ONLY the identity 'password' wrapper from old_password -> new_password,
    preserving payload and other wrappers (recovery/yubi/etc).
    """
    try:
        username = (username or "").strip()
        if not username or not old_password or not new_password:
            return False, _tr("missing username or password")

        # Open with OLD password (proves user knows it)
        dmk, inner, hdr = create_or_open_with_password(username, old_password)

        # Update password wrapper using NEW password (keep salt unless you want to rotate)
        wrappers = hdr.setdefault("wrappers", [])
        pw = next((w for w in wrappers if (w.get("type") or "").lower() == "password"), None)
        if not pw:
            return False, _tr("identity has no password wrapper")

        pw_salt = _b64d(pw["salt"]) if pw.get("salt") else os.urandom(16)
        kek_new = derive_key_argon2id(new_password, pw_salt)

        # Keep alignment with create_or_open_with_password()
        n1, ct1 = _aes_enc(kek_new, b"KQID-DMK", dmk)

        pw.update({"salt": _b64e(pw_salt), "nonce": _b64e(n1), "ct": _b64e(ct1)})

        # Re-encrypt payload with SAME DMK (payload unchanged logically)
        n2, ct2 = _aes_enc(dmk, b"KQID-PAYLOAD", _canon(inner))
        _write_all(_user_id_file(username, ensure_parent=True), hdr, n2, ct2)

        return True, ""
    except Exception as e:
        log.error("[identity] rewrap_identity_password failed for %s: %r", username, e)
        return False, _tr("could not update identity password wrapper") + f": {e}"

