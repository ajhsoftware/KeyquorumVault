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
import time, base64, hashlib, secrets, urllib.parse as _url
from typing import List, Optional, Tuple
import logging
log = logging.getLogger("keyquorum")
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Runtime deps
try:
    import pyotp
except Exception:
    pyotp = None

# Use vault APIs for CRUD
from vault_store.vault_store import load_vault, add_vault_entry, save_vault
# --- field wrapping uses the NATIVE session API (no raw key bytes) ---
from native.native_core import get_core
from qtpy.QtCore import QCoreApplication

# ==============================
# ---------- helpers ----------
# ==============================

def _tr(text: str) -> str:
    return QCoreApplication.translate("authenticator_store", text)

def _field_encrypt(session_handle: int, plaintext: bytes) -> str:
    """Encrypt a small secret field using the native session (AES-256-GCM).

    Returns base64 of: iv(12) | tag(16) | ciphertext.
    """
    if not isinstance(session_handle, int) or not session_handle:
        raise RuntimeError(_tr("Vault must be unlocked (native session missing)."))

    core = get_core()
    nonce = secrets.token_bytes(12)
    ct_ba, tag_ba = core.session_encrypt(session_handle, nonce, plaintext)
    blob = nonce + bytes(tag_ba) + bytes(ct_ba)
    return base64.b64encode(blob).decode("ascii")

def _field_decrypt(session_handle: int, enc_b64: str) -> bytes:
    """Decrypt base64(iv|tag|ct) produced by _field_encrypt()."""
    if not isinstance(session_handle, int) or not session_handle:
        raise RuntimeError(_tr("Vault must be unlocked (native session missing)."))
    if not enc_b64:
        return b""
    raw = base64.b64decode(enc_b64.encode("ascii"))
    if len(raw) < (12 + 16):
        raise ValueError("bad wrapped field")
    iv = raw[:12]
    tag = raw[12:28]
    ct = raw[28:]
    core = get_core()
    pt_ba = core.session_decrypt(session_handle, iv, ct, tag)
    try:
        return bytes(pt_ba)
    finally:
        try:
            core.secure_wipe(pt_ba)
        except Exception:
            pass

# NOTE: Strict DLL-only mode.
# A historical Python AESGCM fallback existed here. It is intentionally removed
# to avoid accidentally treating a native session handle (int) as raw key bytes.

def _normalize_algo(algo: str) -> str:
    a = (algo or "SHA1").upper()
    return a if a in {"SHA1","SHA256","SHA512"} else "SHA1"

def _pack_secret(session_handle: int, secret_b32: str) -> str:
    return _field_encrypt(session_handle, secret_b32.encode("utf-8"))

def _unpack_secret(session_handle: int, enc_b64: str) -> str:
    return _field_decrypt(session_handle, enc_b64).decode("utf-8")

def _now() -> float:
    return time.time()

# ==============================
# ---------- public API (vault-backed) ----------
# ==============================

AUTH_CATEGORY_NAME = "Authenticator"

def _entries_list(vu) -> List[dict]:
    """Normalize whatever load_vault returns into a list of entry dicts."""
    if isinstance(vu, dict):
        if isinstance(vu.get("entries"), list):
            return vu["entries"]
        if isinstance(vu.get("vault"), list):
            return vu["vault"]
        return []
    return list(vu or [])

def list_authenticators(username: str, session_handle: int) -> List[dict]:
    """
    Return authenticator entries stored inside the user's vault.
    """
    vu = load_vault(username, session_handle)
    entries = _entries_list(vu)
    return [
        e for e in entries
        if isinstance(e, dict) and (
            e.get("_type") == "authenticator" or
            (e.get("Category") == AUTH_CATEGORY_NAME) or
            (str(e.get("category","")).lower() == "authenticator")
        )
    ]

def add_authenticator(
    username: str,
    session_handle: int,
    *,
    label: str,
    account: str,
    issuer: str,
    secret_base32: str,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> dict:
    sb32 = (secret_base32 or "").replace(" ", "")
    if not sb32:
        raise ValueError(_tr("Secret is empty"))

    enc = _pack_secret(session_handle, sb32)
    entry = {
        "id": secrets.token_hex(8),
        "_type": "authenticator",
        "Category": AUTH_CATEGORY_NAME,          # UI category (hidden/system)
        "category": AUTH_CATEGORY_NAME,          # defensive duplicate
        "label": (label or account or issuer or "Authenticator").strip(),
        "account": (account or "").strip(),
        "issuer": (issuer or "").strip(),
        "secret_enc_b64": enc,
        "digits": int(digits or 6),
        "period": int(period or 30),
        "algorithm": _normalize_algo(algorithm),
        "created_ts": _now(),
        "updated_ts": _now(),
    }
    # persist a single entry
    add_vault_entry(username, session_handle, entry)
    return entry

# ==============================
# ---------- otpauth export (URI + QR image) ----------
# ==============================

def build_otpauth_uri(session_handle: int, entry: dict) -> str:
    """
    Reconstruct a standards-compliant otpauth:// URI from a stored authenticator entry.
    """
    issuer  = (entry.get("issuer") or "").strip()
    account = (entry.get("account") or "").strip()
    label   = (entry.get("label") or account or issuer or "Authenticator").strip()

    # Decrypt base32 secret
    secret_b32 = _unpack_secret(session_handle, entry["secret_enc_b64"]).replace(" ", "")

    digits = int(entry.get("digits", 6) or 6)
    period = int(entry.get("period", 30) or 30)
    algo   = _normalize_algo(entry.get("algorithm", "SHA1"))
    
    # Label format: issuer:account (if both present)
    if issuer and account:
        label_full = f"{issuer}:{account}"
    else:
        label_full = label or account or issuer or "Authenticator"

    label_enc = _url.quote(label_full)
    q = {
        "secret": secret_b32,
        "digits": str(digits),
        "period": str(period),
        "algorithm": algo,
    }
    if issuer:
        q["issuer"] = issuer
        
    return f"otpauth://totp/{label_enc}?" + _url.urlencode(q)

def export_otpauth_qr_png(session_handle: int, entry: dict, out_path: str) -> str:
    """
    Create a PNG QR code for the given entry's otpauth URI.
    Tries 'segno' (pure-Python). Falls back to 'qrcode' if available.
    Returns the path written.
    """
    uri = build_otpauth_uri(int(session_handle), entry)

    # Try segno first (no pillow dependency)
    try:
        import segno # type: ignore
        q = segno.make(uri, error='M')
        q.save(out_path, scale=6, border=2)  # ~300-400px
        return out_path
    except Exception:
        pass

    # Fallback to qrcode
    try:
        import qrcode
        img = qrcode.make(uri)
        img.save(out_path)
        return out_path
    except Exception as e:
        raise RuntimeError(_tr("No QR generator available. Install 'segno' or 'qrcode'.")) from e
    
def export_otpauth_qr_bytes(session_handle: int, entry: dict) -> bytes:
    """
    Return PNG bytes of the QR (useful for showing in a dialog without touching disk).
    """
    uri = build_otpauth_uri(int(session_handle), entry)

    # segno path
    try:
        import io, segno # type: ignore
        buf = io.BytesIO()
        segno.make(uri, error='M').save(buf, kind='png', scale=6, border=2)
        return buf.getvalue()
    except Exception:
        pass

    # qrcode path
    try:
        import io, qrcode
        buf = io.BytesIO()
        qrcode.make(uri).save(buf, format=_tr("PNG"))
        return buf.getvalue()
    except Exception as e:
        raise RuntimeError(_tr("No QR generator available. Install 'segno' or 'qrcode'.")) from e



# ===================
# ---------- SESSION-BASED migration (DLL ONLY) ----------
# ===================

def rewrap_authenticator_entries_with_sessions(entries: list[dict], old_session: int, new_session: int):
    """
    Rewrap authenticator secrets using native session handles only.

    Returns: (ok: bool, msg: str, changed: int, failed: int)
    """
    if not entries:
        return True, _tr("No authenticator entries to migrate."), 0, 0

    if not isinstance(old_session, int) or old_session <= 0:
        return False, _tr("Old native session missing."), 0, 0

    if not isinstance(new_session, int) or new_session <= 0:
        return False, _tr("New native session missing."), 0, 0

    if old_session == new_session:
        return True, _tr("No session change detected."), 0, 0

    changed = 0
    failed = 0
    had_secrets = 0

    for e in entries:
        if not isinstance(e, dict):
            continue

        enc = e.get("secret_enc_b64")
        if not enc:
            continue

        had_secrets += 1

        try:
            secret_plain = _field_decrypt(old_session, enc)
            e["secret_enc_b64"] = _field_encrypt(new_session, secret_plain)
            e["updated_ts"] = _now()
            changed += 1
        except Exception as ex:
            failed += 1
            try:
                log.warning("[AUTH-MIGRATE] entry_id=%s failed: %s", e.get("id"), ex)
            except Exception:
                pass

    if had_secrets == 0:
        return True, _tr("No encrypted authenticator secrets found to migrate."), 0, 0

    if changed == 0:
        return False, _tr("Migration failed: could not decrypt any secrets with the previous native session."), 0, failed

    if failed > 0:
        return True, _tr("Migrated {changed} authenticator(s), {failed} failed.").format(
            changed=changed, failed=failed
        ), changed, failed

    return True, _tr("Migrated {changed} authenticator(s).").format(changed=changed), changed, 0


def migrate_authenticator_store_with_sessions(username: str, old_session: int, new_session: int):
    """
    DLL-only authenticator migration.
    Load vault with NEW live session, rewrap authenticator secrets from
    OLD session -> NEW session, then save back with NEW session.
    """
    try:
        vu = load_vault(username, new_session)
        entries = _entries_list(vu)

        auths = [
            e for e in entries
            if isinstance(e, dict) and (
                e.get("_type") == "authenticator" or
                (e.get("Category") == AUTH_CATEGORY_NAME) or
                (str(e.get("category", "")).lower() == "authenticator")
            )
        ]

        try:
            log.info(
                "[AUTH-MIGRATE] username=%s total_entries=%s auth_entries=%s",
                username, len(entries or []), len(auths)
            )
        except Exception:
            pass

        ok, msg, changed, failed = rewrap_authenticator_entries_with_sessions(
            auths, old_session, new_session
        )

        if ok and changed:
            save_vault(username, new_session, entries)

        return ok, msg, changed, failed

    except Exception as e:
        return False, _tr("Authenticator migration error: {err}").format(err=e), 0, 0



# ==============================
# ---------- key migration (password change / salt rotation / change password) ----------
# ==============================

def rewrap_authenticator_entries_old(entries: list[dict], old_key: bytes, new_key: bytes):
    """
    Returns: (ok: bool, msg: str, changed: int, failed: int)
    ok=True means migration completed (even if some entries failed).
    ok=False means nothing migrated and likely key mismatch / major issue.
    """
    if not entries:
        return True, _tr("No authenticator entries to migrate."), 0, 0
    if not old_key or not new_key or old_key == new_key:
        return True, _tr("No key change detected."), 0, 0

    changed = 0
    failed = 0
    had_secrets = 0

    for e in entries:
        if not isinstance(e, dict):
            continue
        enc = e.get("secret_enc_b64")
        if not enc:
            continue
        had_secrets += 1
        try:
            secret_plain = _unpack_secret(old_key, enc)
            e["secret_enc_b64"] = _pack_secret(new_key, secret_plain)
            e["updated_ts"] = _now()
            changed += 1
        except Exception:
            failed += 1

    if had_secrets == 0:
        return True, _tr("No encrypted authenticator secrets found to migrate."), 0, 0

    if changed == 0:
        return False, _tr("Migration failed: could not decrypt any secrets with the previous key."), 0, failed

    if failed > 0:
        return True, _tr("Migrated {changed} authenticator(s), {failed} failed.").format(changed=changed, failed=failed), changed, failed

    return True, _tr("Migrated {changed} authenticator(s).").format(changed=changed), changed, 0

def migrate_authenticator_store_old(username: str, old_key: bytes, new_key: bytes):
    """
    Migrate authenticator secrets after a password change / salt rotation.

    Important detail:
    - The vault itself is decrypted/saved using NEW key (post-password-change).
    - The authenticator field secret (secret_enc_b64) may still be wrapped with OLD key.
    So we:
    1) load vault with NEW key
    2) rewrap secret_enc_b64 from OLD -> NEW
    3) save vault with NEW key
    """
    try:
        vu = load_vault(username, new_key)
        entries = _entries_list(vu)
        auths = [
            e for e in entries
            if isinstance(e, dict) and (
                e.get("_type") == "authenticator" or
                (e.get("Category") == AUTH_CATEGORY_NAME) or
                (str(e.get("category","")).lower() == "authenticator")
            )
        ]
        ok, msg, changed, failed = rewrap_authenticator_entries(auths, old_key, new_key)
        if ok and changed:
            # entries list contains the same dict objects; save whole vault back.
            save_vault(username, new_key, entries)
        return ok, msg, changed, failed
    except Exception as e:
        return False, _tr("Authenticator migration error: {err}").format(err=e), 0, 0

def update_authenticator(username: str, session_handle: int, entry_id: str, **updates) -> bool:
    vu = load_vault(username, session_handle)
    entries = _entries_list(vu)
    changed = False

    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("_type") == "authenticator" and e.get("id") == entry_id:
            for k in ("label", "account", "issuer", "digits", "period", "algorithm"):
                if k in updates and updates[k] is not None:
                    e[k] = updates[k]
            if "secret_base32" in updates and updates["secret_base32"]:
                sb32 = (updates["secret_base32"] or "").replace(" ", "")
                e["secret_enc_b64"] = _pack_secret(session_handle, sb32)
            e["updated_ts"] = _now()
            # keep it in the system category
            e["Category"] = AUTH_CATEGORY_NAME
            e["category"] = AUTH_CATEGORY_NAME
            changed = True
            break

    if changed:
        save_vault(username, session_handle, entries)
    return changed

def delete_authenticator(username: str, session_handle: int, entry_id: str) -> bool:
    entries = _entries_list(load_vault(username, session_handle))
    new_entries = [e for e in entries if not (
        isinstance(e, dict) and e.get("_type") == "authenticator" and e.get("id") == entry_id
    )]
    if len(new_entries) != len(entries):
        save_vault(username, session_handle, new_entries)
        return True
    return False

def get_current_code(session_handle: int, entry: dict) -> Tuple[str, int]:
    if pyotp is None:
        return ("—", 0)
    try:
        algo = str(entry.get("algorithm", "SHA1")).upper()
        digest = {
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512,
        }.get(algo, hashlib.sha1)

        secret_b32 = _unpack_secret(session_handle, entry["secret_enc_b64"])
        period = int(entry.get("period", 30))
        digits = int(entry.get("digits", 6))

        totp = pyotp.TOTP(secret_b32, digits=digits, interval=period, digest=digest)
        now = int(time.time())
        code = totp.now()
        rem = period - (now % period)
        return (code, int(rem))
    except Exception:
        return ("—", 0)

# ==============================
# ---------- otpauth parsing + QR (image) ----------
# ==============================

def parse_otpauth_uri(uri: str) -> Optional[dict]:
    try:
        u = _url.urlparse(uri)
        if u.scheme != "otpauth" or u.netloc.lower() != "totp":
            return None
        label_full = _url.unquote(u.path.lstrip("/"))
        label, account = label_full, ""
        if ":" in label_full:
            label, account = [s.strip() for s in label_full.split(":", 1)]
        q = dict(_url.parse_qsl(u.query, keep_blank_values=True))
        secret = (q.get("secret") or "").replace(" ", "")
        if not secret:
            return None
        return {
            "label": label or q.get("issuer","") or account or "Authenticator",
            "account": account,
            "issuer": q.get("issuer",""),
            "secret_base32": secret,
            "digits": int(q.get("digits", 6) or 6),
            "period": int(q.get("period", 30) or 30),
            "algorithm": _normalize_algo(q.get("algorithm", "SHA1")),
        }
    except Exception:
        return None

def add_from_otpauth_uri(username: str, session_handle: int, uri: str) -> dict:
    p = parse_otpauth_uri(uri)
    if not p: raise ValueError(_tr("Invalid otpauth URI"))
    return add_authenticator(username, session_handle, **p)

def import_otpauth_from_qr_image(image_path: str) -> Optional[str]:
    """
    Read a QR image and return the first otpauth:// URI.
    Uses OpenCV's QRCodeDetector only (no zbar dependency).
    """
    try:
        import cv2
        import numpy as np

        # Read the image safely
        data = np.fromfile(image_path, dtype=np.uint8)
        frame = cv2.imdecode(data, cv2.IMREAD_COLOR)
        if frame is None:
            return None

        det = cv2.QRCodeDetector()

        # Try detectAndDecodeMulti (newer OpenCV)
        try:
            ok, infos, points, _ = det.detectAndDecodeMulti(frame)
            payloads = infos if (ok and infos) else []
        except Exception:
            # Fallback: detectAndDecode (single QR)
            payload, pts = det.detectAndDecode(frame)
            payloads = [payload] if payload else []

        for s in payloads:
            if isinstance(s, str) and s.startswith("otpauth://"):
                return s.strip()
    except Exception as e:
            log.warning("QR decode error: %s", e)

    return None
