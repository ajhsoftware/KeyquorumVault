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

"""Per-user persistent X25519/Ed25519 key management"""
import os, json, base64, logging, secrets
from pathlib import Path
from typing import Dict, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

from app.paths import shared_key_file
from native.native_core import get_core

log = logging.getLogger("keyquorum")

B64  = lambda b: base64.b64encode(b).decode("ascii")
B64D = lambda s: base64.b64decode(s.encode("ascii"))

def _is_session_handle(key_or_session) -> bool:
    return isinstance(key_or_session, int) and key_or_session > 0

def _enc_json(path: Path, key_or_session, obj: dict) -> None:
    """Encrypt and write JSON using either AES-GCM (legacy 32-byte key) or native session encryption."""
    pt = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)

    if _is_session_handle(key_or_session):
        core = get_core()
        if core is None:
            raise RuntimeError("share_keys: native core not loaded")
        iv = secrets.token_bytes(12)
        ct_ba, tag_ba = core.session_encrypt(int(key_or_session), iv, pt)
        payload = {"ver": 2, "mode": "native", "iv": B64(iv), "ct": B64(bytes(ct_ba)), "tag": B64(bytes(tag_ba))}
        path.write_text(json.dumps(payload), encoding="utf-8")
        return

    if not isinstance(key_or_session, (bytes, bytearray, memoryview)) or len(key_or_session) != 32:
        raise ValueError("share_keys: user_key must be 32 bytes or a native session handle")
    aead, n = AESGCM(bytes(key_or_session)), os.urandom(12)
    ct = aead.encrypt(n, pt, None)
    payload = {"ver": 1, "mode": "aesgcm", "n": B64(n), "ct": B64(ct)}
    path.write_text(json.dumps(payload), encoding="utf-8")

def _dec_json(path: Path, key_or_session) -> dict:
    """Decrypt JSON previously written by _enc_json()."""
    payload = json.loads(path.read_text(encoding="utf-8"))

    if _is_session_handle(key_or_session):
        mode = payload.get("mode") or ("native" if payload.get("ver") == 2 else "")
        if mode == "native" or (payload.get("iv") and payload.get("tag")):
            core = get_core()
            if core is None:
                raise RuntimeError("share_keys: native core not loaded")
            pt_ba = core.session_decrypt(int(key_or_session), B64D(payload["iv"]), B64D(payload["ct"]), B64D(payload["tag"]))
            return json.loads(bytes(pt_ba).decode("utf-8"))

    if not isinstance(key_or_session, (bytes, bytearray, memoryview)) or len(key_or_session) != 32:
        raise ValueError("share_keys: user_key must be 32 bytes or a native session handle")
    aead = AESGCM(bytes(key_or_session))
    nonce = payload.get("n") or payload.get("nonce")
    if not nonce:
        raise ValueError("share_keys: invalid legacy payload")
    pt = aead.decrypt(B64D(nonce), B64D(payload["ct"]), None)
    return json.loads(pt.decode("utf-8"))

def _bundle(pub_x: bytes, pub_ed: bytes, user_id: str) -> Dict[str, str]:
    return {
        "id": user_id,
        "pub_x25519": B64(pub_x),
        "pub_ed25519": B64(pub_ed),
    }

def ensure_share_keys(username: str, user_key) -> Tuple[Dict[str, str],
                                                               x25519.X25519PrivateKey,
                                                               ed25519.Ed25519PrivateKey]:
    """
    Ensure persistent per-user X25519/Ed25519 keys exist.
    Returns (public_bundle, priv_x25519, priv_ed25519).
    """
    if not (_is_session_handle(user_key) or (isinstance(user_key, (bytes, bytearray, memoryview)) and len(user_key) == 32)):
        raise ValueError("user_key must be 32 bytes or a native session handle")

    keyfile = shared_key_file(username, ensure_parent=True)

    if keyfile.exists():
        data = _dec_json(keyfile, user_key)
        priv_x  = x25519.X25519PrivateKey.from_private_bytes(B64D(data["priv_x"]))
        priv_ed = ed25519.Ed25519PrivateKey.from_private_bytes(B64D(data["priv_ed"]))
        pub = _bundle(
            priv_x.public_key().public_bytes_raw(),
            priv_ed.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            username
        )
        return pub, priv_x, priv_ed

    # --- create new pair ---
    priv_x  = x25519.X25519PrivateKey.generate()
    priv_ed = ed25519.Ed25519PrivateKey.generate()
    data = {
        "priv_x": B64(priv_x.private_bytes_raw()),
        "priv_ed": B64(priv_ed.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )),
        "created": True,
        "ver": 1,
    }
    keyfile.parent.mkdir(parents=True, exist_ok=True)
    _enc_json(keyfile, user_key, data)

    pub = _bundle(
        priv_x.public_key().public_bytes_raw(),
        priv_ed.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        username
    )
    return pub, priv_x, priv_ed

def export_share_id_json(username: str, user_key) -> dict:
    """Return a minimal public Share ID (no private material)."""
    pub, _px, _pe = ensure_share_keys(username, user_key)
    return {
        "ver": 1,
        "id": pub["id"],
        "pub_x25519": pub["pub_x25519"],
        "pub_ed25519": pub["pub_ed25519"],
    }
