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
import os, json, base64, logging
from pathlib import Path
from typing import Dict, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

from app.paths import shared_key_file

log = logging.getLogger("keyquorum")

B64  = lambda b: base64.b64encode(b).decode("ascii")
B64D = lambda s: base64.b64decode(s.encode("ascii"))

def _enc_json(path: Path, key: bytes, obj: dict) -> None:
    """Encrypt and write JSON using AES-GCM (32-byte key)."""
    if len(key) != 32:
        raise ValueError("share_keys: user_key must be 32 bytes")
    aead, n = AESGCM(key), os.urandom(12)
    pt = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ct = aead.encrypt(n, pt, None)
    payload = {"n": B64(n), "ct": B64(ct)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")

def _dec_json(path: Path, key: bytes) -> dict:
    """Decrypt JSON previously written by _enc_json()."""
    if len(key) != 32:
        raise ValueError("share_keys: user_key must be 32 bytes")
    payload = json.loads(path.read_text(encoding="utf-8"))
    aead = AESGCM(key)
    pt = aead.decrypt(B64D(payload["n"]), B64D(payload["ct"]), None)
    return json.loads(pt.decode("utf-8"))

def _bundle(pub_x: bytes, pub_ed: bytes, user_id: str) -> Dict[str, str]:
    return {
        "id": user_id,
        "pub_x25519": B64(pub_x),
        "pub_ed25519": B64(pub_ed),
    }

def ensure_share_keys(username: str, user_key: bytes) -> Tuple[Dict[str, str],
                                                               x25519.X25519PrivateKey,
                                                               ed25519.Ed25519PrivateKey]:
    """
    Ensure persistent per-user X25519/Ed25519 keys exist.
    Returns (public_bundle, priv_x25519, priv_ed25519).
    """
    if len(user_key) != 32:
        raise ValueError("user_key must be 32 bytes")

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

def export_share_id_json(username: str, user_key: bytes) -> dict:
    """Return a minimal public Share ID (no private material)."""
    pub, _px, _pe = ensure_share_keys(username, user_key)
    return {
        "ver": 1,
        "id": pub["id"],
        "pub_x25519": pub["pub_x25519"],
        "pub_ed25519": pub["pub_ed25519"],
    }
