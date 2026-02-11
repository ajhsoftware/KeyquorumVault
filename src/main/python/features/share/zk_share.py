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

import os
import json
import base64
import datetime
import hashlib
import logging
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

log = logging.getLogger("keyquorum")

B64  = lambda b: base64.b64encode(b).decode("ascii")
B64D = lambda s: base64.b64decode(s.encode("ascii"))


def _hkdf_derive(shared_secret: bytes, info: bytes = b"kq-share-v1") -> bytes:
    """Derive a 32-byte key from an X25519 shared secret using HKDF-SHA256."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)


def _now_iso() -> str:
    """UTC timestamp (seconds precision) with trailing 'Z'."""
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _canon(obj: Dict[str, Any]) -> bytes:
    """Deterministic JSON encoding for signatures and hashing."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def make_share_packet(
    entry_json: Dict[str, Any],
    sender_priv_x25519: x25519.X25519PrivateKey,
    sender_priv_ed25519: ed25519.Ed25519PrivateKey,
    sender_pub_bundle: Dict[str, str],
    recipient_pub_x25519_b64: str,
    recipient_id: str,
    scope: str = "entry",
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Create a signed, encrypted share packet for a single entry.

    - Encrypts the canonicalized entry JSON under a random AES-GCM key.
    - Wraps that key using X25519(ECDH)+HKDF and AES-GCM to the recipient.
    - Signs the whole packet (minus the 'auth' field) using Ed25519.

    Returns a JSON-serializable dict safe to send over the wire.
    """
    policy = policy or {"read_only": True, "import_as": "entry", "expires_at": None}

    # 1) Content encryption
    entry_key = AESGCM.generate_key(bit_length=256)
    aead = AESGCM(entry_key)
    n1 = os.urandom(12)
    pt = _canon(entry_json)
    ct = aead.encrypt(n1, pt, None)

    # 2) Wrap key with ECDH (sender priv � recipient pub)
    recipient_pub = x25519.X25519PublicKey.from_public_bytes(B64D(recipient_pub_x25519_b64))
    shared = sender_priv_x25519.exchange(recipient_pub)
    wrap_key = _hkdf_derive(shared)  # 32 bytes
    aead_wrap = AESGCM(wrap_key)
    n2 = os.urandom(12)
    wrapped_key = aead_wrap.encrypt(n2, entry_key, None)

    # Optional integrity meta: hash of canonical payload
    payload_hash = hashlib.sha256(pt).digest()

    packet: Dict[str, Any] = {
        "ver": 1,
        "created_at": _now_iso(),
        "scope": scope,
        "sender": {
            "id": sender_pub_bundle["id"],
            "pub_ed25519": sender_pub_bundle["pub_ed25519"],   # base64
            "pub_x25519": sender_pub_bundle["pub_x25519"],     # base64
        },
        "recipient": {
            "id": recipient_id,
            "pub_x25519": recipient_pub_x25519_b64,
        },
        "policy": policy,
        "payload": {
            "aead": "AES-GCM",
            "nonce": B64(n1),
            "ciphertext": B64(ct),
            "tag_included": True,
        },
        "wrapped_key": {
            "kdf": "HKDF-SHA256",
            "info": "kq-share-v1",
            "nonce": B64(n2),
            "ciphertext": B64(wrapped_key),
        },
        "meta": {
            "payload_hash_alg": "SHA256",
            "payload_hash": B64(payload_hash),
        },
    }

    # Sign (without 'auth')
    to_sign = _canon(packet)
    sig = sender_priv_ed25519.sign(to_sign)
    packet["auth"] = {"sig_alg": "Ed25519", "signature": B64(sig)}

    log.debug("[ZK_SHARE] Packet created for recipient=%s (scope=%s, ver=%s)", recipient_id, scope, packet["ver"])
    return packet


def verify_and_decrypt_share_packet(
    packet: Dict[str, Any],
    recipient_priv_x25519: x25519.X25519PrivateKey,
) -> Dict[str, Any]:
    """
    Verify and decrypt a share packet for the recipient.

    Steps:
      1) Verify Ed25519 signature (if 'auth' present).
      2) X25519(ECDH)+HKDF derive wrap key, decrypt wrapped entry key.
      3) Decrypt payload with entry key (AES-GCM).
      4) If 'meta.payload_hash' exists, verify it matches the decrypted payload.

    Returns the original entry JSON.
    Raises on signature failure; AES-GCM decrypt raises on tampering.
    """
    # 1) Verify signature (if present)
    auth = packet.get("auth")
    if auth:
        sig = B64D(auth["signature"])
        pkt_no_auth = dict(packet)
        pkt_no_auth.pop("auth", None)
        to_verify = _canon(pkt_no_auth)

        sender_pub_ed = ed25519.Ed25519PublicKey.from_public_bytes(
            B64D(packet["sender"]["pub_ed25519"])
        )
        sender_pub_ed.verify(sig, to_verify)  # raises on failure

    # 2) Unwrap entry_key
    sender_pub_x = x25519.X25519PublicKey.from_public_bytes(
        B64D(packet["sender"]["pub_x25519"])
    )
    shared = recipient_priv_x25519.exchange(sender_pub_x)
    wrap_key = _hkdf_derive(shared)

    aead_wrap = AESGCM(wrap_key)
    n2 = B64D(packet["wrapped_key"]["nonce"])
    wrapped_key = B64D(packet["wrapped_key"]["ciphertext"])
    entry_key = aead_wrap.decrypt(n2, wrapped_key, None)

    # 3) Decrypt payload
    aead = AESGCM(entry_key)
    n1 = B64D(packet["payload"]["nonce"])
    ct = B64D(packet["payload"]["ciphertext"])
    plaintext = aead.decrypt(n1, ct, None)
    entry_json = json.loads(plaintext.decode("utf-8"))

    # 4) Optional integrity meta check
    meta = packet.get("meta") or {}
    if meta.get("payload_hash_alg") == "SHA256" and isinstance(meta.get("payload_hash"), str):
        expected = B64D(meta["payload_hash"])
        actual = hashlib.sha256(plaintext).digest()
        if expected != actual:
            raise ValueError("payload hash mismatch")

    log.debug("[ZK_SHARE] Packet verified & decrypted (scope=%s)", packet.get("scope"))
    return entry_json
