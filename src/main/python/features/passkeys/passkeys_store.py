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
# --- minimal helpers (place near the top or with other helpers) ---
import base64, time, json, hashlib, secrets
from dataclasses import dataclass, asdict


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64ud(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


# Expect these to be provided by pkstore.set_io(...)
_READ_BLOB = _WRITE_BLOB = _ENC = _DEC = None


def set_io(read_blob, write_blob, enc, dec):
    global _READ_BLOB, _WRITE_BLOB, _ENC, _DEC
    _READ_BLOB, _WRITE_BLOB, _ENC, _DEC = read_blob, write_blob, enc, dec


# ----- simple model -----
@dataclass
class Entry:
    id: str
    rp_id: str
    user_id_b64: str
    alg: int
    rk: bool
    uv: bool
    display_name: str
    public_key_b64: str
    private_key_b64: str
    sign_count: int = 0
    created: float = 0.0
    updated: float = 0.0

@dataclass
class Model:
    entries: list[Entry]

_STORE_NAME = "passkeys_store.json"

def _load_model() -> Model:
    if _READ_BLOB is None:
        return Model(entries=[])
    raw = _READ_BLOB(_STORE_NAME)
    if not raw:
        return Model(entries=[])
    try:
        data = json.loads(_DEC(raw).decode("utf-8"))
        ents = [Entry(**e) for e in data.get("entries", [])]
        return Model(entries=ents)
    except Exception:
        return Model(entries=[])

def _save_model(m: Model) -> None:
    if _WRITE_BLOB is None: return
    data = {"entries": [asdict(e) for e in m.entries]}
    _WRITE_BLOB(_STORE_NAME, _ENC(json.dumps(data).encode("utf-8")))

def _find(m: Model, *, rp_id: str, cred_id_b64: str | None = None) -> Entry | None:
    for e in m.entries:
        if e.rp_id == rp_id and (cred_id_b64 is None or e.id == cred_id_b64):
            return e
    return None

# ----- crypto helpers (Ed25519 default) -----
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
import base64, json, time, secrets, hashlib, cbor2


def _b64u(b: bytes) -> str:
    """Base64url encode (no padding)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64ud(s: str | bytes) -> bytes:
    """Base64url decode with proper padding (accepts str or bytes)."""
    if isinstance(s, bytes):
        s = s.decode("ascii", "strict")
    s = (s or "").strip().replace("\n", "")
    s += "=" * (-len(s) % 4)  # pad to multiple of 4
    return base64.urlsafe_b64decode(s.encode("ascii"))


def _new_es256_keypair() -> tuple[bytes, bytes, bytes]:
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key()
    sk_der = sk.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    nums = pk.public_numbers()
    x = nums.x.to_bytes(32, "big"); y = nums.y.to_bytes(32, "big")
    return sk_der, x, y



def _new_ed25519_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pb = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return pv, pb

def _load_ed25519_private(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)

# ----- API used by the bridge -----
def create_credential(*, rp_id: str, user_id: bytes, alg: int = -8,
                      resident_key: bool = True, require_uv: bool = False,
                      display_name: str = "") -> dict:
    """
    Create a new credential for rp_id and return data for the provider.
    Supports -8 (Ed25519) and -7 (ES256).
    """
    cred_id = secrets.token_bytes(32)
    now = time.time()
    m = _load_model()

    if alg == -8:  # ---- Ed25519
        pv_raw, pb_raw = _new_ed25519_keypair()
        entry = Entry(
            id=_b64u(cred_id), rp_id=rp_id, user_id_b64=_b64u(user_id),
            alg=-8, rk=bool(resident_key), uv=bool(require_uv),
            display_name=display_name or "",
            public_key_b64=_b64u(pb_raw),
            private_key_b64=_b64u(_ENC(pv_raw)),  # encrypted!
            sign_count=0, created=now, updated=now,
        )
        m.entries = [e for e in m.entries if e.id != entry.id]
        m.entries.append(entry); _save_model(m)

        public_key_cose = cbor2.dumps({1: 1, 3: -8, -1: 6, -2: pb_raw})  # OKP/Ed25519
        # Build a response structure similar to WebAuthn's PublicKeyCredential
        return {
            "id": entry.id,
            # rawId should mirror id (base64url) for WebAuthn compatibility
            "rawId": entry.id,
            # type indicates this is a public-key credential
            "type": "public-key",
            # userHandle is the base64url-encoded user id
            "userHandle": entry.user_id_b64,
            # Provide COSE-encoded public key for Relying Parties
            "publicKeyCose": _b64u(public_key_cose),
            # Provide a JWK representation for debugging/optional usage
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(pb_raw)},
        }

    if alg == -7:  # ---- ES256 (P-256)
        sk_der, x, y = _new_es256_keypair()
        entry = Entry(
            id=_b64u(cred_id), rp_id=rp_id, user_id_b64=_b64u(user_id),
            alg=-7, rk=bool(resident_key), uv=bool(require_uv),
            display_name=display_name or "",
            public_key_b64=_b64u(x + y),          # convenience only
            private_key_b64=_b64u(_ENC(sk_der)),  # encrypted DER/PKCS8
            sign_count=0, created=now, updated=now,
        )
        m.entries = [e for e in m.entries if e.id != entry.id]
        m.entries.append(entry); _save_model(m)

        # COSE EC2: {1:2 (EC2), 3:-7 (ES256), -1:1 (P-256), -2:x, -3:y}
        public_key_cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})
        # Build a response structure similar to WebAuthn's PublicKeyCredential
        return {
            "id": entry.id,
            "rawId": entry.id,
            "type": "public-key",
            "userHandle": entry.user_id_b64,
            "publicKeyCose": _b64u(public_key_cose),
            # Optional JWK for debugging and potential WebAuthn usage
            "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": _b64u(x), "y": _b64u(y)},
        }

    raise ValueError("Unsupported alg; use -7 (ES256) or -8 (Ed25519)")

from cryptography.exceptions import InvalidTag

def _dec_or_plain(b64: str) -> bytes:
    raw = _b64ud(b64)
    # Fast plaintext hints (legacy): 32 bytes (Ed25519 raw) or DER (0x30)
    if len(raw) == 32 or (raw[:1] == b"\x30"):
        return raw
    try:
        return _DEC(raw)  # your injected decrypt
    except (InvalidTag, ValueError, Exception):
        # Legacy unencrypted or different key — use as-is
        return raw


def get_assertion(*, rp_id: str, challenge: bytes,
                  allow_credential_ids: list[str] | None = None,
                  require_uv: bool = False) -> dict:
    """
    Return a WebAuthn-style assertion for the given rp_id/challenge.
    - Ed25519 (-8): signs (authenticatorData || SHA256(clientDataJSON)) with Ed25519.
    - ES256 (-7): signs same message with ECDSA(SHA-256) and returns a DER signature.
    """
    m = _load_model()

    # Pick credential
    target = None
    if allow_credential_ids:
        for cid in allow_credential_ids:
            target = _find(m, rp_id=rp_id, cred_id_b64=cid)
            if target:
                break
    if target is None:
        target = _find(m, rp_id=rp_id, cred_id_b64=None)
    if target is None:
        raise ValueError("No credential for this RP")

    # Build authenticatorData and clientDataJSON
    rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    UP, UV = 0x01, 0x04
    flags = UP | (UV if (require_uv or target.uv) else 0)

    sign_count = target.sign_count + 1
    authenticator_data = rp_hash + bytes([flags]) + sign_count.to_bytes(4, "big")

    client_data_json = json.dumps({
        "type": "webauthn.get",
        "challenge": _b64u(challenge),
        "origin": f"https://{rp_id}",
        "crossOrigin": False,
    }, separators=(",", ":")).encode("utf-8")
    client_hash = hashlib.sha256(client_data_json).digest()

    msg = authenticator_data + client_hash

    # ---- Sign depending on alg --------------------------------------------
    if target.alg == -8:  # Ed25519
        pv_raw = _dec_or_plain(target.private_key_b64)
        pv = Ed25519PrivateKey.from_private_bytes(pv_raw)
        signature = pv.sign(authenticator_data + client_hash)

    elif target.alg == -7:  # ES256 (optional branch; requires you've stored DER PKCS8)
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes, serialization
        sk_der = _dec_or_plain(target.private_key_b64)
        sk = serialization.load_der_private_key(sk_der, password=None)
        signature = sk.sign(authenticator_data + client_hash, ec.ECDSA(hashes.SHA256())) # DER-encoded ECDSA

    else:
        raise ValueError(f"Unsupported alg {target.alg}")

    # Persist counter
    target.sign_count = sign_count
    target.updated = time.time()
    _save_model(m)

    return {
        "id": target.id,
        # rawId mirrors id for WebAuthn compatibility
        "rawId": target.id,
        "type": "public-key",
        "userHandle": target.user_id_b64,
        "authenticatorData": _b64u(authenticator_data),
        "clientDataJSON": _b64u(client_data_json),
        "signature": _b64u(signature),
    }

# ----------------------------------------------------------------------
# Simple helpers for desktop UI (list / rename / delete)
# ----------------------------------------------------------------------
def list_entries() -> list[Entry]:
    """
    Return a copy of all stored passkey entries.
    Desktop UI uses this to populate the table.
    """
    return list(_load_model().entries)


def delete_by_id(cred_id_b64: str) -> None:
    """
    Remove a credential from the store by its id (base64url).
    Safe no-op if not found.
    """
    m = _load_model()
    m.entries = [e for e in m.entries if e.id != cred_id_b64]
    _save_model(m)


def rename_entry(cred_id_b64: str, new_display_name: str) -> None:
    """
    Update the display_name for a credential and bump its updated timestamp.
    """
    new_display_name = (new_display_name or "").strip()
    if not new_display_name:
        return
    m = _load_model()
    now = time.time()
    changed = False
    for e in m.entries:
        if e.id == cred_id_b64:
            e.display_name = new_display_name
            e.updated = now
            changed = True
            break
    if changed:
        _save_model(m)

