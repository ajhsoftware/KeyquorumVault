# Keyquorum Vault - cli Testing Utility
# Copyright (C) 2026 Anthony Hatton
#
# This file is part of Keyquorum Vault.
#
# Keyquorum Vault is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Keyquorum Vault is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#============================================================================

# Keyquorum Vault - Standalone Decrypt Tool
# GPL-3.0-or-later
#
# Supports:
#   - Vault envelope JSON (iv/tag/vault_data)
#   - Identity store binary format (KQID1)
#
# No imports from application code.

from __future__ import annotations

import argparse
import base64
import getpass
import json
import struct
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ===== Argon2 parameters (must match app) =====
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 256_000
ARGON2_PARALLELISM = 2
ARGON2_KEY_LEN = 32


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def derive_argon2(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_KEY_LEN,
        type=Type.ID,
    )


# ============================================================
# VAULT FORMAT  (JSON envelope)
# ============================================================

def decrypt_vault(path: Path, salt_path: Path, password: str):
    obj = json.loads(path.read_text())

    if not all(k in obj for k in ("iv", "tag", "vault_data")):
        raise ValueError("Not a vault envelope file")

    iv = b64d(obj["iv"])
    tag = b64d(obj["tag"])
    ct = b64d(obj["vault_data"])

    salt = salt_path.read_bytes()
    key = derive_argon2(password, salt)

    aes = AESGCM(key)
    plaintext = aes.decrypt(iv, ct + tag, None)

    return json.loads(plaintext.decode())


# ============================================================
# IDENTITY STORE FORMAT  (binary KQID1)
# ============================================================

def decrypt_identity(path: Path, password: str):
    data = path.read_bytes()

    if not data.startswith(b"KQID1"):
        raise ValueError("Not an identity store file")

    header_len = struct.unpack(">I", data[5:9])[0]
    header = json.loads(data[9:9 + header_len].decode())

    offset = 9 + header_len
    payload_nonce = data[offset:offset + 12]
    payload_ct = data[offset + 12:]

    # find password wrapper
    wrappers = header.get("wrappers", [])
    pw_wrap = next((w for w in wrappers if w.get("type") == "password"), None)
    if not pw_wrap:
        raise ValueError("Password wrapper not found")

    pw_salt = b64d(pw_wrap["salt"])
    pw_nonce = b64d(pw_wrap["nonce"])
    pw_ct = b64d(pw_wrap["ct"])

    kek = derive_argon2(password, pw_salt)

    aes = AESGCM(kek)
    dmk = aes.decrypt(pw_nonce, pw_ct, b"KQID-DMK")

    aes_payload = AESGCM(dmk)
    plaintext = aes_payload.decrypt(payload_nonce, payload_ct, b"KQID-PAYLOAD")

    return json.loads(plaintext.decode())


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Keyquorum standalone decrypt tool")
    parser.add_argument("--file", required=True, help="Vault or identity file path")
    parser.add_argument("--salt", help="Salt file path (required for vault)")
    parser.add_argument("--pretty", action="store_true")

    args = parser.parse_args()

    file_path = Path(args.file)
    password = getpass.getpass("Password: ")

    # --- inside main() after reading args + password ---

    p = Path(args.file)

    raw = p.read_bytes()

    # 1) Identity store (binary) detection
    if raw.startswith(b"KQID1"):
        try:
            result = decrypt_identity(p, password)
            print("[OK] Identity store decrypted.")
            print(json.dumps(result, indent=2 if args.pretty else None))
            return 0
        except Exception as e:
            print(f"[ERROR] Identity decrypt failed: {e}")
            return 3

    # 2) Vault (JSON envelope) detection
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        print("[ERROR] Unknown file format. Not KQID1 and not JSON.")
        return 2

    if all(k in obj for k in ("iv", "tag", "vault_data")):
        if not args.salt:
            print("[ERROR] Vault decrypt requires --salt <salt_file_path>.")
            return 2
        try:
            result = decrypt_vault(p, Path(args.salt), password)
            print("[OK] Vault decrypted.")
            print(json.dumps(result, indent=2 if args.pretty else None))
            return 0
        except Exception as e:
            print(f"[ERROR] Vault decrypt failed: {e}")
            return 3

    print("[ERROR] JSON file is not a vault envelope (missing iv/tag/vault_data).")
    return 2

# tools/check_identity_header.py
import argparse, base64, json, struct
from pathlib import Path

def b64_try(s: str):
    try:
        return base64.b64decode(s.encode(), validate=True)
    except Exception:
        return None

def parse_header(p: Path) -> dict:
    raw = p.read_bytes()
    if not raw.startswith(b"KQID1"):
        raise ValueError("Missing KQID1 magic (not an identity store)")
    if len(raw) < 9:
        raise ValueError("Truncated identity file")

    header_len = struct.unpack(">I", raw[5:9])[0]
    if header_len <= 0 or header_len > (len(raw) - 9):
        raise ValueError(f"Invalid header_len={header_len} (file_len={len(raw)})")

    hdr_bytes = raw[9:9+header_len]
    header = json.loads(hdr_bytes.decode("utf-8"))
    if not isinstance(header, dict):
        raise ValueError("Header JSON is not an object")
    return header

def validate_header(header: dict) -> list[str]:
    probs = []
    wrappers = header.get("wrappers")
    if not isinstance(wrappers, list):
        probs.append("missing/invalid 'wrappers' list")

    pw = None
    if isinstance(wrappers, list):
        for w in wrappers:
            if isinstance(w, dict) and w.get("type") == "password":
                pw = w
                break
    if pw is None:
        probs.append("no wrapper with type='password'")
    else:
        for k in ("salt", "nonce", "ct"):
            if k not in pw:
                probs.append(f"password wrapper missing '{k}'")
        if "nonce" in pw:
            b = b64_try(str(pw["nonce"]))
            if b is None or len(b) != 12:
                probs.append("password wrapper nonce invalid (needs base64 of 12 bytes)")
        if "salt" in pw:
            b = b64_try(str(pw["salt"]))
            if b is None or len(b) < 8:
                probs.append("password wrapper salt invalid (base64 decode failed/too short)")
        if "ct" in pw:
            b = b64_try(str(pw["ct"]))
            if b is None or len(b) < 16:
                probs.append("password wrapper ct invalid (base64 decode failed/too short)")

    meta = header.get("meta")
    if isinstance(meta, dict):
        ms = (meta.get("master_salt_b64") or "").strip()
        if ms:
            b = b64_try(ms)
            if b is None:
                probs.append("meta.master_salt_b64 is not valid base64")
            else:
                # Change 16 if your EXPECTED_SALT_LEN differs
                if len(b) != 16:
                    probs.append(f"meta.master_salt_b64 length={len(b)} (expected 16)")

    return probs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("identity_store", help="Path to identity store file (e.g. identity.kq)")
    ap.add_argument("--inspect", action="store_true", help="Print header JSON")
    args = ap.parse_args()

    p = Path(args.identity_store)
    header = parse_header(p)
    probs = validate_header(header)

    if args.inspect:
        print(json.dumps(header, indent=2))

    if probs:
        print("\n[FAIL] Identity header problems:")
        for pr in probs:
            print(f" - {pr}")
        raise SystemExit(10)

    print("[OK] Identity header looks valid.")
    # Helpful summary (salt presence)
    meta = header.get("meta") or {}
    ms = (meta.get("master_salt_b64") or "").strip()
    print(f"[INFO] master_salt_in_header={'YES' if ms else 'NO'}")

if __name__ == "__main__":
    main()

