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

import logging, json, hashlib
from pathlib import Path
from typing import Tuple, List
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

log = logging.getLogger("keyquorum")

# ---------- helpers ----------

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def _map_rel(code_root: Path, rel: str) -> Path:
    """
    Map a manifest-relative path to an absolute on-disk path.
    Supports entries that begin with '_internal/...'.
    """
    rel = rel.replace("\\", "/")
    if rel.startswith("_internal/"):
        return code_root / "_internal" / rel.split("/", 1)[1]
    return code_root / rel

def _require_exists(p: Path, label: str) -> Tuple[bool, str]:
    if not p.exists():
        return False, f"{label} missing: {p}"
    if p.is_dir():
        return False, f"{label} is a directory, expected a file: {p}"
    return True, ""

# ---------- public API ----------

def verify_signed_manifest(
    manifest_path: str | Path,
    signature_path: str | Path,
    public_key_path: str | Path,
    code_root: str | Path,
) -> Tuple[bool, str]:
    """
    Verify a signed manifest and the hashes of all listed files.

    Returns (ok, message)
      ok      : True if signature is valid AND all file hashes match
      message : 'OK' or a human-friendly error/summary
    """
    man = Path(manifest_path)
    sig = Path(signature_path)
    pub = Path(public_key_path)
    root = Path(code_root)

    # 0) Ensure inputs exist
    for p, lbl in ((man, "Manifest"), (sig, "Signature"), (pub, "Public key")):
        ok, msg = _require_exists(p, lbl)
        if not ok:
            return False, msg

    # 1) Verify signature over raw manifest bytes
    try:
        data = man.read_bytes()
        signature = sig.read_bytes()
        pubkey_obj = serialization.load_pem_public_key(pub.read_bytes())
        if not isinstance(pubkey_obj, Ed25519PublicKey):
            return False, "Public key is not Ed25519."
        pubkey_obj.verify(signature, data)
    except InvalidSignature:
        return False, "Manifest signature invalid."
    except Exception as e:
        return False, f"Signature verification error: {e}"

    # 2) Parse manifest JSON
    try:
        manifest = json.loads(data.decode("utf-8"))
        files = manifest.get("files", {})
        if not isinstance(files, dict):
            return False, "Manifest format error: 'files' must be an object of {relpath: sha256}."
    except Exception as e:
        return False, f"Manifest parse error: {e}"

    # 3) Check all file hashes
    missing: List[str] = []
    mismatched: List[str] = []
    for rel, expected in files.items():
        try:
            p = _map_rel(root, str(rel))
            if not p.exists():
                missing.append(str(rel))
                continue
            if expected:
                got = _sha256_file(p)
                if got != expected:
                    mismatched.append(f"{rel} (expected {expected[:8]}…, got {got[:8]}…)")
        except Exception as e:
            mismatched.append(f"{rel} (error: {e})")

    if missing or mismatched:
        parts = []
        if missing:
            parts.append(f"Missing: {len(missing)} file(s) (e.g., {', '.join(missing[:5])})")
        if mismatched:
            parts.append(f"Hash mismatches: {len(mismatched)} (e.g., {', '.join(mismatched[:3])})")
        return False, "; ".join(parts)

    return True, "OK"

def collect_mismatch_report(
    manifest_path: str | Path,
    code_root: str | Path,
    limit: int = 200
) -> str:
    """
    Produce a verbose, multi-line report of missing/mismatched files
    (no signature check; assumes manifest is already trusted).
    Useful for logging after verification fails.
    """
    man = Path(manifest_path)
    root = Path(code_root)
    try:
        manifest = json.loads(man.read_text(encoding="utf-8"))
        files = manifest.get("files", {})
        if not isinstance(files, dict):
            return "Manifest format error: 'files' is not an object."
    except Exception as e:
        return f"Could not read/parse manifest: {e}"

    lines: List[str] = []
    count = 0
    for rel, expected in files.items():
        if count >= limit:
            lines.append(f"... truncated after {limit} entries …")
            break
        p = _map_rel(root, str(rel))
        if not p.exists():
            lines.append(f"[MISSING] {rel}")
            count += 1
            continue
        try:
            got = _sha256_file(p)
        except Exception as e:
            lines.append(f"[ERROR]   {rel} → {e}")
            count += 1
            continue
        if expected and got != expected:
            lines.append(f"[MISMATCH] {rel}\n  expected: {expected}\n  got:      {got}")
            count += 1

    if not lines:
        return "No differences found."

    return "\n".join(lines)
