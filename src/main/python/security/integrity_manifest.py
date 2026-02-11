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

# ---------------------------------------------------------------------
# App-wide manifest integrity verification (Ed25519 + SHA256).
# Looks for signing artifacts under:
#   <app_root>/_internal/resources/signing/{manifest.json, manifest.sig, public_key.pem}
# Then verifies the signature and checks every file hash relative to <app_root>.
#
# Usage in main.py (frozen and dev-safe):
#   from integrity_manifest import verify_manifest_auto
#   ok, msg = verify_manifest_auto(show_ui=True, parent=self)
# ---------------------------------------------------------------------

from __future__ import annotations
from pathlib import Path
from typing import Tuple, Optional, Dict
import sys, json, hashlib

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("integrity_manifest", text)


# Optional Qt UI for error dialogs (safe to import even if not present)
try:
    from qtpy.QtWidgets import QMessageBox, QWidget
except Exception:  # pragma: no cover
    QMessageBox = None
    QWidget = None  


# ---------- Helpers -----------------------------------------------------------

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_dev_app_root(dev_app_name: str) -> Optional[Path]:
    """
    Best-effort search for target/<dev_app_name> when running unfrozen.
    Walks up from this file and checks common dev layouts.
    """
    here = Path(__file__).resolve()
    for base in [here, *here.parents]:
        cand = base / "target" / dev_app_name
        if (cand / "_internal").exists():
            return cand
    # fallback: ../../target/<name>
    try:
        cand = here.parents[2] / "target" / dev_app_name
        if (cand / "_internal").exists():
            return cand
    except Exception:
        pass
    return None


def _resolve_app_root(app_root: Optional[Path], dev_app_name: str) -> Tuple[Optional[Path], str]:
    """
    Determine app_root:
      - If frozen: folder containing the EXE.
      - Else: target/<dev_app_name> (if found).
      - Else: return None with a reason string.
    """
    if app_root:
        return Path(app_root).resolve(), "from-arg"
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent, "frozen"
    dev = _find_dev_app_root(dev_app_name)
    if dev:
        return dev.resolve(), "dev"
    return None, _tr("Could not locate target") + f"/{dev_app_name}" + _tr(" (dev run) and not frozen.")


def _load_public_key(pem_bytes: bytes):
    """
    Load Ed25519 public key from PEM using cryptography (no import at module import time).
    """
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(pem_bytes)


def _verify_signature(pub_pem: bytes, manifest_bytes: bytes, sig_bytes: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    pub = _load_public_key(pub_pem)
    try:
        pub.verify(sig_bytes, manifest_bytes)  # Ed25519
        return True
    except InvalidSignature:
        return False


# ---------- Core API ----------------------------------------------------------

def verify_manifest(app_root: Path,
                    *,
                    show_ui: bool = False,
                    parent = None,
                    log_each: bool = False) -> Tuple[bool, str]:
    """
    Verify the signed manifest and every file hash relative to app_root.

    Returns:
        (ok, message)
        - ok=True  -> all good
        - ok=False -> message contains concise reason; if show_ui=True and Qt is available, a dialog is shown.

    Args:
        app_root: Folder that contains the EXE (and _internal/).
        show_ui:  If True and Qt is available, show QMessageBox on failure.
        parent:   Optional Qt parent widget for the dialog.
        log_each: If True, include first few mismatches/missing files in the message.
    """
    # Signing artifacts
    sign_dir = Path(app_root) / "_internal" / "resources" / "signing"
    manifest_path = sign_dir / "manifest.json"
    sig_path = sign_dir / "manifest.sig"
    pubkey_path = sign_dir / "public_key.pem"

    # Existence check
    missing_artifacts = [p.name for p in (manifest_path, sig_path, pubkey_path) if not p.exists()]
    if missing_artifacts:
        msg = _tr("Signing artifacts missing") + f": {', '.join(missing_artifacts)}"
        if show_ui and QMessageBox is not None:
            QMessageBox.critical(parent, _tr("Manifest Verification"), msg)
        return False, msg

    # Verify signature
    manifest_bytes = manifest_path.read_bytes()
    sig_bytes = sig_path.read_bytes()
    pub_pem = pubkey_path.read_bytes()

    if not _verify_signature(pub_pem, manifest_bytes, sig_bytes):
        msg = _tr("Signature verification failed for manifest.json.")
        if show_ui and QMessageBox is not None:
            QMessageBox.critical(parent, _tr("Manifest Verification"), msg)
        return False, msg

    # Parse manifest and validate files
    try:
        manifest: Dict[str, Dict[str, str] | list[str] | str] = json.loads(manifest_bytes.decode("utf-8"))
    except Exception:
        msg = _tr("manifest.json is not valid JSON.")
        if show_ui and QMessageBox is not None:
            QMessageBox.critical(parent, _tr("Manifest Verification"), msg)
        return False, msg

    files_map: Dict[str, str] = dict(manifest.get("files", {}))  # relpath -> sha256 hex

    missing: list[str] = []
    mismatched: list[str] = []

    for rel, expected_hex in files_map.items():
        rel_norm = rel.replace("\\", "/").lstrip("/")
        p = Path(app_root) / rel_norm
        if not p.exists():
            missing.append(rel_norm)
            continue
        got_hex = _sha256_file(p)
        if got_hex.lower() != str(expected_hex).lower():
            mismatched.append(f"{rel_norm}"+ _tr(" (exp ") + f"{expected_hex[:8]}… " + _tr("got ") + f"{got_hex[:8]}…)")

    if missing or mismatched:
        parts: list[str] = []
        if missing:
            parts.append(_tr("Missing") + f": {len(missing)}")
            if log_each:
                parts.append("  e.g. " + ", ".join(missing[:5]))
        if mismatched:
            parts.append(_tr("Mismatched") + f": {len(mismatched)}")
            if log_each:
                parts.append("  e.g. " + ", ".join(mismatched[:5]))
        msg = "; ".join(parts) if parts else _tr("Files missing or mismatched.")
        if show_ui and QMessageBox is not None:
            QMessageBox.critical(parent, _tr("Manifest Verification"), _tr("Signed verification failed:") + f"\n{msg}")
        return False, msg

    manifest_id = hashlib.sha256(manifest_bytes).hexdigest()[-5:]  # last 5 hex chars
    return True, _tr("OK (manifest id …") + f"{manifest_id})"



def verify_manifest_auto(app_root: Optional[Path] = None,
                         *,
                         show_ui: bool = False,
                         parent: Optional["QWidget"] = None, # type: ignore
                         dev_app_name: str = "keyquorum-vault",
                         log_each: bool = False) -> Tuple[bool, str]:
    """
    Convenience wrapper:
      - Resolve the correct app_root (EXE folder when frozen; target/<dev_app_name> in dev).
      - Run verify_manifest().
    """
    resolved, how = _resolve_app_root(app_root, dev_app_name)
    if not resolved:
        msg = _tr("Manifest verification skipped:") + f" {how}"
        if show_ui and QMessageBox is not None:
            QMessageBox.warning(parent, _tr("Manifest Verification"), msg)
        return False, msg

    return verify_manifest(resolved, show_ui=show_ui, parent=parent, log_each=log_each)


__all__ = ["verify_manifest", "verify_manifest_auto"]
