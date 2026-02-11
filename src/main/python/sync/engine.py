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

from typing import Dict, Tuple
import os, time, shutil, tempfile, json, hashlib
from vault_store.vault_store import verify_vault_owner
from .providers import (
    ProviderBase, LocalPathProvider, SyncError, ConflictError, NotFound, sha256_file
)
import logging
log = logging.getLogger("keyquorum")
import secrets
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("add_entry_dialog", text)

# --- JSON encrypt/decrypt used by _enc_json_write/_enc_json_read -----------
def encrypt_json_file(path: str, key: bytes, data: dict | list) -> None:
    try:
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if key and len(key) >= 32:
            nonce = os.urandom(12)
            ct = AESGCM(key[:32]).encrypt(nonce, payload, None)
            with open(path, "wb") as f:
                f.write(nonce + ct)
        else:
            raise ValueError("no key")
    except Exception:
        # plaintext fallback
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

def decrypt_json_file(path: str, key: bytes) -> dict | list:
    try:
        b = open(path, "rb").read()
        if key and len(b) > 12:
            nonce, ct = b[:12], b[12:]
            pt = AESGCM(key[:32]).decrypt(nonce, ct, None)
            return json.loads(pt.decode("utf-8"))
    except Exception:
        pass
    try:
        return json.loads(open(path, "r", encoding="utf-8").read())
    except Exception:
        return {}

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def verify_integrity(local_path: str, remote_path: str) -> bool:
    return sha256_file(local_path) == sha256_file(remote_path)

def wrap_encrypt(user_key: bytes, blob: bytes) -> bytes:
    """
    Second-layer encryption for the CLOUD COPY ONLY.
    Uses AES-GCM with 'user_key' (32 bytes recommended).
    """
    if not AESGCM:
        # If cryptography isn't available, skip wrapping safely
        return blob
    aead = AESGCM(user_key)
    nonce = secrets.token_bytes(12)
    ct = aead.encrypt(nonce, blob, b"cloud-wrap")
    return nonce + ct

def wrap_decrypt(user_key: bytes, blob: bytes) -> bytes:
    if not AESGCM:
        return blob
    if len(blob) < 13:
        # not a wrapped blob; return as-is
        return blob
    if len(blob) <= 12:
        return blob
    nonce, ct = blob[:12], blob[12:]
    aead = AESGCM(user_key)
    try:
        return aead.decrypt(nonce, ct, b"cloud-wrap")
    except Exception:
        # if it wasn't wrapped, decryption fails -> return original
        return blob

# --- Provider registry NOT in use Future Update Maybe ("onedrive": OneDriveProvider(), "gdrive": GoogleDriveProvider(), ...) ---
PROVIDERS: Dict[str, ProviderBase] = {
    "localpath": LocalPathProvider(),
}

class SyncEngine:
    """
    File-level sync with optional extra AES-GCM wrapping for cloud storage.
    Local vault file remains your standard encrypted .kqvault.
    Remote (cloud) file is wrapped when 'sync.cloud_wrap' is True.
    """
    def __init__(self, load_user_db, save_user_db, get_local_vault_path):
        self._load = load_user_db
        self._save = save_user_db
        self._get_vault = get_local_vault_path

    def provider(self, cfg: Dict) -> ProviderBase:
        name = ((cfg.get("sync") or {}).get("provider") or "localpath")
        p = PROVIDERS.get(name)
        if not p:
            raise SyncError(f"Unknown provider: {name}")
        return p

    def configured(self) -> Tuple[Dict, ProviderBase]:
        cfg = self._load()
        sc = cfg.get("sync") or {}
        p = self.provider(cfg)
        if not (sc.get("enabled") and p.is_configured(sc)):
            raise NotFound(_tr("engine"))
        return cfg, p

    def describe(self) -> str:
        try:
            cfg, p = self.configured()
            return p.describe(cfg["sync"])
        except NotFound:
            return _tr("Sync: disabled")

    def set_localpath(self, remote_path: str) -> None:
        cfg = self._load()
        sc = cfg.get("sync") or {}
        sc.update({
            "enabled": True,
            "provider": "localpath",
            "remote_path": remote_path,
            "remote_id": "",
            "last_sync_ts": 0,
            "last_local_sha256": "",
            "last_remote_sha256": "",
            "last_remote_version": "",
            # leave cloud_wrap as-is if already set
        })
        cfg["sync"] = sc
        self._save(cfg)

    # -------- core sync --------
    def sync_now(self, user_key: bytes, interactive=False) -> str:
        # --- Ownership check before sync ---
        try:
            vp = getattr(self, "_get_vault", lambda: None)()
            cu = getattr(self, "_current_user", None) or getattr(self, "username", None)
            if vp and cu and not verify_vault_owner(vp, cu):
                log.info(f"[SYNC] Blocked — vault owner mismatch for {cu}")
                return _tr("blocked-owner")
        except Exception as e:
            log.error(f"[SYNC] [ERROR] Ownership check failed: {e}")

        # --- main sync logic starts here ---
        cfg, p = self.configured()
        sc = cfg["sync"]
        local_path = self._get_vault()
        cloud_wrap = bool(sc.get("cloud_wrap"))

        # Ensure local exists or bootstrap from remote
        if not os.path.isfile(local_path):
            if p.remote_exists(sc):
                # download → unwrap if needed → write local
                self._download_to_local(p, sc, user_key, local_path, cloud_wrap)
            else:
                raise NotFound(_tr("Neither local nor remote vault file exists"))

        local_sha = sha256_file(local_path)
        local_mtime = os.path.getmtime(local_path)

        if not p.remote_exists(sc):
            # First push
            self._upload_from_local(p, sc, user_key, local_path, cloud_wrap)
            sc.update({
                "last_sync_ts": time.time(),
                "last_local_sha256": sha256_file(local_path),
                "last_remote_sha256": self._remote_sha(p, sc),
            })
            self._save(cfg)
            return _tr("pushed")

        remote_sha, remote_mtime, remote_ver = p.remote_meta(sc)

        # Nothing changed since last sync
        if (remote_sha == sc.get("last_remote_sha256") and
            local_sha  == sc.get("last_local_sha256")):
            return _tr("noop")

        # Both sides changed since last sync → conflict
        if (remote_mtime > sc.get("last_sync_ts", 0) and
            local_mtime  > sc.get("last_sync_ts", 0) and
            remote_sha != local_sha):
            result = self._resolve_conflict(p, sc, user_key, local_path, cloud_wrap,
                                            remote_mtime, local_mtime)
            self._save(cfg)
            return result

        # One-way changes
        if remote_mtime > sc.get("last_sync_ts", 0) and remote_sha != local_sha:
            # PULL
            self._download_to_local(p, sc, user_key, local_path, cloud_wrap)
            sc.update({
                "last_sync_ts": time.time(),
                "last_local_sha256": sha256_file(local_path),
                "last_remote_sha256": self._remote_sha(p, sc),
                "last_remote_version": remote_ver or sc.get("last_remote_version",""),
            })
            self._save(cfg)
            return _tr("pulled")

        if local_mtime > sc.get("last_sync_ts", 0) and remote_sha != local_sha:
            # PUSH
            self._upload_from_local(p, sc, user_key, local_path, cloud_wrap)
            new_remote_sha, _, new_ver = p.remote_meta(sc)
            sc.update({
                "last_sync_ts": time.time(),
                "last_local_sha256": local_sha,
                "last_remote_sha256": new_remote_sha,
                "last_remote_version": new_ver or sc.get("last_remote_version",""),
            })
            self._save(cfg)
            return _tr("pushed")

        return _tr("synced")  

    # -------- helpers --------
    def _remote_sha(self, p: ProviderBase, sc: Dict) -> str:
        try:
            sha, _, _ = p.remote_meta(sc)
            return sha
        except Exception:
            return ""

    def _download_to_local(self, p: ProviderBase, sc: Dict, user_key: bytes,
                           local_path: str, cloud_wrap: bool) -> None:
        # download to temp file first
        with tempfile.NamedTemporaryFile(delete=False, dir=os.path.dirname(local_path) or None) as tmp:
            tmp_path = tmp.name
        try:
            # pull remote into tmp
            p.download_to(sc, tmp_path)

            # if wrapped, unwrap then replace local
            if cloud_wrap:
                with open(tmp_path, "rb") as f:
                    wrapped = f.read()
                plain = wrap_decrypt(user_key, wrapped)
                with open(local_path, "wb") as f:
                    f.write(plain)
                os.remove(tmp_path)
            else:
                # overwrite local
                if os.path.exists(local_path):
                    os.remove(local_path)
                os.replace(tmp_path, local_path)
        except Exception:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
            raise

    def _upload_from_local(self, p: ProviderBase, sc: Dict, user_key: bytes,
                           local_path: str, cloud_wrap: bool) -> None:
        # create a tmp source: either wrapped or the original file
        tmp_path = None
        try:
            if cloud_wrap:
                with open(local_path, "rb") as f:
                    plain = f.read()
                wrapped = wrap_encrypt(user_key, plain)
                with tempfile.NamedTemporaryFile(delete=False, dir=os.path.dirname(sc.get("remote_path") or local_path) or None) as tmp:
                    tmp_path = tmp.name
                with open(tmp_path, "wb") as f:
                    f.write(wrapped)
                p.upload_from(sc, tmp_path)
            else:
                p.upload_from(sc, local_path)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try: os.remove(tmp_path)
                except Exception: pass

    def _resolve_conflict(self, p: ProviderBase, sc: Dict, user_key: bytes,
                      local_path: str, cloud_wrap: bool,
                      remote_mtime: float, local_mtime: float) -> str:
        """
        Conflict policy: 'newest wins' with no extra backup files.
        We simply pull or push based on mtime, then update sync markers.
        """

        # Decide direction
        if remote_mtime >= local_mtime:
            # Remote is newer → pull over local
            self._download_to_local(p, sc, user_key, local_path, cloud_wrap)
            result = _tr("pulled")
        else:
            # Local is newer → push over remote
            self._upload_from_local(p, sc, user_key, local_path, cloud_wrap)
            result = _tr("pushed")

        # Update markers so we don't loop on next sync
        sc.update({
            "last_sync_ts": time.time(),
            "last_local_sha256": sha256_file(local_path),
            "last_remote_sha256": self._remote_sha(p, sc),
            # keep last_remote_version if provider supports it; LocalPath returns ""
            # (leaving as-is avoids churn when not available)
        })
        return result
