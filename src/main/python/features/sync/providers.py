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
from typing import Tuple, Dict
import os, hashlib, shutil, time

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""):
            h.update(chunk)
    return h.hexdigest()

class SyncError(Exception): pass
class ConflictError(SyncError): pass
class NotConfigured(SyncError): pass
class NotFound(SyncError): pass

class ProviderBase:
    """Abstract provider API. Implement these for new providers."""
    name = "base"

    def is_configured(self, cfg: Dict) -> bool:
        raise NotImplementedError

    def describe(self, cfg: Dict) -> str:
        raise NotImplementedError

    def remote_exists(self, cfg: Dict) -> bool:
        raise NotImplementedError

    def remote_meta(self, cfg: Dict) -> Tuple[str, float, str]:
        """
        Returns (sha256, mtime_epoch, version_tag)
        - version_tag: ETag/cTag for API providers; for localpath can be ""
        """
        raise NotImplementedError

    def download_to(self, cfg: Dict, local_path: str) -> None:
        raise NotImplementedError

    def upload_from(self, cfg: Dict, local_path: str) -> str:
        """
        Upload local_path -> remote. Return new version tag ("" if not applicable).
        """
        raise NotImplementedError

class LocalPathProvider(ProviderBase):
    """Treats a path under OneDrive/Google Drive desktop sync as 'remote'."""
    name = "localpath"

    def is_configured(self, cfg: Dict) -> bool:
        return bool(cfg.get("remote_path"))

    def describe(self, cfg: Dict) -> str:
        p = cfg.get("remote_path","")
        return f"LocalPath: {p}" if p else "LocalPath: (not set)"

    def remote_exists(self, cfg: Dict) -> bool:
        p = cfg.get("remote_path","")
        return bool(p and os.path.isfile(p))

    def remote_meta(self, cfg: Dict) -> Tuple[str, float, str]:
        p = cfg["remote_path"]
        if not os.path.isfile(p):
            raise NotFound(p)
        return sha256_file(p), os.path.getmtime(p), ""  # no version tag

    def download_to(self, cfg: Dict, local_path: str) -> None:
        src = cfg["remote_path"]
        if not os.path.isfile(src): raise NotFound(src)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        shutil.copy2(src, local_path)

    def upload_from(self, cfg: Dict, local_path: str) -> str:
        dst = cfg["remote_path"]
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(local_path, dst)
        return ""  # no version tag

# Provider registry (used by SyncEngine)
PROVIDERS = {
    LocalPathProvider.name: LocalPathProvider(),
}
