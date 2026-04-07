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
from pathlib import Path
from typing import Dict, Tuple, Optional
import os
import time
import shutil
import tempfile
import json
import hashlib
import logging
import secrets
import zipfile

from qtpy.QtCore import QCoreApplication, QSettings

from vault_store.vault_store import verify_vault_owner
from native.native_core import get_core
from .providers import (
    ProviderBase,
    SyncError,
    ConflictError,
    NotFound,
    sha256_file,
    PROVIDERS,
)

log = logging.getLogger("keyquorum")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except Exception:
    AESGCM = None


def _tr(text: str) -> str:
    return QCoreApplication.translate("sync_engine", text)

# --- sync file magic helpers
_MAGIC_WRAP = b"KQW1"
_MAGIC_SYNCB = b"KQSB1"


def _peek_magic(path: str, n: int = 4) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n) or b""
    except Exception:
        return b""


def _remote_effective_wrap(p: ProviderBase, sc: Dict, configured_wrap: bool) -> bool:
    """
    Best-effort autodetect for LocalPath provider.
    If remote begins with KQW1, treat it as wrapped even if user didn't toggle the flag on this PC.
    This prevents the 'empty vault' illusion across PCs.
    """
    try:
        if getattr(p, "name", "") == "localpath":
            rp = (sc or {}).get("remote_path") or ""
            if rp and os.path.isfile(rp):
                if _peek_magic(rp, 4) == _MAGIC_WRAP:
                    return True
                return bool(configured_wrap)
    except Exception:
        pass
    return bool(configured_wrap)


# --- JSON encrypt/decrypt used by _enc_json_write/_enc_json_read -----------
def encrypt_json_file(path: str, key: bytes, data: dict | list) -> None:
    """
    Small helper used by some providers/config flows.
    If cryptography isn't available, it falls back to plaintext JSON.
    """
    try:
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if AESGCM is None:
            raise RuntimeError("AESGCM unavailable")
        if key and len(key) >= 32:
            nonce = os.urandom(12)
            ct = AESGCM(key[:32]).encrypt(nonce, payload, None)
            with open(path, "wb") as f:
                f.write(nonce + ct)
        else:
            raise ValueError("no key")
    except Exception:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


def decrypt_json_file(path: str, key: bytes) -> dict | list:
    try:
        b = open(path, "rb").read()
        if AESGCM is None:
            raise RuntimeError("AESGCM unavailable")
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


def wrap_encrypt(session_handle: int, blob: bytes) -> bytes:
    """Second-layer encryption for the CLOUD COPY ONLY (native AES-GCM).

    Format: b'KQW1' + iv12 + tag16 + ciphertext
    """
    if not isinstance(session_handle, int) or not session_handle:
        raise RuntimeError("native session required")
    core = get_core()
    iv = secrets.token_bytes(12)
    ct_ba, tag_ba = core.session_encrypt(session_handle, iv, blob)
    return b"KQW1" + iv + bytes(tag_ba) + bytes(ct_ba)


def wrap_decrypt(session_handle: int, blob: bytes) -> bytes:
    if not isinstance(session_handle, int) or not session_handle:
        raise RuntimeError("native session required")
    if not blob or len(blob) < 4:
        return blob
    if blob[:4] != b"KQW1":
        return blob
    if len(blob) < (4 + 12 + 16):
        return blob
    iv = blob[4:16]
    tag = blob[16:32]
    ct = blob[32:]
    core = get_core()
    pt_ba = core.session_decrypt(session_handle, iv, ct, tag)
    try:
        return bytes(pt_ba)
    finally:
        try:
            core.secure_wipe(pt_ba)
        except Exception:
            pass


class SyncEngine:
    """
    File-level sync with optional extra AES-GCM wrapping for cloud storage.

    Local vault file remains your standard encrypted .kqvault.
    Remote (cloud) file is wrapped when 'sync.cloud_wrap' is True.

    Optional "bundle mode" syncs a single archive containing multiple files
    (vault + user_db + identity + salt). This is only used if:
      - sync.bundle == True, OR
      - remote_path ends with .kqsync/.kqbndl/.kqbundle
    """

    def __init__(self, load_user_db, save_user_db, get_local_vault_path, get_bundle_files=None):
        self._load = load_user_db
        self._save = save_user_db
        self._get_vault = get_local_vault_path
        self._get_bundle_files = get_bundle_files  # optional callable

        # These may be set by the UI layer (sync_ops) for better safety checks.
        self.username: Optional[str] = None
        self._current_user: Optional[str] = None

        # Device-local sync state (baseline-safe). Persisted in QSettings when possible.
        self._volatile_state: Dict[str, str] = {}

    # --- device-local sync state (NOT stored in user_db) ---
    def _state_prefix(self) -> str:
        u = (self.username or self._current_user or "").strip()
        return f"sync/{u}/" if u else ""

    def _state_get(self, key: str, fallback: str = "") -> str:
        try:
            prefix = self._state_prefix()
            if not prefix:
                return str(self._volatile_state.get(key, fallback) or fallback)
            s = QSettings()
            return str(s.value(prefix + key, fallback) or fallback)
        except Exception:
            return str(self._volatile_state.get(key, fallback) or fallback)

    def _state_set(self, key: str, value: str) -> None:
        try:
            v = "" if value is None else str(value)
            self._volatile_state[key] = v
            prefix = self._state_prefix()
            if prefix:
                QSettings().setValue(prefix + key, v)
        except Exception:
            pass

    def _persist_state_from_sc(self, sc: Dict) -> None:
        """Persist only volatile state keys into QSettings (baseline-safe)."""
        try:
            self._state_set("last_local_sha256", str(sc.get("last_local_sha256") or ""))
            self._state_set("last_remote_sha256", str(sc.get("last_remote_sha256") or ""))
            self._state_set("last_remote_version", str(sc.get("last_remote_version") or ""))
            self._state_set("last_remote_revision", str(sc.get("last_remote_revision") or ""))
            self._state_set("last_sync_base_revision", str(sc.get("last_sync_base_revision") or ""))
        except Exception:
            pass

    # --- config / provider ---
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
        sc.update(
            {
                "enabled": True,
                "provider": "localpath",
                "remote_path": remote_path,
                "remote_id": "",
                # leave cloud_wrap / bundle as-is
            }
        )
        cfg["sync"] = sc
        # Reset device-local pairing state when changing targets.
        self._state_set("last_local_sha256", "")
        self._state_set("last_remote_sha256", "")
        self._state_set("last_remote_version", "")
        self._save(cfg)

    # --- bundle helpers ---
    def _is_bundle_mode(self, sc: Dict) -> bool:
        rp = (sc.get("remote_path") or "").lower()
        return bool(sc.get("bundle")) or rp.endswith(".kqsync") or rp.endswith(".kqbndl") or rp.endswith(".kqbundle")

    def _maybe_migrate_to_bundle_target(self, cfg: Dict, sc: Dict, local_vault_path: str) -> None:
        """If the UI provides a multi-file bundle map, ensure we are in bundle mode.

        This prevents the "single vault file" cloud target from becoming ambiguous,
        and makes sync deterministic across devices.
        """
        try:
            files = self._get_bundle_map(sc, local_vault_path)
            if not isinstance(files, dict) or len(files) <= 1:
                return

            if self._is_bundle_mode(sc):
                # Ensure the flag is persisted for clarity.
                if not sc.get("bundle"):
                    sc["bundle"] = True
                    cfg["sync"] = sc
                    self._save(cfg)
                return

            # Auto-migrate remote target filename to .kqsync (same folder).
            rp = (sc.get("remote_path") or "").strip()
            if not rp:
                return
            base_dir = os.path.dirname(rp)
            uname = (getattr(self, "_current_user", None) or getattr(self, "username", None) or "cloudsync").strip()
            if not uname:
                uname = "cloudsync"
            new_rp = os.path.join(base_dir, f"{uname}.kqsync")
            if os.path.normcase(os.path.abspath(new_rp)) != os.path.normcase(os.path.abspath(rp)):
                sc["remote_path"] = new_rp
            sc["bundle"] = True
            # Reset pairing state so we don't mis-detect conflicts after changing remote target.
            self._state_set("last_local_sha256", "")
            self._state_set("last_remote_sha256", "")
            self._state_set("last_remote_version", "")
            sc["files_in_cloud"] = ",".join(sorted(files.keys()))
            cfg["sync"] = sc
            self._save(cfg)
            log.info(f"[SYNC] migrated remote target to bundle file: {new_rp}")
        except Exception as e:
            log.debug(f"[SYNC] bundle auto-migration skipped: {e}")

    def _bundle_local_path(self, local_vault_path: str) -> str:
        """
        Build the local staging bundle OUTSIDE the watched vault folder.

        Writing cloudsync.kqsync beside the vault file causes the local directory
        watcher to see our own sync-generated writes and can trigger endless
        auto-sync loops. Keep the staging bundle in a per-user temp/cache folder
        instead.
        """
        uname = (getattr(self, "_current_user", None) or getattr(self, "username", None) or "default").strip() or "default"
        root = os.path.join(tempfile.gettempdir(), "Keyquorum", "sync_staging", uname)
        os.makedirs(root, exist_ok=True)
        return os.path.join(root, "cloudsync.kqsync")

    def _get_bundle_map(self, sc: Dict, local_vault_path: str) -> Dict[str, str]:
        """
        Returns logical_name -> absolute_path to include in the bundle.
        The UI can provide a callback returning this map.
        """
        if callable(self._get_bundle_files):
            try:
                m = self._get_bundle_files()
                if isinstance(m, dict) and m:
                    return {str(k): str(v) for k, v in m.items() if v}
            except Exception as e:
                log.warning(f"[SYNC] bundle map callback failed: {e}")

        return {"vault": local_vault_path}


    def _device_id(self) -> str:
        """
        Stable per-device identifier for sync metadata.
        Stored in QSettings so one device keeps the same ID across sessions.
        """
        try:
            s = QSettings()
            existing = str(s.value("sync/device_id", "") or "").strip()
            if existing:
                return existing
            did = secrets.token_hex(8)
            s.setValue("sync/device_id", did)
            return did
        except Exception:
            return secrets.token_hex(8)

    @staticmethod
    def _safe_int(value, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return int(default)

    def _read_bundle_manifest_from_path(self, path: str) -> dict:
        try:
            with zipfile.ZipFile(path, "r") as z:
                raw = z.read("manifest.json")
            data = json.loads(raw.decode("utf-8", "ignore") or "{}")
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _bundle_remote_info(
        self,
        p: ProviderBase,
        sc: dict,
        cloud_path: str,
        *,
        session_handle: int = 0,
        wrapped: bool = False,
    ) -> dict:
        """
        Read remote bundle manifest info in a wrap-aware way.
        Returns a dict containing revision/base_revision/content_hash/files.
        """
        tmp = None
        tmp_unwrapped = None
        try:
            remote_path = cloud_path
            if getattr(p, "name", "") != "localpath":
                fd, tmp = tempfile.mkstemp(prefix="kq_sync_remote_", suffix=".bin")
                os.close(fd)
                p.download_to(sc, tmp)
                remote_path = tmp

            if not (remote_path and os.path.isfile(remote_path)):
                return {
                    "revision": 0,
                    "base_revision": 0,
                    "device_id": "",
                    "content_hash": "",
                    "files": [],
                    "manifest": {},
                }

            inspect_path = remote_path
            if wrapped:
                raw = Path(remote_path).read_bytes()
                if raw[:4] == _MAGIC_WRAP:
                    if not isinstance(session_handle, int) or not session_handle:
                        return {
                            "revision": 0,
                            "base_revision": 0,
                            "device_id": "",
                            "content_hash": "",
                            "files": [],
                            "manifest": {},
                        }
                    plain = wrap_decrypt(session_handle, raw)
                    fd, tmp_unwrapped = tempfile.mkstemp(prefix="kq_sync_remote_plain_", suffix=".kqsync")
                    os.close(fd)
                    Path(tmp_unwrapped).write_bytes(plain)
                    inspect_path = tmp_unwrapped

            mf = self._read_bundle_manifest_from_path(inspect_path)
            items = (mf.get("items") or {}) if isinstance(mf, dict) else {}
            if not isinstance(items, dict):
                items = {}
            files = sorted(items.keys())
            return {
                "revision": self._safe_int(mf.get("revision"), 0),
                "base_revision": self._safe_int(mf.get("base_revision"), 0),
                "device_id": str(mf.get("device_id") or ""),
                "content_hash": self._stable_manifest_hash_from_items(items),
                "files": files,
                "manifest": mf,
            }
        except Exception:
            return {
                "revision": 0,
                "base_revision": 0,
                "device_id": "",
                "content_hash": "",
                "files": [],
                "manifest": {},
            }
        finally:
            for path in (tmp_unwrapped, tmp):
                if path and os.path.exists(path):
                    try:
                        os.remove(path)
                    except Exception:
                        pass

    def _build_bundle(self, sc: Dict, local_vault_path: str, *, revision: int | None = None, base_revision: int | None = None, device_id: str | None = None) -> str:
        bundle_path = self._bundle_local_path(local_vault_path)
        files = self._get_bundle_map(sc, local_vault_path)

        manifest = {
            "magic": _MAGIC_SYNCB.decode("ascii", "ignore"),
            "ts": int(time.time()),
            "revision": self._safe_int(revision, 0),
            "base_revision": self._safe_int(base_revision, 0),
            "device_id": str(device_id or self._device_id() or ""),
            "items": {},
        }

        tmp = None
        try:
            os.makedirs(os.path.dirname(bundle_path), exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix="kq_sync_", suffix=".kqsync", dir=os.path.dirname(bundle_path))
            os.close(fd)

            with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as z:
                for logical, path in files.items():
                    arc = f"data/{logical}"
                    z.write(path, arcname=arc)
                    try:
                        manifest["items"][logical] = {
                            "sha256": sha256_file(path),
                            "size": os.path.getsize(path),
                            "mtime": os.path.getmtime(path),
                            "arc": arc,
                        }
                    except Exception:
                        manifest["items"][logical] = {"arc": arc}

                z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))

            shutil.move(tmp, bundle_path)
            return bundle_path
        finally:
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    pass
    
    def _stable_manifest_hash_from_items(self, items: dict) -> str:
        """Compute a stable hash of bundle contents ignoring timestamps/metadata."""
        try:
            h = hashlib.sha256()
            for logical in sorted(items.keys()):
                v = items.get(logical) or {}
                sha = str(v.get("sha256") or "")
                h.update(logical.encode("utf-8", "ignore"))
                h.update(b"\0")
                h.update(sha.encode("ascii", "ignore"))
                h.update(b"\n")
            return h.hexdigest()
        except Exception:
            return ""

    def _bundle_manifest_hash_local(self, sc: dict, local_vault_path: str) -> tuple[str, list[str]]:
        """Manifest hash computed from local plaintext files (stable across wrapping/bundle rebuilds)."""
        files = self._get_bundle_map(sc, local_vault_path)
        items = {}
        for logical, path in files.items():
            try:
                items[logical] = {"sha256": sha256_file(path)}
            except Exception:
                items[logical] = {"sha256": ""}
        return self._stable_manifest_hash_from_items(items), sorted(items.keys())

    def _bundle_manifest_hash_remote(
        self,
        p: ProviderBase,
        sc: dict,
        cloud_path: str,
        *,
        session_handle: int = 0,
        wrapped: bool = False,
    ) -> tuple[str, list[str]]:
        """Manifest hash extracted from the remote .kqsync bundle.

        When Extra Cloud Wrap is enabled, the remote payload starts with KQW1 and must
        be unwrapped before we can inspect manifest.json. Without this, wrapped bundle
        remotes look "different" on every sync and wrap toggles become unstable.
        """
        tmp = None
        tmp_unwrapped = None
        try:
            # For localpath provider we can read directly; for API providers download to a temp file.
            remote_path = cloud_path
            if getattr(p, "name", "") != "localpath":
                fd, tmp = tempfile.mkstemp(prefix="kq_sync_remote_", suffix=".bin")
                os.close(fd)
                p.download_to(sc, tmp)
                remote_path = tmp

            if not (remote_path and os.path.isfile(remote_path)):
                return "", []

            inspect_path = remote_path
            if wrapped:
                raw = Path(remote_path).read_bytes()
                if raw[:4] == _MAGIC_WRAP:
                    if not isinstance(session_handle, int) or not session_handle:
                        return "", []
                    plain = wrap_decrypt(session_handle, raw)
                    fd, tmp_unwrapped = tempfile.mkstemp(prefix="kq_sync_remote_plain_", suffix=".kqsync")
                    os.close(fd)
                    Path(tmp_unwrapped).write_bytes(plain)
                    inspect_path = tmp_unwrapped

            with zipfile.ZipFile(inspect_path, "r") as z:
                try:
                    raw = z.read("manifest.json")
                    mf = json.loads(raw.decode("utf-8", "ignore") or "{}")
                except Exception:
                    mf = {}
            items = (mf.get("items") or {}) if isinstance(mf, dict) else {}
            if not isinstance(items, dict):
                items = {}
            files = sorted(items.keys())
            return self._stable_manifest_hash_from_items(items), files
        except Exception:
            return "", []
        finally:
            for path in (tmp_unwrapped, tmp):
                if path and os.path.exists(path):
                    try:
                        os.remove(path)
                    except Exception:
                        pass

    def _state_mark(self, username: str, key: str, value) -> None:
        """Helper to store device-local sync state in QSettings."""
        try:
            qs = QSettings("AJH Software", "Keyquorum Vault")
            base = f"sync/{(username or '').strip()}/"
            qs.setValue(base + key, value)
        except Exception:
            pass

    def _mark_synced_now(self, username: str, *, pushed: bool = False, pulled: bool = False) -> None:
        now = int(time.time())
        self._state_mark(username, "last_sync_ts", now)
        if pushed:
            self._state_mark(username, "last_pushed_ts", now)
        if pulled:
            self._state_mark(username, "last_pulled_ts", now)

    def _apply_bundle(self, sc: Dict, local_vault_path: str, bundle_path: str) -> None:
            """
            Extract a downloaded bundle into place.
            Only files present in the bundle map are written (safety).
            """
            log.info("[SYNC-BUNDLE] apply bundle_path=%r local_vault_path=%r", bundle_path, local_vault_path)
            files = self._get_bundle_map(sc, local_vault_path)
            log.info("[SYNC-BUNDLE] expected targets=%r", files)

            with zipfile.ZipFile(bundle_path, "r") as z:
                names = z.namelist()
                log.info("[SYNC-BUNDLE] zip names=%r", names)
                try:
                    manifest = json.loads(z.read("manifest.json").decode("utf-8"))
                except Exception as e:
                    log.warning("[SYNC-BUNDLE] manifest read failed: %r", e)
                    manifest = {}

                for logical, target in files.items():
                    arc = None
                    try:
                        arc = (manifest.get("items") or {}).get(logical, {}).get("arc")
                    except Exception:
                        arc = None
                    if not arc:
                        arc = f"data/{logical}"

                    present = arc in names
                    log.info("[SYNC-BUNDLE] logical=%r target=%r arc=%r present=%r", logical, target, arc, present)
                    if not present:
                        log.warning("[SYNC-BUNDLE] missing arc for logical=%r arc=%r", logical, arc)
                        continue

                    tmp = None
                    try:
                        os.makedirs(os.path.dirname(target), exist_ok=True)
                        fd, tmp = tempfile.mkstemp(prefix=f"kq_{logical}_", dir=os.path.dirname(target))
                        os.close(fd)
                        with open(tmp, "wb") as f:
                            f.write(z.read(arc))
                        shutil.move(tmp, target)
                        log.info("[SYNC-BUNDLE] wrote logical=%r -> %r exists=%r", logical, target, os.path.exists(target))
                    finally:
                        if tmp and os.path.exists(tmp):
                            try:
                                os.remove(tmp)
                            except Exception:
                                pass

    # --- core sync ---
    
    def sync_now(self, session_handle: int, interactive: bool = False) -> str:
        """
        Stable sync policy for desktop + Android bundle sync.

        Rules:
        - Never create a conflict copy during normal sync.
        - First pairing with an existing remote prefers pulling the remote.
        - Auto/live sync prefers pushing the current local edit after backing up the remote.
        - If both sides changed, use a deterministic winner:
            * remote wins when it has advanced past this device's last known base revision
            * otherwise local wins
        - Before overwriting either side, create a safety backup of the side being replaced.
        """
        notice_prefix = ""

        try:
            vault_path = getattr(self, "_get_vault", lambda: None)()
            cu = getattr(self, "_current_user", None) or getattr(self, "username", None)
            if vault_path and cu and not verify_vault_owner(vault_path, cu):
                log.info(f"[SYNC] Blocked — vault owner mismatch for {cu}")
                return _tr("blocked-owner")
        except Exception as e:
            log.error(f"[SYNC] [ERROR] Ownership check failed: {e}")
            cu = getattr(self, "_current_user", None) or getattr(self, "username", None)

        cfg, p = self.configured()
        sc = cfg["sync"]
        self._maybe_migrate_to_bundle_target(cfg, sc, getattr(self, "_get_vault", lambda: "")())

        local_vault_path = self._get_vault()
        local_path = local_vault_path
        bundle_mode = self._is_bundle_mode(sc)
        device_id = self._device_id()

        if bundle_mode:
            local_path = self._build_bundle(sc, local_vault_path)
            try:
                sc["files_in_cloud"] = ",".join(sorted(self._get_bundle_map(sc, local_vault_path).keys()))
            except Exception:
                pass
            sc["last_sync_items"] = "bundle"
        else:
            sc["last_sync_items"] = "vault"
            sc["files_in_cloud"] = "vault"

        cloud_wrap = bool(sc.get("cloud_wrap"))
        effective_wrap = _remote_effective_wrap(p, sc, cloud_wrap)
        if effective_wrap and not cloud_wrap:
            sc["cloud_wrap"] = True
            sc["wrap_autodetected"] = True
            cloud_wrap = True
            log.info("[SYNC] Auto-enabled Extra Wrap because remote file is wrapped (KQW1).")
            if interactive:
                notice_prefix = _tr(
                    "Extra Wrap was enabled automatically to match the synced vault.\n"
                    "Keep Extra Wrap enabled on all devices for this sync path.\n\n"
                )
            try:
                self._save(cfg)
            except Exception:
                pass

        remote_exists = p.remote_exists(sc)

        # Prefer bootstrapping from the remote when the current local copy does not exist.
        if not os.path.isfile(local_path):
            if remote_exists:
                self._download_to_local(p, sc, session_handle, local_path, cloud_wrap)
                if bundle_mode:
                    try:
                        self._apply_bundle(sc, local_vault_path, local_path)
                    except Exception as e:
                        log.warning(f"[SYNC] bundle extract failed during bootstrap: {e}")
                    local_path = self._build_bundle(sc, local_vault_path)
            else:
                raise NotFound(_tr("Neither local nor remote vault file exists"))

        if bundle_mode:
            local_sha, local_files = self._bundle_manifest_hash_local(sc, local_vault_path)
        else:
            local_sha = sha256_file(local_path) if os.path.isfile(local_path) else ""
            local_files = []

        remote_ver = ""
        remote_revision = 0
        remote_base_revision = 0
        remote_files = []
        remote_manifest = {}
        if bundle_mode and remote_exists:
            remote_info = self._bundle_remote_info(
                p,
                sc,
                sc.get("remote_path", ""),
                session_handle=session_handle,
                wrapped=bool(effective_wrap),
            )
            remote_sha = str(remote_info.get("content_hash") or "")
            remote_files = list(remote_info.get("files") or [])
            remote_revision = self._safe_int(remote_info.get("revision"), 0)
            remote_base_revision = self._safe_int(remote_info.get("base_revision"), 0)
            remote_manifest = dict(remote_info.get("manifest") or {})
        elif remote_exists:
            remote_sha, _remote_mtime, remote_ver = p.remote_meta(sc)
        else:
            remote_sha = ""

        last_local_sha = self._state_get("last_local_sha256", str(sc.get("last_local_sha256") or ""))
        last_remote_sha = self._state_get("last_remote_sha256", str(sc.get("last_remote_sha256") or ""))
        last_remote_revision = self._safe_int(
            self._state_get("last_remote_revision", str(sc.get("last_remote_revision") or "0")),
            0,
        )
        last_sync_base_revision = self._safe_int(
            self._state_get("last_sync_base_revision", str(sc.get("last_sync_base_revision") or "0")),
            0,
        )

        def _mark_files_cloud(files: list[str]) -> None:
            try:
                self._state_mark(str(cu or ""), "files_in_cloud", ",".join(files) if bundle_mode else "vault")
            except Exception:
                pass

        def _save_state_synced(local_hash: str, remote_hash: str, revision: int, *, pushed: bool = False, pulled: bool = False) -> None:
            sc.update(
                {
                    "last_local_sha256": local_hash,
                    "last_remote_sha256": remote_hash,
                    "last_remote_version": remote_ver or sc.get("last_remote_version", ""),
                    "last_remote_revision": str(revision),
                    "last_sync_base_revision": str(revision),
                    "conflict_pending": False,
                    "conflict_path": "",
                }
            )
            self._persist_state_from_sc(sc)
            self._save(cfg)
            self._mark_synced_now(str(cu or ""), pushed=pushed, pulled=pulled)

        def _pull_remote() -> str:
            self._download_to_local(p, sc, session_handle, local_path, cloud_wrap)
            if bundle_mode:
                try:
                    self._apply_bundle(sc, local_vault_path, local_path)
                except Exception as e:
                    log.warning(f"[SYNC] bundle extract failed during pull: {e}")
            _mark_files_cloud(remote_files or local_files)
            _save_state_synced(remote_sha, remote_sha, remote_revision, pulled=True)
            return notice_prefix + _tr("pulled")

        def _push_local(push_base_revision: int | None = None) -> str:
            base_rev = max(push_base_revision if push_base_revision is not None else 0, last_sync_base_revision, remote_revision, last_remote_revision, 0) if bundle_mode else 0
            next_revision = base_rev + 1 if bundle_mode else 0
            upload_path = self._build_bundle(
                sc,
                local_vault_path,
                revision=next_revision,
                base_revision=base_rev,
                device_id=device_id,
            ) if bundle_mode else local_path
            self._upload_from_local(p, sc, session_handle, upload_path, cloud_wrap)
            if bundle_mode:
                pushed_remote_info = self._bundle_remote_info(
                    p,
                    sc,
                    sc.get("remote_path", ""),
                    session_handle=session_handle,
                    wrapped=bool(cloud_wrap),
                )
                new_remote_sha = str(pushed_remote_info.get("content_hash") or local_sha)
                new_remote_revision = self._safe_int(pushed_remote_info.get("revision"), next_revision)
                _mark_files_cloud(local_files or remote_files)
            else:
                try:
                    new_remote_sha, _, _new_remote_ver = p.remote_meta(sc)
                except Exception:
                    new_remote_sha = local_sha
                new_remote_revision = 0
                _mark_files_cloud([])
            _save_state_synced(local_sha, new_remote_sha, new_remote_revision, pushed=True)
            return notice_prefix + _tr("pushed")

        # One-time migration: rewrite the cloud copy with wrap if enabled locally.
        if cloud_wrap and (not effective_wrap) and not sc.get("wrap_migrated"):
            try:
                result = _push_local(push_base_revision=max(remote_revision, last_remote_revision, 0))
                sc["wrap_migrated"] = True
                self._save(cfg)
                return result if result != _tr("pushed") else notice_prefix + _tr("synced")
            except Exception as e:
                log.error(f"[SYNC] wrap migration failed: {e}")

        if remote_exists and remote_sha == local_sha:
            _mark_files_cloud(remote_files or local_files)
            _save_state_synced(local_sha, remote_sha, remote_revision)
            return notice_prefix + (_tr("noop") if last_local_sha == local_sha and last_remote_sha == remote_sha else _tr("synced"))

        if not remote_exists:
            return _push_local(push_base_revision=max(last_remote_revision, 0))

        # Stable first-pair rule:
        # If this device has no recorded sync lineage yet, prefer seeding the cloud
        # from the current local state instead of blindly pulling and overwriting
        # a freshly-added local entry.
        if not last_local_sha and not last_remote_sha:
            log.info("[SYNC-FIX] First pair detected → prefer LOCAL push")
            if remote_exists:
                try:
                    self._backup_remote_for_live_sync(p, sc)
                    log.info("[SYNC-FIX] Remote backup created before first push")
                except Exception as e:
                    log.warning(f"[SYNC-FIX] Remote backup failed: {e}")
            return _push_local(push_base_revision=max(last_remote_revision, remote_revision, 0))

        local_changed = (local_sha != last_local_sha)
        remote_changed = (remote_sha != last_remote_sha)
        remote_advanced_since_base = False
        remote_is_known_base = False
        if bundle_mode:
            remote_is_known_base = (remote_revision == last_sync_base_revision)
            remote_advanced_since_base = (remote_revision > last_sync_base_revision) or (remote_base_revision > last_sync_base_revision)
            if remote_sha == last_remote_sha and remote_revision == last_remote_revision:
                remote_is_known_base = True

        try:
            log.info(
                "[SYNC] stable decision interactive=%s local_changed=%s remote_changed=%s remote_rev=%s last_base=%s last_remote_rev=%s remote_base_rev=%s",
                interactive,
                local_changed,
                remote_changed,
                remote_revision,
                last_sync_base_revision,
                last_remote_revision,
                remote_base_revision,
            )
        except Exception:
            pass

        if not local_changed and remote_changed:
            return _pull_remote()

        if local_changed and not remote_changed:
            if not interactive:
                try:
                    self._backup_remote_for_live_sync(p, sc)
                except Exception as e:
                    log.warning(f"[SYNC] live backup failed (continuing with push): {e}")
            return _push_local()

        if local_changed and remote_changed:
            remote_wins = False
            if bundle_mode:
                remote_wins = remote_advanced_since_base
            else:
                remote_wins = bool(last_remote_sha and remote_sha != last_remote_sha)

            if remote_wins:
                try:
                    self._backup_local_for_pull(local_path, label="before_pull")
                except Exception as e:
                    log.warning(f"[SYNC] local backup before pull failed: {e}")
                return _pull_remote()

            try:
                self._backup_remote_for_live_sync(p, sc)
            except Exception as e:
                log.warning(f"[SYNC] remote backup before push failed: {e}")
            return _push_local()

        _mark_files_cloud(remote_files or local_files)
        _save_state_synced(local_sha, remote_sha, remote_revision)
        return notice_prefix + _tr("synced")


    # --- internal helpers ---

    def _backup_remote_for_live_sync(self, p: ProviderBase, sc: Dict) -> None:
        """Best-effort remote backup before non-interactive live push."""
        try:
            if not p.remote_exists(sc):
                return
        except Exception:
            return

        remote_path = (sc.get("remote_path") or "").strip()
        if not remote_path:
            return

        try:
            base_dir = os.path.dirname(remote_path) or tempfile.gettempdir()
            backup_dir = os.path.join(base_dir, "cloud_history")
            os.makedirs(backup_dir, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            ext = os.path.splitext(remote_path)[1] or ".bin"
            backup_path = os.path.join(backup_dir, f"backup_{stamp}{ext}")
            if getattr(p, "name", "") == "localpath" and os.path.isfile(remote_path):
                shutil.copy2(remote_path, backup_path)
            else:
                p.download_to(sc, backup_path)
            log.info(f"[SYNC] remote backup saved -> {backup_path}")
        except Exception:
            raise


    def _backup_local_for_pull(self, local_path: str, label: str = "pull") -> None:
        """Best-effort local backup before a remote pull overwrites local files."""
        try:
            if not (local_path and os.path.isfile(local_path)):
                return
            base_dir = os.path.dirname(local_path) or tempfile.gettempdir()
            backup_dir = os.path.join(base_dir, "pull_history")
            os.makedirs(backup_dir, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            ext = os.path.splitext(local_path)[1] or ".bin"
            backup_path = os.path.join(backup_dir, f"{label}_{stamp}{ext}")
            shutil.copy2(local_path, backup_path)
            log.info(f"[SYNC] local backup saved -> {backup_path}")
        except Exception:
            raise

    def _remote_sha(self, p: ProviderBase, sc: Dict) -> str:
        try:
            return p.remote_meta(sc)[0]
        except Exception:
            return ""

    def _download_to_local(self, p: ProviderBase, sc: Dict, session_handle: int,
                           local_path: str, cloud_wrap: bool) -> None:
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tmp = tf.name
            p.download_to(sc, tmp)
            if cloud_wrap:
                blob = open(tmp, "rb").read()
                blob = wrap_decrypt(session_handle, blob)
                with open(tmp, "wb") as f:
                    f.write(blob)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            shutil.move(tmp, local_path)
        finally:
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    pass

    def _upload_from_local(self, p: ProviderBase, sc: Dict, session_handle: int,
                           local_path: str, cloud_wrap: bool) -> None:
        tmp = None
        try:
            if cloud_wrap:
                plain = open(local_path, "rb").read()
                wrapped = wrap_encrypt(session_handle, plain)
                with tempfile.NamedTemporaryFile(delete=False) as tf:
                    tmp = tf.name
                with open(tmp, "wb") as f:
                    f.write(wrapped)
                p.upload_from(sc, tmp)
            else:
                p.upload_from(sc, local_path)
        finally:
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    pass

    def _resolve_conflict(
        self,
        p: ProviderBase,
        sc: Dict,
        session_handle: int,
        local_path: str,
        cloud_wrap: bool,
        remote_mtime: float,
        local_mtime: float,
    ) -> str:
        """
        Conflict policy: NEVER overwrite either side silently.

        If both local + remote changed since last sync and differ, we:
        - Download remote into a timestamped conflict copy (unwrapped to local vault format if possible)
        - Keep the current local vault intact
        - Mark conflict_pending in sync config so the UI can surface it
        """
        try:
            conflicts_dir = os.path.join(os.path.dirname(local_path), "conflicts")
            os.makedirs(conflicts_dir, exist_ok=True)
            ts = time.strftime("%Y%m%d-%H%M%S", time.localtime())
            base = os.path.splitext(os.path.basename(local_path))[0] or "vault"
            conflict_local = os.path.join(conflicts_dir, f"{base}-remote-{ts}.kqvault")

            try:
                self._download_to_local(p, sc, session_handle, conflict_local, cloud_wrap)
            except Exception:
                raw = os.path.join(conflicts_dir, f"{base}-remote-RAW-{ts}")
                with tempfile.NamedTemporaryFile(delete=False) as tf:
                    tmp = tf.name
                try:
                    p.download_to(sc, tmp)
                    shutil.move(tmp, raw)
                finally:
                    try:
                        os.unlink(tmp)
                    except Exception:
                        pass
                conflict_local = raw

            sc.update(
                {
                    "conflict_pending": True,
                    "conflict_path": conflict_local,
"last_local_sha256": sha256_file(local_path) if os.path.isfile(local_path) else "",
                    "last_remote_sha256": self._remote_sha(p, sc),
                }
            )
            return _tr("Conflict detected — remote copy saved to Vault/conflicts. No data was overwritten.")
        except Exception as e:
            log.error(f"[SYNC] [ERROR] conflict handling failed: {e}")
            raise ConflictError(str(e))


