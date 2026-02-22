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
"""
Public ops:
- build_portable_app(parent, target_root)
- move_user_data_to_usb(parent, target_root, username)
- restore_from_usb(parent, usb_root, username)

Rules:
- Never hardcode AppData//Users trees. Always use paths.* for local user files.
- USB layout: <USB>\KeyquorumPortable\\Users\<user>\  + canonical filenames from app.paths.py
- Verification before deletion. Secure deletion on success.
"""

from pathlib import Path
import os, json, time, shutil, logging, io, zipfile, subprocess, ctypes, string, sys
from ctypes import wintypes
from typing import Optional, Tuple, Iterable

log = logging.getLogger("keyquorum")
try:
    import app.kq_logging as kql
except Exception:
    class _K:
        def i(self, *_a, **_k): return ""
    kql = _K()

# ---- Optional Qt UI ----
try:
    from qtpy.QtWidgets import QMessageBox, QInputDialog
except Exception:
    QMessageBox = None
    QInputDialog = None

# ---- Source of truth paths
from app.paths import (
    APP_ROOT, salt_file, user_db_file, identities_file,
    security_prefs_file, vault_file, baseline_file,)
# ---- USB helpers / binding
from features.portable.portable_user_usb import (ensure_portable_layout, portable_root, install_binding_overrides,)
from features.portable.portable_binding import set_user_usb_binding

# ==============================
# Utility helpers
# ==============================
def _bytestr(n: int) -> str:
    u = ["B","KB","MB","GB","TB"]
    i, f = 0, float(n)
    while f >= 1024 and i < len(u)-1:
        f /= 1024.0; i += 1
    return f"{f:.1f}{u[i]}"

def _safe_copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    if tmp.exists():
        try: os.remove(tmp)
        except Exception: pass
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)

def _copy_tree(src: Path, dst: Path, ignore=None):
    if not src.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=ignore)

# ==============================
# Secure deletion
# ==============================
def _movefileex_delete_on_reboot(path: Path) -> None:
    MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
    try:
        if sys.platform.startswith("win"):
            ctypes.windll.kernel32.MoveFileExW(str(path), None, MOVEFILE_DELAY_UNTIL_REBOOT)  
    except Exception:
        pass

def _shred_file(p: Path, passes: int = 1) -> None:
    try:
        if not p.exists() or not p.is_file():
            return
        size = p.stat().st_size
        with open(p, "r+b", buffering=0) as f:
            chunk = 1024 * 1024
            for _ in range(max(1, passes)):
                f.seek(0)
                left = size
                while left > 0:
                    n = min(chunk, left)
                    f.write(os.urandom(n))
                    left -= n
                f.flush(); os.fsync(f.fileno())
        try:
            rnd = p.with_name(f"._{p.stem}_{os.urandom(4).hex()}{p.suffix}")
            p.rename(rnd)
            rnd.unlink(missing_ok=True)
        except Exception:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                _movefileex_delete_on_reboot(p)
    except Exception as e:
        log.warning(f"{kql.i('warn')} [WIPE] shred failed for {p}: {e}")
        try:
            _movefileex_delete_on_reboot(p)
        except Exception:
            pass

# ==============================
# Drive picker (simplified; no auto-BitLocker prompts here)
# ==============================
DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

if sys.platform.startswith("win"):
    GetDriveTypeW = ctypes.windll.kernel32.GetDriveTypeW  
    GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    GetDriveTypeW.restype = wintypes.UINT
else:
    # Non-Windows: portable USB drive enumeration via Win32 isn't available.
    GetDriveTypeW = None

def _iter_roots() -> Iterable[Path]:
    for d in string.ascii_uppercase:
        yield Path(f"{d}:\\")

def _safe_exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False

def _safe_disk_usage(p: Path) -> Optional[Tuple[int, int, int]]:
    try:
        du = shutil.disk_usage(str(p))
        return (du.total, du.used, du.free)
    except OSError:
        return None

def _drive_type(root: Path) -> int:
    try:
        if GetDriveTypeW:
            return int(GetDriveTypeW(str(root)))
    except Exception:
        return DRIVE_UNKNOWN
    return DRIVE_UNKNOWN

def _bytes_free(p: Path) -> str:
    try:
        return _bytestr(shutil.disk_usage(p).free)
    except Exception:
        return "?"

def pick_usb_drive(parent) -> Optional[Path]:
    items: list[tuple[str, Path]] = []
    sys_drive = (os.environ.get("SystemDrive") or "C:").rstrip("\\/").upper()
    for root in _iter_roots():
        letter = root.drive.rstrip("\\/").upper()
        dtype = _drive_type(root)
        if dtype in (DRIVE_NO_ROOT_DIR, DRIVE_REMOTE, DRIVE_CDROM):
            continue
        if letter == sys_drive:
            continue
        if not _safe_exists(root):
            continue
        usage = _safe_disk_usage(root)
        if usage is None:
            continue
        # test writable
        try:
            probe = root / ".kq_probe"; probe.mkdir(exist_ok=True)
            t = probe / "t.tmp"; t.write_bytes(b"x"); t.unlink(missing_ok=True); probe.rmdir()
            writable = True
        except Exception:
            writable = False
        if not writable:
            continue
        label = f"{root} — {'Removable' if dtype==DRIVE_REMOVABLE else 'Fixed'} — free { _bytes_free(root) }"
        items.append((label, root))

    if not items:
        if QMessageBox:
            QMessageBox.warning(parent, "Select USB Drive",
                                "No unlocked, writable drives detected. Insert and unlock a USB drive, then try again.")
        return None

    if QInputDialog:
        choice, ok = QInputDialog.getItem(parent, "Select USB Drive",
                                          "Choose the target drive:", [lbl for (lbl, _) in items], 0, False)
        if not ok:
            return None
        for (lbl, path) in items:
            if lbl == choice:
                return path
    return items[0][1]

def _probe_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        tmp = path / ".kq_probe"
        tmp.write_text("ok", encoding="utf-8")
        tmp.unlink(missing_ok=True)
        return True
    except Exception as e:
        log.error(f"{kql.i('err')} [PORTABLE] USB not writable: {e}")
        try:
            if QMessageBox:
                QMessageBox.critical(None, "USB Not Writable", f"Cannot write to:\n{path}\n\n{e}")
        except Exception:
            pass
        return False

# ==============================
# Encrypted app staging (portable app payload)
# ==============================
PORTABLE_DIRNAME       = "KeyquorumPortable"
PORTABLE_STAGE_SUFFIX  = ".staging"
PORTABLE_APP_SUBDIR    = "app"
PORTABLE_DATA_SUBDIR   = "data"
PORTABLE_CFG_SUBDIR    = "config"
PORTABLE_DOCS_SUBDIR   = "docs"

BLOB_REL_PATH = r"resources\\portable\\core.kqpkg"
KEY0_B64 = "base64 32B key here"

def _get_pfn() -> str:
    p = os.getenv("KQ_APP_PFN")
    if p: return p.strip()
    try:
        from winsdk.windows.applicationmodel import Package  
        return str(Package.current.id.family_name)
    except Exception:

        return  "<PackageFamilyName>"

def _read_blob_pfn(blob_path: Path) -> str | None:
    try:
        raw = blob_path.read_bytes()
        if not raw.startswith(b"KQPKG1"):
            return None
        pos = 6
        pos += 12
        aad_len = int.from_bytes(raw[pos:pos+2], "big"); pos += 2
        aad = raw[pos:pos+aad_len]
        return aad.decode("utf-8", errors="replace")
    except Exception:
        return None

def _derive_key(pfn: str) -> bytes:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    import base64, hashlib as _hashlib
    key0 = base64.b64decode(KEY0_B64)
    hk = HKDF(algorithm=hashes.SHA256(), length=32,
              salt=_hashlib.sha256(pfn.encode("utf-8")).digest(),
              info=b"kqportable-v1")
    return hk.derive(key0)

def _decrypt_blob(blob: bytes, pfn: str) -> bytes:
    if len(blob) < 20 or not blob.startswith(b"KQPKG1"):
        raise ValueError("invalid blob header")
    nonce   = blob[6:18]
    aad_len = int.from_bytes(blob[18:20], "big")
    aad     = blob[20:20+aad_len]
    ct      = blob[20+aad_len:]
    if aad.decode("utf-8", "ignore") != pfn:
        raise ValueError("PFN mismatch in blob")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(_derive_key(pfn)).decrypt(nonce, ct, aad)

def _stage_app_from_encrypted_blob(app_stage: Path) -> tuple[bool, str]:
    try:
        blob_path = Path(APP_ROOT) / BLOB_REL_PATH
        if not blob_path.exists():
            return False, f"encrypted payload not found at: {blob_path}"
        runtime_pfn = _get_pfn()
        blob_pfn = _read_blob_pfn(blob_path)
        if not blob_pfn or blob_pfn.strip() != runtime_pfn:
            return False, f"PFN mismatch: runtime='{runtime_pfn}' vs blob='{blob_pfn}'"
        raw = blob_path.read_bytes()
        zip_bytes = _decrypt_blob(raw, runtime_pfn)
        base = app_stage.parent
        tmp_dir = base / (app_stage.name + ".unz")
        if tmp_dir.exists(): shutil.rmtree(tmp_dir)
        base.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as z:
            # Use hardened extraction to prevent Zip Slip and symlink abuse
            try:
                from features.portable.safe_zip import safe_extract_zip  
            except Exception:
                # Fallback: use unsafe extraction if helper is unavailable
                def safe_extract_zip(zf, dest_dir): zf.extractall(dest_dir)
            tmp_dir.mkdir(parents=True, exist_ok=True)
            safe_extract_zip(z, tmp_dir)
        payload_root = (tmp_dir / "app") if (tmp_dir / "app").is_dir() else tmp_dir
        if app_stage.exists(): shutil.rmtree(app_stage)
        app_stage.mkdir(parents=True, exist_ok=True)
        for item in payload_root.iterdir():
            dest = app_stage / item.name
            try: os.replace(item, dest)
            except Exception:
                if item.is_dir():
                    shutil.copytree(item, dest, dirs_exist_ok=True)
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    shutil.copy2(item, dest)
                    try: item.unlink(missing_ok=True)
                    except Exception: pass
        try: shutil.rmtree(tmp_dir)
        except Exception: pass
        return True, ""
    except Exception as e:
        return False, str(e)

def _create_root_shortcut(usb_base: Path, portable_dir: Path, exe_name: str = "Keyquorum.exe") -> tuple[bool, str]:
    try:
        app_dir = portable_dir / "app"
        if not app_dir.exists():
            return False, f"app dir not found: {app_dir}"
        exe_path = next((p for p in [app_dir / exe_name] + list(app_dir.glob("*.exe")) if p.exists()), None)
        if not exe_path:
            return False, f"no .exe found in {app_dir}"
        ps = f"""$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut('{(usb_base / "Keyquorum Portable.lnk")}'.Replace("'", "''"))
$s.TargetPath    = '{str(exe_path).replace("'", "''")}'
$s.WorkingDirectory = '{str(app_dir).replace("'", "''")}'
$s.IconLocation  = '{str(exe_path).replace("'", "''")},0'
$s.Arguments     = ''
$s.Description   = 'Keyquorum Vault (Portable)'
$s.Save()"""
        ps_file = usb_base / "_mk_kq_shortcut.ps1"
        ps_file.write_text(ps, encoding="utf-8")
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        startupinfo = None
        if os.name == "nt":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            startupinfo = si
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps_file)],
            check=True,
            capture_output=True,
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
        try: ps_file.unlink(missing_ok=True)
        except Exception: pass
        return True, "lnk"
    except Exception as e:
        try:
            cmd_path = usb_base / "Keyquorum Portable.cmd"
            rel = f"{portable_dir.name}\\app\\{exe_name}"
            cmd = (
                "@echo off\r\n"
                "set ROOT=%~dp0\r\n"
                f"set APP=\"%ROOT%{rel}\"\r\n"
                "if exist %APP% ( start \"\" %APP% ) else ( echo Portable app not found & pause )\r\n"
            )
            cmd_path.write_text(cmd, encoding="utf-8")
            return True, f"cmd fallback: {e}"
        except Exception as e2:
            return False, f"shortcut failed: {e2}"

# ==============================
# BUILD PORTABLE APP ONLY (no user data touched)
# ==============================
def build_portable_app(parent, target_root: Path) -> bool:
    usb_base = Path(target_root)
    if not _probe_writable(usb_base):
        return False
    usb_final = usb_base / PORTABLE_DIRNAME
    usb_stage = usb_base / (PORTABLE_DIRNAME + PORTABLE_STAGE_SUFFIX)
    app_stage  = usb_stage / PORTABLE_APP_SUBDIR

    if usb_stage.exists():
        shutil.rmtree(usb_stage)

    ok, why = _stage_app_from_encrypted_blob(app_stage)
    if not ok:
        try: shutil.rmtree(usb_stage)
        except Exception: pass
        if QMessageBox:
            QMessageBox.warning(parent, "Portable Payload Missing/Invalid", str(why))
        return False

    try:
        (app_stage / "portable.marker").write_text("1", encoding="utf-8")
        (usb_stage / PORTABLE_CFG_SUBDIR).mkdir(parents=True, exist_ok=True)
        (usb_stage / PORTABLE_DATA_SUBDIR).mkdir(parents=True, exist_ok=True)
        (usb_stage / PORTABLE_DOCS_SUBDIR).mkdir(parents=True, exist_ok=True)
        (app_stage / "portable.json").write_text(json.dumps({
            "config_dir": "../config",
            "data_dir": "../data",
            "docs_dir": "../docs",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1",
        }, indent=2), encoding="utf-8")
    except Exception:
        pass

    try:
        if usb_final.exists():
            old = usb_final.with_suffix(f".old.{time.strftime('%Y%m%d%H%M%S')}")
            os.replace(usb_final, old)
        os.replace(usb_stage, usb_final)
    except Exception as e:
        try: shutil.rmtree(usb_stage)
        except Exception: pass
        if QMessageBox:
            QMessageBox.critical(parent, "Finalize Failed", str(e))
        return False

    _create_root_shortcut(usb_base, usb_final)
    if QMessageBox:
        QMessageBox.information(parent, "Portable App Ready",
                                f"Portable app created at:\n{usb_final}\n\n"
                                "You can now move user data separately.")
    return True

# ============================== Back-compat / utility helpers ========

def wipe_portable(usb_root: Path, username: str | None = None) -> bool:
    """
    Wipe portable data on the USB.

    - If username is provided, delete only that user's folder:
          <USB>\\KeyquorumPortable\\Users\\<username>
    - If username is None, delete the entire portable directory:
          <USB>\\KeyquorumPortable

    Returns True on success, False on partial/failed removal.
    """
    try:
        pr = portable_root(usb_root)
        target = (pr / "Users" / username) if username else pr
        if not target.exists():
            return True  # already gone

        # Prefer secure-ish removal for files, robust for dirs.
        if target.is_dir():
            # Use our shred for files, then remove directories
            for root, dirs, files in os.walk(target):
                for fn in files:
                    _shred_file(Path(root) / fn)
            shutil.rmtree(target, ignore_errors=True)
        else:
            _shred_file(target)

        return not target.exists()
    except Exception as e:
        log.error(f"[PORTABLE] wipe_portable failed: {e}")
        return False

# ==============================
# MOVE USER DATA ONLY (copy → verify → delete local)
# ==============================
def _selective_copy_phase2_user_tree(src_root: Path, dst_root: Path, username: str) -> None:
    """
    Copy only the Phase-2 canonical locations for a user from src_root -> dst_root.
    Avoids bringing across any legacy top-level 'Vault' or stray root files.
    Adds detailed logging for visibility during USB move.
    Also hoovers up root-level Config.* (e.g., Config.enc / Config.hmac) into Config/,
    and copies global logs if present.
    """
    import logging
    log = logging.getLogger("keyquorum")

    # names from app.paths to stay future-proof
    name_vault = Path(vault_file(username, name_only=True)).name
    name_salt  = Path(salt_file(username, name_only=True)).name
    name_db    = Path(user_db_file(username, ensure_parent=False)).name
    name_ids   = Path(identities_file(username, name_only=True)).name
    name_prefs = Path(security_prefs_file(username, name_only=True)).name
    name_bline = Path(baseline_file(username, name_only=True)).name

    # canonical src/dst (per-user roots)
    src_MAIN, dst_MAIN = src_root / "Main", dst_root / "Main"
    src_VAULT, dst_VAULT = src_MAIN / "Vault", dst_MAIN / "Vault"
    src_STORE, dst_STORE = src_root / "KQ_Store", dst_root / "KQ_Store"
    src_CONFIG, dst_CONFIG = src_root / "Config", dst_root / "Config"
    src_SETTINGS, dst_SETTINGS = src_root / "settings", dst_root / "settings"
    src_SOFTWARE, dst_SOFTWARE = src_root / "Software", dst_root / "Software"

    # global logs live at Keyquorum\logs (sibling of Users)
    src_GLOBAL_LOGS = src_root.parent.parent / "logs"
    dst_GLOBAL_LOGS = dst_root.parent.parent / "logs"

    # ensure structure
    for d in (dst_MAIN, dst_VAULT, dst_STORE, dst_CONFIG, dst_SETTINGS, dst_SOFTWARE):
        d.mkdir(parents=True, exist_ok=True)

    def _try_copy(src: Path, dst: Path, label: str):
        """Wrapper around _safe_copy_file with logging."""
        try:
            if src.exists():
                _safe_copy_file(src, dst)
                log.info(f"[USB MOVE] ✅ Copied {label}: {src} → {dst}")
            else:
                log.warning(f"[USB MOVE] ⚠️ Missing {label}: {src}")
        except Exception as e:
            log.error(f"[USB MOVE] ❌ Failed to copy {label}: {src} → {dst} ({e})")

    def _try_copy_tree(src: Path, dst: Path, label: str):
        try:
            if src.exists():
                _copy_tree(src, dst)
                log.info(f"[USB MOVE] ✅ Copied tree {label}: {src} → {dst}")
            else:
                log.warning(f"[USB MOVE] ⚠️ Missing tree {label}: {src}")
        except Exception as e:
            log.error(f"[USB MOVE] ❌ Failed to copy tree {label}: {src} → {dst} ({e})")

    # ---- Vault (file + any wrap files next to it) ----
    _try_copy(src_VAULT / name_vault, dst_VAULT / name_vault, "vault file")
    if src_VAULT.exists():
        for p in src_VAULT.glob("*.kq_wrap"):
            _try_copy(p, dst_VAULT / p.name, "vault wrap")

    # ---- DB & identities ----
    _try_copy(src_MAIN / name_db,   dst_MAIN / name_db,   "user_db")
    _try_copy(src_MAIN / name_ids,  dst_MAIN / name_ids,  "identities")

    # ---- Salt ----
    _try_copy(src_STORE / name_salt, dst_STORE / name_salt, "salt file")

    # ---- Config (prefs, baseline, audits) ----
    _try_copy(src_CONFIG / name_prefs, dst_CONFIG / name_prefs, "security prefs")
    _try_copy(src_CONFIG / name_bline, dst_CONFIG / name_bline, "baseline")

    if src_CONFIG.exists():
        for pat in (f"{username}*.kqad*", f"{username}*_bline.*", "Config.*"):
            for p in src_CONFIG.glob(pat):
                if p.is_file():
                    _try_copy(p, dst_CONFIG / p.name, f"config pattern {p.name}")

    # ---- NEW: root-level Config.* (e.g., Config.enc / Config.hmac) → put into Config/ ----
    for p in src_root.glob("Config.*"):
        if p.is_file():
            _try_copy(p, dst_CONFIG / p.name, f"root config {p.name}")

    # ---- Optional trees ----
    _try_copy_tree(src_SETTINGS, dst_SETTINGS, "settings")
    _try_copy_tree(src_SOFTWARE, dst_SOFTWARE, "software")

    # ---- NEW: Global logs (e.g., KQ_App.log) ----
    if src_GLOBAL_LOGS.exists():
        dst_GLOBAL_LOGS.mkdir(parents=True, exist_ok=True)
        for p in src_GLOBAL_LOGS.glob("*.log"):
            if p.is_file():
                _try_copy(p, dst_GLOBAL_LOGS / p.name, f"global log {p.name}")
    else:
        log.info(f"[USB MOVE] (logs) No global 'logs' folder at: {src_GLOBAL_LOGS}")

    log.info(f"[USB MOVE] ✅ Completed Phase-2 selective copy for user '{username}'")

def _orig_paths():
    """Snapshot ORIGINAL paths.* callables (so overrides can't recurse)."""
    import app.paths as _paths
    # Prefer the module's registry if present
    ORIG = getattr(_paths, "_KQ_ORIG_FUNCS", {}) or {}
    # Fill any gaps directly from the module (tolerant of missing items)
    keys = ["user_db_file", "vault_file", "salt_file", "identities_file",
            "security_prefs_file", "baseline_file",
            "user_root_local", "user_root_roaming",
            "users_root_local", "users_root_roaming"]
    for k in keys:
        ORIG.setdefault(k, getattr(_paths, k, None))
    return ORIG, _paths

def _discover_local_user_roots(username: str) -> list[Path]:
    """
    Return all real LOCAL per-user roots (Local and/or Roaming), using paths.py only.
    Local root = parent of Main/, KQ_Store/, Config/, etc.
    """
    ORIG, _ = _orig_paths()
    roots: set[Path] = set()

    # Ask paths.py directly for canonical Local/Roaming user roots
    for fn_key in ("user_root_local", "user_root_roaming"):
        fn = ORIG.get(fn_key)
        if callable(fn):
            try:
                r = Path(fn(username, ensure=False))
                if r.exists() and r.is_dir():
                    roots.add(r)
            except Exception:
                pass

    # If those aren’t available, infer from the concrete files
    def _add_from_file(fn_key: str, how: str):
        fn = ORIG.get(fn_key)
        if not callable(fn):
            return
        try:
            # user_db_file returns full path under .../Main/
            if fn_key == "user_db_file":
                p = Path(fn(username, ensure_parent=False))
            else:
                p = Path(fn(username, name_only=False))
            if not p:
                return
            if how == "vault":      roots.add(p.parent.parent)    # .../Main/Vault/<file> → ..\.. (user root)
            elif how in ("db","ids"): roots.add(p.parent.parent) # .../Main/<file>       → ..\ (user root)
            elif how in ("salt","prefs","baseline"):
                roots.add(p.parent)                              # .../KQ_Store or Config → ..\ (user root)
        except Exception:
            pass

    _add_from_file("vault_file", "vault")
    _add_from_file("user_db_file", "db")
    _add_from_file("identities_file", "ids")
    _add_from_file("salt_file", "salt")
    _add_from_file("security_prefs_file", "prefs")
    _add_from_file("baseline_file", "baseline")

    # Prefer Local first (contains vault), then Roaming — stable order
    ordered = sorted(
        {r for r in roots if isinstance(r, Path) and r.exists() and r.is_dir()},
        key=lambda p: "\\AppData\\Roaming\\" in str(p)
    )
    return ordered

def _expected_phase2_paths(username: str, base: Path) -> dict[str, Path]:
    """
    Build expected Phase-2 file locations under 'base' (either a Local/Roaming root, or the USB user root),
    using only names from app.paths.py.
    """
    ORIG, _ = _orig_paths()
    def _name(key: str):
        fn = ORIG.get(key)
        if not callable(fn):
            return None
        try:
            if key == "user_db_file":
                # returns a full path; we just need the filename
                return Path(fn(username, ensure_parent=False)).name
            return Path(fn(username, name_only=True)).name
        except Exception:
            return None

    names = {
        "db":   _name("user_db_file"),
        "vault":_name("vault_file"),
        "salt": _name("salt_file"),
        "ids":  _name("identities_file"),
        "prefs":_name("security_prefs_file"),
        "bsl":  _name("baseline_file"),
    }

    p = {
        "Main":        base / "Main",
        "VaultDir":    base / "Main" / "Vault",
        "KQ_Store":    base / "KQ_Store",
        "Config":      base / "Config",
        "settingsDir": base / "settings",
        "SoftwareDir": base / "Software",
    }
    if names["db"]:    p["db"]    = p["Main"]     / names["db"]
    if names["vault"]: p["vault"] = p["VaultDir"] / names["vault"]
    if names["salt"]:  p["salt"]  = p["KQ_Store"] / names["salt"]
    if names["ids"]:   p["ids"]   = p["Main"]     / names["ids"]
    if names["prefs"]: p["prefs"] = p["Config"]   / names["prefs"]
    if names["bsl"]:   p["bsl"]   = p["Config"]   / names["bsl"]
    return p

from pathlib import Path
from app.paths import (
    users_root_portable,
    vault_dir,
    user_db_file,
    identities_file,
    salt_file,
    config_dir,
    baseline_file,
)

def _list_portable_users_verbose(portable_root: Path, username_hint: str | None = None):
    """
    Discover portable users using canonical paths helpers.
    Matches modern Keyquorum portable layout.
    """
    users_dir = users_root_portable(ensure=False)
    out = []

    if not users_dir.exists():
        return out

    hint = username_hint.casefold() if username_hint else None

    for p in users_dir.iterdir():
        if not p.is_dir():
            continue

        username = p.name

        if hint and hint not in username.casefold():
            continue

        # --- Canonical checks (authoritative) ---
        has_vault = vault_dir(username).exists()
        has_db    = user_db_file(username).exists()
        has_id    = identities_file(username).exists()
        has_salt  = salt_file(username).exists()
        has_cfg   = (config_dir(username) / "Config.enc").exists()

        # Minimum viable portable user
        if not (has_vault and has_db and has_id):
            continue

        out.append({
            "username": username,
            "path": str(p),
            "has_vault": has_vault,
            "has_db": has_db,
            "has_identity": has_id,
            "has_salt": has_salt,
            "has_config": has_cfg,
            "has_baseline": baseline_file(username).exists(),
        })

    out.sort(key=lambda d: d["username"].casefold())
    return out


def move_user_data_to_usb(parent, target_root: Path, username: str, *, delete_local: bool = True) -> bool:
    """
    COPY the union of LOCAL and ROAMING per-user trees to USB, preserving Phase-2 layout.
    Verifies presence of salt + user_db; vault is recommended but not mandatory.
    PERMANENTLY deletes the original local user folders after successful verification.
    """
    from qtpy.QtWidgets import QMessageBox
    import logging
    log = logging.getLogger("keyquorum")

    # Force deletion on (ignore any caller-provided value)
    delete_local = True

    if not username:
        QMessageBox.information(parent, "Move to USB", "Please select a user first.")
        return False

    # Discover Local/Roaming roots via paths.py
    roots = _discover_local_user_roots(username)
    if not roots:
        QMessageBox.critical(parent, "Move to USB", "Could not locate any local user folder.")
        return False

    # Prepare USB user dir
    if not _probe_writable(Path(target_root)):
        return False
    pr, users_dir = ensure_portable_layout(Path(target_root))
    dst_root = users_dir / username
    dst_root.mkdir(parents=True, exist_ok=True)

    # Copy only Phase-2 contents from each discovered root
    for src_root in roots:
        try:
            _selective_copy_phase2_user_tree(src_root, dst_root, username)
            log.info("[MOVE→USB] Copied Phase-2 set %s → %s", src_root, dst_root)
        except Exception as e:
            QMessageBox.critical(parent, "Move to USB", f"Copy failed from:\n{src_root}\n\n{e}")
            return False

    # Verify minimal presence (salt + db); vault warn-only
    expect = _expected_phase2_paths(username, dst_root)
    missing = [k for k in ("salt", "db") if k not in expect or not expect[k].exists()]
    if missing:
        QMessageBox.critical(
            parent, "Move to USB",
            "Verification failed on USB — required files missing:\n" +
            "\n".join(f" • {k}: {expect.get(k)}" for k in missing)
        )
        return False

    if "vault" in expect and not expect["vault"].exists():
        log.warning("[MOVE→USB] Vault missing after copy (OK for brand-new users): %s", expect["vault"])

    # Persist binding & install overrides so this session uses USB immediately
    try:
        set_user_usb_binding(username, usb_root=Path(target_root), user_dir=dst_root)
        install_binding_overrides(username, dst_root)
        log.info("[MOVE→USB] Session bound to USB for user=%s", username)
    except Exception as e:
        log.warning("[MOVE→USB] Moved, but could not bind session: %s", e)

    # PERMANENT: delete entire local user folders (ALL discovered roots)
    try:
        _hard_delete_local_user_trees(username, roots, dst_root)

    except Exception as e:
        log.warning("[MOVE→USB] Local delete failed: %s", e)

    QMessageBox.information(
        parent, "Move Complete",
        f"✅ Moved user '{username}' into:\n{dst_root}\n\n"
        f"Local/Roaming copies were PERMANENTLY deleted.\n"
        f"Binding saved; this session now uses the USB data."
    )
    return True

def _hard_delete_local_user_trees(username: str, roots: list[Path], dst_root: Path) -> None:
    """
    Permanently delete the per-user folders from all discovered local roots.
    'roots' are the Local/Roaming user roots (…\Keyquorum\\Users\<user>).
    Never touches the USB dst_root.
    Handles read-only files on Windows.
    """
    import logging, shutil, os, stat, time
    log = logging.getLogger("keyquorum")

    def _onerror(func, path, exc_info):
        # Make files writable then retry once
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass  # let rmtree continue

    for src_root in roots:
        try:
            # Safety: don't delete the USB user folder by mistake
            try:
                if src_root.resolve() == dst_root.resolve():
                    log.warning("[DEL] Skipping (is USB dst): %s", src_root)
                    continue
            except Exception:
                pass

            if not src_root.exists():
                log.info("[DEL] (missing) %s", src_root)
                continue

            log.info("[DEL] Removing user tree → %s", src_root)
            shutil.rmtree(src_root, onerror=_onerror)
            # Sometimes Windows keeps a handle briefly; double-check & retry once
            if src_root.exists():
                time.sleep(0.3)
                shutil.rmtree(src_root, onerror=_onerror, ignore_errors=True)

            if not src_root.exists():
                log.info("[DEL] ✅ Removed %s", src_root)
            else:
                log.warning("[DEL] ⚠️ Could not fully remove %s (in use)", src_root)
        except Exception as e:
            log.warning("[DEL] Failed to remove %s: %s", src_root, e)

# ==============================
# RESTORE USER DATA (USB -> LOCAL; no deletion on USB)
# ==============================
def _detect_portable_root(usb_root):
    """
    Try to detect the Keyquorum portable root folder on a given USB drive.
    e.g., I:/KeyquorumPortable
    Falls back to the drive itself if no subfolder found.
    """
    from pathlib import Path
    try:
        from features.portable.portable_user_usb import get_portable_root
        return get_portable_root(Path(usb_root))
    except Exception:
        usb_root = Path(usb_root)
        candidate = usb_root / "KeyquorumPortable"
        return candidate if candidate.exists() else usb_root

def _detach_file_handlers_under(path_like):
    """
    Detach any logging.FileHandler whose baseFilename lives under 'path_like'.
    Prevents crashes if we delete that directory afterwards.
    """
    import logging, os
    base = os.path.normcase(str(path_like))
    lg = logging.getLogger("keyquorum")
    to_remove = []
    for h in list(lg.handlers):
        fn = getattr(h, "baseFilename", None)
        if not fn:
            continue
        if os.path.normcase(fn).startswith(base):
            to_remove.append(h)
    for h in to_remove:
        try:
            lg.removeHandler(h)
            try: h.close()
            except Exception: pass
        except Exception:
            pass

# --- core: restore from USB back to system and delete USB copy ---
def restore_from_usb(parent, usb_root: Path, username: str) -> bool:
    """
    Restore a user's data from USB back to the PC, honoring Phase-2 layout:
      - Vault -> LOCAL
      - DB/IDs/Config/Salt -> ROAMING
      - settings//Software -> LOCAL
    After verification, permanently deletes the USB user folder.
    """
    import logging, shutil, os, stat, time
    from pathlib import Path
    from qtpy.QtWidgets import QMessageBox

    log = logging.getLogger("keyquorum")

    if not username:
        QMessageBox.information(parent, "Restore from USB", "Please select a user first.")
        return False

    # --- locate USB user folder ---
    pr = _detect_portable_root(usb_root)
    users_dir = pr / "Users"
    usb_user = users_dir / username
    if not usb_user.exists():
        for p in users_dir.iterdir():
            if p.is_dir() and p.name.casefold() == username.casefold():
                usb_user = p
                username = p.name
                break
    if not usb_user.exists():
        QMessageBox.warning(parent, "Restore from USB",
                            f"User '{username}' not found under {users_dir}.")
        return False

    log.info(f"[RESTORE] Starting restore for {username} from {usb_user}")

    # USB subfolders
    src_MAIN    = usb_user / "Main"
    src_VAULT_D = src_MAIN / "Vault"
    src_STORE   = usb_user / "KQ_Store"
    src_CONFIG  = usb_user / "Config"
    src_SET     = usb_user / "settings"
    src_SOFT    = usb_user / "Software"

    # Destination roots
    ORIG, _ = _orig_paths()
    dst_local_root, dst_roam_root = None, None
    try:
        fn = ORIG.get("user_root_local")
        if callable(fn):
            dst_local_root = Path(fn(username, ensure=True))
    except Exception:
        pass
    try:
        fn = ORIG.get("user_root_roaming")
        if callable(fn):
            dst_roam_root = Path(fn(username, ensure=True))
    except Exception:
        pass

    if not dst_local_root:
        try:
            dst_local_root = Path(ORIG["vault_file"](username)).parent.parent
            dst_local_root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
    if not dst_roam_root:
        try:
            dbp = Path(ORIG["user_db_file"](username, ensure_parent=False))
            dst_roam_root = dbp.parent.parent
            dst_roam_root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    if not (dst_local_root and dst_roam_root):
        QMessageBox.critical(parent, "Restore from USB",
                             "Cannot resolve local user folders (Local/Roaming).")
        return False

    # Destinations
    dst_LOCAL_Main     = dst_local_root / "Main"
    dst_LOCAL_VaultDir = dst_LOCAL_Main / "Vault"
    dst_LOCAL_Set      = dst_local_root / "settings"
    dst_LOCAL_Soft     = dst_local_root / "Software"
    dst_ROAM_Main      = dst_roam_root / "Main"
    dst_ROAM_Store     = dst_roam_root / "KQ_Store"
    dst_ROAM_Config    = dst_roam_root / "Config"

    for d in (dst_LOCAL_VaultDir, dst_LOCAL_Set, dst_LOCAL_Soft,
              dst_ROAM_Main, dst_ROAM_Store, dst_ROAM_Config):
        d.mkdir(parents=True, exist_ok=True)

    # Canonical filenames
    def _name(key: str):
        fn = ORIG.get(key)
        if not callable(fn):
            return None
        try:
            if key == "user_db_file":
                return Path(fn(username, ensure_parent=False)).name
            return Path(fn(username, name_only=True)).name
        except Exception:
            return None

    name_db    = _name("user_db_file")
    name_vault = _name("vault_file")
    name_salt  = _name("salt_file")
    name_ids   = _name("identities_file")
    name_prefs = _name("security_prefs_file")
    name_bline = _name("baseline_file")

    # Copy USB → system
    try:
        if name_vault and (src_VAULT_D / name_vault).exists():
            shutil.copy2(src_VAULT_D / name_vault, dst_LOCAL_VaultDir / name_vault)
        if name_db and (src_MAIN / name_db).exists():
            shutil.copy2(src_MAIN / name_db, dst_ROAM_Main / name_db)
        if name_ids and (src_MAIN / name_ids).exists():
            shutil.copy2(src_MAIN / name_ids, dst_ROAM_Main / name_ids)
        if name_salt and (src_STORE / name_salt).exists():
            shutil.copy2(src_STORE / name_salt, dst_ROAM_Store / name_salt)
        if name_prefs and (src_CONFIG / name_prefs).exists():
            shutil.copy2(src_CONFIG / name_prefs, dst_ROAM_Config / name_prefs)
        if name_bline and (src_CONFIG / name_bline).exists():
            shutil.copy2(src_CONFIG / name_bline, dst_ROAM_Config / name_bline)
        if src_SET.exists() and src_SET.is_dir():
            shutil.copytree(src_SET, dst_LOCAL_Set, dirs_exist_ok=True)
        if src_SOFT.exists() and src_SOFT.is_dir():
            shutil.copytree(src_SOFT, dst_LOCAL_Soft, dirs_exist_ok=True)
    except Exception as e:
        QMessageBox.critical(parent, "Restore from USB", f"Copy failed:\n{e}")
        return False

    # Verify
    expect_local  = _expected_phase2_paths(username, dst_local_root)
    expect_roam   = _expected_phase2_paths(username, dst_roam_root)
    def _exists(d, key): return key in d and d[key].exists()
    if not (_exists(expect_roam, "salt") and _exists(expect_roam, "db")):
        QMessageBox.critical(parent, "Restore from USB", "Verification failed: salt or db missing.")
        return False

    # Detach any FileHandlers pointing under the USB user dir, then delete it
    try:
        _detach_file_handlers_under(usb_user)
    except Exception:
        pass

    try:
        def _onerror(func, path, exc_info):
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception:
                pass
        shutil.rmtree(usb_user, onerror=_onerror, ignore_errors=True)
        if usb_user.exists():
            time.sleep(0.3)
            shutil.rmtree(usb_user, onerror=_onerror, ignore_errors=True)
        logging.getLogger("keyquorum").info(f"[RESTORE] ✅ Deleted USB copy for {username}")
    except Exception as e:
        logging.getLogger("keyquorum").warning(f"[RESTORE] USB delete failed: {e}")

    QMessageBox.information(parent, "Restore Complete",
                            f"User '{username}' restored to this PC.\n\n"
                            f"Local:   {dst_local_root}\n"
                            f"Roaming: {dst_roam_root}\n\n"
                            f"The USB copy was permanently deleted.")
    return True





