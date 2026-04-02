#!/usr/bin/env python3
"""
Keyquorum Tools (standalone)
- Discover user storage roots (installed + portable)
- Inspect identity store header / decrypt identity payload
- Resolve master salt (identity header or legacy .slt) (read-only)
- Vault health check + decrypt vault (supports JSON envelope and binary formats)
- Outputs human-friendly text or JSON report
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import getpass
import hashlib
import json
import os
import platform
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Local (standalone) helpers
from check_identity_header import parse_identity_public_header, validate_identity_header

# Native DLL wrapper (Windows only, but tool runs elsewhere for non-vault tasks)
try:
    from keyquorum_core_ctypes import KeyquorumCore
except Exception:
    KeyquorumCore = None  # type: ignore




# ---------------------------
# DLL health check
# ---------------------------

def dll_health_report(dll_path: str, *, self_test: bool = True) -> Dict[str, Any]:
    """Load the native DLL and report version/features. Optionally run a quick encrypt/decrypt self-test.
    This is READ-ONLY and does not touch user data.
    """
    rep: Dict[str, Any] = {
        "dll": dll_path,
        "exists": False,
        "load_ok": False,
        "version": None,
        "crypto_backend": None,
        "features": {},
        "self_test": {"ran": False, "ok": False, "error": None},
    }

    p = Path(dll_path)
    rep["exists"] = p.exists()

    if KeyquorumCore is None:
        rep["self_test"]["error"] = "KeyquorumCore wrapper not available (import failed)"
        return rep

    if not rep["exists"]:
        rep["self_test"]["error"] = "DLL file not found"
        return rep

    try:
        core = KeyquorumCore(dll_path)
        rep["load_ok"] = True
        rep["version"] = core.version()
        rep["crypto_backend"] = core.crypto_backend()
        rep["features"] = {
            "session_open_ex": bool(getattr(core, "has_session_open_ex", lambda: False)()),
            "derive_vault_key_ex": bool(getattr(core, "has_derive_vault_key_ex", lambda: False)()),
            "dpapi_unprotect_to_session": bool(getattr(core, "_has_dpapi_to_session", False)),
            "session_export_key_dpapi": bool(getattr(core, "_has_session_export_dpapi", False)),
        }

        if self_test:
            rep["self_test"]["ran"] = True
            try:
                import os as _os
                key32 = _os.urandom(32)
                iv = _os.urandom(12)
                pt = b"kq_dll_healthcheck_v1"
                h = core.open_session_from_key(key32)
                try:
                    ct, tag = core.session_encrypt(h, iv, pt)
                    pt2 = core.session_decrypt(h, iv, bytes(ct), bytes(tag))
                finally:
                    try:
                        core.close_session(h)
                    except Exception:
                        pass

                rep["self_test"]["ok"] = (bytes(pt2) == pt)
                if not rep["self_test"]["ok"]:
                    rep["self_test"]["error"] = "roundtrip mismatch"
            except Exception as e:
                rep["self_test"]["ok"] = False
                rep["self_test"]["error"] = repr(e)

    except Exception as e:
        rep["load_ok"] = False
        rep["self_test"]["error"] = repr(e)

    return rep

# ---------------------------
# Defaults & path discovery
# ---------------------------

APP_NAME = "Keyquorum"
USERS_DIR_NAME = "Users"

def _env_path(name: str) -> Optional[Path]:
    v = os.environ.get(name)
    if v:
        try:
            return Path(v)
        except Exception:
            return None
    return None

def default_installed_local_root() -> Optional[Path]:
    """
    Installed Local root: %LOCALAPPDATA%\\Keyquorum
    """
    p = _env_path("LOCALAPPDATA")
    if not p:
        return None
    return (p / APP_NAME).resolve()

def default_installed_roaming_root() -> Optional[Path]:
    """
    Installed Roaming root: %APPDATA%\\Keyquorum
    """
    p = _env_path("APPDATA")
    if not p:
        return None
    return (p / APP_NAME).resolve()

def portable_root_from_marker(start: Path) -> Optional[Path]:
    """
    If user points at a folder that contains portable.marker, treat it as the portable root.
    """
    try:
        start = start.resolve()
    except Exception:
        return None
    if start.is_file():
        start = start.parent
    # walk up a few levels
    cur = start
    for _ in range(6):
        if (cur / "portable.marker").exists():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None

def users_root_candidates(users_root: Optional[Path], local_root: Optional[Path], roaming_root: Optional[Path], portable_root: Optional[Path]) -> List[Path]:
    out: List[Path] = []
    def add(p: Optional[Path]):
        if p and p not in out:
            out.append(p)

    # explicit override: already a Users directory OR a root containing Users
    if users_root:
        ur = users_root
        if ur.name.lower() != USERS_DIR_NAME.lower():
            ur = ur / USERS_DIR_NAME
        add(ur)

    # installed candidates
    add((local_root or default_installed_local_root() or Path()) / USERS_DIR_NAME if (local_root or default_installed_local_root()) else None)
    add((roaming_root or default_installed_roaming_root() or Path()) / USERS_DIR_NAME if (roaming_root or default_installed_roaming_root()) else None)

    # portable candidate
    if portable_root:
        add(portable_root / USERS_DIR_NAME)

    # filter existing
    return [p for p in out if p and p.exists()]

def list_users(roots: List[Path]) -> Dict[str, Dict[str, str]]:
    """
    Returns {username: {"root": "...", "type": "local/roaming/portable/unknown"}}
    """
    users: Dict[str, Dict[str, str]] = {}
    for r in roots:
        try:
            for d in r.iterdir():
                if d.is_dir():
                    uname = d.name
                    if uname not in users:
                        users[uname] = {"root": str(d), "users_root": str(r)}
        except Exception:
            continue
    return users

def guess_user_files(username: str, user_dir: Path, *, roaming_root: Optional[Path], local_root: Optional[Path], portable_root: Optional[Path]) -> Dict[str, Path]:
    """
    Compute canonical file paths using the same conventions as app.paths.
    We try:
    - vault in Local Users/<u>/Main/Vault/<u>.kq_user   (or relative to found user_dir)
    - identities in Roaming Users/<u>/Main/<u>.kq_id
    - legacy salt in Roaming Users/<u>/KQ_Store/kq_user_<u>.slt
    - user_db in Roaming Users/<u>/KQ_Store/user_db.json (fallback)
    """
    u = username.strip()
    # base dirs
    # If user_dir is already ...Users/<u>, we can derive both local/roaming siblings if roots known.
    # Otherwise use passed roots.
    def _users_root_of(p: Path) -> Path:
        # expects .../Users/<u>
        return p.parent

    users_root = _users_root_of(user_dir)
    # Try to determine whether this root is Local or Roaming by name (best effort)
    # We'll also accept overrides.
    local_users_root = (local_root / USERS_DIR_NAME) if local_root else None
    roaming_users_root = (roaming_root / USERS_DIR_NAME) if roaming_root else None
    portable_users_root = (portable_root / USERS_DIR_NAME) if portable_root else None

    # If user_dir lives under some root, mirror across to the other roots too.
    candidates_user_dirs: List[Path] = []
    candidates_user_dirs.append(user_dir)
    for ur in [local_users_root, roaming_users_root, portable_users_root]:
        if ur and ur.exists():
            candidates_user_dirs.append(ur / u)

    # Choose best existing for vault (Local preferred), identities (Roaming preferred)
    def _first_existing(paths: List[Path]) -> Optional[Path]:
        for p in paths:
            if p.exists():
                return p
        return None

    # Vault path candidates
    vault_candidates = []
    for ud in candidates_user_dirs:
        vault_candidates.append(ud / "Main" / "Vault" / f"{u}.kq_user")
        vault_candidates.append(ud / "Vault" / f"{u}.kq_user")  # older layouts
    vault_path = _first_existing(vault_candidates) or vault_candidates[0]

    # Identity store candidates (roaming main)
    id_candidates = []
    for ud in candidates_user_dirs:
        id_candidates.append(ud / "Main" / f"{u}.kq_id")
        id_candidates.append(ud / f"{u}.kq_id")
    identities_path = _first_existing(id_candidates) or id_candidates[0]

    # Legacy salt candidates (roaming store)
    salt_candidates = []
    for ud in candidates_user_dirs:
        salt_candidates.append(ud / "KQ_Store" / f"kq_user_{u}.slt")
        salt_candidates.append(ud / "Main" / "KQ_Store" / f"kq_user_{u}.slt")
    legacy_salt_path = _first_existing(salt_candidates) or salt_candidates[0]

    # Wrapped key (recovery)
    wrap_candidates = []
    for ud in candidates_user_dirs:
        wrap_candidates.append(ud / "Main" / "Vault" / f"{u}.kq_wrap")
        wrap_candidates.append(ud / "Vault" / f"{u}.kq_wrap")
    wrapped_key_path = _first_existing(wrap_candidates) or wrap_candidates[0]

    # user_db
    db_candidates = []
    for ud in candidates_user_dirs:
        db_candidates.append(ud / "KQ_Store" / "user_db.json")
        db_candidates.append(ud / "Main" / "KQ_Store" / "user_db.json")
    user_db_path = _first_existing(db_candidates) or db_candidates[0]

    return {
        "vault": vault_path,
        "identities": identities_path,
        "legacy_salt": legacy_salt_path,
        "wrapped_key": wrapped_key_path,
        "user_db": user_db_path,
    }

def sha256_file(p: Path, limit_mb: int = 64) -> str:
    """
    Hash first N MB (default 64) to keep it fast on huge files.
    """
    h = hashlib.sha256()
    if not p.exists() or not p.is_file():
        return ""
    max_bytes = limit_mb * 1024 * 1024
    with p.open("rb") as f:
        remaining = max_bytes
        while remaining > 0:
            chunk = f.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
    return h.hexdigest()

# ---------------------------
# Identity store helpers
# ---------------------------

def inspect_identity(path: Path) -> Dict[str, Any]:
    raw = path.read_bytes()
    header = parse_identity_public_header(raw)
    problems = validate_identity_header(header)
    meta = header.get("meta") if isinstance(header, dict) else None
    ms = ""
    if isinstance(meta, dict):
        ms = (meta.get("master_salt_b64") or "").strip()
    return {
        "path": str(path),
        "exists": path.exists(),
        "size": path.stat().st_size if path.exists() else 0,
        "sha256": sha256_file(path),
        "header_ok": (not any(str(x).startswith("FAIL:") for x in problems)),
        "problems": problems,
        "master_salt_in_header": bool(ms),
        "header": header,
    }


# ---------------------------
# Master salt (read-only, tool-side)
# ---------------------------

def resolve_master_salt_readonly(identity_report: Dict[str, Any], legacy_salt_path: Optional[Path]) -> Tuple[Optional[bytes], str, Optional[str]]:
    """
    Read-only master-salt resolver for tooling.

    Order:
      1) Identity public header meta.master_salt_b64 (if present)
      2) Legacy .slt file (raw bytes)
    Returns: (salt_bytes_or_None, source, error_or_None)
    """

    # 1) identity header
    try:
        meta = identity_report.get("meta") if isinstance(identity_report, dict) else None
    except Exception:
        meta = None

    # Our inspect_identity() stores master_salt_in_header boolean but doesn't expose meta,
    # so we also accept "header" if present. If not present, we re-parse via check_identity_header in inspect_identity.
    header = identity_report.get("header") if isinstance(identity_report, dict) else None
    if isinstance(header, dict):
        meta = header.get("meta") if isinstance(header.get("meta"), dict) else meta

    if isinstance(meta, dict):
        ms = (meta.get("master_salt_b64") or "").strip()
        if ms:
            try:
                b = base64.b64decode(ms.encode(), validate=True)
                if len(b) >= 8:
                    return b, "identity_header", None
            except Exception as e:
                return None, "identity_header", f"master_salt_b64 invalid: {e}"

    # 2) legacy .slt file
    if legacy_salt_path and legacy_salt_path.exists():
        try:
            b = legacy_salt_path.read_bytes()
            if len(b) >= 8:
                return b, "legacy_slt", None
            return None, "legacy_slt", f"legacy salt file too short ({len(b)} bytes)"
        except Exception as e:
            return None, "legacy_slt", repr(e)

    return None, "missing", "no master salt found in identity header or legacy .slt"

# ---------------------------
# Vault decrypt (v1/v2 formats)
# ---------------------------

def _find_dll(dll_arg: Optional[str]) -> Optional[Path]:
    if dll_arg:
        p = Path(dll_arg)
        if p.exists():
            return p.resolve()
    # common: same folder as script
    here = Path(__file__).resolve().parent
    for cand in [here / "keyquorum_core.dll", here / "native" / "keyquorum_core.dll"]:
        if cand.exists():
            return cand.resolve()
    return None

def open_native_session(dll_path: Path, password: str, salt: bytes, *, kdf_ex: Optional[Tuple[int,int,int]]=None) -> int:
    if not KeyquorumCore:
        raise RuntimeError("Native core wrapper not available (keyquorum_core_ctypes import failed)")
    core = KeyquorumCore(str(dll_path))
    pwb = bytearray(password.encode("utf-8"))
    if kdf_ex:
        tcost, mem_kib, par = kdf_ex
        return core.open_session_ex(pwb, salt, tcost, mem_kib, par)
    return core.open_session(pwb, salt)

def decrypt_vault_with_session(dll_path: Path, session_handle: int, vault_path: Path) -> Any:
    """
    Supports:
      A) JSON envelope: {"iv","tag","vault_data"} base64
      B) Binary blob: iv(12) || tag(16) || ct
      C) Binary blob: iv(12) || ct || tag(16)
    """
    if not KeyquorumCore:
        raise RuntimeError("Native core wrapper not available (keyquorum_core_ctypes import failed)")
    core = KeyquorumCore(str(dll_path))
    blob = vault_path.read_bytes()
    if len(blob) == 0:
        raise RuntimeError("Vault file is empty")

    def _decrypt(iv: bytes, ct: bytes, tag: bytes):
        pt_buf = core.session_decrypt(int(session_handle), iv, ct, tag)
        try:
            pt = bytes(pt_buf)
        finally:
            try:
                core.secure_wipe(pt_buf)
            except Exception:
                pass
        return json.loads(pt.decode("utf-8"))

    # A) JSON envelope or plaintext JSON
    if blob[:1] in (b"{", b"["):
        obj = json.loads(blob.decode("utf-8"))
        if isinstance(obj, (list, dict)) and ("iv" not in obj or ("vault_data" not in obj and "data" not in obj)):
            return obj
        iv = base64.b64decode(obj["iv"])
        tag = base64.b64decode(obj["tag"])
        ct  = base64.b64decode(obj.get("vault_data") or obj.get("data"))
        return _decrypt(iv, ct, tag)

    if len(blob) < 12 + 16:
        raise RuntimeError("Encrypted vault file too small / invalid format")
    iv = blob[:12]
    rest = blob[12:]

    # B: iv || tag || ct
    tag1 = rest[:16]
    ct1  = rest[16:]
    try:
        return _decrypt(iv, ct1, tag1)
    except Exception:
        pass
    # C: iv || ct || tag
    tag2 = rest[-16:]
    ct2  = rest[:-16]
    return _decrypt(iv, ct2, tag2)

# ---------------------------
# Reporting
# ---------------------------

def file_info(p: Path) -> Dict[str, Any]:
    return {
        "path": str(p),
        "exists": p.exists(),
        "size": p.stat().st_size if p.exists() else 0,
        "sha256": sha256_file(p) if p.exists() else "",
    }

def health_report(username: str, *, users_root: Optional[Path], local_root: Optional[Path], roaming_root: Optional[Path], portable_root: Optional[Path], vault_path: Optional[Path], identities_path: Optional[Path], dll_path: Optional[Path], do_vault_decrypt: bool, password: Optional[str]) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "username": username,
        "platform": platform.platform(),
        "roots": {
            "users_root_override": str(users_root) if users_root else "",
            "local_root": str(local_root) if local_root else str(default_installed_local_root() or ""),
            "roaming_root": str(roaming_root) if roaming_root else str(default_installed_roaming_root() or ""),
            "portable_root": str(portable_root) if portable_root else "",
        },
        "files": {},
        "salt": {},
        "identity": {},
        "vault": {},
        "ready_to_unlock": False,
    }

    # locate user dir
    roots = users_root_candidates(users_root, local_root, roaming_root, portable_root)
    users = list_users(roots)
    if username not in users:
        # still allow explicit file paths
        report["notes"] = f"User '{username}' not found under discovered roots."
        user_dir = None
    else:
        user_dir = Path(users[username]["root"])

    paths = {}
    if user_dir:
        paths = guess_user_files(username, user_dir, roaming_root=roaming_root or default_installed_roaming_root(), local_root=local_root or default_installed_local_root(), portable_root=portable_root)
    # apply overrides
    if vault_path:
        paths["vault"] = vault_path
    if identities_path:
        paths["identities"] = identities_path

    # file info
    for k, p in paths.items():
        report["files"][k] = file_info(Path(p))

    # identity header
    idp = Path(paths.get("identities")) if paths.get("identities") else None
    if idp and idp.exists():
        try:
            report["identity"] = inspect_identity(idp)
        except Exception as e:
            report["identity"] = {"path": str(idp), "header_ok": False, "error": repr(e)}
    else:
        report["identity"] = {"path": str(idp) if idp else "", "header_ok": False, "error": "identity file missing"}

    # salt resolution (read-only, no app imports)
    salt_bytes = None
    try:
        legacy_salt_path = Path(paths.get("legacy_salt")) if paths.get("legacy_salt") else None
        salt_bytes, salt_src, salt_err = resolve_master_salt_readonly(report.get("identity", {}), legacy_salt_path)
        report["salt"] = {
            "ok": bool(salt_bytes),
            "len": len(salt_bytes) if salt_bytes else 0,
            "source": salt_src,
        }
        if salt_err:
            report["salt"]["error"] = salt_err
        if salt_bytes:
            report["salt"]["sha256"] = hashlib.sha256(salt_bytes).hexdigest()
    except Exception as e:
        report["salt"] = {"ok": False, "error": repr(e)}

    # vault decrypt preflight
    vp = Path(paths.get("vault")) if paths.get("vault") else None
    report["vault"] = {"path": str(vp) if vp else "", "exists": bool(vp and vp.exists())}

    if not vp or not vp.exists():
        report["vault"]["ok"] = False
        report["vault"]["error"] = "vault file missing"
        return report

    # ready if vault exists and salt ok, plus dll if decrypting
    salt_ok = bool(report["salt"].get("ok"))
    dll_ok = bool(dll_path and dll_path.exists()) if do_vault_decrypt else True

    if do_vault_decrypt:
        report["vault"]["dll"] = str(dll_path) if dll_path else ""
        report["vault"]["dll_ok"] = bool(dll_ok)

    if do_vault_decrypt and salt_ok and dll_ok:
        if password is None:
            password = getpass.getpass("Password for vault decrypt: ")
        # Actually open session & decrypt
        try:
            salt = salt_bytes  # from resolve_master_salt_readonly
            session_handle = open_native_session(dll_path, password, salt)
            data = decrypt_vault_with_session(dll_path, session_handle, vp)
            # minimal sanity
            count = len(data) if isinstance(data, list) else (1 if isinstance(data, dict) else 0)
            report["vault"]["ok"] = True
            report["vault"]["entries"] = count
        except Exception as e:
            report["vault"]["ok"] = False
            report["vault"]["error"] = repr(e)
    else:
        report["vault"]["ok"] = salt_ok and bool(vp.exists())
        report["vault"]["note"] = "Decrypt not attempted (missing salt and/or DLL and/or password)."

    report["ready_to_unlock"] = bool(report["vault"].get("ok")) and bool(report["identity"].get("header_ok")) and salt_ok
    return report


def cmd_discover(args) -> int:
    portable = Path(args.portable_root) if args.portable_root else None
    roots = users_root_candidates(Path(args.users_root) if args.users_root else None,
                                 Path(args.local_root) if args.local_root else None,
                                 Path(args.roaming_root) if args.roaming_root else None,
                                 portable)
    users = list_users(roots)
    out = {"roots": [str(r) for r in roots], "users": users}
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print("Discovered roots:")
        for r in roots:
            print(f" - {r}")
        print("\nUsers:")
        for u, info in users.items():
            print(f" - {u}  ({info.get('root')})")
    return 0

def cmd_inspect_user(args) -> int:
    username = args.user
    portable = Path(args.portable_root) if args.portable_root else None
    report = health_report(
        username,
        users_root=Path(args.users_root) if args.users_root else None,
        local_root=Path(args.local_root) if args.local_root else None,
        roaming_root=Path(args.roaming_root) if args.roaming_root else None,
        portable_root=portable,
        vault_path=Path(args.vault) if args.vault else None,
        identities_path=Path(args.identity) if args.identity else None,
        dll_path=_find_dll(args.dll),
        do_vault_decrypt=False,
        password=None,
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"User: {username}")
        print("\nFiles:")
        for k, info in report.get("files", {}).items():
            print(f" - {k}: {info.get('path')}  exists={info.get('exists')}  size={info.get('size')}")
        print("\nIdentity:")
        ident = report.get("identity", {})
        print(f" - header_ok={ident.get('header_ok')} master_salt_in_header={ident.get('master_salt_in_header', False)}")
        if ident.get("problems"):
            for pr in ident["problems"]:
                print(f"   * {pr}")
        print("\nSalt:")
        s = report.get("salt", {})
        print(f" - ok={s.get('ok')} len={s.get('len')} sha256={s.get('sha256','')[:12]}...")
        print("\nVault:")
        v = report.get("vault", {})
        print(f" - exists={v.get('exists')} ok={v.get('ok')} note={v.get('note','')}")
    return 0

def cmd_check_identity(args) -> int:
    p = Path(args.identity)
    raw = p.read_bytes()
    header = parse_identity_public_header(raw)
    probs = validate_identity_header(header)
    if args.inspect:
        print(json.dumps(header, indent=2))
    if probs:
        print("[FAIL] Identity header problems:")
        for pr in probs:
            print(f" - {pr}")
        return 10
    print("[OK] Identity header looks valid.")
    meta = header.get("meta") if isinstance(header, dict) else None
    ms = (meta.get("master_salt_b64") or "").strip() if isinstance(meta, dict) else ""
    print(f"[INFO] master_salt_in_header={'YES' if ms else 'NO'}")
    return 0


def cmd_decrypt_vault(args) -> int:
    username = args.user
    dll = _find_dll(args.dll)

    if not dll or not dll.exists():
        print("ERROR: keyquorum_core.dll not found. Use --dll PATH.", file=sys.stderr)
        return 2

    portable = Path(args.portable_root) if args.portable_root else None

    # Discover user directory
    roots = users_root_candidates(
        Path(args.users_root) if args.users_root else None,
        Path(args.local_root) if args.local_root else None,
        Path(args.roaming_root) if args.roaming_root else None,
        portable,
    )
    users = list_users(roots)

    if username not in users and not args.vault:
        print("ERROR: user not found and --vault not provided.", file=sys.stderr)
        return 4

    # Resolve file paths
    if args.vault:
        vault_path = Path(args.vault)
        identity_path = Path(args.identity) if args.identity else None
        legacy_salt_path = None
    else:
        user_dir = Path(users[username]["root"])
        paths = guess_user_files(
            username,
            user_dir,
            roaming_root=Path(args.roaming_root) if args.roaming_root else default_installed_roaming_root(),
            local_root=Path(args.local_root) if args.local_root else default_installed_local_root(),
            portable_root=portable,
        )
        vault_path = Path(paths["vault"])
        identity_path = Path(paths["identities"])
        legacy_salt_path = Path(paths["legacy_salt"])

    if not vault_path.exists():
        print(f"ERROR: vault file not found: {vault_path}", file=sys.stderr)
        return 5

    # Inspect identity
    identity_report = {}
    if identity_path and identity_path.exists():
        identity_report = inspect_identity(identity_path)

    # Resolve salt (correct way)
    salt_bytes, salt_src, salt_err = resolve_master_salt_readonly(identity_report, legacy_salt_path)

    if not salt_bytes:
        print(f"ERROR: master salt missing ({salt_err})", file=sys.stderr)
        return 3

    # Password
    pw = args.password or getpass.getpass("Password: ")

    # Open native session
    session = open_native_session(dll, pw, salt_bytes)

    # Decrypt
    data = decrypt_vault_with_session(dll, session, vault_path)

    if args.out:
        Path(args.out).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[OK] Decrypted vault -> {args.out}")
    else:
        if isinstance(data, list):
            print(f"[OK] Decrypted vault entries: {len(data)}")
        elif isinstance(data, dict):
            print("[OK] Decrypted vault (single object)")
        else:
            print("[OK] Decrypted vault (unknown shape)")

    return 0



def cmd_health(args) -> int:
    username = args.user
    dll = _find_dll(args.dll)
    portable = Path(args.portable_root) if args.portable_root else None
    report = health_report(
        username,
        users_root=Path(args.users_root) if args.users_root else None,
        local_root=Path(args.local_root) if args.local_root else None,
        roaming_root=Path(args.roaming_root) if args.roaming_root else None,
        portable_root=portable,
        vault_path=Path(args.vault) if args.vault else None,
        identities_path=Path(args.identity) if args.identity else None,
        dll_path=dll,
        do_vault_decrypt=bool(args.decrypt_vault),
        password=args.password,
    )
    print(json.dumps(report, indent=2))
    # nonzero if not ready
    return 0 if report.get("ready_to_unlock") else 11


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="kq_tool", description="Keyquorum standalone tools (v1/v2 vault + identity + health)")
    ap.add_argument("--json", action="store_true", help="JSON output (where applicable)")
    ap.add_argument("--users-root", help="Override Users root (path to ...\\Users or a root containing Users)")
    ap.add_argument("--local-root", help="Override installed Local root (default %LOCALAPPDATA%\\Keyquorum)")
    ap.add_argument("--roaming-root", help="Override installed Roaming root (default %APPDATA%\\Keyquorum)")
    ap.add_argument("--portable-root", help="Portable root (folder containing portable.marker), if applicable")
    ap.add_argument("--dll", help="Path to keyquorum_core.dll (required for vault decrypt checks)")

    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("dll-health", help="Check native DLL version/features and run a crypto self-test")
    p.add_argument("--no-self-test", action="store_true", help="Skip encrypt/decrypt self-test")
    p.set_defaults(fn=cmd_dll_health)


    p = sub.add_parser("discover", help="Discover user roots and list users")
    p.set_defaults(fn=cmd_discover)

    p = sub.add_parser("inspect-user", help="Show files + identity header + salt status (no decrypt)")
    p.add_argument("--user", required=True)
    p.add_argument("--vault", help="Vault file path override")
    p.add_argument("--identity", help="Identity file path override")
    p.set_defaults(fn=cmd_inspect_user)

    p = sub.add_parser("check-identity", help="Validate identity header (read-only)")
    p.add_argument("identity", help="Path to <user>.kq_id")
    p.add_argument("--inspect", action="store_true", help="Print header JSON")
    p.set_defaults(fn=cmd_check_identity)

    p = sub.add_parser("decrypt-vault", help="Decrypt vault using native DLL session (requires password)")
    p.add_argument("--user", required=True)
    p.add_argument("--vault", help="Vault file path override")
    p.add_argument("--password", help="Password (discouraged; prefer prompt)")
    p.add_argument("--out", help="Write decrypted JSON to file")
    p.set_defaults(fn=cmd_decrypt_vault)

    p = sub.add_parser("health", help="Full health report (optionally tries vault decrypt)")
    p.add_argument("--user", required=True)
    p.add_argument("--vault", help="Vault file path override")
    p.add_argument("--identity", help="Identity file path override")
    p.add_argument("--decrypt-vault", action="store_true", help="Attempt real vault decrypt (requires DLL + password)")
    p.add_argument("--password", help="Password (discouraged; prefer prompt)")
    p.set_defaults(fn=cmd_health)

    return ap

def cmd_dll_health(args) -> int:
    if not args.dll:
        print("[ERR] --dll is required for dll-health")
        return 2
    rep = dll_health_report(args.dll, self_test=(not args.no_self_test))
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"DLL: {rep.get('dll')}")
        print(f"Exists: {rep.get('exists')}, Load OK: {rep.get('load_ok')}")
        print(f"Version: {rep.get('version')}")
        print(f"Backend: {rep.get('crypto_backend')}")
        feats = rep.get('features') or {}
        print("Features:")
        for k, v in feats.items():
            print(f"  - {k}: {v}")
        st = rep.get('self_test') or {}
        if st.get("ran"):
            print(f"Self-test: {'OK' if st.get('ok') else 'FAIL'}")
            if st.get("error"):
                print(f"  Error: {st.get('error')}")
        else:
            print("Self-test: skipped")
    return 0 if rep.get("load_ok") and ((rep.get("self_test") or {}).get("ok") or args.no_self_test) else 10



def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    return int(args.fn(args))

if __name__ == "__main__":
    raise SystemExit(main())
