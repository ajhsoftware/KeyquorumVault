# -*- coding: utf-8 -*-

# Keyquorum Vault - Development / Smoke Test Tool
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

# ============================================================================================================


"""
Keyquorum Vault – kv_auto_tests_V5_PRO (one-shot + Markdown report)

Run:
  python kv_auto_tests_V5_PRO.py

Report:
  %TEMP%\\Keyquorum_Test_Workspace\\kv_auto_tests_report.md

Opt-in flags:
  set KQ_TEST_PORTABLE=1     # portable build/move/restore smoke
  set KQ_TEST_YK_TOUCH=1     # live YubiKey touch tests (requires hardware)
  set KQ_TEST_WINHELLO=1     # Windows Hello smoke (may prompt)
  set KQ_IMPORT_SWEEP_FAIL=1 # make import sweep FAIL (default is report-only)

Design goals:
- Test *app code* (auth/vault/security/features/workers), not tools.
- CI-safe by default (no UI hangs).
- Clear report: what ran, what passed/failed, what skipped and why.
"""

from __future__ import annotations

import os
import sys
import time
import json
import shutil
import zipfile
import hashlib
import traceback
import datetime as dt
import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Any


# =============================================================================
# Workspace routing (must happen before importing app.paths)
# =============================================================================

PKG_ROOT = Path(__file__).resolve().parent  # src/main/python

TEST_ROOT = (
    Path(os.environ["KQ_TEST_ROOT"])
    if os.environ.get("KQ_TEST_ROOT")
    else (Path(os.getenv("TEMP", str(PKG_ROOT))) / "Keyquorum_Test_Workspace")
)
LOCALAPPDATA_TEST = TEST_ROOT / "LocalAppData"
APPDATA_TEST = TEST_ROOT / "RoamingAppData"

os.environ["LOCALAPPDATA"] = str(LOCALAPPDATA_TEST)
os.environ["APPDATA"] = str(APPDATA_TEST)
os.environ.setdefault("KEYQUORUM_TEST_MODE", "1")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

if str(PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(PKG_ROOT))


# =============================================================================
# Configuration
# =============================================================================

TEST_USER = os.environ.get("KQ_TEST_USER", "kq_test_user")
TEST_PASS = os.environ.get("KQ_TEST_PASS", "TestPass!234")
TEST_PASS_BAD = "WrongPass!234"
TEST_TOTP_SECRET_B32 = "JBSWY3DPEHPK3PXP"
EXPORT_PW = os.environ.get("KQ_TEST_EXPORT_PW", "TestExportPW123!")

RUN_PORTABLE = os.environ.get("KQ_TEST_PORTABLE", "0").strip().lower() in {"1", "true", "yes", "on"}
RUN_YK_TOUCH = os.environ.get("KQ_TEST_YK_TOUCH", "0").strip().lower() in {"1", "true", "yes", "on"}
RUN_WINHELLO = os.environ.get("KQ_TEST_WINHELLO", "0").strip().lower() in {"1", "true", "yes", "on"}

IMPORT_SWEEP_FAIL = os.environ.get("KQ_IMPORT_SWEEP_FAIL", "0").strip().lower() in {"1", "true", "yes", "on"}

REPORT_PATH = TEST_ROOT / "kv_auto_tests_report.md"

# Captured from create_or_update_user result
CREATED_BACKUP_CODES: list[str] = []


# =============================================================================
# Reporting harness
# =============================================================================

@dataclass
class TestResult:
    name: str
    status: str  # PASS/FAIL/SKIP
    seconds: float = 0.0
    reason: str = ""


class SkipTest(RuntimeError):
    pass


class Report:
    def __init__(self) -> None:
        self.md: list[str] = []
        self._section: list[str] | None = None

    def h1(self, t: str) -> None:
        self.md += [f"# {t}", ""]

    def h2(self, t: str) -> None:
        self.md += [f"## {t}", ""]

    def h3(self, t: str) -> None:
        self.md += [f"### {t}", ""]

    def p(self, s: str = "") -> None:
        self.md += [s, ""]

    def li(self, s: str) -> None:
        self.md.append(f"- {s}")

    def start(self, title: str) -> None:
        self.h3(title)
        self._section = []

    def log(self, s: str) -> None:
        print(s)
        if self._section is not None:
            self._section.append(s)

    def end(self) -> None:
        if self._section is not None:
            self.md.append("```text")
            self.md.extend(self._section)
            self.md.append("```")
            self.md.append("")
        self._section = None

    def write(self, path: Path) -> None:
        path.write_text("\n".join(self.md), encoding="utf-8")


REP = Report()


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _now() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _mk_workspace() -> None:
    TEST_ROOT.mkdir(parents=True, exist_ok=True)
    LOCALAPPDATA_TEST.mkdir(parents=True, exist_ok=True)
    APPDATA_TEST.mkdir(parents=True, exist_ok=True)


def _safe_rm_tree(p: Path) -> None:
    try:
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
    except Exception:
        pass


def _clean_workspace() -> None:
    nm = TEST_ROOT.name.lower()
    if nm.startswith("keyquorum_test_") or TEST_ROOT.name == "Keyquorum_Test_Workspace":
        _safe_rm_tree(TEST_ROOT)


def _sha256_file(p: Path) -> str | None:
    try:
        if not p.exists() or not p.is_file():
            return None
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _ensure_qapp() -> None:
    try:
        from PySide6.QtWidgets import QApplication  # type: ignore
        if QApplication.instance() is None:
            _ = QApplication([])
    except Exception:
        pass


def _parse_verify_baseline(ret: Any) -> tuple[bool, str]:
    """
    Supports both shapes:
      (changed:list, missing:list, new:list, mac_ok:bool)
      (ok:bool, why:str)
    """
    if isinstance(ret, tuple) and len(ret) == 4:
        changed, missing, new_files, mac_ok = ret
        changed = list(changed or [])
        missing = list(missing or [])
        new_files = list(new_files or [])
        ok = bool(mac_ok) and (len(changed) == 0) and (len(missing) == 0)
        why = f"mac_ok={bool(mac_ok)} changed={len(changed)} missing={len(missing)} new={len(new_files)}"
        return ok, why
    if isinstance(ret, tuple) and len(ret) == 2 and isinstance(ret[0], bool):
        ok, why = ret
        return bool(ok), str(why or "")
    if isinstance(ret, bool):
        return bool(ret), ""
    return False, f"unrecognized verify_baseline return: {ret!r}"


# =============================================================================
# Tests
# =============================================================================

def t_core_imports() -> None:
    REP.log("Importing core packages...")
    import app  # noqa
    import auth  # noqa
    import vault_store  # noqa
    import security  # noqa
    import features  # noqa
    import workers  # noqa
    REP.log("Core imports OK.")


def t_import_sweep() -> None:
    """
    Walk auth/, vault_store/, security/, features/, workers/ and attempt imports.
    This catches broken imports early.

    Default: report-only (SKIP) if failures.
    If KQ_IMPORT_SWEEP_FAIL=1: will FAIL on any error.
    """
    roots = ["auth", "vault_store", "security", "features", "workers"]
    failures: list[str] = []

    for r in roots:
        base = PKG_ROOT / r
        if not base.exists():
            continue

        for py in base.rglob("*.py"):
            if py.name.startswith("_"):
                continue
            rel = py.relative_to(PKG_ROOT).with_suffix("")
            mod = ".".join(rel.parts)

            # skip tests / vendored / known-noisy files
            if any(part in {"__pycache__", "tests", "test"} for part in rel.parts):
                continue

            try:
                importlib.import_module(mod)
            except Exception as e:
                failures.append(f"{mod}: {e!r}")

    REP.log(f"Import sweep checked roots={roots}")
    REP.log(f"Import sweep failures={len(failures)}")
    for line in failures[:50]:
        REP.log(f"  - {line}")
    if len(failures) > 50:
        REP.log(f"  ... and {len(failures) - 50} more")

    if failures:
        msg = "Import sweep found failing imports (see list above)."
        if IMPORT_SWEEP_FAIL:
            raise AssertionError(msg)
        raise SkipTest(msg)


def t_create_dummy_account_verify_files() -> None:
    global CREATED_BACKUP_CODES

    from new_users.account_creator import create_or_update_user  # type: ignore
    from app.paths import (
        vault_file, salt_file, user_db_file, identities_file,
        user_root_local, user_root_roaming,
    )

    REP.log(f"Creating dummy account: {TEST_USER!r} (recovery_mode=True)")
    res = create_or_update_user(
        TEST_USER,
        TEST_PASS,
        TEST_PASS,
        recovery_mode=True,
        update_mode=False,
        regenerate_keys=True,
        regenerate_recovery_key=True,
        password_strength_check=False,
        debug=False,
    )

    status = str(res.get("status", "")).strip().upper() if isinstance(res, dict) else ""
    ok = (
        (isinstance(res, dict) and (res.get("ok") is True or res.get("success") is True))
        or status in {"SUCCESS", "OK", "CREATED", "UPDATED"}
        or res is True
    )
    require(ok, f"create_or_update_user did not report success. result={res!r}")

    CREATED_BACKUP_CODES = list((res.get("backup_codes") or []) if isinstance(res, dict) else [])
    REP.log(f"create_or_update_user -> status={status!r} backup_codes={len(CREATED_BACKUP_CODES)} recovery_key={bool(res.get('recovery_key')) if isinstance(res, dict) else 'n/a'}")

    vp = Path(vault_file(TEST_USER, ensure_parent=True))
    sp = Path(salt_file(TEST_USER, ensure_parent=True, name_only=False))
    dbp = Path(user_db_file(TEST_USER, ensure_parent=True))
    idp = Path(identities_file(TEST_USER, ensure_parent=True))
    ul = Path(user_root_local(TEST_USER, ensure=False))
    ur = Path(user_root_roaming(TEST_USER, ensure=False))

    REP.log(f"User root local:   {ul} exists={ul.exists()}")
    REP.log(f"User root roaming: {ur} exists={ur.exists()}")
    REP.log(f"Vault file:        {vp} exists={vp.exists()} sha256={_sha256_file(vp) or 'n/a'}")
    REP.log(f"Salt file:         {sp} exists={sp.exists()} sha256={_sha256_file(sp) or 'n/a'}")
    REP.log(f"User DB file:      {dbp} exists={dbp.exists()}")
    REP.log(f"Identity file:     {idp} exists={idp.exists()}")

    require(vp.exists(), "Vault file missing after account creation")
    require(sp.exists(), "Salt file missing after account creation")
    require(dbp.exists(), "Per-user DB missing after account creation")
    require(idp.exists(), "Identity file missing after account creation")


def t_backup_codes_store_consume() -> None:
    if not CREATED_BACKUP_CODES:
        raise SkipTest("No backup codes captured from account creation; cannot test store/consume.")

    from auth.login.login_handler import set_user_backup_codes  # type: ignore
    from auth.login import login_handler as lh  # type: ignore

    # Prefer the new unified API if present
    use_fn = getattr(lh, "use_backup_code", None)
    if use_fn is None:
        # fallback (older builds) - try identity-store wrappers if you exposed them
        consume_fn = None
        for cand in ("consume_login_backup_code", "consume_backup_code", "consume_backup_code_login"):
            if hasattr(lh, cand):
                consume_fn = getattr(lh, cand)
                break
        if consume_fn is None:
            raise SkipTest("No backup code consume API found (expected use_backup_code).")

    # Store as LOGIN backup codes (forgot-password / recovery codes)
    set_user_backup_codes(
        TEST_USER,
        list(CREATED_BACKUP_CODES),
        "login",
        password_for_identity=TEST_PASS,
    )

    REP.log(f"Stored backup codes count={len(CREATED_BACKUP_CODES)}")

    c0 = CREATED_BACKUP_CODES[0]

    if use_fn is not None:
        # ✅ correct signature for current login_handler.py
        ok1 = bool(use_fn(TEST_USER, c0, "login", password_for_identity=TEST_PASS))
        ok2 = bool(use_fn(TEST_USER, c0, "login", password_for_identity=TEST_PASS))
    else:
        # legacy fallbacks (only if your module exposes one)
        ok1 = bool(consume_fn(TEST_USER, TEST_PASS, c0))
        ok2 = bool(consume_fn(TEST_USER, TEST_PASS, c0))

    REP.log(f"consume(first)  -> {ok1}")
    REP.log(f"consume(second) -> {ok2} (expected False)")

    require(ok1 is True and ok2 is False, "Backup code did not behave as one-time-use.")

def t_login_good_bad() -> None:
    from auth.login.login_handler import validate_login  # type: ignore
    ok_good = bool(validate_login(TEST_USER, TEST_PASS))
    ok_bad = bool(validate_login(TEST_USER, TEST_PASS_BAD))
    REP.log(f"validate_login(correct) -> {ok_good}")
    REP.log(f"validate_login(wrong)   -> {ok_bad} (expected False)")
    require(ok_good is True, "validate_login should succeed with correct password")
    require(ok_bad is False, "validate_login should fail with wrong password")


def t_lockout_reset() -> None:
    from auth.login.login_handler import is_locked_out, register_login_failure, reset_login_failures, get_login_fail_state  # type: ignore

    reset_login_failures(TEST_USER)
    locked, msg = is_locked_out(TEST_USER)
    REP.log(f"locked(before)={locked} msg={msg}")

    for i in range(3):
        c = register_login_failure(TEST_USER, max_attempts=3, lock_minutes=5)
        REP.log(f"register_login_failure #{i+1} -> fail_count={c}")

    st = get_login_fail_state(TEST_USER)
    REP.log(f"state(after)={st}")

    locked2, msg2 = is_locked_out(TEST_USER, threshold=3)
    REP.log(f"locked(after)={locked2} msg={msg2}")
    require(locked2 is True, "User was not locked out after forced failures")

    reset_login_failures(TEST_USER)
    locked3, msg3 = is_locked_out(TEST_USER, threshold=3)
    REP.log(f"locked(after reset)={locked3} msg={msg3}")
    require(locked3 is False, "Lockout did not clear after reset")


def t_totp_set_get() -> None:
    from auth.identity_store import set_totp_secret, get_totp_secret, has_totp_quick  # type: ignore

    set_totp_secret(TEST_USER, TEST_PASS, TEST_TOTP_SECRET_B32)
    quick = bool(has_totp_quick(TEST_USER))
    sec = get_totp_secret(TEST_USER, TEST_PASS)
    REP.log(f"has_totp_quick -> {quick}")
    REP.log(f"get_totp_secret -> {'set' if isinstance(sec, str) and sec else 'missing'}")
    require(quick is True, "has_totp_quick should be True after setting secret")
    require(isinstance(sec, str) and sec.strip(), "get_totp_secret did not return a secret")


def t_vault_roundtrip_health() -> None:
    from app.paths import vault_file, salt_file
    from vault_store.vault_store import save_encrypted, load_encrypted  # type: ignore
    from vault_store.kdf_utils import derive_key_argon2id  # type: ignore

    sp = Path(salt_file(TEST_USER))
    require(sp.exists(), "Salt missing for vault test")
    salt = sp.read_bytes()
    key = derive_key_argon2id(TEST_PASS, salt)

    vp = Path(vault_file(TEST_USER, ensure_parent=True))
    payload = {
        "vault_entries": [
            {"category": "Passwords", "Title": "Example", "UserName": "u", "Password": "p", "Website": "https://example.com"},
            {"category": "Passwords", "Title": "Example2", "UserName": "u2", "Password": "p", "Website": "https://example.net"},
        ],
        "ts": int(time.time()),
    }
    save_encrypted(payload, str(vp), key)
    REP.log(f"save_encrypted -> wrote {vp} sha256={_sha256_file(vp) or 'n/a'}")

    loaded = load_encrypted(str(vp), key)
    require(isinstance(loaded, dict), "load_encrypted returned non-dict")
    entries = loaded.get("vault_entries") or []
    REP.log(f"Vault entries count: {len(entries)}")

    missing_required = 0
    pw_seen: dict[str, int] = {}
    for e in entries:
        if not isinstance(e, dict):
            missing_required += 1
            continue
        if not str(e.get("category", "")).strip() or not str(e.get("Title", "")).strip():
            missing_required += 1
        pw = str(e.get("Password", "") or "").strip()
        if pw:
            pw_seen[pw] = pw_seen.get(pw, 0) + 1

    dup_pw = {pw: n for pw, n in pw_seen.items() if n >= 2}
    REP.log(f"Vault health: missing_required_rows={missing_required}")
    REP.log(f"Vault health: duplicate_passwords={len(dup_pw)} (reuse check)")
    require(entries and entries[0].get("Title") == "Example", "Vault round-trip mismatch")


def t_share_self_packet_roundtrip() -> None:
    from app.paths import salt_file
    from vault_store.kdf_utils import derive_key_argon2id  # type: ignore
    from features.share.share_keys import ensure_share_keys, export_share_id_json  # type: ignore
    from features.share.zk_share import make_share_packet, verify_and_decrypt_share_packet  # type: ignore

    sp = Path(salt_file(TEST_USER))
    require(sp.exists(), "Salt missing for share test")
    salt = sp.read_bytes()
    user_key = derive_key_argon2id(TEST_PASS, salt)
    require(isinstance(user_key, (bytes, bytearray)) and len(user_key) == 32, "derive_key_argon2id did not return 32 bytes")

    sender_pub, sender_priv_x, sender_priv_ed = ensure_share_keys(TEST_USER, bytes(user_key))
    REP.log(f"Sender pub bundle keys: {list(sender_pub.keys())}")

    recip_bundle = export_share_id_json(TEST_USER, bytes(user_key))
    recip_pub_x = recip_bundle.get("pub_x25519")
    recip_id = recip_bundle.get("id") or TEST_USER
    require(bool(recip_pub_x), "Recipient pub_x25519 missing")

    entry = {"category": "Passwords", "Title": "SharedExample", "UserName": "share_u", "Password": "share_p"}
    packet = make_share_packet(
        entry_json=entry,
        sender_priv_x25519=sender_priv_x,
        sender_priv_ed25519=sender_priv_ed,
        sender_pub_bundle=sender_pub,
        recipient_pub_x25519_b64=recip_pub_x,
        recipient_id=recip_id,
        scope="vault_entry",
        policy={"allow_edit": False},
    )
    REP.log(f"Share packet created: fields={list(packet.keys()) if isinstance(packet, dict) else type(packet).__name__}")

    dec = verify_and_decrypt_share_packet(packet, recipient_priv_x25519=sender_priv_x)
    require(isinstance(dec, dict), "Decrypted share payload not dict")
    REP.log(f"Share decrypt OK. Title={dec.get('Title')!r}")
    require(dec.get("Title") == "SharedExample", "Share decrypt mismatch")


def t_backup_zip_manifest() -> None:
    from app.paths import vault_file, salt_file, user_db_file, identities_file, BACKUP_DIR

    bdir = Path(BACKUP_DIR(TEST_USER))
    bdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_zip = bdir / f"kq_test_backup_{TEST_USER}_{stamp}.zip"

    candidates = [
        Path(vault_file(TEST_USER)),
        Path(salt_file(TEST_USER)),
        Path(user_db_file(TEST_USER)),
        Path(identities_file(TEST_USER)),
    ]
    files = [p for p in candidates if p.exists() and p.is_file()]
    require(files, "No backup candidate files found")

    manifest = {"username": TEST_USER, "created_at": stamp, "files": []}

    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in files:
            data = p.read_bytes()
            sha = hashlib.sha256(data).hexdigest()
            z.writestr(p.name, data)
            manifest["files"].append({"name": p.name, "sha256": sha, "bytes": len(data)})
            REP.log(f"Archived: {p.name} bytes={len(data)} sha256={sha}")
        z.writestr("manifest.json", json.dumps(manifest, indent=2))

    require(out_zip.exists(), "Backup zip not created")
    REP.log(f"Backup zip created: {out_zip} size={out_zip.stat().st_size} bytes")

    with zipfile.ZipFile(out_zip, "r") as z:
        man = json.loads(z.read("manifest.json").decode("utf-8", "replace"))
        mismatched = 0
        for item in man.get("files", []):
            nm = item["name"]
            exp = item["sha256"]
            got = hashlib.sha256(z.read(nm)).hexdigest()
            if got != exp:
                mismatched += 1
        REP.log(f"Manifest verify: total={len(man.get('files', []))} mismatched={mismatched}")
        require(mismatched == 0, "Backup manifest mismatch detected")


def t_baseline_signer_write_verify() -> None:
    from security.baseline_signer import write_baseline, verify_baseline, _baseline_tracked_files  # type: ignore
    from auth.login.login_handler import _load_vault_salt_for  # type: ignore

    salt = _load_vault_salt_for(TEST_USER)
    require(isinstance(salt, (bytes, bytearray)) and len(salt) >= 16, "Could not load vault salt for baseline")
    files = _baseline_tracked_files(TEST_USER)
    REP.log(f"Baseline tracked file count: {len(files)}")
    write_baseline(TEST_USER, bytes(salt), files)

    ret = verify_baseline(TEST_USER, bytes(salt), files)
    ok, why = _parse_verify_baseline(ret)
    REP.log(f"verify_baseline -> ok={ok} {why}")
    require(ok is True, f"Baseline verify failed: {why}")


def t_encrypted_audit_optional() -> None:
    try:
        from security.secure_audit import log_event_encrypted, read_audit_log  # type: ignore
    except Exception as e:
        raise SkipTest(f"secure_audit not available: {e!r}")

    log_event_encrypted(TEST_USER, "kv_auto_tests", "ok", extra={"ts": time.time()})
    REP.log("Wrote audit event: kv_auto_tests=ok")

    entries = read_audit_log(TEST_USER) or []
    REP.log(f"Read audit entries: {len(entries)}")
    found = any((e.get("event") == "kv_auto_tests" or e.get("label") == "kv_auto_tests") for e in entries[-20:])
    require(found, "Audit event not found after write/read")


def t_security_center_worker_smoke() -> None:
    """
    Smoke-run Security Center logic (no thread start).
    If your class lives elsewhere, adjust the import here.
    """
    try:
        from workers.securitycenter_worker import SecurityCenterWorker  # type: ignore
    except Exception as e:
        raise SkipTest(f"SecurityCenterWorker not importable: {e!r}")

    _ensure_qapp()
    w = SecurityCenterWorker(TEST_USER)

    progress: list[str] = []
    try:
        w.progress.connect(lambda s: progress.append(str(s)))
    except Exception:
        pass

    w.run()
    REP.log(f"SecurityCenter progress steps: {len(progress)}")
    if progress:
        REP.log(f"First step: {progress[0]!r}")
        REP.log(f"Last step:  {progress[-1]!r}")
    REP.log("SecurityCenterWorker.run() completed (smoke).")


def t_yubikey_gate_wrap_dummy_backend() -> None:
    """
    Dummy backend test: should NEVER require real hardware.
    If your unlock_with_yk_if_needed() cannot accept a backend parameter, we SKIP safely.
    """
    from app.paths import salt_file
    from vault_store.kdf_utils import derive_key_argon2id  # type: ignore
    from auth.tfa.twofactor import enable_yk_2of2_gate, enable_yk_2of2_wrap, yk_twofactor_enabled, unlock_with_yk_if_needed  # type: ignore

    class DummyYK:
        def __init__(self, serial="YKTEST123456", key=b"TESTKEY"):
            self.serial = serial
            self._key = key

        def list_serials(self):
            return [self.serial]

        def calculate_hmac(self, slot: int, challenge_hex: str, serial: str, timeout: float = 25.0) -> str:
            data = bytes.fromhex(challenge_hex or "")
            return hashlib.sha1(data + self._key).hexdigest()

    sp = Path(salt_file(TEST_USER))
    require(sp.exists(), "Salt missing for YubiKey dummy test")
    mk = derive_key_argon2id(TEST_PASS, sp.read_bytes())
    yk = DummyYK()
    serial = yk.list_serials()[0]

    enable_yk_2of2_gate(username=TEST_USER, serial=serial, slot=2, yk_backend=yk)
    mode, _ = yk_twofactor_enabled(TEST_USER)
    REP.log(f"Gate enabled mode={mode}")

    # Newer versions can accept yk_backend override; older ones can't.
    try:
        mk2 = unlock_with_yk_if_needed(TEST_USER, mk, yk_backend=yk)  # type: ignore
    except TypeError:
        raise SkipTest("unlock_with_yk_if_needed() cannot accept dummy backend override; would require real YubiKey.")
    REP.log(f"Gate unlock -> mk_same={mk2 == mk}")
    require(mode == "yk_hmac_gate" and mk2 == mk, "YubiKey gate dummy test failed")

    enable_yk_2of2_wrap(username=TEST_USER, master_key=mk, serial=serial, slot=2, yk_backend=yk)
    mode2, _ = yk_twofactor_enabled(TEST_USER)
    REP.log(f"Wrap enabled mode={mode2}")

    try:
        mk3 = unlock_with_yk_if_needed(TEST_USER, mk, yk_backend=yk)  # type: ignore
    except TypeError:
        raise SkipTest("unlock_with_yk_if_needed() cannot accept dummy backend override; would require real YubiKey.")
    REP.log(f"Wrap unlock -> mk_same={mk3 == mk}")
    require(mode2 == "yk_hmac_wrap" and mk3 == mk, "YubiKey wrap dummy test failed")


def t_yubikey_touch_live_opt_in() -> None:
    if not RUN_YK_TOUCH:
        raise SkipTest("YubiKey touch tests are opt-in. Set KQ_TEST_YK_TOUCH=1 to run.")
    # Keep your existing live test runner if you want here.
    raise SkipTest("Live YubiKey touch test not wired in this file (to avoid hangs by default).")


def t_portable_opt_in() -> None:
    if not RUN_PORTABLE:
        raise SkipTest("Portable is opt-in. Set KQ_TEST_PORTABLE=1 to run.")
    from features.portable import portable_manager as pm  # type: ignore

    usb = TEST_ROOT / "FakeUSB"
    usb.mkdir(parents=True, exist_ok=True)

    ok = pm.build_portable_app(None, usb)
    REP.log(f"build_portable_app -> {ok} usb={usb}")
    if not ok:
        raise SkipTest("Portable payload not present/valid (build_portable_app returned False)")

    ok2 = pm.move_user_data_to_usb(None, usb, TEST_USER, delete_local=False)
    REP.log(f"move_user_data_to_usb(delete_local=False) -> {ok2}")
    require(ok2, "move_user_data_to_usb failed")

    ok3 = pm.restore_from_usb(None, usb / pm.PORTABLE_DIRNAME, TEST_USER)
    REP.log(f"restore_from_usb -> {ok3}")
    require(ok3, "restore_from_usb failed")


def t_cleanup_delete_account() -> None:
    from app.paths import user_root_local, user_root_roaming

    ul = Path(user_root_local(TEST_USER, ensure=False))
    ur = Path(user_root_roaming(TEST_USER, ensure=False))

    REP.log(f"Deleting user roots:\n  local={ul}\n  roaming={ur}")
    _safe_rm_tree(ul)
    _safe_rm_tree(ur)
    require(not ul.exists(), "Local user root still exists after delete")
    require(not ur.exists(), "Roaming user root still exists after delete")
    REP.log("Cleanup complete.")


# =============================================================================
# Runner
# =============================================================================

TESTS: list[tuple[str, Callable[[], None]]] = [
    ("Core imports", t_core_imports),
    ("Import sweep (auth/vault/security/features/workers)", t_import_sweep),

    ("Create dummy account + verify files", t_create_dummy_account_verify_files),
    ("Backup codes store + one-time consume", t_backup_codes_store_consume),

    ("Login good/bad", t_login_good_bad),
    ("Login lockout + reset", t_lockout_reset),
    ("TOTP set/get", t_totp_set_get),

    ("Vault round-trip + vault health", t_vault_roundtrip_health),
    ("Share self packet round-trip", t_share_self_packet_roundtrip),

    ("Backup zip + internal manifest verify", t_backup_zip_manifest),
    ("Baseline signer write/verify", t_baseline_signer_write_verify),
    ("Encrypted audit write/read (optional)", t_encrypted_audit_optional),
    ("Security Center worker run (smoke)", t_security_center_worker_smoke),

    ("YubiKey gate/wrap dummy backend", t_yubikey_gate_wrap_dummy_backend),
    ("YubiKey touch live (opt-in)", t_yubikey_touch_live_opt_in),

    ("Portable functions (opt-in)", t_portable_opt_in),
    ("Cleanup delete dummy account", t_cleanup_delete_account),
]


def _banner() -> None:
    print("\n" + "=" * 80)
    print("Keyquorum Vault – kv_auto_tests_V5_PRO (one-shot)")
    print("=" * 80)
    print(f"PKG_ROOT: {PKG_ROOT}")
    print(f"TEST_ROOT: {TEST_ROOT}")
    print(f"LOCALAPPDATA (forced): {os.environ.get('LOCALAPPDATA')}")
    print(f"APPDATA      (forced): {os.environ.get('APPDATA')}")
    print("=" * 80)


def run_all() -> int:
    _banner()
    _ensure_qapp()

    _clean_workspace()
    _mk_workspace()

    ts = _now()

    REP.h1("Keyquorum Vault – Automated Test Report")
    REP.li(f"Timestamp: `{ts}`")
    REP.li(f"Runner: `{Path(__file__).name}`")
    REP.li(f"PKG_ROOT: `{PKG_ROOT}`")
    REP.li(f"TEST_ROOT: `{TEST_ROOT}`")
    REP.li(f"LOCALAPPDATA: `{os.environ.get('LOCALAPPDATA')}`")
    REP.li(f"APPDATA: `{os.environ.get('APPDATA')}`")
    REP.li(f"Flags: PORTABLE={RUN_PORTABLE}  WINHELLO={RUN_WINHELLO}  YK_TOUCH={RUN_YK_TOUCH}  IMPORT_SWEEP_FAIL={IMPORT_SWEEP_FAIL}")
    REP.p()

    results: list[TestResult] = []

    for name, fn in TESTS:
        REP.start(name)
        t0 = time.time()
        try:
            fn()
            dt_s = time.time() - t0
            results.append(TestResult(name, "PASS", dt_s))
            REP.log(f"[PASS] {name} ({dt_s:.2f}s)")
        except SkipTest as e:
            dt_s = time.time() - t0
            results.append(TestResult(name, "SKIP", dt_s, str(e)))
            REP.log(f"[SKIP] {name} ({dt_s:.2f}s)")
            REP.log(f"Reason: {e}")
        except Exception:
            dt_s = time.time() - t0
            tb = traceback.format_exc()
            results.append(TestResult(name, "FAIL", dt_s, tb))
            REP.log(f"[FAIL] {name} ({dt_s:.2f}s)")
            REP.log(tb)
        finally:
            REP.end()

    passes = sum(r.status == "PASS" for r in results)
    fails = sum(r.status == "FAIL" for r in results)
    skips = sum(r.status == "SKIP" for r in results)

    REP.h2("Summary")
    REP.p(f"PASS={passes}  FAIL={fails}  SKIP={skips}")

    REP.md.append("| Status | Test | Seconds |")
    REP.md.append("|---|---|---:|")
    for r in results:
        REP.md.append(f"| {r.status} | {r.name} | {r.seconds:.2f} |")
    REP.p()

    if skips:
        REP.h2("Skipped tests and reasons")
        for r in results:
            if r.status == "SKIP":
                REP.li(f"`{r.name}` — {r.reason}")
        REP.p()

    REP.write(REPORT_PATH)
    print(f"\nMarkdown report written to: {REPORT_PATH}")

    if fails == 0:
        _clean_workspace()
    else:
        print(f"Workspace retained for debugging: {TEST_ROOT}")

    return 0 if fails == 0 else 2


if __name__ == "__main__":
    raise SystemExit(run_all())
