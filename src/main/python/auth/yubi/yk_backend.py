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
import os, sys, subprocess, binascii, logging, secrets
from typing import Optional, Sequence, Tuple

log = logging.getLogger("keyquorum")
L = lambda m: log.debug("[yk-backend] " + m)

PROBE_ENABLED = True
_YKMAN_CACHE: Optional[str] = None 

def set_probe_enabled(val: bool) -> None:
    global PROBE_ENABLED
    PROBE_ENABLED = bool(val)

class YubiKeyError(RuntimeError): pass

# ---------------------------
# ykman path resolution (bundle-first)
# ---------------------------
def _candidate_ykman_paths(explicit: Optional[str] = None) -> list[str]:
    cands: list[str] = []
    if explicit and explicit.strip():
        cands.append(explicit.strip())

    # Detect app base (frozen or dev)
    if getattr(sys, "frozen", False):
        base_dir = getattr(sys, "_MEIPASS", None) or os.path.dirname(sys.executable)
    else:
        base_dir = os.path.abspath(os.path.dirname(__file__))

    # 1) Bundled (prefer)
    cands += [
        os.path.join(base_dir, "_internal", "resources", "bin", "ykman.exe"),
        os.path.join(base_dir, "resources", "bin", "ykman.exe"),
    ]

    # 2) PATH
    cands.append("ykman")

    # 3) Typical Windows installs
    if os.name == "nt":
        pf  = os.environ.get("ProgramFiles")
        pfx = os.environ.get("ProgramFiles(x86)")
        la  = os.environ.get("LOCALAPPDATA")
        if pf:  cands.append(os.path.join(pf,  "Yubico", "YubiKey Manager", "ykman.exe"))
        if pfx: cands.append(os.path.join(pfx, "Yubico", "YubiKey Manager", "ykman.exe"))
        if la:  cands.append(os.path.join(la,  "Yubico", "YubiKey Manager", "ykman.exe"))
        if la:  cands.append(os.path.join(la,  "Microsoft", "WindowsApps", "ykman.exe"))

    # de-dup while preserving order
    seen, uniq = set(), []
    for p in cands:
        if p and p not in seen:
            seen.add(p); uniq.append(p)
    return uniq

def _resolve_ykman(explicit: Optional[str] = None) -> str:
    global _YKMAN_CACHE

    # cache result so we don't re-probe constantly
    if _YKMAN_CACHE is not None:
        return _YKMAN_CACHE

    for cand in _candidate_ykman_paths(explicit):
        try:
            if cand != "ykman" and not os.path.isfile(cand):
                continue
            cp = subprocess.run(
                [cand, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                **_hidden_win_spawn_kwargs(),   # 🔥 hide console
            )
            if cp.returncode == 0:
                _YKMAN_CACHE = cand
                return cand
        except Exception:
            continue

    raise YubiKeyError("Cannot find ykman (looked in bundle, PATH, and Program Files).")

def _hidden_win_spawn_kwargs():
    if sys.platform != "win32":
        return {}
    CREATE_NO_WINDOW = 0x08000000
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return {"startupinfo": si, "creationflags": CREATE_NO_WINDOW}

# ---------------------------
# - runner
# ---------------------------
def _run(cmd: Sequence[str], *, timeout: float = 30.0) -> Tuple[int, str, str]:
    #L("run: " + " ".join(cmd))
    try:
        cp = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout, **_hidden_win_spawn_kwargs()
        )
        return cp.returncode, (cp.stdout or "").strip(), (cp.stderr or "").strip()
    except subprocess.TimeoutExpired:
        raise YubiKeyError("ykman: timed out (touch not received?)")
    except FileNotFoundError:
        raise YubiKeyError("ykman executable not found")

# ---------------------------
# - Test GATE mode
# ---------------------------

def yk_hmac_challenge_gate_test(username: str, *, cfg: Optional[dict] = None, timeout: float = 25.0) -> bool:
    """
    Best-effort live test for GATE mode.

    - Requires a YubiKey touch (ykman chalresp/calculate).
    - Uses non-sensitive random challenge material (no secrets).
    - If cfg is not provided, attempts to read public Yubi config from identity_store.

    Returns True if a non-empty response is returned.
    """
    try:
        if cfg is None:
            try:
                from auth.identity_store import get_yubi_config_public
            except Exception:
                from identity_store import get_yubi_config_public
            cfg = get_yubi_config_public((username or "").strip()) or {}

        if (cfg.get("mode") or "").strip().lower() != "yk_hmac_gate":
            return False

        slot   = int(cfg.get("slot", 2) or 2)
        serial = (cfg.get("serial") or "").strip() or None
        ykpath = (cfg.get("ykman_path") or "").strip() or None

        # Random, non-secret challenge to force touch
        challenge_hex = secrets.token_hex(32)
        yk = YKBackend(ykpath)
        resp = yk.calculate_hmac(slot, challenge_hex, serial, timeout=timeout)
        return bool(resp and len(resp.strip()) >= 20)
    except Exception:
        return False


def test_yk_wrap_unwrap(*, username: str, password: str, timeout: float = 25.0) -> bool:
    """
    Best-effort live test for WRAP mode: attempt to unwrap the master key using
    stored wrap artifacts + provided password + YubiKey touch.

    Returns True if unwrap succeeds AND (if available) mk_hash verifies.
    """
    try:
        # Read WRAP config (needs password because the full config is encrypted)
        try:
            from auth.identity_store import get_yubi_config
        except Exception:
            from identity_store import get_yubi_config

        cfg = get_yubi_config((username or "").strip(), password or "") or {}
        if (cfg.get("mode") or "").strip().lower() != "yk_hmac_wrap":
            return False

        # Derive password_key from user salt
        try:
            from app.paths import salt_file
            user_salt = salt_file(username, ensure_parent=False).read_bytes()
        except Exception:
            # best-effort fallback for older layouts
            from app.paths import get_salt_path
            with open(get_salt_path(username), "rb") as f:
                user_salt = f.read()

        from vault_store.kdf_utils import derive_key_argon2id
        password_key = derive_key_argon2id(password or "", user_salt)

        # Unwrap using stored artifacts
        try:
            from auth.yubi.yubihmac_wrap import unwrap_master_key_with_yubi
        except Exception:
            from yubihmac_wrap import unwrap_master_key_with_yubi

        # For WRAP mode, the encrypted MK is stored in cfg; pass dummy master_key input.
        mk = unwrap_master_key_with_yubi(b"", password_key=password_key, cfg=cfg)
        return bool(mk and isinstance(mk, (bytes, bytearray)) and len(mk) in (32, 64))
    except Exception:
        return False

# ---------------------------
# - Backend

# ---------------------------
class YKBackend:
    """
    Small CLI wrapper around ykman for OTP HMAC-SHA1 C/R with:
      • bundle-first ykman.exe resolution
      • variant fallback for calculate/chalresp
      • slot provisioning with --touch --force
    """
    def __init__(self, explicit_path: Optional[str] = None, **_):
        # accept both explicit_path or ykman_path from callers
        self.ykman = _resolve_ykman(explicit_path)

    # --- info / presence ---
    def yk_version(self) -> str:
        code, out, err = _run([self.ykman, "--version"], timeout=5)
        if code != 0: raise YubiKeyError(err or out or "ykman failed")
        return out

    def list_serials(self) -> list[str]:
        code, out, err = _run([self.ykman, "list", "--serials"], timeout=5)
        if code == 0 and out.strip():
            return [s.strip() for s in out.splitlines() if s.strip()]
        # fallback: if 'list --serials' unsupported, use 'info' to indicate presence
        code2, out2, err2 = _run([self.ykman, "info"], timeout=5)
        if code2 == 0 and (out2 or "").strip():
            return ["(present)"]
        return []

    def otp_enabled(self) -> bool:
        try:
            code, out, err = _run([self.ykman, "info"], timeout=5)
            if code != 0: return True
            lines = [l.strip().lower() for l in (out or "").splitlines()]
            for i, ln in enumerate(lines):
                if ln.startswith("applications"):
                    for r in lines[i+1:i+10]:
                        if r.startswith("yubico otp"):
                            return "enabled" in r
        except Exception:
            pass
        return True

    def is_slot_configured(self, slot: int) -> bool:
        code, out, err = _run([self.ykman, "otp", "info"], timeout=5)
        if code != 0: return True
        want = f"slot {int(slot)}:".lower()
        for ln in (out or "").splitlines():
            l = ln.strip().lower()
            if l.startswith(want):
                return ("programmed" in l) or ("configured" in l)
        return True

    # --- provisioning ---
    def program_slot_generate_touch(self, slot: int = 2, *, timeout: float = 25.0) -> None:
        # ykman otp chalresp --generate --touch --force <slot>
        code, out, err = _run([self.ykman, "otp", "chalresp", "--generate", "--touch", "--force", str(int(slot))], timeout=timeout)
        if code != 0:
            raise YubiKeyError(err or out or "slot programming failed")

    def program_slot2_generate_touch(self) -> None:
        self.program_slot_generate_touch(2)

    def program_slot1_generate_touch(self) -> None:
        self.program_slot_generate_touch(1)

    def program_slot_generate_no_touch(self, slot: int = 2, *, timeout: float = 15.0) -> None:
        code, out, err = _run([self.ykman, "otp", "chalresp", "--generate", "--force", str(int(slot))], timeout=timeout)
        if code != 0:
            raise YubiKeyError(err or out or "slot programming (no-touch) failed")

    # --- calculate HMAC (variant autodetect) ---
    def _calc_try_variants(self, slot: int, chal_hex: str, *, timeout: float) -> str:
        slot_s = str(int(slot))
        # 1) modern
        code, out, err = _run([self.ykman, "otp", "calculate", slot_s, chal_hex], timeout=timeout)
        if code == 0 and (out or "").strip(): return out.strip().lower()
        # 2) older (-H)
        code, out, err = _run([self.ykman, "otp", "chalresp", "-H", chal_hex, slot_s], timeout=timeout)
        if code == 0 and (out or "").strip(): return out.strip().lower()
        # 3) positional
        code, out, err = _run([self.ykman, "otp", "chalresp", slot_s, chal_hex], timeout=timeout)
        if code == 0 and (out or "").strip(): return out.strip().lower()
        raise YubiKeyError(err or out or "ykman chalresp/calculate failed")

    def _calc_try_with_device(self, serial: str, slot: int, chal_hex: str, *, timeout: float) -> str:
        slot_s = str(int(slot)); dev = ["--device", str(serial)]
        code, out, err = _run([self.ykman, *dev, "otp", "calculate", slot_s, chal_hex], timeout=timeout)
        if code == 0 and (out or "").strip(): return out.strip().lower()
        code, out, err = _run([self.ykman, *dev, "otp", "chalresp", "-H", chal_hex, slot_s], timeout=timeout)
        if code == 0 and (out or "").strip(): return out.strip().lower()
        code, out, err = _run([self.ykman, *dev, "otp", "chalresp", slot_s, chal_hex], timeout=timeout)
        if code == 0 and (out or "").strip(): return out.strip().lower()
        raise YubiKeyError(err or out or "ykman (with --device) failed")

    def calculate_hmac(self, slot: int, challenge_hex: str, serial: Optional[str] = None, *, timeout: float = 25.0) -> str:
        chal = (challenge_hex or "").strip().lower()
        if not chal or any(c not in "0123456789abcdef" for c in chal):
            raise YubiKeyError("Invalid challenge hex")
        if serial:
            try:
                return self._calc_try_with_device(serial, slot, chal, timeout=timeout)
            except Exception:
                pass
        return self._calc_try_variants(slot, chal, timeout=timeout)

    # --- quick touch probe ---
    def probe_chalresp_touch(self, *, slot: int = 2, timeout: float = 12.0) -> bool:
        ch = binascii.hexlify(os.urandom(32)).decode("ascii")
        try:
            _ = self.calculate_hmac(slot, ch, None, timeout=timeout)
            return True
        except YubiKeyError as e:
            msg = str(e).lower()
            if "timed out" in msg or "touch" in msg:
                return False
            raise

# ---------------------------
# Bridge for login worker (optional; keep API stable)
# ---------------------------
def do_yk_gate_or_wrap(username: str, *, password: str, master_key: bytes, password_key: bytes) -> bytes:
    """
    - If not enabled: return master_key unchanged
    - Gate: prove possession via touch and return master_key unchanged
    - Wrap: unwrap via yubihmac_wrap
    """
    user = (username or "").strip()
    if not user:
        raise RuntimeError("Username missing")

    # identity lookup
    try:
        from auth.identity_store import get_yubi_config
    except Exception:
        from identity_store import get_yubi_config  

    cfg = get_yubi_config(user, password) or {}
    mode = (cfg.get("mode") or "").strip().lower()
    if not mode:
        return master_key

    if mode == "yk_hmac_gate":
        slot   = int(cfg.get("slot", 2) or 2)
        serial = (cfg.get("serial") or "").strip() or None
        ykpath = (cfg.get("ykman_path") or "").strip() or None
        yk = YKBackend(ykpath)
        ch_hex = binascii.hexlify(user.encode("utf-8")).decode("ascii")
        _ = yk.calculate_hmac(slot, ch_hex, serial, timeout=25.0)  # blocks for touch
        return master_key

    if mode == "yk_hmac_wrap":
        try:
            from auth.yubi.yubihmac_wrap import unwrap_master_key_with_yubi
            return unwrap_master_key_with_yubi(master_key, password_key=password_key, cfg=cfg)
        except Exception as e:
            raise YubiKeyError(str(e))
    return master_key

def debug_resolved_ykman_path(explicit: Optional[str] = None) -> str:
    try:
        return _resolve_ykman(explicit)
    except Exception as e:
        return f"(not found) {e}"
