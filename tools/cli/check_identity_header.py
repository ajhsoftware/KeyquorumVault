#!/usr/bin/env python3
r"""
Identity Store header inspector / validator (read-only).
Supports:
- parse_identity_public_header(raw_bytes) -> dict
- validate_identity_header(header_dict) -> list[str]
CLI:
  python check_identity_header.py path\to\user.kq_id --inspect
"""
from __future__ import annotations

import argparse
import base64
import json
import struct
from pathlib import Path
from typing import Any, Dict, List

def _b64_try(s: str):
    try:
        return base64.b64decode(s.encode(), validate=True)
    except Exception:
        return None

def parse_identity_public_header(raw: bytes) -> Dict[str, Any]:
    if not raw.startswith(b"KQID1"):
        raise ValueError("Not an identity store file (missing KQID1)")
    if len(raw) < 9:
        raise ValueError("Truncated identity file")

    header_len = struct.unpack(">I", raw[5:9])[0]
    if header_len <= 0 or header_len > (len(raw) - 9):
        raise ValueError(f"Invalid header_len={header_len} (file_len={len(raw)})")

    hdr_bytes = raw[9:9 + header_len]
    try:
        header = json.loads(hdr_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Header JSON decode failed: {e}")

    if not isinstance(header, dict):
        raise ValueError("Header JSON is not an object")
    return header

def validate_identity_header(header: Dict[str, Any]) -> List[str]:
    """
    Validate the *public* identity header.

    Returns a list of issues as strings, prefixed with:
      - "FAIL:"  => structural/corruption issues
      - "WARN:"  => non-fatal / schema differences / optional sections missing

    NOTE:
      Older/newer schema variants may legitimately omit "wrappers" in the public header.
      We only treat wrappers-related problems as WARN unless wrappers are present but malformed.
    """
    issues: List[str] = []

    if not isinstance(header, dict):
        return ["FAIL: header JSON is not an object"]

    wrappers = header.get("wrappers", None)

    if wrappers is None:
        issues.append("WARN: missing 'wrappers' (ok for public-header-only schema)")
        wrappers_list: List[Any] = []
    elif not isinstance(wrappers, list):
        issues.append("FAIL: 'wrappers' exists but is not a list")
        wrappers_list = []
    else:
        wrappers_list = wrappers

    # If wrappers exist, validate password wrapper fields (non-fatal if not present)
    pw = None
    for w in wrappers_list:
        if isinstance(w, dict) and w.get("type") == "password":
            pw = w
            break

    if wrappers is not None and pw is None:
        issues.append("WARN: wrappers present but no password wrapper found (type='password')")

    if pw is not None:
        for k in ("salt", "nonce", "ct"):
            if k not in pw:
                issues.append(f"FAIL: password wrapper missing '{k}'")

        if "nonce" in pw:
            b = _b64_try(str(pw["nonce"]))
            if b is None:
                issues.append("FAIL: password wrapper nonce is not valid base64")
            elif len(b) != 12:
                issues.append(f"FAIL: password wrapper nonce length={len(b)} (expected 12 bytes)")

        if "salt" in pw:
            b = _b64_try(str(pw["salt"]))
            if b is None:
                issues.append("FAIL: password wrapper salt is not valid base64")
            elif len(b) < 8:
                issues.append(f"FAIL: password wrapper salt too short ({len(b)} bytes)")

        if "ct" in pw:
            b = _b64_try(str(pw["ct"]))
            if b is None:
                issues.append("FAIL: password wrapper ct is not valid base64")
            elif len(b) < 16:
                issues.append(f"FAIL: password wrapper ct too short ({len(b)} bytes)")

    # Validate migrated master salt if present
    meta = header.get("meta")
    if meta is not None and isinstance(meta, dict):
        ms = (meta.get("master_salt_b64") or "").strip()
        if ms:
            b = _b64_try(ms)
            if b is None:
                issues.append("FAIL: meta.master_salt_b64 is not valid base64")
            else:
                # Most common: 16 bytes, but we only hard-fail if clearly wrong.
                if len(b) != 16:
                    issues.append(f"WARN: meta.master_salt_b64 decoded length={len(b)} (expected 16)")
    elif meta is not None:
        issues.append("WARN: meta exists but is not an object")

    return issues

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("identity_store", help="Path to identity store file (e.g. user.kq_id)")
    ap.add_argument("--inspect", action="store_true", help="Print header JSON")
    ap.add_argument("--check", action="store_true", help="Validate header and exit nonzero if problems")
    args = ap.parse_args()

    p = Path(args.identity_store)
    raw = p.read_bytes()
    header = parse_identity_public_header(raw)
    problems = validate_identity_header(header)

    if args.inspect:
        print(json.dumps(header, indent=2))

    if problems:
        fails = [x for x in problems if str(x).startswith("FAIL:")]
        warns = [x for x in problems if str(x).startswith("WARN:")]

        if warns:
            print("[WARN] Identity header warnings:")
            for pr in warns:
                print(f" - {pr}")

        if fails:
            print("[FAIL] Identity header problems:")
            for pr in fails:
                print(f" - {pr}")
            return 10


    print("[OK] Identity header looks valid.")
    meta = header.get("meta") if isinstance(header, dict) else None
    ms = (meta.get("master_salt_b64") or "").strip() if isinstance(meta, dict) else ""
    print(f"[INFO] master_salt_in_header={'YES' if ms else 'NO'}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
