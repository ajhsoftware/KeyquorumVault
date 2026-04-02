#!/usr/bin/env python3
"""
Backwards-compatible wrapper: checks which salt source is available for a user.
Read-only. Does NOT migrate.
"""
from __future__ import annotations
import argparse, json
from salt_file import read_master_salt_readonly

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    out = {"user": args.user, "salt_ok": False, "salt_len": 0}
    try:
        s = read_master_salt_readonly(args.user)
        out["salt_ok"] = bool(s)
        out["salt_len"] = len(s) if s else 0
    except Exception as e:
        out["error"] = repr(e)

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        if out.get("salt_ok"):
            print(f"[OK] master salt resolved for {args.user} (len={out['salt_len']})")
        else:
            print(f"[FAIL] master salt missing for {args.user}: {out.get('error','')}")
    return 0 if out.get("salt_ok") else 10

if __name__ == "__main__":
    raise SystemExit(main())
