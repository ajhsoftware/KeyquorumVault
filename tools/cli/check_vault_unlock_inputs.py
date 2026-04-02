#!/usr/bin/env python3
"""
Vault unlock preflight (read-only):
- Locates vault + identity files using standard roots (or overrides)
- Validates identity header
- Resolves master salt via salt_file.py (identity header or legacy)
- Optionally attempts vault decrypt if --decrypt-vault is provided
This is a thin wrapper around kq_tool.py health.
"""
from __future__ import annotations
import argparse, subprocess, sys, os
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--users-root")
    ap.add_argument("--local-root")
    ap.add_argument("--roaming-root")
    ap.add_argument("--portable-root")
    ap.add_argument("--vault")
    ap.add_argument("--identity")
    ap.add_argument("--dll")
    ap.add_argument("--decrypt-vault", action="store_true")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    tool = here / "kq_tool.py"

    cmd = [sys.executable, str(tool), "health", "--user", args.user]
    for k in ["users_root","local_root","roaming_root","portable_root","vault","identity","dll"]:
        v = getattr(args, k)
        if v:
            cmd += [f"--{k.replace('_','-')}", v]
    if args.decrypt_vault:
        cmd += ["--decrypt-vault"]

    return subprocess.call(cmd)

if __name__ == "__main__":
    raise SystemExit(main())
