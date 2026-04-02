# -*- coding: utf-8 -*-
# tools/check_manifest_portable.py
# Usage: python tools/check_manifest_portable.py "C:\fbs\Keyquorum\target\keyquorum-vault"

import sys, json, hashlib
from pathlib import Path
import datetime as dt

def h(p: Path) -> str:
    hh = hashlib.sha256()
    with p.open("rb") as f:
        for ch in iter(lambda: f.read(1<<20), b""):
            hh.update(ch)
    return hh.hexdigest()

def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/check_manifest_portable.py <BUILD_DIR>")
        sys.exit(2)

    BUILD = Path(sys.argv[1]).resolve()
    sign_dir = BUILD / "_internal" / "resources" / "signing"
    mpath = sign_dir / "manifest.json"
    spath = sign_dir / "manifest.sig"
    ppath = sign_dir / "public_key.pem"

    ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] Build: {BUILD}")
    print(f"[{ts}] Manifest:  {mpath.exists()} -> {mpath}")
    print(f"[{ts}] Signature: {spath.exists()} -> {spath}")
    print(f"[{ts}] PubKey:    {ppath.exists()} -> {ppath}")

    if not mpath.exists(): sys.exit("Manifest missing")
    data = json.loads(mpath.read_text(encoding="utf-8"))
    files = data.get("files", {})
    if not files:
        sys.exit("Manifest has 0 files")

    # Try signature verify (optional)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
        pub = serialization.load_pem_public_key(ppath.read_bytes())
        pub.verify(spath.read_bytes(), mpath.read_bytes())
        print(f"[{ts}] [SIGNATURE OK] Manifest signature valid.")
    except Exception as e:
        print(f"[{ts}] [SIGNATURE FAIL] {e}")

    missing, diffs = [], []
    for rel, exp in files.items():
        p = BUILD / rel
        if not p.exists():
            missing.append(rel)
            continue
        got = h(p)
        if got != exp:
            diffs.append((rel, exp, got))

    print(f"[{ts}] [SUMMARY] total={len(files)} missing={len(missing)} mismatched={len(diffs)}")
    if missing:
        print(f"[{ts}] Missing files:")
        for rel in missing[:50]:
            print("  -", rel)
        if len(missing) > 50:
            print(f"  ... and {len(missing)-50} more")

    if diffs:
        print(f"[{ts}] Mismatched files:")
        for rel, exp, got in diffs[:50]:
            print(f"  - {rel}\n    Expected: {exp}\n    Got:      {got}")
        if len(diffs) > 50:
            print(f"  ... and {len(diffs)-50} more")

    sys.exit(0 if not missing and not diffs else 1)

if __name__ == "__main__":
    main()
