# -*- coding: utf-8 -*-

# tools/build_portable_release.py
# One-freeze portable build:
#  1) fbs clean && fbs freeze
#  2) Hash EVERY file in target\<app-name>\ (exclude manifest files)
#  3) Sign manifest with Ed25519 private key
#  4) Drop manifest.json, manifest.sig, public_key.pem into _internal/resources/signing/
#  5) Zip the portable folder (optional)

EXCLUDE_RELS = {
    "resources/signing/manifest.json",
    "resources/signing/manifest.sig",
    "_internal/resources/signing/manifest.json",
    "_internal/resources/signing/manifest.sig",
}

import argparse, subprocess, sys, json, hashlib, shutil
from pathlib import Path
import datetime as dt

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except Exception:
    print("Please: pip install cryptography")
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]  # repo root


def run(cmd: list[str]) -> None:
    print(">", " ".join(cmd))
    subprocess.check_call(cmd, cwd=ROOT)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_or_create_private_key(key_path: Path) -> Ed25519PrivateKey:
    if key_path.exists():
        return serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    # Generate new key if missing
    key_path.parent.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    key_path.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    print(f"[WARN] No private key found. Generated new Ed25519 key at: {key_path}")
    return priv


def sign_build(build_dir: Path, private_key_path: Path) -> dict:
    sign_dir = build_dir / "_internal" / "resources" / "signing"
    sign_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = sign_dir / "manifest.json"
    sig_path = sign_dir / "manifest.sig"
    pubkey_path = sign_dir / "public_key.pem"

    files = {}
    total_scanned = 0
    for p in build_dir.rglob("*"):
        if p.is_file():
            rel = p.relative_to(build_dir).as_posix()
            total_scanned += 1
            # exclude all known manifest/sig locations
            if rel in EXCLUDE_RELS or rel.endswith("/resources/signing/manifest.json") or rel.endswith("/resources/signing/manifest.sig"):
                continue
            files[rel] = sha256_file(p)

    manifest = {"files": files}
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    priv = load_or_create_private_key(private_key_path)
    pub = priv.public_key()

    # write public key
    pubkey_path.write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    # sign manifest
    sig_path.write_bytes(priv.sign(manifest_path.read_bytes()))

    return {
        "sign_dir": str(sign_dir),
        "manifest": str(manifest_path),
        "signature": str(sig_path),
        "pubkey": str(pubkey_path),
        "covered": len(files),
        "scanned": total_scanned,
        "excluded": len(EXCLUDE_RELS),
    }


def zip_portable(build_dir: Path, zip_out: Path) -> None:
    if zip_out.exists():
        zip_out.unlink()
    shutil.make_archive(zip_out.with_suffix(""), "zip", root_dir=build_dir, base_dir=".")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-name", required=True, help="Folder name under target (e.g., keyquorum-vault)")
    ap.add_argument("--key", required=True, help="Path to Ed25519 private key (PEM). Will be created if missing.")
    ap.add_argument("--zip", action="store_true", help="Create a portable zip of the build folder")
    args = ap.parse_args()

    target_dir = ROOT / "target" / args.app_name
    key_path = Path(args.key).resolve()

    # 1) Freeze once
    run(["fbs", "clean"])
    run(["fbs", "freeze"])

    if not target_dir.exists():
        print(f"[ERROR] Build folder not found: {target_dir}")
        sys.exit(2)

    # 2–4) Sign in-place
    info = sign_build(target_dir, key_path)
    ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [OK] Portable manifest created and signed")
    print("  Build:    ", target_dir)
    print("  Manifest: ", info["manifest"])
    print("  Signature:", info["signature"])
    print("  PubKey:   ", info["pubkey"])
    print(f"  Covered files: {info['covered']} (scanned {info['scanned']}, excluded {info['excluded']} signing files)")
    print("  IMPORTANT: Do NOT modify this folder after signing. Zip and ship as-is.\n")

    # 5) Optional ZIP
    if args.zip:
        zip_out = ROOT / f"{args.app_name}-portable"
        zip_portable(target_dir, zip_out)
        print(f"[OK] Portable ZIP created: {zip_out.with_suffix('.zip')}")


if __name__ == "__main__":
    main()
