# tools/make_portable_blob.py
# PortableAppRoot = the folder containing your portable app’s App contents (no user data).
# OutBlobPath = where your MSIX layout expects it, e.g.
# C:\fbs\Keyquorum\msix\layout\App\_internal\resources\portable\core.kqpkg
# PackageFamilyName (PFN) = the reserved PFN for your Store app (e.g. YourCompany.Keyquorum_1234567890abc).

"""python tools\make_portable_blob.py "C:\fbs\Keyquorum\target\keyquorum-vault" ^
  "src\main\resources\base\_internal\resources\portable\core.kqpkg" ^
  "ajhsoftware.Keyquorum_m7005c4h488m6"""

# tools/make_portable_blob.py
import io, os, json, zipfile, secrets, hashlib, base64, sys
from pathlib import Path
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 32 random bytes you generate once and keep in source control (replace with your own)
KEY0_B64 = "9i7nN9s+vA65Ugz15nUhdf4tVStPoao0osNootntxs4="
KEY0 = base64.b64decode(KEY0_B64)

def hkdf_key(pfn: str) -> bytes:
    hk = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(pfn.encode("utf-8")).digest(),
        info=b"kqportable-v1",
    )
    return hk.derive(KEY0)

def list_files_under(root: Path) -> list[Path]:
    files: list[Path] = []
    for r, _, fs in os.walk(root):
        for name in fs:
            files.append(Path(r) / name)
    return files

def zip_folder_to_bytes(src_dir: Path) -> bytes:
    # If the caller points at ".../App", treat its parent as base so archive has "app/..."
    base_for_rel = src_dir if src_dir.name.lower() != "app" else src_dir.parent
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for root, _, files in os.walk(src_dir):
            for name in files:
                p = Path(root) / name
                arc = Path("app") / p.relative_to(base_for_rel)
                zf.write(p, arcname=str(arc).replace("\\", "/"))
    return bio.getvalue()

def encrypt_zip(zip_bytes: bytes, pfn: str) -> bytes:
    key   = hkdf_key(pfn)
    nonce = secrets.token_bytes(12)
    aad   = pfn.encode("utf-8")
    ct    = AESGCM(key).encrypt(nonce, zip_bytes, aad)
    magic = b"KQPKG1"
    aad_len = len(aad).to_bytes(2, "big")
    return magic + nonce + aad_len + aad + ct

def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("Usage: make_portable_blob.py <PortableAppRoot> <OutBlobPath> <PackageFamilyName>")
        return 2

    src = Path(argv[1]).resolve()
    out = Path(argv[2]).resolve()
    pfn = argv[3].strip()

    print(f"[info] Source (PortableAppRoot): {src}")
    print(f"[info] Output blob path:        {out}")
    print(f"[info] PFN:                     {pfn}")

    if not src.exists() or not src.is_dir():
        print(f"[error] Source folder does not exist or is not a directory: {src}")
        return 3

    all_files = list_files_under(src)
    print(f"[info] Files found under source: {len(all_files)}")
    if len(all_files) == 0:
        print("[error] Source contains no files. Refusing to create an empty package.")
        return 4

    # Optional: show a few example entries for sanity
    for p in all_files[:5]:
        print(f"  - {p.relative_to(src)}")
    if len(all_files) > 5:
        print(f"  ... (+{len(all_files)-5} more)")

    zip_bytes = zip_folder_to_bytes(src)
    print(f"[info] Zipped size (bytes): {len(zip_bytes)}")

    blob = encrypt_zip(zip_bytes, pfn)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    print(f"[ok] Wrote portable blob:\n     {out}\n     size: {len(blob)} bytes")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
