#!/usr/bin/env python3
"""
collect_licenses.py — harvest LICENSE/NOTICE files from installed packages

Usage:
  python collect_licenses.py --out License/SPDX_LICENSES/vendors
  python collect_licenses.py --out License/SPDX_LICENSES/vendors --packages PySide6 requests Pillow

What it does:
- Scans installed distributions (via importlib.metadata) in the CURRENT interpreter.
- Finds files named like LICENSE*, LICENCE*, COPYING*, NOTICE*, AUTHORS* (case-insensitive).
- Copies them into the --out folder with names like: <name>-<version>-<original-filename>.
- Writes a summary JSON report and a concatenated ALL_LICENSES_CONCAT.txt.
"""
import argparse
import os
import re
import shutil
import sys
from pathlib import Path

try:
    import importlib.metadata as importlib_metadata  # Python 3.8+
except Exception:
    import importlib_metadata  # type: ignore

PATTERNS = re.compile(r'(?i)(^|/)(license|licence|copying|notice|licenses|authors)(\.|/|$)')

def find_candidate_files(dist):
    """Yield (Path, relative_str) for files that look like license/notice files."""
    files = getattr(dist, "files", None)
    if not files:
        return
    for f in files:
        # f is a importlib.metadata.PackagePath (relative to distribution base)
        rel = str(f)
        if PATTERNS.search(rel.replace("\\", "/")):
            try:
                abs_path = dist.locate_file(f)
                if abs_path and Path(abs_path).is_file():
                    yield Path(abs_path), rel
            except Exception:
                continue

def safe_name(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9._+-]+', '-', s.strip())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="Output directory to copy license files")
    ap.add_argument("--packages", nargs="*", help="Optional package name filters (case-insensitive)")
    args = ap.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    name_filters = set([p.lower() for p in args.packages]) if args.packages else None

    report = []
    for dist in importlib_metadata.distributions():
        name = dist.metadata.get("Name") or ""
        version = dist.metadata.get("Version") or ""
        if not name:
            continue
        if name_filters and name.lower() not in name_filters:
            continue

        copied = []
        for abs_path, rel in find_candidate_files(dist) or []:
            dest_name = f"{safe_name(name)}-{safe_name(version)}-{safe_name(Path(rel).name)}"
            dest = outdir / dest_name
            try:
                shutil.copy2(abs_path, dest)
                copied.append(str(dest.name))
            except Exception as e:
                copied.append(f"ERROR: {abs_path} -> {e}")

        # If nothing found, write a small text with the License field from METADATA (best-effort)
        if not copied:
            lic_field = (dist.metadata.get("License") or "").strip()
            if lic_field:
                fallback = outdir / f"{safe_name(name)}-{safe_name(version)}-LICENSE-from-METADATA.txt"
                try:
                    fallback.write_text(lic_field + "\n", encoding="utf-8")
                    copied.append(str(fallback.name))
                except Exception as e:
                    copied.append(f"ERROR: write fallback -> {e}")

        base = dist.locate_file("")  # folder path (e.g., site-packages/<dist>.dist-info or root)
        report.append({
            "name": name,
            "version": version,
            "base": str(base),
            "copied_files": copied,
        })

    # Write summary JSON and concatenated text
    import json
    (outdir / "SUMMARY.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    concat_path = outdir / "ALL_LICENSES_CONCAT.txt"
    with open(concat_path, "w", encoding="utf-8") as outfh:
        for item in report:
            for fname in item["copied_files"]:
                p = outdir / fname
                if p.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".md"):
                    # skip binary or markdown images
                    continue
                outfh.write(f"\n\n=== {item['name']} {item['version']} — {fname} ===\n\n")
                try:
                    outfh.write(p.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    outfh.write("[[unreadable or binary]]")

    print(f"Done. Copied license files into: {outdir}")
    print(f"Summary: {outdir / 'SUMMARY.json'}")
    print(f"Concatenated: {concat_path}")

if __name__ == "__main__":
    main()
