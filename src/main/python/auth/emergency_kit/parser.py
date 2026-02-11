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
import base64
import json
import re
from typing import Optional

from .types import ParsedKit, AccountSnapshot

try:
    import PyPDF2  # type: ignore
except Exception:  # pragma: no cover
    PyPDF2 = None  # type: ignore

import difflib


def parse_emergency_kit_pdf(path: str) -> ParsedKit:
    """
    Parse a Keyquorum Emergency Kit PDF.

    Strategy:
      1) Try to extract the KQEM1 payload (hidden line / QR ID).
      2) If found and valid, return that as the primary result.
      3) If not, fall back to best-effort text parsing of codes.

    Returns a ParsedKit dict; all fields are optional.
    """
    if PyPDF2 is None:
        raise RuntimeError("PyPDF2 is not installed; cannot parse Emergency Kit PDF.")

    reader = PyPDF2.PdfReader(path)
    texts: list[str] = []
    for page in reader.pages:
        try:
            t = page.extract_text() or ""
        except Exception:
            t = ""
        if t:
            texts.append(t)
    full_text = "\n\n".join(texts)

    # 1) Try the machine-readable payload first
    payload_result = _extract_kqem_payload(full_text)
    if payload_result is not None:
        return payload_result

    # 2) Fallback: best-effort parsing of the visible tables / sections
    return _parse_legacy_kit_text(full_text)


def parse_and_merge_kit(username: str, pdf_path: str, snapshot: AccountSnapshot) -> tuple[bool, str, AccountSnapshot]:
    """
    Safe helper: parse a kit PDF and merge it into an existing snapshot.

    Validations:
      - If the kit contains a username, it must match the expected username.
    """
    try:
        parsed = parse_emergency_kit_pdf(pdf_path)
        kit_user = parsed.get("username")
        if kit_user and kit_user != username:
            return False, f"Kit username mismatch: expected '{username}', got '{kit_user}'", snapshot

        merged = merge_kit_into_account_snapshot(snapshot, parsed)
        return True, "Kit merged successfully", merged
    except Exception as e:
        return False, f"Parse failed: {e}", snapshot


def merge_kit_into_account_snapshot(snapshot: AccountSnapshot, parsed: ParsedKit) -> AccountSnapshot:
    """
    Merge rules:
      - Codes: current ∪ kit_codes, MINUS any already-used codes
      - Used codes remain used (never resurrect consumed codes)
      - Recovery Key: NEVER imported (must be entered manually)

    IMPORTANT:
      Caller should validate kit username before calling.
    """
    merged: AccountSnapshot = dict(snapshot)

    current_rec = list(snapshot.get("recovery_backup_codes") or [])
    used_rec = set(snapshot.get("used_recovery_codes") or [])
    kit_rec = list(parsed.get("recovery_backup_codes") or [])

    merged_rec = sorted(set(current_rec) | set(kit_rec))
    merged_rec = [c for c in merged_rec if c not in used_rec]
    merged["recovery_backup_codes"] = merged_rec

    current_2fa = list(snapshot.get("twofa_backup_codes") or [])
    used_2fa = set(snapshot.get("used_twofa_codes") or [])
    kit_2fa = list(parsed.get("twofa_backup_codes") or [])

    merged_2fa = sorted(set(current_2fa) | set(kit_2fa))
    merged_2fa = [c for c in merged_2fa if c not in used_2fa]
    merged["twofa_backup_codes"] = merged_2fa

    return merged


# ----------------------------- internals -----------------------------------

def _extract_kqem_payload(text: str) -> Optional[ParsedKit]:
    """
    Find and decode a KQEM1:<base64-json> token from the PDF text.
    """
    m = re.search(r"KQEM1:([A-Za-z0-9_\-]+)", text)
    if not m:
        return None

    token = m.group(0)  # full "KQEM1:...."
    b64_part = m.group(1)
    try:
        raw = base64.urlsafe_b64decode(b64_part + "===")  # tolerate missing padding
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return None

    if not isinstance(data, dict):
        return None
    if data.get("kq_type") != "emergency_kit":
        return None

    ver = int(data.get("kq_ver", 0) or 0)

    pk: ParsedKit = {
        "has_payload": True,
        "payload_version": ver,
        "username": data.get("username"),
        "recovery_key_present": bool(data.get("has_recovery_key")),
        "recovery_key_fingerprint": data.get("recovery_key_fp"),
        "recovery_backup_codes": list(data.get("recovery_backup_codes") or []),
        "twofa_backup_codes": list(data.get("twofa_backup_codes") or []),
        "totp_secret_hint": data.get("totp_hint"),
        "raw_payload": token,
    }
    return pk


def _parse_legacy_kit_text(text: str) -> ParsedKit:
    """
    Fallback parser for older kits that do NOT contain a KQEM1 payload.
    Best-effort and intentionally conservative.
    """
    norm = text.replace("\r\n", "\n").replace("\r", "\n")

    rec_section = _extract_section(
        norm,
        "Recovery Backup Codes",
        stop_titles=[
            "2FA Backup Codes",
            "Two-Factor Authenticator",
            "Emergency Notes",
            "Emergency Contact Notes",
            "Keyquorum Vault — Emergency Kit",
        ],
    )
    rec_codes = _parse_section_codes(rec_section)

    twofa_section = _extract_section(
        norm,
        "2FA Backup Codes",
        stop_titles=[
            "Two-Factor Authenticator",
            "Emergency Notes",
            "Emergency Contact Notes",
            "Keyquorum Vault — Emergency Kit",
        ],
    )
    twofa_codes = _parse_section_codes(twofa_section)

    totp_hint = None
    hint_match = re.search(r"Secret\s*\(hint\)\s*:\s*(.+)", norm)
    if hint_match:
        totp_hint = hint_match.group(1).strip()

    pk: ParsedKit = {
        "has_payload": False,
        "payload_version": 0,
        "username": None,
        "recovery_key_present": False,
        "recovery_key_fingerprint": None,
        "recovery_backup_codes": rec_codes,
        "twofa_backup_codes": twofa_codes,
        "totp_secret_hint": totp_hint,
        "raw_payload": None,
    }
    return pk


def _find_section_fuzzy(text: str, title: str, threshold: float = 0.8) -> tuple[int, str]:
    """
    Returns (start_index, matched_line). start_index is the character index
    of the matched heading line in `text`. Returns (-1, "") if not found.
    """
    title_l = title.strip().lower()
    offset = 0

    for line in text.splitlines(True):  # keep newline chars
        line_stripped = line.strip()
        if not line_stripped:
            offset += len(line)
            continue

        ratio = difflib.SequenceMatcher(None, line_stripped.lower(), title_l).ratio()
        if ratio >= threshold:
            return offset, line
        offset += len(line)

    return -1, ""


def _extract_section(text: str, title: str, stop_titles: list[str], threshold: float = 0.8) -> str:
    """
    Extract text from the (fuzzy-matched) heading `title` until the earliest
    next stop_title (exact match search). Returns "" if the heading isn't found.
    """
    start_idx, matched_line = _find_section_fuzzy(text, title, threshold=threshold)
    if start_idx == -1:
        return ""

    after_start = start_idx + len(matched_line)
    after = text[after_start:]

    end_idx = len(after)
    for stop in stop_titles:
        j = after.find(stop)
        if j != -1 and j < end_idx:
            end_idx = j

    return after[:end_idx].strip()


def _parse_section_codes(section: str) -> list[str]:
    """
    Parse backup codes from a section that looks like:
      1. ABCD-EFGH
      2. IJKL-MNOP
    """
    codes: list[str] = []
    for line in section.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^\s*\d+\.\s+(.+?)\s*$", line)
        if not m:
            continue
        code = m.group(1).strip()
        if code and code not in codes:
            codes.append(code)
    return codes
