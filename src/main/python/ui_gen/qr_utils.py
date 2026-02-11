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

import io, json, gzip, base64, math
from typing import List, Iterable

# QR: keep chunks conservative to ensure fast scanning on mid phones
_QR_CHUNK_BYTES = 900     # payload bytes per QR *after* base64 (tuned for reliability)
_QR_PREFIX = "KQ1"        # version tag to identify our QR payloads

def _encode_for_qr(payload_obj: dict) -> bytes:
    """gzip+json, then base64 to ASCII bytes"""
    raw = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    gz = gzip.compress(raw, compresslevel=9)
    b64 = base64.b64encode(gz)
    return b64

def _chunk_bytes(b: bytes, n: int) -> Iterable[bytes]:
    for i in range(0, len(b), n):
        yield b[i:i+n]

def qr_chunks_for_payload(payload_obj: dict) -> List[str]:
    """
    Turn a dict into 1..N QR-safe ASCII strings.
    Format: KQ1:<i>/<N>:<base64_gzip_json_chunk>
    """
    b64 = _encode_for_qr(payload_obj)
    chunks = list(_chunk_bytes(b64, _QR_CHUNK_BYTES))
    total = len(chunks)
    parts: List[str] = []
    for i, c in enumerate(chunks, start=1):
        parts.append(f"{_QR_PREFIX}:{i}/{total}:" + c.decode("ascii"))
    return parts
