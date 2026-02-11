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
"""Module for breach check functionality.

This file is part of the Keyquorum Vault codebase.
"""

import logging, hashlib, time, random
from typing import Optional
import requests
from qtpy.QtCore import QThread
from qtpy.QtCore import Signal as pyqtSignal
log = logging.getLogger("keyquorum")

# Reuse a single session for connection pooling
_SESSION = requests.Session()
_HEADERS = {
    "User-Agent": "KeyquorumVault/1.0 (Password Breach Checker)",
    "Add-Padding": "true",  # HIBP privacy hardening
}


def _retry_delay(attempt: int) -> float:
    # Exponential backoff with jitter: 0.5, 1.0, 2.0 (20%)
    base = 0.5 * (2 ** max(0, attempt))
    jitter = base * (0.6 + 0.8 * random.random())
    return min(4.0, jitter)

def check_password_breach(
    password: str,
    *,
    session: Optional[requests.Session] = None,
    timeout: float = 8.0,
    max_retries: int = 2,
) -> int:
    from features.url.main_url import PWNEDPASSWORD
    """
    Query HIBP 'range' API using k-anonymity (first 5 SHA-1 hex chars).
    Returns:
        >=0  number of occurrences in breaches
        -1   on error (network/parse/HTTP)
    NOTE: Never logs the password or hash; only returns counts.
    """
    try:
        if not isinstance(password, str) or password == "":
            return 0  # treat empty as not breached (and avoid network)
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"{PWNEDPASSWORD}{prefix}"

        sess = session or _SESSION
        attempts = 0
        while True:
            try:
                resp = sess.get(url, headers=_HEADERS, timeout=timeout)
                if resp.status_code == 200:
                    # Each line: HASH_SUFFIX:COUNT
                    for line in resp.text.splitlines():
                        if not line:
                            continue
                        try:
                            h, count = line.split(":", 1)
                        except ValueError:
                            continue
                        if h.strip().upper() == suffix:
                            try:
                                return int(count.strip())
                            except ValueError:
                                return -1
                    return 0
                elif resp.status_code in (429, 500, 502, 503, 504):
                    if attempts >= max_retries:
                        return -1
                    time.sleep(_retry_delay(attempts))
                    attempts += 1
                    continue
                else:
                    return -1
            except requests.RequestException:
                if attempts >= max_retries:
                    return -1
                time.sleep(_retry_delay(attempts))
                attempts += 1
    except Exception as e:
        # Dont leak secrets; keep log minimal
        log.debug(f"[breach] error: {e}")
        return -1


class BreachCheckWorker(QThread):
    """
    Qt worker thread that emits the breach count (or -1 on error).
    Call .stop() to request cancellation (best-effort).
    """
    resultReady = pyqtSignal(int)

    def __init__(self, password: str, parent=None):
        super().__init__(parent)
        self._password = password
        self._stopped = False

    def stop(self):
        # Best-effort cancel: we honor this between retries
        self._stopped = True

    def run(self):
        if self._stopped:
            return
        count = check_password_breach(self._password, max_retries=2, timeout=8.0)
        if not self._stopped:
            self.resultReady.emit(count)

