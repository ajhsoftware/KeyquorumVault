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

"""Module for workers functionality.

This file is part of the Keyquorum Vault codebase.
"""

# --- QtCore ---
from qtpy.QtCore import (QObject, Signal, Slot,)

# --- helper ---
from vault_store.vault_store import load_vault
import re


class VaultSearchWorker(QObject):
    finished = Signal(list)
    error = Signal(str)
    progress = Signal(int, int)

    def __init__(self, username: str, user_key, query: str, max_results: int):
        super().__init__()
        self._username = (username or "").strip()
        self._user_key = user_key
        self._query = query
        self._max = max_results
        self._cancel = False

    @Slot()
    def run(self):
        try:
            entries = load_vault(self._username, self._user_key) or []
            def _cb(done, total): self.progress.emit(done, total)
            results = _scan_entries_for_query(
                entries, self._query,
                max_results=self._max,
                progress_cb=_cb,
                should_cancel=lambda: self._cancel
            )
            self.finished.emit(results)
        except Exception as e:
            self.error.emit(str(e))

    @Slot()
    def cancel(self):
        self._cancel = True


def _scan_entries_for_query(entries: list[dict], query: str, *, max_results: int = 200,
                        progress_cb=None, should_cancel=lambda: False) -> list[dict]:
    """
    Thread-safe scanner: NO UI calls here. Just crunches data.
    Returns list[{index, category, entry, score, matched}]
    """
    q = (query or "").strip().lower()
    if not q:
        return []

    from catalog_category.category_fields import get_fields_for  # safe import


    common_keys = [
        "Title", "Name", "Username", "User", "Email",
        "URL", "Site", "Website", "Login URL", "Address",
        "Notes", "Note", "Description", "Label",
    ]
    weight = {
        "Title": 4, "Name": 4, "Username": 3, "Email": 3,
        "URL": 3, "Site": 3, "Website": 3, "Login URL": 3,
        "Notes": 1, "Description": 1, "Label": 2,
    }

    hits: list[dict] = []
    q_re = re.escape(q)
    total = len(entries)

    for i, e in enumerate(entries, 1):
        if should_cancel and should_cancel():
            break

        cat = (e.get("category") or e.get("Category") or "").strip()
        try:
            cat_fields = get_fields_for(cat) or []
        except Exception:
            cat_fields = []

        fields_to_scan = list(dict.fromkeys([*cat_fields, *common_keys]))
        score = 0.0
        matched = set()

        for key in fields_to_scan:
            val = e.get(key)
            if not isinstance(val, str) or not val:
                continue
            s = val.lower()
            if q in s:
                matched.add(key)
                base = weight.get(key, 1)
                pos_bonus = max(0, 1.0 - (s.find(q) / max(1, len(s))))
                score += base * (1.0 + 0.25 * pos_bonus)
            elif re.search(rf"\b{q_re}", s):
                matched.add(key)
                score += weight.get(key, 1) * 0.9

        if score > 0:
            hits.append({"index": i-1, "category": cat, "entry": e, "score": score, "matched": matched})

        if progress_cb and (i % 25 == 0 or i == total):
            try:
                progress_cb(i, total)
            except Exception:
                pass

    hits.sort(key=lambda h: (-h["score"], h["category"], h["entry"].get("Title") or h["entry"].get("Name") or ""))
    return hits[:max_results]

