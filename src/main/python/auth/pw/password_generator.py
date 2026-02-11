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

import logging
import secrets
import string
import re
from qtpy.QtWidgets import (
    QDialog, QVBoxLayout, QLineEdit, QHBoxLayout, QPushButton, QLabel,
    QSpinBox, QComboBox, QCheckBox, QGridLayout, QGroupBox, QWidget
)
from qtpy.QtCore import Qt, QTimer, QCoreApplication
from features.clipboard.secure_clipboard import copy_secret
from auth.pw.password_utils import estimate_strength_score, validate_password_policy, SYMBOLS as POLICY_SYMBOLS

log = logging.getLogger("keyquorum")
SYMBOLS = POLICY_SYMBOLS


# ----------------- helpers -----------------

def _shuffle_inplace(lst: list[str]) -> None:
    for i in range(len(lst) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        lst[i], lst[j] = lst[j], lst[i]


def _obfuscate_seed(seed: str) -> str:
    """Light, reversible-unfriendly obfuscation (random case + occasional leet)"""
    if not seed:
        return seed
    # Trim and replace whitespace by a small separator
    s = seed.strip()
    s = re.sub(r"\s+", secrets.choice(["-", "_", ".", ""]), s)
    chars = []
    for ch in s:
        if ch.isalpha():
            ch = ch.upper() if secrets.randbits(1) else ch.lower()
        chars.append(ch)
    mapping = {"a": "@", "A": "@", "i": "!", "I": "!", "e": "3", "E": "3",
               "o": "0", "O": "0", "s": "$", "S": "$", "l": "1", "L": "1"}
    out = []
    for ch in chars:
        if ch in mapping and secrets.randbelow(3) == 0:
            out.append(mapping[ch])
        else:
            out.append(ch)
    return "".join(out)


def _count_kinds_text(text: str) -> tuple[int, int, int, int]:
    l = sum(1 for c in text if c.islower())
    u = sum(1 for c in text if c.isupper())
    d = sum(1 for c in text if c.isdigit())
    s = sum(1 for c in text if c in SYMBOLS)
    return l, u, d, s


def _enforce_minimums_on_parts(parts: list[str], need_upper: int, need_digits: int, need_symbols: int) -> list[str]:
    """
    parts: list of strings, some may be single chars, one may be the seed-block
    This will replace characters in-place (within parts) to reach needed counts.
    """
    # flatten to char list but keep mapping to part indices
    chars = []
    idx_map = []  # maps char index -> (part_index, char_index_in_part)
    for pi, part in enumerate(parts):
        for ci, ch in enumerate(part):
            chars.append(ch)
            idx_map.append((pi, ci))

    # current counts
    u = sum(1 for c in chars if c.isupper())
    d = sum(1 for c in chars if c.isdigit())
    s = sum(1 for c in chars if c in SYMBOLS)

    rng = secrets.SystemRandom()
    indices = list(range(len(chars)))
    rng.shuffle(indices)

    # helpers to write back into parts
    def write_char_at(flat_idx, ch):
        pi, ci = idx_map[flat_idx]
        lst = list(parts[pi])
        lst[ci] = ch
        parts[pi] = "".join(lst)

    # fill uppercase
    while sum(1 for c in (ch for part in parts for ch in part) if c.isupper()) < need_upper:
        if not indices:
            break
        i = indices.pop()
        write_char_at(i, rng.choice(string.ascii_uppercase))

    # fill digits
    while sum(1 for c in (ch for part in parts for ch in part) if c.isdigit()) < need_digits:
        if not indices:
            break
        i = indices.pop()
        write_char_at(i, rng.choice(string.digits))

    # fill symbols
    while sum(1 for c in (ch for part in parts for ch in part) if c in SYMBOLS) < need_symbols:
        if not indices:
            break
        i = indices.pop()
        write_char_at(i, rng.choice(SYMBOLS))

    return parts


def _apply_max_limits_on_parts(parts: list[str], minU: int, minD: int, minS: int, maxU: int, maxD: int, maxS: int) -> list[str]:
    """
    Reduce counts of categories that exceed maxima (0 = no limit).
    Ensure minimums are never violated.
    Strategy: replace characters from overfull categories with lowercase (or another allowed category that has headroom).
    """
    rng = secrets.SystemRandom()

    def counts():
        flat = "".join(parts)
        u = [i for i, c in enumerate(flat) if c.isupper()]
        d = [i for i, c in enumerate(flat) if c.isdigit()]
        s = [i for i, c in enumerate(flat) if c in SYMBOLS]
        l = [i for i, c in enumerate(flat) if c.islower() and c not in SYMBOLS]
        return flat, l, u, d, s

    # Helper to write back a replacement at flat index to parts
    def write_flat_index(flat_idx, ch):
        # find mapping to parts
        count = 0
        for pi, part in enumerate(parts):
            if flat_idx < count + len(part):
                ci = flat_idx - count
                lst = list(parts[pi])
                lst[ci] = ch
                parts[pi] = "".join(lst)
                return
            count += len(part)

    # For U/D/S categories
    for cat, mx, mn in (("U", maxU, minU), ("D", maxD, minD), ("S", maxS, minS)):
        if mx == 0:
            continue
        guard = 0
        while True:
            flat, l, u, d, s = counts()
            cur = {"U": len(u), "D": len(d), "S": len(s)}[cat]
            if cur <= mx or cur <= mn:
                break
            # pick an index from the overfull category
            pool_idx = {"U": u, "D": d, "S": s}[cat]
            if not pool_idx:
                break
            i = rng.choice(pool_idx)
            # choose target replacement: prefer lowercase if that doesn't violate min (lowercase has no min)
            if l:
                write_flat_index(i, rng.choice(string.ascii_lowercase))
            else:
                # choose any category with headroom
                # try lower, then other categories under max
                choices = []
                _, _, cu, cd, cs = counts()
                if maxU == 0 or len(cu) < maxU:
                    choices.append("U")
                if maxD == 0 or len(cd) < maxD:
                    choices.append("D")
                if maxS == 0 or len(cs) < maxS:
                    choices.append("S")
                if not choices:
                    write_flat_index(i, rng.choice(string.ascii_lowercase))
                else:
                    target = rng.choice(choices)
                    if target == "U":
                        write_flat_index(i, rng.choice(string.ascii_uppercase))
                    elif target == "D":
                        write_flat_index(i, rng.choice(string.digits))
                    else:
                        write_flat_index(i, rng.choice(SYMBOLS))
            guard += 1
            if guard > 1024:
                break

    return parts


def _composition_text(pwd: str) -> str:
    u = sum(1 for c in pwd if c.isupper())
    l = sum(1 for c in pwd if c.islower() and c not in SYMBOLS)
    d = sum(1 for c in pwd if c.isdigit())
    s = sum(1 for c in pwd if c in SYMBOLS)
    pattern = QCoreApplication.translate(
        "PasswordGeneratorDialog",
        "Aa:{u}  a:{l}  0-9:{d}  sym:{s}",
    )
    return pattern.format(u=u, l=l, d=d, s=s)


def _next_random_char(exclude_last_two: list[str], pool: str) -> str:
    for _ in range(8):
        c = secrets.choice(pool)
        if len(exclude_last_two) >= 2 and exclude_last_two[-1] == c == exclude_last_two[-2]:
            continue
        return c
    return secrets.choice(pool)


def generate_strong_password(length: int = 14, num_upper: int = 2, num_digits: int = 2, num_symbols: int = 2,
                             seed: str | None = None, obfuscate_seed: bool = True) -> str:
    """
    Generate a password where the seed (if provided) is inserted as a block.
    Min counts are guaranteed; max limits are applied later in dialog logic.
    """
    length = max(8, int(length))
    num_upper = max(0, int(num_upper))
    num_digits = max(0, int(num_digits))
    num_symbols = max(0, int(num_symbols))

    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    pool = lowers + uppers + digits + SYMBOLS

    # Prepare seed block (as single element if present)
    seed_block = ""
    if seed:
        seed_block = _obfuscate_seed(seed) if obfuscate_seed else seed.strip()
        seed_block = re.sub(r"\s+", secrets.choice(["-", "_", "."]), seed_block)

    parts: list[str] = []
    if seed_block:
        parts.append(seed_block)  # keep as block to guarantee presence

    # Count what seed already provides
    l0, u0, d0, s0 = _count_kinds_text(seed_block)
    need_u = max(0, num_upper - u0)
    need_d = max(0, num_digits - d0)
    need_s = max(0, num_symbols - s0)

    # Add required chars (single-char parts)
    parts += [secrets.choice(uppers) for _ in range(need_u)]
    parts += [secrets.choice(digits) for _ in range(need_d)]
    parts += [secrets.choice(SYMBOLS) for _ in range(need_s)]

    # Fill remaining with random chars
    # Compute how many more chars required (counting seed length if present)
    current_len = sum(len(p) for p in parts)
    if current_len < length:
        extra_needed = length - current_len
        last_two = []
        for _ in range(extra_needed):
            c = _next_random_char(last_two, pool)
            parts.append(c)
            last_two.append(c)
            if len(last_two) > 2:
                last_two.pop(0)

    # Shuffle the single-char parts but keep seed_block as block — to do so, separate
    seed_parts = [p for p in parts if len(p) > 1]  # should be at most seed_block
    single_parts = [p for p in parts if len(p) == 1]
    _shuffle_inplace(single_parts)

    # Insert seed_block at random position among the single parts (or at ends)
    final_parts: list[str] = []
    if seed_parts:
        seed_val = seed_parts[0]
        insert_at = secrets.randbelow(len(single_parts) + 1)
        final_parts = single_parts[:insert_at] + [seed_val] + single_parts[insert_at:]
    else:
        final_parts = single_parts

    return "".join(final_parts)


# ----------------- Dialog -----------------

class PasswordGeneratorDialog(QDialog):
    def __init__(self, target_field=None, confirm_field=None, parent=None):
        super().__init__(parent)

        self.setWindowTitle(self.tr("Password Generator"))
        self.setMinimumWidth(520)
        self.target_field = target_field
        self.confirm_field = confirm_field

        layout = QVBoxLayout(self)

        # Output + visibility
        self.output = QLineEdit()
        self.output.setEchoMode(QLineEdit.EchoMode.Password)
        self.output.textChanged.connect(self.update_strength_label)
        self.toggle_visibility = QPushButton("👁")
        self.toggle_visibility.setFixedWidth(44)
        self.toggle_visibility.setCheckable(True)
        self.toggle_visibility.clicked.connect(self.toggle_password_visibility)
        row = QHBoxLayout()
        row.addWidget(self.output)
        row.addWidget(self.toggle_visibility)
        layout.addLayout(row)

        # Seed input
        self.seed_edit = QLineEdit()
        self.seed_edit.setPlaceholderText(
            self.tr("Include word (optional) e.g. orchid or 'Jane1985'")
        )
        self.seed_edit.setToolTip(
            self.tr(
                "Optional word or phrase to include verbatim (if Obfuscate is off) "
                "or obfuscated (if on)."
            )
        )
        self.obf_box = QCheckBox(self.tr("Obfuscate word (recommended)"))
        self.obf_box.setChecked(True)
        layout.addWidget(self.seed_edit)
        layout.addWidget(self.obf_box)

        # Strength label
        self.strength_label = QLabel(
            self.tr("Password strength will appear here")
        )
        layout.addWidget(self.strength_label)

        # Controls (Min/Max & length) in compact group
        self.length_box = QSpinBox()
        self.length_box.setRange(8, 256)
        self.length_box.setValue(14)
        self.upper_box = QSpinBox()
        self.upper_box.setRange(0, 64)
        self.upper_box.setValue(3)
        self.digits_box = QSpinBox()
        self.digits_box.setRange(0, 64)
        self.digits_box.setValue(3)
        self.symbols_box = QSpinBox()
        self.symbols_box.setRange(0, 64)
        self.symbols_box.setValue(3)

        self.max_upper_box = QSpinBox()
        self.max_upper_box.setRange(0, 64)
        self.max_upper_box.setValue(0)
        self.max_digits_box = QSpinBox()
        self.max_digits_box.setRange(0, 64)
        self.max_digits_box.setValue(0)
        self.max_symbols_box = QSpinBox()
        self.max_symbols_box.setRange(0, 64)
        self.max_symbols_box.setValue(0)

        # Tooltips
        self.length_box.setToolTip(
            self.tr("Total password length in characters.")
        )
        self.upper_box.setToolTip(
            self.tr(
                "Minimum number of UPPERCASE letters (A–Z). The generator may include more."
            )
        )
        self.digits_box.setToolTip(
            self.tr(
                "Minimum number of digits (0–9). The generator may include more."
            )
        )
        self.symbols_box.setToolTip(
            self.tr(
                "Minimum number of symbols. The generator may include more."
            )
        )
        self.max_upper_box.setToolTip(
            self.tr("Maximum uppercase letters allowed. Set 0 for no limit.")
        )
        self.max_digits_box.setToolTip(
            self.tr("Maximum digits allowed. Set 0 for no limit.")
        )
        self.max_symbols_box.setToolTip(
            self.tr("Maximum symbols allowed. Set 0 for no limit.")
        )

        self.min_strength_box = QComboBox()
        # Visible labels translated, internal keys stay English
        self.min_strength_box.addItem(self.tr("Medium"), "Medium")
        self.min_strength_box.addItem(self.tr("Strong"), "Strong")
        self.min_strength_box.addItem(self.tr("Excellent"), "Excellent")
        self.min_strength_box.setCurrentIndex(2)  # Excellent
        self.min_strength_box.setToolTip(
            self.tr("Minimum strength target: Strong ≈ 70+, Excellent ≈ 85+.")
        )
        self.min_strength_box.currentIndexChanged.connect(
            self.adjust_spinners_for_strength
        )

        # Ensure length >= mins
        for s in (self.upper_box, self.digits_box, self.symbols_box):
            s.valueChanged.connect(self._ensure_valid_length)

        # Compact rules group (grid)
        rules = QGroupBox(self.tr("Rules"))
        grid = QGridLayout(rules)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(6)
        grid.setContentsMargins(8, 8, 8, 8)

        grid.addWidget(QLabel(self.tr("Password Length:")), 0, 0)
        grid.addWidget(self.length_box, 0, 1)

        def minmax_row(row: int, label: str, min_spin, max_spin):
            grid.addWidget(QLabel(self.tr(label)), row, 0)
            w = QWidget()
            hb = QHBoxLayout(w)
            hb.setContentsMargins(0, 0, 0, 0)
            hb.setSpacing(8)
            hb.addWidget(QLabel(self.tr("Min:")))
            hb.addWidget(min_spin)
            hb.addWidget(QLabel(self.tr("Max:")))
            hb.addWidget(max_spin)
            hb.addStretch(1)
            grid.addWidget(w, row, 1)

        minmax_row(1, "Uppercase Letters:", self.upper_box, self.max_upper_box)
        minmax_row(2, "Digits:", self.digits_box, self.max_digits_box)
        minmax_row(3, "Symbols:", self.symbols_box, self.max_symbols_box)

        grid.addWidget(
            QLabel(self.tr("Minimum Strength (target):")), 4, 0
        )
        grid.addWidget(self.min_strength_box, 4, 1)

        layout.addWidget(rules)

        # Buttons
        btns = QHBoxLayout()
        self.generate_btn = QPushButton(self.tr("🔄 Generate"))
        self.copy_btn = QPushButton(self.tr("📋 Copy"))
        self.autofill_btn = QPushButton(self.tr("⚡ Auto Add"))
        btns.addWidget(self.generate_btn)
        btns.addWidget(self.copy_btn)
        btns.addWidget(self.autofill_btn)
        layout.addLayout(btns)

        self.generate_btn.clicked.connect(self.generate_password)
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        self.autofill_btn.clicked.connect(self.auto_fill)

        # initial generation
        QTimer.singleShot(0, self.generate_password)

    # ---------------- helpers ----------------
    def _ensure_valid_length(self):
        req = (
            self.upper_box.value()
            + self.digits_box.value()
            + self.symbols_box.value()
        )
        if self.length_box.value() < req:
            self.length_box.setValue(req)

    def toggle_password_visibility(self):
        self.output.setEchoMode(
            QLineEdit.EchoMode.Normal
            if self.toggle_visibility.isChecked()
            else QLineEdit.EchoMode.Password
        )

    def update_strength_label(self):
        pwd = self.output.text()
        if not pwd:
            self.strength_label.setText(
                self.tr("No password generated yet.")
            )
            return
        if len(pwd) < 8:
            self.strength_label.setText(
                self.tr("Too Short: must be at least 8 characters.")
            )
            self.strength_label.setStyleSheet(
                "color: darkred; font-weight: bold"
            )
            return
        score = int(estimate_strength_score(pwd))
        # Logical level keys (English, internal)
        if score < 40:
            level_key = "Weak"
        elif score < 70:
            level_key = "Medium"
        elif score < 85:
            level_key = "Strong"
        else:
            level_key = "Excellent"

        # Translated display level
        level_display = {
            "Weak": self.tr("Weak"),
            "Medium": self.tr("Medium"),
            "Strong": self.tr("Strong"),
            "Excellent": self.tr("Excellent"),
        }[level_key]

        info_map = {
            "Weak": self.tr("Add variety (Aa1!) and length."),
            "Medium": self.tr("Add more length/variety."),
            "Strong": self.tr("Great—enable 2FA where possible."),
            "Excellent": self.tr("Strong, long, and complex."),
        }
        info = info_map[level_key]

        color = {
            "Weak": "red",
            "Medium": "orange",
            "Strong": "green",
            "Excellent": "darkgreen",
        }[level_key]

        comp = _composition_text(pwd)
        text_pattern = self.tr(
            "{level} ({score}/100): {info}\n{composition}"
        )
        self.strength_label.setText(
            text_pattern.format(
                level=level_display,
                score=score,
                info=info,
                composition=comp,
            )
        )
        self.strength_label.setStyleSheet(
            f"color: {color}; font-weight: bold"
        )

    def adjust_spinners_for_strength(self, index: int):
        # Use internal key (not translated text) for logic
        level_key = self.min_strength_box.itemData(index) or "Excellent"
        if level_key == "Excellent":
            self.length_box.setValue(14)
            self.upper_box.setValue(3)
            self.digits_box.setValue(3)
            self.symbols_box.setValue(3)
        elif level_key == "Strong":
            self.length_box.setValue(12)
            self.upper_box.setValue(2)
            self.digits_box.setValue(2)
            self.symbols_box.setValue(2)
        else:  # "Medium"
            self.length_box.setValue(10)
            self.upper_box.setValue(1)
            self.digits_box.setValue(1)
            self.symbols_box.setValue(1)
        self._ensure_valid_length()

    # ---------------- actions ----------------
    def generate_password(self):
        length = int(self.length_box.value())
        minU = int(self.upper_box.value())
        minD = int(self.digits_box.value())
        minS = int(self.symbols_box.value())
        maxU = int(self.max_upper_box.value())
        maxD = int(self.max_digits_box.value())
        maxS = int(self.max_symbols_box.value())
        seed = (self.seed_edit.text() or "").strip()
        obf = self.obf_box.isChecked()
        req = minU + minD + minS
        if length < max(8, req):
            length = max(8, req)
            self.length_box.setValue(length)

        # Use internal level key, not translated label
        level_key = self.min_strength_box.currentData() or "Excellent"
        min_score_map = {"Medium": 50, "Strong": 70, "Excellent": 85}
        min_score = min_score_map.get(level_key, 85)

        best = None
        best_score = -1
        for _ in range(300):
            pwd = generate_strong_password(
                length, minU, minD, minS, seed=seed or None, obfuscate_seed=obf
            )
            # Convert to parts where seed is block if present
            parts = []
            if seed:
                seed_block = _obfuscate_seed(seed) if obf else seed.strip()
                seed_block = re.sub(
                    r"\s+", secrets.choice(["-", "_", "."]), seed_block
                )
                # We expect generate_strong_password to already include seed_block as contiguous block,
                # but for safety, rebuild parts: if seed_block in pwd we split around it
                if seed_block in pwd:
                    before, after = pwd.split(seed_block, 1)
                    parts = []
                    if before:
                        parts += list(before)
                    parts.append(seed_block)
                    if after:
                        parts += list(after)
                else:
                    # if not present, insert block at random
                    parts = list(pwd)
                    insert_at = secrets.randbelow(len(parts) + 1)
                    parts = parts[:insert_at] + [seed_block] + parts[insert_at:]
            else:
                parts = list(pwd)

            # Ensure parts are strings (single chars or seed block)
            canonical_parts = []
            for p in parts:
                if isinstance(p, str) and len(p) == 1:
                    canonical_parts.append(p)
                else:
                    canonical_parts.append(str(p))

            # Enforce minimums (works across parts, preserves seed block as unit)
            canonical_parts = _enforce_minimums_on_parts(
                canonical_parts, minU, minD, minS
            )

            # If final total length exceeds requested length because of seed, trim characters but keep seed block intact:
            total_len = sum(len(p) for p in canonical_parts)
            if total_len > length:
                # attempt to trim single-char parts while preserving seed block
                # build flat string and remove from ends until fits, but keep seed block substring intact
                flat = "".join(canonical_parts)
                # if seed present ensure not to truncate seed
                if seed:
                    seed_block = (
                        _obfuscate_seed(seed) if obf else seed.strip()
                    )
                    seed_block = re.sub(
                        r"\s+", secrets.choice(["-", "_", "."]), seed_block
                    )
                    if seed_block in flat:
                        # try trimming from both ends while preserving seed
                        while len(flat) > length:
                            if flat.endswith(seed_block) or flat.startswith(
                                seed_block
                            ):
                                # remove from the other side
                                if flat.startswith(seed_block):
                                    flat = flat[:length]  # trim end
                                else:
                                    flat = flat[-length:]  # trim start
                                break
                            # otherwise trim from end
                            flat = flat[:-1]
                    else:
                        flat = flat[:length]
                else:
                    flat = flat[:length]
                # rebuild parts as simple chars
                canonical_parts = [c for c in flat]

                # re-enforce mins if trimming broke them
                canonical_parts = _enforce_minimums_on_parts(
                    canonical_parts, minU, minD, minS
                )

            # Apply maxima (clamp) but never violate mins
            canonical_parts = _apply_max_limits_on_parts(
                canonical_parts, minU, minD, minS, maxU, maxD, maxS
            )

            candidate = "".join(canonical_parts)
            score = int(estimate_strength_score(candidate))
            if validate_password_policy(candidate) and score >= min_score:
                self.output.setText(candidate)
                return
            if score > best_score:
                best, best_score = candidate, score

        # fallback
        self.output.setText(best or "")
        if best:
            self.length_box.setValue(len(best))

    def copy_to_clipboard(self):
        copy_secret(self.output.text())
        self.close()

    def auto_fill(self):
        pwd = self.output.text()
        if self.target_field:
            self.target_field.clear()
            self.target_field.setText(pwd)
            try:
                self.target_field.editingFinished.emit()
            except Exception:
                pass
        if self.confirm_field:
            self.confirm_field.clear()
            self.confirm_field.setText(pwd)
            try:
                self.confirm_field.editingFinished.emit()
            except Exception:
                pass
        self.close()


# Launcher
def show_password_generator_dialog(parent=None, target_field=None, confirm_field=None):
    dlg = PasswordGeneratorDialog(parent=parent, target_field=target_field, confirm_field=confirm_field)
    dlg.setWindowModality(Qt.WindowModal if parent else Qt.ApplicationModal)
    dlg.setAttribute(Qt.WA_DeleteOnClose, True)
    dlg.exec()
