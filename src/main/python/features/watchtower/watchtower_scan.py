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
"""Background scanning logic for the Watchtower dashboard.

UI-light:
- WTIssue dataclass describing a finding
- ScanTask (QRunnable) which emits progress and a list of issues

The Watchtower UI/controller owns widget updates and button wiring.
"""

from dataclasses import dataclass
from typing import Callable, Dict, Optional
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from calendar import monthrange

from qtpy.QtCore import QObject, QRunnable, Signal

# Canonical mapping (user-customisable field labels live under catalog_category)
try:
    from catalog_category.category_fields import canonical_autofill_key
except Exception:  # pragma: no cover
    try:
        from category_fields import canonical_autofill_key  # type: ignore
    except Exception:  # pragma: no cover
        def canonical_autofill_key(label: str):  # type: ignore
            return None

log = logging.getLogger("keyquorum")


@dataclass
class WTIssue:
    kind: str
    entry_id: str
    title: str
    detail: str
    severity: int = 2  # 1=info, 2=warn, 3=high


class _Signals(QObject):
    progress = Signal(int)
    finished = Signal(list)  # list[WTIssue]
    error = Signal(str)


def _norm(s: str) -> str:
    return (s or "").strip()


def _parse_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, (int, float)):
        return bool(v)

    s = str(v).strip().lower()

    if s in ("true", "yes", "y", "1", "enabled", "on"):
        return True

    if s in ("false", "no", "n", "0", "disabled", "off", ""):
        return False

    return False


def stable_id_for_entry(e: dict) -> str:
    """Stable identifier derived from non-secret entry content."""
    try:
        title = _norm(e.get("title") or e.get("name") or e.get("Website") or e.get("Site") or "")
        user_val = ""
        site_val = ""
        for k in e.keys():
            ck = canonical_autofill_key(k)
            if ck == "username" and not user_val:
                user_val = _norm(str(e.get(k) or ""))
            elif ck in ("site", "url") and not site_val:
                site_val = _norm(str(e.get(k) or ""))
        key = {"t": title.lower(), "u": user_val.lower(), "url": site_val.lower()}
        raw = json.dumps(key, sort_keys=True, ensure_ascii=False).encode("utf-8", "ignore")
        return hashlib.sha1(raw).hexdigest()
    except Exception:
        try:
            raw = json.dumps(e, sort_keys=True, default=str).encode("utf-8", "ignore")
            return hashlib.sha1(raw).hexdigest()
        except Exception:
            return "unknown"


def _parse_expiry_to_last_day(exp: str) -> Optional[datetime]:
    """Accepts: MM/YY, MM/YYYY, MM-YY, MM-YYYY, YYYY-MM."""
    s = (exp or "").strip()
    if not s:
        return None

    m = re.match(r"^\s*(\d{4})[-/](\d{1,2})\s*$", s)  # YYYY-MM
    if m:
        y = int(m.group(1))
        mo = int(m.group(2))
        if 1 <= mo <= 12:
            last = monthrange(y, mo)[1]
            return datetime(y, mo, last, 23, 59, 59, tzinfo=timezone.utc)

    m = re.match(r"^\s*(\d{1,2})\s*[-/]\s*(\d{2}|\d{4})\s*$", s)  # MM/YY or MM/YYYY
    if m:
        mo = int(m.group(1))
        y = int(m.group(2))
        if y < 100:
            y = 2000 + y
        if 1 <= mo <= 12 and 2000 <= y <= 2100:
            last = monthrange(y, mo)[1]
            return datetime(y, mo, last, 23, 59, 59, tzinfo=timezone.utc)

    return None


def _get_password_fast(e: dict, canon: dict) -> str:
    if "password" in canon:
        v = e.get(canon["password"])
        if isinstance(v, str) and v.strip():
            return v.strip()

    return e.get("password") or e.get("Password") or ""


class ScanTask(QRunnable):
    def __init__(
        self,
        *,
        entries: list[dict],
        id_fn: Callable[[dict, int], str],
        get_strength: Callable[[str], int],
        breach_check: Optional[Callable[[str], int]],
        max_age_days: int,
        weak_threshold: int,
        enable_breach: bool,
        enable_card_expiry: bool = True,
        enable_missing_2fa: bool = True,
        card_warn_days: int = 30,
    ):
        super().__init__()
        self.s = _Signals()
        self.entries = list(entries or [])
        self.id_fn = id_fn
        self.get_strength = get_strength
        self.breach_check = breach_check
        self.max_age_days = int(max_age_days or 0)
        self.weak_threshold = int(weak_threshold or 0)
        self.enable_breach = bool(enable_breach)
        self.enable_card_expiry = bool(enable_card_expiry)
        self.enable_missing_2fa = bool(enable_missing_2fa)
        self.card_warn_days = int(card_warn_days or 30)
        self._canon_cache = {}
        self._expiry_cache = {}

    def _mk_eid(self, e: dict, i: int) -> str:
        try:
            raw_id = str(self.id_fn(e, i))
        except Exception:
            raw_id = ""
        raw_id = (raw_id or "").strip()
        if raw_id.startswith("idx:"):
            return raw_id
        if len(raw_id) >= 12:
            return raw_id
        return stable_id_for_entry(e)

    @staticmethod
    def _title(e: dict) -> str:
        best = e.get("title") or e.get("name") or ""
        if best:
            return str(best).strip()
        # Try site-like fields
        for k in e.keys():
            try:
                if canonical_autofill_key(k) in ("site", "url"):
                    v = e.get(k)
                    if v:
                        return str(v).strip()
            except Exception:
                continue
        return "(untitled)"

    def _canon_map(self, e: dict) -> Dict[str, str]:
        key = tuple(sorted(e.keys()))

        if key in self._canon_cache:
            return self._canon_cache[key]

        out = {}
        for label in key:
            try:
                ck = canonical_autofill_key(label)
            except Exception:
                ck = None
            if ck and ck not in out:
                out[ck] = label

        self._canon_cache[key] = out
        return out

    def _find_expiry_label(self, e: dict) -> Optional[str]:

        key = tuple(sorted(e.keys()))
        if key in self._expiry_cache:
            return self._expiry_cache[key]

        # 1️⃣ Prefer canonical mapping first
        for label in e.keys():
            try:
                key = canonical_autofill_key(label)
                if key in ("expiry_date", "expiry date", "card_expiry"):
                    self._expiry_cache[key] = label
                    return label
            except Exception:
                pass

        # 2️⃣ Exact schema match (safe)
        for label in e.keys():
            low = str(label).strip().lower()

            if low in {
                "expiry date",
                "exp",
                "exp date",
                "valid thru",
                "valid through",
                "card expiry"
            }:
                self._expiry_cache[key] = label
                return label

        # 3️⃣ Safe fallback (must contain expiry but NOT password)
        for label in e.keys():
            low = str(label).strip().lower()

            if "expiry" in low and "password" not in low:
                self._expiry_cache[key] = label
                return label


        return None

    def run(self):
        try:
            issues: list[WTIssue] = []
            entries = self.entries
            total = max(len(entries), 1)

            pwd_groups: Dict[str, list[dict]] = {}

            for i, e in enumerate(entries):
                if not e:
                    continue

                #if i % 5 == 0:
                if i % 200 == 0:
                    self.s.progress.emit(int((i / total) * 35))

                title = self._title(e)
                eid = self._mk_eid(e, i)
                canon = self._canon_map(e)
                pw = _get_password_fast(e, canon)

                is_card = (str(e.get("kind") or "").lower() == "credit_card")
                # Only treat as "login-like" if it really looks like a password login entry
                has_password_field = ("password" in canon) or ("Password" in e) or bool(pw)

                # -------- Username / URL applicability --------
                url = _norm(str(e.get("url") or ""))

                if not pw and not url and not is_card:
                    continue

                # Skip URL-related checks if no URL exists
                if url:

                    if "username" in canon and has_password_field:
                        username = _norm(str(e.get(canon["username"]) or ""))
                        if not username:
                            issues.append(WTIssue("Missing Username", eid, title, "No username set.", 1))

                    
                    if has_password_field:
                        if url.startswith("http://"):
                            issues.append(
                                WTIssue(
                                    "Insecure URL (HTTP)",
                                    eid,
                                    title,
                                    "URL uses HTTP instead of HTTPS.",
                                    2,
                                )
                            )

                    # -------- Missing 2FA (per-entry flag) --------
                    # Only for login-type entries (not cards) and only if the user enabled this rule.
                    if self.enable_missing_2fa and (not is_card) and has_password_field:
                        twofa_raw = None

                        # Try canonical mapping first
                        for label in e.keys():
                            try:
                                ck = canonical_autofill_key(label)
                            except Exception:
                                ck = None
                            if ck in ("2fa", "twofa", "totp", "otp", "has_totp", "two_factor", "2fa_enabled", "2FA Enabled"):
                                twofa_raw = e.get(label)
                                break

                        # Fallback: label name contains "2fa" / "totp"
                        if twofa_raw is None:
                            for label in e.keys():
                                low = str(label).strip().lower()
                                if "2fa" in low or "totp" in low or "two-factor" in low or "two factor" in low:
                                    twofa_raw = e.get(label)
                                    break

                        # Only warn if field exists and is explicitly false
                        if twofa_raw is not None:
                            if not _parse_bool(twofa_raw):
                                issues.append(
                                    WTIssue("Missing 2FA", eid, title, "2FA is disabled for this login.", 2)
                                )

                # -------- Expired item flag / age --------
                flag = _parse_bool(e.get("password_expired"))
                if flag:
                    issues.append(WTIssue("Expired Item", eid, title, "Entry is marked as expired.", 3))

                days = None
                matched_key = None
                for key in ("pw_changed_at", "updated_at", "last_updated", "Date", "created_at"):
                    v = e.get(key)
                    if not v:
                        continue
                    try:
                        sv = str(v).strip()
                        if len(sv) == 10 and "-" in sv:
                            dtv = datetime.strptime(sv, "%Y-%m-%d")
                            days = (datetime.now() - dtv).days
                        else:
                            dtv = datetime.fromisoformat(sv.replace("Z", "+00:00"))
                            if getattr(dtv, "tzinfo", None):
                                days = (datetime.now(dtv.tzinfo) - dtv).days
                            else:
                                days = (datetime.now() - dtv).days
                        matched_key = key
                       
                        break
                    except Exception as ex:
                        log.error(f"[WT-EXPIRE] {ex}, key {key}")

                if days is not None and self.max_age_days and days > self.max_age_days:
                    issues.append(WTIssue("Expired Item", eid, title, f"Last changed {days} days ago.", 3))

                # -------- Password age/strength/reuse/breach --------
                if pw:
                    try:
                        score = int(self.get_strength(pw))
                    except Exception:
                        score = 0
                    if self.weak_threshold and score < self.weak_threshold:
                        issues.append(WTIssue("Weak Password", eid, title, f"Strength {score}/100.", 3))

                    pwh = hashlib.sha256(pw.encode("utf-8")).hexdigest()
                    pwd_groups.setdefault(pwh, []).append({"eid": eid, "title": title})

                    # Respect user settings: only check HIBP when the feature is enabled.
                    # This must run per entry, otherwise only the last password scanned is checked.
                    if self.enable_breach and self.breach_check:
                        try:
                            count = int(self.breach_check(pw) or 0)
                        except Exception:
                            count = 0

                        if count > 0:
                            issues.append(
                                WTIssue("Known Breach", eid, title, f"Seen {count}× in breaches.", 3)
                            )

                # -------- Card expiry checks (field-driven) --------
                if self.enable_card_expiry and (e.get("kind") == "credit_card"):
                    exp_label = self._find_expiry_label(e)
                    if exp_label:
                        exp_val = _norm(str(e.get(exp_label) or ""))
                        dt = _parse_expiry_to_last_day(exp_val) if exp_val else None
                        if not exp_val:
                            issues.append(WTIssue("Missing Expiry Date", eid, title, "Expiry date field is empty.", 2))
                        elif not dt:
                            issues.append(WTIssue("Invalid Expiry Date", eid, title,
                                                 f"Expiry date format not recognised ({exp_val}).", 2))
                        else:
                            now = datetime.now(timezone.utc)
                            if dt < now:
                                issues.append(WTIssue("Card Expired", eid, title, f"Card expired ({exp_val}).", 3))
                            else:
                                days_left = (dt - now).days
                                if days_left <= self.card_warn_days:
                                    issues.append(WTIssue("Card Expiring Soon", eid, title,
                                                         f"Expires in {days_left} days ({exp_val}).", 2))

            # Reused passwords
            for lst in pwd_groups.values():
                if len(lst) <= 1:
                    continue
                names = ", ".join(x["title"] for x in lst[:4])
                more = "" if len(lst) <= 4 else f" (+{len(lst)-4} more)"
                for x in lst:
                    issues.append(WTIssue("Reused Password", x["eid"], x["title"],
                                         f"Same password used in: {names}{more}.", 3))

            expire_count = sum(1 for it in issues if it.kind == "Expired Item")
            self.s.progress.emit(100)
            self.s.finished.emit(issues)

        except Exception as exc:
            log.exception("[Watchtower] scan task crashed")
            try:
                self.s.error.emit(str(exc))
            except Exception:
                pass
