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
"""
This module defines a standalone controller for the Watchtower feature.  It
contains a `WatchtowerPanel` class that binds to the widgets embedded in
`keyquorum_ui.ui` and orchestrates scans, summary updates, export, and
ignoring/fixing issues.  A companion `build_watchtower_panel()` function
constructs and wires a panel given a reference to the main window.  The
implementation in this file intentionally avoids any dependence on the old
`uiwatchtower_old.py` or the previously separate Watchtower UI.  Instead,
it assumes that all Watchtower widgets live directly in the main UI and
locates them via `findChild` on the main window.

The controller does not subclass `QWidget`; instead it operates purely as
a QObject, managing state and connecting signals.  It uses the helper
modules `watchtower_scan.py`, `watchtower_actions.py`, `watchtower_helpers.py`
and `watchtower_settings.py` for scanning, fixing entries, persistence,
and per‑user settings.  All strings are translated through Qt's
translation system using the "uiwatchtower" context.
"""

from vault_store.vault_store import load_vault
from auth.pw.password_generator import generate_strong_password
from features.watchtower.watchtower_helpers import (
    persist_entry_with_history as _persist_entry_with_history,
    find_entry_index_by_id as _find_entry_index_by_id,
)

from features.watchtower.watchtower_scan import stable_id_for_entry
import string
import secrets
from typing import Callable, Iterable, Optional, List, Dict

from qtpy.QtCore import QObject, QSettings, QThreadPool
from qtpy.QtWidgets import (
    QMessageBox,
    QFileDialog,
    QCheckBox,
    QLabel,
    QPushButton,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
    QHBoxLayout,
)
from qtpy.QtCore import QCoreApplication, Qt

from .watchtower_scan import ScanTask, WTIssue

# --- log ---
import logging
log = logging.getLogger("keyquorum")


def _tr(text: str) -> str:
    """Qt translation helper scoped to the Watchtower UI."""
    return QCoreApplication.translate("uiwatchtower", text)


class WatchtowerPanel(QObject):
    """
    Controller for the Watchtower feature.  It binds to the existing
    Watchtower widgets in the main window, orchestrates scans in a
    background thread, updates the summary and tables, and handles
    ignoring or fixing issues.  This class contains no references to
    the old standalone UI.
    """

    def __init__(
        self,
        *,
        mw: QWidget,
        get_entries: Callable[[], Iterable[dict]],
        get_strength: Callable[[str], int],
        breach_check: Optional[Callable[[str], int]] = None,
        max_age_days: int = 180,
        weak_threshold: int = 60,
        enable_breach_provider: Callable[[], bool] = lambda: False,
        on_fix: Optional[Callable[[str], None]] = None,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        # Main window reference (used for parent of message boxes)
        self._mw = mw
        # data providers supplied by main
        self.get_entries = get_entries
        self.get_strength = get_strength
        self.breach_check = breach_check
        self.max_age_days = int(max_age_days)
        self.weak_threshold = int(weak_threshold)
        self.enable_breach_provider = enable_breach_provider
        self.on_fix = on_fix
        self.show_msg = False

        # thread pool for running scans
        self.threadpool = QThreadPool.globalInstance()

        # settings providers (wired by set_settings_providers)
        self._get_rules: Optional[Callable[[], dict]] = None
        self._set_rules: Optional[Callable[[dict], None]] = None
        self._get_ignored: Optional[Callable[[], list]] = None
        self._set_ignored: Optional[Callable[[list], None]] = None
        self._get_global_flags: Optional[Callable[[], dict]] = None

        # last issues from a scan
        self._last_issues: List[WTIssue] = []

        # Bind UI elements from the main window
        self._bind_ui_from_mainwindow(mw)

        # Connect checkboxes to save rules when toggled
        for cb in (
            self.chk_weak,
            self.chk_reused,
            self.chk_http,
            self.chk_missing_user,
            self.chk_missing_url,
            self.chk_2fa,
            self.chk_cards,
            self.chk_expired,
        ):
            if cb is not None:
                try:
                    cb.toggled.connect(self._save_rules_from_ui)
                except Exception:
                    pass

        # Connect primary buttons
        if self.scan_btn is not None:
            try:
                self.scan_btn.clicked.connect(self._on_scan_clicked)
            except Exception:
                pass
        if self.preflight_btn is not None:
            try:
                self.preflight_btn.clicked.connect(self._run_preflight)
            except Exception:
                pass
        if self.export_btn is not None:
            try:
                self.export_btn.clicked.connect(self.export_report)
            except Exception:
                pass

        try:
            self.ignoreSelectedBtn.clicked.connect(self.on_ignore_selected)
        except Exception as e:
            pass

        try:
            self.unignoreSelectedBtn.clicked.connect(self.on_unignore_selected)
        except Exception as e:
            pass

        # Load saved rules into the UI
        self._load_rules_into_ui()

        # Neutral initial state
        self._set_summary(0, 0, 0, 0, 0, 0, 0, 0, 0, score=0)
        if self.score_lbl is not None:
            try:
                self.score_lbl.setText(_tr("Security Score: –"))
            except Exception:
                pass
        if self.export_btn is not None:
            try:
                self.export_btn.setEnabled(False)
            except Exception:
                pass

    # ------------------------
    # Settings wiring
    # ------------------------

    def set_settings_providers(
        self,
        *,
        get_rules: Optional[Callable[[], dict]] = None,
        set_rules: Optional[Callable[[dict], None]] = None,
        get_ignored: Optional[Callable[[], list]] = None,
        set_ignored: Optional[Callable[[list], None]] = None,
        get_global_flags: Optional[Callable[[], dict]] = None,
    ) -> None:
        """
        Provide callbacks for per‑user rule/ignore settings and global flags.
        These functions are typically bound to helpers in
        `watchtower_settings.py` by the main window.  Each callable
        should require no arguments and return a dict or list, or in the
        case of setters, accept a dict/list.  All arguments are optional;
        when not provided the panel falls back to QSettings.
        """
        self._get_rules = get_rules
        self._set_rules = set_rules
        self._get_ignored = get_ignored
        self._set_ignored = set_ignored
        self._get_global_flags = get_global_flags

    # ------------------------
    # UI binding
    # ------------------------

    def _bind_ui_from_mainwindow(self, mw: QWidget) -> None:
        """
        Locate all Watchtower widgets from the main window and store them
        as attributes on this controller.  Widgets may be missing in
        certain builds; in those cases the attribute will be set to None
        and referenced defensively.
        """
        # Buttons
        self.scan_btn = mw.findChild(QPushButton, "scan_btn")
        self.preflight_btn = mw.findChild(QPushButton, "preflight_btn")
        self.export_btn = mw.findChild(QPushButton, "export_btn")
        self.ignoreSelectedBtn = mw.findChild(QPushButton, "ignoreSelectedBtn")
        self.unignoreSelectedBtn = mw.findChild(QPushButton, "unignoreSelectedBtn")
        # Filters / checkboxes
        self.chk_weak = mw.findChild(QCheckBox, "chk_weak")
        self.chk_reused = mw.findChild(QCheckBox, "chk_reused")
        self.chk_http = mw.findChild(QCheckBox, "chk_http")
        self.chk_missing_user = mw.findChild(QCheckBox, "chk_missing_user")
        self.chk_missing_url = mw.findChild(QCheckBox, "chk_missing_url")
        self.chk_2fa = mw.findChild(QCheckBox, "chk_2fa")
        self.chk_cards = mw.findChild(QCheckBox, "chk_cards")
        self.chk_expired = (
            mw.findChild(QCheckBox, "chk_password_expired")
            or mw.findChild(QCheckBox, "chk_expired")
            or mw.findChild(QCheckBox, "pw_exp")
        )

        # Summary value labels
        self.lbl_reused = mw.findChild(QLabel, "lbl_reused")
        self.lbl_weak = mw.findChild(QLabel, "lbl_weak")
        self.lbl_old = mw.findChild(QLabel, "lbl_old")
        self.lbl_breach = mw.findChild(QLabel, "lbl_breach")
        self.lbl_http = mw.findChild(QLabel, "lbl_http")
        self.lbl_missing_user = mw.findChild(QLabel, "lbl_missing_user")
        self.lbl_missing_url = mw.findChild(QLabel, "lbl_missing_url")
        self.lbl_2fa = mw.findChild(QLabel, "lbl_2fa")
        self.lbl_cards = mw.findChild(QLabel, "lbl_cards")

        # Preserve the original label text so we can append counts without
        # destroying the UI headings (Designer often uses the same QLabel).
        self._summary_base = {}
        for _lbl in (self.lbl_weak, self.lbl_reused, self.lbl_http, self.lbl_missing_user,
                     self.lbl_missing_url, self.lbl_old, self.lbl_breach, self.lbl_2fa, self.lbl_cards):
            if _lbl is not None:
                try:
                    self._summary_base[id(_lbl)] = str(_lbl.text() or "").strip()
                except Exception:
                    self._summary_base[id(_lbl)] = ""

        # Progress + tables + score
        self.progress = mw.findChild(QProgressBar, "progress")
        self.score_lbl = mw.findChild(QLabel, "score_lbl")
        self.tbl = mw.findChild(QTableWidget, "tbl")
        self.tbl_ignored = mw.findChild(QTableWidget, "tbl_ignored")

        # Context menu for Ignore/Unignore (no per-row widgets)
        try:
            if self.tbl is not None:
                self.tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
                self.tbl.customContextMenuRequested.connect(self._on_active_context_menu)
        except Exception:
            pass

        try:
            if self.tbl_ignored is not None:
                self.tbl_ignored.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
                self.tbl_ignored.customContextMenuRequested.connect(self._on_ignored_context_menu)
        except Exception:
            pass

        # Defensive warning for missing widgets
        missing: List[str] = []
        for attr in (
            "scan_btn",
            "preflight_btn",
            "ignoreSelectedBtn",
            "unignoreSelectedBtn",
            "export_btn",
            "chk_weak",
            "chk_reused",
            "chk_http",
            "chk_missing_user",
            "chk_missing_url",
            "chk_2fa",
            "chk_cards",
            # chk_expired is optional in older UI builds
            "lbl_reused",
            "lbl_weak",
            "lbl_old",
            "lbl_breach",
            "lbl_http",
            "lbl_missing_user",
            "lbl_missing_url",
            "lbl_2fa",
            # lbl_cards intentionally optional
            "progress",
            "score_lbl",
            "tbl",
            "tbl_ignored",
        ):
            if getattr(self, attr, None) is None:
                missing.append(attr)
        if missing:
            log.debug(
                "Watchtower: missing UI widgets in keyquorum_ui.ui: %s",
                ", ".join(missing),
            )


    # ------------------------
    # Settings helpers
    # ------------------------

    def _settings(self) -> QSettings:
        """Return a QSettings instance for Watchtower defaults."""
        return QSettings("Keyquorum", "Watchtower")

    def _preface_suppressed(self) -> bool:
        try:
            return bool(self._settings().value("preface_suppressed", False, type=bool))
        except Exception:
            return False

    def _set_preface_suppressed(self, yes: bool) -> None:
        try:
            self._settings().setValue("preface_suppressed", bool(yes))
        except Exception:
            pass

    def _maybe_show_preface(self) -> bool:
        """
        Show a one‑time informational preface before the first scan.  Returns
        True to proceed with the scan or False if cancelled.
        """
        if self._preface_suppressed():
            return True

        text = (
            "<b>"
            + _tr("Before you run Watchtower")
            + "</b><br><br>"
            + _tr(
                "• This scan flags reused, weak or old passwords, missing usernames/URLs, and HTTP-only logins."
            )
            + "<br>"
            + "• <b>"
            + _tr("Known breach checks")
            + "</b>"
            + _tr(
                " are optional. When enabled in Settings, they use a k-anonymity API so "
            )
            + "<i>"
            + _tr("your passwords never leave your device")
            + "</i>"
            + _tr(". Results are not exhaustive")
            + ".<br>"
            + _tr("• Never paste real passwords into websites. For manual research, use reputable sources like ")
            + "<i>"
            + _tr("Have I Been Pwned – Pwned Passwords")
            + "</i> "
            + _tr("and their documented API/datasets")
            + ".<br><br>"
            + _tr("Keep your OS/browser up to date and rotate important passwords regularly.")
        )

        box = QMessageBox(self._mw)
        box.setWindowTitle(_tr("Watchtower"))
        box.setIcon(QMessageBox.Icon.Information)
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(text)

        dont = QCheckBox(_tr("Don't show this again"), box)
        box.setCheckBox(dont)

        run_btn = box.addButton(_tr("Run Scan"), QMessageBox.ButtonRole.AcceptRole)
        cancel_btn = box.addButton(_tr("Cancel"), QMessageBox.ButtonRole.RejectRole)

        # Inform if breach checking is currently disabled
        try:
            if not bool(self.enable_breach_provider()):
                box.setInformativeText(
                    _tr(
                        "Password breach checking is currently disabled (Settings → Security)."
                    )
                )
        except Exception:
            pass

        res = box.exec()
        if box.clickedButton() is run_btn:
            try:
                self._set_preface_suppressed(dont.isChecked())
            except Exception:
                pass
            return True
        # Cancelled
        return False

    def _get_selected_issue(self, table, rows_list):
        r = table.currentRow()
        if r < 0 or r >= len(rows_list):
            return None
        return rows_list[r]

    def on_unignore_selected(self):
        it, which = self._wt_get_selected_issue()
        if not it:
            return
        if which != "ignored":
            return

        self._wt_unignore_issue(it.entry_id, it.kind)
        try:
            self._rebuild_tables(getattr(self, "_last_issues", []) or [])
        except Exception:
            pass

    # ------------------------
    # Rules + ignored handling
    # ------------------------

    def _default_rules(self) -> dict:
        return {
            "weak_pw": True,
            "reused_pw": True,
            "http_only": True,
            "missing_user": True,
            "missing_url": True,
            "missing_2fa": True,
            "card_expire": True,
            "password_expired": True,
        }

    def _load_rules_dict(self) -> dict:
        base = self._default_rules().copy()
        # Prefer per‑user providers if defined
        if self._get_rules:
            try:
                got = self._get_rules() or {}
                if isinstance(got, dict):
                    for k in base.keys():
                        if k in got:
                            base[k] = bool(got[k])
                return base
            except Exception:
                pass
        # Fallback to QSettings
        s = self._settings()
        for key, defv in base.items():
            try:
                base[key] = bool(
                    s.value(f"rule_{key}", defv, type=bool)
                )
            except Exception:
                base[key] = defv
        return base

    def _save_rules_dict(self, rules: dict) -> None:
        if self._set_rules:
            try:
                self._set_rules(rules)
                return
            except Exception:
                pass
        # Fallback to QSettings
        s = self._settings()
        for k, v in rules.items():
            try:
                s.setValue(f"rule_{k}", bool(v))
            except Exception:
                pass

    def _load_rules_into_ui(self) -> None:
        rules = self._load_rules_dict()
        try:
            if self.chk_weak is not None:
                self.chk_weak.setChecked(bool(rules.get("weak_pw", True)))
            if self.chk_reused is not None:
                self.chk_reused.setChecked(bool(rules.get("reused_pw", True)))
            if self.chk_http is not None:
                self.chk_http.setChecked(bool(rules.get("http_only", True)))
            if self.chk_missing_user is not None:
                self.chk_missing_user.setChecked(bool(rules.get("missing_user", True)))
            if self.chk_missing_url is not None:
                self.chk_missing_url.setChecked(bool(rules.get("missing_url", True)))
            if self.chk_2fa is not None:
                self.chk_2fa.setChecked(bool(rules.get("missing_2fa", True)))
            if self.chk_cards is not None:
                self.chk_cards.setChecked(bool(rules.get("card_expire", True)))
            if self.chk_expired is not None:
                self.chk_expired.setChecked(bool(rules.get("password_expired", True)))
        except Exception:
            pass

    def _save_rules_from_ui(self) -> None:
        # Called whenever a checkbox is toggled
        try:
            rules = {
                "weak_pw": bool(self.chk_weak.isChecked()) if self.chk_weak is not None else True,
                "reused_pw": bool(self.chk_reused.isChecked()) if self.chk_reused is not None else True,
                "http_only": bool(self.chk_http.isChecked()) if self.chk_http is not None else True,
                "missing_user": bool(self.chk_missing_user.isChecked()) if self.chk_missing_user is not None else True,
                "missing_url": bool(self.chk_missing_url.isChecked()) if self.chk_missing_url is not None else True,
                "missing_2fa": bool(self.chk_2fa.isChecked()) if self.chk_2fa is not None else True,
                "card_expire": bool(self.chk_cards.isChecked()) if self.chk_cards is not None else True,
                "password_expired": bool(self.chk_expired.isChecked()) if self.chk_expired is not None else True,
            }
            self._save_rules_dict(rules)
        except Exception:
            pass

    def _issue_rule_key(self, kind: str) -> Optional[str]:
        k = kind.strip()
        mapping = {
            "Weak Password": "weak_pw",
            "Reused Password": "reused_pw",
            "Insecure URL (HTTP)": "http_only",
            "Missing Username": "missing_user",
            "Missing URL": "missing_url",
            "Missing 2FA": "missing_2fa",
            "Account Missing 2FA": "missing_2fa",
            "Card Expired": "card_expire",
            "Card Expiring Soon": "card_expire",
            "Old Password": "password_expired",
            "Expired Item": "password_expired",
            "Password Expired": "password_expired",
            # Breach & Old always on if present
        }
        return mapping.get(k)

    def _load_ignored_list(self) -> list:
        if self._get_ignored:
            try:
                lst = self._get_ignored() or []
                if isinstance(lst, list):
                    return lst
            except Exception:
                pass
        return []

    def _save_ignored_list(self, lst: list) -> None:
        if self._set_ignored:
            try:
                self._set_ignored(lst)
                return
            except Exception:
                pass
        # No setter provided → do nothing

    def _is_issue_ignored(self, it: WTIssue, ignored: list) -> bool:
        for entry in ignored:
            try:
                if (
                    str(entry.get("entry_id")) == str(it.entry_id)
                    and str(entry.get("issue")) == str(it.kind)
                ):
                    return True
            except Exception:
                continue
        return False

    # ------------------------
    # Preflight + scanning
    # ------------------------

    def _run_preflight(self) -> None:
        """
        Quick environment check; shows a summary dialog.
        """
        issues: List[str] = []
        # 1) entries available?
        try:
            entries = list(self.get_entries() or [])
        except Exception as e:
            entries = []
            issues.append(_tr("Could not read vault entries ({err}).").format(err=e))

        if not entries:
            issues.append(_tr("No entries found in the vault."))

        # 2) breach check enabled?
        try:
            if not bool(self.enable_breach_provider()):
                issues.append(
                    _tr(
                        "Breach checking is disabled (enable it in Settings for leak exposure checks)."
                    )
                )
        except Exception:
            pass

        # 3) quick content heuristics
        pw_missing = 0
        url_http = 0
        for e in entries:
            try:
                if not (e.get("password") or "").strip():
                    pw_missing += 1
                url0 = str(e.get("url") or e.get("origin") or "").strip().lower()
                if url0.startswith("http://"):
                    url_http += 1
            except Exception:
                pass

        if pw_missing:
            issues.append(
                _tr("{count} entr{suffix} without a password.").format(
                    count=pw_missing,
                    suffix="y" if pw_missing == 1 else "ies",
                )
            )
        if url_http:
            issues.append(
                _tr("{count} URL{suffix} HTTP-only.").format(
                    count=url_http,
                    suffix=" is" if url_http == 1 else "s are",
                )
            )

        msg = QMessageBox(self._mw)
        msg.setWindowTitle(_tr("Preflight Check"))
        msg.setIcon(QMessageBox.Icon.Information)
        if issues:
            html = "<ul style='margin-left:14px'>" + "".join(f"<li>{i}</li>" for i in issues) + "</ul>"
            msg.setText(
                "<b>" + _tr("Preflight found a few things to review") + ":</b>" + html
            )
        else:
            msg.setText(_tr("All basic checks look good. You can run Watchtower now."))
        msg.addButton(_tr("OK"), QMessageBox.ButtonRole.AcceptRole)
        msg.exec()

    def _on_scan_clicked(self) -> None:
        # show preface once
        try:
            if not self._maybe_show_preface():
                return
        except Exception:
            # if anything goes wrong, still proceed
            pass
        self.start_scan()

    def start_scan(self, show_msg=True) -> None:
        """
        Launch a background scan over all entries.  Resets UI state,
        kicks off a `ScanTask`, and wires up progress/finished/error.
        """
        self.show_msg = show_msg
        try:
            if self.progress is not None:
                self.progress.setValue(0)
        except Exception:
            pass
        try:
            if self.score_lbl is not None:
                self.score_lbl.setText(_tr("Security Score: …"))
        except Exception:
            pass
        try:
            if self.export_btn is not None:
                self.export_btn.setEnabled(False)
        except Exception:
            pass

        try:
            entries = list(self.get_entries() or [])
        except Exception:
            entries = []

        # If no entries → neutral state
        if not entries:
            try:
                if self.tbl is not None:
                    self.tbl.setRowCount(0)
                if self.tbl_ignored is not None:
                    self.tbl_ignored.setRowCount(0)
                self._set_summary(0, 0, 0, 0, 0, 0, 0, 0, 0, score=0)
                if self.score_lbl is not None:
                    self.score_lbl.setText(_tr("Security Score: – (no entries)"))
            except Exception:
                pass
            return


        # Match the same expiry-days setting used by the vault table.
        max_age_days = int(self.max_age_days)
        try:
            from auth.login.login_handler import get_user_setting, _canonical_username_ci
            raw_name = ""
            try:
                raw_name = (self._mw.currentUsername.text() or "").strip()
            except Exception:
                raw_name = ""
            username_ci = _canonical_username_ci(raw_name) or raw_name
            max_age_days = int(get_user_setting(username_ci, "password_expiry_days", max_age_days))
        except Exception:
            pass

        # Launch ScanTask
        task = ScanTask(
            entries=entries,
            id_fn=self._stable_id,
            get_strength=self.get_strength,
            breach_check=self.breach_check,
            max_age_days=max_age_days,
            weak_threshold=self.weak_threshold,
            enable_breach=bool(self.enable_breach_provider()),
            enable_card_expiry=bool(self.chk_cards.isChecked()) if self.chk_cards else True,
            enable_missing_2fa=bool(self.chk_2fa.isChecked()) if self.chk_2fa is not None else True,

            )
        task.s.progress.connect(self._set_progress)
        task.s.finished.connect(self._on_finished)
        task.s.error.connect(self._on_error)
        # keep a reference to the task to prevent GC until it finishes
        self._current_task = task
        self.threadpool.start(task)


    def clear_state(self) -> None:
        """Clear Watchtower UI + cached state when the user logs out or switches account."""
        try:
            self._last_issues = []
        except Exception:
            pass

        try:
            self._wt_active_rows = []
        except Exception:
            pass

        try:
            self._wt_ignored_rows = []
        except Exception:
            pass

        try:
            if hasattr(self, "_current_task"):
                del self._current_task
        except Exception:
            pass

        try:
            if self.progress is not None:
                self.progress.setValue(0)
        except Exception:
            pass

        try:
            self._set_summary(0, 0, 0, 0, 0, 0, 0, 0, 0, score=0)
        except Exception:
            pass

        try:
            if self.score_lbl is not None:
                self.score_lbl.setText(_tr("Security Score: –"))
        except Exception:
            pass

        for tbl in (getattr(self, "tbl", None), getattr(self, "tbl_ignored", None)):
            if tbl is None:
                continue
            try:
                tbl.blockSignals(True)
                tbl.clearContents()
                tbl.setRowCount(0)
            except Exception:
                pass
            finally:
                try:
                    tbl.blockSignals(False)
                except Exception:
                    pass

        try:
            if self.export_btn is not None:
                self.export_btn.setEnabled(False)
        except Exception:
            pass

    def _set_progress(self, value: int) -> None:
        try:
            if self.progress is not None:
                self.progress.setValue(int(value))
        except Exception:
            pass

    def _on_error(self, msg: str) -> None:
        log.error(f"[Watchtower] scan error: {msg}")
        try:
            QMessageBox.warning(
                self._mw,
                _tr("Watchtower"),
                _tr("Scan failed: {msg}").format(msg=msg),
            )
        except Exception:
            pass

    def _on_finished(self, issues: List[WTIssue]) -> None:
        # Ignore late scan results after logout / account switch
        try:
            raw_name = ""
            try:
                raw_name = (self._mw.currentUsername.text() or "").strip()
            except Exception:
                raw_name = ""
            if not raw_name:
                try:
                    del self._current_task
                except Exception:
                    pass
                return
        except Exception:
            try:
                del self._current_task
            except Exception:
                pass
            return

        # Save last issues and rebuild tables
        try:
            self._last_issues = list(issues or [])
        except Exception:
            self._last_issues = []
        self._rebuild_tables(self._last_issues)
        # Clear current task reference
        try:
            del self._current_task
        except Exception:
            pass

    # ------------------------
    # Table + summary rebuilding
    # ------------------------

    def _on_active_context_menu(self, pos):
        from qtpy.QtWidgets import QMenu
        if self.tbl is None:
            return
        row = self.tbl.rowAt(pos.y())
        if row < 0:
            return
        self.tbl.selectRow(row)
        it = None
        try:
            rows = getattr(self, "_wt_active_rows", [])
            if 0 <= row < len(rows):
                it = rows[row]
        except Exception:
            it = None
        if not it:
            return

        m = QMenu(self._mw)
        act_ignore = m.addAction(_tr("Ignore selected issue"))
        chosen = m.exec(self.tbl.viewport().mapToGlobal(pos))
        if chosen == act_ignore:
            self._wt_ignore_issue(it.entry_id, it.kind)

    def _on_ignored_context_menu(self, pos):
        from qtpy.QtWidgets import QMenu
        if self.tbl_ignored is None:
            return
        row = self.tbl_ignored.rowAt(pos.y())
        if row < 0:
            return
        self.tbl_ignored.selectRow(row)
        it = None
        try:
            rows = getattr(self, "_wt_ignored_rows", [])
            if 0 <= row < len(rows):
                it = rows[row]
        except Exception:
            it = None
        if not it:
            return

        m = QMenu(self._mw)
        act_unignore = m.addAction(_tr("Unignore selected issue"))
        chosen = m.exec(self.tbl_ignored.viewport().mapToGlobal(pos))
        if chosen == act_unignore:
            self._wt_unignore_issue(it.entry_id, it.kind)

    def _rebuild_tables(self, issues: List[WTIssue]) -> None:
        from qtpy.QtCore import Qt, QSignalBlocker, QTimer
        from qtpy.QtWidgets import QTableWidgetItem

        # ---------- helpers ----------
        rules = self._load_rules_dict()
        ignored = self._load_ignored_list()

        def rule_enabled(kind: str) -> bool:
            key = self._issue_rule_key(kind)
            if not key:
                return True
            return bool(rules.get(key, True))

        def _prep_table(tbl):
            if not tbl:
                return
            b = QSignalBlocker(tbl)
            tbl.setSortingEnabled(False)
            tbl.setUpdatesEnabled(False)
            tbl.clearContents()
            tbl.setRowCount(0)
            # ensure columns exist (Type, Title, Detail, Action)
            if tbl.columnCount() < 4:
                tbl.setColumnCount(4)

            try:
                tbl.setHorizontalHeaderLabels([_tr("Type"), _tr("Entry"), _tr("Detail"), _tr("Action")])
            except Exception:
                pass
            try:
                tbl.setUniformRowHeights(True)
            except Exception:
                pass
            # keep blockers alive until end of function
            return b

        bt = _prep_table(self.tbl)
        bi = _prep_table(self.tbl_ignored)

        # ---------- build active/ignored lists ----------
        active_list: List[WTIssue] = []
        ignored_list: List[WTIssue] = []

        for it in (issues or []):
            if not rule_enabled(it.kind):
                continue
            if self._is_issue_ignored(it, ignored):
                ignored_list.append(it)
            else:
                active_list.append(it)

        # Keep row->issue mapping for click handlers
        self._wt_active_rows = active_list
        self._wt_ignored_rows = ignored_list

        # ---------- scoring ----------
        score = 100
        score_weights = {
            "Known Breach": 15,
            "Reused Password": 10,
            "Weak Password": 8,
            "Old Password": 5,
            "Insecure URL (HTTP)": 2,
            "Missing Username": 1,
            "Missing URL": 1,
            "Missing 2FA": 10,
            "Account Missing 2FA": 15,
            "Card Expired": 4,
            "Card Expiring Soon": 2,
            "Expired Item": 12,
            "Password Expired": 12,
        }
        counts = {
            "Reused Password": 0,
            "Weak Password": 0,
            "Old Password": 0,
            "Known Breach": 0,
            "Insecure URL (HTTP)": 0,
            "Missing Username": 0,
            "Missing URL": 0,
            "Missing 2FA": 0,
            "Account Missing 2FA": 0,
            "Card Expired": 0,
            "Card Expiring Soon": 0,
            "Expired Item": 0,
            "Password Expired": 0,
        }

        for it in active_list:
            k = it.kind
            if k in counts:
                counts[k] = counts.get(k, 0) + 1
            score -= score_weights.get(k, 0)

        score = max(0, min(100, score))

        # update summary (keep your existing fields; these names match your original)
        try:
            self._set_summary(
                counts.get("Reused Password", 0),
                counts.get("Weak Password", 0),
                counts.get("Old Password", 0) + counts.get("Expired Item", 0) + counts.get("Password Expired", 0),
                counts.get("Known Breach", 0),
                counts.get("Insecure URL (HTTP)", 0),
                counts.get("Missing Username", 0),
                counts.get("Missing URL", 0),
                counts.get("Missing 2FA", 0),
                counts.get("Account Missing 2FA", 0),
                score=score,
            )
            if self.score_lbl is not None:
                self.score_lbl.setText(_tr(f"Security Score: {score}/100"))
        except Exception:
            pass

        last_counts = getattr(self._mw, "_last_watchtower_counts", {}) or {}

        if self.show_msg and counts != last_counts:  # warn user only if counts changed
            try:
                self._mw._last_watchtower_counts = counts.copy()  # Cache for reminder/watcher

                from features.systemtray.systemtry_ops import notify_update_watchtower

                mw = getattr(self, "_mw", None)
                if mw is not None:
                    notify_update_watchtower(
                        mw,
                        weak_pw=counts.get("Weak Password", 0),
                        reused_pw=counts.get("Reused Password", 0),
                        breach_pw=counts.get("Known Breach", 0), 
                        http_only_urls=counts.get("Insecure URL (HTTP)", 0),
                        missing_username=counts.get("Missing Username", 0),
                        missing_urls=counts.get("Missing URL", 0),
                        tfa_disabled=counts.get("Missing 2FA", 0) + counts.get("Account Missing 2FA", 0),
                        card_exp=counts.get("Card Expired", 0) + counts.get("Card Expiring Soon", 0),
                        item_exp=counts.get("Expired Item", 0) + counts.get("Password Expired", 0) + counts.get("Old Password", 0),
                    )
                else:
                    log.warning("[Watchtower] main window reference missing; tray notify skipped")
            except Exception as e:
                log.error(f"[Watchtower] tray notify failed: {e}")

        try:
            expired_rows = [it.title for it in active_list if it.kind == "Expired Item"]
            log.info("[WT-UI] active expired items count=%s", len(expired_rows))
        except Exception:
            pass


        # ---------- ensure click handlers connected once ----------
        def _disconnect(tbl):
            try:
                tbl.cellClicked.disconnect()
            except Exception:
                pass

        def _connect(tbl, handler):
            if not tbl:
                return
            _disconnect(tbl)
            tbl.cellClicked.connect(handler)

        def _on_active_click(row: int, col: int):
            # Only react to Action column (3)
            if col != 3:
                return
            if row < 0 or row >= len(getattr(self, "_wt_active_rows", [])):
                return
            it = self._wt_active_rows[row]

            # Decide action from cell text
            txt = (self.tbl.item(row, 3).text() if self.tbl and self.tbl.item(row, 3) else "").strip().lower()
            if "fix" in txt:
                # call same fix path as your button did
                self._wt_fix_issue(it.entry_id, it.kind)
            else:
                # default ignore
                self._wt_ignore_issue(it.entry_id, it.kind)

        def _on_ignored_click(row: int, col: int):
            if col != 3:
                return
            if row < 0 or row >= len(getattr(self, "_wt_ignored_rows", [])):
                return
            it = self._wt_ignored_rows[row]
            self._wt_unignore_issue(it.entry_id, it.kind)

        _connect(self.tbl, _on_active_click)
        _connect(self.tbl_ignored, _on_ignored_click)

        # ---------- fast + batched fill ----------
        def _fill(tbl, data: List[WTIssue], mode: str):
            if not tbl:
                return

            tbl.setRowCount(len(data))
            tbl.setUpdatesEnabled(True)   # IMPORTANT – enable updates BEFORE filling

            for r, it in enumerate(data):
                tbl.setItem(r, 0, QTableWidgetItem(_tr(it.kind)))
                tbl.setItem(r, 1, QTableWidgetItem(it.title))
                tbl.setItem(r, 2, QTableWidgetItem(it.detail))

                act = QTableWidgetItem(_tr("Unignore") if mode == "ignored" else _tr("Fix"))
                act.setTextAlignment(Qt.AlignCenter)
                act.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                tbl.setItem(r, 3, act)

        # turn updates back on AFTER batches finish
        if self.tbl:
            self.tbl.setUpdatesEnabled(False)
        if self.tbl_ignored:
            self.tbl_ignored.setUpdatesEnabled(False)

        _fill(self.tbl, active_list, mode="active")
        _fill(self.tbl_ignored, ignored_list, mode="ignored")

    def _wt_fix_issue(self, entry_id: str, kind: str) -> None:
        # Fix uses your existing handler (on_fix)
        try:
            if callable(getattr(self, "on_fix", None)):
                self.on_fix(str(entry_id))
        except Exception as e:
            log.error(f"[Watchtower] fix failed: {e}")

    def _wt_get_selected_issue(self):
        """
        Returns (issue, which_table) where which_table is "active" or "ignored".
        Does NOT rely on a tab widget name. It checks which table has a valid selection.
        """
        # 1) Prefer ignored table if it has a real selection
        try:
            if self.tbl_ignored is not None:
                r = self.tbl_ignored.currentRow()
                rows = getattr(self, "_wt_ignored_rows", []) or []
                if 0 <= r < len(rows):
                    return rows[r], "ignored"
        except Exception:
            pass

        # 2) Otherwise fall back to active table
        try:
            if self.tbl is not None:
                r = self.tbl.currentRow()
                rows = getattr(self, "_wt_active_rows", []) or []
                if 0 <= r < len(rows):
                    return rows[r], "active"
        except Exception:
            pass

        return None, None

    def on_ignore_selected(self):
        it, which = self._wt_get_selected_issue()
        if not it:
            return

        # If user is on ignored tab, ignore doesn't make sense
        if which == "ignored":
            return

        self._wt_ignore_issue(it.entry_id, it.kind)

        # refresh UI using last scan results (so the row moves immediately)
        try:
            self._rebuild_tables(getattr(self, "_last_issues", []) or [])
        except Exception:
            pass

    def _wt_ignore_issue(self, entry_id: str, kind: str) -> None:
        # Your existing ignore implementation expects (kind, entry_id)
        try:
            self._ignore_issue(str(kind), str(entry_id))
        except Exception as e:
            log.error(f"[Watchtower] ignore failed: {e}")

    def _wt_unignore_issue(self, entry_id: str, kind: str) -> None:
        # Your existing unignore implementation expects (kind, entry_id)
        try:
            self._unignore_issue(str(kind), str(entry_id))
        except Exception as e:
            log.error(f"[Watchtower] unignore failed: {e}")

    # ------------------------
    # Fix / ignore handlers
    # ------------------------

    def _fill(tbl, data: List[WTIssue], mode: str):
        if not tbl:
            return

        tbl.setRowCount(len(data))
        tbl.setUpdatesEnabled(True)   # IMPORTANT – enable updates BEFORE filling

        for r, it in enumerate(data):
            tbl.setItem(r, 0, QTableWidgetItem(_tr(it.kind)))
            tbl.setItem(r, 1, QTableWidgetItem(it.title))
            tbl.setItem(r, 2, QTableWidgetItem(it.detail))

            act = QTableWidgetItem(_tr("Unignore") if mode == "ignored" else _tr("Fix… / Ignore"))
            act.setTextAlignment(Qt.AlignCenter)
            act.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            tbl.setItem(r, 3, act)

    def _fix_from_button(self) -> None:
        try:
            btn = self.sender()
            eid = str(btn.property("entry_id"))
            if eid:
                self._fix(eid)
        except Exception as e:
            log.error(f"[Watchtower] fix button failed: {e}")

    def _ignore_issue(self, kind: str, entry_id: str) -> None:
        try:
            ignored = self._load_ignored_list()
            # ensure it's a list of dicts
            if not isinstance(ignored, list):
                ignored = []
            # only add if not present
            found = False
            for x in ignored:
                try:
                    if str(x.get("entry_id")) == str(entry_id) and str(x.get("issue")) == str(kind):
                        found = True
                        break
                except Exception:
                    pass
            if not found:
                ignored.append({"entry_id": entry_id, "issue": kind})
                self._save_ignored_list(ignored)
        except Exception:
            pass
        # After ignoring, rescan or rebuild tables
        try:
            if self._last_issues:
                self._rebuild_tables(self._last_issues)
            else:
                self.start_scan()
        except Exception:
            pass

    def _unignore_issue(self, kind: str, entry_id: str) -> None:
        try:
            ignored = self._load_ignored_list()
            if not isinstance(ignored, list):
                ignored = []
            new_list = [x for x in ignored if not (
                str(x.get("entry_id")) == str(entry_id) and str(x.get("issue")) == str(kind)
            )]
            self._save_ignored_list(new_list)
        except Exception:
            pass
        # After unignoring, rescan or rebuild tables
        try:
            if self._last_issues:
                self._rebuild_tables(self._last_issues)
            else:
                self.start_scan()
        except Exception:
            pass

    def _ignore_from_button(self) -> None:
        try:
            btn = self.sender()
            eid = str(btn.property("entry_id"))
            kind = str(btn.property("kind"))
            if eid and kind:
                self._ignore_issue(kind, eid)
        except Exception as e:
            log.error(f"[Watchtower] ignore button failed: {e}")

    def _unignore_from_button(self) -> None:
        try:
            btn = self.sender()
            eid = str(btn.property("entry_id"))
            kind = str(btn.property("kind"))
            if eid and kind:
                self._unignore_issue(kind, eid)
        except Exception as e:
            log.error(f"[Watchtower] unignore button failed: {e}")

    # ------------------------
    # Summary + ID helpers
    # ------------------------

    def _set_summary(
        self,
        reused: int,
        weak: int,
        old: int,
        breach: int,
        http: int,
        miss_user: int,
        miss_url: int,
        twofa: int,
        cards: int,
        *,
        score: int,
    ) -> None:
        """Update the summary area.

        Some UI versions use dedicated labels for counts, others reuse the heading labels.
        To keep the UI readable, we always render 'Heading: <count>'.
        """

        def _set(lbl, heading: str, value: int) -> None:
            if lbl is None:
                return
            try:
                # If Designer already put a heading on this label, preserve it.
                base = (getattr(self, "_summary_base", {}).get(id(lbl)) or "").strip()
                if base and not base.isdigit():
                    lbl.setText(f"{base}: {value}")
                else:
                    lbl.setText(f"{heading}: {value}")
            except Exception:
                pass

        _set(self.lbl_reused, _tr("Reused passwords"), reused)
        _set(self.lbl_weak, _tr("Weak passwords"), weak)
        _set(self.lbl_old, _tr("Old passwords (>180d)"), old)
        _set(self.lbl_breach, _tr("Known breaches"), breach)
        _set(self.lbl_http, _tr("HTTP-only URLs"), http)
        _set(self.lbl_missing_user, _tr("Missing usernames"), miss_user)
        _set(self.lbl_missing_url, _tr("Missing URLs"), miss_url)
        _set(self.lbl_2fa, _tr("2FA warnings"), twofa)
        _set(self.lbl_cards, _tr("Card expiry issues"), cards)

        try:
            if self.score_lbl is not None:
                self.score_lbl.setText(_tr("Security Score: {score}/100").format(score=score))
        except Exception:
            pass

    def _stable_id(self, e: dict, idx: Optional[int] = None) -> str:
        """
        Return a stable identifier for a scan finding.

        For Watchtower, we must be able to re-locate the exact entry later even
        when titles are blank ("(untitled)") and even when the UI table masks
        passwords. The most reliable reference is the index of the entry in the
        decrypted vault list: "idx:<n>".

        If the entry already has a persisted id/_id/row_id, we use that.
        Otherwise we use idx:<n>.
        """
        rid = e.get("id") or e.get("_id") or e.get("row_id")
        if isinstance(rid, int):
            rid = str(rid)
        if isinstance(rid, str) and rid.strip() and not (rid.isdigit() and int(rid) < 100000):
            return rid

        # Prefer explicit idx passed from ScanTask
        if idx is not None:
            return f"idx:{int(idx)}"

        # Or an embedded watchtower index
        try:
            if "__wt_idx" in e:
                return f"idx:{int(e['__wt_idx'])}"
        except Exception:
            pass

        return "idx:0"


def build_watchtower_panel(w: QWidget) -> WatchtowerPanel:
    """
    Factory that constructs and configures a WatchtowerPanel for the given
    main window.  It injects the appropriate providers (entry iteration,
    strength function, breach checking, settings and fix handlers).  This
    function should be called from the main window's `_init_watchtower`.
    """
    from auth.pw.password_utils import estimate_strength_score as _est
    from . import watchtower_settings as wt_settings

    def _strength100(pw: str) -> int:
        try:
            return max(0, min(100, int(_est(pw))))
        except Exception:
            return 0

    #handler that binds the main window into the watchtower_actions
    def _fix_handler(entry_id: str) -> None:
        try:
            _watchtower_fix_entry(w, entry_id)
        except Exception:
            pass

    # Create panel
    def _get_entries() -> Iterable[dict]:
        try:
            return list(_iter_vault_entries(w))
        except Exception:
            return []

    def _breach_count(pw: str) -> int:
        try:
            return _hibp_count(w, pw)
        except Exception:
            return 0

    wt = WatchtowerPanel(
        mw=w,
        get_entries=_get_entries,
        get_strength=_strength100,
        breach_check=_breach_count,
        max_age_days=180,
        weak_threshold=60,
        enable_breach_provider=lambda: bool(getattr(w, "enable_breach_checker", False)),
        on_fix=_fix_handler,
        parent=w,
    )

    # Wire per‑user settings providers
    try:
        wt.set_settings_providers(
            get_rules=lambda: wt_settings.wt_get_rules(w),
            set_rules=lambda rules: wt_settings.wt_set_rules(w, rules),
            get_ignored=lambda: wt_settings.wt_get_ignored(w),
            set_ignored=lambda lst: wt_settings.wt_set_ignored(w, lst),
            get_global_flags=lambda: wt_settings.wt_get_global_flags(w),
        )
    except Exception:
        pass
    return wt


def _hibp_count(w, password: str) -> int:
    try:
        if not bool(getattr(w, "enable_breach_checker", False)):
            return 0
        try:
            from features.breach_check.breach_checker import check_password_breach
        except Exception:
            # fallback if it's not under auth/
            from features.passkeys.passkeys_panel import check_password_breach

        c = int(check_password_breach(password))
        return 0 if c < 0 else c   # -1 means error in the checker
    except Exception as e:
        log.error(f"[WT] breach skip: {e}")
        return 0



def _iter_vault_entries(w):
    """
    Yield entries for Watchtower from the *decrypted vault on disk only*.

    This must NOT read from the visible vault table because the table often
    masks/omits secrets (passwords), which causes false "reused password"
    results and makes Fix/Ignore unable to re-locate entries.

    Each yielded entry is a normalized dict with keys:
      id, title, username, password, url, updated_at, kind, __wt_idx
    """
    def _norm(s): return (s or "").strip().lower()

    def _classify_kind(cat: str) -> str:
        c = _norm(cat)
        if "credit" in c and "card" in c: return "credit_card"
        if "bank" in c: return "bank_account"
        if "authenticator" in c: return "otp"
        if "note" in c or "personal" in c: return "note"
        return "login"

    username = ""
    key = None
    try:
        username = w.currentUsername.text()
    except Exception:
        username = ""
    try:
        key = getattr(w, "core_session_handle", None)
    except Exception:
        key = None

    try:
        all_rows = load_vault(username, key) or []
    except Exception:
        all_rows = []

    for i, r in enumerate(all_rows):
        try:
           
            title = r.get("title") or r.get("site") or r.get("name") or r.get("Title") or r.get("Website") or ""
            cat   = r.get("category") or r.get("type") or r.get("Category") or ""
            kind = _classify_kind(str(cat))

            # Username/URL only make sense for login entries
            if kind == "credit_card":
                user = ""
                url = ""
            else:
                user  = r.get("username") or r.get("user") or r.get("email") or r.get("Username") or r.get("UserName") or "" 
                url   = r.get("url") or r.get("origin") or r.get("website") or r.get("URL") or r.get("Website") or ""

            pw = r.get("password") or r.get("pwd") or r.get("pass") or r.get("secret") or r.get("Password") or ""
            upd = (r.get("pw_changed_at") or r.get("updated_at") or r.get("last_changed") or r.get("Date") or r.get("created_at") or "")
            password_expired = (
                r.get("Password Expired") or r.get("password_expired") or r.get("password expired") or False
            )

            # Card expiry (pass through so watchtower_scan can evaluate it)
            expiry = (
                r.get("Expiry Date") or r.get("Expiry") or r.get("expiry") or r.get("expiry_date")
                or r.get("Valid Thru") or r.get("Valid Through") or r.get("valid_thru")
                or r.get("Exp") or r.get("exp") or "")

            rid = r.get("id") or r.get("_id") or r.get("row_id")
            if isinstance(rid, int):
                rid = str(rid)
            if not (isinstance(rid, str) and rid.strip()):
                rid = f"idx:{i}"

            yield {
                "id": str(rid),
                "title": title or "(untitled)",
                "username": user,
                "password": pw,
                "url": url,
                "updated_at": upd,
                "kind": _classify_kind(str(cat)),
                "expiry": expiry,
                "password_expired": password_expired,
                "__wt_idx": i,
            }
        except Exception:
            continue


def _watchtower_generate_new_password_for(w, entry_id: str) -> None:
    """
    Generate a strong new password for the given vault entry and update it.

    A confirmation dialog is presented to the user.  If the operation
succeeds, an informational message is shown.  Otherwise, an error
    message is displayed.  The `w` argument should be the main window
    instance with access to the current username and vault key, and with
    a `tr()` method for translations.
    """
    # Locate the entry index in the vault
    try:
        idx = _find_entry_index_by_id(w, entry_id)
    except Exception:
        idx = -1
    if idx < 0:
        try:
            QMessageBox.warning(
                w,
                w.tr("Watchtower"),
                w.tr("Couldn't locate that entry in the vault."),
            )
        except Exception:
            pass
        return

    # Load the existing entry for display purposes
    try:
        entries = load_vault(w.currentUsername.text(), w.core_session_handle)
        entry = dict(entries[idx]) if 0 <= idx < len(entries) else {}
    except Exception:
        entry = {}

    # Ask the user to confirm the password replacement
    try:
        name = entry.get("title") or entry.get("site") or entry.get("name") or "(untitled)"
        resp = QMessageBox.question(
            w,
            w.tr("Generate New Password"),
            w.tr(
                'Generate a new strong password for "{name}" and update this entry?\n\n'
                "You'll need to update it on the website/app next."
            ).format(name=name),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if resp != QMessageBox.StandardButton.Yes:
            return
    except Exception:
        pass

    # Generate a new strong password; fall back to a random string on failure
    new_pw: str | None = None
    if callable(generate_strong_password):
        try:
            new_pw = generate_strong_password(length=20)
        except Exception:
            new_pw = None
    if not new_pw:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,./?"
        new_pw = "".join(secrets.choice(alphabet) for _ in range(24))

    # Update the entry and persist with history (max 5 previous passwords)
    entry["password"] = new_pw
    ok = _persist_entry_with_history(
        w,
        w.currentUsername.text(),
        w.core_session_handle,
        idx,
        entry,
        max_hist=5,
    )
    try:
        if ok:
            QMessageBox.information(
                w,
                w.tr("Password Updated"),
                w.tr(
                    "New password generated and saved to the vault.\n"
                    "Remember to change it on the actual site/app."
                ),
            )
        else:
            QMessageBox.critical(
                w,
                w.tr("Update Failed"),
                w.tr("Could not save the updated entry."),
            )
    except Exception:
        pass


def _watchtower_fix_entry(w, entry_id: str) -> None:
    """
    Handle a Watchtower 'Fix' action.

    If `entry_id` equals the special ``"__GLOBAL_2FA__"`` token then the user
    is directed to enable two‑factor authentication in the settings.  For
    regular entries the function attempts to switch to the correct category,
    locate the corresponding row in the vault table and open the entry
    editor.  Should the entry be missing or the editor fail to open, the
    user is notified accordingly.
    """
    # Special-case: prompt to enable 2FA and switch to the Settings/Security tab
    if str(entry_id) == "__GLOBAL_2FA__":
        try:
            tabs = getattr(w, "mainTabs", None)
            if tabs is not None:
                target_idx = -1
                for i in range(tabs.count()):
                    txt = (tabs.tabText(i) or "").strip().lower()
                    if "setting" in txt or "security" in txt:
                        target_idx = i
                        break
                if target_idx >= 0:
                    tabs.setCurrentIndex(target_idx)
            QMessageBox.information(
                w,
                w.tr("Enable Two-Factor Authentication"),
                w.tr(
                    "To fix this warning, enable 2FA (TOTP) for your account in the "
                    "Settings / Security section.\n\n"
                    "Once enabled, run Watchtower again and this warning will disappear."
                ),
            )
        except Exception:
            pass
        return

    # Locate the entry index using fingerprint or ID
    try:
        idx = _find_entry_index_by_id(w, entry_id)
    except Exception:
        idx = -1
    if idx < 0:
        try:
            QMessageBox.warning(
                w,
                w.tr("Watchtower"),
                w.tr("Couldn't locate that entry in the vault."),
            )
        except Exception:
            pass
        return

    # Load entries to retrieve the category for switching
    try:
        try:
            all_entries = load_vault(w.currentUsername.text(), w.core_session_handle) or []
        except TypeError:
            all_entries = load_vault(w.currentUsername.text()) or []
    except Exception:
        all_entries = []
    # If the direct-id lookup failed, try matching by stable content id.
    if idx < 0 and all_entries:
        try:
            for j, e in enumerate(all_entries):
                try:
                    if stable_id_for_entry(e) == str(entry_id):
                        idx = j
                        break
                except Exception:
                    continue
        except Exception:
            pass
    if not (0 <= idx < len(all_entries)):
        try:
            QMessageBox.warning(
                w,
                w.tr("Watchtower"),
                w.tr("The vault entry for this issue could not be found."),
            )
        except Exception:
            pass
        return

    entry = dict(all_entries[idx])
    category = (entry.get("category") or "Passwords").strip()

    # Attempt to switch the UI to the correct category (if available)
    cat_sel = getattr(w, "categorySelector_2", None)
    if cat_sel is not None:
        try:
            target_index = -1
            want = category.lower()
            for i in range(cat_sel.count()):
                try:
                    txt = cat_sel.itemText(i)
                except Exception:
                    txt = ""
                if (txt or "").strip().lower() == want:
                    target_index = i
                    break
            if target_index >= 0 and cat_sel.currentIndex() != target_index:
                cat_sel.setCurrentIndex(target_index)
                # Force table reload in case the signal isn't wired
                if hasattr(w, "load_vault_table"):
                    w.load_vault_table()
        except Exception:
            pass
    else:
        try:
            if hasattr(w, "load_vault_table"):
                w.load_vault_table()
        except Exception:
            pass

    # Map the global index back to a row in the visible table
    tbl = getattr(w, "vaultTable", None)
    idx_map = getattr(w, "current_entries_indices", None)
    row = -1
    if isinstance(idx_map, list):
        try:
            for r, gi in enumerate(idx_map):
                if gi == idx:
                    row = r
                    break
        except Exception:
            row = -1

    # Open the entry in the editor if we found a row
    if tbl is not None and 0 <= row < getattr(tbl, "rowCount", lambda: 0)():
        try:
            tbl.selectRow(row)
        except Exception:
            pass
        try:
            w.edit_selected_vault_entry(row, 0)
            return
        except Exception:
            pass

    # Final fallback: could not open automatically
    try:
        QMessageBox.information(
            w,
            w.tr("Watchtower"),
            w.tr(
                "Could not open this entry automatically.\n"
                "Use the search box or filters to locate it manually."
            ),
        )
    except Exception:
        pass


def _entry_kind(w, e: dict) -> str:
    """
    Rough classifier: 'login', 'credit_card', or 'other'.
    Uses category and common field names.
    """
    cat = (e.get("category") or e.get("Category") or "").strip().lower()
    if "credit" in cat and "card" in cat:
        return "credit_card"

    keys = {k.lower() for k in e.keys()}
    # Heuristics: typical card fields present?
    cardish = {"card", "card number", "card_number", "pan", "cvv", "cvc", "expiry",
               "exp", "exp_month", "exp_year", "valid thru", "valid_thru"}
    if keys & cardish:
        return "credit_card"

    # If it has a password/secret it's likely a login
    if keys & {"password", "pwd", "pass", "secret"}:
        return "login"

    return "other"


def _luhn_ok(w, pan: str) -> bool:
    s = "".join(ch for ch in str(pan or "") if ch.isdigit())
    if len(s) < 12:  # too short to be a card
        return False
    tot = 0
    dbl = False
    for ch in reversed(s):
        d = ord(ch) - 48
        if dbl:
            d = d * 2
            if d > 9: d -= 9
        tot += d
        dbl = not dbl
    return (tot % 10) == 0


def _card_brand_last4(w, pan: str) -> tuple[str, str]:
    s = "".join(ch for ch in str(pan or "") if ch.isdigit())
    last4 = s[-4:] if len(s) >= 4 else ""
    brand = "Card"
    if s.startswith("4"):              brand = "Visa"
    elif any(s.startswith(p) for p in ("51","52","53","54","55")) or (2221 <= int(s[:4] or 0) <= 2720):
        brand = "Mastercard"
    elif s.startswith(("34", "37")):   brand = "Amex"
    elif s.startswith("6011") or s.startswith("65"): brand = "Discover"
    elif s.startswith(("35",)):        brand = "JCB"
    return brand, last4


def _safe_url_for_entry(w, e: dict) -> str:
    """
    Provide a non-web placeholder URL for entries that shouldn't require a web URL.
    Avoids 'Missing URL' warnings for cards/bank/etc.
    """
    kind = w._entry_kind(e)
    url  = (e.get("url") or e.get("origin") or "").strip()
    if url:
        return url
    if kind == "credit_card":
        # Try to derive a nice label
        pan = e.get("card_number") or e.get("Card Number") or e.get("card") or ""
        brand, last4 = w._card_brand_last4(pan)
        return f"card://{brand.lower()}"  # placeholder scheme
    return ""  # other kinds: leave as-is


def _looks_masked(w, pw: str) -> bool:
    if not isinstance(pw, str) or len(pw) < 6:
        return False
    bullets = set("●•▪▫◦◉○⦁*· ")  # common mask glyphs + space
    return all(ch in bullets for ch in pw)


def _watchtower_fix_entry_old(w, entry_id: str):
    """
    Watchtower 'Fix' handler:
        • Special-case global 2FA warning.
        • Otherwise:
            - Ask if user wants a new generated password.
            - Or open the correct entry in the editor.
    """

    # --- 1) Global 2FA warning: jump to Settings / Security tab -------------
    if str(entry_id) == "__GLOBAL_2FA__":
        try:
            tabs = getattr(w, "mainTabs", None)
            if tabs is not None:
                target_idx = -1
                for i in range(tabs.count()):
                    txt = (tabs.tabText(i) or "").strip().lower()
                    if "setting" in txt or "security" in txt:
                        target_idx = i
                        break
                if target_idx >= 0:
                    tabs.setCurrentIndex(target_idx)
            QMessageBox.information(
                w,
                w.tr("Enable Two-Factor Authentication"),
                w.tr("To fix this warning, enable 2FA (TOTP) for your account in the "
                "Settings / Security section.\n\n"
                "Once enabled, run Watchtower again and this warning will disappear."),
            )
        except Exception:
            pass
        return

    # --- 3) Locate the entry index in the vault file ------------------------
    try:
        idx = _find_entry_index_by_id(w,  entry_id)
    except Exception:
        idx = -1

    if idx < 0:
        try:
            QMessageBox.warning(
                w,
                w.tr("Watchtower"),
                w.tr("Couldn't locate that entry in the vault."),)

        except Exception:
            pass
        return

    # --- 4) Load entries and get this entry's category ----------------------
    try:
        try:
            all_entries = load_vault(w.currentUsername.text(), w.core_session_handle) or []
        except TypeError:
            # Fallback signature if core_session_handle isn't expected
            all_entries = load_vault(w.currentUsername.text()) or []
    except Exception:
        all_entries = []

    if not (0 <= idx < len(all_entries)):
        try:
            QMessageBox.warning(
                w,
                w.tr("Watchtower"),
                w.tr("The vault entry for this issue could not be found."),
            )
        except Exception:
            pass
        return

    entry = dict(all_entries[idx])
    category = (entry.get("category") or "Passwords").strip()

    # --- 5) Switch the UI to the correct category (if possible) ------------
    cat_sel = getattr(w, "categorySelector_2", None)
    if cat_sel is not None:
        try:
            target_index = -1
            want = category.lower()
            for i in range(cat_sel.count()):
                if cat_sel.itemText(i).strip().lower() == want:
                    target_index = i
                    break
            if target_index >= 0 and cat_sel.currentIndex() != target_index:
                cat_sel.setCurrentIndex(target_index)
                # In case the signal isn't wired or has been changed, force a reload
                if hasattr(w, "load_vault_table"):
                    w.load_vault_table()
        except Exception:
            # Best effort – worst case, we stay on current category.
            pass
    else:
        # No category selector; just make sure the table is fresh.
        try:
            if hasattr(w, "load_vault_table"):
                w.load_vault_table()
        except Exception:
            pass

    # --- 6) Map the global index back to a row in the current table --------
    tbl = getattr(w, "vaultTable", None)
    idx_map = getattr(w, "current_entries_indices", None)
    row = -1

    if isinstance(idx_map, list):
        try:
            for r, gi in enumerate(idx_map):
                if gi == idx:
                    row = r
                    break
        except Exception:
            row = -1

    # --- 7) Open the editor on that row ------------------------------------
    if tbl is not None and 0 <= row < tbl.rowCount():
        try:
            tbl.selectRow(row)
        except Exception:
            pass
        try:
            # Your existing editor uses the row index + current_entries_indices
            w.edit_selected_vault_entry(row, 0)
            return
        except Exception:
            pass

    # --- 8) Fallback: couldn't locate / open -------------------------------
    try:
        QMessageBox.information(
            w,
            w.tr("Watchtower"),
            w.tr("Could not open this entry automatically.\n"
            "Use the search box or filters to locate it manually."),
        )
    except Exception:
        pass


