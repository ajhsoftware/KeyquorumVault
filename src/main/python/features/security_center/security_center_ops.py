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


# This module contains methods extracted from main.py to reduce file size.
# We intentionally "inherit" main module globals so the moved code can run unchanged.
import sys as _sys
from app.app_window import _load_vault_salt_for
from security.baseline_signer import _baseline_tracked_files, verify_baseline, update_baseline
from auth.login.login_handler import get_user_setting, set_user_setting
import time as _t

_MAIN = (
    _sys.modules.get("__main__")
    or _sys.modules.get("main")
    or _sys.modules.get("app.app_window")
    or _sys.modules.get("app_window")
)
if _MAIN is not None:
    globals().update(_MAIN.__dict__)

# Safety net: ensure Qt symbols exist even when __main__ differs (e.g., frozen builds)
try:
    from app.qt_imports import *  # noqa: F401,F403
except Exception:
    pass
def integrity_check_and_prompt(self, username: str) -> bool:
    """
        Run a full per-user baseline verification and, if mismatched, show a dialog
        with details and options (Quit / Update Baseline / Proceed).

        Args:
            username: logical user id.
            allow_update: if False, do not offer 'Update Baseline' in the dialog.

        Returns:
            True  -> continue running the app
            False -> caller should quit
        """
    username = (username or "").strip()
    if not username:
        # Nothing to check -> don't block
        return True

    log.debug(f"integrity_check_and_prompt for user  {username}")
    self.reset_logout_timer()
    self.set_status_txt(self.tr("Checking integrity…"))

    # ------------------------------------------------------------------
    # 1) Assemble inputs: salt + tracked file set
    # ------------------------------------------------------------------
    try:
        
        salt_for_baseline = _load_vault_salt_for(username)
        files = _baseline_tracked_files(username)
        log.debug(f"files to check basline = {files}")
        files = [str(p) for p in files]
        log.debug(f"files afterpass to check basline = {files}")
    except Exception as e:
        # If we can't assemble inputs, log but DO NOT brick the session
        try:
            msg = self.tr("{ok} integrity_setup_error {err}").format(
                ok=kql.i("err"), err=e
            )
            from security.secure_audit import log_event_encrypted
            log_event_encrypted(username, self.tr("integrity_setup_error"), msg)
        except Exception:
            pass
        log.error(f"[INTEGRITY] setup error: {e}")
        return True

    # ------------------------------------------------------------------
    # 2) Run verification
    # ------------------------------------------------------------------
    try:
        changed, missing, new_, mac_ok = verify_baseline(
            username, salt_for_baseline, files
        )
        log.info(f"[integrity_check_and_prompt]: changed: {changed}, missing: {missing}, new_: {new_}, mac_ok: {mac_ok}")

    except Exception as e:
        try:
            msg = self.tr("{ok} integrity_verify_error {err}").format(
                ok=kql.i("err"), err=e
            )
            log_event_encrypted(username, "integrity_verify_error", msg)
        except Exception:
            pass
        log.error(f"[INTEGRITY] verify error: {e}")
        return True  # do not block session on errors

    ok_base = mac_ok and not changed and not missing and not new_
    why_base = "OK" if ok_base else " ".join(
        filter(
            None,
            [
                (self.tr("bad-signature") + f":{len(changed)}") if not mac_ok else "",
                (self.tr("changed") + f":{len(changed)}") if changed else "",
                (self.tr("missing") + f":{len(missing)}") if missing else "",
                (self.tr("new") + f":{len(new_)}") if new_ else "",
            ],
        )
    )
    log.info(f"[integrity_check_and_prompt] is base ok ? {ok_base}")
    if ok_base:
        log.debug("[INTEGRITY] baseline OK")
        self.set_status_txt(self.tr("Baseline OK"))
        return True

    # ------------------------------------------------------------------
    # 3) Build details text for "Show Details"
    # ------------------------------------------------------------------
    details_text = (
        self._format_list("CHANGED", changed)
        + self._format_list("MISSING", missing)
        + self._format_list("NEW", new_)
    )

    # ------------------------------------------------------------------
    # 4) Interactive warning dialog with Copy / Quit / Update / Proceed
    # ------------------------------------------------------------------
    while True:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle(self.tr("Integrity Warning"))
        box.setTextFormat(Qt.RichText)

        msg = (
            "<b>" + self.tr("Integrity check failed") + "</b><br>"
            + self.tr("Signature")
            + ": {ok}<br>"
            + self.tr("Changed")
            + f": {len(changed)} · "
            + self.tr("Missing")
            + f": {len(missing)} · "
            + self.tr("New")
            + f": {len(new_)}<br><br>"
            + self.tr("Click ")
            + "<i>"
            + self.tr("Show Details")
            + "</i> "
            + self.tr("to view the affected files")
            + ".<br><br>"
            + self.tr(
                "This can be normal after an update, restore, new user, settings change, or vault update, "
            )
            + self.tr("but it may also indicate external modification.")
            + "<br><br>"
            + "<b>"
            + self.tr("What would you like to do?")
            + "</b><br>"
            + "• <b>"
            + self.tr("Quit")
            + "</b> — "
            + self.tr("close the app and investigate.")
            + "<br>"
            + "• <b>"
            + self.tr("Update Baseline")
            + "</b> — "
            + self.tr("trust the current state ")
            + self.tr("(only if you know these changes are legitimate).")
            + "<br>"
            + "• <b>"
            + self.tr("Proceed (Higher Risk)")
            + "</b> — "
            + self.tr("continue this session with risk or known modification.")
        ).format(ok=self.tr("OK") if mac_ok else "<b>" + self.tr("BAD") + "</b>")

        box.setText(msg)
        box.setDetailedText(details_text)

        btn_copy = box.addButton(self.tr("Copy details"), QMessageBox.ActionRole)
        btn_quit = box.addButton(self.tr("Quit"), QMessageBox.RejectRole)
        btn_update = box.addButton(self.tr("Update Baseline"), QMessageBox.ActionRole)
        btn_go = box.addButton(
            self.tr("Proceed (Higher Risk)"), QMessageBox.AcceptRole
        )


        if hasattr(box, "exec_"):
            box.exec_()
        else:
            box.exec()
        clicked = box.clickedButton()

        # log once per loop iteration
        try:
            log_msg = self.tr("❌ detected: why:") + f" {why_base}"
            log_event_encrypted(username, self.tr("integrity_warning"), log_msg)
        except Exception:
            pass

        # --- Actions ---------------------------------------------------
        if clicked is btn_copy:
            try:
                QApplication.clipboard().setText(details_text)
            except Exception:
                pass
            # show the same dialog again
            continue

        if clicked is btn_quit:
            return False

        if clicked is btn_update:
            # Use the shared helper so Settings + login use the same logic
            ok = update_baseline(username=username, verify_after=True, who="Interactive warning")
            if ok:
                QMessageBox.information(
                    self,
                    self.tr("Baseline Updated"),
                    self.tr("Integrity baseline updated for this user."),
                )
                try:
                    log_event_encrypted(
                        username, self.tr("integrity_update"), self.tr("baseline updated")
                    )
                except Exception:
                    pass
                self.set_status_txt(self.tr("Baseline updated"))
                return True
            else:
                # update_baseline already logged the reason
                try:
                    self.safe_messagebox_warning(
                        self,
                        self.tr("Baseline Update Failed"),
                        self.tr("Could not update integrity baseline. See log for details."),
                    )
                except Exception:
                    QMessageBox.warning(
                        self,
                        self.tr("Baseline Update Failed"),
                        self.tr("Could not update integrity baseline. See log for details."),
                    )
                # Re-show the same dialog so the user can Quit/Proceed instead
                continue

        if clicked is btn_go:
            return True

# =============================================================================
# --- preflight---

# --- add to serecty preflight check list


def enable_breach_checker_change(self, checked) -> None:
    self.set_status_txt(self.tr("Saving breach checker") + f" {checked}")
    """
    Handle the 'Password Breach Checker' toggle.
    - On first enable: show one-time consent modal (k-anonymity explanation).
    - Persist setting and update baseline.
    """
    log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} Breach Checker Change Called {checked}")
    self.reset_logout_timer()

    # Resolve user
    try:
        username = (self.currentUsername.text() or "").strip()
    except Exception:
        username = None

    if not username:
        log.debug(f"{kql.i('tool')} [WARN] {kql.i('warn')} Cannot update breach checker setting — user not found")
        # Best-effort: revert UI toggle if this came from a QCheckBox
        src = self.sender()
        try:
            if isinstance(src, QCheckBox) and bool(checked):
                src.blockSignals(True)
                src.setChecked(False)
                src.blockSignals(False)
        except Exception:
            pass
        return

    # Helper: read prior consent timestamp (if your project has get_user_setting; else treat as None)
    try:
        prior_ack_ts = get_user_setting(username, "hibp_ack_ts") or 0
    except Exception:
        prior_ack_ts = 0  # fallback if getter not available

    # If enabling and no prior consent, show the one-time consent
    if bool(checked) and not prior_ack_ts:
        if not self._show_hibp_consent_modal():
            # User cancelled — revert the UI toggle and do not persist
            src = self.sender()
            try:
                if isinstance(src, QCheckBox):
                    src.blockSignals(True)
                    src.setChecked(False)
                    src.blockSignals(False)
            except Exception:
                pass
            log.debug(f"{kql.i('tool')} [INFO] {kql.i('warn')} Breach checker enable cancelled by user")
            return
        # Persist the consent timestamp so we don’t show again
        try:
            set_user_setting(username, "hibp_ack_ts", int(_t.time()))
        except Exception as e:
            log.debug(f"{kql.i('tool')} [WARN] {kql.i('warn')} Failed to persist hibp_ack_ts: {e}")

    # Persist the enabled/disabled state
    try:
        set_user_setting(username, "enable_breach_checker", bool(checked))
        self.enable_breach_checker = bool(checked)           
        update_baseline(username=username, verify_after=False, who=self.tr("Breach Check Settings Changed"))
        log.debug(f"{kql.i('tool')} [TOOLS] {kql.i('ok')} Breach Checker setting persisted; baseline updated")
    except Exception as e:
        log.debug(f"{kql.i('tool')} [ERROR] {kql.i('err')} Failed to set breach checker enabled: {e}")
        # Best-effort: revert UI toggle to the last known good value
        src = self.sender()
        try:
            if isinstance(src, QCheckBox):
                src.blockSignals(True)
                src.setChecked(not bool(checked))
                src.blockSignals(False)
        except Exception:
            pass


