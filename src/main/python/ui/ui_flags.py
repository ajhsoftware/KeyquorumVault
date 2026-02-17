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
Small UI helper callbacks that are referenced by ui/ui_bind.py.

Keeping these callbacks in a tiny module avoids circular imports, and lets us
keep main.py smaller while still satisfying signal wiring.
"""

# --- log ---
import logging
log = logging.getLogger("keyquorum")

# --- qtpy pysider backend ---
from qtpy.QtCore import QSettings, QUrl, Qt
from qtpy.QtGui import QDesktopServices
from qtpy.QtWidgets import (QMessageBox, QVBoxLayout, QDialog, QHBoxLayout, QLabel, QCheckBox, QDialogButtonBox,
                            QTextBrowser, QStyle, )
try:
    from auth.login.login_handler import set_user_setting, get_user_setting
except Exception:  # pragma: no cover
    set_user_setting = None


# ==============================
# --- Maybe dont show again popups ---  Maybe Popups ---
# ==============================

# --- reset hide flags
def on_reset_hide_flags_clicked(w):
    """
    Reset all 'Don't show again' flags.

    Clears:
    - QSettings keys used by various popups
    - Per-user suppress flags stored in user_db (URL warnings, USB notice, etc.)
    """

    try:
        # ---- 1) Clear QSettings-based flags ----
        settings = QSettings("AJHSoftware", "KeyquorumVault")

        keys = [
            "hide_autofill_tip",
            "hide_release_notes",
            "suppress_clipboard_warn",
            "hide_security_warning",
            "hide_backup_prompt",
            "hide_update_notice",
            "suppress_url_http_warn",
            "suppress_url_noscheme_warn",
        ]

        removed = 0
        for k in keys:
            if settings.contains(k):
                settings.remove(k)
                removed += 1

        # ---- 2) Clear per-user suppress flags in user_db ----
        cleared_user_flags = 0
        try:
            username = w._active_username().strip()
        except Exception:
            username = ""

        if username:
            for key in (
                "suppress_url_http_warn",
                "suppress_url_noscheme_warn",
                "suppress_usb_notice",      # optional: also reset USB “don’t show again”
            ):
                try:
                    # Setting to False is enough; callers check bool(...)
                    set_user_setting(username, key, False)
                    cleared_user_flags += 1
                except Exception:
                    pass

        total = removed + cleared_user_flags

        # user-friendly message
        msg = QMessageBox(w)
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle(w.tr("Reset Complete"))
        msg.setText(
            w.tr(
                "Reset {n} hidden warnings and notices.\n"
                "They will show again next time."
            ).format(n=total)
        )
        msg.exec()

    except Exception as e:
        QMessageBox.warning(
            w,
            w.tr("Error"),
            w.tr("Unable to reset settings:\n{err}").format(err=e),
        )


# --- fill app with process select
def _maybe_show_autofill_tip(w):
    """
    Show the 'Auto-fill guidance' popup the first time the feature is used.
    User can tick 'Don't show again' to hide it permanently.
    you can reset that setting from your app’s “About / Tips / Reset Warnings” section if you ever add one:
    QSettings("AJHSoftware", "KeyquorumVault").remove("hide_autofill_tip")
    if you want it to appear again after an update, store the version key too:
    settings.setValue("hide_autofill_tip_version", "1.4.8")
    """
    settings = QSettings("AJHSoftware", "KeyquorumVault")
    if settings.value("hide_autofill_tip", False, type=bool):
        return  # already dismissed

    msg = QMessageBox(w)
    msg.setIcon(QMessageBox.Information)
    msg.setWindowTitle(w.tr("About Auto-Fill"))
    msg.setText(
        w.tr("<b>Auto-Fill may not work perfectly on all apps.</b><br><br>"
        "• It needs to communicate with the target window and find its fields.<br>"
        "• Filling can take a few seconds while the app is scanned.<br>"
        "• If only an email/username field is on screen, it will fill that first.<br>"
        "• You might need to click Auto-Fill again once the password field appears.<br><br>"
        "This is normal and depends on how each app renders its login UI.")
    )
    chk = QCheckBox(w.tr("Don't show this again"))
    msg.setCheckBox(chk)
    msg.addButton("OK", QMessageBox.AcceptRole)
    msg.exec()

    if chk.isChecked():
        settings.setValue("hide_autofill_tip", True)


# --- new = show app whats new
def _maybe_show_release_notes(w):
    """
    Startup 'What's New' popup for the 10/12/2025 update.
    User can tick 'Don't show again' to hide it for this update.
    To reset later:
        QSettings("AJHSoftware", "KeyquorumVault").remove("hide_release_notes")
    """
    try:
        settings = QSettings("AJHSoftware", "KeyquorumVault")
        key = "hide_release_notes"

        # Already dismissed for this update?
        if settings.value(key, False, type=bool):
            return

        # --- HTML content ----------
        # --- Break text into properly translatable blocks --------------------------

        t_date = "<b>" + w.tr("Date") + ":</b>" + w.tr("10/12/2025") + "<br><br>"

        t_header_whatsnew = "<b>" + w.tr("What’s New") + "</b> (" + w.tr("new features may contain bugs — please report anything unexpected") + "):<br>"
        t_feedback_link = w.tr("Report issues here") + ": <a href='https://forms.gle/118nQkUeV5cZyFj27'>" + w.tr("Feedback Form") + "</a><br><br>"

        t_language = "<li><b>" + w.tr("Language") + ":</b>" + w.tr("Client-side language selection added to the UI. Additional category-schema packs are now downloadable from the website.") + "</li>"
        t_main_menu = "<li><b>" + w.tr("Main Menu") + ":</b> " + w.tr("Added a Reddit link and a category-download link.") + "</li>"
        t_open_site = "<li><b>" + w.tr("Open Website button") + ":</b> " + w.tr("If a URL uses HTTP, the app now asks whether you want to upgrade it to HTTPS. If you continue with HTTP, it will warn you about the additional security risk.") + "</li>"
        t_autofill = "<li><b>" + w.tr("Auto-Fill") + ":</b> " + w.tr("AutoFill now prioritises the platform selected in Settings") + ".</li>"
        t_slow_login = "<li><b>" + w.tr("Slow login fixed") + ":</b> " + w.tr("Theme is now applied directly on UI load, removing the delay previously caused by theme re-initialisation.") + "</li>"

        t_section_issues = "<b>" + w.tr("Known Issues, Fixes & Work in Progress") + ":</b><br>"
        t_pro_features = "<li><b>" + w.tr("Pro features") + ":</b> " + w.tr("Behaviour may vary depending on Microsoft Store licensing. Testing is only possible after publishing, so please report any issues") + ".</li>"
        t_webfill = "<li><b>" + w.tr("WebFill, AppFill and other fill features") + ":</b>" + w.tr(" Some languages may not yet be fully supported. Please report the affected language and include logs if possible") + ".</li>"
        t_pw_gen = "<li><b>" + w.tr("Password Generator") + ":</b> " + w.tr("Currently generates English-only passwords") + ".</li>"
        t_window_bug = "<li><b>" + w.tr("Window movement bug") + ":</b> <b>" + w.tr("Fixed") + "</b>. " + w.tr("Previously, clicking anywhere on the UI could drag the window. Now only the title bar is draggable") + ".</li>"

        t_section_security = "<b>" + w.tr("Security Notes") + ":</b><br>"
        t_security_notes = "<li>" + w.tr("No known vault or data-integrity issues at this time. Security updates will be posted on the website and Reddit. The app does not use remote notifications — all checks are local for privacy") + ".</li>"

        t_section_feedback = "<b>" + w.tr("Feedback & Contributions") + ":</b><br>"
        t_feedback_intro = w.tr("I would love to hear your feedback, improvements, ideas, and bug reports. Everything submitted through the feedback link is reviewed manually") + ".<br><br>"

        t_contrib_licence = w.tr(
            "If you choose to submit ideas, text, or code, you agree that AJH Software may use, "
            "modify, publish, display (including on the website), or integrate your contribution "
            "into any edition of the app, including the Free and Pro versions, without compensation. "
            "You remain the owner of your work — by submitting it, you are granting AJH Software "
            "a perpetual, non-exclusive, worldwide, royalty-free licence to use, adapt, and share "
            "your contribution as part of the product or its documentation. "
            "Your name can be added to the credits page (optional). "
            "Please only submit work you created yourw and have the rights to share."
        )

        # --- Build the final HTML safely -------------------------------------------

        html = (
            t_date +
            t_header_whatsnew +
            t_feedback_link +
            "<ul>" +
                t_language +
                t_main_menu +
                t_open_site +
                t_autofill +
                t_slow_login +
            "</ul>" +
            t_section_issues +
            "<ul>" +
                t_pro_features +
                t_webfill +
                t_pw_gen +
                t_window_bug +
            "</ul>" +
            t_section_security +
            "<ul>" +
                t_security_notes +
            "</ul>" +
            t_section_feedback +
            t_feedback_intro +
            t_contrib_licence
        )


        # --- Build a small dialog inline ------------------------------------
        dlg = QDialog(w)
        dlg.setWindowTitle(w.tr("What’s New in Keyquorum Vault"))
        dlg.setModal(True)
        dlg.setMinimumSize(700, 450)
        dlg.resize(700, 450)

        main_layout = QVBoxLayout(dlg)

        # icon + text
        top_layout = QHBoxLayout()
        icon_label = QLabel()
        icon = dlg.style().standardIcon(QStyle.SP_MessageBoxInformation)
        icon_label.setPixmap(icon.pixmap(48, 48))
        icon_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        top_layout.addWidget(icon_label)

        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)
        text_browser.setReadOnly(True)
        text_browser.setHtml(html)
        top_layout.addWidget(text_browser)

        main_layout.addLayout(top_layout)

        chk = QCheckBox(w.tr("Don't show this again for this update"))
        main_layout.addWidget(chk)

        btn_box = QDialogButtonBox(QDialogButtonBox.Ok)
        btn_box.accepted.connect(dlg.accept)
        main_layout.addWidget(btn_box)

        # show dialog
        if dlg.exec() == QDialog.Accepted and chk.isChecked():
            settings.setValue(key, True)

    except Exception as e:
        try:
            log.debug(f"[WHATSNEW] Popup failed: {e}")
        except Exception:
            pass
    

# --- user running from usb 
def notify_usb_loaded_once(w, username: str) -> None:
    """
    If running from USB, show a one-time notice with a
    'Don't show again' checkbox.

    Stored globally via QSettings (not per-user).
    Safe to call multiple times.
    """
    from qtpy.QtWidgets import QMessageBox, QCheckBox
    from qtpy.QtCore import QSettings
    import app.paths as _paths
    import logging

    log = logging.getLogger("keyquorum")

    # Only show if we're actually in portable (USB) mode
    try:
        if not _paths.is_portable_mode():
            return
    except Exception:
        return

    settings = QSettings("AJHSoftware", "KeyquorumVault")

    # Already dismissed?
    if settings.value("suppress_usb_notice", False, type=bool):
        return

    text = (
        "You have loaded Keyquorum Vault from a USB drive.\n\n"
        "If you plan to sign in to a local (installed, non-portable) user next, "
        "please restart the app and unplug the USB before logging in."
    )

    box = QMessageBox(w)
    box.setIcon(QMessageBox.Information)
    box.setWindowTitle(w.tr("Running from USB"))
    box.setText(text)
    box.setStandardButtons(QMessageBox.Ok)

    chk = QCheckBox(w.tr("Don't show this again"))
    box.setCheckBox(chk)

    box.exec_()

    if chk.isChecked():
        settings.setValue("suppress_usb_notice", True)

    log.info(
        "[USB] notice shown (suppress=%s)",
        chk.isChecked(),
    )


# --- clipboard 
def maybe_warn_windows_clipboard(w, copy=True) -> None:
    """Show a one-time warning if Windows Clipboard history / sync are ON."""
    # - imports
    from features.clipboard.secure_clipboard import _win_clipboard_risk_state

    w.set_status_txt(w.tr("Checking Windows Clipboard save is On"))

    settings = QSettings("AJHSoftware", "KeyquorumVault")
    if settings.value("suppress_clipboard_warn", False, type=bool):
        return  # already dismissed

    s = _win_clipboard_risk_state()
    risky = s.get("history") or s.get("cloud")
    if not risky:
        return

    msg = (
        "Windows Clipboard history and/or Sync are ON.\n\n"
        "Anything you copy (including passwords) may be kept in clipboard history "
        "and could sync to your Microsoft account.\n\n"
        "For maximum privacy, turn these features OFF in Settings → System → Clipboard."
    )
    box = QMessageBox(w)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle(w.tr("Clipboard history is ON"))
    box.setText(msg)
    open_btn   = box.addButton(w.tr("Open Clipboard Settings"), QMessageBox.ButtonRole.AcceptRole)
    if copy:
        copy_btn   = box.addButton(w.tr("Copy anyway"), QMessageBox.ButtonRole.YesRole)
    else:
        copy_btn   = box.addButton(w.tr("OK"), QMessageBox.ButtonRole.YesRole)
    dont_btn   = box.addButton(w.tr("Don’t warn again"), QMessageBox.ButtonRole.DestructiveRole)
    box.setDefaultButton(copy_btn)
    box.exec()

    if box.clickedButton() is open_btn:
        try:
            QDesktopServices.openUrl(QUrl("ms-settings:clipboard"))
        except Exception:
            pass
    elif box.clickedButton() is dont_btn and set_user_setting:
        try:
            settings.setValue("suppress_clipboard_warn", True)
        except Exception:
            pass
