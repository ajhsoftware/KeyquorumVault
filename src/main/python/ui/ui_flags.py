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
from turtle import up
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

from security.preflight import save_security_prefs, load_security_prefs 

# ==============================
# --- pre warn message box
# ==============================
def _maybe_warn_first_time(self, pref_key: str, title: str, message: str) -> bool:
    """
    Show a one-time warning with 'Don't show again'. Returns True to continue.
    Store the user's choice in user settings prefs.
    """
    try:
        prefs = getattr(self, "userPrefs", {}) or {}
        if prefs.get(pref_key) is True:
            return True
    except Exception:
        prefs = {}

    box = QMessageBox(self)
    box.setIcon(QMessageBox.Warning)
    box.setWindowTitle(title)
    box.setText(message)
    box.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
    box.button(QMessageBox.Ok).setText(self.tr("I understand"))
    chk = QCheckBox(self.tr("Don't show again"))
    box.setCheckBox(chk)
    ret = box.exec()
    if ret == QMessageBox.Ok and chk.isChecked():
        prefs[pref_key] = True
        try:
            self.userPrefs = prefs
        except Exception:
            pass
    return ret == QMessageBox.Ok


# ==============================
# --- reset hide flags
# ==============================
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


# ==============================
# --- fill app with process select
# ==============================
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


# ==============================
# --- new = show app whats new
# ==============================

def _maybe_show_release_notes(w):
    """
    Startup 'What's New' popup for the 09/04/2026 update.
    User can tick 'Don't show again' to hide it for this update.

    To reset later:
        QSettings("AJHSoftware", "KeyquorumVault").remove("hide_release_notes_09-04-2026")
    """
    try:
        settings = QSettings("AJHSoftware", "KeyquorumVault")
        key = "hide_release_notes_09-04-2026"  # change on every release

        # Already dismissed for this update?
        if settings.value(key, False, type=bool):
            return

        # -------------------------------
        # Translatable HTML content
        # -------------------------------
        t_date = "<b>" + w.tr("Date") + ":</b> 09 Apr 2026<br><br>"

        t_header_whatsnew = (
            "<b>" + w.tr("What’s New") + "</b> ("
            + w.tr("new features and recent fixes may still contain bugs — please report anything unexpected")
            + ")<br><br>"
        )

        t_feedback_link = (
            "<b>" + w.tr("Report issues") + ":</b><br>"
            "<a href='https://github.com/ajhsoftware/KeyquorumVault/issues'>"
            + w.tr("GitHub Issues")
            + "</a><br>"
            + w.tr("For non-technical feedback, you may also use")
            + " <a href='https://forms.gle/71zuZFXuZWpFu5Ew6'>"
            + w.tr("Google Feedback Form")
            + "</a><br><br>"
        )

        t_update = (
            "<li><b>" + w.tr("Update") + ":</b> "
            + w.tr(
                "This update continues the recent stability work with a strong focus on sync reliability, conflict handling, refresh behaviour, and general bug fixing."
            )
            + "</li>"
        )

        t_sync_logic = (
            "<li><b>" + w.tr("Sync decision logic") + ":</b> "
            + w.tr(
                "Sync now makes better decisions about when to push, when to pull, and when no transfer is needed. This helps prevent cases where local changes were treated as cloud changes, or cloud restores were treated as local updates."
            )
            + "</li>"
        )

        t_sync_timestamps = (
            "<li><b>" + w.tr("Timestamp-based sync fixes") + ":</b> "
            + w.tr(
                "Timestamp handling has been improved so the app can more reliably tell whether the local vault or the synced copy is newer. This reduces wrong-direction sync actions and improves restore behaviour."
            )
            + "</li>"
        )

        t_manual_sync = (
            "<li><b>" + w.tr("Manual Push and Pull") + ":</b> "
            + w.tr(
                "Manual sync actions now behave more clearly. Manual Pull is less likely to incorrectly push data, and Manual Push is more consistent about sending the correct latest local data."
            )
            + "</li>"
        )

        t_sync_refresh = (
            "<li><b>" + w.tr("Refresh after pull") + ":</b> "
            + w.tr(
                "After pulling newer data, the app now refreshes vault views more reliably so restored or incoming changes appear properly without needing extra steps."
            )
            + "</li>"
        )

        t_autosync_refresh = (
            "<li><b>" + w.tr("Auto-sync refresh") + ":</b> "
            + w.tr(
                "Auto-sync behaviour has been improved so UI data refresh is more reliable after sync activity. This helps reduce cases where the sync completed but the table or visible data did not immediately update."
            )
            + "</li>"
        )

        t_conflict = (
            "<li><b>" + w.tr("Sync conflict handling") + ":</b> "
            + w.tr(
                "Conflict handling has been tightened up to reduce false or confusing conflict states when switching between local backups, cloud copies, and recently changed vault data."
            )
            + "</li>"
        )

        t_sync_logging = (
            "<li><b>" + w.tr("Sync troubleshooting logs") + ":</b> "
            + w.tr(
                "Additional sync logging and decision tracking have been improved to make troubleshooting easier when checking why the app chose to push, pull, or report a conflict."
            )
            + "</li>"
        )

        t_sync_bundle = (
            "<li><b>" + w.tr("Sync bundle safety") + ":</b> "
            + w.tr(
                "Sync handling continues to better protect related vault files and companion metadata so they stay together more safely during backup, restore, device moves, and cloud-backed syncing."
            )
            + "</li>"
        )

        t_windows_notify = (
            "<li><b>" + w.tr("Windows notifications") + ":</b> "
            + w.tr(
                "Watchtower and Reminders can now show clearer Windows notifications, helping surface important changes without opening the app."
            )
            + "</li>"
        )

        t_watchtower_perf = (
            "<li><b>" + w.tr("Watchtower performance") + ":</b> "
            + w.tr(
                "Watchtower scanning has been significantly improved for large vaults. Scans on big datasets are much faster, smoother, and more reliable."
            )
            + "</li>"
        )

        t_watchtower_breach = (
            "<li><b>" + w.tr("Breach detection") + ":</b> "
            + w.tr(
                "Password breach checking has been fixed so entries are checked correctly. Cache handling has also been improved to reduce repeated work and improve speed."
            )
            + "</li>"
        )

        t_background_alerts = (
            "<li><b>" + w.tr("Background alerts") + ":</b> "
            + w.tr(
                "A lightweight background worker now checks Watchtower and reminder states and only alerts when something changes, helping avoid repeated notification spam."
            )
            + "</li>"
        )

        t_url_checks = (
            "<li><b>" + w.tr("Smarter URL handling") + ":</b> "
            + w.tr(
                "Watchtower now only performs URL-related checks when a real URL exists. This reduces false warnings on entries such as cards, notes, and other non-login items."
            )
            + "</li>"
        )

        t_native = (
            "<li><b>" + w.tr("Native security core") + ":</b> "
            + w.tr(
                "The app now requires the native C++ DLL for sensitive operations. This improves handling for keys, encryption, session-based protection, and memory cleanup."
            )
            + "</li>"
        )

        t_auth = (
            "<li><b>" + w.tr("Encrypted data migration") + ":</b> "
            + w.tr(
                "Encrypted items now migrate more safely when changing password, updating vault security, or enabling or disabling YubiKey WRAP. This helps keep vault data, password history, trash, authenticator data, and related encrypted stores working correctly after security changes."
            )
            + "</li>"
        )

        t_yubi = (
            "<li><b>" + w.tr("YubiKey WRAP fixes") + ":</b> "
            + w.tr(
                "YubiKey WRAP flows have been improved to better protect against data loss during rekey operations and to make migration between old and new secure sessions more reliable."
            )
            + "</li>"
        )

        t_kdf = (
            "<li><b>" + w.tr("Vault security upgrade") + ":</b> "
            + w.tr(
                "Support for stronger Argon2-based vault settings has been improved, including better handling for newer KDF profiles and stricter DLL-only security paths."
            )
            + "</li>"
        )

        t_csv = (
            "<li><b>" + w.tr("CSV import") + ":</b> "
            + w.tr(
                "CSV import performance has been improved and can now handle very large imports much more smoothly."
            )
            + "</li>"
        )

        t_salt = (
            "<li><b>" + w.tr("Salt storage") + ":</b> "
            + w.tr(
                "Vault salt handling has been simplified by moving away from a separate salt file and integrating that information into the identity data for easier maintenance and syncing."
            )
            + "</li>"
        )

        t_logging = (
            "<li><b>" + w.tr("Per-user logging") + ":</b> "
            + w.tr(
                "Logging has been improved so user-specific logs are created more reliably after login, helping with troubleshooting and support."
            )
            + "</li>"
        )

        t_bridge = (
            "<li><b>" + w.tr("Browser extension bridge") + ":</b> "
            + w.tr(
                "Communication with the browser extension has been improved with stronger signed local authentication between the extension and the app."
            )
            + "</li>"
        )

        t_catalog = (
            "<li><b>" + w.tr("Autofill and launch reliability") + ":</b> "
            + w.tr(
                "Autofill-related handling and app launch or open flows have been improved for better reliability."
            )
            + "</li>"
        )

        t_cleaning = (
            "<li><b>" + w.tr("Code cleanup") + ":</b> "
            + w.tr(
                "The app is still being split into cleaner modules. This should make future updates easier to maintain, but during this transition some areas may still be rough. Please report bugs with logs where possible."
            )
            + "</li>"
        )

        t_older = (
            "<li><b>" + w.tr("Older updates") + ":</b> "
            + w.tr(
                "The notes below include older improvements still relevant to current builds."
            )
            + "</li>"
        )

        t_login_hello = (
            "<li><b>" + w.tr("Device unlock") + ":</b> "
            + w.tr(
                "Secure device-based unlock has been added. You can enable 'Remember this device' for faster login on trusted devices. This can be cleared at any time in Settings → Profile."
            )
            + "</li>"
        )

        t_login_username = (
            "<li><b>" + w.tr("Remember username") + ":</b> "
            + w.tr(
                "A Remember Username option has been added. You can clear the saved username at any time in Settings → Profile."
            )
            + "</li>"
        )

        t_reminder = (
            "<li><b>" + w.tr("Reminders") + ":</b> "
            + w.tr(
                "A reminder checkbox has been added to category editing. When enabled, Reminder Date and Reminder Note fields appear. Items with reminders are shown in the Reminders section of the vault."
            )
            + "</li>"
        )

        t_language = (
            "<li><b>" + w.tr("Language") + ":</b> "
            + w.tr(
                "Client-side language selection has been added to the UI. Additional category-schema packs are also available from the website."
            )
            + "</li>"
        )

        t_main_menu = (
            "<li><b>" + w.tr("Main menu") + ":</b> "
            + w.tr(
                "Added links for Reddit and category downloads."
            )
            + "</li>"
        )

        t_open_site = (
            "<li><b>" + w.tr("Open Website button") + ":</b> "
            + w.tr(
                "If a URL uses HTTP, the app now asks whether you want to upgrade it to HTTPS. If you continue with HTTP, it warns you about the additional security risk."
            )
            + "</li>"
        )

        t_autofill = (
            "<li><b>" + w.tr("Auto-fill") + ":</b> "
            + w.tr(
                "AutoFill now prioritises the platform selected in Settings."
            )
            + "</li>"
        )

        t_slow_login = (
            "<li><b>" + w.tr("Faster startup") + ":</b> "
            + w.tr(
                "Theme handling is now applied more directly on UI load, reducing the delay previously caused by theme re-initialisation."
            )
            + "</li>"
        )

        t_licence = (
            "<li><b>" + w.tr("Licence") + ":</b> "
            + w.tr(
                "Keyquorum Vault is now open source under the GNU General Public License v3 (GPL-3.0). The full source code is available on GitHub, and contributions are welcome."
            )
            + " <a href='https://github.com/ajhsoftware/KeyquorumVault'>"
            + w.tr("GitHub Repository")
            + "</a></li>"
        )

        t_official_source = (
            "<li><b>" + w.tr("Updates & Privacy") + ":</b> "
            + w.tr(
                "Keyquorum Vault is designed as a privacy-first application. The app does not perform automatic background network connections, telemetry, or remote update checks. Network activity only occurs when you explicitly open a website or when communicating locally with the browser extension. Updates are manual unless installed through the Microsoft Store. Adding update verification and optional automatic updates is on the roadmap. For security reasons, always download updates from the official GitHub repository or the AJH Software website. Where provided, verify the SHA256 checksum before installing."
            )
            + "</li>"
        )

        t_section_issues = (
            "<b>" + w.tr("Known Issues, Fixes & Work in Progress") + ":</b><br>"
        )

        t_webfill = (
            "<li><b>" + w.tr("WebFill, AppFill and related fill features") + ":</b> "
            + w.tr(
                "Some languages may not yet be fully supported. Please report the affected language and include logs if possible."
            )
            + "</li>"
        )

        t_pw_gen = (
            "<li><b>" + w.tr("Password Generator") + ":</b> "
            + w.tr(
                "Currently generates English-only passwords."
            )
            + "</li>"
        )

        t_window_bug = (
            "<li><b>" + w.tr("Window movement bug") + ":</b> <b>"
            + w.tr("Fixed")
            + "</b>. "
            + w.tr(
                "Previously, clicking anywhere on the UI could drag the window. Now only the title bar is draggable."
            )
            + "</li>"
        )

        t_section_security = "<b>" + w.tr("Security Notes") + ":</b><br>"

        t_security_notes = (
            "<li>"
            + w.tr(
                "No known vault or data-integrity issues are currently expected in this release. Security updates will be posted on the website and Reddit. The app does not use remote notifications for privacy; checks remain local where possible."
            )
            + "</li>"
        )

        t_section_feedback = (
            "<b>" + w.tr("Feedback & Contributions") + ":</b><br>"
        )

        t_feedback_intro = (
            w.tr(
                "I would love to hear your feedback, improvements, ideas, and bug reports. Everything submitted through the feedback links is reviewed manually."
            )
            + "<br><br>"
        )

        t_contrib_licence = w.tr(
            "<b>Contributions:</b> If you submit ideas, text, translations, or code, please only submit work you created and have the rights to share. Unless you clearly state otherwise, your contribution will be treated as licensed under the same licence as this project (GPL-3.0-or-later) and may be included in the app and its documentation."
        )

        html = (
            t_date
            + t_header_whatsnew
            + t_feedback_link
            + "<ul>"
            + t_update
            + t_sync_logic
            + t_sync_timestamps
            + t_manual_sync
            + t_sync_refresh
            + t_autosync_refresh
            + t_conflict
            + t_sync_logging
            + t_sync_bundle
            + t_windows_notify
            + t_watchtower_perf
            + t_watchtower_breach
            + t_background_alerts
            + t_url_checks
            + t_native
            + t_auth
            + t_yubi
            + t_kdf
            + t_csv
            + t_salt
            + t_logging
            + t_bridge
            + t_catalog
            + t_cleaning
            + t_older
            + t_login_hello
            + t_licence
            + t_official_source
            + t_language
            + t_login_username
            + t_reminder
            + t_main_menu
            + t_open_site
            + t_autofill
            + t_slow_login
            + "</ul>"
            + t_section_issues
            + "<ul>"
            + t_webfill
            + t_pw_gen
            + t_window_bug
            + "</ul>"
            + t_section_security
            + "<ul>"
            + t_security_notes
            + "</ul>"
            + t_section_feedback
            + t_feedback_intro
            + t_contrib_licence
        )

        # -------------------------------
        # Build dialog
        # -------------------------------
        dlg = QDialog(w)
        dlg.setWindowTitle(w.tr("What’s New in Keyquorum Vault"))
        dlg.setModal(True)
        dlg.setMinimumSize(700, 450)
        dlg.resize(700, 450)

        main_layout = QVBoxLayout(dlg)

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

        # Show dialog
        if dlg.exec() == QDialog.Accepted and chk.isChecked():
            settings.setValue(key, True)

    except Exception as e:
        try:
            log.debug(f"[WHATSNEW] Popup failed: {e}")
        except Exception:
            pass

# ==============================
# --- user running from usb
# ==============================
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


# ==============================
# --- clipboard
# ==============================
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


# ==============================
# --- preflight 
# ==============================
def maybe_prompt_enable_preflight(self, parent=None):
    prefs = load_security_prefs()
    if prefs.get("preflight_prompted", False):
        return

    box = QMessageBox(parent or self)
    box.setWindowTitle(self.tr("Security Preflight"))
    box.setIcon(QMessageBox.Icon.Question)
    box.setText(self.tr("Enable Security Preflight checks?"))
    box.setInformativeText(
        "Preflight can warn you about packet sniffers, debuggers, and other tools "
        "that increase risk. You can change this later in Settings."
    )
    enable_btn = box.addButton(self.tr("Enable (Recommended)"), QMessageBox.ButtonRole.AcceptRole)
    later_btn  = box.addButton(self.tr("Not Now"), QMessageBox.ButtonRole.RejectRole)
    box.setDefaultButton(enable_btn)
    box.exec()

    prefs["preflight_prompted"] = True
    prefs["enable_preflight"] = (box.clickedButton() is enable_btn)
    save_security_prefs(prefs)


# ==============================
# --- Url Warn 
# ==============================
def open_vendor_url(self, url: str, builtins_url: str | None = None) -> None:
    """Open a URL safely. If it looks user-added, show one-time warning."""
    u = (url or "").strip()
    if not u:
        QMessageBox.warning(self, self.tr("URL missing"), self.tr("There is no URL configured for this item."))
        return
    try:
        from urllib.parse import urlparse
        p = urlparse(u)
        if p.scheme not in ("https", "http"):
            QMessageBox.warning(self, self.tr("Blocked URL"), self.tr("Only http/https links are allowed."))
            return
    except Exception:
        QMessageBox.warning(self, self.tr("Invalid URL"), self.tr("The link appears malformed."))
        return

    # One-time warning for user-added/overridden URLs
    if self._is_probably_user_added(u, builtins_url):
        cont = self._maybe_warn_first_time(
            pref_key="suppress_user_url_warning",
            title="Custom URL — be careful",
            message=(
                "This link was added or changed by a user.\n\n"
                "Only open official vendor sites or trusted direct download links.\n"
                "Malicious links can harm your device."
            )
        )
        if not cont:
            return

    QDesktopServices.openUrl(QUrl(u))



