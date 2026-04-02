# Keyquorum Vault

Offline-first password manager by **AJH Software**.

> ⚠️ Note: The project is currently being refactored and modularised.  
> Folder structure and internal modules may change while this stabilises.

---

## 🔐 Overview

Keyquorum Vault is a **privacy-first, offline password manager** designed with a strict local-only security model.

- No required accounts
- No forced cloud sync
- No telemetry or hidden network activity
- Full local encryption and control

All sensitive data is handled locally using authenticated encryption (**AES-GCM**) and a strong KDF (**Argon2id**).

---

## 🚀 Recent Updates (April 2026)

### 🔒 Security Core
- Native **C++ DLL is now required** for all sensitive operations  
- Improved memory handling and key isolation  
- Removal of Python fallback for cryptographic operations  

### 🔁 Encryption & Rekeying
- Safer migration when:
  - Changing password
  - Updating vault security
  - Enabling/disabling YubiKey WRAP  
- Covers:
  - Vault data
  - Password history
  - Trash store
  - Authenticator store

### 🔐 Vault Security
- Improved Argon2id handling (KDF v2 support)
- Better compatibility with future security upgrades

### 🔑 YubiKey Support
- More reliable WRAP enable/disable flows  
- Improved rekey safety and session handling  

---

### ⚡ Performance

#### Watchtower
- Major performance improvements (large vaults)
- Fixed breach detection issues
- Added smarter caching to reduce repeated checks
- Reduced false positives (e.g. non-URL categories)

#### CSV Import
- Handles **10K+ entries smoothly**
- Improved import speed and UI responsiveness

---

### 🔔 Notifications & Background Tasks
- Windows notifications for:
  - Watchtower changes
  - Reminders
- New background worker:
  - Only alerts on changes (no spam)

---

### 🔄 Sync Improvements
- More reliable sync across:
  - NAS
  - Local folders
  - Cloud-backed folders (user-selected)
- Improved:
  - Sync state visibility
  - Restore on new devices
- Better handling of:
  - Vault
  - Metadata
  - Side stores (trash, history, etc.)

---

### 🌉 Browser Extension Bridge
- Secure **signed local authentication**
- Improved reliability of autofill communication
- Strict localhost-only communication (`127.0.0.1`)

---

### 🧠 Storage Changes
- Salt is now stored in the **identity file**
- Removed separate salt file for:
  - Easier sync
  - Simpler maintenance

---

### 📜 Logging
- Improved per-user logging
- Logs now initialise correctly after login

---

### 🧹 Codebase
- Ongoing refactor:
  - Breaking large files into modules
  - Improving maintainability
- Some areas may still be unstable — feedback welcome

---

## 🧩 What this repository contains

- Desktop application (Qt / PySide6 via `qtpy`)
- Vault encryption & storage logic
- Feature modules:
  - Watchtower
  - Reminders
  - Security Center
  - Sync system
- Background workers

---

## 🛠 Running from source (developer)

This project is packaged using **fbs Pro** for Windows builds, but can be run locally.

### Steps:
1. Create a virtual environment
2. Install dependencies
3. Run the app

---

### 📦 Suggested dependencies

- `PySide6`
- `qtpy`
- `cryptography`
- `argon2-cffi`
- `pyotp`
- `qrcode`
- `reportlab`

Optional:
- `opencv-python` (QR/camera features)
- `pywinauto` (Windows automation)

---

## 📁 Repository layout

def _maybe_show_release_notes(w):
    """
    Startup 'What's New' popup for the 20/02/2026 update.
    User can tick 'Don't show again' to hide it for this update.
    To reset later:
        QSettings("AJHSoftware", "KeyquorumVault").remove("hide_release_notes")
    """
    try:
        settings = QSettings("AJHSoftware", "KeyquorumVault")
        key = "hide_release_notes_01-04-2026"  # change on every release

        # Already dismissed for this update?
        if settings.value(key, False, type=bool):
            return

        # --- HTML content ----------
        # --- Break text into properly translatable blocks --------------------------
        t_date = "<b>" + w.tr("Date") + ":</b> 20 Feb 2026<br><br>"

        t_header_whatsnew = (
            "<b>" + w.tr("What’s New") + "</b> ("
            + w.tr("new features may contain bugs — please report anything unexpected")
            + " ) :<br>"
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

        t_licence = (
            "<li><b>" + w.tr("Licence") + ":</b> "
            + w.tr(
                "Keyquorum Vault is now open source under the GNU General Public License v3 (GPL-3.0). "
                "The full source code is available on GitHub, and contributions are welcome."
            )
            + " <a href='https://github.com/ajhsoftware/KeyquorumVault'>"
            + w.tr("GitHub Repository")
            + "</a></li>"
        )

        t_official_source = (
            "<li><b>" + w.tr("Updates & Privacy") + ":</b> "
            + w.tr(
                "Keyquorum Vault is designed as a privacy-first application. "
                "The app does not perform automatic background network connections, telemetry, "
                "or remote update checks. Network activity only occurs when you explicitly open a website "
                "or when communicating locally with the browser extension. "
                "Updates are manual unless installed through the Microsoft Store. "
                "Adding update verification and optional automatic updates is on the roadmap, but in the meantime, "
                "For security reasons, always download updates from the official GitHub repository "
                "or the AJH Software website. Where provided, verify the SHA256 checksum before installing."
            )
            + "</li>"
        )
        update = (
            "<li><b>" + ":</b> "
            + w.tr(
                "Updated on 01/04/2026 "
                "This Update includes new features, security improvements, and bug fixes."
            )
            + "</li>"
        )
        t_windows_notify = (
            "<li><b>" + w.tr("Windows Notify") + ":</b> "
            + w.tr(
                "WatchTower, Reminder. cloud sync now shows a message in windows noticafsion bar"
            )
            + "</li>"
        )
        t_native = (
            "<li><b>" + w.tr("C++ Dll") + ":</b> "
            + w.tr(
                "App now requres native dll to run, this is a c++ dll for all senstive data making more contralled for memry wipping on close"
                "this has changed how the app runs and hands sensitive data like keys, vault data, and other sensitive data"
                "That said yubi key, changed passwords, forgot password, encrypsion have all been updated to work with the new dll and in some cases have been made more secure with the new dll"
            )
            + "</li>"
        )
        t_auth = (
            "<li><b>" + w.tr("userkey") + ":</b> "
            + w.tr(
                "with the native dll this has changed how all encrted files or items or encrtyed, upon changing password, update vault secerty, yubi key wrap"
                "this changes the encertypin of files a items, the app will update all encrted items and files then logout allowing for the items to keep working"
                "affected items incloude vault, password history, trash bin, authcstor store, and other items that are encrted with the user key, this is all done to make sure that if a user changes password or updates vault security or yubi key wrap the items will still work and be protected with the new settings""
                )
            + "</li>"
        )
        t_cleaning = (
            "<li><b>" + w.tr("code cleaning") + ":</b> "
            + w.tr(
                "The app was bult with most of the funcsions in one file, this making the app very hard to maintane update, a code clean and split is still taking place"
                "as this is still happening some features may be buggy or not working as intended, if you find any bugs please report them with logs if possible and i will fix asap"
            )
            + "</li>"
        )


        t_brige = (
            "<li><b>" + w.tr("brige") + ":</b> "
            + w.tr(
                "The app now commucsaes with the web exsged tocken + sined auth making a more secure communicasion"
            )
            + "</li>"
        )
        t_catalog = (
            "<li><b>" + w.tr("catalog") + ":</b> "
            + w.tr(
                "App autofill or download and install/open more reliable with more added configrasion"
            )
            + "</li>"
        )
        t_sync = (
            "<li><b>" + w.tr("sync") + ":</b> "
            + w.tr(
                "fixed sync error, now sync is more reliable once setup a user can seleted nas,cloud folder or just a folder, to sync to and from"
                "with clear sync status, files that are being synced last pyshed or pulled."
                "sync now holds a copy of user data, trash bin, password history, vault and other important data needed for synced devices"
                "users can now also chose a sync folder from any device and this will copy the data to the device. no more making full backups to sync devices"
                "allowing for a more seamless and user friendly sync experience" 
            )
            + "</li>"
        )
        t_sync = (
            "<li><b>" + w.tr("sync") + ":</b> "
            + w.tr(
                "fixed sync error, now sync is more reliable once setup a user can seleted nas,cloud folder or just a folder, to sync to and from"
                "with clear sync status, files that are being synced last pyshed or pulled."
                "sync now holds a copy of user data, trash bin, password history, vault and other important data needed for synced devices"
                "users can now also chose a sync folder from any device and this will copy the data to the device. no more making full backups to sync devices"
                "allowing for a more seamless and user friendly sync experience" 
            )
            + "</li>"
        )

        t_csv = (
            "<li><b>" + w.tr("sync") + ":</b> "
            + w.tr(
                "csv can now import 10K+ with a resbial time and smothness"
            )
            + "</li>"
        )

        t_salt = (
            "<li><b>" + w.tr("Salt") + ":</b> "
            + w.tr(
                "There is no longer a singal salt file this has been margeged into identity file for easer mainting and syncing"
            )
            + "</li>"
        )
        t_older = (
            "<li><b>" + w.tr("Older Updates") + ":</b> "
            + w.tr(
                "below is older updates"
            )
            + "</li>"
        )

        t_login_hello = (
            "<li><b>" + w.tr("Device unlock") + ":</b> "
            + w.tr(
                "Secure device-based unlock added. You can enable 'Remember this device' for faster login on trusted devices. "
                "This can be cleared at any time in Settings → Profile."
            )
            + "</li>"
        )

        t_login_username = (
            "<li><b>" + w.tr("Remember Username") + ":</b> "
            + w.tr(
                "Remember Username option added. You can clear the saved username at any time in Settings → Profile."
            )
            + "</li>"
        )

        t_reminder = (
            "<li><b>" + w.tr("Reminder") + ":</b> "
            + w.tr(
                "A reminder checkbox has been added to categorie Edit. When enabled, additional fields for Reminder Date and "
                "Reminder Note appear. Items with a reminder will be shown in the Reminders section of the Vault."
            )
            + "</li>"
        )

        t_language = "<li><b>" + w.tr("Language") + ":</b> " + w.tr(
            "Client-side language selection added to the UI. Additional category-schema packs are now downloadable from the website."
        ) + "</li>"

        t_main_menu = "<li><b>" + w.tr("Main Menu") + ":</b> " + w.tr(
            "Added a Reddit link and a category-download link."
        ) + "</li>"

        t_open_site = "<li><b>" + w.tr("Open Website button") + ":</b> " + w.tr(
            "If a URL uses HTTP, the app now asks whether you want to upgrade it to HTTPS. If you continue with HTTP, it will warn you about the additional security risk."
        ) + "</li>"

        t_autofill = "<li><b>" + w.tr("Auto-Fill") + ":</b> " + w.tr(
            "AutoFill now prioritises the platform selected in Settings."
        ) + "</li>"

        t_slow_login = "<li><b>" + w.tr("Slow login fixed") + ":</b> " + w.tr(
            "Theme is now applied directly on UI load, removing the delay previously caused by theme re-initialisation."
        ) + "</li>"

        t_section_issues = "<b>" + w.tr("Known Issues, Fixes & Work in Progress") + ":</b><br>"
        t_webfill = "<li><b>" + w.tr("WebFill, AppFill and other fill features") + ":</b> " + w.tr(
            "Some languages may not yet be fully supported. Please report the affected language and include logs if possible."
        ) + "</li>"

        t_pw_gen = "<li><b>" + w.tr("Password Generator") + ":</b> " + w.tr(
            "Currently generates English-only passwords."
        ) + "</li>"

        t_window_bug = "<li><b>" + w.tr("Window movement bug") + ":</b> <b>" + w.tr("Fixed") + "</b>. " + w.tr(
            "Previously, clicking anywhere on the UI could drag the window. Now only the title bar is draggable."
        ) + "</li>"

        t_section_security = "<b>" + w.tr("Security Notes") + ":</b><br>"
        t_security_notes = "<li>" + w.tr(
            "No known vault or data-integrity issues at this time. Security updates will be posted on the website and Reddit. "
            "The app does not use remote notifications — all checks are local for privacy."
        ) + "</li>"

        t_section_feedback = "<b>" + w.tr("Feedback & Contributions") + ":</b><br>"
        t_feedback_intro = w.tr(
            "I would love to hear your feedback, improvements, ideas, and bug reports. Everything submitted through the feedback links is reviewed manually."
        ) + "<br><br>"

        t_contrib_licence = w.tr(
            "<b>Contributions:</b> If you submit ideas, text, translations, or code, please only submit work you created "
            "and have the rights to share. Unless you clearly state otherwise, your contribution will be treated as "
            "licensed under the same licence as this project (GPL-3.0-or-later) and may be included in the app and its "
            "documentation."
        )

        html = (
            t_date
            + t_header_whatsnew
            + t_feedback_link
            + "<ul>"
                + update
                + t_windows_notify
                + t_native
                + t_auth
                + t_cleaning
                + t_brige
                + t_catalog
                + t_sync
                + t_csv
                + t_salt
                + t_older
            + "<ul>"
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

The main hard error is in t_auth.

You have an extra quote at the end of this string:

"affected items incloude vault, password history, trash bin, authcstor store, and other items that are encrted with the user key, this is all done to make sure that if a user changes password or updates vault security or yubi key wrap the items will still work and be protected with the new settings""
That final "" breaks the code.

Use this instead:

t_auth = (
    "<li><b>" + w.tr("User key") + ":</b> "
    + w.tr(
        "With the native DLL, this has changed how all encrypted files and items are handled. "
        "When changing password, updating vault security, or enabling/disabling YubiKey wrap, "
        "the app now updates encrypted items and files, then logs out so everything continues to work correctly. "
        "Affected items include the vault, password history, trash bin, authenticator store, and other data encrypted with the user key. "
        "This is done to make sure that if a user changes password, updates vault security, or changes YubiKey wrap, "
        "those items still work and remain protected with the new settings."
    )
    + "</li>"
)
A few other things are not syntax errors, but should be fixed:

1. t_sync is defined twice
You have the same block twice. The second one overwrites the first one. It will not crash, but it is messy.

2. Your HTML list structure is broken
Here:

+ "<ul>"
    + update
    + t_windows_notify
    ...
    + t_salt
    + t_older
+ "<ul>"
You open a <ul> and then open another <ul> without closing the first one.

That part should be more like:

html = (
    t_date
    + t_header_whatsnew
    + t_feedback_link
    + "<ul>"
        + update
        + t_windows_notify
        + t_native
        + t_auth
        + t_cleaning
        + t_brige
        + t_catalog
        + t_sync
        + t_csv
        + t_salt
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
3. Dates do not match
You currently have:

docstring says 20/02/2026

t_date says 20 Feb 2026

key says hide_release_notes_01-04-2026

update text says 01/04/2026

That will confuse users. Pick one release date and use it everywhere.

4. Minor text issues
These will not crash, but they look rough:

brige → bridge

commucsaes → communicates

tocken → token

sined → signed

noticafsion → notification

requres → requires

senstive → sensitive

memry wipping → memory wiping

5. Small label mistake
This says "sync" even though it is CSV:

t_csv = (
    "<li><b>" + w.tr("sync") + ":</b> "
It should probably be:

t_csv = (
    "<li><b>" + w.tr("CSV Import") + ":</b> "
    + w.tr("CSV import can now handle 10K+ entries much more smoothly and in a reasonable time.")
    + "</li>"
)
The actual error is the extra quote in t_auth.
The next thing to fix is the broken <ul> structure.

I can tidy this whole release notes block into a cleaner, corrected version if you want.



New Microsoft Word Document (2).zip
Zip Archive
return full funcsion cleaned and working :) heres the readme files for what we done on some part :)  maybe this will help to updated tese parts  ? 


Thought for 17s
Yep — here is the full cleaned function, fixed so it should work properly and read much better.

I also updated the release notes text to match the things in your notes:

Watchtower speed improvements

breach detection/cache fix

background alerts

smarter URL handling

native DLL / DLL-only security core

YubiKey WRAP migration fixes

KDF v2 / stronger Argon2 support

improved sync / sync bundle handling

per-user logging

manual updates / privacy-first behaviour

def _maybe_show_release_notes(w):
    """
    Startup 'What's New' popup for the 01/04/2026 update.
    User can tick 'Don't show again' to hide it for this update.

    To reset later:
        QSettings("AJHSoftware", "KeyquorumVault").remove("hide_release_notes_01-04-2026")
    """
    try:
        settings = QSettings("AJHSoftware", "KeyquorumVault")
        key = "hide_release_notes_01-04-2026"  # change on every release

        # Already dismissed for this update?
        if settings.value(key, False, type=bool):
            return

        # -------------------------------
        # Translatable HTML content
        # -------------------------------
        t_date = "<b>" + w.tr("Date") + ":</b> 01 Apr 2026<br><br>"

        t_header_whatsnew = (
            "<b>" + w.tr("What’s New") + "</b> ("
            + w.tr("new features may contain bugs — please report anything unexpected")
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
                "This update includes new features, security improvements, performance work, and bug fixes."
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

        t_sync = (
            "<li><b>" + w.tr("Sync improvements") + ":</b> "
            + w.tr(
                "Sync is now more reliable. It better handles important companion data, shows clearer sync state, and improves restoring user data between devices, folders, NAS locations, and cloud-backed folders chosen by the user."
            )
            + "</li>"
        )

        t_sync_bundle = (
            "<li><b>" + w.tr("Sync bundle safety") + ":</b> "
            + w.tr(
                "Sync handling has been improved so vault data and related metadata stay together more safely, helping reduce problems caused by partial or mismatched syncs across devices."
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
            + t_windows_notify
            + t_watchtower_perf
            + t_watchtower_breach
            + t_background_alerts
            + t_url_checks
            + t_native
            + t_auth
            + t_yubi
            + t_kdf
            + t_sync
            + t_sync_bundle
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
A couple of quick notes:

this version fixes the broken quote error

removes the duplicate t_sync

fixes the broken <ul> HTML structure

makes the date consistent with 01-04-2026

cleans up wording so it looks much more professional

Also make sure you have the needed imports somewhere in the file:

from qtpy.QtCore import Qt, QSettings
from qtpy.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QStyle,
    QTextBrowser,
    QVBoxLayout,
)
If you want, next I can also make you a shorter, more polished version of these release notes so the popup is easier for users to read.



README.md
File
return updated verson of readme file? 

Nice — your README is already solid. I’ve cleaned it up, tightened wording, and updated it to match your latest release (DLL-only core, Watchtower improvements, sync fixes, etc.) while keeping your tone and structure.

Here’s a clean, updated version you can drop in directly 👇

✅ Updated README.md
# Keyquorum Vault

Offline-first password manager by **AJH Software**.

> ⚠️ Note: The project is currently being refactored and modularised.  
> Folder structure and internal modules may change while this stabilises.

---

## 🔐 Overview

Keyquorum Vault is a **privacy-first, offline password manager** designed with a strict local-only security model.

- No required accounts
- No forced cloud sync
- No telemetry or hidden network activity
- Full local encryption and control

All sensitive data is handled locally using authenticated encryption (**AES-GCM**) and a strong KDF (**Argon2id**).

---

## 🚀 Recent Updates (April 2026)

### 🔒 Security Core
- Native **C++ DLL is now required** for all sensitive operations  
- Improved memory handling and key isolation  
- Removal of Python fallback for cryptographic operations  

### 🔁 Encryption & Rekeying
- Safer migration when:
  - Changing password
  - Updating vault security
  - Enabling/disabling YubiKey WRAP  
- Covers:
  - Vault data
  - Password history
  - Trash store
  - Authenticator store

### 🔐 Vault Security
- Improved Argon2id handling (KDF v2 support)
- Better compatibility with future security upgrades

### 🔑 YubiKey Support
- More reliable WRAP enable/disable flows  
- Improved rekey safety and session handling  

---

### ⚡ Performance

#### Watchtower
- Major performance improvements (large vaults)
- Fixed breach detection issues
- Added smarter caching to reduce repeated checks
- Reduced false positives (e.g. non-URL categories)

#### CSV Import
- Handles **10K+ entries smoothly**
- Improved import speed and UI responsiveness

---

### 🔔 Notifications & Background Tasks
- Windows notifications for:
  - Watchtower changes
  - Reminders
- New background worker:
  - Only alerts on changes (no spam)

---

### 🔄 Sync Improvements
- More reliable sync across:
  - NAS
  - Local folders
  - Cloud-backed folders (user-selected)
- Improved:
  - Sync state visibility
  - Restore on new devices
- Better handling of:
  - Vault
  - Metadata
  - Side stores (trash, history, etc.)

---

### 🌉 Browser Extension Bridge
- Secure **signed local authentication**
- Improved reliability of autofill communication
- Strict localhost-only communication (`127.0.0.1`)

---

### 🧠 Storage Changes
- Salt is now stored in the **identity file**
- Removed separate salt file for:
  - Easier sync
  - Simpler maintenance

---

### 📜 Logging
- Improved per-user logging
- Logs now initialise correctly after login

---

### 🧹 Codebase
- Ongoing refactor:
  - Breaking large files into modules
  - Improving maintainability
- Some areas may still be unstable — feedback welcome

---

## 🧩 What this repository contains

- Desktop application (Qt / PySide6 via `qtpy`)
- Vault encryption & storage logic
- Feature modules:
  - Watchtower
  - Reminders
  - Security Center
  - Sync system
- Background workers

---

## 🛠 Running from source (developer)

This project is packaged using **fbs Pro** for Windows builds, but can be run locally.

### Steps:
1. Create a virtual environment
2. Install dependencies
3. Run the app

---

### 📦 Suggested dependencies

- `PySide6`
- `qtpy`
- `cryptography`
- `argon2-cffi`
- `pyotp`
- `qrcode`
- `reportlab`

Optional:
- `opencv-python` (QR/camera features)
- `pywinauto` (Windows automation)

---

## 📁 Repository layout
python/
app/ # App bootstrap & UI
auth/ # Login, 2FA, YubiKey, device unlock
features/ # Watchtower, reminders, etc.
security/ # Audit, baseline, integrity
vault_store/ # Encryption, storage, import/export
workers/ # Background workers


---

## 🔐 Security Model

Keyquorum is designed as **offline-first**:

- No automatic cloud sync
- No remote servers
- No telemetry
- No hidden background connections

Network activity only occurs when:
- User explicitly opens a link
- Browser extension communicates locally

All encryption is performed locally.

---

## 🧱 Future Architecture

Keyquorum is moving toward a **native security core**:

- Shared C++ "VaultCore"
- Stronger memory isolation
- Cross-platform support (future Android)
- Stable vault format

The current desktop app remains the primary client.

---

## 🔐 Security Direction

All future changes will:

- Be open-source and reviewable
- Avoid hidden network features
- Maintain backward compatibility where possible
- Prioritise user control and transparency

---

## 🌐 Browser Extension

👉 https://github.com/ajhsoftware/Keyquorum-Browser-Extension

Provides secure autofill via local bridge:
- No cloud communication
- No credential storage in extension
- Lock-aware behaviour

---

## ⚖️ License

Licensed under:

**GNU General Public License v3.0 or later (GPL-3.0-or-later)**

See `LICENSE`.

Third-party notices:
`THIRD_PARTY_NOTICES.md`

---

## 💬 Contributing

See `CONTRIBUTING.md`.

---

## 🚨 Security Reporting

Please report vulnerabilities privately.

See `SECURITY.md`.

---

## 🧠 Author

Developed by **AJH Software**  
Solo developer project focused on privacy, security, and local-first design.
