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
"""Browser/URL and bridge helpers extracted from the main window.
This file is part of the Keyquorum Vault codebase.
"""

import sys as _sys
import importlib
from PySide6 import QtCore
import logging
import app.kq_logging as kql
log = logging.getLogger("keyquorum")
import winreg
from app.platform_utils import open_path
from features.url.main_url import open_url
from auth.login.login_handler import get_user_setting, set_user_setting, _canonical_username_ci, get_user_record


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
def launch_or_download(self, link: str, platform_hint: str | None = None):
    """
    Order:
      1) Launch installed exe if present
      2) Try installer (prefer table 'link' if it's a URL), then client's installer (URL or local path)
      3) Open 'page' fallback (vendor/store page)
      4) Finally, try protocols *only if registered* (to avoid jumping to Microsoft Store)
    """
    import os
    import subprocess
    import tempfile
    import urllib.request
    import urllib.error
    from urllib.parse import urlparse

    try:
        from qtpy.QtWidgets import QMessageBox
    except Exception:
        QMessageBox = None

    clients = getattr(self, "CLIENTS", globals().get("CLIENTS", {}))
    aliases = getattr(self, "ALIASES", globals().get("ALIASES", {}))
    def _expand(path: str) -> str:
        return os.path.expanduser(os.path.expandvars(path or ""))

    def _looks_like_binary(url: str) -> bool:
        try:
            pth = urlparse(url).path.lower()
        except Exception:
            pth = (url or "").lower()
        return pth.endswith((".exe", ".msi", ".zip", ".7z"))

    def _is_url(s: str) -> bool:
        return isinstance(s, str) and s.startswith(("http://", "https://", "ms-windows-store://"))

    def _open(target: str) -> None:
        """Best-effort open for URLs, store links, and local paths."""
        if not target:
            return

        # 1) Try helper that can handle local paths + some schemes
        try:
            open_path(target)
            return
        except Exception:
            pass

        # 2) Try URL opener helper
        try:
            open_url(target)
            return
        except Exception:
            pass

        # 3) Final fallback: Qt openUrl (browser / registered handler)
        try:
            from qtpy.QtGui import QDesktopServices
            from qtpy.QtCore import QUrl
            QDesktopServices.openUrl(QUrl(target))
        except Exception:
            pass

    def _protocol_registered(proto_url: str) -> bool:
        """Return True if the URI scheme has a handler (to avoid Store fallback)."""
        if not winreg:
            return False
        try:
            scheme = proto_url.split(":", 1)[0]
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, scheme):
                return True
        except Exception:
            return False

    def _try_installer(installer: str, fallback_page: str | None) -> bool:
        """
        Return True if something was launched/opened; False if next fallback should be tried.
        Supports:
          - local exe/msi paths
          - http(s) direct binaries (download+run)
          - landing URLs (open in browser)
          - ms-windows-store:// deep links (open)
        """
        installer = (installer or "").strip()
        if not installer:
            return False

        # Local path? Run it if it exists.
        if not _is_url(installer):
            try:
                pth = _expand(installer)
                log.debug(f"pth {pth}")
                if pth and os.path.exists(pth):
                    log.debug(f"Open path {pth}")
                    open_path(pth)
                    return True
                return False
            except Exception:
                return False
        # Store deep-link: just open
        if installer.startswith("ms-windows-store://"):
            _open(installer)
            return True

        # Direct binary: download to temp & run
        if installer.startswith(("http://", "https://")) and _looks_like_binary(installer):
            try:
                tmpdir = tempfile.mkdtemp(prefix="kq_dl_")
                filename = os.path.basename(urlparse(installer).path) or "setup.exe"
                dest = os.path.join(tmpdir, filename)
                req = urllib.request.Request(installer, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req) as resp, open(dest, "wb") as f:
                    f.write(resp.read())
                open_path(dest)
                return True
            except urllib.error.HTTPError:
                # CDN blocked: open URL in browser, else page
                try:
                    _open(installer)
                    return True
                except Exception:
                    if fallback_page:
                        _open(fallback_page)
                        return True
                    return False
            except Exception:
                # Fallback: open in browser, else page
                try:
                    _open(installer)
                    return True
                except Exception:
                    if fallback_page:
                        _open(fallback_page)
                        return True
                    return False

        # Not a binary (landing/short link) → open it
        try:
            _open(installer)
            return True
        except Exception:
            if fallback_page:
                _open(fallback_page)
                return True
            return False

    # --- Resolve platform key (normalize, prefer configured CLIENTS aliases) ---
    plat_src = (platform_hint or link or "").strip()

    norm = plat_src.replace("\u00a0", "").replace("\u200b", "").replace("•", "")
    norm = norm.replace("—", "-").replace("–", "-")
    norm_lc = norm.lower().replace(".net", "net").replace(" ", "")

    plat_key = aliases.get(norm_lc, norm_lc)

    # Heuristic fallbacks for common launchers
    if plat_key not in clients:
        if "battle" in norm_lc:
            plat_key = "battlenet"
        elif "ubisoft" in norm_lc or "uplay" in norm_lc:
            plat_key = "uplay"
        elif "steam" in norm_lc:
            plat_key = "steam"
        elif "epic" in norm_lc:
            plat_key = "epic"
        elif "xbox" in norm_lc or "microsoftstore" in norm_lc:
            plat_key = "xbox"

    cdata = clients.get(plat_key)

    if not cdata:
        # If incoming is a URL, open it at least
        if _is_url(plat_src):
            _open(plat_src)
            return
        if _is_url(link):
            _open(link)
            return

        if QMessageBox:
            QMessageBox.warning(
                self,
                self.tr("Not Found"),
                self.tr("No installer or launcher registered for ") + f"'{plat_src or link}' " +
                self.tr("configured in Settings"),
            )
        return

    # --- 1) Already installed? Launch it. ---
    for exe in (_expand(p) for p in cdata.get("exe_paths", ()) if p):
        try:
            if exe and os.path.exists(exe):
                subprocess.Popen([exe])
                return
        except Exception as e:
            try:
                log.info(f"[WARN] Launch failed for {exe}: {e}")
            except Exception:
                pass

    # --- 2) Prepare installer + page fallbacks ---
    client_installer = cdata.get("installer")
    fallback_page = cdata.get("page")  # optional per-entry page

    # Prefer table-provided URL only if it's a URL (never treat random text as installer)
    table_installer = link if _is_url(link) else None

    if not client_installer and not table_installer and not fallback_page and not cdata.get("protocols"):
        if QMessageBox:
            msg = self.tr("No download/open link registered for ") + f"'{plat_key}'"
            QMessageBox.information(self, self.tr("No Installer Found"), msg)
        return

    # Ask before leaving app / downloading
    if QMessageBox:
        msg = (
            f"{plat_key.title()}" +
            self.tr(" is not installed or not configured in Settings ") +
            "→ " + self.tr("General ") + "→ " + self.tr("Catalog. ") +
            self.tr("Open its installer/page now?")
        )
        ans = QMessageBox.question(
            self,
            self.tr("Install / Open"),
            msg,
            QMessageBox.Yes | QMessageBox.No,
        )
        if ans != QMessageBox.Yes:
            return

    try:
        # --- 2a) Try the table link first (if present) ---
        tried_any = False
        if table_installer:
            tried_any = _try_installer(table_installer, fallback_page)

        # --- 2b) Then try the client's installer (URL or local path) ---
        if not tried_any and client_installer:
            tried_any = _try_installer(client_installer, fallback_page)

        # --- 3) Final non-protocol fallback: open the vendor/page (if defined) ---
        if not tried_any and fallback_page:
            _open(fallback_page)
            return

        # --- 4) Only now try protocols, and only if *registered* ---
        if not tried_any:
            for proto in cdata.get("protocols", ()):
                if _protocol_registered(proto):
                    try:
                        _open(proto)
                        return
                    except Exception:
                        pass

        if not tried_any and QMessageBox:
            QMessageBox.warning(self, self.tr("Open Error"),
                                self.tr("Could not open or download the installer/page."))
    except Exception as e:
        log.error(f"install error: {e}")
def open_url_with_warnings(self, raw_url: str) -> None:
    """Open a URL from the vault with HTTPS/HTTP safety prompts."""
    self.reset_logout_timer()
    url = (raw_url or "").strip()
    log.info(f"raw_url {raw_url}")
    if not url:
        QMessageBox.information(
            self,
            self.tr("Open Website"),
            self.tr("No website or URL was found for this entry."),
        )
        return

    # Try to get the current username for per-user suppression flags
    username = ""
    try:
        username = self._active_username()
    except Exception:
        username = ""

    # Small helper so we don't duplicate open logic everywhere
    def _open_final(u: str) -> None:
        try:
            open_url(u)
        except Exception:
            try:
                QDesktopServices.openUrl(QUrl(u))
            except Exception as e:
                QMessageBox.warning(
                    self,
                    self.tr("Open Website"),
                    self.tr("Could not open the browser.\n\nError: {err}").format(err=e),
                )

    # ------------------------
    # Case 1: URL has NO scheme (no 'http://' or 'https://')
    # ------------------------
    if "://" not in url:
        # If user chose "don't show again" before, always add https:// automatically
        try:
            if username and bool(get_user_setting(username, "suppress_url_noscheme_warn", False)):
                final_url = "https://" + url.lstrip("/")
                _open_final(final_url)
                return
        except Exception:
            pass

        from qtpy.QtWidgets import QCheckBox  # already imported elsewhere, but safe

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle(self.tr("Open Website"))

        box.setText(self.tr(
            "This link does not contain 'http://' or 'https://'.\n\n"
            "Because no scheme was provided, the browser will decide how to open it. "
            "Most modern sites will upgrade automatically to HTTPS, but it is not guaranteed.\n\n"
            "If the browser opens this site using HTTP instead of HTTPS, anything you enter "
            "(usernames, passwords or private information) could be visible in clear text.\n\n"
            "You can:\n"
            "  • Open the link exactly as saved\n"
            "  • Add 'https://' before opening (recommended if unsure)\n"
            "  • Cancel and manually check the URL in your browser first\n\n"
            "After opening, always double-check the address bar before entering credentials."
        ))

        btn_as_is = box.addButton(self.tr("Open as saved"), QMessageBox.AcceptRole)
        btn_https = box.addButton(self.tr("Open with HTTPS"), QMessageBox.YesRole)
        btn_cancel = box.addButton(self.tr("Cancel"), QMessageBox.RejectRole)

        cb = QCheckBox(self.tr(
            "Don’t show this again (always add 'https://' automatically)"
        ))
        box.setCheckBox(cb)

        box.setDefaultButton(btn_https)
        box.exec()

        clicked = box.clickedButton()
        dont_show = bool(cb.isChecked()) if cb is not None else False

        if clicked is btn_cancel or clicked is None:
            return

        # If user ticked "don't show again", we always force HTTPS now and in future
        if dont_show:
            final_url = "https://" + url.lstrip("/")
            if username:
                try:
                    set_user_setting(username, "suppress_url_noscheme_warn", True)
                except Exception:
                    pass
        else:
            if clicked is btn_as_is:
                final_url = url
            elif clicked is btn_https:
                final_url = "https://" + url.lstrip("/")
            else:
                return  # safety

        _open_final(final_url)
        return

    # ------------------------
    # Case 2: URL already has a scheme: http://, https://, etc.
    # ------------------------
    qurl = QUrl(url)
    scheme = (qurl.scheme() or "").lower()
    final_url = url

    # --- Explicit http:// → offer HTTPS upgrade OR HTTP (insecure) ---
    if scheme == "http":
        # Build an https:// version to try first
        if url.lower().startswith("http://"):
            https_url = "https://" + url[7:]
        else:
            https_url = "https://" + url

        # If user chose "don't show again" before, always try HTTPS first automatically
        try:
            if username and bool(get_user_setting(username, "suppress_url_http_warn", False)):
                final_url = https_url
                _open_final(final_url)
                return
        except Exception:
            pass

        from qtpy.QtWidgets import QCheckBox  # already imported elsewhere, but safe

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle(self.tr("Insecure Website (no HTTPS)"))

        box.setText(self.tr(
            "Warning: this site uses http:// and is NOT encrypted.\n\n"
            "Anything you send (including usernames, passwords or private "
            "information) can be seen in clear text on the other side.\n\n"
            "Keyquorum Vault can first try to open the site using HTTPS:\n"
            "{https_url}\n\n"
            "If the site does not support HTTPS, your browser or the site "
            "itself may still redirect you back to plain http://.\n"
            "Always double-check the address bar before entering any "
            "credentials or sensitive information.\n\n"
            "How would you like to continue?"
        ).format(https_url=https_url))

        btn_try_https = box.addButton(
            self.tr("Try HTTPS first (recommended)"),
            QMessageBox.YesRole,
        )
        btn_stay_http = box.addButton(
            self.tr("Continue with HTTP (insecure)"),
            QMessageBox.NoRole,
        )
        btn_cancel = box.addButton(
            self.tr("Cancel"),
            QMessageBox.RejectRole,
        )

        cb = QCheckBox(self.tr(
            "Don’t show this again (always try HTTPS automatically)"
        ))
        box.setCheckBox(cb)

        box.setDefaultButton(btn_try_https)
        box.exec()

        clicked = box.clickedButton()
        dont_show = bool(cb.isChecked()) if cb is not None else False

        if clicked is btn_cancel or clicked is None:
            return

        # If user ticked "don't show again", always try HTTPS now and in future
        if dont_show:
            final_url = https_url
            if username:
                try:
                    set_user_setting(username, "suppress_url_http_warn", True)
                except Exception:
                    pass
        else:
            if clicked is btn_try_https:
                final_url = https_url
            elif clicked is btn_stay_http:
                final_url = url
            else:
                return  # safety

    # https or other schemes just pass through unchanged
    _open_final(final_url)


def build_launch_install_menu(self, *args, **kwargs):
    """
    Scroll-friendly menu:
      - Uses user catalog.enc over my_catalog_builtin
      - Each section is a submenu containing a scrollable QListWidget
      - Double-click / Enter on an item calls launch_or_download("", key)
    """
    # --- load effective catalog (user overlay + built-ins)
    import catalog_category.my_catalog_builtin as my_catalog_builtin
    importlib.reload(my_catalog_builtin)
    try:
        from catalog_category.catalog_user import load_effective_catalogs_from_user
        effective = load_effective_catalogs_from_user(
            user_root=getattr(self, "user_root", None),
            user_key=getattr(self, "user_key", None),
            b_clients=my_catalog_builtin.CLIENTS,
            b_aliases=my_catalog_builtin.ALIASES,
            b_guide=my_catalog_builtin.PLATFORM_GUIDE,
        )
        clients = effective.get("CLIENTS", {})
        platform_guide = effective.get("PLATFORM_GUIDE", {})
    except Exception:
        clients = my_catalog_builtin.CLIENTS
        platform_guide = my_catalog_builtin.PLATFORM_GUIDE

    def label_for(key: str) -> str:
        return str(platform_guide.get(key, key))

    def domains(meta: dict) -> str:
        d = meta.get("domains") or ()
        return " ".join(d).lower() if isinstance(d, (list, tuple)) else str(d).lower()

    def classify(key: str, meta: dict) -> str:
        dom = domains(meta)
        if any(s in dom for s in ("steampowered", "epicgames", "ubisoft", "uplay", "gog.com", "riotgames", "valorant", "battle.net", "xbox", "steamcommunity")):
            return "games"
        if any(s in dom for s in ("netflix", "primevideo", "disneyplus", "hbomax", "max.com", "hulu", "youtube", "twitch", "plex", "crunchyroll", "tv.apple", "bbc.co.uk", "nowtv", "paramountplus", "sky.com", "spotify")):
            return "streaming"
        if any(s in dom for s in ("google.com", "chrome.google.com", "microsoft.com", "bing.com", "mozilla.org", "firefox.com", "opera.com", "brave.com", "vivaldi.com", "torproject.org")):
            return "browsers"
        if any(s in dom for s in ("discord.com", "teams.microsoft.com", "zoom.us", "slack.com", "telegram.org", "signal.org", "whatsapp.com", "messenger.com", "facebook.com", "outlook.com", "office.com")):
            return "work"
        if any(s in dom for s in ("onedrive.live.com", "dropbox.com", "drive.google.com", "evernote.com", "notion.so", "obsidian.md", "todoist.com", "atlassian.net", "jira.com", "confluence", "clickup.com", "trello.com", "figma.com", "adobe.com", "getpaint.net", "paintshoppro.com", "painterartist.com", "photomirage.io")):
            return "productivity"
        if any(s in dom for s in ("intel.com", "amd.com", "nvidia.com", "logitechg.com", "logi.com", "corsair.com", "razer.com", "nzxt.com", "msi.com", "asus.com", "rog.asus.com",
                                  "gigabyte.com", "asrock.com", "steelseries.com", "hp.com", "dell.com", "lenovo.com", "realtek.com", "elgato.com", "lian-li.com",
                                  "benchmarks.ul.com", "win-rar.com", "easeus.com")):
            return "utilities"
        return "other"

    sections = {
        "games":        {"title": "🎮 " + self.tr("Game Launchers"),          "items": []},
        "utilities":    {"title": "🧰 " + self.tr("PC Utilities / Drivers"),   "items": []},
        "streaming":    {"title": "📺 " + self.tr("Streaming / Entertainment"),"items": []},
        "browsers":     {"title": "🌐 " + self.tr("Browsers"),                 "items": []},
        "work":         {"title": "💬 " + self.tr("Communication / Work"),     "items": []},
        "productivity": {"title": "🗂️ " + self.tr("Cloud / Productivity"),     "items": []},
        "other":        {"title": "📦 " + self.tr("Other"),                    "items": []},
    }

    for key, meta in clients.items():
        sections[classify(key, meta)]["items"].append((label_for(key), key))
    for s in sections.values():
        s["items"].sort(key=lambda x: x[0].lower())

    # ---- menu + helpers ------------
    menu = QMenu(self.launch_download)
    menu.setSeparatorsCollapsible(False)

    # Top: use selected row
    act_from_row = menu.addAction(self.tr("Use Selected Row (Install / Open)"))
    def _use_selected_row():
        try:
            idx = self.vaultTable.currentIndex()
            if not idx.isValid():
                try: self.toast(self.tr("No selection"), self.tr("Select a row first."))
                except Exception: pass
                return
            row = idx.row()
            entry = {}
            for col in range(self.vaultTable.columnCount()):
                header = self.vaultTable.horizontalHeaderItem(col)
                key = (header.text() if header else f"Column {col}").strip()
                item = self.vaultTable.item(row, col)
                entry[key] = (item.text().strip() if item and item.text() else "")
            self.launch_or_download(entry.get("Install Link", ""), entry.get("Platform", ""))
        except Exception as e:
            log.info("Launch-from-row error:", e)
    act_from_row.triggered.connect(_use_selected_row)

    menu.addSeparator()

    def add_scrollable_submenu(parent_menu: QMenu, title: str, items: list[tuple[str, str]]):
        """
        Create a submenu that contains a search box + scrollable list of items.
        Each item -> calls launch_or_download("", key)
        """
        if not items:
            return
        sub = parent_menu.addMenu(title)

        # Container widget (search + list)
        container = QWidget()
        v = QVBoxLayout(container); v.setContentsMargins(8, 8, 8, 8); v.setSpacing(6)

        search = QLineEdit(); search.setPlaceholderText(self.tr("Search…"))
        lst = QListWidget()
        lst.setUniformItemSizes(True)
        lst.setVerticalScrollMode(QListWidget.ScrollPerPixel)
        lst.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        lst.setMinimumWidth(280)
        lst.setFixedHeight(320)  # <-- controls visible height (scroll inside)
        for label, key in items:
            it = QListWidgetItem(label)
            it.setData(QtCore.Qt.UserRole, key)
            lst.addItem(it)

        def activate_current(item: QListWidgetItem = None):
            it = item or lst.currentItem()
            if not it:
                return
            key = it.data(QtCore.Qt.UserRole)
            # Close all menus before launching
            parent_menu.close()
            sub.close()
            self.launch_or_download("", key)

        lst.itemActivated.connect(activate_current)   # Enter/click
        lst.itemClicked.connect(activate_current)

        # simple filter
        def _filter(text: str):
            t = (text or "").lower().strip()
            for i in range(lst.count()):
                it = lst.item(i)
                it.setHidden(t not in it.text().lower())
        search.textChanged.connect(_filter)

        v.addWidget(search)
        v.addWidget(lst)

        wa = QWidgetAction(sub)
        wa.setDefaultWidget(container)
        sub.addAction(wa)

    # Add sections as scrollable submenus
    for key in ("games", "utilities", "streaming", "browsers", "work", "productivity", "other"):
        sec = sections.get(key)
        if sec and sec["items"]:
            add_scrollable_submenu(menu, sec["title"], sec["items"])

    # attach to button
    self.launch_download.setMenu(menu)
    self.launch_download.setPopupMode(QToolButton.MenuButtonPopup)
    self.launch_download.setDefaultAction(act_from_row)

# help note


def open_forgot_password_dialog(self, *args, **kwargs):
    log.debug(str(f"{kql.i('ui')} [UI OPEN] Opening Forgot Password Dialog"))

    username = (self.usernameField.text() or "").strip()
    if not username:
        self.safe_messagebox_warning(self, self.tr("Missing Username"), self.tr("Please enter your username first."))
        return

    # Map to canonical folder name (case-insensitive) if available
    try:
        username = _canonical_username_ci(username) or username
    except Exception:
        pass

    # Load the per-user record (NOT a global dict)
    try:
        rec = get_user_record(username)
    except Exception as e:
        log.error(str(f"{kql.i('ui')} [ERROR] {kql.i('err')} Could not read user record: {e}"))
        QMessageBox.critical(self, self.tr("Error"), self.tr("Could not read the user record."))
        return

    if not isinstance(rec, dict) or not rec:
        self.safe_messagebox_warning(
            self,
            self.tr("Invalid User"),
            self.tr("Username '{username1}' not found.").format(username1=username),
        )
        log.debug(str(f"{kql.i('ui')} [UI OPEN] {kql.i('err')} Invalid User {username}"))
        return

    # Respect maximum-security accounts (no recovery allowed)
    if not rec.get("recovery_mode", False):
        self.safe_messagebox_warning(
            self,
            self.tr("Recovery Mode"),
            self.tr("🔐 Maximum Security Account — recovery is not available."),
        )
        log.debug(str(f"{kql.i('ui')} [UI OPEN] {kql.i('ok')} Maximum Security — recovery not available"))
        return


    # ✅ Header-based capability check (no wrapped-key file required)
    try:
        from auth.identity_store import get_public_header
        hdr = get_public_header(username) or {}
         # --- 0a) Block recovery only for WRAP mode -----------------------
        yubi_mode = None
        try:
            if hdr["meta"].get("yubi_enabled"):
                yubi_mode = hdr["meta"].get("yubi_mode")
        except Exception:
            pass
        # Only WRAP is forbidden; GATE is allowed
        if yubi_mode == "yk_hmac_wrap":
            try:
                QMessageBox.warning(
                    self,
                    self.tr("YubiKey Enabled"),
                    (
                        self.tr("This account is protected by YubiKey WRAP.\n\n"
                        "Forgot Password recovery is disabled for WRAP mode.\n"
                        "You can still use your Recovery Key to remove YubiKey if it is lost,\n"
                        "but not to reset a forgotten password.\n\n"
                        "To change your password, plug in your YubiKey, log in normally,\n"
                        "and use the in-app \"Change Password\" option.")
                    ),
                )
            except Exception:
                pass
            return log.info("YubiKey WRAP account: Forgot Password is disabled.")


        mkhash = ((hdr.get("meta") or {}).get("mk_hash_b64") or "").strip()
    except Exception:
        mkhash = ""

    if not mkhash:
        # Legacy identity or mirror not written yet — warn but continue.
        log.warning("[RECOVERY] mk_hash_b64 missing for %s; continuing to Forgot Password dialog.", username)


    # ✅ Launch the dialog with username prefilled
    from auth.change_pw.forgot_password_dialog import ForgotPasswordDialog
    dlg = ForgotPasswordDialog(username_prefill=username, parent=self)
    self._track_window(dlg)
    dlg.exec()

# --- open delete account dialog (wrapper) ---

