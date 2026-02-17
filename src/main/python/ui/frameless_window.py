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

from PySide6.QtCore import Qt, QPoint, QEvent, QTimer
from PySide6.QtGui import QMouseEvent, QColor
from PySide6.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QLabel, QMainWindow,
    QMenu, QSpacerItem, QSizePolicy, QGraphicsDropShadowEffect, QToolButton
)
import webbrowser
# --- password gen ---
from auth.pw.password_generator import show_password_generator_dialog
from features.url.main_url import (SITE_MAIN, SITE_HELP, SITE_SUPPORT, SITE_SUPPORT_ME, PRIVACY_POLICY,
                    SITE_ANDROID, SITE_LINUX, SITE_VIDEO, SITE_SEC, SITE_THREAT, SITE_BUG_FIX,
                    SITE_CATALOG, SITE_BROWSER, SITE_BROW_TEST, REDDIT, CATEGORY_DOWN,WATCH)

from qtpy.QtCore import QCoreApplication
import datetime

def _tr(text: str) -> str:
    return QCoreApplication.translate("frameless_window", text)

# ==============================
# Credits helpers
# ==============================
import os
import json
import logging

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QVBoxLayout,
    QTextBrowser,
)
from PySide6.QtCore import Qt
try:
    from fbs_runtime.application_context.qtpy import ApplicationContext
    # Attempt to get app version from fbs build settings. If this fails, fallback below.
    APP_VERSION = ApplicationContext().build_settings.get('version', 'dev')
except Exception:
    # In dev mode or if ApplicationContext is unavailable, fall back to a hard-coded version string.
    APP_VERSION = "1.5.6"

# ---------------------------------
# Static credits list (grouped by section)
# ---------------------------------
SPECIAL_THANKS: dict[str, list[str]] = {
     _tr("Testers & Early Users"): [
        _tr("Testers and early users of Keyquorum Vault"),
        _tr("People who reported bugs and rough edges"),
    ],
     _tr("Community & Feedback"): [
        _tr("Reddit and wider security communities"),
        _tr("Friends who gave honest UI/UX feedback"),
    ],
     _tr("Open Source & Tools"): [
        _tr("Qt / PySide6 ecosystem"),
        _tr("Python and its amazing package authors"),
        _tr("Open-source crypto, security, UI, and utility libraries that power this application"),
    ],
     _tr("AI Assistance"): [
        _tr("ChatGPT (OpenAI) — wording help, ideas, code suggestions, and security check & improvement"),
       _tr("Claude (Anthropic) — comprehensive security audit, GPL licensing review, GitHub preparation, and encryption analysis"),
    ],
}

# add direct or append: 
# SPECIAL_THANKS["Testers & Early Users"].append("Jane Doe – regression testing")
# # or
# SPECIAL_THANKS["AI Assistance"].append("Another AI tool if you ever use one")
# # or create a new section:
# SPECIAL_THANKS["Partners"] = ["Some Company Ltd — co-marketing"]

def load_special_thanks() -> dict[str, list[str]]:
    """
    Return the grouped special thanks data.
    """
    return {section: names[:] for section, names in SPECIAL_THANKS.items()}


# ---------------------------------
# Credits dialog (scrollable)
# ---------------------------------

class CreditsDialog(QDialog):
    def __init__(self, parent=None, app_version: str = APP_VERSION):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Keyquorum Vault — Credits"))
        self.resize(600, 500)

        layout = QVBoxLayout(self)

        self.text_browser = QTextBrowser(self)
        self.text_browser.setOpenExternalLinks(True)
        self.text_browser.setTextInteractionFlags(
            Qt.TextSelectableByMouse | Qt.LinksAccessibleByMouse
        )

        html = self.build_credits_html(app_version=APP_VERSION)
        self.text_browser.setHtml(html)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok, parent=self)
        buttons.accepted.connect(self.accept)

        layout.addWidget(self.text_browser)
        layout.addWidget(buttons)

    def build_credits_html(self, app_version: str = "1.0.0") -> str:
        """
        Build the full HTML body for the Credits window,
        combining static text with grouped special thanks.
        """
        grouped = load_special_thanks()

        # Build dynamic "Special Thanks" HTML from sections
        if grouped:
            parts: list[str] = []
            for section, names in grouped.items():
                if not names:
                    continue
                items_html = "".join(f"<li>{name}</li>" for name in names)
                # 'section' values come from data; leave as-is or localise at source
                parts.append(f"<h4>{section}</h4><ul>{items_html}</ul>")
            special_html = "\n".join(parts)
        else:
            special_html = "<i> " + self.tr("No additional names listed yet.") + "</i>"

        # Translatable chunks
        title =  self.tr("Keyquorum Vault — Credits")
        label_version =  self.tr("Version:")

        h_author =  self.tr("Author / Owner")
        author_line =  self.tr("Anthony Hatton (trading as ") + "<b>AJH Software</b>)"
        website_label =  self.tr("Website:")

        h_dev_support =  self.tr("Development &amp; Support")
        dev_para =  self.tr("Design, coding, testing, documentation, security hardening, ") +  self.tr("and support by ") + "Anthony Hatton.<br>" +  self.tr("Keyquorum Vault has also been developed with extensive assistance from") + "<b>" +  self.tr("ChatGPT (OpenAI)") + " </b> " +  self.tr(" for wording, ideas, and code suggestions.")
    

        h_feedback_libs =  self.tr("Feedback, Open Source &amp; Libraries")
        feedback_para =  self.tr(
            "This app stands on the shoulders of open-source software and community "
            "feedback. Thank you to everyone who helped shape it."
        )

        h_special =  self.tr("Special Thanks")
        special_intro =  self.tr(
            "The following people, tools, and communities have provided "
            "feedback, testing, or inspiration:"
        )

        # Final HTML
        html = f"""<h2>{title}</h2>
    <p><b>{label_version}</b> {app_version}</p>

    <h3>{h_author}</h3>
    <p>
      {author_line}<br>
      {website_label}
      <a href="https://www.ajhsoftware.uk">https://www.ajhsoftware.uk</a>
    </p>

    <h3>{h_dev_support}</h3>
    <p>
      {dev_para}
    </p>

    <h3>{h_feedback_libs}</h3>
    <p>
      {feedback_para}
    </p>

    <h3>{h_special}</h3>
    <p>
      {special_intro}
    </p>
    {special_html}
    """
        return html

# ==============================
# --- Main Window
# ==============================

class FramelessWindowMixin:
    _drag_pos: QPoint | None = None
    _radius = 0  # square edges

    def _init_frameless(self: QMainWindow, title_text: str = "App",
                        use_translucency: bool = False, glow: bool = False):
        if getattr(self, "_frameless_inited", False):
            try:
                self.refresh_frameless_theme()
            except Exception:
                pass
            return

        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground, bool(use_translucency))

        self._outer = QWidget(self)
        self._outer.setObjectName("OuterHost")
        self._inner = QWidget(self._outer)
        self._inner.setObjectName("InnerRounded")

        self.titleBar = QWidget(self._inner)
        self.titleBar.setObjectName("TitleBar")
        self.titleBar.setFixedHeight(40)

        self.btnMenu = QToolButton(self.titleBar)
        self.btnMenu.setObjectName("BtnMenu")
        self.btnMenu.setText("☰")
        self.btnMenu.setFixedSize(36, 28)
        self.btnMenu.setToolButtonStyle(Qt.ToolButtonTextOnly)
        self.btnMenu.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)

        self.lblTitle = QLabel(title_text, self.titleBar)
        self.lblTitle.setObjectName("TitleText")

        self.btnMin  = QPushButton("–", self.titleBar)
        self.btnMin.setObjectName("BtnMin");  self.btnMin.setFixedSize(36, 28)
        self.btnMax  = QPushButton("□", self.titleBar)
        self.btnMax.setObjectName("BtnMax");  self.btnMax.setFixedSize(36, 28)
        self.btnClose= QPushButton("✕", self.titleBar)
        self.btnClose.setObjectName("BtnClose"); self.btnClose.setFixedSize(36, 28)

        tb = QHBoxLayout(self.titleBar)
        tb.setContentsMargins(8, 6, 8, 6)
        tb.setSpacing(6)
        tb.addWidget(self.btnMenu)
        tb.addWidget(self.lblTitle)
        tb.addItem(QSpacerItem(10, 10, QSizePolicy.Expanding, QSizePolicy.Minimum))
        tb.addWidget(self.btnMin)
        tb.addWidget(self.btnMax)
        tb.addWidget(self.btnClose)

        old_central = QMainWindow.takeCentralWidget(self)
        if old_central is None:

            old_central = QWidget(self)
        inner_layout = QVBoxLayout(self._inner)
        inner_layout.setContentsMargins(0, 0, 0, 0)
        inner_layout.addWidget(self.titleBar)
        inner_layout.addWidget(old_central)

        outer_layout = QVBoxLayout(self._outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(self._inner)
        QMainWindow.setCentralWidget(self, self._outer)

        # Build the menu
        self._build_menu()

        # Window control connections
        self.btnMin.clicked.connect(self.showMinimized)
        self.btnMax.clicked.connect(self._toggle_max_restore)
        self.btnClose.clicked.connect(self.close)

        # Optional shadow
        if glow and use_translucency:
            shadow = QGraphicsDropShadowEffect(self._inner)
            shadow.setBlurRadius(28)
            shadow.setOffset(0, 8)
            c = self.palette().shadow().color(); c.setAlpha(140)
            shadow.setColor(c)
            self._inner.setGraphicsEffect(shadow)

        self.refresh_frameless_theme()
        self._frameless_inited = True

    # --------------- creadits --------------
    def show_credits_popup(self) -> None:
        """Open the scrollable Credits dialog."""
        if hasattr(self, "reset_logout_timer"):
            self.reset_logout_timer()

        dlg = CreditsDialog(self, app_version=APP_VERSION)
        dlg.exec()

    def show_about_dialog(self):
        # Gather status text
        edition = self.tr("Free")
        summary = {}
        try:
            if getattr(self, "lic_service", None):
                summary = self.lic_service.summary or {}
        except Exception:
            pass
        if not summary and getattr(self, "lic", None):
            try: summary = self.lic.status_summary(check_now=False) or {}
            except Exception: pass

        ver = getattr(self, "app_version", None) or getattr(QCoreApplication.instance(), "applicationVersion", lambda: "")()
        ver = ver() if callable(ver) else ver
        ver = ver or "unknown"

        year = datetime.datetime.now().strftime('%Y')

        title = self.tr("Keyquorum Vault")
        version_label = self.tr("Version:")
        copyright_line = f"© {year} Anthony Hatton. " + self.tr("Licensed under the GNU GPL-3.0.")
        qt_notice = "Qt® " + self.tr("is a registered trademark of The Qt Company Ltd.")

        links_title = self.tr("Links")
        website_label = self.tr("Website")
        support_label = self.tr("Support")
        open_licenses_label = self.tr("Open Licenses Folder")
        open_logs_label = self.tr("Open Logs Folder")

        oss_notice_1 = self.tr("This product includes open-source software. License notices and full texts " + 
            self.tr("are available in Menu ") + "→" + self.tr("Show Licenses and in the ") + "<b>" + self.tr("licenses") + "/</b>" + self.tr(" folder.")
        )
        oss_notice_2 = self.tr(
            "Keyquorum Vault is licensed under the GNU GPL-3.0.<br>"
            "This product uses PySide6 (Qt for Python), which is licensed under LGPL-3.0-only.<br>"
            "In accordance with the LGPL, you may replace the LGPL-covered libraries with compatible versions."
        )
        text = (
            f"<b>{title}</b><br>"
            f"{version_label} {ver}<br>"
            f"{copyright_line.format(year=year)}<br><br>"
            f"{qt_notice}<br><br>"
            f"<b>{links_title}</b><br>"
            f"• <a href=\"https://www.ajhsoftware.uk\">{website_label}</a><br>"
            f"• <a href=\"https://forms.gle/118nQkUeV5cZyFj27\">{support_label}</a><br>"
            f"• <a href=\"app:open_licenses\">{open_licenses_label}</a><br>"
            f"• <a href=\"app:open_logs\">{open_logs_label}</a><br><br>"
            f"{oss_notice_1}<br>"
            f"{oss_notice_2}"
        )


        dlg = QDialog(self)
        dlg.setWindowTitle(self.tr("About Keyquorum"))
        lay = QVBoxLayout(dlg)

        lab = QLabel(text, dlg)
        lab.setTextFormat(Qt.RichText)  
        lab.setOpenExternalLinks(False)
        lab.linkActivated.connect(self._about_link_handler)
        
        lay.addWidget(lab)

        # Close button
        btns = QHBoxLayout()
        btns.addStretch(1)
        btn_close = QPushButton(self.tr("Close"), dlg)
        btn_close.clicked.connect(dlg.accept)
        btns.addWidget(btn_close)
        lay.addLayout(btns)

        dlg.resize(460, 260)
        dlg.exec_()


    # ---------------- MENU -----------------
    def _build_menu(self):
        """Builds the ☰ popup menu and connects each item."""
        self._mainMenu = QMenu(self)
        self._mainMenu.setObjectName("MainMenu")

        # Helper to add clickable entries
        def add_entry(label, func=None, url=None):
            act = self._mainMenu.addAction(label)
            if func:
                act.triggered.connect(func)
            elif url:
                act.triggered.connect(lambda: webbrowser.open(url))
            return act
        add_entry("🔒 " + self.tr("Password Generator"), self.open_generator)
        self._mainMenu.addSeparator()
        add_entry("🏠 " + self.tr("AJH Software"), url=SITE_MAIN)
        add_entry("📱 " + self.tr("Android (Soon)"), url=SITE_ANDROID)  # or SITE_MAIN
        add_entry("📱 " + self.tr("Watch Auth (Soon)"), url=WATCH)      # or SITE_MAIN
        add_entry("🐧 " + self.tr("Linux (Soon)"), url=SITE_LINUX)      # or SITE_MAIN
        self._mainMenu.addSeparator()
        add_entry("💡 " + self.tr("Help / Feedback"), url=SITE_HELP)
        add_entry("💡 " + self.tr("Help (Videos)"), url=SITE_VIDEO)
        add_entry("🐞 " + self.tr("Bugs / Fixes"), url=SITE_BUG_FIX)
        add_entry("💡 " + self.tr("Catalog Help"), url=SITE_CATALOG)
        add_entry("💡 " + self.tr("Reddit (Support)"), url=REDDIT)
        add_entry("💡 " + self.tr("Form (Support)"), url=SITE_SUPPORT)
        self._mainMenu.addSeparator()
        add_entry("🔒 " + self.tr("Privacy Policy"), url=PRIVACY_POLICY)
        add_entry("🔒 " + self.tr("Security & Privacy Guide"), url=SITE_SEC)
        add_entry("🔒 " + self.tr("Threat Model"), url=SITE_THREAT)
        self._mainMenu.addSeparator()
        add_entry("🌐 " + self.tr("Browser Extension Help"), url=SITE_BROWSER)
        add_entry("🌐 " + self.tr("Browser Test Page"), url=SITE_BROW_TEST)
        add_entry("🌐 " + self.tr("Download language category"), url=CATEGORY_DOWN)
        self._mainMenu.addSeparator()
        add_entry("🧾 " + self.tr("Open Logs"), func=lambda: getattr(self, "open_logs_folder", lambda: None)())
        add_entry("📂 " + self.tr("Open Licenses"), func=lambda: getattr(self, "open_licenses_folder", lambda: None)())
        self._mainMenu.addSeparator()
        add_entry("ℹ️ " + self.tr("credits"), func=lambda: getattr(self, "show_credits_popup", lambda: None)())
        add_entry("ℹ️ " + self.tr("About"), func=lambda: getattr(self, "show_about_dialog", lambda: None)())
        self._mainMenu.addSeparator()
        add_entry("❤️ " + self.tr("Support Me"), url=SITE_SUPPORT_ME)

        self._mainMenu.addSeparator()
        # Attach + keep reference
        self.btnMenu.setMenu(self._mainMenu)
        self.btnMenu.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)

    # ---------------- BEHAVIOR -----------------
    def _in_titlebar(self, pos_in_window):
        """
        Return True if the mouse position is somewhere inside the title bar.

        We do this by asking which child widget is under the cursor and then
        walking up its parents until we either hit the titleBar or run out.
        This avoids any coordinate-space issues between self and _inner.
        """
        if not hasattr(self, "titleBar") or self.titleBar is None:
            return False

        w = self.childAt(pos_in_window)
        while w is not None:
            if w is self.titleBar:
                return True
            w = w.parentWidget()
        return False


    def _hit_titlebar_control(self, pos_in_window):
        w = self.childAt(pos_in_window)
        controls = {self.btnMenu, self.btnMin, self.btnMax, self.btnClose}
        if w in controls:
            return True
        return getattr(w, "parent", lambda: None)() in controls

    def mousePressEvent(self, e: QMouseEvent):
        p = e.position().toPoint()
        if (e.button() == Qt.LeftButton
                and self._in_titlebar(p)
                and not self._hit_titlebar_control(p)):
            self._drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()
            e.accept()
        else:
            self._drag_pos = None
            super().mousePressEvent(e)

    def mouseMoveEvent(self, e: QMouseEvent):
        if self._drag_pos and e.buttons() & Qt.LeftButton:
            self.move(e.globalPosition().toPoint() - self._drag_pos)
            e.accept()
        else:
            super().mouseMoveEvent(e)

    def mouseReleaseEvent(self, e: QMouseEvent):
        self._drag_pos = None
        super().mouseReleaseEvent(e)

    def mouseDoubleClickEvent(self, e: QMouseEvent):
        p = e.position().toPoint()
        if self._in_titlebar(p) and not self._hit_titlebar_control(p):
            self._toggle_max_restore()
            e.accept()
        else:
            super().mouseDoubleClickEvent(e)

    def _toggle_max_restore(self):
        if self.isMaximized():
            self.showNormal()
            self.btnMax.setText("□")
        else:
            self.showMaximized()
            self.btnMax.setText("❐")

    # ---------------- STYLE -----------------
    def refresh_frameless_theme(self):
        border = QColor(self.palette().mid().color())
        border.setAlpha(60)
        rgba = f"rgba({border.red()},{border.green()},{border.blue()},{border.alpha()})"

        self.setStyleSheet(f"""
            QMainWindow {{
                border: 1px solid {rgba};
                border-radius: 0px;
                background-color: transparent;
            }}
            #InnerRounded {{
                border-radius: 0px;
                background: transparent;
            }}
            #TitleBar {{
                background: palette(window);
                border-bottom: 1px solid palette(mid);
            }}
            #TitleText {{
                color: palette(windowText);
                font-weight: 600;
            }}
            QToolButton#BtnMenu,
            QPushButton#BtnMin,
            QPushButton#BtnMax,
            QPushButton#BtnClose {{
                border: none; background: transparent; border-radius: 6px; font-size: 16px;
            }}
            QToolButton#BtnMenu:hover,
            QPushButton#BtnMin:hover,
            QPushButton#BtnMax:hover {{
                background: rgba(255,255,255,0.10);
            }}
            QPushButton#BtnClose:hover {{ background: rgba(255,0,0,0.20); }}
            QToolButton#BtnMenu::menu-indicator {{ image: none; width: 0; }}
        """)

    def open_generator(self):  
        self.set_status_txt(self.tr("Opening Password Generator"))
        return show_password_generator_dialog(target_field=None, confirm_field=None)
