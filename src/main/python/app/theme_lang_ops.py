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
"""Theme and language application/persistence helpers."""

# This module contains methods extracted from main.py to reduce file size.
# We intentionally "inherit" main module globals so the moved code can run unchanged.
import sys as _sys
import app.kq_logging as kql
import logging
log = logging.getLogger("keyquorum")


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

def apply_theme2(self, theme: str, persist: bool = True):
    self.set_status_txt(self.tr("Setting theme please wait"))
    QApplication.processEvents()  
    # --- Idempotent guard (prevents unnecessary re-apply + visual hiccups)
    if getattr(self, "_current_theme", None) == theme:
        return
    self._current_theme = theme

    self.reset_logout_timer()
    try:
        log.debug(str(f"{kql.i('theme')} [SETTINGS] {kql.i('ui')} apply_theme called with theme: {theme}"))
    except Exception:
        pass

    app = QApplication.instance()
    if not app:
        return

    # --- No-flicker guard while changing palette/stylesheet
    prev_updates = self.updatesEnabled()
    self.setUpdatesEnabled(False)
    try:
        # --- Normalize legacy labels + handle System Default ---
        t = (theme or "").strip()
        legacy_alias = {
            "Blue Mode":   "Light Blue (Color)",
            "Gray Mode":   "Light Gray (Color)",
            "Purple Mode": "Light Purple (Color)",
            "Green Mode":  "Light Green (Color)",
        }
        t = legacy_alias.get(t, t)

        if t == "System Default":
            app.setStyleSheet("")
            self.setStyleSheet("")
            app.setPalette(QPalette())
            if self.centralWidget(): self.centralWidget().update()
            self.update()

            # Sync native title bar to current palette
            try:
                pal_now = app.palette()
                cap = pal_now.color(QPalette.ColorRole.Window)
                txt = pal_now.color(QPalette.ColorRole.WindowText)
                dark_guess = _luma(cap) < 128
                if hasattr(self, "set_win_titlebar"):
                    self.set_win_titlebar(
                        self,
                        dark=dark_guess,
                        caption_rgb=(cap.red(), cap.green(), cap.blue()),
                        text_rgb=(txt.red(), txt.green(), txt.blue())
                    )
            except Exception:
                pass

            if persist:
                self._persist_theme_choice(t)

        # ---------------- base setup for themed modes ----------------
        app.setStyle("Fusion")
        app.setStyleSheet("")
        self.setStyleSheet("")
        pal = QPalette()

        # ---------- helpers ----------
        def _light_base(text=QColor(0, 0, 0)):
            pal.setColor(QPalette.ColorRole.Window, QColor(255, 255, 255))
            pal.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
            pal.setColor(QPalette.ColorRole.AlternateBase, QColor(245, 245, 245))
            pal.setColor(QPalette.ColorRole.Text, text)
            pal.setColor(QPalette.ColorRole.WindowText, text)
            pal.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
            pal.setColor(QPalette.ColorRole.ButtonText, text)
            pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 255))
            pal.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 0, 0))
            pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(0, 0, 0, 128))

        def _dark_base():
            pal.setColor(QPalette.ColorRole.Window, QColor(45, 45, 45))
            pal.setColor(QPalette.ColorRole.Base, QColor(34, 34, 34))
            pal.setColor(QPalette.ColorRole.AlternateBase, QColor(48, 48, 48))
            pal.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
            pal.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
            pal.setColor(QPalette.ColorRole.Button, QColor(58, 58, 58))
            pal.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
            pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 255))
            pal.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 0, 0))
            pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(200, 200, 200, 160))

        def _accent_rgb(name: str) -> QColor:
            name = name.lower().strip()
            table = {
                "blue":   QColor(0x19, 0x76, 0xD2),
                "purple": QColor(0x7E, 0x57, 0xC2),
                "green":  QColor(0x43, 0xA0, 0x47),
                "teal":   QColor(0x00, 0x9A, 0xA7),
                "orange": QColor(0xFB, 0x8C, 0x00),
                "pink":   QColor(0xD8, 0x3C, 0x8D),
                "gray":   QColor(0x5F, 0x63, 0x68),
            }
            return table.get(name, QColor(53, 132, 228))  # default blue

        def _inputs_qss(accent: QColor, dark: bool) -> str:
            sel_text = "#000000" if (0.2126*accent.red() + 0.7152*accent.green() + 0.0722*accent.blue()) > 150 and not dark else "#ffffff"
            border = "#3a3a3a" if dark else "#cfd6e4"
            bg     = "#222222" if dark else "#ffffff"
            fg     = "#ffffff" if dark else "#000000"
            return f"""
            QLabel {{ background: transparent; }}
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox,
            QDateEdit, QTimeEdit, QDateTimeEdit, QComboBox, QListView, QTableView, QTreeView {{
                background: {bg};
                color: {fg};
                border: 1px solid {border};
                border-radius: 4px;
                selection-background-color: {accent.name()};
                selection-color: {sel_text};
            }}
            QComboBox QAbstractItemView {{
                selection-background-color: {accent.name()};
                selection-color: {sel_text};
            }}
            """

        def _qss_rgba(c: QColor, alpha_float: float) -> str:
            a = max(0, min(255, int(alpha_float * 255)))
            return f"rgba({c.red()},{c.green()},{c.blue()},{a})"

        def _luma(c: QColor) -> float:
            return 0.2126 * c.red() + 0.7152 * c.green() + 0.0722 * c.blue()

        def _button_qss(accent: QColor, dark_base: bool) -> str:
            def _lm(cc): return 0.2126*cc.red() + 0.7152*cc.green() + 0.0722*cc.blue()
            txt_on_accent = QColor(255, 255, 255) if _lm(accent) < 150 else QColor(0, 0, 0)
            normal = accent if not dark_base else accent.darker(115)
            hover  = accent.lighter(115)
            press  = accent.darker(125)
            border = accent.darker(120) if not dark_base else accent.lighter(120)
            dis_bg = QColor(210,210,210) if not dark_base else QColor(70,70,70)
            dis_tx = QColor(120,120,120) if not dark_base else QColor(180,180,180)

            return f"""
            QPushButton, QToolButton {{
                background-color: {normal.name()};
                color: {txt_on_accent.name()};
                border: 1px solid {border.name()};
                border-radius: 6px;
                padding: 6px 12px;
            }}
            QPushButton:hover, QToolButton:hover {{ background-color: {hover.name()}; }}
            QPushButton:pressed, QToolButton:pressed {{ background-color: {press.name()}; }}
            QPushButton:disabled, QToolButton:disabled {{
                background-color: {dis_bg.name()};
                color: {dis_tx.name()};
                border-color: {dis_bg.name()};
            }}
            QToolButton::menu-button {{
                border: none;
                width: 16px;
                background: transparent;
                margin: 0px;
            }}
            QMenu {{
                border: 1px solid {border.name()};
                border-radius: 6px;
                padding: 4px;
                {"background:#2b2b2b; color:#ffffff;" if dark_base else "background:#ffffff; color:#000000;"}
            }}
            QMenu::item {{
                padding: 6px 14px;
                border-radius: 4px;
            }}
            QMenu::item:selected {{
                background: {hover.name()};
                color: {txt_on_accent.name()};
            }}
            QMenu::separator {{
                height: 1px;
                margin: 6px 8px;
                {"background:#444;" if dark_base else "background:#ddd;"}
            }}
            """

        def _apply_light_with_accent(accent: QColor, strength: str):
            _light_base()
            pal.setColor(QPalette.ColorRole.Highlight, accent)
            pal.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
            pal.setColor(QPalette.ColorRole.Link, accent)
            pal.setColor(QPalette.ColorRole.LinkVisited, accent.darker(120))
            app.setPalette(pal)

            alpha = {"light": 0.05, "color": 0.09, "deep": 0.13}.get(strength, 0.09)
            card_bg = _qss_rgba(accent, alpha)
            app.setStyleSheet(
                f"""
                QGroupBox{{border:1px solid #d9dee7; background:{card_bg}; margin-top:8px; border-radius:6px;}}
                QGroupBox::title{{left:8px; padding:0 4px; background:transparent;}}
                QTabWidget::pane{{border:1px solid #d9dee7;}}
                QScrollArea, QFrame, QWidget#centralwidget{{background:#ffffff;}}
                {_button_qss(accent, dark_base=False)}
                {_inputs_qss(accent, dark=False)}
                """
            )

        def _apply_dark_with_accent(accent: QColor, strength: str):
            _dark_base()
            hl = accent.lighter(120)
            pal.setColor(QPalette.ColorRole.Highlight, hl)
            pal.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
            pal.setColor(QPalette.ColorRole.Link, hl)
            pal.setColor(QPalette.ColorRole.LinkVisited, hl.darker(120))
            app.setPalette(pal)

            alpha = {"light": 0.08, "color": 0.14, "deep": 0.22}.get(strength, 0.14)
            card_bg = _qss_rgba(accent, alpha)
            app.setStyleSheet(
                f"""
                QGroupBox{{border:1px solid #444; background:{card_bg}; margin-top:8px; border-radius:6px;}}
                QGroupBox::title{{left:8px; padding:0 4px; background:transparent; color:#fff;}}
                QTabWidget::pane{{border:1px solid #444;}}
                {_button_qss(accent, dark_base=True)}
                {_inputs_qss(accent, dark=True)}
                """
            )

        # ---------- themed branches ----------
        if t == "Dark Mode":
            _dark_base()
            base_accent = QColor(92, 171, 255)
            pal.setColor(QPalette.ColorRole.Highlight, base_accent)
            pal.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
            app.setPalette(pal)
            app.setStyleSheet(_button_qss(base_accent, dark_base=True))

        elif t == "Light Mode":
            _light_base()
            base_accent = QColor(53, 132, 228)
            pal.setColor(QPalette.ColorRole.Highlight, base_accent)
            pal.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
            app.setPalette(pal)
            app.setStyleSheet(
                f"""
                QGroupBox{{border:1px solid #ccc; margin-top:8px; border-radius:6px;}}
                QGroupBox::title{{left:8px; padding:0 4px;}}
                QTabWidget::pane{{border:1px solid #ccc;}}
                QScrollArea, QFrame, QWidget#centralwidget{{background:#ffffff;}}
                {_button_qss(base_accent, dark_base=False)}
                {_inputs_qss(base_accent, dark=False)}
                """
            )

        else:
            # Accept patterns like "Dark Blue (Light)", "Light Green (Deep)"
            base = "Dark" if t.lower().startswith("dark") else "Light"
            inside = t.replace("Dark", "", 1).replace("Light", "", 1).strip()
            accent_name = inside.split("(")[0].strip() or "Blue"
            if "(" in t and ")" in t:
                strength = t[t.find("(")+1:t.find(")")].strip().lower()
            else:
                strength = "color"
            accent = _accent_rgb(accent_name)

            if base == "Dark":
                _apply_dark_with_accent(accent, strength)
            else:
                _apply_light_with_accent(accent, strength)

        if self.centralWidget(): self.centralWidget().update()
        self.update()

        # Sync native Windows title bar to the palette just applied
        try:
            pal_now = app.palette()
            cap = pal_now.color(QPalette.ColorRole.Window)
            txt = pal_now.color(QPalette.ColorRole.WindowText)
            dark_mode = _luma(cap) < 128
            if hasattr(self, "set_win_titlebar"):
                self.set_win_titlebar(
                    self,
                    dark=dark_mode,
                    caption_rgb=(cap.red(), cap.green(), cap.blue()),
                    text_rgb=(txt.red(), txt.green(), txt.blue())
                )
        except Exception:
            pass

        # Persist choice if requested
        if persist:
            self._persist_theme_choice(t)
        
        try:
            pal_now = app.palette()
            extra = self._bars_qss(pal_now, getattr(self, "_force_black_header", False)) + self._titlebar_btn_qss()
            combined_css = (app.styleSheet() or "") + "\n" + extra
            self._set_theme_stylesheet(combined_css)
        except Exception:
            pass

        # --- Touch mode (Windows default ON, others auto; env KEYQUORUM_TOUCH can override)

        app_css = app.styleSheet() or ""
        self._base_css = app_css

        try:
            app_css = app.styleSheet() or ""
            self._base_css = app_css  # capture actual theme CSS as the base

            if not getattr(self, "_touch_init_done", False):
                env = (os.environ.get("KEYQUORUM_TOUCH", "").strip().lower())
                if env in ("1", "true", "yes", "on"):
                    self._enable_touch_mode(force=True)
                elif env in ("0", "false", "no", "off"):
                    self._enable_touch_mode(force=False)
                else:
                    # default only on first time:
                    if sys.platform == "win32":
                        self._enable_touch_mode(force=True)   # default ON on Windows (once)
                    else:
                        self._enable_touch_mode(force=None)   # auto-detect (once)
                self._touch_init_done = True
            else:
                # Do NOT change state; just re-apply combined CSS so touch suffix stays/clears correctly
                self._refresh_stylesheet()
                # keep checkbox in sync without firing handler
                try:
                    self.tuchmode_.blockSignals(True)
                    self.tuchmode_.setChecked(bool(getattr(self, "_touch_mode_active", False)))
                    self.tuchmode_2.setChecked(bool(getattr(self, "_touch_mode_active", False)))
                    self.tuchmode_.blockSignals(False)
                except Exception:
                    pass
        except Exception:
            pass

    finally:
        # Re-enable repaints
        self.setUpdatesEnabled(prev_updates)
   
    self.set_status_txt(self.tr("Theme Set")) 

# --- apply tuch in theme call reset

