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

"""Tour shows on new user or on ? click"""

# --- Pysider6 backend QtCore ---
from qtpy.QtCore import Qt, QRect, QPoint, QEvent, QTimer

# --- Pysider6 backend QtGui ---
from qtpy.QtGui import (QPainter, QPainterPath, QColor, QPen, QBrush, QPolygon,) 
# --- Pysider6 backend QtWidgets ---
from qtpy.QtWidgets import (QApplication, QWidget, QLabel, QPushButton, QTabWidget, 
                            QVBoxLayout, QFrame, QHBoxLayout, QAbstractScrollArea,)    

# --- helpers
from ui.ui_helpers import center_on_screen


# ==============================
# --- UI Start
# ==============================

def maybe_show_quick_tour(w, which: str = "core"):
    """"core": core_steps,
        "authenticator": authenticator_steps,
        "audit": audit_steps,
        "profile": profile_steps,
        "settings": settings_steps,
        "portable": portable_steps,
        "backup": backup_steps,
        "category": category_steps,
        "watchtower": watchtower_steps,"""

    core_steps = [
            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "vaultTable",
                "title": "Items table", "text": "Everything you add appears here. Select a row to view or act on it.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "categorySelector_2",
                "title": "Category", "text": "Switch categories. The table updates to show items in the selected category.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "widget_2",
                "title": "Add / Edit / Delete", "text": "Add new items, edit the selected one, or remove it. Tip: choose the category first.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "vaultSearchBox",
                "title": "Search", "text": "Find items instantly in the current category. Filters are supported.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "password_generator",
                "title": "Password generator", "text": "Create strong passwords with customizable length and characters.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "bowser_btn",
                "title": "Browser extension", "text": "Install and pair the Token to enable on-site autofill and saving. Remove the Token to disconnect. A fresh token is created each login.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "breach_check_",
                "title": "Breach check", "text": "Email: open Have I Been Pwned for the selected address. Password: check a password against known breach data (we don’t store what you type).", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "share_",
                "title": "Share", "text": "Securely share with other Keyquorum users. Enter their Share ID to send an encrypted packet only they can open. Use ‘Import packet’ to add one you’ve received.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "softdelete_",
                "title": "Soft delete", "text": "A safety net for deletions: items stay here for 30 days for easy restore, then are removed permanently.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "move_category_",
                "title": "Move to category", "text": "Move the selected item to a different category. Unmapped fields are preserved in Notes.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "qrshow_",
                "title": "Create QR", "text": "Make a QR for the selected item. Most categories encode only the website URL; Wi-Fi encodes full credentials so scanning can join the network.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "logoutButton",
                "title": "Log out", "text": "Securely sign out. Clears sensitive data and resets the session. Works here, on app close, or after idle timeout.", "padding": 10},
        ]

    authenticator_steps = [
            {"tab": {"widget": "mainTabs", "title": "Authenticator"}, "target": "widget_27",
                "title": "Authenticator", "text": "Add, edit, and delete authenticator entries. Add manually or quickly via camera/image. Important: don’t add your vault’s own 2FA here to avoid lockouts.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Authenticator"}, "target": "authTable",
                "title": "Codes table", "text": "Your authenticators are listed here. Codes refresh every ~30 seconds by default.", "padding": 10},
        ]

    audit_steps = [
            {"tab": {"widget": "mainTabs", "title": "Audit Logs"}, "target": "auditTable",
                "title": "Audit logs", "text": "Review recent account activity, including failed login attempts.", "padding": 10, "dim": 110},
        ]

    profile_steps = [
            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "Profile",
                "title": "Profile", "text": "Update your account profile and preferences.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "twoFACheckbox",
                "title": "Two-Factor Authentication", "text": "Enable or disable 2FA for login. This secures account sign-in (vault protection is configured separately).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "btnDeviceUnlock",
                "title": "YubiKey", "text": "Enable a genuine, modern YubiKey for stronger login and vault protection.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "regenerateBackupCodesButton",
                "title": "Regenerate backup codes", "text": "Create new account backup codes if you’ve lost the old ones. Not available in ‘no-recovery’ mode.", "padding": 10, "dim": 110},
        ]

    settings_steps = [
            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "enablePreflightCheckbox_",
                "title": "Preflight checks", "text": "Scan running processes at startup and warn about risky ones (defaults or your allow/block list).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "vault_safety_btn",
                "title": "Preflight lists", "text": "Manage your allow/deny lists for process scanning.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "runPreflightNowButton",
                "title": "Run preflight now", "text": "Run the process check on demand. If Windows Defender is available, you can kick off a quick scan.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "enableWinDefCheckbox_",
                "title": "Antivirus check", "text": "On startup/login, check whether antivirus is present and alert on issues.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "DefenderQuickScan_",
                "title": "Quick scan prompt", "text": "Offer a Windows Defender quick scan at app start.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "vault_safety_btn_2",
                "title": "Integrity baseline", "text": "Update file-integrity baseline for key files.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "clipboard_clear_timeout_",
                "title": "Clipboard safety", "text": "Auto-clear copied secrets after a delay.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "auto_logout_timeout_",
                "title": "Auto-logout", "text": "Automatically log out after inactivity.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "lockoutSpinBox",
                "title": "Lockout", "text": "Lock the account after too many failed login or 2FA attempts.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "password_expiry_days",
                "title": "Password expiry", "text": "Set how long passwords can live before reminders nudge you to rotate them.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "enable_breach_checker_",
                "title": "Breach checker", "text": "Check (hashed) passwords against known breach databases when saving items.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "ontop_",
                "title": "Always on top", "text": "Keep the app window above others.", "padding": 10, "dim": 110},

            #{"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "btnCreatePortable",
                #"title": "Portable build", "text": "Create a portable copy of the app on a USB drive, or rebuild for repair. User data is not touched.", "padding": 10, "dim": 110},

            #{"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "btnMoveToUSB",
                #"title": "Move data to USB", "text": "Move current user data to USB (vault + user data will be removed from this system).", "padding": 10, "dim": 110},

            #{"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "btnMoveBack",
                #"title": "Move data back", "text": "Move user data back from USB to this system.", "padding": 10, "dim": 110},
        ]

    backup_steps = [
            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "BackUp/Restore",
                "title": "Backups", "text": "Regular backups are essential. Create and store them safely.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_28",
                "title": "Cloud sync", "text": "keep a copy of your data in a cloud folder you control.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "select_cloud",
                "title": "Choose cloud folder", "text": "Pick a signed-in, accessible folder for backups.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "extra_cloud_wrap",
                "title": "Cloud safety", "text": "Add extra protection for data stored in the cloud copy.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "autosync_",
                "title": "Auto-sync", "text": "Automatically sync to cloud when data changes.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_16",
                "title": "Full backup / restore", "text": "Create a full backup of vault + account, or import one (also available on the login screen).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_29",
                "title": "Vault-only backup", "text": "Back up just the vault (restorable to the same account).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_30",
                "title": "CSV import / export", "text": "Import from other managers’ CSV, or export your vault to CSV (optionally password-protected).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_31",
                "title": "Software folder backup", "text": "back up the software folder separately if it’s large.", "padding": 10, "dim": 110},
        ]

    category_steps = [
            {"tab": {"widget": "mainTabs", "title": "Edit/Add Category"}, "target": "Edit/Add Category",
                "title": "Customize categories", "text": "Create and edit categories to fit your workflow.", "padding": 10, "dim": 110},
        ]

    watchtower_steps = [
            {"tab": {"widget": "mainTabs", "title": "Watchtower"}, "target": "Watchtower",
                "title": "Watchtower", "text": "Spot weak, reused, or unsafe items at a glance and fix them quickly.", "padding": 10, "dim": 110},
        ]
        
    # ---- choose steps by key
    steps_by_type = {
        "core": core_steps,
        "authenticator": authenticator_steps,
        "audit": audit_steps,
        "profile": profile_steps,
        "settings": settings_steps,
        "backup": backup_steps,
        "category": category_steps,
        "watchtower": watchtower_steps,
    }
    steps = steps_by_type.get(which)
    if not steps:
        return

    # ---- finish any running tour
    try:
        if getattr(w, "_tour", None):
            w._tour.finish()
    except Exception:
        pass

    # ---- start new tour; keep a ref so it doesn't get GC’d
    default_dim = 120 if which in ("core",) else 110
    tour = GuidedTour(w, steps, default_dim=default_dim)
    tour.start()


# ==============================
# --- (UI) Guided Tour / Coach Marks ---
# ==============================
class _TourBubble(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("KQTourBubble")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setAutoFillBackground(True)

        self.title = QLabel("Title", self)
        self.body  = QLabel("Body", self); self.body.setWordWrap(True)

        self.btnBack = QPushButton(self.tr("Back")); self.btnNext = QPushButton(self.tr("Next"))
        self.btnSkip = QPushButton(self.tr("Skip"))

        top = QVBoxLayout(self); top.setContentsMargins(16, 14, 16, 12); top.setSpacing(10)
        top.addWidget(self.title); top.addWidget(self.body)

        row = QHBoxLayout(); row.addStretch(1)
        row.addWidget(self.btnBack); row.addWidget(self.btnNext); row.addWidget(self.btnSkip)
        top.addLayout(row)

        # subtle rounded “card” feel (palette-safe)
        self.setStyleSheet("""
            QWidget#KQTourBubble {
                background: palette(Window);
                border: 1px solid rgba(0,0,0,60);
                border-radius: 12px;
            }
            QWidget#KQTourBubble QLabel { color: palette(WindowText); }
            QWidget#KQTourBubble QPushButton { min-width: 72px; }
        """)

class GuidedTour(QWidget):
    """
    GuidedTour(parent, steps=[{
        "target": <QWidget or "objectName">,
        # optional helpers to make the target visible BEFORE measuring:
        "tab": {"widget": <QTabWidget or objectName>, "index": 2}    # or {"title": "Settings"} or {"page":"settingsPageObjName"}
        "scroll": True,                  # ensureWidgetVisible if target sits in a scroll area
        "padding": 12,                   # hole padding
        "dim": 130,                      # alpha 0..255 for this step (default 130)
        "title": "…", "text": "…"
    }], default_dim=130)
    """
    def __init__(self, parent, steps, default_dim=130):
        super().__init__(parent)
        self.setObjectName("KQGuidedTourOverlay")
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Tool)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self.setAttribute(Qt.WA_NoSystemBackground, True)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setFocusPolicy(Qt.StrongFocus)
        self._root_parent    = parent      # remember main window
        self._entered_steps  = set()       # run-once guard for on_enter
        self._opened_by_step = {}          # step index -> QWidget opened there
        self._opened_widget  = None        # last opened widget for this step
        self._opened_by_step = {}  
        self._parent         = parent
        self._steps          = steps or []
        self._default_dim    = int(default_dim)
        self._i              = -1
        self._highlight      = QRect()

        # bubble
        self._bubble = _TourBubble(self)
        self._bubble.btnBack.clicked.connect(self.prev)
        self._bubble.btnNext.clicked.connect(self.next)
        self._bubble.btnSkip.clicked.connect(self.finish)

        # track parent changes
        parent.installEventFilter(self)
        # gentle polling to re-measure when layouts move
        self._tick = QTimer(self); self._tick.setInterval(150); self._tick.timeout.connect(self._recalc)
        QTimer.singleShot(0, lambda: center_on_screen(self))

    # ---------- public
    def start(self, start_index=0):
        if not self._steps:
            return
        self._i = max(0, min(start_index, len(self._steps)-1))
        self._sync_geometry()
        self.show(); self.raise_()
        self._tick.start()
        self._goto(self._i)

    def next(self):
        # run optional on-exit for current step
        if 0 <= self._i < len(self._steps):
            step = self._steps[self._i]
            # user-defined on_exit
            fn = step.get("on_exit") or step.get("after")
            if callable(fn):
                try: fn()
                except Exception: pass

            # auto-close opened dialog if requested
            if step.get("close_on_next") or step.get("close_opened"):
                w = self._opened_by_step.pop(self._i, None)
                if isinstance(w, QWidget) and w.isVisible():
                    try: w.close()
                    except Exception: pass
                # reparent overlay back to the main window unless the NEXT step re-adopts
                self._adopt_parent(self._root_parent)

            self._clear_highlight()

        # advance
        if self._i < len(self._steps) - 1:
            self._goto(self._i + 1)
        else:
            self.finish()


    def prev(self):
        if self._i > 0:

            self._clear_highlight()
            self._goto(self._i - 1)

    def finish(self):
        self._tick.stop()
        self.hide()
        self.deleteLater()

    # ---------- internals
    def eventFilter(self, obj, ev):
        if obj is self._parent and ev.type() in (QEvent.Resize, QEvent.Move, QEvent.WindowStateChange, QEvent.LayoutRequest):
            self._sync_geometry(); self._recalc()
        return super().eventFilter(obj, ev)

    def _recalc(self):
        """Recompute the highlight/bubble for the current step."""
        if 0 <= self._i < len(self._steps):
            self._goto(self._i)

    def _adopt_parent(self, new_parent: QWidget):
        """Reparent the overlay to a new top-level (e.g., a dialog) and resync."""
        try:
            self._parent.removeEventFilter(self)
        except Exception:
            pass
        self.setParent(new_parent)
        self._parent = new_parent
        new_parent.installEventFilter(self)
        self._sync_geometry()
        self.raise_()
        self.show()
        QTimer.singleShot(0, lambda: center_on_screen(self))



    def _sync_geometry(self):
        self.setGeometry(self._parent.rect())

    def _resolve_widget(self, w):
        if hasattr(w, "rect") and hasattr(w, "mapToGlobal"):
            return w
        if isinstance(w, str):
            return self._parent.findChild(QWidget, w)
        return None

    def _clear_highlight(self):
        # immediately drop the old hole/arrow so you don't see a stale box
        self._highlight = QRect()
        self.update()

    def _ensure_context(self, step):
        """Make sure the target is visible (switch tab, etc.) before measuring."""
        tab = step.get("tab")
        if tab:
            tabs = self._resolve_widget(tab.get("widget"))
            if isinstance(tabs, QTabWidget):
                idx = tab.get("index")
                if idx is None and "title" in tab:
                    title = str(tab["title"])
                    for i in range(tabs.count()):
                        if tabs.tabText(i).strip() == title.strip():
                            idx = i; break
                if idx is None and "page" in tab:
                    page = self._resolve_widget(tab["page"])
                    if page:
                        i = tabs.indexOf(page)
                        if i != -1: idx = i
                if isinstance(idx, int) and 0 <= idx < tabs.count():
                    if tabs.currentIndex() != idx:
                        tabs.setCurrentIndex(idx)
                        QApplication.processEvents()  # let layout update

        # try to scroll the target into view
        if step.get("scroll"):
            t = self._resolve_widget(step.get("target"))
            if t:
                # find an ancestor scroll area
                anc = t.parent()
                while anc is not None and not isinstance(anc, QAbstractScrollArea):
                    anc = anc.parent()
                if isinstance(anc, QAbstractScrollArea):
                    try:
                        anc.ensureWidgetVisible(t)
                        QApplication.processEvents()
                    except Exception:
                        pass


    def _goto(self, idx: int):
        # ---- safety guards (avoid AttributeError on old instances)
        if not hasattr(self, "_entered_steps"):  self._entered_steps  = set()
        if not hasattr(self, "_opened_by_step"): self._opened_by_step = {}
        if not hasattr(self, "_opened_widget"):  self._opened_widget  = None
        if not hasattr(self, "_root_parent"):    self._root_parent    = self._parent
        # ---------------------------------------

        self._i = idx
        step = self._steps[idx]

        # Run hook ONCE for this step
        if idx not in self._entered_steps:
            fn = step.get("on_enter") or step.get("before") or step.get("open")
            ret = None
            if callable(fn):
                if hasattr(self, "_tick"): self._tick.stop()
                try:
                    ret = fn()    # may return a dialog/widget
                finally:
                    if hasattr(self, "_tick"): self._tick.start()

            if isinstance(ret, QWidget):
                self._opened_widget = ret                      # << set it!
                self._opened_by_step[idx] = ret
                if step.get("reparent_to") in ("opened", "dialog"):
                    self._adopt_parent(ret)

            # allow explicit hop back to main window
            if step.get("reparent_to") in ("root", "main"):
                self._adopt_parent(self._root_parent)

            self._entered_steps.add(idx)

        # If the step expects to live on the opened dialog, ensure we’re parented to it
        if step.get("reparent_to") in ("opened", "dialog"):
            w = self._opened_by_step.get(idx) or self._opened_widget
            if isinstance(w, QWidget) and self.parent() is not w:
                self._adopt_parent(w)

        # 1) prepare context (tabs, scroll) now that parenting is correct
        self._ensure_context(step)

        # 2) bubble text/buttons
        self._bubble.title.setText(step.get("title") or "Tip")
        self._bubble.body.setText(step.get("text") or "")
        self._bubble.btnBack.setEnabled(idx > 0)
        # Translate the button label depending on whether it's the final step
        self._bubble.btnNext.setText(
            self.tr("Next") if idx < len(self._steps) - 1 else self.tr("Finish")
        )

        # 3) compute highlight rect using global→overlay mapping
        pad = int(step.get("padding", 12))
        target = self._resolve_widget(step.get("target"))
        r = QRect()
        if target and target.isVisible():
            tr = target.rect()
            tl_global  = target.mapToGlobal(tr.topLeft())
            tl_overlay = self.mapFromGlobal(tl_global)
            r = QRect(tl_overlay, tr.size()).adjusted(-pad, -pad, pad, pad)
            if not self.rect().intersects(r):
                r = QRect()  # off-screen → no hole/arrow
        self._highlight = r

        # 4) place and show bubble, repaint
        self._bubble.adjustSize()
        self._position_bubble()
        self.update()


    def _position_bubble(self):
        margin = 16
        bsz = self._bubble.sizeHint()
        r = self.rect()

        if not self._highlight.isNull():
            tgt = self._highlight
            # center bubble horizontally on target; prefer above, else below
            bx = tgt.center().x() - bsz.width() // 2
            by = tgt.top() - bsz.height() - 16
            if by < r.top() + margin:
                by = tgt.bottom() + 16
            # clamp inside overlay
            bx = max(r.left() + margin, min(bx, r.right() - bsz.width() - margin))
            by = max(r.top() + margin,  min(by, r.bottom() - bsz.height() - margin))
        else:
            # true center if no target
            bx = r.center().x() - bsz.width() // 2
            by = r.center().y() - bsz.height() // 2
            
        self._bubble.setGeometry(int(bx), int(by), bsz.width(), bsz.height())
        self._bubble.show(); self.raise_(); self._bubble.raise_()
        QTimer.singleShot(0, lambda: center_on_screen(self))

    def paintEvent(self, ev):
        # dim level can vary per step
        dim_alpha = int(self._steps[self._i].get("dim", self._default_dim)) if (0 <= self._i < len(self._steps)) else self._default_dim
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing, True)

        path = QPainterPath(); path.addRect(self.rect())
        if not self._highlight.isNull():
            hole = QPainterPath(); hole.addRoundedRect(self._highlight, 10, 10)
            path = path.subtracted(hole)

        p.fillPath(path, QColor(0, 0, 0, dim_alpha))

        if not self._highlight.isNull():
            p.setPen(QPen(QColor(255, 255, 255, 200), 2)); p.setBrush(Qt.NoBrush)
            p.drawRoundedRect(self._highlight, 10, 10)

            # arrow
            bc = self._bubble.geometry().center(); tc = self._highlight.center()
            p.setPen(QPen(QColor(255, 255, 255, 230), 2)); p.drawLine(bc, tc)
            v = tc - bc; L = max(1, (v.x()**2 + v.y()**2) ** 0.5)
            ux, uy = v.x()/L, v.y()/L
            left  = QPoint(int(tc.x() - 10*ux - 6*uy), int(tc.y() - 10*uy + 6*ux))
            right = QPoint(int(tc.x() - 10*ux + 6*uy), int(tc.y() - 10*uy - 6*ux))
            p.setBrush(QBrush(QColor(255, 255, 255, 230)))
            p.drawPolygon(QPolygon([tc, left, right]))
        p.end()

    def mousePressEvent(self, e):
        # clicking anywhere outside the bubble advances
        if not self._bubble.geometry().contains(e.pos()):
            self.next()
        else:
            super().mousePressEvent(e)

    def keyPressEvent(self, e):
        if e.key() in (Qt.Key_Right, Qt.Key_Space, Qt.Key_Enter, Qt.Key_Return): self.next()
        elif e.key() in (Qt.Key_Left, Qt.Key_Backspace): self.prev()
        elif e.key() in (Qt.Key_Escape,): self.finish()
        else: super().keyPressEvent(e)


