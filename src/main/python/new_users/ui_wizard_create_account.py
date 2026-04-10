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

"""moved from main to shrink 
binding creact account ui
"""
# --- log ---
import logging
log = logging.getLogger("keyquorum")
import app.kq_logging as kql

# ---  pysider backend QtWidgets ---
from qtpy.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QMessageBox, QVBoxLayout, QTextEdit, QFormLayout, QFrame, QGraphicsDropShadowEffect,
    QHBoxLayout, QCheckBox, QWizard, QWizardPage, QRadioButton, QSizePolicy, QSpinBox)    
# --- pysider backend QtGui ---
from qtpy.QtGui import QColor, QPalette
# --- pysider backend QtCore ---
from qtpy.QtCore import Qt 

# --- helpers ---
import sys
from pathlib import Path  
from native.native_core import get_core
import hashlib
import secrets
from auth.pw.password_utils import get_password_strength
from auth.pw.password_generator import show_password_generator_dialog
from new_users.account_creator import create_or_update_user
from security.secure_audit import log_event_encrypted
from auth.tfa.twofa_dialog import twofa_setup
from auth.tfa.twofactor import enable_recovery_2of2_wrap
from features.url.main_url import SITE_SUPPORT, SITE_GITHUB
from auth.login.login_handler import get_user_setting, set_user_setting, get_user_record
from auth.yubi.yubikeydialog import YubiKeySetupDialog
from ui_gen.emergency_kit_dialog import EmergencyKitDialog
from app.basic import get_app_version
from ui.ui_helpers import center_on_screen
from security.baseline_signer import update_baseline
from app.paths import APP_ROOT 

LICENSES_DIR    = APP_ROOT / "licenses"

# ==============================
# --- ui load create account
# ==============================
    
def create_account(w):
    """
    Start the Create Account flow.
    """
    # Proceed to the onboarding wizard
    try:
        # Use w as parent (your snippet used `w`, which likely isn't defined here)
        wiz = InlineOnboardingWizard(parent=w)
    except NameError:
        raise

    try:
        center_on_screen(wiz)
    except Exception:
        pass

    wiz.exec()

def _mask_secret(s: str | None) -> str | None:
    if not s: return None
    return (s[:4] + ("*" * max(0, len(s) - 6)) + s[-2:]) if len(s) > 6 else "***"



def _derive_current_mk_native(username: str, password: str) -> bytes:
    """
    Strict DLL-only derivation of the current vault/master key for features that
    still require the raw 32-byte key in Python (e.g. current YubiKey WRAP flow).

    Reads the authoritative salt from the identity header and honors the user's
    stored KDF profile. No Python Argon2 fallback is used.
    """
    username = (username or "").strip()
    password = password or ""
    if not username or not password:
        raise ValueError("username and password are required")

    from auth.salt_file import read_master_salt_strict

    salt = read_master_salt_strict(username)
    if not salt:
        raise ValueError("User salt not found")

    rec = get_user_record(username) or {}
    kdf = rec.get("kdf") or {}

    core = get_core()
    if not core:
        raise RuntimeError("Native core not loaded. DLL is required.")

    pw_buf = bytearray(password.encode("utf-8"))
    try:
        if (
            isinstance(kdf, dict)
            and int(kdf.get("kdf_v", 1)) >= 2
            and hasattr(core, "derive_vault_key_ex")
            and getattr(core, "has_derive_vault_key_ex", lambda: False)()
        ):
            return bytes(core.derive_vault_key_ex(
                pw_buf,
                bytes(salt),
                time_cost=int(kdf.get("time_cost", 3)),
                memory_kib=int(kdf.get("memory_kib", 256000)),
                parallelism=int(kdf.get("parallelism", 2)),
            ))
        return bytes(core.derive_vault_key(pw_buf, bytes(salt)))
    finally:
        try:
            core.secure_wipe(pw_buf)
        except Exception:
            for i in range(len(pw_buf)):
                pw_buf[i] = 0


# ==============================
# --- (UI) Inline First-Run Wizard Create Account---
# ==============================
class _GatePage(QWizardPage):
    # Consider the page complete only after we’ve actually created a user.
    def isComplete(self):
        w = self.wizard()
        return bool(getattr(w, "_created_user", None))


class InlineOnboardingWizard(QWizard):
    
    def _wrap_as_card(self, inner: QWidget) -> QFrame:
        card = QFrame()
        card.setObjectName("wizCard")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(12)
        lay.addWidget(inner)

        # Soft shadow to blend the edges (optional, looks nice on Win11)
        try:
            eff = QGraphicsDropShadowEffect(card)
            eff.setBlurRadius(28)
            eff.setOffset(0, 2)
            eff.setColor(QColor(0, 0, 0, 90))
            card.setGraphicsEffect(eff)
        except Exception:
            pass
        return card
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Welcome to Keyquorum — Account Setup"))
        self.setWindowModality(Qt.ApplicationModal)
        self.setOption(QWizard.NoBackButtonOnStartPage, True)
        self.resize(720, 540)
        self.setMinimumSize(640, 480)
        # Inherit the app palette + stylesheet so the theme applies immediately
        app = QApplication.instance()
        if app:

            page_pal = QPalette(app.palette())   # use theme as-is (no remap)
            self._kq_page_palette = page_pal
            self.setPalette(page_pal)
            self.setAutoFillBackground(True)
            # Defer colors to the palette so dark/light both work
            self.setStyleSheet("""
                    QWidget#KQOnboardWizard,
                    QWidget#KQOnboardWizard QWizardPage {
                        background: palette(Base);
                        color: palette(Text);
                    }

                    /* Rounded card that holds the page's content */
                    QWidget#KQOnboardWizard QFrame#wizCard {
                        background: palette(Window);
                        border: 1px solid rgba(0,0,0,60);
                        border-radius: 12px;
                    }

                    QWidget#KQOnboardWizard QLabel,
                    QWidget#KQOnboardWizard QCheckBox,
                    QWidget#KQOnboardWizard QRadioButton,
                    QWidget#KQOnboardWizard QGroupBox::title {
                        color: palette(Text);
                    }
                """)

        # state
        self._created_user = None
        self._entered_steps = set()
        # pages
        self._p_create  = self._page_create_account()
        self._p_how     = self._page_how_it_works()
        self._p_prot    = self._page_protections()
        self._p_finish  = self._page_finish()
        for pg in (self._p_create, self._p_how, self._p_prot, self._p_finish):
            self.addPage(pg)

    # ---------- Page 1: Create Account ----------
    def _page_create_account(self) -> QWizardPage:
        p = _GatePage()
        p.setTitle("Create your account")
        p.setSubTitle("After you create your account and finish the Emergency Kit step, you can continue.")
        try:
            p.setPalette(self._kq_page_palette); p.setAutoFillBackground(True)
        except Exception:
            pass

        outer = QVBoxLayout(p)

        container = QWidget()
        form = QFormLayout(container)

        self._create_username = QLineEdit(); self._create_username.setPlaceholderText("Choose a username")
        self._create_password = QLineEdit(); self._create_password.setEchoMode(QLineEdit.Password); self._create_password.setPlaceholderText("Choose a strong password")
        self._create_confirm  = QLineEdit(); self._create_confirm.setEchoMode(QLineEdit.Password); self._create_confirm.setPlaceholderText("Confirm password")

        self._pw_hint = QLabel(self.tr("Password must be at least 8 characters and include upper, lower, number, and symbol."))
        self._create_pw_info = QLabel("")

        # Security profile radios (tooltips)
        self._rb_max  = QRadioButton(self.tr("Maximum security — NO recovery"))
        self._rb_norm = QRadioButton(self.tr("Normal security — Recovery key + backup codes"))
        self._rb_norm.setChecked(True)
        self._rb_max.setToolTip(self.tr("Most secure. No recovery. If you forget the master password, your vault is unrecoverable."))
        self._rb_norm.setToolTip(self.tr("Balanced. Generates a one-time recovery key and backup codes so you can recover access."))
        for _w in (self._rb_norm, self._rb_max):
            _w.setStyleSheet("color: palette(WindowText);")
        rb_col = QVBoxLayout(); rb_col.addWidget(self._rb_norm); rb_col.addWidget(self._rb_max)
        rb_wrap = QWidget(); rb_wrap.setLayout(rb_col)

        # Extras
        self._cb_2fa = QCheckBox(self.tr("Enable Two-Factor Authentication (TOTP)"))
        self._cb_2fa.setToolTip(self.tr("Adds an authenticator code at login (time-based one-time password). Recommended."))
        self._cb_yk  = QCheckBox(self.tr("Require YubiKey (2-of-2) at login"))
        self._cb_yk.setToolTip(self.tr("Hardware key required at login (GATE). You can enable WRAP later in Settings after first login."))
        for _w in (self._cb_2fa, self._cb_yk):
            _w.setStyleSheet("color: palette(WindowText);")
        self._cb_yk.hide()
        # Buttons
        self._btn_gen = QPushButton(self.tr("Generate Password"))
        self._btn_create = QPushButton(self.tr("Create Account"))
        self._btn_close = QPushButton(self.tr("Close"))
        for b in (self._btn_create, self._btn_close):
            b.setMinimumWidth(140); b.setMaximumWidth(220); b.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        row = QHBoxLayout(); row.addWidget(self._btn_gen); row.addStretch(1); row.addWidget(self._btn_create); row.addWidget(self._btn_close)

        # Build form with explicit labels (so we can style them)
        u_lbl = QLabel(self.tr("Username")); p_lbl = QLabel(self.tr("Password")); c_lbl = QLabel(self.tr("Confirm"))
        for _lbl in (u_lbl, p_lbl, c_lbl):
            _lbl.setStyleSheet("color: palette(WindowText);")

        form.addRow(u_lbl, self._create_username)
        form.addRow(p_lbl, self._create_password)
        form.addRow(c_lbl, self._create_confirm)
        form.addRow("", self._pw_hint)
        form.addRow("", self._create_pw_info)
        form.addRow("Security profile", rb_wrap)
        form.addRow(self._cb_2fa)
        form.addRow(self._cb_yk)
        form.addRow(row)

        container.setMaximumWidth(600)
        outer.addWidget(container)
        outer.setAlignment(container, Qt.AlignHCenter)

        # Wiring
        try: self._create_password.textChanged.connect(self._update_pw_feedback)
        except Exception: pass
        self._btn_gen.clicked.connect(self._do_generate_password)
        self._btn_create.clicked.connect(self._handle_create_clicked)
        self._btn_close.clicked.connect(self.reject)

        # start with Next disabled
        self._set_next_enabled(False)
        return p

    def _update_pw_feedback(self):
        try:
            pw = self._create_password.text() or ""
            if 'get_password_strength' in globals() and callable(get_password_strength):
                _, level, msg = get_password_strength(pw)
                self._create_pw_info.setText(f"{level}: {msg}")
            else:
                self._create_pw_info.setText(self.tr("Weak: use a longer password with symbols."))
        except Exception:
            pass

    def _do_generate_password(self):
        try:
            if 'show_password_generator_dialog' in globals() and callable(show_password_generator_dialog):
                show_password_generator_dialog(target_field=self._create_password, confirm_field=self._create_confirm)
                return
        except Exception:
            pass
        # fallback
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{};:,./?"
        pw = "".join(secrets.choice(alphabet) for _ in range(20))
        self._create_password.setText(pw)
        self._create_confirm.setText(pw)

    def _handle_create_clicked(self):
        try:
            username = (self._create_username.text() or "").strip()
            password = self._create_password.text() or ""
            confirm  = self._create_confirm.text() or ""
            if not username or not password:
                QMessageBox.warning(self, self.tr("Missing details"), self.tr("Please enter a username and password."))
                return

            recovery_mode = self._rb_norm.isChecked()   # Normal => recovery ON
            want_2fa = bool(self._cb_2fa.isChecked())
            want_yk  = bool(self._cb_yk.isChecked())

            if 'create_or_update_user' not in globals() or not callable(create_or_update_user):
                raise RuntimeError("create_or_update_user() not available")

            res = create_or_update_user(
                username=username,
                password=password,
                confirm=confirm,
                recovery_mode=recovery_mode,
                update_mode=False
            )
            ok = (res.get("status") == "SUCCESS") or (res.get("success") is True)
            if not ok:
                msg = res.get("message") or res.get("error") or "Unknown error occurred."
                QMessageBox.warning(self, "Account creation failed", msg)
                return

            log_event_encrypted(username, "Account", f"{kql.i('ok')} (new) -> Hello World")

            # Make plaintext password available for identity-store operations used by dialogs
            self.current_password = password

            # Only derive the current raw vault key if a YubiKey flow actually needs it.
            # This stays strict DLL-only and uses identity-header salt + the user's stored KDF.
            current_mk = None
            if want_yk:
                current_mk = _derive_current_mk_native(username, password)

            # ---------------- Optional YubiKey (GATE) ----------------
            try:
                if want_yk:
                    YubiKeySetupDialog(self, username=username, current_mk=current_mk, identity_password=self.current_password).exec()

                    if recovery_mode:
                        # IMPORTANT: use the recovery *key* for the wrap
                        rk = res.get("recovery_key")
                        if rk:
                            enable_recovery_2of2_wrap(username, master_key=current_mk, recovery_key=rk)

                    QMessageBox.information(self, self.tr("YubiKey"), self.tr("YubiKey (2-of-2 GATE) enabled for this account."))
            except Exception as e:
                msg = self.tr("Couldn’t enable YubiKey right now:") + f"\n{e}"
                QMessageBox.warning(self, self.tr("YubiKey"), msg)

            # ---------------- Optional 2FA (TOTP + backup codes) ----------------
            totp_uri = totp_secret_plain = totp_qr_png = None
            twofa_backup_codes = []
            if want_2fa and 'twofa_setup' in globals() and callable(twofa_setup):
                try:
                    # New signature: twofa_setup(parent, username) — reads parent.current_password
                    r = twofa_setup(self, username)
                    if isinstance(r, dict) and r.get("ok"):
                        totp_uri = r.get("otpauth_uri")
                        totp_secret_plain = r.get("secret")
                        totp_qr_png = r.get("qr_png")
                        twofa_backup_codes = (r.get("backup_codes") or []).copy()
                    else:
                        QMessageBox.warning(
                            self, "Two-Factor Authentication",
                            "Setup not completed; 2FA has not been enabled."
                        )
                except Exception as e:
                    QMessageBox.warning(self, self.tr("Two-Factor Authentication"), f"Setup error: {e}")

            # ---------------- Emergency Kit (force acknowledge) ----------------
            one_time_recovery_key = res.get("recovery_key") if res else None
            # These are the LOGIN/Yubi backup codes (if recovery_mode True) created during account creation
            recovery_backup_codes = (res.get("backup_codes") or []).copy()

            show_kit = bool(
                one_time_recovery_key or recovery_backup_codes or twofa_backup_codes
                or totp_uri or totp_qr_png or recovery_mode or want_2fa
            )

            if show_kit:
                try:
                    log.debug("EK PDF: sys.executable = %s", sys.executable)
                    dlg = EmergencyKitDialog(
                        self,
                        username=username,
                        app_version=get_app_version(),                # app version 
                        recovery_key=one_time_recovery_key,           # recovery key
                        recovery_backup_codes=recovery_backup_codes,  # LOGIN/Yubi codes
                        twofa_backup_codes=twofa_backup_codes,        # 2FA codes
                        totp_uri=totp_uri,                            
                        # If prefer not to mask on the PDF, pass totp_secret_plain directly NOT (_mask_secret())
                        totp_secret_hint=_mask_secret(totp_secret_plain) if totp_secret_plain else None,
                        totp_qr_png=totp_qr_png,
                    )
                    dlg.exec()
                except Exception as e:
                    log.warning("%s [KIT] EmergencyKitDialog unavailable, fallback text: %s", kql.i('warn'), e)
            msg = self.tr("Account ") + f"'{username}'" + self.tr(" was created successfully.\nYou can continue.")
            QMessageBox.information(
                self, self.tr("Account Created"), msg)
            self._created_user = username
            try:
                self._p_create.completeChanged.emit()
            except Exception:
                pass
            self._set_next_enabled(True)
            try:
                self.button(QWizard.NextButton).click()
            except Exception:
                pass

        except Exception as e:
            msg = "❌" + self.tr(" Failed to create account: ") + f"\n {e}"
            QMessageBox.critical(self, self.tr("Account Creation Error"), msg)
        finally:
            # Best-effort: clear the cached plaintext password after we’re done
            try:
                self.current_password = None
            except Exception:
                pass

    def _set_next_enabled(self, enabled: bool):
        try: self.button(QWizard.NextButton).setEnabled(bool(enabled))
        except Exception: pass

    # ---------- Page 3–6 (short text pages) ----------
    def _page_how_it_works(self) -> QWizardPage:
        from PySide6.QtWidgets import QWizardPage, QVBoxLayout, QLabel, QScrollArea
        from PySide6.QtCore import Qt

        p = QWizardPage()
        p.setTitle("How Keyquorum Works (Quick Tour)")
        try:
            p.setPalette(self._kq_page_palette)
            p.setAutoFillBackground(True)
        except Exception:
            pass

        t = QLabel(
            "Welcome! Here are the basics to get the most out of Keyquorum:\n\n"
            "For more information, please open the menu button at the top-left of the UI. "
            "There you’ll find links to:\n"
            "• **Help / Feedback**\n"
            "• **Help (Videos)**\n"
            "• **Bugs & Feature Requests**\n"
            "• **Catalog Help**\n"
            "• **Privacy Policy**\n"
            "• **Security & Privacy Guide**\n"
            "• **Threat Model**\n"
            "• **Browser Extension**\n"
            "• **Open Licenses Folder**\n\n"
        
            "🔑 **Vault Features**\n"
            "• **Red alerts** show entries that need attention (duplicates, weak or old passwords).\n"
            "• **Expiry reminders** warn you when logins are getting old.\n"
            "• **Auto-clearing clipboard** protects sensitive data after copying.\n"
            "• **Password history** keeps old versions whenever you update an entry.\n"
            "• **Watchtower** gives you a full health dashboard (weak, reused, outdated passwords).\n"
            "• **Password Generator** quickly creates strong, unique passwords.\n"
            "• **Browser Extension** supports local autofill (HTTPS-only).\n"
            "• **Preflight checks** warn you about risky processes that may affect vault security.\n\n"

            "🛡️ **Safety Tips**\n"
            "• Store **recovery PDFs and codes** on a separate device — never in the same place as your vault.\n"
            "• Make **regular encrypted backups** to USB or an external drive.\n"
            "• Keep your **operating system and browser updated**.\n"
            "• Remember: your vault is only as secure as the system it runs on.\n\n"

            "Thank you for using Keyquorum Vault!"
        )

        t.setWordWrap(True)
        t.setAlignment(Qt.AlignTop | Qt.AlignLeft)

        # Put the label inside a scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        from PySide6.QtWidgets import QFrame
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(t)

        lay = QVBoxLayout(p)
        lay.addWidget(scroll)

        return p

    def _page_protections(self) -> QWizardPage:
        import platform as _plat

        p = QWizardPage()
        p.setTitle("Optional protections")
        try:
            p.setPalette(self._kq_page_palette)
            p.setAutoFillBackground(True)
        except Exception:
            pass

        settings = getattr(self, "settings", {}) or {}

        # --- defaults (same keys you'll save later) ------------------------------
        lockout_threshold            = int(settings.get("lockout_threshold", 5))
        password_expiry_days         = int(settings.get("password_expiry_days", 90))
        clipboard_clear_timeout_sec  = int(settings.get("clipboard_clear_timeout_sec", 15))
        auto_logout_timeout_sec      = int(settings.get("auto_logout_timeout_sec", 300))
        ontop                        = bool(settings.get("ontop", False))
        touch_mode                   = bool(settings.get("touch_mode", False))
        known_scan                   = bool(settings.get("known_process_scan", False))
        win_def_checkbox             = bool(settings.get("WinDefCheckbox", False))
        defender_quick_scan          = bool(settings.get("DefenderQuickScan", False))

        # --- header --------------------
        hdr = QLabel(self.tr("You can turn these on now (you can change all of them later in Settings)."))
        hdr.setWordWrap(True)

        # --- checkboxes ----------------
        self._cb_known = QCheckBox(self.tr("Enable known-process scan (block/allow list)"))
        self._cb_known.setChecked(known_scan)
        self._cb_known.setToolTip(self.tr("Warn/block if suspicious or disallowed processes are running before unlock."))

        self._cb_ontop = QCheckBox(self.tr("Keep window on top"))
        self._cb_ontop.setChecked(ontop)

        self._cb_touch = QCheckBox(self.tr("Enable touch-friendly UI"))
        self._cb_touch.setChecked(touch_mode)

        # Windows-only Defender options
        self._cb_win_def = QCheckBox(self.tr("Check for Antivirus installed on App Startup (Windows only)"))
        self._cb_win_def.setChecked(win_def_checkbox)

        self._cb_def_quick = QCheckBox(self.tr("Run Windows Defender Quick Scan at login (Windows only)"))
        self._cb_def_quick.setChecked(defender_quick_scan)

        is_windows = _plat.system().lower().startswith("win")
        self._cb_win_def.setEnabled(is_windows)
        self._cb_def_quick.setEnabled(is_windows)

        # --- numeric controls ----------
        self._sp_lockout = QSpinBox()
        self._sp_lockout.setRange(0, 15)
        self._sp_lockout.setValue(lockout_threshold)
        self._sp_lockout.setToolTip(self.tr("Number of failed logins before temporary lockout."))

        self._sp_expiry = QSpinBox()
        self._sp_expiry.setRange(30, 365)
        self._sp_expiry.setValue(password_expiry_days)
        self._sp_expiry.setSuffix(" days")
        self._sp_expiry.setToolTip(self.tr("Days before an item is flagged as old in Watchtower."))

        self._sp_clip = QSpinBox()
        self._sp_clip.setRange(5, 180)
        self._sp_clip.setValue(clipboard_clear_timeout_sec)
        self._sp_clip.setSuffix(" sec")
        self._sp_clip.setToolTip(self.tr("How long secrets stay in the clipboard before auto-clear."))

        self._sp_logout = QSpinBox()
        self._sp_logout.setRange(0, 7200)
        self._sp_logout.setSingleStep(0)
        self._sp_logout.setValue(auto_logout_timeout_sec)
        self._sp_logout.setSuffix(" sec")
        self._sp_logout.setToolTip(self.tr("Idle time before the app auto-locks."))

        # --- layout --------------------
        lay = QVBoxLayout(p)
        lay.addWidget(hdr)

        form = QFormLayout()
        form.addRow("Failed-login lockout threshold:", self._sp_lockout)
        form.addRow("Password expiry reminder:",       self._sp_expiry)
        form.addRow("Clipboard clear timeout:",        self._sp_clip)
        form.addRow("Auto-logout (idle) timeout:",     self._sp_logout)
        lay.addLayout(form)

        for w in (
            self._cb_known, self._cb_ontop, self._cb_touch,
            self._cb_win_def, self._cb_def_quick
        ):
            lay.addWidget(w)
            w.setStyleSheet("color: palette(WindowText);")

        return p

    def _page_finish(self) -> QWizardPage:

        p = QWizardPage()
        p.setTitle("All set!")
        try:
            p.setPalette(self._kq_page_palette)
            p.setAutoFillBackground(True)
        except Exception:
            pass

        msg = (
            "<b>Welcome to Keyquorum Vault!</b><br><br>"
            "Your account has been created successfully.<br><br>"
            "Keyquorum Vault is free and open-source, built with a focus on privacy, security, and offline-first design.<br><br>"
            f"Project source code and updates are available on GitHub: "
            f"<a href='{SITE_GITHUB}'>{SITE_GITHUB}</a><br><br>"
            f"If you run into any issues, please contact support at "
            f"<a href='{SITE_SUPPORT}'>{SITE_SUPPORT}</a>.<br><br>"
            "<b>Important:</b> Make regular backups of your vault and store them offline for maximum safety.<br><br>"
            "When reporting a bug, please include helpful details (screenshots, what happened and when, and relevant logs). "
            "Logs are filtered to avoid sensitive data, but it’s still wise to review them before sharing.<br><br>"
            "Feedback — good or bad — is always welcome. It helps improve Keyquorum for everyone."

        )
        
        
        lbl = QLabel(msg, p)
        lbl.setWordWrap(True)
        lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)

        lay = QVBoxLayout(p)
        lay.addWidget(lbl)

        return p

    # apply toggles to the created user
    def accept(self):
        try:
            if self._created_user:
                self._apply_settings_to_user(self._created_user)
        except Exception as e:
            try:
                log.error("[onboarding] failed to apply settings: %s", e)
            except Exception:
                pass
        super().accept()

    def _apply_settings_to_user(self, username: str):
        # Get existing settings dict (or empty)
        settings = get_user_setting(username=username, key="all") or {}

        # --- Persist all wizard settings under the same keys used on read -------
        settings.update({
            "known_process_scan": bool(self._cb_known.isChecked()),
            "ontop": bool(self._cb_ontop.isChecked()),
            "touch_mode": bool(self._cb_touch.isChecked()),
            "WinDefCheckbox": bool(self._cb_win_def.isChecked()),
            "DefenderQuickScan": bool(self._cb_def_quick.isChecked()),
            "lockout_threshold": int(self._sp_lockout.value()),
            "password_expiry_days": int(self._sp_expiry.value()),
            "clipboard_clear_timeout_sec": int(self._sp_clip.value()),
            "auto_logout_timeout_sec": int(self._sp_logout.value()),
        })

        # --- Save only the settings blob ----------------------------------------
        try:
            ok = set_user_setting(username=username, key="all", value=settings)
            if not ok:
                log.error("Saving settings failed for user %r", username)
        except Exception as e:
            log.error(f"Saving Settings on create account failed with: {e}")
            
        # --- update baseline note 
        update_baseline(username=username, verify_after=False, who="Create Account Settings Set")
            
    def _sha256_file(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

