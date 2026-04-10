"""Keyquorum Vault
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
Central UI wiring for Keyquorum Vault.

This file is responsible for:
- Finding widgets created by the .ui file (via findChild)
- Wiring UI controls (buttons, menus, text changes, spin boxes)
- Connecting signals to existing MainWindow methods

IMPORTANT:
- This file must NOT contain business logic (auth, vault, crypto).
- It should only connect UI elements to methods defined elsewhere.
- All functions here receive the MainWindow instance as `w`.

If you are looking for:
- What a button does → look here
- Where widgets are found → look here
- How signals are connected → look here
"""

# - import Logging
from ast import Lambda
import logging
import app.kq_logging as kql
log = kql.setup_logging("keyquorum")

import os, sys
from typing import Dict, List, Optional
from features.url.main_url import open_url
from ui.ui_find import find_all
from ui.ui_flags import on_reset_hide_flags_clicked, _maybe_show_release_notes
from new_users.ui_wizard_create_account import create_account
from new_users.tour import maybe_show_quick_tour
from features.backup_advisor.ui_backup_bind import init_backup_avisor
from features.autofill.autofill_ui_bind import on_autofill_to_app_clicked
from auth.logout.logout_flow import logout_user
from app.basic import _UiBus
from security.baseline_signer import update_baseline
from features.backup_advisor.ui_backup_bind import backup_software_folder, restore_software_folder
from features.security_center.security_center_ui import _run_security_center_scan, on_security_open_integrity_clicked

from features.sync.sync_ops import (on_autosync_clicked, one_time_mobile_transfer, on_stop_cloud_sync_keep_local,
                                    on_toggle_extra_cloud_wrap, on_copy_vault_to_cloud, on_button_sync_cloud, on_select_cloud_vault, )

from auth.login.auth_flow_ops import (on_yk_setup_clicked, on_generate_recovery_key_clicked,
                           clear_passwordless_unlock_on_this_device, clear_remembered_username,)

from features.auth_store.auth_ops import (_auth_add_from_screen, _auth_add_from_camera, _auth_edit_selected,
                                          _auth_delete_selected,_auth_add_manual,
                                            _auth_show_qr_selected,_auth_copy_code, _auth_import_safe, _auth_export_safe,
                                            _auth_add_from_qr, init_authenticator_tab)
import webbrowser

from app.dev import dev_ops
is_dev = dev_ops.dev_set

from features.share.share_ops import(import_share_packet, make_share_packet, export_my_share_id,
                                        quick_import_from_qr, quick_export_scan_only,)

from bridge.bridge_ops import on_pair_browser_, on_install_ext_, _on_bridge_toggle
from features.systemtray.systemtry_ops import setup_tray

from app.update import AppUpdater

def setup_update_button(self):
    self.updater = AppUpdater(parent=self)
    self.update_btn.clicked.connect(self.updater.check_for_updates)


try:
    from app.qt_imports import *  # noqa: F401,F403
except Exception:
    pass

def bind_all(w):
    find_all(w)
    init__lang(w)
    init_buttons(w)
    init_text_change(w)
    init_menu_list(w)
    init_setText(w)
    init_spin_box(w)
    init_authenticator_tab(w)
    init_watchtower(w)
    init_backup_avisor(w)
    init__default(w)
    init__setitems(w)        
    install_windows_auto_lock(w)
    init_login_remember_username(w)
    setup_tray(w)
    setup_update_button(w)


def init_login_remember_username(w):
    try:
        cb = getattr(w, "remember_username", None)
        le = getattr(w, "usernameField", None)

        if cb is None or le is None:
            log.info("[LOGIN] remember-username init: missing widgets cb=%s le=%s", bool(cb), bool(le))
            return

        s = QSettings("AJHSoftware", "KeyquorumVault")
        remembered = (s.value("login/remembered_username", "") or "").strip()

        if remembered and not cb.isChecked():
            cb.setChecked(True)

        def _apply():
            try:
                # re-fetch (in case UI recreated widgets)
                le2 = getattr(w, "usernameField", None) or le
                cb2 = getattr(w, "remember_username", None) or cb

                if cb2 and cb2.isChecked() and remembered:
                    # Only set if currently empty
                    if not (le2.text() or "").strip():
                        le2.setText(remembered)
                    le2.repaint()

                    log.info(
                        "[LOGIN] remember-username applied widget=%s name=%s text_now=%r",
                        getattr(le2, "objectName", lambda: "?")(),
                        type(le2).__name__,
                        le2.text(),
                    )
            except Exception as e:
                log.debug("[LOGIN] remember-username apply failed: %s", e)

        # Apply immediately + once again after the UI is fully shown
        _apply()
        QTimer.singleShot(0, _apply)
        QTimer.singleShot(200, _apply)

    except Exception as e:
        log.debug(f"[LOGIN] remember-username init failed: {e}")


def apply_remembered_username_to_login_screen(w):
    try:
        cb = getattr(w, "remember_username", None)
        le = getattr(w, "usernameField", None)
        if cb is None or le is None:
            return

        s = QSettings("AJHSoftware", "KeyquorumVault")
        remembered = (s.value("login/remembered_username", "") or "").strip()

        if cb.isChecked() and remembered:
            le.setText(remembered)
        else:
            le.clear()
    except Exception:
        pass


def init_buttons(w):
    # ==============================
    # --- settings menu buttons
    # ==============================

    w.mainTabs.currentChanged.connect(w.on_tab_changed)

    getattr(w, 'restHidden', None) and w.restHidden.clicked.connect(lambda: on_reset_hide_flags_clicked(w))   # - reset all hiden flages (must update when adding new ones)
    w.newBug.clicked.connect(lambda: _maybe_show_release_notes(w))                # - show whats new/bug
    w.general_.clicked.connect(lambda: w.stackedWidget.setCurrentIndex(0))        # - change widget
    w.audit_log_.clicked.connect(lambda: w.stackedWidget.setCurrentIndex(4))      # - change widget
    w.profile_.clicked.connect(lambda: w.stackedWidget.setCurrentIndex(2))        # - change widget
    w.portable_.clicked.connect(lambda: w.stackedWidget.setCurrentIndex(1))       # - change widget
    w.backup_retore_.clicked.connect(lambda: w.stackedWidget.setCurrentIndex(3))  # - change widget
    w.pre_security_.clicked.connect(lambda: w.stackedWidget.setCurrentIndex(5))   # - change widget
    w.categoryeditor_.clicked.connect(w.categury_load_schema)                     # - load schema
    w.sync_button.clicked.connect(lambda: w.stackedWidget.setCurrentIndex(7))     # - cloud sync 
    w.clear_passwordless.clicked.connect(lambda: clear_passwordless_unlock_on_this_device(w))    # - clear passwordless
    w.deleteAccountButton.clicked.connect(lambda: w.open_delete_account_dialog(w.currentUsername.text() or "").strip())    # - delete user
    w.clear_username.clicked.connect(lambda: clear_remembered_username(w))    
    
    try:
        from features.url.main_url import SITE_SUPPORT_ME
        w.support_me2.clicked.connect(lambda: webbrowser.open(SITE_SUPPORT_ME))
    except Exception as e:
        pass 

    # ==============================
    # --- Login/Out 
    # ==============================
    # - Login Screen Button
    w.createAccountButton.clicked.connect(lambda: create_account(w))
    w.loginButton.clicked.connect(w.attempt_login)
    w.importVaultButton_2.clicked.connect(w.import_vault_custom)
    w.forgotPassword.clicked.connect(w.open_forgot_password_dialog)  
    w.showPasswordCheckbox.toggled.connect(
    lambda checked: _on_show_password_toggled(checked, w))

    w.fast_mode.hide()  # fast autofill hidden as new fucsion same speed, note: remove ui/code soon
    # - slecte usb for vault  

    w.selectUsbButton.clicked.connect(w.on_select_usb_clicked)
    # setup ykSetupBtn 
    w.btnDeviceUnlock.clicked.connect(lambda: on_yk_setup_clicked(w))
    w.regen_key_.clicked.connect(lambda: on_generate_recovery_key_clicked(w, "login"))
    w.regen_key_2fa.clicked.connect(lambda: on_generate_recovery_key_clicked(w, "2fa"))
    w.regen_key_both.clicked.connect(lambda: on_generate_recovery_key_clicked(w, "both"))
    # - Logout Screen Button
    w.logoutButton.clicked.connect(lambda: logout_user(w, skip_backup=False))

    # ==============================
    # --- backup restore
    # ==============================

    w.exportVaultButton.clicked.connect(w.export_vault)
    w.importVaultButton.clicked.connect(w.import_vault_custom)
    w.exportWithPasswordButton.clicked.connect(lambda: w.export_vault_with_password(skip_ask=False))
    w.importWithPasswordButton.clicked.connect(w.import_vault_with_password)
    w.backup_software.clicked.connect(lambda: backup_software_folder(w))
    w.restore_software.clicked.connect(lambda: restore_software_folder(w))

    # ==============================
    # --- Portable
    # ==============================
    w.btnMoveToUSB.clicked.connect(w.action_move_user_to_usb)                     # - move user to usb
    w.btnMoveBack.clicked.connect(w.action_move_user_from_usb)                    # - move user back from usb
    try:
        # Prefer non-blocking rebuild if available
        if hasattr(w, 'on_rebuild_portable_clicked2'):
            w.btnCreatePortable.clicked.connect(w.on_rebuild_portable_clicked2)
        else:
            w.btnCreatePortable.clicked.connect(w.on_rebuild_portable_clicked)
    except Exception:
        try:
            w.btnCreatePortable.clicked.connect(w.on_rebuild_portable_clicked)
        except Exception:
            pass            # - create porable (build/rebuild)

    # ==============================
    # --- security/prefs
    # ==============================
    # --- Login (per-user) controls ---
    w.preflight_config.clicked.connect(w.open_security_prefs)
    w.enableWinDefCheckbox_.toggled.connect(w.on_enable_WinDefCheckbox_toggled)
    w.DefenderQuickScan_.toggled.connect(w.on_enable_DefenderQuickScan_toggled)
    w.preflight_check_now.clicked.connect(w.on_run_preflight_now_clicked)
    w.enablePreflightCheckbox.toggled.connect(w.on_enable_preflight_toggled)
    # --- Startup (global/default) controls (newer UI names end with _2). Guard so older .ui still works. ---
    w.preflight_config_2.clicked.connect(w.open_security_prefs_startup)
    w.enableWinDefCheckbox_2.toggled.connect(w.on_enable_WinDefCheckbox_toggled)
    w.DefenderQuickScan_2.toggled.connect(w.on_enable_DefenderQuickScan_toggled)
    w.enablePreflightCheckbox_2.toggled.connect(w.on_enable_preflight_toggled)   
    w.preflight_check_now_2.clicked.connect(w.run_preflight_now_startup)
    # --- password breach checker ---
    w.enable_breach_checker_.toggled.connect(w.enable_breach_checker_change)    
    # --- baseline check ---
    w.updatebaseline_2.clicked.connect(lambda: update_baseline(username=w.currentUsername.text(), verify_after=False, who=w.tr("Setting Updated Basline Button Clicked"), show_message=True, parent=w))
    w.check_baseline.clicked.connect(lambda: w.integrity_check_and_prompt(w.currentUsername.text()))
    w.check_baseline_2.clicked.connect(lambda: w.integrity_check_and_prompt(w.currentUsername.text()))
    # --- backup code regen login/yubi & tfa ---
    w.regen_key_1.clicked.connect(lambda: on_generate_recovery_key_clicked(w, "login"))
    w.regen_key_2fa_2.clicked.connect(lambda: on_generate_recovery_key_clicked(w, "2fa"))


    # ==============================
    # - vault table
    # ==============================
    w.openSite.clicked.connect(w.on_open_site_clicked)                         
    w.addEntryButton.clicked.connect(w.open_add_entry_dialog)                   
    w.editEntryButton.clicked.connect(w.handle_edit_button)
    from vault_store.soft_delete_ops import delete_selected_vault_entry, show_trash_manager
    w.vaultDeleteButton.clicked.connect(lambda: delete_selected_vault_entry(w))
    w.softdelete_.clicked.connect(lambda: show_trash_manager(w))
    from features.reminders.reminder_ops import notify_due_reminders
    w.recheck_btn.clicked.connect(lambda: notify_due_reminders(w, force_not=True))
    w.autofill_app.clicked.connect(lambda checked=False, w=w: on_autofill_to_app_clicked(w, checked))
    w._wire_move_button()                                                        
    if w.vaultTable is not None:                                              
        w.vaultTable.cellDoubleClicked.connect(w.on_table_double_clicked)     
        w.vaultTable.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)   
        w.vaultTable.customContextMenuRequested.connect(w.show_entry_context_menu)
    w.qrshow_.clicked.connect(w.show_qr_for_selected)
    w.reminder_btn.clicked.connect(w.open_reminders_dialog)  
    # ==============================
    # - other
    # ==============================
    w.ontop_.toggled.connect(w.on_enable_ontop_toggled)                      
    w.debug_set_.toggled.connect(w.enable_debug_logging_change)            
    w.deleteAuditLogs.clicked.connect(w.delete_audit_logs)                 
    w.audit_export_.clicked.connect(w.on_export_audit_clicked)     
    w.refreshAuditLogs_.clicked.connect(w.load_audit_table)
    w.changePasswordButton.clicked.connect(w.open_change_password_dialog) 
    w.twoFACheckbox.toggled.connect(w.toggle_2fa_setting)                    
    w.changePicButton.clicked.connect(w.change_profile_picture)       
    from features.backup_advisor.ui_backup_bind import export_csv, import_csv_entries
    w.import_csv_entries_bn.clicked.connect(lambda: import_csv_entries(w))
    w.export_csv_entries_bn.clicked.connect(lambda: export_csv(w))              
    w.password_generator.clicked.connect(w.open_generator)      
    # -----------------------
    # - Cloud Sync
    # -----------------------
    w.cloud_widget.hide()
    w.on_sync_now.clicked.connect(lambda: on_button_sync_cloud(w))

    # ---
    w.on_sync_now_2.clicked.connect(lambda: on_button_sync_cloud(w))
    w.autosync_.clicked.connect(lambda c: on_autosync_clicked(w,c))
    # ---

    from features.sync.sync_ops import _manual_pull, _manual_push
    w.pull_btn.clicked.connect(lambda: _manual_pull(w))
    w.push_btn.clicked.connect(lambda: _manual_push(w))

    w.select_cloud.clicked.connect(lambda: on_select_cloud_vault(w))
    w.select_cloud_2.clicked.connect(lambda: on_select_cloud_vault(w))
    w.move_vault_to_cloud.clicked.connect(lambda: on_copy_vault_to_cloud(w))       
    w.extra_cloud_wrap.clicked.connect(lambda: on_toggle_extra_cloud_wrap(w))    
    w.stop_cloud_sync.clicked.connect(lambda: on_stop_cloud_sync_keep_local(w))    
    w.one_time_mobile_transfer_.clicked.connect(lambda: one_time_mobile_transfer(w))


    w.tuchmode_.toggled.connect(w.save_to_user_on_touch)
    w.tuchmode_2.toggled.connect(w.on_touch_mode_toggled_set)
    # -----------------------
    # - First time boot/tour button
    # -----------------------
    w.bowser_btn_2.clicked.connect(lambda: maybe_show_quick_tour(w, "core"))
    w.bowser_btn_3.clicked.connect(lambda: maybe_show_quick_tour(w, "authenticator"))
    w.bowser_btn_4.clicked.connect(lambda: maybe_show_quick_tour(w, "audit"))
    w.bowser_btn_7.clicked.connect(lambda: maybe_show_quick_tour(w, "backup"))
    # -----------------------
    # - Passkey
    # -----------------------
    import features.passkeys.passkeys_windows as pkwin
    import features.passkeys.capabilities as cap
    w.btnEnablePasskeyProvider.clicked.connect(
        lambda: (pkwin.ensure_enabled_ui(w), w._refresh_passkey_ui())
    )
    w.btnOpenSettings.clicked.connect(
        lambda: (cap.open_windows_passkey_settings(), w._refresh_passkey_ui())
    )
    w.btnInstallPasskey.clicked.connect(w.on_install_passkeys_clicked)
    w.btnUninstallPasskey.clicked.connect(w.on_uninstall_passkeys_clicked)
    # - Stored Passkeys manager
    w._init_passkeys_table()
    w.btnPasskeyRefresh.clicked.connect(w._reload_passkeys_for_current_user)
    w.btnPasskeyDelete.clicked.connect(w._delete_selected_passkey)
    w.btnPasskeyDisable.clicked.connect(lambda: w._set_selected_passkey_disabled(True))
    w.btnPasskeyEnable.clicked.connect(lambda: w._set_selected_passkey_disabled(False))
    w.btnPasskeyRename.clicked.connect(w._rename_selected_passkey)
    w.pair_passkey.clicked.connect(w.launch_passkey_manager_with_token)
    # -----------------------
    # - catalog 
    # -----------------------
    w.catalog_edit_.clicked.connect(w.open_catalog_editor)
    # -----------------------
    # - Security Center tab 
    # -----------------------
    w.securityRefreshButton.clicked.connect(lambda: _run_security_center_scan(w))        
    w.securityOpenIntegrityButton.clicked.connect(lambda: on_security_open_integrity_clicked(w))
    w.securityPreflightConfigButton.clicked.connect(w.open_security_prefs)
    w.changePasswordButton_2.clicked.connect(w.open_change_password_dialog)  
    w.btnDeviceUnlock_2.clicked.connect(lambda: on_yk_setup_clicked(w))
    w.exportWithPasswordButton_2.clicked.connect(lambda: w.export_vault_with_password(skip_ask=False)) 
    w.exportVaultButton_2.clicked.connect(w.export_vault)
    w.exportVaultButton_3.clicked.connect(w.export_vault)
    # -----------------------
    # - bridge 
    # -----------------------

    if hasattr(w, "bridgeEnableSwitch"):
        w.bridgeEnableSwitch.toggled.connect(lambda checked: _on_bridge_toggle(w, checked))
    # -----------------------
    # - authenticator 
    # -----------------------
    w.btnAuthAdd.clicked.connect(lambda: _auth_add_manual(w))
    w.btnAuthAddQR.clicked.connect(lambda: _auth_add_from_qr(w))
    w.btnAuthAddScreen.clicked.connect(lambda: _auth_add_from_screen(w))
    w.btnAuthEdit.clicked.connect(lambda: _auth_edit_selected(w))
    w.btnAuthDelete.clicked.connect(lambda: _auth_delete_selected(w))
    w.btnAuthCopy.clicked.connect(lambda: _auth_copy_code(w))
    w.btnAuthAddCam.clicked.connect(lambda: _auth_add_from_camera(w))
    w.auth_qr_.clicked.connect(lambda: _auth_show_qr_selected(w))
    w.btnAuthSafeExport.clicked.connect(lambda: _auth_export_safe(w))
    w.btnAuthSafeImport.clicked.connect(lambda: _auth_import_safe(w))

    # ------------------------
    # Watchtower scan button
    # ------------------------
    btn = getattr(w, "scan_btn", None)
    if btn is not None:
        try:
            btn.clicked.disconnect()
        except Exception:
            pass

        if hasattr(w, "_watchtower_rescan"):
            btn.clicked.connect(w._watchtower_rescan)
        else:
            # No rescan method available → disable button safely
            btn.setEnabled(False)


def init_text_change(w):
    """Wire live local search + global(All vault) search. Auto-resolve the checkbox."""

    # --- Debounce timer for local filter ---
    try:
        if getattr(w, "_local_search_debounce", None):
            w._local_search_debounce.stop()
            w._local_search_debounce.deleteLater()
    except Exception:
        pass

    w._local_search_debounce = QTimer(w)
    w._local_search_debounce.setSingleShot(True)
    w._local_search_debounce.setInterval(160)

    # --- Username debounce (NEW – fixes tick / login UX) ---
    if not hasattr(w, "_username_debounce"):
        w._username_debounce = QTimer(w)
        w._username_debounce.setSingleShot(True)
        w._username_debounce.setInterval(140)
        w._username_debounce.timeout.connect(w.update_login_picture)

    # --- 3) Helper to (re)apply placeholder and maybe trigger a local filter ---
    def _reflect_badge_and_maybe_filter(on: bool | None = None):
        on = w.search_all_.isChecked() if (on is None and w.search_all_) else bool(on)
        try:
            w.vaultSearchBox.setPlaceholderText(
                "🔎" + w.tr(" Search across vault") + " 🔐 " + w.tr("press Enter")
                if on else
                "🔎" + w.tr(" Search current category… (start typing)")
            )
        except Exception:
            pass

        if not on:
            txt = (w.vaultSearchBox.text() or "").strip()
            try:
                w._local_search_debounce.stop()
                w._local_search_debounce.timeout.disconnect()
            except Exception:
                pass
            w._local_search_debounce.timeout.connect(lambda t=txt: w.filter_vault_table(t))
            w._local_search_debounce.start()

    # --- 4) (Re)connect search signals defensively ---
    try:
        try: w.vaultSearchBox.returnPressed.disconnect()
        except Exception: pass
        w.vaultSearchBox.returnPressed.connect(w.on_vault_search_committed)
    except Exception as e:
        log.debug(f"[SEARCH] returnPressed connect failed: {e}")

    def _on_text_changed(text: str):
        try:
            if w.search_all_ and w.search_all_.isChecked():
                return
            try:
                w._local_search_debounce.stop()
                w._local_search_debounce.timeout.disconnect()
            except Exception:
                pass
            w._local_search_debounce.timeout.connect(
                lambda: w.filter_vault_table((text or "").strip())
            )
            w._local_search_debounce.start()
        except Exception as e:
            log.debug(f"[SEARCH] _on_text_changed failed: {e}")

    try:
        try: w.vaultSearchBox.textChanged.disconnect()
        except Exception: pass
        w.vaultSearchBox.textChanged.connect(_on_text_changed)
    except Exception as e:
        log.debug(f"[SEARCH] textChanged connect failed: {e}")

    # --- Checkbox wiring ---
    if w.search_all_:
        try:
            w.search_all_.setChecked(False)
            try: w.search_all_.toggled.disconnect()
            except Exception: pass
            w.search_all_.toggled.connect(lambda on: _reflect_badge_and_maybe_filter(on))
            _reflect_badge_and_maybe_filter(False)
        except Exception as e:
            log.debug(f"[SEARCH] checkbox init error: {e}")

    # --- ✅ Username live validation / picture / tick (debfounced) ---
    if getattr(w, "usernameField", None):
        try:
            try:
                w.usernameField.textChanged.disconnect()
            except Exception:
                pass

            def _on_username_typed(_text: str = ""):
                try:
                    # Recreate if someone cleared it after init
                    if getattr(w, "_username_debounce", None) is None:
                        w._username_debounce = QTimer(w)
                        w._username_debounce.setSingleShot(True)
                        w._username_debounce.setInterval(140)
                        try:
                            w._username_debounce.timeout.connect(w.update_login_picture)
                        except Exception:
                            pass
                    w._username_debounce.stop()
                    w._username_debounce.start()
                except Exception:
                    # Last resort: update immediately
                    try:
                        w.update_login_picture()
                    except Exception:
                        pass

            w.usernameField.textChanged.connect(_on_username_typed)

            # Enter in username box: attempt login if available, otherwise just refresh picture
            try:
                w.usernameField.returnPressed.disconnect()
            except Exception:
                pass
            try:
                w.usernameField.returnPressed.connect(lambda: w.passwordField.setFocus())
            except Exception:
                pass

                        # Enter in username box: attempt login if available, otherwise just refresh picture
            try:
                w.passwordField.returnPressed.disconnect()
            except Exception:
                pass
            try:
                w.passwordField.returnPressed.connect(w.attempt_login)
            except Exception:
                pass
        except Exception as e:
            log.debug(f"[LOGIN] username wiring failed: {e}")
    log.debug("%s [UI] Text Change Wired", kql.i("ok"))


def init_menu_list(w):
    # -----------------------
    # --- browser menu ----------------
    # -----------------------
    menu = QMenu(w.bowser_btn)                      
    menu.addAction(w.actionInstall_Extension)                        
    menu.addAction(w.actionPair_Browser_Token)         
    menu.addAction(w.actionAutofill_test_site)  
    menu.addAction(w.actionExtension_Help)           
    w.bowser_btn.setMenu(menu)                 
    w.bowser_btn.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)

    w.actionPair_Browser_Token.triggered.connect(lambda: on_pair_browser_(w))        
    w.actionInstall_Extension.triggered.connect(lambda: on_install_ext_(w)) 
    w.actionAutofill_test_site.triggered.connect(lambda: open_url("SITE_BROW_TEST", default_=True)) 
    w.actionExtension_Help.triggered.connect(lambda: open_url("SITE_BROWSER", default_=True)) 
    w.bowser_btn.setDefaultAction(w.actionPair_Browser_Token)     

    # -----------------------
    # --- shared ----------------
    # -----------------------
    menu2 = QMenu(w.share_)                            
    menu2.addAction(w.actionMake_Share_Packet) 
    menu2.addAction(w.actionImport_Share_Packet)  
    menu2.addAction(w.actionExport_My_Share_ID)  
    menu2.addAction(w.action_quick_scan_qr)  
    menu2.addAction(w.actionQuick_Export_Scan_Only)  

    w.share_.setMenu(menu2)                                                  
    w.share_.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)  
    w.actionMake_Share_Packet.triggered.connect(lambda: make_share_packet(w))      
    w.actionExport_My_Share_ID.triggered.connect(lambda: export_my_share_id(w))   
    w.actionImport_Share_Packet.triggered.connect(lambda: import_share_packet(w))   
    w.action_quick_scan_qr.triggered.connect(lambda: quick_import_from_qr(w))  
    w.actionQuick_Export_Scan_Only.triggered.connect(lambda: quick_export_scan_only(w))
        
    # -----------------------
    # --- Breach menu ----------------
    # -----------------------
    menu3 = QMenu(w.bowser_btn)                                       
    menu3.addAction(w.actionCheck_Email)                      
    menu3.addAction(w.actionCheck_Password)      
    w.breach_check_.setMenu(menu3)            
    w.breach_check_.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup) 
    w.actionCheck_Password.triggered.connect(w.open_password_breach_checker)    
    w.actionCheck_Email.triggered.connect(w.check_selected_email_breach)  
    w.breach_check_.setDefaultAction(w.actionCheck_Email)  

    # -----------------------
    # --- launch/install menu ----------------
    # -----------------------
    w.build_launch_install_menu() 


def init_setText(w):
    w.vaultSearchBox.setText("")              
    if w.tr("Label") != "Label":   # - Translate text from auth store
        msg1 = w.tr(
            "Translate: Label = {label}, Code = {code}, Remaining = {remaining}, "
            "Account = {account}, Issuer = {issuer}, Algorithm = {algorithm}, "
            "Digits = {digits}, Period = {period}\n"
            "0 = {d0}, 1 = {d1}, 2 = {d2}, 3 = {d3}, 4 = {d4}, "
            "5 = {d5}, 6 = {d6}, 7 = {d7}, 8 = {d8}, 9 = {d9}"
        ).format(
            label=w.tr("Label"),
            code=w.tr("Code"),
            remaining=w.tr("Remaining"),
            account=w.tr("Account"),
            issuer=w.tr("Issuer"),
            algorithm=w.tr("Algorithm"),
            digits=w.tr("Digits"),
            period=w.tr("Period"),
            d0=w.tr("0"),
            d1=w.tr("1"),
            d2=w.tr("2"),
            d3=w.tr("3"),
            d4=w.tr("4"),
            d5=w.tr("5"),
            d6=w.tr("6"),
            d7=w.tr("7"),
            d8=w.tr("8"),
            d9=w.tr("9"),
        )
        w.auth_tran_halp.setText(msg1)


def init_spin_box(w):
    if getattr(w, "lockoutSpinBox", None):                                                      # - lockout (int)
        _wire_spin(w.lockoutSpinBox, w.on_lockout_threshold_changed, int)

    if getattr(w, "password_expiry_days", None):                                                # - expiry days (int)  
        _wire_spin(w.password_expiry_days, w.on_password_expiry_days_change, int)

    if getattr(w, "clipboard_clear_timeout_", None):                                            # - clipboard clear (int)
        _wire_spin(w.clipboard_clear_timeout_, w.on_clipboard_clear_timeout_sec_change, int)

    if getattr(w, "auto_logout_timeout_", None):                                                # - Auto-logout (int, 0 = OFF)                                       
        w.auto_logout_timeout_.setMinimum(0)
        w.auto_logout_timeout_.setSpecialValueText(w.tr("Off"))
        _wire_spin(w.auto_logout_timeout_, w.on_auto_logout_timeout_sec_change, int)

    if getattr(w, "zoom_factor_", None):                                                        # - Zoom factor (QDoubleSpinBox) Profile PitcheFr Zoom
        _wire_spin(w.zoom_factor_, w.auto_zoom_factor, float)
        w.zoom_factor_.setKeyboardTracking(False)
        w.zoom_factor_.valueChanged.connect(lambda v: w.auto_zoom_factor(float(v)))
        w.zoom_factor_.editingFinished.connect(
            lambda: w.auto_zoom_factor(float(w.zoom_factor_.value()), flush=True)
        )

    log.debug("%s [UI] SpinBox", kql.i("ok"))
    

def init_watchtower(w):
    """Initialise Watchtower.
    For Pro gating / tab locking we keep a reference to the actual
    Watchtower tab page widget (w.watchtower_tab).
    """

    # Feature init (controller binds to embedded widgets)
    from features.watchtower.watchtower import build_watchtower_panel
    w.watchtower = build_watchtower_panel(w)

    # Cache the actual tab page widget for Pro-locking.
    w.watchtower_tab = None
    try:
        # Preferred: objectName in .ui
        from qtpy.QtWidgets import QWidget
        w.watchtower_tab = w.findChild(QWidget, "watchtowerTab")
    except Exception:
        w.watchtower_tab = None

    if w.watchtower_tab is None:
        # Fallback: find by tab label
        try:
            tabs = getattr(w, "mainTabs", None)
            if tabs is not None:
                for i in range(tabs.count()):
                    txt = (tabs.tabText(i) or "").strip().lower()
                    if "watchtower" in txt:
                        w.watchtower_tab = tabs.widget(i)
                        break
        except Exception:
            w.watchtower_tab = None

    # UI-only attach/wiring (now effectively a no-op, kept for compatibility)
    try:
        from ui.ui_bind import init_watchtower_ui
        init_watchtower_ui(w)
    except Exception:
        pass


def _wire_spin(spin, handler, cast=float):
    """Wire a QSpinBox/QDoubleSpinBox with debounced live updates + flush on commit."""
    if not spin or not handler:
        return

    # Don't emit on every keystroke
    try: spin.setKeyboardTracking(False)
    except Exception: pass

    # If we wired this spin before, cleanly disconnect old callbacks
    cb_val  = getattr(spin, "_kwire_value_cb", None)
    cb_edit = getattr(spin, "_kwire_edit_cb", None)
    if cb_val:
        try: spin.valueChanged.disconnect(cb_val)
        except Exception: pass
    if cb_edit:
        try: spin.editingFinished.disconnect(cb_edit)
        except Exception: pass

    # New callbacks (named so we can disconnect next time)
    def _on_val(v):
        try:
            handler(cast(v), flush=False)
        except TypeError:
            handler(cast(v))  # fallback if handler has no 'flush' kw

    def _on_edit():
        try:
            handler(cast(spin.value()), flush=True)
        except TypeError:
            handler(cast(spin.value()))
    spin.valueChanged.connect(_on_val)
    spin.editingFinished.connect(_on_edit)
    # Stash refs on the widget so we can disconnect later
    spin._kwire_value_cb = _on_val
    spin._kwire_edit_cb  = _on_edit


def init__default(w):
    """Default UI/runtime values."""
    if not is_dev:
        w.mainTabs.setTabEnabled(1, False)
        w.mainTabs.setTabEnabled(3, False)

    # ----- default values / sets -----
    w._yk_gate_satisfied = False
    w.expiry_days = None
    w.clipboard_clear_timeout_sec = None
    w.auto_logout_timeout_sec = None
    w.enable_breach_checker = None
    w.debug_set = False
    w.zoom_factor = 1.0
    w.threshold = None
    w._last_watchtower_counts = {}

    w._pending_values = {}   # type: Dict[str, float]  # type: ignore
    w._last_saved = {}       # type: Dict[str, float]  # type: ignore
    w._debouncers = {}       # type: Dict[str, QTimer]  # type: ignore

    w.user_remove_risk = True  # TODO: expose in settings
    w.successfulUser = None

    # - bridge
    w._uibus = _UiBus()
    w._bridge_token = None

    # - cloud
    w.auto = False

    # - auth store
    w._auth_timer = None      # type: Optional[QTimer]  # type: ignore
    w._auth_entries = []      # type: List[dict]  # type: ignore

    w.updatebaseline = update_baseline

    # lock / touch mode
    w._touch_init_done = True
    w.ps_score = None

    # vault state
    w.vault_unlocked = False          # type: bool  # type: ignore
    w.current_username = None         # type: Optional[str]  # type: ignore
    w.current_mk = None               # type: Optional[bytes]  # type: ignore

    log.debug("%s [UI] Default values set", kql.i("ok"))


def init__lang(w):
    from ui import ui_language as _lang
    w._init_language_from_file = lambda: _lang._init_language_from_file(w)
    w._startup_language_code = lambda: _lang._startup_language_code(w)
    w._init_language_selector = lambda code=None: _lang._init_language_selector(w, code)
    w._on_language_combo_changed = lambda idx: _lang._on_language_combo_changed(w, idx)


def init__setitems(w):
    from bridge.bridge_ops import stop_bridge_server
    STORE_BUILD = os.getenv("KQ_STORE_BUILD", "").lower() in ("1", "true", "yes")
    w.vaultTable.setEditTriggers(QAbstractItemView.NoEditTriggers)                   # - Vault table Edited Triggers
    w.auditTable.setEditTriggers(QAbstractItemView.NoEditTriggers)                   # - Audit table Edited Triggers
    w.authTable.setEditTriggers(QAbstractItemView.NoEditTriggers)                    # - Auth table Edited Triggers
    QApplication.instance().aboutToQuit.connect(lambda: stop_bridge_server(w))                # - Stop Bridge

    from features.backup_advisor.backup_advisor import FullBackupReminder
    w.full_backup_reminder = FullBackupReminder(                                     # - Hook full backup reminders
        parent=w,
        do_full_backup_callable=w.export_vault,)


def install_windows_auto_lock(w):
    """
    Always lock the vault on Windows lock / sleep / logoff / shutdown.
    Safe no-op on non-Windows.
    """
    try:
        from auth.logout.logout_flow import WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION, _WindowsSessionLockFilter
    except Exception as f:
        log.error(f"Error {f}")

    if not sys.platform.startswith("win"):
        return

    try:
        hwnd = int(w.winId())  # window handle

        # register for session notifications
        ok = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)
        if not ok:
            # don’t crash the app if Windows denies it
            return

        def _lock_cb(reason: str):
            # keep this VERY quiet: no popups
            try:
                w.force_logout()
            except Exception:
                pass

        w._win_lock_filter = _WindowsSessionLockFilter(hwnd, _lock_cb)
        from PySide6.QtWidgets import QApplication
        QApplication.instance().installNativeEventFilter(w._win_lock_filter)

    except Exception:
        # never break startup
        return


def _on_show_password_toggled(checked: bool, w):
    try:
        w.passwordField.setEchoMode(
            QLineEdit.Normal if checked else QLineEdit.Password
        )
    except Exception:
        pass
