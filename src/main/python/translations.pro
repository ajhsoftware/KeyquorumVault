# translations.pro – Qt translation project for Keyquorum
# All paths are relative to:  src/main/python/

# translations.pro – Qt translation project for Keyquorum

TEMPLATE = aux
TARGET = translations

# ----------------------------------------------------------
# SOURCES: tell lupdate what to scan
# ----------------------------------------------------------

# All Python files (recursive)
SOURCES += $$files(./*.py, true)
SOURCES += $$files(./pass_/*.py, true)
SOURCES += $$files(./ui_gen/*.py, true)
SOURCES += $$files(./resources/*.py, true)

SOURCES += \
    main.py \
    frameless_window.py \
    qr_tools.py \
    main.fixed.py \
    vault_store/add_entry_dialog.py \
    vault_store/authenticator_store.py \
    vault_store/key_utils.py \
    vault_store/delete_account_dialog.py \
    vault_store/account_creator.py \
    sync/engine.py \
    security/integrity_manifest.py \
    security/preflight.py \
    security/secure_audit.py \
    security/security_prefs_dialog.py \
    security/system_info.py \
    ui_gen/change_password_dialog_ui.py \
    ui_gen/activate_pre_dialog.py \
    ui_gen/device_unlock_dialog.py \
    ui_gen/emergency_kit_dialog.py \
    ui_gen/forgot_password_ui.py \
    ui_gen/password_history_dialog.py \
    ui_gen/qr_utils.py \
    ui_gen/uiwatchtower.py \
    pass_/password_generator.py \
    pass_/password_utils.py \
    pass_/twofa_dialog.py \
    pass_/yubikeydialog.py \
    pass_/forgot_password_dialog.py \
    pass_/identity_store.py \
    pass_/passkeys_panel.py \
    pass_/passkeys_windows.py \
    pass_/utils_recovery.py \
    pass_/change_password_dialog.py \
    lincence/licenses_dialog.py \
    lincence/rate_nudger.py \
    catalog_category/catalog_editor_user.py \
    catalog_category/category_editor.py \
    breach_check/breach_check_dialog.py \
    autofill/window_picker.py \
    auth/emergency_kit.py 


FORMS += \
    resources/ui/keyquorum_ui.ui

# (Add more .ui here later if you want them translated too)

TRANSLATIONS += \
    resources/i18n/keyquorum_en_GB.ts \
    resources/i18n/keyquorum_en_US.ts \
    resources/i18n/keyquorum_de_DE.ts \
    resources/i18n/keyquorum_fr_FR.ts \
    resources/i18n/keyquorum_es_ES.ts \
    resources/i18n/keyquorum_he_IL.ts \
    resources/i18n/keyquorum_it_IT.ts \
    resources/i18n/keyquorum_pt_BR.ts \
    resources/i18n/keyquorum_nl_NL.ts \
    resources/i18n/keyquorum_pl_PL.ts \
    resources/i18n/keyquorum_ro_RO.ts \
    resources/i18n/keyquorum_sv_SE.ts \
    resources/i18n/keyquorum_ru_RU.ts \
    resources/i18n/keyquorum_th_TH.ts \
    resources/i18n/keyquorum_uk_UA.ts \
    resources/i18n/keyquorum_ko_KR.ts \
    resources/i18n/keyquorum_zh_CN.ts \
    resources/i18n/keyquorum_en_CA.ts \
    resources/i18n/keyquorum_vi_VN.ts \
    resources/i18n/keyquorum_zh_TW.ts \
    resources/i18n/keyquorum_ms_MY.ts \
    resources/i18n/keyquorum_tr_TR.ts \
    resources/i18n/keyquorum_no_NO.ts \
    resources/i18n/keyquorum_ja_JP.ts \
    resources/i18n/keyquorum_id_ID.ts \
    resources/i18n/keyquorum_hu_HU.ts \
    resources/i18n/keyquorum_ar_EG.ts \
    resources/i18n/keyquorum_bg_BG.ts \
    resources/i18n/keyquorum_cs_CZ.ts \
    resources/i18n/keyquorum_da_DK.ts \
    resources/i18n/keyquorum_hi_IN.ts \
    resources/i18n/keyquorum_fi_FI.ts \
    resources/i18n/keyquorum_en_NZ.ts \
    resources/i18n/keyquorum_en_IN.ts \
    resources/i18n/keyquorum_fa_IR.ts \
    resources/i18n/keyquorum_en_IE.ts \
    resources/i18n/keyquorum_en_AU.ts 


# ----------------------------------------------------------
# Let lupdate treat _tr() as translate function
# ----------------------------------------------------------

LUPDATE = -tr-function-alias tr=_tr
