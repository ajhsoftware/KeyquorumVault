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

# --- log ---
import logging
log = logging.getLogger("keyquorum")
import app.kq_logging as kql
import json
from app.paths import config_dir
from qtpy.QtCore import QLocale, QTranslator
from qtpy.QtWidgets import QMessageBox

# ==============================
# --- ui link language
# ==============================

# Single global language preference file
lang_file = config_dir(None, ensure_parent=True) / "language.json"

def _load_ui_language() -> str:
    """
    Read the last chosen UI language from language.json.
    Returns "" if no preference is stored.
    """
    try:
        if lang_file.exists():
            with open(lang_file, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
            return str(data.get("ui_language", "")).strip()
    except Exception as e:
        try:
            log.warning(f"[LANG] failed to load language.json: {e}")
        except Exception:
            pass
    return ""


# ==============================
# --- UI language preference (per-user) -----------------------------------
# ==============================

def _init_language_from_file(w) -> None:
    """
    Resolve startup language from language.json and sync the combo box.
    """
    # 1) Get the startup language code ("system", "en_GB", "de_DE", etc.)
    w.ui_language_code = w._startup_language_code()

    # 2) Log what we chose
    log.info(
        "%s [LANG] startup ui_language_code=%r (source=file or default)",
        kql.i("tool"),
        w.ui_language_code,
    )

    # 3) Prepare the language selector combo with that code pre-selected
    try:
        w._init_language_selector(w.ui_language_code)
    except Exception as e:
        log.error(
            "%s [LANG] Failed to init language selector: %s",
            kql.i("tool"),
            e,
        )

def _available_languages(w) -> list[tuple[str, str]]:
    """
    list of (label, code). Code is what we store in user_db.json as
    `settings.ui_language`. You can add/remove languages here later.
    """
    # Extend the list of available UI languages.  Each entry is a tuple
    # of (human‑readable label, locale code).  The locale code must
    # correspond to a compiled translation file (e.g. keyquorum_<code>.qm)
    # in the i18n resources directory.  When adding new languages,
    # ensure you also provide the matching .ts and .qm files.
    return [
        ("System default", "system"),

    # ── English variants ─────────────────────────
    ("English (United Kingdom)", "en_GB"),
    ("English (United States)", "en_US"),
    ("English (Australia)", "en_AU"),
    ("English (Canada)", "en_CA"),
    ("English (Ireland)", "en_IE"),
    ("English (India)", "en_IN"),
    ("English (New Zealand)", "en_NZ"),

    # ── Major European languages ─────────────────
    ("Deutsch (German)", "de_DE"),
    ("Español (Spanish)", "es_ES"),
    ("Français (French)", "fr_FR"),
    ("Italiano (Italian)", "it_IT"),
    ("Português (Brazil)", "pt_BR"),
    ("Nederlands (Dutch)", "nl_NL"),
    ("Polski (Polish)", "pl_PL"),
    ("Čeština (Czech)", "cs_CZ"),
    ("Dansk (Danish)", "da_DK"),
    ("Suomi (Finnish)", "fi_FI"),
    ("Magyar (Hungarian)", "hu_HU"),
    ("Română (Romanian)", "ro_RO"),
    ("Svenska (Swedish)", "sv_SE"),
    ("Norsk Bokmål (Norwegian)", "no_NO"),
    ("Български (Bulgarian)", "bg_BG"),
    ("Українська (Ukrainian)", "uk_UA"),
    ("Русский (Russian)", "ru_RU"),

    # ── East Asian languages ─────────────────────
    ("日本語 (Japanese)", "ja_JP"),
    ("한국어 (Korean)", "ko_KR"),
    ("简体中文 (Chinese Simplified)", "zh_CN"),
    ("繁體中文 (Chinese Traditional)", "zh_TW"),

    # ── Other languages ──────────────────────────
    ("Türkçe (Turkish)", "tr_TR"),
    ("Bahasa Indonesia (Indonesian)", "id_ID"),
]

def _init_language_selector(w, selected_code: str | None = None) -> None:
    """
    Populate the Settings → Language combo and set it to the saved value.
    """
    combo = getattr(w, "language_combo", None)
    if combo is None:
        return

    langs = w._available_languages()
    code = selected_code or "system"

    try:
        combo.blockSignals(True)
        combo.clear()
        for label, c in langs:
            combo.addItem(label, c)

        # Pick matching code
        idx = 0
        for i in range(combo.count()):
            if combo.itemData(i) == code:
                idx = i
                break
        combo.setCurrentIndex(idx)
    finally:
        try:
            combo.blockSignals(False)
        except Exception:
            pass

    # Wire change handler (idempotent)
    try:
        combo.currentIndexChanged.disconnect(w._on_language_combo_changed)
    except Exception:
        pass
    combo.currentIndexChanged.connect(w._on_language_combo_changed)

def _on_language_combo_changed(w, idx: int):
    if not getattr(w, "language_combo", None):
        return
    combo = w.language_combo
    code = combo.itemData(idx)
    if not code:
        return

    # Save the preference (__global__ settings)
    w._persist_language_choice(code)

    # Apply translator immediately
    try:
        w._install_translator_for_code(code, persist=False)
        eff = w._effective_lang_code(code)
        w.set_status_txt(
            w.tr("App language set to: ") + f"{eff}" + w.tr(" (most texts updated; restart to refresh everything).")
        )
        log.info("%s [LANG] user changed app language → %r (effective=%r)",
                    kql.i("ok"), code, eff)
    except Exception as e:
        log.warning("%s [LANG] failed to apply language %r: %s",
                    kql.i("warn"), code, e)
        w.set_status_txt(
            w.tr("Saved language preference ") + f"'{code}'" + w.tr(", but could not apply translator now.")
        )

    # Ask the user if they want to restart now
    try:
        reply = QMessageBox.question(
            w,
            w.tr("Restart required"),
            (
                w.tr("To fully apply the language change, Keyquorum Vault needs to restart.\n\n"
                "Do you want to restart now?")
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if reply == QMessageBox.Yes:
            w._restart_application()
    except Exception as e:
        log.warning("%s [LANG] failed to show restart prompt: %s", kql.i("warn"), e)

def _persist_language_choice(w, code: str, flush: bool = True) -> None:
    """
    Save UI language to a single global language.json file.
    We no longer write ui_language into user_db.json.
    """
    w.ui_language_code = code or "system"

    try:
        with open(lang_file, "w", encoding="utf-8") as f:
            json.dump({"ui_language": w.ui_language_code}, f, indent=2)
        log.debug(
            "%s [LANG] wrote language.json → %s",
            kql.i("tool"),
            w.ui_language_code,
        )
    except Exception as e:
        log.error("%s [LANG] failed write language.json: %s", kql.i("err"), e)

def _startup_language_code(w) -> str:
    """
    Language to use at app start:
    - First, try language.json (global UI preference).
    - Fallback to 'system' if nothing is stored.
    """
    code = _load_ui_language()
    if not code:
        code = "system"
    return code

def _effective_lang_code(w, code: str | None) -> str:
    """
    Turn 'system' / None / 'en_US' into something usable.
    - 'system' or None  → use OS default / built-in English
    - 'en_US'           → alias to 'system' (no .qm required)
    - others            → locale code like 'de_DE', 'fr_FR', etc.
    """
    # Treat US English as just "system" (no QM, no warning)
    if code == "en_US":
        return "system"

    if not code or code == "system":
        try:
            return QLocale.system().name() or "en_GB"
        except Exception:
            return "en_GB"

    return str(code).replace("-", "_")

def _install_translator_for_code(w, ui_lang: str | None, *, persist: bool = False) -> None:
    """
    Install a Qt translator for the requested UI language and retranslate the UI.
    ui_lang is the stored preference: "system", "en_GB", "de_DE", etc.
    """
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        log.warning("%s [LANG] QApplication.instance() is None, cannot install translator",
                    kql.i("warn"))
        return

    # Work out the effective language code
    try:
        effective = w._effective_lang_code(ui_lang)
    except Exception as e:
        log.warning("%s [LANG] _effective_lang_code failed for %r: %s",
                    kql.i("warn"), ui_lang, e)
        effective = None

    # Remove any previous translator
    try:
        old = getattr(w, "_translator", None)
        if old is not None:
            app.removeTranslator(old)
    except Exception:
        pass
    w._translator = None

    # "system" means: no explicit .qm, just default English
    if not effective or effective == "system":
        log.info("%s [LANG] using system/default language (no .qm)", kql.i("ok"))

        # If we’re asked to persist, write "system" into language.json
        if persist:
            try:
                with open(lang_file, "w", encoding="utf-8") as f:
                    json.dump({"ui_language": "system"}, f, indent=2)
                log.debug("%s [LANG] persisted language.json → system", kql.i("tool"))
            except Exception as e:
                log.error("%s [LANG] failed to persist language.json (system): %s",
                            kql.i("err"), e)

        if hasattr(w, "retranslateUi"):
            try:
                w.retranslateUi(w)
            except Exception as e:
                # Only log at debug level to avoid spamming warnings; this
                # call is best-effort and the UI will be refreshed on restart
                log.debug("%s [LANG] retranslateUi(system) failed: %s",
                            kql.i("warn"), e)
        return

    qm_filename = f"keyquorum_{effective}.qm"
    from app.paths import lang_dir
    lang_dir_ = lang_dir()
    qm_path = lang_dir_ / qm_filename
 
    log.info(log.info(f"{kql.i('ui')} [LANG] Current Lang file: {qm_filename} (exists={qm_path.exists()})"))

    if qm_path is None:
        log.warning("%s [LANG] No QM file found for %r (candidates: %s)",
                    kql.i("warn"), effective, {qm_path})
        return

    tr = QTranslator()
    if not tr.load(str(qm_path)):
        log.warning("%s [LANG] Failed to load QM %s", kql.i("warn"), qm_path)
        return

    app.installTranslator(tr)
    w._translator = tr

    # If requested, persist the current choice into language.json
    if persist:
        try:
            with open(lang_file, "w", encoding="utf-8") as f:
                json.dump(
                    {"ui_language": ui_lang or effective or "system"},
                    f,
                    indent=2,
                )
            log.debug("%s [LANG] persisted language.json via _install_translator_for_code → %s",
                        kql.i("tool"), ui_lang or effective or "system")
        except Exception as e:
            log.error("%s [LANG] failed to persist language.json: %s", kql.i("err"), e)

    # Retranslate the whole UI so labels/buttons update immediately, but only
    # if a retranslateUi() method exists.  When the UI is loaded from
    # .ui files at runtime, KeyquorumApp itw has no retranslateUi
    # attribute; skipping avoids AttributeError warnings.  Any missing
    # translations will be applied on restart.
    if hasattr(w, "retranslateUi"):
        try:
            w.retranslateUi(w)
        except Exception as e:
            log.debug("%s [LANG] retranslateUi(%r) failed: %s",
                        kql.i("warn"), effective, e)

    log.info("%s [LANG] translator installed: requested=%r effective=%r qm=%s",
                kql.i("ui"), ui_lang, effective, qm_path)
