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
from app.qt_imports import *
from auth.login.login_handler import _canonical_username_ci, get_user_setting, set_user_setting
from urllib.parse import urlparse



# =============================
# = Category dropdown population and styling ==
# =============================

# This function retrieves the list of category names for the active user, 
# using the same logic as the Category Editor (find_user + load_schema_for). 
# It falls back to built-in defaults if anything goes wrong, and it never returns an empty list. 
# Internal categories like 'Authenticator' are hidden from the main vault category dropdown.
def _schema_category_names(self, *args, **kwargs) -> list[str]:
    """
    Category names for the active user, using the same logic
    as the Category Editor (find_user + load_schema_for).
    Falls back to built-in defaults. Never returns an empty list.

    NOTE: internal categories like 'Authenticator' are hidden from the
    main vault category dropdown.
    """
    names: list[str] = []

    # categories we never want shown in the vault dropdown
    HIDDEN = {"authenticator"}

    try:
        # Work out current username as shown in the UI
        raw_name = ""
        if hasattr(self, "currentUsername") and hasattr(self.currentUsername, "text"):
            raw_name = self._active_username()

        canonical = ""
        if raw_name:
            try:
                canonical = _canonical_username_ci(raw_name) or raw_name
            except Exception:
                canonical = raw_name

        # Load the same schema the Category Editor uses
        if canonical:
            try:
                from catalog_category.category_editor import load_schema_for
                schema = load_schema_for(canonical) or {}
            except Exception:
                schema = {}
        else:
            schema = {}

        # Extract names from schema, skipping hidden ones
        for c in schema.get("categories", []):
            if not isinstance(c, dict):
                continue
            nm = (c.get("name") or "").strip()
            if nm and nm.strip().lower() not in HIDDEN:
                names.append(nm)

    except Exception as e:
        try:
            log.debug(f"[DEBUG] _schema_category_names failed: {e}")
        except Exception:
            pass

    # Fallback if we got nothing
    if not names:
        try:
            from catalog_category.category_fields import get_categories
            names = [
                n for n in get_categories()
                if isinstance(n, str) and n.strip().lower() not in HIDDEN
            ]
        except Exception:
            names = ["Passwords"]

    return names

# This function enforces a compact, consistent style for the category dropdown (QComboBox) used in the AddEntryDialog. 
# It sets fixed height, custom styles to remove extra padding/margins, and ensures the popup list is styled and sized appropriately. 
# This is necessary because QComboBox can have inconsistent appearances across platforms and styles, and we want to ensure it looks clean and compact.
def _enforce_category_compact(self, *args, **kwargs):
    combo: QComboBox = getattr(self, "categorySelector_2", None)
    if not isinstance(combo, QComboBox):
        return

    # ----- closed box (compact but readable) -----
    if not combo.objectName():
        combo.setObjectName("categorySelector_2")

    fm = combo.fontMetrics()
    h = max(fm.height() + 8, 28)                 # a touch larger so it feels deliberate
    combo.setMinimumHeight(h)
    combo.setMaximumHeight(h)
    combo.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

    # keep this widget’s style local
    combo.setStyleSheet(
        f"""
        QComboBox#categorySelector_2 {{
            combobox-popup: 0;                   /* ensure Qt uses stylable popup */
            min-height: {h}px;
            max-height: {h}px;
            padding: 4px 8px;
            margin: 0;
        }}
        QComboBox#categorySelector_2::drop-down {{ width: 16px; }}
        /* popup list (remove frame/margins that create the black bands) */
        QComboBox#categorySelector_2 QAbstractItemView {{
            padding: 0;
            margin: 0;
            border: 0;
            background: palette(Base);
            max-height: 260px;
        }}
        QComboBox#categorySelector_2 QAbstractItemView::item {{
            padding: 2px 8px;                    /* tidy row padding */
        }}
        """
    )

    # ----- popup view: own view so we fully control it -----
    view = getattr(combo, "_kq_view", None)
    if view is None:
        view = QListView(combo)
        combo._kq_view = view
        combo.setView(view)

    # remove the frame + any internal margins that draw black bars
    view.setFrameShape(QFrame.NoFrame)
    view.setFrameShadow(QFrame.Plain)
    view.setContentsMargins(0, 0, 0, 0)
    if view.viewport():
        view.viewport().setContentsMargins(0, 0, 0, 0)

    view.setUniformItemSizes(True)
    view.setVerticalScrollMode(QListView.ScrollPerPixel)
    view.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)  # keep bar visible
    view.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)

    # cap popup height so it must scroll (prevents it from filling and leaving empty bands)
    view.setMinimumHeight(180)
    view.setMaximumHeight(260)
    combo.setMaxVisibleItems(10)

    # make popup at least as wide as the combo + scrollbar
    try:
        sbw = view.verticalScrollBar().sizeHint().width()
    except Exception:
        sbw = 14
    view.setMinimumWidth(max(combo.width(), 220) + sbw)

    combo.update()

# Category-specific field metadata — used by AddEntryDialog to determine which fields to show for each category, 
# and how to label them.  See user_db setting "category_schema" for per-user overrides, and 
# built-in defaults in auth.category_fields and category_editor.schema.
def user_field_meta_for_category(self, category: str) -> list[dict]:
    """
    Return normalized field metadata for the given category.  The lookup
    order is:

    1. Active user's schema (``category_schema`` in user_db) – use field
       definitions for the matching category.
    2. Built-in defaults from ``auth.category_fields`` (if available).
    3. Application-specific defaults via ``_default_fields_for_category``.
    4. Minimal fallback with a small set of generic fields.

    This ensures that meta is never empty, preventing the vault table from
    returning early when encountering new or unknown categories.
    """
    # Normalize category name
    cat_norm = (category or "").strip().lower()

    # 1) Per-user schema
    try:
        uname = ""
        if hasattr(self, "currentUsername") and self.currentUsername:
            uname = self._active_username()
        uname = self._active_username()
        if uname:
            schema = get_user_setting(uname, "category_schema") or {}
            cats = schema.get("categories") or []
            for c in cats:
                if not isinstance(c, dict):
                    continue
                name = (c.get("name") or "").strip()
                if name.lower() != cat_norm:
                    continue
                fields = c.get("fields") or []
                out: list[dict] = []
                for f in fields:
                    if isinstance(f, str):
                        label = f.strip()
                        if not label:
                            continue
                        low = label.lower()
                        out.append({
                            "label": label,
                            "sensitive": low in {"password","pin","cvv","secret","key"},
                            "hide": False,
                            "url": low in {"url","website","site"},
                            "file_load": False,
                        })
                    elif isinstance(f, dict):
                        label = (f.get("label") or f.get("name") or "").strip()
                        if not label:
                            continue
                        out.append({
                            "label": label,
                            "sensitive": bool(f.get("sensitive") or f.get("hide")),
                            "hide": bool(f.get("hide")),
                            "url": bool(f.get("url")),
                            "file_load": bool(f.get("file_load")),
                        })
                if out:
                    return out
    except Exception as e:
        # Log and continue to fallback
        try:
            log.error(str(f"[DEBUG] user_field_meta_for_category user_db path failed: {e}"))
        except Exception:
            pass

    # 2) Built-in category definitions (legacy)
    try:
        from catalog_category.category_fields import get_fields_for, preferred_url_fields  
        fields = get_fields_for(category)
        urls = {s.lower() for s in preferred_url_fields(category)}
        out: list[dict] = []
        for lbl in fields:
            low = lbl.lower()
            out.append({
                "label": lbl,
                "sensitive": low in {"password","pin","cvv","secret","key"},
                "hide": False,
                "url": low in urls or low in {"url","website","site"},
                "file_load": False,
            })
        if out:
            return out
    except Exception:
        # Ignore and continue to next fallback
        pass

    # 3) Global category definitions from category_editor
    try:
        # Some categories may be defined in a shared schema via category_editor;
        # use those field definitions if available.  Note: we avoid
        # importing heavy UI modules unless necessary.
        from catalog_category.category_editor import load_schema as _load_global_schema
        schema = _load_global_schema()
        for c in (schema.get("categories") or []):
            if not isinstance(c, dict):
                continue
            name = (c.get("name") or "").strip().lower()
            if name != cat_norm:
                continue
            fields = c.get("fields") or []
            out: list[dict] = []
            for f in fields:
                if isinstance(f, str):
                    label = f.strip()
                    if not label:
                        continue
                    low = label.lower()
                    out.append({
                        "label": label,
                        "sensitive": low in {"password","pin","cvv","secret","key"},
                        "hide": False,
                        "url": low in {"url","website","site"},
                        "file_load": False,
                    })
                elif isinstance(f, dict):
                    label = (f.get("label") or f.get("name") or "").strip()
                    if not label:
                        continue
                    low = label.lower()
                    out.append({
                        "label": label,
                        "sensitive": bool(f.get("sensitive") or f.get("hide")),
                        "hide": bool(f.get("hide")),
                        "url": bool(f.get("url")) or low in {"url","website","site"},
                        "file_load": bool(f.get("file_load")),
                    })
            if out:
                return out
    except Exception:
        pass

    # 4) Application-specific defaults via _default_fields_for_category
    try:
        if hasattr(self, "_default_fields_for_category"):
            fields = self._default_fields_for_category(category) or []
            out: list[dict] = []
            for f in fields:
                if isinstance(f, str):
                    label = f
                elif isinstance(f, dict):
                    label = f.get("label") or f.get("name") or ""
                else:
                    label = ""
                label = label.strip()
                if not label:
                    continue
                low = label.lower()
                out.append({
                    "label": label,
                    "sensitive": low in {"password","pin","cvv","secret","key"},
                    "hide": False,
                    "url": low in {"url","website","site"},
                    "file_load": False,
                })
            if out:
                return out
    except Exception:
        pass

    # 5) Final minimal fallback: use a small generic field set
    default_fields = ["Title", "Username", "Password", "URL", "Notes"]
    out: list[dict] = []
    for lbl in default_fields:
        low = lbl.lower()
        out.append({
            "label": lbl,
            "sensitive": low in {"password","pin","cvv","secret","key"},
            "hide": False,
            "url": low in {"url","website","site"},
            "file_load": False,
        })
    return out


def _load_catalog_effective(self, username: str):  # native care update
    from catalog_category.my_catalog_builtin import CLIENTS, ALIASES, PLATFORM_GUIDE
    from catalog_category.catalog_user import (
    ensure_user_catalog_created,
    load_user_catalog_raw,
    load_effective_catalogs_from_user,)

    h = getattr(self, "core_session_handle", None)
    if not isinstance(h, int) or not h:
        log.info("[CATALOG] ERROR: native session missing/invalid in _load_catalog_effective (handle=%r)", h)
        return CLIENTS, ALIASES, PLATFORM_GUIDE, getattr(self, "AUTOFILL_RECIPES", {}), {}

    ensure_user_catalog_created(
        username,
        CLIENTS, ALIASES, PLATFORM_GUIDE,
        session_handle=h
    )

    overlay = load_user_catalog_raw(username, h) or {}

    return load_effective_catalogs_from_user(
        username,
        CLIENTS, ALIASES, PLATFORM_GUIDE,
        session_handle=h,
        user_overlay=overlay
    )


# ==============
# --- category schema 
# ==============

# Handler for when the category editor signals that a schema has been saved.
def _on_editor_schema_saved(self, *args, **kwargs):
    """
    Called by CategoryEditor when it has finished saving the new schema.

    We:
    - persist schema into the per-user user_db.json (authoritative)
    - mirror into login_handler settings
    - refresh vault schema + category selector immediately
    """
    log.debug("[CAT] _on_editor_schema_saved: starting")
    try:
        # schema from the editor
        schema = getattr(self, "category_schema", None) or getattr(self, "_category_schema", None)
        if not isinstance(schema, dict):
            log.debug("[CAT] _on_editor_schema_saved: no schema dict on host")
            return

        # target user
        try:
            uname = getattr(self, "_category_editor_user", "") or ""
        except Exception:
            uname = ""
        if not uname:
            try:
                uname = self._active_username()
            except Exception:
                uname = ""

        if not uname:
            log.warning("[CAT] _on_editor_schema_saved: no username; schema not saved")
            return

        canonical = uname.strip().lower()

        # 1) Write to per-user user_db.json
        try:
            from catalog_category.category_editor import save_full_schema_dict_for
            save_full_schema_dict_for(canonical, schema)
            log.debug("[CAT] _on_editor_schema_saved: user_db schema saved for %s", canonical)
        except Exception as e:
            log.error("[CAT] _on_editor_schema_saved: save_full_schema_dict_for failed for %s: %s", canonical, e)

        # 2) Mirror into login_handler settings
        try:
            set_user_setting(canonical, "category_schema", schema)
        except Exception as e:
            log.debug("[CAT] _on_editor_schema_saved: set_user_setting(category_schema) failed for %s: %s", canonical, e)

        # 3) Refresh vault + UI now
        try:
            self._do_vault_schema_refresh()
        except Exception as e:
            log.debug("[CAT] _on_editor_schema_saved: _do_vault_schema_refresh failed: %s", e)

    except Exception as e:
        log.error("[CAT] _on_editor_schema_saved outer error: %s", e)



# =============
# --- catalog
# =============
from catalog_category.catalog_user import (
    ensure_user_catalog_created,
    load_user_catalog_raw,
    load_effective_catalogs_from_user,
)
from catalog_category.my_catalog_builtin import CLIENTS, ALIASES, PLATFORM_GUIDE
from app.paths import config_dir, catalog_file
from catalog_category.catalog_editor_user import CatalogEditorUserDialog


def on_user_logged_in(self, canonical_user: str, _users_base_ignored: str = ""):
    username = (canonical_user or "").strip()
    if not username:
        return

    user_cfg = Path(config_dir(username))            
    self._catalog_user_root = str(user_cfg)

    cat_path  = Path(catalog_file(username, ensure_dir=True, name_only=False))
       
    # Ensure catalog exists (encrypted).
    try:
        ensure_user_catalog_created(cat_path, CLIENTS, ALIASES, PLATFORM_GUIDE, session_handle=self.core_session_handle)
    except TypeError:
        ensure_user_catalog_created(user_cfg, CLIENTS, ALIASES, PLATFORM_GUIDE, session_handle=self.core_session_handle)

    # Load decrypted overlay (user edits)
    try:
        overlay = load_user_catalog_raw(cat_path, self.core_session_handle)
    except TypeError:
        overlay = load_user_catalog_raw(user_cfg, self.core_session_handle)

    # Effective view (built-ins + user overlay)
    self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE, _ = load_effective_catalogs_from_user(
        user_cfg, CLIENTS, ALIASES, PLATFORM_GUIDE, session_handle=self.core_session_handle, user_overlay=overlay
    )


def open_catalog_editor(self):
    try:
        from catalog_category.my_catalog_builtin import (
            CLIENTS,
            ALIASES,
            PLATFORM_GUIDE,
            AUTOFILL_RECIPES,
        )
            
        uname = self._active_username()
        if not uname:
            QMessageBox.warning(self, self.tr("Catalog"), self.tr("Please log in first."))
            return

        user_cfg = str(config_dir(uname))   # editor works with a root dir
        self.set_status_txt(self.tr("Opening Catalog"))

        dlg = CatalogEditorUserDialog(
            user_cfg,
            CLIENTS,
            ALIASES,
            PLATFORM_GUIDE,
            AUTOFILL_RECIPES,
            parent=self,
            session_handle=self.core_session_handle,
            username=uname,
        )

        dlg.saved.connect(lambda: self._on_catalog_saved(user_cfg))

        if dlg.exec():
            self._on_catalog_saved(user_cfg)
    except Exception as e:
        log.error(f"CatalogEditorUserDialog: {e}")


def _on_catalog_saved(self, user_root: str):
    try:
        uname = self._active_username()
        cat_path  = Path(catalog_file(uname, ensure_dir=True, name_only=False))
        try:
            overlay = load_user_catalog_raw(cat_path, self.core_session_handle)
        except TypeError:
            overlay = load_user_catalog_raw(Path(user_root), self.core_session_handle)

        self.CLIENTS, self.ALIASES, self.PLATFORM_GUIDE, _ = load_effective_catalogs_from_user(
            Path(user_root), CLIENTS, ALIASES, PLATFORM_GUIDE, session_handle=self.core_session_handle, user_overlay=overlay
        )
    except Exception:
        pass

    for attr in ("_client_domains_cache", "_client_exec_cache", "_client_protocol_cache"):
        if hasattr(self, attr):
            setattr(self, attr, None)
    try: self._refresh_platform_help_badge()
    except Exception: pass
    try: self._toast("Catalog updated")
    except Exception: pass


def _is_probably_user_added(self, url: str, built_value: str | None) -> bool:
    """If built-ins had a value and this one differs, treat as user-added/overridden; or new key entirely."""
    return not built_value or (built_value.strip() != (url or "").strip())



