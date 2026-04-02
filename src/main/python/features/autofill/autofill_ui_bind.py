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

# This module contains methods extracted from main.py to reduce file size.
# We intentionally "inherit" main module globals so the moved code can run unchanged.
import sys as _sys
import os
from pathlib import Path
from catalog_category.catalog_user import load_effective_catalogs_from_user

from catalog_category.my_catalog_builtin import CLIENTS, ALIASES, PLATFORM_GUIDE

# translat helpers
from app.app_translation_fields import PLATFORM_LABELS, INSTALL_LINK_LABELS, EMAIL_LABELS, PRIMARY_PASSWORD_LABELS
from app.platform_utils import open_path

import time as _t
import subprocess

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


def _try_launch_from_catalog(w, username: str, client_key: str):
    """Tier-1 launch: use effective catalog (built-in + user overrides).

    Returns: (ok: bool, how: str, pid: int | None)
    """
    try:
        # Pull built-ins from the host if available
        CLIENTS = getattr(w, "CLIENTS", None) or getattr(w, "_CLIENTS", None) or {}
        ALIASES = getattr(w, "ALIASES", None) or getattr(w, "_ALIASES", None) or {}
        PLATFORM_GUIDE = getattr(w, "PLATFORM_GUIDE", None) or getattr(w, "_PLATFORM_GUIDE", None) or {}

        user_key = getattr(w, "core_session_handle", None) or getattr(w, "user_key", None)
        clients, aliases, guide, recipes, _overlay = load_effective_catalogs_from_user(
            username, CLIENTS, ALIASES, PLATFORM_GUIDE, getattr(w, 'AUTOFILL_RECIPES', None), user_key=user_key
        )

        # Resolve aliases (if present)
        ck = (client_key or "").strip()
        if not ck:
            return False, "catalog:none", None
        ck = (aliases.get(ck) or ck)

        client = (clients or {}).get(ck)
        if not isinstance(client, dict):
            return False, "catalog:missing", None

        # --- 1) exe paths ---
        exe_paths = client.get("exe_paths") or []
        for raw in exe_paths:
            import glob
            raw = (raw or "").strip()
            if not raw:
                continue
            expanded = os.path.expandvars(raw)
            candidates = glob.glob(expanded) if any(ch in expanded for ch in "*?[]") else [expanded]
            for path in candidates:
                if not path or not os.path.exists(path):
                    continue
                try:
                   p = subprocess.Popen([path], shell=False)
                   return True, f"catalog:exe:{ck}", p.pid
                except Exception:
                    continue

        # --- 2) protocols (e.g., steam://, battlenet://) ---
        protocols = client.get("protocols") or []
        for proto in protocols:
            proto = (proto or "").strip()
            if not proto:
                continue
            try:
                # Windows protocol handler
                os.startfile(proto)  # type: ignore[attr-defined]
                return True, f"catalog:proto:{ck}", None
            except Exception:
                continue

        return False, f"catalog:failed:{ck}", None
    except Exception as e:
        try:
            log.exception(f"[AUTOFILL] catalog launch error: {e}")
        except Exception:
            pass
        return False, "catalog:error", None

def _tr(text: str) -> str:
    return QCoreApplication.translate("main", text)

# ==============================
# AutoFill: robust launcher
# ==============================

def _norm_str(x: str) -> str:
    return (x or "").strip()

def _key_from_hint(hint: str) -> str | None:
    """
    Map a user/title hint to a known launcher key using ALIASES and CLIENTS.
    Accepts things like 'battle.net', 'bnet', 'blizzard', etc.
    """
    h = _norm_str(hint).lower()
    if not h:
        return None
    # try alias map first
    try:
        from __main__ import ALIASES, CLIENTS  # ensure we use the same dicts

        from catalog_category.catalog_user import load_effective_catalogs_from_user
    except Exception:
        return None

    if h in ALIASES:
        return ALIASES[h]
    if h in CLIENTS:
        return h

    # loose matching over aliases and client keys
    for k in list(ALIASES.keys()) + list(CLIENTS.keys()):
        if h in k or k in h:
            return ALIASES.get(k, k)

    # specific normalisations
    if "battle" in h and "net" in h:
        return "battlenet"
    if "ubisoft" in h or "uplay" in h:
        return "uplay"
    if "steam" in h:
        return "steam"
    if "epic" in h:
        return "epic"
    return None

def _expand_exe_paths(paths: tuple[str, ...]) -> list[Path]:
    out = []
    for p in paths or ():
        try:
            p = os.path.expandvars(p)
            out.append(Path(p))
        except Exception:
            pass
    return out

def _find_installed_exe(client_key: str) -> Path | None:
    """
    Return the first existing EXE from CLIENTS[client_key]['exe_paths'].
    """
    try:
        rec = CLIENTS.get(client_key) or {}
        for p in _expand_exe_paths(tuple(rec.get("exe_paths") or ())):
            if p.exists():
                return p
    except Exception:
        pass
    return None

def _try_protocols(client_key: str) -> bool:
    """
    Try to open a registered protocol (steam://, battlenet://, etc).
    Returns True if we managed to invoke something.
    """
    try:
        rec = CLIENTS.get(client_key) or {}
        for proto in rec.get("protocols") or ():
            try:
                open_path(proto)  # Windows protocol handler
                return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def _fallback_open_vendor_url(url: str, label: str | None = None) -> None:
    """Fallback opener when we don't have a UI host window."""
    try:
        import webbrowser
        if url:
            webbrowser.open(url)
    except Exception:
        pass


def _open_installer_or_page(w, client_key: str) -> None:
    """
    Open the best vendor link for a platform/app.

    Priority: download_url -> homepage -> installer -> page.

    If a host window (w) is provided and it exposes open_vendor_url(), we use it
    so the user gets the usual safety prompt/UX. Otherwise we fall back to
    webbrowser.open().
    """
    import webbrowser
    key = (client_key or "").strip()
    if not key:
        return

    url = None
    try:
        # Prefer merged user catalog if available, fall back to built-ins
        clients = None
        if w is not None:
            clients = getattr(w, "CLIENTS", None)
        if not isinstance(clients, dict):
            clients = None

        if clients and isinstance(clients.get(key), dict):
            rec = clients.get(key) or {}
        else:
            rec = (CLIENTS or {}).get(key) if isinstance(globals().get("CLIENTS"), dict) else {}

        # Try known fields in order
        for k in ("download_url", "homepage", "installer", "page"):
            v = rec.get(k) if isinstance(rec, dict) else None
            if isinstance(v, str) and v.strip():
                url = v.strip()
                break
    except Exception:
        url = None

    if not url:
        return

    try:
        if w is not None and hasattr(w, "open_vendor_url"):
            w.open_vendor_url(url)
        else:
            webbrowser.open(url)
    except Exception:
        try:
            webbrowser.open(url)
        except Exception:
            pass


def _launch_client_safely(w, client_key: str) -> tuple[bool, str, int | None]:
    """Launch a client by EXE, else protocol, else open installer/page.

    Returns: (ok, how, pid)
    """
    exe = _find_installed_exe(client_key)
    if exe:
        try:
            p = subprocess.Popen(
                [str(exe)],
                shell=False,
                creationflags=(
                    getattr(subprocess, "DETACHED_PROCESS", 0)
                    | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                ),
            )
            return True, f"exe:{exe.name}", getattr(p, "pid", None)
        except Exception as e:
            log.debug(f"[AUTOFILL] failed to launch exe: {exe} ({e})")

    if _try_protocols(client_key):
        return True, "protocol", None

    try:
        _open_installer_or_page(w, client_key)
    except Exception:
        pass
    return False, "installer_or_page", None


def _build_title_patterns(hint: str, client_key: str) -> list[str]:
    """
    Possible window title regex patterns we’ll accept for the login window.
    """
    h = _norm_str(hint)
    patterns = []
    # direct hint
    if h:
        patterns += [rf"(?i){re.escape(h)}", rf"(?i){re.escape(h)}.*login", rf"(?i)login.*{re.escape(h)}"]

    # known variants per client
    variants = {
        "battlenet": [r"(?i)Battle\.net", r"(?i)Blizzard", r"(?i)Battle\.net.*Login", r"(?i)Login.*Battle\.net"],
        "steam":     [r"(?i)Steam", r"(?i)Steam.*Sign[- ]?in", r"(?i)Sign[- ]?in.*Steam"],
        "epic":      [r"(?i)Epic Games Launcher", r"(?i)Epic Games.*Sign[- ]?in"],
        "uplay":     [r"(?i)Ubisoft Connect", r"(?i)Uplay", r"(?i)Ubisoft.*Login"],
        "ea":        [r"(?i)EA app", r"(?i)EA.*Sign[- ]?in"],
        "gog":       [r"(?i)GOG Galaxy", r"(?i)GOG.*Login"],
        "riot":      [r"(?i)Riot Client", r"(?i)League of Legends", r"(?i)VALORANT"],
        "xbox":      [r"(?i)Xbox", r"(?i)Microsoft Store"],
    }
    patterns += variants.get(client_key, [])
    # dedupe while preserving order
    seen, out = set(), []
    for p in patterns:
        if p not in seen:
            out.append(p); seen.add(p)
    return out

def _sleep_ms(ms: int):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()

# ==============================
# --- Autofill helpers (V2) ----
# ==============================

def _clear_and_type(control, text: str, is_password: bool = False):
    """
    Clear a UI control and type text into it.
    - Redacts logged text if it's a password
    - Avoids typing placeholder/invalid values like 'Invalid', masked bullets, etc.
    """
    from pywinauto.keyboard import send_keys

    def _is_placeholder(s: str) -> bool:
        if s is None:
            return True
        s2 = str(s).strip()
        if not s2:
            return True
        low = s2.lower()
        if low in ("invalid", "n/a", "na", "none", "null"):
            return True
        # masked placeholders often used in UI tables
        if set(s2) <= {"●"} or set(s2) <= {"*"}:
            return True
        return False

    if _is_placeholder(text):
        log.info(f"_clear_and_type: skipped placeholder value (is_password={is_password})")
        return False

    safe_text_for_log = "<redacted>" if is_password else text
    try:
        log.info(f"_clear_and_type: control:{control}, text:{safe_text_for_log}")
        control.set_edit_text("")
        control.set_edit_text(text)
        return True
    except Exception:
        pass

    try:
        control.set_focus()
    except Exception:
        pass

    # keyboard fallback
    send_keys("^a{BACKSPACE}", pause=0.002)
    send_keys(text, with_spaces=True, pause=0.002 if is_password else 0.0)
    return True

def _connect_window(w, hwnd=None, titlere: str = "", pid=None):
    """Connect to target window either by handle or by regex (+ optional PID)."""
    from pywinauto.application import Application
    from pywinauto.findwindows import find_window, ElementNotFoundError

    if hwnd:
        app = Application(backend="uia").connect(handle=hwnd, timeout=7)
        return app.window(handle=hwnd)

    # fallback: find by regex (picker already gave a forgiving regex)
    try:
        if pid:
            Application(backend="uia").connect(process=pid, timeout=7)
            wh = find_window(title_re=titlere, process=pid)
        else:
            wh = find_window(title_re=titlere)
    except Exception:
        raise ElementNotFoundError(f"No window matches {titlere!r}")

    app = Application(backend="uia").connect(handle=wh, timeout=7)
    return app.window(handle=wh)

def _find_email_edit(dlg):
    """
    Prefer an Edit control that looks like an email field.
    Falls back to None if nothing clearly email-like is found.
    """
    try:
        edits = dlg.descendants(control_type="Edit")
    except Exception:
        return None

    for e in edits:
        try:
            # combine visible text + accessible name
            label = ((e.window_text() or "") + " " + (e.element_info.name or "")).lower()
            # common signals of an email field
            if ("email" in label) or ("e-mail" in label) or ("mail" in label):
                return e
            # some apps show a placeholder with '@'
            if "@" in (e.window_text() or ""):
                return e
        except Exception:
            continue
    return None

def _find_username_edit(dlg):
    try:
        edits = dlg.descendants(control_type="Edit")
    except Exception:
        return None
    for e in edits:
        try:
            nm = (e.window_text() or e.element_info.name or "").lower()
            if "pass" in nm:
                continue
            return e
        except Exception:
            continue
    return edits[0] if edits else None

def _find_password_edit(dlg):
    try:
        edits = dlg.descendants(control_type="Edit")
    except Exception:
        return None
    for e in edits:
        try:
            nm = (e.window_text() or e.element_info.name or "").lower()
            if "pass" in nm:
                return e
        except Exception:
            pass
    return edits[-1] if edits else None

def _find_next_button(dlg):
    labels = ("next", "continue", "sign in", "log in", "proceed", "weiter", "avanti")
    try:
        btns = dlg.descendants(control_type="Button")
    except Exception:
        btns = []
    for b in btns:
        try:
            nm = (b.window_text() or b.element_info.name or "").strip().lower()
            if any(lbl in nm for lbl in labels):
                return b
        except Exception:
            continue
    return None

def _find_submit_button(dlg):
    labels = ("sign in", "log in", "login", "submit", "anmelden", "se connecter")
    try:
        btns = dlg.descendants(control_type="Button")
    except Exception:
        btns = []
    for b in btns:
        try:
            nm = (b.window_text() or b.element_info.name or "").strip().lower()
            if any(lbl in nm for lbl in labels):
                return b
        except Exception:
            continue
    return None


def _find_by_title_re(controls, title_re: str):
    """Find first control whose accessible label matches title_re (regex, case-insensitive)."""
    if not title_re:
        return None
    try:
        rx = re.compile(title_re, re.I)
    except Exception:
        return None
    for c in controls or []:
        try:
            label = ((getattr(c, "window_text", lambda: "")() or "") + " " + (getattr(getattr(c, "element_info", None), "name", "") or "")).strip()
        except Exception:
            label = ""
        try:
            if rx.search(label):
                return c
        except Exception:
            continue
    return None

def _recipe_key_from_entry(w, entry: dict) -> str | None:
    """Resolve a client_key (e.g. 'battlenet') from entry hints using merged catalog aliases."""
    hint = (
        entry.get("platform")
        or entry.get("Platform")
        or entry.get("title")
        or entry.get("Title")
        or entry.get("game name")
        or entry.get("app")
        or ""
    )
    try:
        return _key_from_hint_with_ctx(w, str(hint))
    except Exception:
        try:
            return _key_from_hint(str(hint))
        except Exception:
            return None

def _autofill_split_flow(w, entry, *, hwnd=None, titlere: str = "", pid=None) -> bool:
    """
    Two-stage flow: identifier (email preferred, else username) -> Next -> wait -> password -> submit.
    Returns True on success.
    """
    # Lazy-import pywinauto and keyboard
    try:
        from pywinauto.keyboard import send_keys
        from pywinauto.findwindows import ElementNotFoundError
    except Exception:
        QMessageBox.warning(w, "Auto-fill",
                            "pywinauto is not installed in this build. Please install it to use desktop autofill.")
        return False

    email = (entry.get("email") or "").strip()
    username = (entry.get("username") or "").strip()
    password = (entry.get("password") or "").strip()

    ident_val = email or username
    # Safety: never type identifier into password by mistake
    if password and ident_val and password.strip().lower() == ident_val.strip().lower():
        QMessageBox.warning(w, _tr("Auto-fill"), _tr("Password appears to match the email/username. Autofill stopped."))
        return False
    if not ident_val or not password:
        QMessageBox.warning(w, _tr("Auto-fill"), _tr("This entry needs an email/username and a password."))
        return False

    # Connect + focus
    target = _connect_window(w, hwnd=hwnd) if hwnd else _connect_window(w, hwnd=None, titlere=titlere, pid=pid)

    # --- Recipe-first (catalog-defined selectors) ---
    try:
        recipes = getattr(w, "AUTOFILL_RECIPES", {}) or {}
        r_key = _recipe_key_from_entry(w, entry) or None
        recipe = recipes.get(r_key) if (r_key and isinstance(recipes, dict)) else None
    except Exception:
        recipe = None
        r_key = None

    if isinstance(recipe, dict):
        try:
            # If recipe provides a tighter window title regex, reconnect once (unless hwnd already fixed)
            win_re = (recipe.get("window_title_re") or "").strip()
            if win_re and not hwnd:
                try:
                    target = _connect_window(w, hwnd=None, titlere=win_re, pid=pid)
                    try:
                        target.set_focus()
                    except Exception:
                        pass
                except Exception:
                    pass

            edits = []
            try:
                edits = target.descendants(control_type="Edit")
            except Exception:
                edits = []

            u_cfg = recipe.get("username") or {}
            p_cfg = recipe.get("password") or {}
            s_cfg = recipe.get("submit") or {}

            id_title_re = (u_cfg.get("title_re") or "").strip()
            pw_title_re = (p_cfg.get("title_re") or "").strip()

            id_edit = _find_by_title_re(edits, id_title_re) if id_title_re else None
            pw_edit = _find_by_title_re(edits, pw_title_re) if pw_title_re else None

            # if recipe says prefer_password, require is_password()
            if pw_edit and (p_cfg.get("prefer_password") is True):
                try:
                    if not pw_edit.is_password():
                        pw_edit = None
                except Exception:
                    pass

            if id_edit and pw_edit:
                try:
                    id_edit.wait("ready", timeout=1)
                except Exception:
                    pass
                _clear_and_type(id_edit, ident_val, is_password=False)

                # Lock hwnd as soon as we successfully touch the window
                try:
                    hwnd = getattr(target, "handle", None) or hwnd
                    try:
                        setattr(w, "_autofill_last_hwnd", hwnd)
                    except Exception:
                        pass
                except Exception:
                    pass

                try:
                    pw_edit.wait("ready", timeout=1)
                except Exception:
                    pass
                _clear_and_type(pw_edit, password, is_password=True)

                # Submit if recipe defines it
                btn = None
                submit_re = (s_cfg.get("title_re") or "").strip()
                if submit_re:
                    try:
                        btns = target.descendants(control_type="Button")
                    except Exception:
                        btns = []
                    btn = _find_by_title_re(btns, submit_re)
                if btn:
                    try:
                        btn.click_input()
                    except Exception:
                        pass
                else:
                    # fallback submit by ENTER in password field
                    try:
                        pw_edit.set_focus()
                    except Exception:
                        pass
                    try:
                        send_keys("{ENTER}", pause=0.002)
                    except Exception:
                        pass

                try:
                    w._toast(f"Auto-fill used recipe: {r_key}")
                except Exception:
                    pass
                return True
        except Exception:
            # fall back to heuristic flow below
            pass
    try:
        target.set_focus()
    except Exception:
        pass
    _t.sleep(0.05)

    # --- Stage 1: fill identifier (EMAIL first, fallback to USERNAME) ---
    id_edit = None
    if email:
        id_edit = _find_email_edit(target)  # prefer explicit email control
    if not id_edit:
        id_edit = _find_username_edit(target)  # generic user/identifier field
    if not id_edit:
        QMessageBox.information(w, _tr("Auto-fill"), _tr("Could not locate the email/username field in the target app."))
        return False

    try:
        id_edit.wait("ready", timeout=1)
    except Exception:
        pass
    _clear_and_type(id_edit, ident_val, is_password=False)
    # ✅ Once we've filled the identifier, we know this is the right window.
    # Lock the HWND so we stop searching by title/PID (avoids "still looking for windows" after we've found it).
    try:
        hwnd = getattr(target, "handle", None) or hwnd
        try:
            setattr(w, "_autofill_last_hwnd", hwnd)
        except Exception:
            pass
    except Exception:
        pass


    # Click Next (or Enter)
    pressed_next = False
    btn_next = _find_next_button(target)
    if btn_next:
        try:
            btn_next.click_input()
            pressed_next = True
        except Exception:
            pass
    if not pressed_next:
        try:
            id_edit.set_focus()
        except Exception:
            pass
        send_keys("{ENTER}", pause=0.002)

    # --- Stage 2: wait for password, then fill ---
    pw_edit = None
    deadline = _t.time() + 8.0
    while _t.time() < deadline:
        try:
            target = _connect_window(w, hwnd=hwnd, titlere=titlere, pid=pid)
            pw_edit = _find_password_edit(target)
            if pw_edit:
                try:
                    pw_edit.wait("ready", timeout=1)
                except Exception:
                    pass
                _clear_and_type(pw_edit, password, is_password=True)
                break
        except Exception:
            pass
        _t.sleep(0.2)

    if not pw_edit:
        QMessageBox.information(
            w, _tr("Auto-fill"),
            _tr("Identifier filled. Waiting for password field timed out—please press Next and try again.")
        )
        return False

    # Submit
# Refresh the same window by handle (do not re-search by title) once more before submitting
    try:
        if hwnd:
            target = _connect_window(w, hwnd=hwnd)
    except Exception:
        pass

    btn_submit = _find_submit_button(target)
    if btn_submit:
        try:
            btn_submit.click_input()
        except Exception:
            try:
                pw_edit.set_focus()
            except Exception:
                pass
            send_keys("{ENTER}", pause=0.002)
    else:
        try:
            pw_edit.set_focus()
        except Exception:
            pass
        send_keys("{ENTER}", pause=0.002)

    try:
        w._toast("Filled email/username, waited for password, and signed in.")
    except Exception:
        pass
    return True


# helper to read a specific column from the current row
def _row_field(w, row: int, names: tuple[str, ...], label_set: set[str] | None = None) -> str:
    """
    Read a value from the current row by matching the localized header text.
    """
    tbl = getattr(w, "vaultTable", None)
    if tbl is None or row < 0:
        return ""
    wanted = {n.strip().lower() for n in names}
    if label_set:
        wanted |= {lab.strip().lower() for lab in label_set}

    for col in range(tbl.columnCount()):
        header = tbl.horizontalHeaderItem(col)
        key = (header.text() if header else "").strip().lower()
        if key in wanted:
            item = tbl.item(row, col)
            return (item.text().strip() if item and item.text() else "")
    return ""


def _row_secret_local(w, row: int, names: tuple[str, ...], label_set: set[str] | None = None) -> str:
    """Read a secret from the table using Qt.UserRole (never from display text)."""
    tbl = getattr(w, "vaultTable", None)
    if tbl is None or row < 0:
        return ""
    wanted = {n.strip().lower() for n in names}
    if label_set:
        wanted |= {lab.strip().lower() for lab in label_set}

    for col in range(tbl.columnCount()):
        header = tbl.horizontalHeaderItem(col)
        key = (header.text() if header else "").strip().lower()
        if key in wanted:
            item = tbl.item(row, col)
            if not item:
                return ""
            for role in (Qt.UserRole, Qt.UserRole + 1, Qt.UserRole + 2):
                try:
                    v = item.data(role)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
                except Exception:
                    pass
            return ""
    return ""


def _entry_value_by_labelset(entry: dict, labels) -> str:
    """
    Return the first non-empty value from an entry dict whose key matches
    any label in the provided label set, case-insensitively.
    """
    if not isinstance(entry, dict) or not labels:
        return ""

    try:
        wanted = {str(x).strip().lower() for x in labels if str(x).strip()}
    except Exception:
        wanted = set()

    if not wanted:
        return ""

    # Exact case-insensitive key match
    for k, v in entry.items():
        try:
            key_norm = str(k).strip().lower()
        except Exception:
            continue

        if key_norm in wanted:
            if v is None:
                continue
            s = str(v).strip()
            if s:
                return s

    # Loose fallback: ignore extra spaces
    def _norm(s: str) -> str:
        return " ".join((s or "").strip().lower().split())

    wanted_loose = {_norm(x) for x in wanted}

    for k, v in entry.items():
        try:
            key_norm = _norm(str(k))
        except Exception:
            continue

        if key_norm in wanted_loose:
            if v is None:
                continue
            s = str(v).strip()
            if s:
                return s

    return ""

    
def on_autofill_to_app_clicked(w, checked: bool = False) -> bool:
    """
    Auto-fill to desktop app or site with user-visible stage feedback and
    robust stabilization: retries autofill a few times before showing errors.
    """
    w.set_status_txt(_tr("Attempting Autofill"))

    # ---------------- helpers ----------------
    def _sleep_ms(ms: int):
        loop = QEventLoop()
        QTimer.singleShot(ms, loop.quit)
        loop.exec()

    def _norm(s: str) -> str:
        return (s or "").strip()

    class _SilenceQMessageBox:
        """
        Silence QMessageBox.* temporarily (used to hide noisy field-not-found popups
        coming from _autofill_split_flow during timing retries).
        """
        def __enter__(w):
            w._orig_info = QMessageBox.information
            w._orig_warn = QMessageBox.warning
            w._orig_crit = QMessageBox.critical

            def _noop(*a, **k):
                try:
                    return QMessageBox.StandardButton.Ok
                except Exception:
                    return 0

            QMessageBox.information = _noop
            QMessageBox.warning     = _noop
            QMessageBox.critical    = _noop
            return w

        def __exit__(w, exc_type, exc, tb):
            QMessageBox.information = w._orig_info
            QMessageBox.warning     = w._orig_warn
            QMessageBox.critical    = w._orig_crit

    def resolve_client_key(hint: str):
        ALIASES = getattr(w, "ALIASES", {})
        CLIENTS = getattr(w, "CLIENTS", {})

        h = _norm(hint).lower()
        if not h:
            return None
        # normalize common platform text
        h = (h.replace("\u00a0", "").replace("\u200b", "").replace("•", "")
               .replace("—", "-").replace("–", "-").replace(".net", "net").replace(" ", ""))

        if h in ALIASES:
            return ALIASES[h]
        if h in CLIENTS:
            return h

        # fuzzy contains
        for k, v in ALIASES.items():
            ks = k.replace(" ", "").lower()
            if h in ks or ks in h:
                return v
        for k in CLIENTS.keys():
            ks = k.replace(" ", "").lower()
            if h in ks or ks in h:
                return k

        if "battle" in h and "net" in h:
            return "battlenet"
        if "ubisoft" in h or "uplay" in h:
            return "uplay"
        if "steam" in h:
            return "steam"
        if "epic" in h:
            return "epic"
        if "xbox" in h or "microsoftstore" in h:
            return "xbox"
        return None

    def _find_installed_exe(client_key: str):
        CLIENTS = getattr(w, "CLIENTS", {})
        try:
            rec = CLIENTS.get(client_key) or {}
            for p in _expand_exe_paths(tuple(rec.get("exe_paths") or ())):
                if p.exists():
                    return p
        except Exception:
            pass
        return None

    def _try_protocols(client_key: str) -> bool:
        CLIENTS = getattr(w, "CLIENTS", {})
        try:
            rec = CLIENTS.get(client_key) or {}
            for proto in rec.get("protocols") or ():
                try:
                    open_path(proto)
                    return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    def _expand_exe_paths(paths):
        out = []
        for p in (paths or ()):
            try:
                out.append(Path(os.path.expandvars(p)))
            except Exception:
                pass
        return out


    def _title_patterns(title_hint: str, client_key: str | None):
        h = _norm(title_hint)
        pats = []
        if h:
            esc = re.escape(h)
            pats += [
                rf"(?i){esc}",
                rf"(?i){esc}.*login",
                rf"(?i)login.*{esc}",
                rf"(?i){esc}.*sign[- ]?in",
                rf"(?i)sign[- ]?in.*{esc}",
            ]
        variants = {
            "battlenet": [r"(?i)Battle\.net", r"(?i)Blizzard", r"(?i)Battle\.net.*Login", r"(?i)Login.*Battle\.net"],
            "steam":     [r"(?i)Steam", r"(?i)Steam.*Sign[- ]?in", r"(?i)Sign[- ]?in.*Steam"],
            "epic":      [r"(?i)Epic Games Launcher", r"(?i)Epic Games.*Sign[- ]?in"],
            "uplay":     [r"(?i)Ubisoft Connect", r"(?i)Uplay", r"(?i)Ubisoft.*Login"],
            "ea":        [r"(?i)EA app", r"(?i)EA.*Sign[- ]?in"],
            "gog":       [r"(?i)GOG Galaxy", r"(?i)GOG.*Login"],
            "riot":      [r"(?i)Riot Client", r"(?i)League of Legends", r"(?i)VALORANT"],
            "xbox":      [r"(?i)Xbox", r"(?i)Microsoft Store"],
        }
        if client_key:
            pats += variants.get(client_key, [])
        pats += [r"(?i)Login", r"(?i)Sign[- ]?in"]
        seen, out = set(), []
        for p in pats:
            if p not in seen:
                out.append(p)
                seen.add(p)
        return out

    def _autofill_withretries(
        *,
        entry: dict,
        titlere: str = "",
        hwnd=None,
        pid=None,
        attempts: int = 3,
        delay_ms: int = 900,
    ) -> bool:
        for i in range(1, max(1, attempts) + 1):
            with _SilenceQMessageBox():
                try:
                    w.set_status_txt(_tr("AutoFill Looking for ") + f"{titlere}")
                    saved_hwnd = hwnd or getattr(w, "_autofill_last_hwnd", None)
                    ok = _autofill_split_flow(w, entry, hwnd=saved_hwnd, titlere=titlere, pid=pid)
                    if ok:
                        return True
                except Exception as e:
                    log.debug(f"[AUTOFILL] try {i}/{attempts} failed: {e}")
            _sleep_ms(delay_ms)
        _sleep_ms(600)
        return False

    def _as_bool(v) -> bool:
        if isinstance(v, bool):
            return v
        if v is None:
            return False
        if isinstance(v, (int, float)):
            return bool(v)
        s = str(v).strip().lower()
        return s in ("1", "true", "yes", "y", "on", "enabled")


    # ---------------- entry & prefs ----------------
    entry = w._get_selected_entry()

    # Gate categories (language-aware)
    def _cat_norm(x: str) -> str:
        return (x or "").strip().lower()

    try:
        current_cat_raw = w.categorySelector_2.currentText()
    except Exception:
        current_cat_raw = ""
    w.set_status_txt(_tr("AutoFill: Checking Category"))
    current_cat = _cat_norm(current_cat_raw)

    aliases = {
        "gaming": "games",
        "launcher": "games",
        "video": "streaming",
        "videos": "streaming",
        "socialmedia": "social media",
        "messaging": "social media",
        "application": "apps",
        "program": "software",
    }
    current_cat = _cat_norm(aliases.get(current_cat, current_cat))

    if not entry:
        QMessageBox.warning(w, _tr("Auto-fill"), _tr("Select an entry first."))
        return False

    # --- LANGUAGE-AWARE FIELD EXTRACTION ---
    from app.app_translation_fields import USERNAME_HEADER_LABELS, EMAIL_LABELS, PRIMARY_PASSWORD_LABELS

    username = (
        _entry_value_by_labelset(entry, EMAIL_LABELS)
        or _entry_value_by_labelset(entry, USERNAME_HEADER_LABELS)
        or entry.get("username")
        or entry.get("email")
        or ""
    ).strip()

    password = ""
    # Prefer explicit password field from the entry dict (table text may be masked).
    raw_pw = entry.get("password")
    if isinstance(raw_pw, str):
        password = raw_pw.strip()
    else:
        password = ""

    # ---- NEW: pull Platform / Install Link from the *row* first ----
    tbl = getattr(w, "vaultTable", None)
    if tbl is not None:
        row_idx = tbl.currentRow()
    else:
        row_idx = -1

    # ✅ Pull real password from the table UserRole if the extracted password is fake/masked
    def _looks_fake_pw(p: str) -> bool:
        if not p:
            return True
        pl = p.strip().lower()
        if pl in ("invalid", "n/a", "na", "none", "null"):
            return True
        if set(p) <= {"●"} or set(p) <= {"*"}:
            return True
        return False

    # Prefer the real secret stored on the table item (Qt.UserRole) if available.
    if row_idx >= 0:
        try:
            pw_secret = _row_secret_local(w, row_idx, ("Password",), PRIMARY_PASSWORD_LABELS)
            if pw_secret:
                password = pw_secret.strip()
        except Exception:
            pass


    # Safety: never type username/email into the password field by mistake
    if username and password and password.strip().lower() == username.strip().lower():
        log.error("[AUTOFILL] password equals username/email — aborting")
        QMessageBox.warning(
            w,
            _tr("Auto-fill"),
            _tr("Password appears to be incorrect (same as username). Autofill stopped.")
        )
        return False

    w.set_status_txt(_tr("AutoFill: Getting Username, Password For Selected"))
    if not username or not password:
        QMessageBox.warning(w, _tr("Auto-fill"), _tr("This entry needs a username and password."))
        return False

    # ✅ CRITICAL: Inject back into entry so _autofill_split_flow() uses the real secrets
    entry = dict(entry)  # do not mutate shared reference
    entry["username"] = username
    entry["password"] = password

    try:
        from ui.ui_flags import _maybe_show_autofill_tip
        _maybe_show_autofill_tip(w)
    except Exception:
        pass

    try:
        from auth.login.login_handler import get_user_setting
        u = (w.currentUsername.text() or "").strip()
        raw = get_user_setting(u, "autofill_launch_first")
        launch_first = _as_bool(raw)
        log.debug(f"[AUTOFILL] launch_first={launch_first} (raw={raw!r})")
    except Exception as f:
        log.debug(f"[AUTOFILL] Error = {f})")
        launch_first = False

    try:
        exe_hint, title_hint = w._extract_app_launch_hints(entry)
    except Exception:
        exe_hint, title_hint = "", ""

    w.set_status_txt(_tr("AutoFill: Getting Platform"))
    platform_raw = _row_field(w, row_idx, ("Platform", "Platform / Store"), PLATFORM_LABELS)
    w.set_status_txt(_tr("AutoFill: Getting Install Link"))
    install_link = _row_field(w, row_idx, ("Install Link", "Link"), INSTALL_LINK_LABELS)

    if not platform_raw:
        platform_raw = (
            _entry_value_by_labelset(entry, PLATFORM_LABELS)
            or entry.get("Platform")
            or entry.get("platform")
            or ""
        ).strip()

    if not install_link:
        install_link = (
            _entry_value_by_labelset(entry, INSTALL_LINK_LABELS)
            or entry.get("Install Link")
            or entry.get("Link")
            or ""
        ).strip()

    w.set_status_txt(_tr("AutoFill: Getting App Name"))
    app_name = (
        entry.get("App Name")
        or entry.get("App")
        or entry.get("Title")
        or entry.get("Site")
        or ""
    ).strip()

    ui_name = (platform_raw or app_name or title_hint or "").strip()
    if ui_name:
        title_hint = ui_name

    resolve_hint = platform_raw or ui_name
    client_key = resolve_client_key(resolve_hint) or resolve_client_key(install_link)

    log.debug(
        "[AUTOFILL] row_idx=%r platform_raw=%r install_link=%r resolve_hint=%r client_key=%r",
        row_idx,
        platform_raw,
        install_link,
        resolve_hint,
        client_key,
    )

    # ---------------- status dialog ----------------
    stages = [
        "Trying to open app",
        "Unable to open – please open and wait for autofill",
        "No app found running – select manually",
        "Waiting for login window",
        "Attempting to autofill email",
        "Attempting to autofill password",
        "Attempting to submit / log in",
        "Complete – thank you for flying with Keyquorum",
    ]
    dlg = AutoFillProgressDialog(w)

    # --- Recipe presence (controls whether we wait longer before showing picker) ---
    try:
        _recipes_all = getattr(w, "AUTOFILL_RECIPES", {}) or {}
        _recipe = _recipes_all.get(client_key) if (client_key and isinstance(_recipes_all, dict)) else None
        has_recipe = isinstance(_recipe, dict)
        recipe_win_re = (_recipe.get("window_title_re") or "").strip() if has_recipe else ""
    except Exception:
        has_recipe = False
        recipe_win_re = ""
    dlg.start(stages)
    dlg.show()
    QApplication.processEvents()

    tried_launch = False
    launched_pid = None
    matched_pat = None

    # ---------------- PATH A: launch-first ----------------
    if launch_first:
        dlg.set_stage(1, "Trying to open app", "doing")
        w.set_status_txt(_tr("AutoFill: Trying to open app"))

        try:
            log.info(f"[AUTO FILL] first attempt launch platform={platform_raw!r} row_idx={row_idx}")
            if platform_raw:
                entry_text = {"title": platform_raw}
                w.set_status_txt(_tr("AutoFill: Trying platform (catalog)"))
                invoked, derived_hint = (w._launch_via_existing_menu(entry_text) if hasattr(w, '_launch_via_existing_menu') else (False, None))
            else:
                w.set_status_txt(_tr("AutoFill: Trying App Full Entry (Table)"))
                invoked, derived_hint = (w._launch_via_existing_menu(entry) if hasattr(w, '_launch_via_existing_menu') else (False, None))
            log.info(f"[AUTO FILL] first attempt launch via existing invoked: {invoked}, derived_hint: {derived_hint}")
        except Exception as e:
            log.info(f"[AUTO FILL] first attempt Error {e}")
            invoked, derived_hint = (False, None)

        if invoked:
            tried_launch = True

        if not tried_launch and client_key:
            try:
                w.set_status_txt(w.tr("AutoFill: Waiting to see client (Platform)"))
                log.info(f"[AUTOFILL] Second attempt launch client safely client_key={client_key!r}")

                ok_cat, how_cat, pid_cat = _try_launch_from_catalog(w, u, client_key)
                log.debug(f"[AUTOFILL] catalog launch ok={ok_cat} how={how_cat!r} pid={pid_cat!r}")
                if ok_cat:
                    tried_launch = True
                    launched_pid = pid_cat

                if not tried_launch:
                    ok, _how, pid = _launch_client_safely(w, client_key)
                    log.debug(f"[AUTOFILL] client launch ok={ok} how={_how!r} pid={pid!r}")
                    if ok:
                        tried_launch = True
                        launched_pid = pid
            except Exception as e:
                log.exception(f"[AUTOFILL] Second attempt error: {e}")

        if not tried_launch:
            w.set_status_txt(_tr("AutoFill: Trying install link (table)"))
            link = (entry.get("Install Link") or entry.get("Link") or "").strip()
            if link:
                try:
                    w.launch_or_download(link, platform_hint=(platform_raw or ""))
                    tried_launch = True
                    launched_pid = None
                except Exception:
                    tried_launch = False

        if not tried_launch and exe_hint:
            w.set_status_txt(_tr("AutoFill: Trying Real exe"))
            if exe_hint.lower().endswith((".exe", ".bat", ".cmd", ".lnk")) or os.path.sep in exe_hint:
                try:
                    p = subprocess.Popen([exe_hint], shell=False)
                    tried_launch = True
                    launched_pid = p.pid
                except Exception:
                    tried_launch = False

        if not tried_launch:
            dlg.set_stage(1, "Trying to open app", "fail")
            dlg.set_stage(2, "Unable to open – please open and wait for autofill", "info")
        else:
            _sleep_ms(700)
            dlg.set_stage(1, "Trying to open app", "ok")

    # ---------------- PATH B: wait for login window, then autofill ----------------
    if launch_first and tried_launch:
        w.set_status_txt(w.tr("AutoFill: Opening app, waiting for login window..."))

        patterns = _title_patterns(title_hint, client_key) or [r".*"]
        matched_pat = None

        deadline = _t.time() + (
            45.0 if (client_key and client_key.lower() in ("battlenet", "battle.net"))
            else (35.0 if client_key else 20.0)
        )

        while _t.time() < deadline:
            if launched_pid:
                if _autofill_withretries(entry=entry, titlere=r".*", pid=launched_pid, attempts=1, delay_ms=1):
                    matched_pat = r".*"
                    break

            for pat in patterns:
                if _autofill_withretries(entry=entry, titlere=pat, pid=None, attempts=1, delay_ms=1):
                    matched_pat = pat
                    break

            if matched_pat:
                break

            _sleep_ms(500)

        if matched_pat:
            dlg.set_stage(4, _tr("Waiting for login window"), "ok")
            dlg.set_stage(5, _tr("Attempting to autofill email"), "doing")
            dlg.set_stage(6, _tr("Attempting to autofill password"), "doing")
            dlg.set_stage(7, _tr("Attempting to submit / log in"), "doing")
            w.set_status_txt(_tr("AutoFill: Attempting autofill email, password"))

            ok = _autofill_withretries(entry=entry, titlere=matched_pat, pid=launched_pid, attempts=3, delay_ms=900)
            if not ok:
                w.set_status_txt(_tr("AutoFill: Reattempting autofill email"))
                ok = _autofill_withretries(entry=entry, titlere=matched_pat, pid=launched_pid, attempts=1, delay_ms=0)

            if ok:
                dlg.set_stage(5, None, "ok")
                dlg.set_stage(6, None, "ok")
                dlg.set_stage(7, None, "ok")
                dlg.set_stage(8, None, "ok")
                dlg.finish(True)
                try:
                    w._toast(_tr("Opened app and filled."))
                except Exception:
                    pass
                return True

            w.set_status_txt(_tr("AutoFill: Waiting for login window"))
            
            # Final pass before picker: if we launched something, try a broad match a few times
            if not matched_pat:
                try:
                    broad_attempts = 6 if (has_recipe or (client_key and client_key.lower() in ("battlenet", "battle.net"))) else 3
                    for _ in range(broad_attempts):
                        if _autofill_withretries(entry=entry, titlere=r".*", pid=launched_pid, attempts=1, delay_ms=1):
                            matched_pat = r".*"
                            break
                        _sleep_ms(600)
                except Exception:
                    pass
            dlg.set_stage(4, _tr("Waiting for login window"), "fail")
            w.set_status_txt(_tr("AutoFill: No app found running – select manually"))
            dlg.set_stage(3, _tr("No app found running – select manually"), "info")

    # ---------------- PATH C: manual picker ----------------
    if not launch_first:
        dlg.set_stage(3, _tr("Select the app window to autofill"), "doing")
    else:
        dlg.set_stage(3, _tr("No app found running – select manually"), "doing")

    from features.autofill.window_picker import WindowPickerDialog
    picker = WindowPickerDialog(w)
    if picker.exec() != QDialog.Accepted:
        dlg.set_stage(3, _tr("No app found running – select manually"), "fail")
        dlg.finish(False)
        return False

    try:
        titlere = picker.selected_titleregex() or ""
    except Exception:
        titlere = ""
    try:
        pid = picker.selected_pid()
    except Exception:
        pid = None
    hwnd = None
    try:
        if hasattr(picker, "selected_handle"):
            hwnd = picker.selected_handle()
    except Exception:
        hwnd = None

    dlg.set_stage(5, _tr("Attempting to autofill email"), "doing")
    dlg.set_stage(6, _tr("Attempting to autofill password"), "doing")
    dlg.set_stage(7, _tr("Attempting to submit / log in"), "doing")

    ok = _autofill_withretries(entry=entry, hwnd=hwnd, titlere=titlere, pid=pid, attempts=3, delay_ms=900)
    if not ok:
        ok = _autofill_withretries(entry=entry, hwnd=hwnd, titlere=titlere, pid=pid, attempts=1, delay_ms=0)

    if ok:
        dlg.set_stage(5, None, "ok")
        dlg.set_stage(6, None, "ok")
        dlg.set_stage(7, None, "ok")
        dlg.set_stage(8, None, "ok")
        dlg.finish(True)
        return True

    dlg.set_stage(5, None, "fail")
    dlg.set_stage(6, None, "fail")
    dlg.set_stage(7, None, "fail")
    dlg.finish(False)
    return False

def _key_from_hint_with_ctx(w, hint: str) -> str | None:
    h = (hint or "").strip().lower()
    if not h:
        return None
    ALIASES = getattr(w, "ALIASES", {})  # merged user+builtin
    CLIENTS = getattr(w, "CLIENTS", {})

    if h in ALIASES:
        return ALIASES[h]
    if h in CLIENTS:
        return h

    for k in list(ALIASES.keys()) + list(CLIENTS.keys()):
        if h in k or k in h:
            return ALIASES.get(k, k)

    if "battle" in h and "net" in h: return "battlenet"
    if "ubisoft" in h or "uplay" in h: return "uplay"
    if "steam" in h: return "steam"
    if "epic" in h: return "epic"
    return None

def _row_secret(w, row: int, names: tuple[str, ...], label_set: set[str] | None = None) -> str:
    tbl = getattr(w, "vaultTable", None)
    if tbl is None or row < 0:
        return ""

    wanted = {n.strip().lower() for n in names}
    if label_set:
        wanted |= {lab.strip().lower() for lab in label_set}

    for col in range(tbl.columnCount()):
        header = tbl.horizontalHeaderItem(col)
        key = (header.text() if header else "").strip().lower()
        if key in wanted:
            item = tbl.item(row, col)
            if not item:
                return ""
            try:
                secret = item.data(Qt.UserRole)
                if isinstance(secret, str) and secret.strip():
                    return secret.strip()
            except Exception:
                pass
            return (item.text().strip() if item.text() else "")
    return ""

def launch_then_autofill(w, entry: dict, title_hint: str, *, prefer_launch_first: bool = True, max_wait_sec: int = 35) -> bool:
    """
    1) Resolve client from hint (aliases supported)
    2) Try to launch via EXE or protocol (never a raw 'battle.net' command)
    3) Poll for a matching window title and attempt autofill repeatedly
    Returns True if autofill succeeded.
    """
    username = (entry.get("username") or entry.get("email") or "").strip()

    from app.app_translation_fields import PRIMARY_PASSWORD_LABELS

    # get selected row index
    tbl = getattr(w, "vaultTable", None)
    if tbl is not None:
        row_idx = tbl.currentRow()
    else:
        row_idx = -1

    # try table secret FIRST
    password = _row_secret_local(w, row_idx, ("Password",), PRIMARY_PASSWORD_LABELS)

    # fallback only if needed
    if not password:
        password = (entry.get("password") or "").strip()

    if not username or not password:
        QMessageBox.warning(None, None.tr("Auto-fill"), None.tr("This entry needs a username and password."))
        return False

    client_key = _key_from_hint(title_hint) or _key_from_hint(entry.get("app") or "") or _key_from_hint(entry.get("Title") or "")
    if not client_key:
        log.debug("[AUTOFILL] could not resolve client key from hint; will only try existing windows")
    else:
        log.debug(f"[AUTOFILL] resolved client_key={client_key}")

    tried_launch = False
    how = ""

    if prefer_launch_first and client_key:
        if not tried_launch:
            tried_launch, how, _pid = _launch_client_safely(None, client_key)
        log.debug(f"[AUTOFILL] tried_launch={tried_launch} via {how}")

    # Title patterns to look for
    pats = _build_title_patterns(title_hint, client_key or "")
    if not pats:
        pats = [r"(?i)Login", r"(?i)Sign[- ]?in"]

    deadline = _t.time() + max_wait_sec
    last_err = None

    while _t.time() < deadline:
        for pat in pats:
            try:
                # desktop_autofill.autofill_to_window takes a title regex and handles the keystrokes
                from features.autofill.desktop_autofill import autofill_to_window
                ok = autofill_to_window(pat, username=username, password=password, recipe_key="generic", pid=None)
                if ok:
                    log.debug(f"[AUTOFILL] success with title pattern: {pat}")
                    return True
            except Exception as e:
                last_err = e
        _sleep_ms(800)  # let the window spin up

    log.debug("[AUTOFILL] launched but no matching window; giving up after wait.")
    if last_err:
        log.debug(f"[AUTOFILL] last error: {last_err}")
    # Optionally nudge the user
    QMessageBox.information(None, _tr("Auto-fill"), _tr("Launched the app but couldn’t see a login window yet.\n"
                                               "If the app is still loading, try Auto-fill again in a few seconds."))
    return False


# show window maybe move to ui_gui 
class AutoFillProgressDialog(QDialog):
        """
        Minimal stage-tracker UI for desktop autofill.
        Use: dlg = AutoFillProgressDialog(self); dlg.start(); dlg.set_stage(n, "msg", "state")
        states: "pending" | "doing" | "ok" | "fail" | "info"
        """
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle(_tr("Keyquorum – Auto-fill status"))
            self.setModal(True)
            self.setMinimumWidth(480)
            self._rows = []
            self._stage_count = 0

            lay = QVBoxLayout(self)
            self._title = QLabel(_tr("We’ll try to open the app and auto-fill for you."))
            self._title.setWordWrap(True)
            lay.addWidget(self._title)

            self._table = QTableWidget(0, 2, self)
            self._table.setHorizontalHeaderLabels(["Stage", "Status"])
            self._table.verticalHeader().setVisible(False)
            self._table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
            self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self._table.setFocusPolicy(Qt.NoFocus)
            self._table.setWordWrap(True)
            self._table.setColumnWidth(1, 350)
            lay.addWidget(self._table)

            self._pb = QProgressBar(self)
            self._pb.setRange(0, 0)  # indefinite while running
            lay.addWidget(self._pb)

            row = QHBoxLayout()
            row.addStretch(1)
            self._btn_close = QPushButton(_tr("Close"))
            self._btn_close.setEnabled(False)
            self._btn_close.clicked.connect(self.accept)
            row.addWidget(self._btn_close)
            lay.addLayout(row)

            self._icons = {
                "pending": "⏳",
                "doing":   "🟡",
                "ok":      "✅",
                "fail":    "❌",
                "info":    "ℹ️",
            }

        def start(self, stages: list[str]):
            """Initialize with a fixed set of stage labels (strings)."""
            self._table.setRowCount(0)
            self._rows.clear()
            self._stage_count = len(stages)
            for i, label in enumerate(stages, 1):
                self._table.insertRow(self._table.rowCount())
                it_stage = QTableWidgetItem(f"{i}. {label}")
                it_status = QTableWidgetItem(self._icons["pending"] + "  Waiting…")
                # cosmetic
                it_stage.setFlags(it_stage.flags() ^ Qt.ItemIsEditable)
                it_status.setFlags(it_status.flags() ^ Qt.ItemIsEditable)
                self._table.setItem(self._table.rowCount()-1, 0, it_stage)
                self._table.setItem(self._table.rowCount()-1, 1, it_status)
                self._rows.append((it_stage, it_status))
            self._table.resizeColumnsToContents()
            self._table.horizontalHeader().setStretchLastSection(True)
            self._pump()

        def set_stage(self, idx: int, text: str | None = None, state: str = "doing"):
            """
            idx: 1-based stage index
            state: "pending" | "doing" | "ok" | "fail" | "info"
            """
            try:
                row = idx - 1
                if row < 0 or row >= len(self._rows):
                    return
                it_stage, it_status = self._rows[row]
                if text:
                    it_stage.setText(f"{idx}. {text}")
                icon = self._icons.get(state, self._icons["info"])
                msg = {
                    "pending": "Waiting…",
                    "doing":   "Working…",
                    "ok":      "Done",
                    "fail":    "Failed",
                    "info":    "Info",
                }.get(state, "Info")
                it_status.setText(f"{icon}  {msg}")
                self._pump()
            except Exception:
                pass

        def finish(self, success: bool):
            try:
                self._pb.setRange(0, 1)
                self._pb.setValue(1)
                self._btn_close.setEnabled(True)
                if success:
                    self._title.setText(_tr("All set. Thanks for flying with Keyquorum ✈️"))
                else:
                    self._title.setText(_tr("We couldn’t complete this automatically. You can select a window manually."))
                self._pump()
            except Exception:
                pass

        def _pump(self):
            try:
                QApplication.processEvents(QEventLoop.AllEvents, 50)
            except Exception:
                pass
