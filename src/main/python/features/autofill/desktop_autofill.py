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
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

try:
    # On non‑Windows platforms pywinauto is typically unavailable; keep imports
    # optional so the rest of the app can still run.
    from pywinauto import Desktop
    from pywinauto.application import Application
    from pywinauto.keyboard import send_keys
    from pywinauto.findwindows import ElementNotFoundError  
except Exception:
    Desktop = None  
    Application = None  
    def send_keys(*args, **kwargs): 
        raise RuntimeError("pywinauto is not available on this platform")
    class ElementNotFoundError(Exception): 
        pass

RECIPES_PATH = os.path.join(os.path.dirname(__file__), "autofill_recipes.json")

@dataclass
class TargetWindow:
    title: str
    process: str
    pid: int
    handle: int

def _load_recipes() -> Dict[str, Any]:
    try:
        with open(RECIPES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"generic": {}}

def list_top_windows() -> list[TargetWindow]:
    """
    Prefer UIA to enumerate top-level windows.
    Fall back to raw Win32 enumeration if UIA can't.
    """
    wins: list[TargetWindow] = []
    try:
        from pywinauto import Desktop
        d = Desktop(backend="uia")
        for w in d.windows():
            try:
                t = (w.window_text() or "").strip()
                if not t:
                    continue
                ei = getattr(w, "element_info", None)
                pid = int(getattr(ei, "process_id", 0) or 0)
                handle = int(getattr(ei, "handle", 0) or 0)
                # process name (best effort)
                pname = ""
                try:
                    import psutil
                    if pid:
                        pname = psutil.Process(pid).name()
                except Exception:
                    pass
                wins.append(TargetWindow(title=t, process=pname, pid=pid, handle=handle))
            except Exception:
                continue
        if wins:
            return wins
    except Exception:
        pass

    # Fallback to Win32 path implemented in window_picker.py
    try:
        from window_picker import _fallback_list_top_windows
        return _fallback_list_top_windows()
    except Exception:
        return wins

def _clear_and_type(control, text: str, is_password: bool = False):
    """Set text via UIA if possible, otherwise focus + send_keys."""
    try:
        control.set_edit_text("")   # clear
        control.set_edit_text(text) # many controls accept this
    except Exception:
        control.set_focus()
        # Avoid clipboard use; type directly
        send_keys("^a{BACKSPACE}")
        # Slower for reliability in password boxes
        send_keys(text, with_spaces=True, pause=0.01 if is_password else 0.0)

def _find_control_by_recipe(container, spec: Dict[str, Any]):
    """Find a child by recipe (title_re/control_type) with fallbacks."""
    title_re = spec.get("title_re")
    ctype    = spec.get("control_type")
    index    = int(spec.get("index", 0))

    # First attempt: direct child_window query
    if title_re and ctype:
        try:
            c = container.child_window(title_re=title_re, control_type=ctype)
            c.wait("exists ready", timeout=5)
            return c
        except Exception:
            pass

    # Second attempt: collect descendants and filter
    try:
        nodes = container.descendants(control_type=ctype) if ctype else container.descendants()
        filtered = []
        rx = re.compile(title_re, re.I) if title_re else None
        for n in nodes:
            try:
                name = (n.window_text() or n.element_info.name or "") or ""
                if rx and not rx.search(name):
                    continue
                filtered.append(n)
            except Exception:
                pass
        if filtered:
            return filtered[min(index, len(filtered)-1)]
    except Exception:
        pass

    # Give up
    return None

def _guess_password_edit(container):
    try:
        edits = container.descendants(control_type="Edit")
    except Exception:
        return None
    # Prefer ones whose accessible name includes "pass"
    for e in edits:
        try:
            nm = (e.window_text() or e.element_info.name or "").lower()
            if "pass" in nm:
                return e
        except Exception:
            pass
    # Otherwise return last edit (common layout)
    return edits[-1] if edits else None

import time
try:
    from pywinauto import Application, findwindows
    from pywinauto.keyboard import send_keys
except Exception:
    Application = None
    findwindows = None
    def send_keys(*args, **kwargs):
        raise RuntimeError("pywinauto is not available on this platform")

def autofill_to_window(
    window_title_regex: str,
    username: str,
    password: str,
    recipe_key: str = "generic",
    submit_enter_fallback: bool = True
) -> bool:
    """
    Focus the first top-level window matching /window_title_regex/,
    try to fill username/password via recipe; fall back to a blind TAB sequence.
    """
    recipes = _load_recipes()
    recipe = recipes.get(recipe_key, recipes.get("generic", {}))

    # Locate window handle explicitly so we don't grab the wrong top_window()
    try:
        hwnd = findwindows.find_window(title_re=window_title_regex)
    except findwindows.ElementNotFoundError:
        raise ElementNotFoundError(f"No window matches /{window_title_regex}/")

    app = Application(backend="uia")
    app.connect(handle=hwnd, timeout=10)
    dlg = app.window(handle=hwnd)

    # Focus + settle
    try:
        dlg.set_focus()
    except Exception:
        pass
    time.sleep(0.05)  # 0.15

    # Username control
    u_spec = recipe.get("username", {"control_type": "Edit"})
    u_edit = _find_control_by_recipe(dlg, u_spec)
    if not u_edit:
        try:
            edits = dlg.descendants(control_type="Edit")
            if edits:
                u_edit = edits[0]
        except Exception:
            u_edit = None

    # Password control
    p_spec = recipe.get("password", {"control_type": "Edit", "prefer_password": True})
    p_edit = _find_control_by_recipe(dlg, p_spec)
    if not p_edit and p_spec.get("prefer_password", False):
        p_edit = _guess_password_edit(dlg)

    did_fill = False

    # Fill username
    if u_edit:
        try:
            u_edit.wait("ready", timeout=1)  # 5
            _clear_and_type(u_edit, username, is_password=False)
            did_fill = True
        except Exception:
            pass

    # Fill password
    if p_edit:
        try:
            p_edit.wait("ready", timeout=1)
            _clear_and_type(p_edit, password, is_password=True)
            did_fill = True
        except Exception:
            pass

    # Try submit button
    s_spec = recipe.get("submit", {"control_type": "Button"})
    button = _find_control_by_recipe(dlg, s_spec)

    if button:
        try:
            button.wait("ready", timeout=1)
            button.click_input()
        except Exception:
            # fallback: press Enter from password field or globally
            if p_edit:
                try:
                    p_edit.set_focus()
                except Exception:
                    pass
            if submit_enter_fallback:
                send_keys("{ENTER}")
    elif submit_enter_fallback:
        if p_edit:
            try:
                p_edit.set_focus()
            except Exception:
                pass
        send_keys("{ENTER}")

    time.sleep(0.2)
    return bool(did_fill)
