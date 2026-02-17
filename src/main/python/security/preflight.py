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
import logging
import os
import platform
import subprocess
from glob import glob
from pathlib import Path
from typing import Tuple, Optional, Dict

log = logging.getLogger("keyquorum")

from qtpy.QtCore import QCoreApplication

def _tr(text: str) -> str:
    return QCoreApplication.translate("preflight", text)

# ---- Single source of truth for prefs file
from app.paths import security_prefs_file  # returns a FILE path for per-user prefs

# ==============================
# Defaults
# ==============================


# Optional per-tool explanations shown in the preflight warning dialog
# Key: process name (e.g. 'wireshark.exe' or 'wireshark')
# Value: {title, risk, why, recommended}
DEFAULT_PROCESS_NOTES: Dict[str, Dict[str, str]] = {
    'x64dbg': {
        'title': 'x64dbg',
        'risk': 'Debugger / memory inspection',
        'why': 'Can attach to running processes and inspect or modify memory.',
        'recommended': 'Close before unlocking the vault.'
    },
    'ida': {
        'title': 'IDA',
        'risk': 'Reverse engineering tool',
        'why': 'Used to analyse binaries and program behaviour.',
        'recommended': 'Not recommended while unlocking the vault.'
    },
    'ollydbg': {
        'title': 'OllyDbg',
        'risk': 'Debugger',
        'why': 'Can inspect execution flow and memory of running programs.',
        'recommended': 'Close before proceeding.'
    },
    'gdb': {
        'title': 'GDB',
        'risk': 'Debugger',
        'why': 'Can attach to and control running processes.',
        'recommended': 'Close before unlocking the vault.'
    },
    'lldb': {
        'title': 'LLDB',
        'risk': 'Debugger',
        'why': 'Low-level debugger capable of inspecting memory and execution state.',
        'recommended': 'Close before proceeding.'
    },
    'cheatengine': {
        'title': 'Cheat Engine',
        'risk': 'Memory scanner / modifier',
        'why': 'Can scan and modify memory values of running processes.',
        'recommended': 'Strongly recommended to close before unlocking the vault.'
    },
    'wireshark': {
        'title': 'Wireshark',
        'risk': 'Network packet capture',
        'why': 'Can capture and inspect network traffic on this system.',
        'recommended': 'Avoid running while logging in or unlocking the vault.'
    },
    'fiddler': {
        'title': 'Fiddler',
        'risk': 'HTTP/HTTPS interception',
        'why': 'Can intercept and inspect web traffic from applications.',
        'recommended': 'Close before unlocking the vault.'
    },
    'procmon': {
        'title': 'Process Monitor (Procmon)',
        'risk': 'System activity monitoring',
        'why': 'Can observe process, registry and file activity which may aid analysis of app behaviour.',
        'recommended': 'Close before unlocking the vault if you don\'t trust the environment.'
    },
    'processhacker': {
        'title': 'Process Hacker',
        'risk': 'Process inspection / memory access',
        'why': 'Can inspect processes, handles and memory; may weaken local security during unlock.',
        'recommended': 'Close before unlocking the vault.'
    },
    'tcpdump': {
        'title': 'tcpdump',
        'risk': 'Network packet capture',
        'why': 'Can capture and inspect network traffic on this system.',
        'recommended': 'Avoid running while logging in or unlocking the vault.'
    },
    'keylogger': {
        'title': 'Keylogger (generic match)',
        'risk': 'Keystroke capture',
        'why': 'Any keylogging process may capture passwords or 2FA codes.',
        'recommended': 'Quit and investigate immediately.'
    },
    'hookdll': {
        'title': 'Hook DLL (generic match)',
        'risk': 'Input / API hooking',
        'why': 'Hooking components can intercept keyboard input or manipulate application behaviour.',
        'recommended': 'Quit and investigate before proceeding.'
    }
  }

DEFAULT_PREFS: Dict[str, object] = {
    "enable_preflight": True,

    # Vendor-agnostic AV check (WMI on Windows, Defender fallback)
    "check_av": True,

    # Ask to run Windows Defender Quick Scan (we PROMPT; never auto-run)
    "defender_quick_scan": False,

    # If another AV is present and Defender is off, offer to open the vendor UI
    "offer_vendor_ui_on_login": False,

    # Blocking behavior
    "block_on_av_absent": True,    # if no AV is detected → recommend Quit
    "block_on_scan_issue": True,   # if Defender scan returns non-zero → recommend Quit

    # Suspicious tooling
    "severity": "basic",
    "suspect_process_names": [
        "x64dbg", "ida", "ollydbg", "gdb", "lldb", "cheatengine",
        "wireshark", "fiddler", "procmon", "processhacker", "tcpdump",
        "keylogger", "hookdll",
    ],
    "allowlist": [],

    # Optional per-tool explanations shown in the preflight warning dialog
    # Key: process name (e.g. "wireshark.exe" or "wireshark")
    # Value: {title, risk, why, recommended}
    "process_notes": DEFAULT_PROCESS_NOTES,

    # Verbose console logs (set False in release if you want)
    "debug": True,
}

# ==============================
# Small utils
# ==============================

def _dbg(enabled: bool, *args) -> None:
    if enabled:
        try:
            log.debug(" ".join(map(str, ("[preflight]", *args))))
        except Exception:
            pass

def _is_windows() -> bool:
    try:
        return platform.system().lower().startswith("win")
    except Exception:
        return False

# ==============================
# Antivirus detection
# ==============================

def _wmi_av_products_full() -> Tuple[list[dict], Optional[str]]:
    """
    Returns (products, error). Each product:
      { "name": str, "product_exe": str, "report_exe": str, "state": int }
    """
    if not _is_windows():
        return [], "not-windows"
    try:
        import wmi # type: ignore
    except Exception as e:
        return [], f"wmi-import-failed: {e}"
    try:
        c = wmi.WMI(namespace="root\\SecurityCenter2")
        prods = c.AntiVirusProduct()  
        out: list[dict] = []
        for p in prods:
            out.append({
                "name": (getattr(p, "displayName", "") or "").strip(),
                "product_exe": getattr(p, "pathToSignedProductExe", "") or "",
                "report_exe": getattr(p, "pathToSignedReportingExe", "") or "",
                "state": int(getattr(p, "productState", 0) or 0),
            })
        return out, None
    except Exception as e:
        return [], f"wmi-query-failed: {e}"

def _detect_av_products_wmi(debug: bool=False) -> Tuple[list[str], Optional[str]]:
    prods, err = _wmi_av_products_full()
    if err:
        _dbg(debug, "WMI error:", err)
        return [], err
    names = [p["name"] for p in prods if p.get("name")]
    if names:
        _dbg(debug, "WMI detected AV:", names)
    return names, None

def _is_defender_running() -> bool:
    """Fallback if WMI isn't available or nothing is registered; checks WinDefend service."""
    if not _is_windows():
        # On non-Windows, we don't block startup on AV absence.
        return True
    try:
        out = subprocess.check_output(
            ["sc", "query", "WinDefend"],
            encoding="utf-8",
            errors="ignore",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return _tr("RUNNING") in out.upper()
    except Exception:
        return False

def _any_av_present(debug: bool=False) -> Tuple[bool, list[str], str]:
    """
    Returns (present, product_names, source):
      source ∈ {"wmi", "defender-fallback", "none"}
    """
    names, err = _detect_av_products_wmi(debug=debug)
    if names:
        return True, names, "wmi"
    if err:
        _dbg(debug, _tr("WMI AV detection error:"), err)
    if _is_defender_running():
        _dbg(debug, _tr("Defender service RUNNING (fallback)."))
        return True, [_tr("Windows Defender")], "defender-fallback"
    _dbg(debug, _tr("No AV detected via WMI or Defender service."))
    return False, [], _tr("none")

# ---- Defender quick scan (non-freezing when Qt available) ------------------

def _find_mpcmdrun() -> Optional[str]:
    if not _is_windows():
        return None
    candidates: list[str] = []
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    candidates.append(os.path.join(pf, "Windows Defender", "MpCmdRun.exe"))
    base = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                        "Microsoft", "Windows Defender", "Platform")
    try:
        versions = sorted(glob(os.path.join(base, "*")), reverse=True)
        for v in versions:
            candidates.append(os.path.join(v, "MpCmdRun.exe"))
    except Exception:
        pass
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None

def _run_defender_quick_scan_interactive(parent=None, debug: bool=False) -> Tuple[int, str]:
    """
    Run Defender Quick Scan without freezing the UI using QProcess + QProgressDialog.
    Returns (rc, message). rc==0 means OK.
    """
    exe = _find_mpcmdrun()
    if not exe:
        return 127, "MpCmdRun.exe not found"

    try:
        from qtpy.QtWidgets import QProgressDialog, QApplication
        from qtpy.QtCore import QProcess, QEventLoop, Qt
    except Exception as e:
        # fallback: blocking call (last resort)
        _dbg(debug, _tr("No Qt widgets available, running blocking scan:") + f" {e}")
        try:
            rc = subprocess.call(
                [exe, "-Scan", "-ScanType", "1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if rc == 0:
                return 0, _tr("Defender quick scan completed (rc=0)")
            return rc, _tr("Defender quick scan returned rc=") + f"{rc} " + _tr("(threats or error)")
        except Exception as ex:
            return 126, _tr("Defender quick scan error: ") + f"{ex}"

    app = QApplication.instance()
    if app is None:
        raise RuntimeError(_tr("QApplication must exist before showing dialogs."))

    dlg = QProgressDialog(_tr("Running Windows Defender Quick Scan…"), _tr("Cancel"), 0, 0, parent)
    dlg.setWindowModality(Qt.ApplicationModal if parent else Qt.ApplicationModal)
    dlg.setAutoClose(False)
    dlg.setAutoReset(False)
    dlg.setMinimumDuration(0)
    dlg.setAttribute(Qt.WA_DeleteOnClose, True)
    dlg.show()

    proc = QProcess(parent)
    # Best-effort hide console window on Windows
    if _is_windows():
        try:
            proc.setCreateProcessArgumentsModifier(
                lambda args: args.setCreationFlags(0x08000000)  # CREATE_NO_WINDOW
            )
        except Exception:
            pass

    proc.setProgram(exe)
    proc.setArguments(["-Scan", "-ScanType", "1"])

    loop = QEventLoop()
    result = {"rc": -1, "out": ""}

    def on_finished(code: int, _status):
        try:
            out = bytes(proc.readAllStandardOutput()).decode("utf-8", "ignore")
            err = bytes(proc.readAllStandardError()).decode("utf-8", "ignore")
            result["out"] = (out + err).strip()
        except Exception:
            pass
        result["rc"] = code
        loop.quit()

    def on_canceled():
        # We can’t truly cancel Defender; disable button and let it finish
        dlg.setLabelText(_tr("Finishing… (Windows Defender will close shortly)"))
        dlg.setCancelButton(None)

    dlg.canceled.connect(on_canceled)
    proc.finished.connect(on_finished)

    proc.start()
    loop.exec()
    dlg.reset()

    rc = result["rc"]
    if rc == 0:
        return 0, _tr("Defender quick scan completed (rc=0)")
    return rc, _tr("Defender quick scan returned rc=") + f"{rc}" + _tr(" (threats or error)\n") + f"{result['out']}"

# ==============================
# Process listing & suspicious tooling
# ==============================

def get_running_processes() -> list[str]:
    try:
        if _is_windows():
            # Hide console window when listing processes on Windows
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            startupinfo = None
            if os.name == "nt":
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                startupinfo = si
            out = subprocess.check_output(
                "tasklist",
                encoding="utf-8",
                errors="ignore",
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
            lines = [ln for ln in out.splitlines()[3:] if ln.strip()]
            names: list[str] = []
            for ln in lines:
                parts = ln.split()
                if parts:
                    names.append(parts[0].lower())
            return names
        else:
            # Hide console on non-Windows as a best-effort (not typically needed)
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            startupinfo = None
            if os.name == "nt":
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                startupinfo = si
            out = subprocess.check_output(
                ["ps", "aux"],
                encoding="utf-8",
                errors="ignore",
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
            lines = [ln for ln in out.splitlines()[1:] if ln.strip()]
            names: list[str] = []
            for ln in lines:
                parts = ln.split(None, 10)
                if len(parts) >= 11:
                    cmd = parts[10]
                    base = os.path.basename(cmd.split()[0]) if cmd else ""
                    if base:
                        names.append(base.lower())
            return names
    except Exception as e:
        log.error(f"[preflight] Could not retrieve process list: {e}")
        return []

def scan_for_suspicious_processes(prefs: dict) -> list[str]:
    processes = set(get_running_processes())
    badlist = [str(b).lower().rstrip(".exe") for b in prefs.get("suspect_process_names", [])]
    allow = set(str(a).lower().rstrip(".exe") for a in prefs.get("allowlist", []))

    suspects: list[str] = []
    for pname in processes:
        pname_clean = pname.lower().rstrip(".exe")
        if pname_clean in allow:
            continue
        for bad in badlist:
            if bad and bad in pname_clean:
                suspects.append(pname)
                break
    return sorted(set(suspects))

def _kill_process_by_name(name: str) -> Tuple[bool, str]:
    try:
        if _is_windows():
            rc = subprocess.call(
                ["taskkill", "/F", "/IM", name],
                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if rc == 0:
                return True, _tr("Killed") + f" {name}"
            return False, _tr("Failed to kill") + f" {name} (rc={rc})"
        else:
            rc = subprocess.call(
                ["pkill", "-x", name],
                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
            )
            if rc == 0:
                return True, _tr("Killed") + f" {name}"
            return False, _tr("Failed to kill") + f" {name} (rc={rc})"
    except Exception as e:
        return False, _tr("Error killing") + f" {name}: {e}"

def try_kill_processes(names: list[str]) -> list[Tuple[str, bool, str]]:
    results: list[Tuple[str, bool, str]] = []
    for n in names:
        ok, msg = _kill_process_by_name(n)
        results.append((n, ok, msg))
    return results

# ==============================
# Dialog helpers (Qt optional)
# ==============================

def _ensure_qapp():
    try:
        from qtpy.QtWidgets import QApplication
    except Exception:
        return None
    # If no QApplication exists, we won't create one here (caller manages app).

def _show_info_dialog(message: str, parent=None) -> None:
    try:
        from qtpy.QtWidgets import QMessageBox
        _ensure_qapp()
        QMessageBox.information(parent, _tr("Security Notice"), message)
    except Exception:
        log.info(f"[i] {message}")

def _show_warning_dialog(message: str, parent=None) -> None:
    try:
        from qtpy.QtWidgets import QMessageBox
        _ensure_qapp()
        QMessageBox.warning(parent, _tr("Security Warning"), message)
    except Exception:
        log.warning(f"[!] {message}")

def _ask_quit_or_continue(parent, title: str, message: str, default_quit: bool=True) -> bool:
    """Return True to continue, False to quit."""
    try:
        from qtpy.QtWidgets import QMessageBox
        _ensure_qapp()
        box = QMessageBox(parent)
        box.setWindowTitle(title)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(message)
        cont_btn = box.addButton(_tr("Continue Anyway"), QMessageBox.ButtonRole.AcceptRole)
        quit_btn = box.addButton(_tr("Quit (Recommended)"), QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(quit_btn if default_quit else cont_btn)
        box.exec()
        return box.clickedButton() is cont_btn
    except Exception:
        # Safer default when no GUI available: abort startup
        return False

def _norm_proc_key(name: str) -> str:
    s = (name or "").strip().lower()
    # keep both forms in config; normalize for lookup
    return s


def _deep_merge_process_notes(defaults: dict, override: dict) -> dict:
    """Deep-merge process_notes dicts.

    Keeps shipped defaults, while allowing user overrides:
    - Keys are process names (case-insensitive).
    - Values are dicts: {title, risk, why, recommended}
    - If override provides only some fields, remaining default fields are kept.
    """
    out: dict = {}
    if isinstance(defaults, dict):
        for k, v in defaults.items():
            if isinstance(k, str) and isinstance(v, dict):
                out[k] = dict(v)

    if isinstance(override, dict):
        for k, v in override.items():
            if not isinstance(k, str) or not isinstance(v, dict):
                continue
            base = dict(out.get(k, {})) if isinstance(out.get(k), dict) else {}
            base.update(v)  # user fields win
            out[k] = base

    return out

def _normalize_process_notes_keys(notes: dict) -> dict:
    """Normalize process_notes keys to lower-case strings."""
    if not isinstance(notes, dict):
        return {}
    out: dict = {}
    for k, v in notes.items():
        if not isinstance(k, str) or not isinstance(v, dict):
            continue
        key = k.strip().lower()
        if not key:
            continue
        out[key] = dict(v)
    return out

def _get_process_note(prefs: dict | None, proc_name: str) -> dict:
    """Return note dict for proc_name, trying both 'name' and 'name.exe' keys."""
    try:
        notes = (prefs or {}).get("process_notes", {}) or {}
        if not isinstance(notes, dict):
            return {}

        key = _norm_proc_key(proc_name)

        # try exact key
        if key in notes and isinstance(notes[key], dict):
            return notes[key]

        # try stripping/adding ".exe"
        if key.endswith(".exe"):
            k2 = key[:-4]
            if k2 in notes and isinstance(notes[k2], dict):
                return notes[k2]
        else:
            k2 = key + ".exe"
            if k2 in notes and isinstance(notes[k2], dict):
                return notes[k2]

        return {}
    except Exception:
        return {}

def ask_preflight_decision(parent, suspicious: list[str], prefs: dict | None = None) -> str:
    """Return 'kill', 'continue', or 'quit'.

    If prefs includes a 'process_notes' dict, we show per-tool details in the dialog.
    We soften messaging for legitimate tools (debuggers/sniffers/etc.) and use
    stronger language for suspicious indicators (e.g., keylogger/hookdll).
    """
    try:
        from qtpy.QtWidgets import QMessageBox
        _ensure_qapp()

        box = QMessageBox(parent)
        box.setWindowTitle(_tr("Preflight Warning"))
        box.setIcon(QMessageBox.Icon.Warning)

        def _is_suspicious_indicator(proc: str, note: dict) -> bool:
            name = (proc or "").strip().lower()
            title = str((note or {}).get("title", "")).lower()
            risk = str((note or {}).get("risk", "")).lower()
            why = str((note or {}).get("why", "")).lower()
            blob = " ".join([name, title, risk, why])

            # Explicit high-risk indicators / malware-ish signals
            indicators = ("keylogger", "hookdll", "inject", "stealer", "rat", "spy", "logger", "hook ")
            if any(tok in blob for tok in indicators):
                return True
            if name in ("keylogger", "hookdll"):
                return True
            return False

        legit: list[str] = []
        suspicious_indicators: list[str] = []

        for p in suspicious:
            info = _get_process_note(prefs, p)
            if _is_suspicious_indicator(p, info):
                suspicious_indicators.append(p)
            else:
                legit.append(p)

        # Main message (soft for legit tools, stronger for suspicious indicators)
        if suspicious_indicators and not legit:
            box.setText("🚨 " + _tr("High-risk processes detected:"))
            box.setInformativeText("\n".join(f"• {p}" for p in suspicious_indicators))
        elif suspicious_indicators and legit:
            box.setText("🚨 " + _tr("Risky processes detected:"))
            box.setInformativeText("\n".join(f"• {p}" for p in suspicious))
        else:
            box.setText("⚠️ " + _tr("Potentially risky tools detected:"))
            box.setInformativeText("\n".join(f"• {p}" for p in legit))

        details: list[str] = []
        any_notes = False

        if suspicious_indicators:
            details.append(_tr(
                "If you did NOT install or expect these processes to be running, it is recommended you QUIT "
                "and investigate your system before entering any credentials or unlocking the vault."
            ))
        else:
            details.append(_tr(
                "These tools can be legitimate, but they may reduce system security while unlocking the vault "
                "(e.g., by inspecting memory or capturing network traffic).\n"
                "If you did NOT install or expect these tools to be running, it is recommended you QUIT and investigate."
            ))

        def _append_tool_details(proc_list: list[str], heading: str) -> None:
            nonlocal any_notes
            if not proc_list:
                return
            details.append("")
            details.append(heading)
            details.append("-" * len(heading))
            for p in proc_list:
                info = _get_process_note(prefs, p)
                if info:
                    any_notes = True
                title = (info.get("title") if isinstance(info, dict) else None) or p
                risk = (info.get("risk") if isinstance(info, dict) else None)
                why = (info.get("why") if isinstance(info, dict) else None)
                rec = (info.get("recommended") if isinstance(info, dict) else None)

                if title != p:
                    details.append(f"{title} ({p})")
                else:
                    details.append(f"{p}")

                if risk:
                    details.append("  • " + _tr("Risk") + f": {risk}")
                if why:
                    details.append("  • " + _tr("Why") + f": {why}")
                if rec:
                    details.append("  • " + _tr("Recommended") + f": {rec}")
                details.append("")

        _append_tool_details(suspicious_indicators, _tr("Suspicious indicators"))
        _append_tool_details(legit, _tr("Legitimate tools (higher risk while unlocking)"))

        if not any_notes:
            details.append("")
            details.append(_tr(
                "These processes may reduce system security (e.g., capture keystrokes, inspect memory, or capture network data)."
            ))

        details.append("")
        details.append(_tr(
            "Choose Kill & Continue to terminate them, Continue Anyway (higher risk), or Quit."
        ))

        box.setDetailedText("\n".join(details).strip())

        kill_btn = box.addButton(_tr("Kill & Continue"), QMessageBox.ButtonRole.AcceptRole)
        cont_btn = box.addButton(_tr("Continue Anyway"), QMessageBox.ButtonRole.ActionRole)
        quit_btn = box.addButton(_tr("Quit"), QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(kill_btn)

        box.exec()
        clicked = box.clickedButton()
        if clicked is kill_btn:
            return "kill"
        if clicked is cont_btn:
            return "continue"
        return "quit"
    except Exception:
        log.error("[preflight] No GUI available; defaulting to quit.")
        return "quit"

def _offer_vendor_scan(parent, debug: bool=False) -> Optional[str]:
    """
    If a vendor AV is active but Defender is off, offer to launch the vendor product UI.
    Returns a message describing action taken (or None).
    """
    prods, err = _wmi_av_products_full()
    if err or not prods:
        return None
    for p in prods:
        name = (p.get("name") or "").strip()
        exe = (p.get("product_exe") or "").strip()
        if not name or "defender" in name.lower():
            continue
        if exe and os.path.isfile(exe):
            try:
                from qtpy.QtWidgets import QMessageBox
                _ensure_qapp()
                box = QMessageBox(parent)
                box.setWindowTitle(_tr("Antivirus Scan"))
                box.setIcon(QMessageBox.Icon.Question)
                box.setText(f"{name} " + _tr("appears to be active.\n\nOpen its app so you can start a Quick Scan?"))
                open_btn = box.addButton(_tr("Open") + f" {name}", QMessageBox.ButtonRole.AcceptRole)
                skip_btn = box.addButton(_tr("Skip"), QMessageBox.ButtonRole.RejectRole)
                box.setDefaultButton(open_btn)
                box.exec()
                if box.clickedButton() is open_btn:
                    _dbg(debug, _tr("Launching vendor AV UI:"), name, exe)
                    subprocess.Popen([exe], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                    return f"Launched {name} UI"
            except Exception as e:
                _dbg(debug, f"Failed to prompt/launch {name}: {e}")
    return None

# ==============================
# Prefs I/O (via paths.security_prefs_file)
# ==============================

def _prefs_path(username: Optional[str]) -> Optional[Path]:
    try:
        # Treat "no username" as the shared/global prefs file.
        # This is used for "preflight on startup" before a user is selected.
        if username is None:
            username = "default"
        return Path(security_prefs_file(username, ensure_parent=True, name_only=False))
    except Exception:
        return None

def load_security_prefs(username: Optional[str] = None) -> dict:
    """Load security prefs (per-user or global default), merged with defaults.

    process_notes are deep-merged so shipped defaults remain available
    while user edits override individual fields.
    """
    prefs = dict(DEFAULT_PREFS)

    # Always start with shipped notes (normalized)
    prefs["process_notes"] = _deep_merge_process_notes(
        _normalize_process_notes_keys(DEFAULT_PROCESS_NOTES), {}
    )

    try:
        p = _prefs_path(username)
        if p and p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                # Shallow merge: user values override defaults
                prefs.update(data)

                # Deep-merge process notes (user overrides win per-field)
                user_notes = _normalize_process_notes_keys(data.get("process_notes", {}) or {})
                prefs["process_notes"] = _deep_merge_process_notes(
                    _normalize_process_notes_keys(DEFAULT_PROCESS_NOTES),
                    user_notes,
                )
    except Exception as e:
        log.error(f"[preflight] load_security_prefs({username}): {e}")

    return prefs

def save_security_prefs(prefs: dict, username: Optional[str] = None) -> None:
    """Save per-user prefs file (atomic)."""
    try:
        p = _prefs_path(username)
        if not p:
            return
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(prefs, indent=2), encoding="utf-8")
        os.replace(tmp, p)
    except Exception as e:
        log.error(f"[preflight] Failed to save security prefs for {username}: {e}")

def ensure_preflight_defaults(username: str | None = None) -> None:
    """Ensure a security prefs file exists and contains required default keys.

    - If missing, create from DEFAULT_PREFS.
    - If present, merge in missing keys (without deleting user values).
    - process_notes are deep-merged so shipped defaults are kept while user edits win.
    """
    try:
        username = (username or "default").strip() or "default"
        p = _prefs_path(username)
        if not p:
            return

        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            base = dict(DEFAULT_PREFS)
            base["process_notes"] = _deep_merge_process_notes(
                _normalize_process_notes_keys(DEFAULT_PROCESS_NOTES), {}
            )
            p.write_text(json.dumps(base, indent=2), encoding="utf-8")
            log.info(f"[preflight] Created new security prefs for user '{username}'")
            return

        try:
            existing = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            existing = {}

        merged = dict(DEFAULT_PREFS)
        if isinstance(existing, dict):
            merged.update(existing)

        existing_notes = _normalize_process_notes_keys(
            (existing.get("process_notes", {}) if isinstance(existing, dict) else {}) or {}
        )
        merged["process_notes"] = _deep_merge_process_notes(
            _normalize_process_notes_keys(DEFAULT_PROCESS_NOTES),
            existing_notes,
        )

        p.write_text(json.dumps(merged, indent=2), encoding="utf-8")

    except Exception as e:
        log.error(f"[preflight] ensure_preflight_defaults({username}) failed: {e}")

# ==============================
# Merge helpers (global + per-user overrides)
# ==============================

def _merge_prefs(global_prefs: dict, user_overrides: Optional[dict]) -> dict:
    out = dict(DEFAULT_PREFS)

    gp = global_prefs or {}
    uo = user_overrides or {}

    # Back-compat: map 'check_defender' -> 'check_av'
    if gp.get("check_defender") and not gp.get("check_av"):
        gp = dict(gp)
        gp["check_av"] = True

    # Merge global first (only known keys)
    for k, v in gp.items():
        if k in out:
            out[k] = v

    # Merge user overrides (only known keys)
    for k in (
        "enable_preflight", "severity", "check_av", "defender_quick_scan", "debug",
        "block_on_av_absent", "block_on_scan_issue", "allowlist", "suspect_process_names",
        "offer_vendor_ui_on_login", "process_notes",
    ):
        if k in uo:
            out[k] = uo[k]

    def _norm_list(v) -> list[str]:
        return [str(x).lower() for x in (v or [])]

    out["allowlist"] = sorted(set(_norm_list(out.get("allowlist", []))))
    out["suspect_process_names"] = sorted(set(_norm_list(out.get("suspect_process_names", []))))

    # Deep-merge process_notes: defaults -> global -> user
    base_notes = _normalize_process_notes_keys(DEFAULT_PROCESS_NOTES)
    gp_notes = _normalize_process_notes_keys(gp.get("process_notes", {}) or {})
    uo_notes = _normalize_process_notes_keys(uo.get("process_notes", {}) or {})
    out["process_notes"] = _deep_merge_process_notes(
        _deep_merge_process_notes(base_notes, gp_notes),
        uo_notes,
    )

    return out

# ==============================
# Entrypoints
# ==============================

def run_preflight_for_user(
    username: str,
    user_prefs_loader,
    is_dev: bool = False,
    parent=None
) -> bool:
    """
    Classic single flow:
    - AV presence check (with optional vendor UI offer)
    - Prompted Defender quick scan if enabled
    - Suspicious tooling scan with Kill/Continue/Quit
    """
    base = load_security_prefs(username)
    try:
        per_user = user_prefs_loader(username) or {}
    except Exception:
        per_user = {}
    merged = _merge_prefs(base, per_user)
    return run_preflight_checks(is_dev=is_dev, parent=parent, prefs=merged)

def run_preflight_checks(
    is_dev: bool = False,
    parent=None,
    prefs: Optional[dict] = None
) -> bool:
    try:
        effective = prefs if isinstance(prefs, dict) else load_security_prefs()
    except Exception as e:
        log.error(f"[preflight] load_security_prefs failed: {e}")
        effective = dict(DEFAULT_PREFS)

    debug = bool(effective.get("debug", True))

    # Global switch
    if not effective.get("enable_preflight", True):
        _dbg(debug, "Disabled in config.")
        return True

    # ---------------- Antivirus presence check ----------------
    check_av_flag = bool(effective.get("check_av", effective.get("check_defender", False)))
    if check_av_flag and _is_windows():
        ok_av, names, source = _any_av_present(debug=debug)
        if ok_av:
            _dbg(debug, f"AV present via {source}: {names}")

            # If Defender is OFF but another AV is present, offer to open vendor UI (respect config)
            if not _is_defender_running():
                if bool(effective.get("offer_vendor_ui_on_login", False)):
                    _offer_vendor_scan(parent, debug=debug)
        else:
            msg = _tr(
                "⚠️ No active antivirus was detected.\n\n"
                "To help protect your vault, it is recommended that an antivirus solution "
                "is installed and enabled before proceeding.\n\n"
                "Please enable or install an antivirus first.\n\n"
                "If no antivirus is installed on this system, it is strongly recommended "
                "that you do NOT enter any credentials or unlock the vault, to help keep "
                "your data safe.\n\n"
                "Remember: this app is only as secure as the system it runs on.\n"
                "Strong system security = a strong vault."
            )
            if bool(effective.get("block_on_av_absent", True)):
                cont = _ask_quit_or_continue(parent, _tr("No Antivirus Detected"), msg, default_quit=True)
                if not cont:
                    return False
            else:
                _show_warning_dialog(msg, parent)

        # -------------- ask to run Defender Quick Scan --------------
        if bool(effective.get("defender_quick_scan", False)):
            try:
                from qtpy.QtWidgets import QMessageBox
                _ensure_qapp()
                box = QMessageBox(parent)
                box.setWindowTitle(_tr("Windows Defender Quick Scan"))
                box.setIcon(QMessageBox.Icon.Question)
                box.setText(_tr("Run a Windows Defender Quick Scan before proceeding?"))
                run_btn = box.addButton(_tr("Run Scan"), QMessageBox.ButtonRole.AcceptRole)
                skip_btn = box.addButton(_tr("Skip"), QMessageBox.ButtonRole.RejectRole)
                quit_btn = box.addButton(_tr("Quit"), QMessageBox.ButtonRole.DestructiveRole)
                box.setDefaultButton(run_btn)
                box.exec()

                if box.clickedButton() is quit_btn:
                    return False
                if box.clickedButton() is run_btn:
                    rc, msg = _run_defender_quick_scan_interactive(parent=parent, debug=debug)
                    _dbg(debug, msg)
                    if rc != 0 and bool(effective.get("block_on_scan_issue", True)):
                        warn = (_tr(
                            "⚠️ Windows Defender reported issues during a Quick Scan "
                            "(threats found or error).\n\n"
                            "Do NOT proceed until you've resolved all threats or removed external media."
                        ))
                        cont = _ask_quit_or_continue(parent, _tr("Defender Scan Warning"), warn, default_quit=True)
                        if not cont:
                            return False
            except Exception as e:
                _dbg(debug, f"Could not prompt for Defender scan: {e}")

    # ---------------- Suspicious process scan ----------------
    flagged = scan_for_suspicious_processes(effective)
    if not flagged:
        _dbg(debug, _tr("All clear (no suspicious processes)."))
        return True

    if is_dev:
        _show_warning_dialog(_tr(
            "Suspicious tools detected (dev mode):\n\n")
            + "\n".join(f"• {p}" for p in flagged)
            + "\n\n" + _tr("Continuing (higher risk)."),
            parent,
        )
        _dbg(debug, _tr("Dev mode: continuing despite:"), flagged)
        return True

    decision = ask_preflight_decision(parent, flagged, prefs=effective)
    if decision == "quit":
        _dbg(debug, _tr("User chose to quit."))
        return False
    if decision == "continue":
        _show_warning_dialog(_tr("Continuing with suspicious tools running (higher risk)."), parent)
        _dbg(debug, "User continued at risk.")
        return True

    results = try_kill_processes(flagged)
    killed = [n for (n, ok, _msg) in results if ok]
    failed = [n for (n, ok, _msg) in results if not ok]

    remaining = scan_for_suspicious_processes(effective)
    if remaining:
        lines: list[str] = []
        if killed:
            lines.append(_tr("Terminated") + ":\n" + "\n".join(f"  • {k}" for k in killed))
        if failed:
            lines.append(_tr("Failed to terminate") + ":\n" + "\n".join(f"  • {f}" for f in failed))
        lines.append(_tr(
            "\nSome suspicious tools are still running.\n"
            "You can Quit now, or Continue Anyway at higher risk.")
        )
        _show_warning_dialog("\n".join(lines), parent)

        final = ask_preflight_decision(parent, remaining, prefs=effective)
        if final == "quit":
            _dbg(debug, _tr("Quit after failed terminations."))
            return False
        _dbg(debug, _tr("Continuing despite remaining:"), remaining)
        return True

    _show_info_dialog(_tr("All suspicious tools terminated. Continuing."), parent)
    _dbg(debug, "Cleared after termination.")
    return True

# ==============================
# Improved AV summary for UI (Windows 10/11)
# ==============================

def detect_antivirus_status():
    """Return dict: { overall, providers: [{name,state,upToDate,detailed}], source }"""
    if not _is_windows():
        return {"overall": "Unknown", "providers": [], "source": "none"}

    # 1) Windows Security Center API (overall health)
    try:
        import ctypes
        from ctypes import wintypes
        WSC_SECURITY_PROVIDER_ANTIVIRUS = 0x00000004
        WSC_HEALTH = {
            0: "Unknown",
            1: "Good",
            2: "NotMonitored",
            3: "Poor",
            4: "Snoozed",
        }
        wscapi = ctypes.WinDLL("wscapi.dll")
        WscGetSecurityProviderHealth = wscapi.WscGetSecurityProviderHealth
        WscGetSecurityProviderHealth.argtypes = [wintypes.DWORD, ctypes.POINTER(ctypes.c_int)]
        WscGetSecurityProviderHealth.restype  = ctypes.c_long
        health = ctypes.c_int(0)
        hr = WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS, ctypes.byref(health))
        if hr == 0:
            overall = WSC_HEALTH.get(health.value, "Unknown")
            providers = _cim_antivirus_products_quick()
            return {"overall": overall, "providers": providers, "source": "wsc"}
    except Exception:
        pass

    # 2) CIM AntiVirusProduct
    providers = _cim_antivirus_products_quick()
    if providers:
        overall = _overall_from_providers(providers)
        return {"overall": overall, "providers": providers, "source": "cim"}

    # 3) Defender fallback
    try:
        ps = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
              "Get-MpComputerStatus | ConvertTo-Json -Compress"]
        # Hide console when falling back to Defender
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        startupinfo = None
        if os.name == "nt":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            startupinfo = si
        out = subprocess.check_output(
            ps,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=8,
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
        data = json.loads(out)
        name = "Microsoft Defender Antivirus"
        enabled = bool(data.get("RealTimeProtectionEnabled", False)) or bool(data.get("AntispywareEnabled", False))
        uptodate = bool(data.get("AntivirusSignatureVersion", ""))
        state = "Enabled" if enabled else "Disabled"
        prov = {"name": name, "state": state, "upToDate": uptodate, "detailed": "Defender fallback"}
        overall = _overall_from_providers([prov])
        return {"overall": overall, "providers": [prov], "source": "defender"}
    except Exception:
        return {"overall": "Unknown", "providers": [], "source": "none"}

def _cim_antivirus_products_quick():
    try:
        ps = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
              r"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
              r"Select-Object displayName,productState,timestamp | ConvertTo-Json -Compress"]
        # Hide console when querying AV products
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        startupinfo = None
        if os.name == "nt":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            startupinfo = si
        out = subprocess.check_output(
            ps,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=8,
            creationflags=creationflags,
            startupinfo=startupinfo,
        ).strip()
        if not out:
            return []
        data = json.loads(out)
        items = data if isinstance(data, list) else [data]
        providers = []
        for item in items:
            name = (item.get("displayName") or "").strip() or "Unknown AV"
            try:
                state_raw = int(item.get("productState") or 0)
            except Exception:
                state_raw = 0
            state, uptodate, detail = _decode_product_state(state_raw)
            providers.append({"name": name, "state": state, "upToDate": uptodate, "detailed": f"{detail} (0x{state_raw:06X})"})
        return providers
    except Exception:
        return []

def _decode_product_state(ps_int):
    aa = (ps_int >> 16) & 0xFF
    bb = (ps_int >> 8) & 0xFF
    cc = ps_int & 0xFF
    uptodate = None
    if aa == 0x00:
        uptodate = True
    elif aa == 0x10:
        uptodate = False
    if bb == 0x10:
        prod = "Enabled"
    elif bb == 0x01:
        prod = "Snoozed"
    elif bb == 0x00:
        prod = "Disabled"
    else:
        prod = "Unknown"
    detail = f"sig={'UpToDate' if uptodate else 'OutOfDate' if uptodate is False else 'Unknown'}, product={hex(bb)}, realtime={hex(cc)}"
    if uptodate is False and prod != "Enabled":
        state = "Expired"
    else:
        state = prod
    return state, uptodate, detail

def _overall_from_providers(providers):
    any_enabled = any(p.get('state') == 'Enabled' for p in providers)
    any_snoozed = any(p.get('state') == 'Snoozed' for p in providers)
    any_expired = any(p.get('state') == 'Expired' for p in providers)
    any_disabled = any(p.get('state') == 'Disabled' for p in providers)
    if any_enabled and not (any_snoozed or any_expired):
        return "Good"
    if any_snoozed:
        return "Snoozed"
    if any_expired or any_disabled:
        return "Poor"
    return "Unknown"

def summarize_antivirus_for_ui(av):
    if not av or not isinstance(av, dict):
        return _tr("Antivirus: Unknown")
    if not av.get("providers"):
        return _tr("Antivirus") + f": {av.get('overall','Unknown')}" + _tr(" (no providers)")
    pieces = []
    for p in av["providers"]:
        up = "Up-to-date" if p.get("upToDate") else ("Out-of-date" if p.get("upToDate") is False else "Unknown")
        pieces.append(f"{p.get('name','?')}: {p.get('state','?')} ({up})")
    return _tr("Antivirus: ") + "; ".join(pieces)


# ============================== Back-compat helpers for main.py =====================

def _norm_proc_name(name: str) -> str:
    s = (name or "").strip().lower()
    if s.endswith(".exe"):
        s = s[:-4]
    return s

def add_process_to_watch(process_name: str, username: str | None = None) -> bool:
    """
    Legacy helper expected by main.py.
    Adds a process to the 'suspect_process_names' list for the given user,
    de-duplicated case-insensitively and with '.exe' stripped.
    """
    try:
        if not (process_name or "").strip():
            return False
        prefs = load_security_prefs(username)
        items = prefs.get("suspect_process_names", []) or []
        norm_new = _norm_proc_name(process_name)

        # remove any duplicates with different casing / .exe suffix
        dedup = []
        seen = set()
        for it in items:
            k = _norm_proc_name(str(it))
            if k in seen:
                continue
            seen.add(k)
            dedup.append(it)

        if norm_new not in seen:
            dedup.append(process_name.strip())

        prefs["suspect_process_names"] = dedup
        save_security_prefs(prefs, username)
        return True
    except Exception:
        return False

def add_allowlist_process(process_name: str, username: str | None = None) -> bool:
    """
    Legacy helper expected by main.py.
    Adds a process to the 'allowlist' for the given user and removes any
    matching entry from 'suspect_process_names'.
    """
    try:
        if not (process_name or "").strip():
            return False
        prefs = load_security_prefs(username)

        # normalise current lists
        allow = prefs.get("allowlist", []) or []
        suspects = prefs.get("suspect_process_names", []) or []
        norm_new = _norm_proc_name(process_name)

        # de-dup allowlist
        allow_seen = set()
        allow_dedup = []
        for it in allow:
            k = _norm_proc_name(str(it))
            if k in allow_seen:
                continue
            allow_seen.add(k)
            allow_dedup.append(it)

        if norm_new not in allow_seen:
            allow_dedup.append(process_name.strip())

        # remove from suspects if present
        suspects_filtered = []
        for it in suspects:
            if _norm_proc_name(str(it)) == norm_new:
                continue
            suspects_filtered.append(it)

        prefs["allowlist"] = allow_dedup
        prefs["suspect_process_names"] = suspects_filtered
        save_security_prefs(prefs, username)
        return True
    except Exception:
        return False
