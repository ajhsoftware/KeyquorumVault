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

"""usage :
App start (pre-login):
import app.kq_logging as kql
log = kql.setup_logging()   # default shared app log
kql.install_qt_message_logging(log)
After successful login:
kql.set_log_user(username)  # switches to %APPDATA%\Keyquorum\\Users\\<user>\logs\<user>.log
log.info("%s user logged in: %s", kql.i("auth"), username)
On logout / user switch back to shared log:
kql.set_log_user(None)
"""


import logging, os, sys, traceback
from logging.handlers import RotatingFileHandler
from typing import Optional
import re
# NOTE: avoid circular import with app.paths; import lazily inside functions
def __user_log_file(username: Optional[str] = None):
    from app.paths import user_log_file as _ulf  # local import (break circular)
    return _ulf(username) if username is not None else _ulf()

# ==============================
# = Redaction filter (hide secrets)
# ==============================

""" Windows (PowerShell)
setx KQ_NO_REDACT 1
Restart the app after setting it.

Linux / macOS
export KQ_NO_REDACT=1

To re-enable redaction:
setx KQ_NO_REDACT "" """

class RedactFilter(logging.Filter):
    PAT = re.compile(
        r"(recovery key|otp|totp|secret|password|token|wrapped_b64|nonce_b64|salt_b64)\s*[:=]\s*([^\s,]+)",
        re.I,
    ) 

    def __init__(self, name: str = ""):
        super().__init__(name)

        # Redaction ON by default
        # Disable ONLY if explicitly requested
        self._disable_redaction = (
            os.getenv("KQ_NO_REDACT", "").strip().lower() in ("1", "true", "yes", "on")
        )

    def filter(self, record: logging.LogRecord) -> bool:
        # ✅ Explicit opt-out only
        return True
        if self._disable_redaction:
            return True

        try:
            msg = record.getMessage()
            redacted = self.PAT.sub(r"\1: [REDACTED]", msg)
            if redacted != msg:
                record.msg = redacted
                record.args = ()
        except Exception:
            pass

        return True


# ==============================
# - Emoji icons (nice-to-have)
# ==============================
ICON = {
    "ok":"✅","info":"ℹ️","debug":"🐞","warn":"⚠️","err":"❌","crit":"🚨",
    "sec":"🔐","locked":"🔒","key":"🗝️","salt":"🧂","sign":"🔏","shield":"🛡️",
    "auth":"🔑","user":"👤","totp":"⏱️","codes":"#️⃣","recovery":"🆘", "add":"➕",
    "vault":"🗄️","backup":"💾","restore":"♻️","export":"📦","import":"📥", "migrate":"🧰",
    "ui":"🖥️","dialog":"🪟","theme":"🎨","search":"🔎","visibility":"👁️‍🗨️",
    "time":"⏱️","slow":"🐢", "fast":"🚀" ,"general": "⚙️", "audit": "📝","rate": "⭐","rate2": "🌟",
    "fs":"📁","file":"📄","path":"🧭","delete":"🗑️","link":"🔗","share2": "🔀","share3": "⇪",
    "net":"🌐","connect":"🔌","req":"📡","resp":"📨","timeout":"⛔","share4": "⤴️","share5": "📣",
    "license":"🪪","qr":"🔳","qr2": "⌗","always_on_top": "📌", "always_on_top2": "📍",
    "always_on_top3": "⬆️", "trial":"🧪","unlock":"🔓","store":"🛍️", "copy": "📋",
    "portable":"💽","preflight":"✈️","scan":"🧪","defender":"🛡️",
    "manifest":"📜","hash":"🧮","verify":"✅","portable": "🧳", 
    "build":"🏗️","pkg":"📦","update":"🔄", "tool":"🧰", "arrow_r": "→",
}
def i(tag: str) -> str:
    return ICON.get(tag, "")

# ==============================
# - Internals / globals
# ==============================
_LOGGER_NAME = "keyquorum"
_FILE_HANDLER_KIND = RotatingFileHandler
_ACTIVE_LOGGER: Optional[logging.Logger] = None
_ACTIVE_FILE_HANDLER: Optional[RotatingFileHandler] = None
_ACTIVE_USERNAME: Optional[str] = None  # None = default app log

# Qt message capture
_qt_logger_ref: Optional[logging.Logger] = None

def install_qt_message_logging(logger: logging.Logger) -> None:
    """Route Qt's messages into Python logging."""
    global _qt_logger_ref
    _qt_logger_ref = logger
    try:
        from qtpy.QtCore import qInstallMessageHandler, QtMsgType
    except Exception:
        return

    def _qt_handler(msg_type, context, message):
        import logging as _logging
        lvl = {
            getattr(QtMsgType, "QtDebugMsg", None): _logging.DEBUG,
            getattr(QtMsgType, "QtInfoMsg", None): _logging.INFO,
            getattr(QtMsgType, "QtWarningMsg", None): _logging.WARNING,
            getattr(QtMsgType, "QtCriticalMsg", None): _logging.ERROR,
            getattr(QtMsgType, "QtFatalMsg", None): _logging.CRITICAL,
        }.get(msg_type, _logging.INFO)
        try:
            if _qt_logger_ref:
                _qt_logger_ref.log(lvl, "[Qt] %s", message)
        except Exception:
            pass

    try:
        qInstallMessageHandler(_qt_handler)
    except Exception:
        pass

# ==============================
# - Paths & handlers
# ==============================
def _default_log_dir() -> str:
    """Default app log directory (pre-login, shared). Overridable via KEYQUORUM_LOG_DIR."""
    p = os.environ.get("KEYQUORUM_LOG_DIR")
    if p:
        try: os.makedirs(p, exist_ok=True)
        except Exception: pass
        return p
    base = os.getenv("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    d = os.path.join(base, "Keyquorum", "logs")
    try: os.makedirs(d, exist_ok=True)
    except Exception: pass
    return d

def _default_log_file() -> str:
    return os.path.join(_default_log_dir(), "KQ_App.log")

def _formatter() -> logging.Formatter:
    return logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")

def _get_logger(logger_name: Optional[str] = None) -> logging.Logger:
    global _ACTIVE_LOGGER
    name = logger_name or _LOGGER_NAME
    if _ACTIVE_LOGGER and _ACTIVE_LOGGER.name == name:
        return _ACTIVE_LOGGER
    lg = logging.getLogger(name)
    if lg.level == logging.NOTSET:
        lg.setLevel(logging.INFO)
    _ACTIVE_LOGGER = lg
    return lg

def _make_file_handler(path: str, level: int) -> RotatingFileHandler:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fh = RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(_formatter())
    return fh

def _attach_file_handler(lg: logging.Logger, handler: RotatingFileHandler) -> None:
    lg.addHandler(handler)

def _detach_active_file_handler(lg: logging.Logger) -> None:
    global _ACTIVE_FILE_HANDLER
    if _ACTIVE_FILE_HANDLER:
        try:
            lg.removeHandler(_ACTIVE_FILE_HANDLER)
            _ACTIVE_FILE_HANDLER.close()
        except Exception:
            pass
        _ACTIVE_FILE_HANDLER = None

def _ensure_console_handler(lg: logging.Logger, level: int) -> None:
    if not any(isinstance(h, logging.StreamHandler) and getattr(h, "_kq_console", False) for h in lg.handlers):
        sh = logging.StreamHandler(sys.__stdout__ or sys.stdout)
        sh._kq_console = True
        sh.setLevel(level)
        sh.setFormatter(_formatter())
        lg.addHandler(sh)
    else:
        for h in lg.handlers:
            if isinstance(h, logging.StreamHandler) and getattr(h, "_kq_console", False):
                h.setLevel(level)

def _remove_console_handler(lg: logging.Logger) -> None:
    for h in list(lg.handlers):
        if isinstance(h, logging.StreamHandler) and getattr(h, "_kq_console", False):
            try:
                lg.removeHandler(h)
            except Exception:
                pass

# ==============================
# - Public API
# ==============================
def setup_logging(logger_name: str = _LOGGER_NAME,
                  level_env: str = "KQ_LOG_LEVEL",
                  *,
                  username: Optional[str] = None) -> logging.Logger:
    """
    Idempotent setup. Before login, writes to default app log.
    After login, call set_log_user(username) to route to per-user log.
    You may also pass username here to start directly in per-user mode.
    """
    global _LOGGER_NAME, _ACTIVE_FILE_HANDLER, _ACTIVE_USERNAME
    _LOGGER_NAME = logger_name or _LOGGER_NAME

    level_name = os.environ.get(level_env, "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    lg = _get_logger(_LOGGER_NAME)
    lg.setLevel(level)

    # Redaction filter (once)
    if not any(isinstance(f, RedactFilter) for f in lg.filters):
        lg.addFilter(RedactFilter())

    # File handler (default or per-user)
    target_path = _user_log_file(username, ensure_parent=True) if username else _default_log_file()
    _detach_active_file_handler(lg)
    _ACTIVE_FILE_HANDLER = _make_file_handler(target_path, level)
    _attach_file_handler(lg, _ACTIVE_FILE_HANDLER)
    _ACTIVE_USERNAME = username

    # Optional console mirror if KQ_CONSOLE=1
    if os.environ.get("KQ_CONSOLE", "0") == "1":
        _ensure_console_handler(lg, level)
    else:
        _remove_console_handler(lg)

    lg.debug("[logging] initialised at %s -> %s", level_name, target_path)
    return lg

def set_log_user(username: Optional[str]) -> None:
    """
    Switch the log target at runtime.
    - username=None -> default app log (pre-login/shared)
    - username='alice' -> per-user log under %APPDATA%\\Keyquorum\\Users\\alice\\logs\\alice.log
    Safe to call multiple times; closes/rotates previous handler.
    """
    global _ACTIVE_USERNAME, _ACTIVE_FILE_HANDLER
    lg = _get_logger()
    # Keep current level / console setup
    current_level = lg.level

    target_path = _user_log_file(username, ensure_parent=True) if username else _default_log_file()
    if _ACTIVE_USERNAME == username and _ACTIVE_FILE_HANDLER:
        # already on the desired file
        return

    _detach_active_file_handler(lg)
    _ACTIVE_FILE_HANDLER = _make_file_handler(target_path, current_level)
    _attach_file_handler(lg, _ACTIVE_FILE_HANDLER)
    _ACTIVE_USERNAME = username
    lg.info("%s switched log target -> %s", i("user"), target_path)



def get_logfile_path() -> str:
    """
    Return the current logfile path (exists or not).
    """
    if _ACTIVE_FILE_HANDLER:
        try:
            return _ACTIVE_FILE_HANDLER.baseFilename  
        except Exception:
            pass
    # Fallback to default path
    return _default_log_file()

def install_global_excepthook(logger: logging.Logger | None = None) -> None:
    def _hook(exc_type, exc, tb):
        msg = "".join(traceback.format_exception(exc_type, exc, tb))
        try:
            (logger or _get_logger()).error("[unhandled] %s", msg)
        finally:
            try:
                sys.__stderr__.write(msg + "\n")
                sys.__stderr__.flush()
            except Exception:
                pass
    sys.excepthook = _hook

def apply_debug_flag(enabled: bool, *, keep_console: bool | None = None) -> None:
    """
    Toggle verbose logging at runtime.
    When enabled=True: level=DEBUG, keeps current file target, optional console.
    When enabled=False: level=WARNING, removes console; keeps file handler (quiet but still logs warnings+).
    """
    lg = _get_logger()
    if enabled:
        lg.setLevel(logging.DEBUG)
        if _ACTIVE_FILE_HANDLER:
            _ACTIVE_FILE_HANDLER.setLevel(logging.DEBUG)
        if keep_console is True or os.environ.get("KQ_CONSOLE", "0") == "1":
            _ensure_console_handler(lg, logging.DEBUG)
        else:
            _remove_console_handler(lg)
        lg.debug("[logging] debug mode enabled")
    else:
        lg.setLevel(logging.WARNING)
        if _ACTIVE_FILE_HANDLER:
            _ACTIVE_FILE_HANDLER.setLevel(logging.WARNING)
        _remove_console_handler(lg)

def set_level(level_name: str) -> None:
    """Manual level control (DEBUG/INFO/WARNING/ERROR/CRITICAL)."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    lg = _get_logger()
    lg.setLevel(level)
    if _ACTIVE_FILE_HANDLER:
        _ACTIVE_FILE_HANDLER.setLevel(level)
