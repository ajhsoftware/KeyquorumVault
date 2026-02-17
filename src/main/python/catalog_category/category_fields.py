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

import logging
from typing import Dict, Any, Optional

log = logging.getLogger("keyquorum")
# ---- System category ----
AUTH_CATEGORY_NAME = "Authenticator"  # system-only, hidden from main table

# ---- Built-in defaults (seed) ----
CATEGORIES = [
    "Passwords","Email Accounts","Social Media","Tenants","Phone Book","Clients","Games","Software","Streaming",
    "Credit Cards","Banks","Money","Personal Info","Webfill","Windows Key","MAC","App","Pins","Wifi","Encrypted Drives",
    "Notes","Other","Temp Accounts","VPN Config","Recovery Codes","SSH Config","SSH Keys","API Keys","Crypto"]

FIELDS_TO_COPY: Dict[str, list[str]] = {
    "Passwords":      ["Website","Email","UserName","Password","Phone Number","Backup Code","2FA Enabled","Notes"],
    "Software":       ["Name","Website","Email","UserName","Password","License Key","Executable Path","Key Path","Platform","Install Link","Notes"],
    "App":            ["App Name","UserName","Password","Email","Backup Code","2FA Enabled","Site","Platform","Install Link","Notes"],
    "Games":          ["Game Name","UserName","Email","Password","Backup Code","2FA Enabled","Platform","Install Link","Notes"],
    "MAC":            ["MAC Address","IP Address","IPv6 Address","Device","Notes"],
    "Streaming":      ["Name","Website","Email","Password","Phone Number","2FA Enabled","Backup Code","Notes"],
    "Windows Key":    ["Windows Name","Product Key","Notes"],
    "Encrypted Drives":["Identifier Key","Password","Recovery Key","Notes"],
    "Personal Info":  ["Full Name","Driving Licence","NHS Number","BlueBadge Info","National Insurance Number","Work Code","Other","Notes"],
    "SSH Keys":       ["Key Name","Public Key","Private Key","Passphrase","Notes"],
    "API Keys":       ["API Name","API Key","Secret Key","Notes"],
    "Recovery Codes": ["Service Name","Recovery Codes","Notes"],
    "SSH Config":     ["Host","User","Port","Identity File","Known Hosts File","Notes"],
    "VPN Config":     ["VPN Name","Config File","UserName","Password","Notes"],
    "Temp Accounts":  ["Account Name","Email","Password","Expiration Date","Notes"],
    "Other":          ["Custom Field 1","Custom Field 2","Custom Field 3","Custom Field 4","Custom Field 5","Notes"],
    "Notes":          ["Title","Content"],
    "Banks":          ["Bank Name","UserName","Customer Number","IBAN","BIC","Account Number","Sort Code","Email","Password","Phone Number"],
    "Credit Cards":   ["Card Type","Cardholder Name","Card Number","Expiry Date","CVV","Billing Address"],
    "Social Media":   ["Platform","UserName","Email","Password","Phone Number","Backup Code","2FA Enabled","Profile URL","Notes"],
    "Money":          ["Name","Website","Email","Password","2FA Enabled","Backup Code","Phone Number","Notes"],
    "Email Accounts": ["Email Provider","Email","UserName","Password","Phone Number","Backup Code","2FA Enabled","IMAP Server","SMTP Server","Notes"],
    "Crypto":         ["Crypto Name","Wallet Address","Private Key","Password","Backup Code","2FA Enabled","Wallet File","Public Key","Exchange Account","Notes"],
    "Pins":           ["PIN Name","PIN Code","Notes"],
    "Wifi":           ["SSID","Password","Encryption Type","MAC Address","Notes"],
    "Webfill":        ["Name Title","First name","Middle name","Surname","Email","Phone Number","Address line 1","Address line 2","City / Town","State / Province / Region","Postal code / ZIP","Country"],
    "Tenants":        ["Tenant Name","Phone Number","Email","Address Line 1","Address Line 2","City / Town","Postal Code / ZIP","Country","Pets","Moved In On","Need Doing","Notes"],
    "Phone Book":     ["Name","Phone Number","Alt Phone","Email","Address","Notes"],
    "Clients":        ["Client Name","Company","Phone Number","Email","Address","Project / Service","Rate / Terms","Notes"],
    # System category fields for OTP:
    AUTH_CATEGORY_NAME: ["Issuer","Account","Secret","Type","Digits","Period","Algorithm","Counter","URI","Notes"],
}

MOVABLE_CATEGORIES   = ["Passwords","Games","App","Temp Accounts"]
SHOWPREFILED         = ["games","app","software","social media"]
BLOCKED_MOVE_TARGETS = ["Banks","Credit Cards"]

_SENSITIVE_DATA = [
    "password","key","code","cvv","account number","secret","iban","bic",
    "private","otp","totp","hotp","customer number","secret"
]

_FILE_LOAD = [
    "Executable Path","Key Path","Wallet File","Identity File","Known Hosts File","Config File"
]

_REQUIRED_PREFS: Dict[str, list[str]] = {
    "Passwords": ["Website"], "Software": ["Name"], "App": ["App Name"], "Games": ["Game Name"], "MAC": ["MAC Address"],
    "Windows Key": ["Windows Name","Product Key"], "Encrypted Drives": ["Identifier Key"], "Personal Info": ["Full Name"],
    "SSH Keys": ["Key Name"], "API Keys": ["API Name"], "Recovery Codes": ["Service Name"], "SSH Config": ["Host"],
    "VPN Config": ["VPN Name"], "Temp Accounts": ["Account Name"], "Other": ["Custom Field 1"], "Notes": ["Title"],
    "Banks": ["Bank Name","Account Number"], "Credit Cards": ["Cardholder Name","Card Number"],
    "Social Media": ["Platform","UserName"], "Email Accounts": ["Email"],
    "Crypto": ["Crypto Name","Wallet Address"], "pins": ["PIN Name"],
    "Wifi": ["SSID","Password"], "Money": ["Name","Email"],
    "Tenants": ["Tenant Name","Email","Address Line 1"],
    "Phone Book": ["Name","Phone Number","Email"],
    "Clients": ["Client Name","Company","Email"],
}

_URL_PREFS: Dict[str, list[str]] = {
    "Passwords": ["Website"],
}

PROTECTED_CATEGORIES = {
    "passwords","credit cards","bank","banks","webfill","web fill","web-fill","app","games","software",
    AUTH_CATEGORY_NAME.lower(),
}

# ---------------------------------
#  Autofill canonical fields (multi-language label map)
#
#  Shape:
#      AUTOFILL_FIELDS = {
#          "password": { "gn": [...english-like...], "no": [...other langs...] },
#          "email":    { "gn": [...],                "no": [...] },
#          ...
#      }
#
#  "gn" = generic/canonical names (usually English)
#  "no" = translated / alternative names (other languages, abbreviations, etc.)
#
#  Usage:
#      key = canonical_autofill_key(label)
#      if key == "password": ...
#
#  This lets autofill / open-site logic keep working even when
#  category fields are translated or imported in a different language.
# ---------------------------------

AUTOFILL_FIELDS: Dict[str, Dict[str, list[str]]] = {
    "password": {
        "gn": [
            "Password",
            "Passcode",
            "PIN",
            "PIN Code",
        ],
        "no": [
            # German
            "Passwort",
            # French
            "Mot de passe",
            # Spanish
            "Contraseña",
            # Italian / Portuguese variants
            "Senha",
            # Dutch
            "Wachtwoord",
            # Russian
            "Пароль",
            # Simplified Chinese
            "密码",
            # Japanese
            "パスワード",
            # Korean
            "비밀번호",
        ],
    },
    "email": {
        "gn": [
            "Email",
            "E-mail",
            "E Mail",
            "Email Address",
        ],
        "no": [
            "Correo electrónico",       # es
            "Dirección de correo",      # es alt
            "Adresse e-mail",           # fr
            "Adresse mail",             # fr alt
            "E-Mail-Adresse",           # de
            "E-mailadres",              # nl
            "电子邮件",                   # zh
            "メールアドレス",              # ja
            "이메일 주소",                # ko
        ],
    },
    "site": {
        "gn": [
            "Website",
            "Site",
            "URL",
            "Login URL",
            "Web URL",
        ],
        "no": [
            "Webseite",                 # de
            "Website-Adresse",          # de alt
            "Sitio web",                # es
            "URL de inicio de sesión",  # es
            "Adresse du site",          # fr
            "URL de connexion",         # fr
            "Сайт",                     # ru
            "网址",                      # zh
            "サイト",                    # ja
            "웹사이트",                  # ko
        ],
    },
    "username": {
        "gn": [
            "UserName",
            "User Name",
            "Login",
            "Account",
            "Login Name",
        ],
        "no": [
            "Benutzername",             # de
            "Nom d’utilisateur",        # fr
            "Nombre de usuario",        # es
            "Nome utente",              # it
            "Nome de usuário",          # pt
            "Kullanıcı adı",            # tr
            "用户名",                     # zh
            "ユーザー名",                 # ja
            "사용자 이름",               # ko
        ],
    },
    "card_number": {
        "gn": [
            "Card Number",
            "Card No",
            "Card #",
            "PAN",
        ],
        "no": [
            "Kartennummer",             # de
            "Número de tarjeta",        # es
            "Numéro de carte",          # fr
            "Número do cartão",         # pt
            "Numero carta",             # it
            "カード番号",                 # ja
            "카드 번호",                 # ko
            "卡号",                      # zh
        ],
    },
}

def _all_autofill_aliases_lower() -> Dict[str, list[str]]:
    """
    Internal helper: return {canonical_key: [all aliases lowercased]}.
    """
    out: Dict[str, list[str]] = {}
    for key, groups in AUTOFILL_FIELDS.items():
        names: list[str] = []
        for group in ("gn", "no"):
            for n in groups.get(group, []):
                n = (n or "").strip()
                if n:
                    names.append(n.lower())
        out[key] = names
    return out

def canonical_autofill_key(label: str) -> Optional[str]:
    """
    Given a field label (possibly translated), return the canonical
    autofill key (e.g. 'password', 'email', 'site', 'card_number', ...),
    or None if it doesn't match any known alias.
    """
    lab = (label or "").strip().lower()
    if not lab:
        return None

    alias_map = _all_autofill_aliases_lower()
    for key, names in alias_map.items():
        if lab in names:
            return key
    return None

def is_password_field(label: str) -> bool:
    return canonical_autofill_key(label) == "password"

def is_email_field(label: str) -> bool:
    return canonical_autofill_key(label) == "email"

def is_site_field(label: str) -> bool:
    return canonical_autofill_key(label) == "site"

def is_card_number_field(label: str) -> bool:
    return canonical_autofill_key(label) == "card_number"

# -------------------- Pure default schema (no disk I/O) --------------------

def _heuristic_sensitive(label: str) -> bool:
    lab = (label or "").lower()
    return any(k in lab for k in _SENSITIVE_DATA)

def _build_default_schema() -> dict:
    cats = []
    for c in CATEGORIES:
        fields = []
        urlset = set(map(str.lower, _URL_PREFS.get(c, [])))
        reqset = set(map(str.lower, _REQUIRED_PREFS.get(c, _URL_PREFS.get(c, []))))
        for label in FIELDS_TO_COPY.get(c, []):
            low = (label or "").lower()
            fields.append({
                "label": label,
                "sensitive": _heuristic_sensitive(label),
                "url": (low in urlset) or low in {"url","website","site"},
                "file_load": (label in _FILE_LOAD),
                "required": (low in reqset),
            })
        cat_meta: Dict[str, Any] = {"name": c, "fields": fields}
        if c == AUTH_CATEGORY_NAME:
            cat_meta["hidden"] = True
            cat_meta["system"] = True
        cats.append(cat_meta)
    return {
        "version": 1,
        "categories": cats,
        "blocked_move_targets": list(BLOCKED_MOVE_TARGETS),
        "movable_categories": list(MOVABLE_CATEGORIES),
    }

def _ensure_authenticator_present(schema: dict) -> dict:
    names = [c.get("name") for c in schema.get("categories", [])]
    if AUTH_CATEGORY_NAME not in names:
        for cat_obj in _build_default_schema().get("categories", []):
            if cat_obj.get("name") == AUTH_CATEGORY_NAME:
                schema.setdefault("categories", []).append(cat_obj)
                break
    else:
        for c in schema.get("categories", []):
            if c.get("name") == AUTH_CATEGORY_NAME:
                c["hidden"] = True
                c["system"] = True
                break
    return schema

def _load_schema() -> dict:
    """
    Return the built-in default schema only.
    No disk access; per-user overrides are handled elsewhere (category_editor/add_entry_dialog).
    """
    schema = _build_default_schema()
    schema = _ensure_authenticator_present(schema)
    return schema

def default_category_schema() -> dict:
    """Return the built-in default category schema (no disk I/O)."""
    return _load_schema()

# -------------------- Public API (defaults-only) --------------------

def hidden_categories() -> list[str]:
    return [c.get("name") for c in _load_schema().get("categories", []) if c.get("hidden")]

def is_hidden_category(name: str) -> bool:
    n = (name or "").strip()
    for c in _load_schema().get("categories", []):
        if (c.get("name") or "").strip() == n:
            return bool(c.get("hidden"))
    return False

def is_system_category(name: str) -> bool:
    n = (name or "").strip()
    for c in _load_schema().get("categories", []):
        if (c.get("name") or "").strip() == n:
            return bool(c.get("system"))
    return False

def get_categories(include_hidden: bool = False) -> list[str]:
    cats = []
    for c in _load_schema().get("categories", []):
        if not include_hidden and c.get("hidden"):
            continue
        cats.append(c.get("name","Unnamed"))
    return cats

def get_fields_for(category: str) -> list[str]:
    for c in _load_schema().get("categories", []):
        if c.get("name") == category:
            return [f.get("label","") for f in c.get("fields", []) if f.get("label")]
    return []

def preferred_url_fields(category: str) -> list[str]:
    for c in _load_schema().get("categories", []):
        if c.get("name") == category:
            return [f["label"] for f in c.get("fields", []) if f.get("url")]
    return []

def showprefiled() -> list[str]:
    d = _load_schema()
    vals = d.get("showprefiled") or SHOWPREFILED
    return [str(v).strip().lower() for v in vals]

def movable_categories() -> list[str]:
    d = _load_schema()
    return list(d.get("movable_categories", MOVABLE_CATEGORIES))

def blocked_move_targets() -> list[str]:
    d = _load_schema()
    return list(d.get("blocked_move_targets", BLOCKED_MOVE_TARGETS))

def sensitive_data_values() -> list[str]:
    labels: list[str] = []
    d = _load_schema()
    for c in d.get("categories", []):
        for f in c.get("fields", []):
            if f.get("sensitive") and f.get("label"):
                labels.append(f["label"])
    # heuristic sweep for user-added-style labels in defaults
    for c in d.get("categories", []):
        for f in c.get("fields", []):
            lab = (f.get("label") or "").lower()
            if any(s in lab for s in _SENSITIVE_DATA) and f.get("label"):
                labels.append(f["label"])
    seen, out = set(), []
    for x in labels:
        k = x.lower()
        if x and k not in seen:
            seen.add(k); out.append(x)
    return out

def file_load_values() -> list[str]:
    labels: list[str] = []
    d = _load_schema()
    for c in d.get("categories", []):
        for f in c.get("fields", []):
            if f.get("file_load") and f.get("label"):
                labels.append(f["label"])
    for x in _FILE_LOAD:
        if x not in labels:
            labels.append(x)
    return labels
