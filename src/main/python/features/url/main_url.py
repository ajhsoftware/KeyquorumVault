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

# ==============================
# --- Main Values ---
# ==============================
SITE_MAIN           = "https://www.ajhsoftware.uk",
SITE_HELP           = "https://www.ajhsoftware.uk/keyquorum/kqhelp"
SITE_SUPPORT        = "https://forms.gle/118nQkUeV5cZyFj27"
SITE_SUPPORT_ME     = "https://www.ajhsoftware.uk/support-me"
PRIVACY_POLICY      = "https://www.ajhsoftware.uk/keyquorum/privacy-policy"
SITE_ANDROID        = ""
SITE_LINUX          = ""
SITE_VIDEO          = "https://www.ajhsoftware.uk/keyquorum/video-help"
SITE_SEC            = "https://www.ajhsoftware.uk/keyquorum/security-practices-tips"
SITE_THREAT         = "https://www.ajhsoftware.uk/keyquorum/threat-model"
SITE_BUG_FIX        = "https://www.ajhsoftware.uk/keyquorum/bugs-fixes"
SITE_CATALOG        = "https://www.ajhsoftware.uk/keyquorum/catalog-help"
SITE_BROWSER        = "https://www.ajhsoftware.uk/keyquorum/browser-extension-help"
SITE_BROW_TEST      = "https://ajhsoftware.github.io/kq-test-pages/"
REDDIT              = "https://www.reddit.com/r/AJHsoftware/"
STORE_URL_CHROME    = "https://chromewebstore.google.com/detail/keyquorum-autofill-local/jcblpckopkkhokdjdojlblknikfahbgb"
STORE_URL_EDGE      = ""  # optional: https://microsoftedge.microsoft.com/addons/detail/<ID> 
WATCH               = ""
PWNEDPASSWORD       = "https://api.pwnedpasswords.com/range/"
PWNEDEMAIL            = "https://haveibeenpwned.com/account/"
CATEGORY_DOWN       = "https://www.ajhsoftware.uk/keyquorum/category"

# ==============================
# --- App Hints Values ---
# ==============================
URI_HINTS = {
    "netflix": "https://www.netflix.com",
    "disneyplus": "https://www.disneyplus.com",
    "primevideo": "https://www.primevideo.com",
    "spotify": "spotify://open",
    "youtube": "https://www.youtube.com",
    "twitch": "https://www.twitch.tv",
    "plex": "https://app.plex.tv",
}

# ==============================
# --- Store IDs ---
# ==============================
APP_ID = "9NCWWM5CMQ55"
MSSTORE_ADDONS = {
    "month":    "9NB534N40VZV",
    "year":     "9P07WTXX553F",
    "onetime": "9P744GF39NFN",
}

STORE_REVIEW_URI = f"ms-windows-store://review/?ProductId={APP_ID}"
# ==============================
# --- Open URL---
# ==============================
URL_REGISTRY = {
    "REDDIT": REDDIT,
    "STORE_URL_CHROME": STORE_URL_CHROME,
    "STORE_URL_EDGE": STORE_URL_EDGE,
    "WATCH": WATCH,
    "PWNEDPASSWORD": PWNEDPASSWORD,
    "PWNEMAIL": PWNEDEMAIL,
    "CATEGORY_DOWN": CATEGORY_DOWN,
    "SITE_MAIN": SITE_MAIN,
    "SITE_HELP": SITE_HELP,
    "SITE_SUPPORT": SITE_SUPPORT,
    "SITE_SUPPORT_ME": SITE_SUPPORT_ME,
    "PRIVACY_POLICY": PRIVACY_POLICY,
    "SITE_ANDROID": SITE_ANDROID,
    "SITE_LINUX": SITE_LINUX,
    "SITE_VIDEO": SITE_VIDEO,
    "SITE_SEC": SITE_SEC,
    "SITE_THREAT": SITE_THREAT,
    "SITE_BUG_FIX": SITE_BUG_FIX,
    "SITE_CATALOG": SITE_CATALOG,
    "SITE_BROWSER": SITE_BROWSER,
    "SITE_BROW_TEST": SITE_BROW_TEST,
    "STORE_REVIEW_URI": STORE_REVIEW_URI,
}

import webbrowser

def open_url(url: str, default_: bool = False) -> bool:
    try:
        # Registry mode (safe / internal)
        if default_:
            target = URL_REGISTRY.get(url)
            if not target:
                return False
        # Direct URL mode
        else:
            target = url

        return bool(webbrowser.open(target, new=2))
    except Exception:
        return False

def pnwed_url(t: str, item:str):
    """t = type/item |pw|em"""
    if t == "pw":
        return open_url(PWNEDPASSWORD + item)
    elif t == "em":
        return open_url(PWNEDEMAIL + item)

