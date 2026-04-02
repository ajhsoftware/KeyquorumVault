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

SITE_MAIN           = "https://www.ajhsoftware.uk"
SITE_HELP           = "https://ajhsoftware.uk/keyquorum.html#support"
SITE_SUPPORT        = "https://forms.gle/VWJjbj8SCXiR2RVp7"
SITE_SUPPORT_ME     = "https://ajhsoftware.uk/supportme.html"
PRIVACY_POLICY      = "https://ajhsoftware.uk/keyquorum.html#security-privacy-overview"
SITE_ANDROID        = ""
SITE_LINUX          = ""
SITE_UPDATE         = "https://github.com/ajhsoftware/KeyquorumVault/releases"
SITE_VIDEO          = "https://ajhsoftware.uk/keyquorum.html#video-help"
SITE_SEC            = "https://ajhsoftware.uk/keyquorum.html#security-practices-tips"
SITE_THREAT         = ""
SITE_BUG_FIX        = "https://ajhsoftware.uk/index.html"
SITE_CATALOG        = "https://www.ajhsoftware.uk/keyquorum/catalog-help"
SITE_BROWSER        = "https://ajhsoftware.uk/keyquorum.html#browser-extension-help"
SITE_BROW_TEST      = "https://ajhsoftware.github.io/kq-test-pages/"
REDDIT              = "https://www.reddit.com/r/AJHsoftware/"
STORE_URL_CHROME    = "https://chromewebstore.google.com/detail/keyquorum-autofill-local/jcblpckopkkhokdjdojlblknikfahbgb"
STORE_URL_EDGE      = ""  # optional: https://microsoftedge.microsoft.com/addons/detail/<ID> 
WATCH               = ""
PWNEDPASSWORD       = "https://api.pwnedpasswords.com/range/"
PWNEDEMAIL          = "https://haveibeenpwned.com/account/"
CATEGORY_DOWN       = "https://ajhsoftware.uk/keyquorum.html#category"
SITE_GITHUB         = "https://github.com/ajhsoftware/KeyquorumVault/"


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

