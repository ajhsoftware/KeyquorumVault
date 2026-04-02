from qtpy.QtCore import Qt
from app.dev import dev_ops
is_dev = dev_ops.dev_set

from typing import Set

# --- URL Bridge Values  ---
# Default allowed origins (e.g., browser extensions)
_DEFAULT_ORIGINS: Set[str] = {
    # Store ID
    "chrome-extension://jcblpckopkkhokdjdojlblknikfahbgb",
    # Dev ID (example)
    "chrome-extension://lciebglepcghjjlaldlejfiehibemgef",
}


TOKEN_HEADER = "X-KQ-Token"
DEFAULT_PORT = 8742
DEFAULT_IP = "127.0.0.1"

appref = None  
LOCAL_TEST_HOSTS = {DEFAULT_IP, "localhost"}

COLUMN_URL      = 0     # - "Website" Match Table
COLUMN_USERNAME = 1     # - "Email" Match Table
COLUMN_PASSWORD = None  # - None if no visible password column

# --- Bridge/table roles (module-level) ---
ENTRY_ID_ROLE = int(Qt.ItemDataRole.UserRole) + 101
HAS_TOTP_ROLE = int(Qt.ItemDataRole.UserRole) + 102
SECRET_ROLE   = int(Qt.ItemDataRole.UserRole)          # real secret for sensitive cells
URL_ROLE      = int(Qt.ItemDataRole.UserRole) + 104    # optional canonical URL (if you ever set it)

# --- Local Server Set
appref = None
server_version = "KQBridge/1.0"
protocol_version = "HTTP/1.0"   # simpler; no keep-alive

# --- Allow Only
_ALLOW_METHODS = "GET, POST, OPTIONS"
_ALLOW_HEADERS = "Content-Type, Authorization, X-Auth-Token, X-KQ-Token"

# --- http/https (NOTE: make option in setting to allow/block http sites)
if is_dev:
    ALLOW_LOCAL_HTTP  = True  # True in dev HTTP Mode 
else:
    ALLOW_LOCAL_HTTP = False

# ---- Header label synonyms (lowercased) ----
URL_LABELS   = {"website", "url", "site", "login url", "web site", "web", "domain"}
USER_LABELS  = {"email", "e-mail", "username", "user", "login", "account", "email address", "user name"}
PASS_LABELS  = {"password", "pass", "passcode", "pwd", "secret", "pin", "key"}
TOTP_LABELS  = {"2fa", "totp", "otp", "two-factor"}
TITLE_LABELS = {"title", "name", "label"}

BULLETS = set("•●▪▮∙∗*◦ ")

WEBFILL_COL = {
    "HONORIFIC": "Name Title",
    "FORENAME": "First name",
    "MIDDLENAME": "Middle name",
    "SURNAME": "Surname",
    "EMAIL": "Email",
    "PHONE": "Phone number",
    "ADDR1": "address line 1",
    "ADDR2": "address line 2",
    "CITY": "City / Town",
    "REGION": "State / Province / Region",
    "POSTAL": "Postal code / ZIP",
    "COUNTRY": "Country",
}

# Small, embedded public-suffix hints for common 2-level ccTLDs.
# This is NOT a full PSL; it's just enough to avoid the most common mismatches.
_TWO_LEVEL_SUFFIXES = {
    "co.uk","org.uk","gov.uk","ac.uk","sch.uk",
    "com.au","net.au","org.au","edu.au","gov.au",
    "co.nz","org.nz","govt.nz","ac.nz",
    "co.jp","ne.jp","or.jp",
    "com.br","com.mx","com.tr","com.sg","com.my",
    "co.za","org.za",
}
