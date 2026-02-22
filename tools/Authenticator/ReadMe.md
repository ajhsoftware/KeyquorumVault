
!!! These utilities are provided for development and testing purposes only. !!! 

--------------
## auth_test_server.py
--------------
	Local HTTP server that generates TOTP QR codes for testing the Authenticator tab.

# Usage:

	python auth_test_server.py

- Then open the local URL shown in the console (default:
http://127.0.0.1:8778/) to display a test QR code.
---

# Default binding:

	127.0.0.1:8778 (localhost only)
---

# Requirements:
	- pyotp
	- qrcode[pil]
---

--------------
## auth_test_cli.py
--------------
	CLI-based TOTP generator for validating algorithm compatibility.

Displays:

	- Base32 secret
	- otpauth URI
	- Live TOTP codes

# Usage:

	python auth_test_cli.py
---
# Optional arguments allow testing:

	Different algorithms (SHA1, SHA256, SHA512)
	- Custom period
	- Custom digits
	- Custom issuer/account
---
# Requirements:
	-pyotp
---
