All Tools are:
# Keyquorum Vault - Development / Smoke Test Tool
# Copyright (C) 2026 Anthony Hatton

# This file is part of Keyquorum Vault.

# Keyquorum Vault is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Keyquorum Vault is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

# ============================================================================================================


!!! These utilities are provided for development and testing purposes only. !!! 

--------------
Tools
--------------
---
This folder contains development and testing utilities for Keyquorum Vault.

These tools are intended for development, validation, and interoperability testing.
They are not part of the production application.
# NOTE:
- These tools are provided for development and interoperability testing.
- They are not bundled with production builds.
- They run locally and do not expose services to external networks.

---

Included Tools
--------------
Authenticator/auth_test_server.py = Local HTTP server that generates TOTP QR codes for testing the Authenticator tab.
Authenticator/auth_test_cli.py = CLI-based TOTP generator for validating algorithm compatibility.

release/build_portable_release.py	= Creates a SHA256 manifest of the build and signs it using Ed25519.
release/KEY0_B64_Generate.ps1		= Generate KEY0_B64 Key.
release/make_portable_blob.py		= Creates an encrypted portable package blob (`core.kqpkg`). for EXE/MSIX builds.
release/release.ps1					= Automate the full release process.
release/check_manifest.py			= It proves that the release integrity system is working and that the build has not been altered after signing.

license/collect_licenses.py			= Harvests LICENSE / NOTICE files from installed.

cli/cli_decrypt_store.py			= Identity / Vault decrypt

smoke

