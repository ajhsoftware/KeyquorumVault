# 📘 Keyquorum CLI Tools (Standalone)

## These tools are read-only by default and are designed to:

   -Diagnose vault unlock issues
   -Validate identity store integrity
   -Verify master salt migration
   -Test native DLL health
   -Confirm v1/v2 vault compatibility
   -Perform controlled vault decrypt tests

## They are intended for:
   -Developers
   -Security auditors
   -Upgrade validation
   -Advanced troubleshooting
   -Forensic verification

>**⚠️ Important:**Vault decrypt requires `keyquorum_core.dll` and runs on Windows.

---

# 🧠 Tool Architecture

The CLI tools are fully standalone and do not import the main app.

## They:
 -Read files directly
 -Never modify identity or vault files
 -Never auto-migrate salt
 -Never write unless explicitly told (--out)

--- 

# 📂 File Overview (What Each Python File Does)

----
## 🟢 kq_tool.py — Main CLI Tool

This is the entry point and primary tool.

### Responsibilities
 -Discover user storage roots (Local / Roaming / Portable)
 -Inspect identity store header
 -Resolve master salt (identity → legacy fallback)
 -Validate vault file presence
 -Attempt real vault decrypt (optional)
 -Generate structured health reports
 -Perform DLL health checks

### Command (exp: user kq_dev2 = the account to check):

#### 1) Discover users
	```bash
	python kq_tool.py discover
	```
#### 2) Inspect a user (no decrypt)
	```bash
	python kq_tool.py inspect-user --user kq_dev2
	```
#### 3) Check identity header
	```bash
	python kq_tool.py check-identity "C:\Users\<username>\AppData\Roaming\Keyquorum\Users\kq_dev2\Main\kq_dev2.kq_id" --inspect```
#### 4) Full health report (JSON)
	```bash
	python kq_tool.py health --user kq_dev2
	```
#### 5) Attempt real vault decrypt (tests unlock)
	```bash
	python kq_tool.py --dll "...\keyquorum_core.dll" health --user kq_dev2 --decrypt-vault
	```
#### 6) Decrypt vault to a JSON file (!!! WARNING VAULT WILL BE IN PLANE TEXT !!!)
	```bash
	python kq_tool.py --dll "...\keyquorum_core.dll" decrypt-vault --user kq_dev2 --out vault_plain.json
	```
#### 7) Full DLL report + self-test
	```bash
	python kq_tool.py --dll "...\keyquorum_core.dll" dll-health
	```
#### 8) Skip self-test (just version/features)
	```bash
	python kq_tool.py --dll "...\keyquorum_core.dll" dll-health --no-self-test
	```
#### 9) Skip self-test (just version/features)
	```bash
	python kq_tool.py --json --dll "...\keyquorum_core.dll" dll-health
	```

----

### Supported Vault Formats

It supports all known Keyquorum vault formats:

JSON envelope:
	{ "iv": "...", "tag": "...", "vault_data": "..." }

Binary layout:
	iv(12) || tag(16) || ciphertext

Binary layout (alt):
	iv(12) || ciphertext || tag(16)

### So it works for:
 -v1 vaults
 -v2 vaults
 -Post-DLL migration vaults

----
## 🟢 check_identity_header.py

### Purpose

Validates the public header of an Identity Store file (*.kq_id).

### What it checks
 -Magic header: KQID1
 -Header length sanity
 -JSON decoding validity
 -Presence of expected schema fields
 -meta.master_salt_b64 integrity
 -Base64 validity
 -Salt length correctness

### It does NOT:
 -Decrypt identity payload
 -Modify the identity file
 -Touch vault data

It is purely a structural validator.

----

## 🟢 check_user_salt_sources.py

### Purpose

Resolves master salt in a read-only way.

### Order of resolution:

1.meta.master_salt_b64 in identity header
2.Legacy .slt file

### It verifies:

 -Base64 decoding
 -Minimum length
 -Source type
 -SHA256 fingerprint of salt

### It does NOT:

 -Perform migration
 -Delete legacy files
 -Modify identity

----

## 🟢 check_vault_unlock_inputs.py

### Wrapper around:

	kq_tool.py health

### It performs a preflight unlock check:

 -Vault file exists
 -Identity exists
 -Salt resolves
 -DLL loads
 -Password works (if decrypt enabled)

### Useful for:

 -Debugging unlock failures
 -Verifying migrations
 -CI validation scripts

----

## 🟢 DLL Health System (inside kq_tool.py)

### Command:
	dll-health

### Checks:

 -DLL file exists
 -DLL loads successfully
 -Returns version number
 -Reports crypto backend
 -Detects available features:
   -session_open_ex
   -derive_vault_key_ex
   -DPAPI exports
 -Runs optional encrypt/decrypt roundtrip self-test

### The self-test:

 -Generates random 32-byte key
 -Opens native session
 -Encrypts test data
 -Decrypts test data
 -Verifies roundtrip match

### This proves:

 -AES-GCM path works
 -Session API works
 -DLL is functional (not just loadable)

 ----

## 🧪 Health Report System

### Command:

	health --user USERNAME

### Outputs structured JSON including:

	{
	  "identity": { ... },
	  "salt": { ... },
	  "vault": { ... },
	  "ready_to_unlock": true/false
	}

### ready_to_unlock is true only if:

 -Identity header valid
 -Salt resolves
 -Vault exists
 -Decrypt (if requested) succeeds

---

# 🔐 Security Model

## These tools are:

 -Read-only by default
 -Do not alter identity or vault files
 -Do not perform automatic migrations
 -Do not expose secrets unless explicitly decrypting

## ⚠️ When using:

	decrypt-vault --out vault_plain.json

The output file is PLAINTEXT.
Treat it as highly sensitive.

---

# 🧩 Root Resolution Logic

## The tool auto-detects:
 
 -%LOCALAPPDATA%\Keyquorum\Users
 -%APPDATA%\Keyquorum\Users
 -Portable installations via portable.marker

## You can override with:

 - --users-root
 - --local-root
 - --roaming-root
 - --portable-root
 
--- 
 

# 🛠 Designed For Upgrades

## These tools were specifically built to support:

 -Salt migration from .slt → identity header
 -DLL-only vault sessions
 -v1 → v2 vault compatibility
 -Native-only unlock enforcement
 -Portable vs installed validation

---

# 📦 Why This Exists

## After major architectural upgrades (DLL migration, identity changes, salt movement), having a standalone validation suite:

 -Reduces upgrade risk
 -Makes debugging deterministic
 -Avoids modifying production app code
 -Allows forensic inspection
 -Enables CI testing


---

# 🧭 Recommended Usage Flow

## For debugging:

 1.discover
 2.inspect-user
 3.check-identity
 4.dll-health
 5.health --decrypt-vault
 6.This gives full system verification.

---
# 🧱 Version Compatibility

## Compatible with:

 -Legacy salt-based vaults
 -Identity-header salt vaults
 -v1 vault encryption
 -v2 DLL encryption
 -Strict DLL-only unlock

--- 

# Root overrides (portable / custom location)

## If you want the tools to locate everything from a custom directory:

- `--users-root` can point to `...\Users` OR a folder that contains `Users`
- `--local-root` should be `...\AppData\Local\Keyquorum`
- `--roaming-root` should be `...\AppData\Roaming\Keyquorum`
- `--portable-root` should be the folder that contains `portable.marker`
 
## Example:
```bash
python kq_tool.py health --user ant --portable-root "E:\KeyquorumPortable" --decrypt-vault --dll ".\keyquorum_core.dll"
```

---

# Legacy wrappers
- `check_identity_header.py` – identity header inspector/validator
- `check_user_salt_sources.py` – master salt resolver (read-only)
- `check_vault_unlock_inputs.py` – wrapper that calls `kq_tool.py health`
