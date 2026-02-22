# Keyquorum Vault – Smoke / Automated Tests (V5)  (22-02-2026)

This folder contains a **safe-by-default smoke test runner** for Keyquorum Vault.  
It is designed to quickly catch broken imports, wiring issues, and core crypto/auth regressions **without opening any UI**.

> ✅ Default behaviour is CI-friendly: no hangs, no hardware prompts, no interactive UI flows.

---

## What it does

`kv_auto_tests_V5.py` runs a one-shot suite that:

- Imports core packages to catch missing/broken dependencies
- Sweeps and imports modules under:
  - `auth/`, `vault_store/`, `security/`, `features/`, `workers/`
- Creates a **dummy test account** in an isolated workspace
- Verifies expected files are created (vault, salt, per-user DB, identity store)
- Stores + consumes **login backup codes** (one-time-use behaviour)
- Tests correct login vs wrong password
- Tests lockout + reset logic
- Sets/gets TOTP secret via identity store
- Vault encrypt/decrypt round-trip sanity + basic “vault health” checks
- Share packet round-trip (self) (if feature is present)
- Creates a backup zip + verifies internal manifest hashes
- Baseline signer write/verify
- Optional encrypted audit write/read (skips if not available)
- Security Center worker smoke-run (no threads)
- Dummy YubiKey gate/wrap backend test (no real YubiKey required)
- Optional portable tests (opt-in)
- Cleans up the dummy user data when finished

Full details are logged into a Markdown report (see below). :contentReference[oaicite:1]{index=1}

---

## Where it writes data (safe / isolated)

The runner **forces** an isolated test workspace by overriding:

- `LOCALAPPDATA`
- `APPDATA`

By default it uses:

`%TEMP%\Keyquorum_Test_Workspace\`

So it **should not touch your real Keyquorum data**. :contentReference[oaicite:2]{index=2}

---

## How to Run

Before running the smoke tests, copy the following files into your project root:

	src\main\python\

Required files:

	- kv_auto_tests_V5.py
	- run.bat (optional but recommended on Windows)

The test runner must be placed inside src\main\python\ so it can correctly resolve package imports.

### Option A — Run via Batch File (Windows Recommended)

From inside:

	src\main\python\

Double-click:
	run.bat

Or run from Command Prompt:
	run.bat

This ensures the correct working directory is used.

### Option B — Run Directly with Python

Open Command Prompt, navigate to:

	cd path\to\your\project\src\main\python

Then run:
	python kv_auto_tests_V5.py

---------------
Important Notes
---------------

- You must run it from inside src\main\python\

- It should not be run from the repository root unless PYTHONPATH is configured correctly

-The script automatically creates an isolated test workspace in:
	
	%TEMP%\Keyquorum_Test_Workspace\

A full Markdown report will be generated after completion
