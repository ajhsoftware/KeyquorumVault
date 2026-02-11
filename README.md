# Keyquorum Vault

Offline-first password manager by **AJH Software**.

> **Note:** the project is **currently being split/refactored** (modules are being moved into clearer folders). Expect a little churn in structure while this stabilises.

## What this repository contains
- Desktop app source (Qt/PySide6 via `qtpy`).
- Encryption and vault storage modules.
- Features (watchtower, reminders, portable/USB mode, security center, etc.).

## Running from source (developer)
This project is packaged for Windows releases using **fbs Pro** in the release workflow, but you can run from source in a normal Python venv.

1. Create and activate a virtual environment.
2. Install dependencies.
3. Run the app.

Because this repo is in active refactor, a pinned dependency file may be added/updated; if you don’t see one yet, install the core dependencies below.

### Suggested core dependencies
- `PySide6` (Qt bindings)
- `qtpy` (Qt abstraction layer)
- `cryptography`
- `argon2-cffi` (Argon2id KDF)
- `pyotp` (TOTP)
- `qrcode`
- `reportlab` (Emergency kit / PDFs)
- Optional: `opencv-python` (`cv2`) for camera/QR features
- Optional: `pywinauto` for certain Windows automation/UX flows

> If you prefer: add these to a `requirements.txt` for your environment, or use `pip install -e .` once a `pyproject.toml` is added.

## Repository layout (current)
- `python/` – main source tree (being reorganised)
  - `app/` – app window, app bootstrap, resources
  - `auth/` – login / logout / 2FA / YubiKey / Windows Hello flows
  - `features/` – feature modules
  - `security/` – baseline/integrity/audit tooling
  - `vault_store/` – vault encryption, storage, import/export
  - `workers/` – background workers

## Contributing
See `CONTRIBUTING.md`.

## Security
Please report security issues privately (see `SECURITY.md`).

## License
Keyquorum Vault is licensed under the **GNU General Public License v3.0 or later** (**GPL-3.0-or-later**).

See `LICENSE`.

Third‑party licensing notes are in `THIRD_PARTY_NOTICES.md`.
