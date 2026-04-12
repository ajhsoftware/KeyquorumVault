# Keyquorum Vault

Offline-first password manager by **AJH Software**.

⚠️ **Important:** This project is currently experimental and under active development.  
   It has not been security audited and is **not recommended for storing real or sensitive passwords** at this stage.

  The codebase is also being actively refactored and modularised, so folder structure and internal modules may change while this stabilises.

---
## AI-assisted development

This project is built on ~2+ years of hands-on learning and research prior to using AI.

Over the last year, AI has become a regular part of my workflow. I use it as a tool to support development, not replace understanding.

AI has been used for:
- brainstorming and design ideas  
- debugging and troubleshooting  
- exploring alternative approaches and trade-offs  
- refactoring and improving code structure  
- improving wording, spelling, and documentation  

I use multiple AI tools (e.g. ChatGPT, Claude, Gemini) to compare outputs and avoid relying on a single source.

I do not blindly copy and paste code. If I don’t understand something, I research it and validate why a solution is better than my original or other approaches.

AI is not always correct. Reviewing, testing, and manually fixing code is essential.

All code is reviewed, tested, and integrated manually.

Contributions that use AI are welcome, but contributors should clearly explain what the code does and ensure it has been properly reviewed before submission.

⚠️ This project is experimental and not security audited.  
Do not rely on it for critical or production use without independent review.

---

## 🔐 Overview

Keyquorum Vault is a **privacy-first, offline password manager** designed with a strict local-only security model.

- No required accounts
- No forced cloud sync
- No telemetry or hidden network activity
- Full local encryption and control

All sensitive data is handled locally using authenticated encryption (**AES-GCM**) and a strong KDF (**Argon2id**).

---

## 🚀 Recent Updates (April 2026)

### 🔒 Security Core
- Native **C++ DLL is now required** for all sensitive operations  
- Improved memory handling and key isolation  
- Removal of Python fallback for cryptographic operations  

### 🔁 Encryption & Rekeying
- Safer migration when:
  - Changing password
  - Updating vault security
  - Enabling/disabling YubiKey WRAP  
- Covers:
  - Vault data
  - Password history
  - Trash store
  - Authenticator store

### 🔐 Vault Security
- Improved Argon2id handling (KDF v2 support)
- Better compatibility with future security upgrades

### 🔑 YubiKey Support
- More reliable WRAP enable/disable flows  
- Improved rekey safety and session handling  

---

### ⚡ Performance

#### Watchtower
- Major performance improvements (large vaults)
- Fixed breach detection issues
- Added smarter caching to reduce repeated checks
- Reduced false positives (e.g. non-URL categories)

#### CSV Import
- Handles **10K+ entries smoothly**
- Improved import speed and UI responsiveness

---

### 🔔 Notifications & Background Tasks
- Windows notifications for:
  - Watchtower changes
  - Reminders
- New background worker:
  - Only alerts on changes (no spam)

---

### 🔄 Sync Improvements
- More reliable sync across:
  - NAS
  - Local folders
  - Cloud-backed folders (user-selected)
- Improved:
  - Sync state visibility
  - Restore on new devices
- Better handling of:
  - Vault
  - Metadata
  - Side stores (trash, history, etc.)

---

### 🌉 Browser Extension Bridge
- Secure **signed local authentication**
- Improved reliability of autofill communication
- Strict localhost-only communication (`127.0.0.1`)

---

### 🧠 Storage Changes
- Salt is now stored in the **identity file**
- Removed separate salt file for:
  - Easier sync
  - Simpler maintenance

---

### 📜 Logging
- Improved per-user logging
- Logs now initialise correctly after login

---

### 🧹 Codebase
- Ongoing refactor:
  - Breaking large files into modules
  - Improving maintainability
- Some areas may still be unstable — feedback welcome

---

## 🧩 What this repository contains

- Desktop application (Qt / PySide6 via `qtpy`)
- Vault encryption & storage logic
- Feature modules:
  - Watchtower
  - Reminders
  - Security Center
  - Sync system
- Background workers

---

## 🛠 Running from source (developer)

This project is packaged using **fbs Pro** for Windows builds, but can be run locally.

### Steps:
1. Create a virtual environment
2. Install dependencies
3. Run the app

---

### 📦 Suggested dependencies

- `PySide6`
- `qtpy`
- `cryptography`
- `argon2-cffi`
- `pyotp`
- `qrcode`
- `reportlab`

Optional:
- `opencv-python` (QR/camera features)
- `pywinauto` (Windows automation)

---

## 📁 Repository layout
python/
app/ # App bootstrap & UI
auth/ # Login, 2FA, YubiKey, device unlock
features/ # Watchtower, reminders, etc.
security/ # Audit, baseline, integrity
vault_store/ # Encryption, storage, import/export
workers/ # Background workers


---

## 🔐 Security Model

Keyquorum is designed as **offline-first**:

- No automatic cloud sync
- No remote servers
- No telemetry
- No hidden background connections

Network activity only occurs when:
- User explicitly opens a link
- Browser extension communicates locally

All encryption is performed locally.

---

## 🧱 Future Architecture

Keyquorum is moving toward a **native security core**:

- Shared C++ "VaultCore"
- Stronger memory isolation
- Cross-platform support (future Android)
- Stable vault format

The current desktop app remains the primary client.

---

## 🔐 Security Direction

All future changes will:

- Be open-source and reviewable
- Avoid hidden network features
- Maintain backward compatibility where possible
- Prioritise user control and transparency

---
## 🌐 site
https://ajhsoftware.uk
---

## 🌐 Browser Extension

👉 https://github.com/ajhsoftware/Keyquorum-Browser-Extension

Provides secure autofill via local bridge:
- No cloud communication
- No credential storage in extension
- Lock-aware behaviour

---

## ⚖️ License

Licensed under:

**GNU General Public License v3.0 or later (GPL-3.0-or-later)**

See `LICENSE`.

Third-party notices:
`THIRD_PARTY_NOTICES.md`

---

## 💬 Contributing

See `CONTRIBUTING.md`.

---

## 🚨 Security Reporting

Please report vulnerabilities privately.

See `SECURITY.md`.

---

## 🧠 Author

Developed by **AJH Software** 
Solo developer project focused on privacy, security, and local-first design.
