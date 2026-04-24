# Keyquorum Vault

Offline-first password manager by AJH Software  
*(Solo developer project focused on learning and security)*

---

## 🔒 Security Notice ⚠️

**Status:** Experimental and under active development

This project has **not undergone an independent security audit**.  
While security is a core focus, bugs or weaknesses may exist.

Use at your own risk, and always maintain secure backups of your data.  
**ABSOLUTELY NO WARRANTY** is provided, to the fullest extent permitted by applicable law.
Backup functionality is available in the UI under **Settings → Backup**.

> ⚠️ This project should not be relied upon for critical data without independent review.

---

The codebase is actively evolving, including ongoing refactoring and modularisation.  
Folder structure and internal modules may change as the project stabilises.

---

## Overview

Keyquorum Vault is a **privacy-first, offline password manager** designed with a strict local-only security model.

- No required accounts  
- No forced cloud sync  
- No telemetry or hidden network activity  
- Full local encryption and control  

All sensitive data is handled locally using authenticated encryption (**AES-GCM**) and a strong KDF (**Argon2id**).

---

## 📸 Screenshots

>  Screenshots are from 2025-09-28 and may be slightly outdated.  
>  UI is currently being updated as part of a Qt6 migration.

---

###  Main Interface
![Main UI](screenshots/main_ui.png)

---

###  Vault View
![Vault](screenshots/vault_view.png)

---

###  Categories
![Categories](screenshots/category.png)

---

###  Add / Edit Entries
![Add / Edit](screenshots/add_edit.png)

---

###  Password Generator
![Password Generator](screenshots/passwordgen.png)

---

##  Recent Updates (April 2026)

###  Security Core
- DLL-based crypto currently in use  
- Planned removal in the next update in favour of a simpler, more maintainable Python-based approach  
- Preflight and antivirus-related checks will also be removed to reduce false positives and improve clarity for users and reviewers  
- A more reliable and transparent security validation approach may be introduced later  

 See `SECURITY.md` and `threat_model.md `  for threat model and security considerations  

---

###  Encryption & Rekeying
- Safer migration when:
  - Changing password  
  - Updating vault security  
  - Enabling/disabling YubiKey WRAP  
- Covers:
  - Vault data  
  - Password history  
  - Trash store  
  - Authenticator store  

---

###  YubiKey Support
- Improved WRAP enable/disable flows  
- More reliable rekey handling  

---

##  What this repository contains

- Desktop application (Qt / PySide6 via `qtpy`)  

>  Ongoing refactor: migrating to Qt6 while simplifying the codebase.  
> qtpy abstraction will be reintroduced once the UI stabilises.

- Vault encryption & storage logic  
- Feature modules:
  - Watchtower  
  - Reminders  
  - Security Center  
  - Sync system  
- Background workers  

---

## Dependencies

Core:
- `PySide6` – Qt6 GUI framework  
- `qtpy` – abstraction layer (planned reintroduction)  
- `cryptography` – encryption primitives  
- `argon2-cffi` – password hashing (KDF)  
- `pyotp` – TOTP / 2FA support  
- `qrcode` – QR code generation  
- `reportlab` – PDF/export features  

Optional:
- `opencv-python` – QR scanning / camera  
- `pywinauto` – Windows automation  

---

##  Repository layout (Updating)
app/ # App bootstrap & UI
auth/ # Login, 2FA, YubiKey, device unlock
features/ # Watchtower, reminders, etc.
security/ # Audit, baseline, integrity
vault_store/ # Encryption, storage, import/export
workers/ # Background workers

---

##  Security Model

Keyquorum is **offline-first**:

- No automatic cloud sync — users must explicitly enable it and choose their own storage (e.g. NAS or cloud folder)  
- No remote servers  
- No telemetry  
- No hidden background connections  

Network activity only occurs when:
- The user explicitly performs an action  
- The browser extension communicates locally (`127.0.0.1`)  
All encryption is performed locally.

---

##  Security Direction

All future changes will:

- Be open-source and fully reviewable  
- Avoid hidden network activity — no outbound connections unless explicitly triggered by the user  
- Maintain backward compatibility (especially vault data and backups)  
- Prioritise user control and transparency  
- Keep users informed through clear and visible notifications  

---

##  Site
👉 https://ajhsoftware.uk

---

##  Browser Extension

👉 https://github.com/ajhsoftware/Keyquorum-Browser-Extension

Provides secure autofill via local bridge:
- No cloud communication  
- No credential storage in extension  
- Lock-aware behaviour  

---

##  License

Licensed under:

**GNU General Public License v3.0 or later (GPL-3.0-or-later)**

See `LICENSE`.

Third-party notices:  
`THIRD_PARTY_NOTICES.md`

---

##  Contributing

See `CONTRIBUTING.md`.

---

##  Security Reporting

Please report vulnerabilities privately.

See `SECURITY.md`.

---

##  AI-assisted development

This project is built on 2+ years of hands-on learning and research prior to using AI.

Over the last year, AI has become a regular part of my workflow. I use it as a tool to support development, not replace understanding.

AI has been used for:
- Brainstorming and design ideas  
- Debugging and troubleshooting  
- Improving spelling and grammar  
- Exploring alternative approaches and trade-offs  
- Refactoring and improving code structure  
- Enhancing wording, clarity, and documentation  
- Assisting with code review and identifying potential issues  

I use multiple AI tools (e.g. ChatGPT, Claude, Gemini) to compare outputs and avoid relying on a single source. This allows me to evaluate different approaches and choose what I believe is the best solution.

I do not blindly copy and paste code. If I don’t understand something, I research it and validate it before use.

AI is not always correct. Reviewing, testing, and manually fixing code is essential.  
All code is reviewed, tested, and integrated manually.

Contributions that use AI are welcome, but contributors should clearly explain what the code does and ensure it has been properly reviewed before submission.

AI/ML is a powerful tool, but if not used carefully, it can introduce issues due to inaccuracies.

---

##  Author

Developed by **AJH Software**  
Solo developer project focused on privacy, security, and local-first design.
