



def maybe_show_quick_tour(self, which: str = "core"):
    """"core": core_steps,
        "authenticator": authenticator_steps,
        "audit": audit_steps,
        "profile": profile_steps,
        "settings": settings_steps,
        "portable": portable_steps,
        "backup": backup_steps,
        "category": category_steps,
        "watchtower": watchtower_steps,"""

    core_steps = [
            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "vaultTable",
             "title": "Items table", "text": "Everything you add appears here. Select a row to view or act on it.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "categorySelector_2",
             "title": "Category", "text": "Switch categories. The table updates to show items in the selected category.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "widget_2",
             "title": "Add / Edit / Delete", "text": "Add new items, edit the selected one, or remove it. Tip: choose the category first.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "vaultSearchBox",
             "title": "Search", "text": "Find items instantly in the current category. Filters are supported.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "password_generator",
             "title": "Password generator", "text": "Create strong passwords with customizable length and characters.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "bowser_btn",
             "title": "Browser extension", "text": "Install and pair the Token to enable on-site autofill and saving. Remove the Token to disconnect. A fresh token is created each login.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "breach_check_",
             "title": "Breach check", "text": "Email: open Have I Been Pwned for the selected address. Password: check a password against known breach data (we don’t store what you type).", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "share_",
             "title": "Share", "text": "Securely share with other Keyquorum users. Enter their Share ID to send an encrypted packet only they can open. Use ‘Import packet’ to add one you’ve received.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "softdelete_",
             "title": "Soft delete", "text": "A safety net for deletions: items stay here for 30 days for easy restore, then are removed permanently.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "move_category_",
             "title": "Move to category", "text": "Move the selected item to a different category. Unmapped fields are preserved in Notes.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "qrshow_",
             "title": "Create QR", "text": "Make a QR for the selected item. Most categories encode only the website URL; Wi-Fi encodes full credentials so scanning can join the network.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Vault"}, "target": "logoutButton",
             "title": "Log out", "text": "Securely sign out. Clears sensitive data and resets the session. Works here, on app close, or after idle timeout.", "padding": 10},
        ]

    authenticator_steps = [
            {"tab": {"widget": "mainTabs", "title": "Authenticator"}, "target": "widget_27",
             "title": "Authenticator", "text": "Add, edit, and delete authenticator entries. Add manually or quickly via camera/image. Important: don’t add your vault’s own 2FA here to avoid lockouts.", "padding": 10},

            {"tab": {"widget": "mainTabs", "title": "Authenticator"}, "target": "authTable",
             "title": "Codes table", "text": "Your authenticators are listed here. Codes refresh every ~30 seconds by default.", "padding": 10},
        ]

    audit_steps = [
            {"tab": {"widget": "mainTabs", "title": "Audit Logs"}, "target": "auditTable",
             "title": "Audit logs", "text": "Review recent account activity, including failed login attempts.", "padding": 10, "dim": 110},
        ]

    profile_steps = [
            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "Profile",
             "title": "Profile", "text": "Update your account profile and preferences.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "twoFACheckbox",
             "title": "Two-Factor Authentication", "text": "Enable or disable 2FA for login. This secures account sign-in (vault protection is configured separately).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "btnDeviceUnlock",
             "title": "YubiKey", "text": "Enable a genuine, modern YubiKey for stronger login and vault protection.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Profile"}, "target": "regenerateBackupCodesButton",
             "title": "Regenerate backup codes", "text": "Create new account backup codes if you’ve lost the old ones. Not available in ‘no-recovery’ mode.", "padding": 10, "dim": 110},
        ]

    settings_steps = [
            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "enablePreflightCheckbox_",
             "title": "Preflight checks", "text": "Scan running processes at startup and warn about risky ones (defaults or your allow/block list).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "vault_safety_btn",
             "title": "Preflight lists", "text": "Manage your allow/deny lists for process scanning.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "runPreflightNowButton",
             "title": "Run preflight now", "text": "Run the process check on demand. If Windows Defender is available, you can kick off a quick scan.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "enableWinDefCheckbox_",
             "title": "Antivirus check", "text": "On startup/login, check whether antivirus is present and alert on issues.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "DefenderQuickScan_",
             "title": "Quick scan prompt", "text": "Offer a Windows Defender quick scan at app start.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "vault_safety_btn_2",
             "title": "Integrity baseline", "text": "Update file-integrity baseline for key files.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "clipboard_clear_timeout_",
             "title": "Clipboard safety", "text": "Auto-clear copied secrets after a delay.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "auto_logout_timeout_",
             "title": "Auto-logout", "text": "Automatically log out after inactivity.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "lockoutSpinBox",
             "title": "Lockout", "text": "Lock the account after too many failed login or 2FA attempts.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "password_expiry_days",
             "title": "Password expiry", "text": "Set how long passwords can live before reminders nudge you to rotate them.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "enable_breach_checker_",
             "title": "Breach checker", "text": "Check (hashed) passwords against known breach databases when saving items.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "Settings"}, "target": "ontop_",
             "title": "Always on top", "text": "Keep the app window above others.", "padding": 10, "dim": 110},

        ]

    backup_steps = [
            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "BackUp/Restore",
             "title": "Backups", "text": "Regular backups are essential. Create and store them safely.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_28",
             "title": "Cloud sync", "text": "keep a copy of your data in a cloud folder you control.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "select_cloud",
             "title": "Choose cloud folder", "text": "Pick a signed-in, accessible folder for backups.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "extra_cloud_wrap",
             "title": "Cloud safety", "text": "Add extra protection for data stored in the cloud copy.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "autosync_",
             "title": "Auto-sync", "text": "Automatically sync to cloud when data changes.", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_16",
             "title": "Full backup / restore", "text": "Create a full backup of vault + account, or import one (also available on the login screen).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_29",
             "title": "Vault-only backup", "text": "Back up just the vault (restorable to the same account).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_30",
             "title": "CSV import / export", "text": "Import from other managers’ CSV, or export your vault to CSV (optionally password-protected).", "padding": 10, "dim": 110},

            {"tab": {"widget": "mainTabs", "title": "BackUp/Restore"}, "target": "label_31",
             "title": "Software folder backup", "text": "back up the software folder separately if it’s large.", "padding": 10, "dim": 110},
        ]

    category_steps = [
            {"tab": {"widget": "mainTabs", "title": "Edit/Add Category"}, "target": "Edit/Add Category",
             "title": "Customize categories", "text": "Create and edit categories to fit your workflow.", "padding": 10, "dim": 110},
        ]

    watchtower_steps = [
            {"tab": {"widget": "mainTabs", "title": "Watchtower"}, "target": "Watchtower",
             "title": "Watchtower", "text": "Spot weak, reused, or unsafe items at a glance and fix them quickly.", "padding": 10, "dim": 110},
        ]
    
    # ---- choose steps by key
    steps_by_type = {
        "core": core_steps,
        "authenticator": authenticator_steps,
        "audit": audit_steps,
        "profile": profile_steps,
        "settings": settings_steps,
        "backup": backup_steps,
        "category": category_steps,
        "watchtower": watchtower_steps,
    }
    steps = steps_by_type.get(which)
    if not steps:
        return

    # ---- finish any running tour
    try:
        if getattr(self, "_tour", None):
            self._tour.finish()
    except Exception:
        pass

    # ---- start new tour; keep a ref so it doesn't get GC’d
    default_dim = 120 if which in ("core",) else 110
    from new_users.tour import GuidedTour
    tour = GuidedTour(self, steps, default_dim=default_dim)
    tour.start()
