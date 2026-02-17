# Vault Schema (Decrypted Structure)

Status: Living document  
Scope: Structure of decrypted vault JSON  
Design: Label-driven, per-user category schema

This document describes the structure of the decrypted vault payload
(after AES-GCM decryption).

For the encrypted envelope format (iv/tag/ciphertext), see `vault-format.md`.

---

## 1. Top-Level Structure (Current)

The decrypted vault currently resolves to:

List[Dict]

That is:

- A JSON array
- Each item is an entry object (dictionary)
- There is currently no enforced top-level `format_version`

The loader is tolerant and may coerce legacy shapes into a list.

---

## 2. Core Design Principle

Vault entries are label-driven.

Field keys inside entries are derived from the per-user category schema.

This means:

- Field names are not fixed constants.
- Users can rename field labels.
- The stored JSON keys match the current label.
- Different users may have different key names.
- The vault does not store canonical internal field identifiers.
- It stores what the category schema defines.

---

## 3. Entry Structure

Each entry is a JSON object.

Minimum expected structure:

{
  "category": "Passwords"
}

Beyond `category`, all other fields depend on the category schema.

---

## 4. Reserved / Application-Level Keys

These keys are managed by the application and are not user-defined fields.

Common reserved keys:

- category (string) — category name
- created_at (string) — creation timestamp
- updated_at (string) — last modified timestamp
- Date (string) — YYYY-MM-DD (used for expiry logic)
- pw_changed_at (string) — password change timestamp
- password_history (list) — previous password hashes

Example password history entry:

{
  "hash": "sha256-hash",
  "ts": "2026-02-11"
}

Clients should preserve unknown metadata keys.

---

## 5. Category-Driven Fields

Each category defines its own fields.

Default categories are defined in category_fields.py and include examples such as:

- Passwords
- Credit Cards
- Software
- SSH Keys
- API Keys
- Crypto
- etc.

Each category contains a structure like:

{
  "name": "Passwords",
  "fields": [
    {
      "label": "Website",
      "sensitive": false,
      "url": true,
      "file_load": false,
      "required": true
    }
  ]
}

The "label" value becomes the JSON key stored in the vault entry.

Example entry:

{
  "category": "Passwords",
  "Website": "https://example.com",
  "Email": "user@example.com",
  "Password": "secret"
}

If the user renames "Website" to "Login URL",
future entries will use:

"Login URL": "https://example.com"

---

## 6. Field Flags (Schema Only)

Field configuration flags are stored in the category schema,
NOT inside each vault entry.

Flags include:

- sensitive (mask in UI)
- url (treated as link)
- file_load (file path selector)
- required (validation)

These affect UI behavior but do not alter vault JSON structure.

---

## 7. Value Types

Vault values are user-entered and may include:

- strings
- booleans (or string representations like "False")
- lists (e.g., password_history)
- empty strings

Because the system is user-edit friendly:

- Type enforcement is loose
- Missing fields are allowed
- Unknown fields must not break loading

Clients should:

- Treat missing keys as empty
- Handle booleans safely
- Avoid assuming strict typing

---

## 8. Case Sensitivity

JSON keys are case-sensitive.

Due to imports or legacy behavior, some entries may contain
keys with alternate casing.

Example:
- "Password"
- "password"

Consumers should prefer exact label matching,
but may optionally implement case-insensitive fallback.

---

## 9. Example: Password Entry (Observed)

{
  "created_at": "2026-02-11T23:57:14.907797",
  "updated_at": "2026-02-11T23:57:14.950180",
  "Date": "2026-02-11",
  "category": "Passwords",

  "Website": "https://example.com",
  "Email": "user944@example.com",
  "UserName": "testuser7",
  "Password": "password",

  "Phone Number": "Test Phone Number",
  "Backup Code": "Test Backup Code",
  "2FA Enabled": "False",
  "Notes": "This is a test entry."
}

---

## 10. Example: Credit Card Entry

{
  "category": "Credit Cards",
  "Cardholder Name": "test",
  "Card Number": "1111222233344445555",
  "Expiry Date": "11/25",
  "CVV": "433",
  "Billing Address": "",
  "created_at": "2026-02-11T23:28:55.223446",
  "updated_at": "2026-02-11T23:28:55.247956"
}

---

## 11. Forward Compatibility Guidelines

Because schema is dynamic:

- Unknown keys must be ignored.
- Unknown keys should be preserved when rewriting entries.
- Clients must not assume fixed field names.
- Category schema should always be consulted when rendering UI.

---

## 12. Future Evolution (Planned)

Future improvements may introduce:

A versioned top-level container:

{
  "format_version": 1,
  "entries": [...]
}

And may later normalize:

- consistent key naming
- strict boolean types
- consistent timestamps
- formal migration logic

These changes will be introduced gradually and remain backward-compatible.
