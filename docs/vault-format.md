# Vault File Format (Encrypted Layer)

Status: Living document  
Scope: On-disk encrypted vault representation  
Audience: Contributors implementing compatible clients (Desktop, Native Core, Android)

This document describes how the vault is stored on disk in encrypted form.

It does NOT describe the decrypted entry structure.
See `vault-schema.md` for plaintext structure.

---

## 1. Design Goals

- Offline-first storage
- Strong authenticated encryption
- Clear separation between:
  - KDF salt
  - Encrypted payload
  - Optional wrapped key material
- Future compatibility with:
  - Native VaultCore (C++ target)
  - Android client

---

## 2. File Components Per User

Each user profile typically has:

- Salt file (raw bytes)
- Vault file (JSON encrypted envelope)
- Optional wrapped vault key file (recovery mode)
- User metadata files (stored separately)

This document focuses only on the encrypted vault file and wrapped key format.

---

## 3. Cryptography Overview

### Key Derivation (Password → Encryption Key)

Algorithm: Argon2id  
Output length: 32 bytes (AES-256 key)

Typical desktop parameters:

- time_cost: 3
- memory_cost: 256000 KiB (~256 MB)
- parallelism: 2
- hash_len: 32

Salt is stored separately as raw bytes.

Derived key is used directly as the AES-256 encryption key.

---

### Vault Encryption

Algorithm: AES-256-GCM (AEAD)  
Nonce (IV): 12 bytes  
Tag: 16 bytes  
Plaintext encoding: UTF-8 JSON

AES-GCM provides:

- Confidentiality
- Integrity
- Authentication

---

## 4. Encrypted Vault File Structure

The vault file stored on disk is JSON containing base64-encoded fields.

Example structure:

{
  "iv": "base64...",
  "tag": "base64...",
  "vault_data": "base64..."
}

Field definitions:

- iv — 12-byte random nonce (base64 encoded)
- tag — 16-byte GCM authentication tag (base64 encoded)
- vault_data — ciphertext bytes (base64 encoded)

All fields are required.

---

## 5. Encryption Process (High-Level)

1. Read salt file.
2. Derive key using Argon2id(password, salt).
3. Serialize vault plaintext JSON (see vault-schema.md).
4. Generate random 12-byte IV.
5. Encrypt using AES-256-GCM.
6. Store base64 fields in JSON envelope.
7. Write envelope JSON to disk.

---

## 6. Decryption Process (High-Level)

1. Read JSON envelope.
2. Base64 decode iv, tag, and vault_data.
3. Derive key from password and salt.
4. Decrypt using AES-256-GCM.
5. Verify authentication tag.
6. Parse decrypted UTF-8 JSON into Python object.

Authentication tag verification MUST succeed before parsing.

If authentication fails, vault is considered invalid.

---

## 7. Wrapped Vault Key (Recovery Mode)

Some account modes store a separately wrapped vault key.

Two layouts are currently supported.

### Password-Based Wrapper

Raw layout:

- 16-byte salt
- 12-byte nonce
- ciphertext + 16-byte tag

Key encryption key (KEK) derived using Argon2id.  
AES-GCM used for wrapping.

AAD label currently used:
KQID-VK-PW

---

### Device-Based Wrapper

Raw layout:

- 12-byte nonce
- ciphertext + 16-byte tag

Key encryption key provided by device flow (e.g., platform-based key).  
AES-GCM used for wrapping.

AAD label currently used:
KQID-VK

---

## 8. Security Requirements

- AES-GCM nonces must never be reused under the same key.
- Authentication tag must always be verified before accepting decrypted data.
- Decrypted secrets must never be logged.
- Corrupted or malformed envelope files must not be partially accepted.

---

## 9. Current Limitations

- No explicit format_version in envelope (yet).
- KDF parameters are not embedded in vault file.
- Cipher identifier is not stored explicitly.
- Wrapper format is not versioned.

---

## 10. Planned Future Improvements

Future versions may include:

- Explicit format_version field
- Embedded KDF parameter block
- Cipher identifier field
- Versioned wrapped key header
- Formal migration handling

All future changes will aim to preserve backward compatibility.

---

## 11. Compatibility Guidance

Implementations (Desktop, Native Core, Android) should:

- Be tolerant of unknown envelope fields.
- Strictly verify authentication tag.
- Avoid assuming schema structure without consulting vault-schema.md.
- Preserve backward compatibility where possible.
