/*
    Keyquorum Vault – Native Core Module
    Copyright (C) 2026 Anthony Hatton

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define KQ_API __declspec(dllexport)
#else
#define KQ_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

    // ----------------------------------------------------------------------------
    // Versioning / info
    // ----------------------------------------------------------------------------
    KQ_API int         kq_version(void);
    KQ_API const char* kq_crypto_backend(void);

    // ----------------------------------------------------------------------------
    // Backwards compatible exports (your current API)
    // ----------------------------------------------------------------------------
    KQ_API int derive_vault_key(
        const unsigned char* password_buffer,
        size_t password_len,
        const unsigned char* salt,
        unsigned char* out_key
    );

    KQ_API int decrypt_vault(
        const unsigned char* key,
        const unsigned char* iv,
        const unsigned char* ciphertext,
        size_t cipher_len,
        const unsigned char* tag,
        unsigned char* out_plaintext
    );

    // NEW: encrypt helper (oneshot, still key passed in)
    KQ_API int encrypt_vault(
        const unsigned char* key,
        const unsigned char* iv,
        const unsigned char* plaintext,
        size_t plain_len,
        unsigned char* out_ciphertext,
        unsigned char* out_tag /*16 bytes*/
    );

    // ----------------------------------------------------------------------------
    // Full DLL-reliant session API (preferred)
    // ----------------------------------------------------------------------------
    typedef void* kq_session_t;

    // Create session and derive/store the vault key INSIDE DLL.
    // Returns 0 on success.
    KQ_API int kq_session_open(
        const unsigned char* password_buffer, size_t password_len,
        const unsigned char* salt, size_t salt_len,
        kq_session_t* out_session
    );

    // Create a session directly from a 32-byte vault key (used for DPAPI/Yubi unwrap paths).
    // Returns 0 on success.
    KQ_API int kq_session_open_from_key(
        const unsigned char* key32,
        size_t key_len,
        kq_session_t* out_session
    );

    // Wipe keys, free session.
    KQ_API void kq_session_close(kq_session_t session);

    // AES-256-GCM decrypt using key stored in session.
    // out_plaintext must be >= cipher_len bytes.
    // Returns 0 on success.
    KQ_API int kq_session_decrypt(
        kq_session_t session,
        const unsigned char* iv, size_t iv_len,
        const unsigned char* ciphertext, size_t cipher_len,
        const unsigned char* tag, size_t tag_len,
        unsigned char* out_plaintext
    );

    // AES-256-GCM encrypt using key stored in session.
    // out_ciphertext must be >= plain_len.
    // out_tag must be >= 16 bytes.
    // Returns 0 on success.
    KQ_API int kq_session_encrypt(
        kq_session_t session,
        const unsigned char* iv, size_t iv_len,
        const unsigned char* plaintext, size_t plain_len,
        unsigned char* out_ciphertext,
        unsigned char* out_tag, size_t tag_len
    );

    // ----------------------------------------------------------------------------
    // Secure wipe helper (Windows SecureZeroMemory)
    // ----------------------------------------------------------------------------
    KQ_API void secure_wipe(void* ptr, size_t len);

#ifdef __cplusplus
} // extern "C"
#endif
