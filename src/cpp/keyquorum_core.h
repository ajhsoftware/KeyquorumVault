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
    // Backwards compatible exports (current API)
    // ----------------------------------------------------------------------------
    KQ_API int derive_vault_key(
        const unsigned char* password_buffer,
        size_t password_len,
        const unsigned char* salt,
        unsigned char* out_key
    );

    

// ----------------------------------------------------------------------------
// Parameterized KDF exports (KDF v2+)
//
// These allow per-vault Argon2id profiles (time/memory/parallelism) while keeping
// legacy fixed-profile exports for backwards compatibility.
// ----------------------------------------------------------------------------
KQ_API int derive_vault_key_ex(
    const unsigned char* password_buffer,
    size_t password_len,
    const unsigned char* salt, size_t salt_len,
    uint32_t time_cost,
    uint32_t memory_kib,
    uint32_t parallelism,
    unsigned char* out_key, size_t out_key_len
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

    

// Create session and derive/store the vault key INSIDE DLL using an explicit
// Argon2id profile (KDF v2+). Returns 0 on success.
KQ_API int kq_session_open_ex(
    const unsigned char* password_buffer, size_t password_len,
    const unsigned char* salt, size_t salt_len,
    uint32_t time_cost,
    uint32_t memory_kib,
    uint32_t parallelism,
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
    // Session key wrapping (no key material leaves the DLL)
    // ----------------------------------------------------------------------------

    // Encrypt the 32-byte key stored in `key_session` using the key stored in `wrapping_session`.
    // Outputs:
    //   - iv: 12 bytes
    //   - out_ciphertext: 32 bytes
    //   - out_tag: 16 bytes
    // Returns 0 on success.
    KQ_API int kq_session_wrap_session_key(
        kq_session_t key_session,
        kq_session_t wrapping_session,
        unsigned char* out_iv, size_t iv_len,
        unsigned char* out_ciphertext, size_t ct_len,
        unsigned char* out_tag, size_t tag_len
    );

    // Decrypt a wrapped session key using `wrapping_session` and create a NEW session from it.
    // The decrypted key is zeroed inside the DLL after the new session is created.
    // Returns 0 on success.
    KQ_API int kq_session_unwrap_to_session(
        kq_session_t wrapping_session,
        const unsigned char* iv, size_t iv_len,
        const unsigned char* ciphertext, size_t ct_len,
        const unsigned char* tag, size_t tag_len,
        kq_session_t* out_session
    );

    // ----------------------------------------------------------------------------
    // Secure wipe helper (Windows SecureZeroMemory)
    // ----------------------------------------------------------------------------
    KQ_API void secure_wipe(void* ptr, size_t len);

#ifdef _WIN32
    // ----------------------------------------------------------------------------
    // DPAPI helpers (Windows)
    //
    // STRICT DLL-only "Remember this device" (v4) uses these to:
    //  - export the current session key as a DPAPI blob (key never returned)
    //  - unprotect a DPAPI blob directly into a native session handle
    // ----------------------------------------------------------------------------

    // Protect plaintext bytes to a DPAPI blob. Caller must free with kq_dpapi_free.
    KQ_API int kq_dpapi_protect(
        const unsigned char* pt, size_t pt_len,
        const unsigned char* entropy, size_t entropy_len,
        void** out_ptr, size_t* out_len
    );

    // Unprotect a DPAPI blob to plaintext bytes. Caller must free with kq_dpapi_free.
    KQ_API int kq_dpapi_unprotect(
        const unsigned char* blob, size_t blob_len,
        const unsigned char* entropy, size_t entropy_len,
        void** out_ptr, size_t* out_len
    );

    // Free buffers returned from kq_dpapi_(un)protect.
    KQ_API void kq_dpapi_free(void* ptr);

    // Unprotect a DPAPI blob that contains a 32-byte vault key,
    // then open a native session from it WITHOUT returning the key.
    KQ_API int kq_dpapi_unprotect_to_session(
        const unsigned char* blob, size_t blob_len,
        const unsigned char* entropy, size_t entropy_len,
        kq_session_t* out_session
    );

    // Export the session's 32-byte key as a DPAPI-protected blob.
    // The plaintext key never leaves the DLL.
    KQ_API int kq_session_export_key_dpapi(
        kq_session_t session,
        const unsigned char* entropy, size_t entropy_len,
        void** out_ptr, size_t* out_len
    );
#endif

#ifdef __cplusplus
} // extern "C"
#endif
