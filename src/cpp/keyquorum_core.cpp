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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "keyquorum_core.h"
#include <new>
#include <cstring>
#include <argon2.h>
#include <openssl/evp.h>


// -----------------------------------------------------------------------------
// Keyquorum Core (native crypto helpers)
//
// - Argon2id KDF (argon2id_hash_raw)
// - AES-256-GCM encrypt/decrypt (OpenSSL EVP)
// - Secure wiping
// - Session handle API (keys stay inside DLL)
//
// IMPORTANT:
//   - Password buffer is treated as input only. Python should wipe it.
//   - Session key is wiped on close.
// -----------------------------------------------------------------------------

// --- MUST match your app settings (or pass them from Python if you prefer)
static constexpr uint32_t ARGON_T_COST = 3;
static constexpr uint32_t ARGON_M_COST_KIB = 256000;
static constexpr uint32_t ARGON_PARALLELISM = 2;
static constexpr size_t   VK_LEN = 32; // AES-256 key
static constexpr size_t   GCM_TAG_LEN = 16;
static constexpr size_t   GCM_IV_DEFAULT_LEN = 12; // recommended

// Small wipe that won't be optimized away (belt + suspenders)
static void secure_bzero(void* p, size_t n) {
    if (!p || n == 0) return;
    SecureZeroMemory(p, n);
}

// Session object holds the vault key only
struct KqSession {
    unsigned char key[VK_LEN];
    bool locked;

    KqSession() : key{ 0 }, locked(false) {}
};

static int aes_gcm_decrypt_key(
    const unsigned char* key,
    const unsigned char* iv, size_t iv_len,
    const unsigned char* ciphertext, size_t cipher_len,
    const unsigned char* tag, size_t tag_len,
    unsigned char* out_plaintext
) {
    if (!key || !iv || !ciphertext || !tag || !out_plaintext) return -1;
    if (tag_len != GCM_TAG_LEN) return -2;
    if (iv_len == 0) return -3;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -4;

    int len = 0;
    int out_len = 0;

    // Init AES-256-GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }

    // Set IV length (OpenSSL default is 12, but allow variable)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }

    // Set key + IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -7;
    }

    // Decrypt
    if (EVP_DecryptUpdate(ctx, out_plaintext, &len, ciphertext, (int)cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -8;
    }
    out_len = len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -9;
    }

    // Final verifies tag
    int final_ok = EVP_DecryptFinal_ex(ctx, out_plaintext + out_len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (final_ok != 1) return -10; // auth failure

    return 0;
}

static int aes_gcm_encrypt_key(
    const unsigned char* key,
    const unsigned char* iv, size_t iv_len,
    const unsigned char* plaintext, size_t plain_len,
    unsigned char* out_ciphertext,
    unsigned char* out_tag, size_t tag_len
) {
    if (!key || !iv || !plaintext || !out_ciphertext || !out_tag) return -1;
    if (tag_len != GCM_TAG_LEN) return -2;
    if (iv_len == 0) return -3;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -4;

    int len = 0;

    // Init AES-256-GCM
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }

    // Set key + IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -7;
    }

    // Encrypt
    if (EVP_EncryptUpdate(ctx, out_ciphertext, &len, plaintext, (int)plain_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -8;
    }

    // Finalize
    int fin_len = 0;
    if (EVP_EncryptFinal_ex(ctx, out_ciphertext + len, &fin_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -9;
    }

    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len, out_tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -10;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

extern "C" {



    KQ_API int kq_version() {
        return 171; // bump when you ship changes
    }

    KQ_API const char* kq_crypto_backend() {
        // Static string: safe to return
        return "Argon2id (argon2) + AES-256-GCM (OpenSSL libcrypto EVP). No TLS/SSL used.";
    }

    // -----------------------------------------------------------------------------
    // Backwards compatible: derive_vault_key (salt length fixed previously)
    // Now uses salt_len passed by caller? Your old signature has no salt_len.
    // We'll keep your signature and assume caller salt is 16 or 32 based on your app.
    // If you need both lengths, prefer session_open which accepts salt_len.
    // -----------------------------------------------------------------------------
    KQ_API int derive_vault_key(
        const unsigned char* password_buffer,
        size_t password_len,
        const unsigned char* salt,
        unsigned char* out_key
    ) {
        if (!password_buffer || password_len == 0 || !salt || !out_key)
            return -1;

        // IMPORTANT: choose salt length that matches your app.
        // If your app uses 16 bytes, keep 16. If 32, set 32.
        // Better: use kq_session_open where salt_len is explicit.
        constexpr size_t SALT_LEN_ASSUMED = 16;

        int rc = argon2id_hash_raw(
            ARGON_T_COST,
            ARGON_M_COST_KIB,
            ARGON_PARALLELISM,
            password_buffer, password_len,
            salt, SALT_LEN_ASSUMED,
            out_key, VK_LEN
        );

        if (rc != ARGON2_OK)
            return -2;

        return 0;
    }

    KQ_API int decrypt_vault(
        const unsigned char* key,
        const unsigned char* iv,
        const unsigned char* ciphertext,
        size_t cipher_len,
        const unsigned char* tag,
        unsigned char* out_plaintext
    ) {
        // Old API assumes iv_len=12 and tag_len=16
        return aes_gcm_decrypt_key(
            key,
            iv, GCM_IV_DEFAULT_LEN,
            ciphertext, cipher_len,
            tag, GCM_TAG_LEN,
            out_plaintext
        );
    }

    KQ_API int encrypt_vault(
        const unsigned char* key,
        const unsigned char* iv,
        const unsigned char* plaintext,
        size_t plain_len,
        unsigned char* out_ciphertext,
        unsigned char* out_tag
    ) {
        return aes_gcm_encrypt_key(
            key,
            iv, GCM_IV_DEFAULT_LEN,
            plaintext, plain_len,
            out_ciphertext,
            out_tag, GCM_TAG_LEN
        );
    }

    // -----------------------------------------------------------------------------
    // Session API (preferred): key stays inside DLL
    // -----------------------------------------------------------------------------

    KQ_API int kq_session_open_from_key(
        const unsigned char* key32,
        size_t key_len,
        kq_session_t* out_session
    ) {
        if (!key32 || key_len != VK_LEN || !out_session)
            return -1;

        KqSession* s = new (std::nothrow) KqSession();
        if (!s)
            return -2;

        // Copy key into session-owned storage
        std::memcpy(s->key, key32, VK_LEN);

        // Optional: lock key memory to reduce paging (best effort)
        s->locked = false;
        if (VirtualLock(s->key, VK_LEN)) {
            s->locked = true;
        }

        *out_session = (kq_session_t)s;
        return 0;
    }


    KQ_API int kq_session_open(
        const unsigned char* password_buffer, size_t password_len,
        const unsigned char* salt, size_t salt_len,
        kq_session_t* out_session
    ) {
        if (!password_buffer || password_len == 0 || !salt || salt_len == 0 || !out_session)
            return -1;

        // Allocate session
        KqSession* s = new (std::nothrow) KqSession();
        if (!s) return -2;

        // Derive key directly into session key
        int rc = argon2id_hash_raw(
            ARGON_T_COST,
            ARGON_M_COST_KIB,
            ARGON_PARALLELISM,
            password_buffer, password_len,
            salt, salt_len,
            s->key, VK_LEN
        );

        if (rc != ARGON2_OK) {
            secure_bzero(s->key, VK_LEN);
            delete s;
            return -3;
        }

        // Optional: lock key memory to reduce paging (best effort)
        s->locked = false;
        if (VirtualLock(s->key, VK_LEN)) {
            s->locked = true;
        }

        *out_session = (kq_session_t)s;
        return 0;
    }

    KQ_API void kq_session_close(kq_session_t session) {
        if (!session) return;
        KqSession* s = (KqSession*)session;

        // Unlock if locked
        if (s->locked) {
            VirtualUnlock(s->key, VK_LEN);
            s->locked = false;
        }

        // Wipe key then free
        secure_bzero(s->key, VK_LEN);
        delete s;
    }

    KQ_API int kq_session_decrypt(
        kq_session_t session,
        const unsigned char* iv, size_t iv_len,
        const unsigned char* ciphertext, size_t cipher_len,
        const unsigned char* tag, size_t tag_len,
        unsigned char* out_plaintext
    ) {
        if (!session) return -1;
        KqSession* s = (KqSession*)session;
        return aes_gcm_decrypt_key(
            s->key,
            iv, iv_len,
            ciphertext, cipher_len,
            tag, tag_len,
            out_plaintext
        );
    }

    KQ_API int kq_session_encrypt(
        kq_session_t session,
        const unsigned char* iv, size_t iv_len,
        const unsigned char* plaintext, size_t plain_len,
        unsigned char* out_ciphertext,
        unsigned char* out_tag, size_t tag_len
    ) {
        if (!session) return -1;
        KqSession* s = (KqSession*)session;
        return aes_gcm_encrypt_key(
            s->key,
            iv, iv_len,
            plaintext, plain_len,
            out_ciphertext,
            out_tag, tag_len
        );
    }

    // -----------------------------------------------------------------------------
    // Wipe helper
    // -----------------------------------------------------------------------------
    KQ_API void secure_wipe(void* ptr, size_t len) {
        if (ptr && len > 0) {
            SecureZeroMemory(ptr, len);
        }
    }



} // extern "C"
