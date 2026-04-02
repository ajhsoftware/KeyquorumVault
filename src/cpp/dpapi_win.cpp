/*
    Keyquorum Vault – Native Core Module (DPAPI helpers)
    Copyright (C) 2026 Anthony Hatton

    GPL-3.0-or-later
*/
#ifdef _WIN32

#include "keyquorum_core.h"
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

// Simple error codes (match python side expectations: 0 = OK)
static int _kq_fail(int rc) { return rc ? rc : -1; }

extern "C" {

// Protect plaintext bytes to a DPAPI blob.
// The returned buffer must be freed with kq_dpapi_free().
KQ_API int kq_dpapi_protect(
    const unsigned char* pt, size_t pt_len,
    const unsigned char* entropy, size_t entropy_len,
    void** out_ptr, size_t* out_len
) {
    if (!out_ptr || !out_len) return _kq_fail(-2);
    *out_ptr = nullptr;
    *out_len = 0;
    if (!pt || pt_len == 0) return _kq_fail(-3);

    DATA_BLOB inBlob{};
    inBlob.pbData = (BYTE*)pt;
    inBlob.cbData = (DWORD)pt_len;

    DATA_BLOB outBlob{};
    DATA_BLOB entBlob{};
    DATA_BLOB* pEnt = nullptr;

    if (entropy && entropy_len > 0) {
        entBlob.pbData = (BYTE*)entropy;
        entBlob.cbData = (DWORD)entropy_len;
        pEnt = &entBlob;
    }

    if (!CryptProtectData(&inBlob, nullptr, pEnt, nullptr, nullptr, 0, &outBlob)) {
        return _kq_fail((int)GetLastError());
    }

    *out_ptr = outBlob.pbData;           // must be LocalFree'd
    *out_len = (size_t)outBlob.cbData;
    return 0;
}

// Unprotect a DPAPI blob to plaintext bytes.
// The returned buffer must be freed with kq_dpapi_free().
KQ_API int kq_dpapi_unprotect(
    const unsigned char* blob, size_t blob_len,
    const unsigned char* entropy, size_t entropy_len,
    void** out_ptr, size_t* out_len
) {
    if (!out_ptr || !out_len) return _kq_fail(-2);
    *out_ptr = nullptr;
    *out_len = 0;

    if (!blob || blob_len == 0) return _kq_fail(-3);

    DATA_BLOB inBlob{};
    inBlob.pbData = (BYTE*)blob;
    inBlob.cbData = (DWORD)blob_len;

    DATA_BLOB outBlob{};
    DATA_BLOB entBlob{};
    DATA_BLOB* pEnt = nullptr;

    if (entropy && entropy_len > 0) {
        entBlob.pbData = (BYTE*)entropy;
        entBlob.cbData = (DWORD)entropy_len;
        pEnt = &entBlob;
    }

    if (!CryptUnprotectData(&inBlob, nullptr, pEnt, nullptr, nullptr, 0, &outBlob)) {
        return _kq_fail((int)GetLastError());
    }

    *out_ptr = outBlob.pbData;           // must be LocalFree'd
    *out_len = (size_t)outBlob.cbData;
    return 0;
}

KQ_API void kq_dpapi_free(void* ptr) {
    if (ptr) {
        LocalFree(ptr);
    }
}

// Unprotect a DPAPI blob that contains a 32-byte vault key,
// then open a native session from it WITHOUT returning the key to Python.
KQ_API int kq_dpapi_unprotect_to_session(
    const unsigned char* blob, size_t blob_len,
    const unsigned char* entropy, size_t entropy_len,
    kq_session_t* out_session
) {
    if (!out_session) return _kq_fail(-2);
    *out_session = nullptr;

    void* pt = nullptr;
    size_t pt_len = 0;
    int rc = kq_dpapi_unprotect(blob, blob_len, entropy, entropy_len, &pt, &pt_len);
    if (rc != 0) return rc;
    if (!pt || pt_len == 0) {
        kq_dpapi_free(pt);
        return _kq_fail(-4);
    }

    // Expect raw 32-byte key
    if (pt_len != 32) {
        // Wipe plaintext then free
        secure_wipe(pt, pt_len);
        kq_dpapi_free(pt);
        return _kq_fail(-5);
    }

    // Open session from key (key never leaves DLL)
    rc = kq_session_open_from_key((const unsigned char*)pt, pt_len, out_session);

    // Always wipe plaintext key before freeing
    secure_wipe(pt, pt_len);
    kq_dpapi_free(pt);

    return rc;
}

// Export the session's 32-byte key as a DPAPI-protected blob.
// The plaintext key is never returned to the caller.
KQ_API int kq_session_export_key_dpapi(
    kq_session_t session,
    const unsigned char* entropy, size_t entropy_len,
    void** out_ptr, size_t* out_len
) {
    if (!session) return _kq_fail(-1);

    // In this build, the session struct begins with key[32].
    // So the first 32 bytes at the session pointer are the key.
    const unsigned char* key32 = (const unsigned char*)session;
    return kq_dpapi_protect(key32, 32, entropy, entropy_len, out_ptr, out_len);
}

} // extern "C"

#endif // _WIN32
