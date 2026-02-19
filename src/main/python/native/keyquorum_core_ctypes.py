import ctypes as C
import os
from typing import Optional

# ---- platform helpers ----

def _load_lib(path: str) -> C.CDLL:
    """
    Load the native library.
    NOTE:
      - If you build with __cdecl (default), CDLL is correct.
      - If you ever switch exports to __stdcall, use WinDLL.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Native library not found: {path}")
    return C.CDLL(path)

# ---- ctypes types ----

c_ubyte_p = C.POINTER(C.c_ubyte)
c_void_p = C.c_void_p
c_size_t = C.c_size_t
c_int = C.c_int
c_char_p = C.c_char_p

KQ_TAG_LEN = 16
KQ_KEY_LEN = 32

def _as_ubyte_ptr(buf) -> c_ubyte_p:
    """
    Get a POINTER(c_ubyte) view of a writable buffer (bytearray, memoryview).
    """
    mv = memoryview(buf)
    if mv.readonly:
        raise TypeError("Buffer must be writable (bytearray/memoryview writable).")
    return C.cast(C.c_void_p(C.addressof(C.c_ubyte.from_buffer(mv))), c_ubyte_p)

def _as_ubyte_ptr_ro(b: bytes) -> c_ubyte_p:
    """
    Pointer to read-only bytes (ctypes will copy).
    For secrets, prefer passing a bytearray to avoid copies.
    For non-secrets (salt/iv/tag), this is fine.
    """
    arr = (C.c_ubyte * len(b)).from_buffer_copy(b)
    return C.cast(arr, c_ubyte_p)

# ---- wrapper class ----

class KeyquorumCore:
    """
    Native crypto wrapper.

    Preferred (secure) mode:
      - open_session() -> returns opaque session handle
      - session_encrypt()/session_decrypt() use keys stored inside the DLL
      - close_session() wipes keys inside the DLL

    Legacy mode (still supported for compatibility):
      - derive_vault_key()
      - decrypt_vault(key,...)
      - encrypt_vault(key,...)
    """

    def __init__(self, lib_path: str):
        self.lib = _load_lib(lib_path)

        # ---- kq_version ----
        self.lib.kq_version.argtypes = []
        self.lib.kq_version.restype = c_int

        # ---- kq_crypto_backend (optional but present in your DLL exports) ----
        # const char* kq_crypto_backend()
        self.lib.kq_crypto_backend.argtypes = []
        self.lib.kq_crypto_backend.restype = c_char_p

        # ---- secure_wipe ----
        self.lib.secure_wipe.argtypes = [c_void_p, c_size_t]
        self.lib.secure_wipe.restype = None

        # ---- legacy: derive_vault_key ----
        self.lib.derive_vault_key.argtypes = [
            c_ubyte_p, c_size_t, c_ubyte_p, c_ubyte_p
        ]
        self.lib.derive_vault_key.restype = c_int

        # ---- legacy: decrypt_vault ----
        self.lib.decrypt_vault.argtypes = [
            c_ubyte_p, c_ubyte_p, c_ubyte_p, c_size_t, c_ubyte_p, c_ubyte_p
        ]
        self.lib.decrypt_vault.restype = c_int

        # ---- legacy: encrypt_vault (you now export this) ----
        self.lib.encrypt_vault.argtypes = [
            c_ubyte_p,         # key
            c_ubyte_p,         # iv
            c_ubyte_p,         # plaintext
            c_size_t,          # plain_len
            c_ubyte_p,         # out_ciphertext
            c_ubyte_p,         # out_tag (16)
        ]
        self.lib.encrypt_vault.restype = c_int

        # ---- session API (preferred) ----
        # int kq_session_open(pw, pwlen, salt, saltlen, out_session)
        self.lib.kq_session_open.argtypes = [
            c_ubyte_p, c_size_t,
            c_ubyte_p, c_size_t,
            C.POINTER(c_void_p)
        ]
        self.lib.kq_session_open.restype = c_int

        # void kq_session_close(session)
        self.lib.kq_session_close.argtypes = [c_void_p]
        self.lib.kq_session_close.restype = None

        # int kq_session_decrypt(session, iv, ivlen, ct, ctlen, tag, taglen, out_pt)
        self.lib.kq_session_decrypt.argtypes = [
            c_void_p,
            c_ubyte_p, c_size_t,
            c_ubyte_p, c_size_t,
            c_ubyte_p, c_size_t,
            c_ubyte_p
        ]
        self.lib.kq_session_decrypt.restype = c_int

        # int kq_session_encrypt(session, iv, ivlen, pt, ptlen, out_ct, out_tag, taglen)
        self.lib.kq_session_encrypt.argtypes = [
            c_void_p,
            c_ubyte_p, c_size_t,
            c_ubyte_p, c_size_t,
            c_ubyte_p,
            c_ubyte_p, c_size_t
        ]
        self.lib.kq_session_encrypt.restype = c_int

    # ------------------------------
    # Version / backend info
    # ------------------------------
    def version(self) -> int:
        return self.lib.kq_version()

    def crypto_backend(self) -> str:
        s = self.lib.kq_crypto_backend()
        return (s.decode("utf-8", "replace") if s else "unknown")

    # ------------------------------
    # Secure wipe (wipes a Python-owned buffer)
    # ------------------------------
    def secure_wipe(self, buf: bytearray) -> None:
        if not buf:
            return
        mv = memoryview(buf)
        ptr = C.c_void_p(C.addressof(C.c_ubyte.from_buffer(mv)))
        self.lib.secure_wipe(ptr, len(buf))

    # ============================================================
    # SESSION MODE (preferred): key never leaves the DLL
    # ============================================================
    def open_session(self, password_buf: bytearray, salt: bytes | bytearray) -> int:
        """
        Create a native session. The derived vault key is stored inside the DLL.
        Returns an opaque session handle (as an int pointer value).
        """
        if not isinstance(password_buf, bytearray):
            raise TypeError("password_buf must be a bytearray")
        if not password_buf:
            raise ValueError("password_buf empty")

        # Salt is not a secret, but keep it copy-minimal anyway.
        salt_ba = bytearray(salt) if isinstance(salt, bytes) else salt
        if not isinstance(salt_ba, bytearray) or not salt_ba:
            raise ValueError("salt must be non-empty bytes/bytearray")

        out = c_void_p()
        rc = self.lib.kq_session_open(
            _as_ubyte_ptr(password_buf),
            len(password_buf),
            _as_ubyte_ptr(salt_ba),
            len(salt_ba),
            C.byref(out),
        )
        if rc != 0 or not out.value:
            raise RuntimeError(f"kq_session_open failed rc={rc}")

        # Return as int to keep it simple for callers / JSON / state.
        return int(out.value)

    def close_session(self, session_handle: Optional[int]) -> None:
        """
        Close session and wipe keys inside the DLL.
        Safe to call multiple times.
        """
        if not session_handle:
            return
        self.lib.kq_session_close(c_void_p(session_handle))

    def session_decrypt(
        self,
        session_handle: int,
        iv: bytes | bytearray,
        ciphertext: bytes | bytearray,
        tag: bytes | bytearray,
    ) -> bytearray:
        """
        Decrypt via session-owned key. Returns plaintext as bytearray.
        """
        if not session_handle:
            raise ValueError("session_handle missing/invalid")

        iv_ba = iv if isinstance(iv, bytearray) else bytearray(iv)
        ct_ba = ciphertext if isinstance(ciphertext, bytearray) else bytearray(ciphertext)
        tag_ba = tag if isinstance(tag, bytearray) else bytearray(tag)

        if len(tag_ba) != KQ_TAG_LEN:
            raise ValueError("tag must be 16 bytes")
        if len(iv_ba) == 0:
            raise ValueError("iv must be non-empty")

        out_pt = bytearray(len(ct_ba))

        rc = self.lib.kq_session_decrypt(
            c_void_p(session_handle),
            _as_ubyte_ptr(iv_ba), len(iv_ba),
            _as_ubyte_ptr(ct_ba), len(ct_ba),
            _as_ubyte_ptr(tag_ba), len(tag_ba),
            _as_ubyte_ptr(out_pt),
        )
        if rc != 0:
            raise RuntimeError(f"kq_session_decrypt failed rc={rc}")

        return out_pt

    def session_encrypt(
        self,
        session_handle: int,
        iv: bytes | bytearray,
        plaintext: bytes | bytearray,
    ) -> tuple[bytearray, bytearray]:
        """
        Encrypt via session-owned key.
        Returns (ciphertext, tag16) as bytearrays.
        """
        if not session_handle:
            raise ValueError("session_handle missing/invalid")

        iv_ba = iv if isinstance(iv, bytearray) else bytearray(iv)
        pt_ba = plaintext if isinstance(plaintext, bytearray) else bytearray(plaintext)

        if len(iv_ba) == 0:
            raise ValueError("iv must be non-empty")

        out_ct = bytearray(len(pt_ba))
        out_tag = bytearray(KQ_TAG_LEN)

        rc = self.lib.kq_session_encrypt(
            c_void_p(session_handle),
            _as_ubyte_ptr(iv_ba), len(iv_ba),
            _as_ubyte_ptr(pt_ba), len(pt_ba),
            _as_ubyte_ptr(out_ct),
            _as_ubyte_ptr(out_tag), len(out_tag),
        )
        if rc != 0:
            raise RuntimeError(f"kq_session_encrypt failed rc={rc}")

        return out_ct, out_tag

    # ============================================================
    # LEGACY MODE (compat): key returned to Python (try to avoid)
    # ============================================================
    def derive_vault_key(self, password_buf: bytearray, salt: bytes | bytearray) -> bytearray:
        """
        Legacy: derive key into Python (try not to use going forward).
        """
        if not isinstance(password_buf, bytearray):
            raise TypeError("password_buf must be a bytearray")
        if not password_buf:
            raise ValueError("password_buf empty")

        salt_ba = bytearray(salt) if isinstance(salt, bytes) else salt
        out_key = bytearray(KQ_KEY_LEN)

        rc = self.lib.derive_vault_key(
            _as_ubyte_ptr(password_buf),
            len(password_buf),
            _as_ubyte_ptr(salt_ba),
            _as_ubyte_ptr(out_key),
        )
        if rc != 0:
            raise RuntimeError(f"derive_vault_key failed rc={rc}")

        return out_key

    def decrypt_vault(
        self,
        key32: bytearray,
        iv: bytes | bytearray,
        ciphertext: bytes | bytearray,
        tag16: bytes | bytearray,
    ) -> bytearray:
        """
        Legacy: decrypt with caller-supplied key (try not to use going forward).
        """
        if len(key32) != KQ_KEY_LEN:
            raise ValueError("key must be 32 bytes")

        iv_ba = iv if isinstance(iv, bytearray) else bytearray(iv)
        ct_ba = ciphertext if isinstance(ciphertext, bytearray) else bytearray(ciphertext)
        tag_ba = tag16 if isinstance(tag16, bytearray) else bytearray(tag16)

        if len(tag_ba) != KQ_TAG_LEN:
            raise ValueError("tag must be 16 bytes")
        if len(iv_ba) == 0:
            raise ValueError("iv must be non-empty")

        out_pt = bytearray(len(ct_ba))

        rc = self.lib.decrypt_vault(
            _as_ubyte_ptr(key32),
            _as_ubyte_ptr(iv_ba),
            _as_ubyte_ptr(ct_ba),
            len(ct_ba),
            _as_ubyte_ptr(tag_ba),
            _as_ubyte_ptr(out_pt),
        )
        if rc != 0:
            raise RuntimeError(f"decrypt_vault failed rc={rc}")

        return out_pt

    def encrypt_vault(
        self,
        key32: bytearray,
        iv: bytes | bytearray,
        plaintext: bytes | bytearray,
    ) -> tuple[bytearray, bytearray]:
        """
        Legacy: encrypt with caller-supplied key (try not to use going forward).
        Returns (ciphertext, tag16).
        """
        if len(key32) != KQ_KEY_LEN:
            raise ValueError("key must be 32 bytes")

        iv_ba = iv if isinstance(iv, bytearray) else bytearray(iv)
        pt_ba = plaintext if isinstance(plaintext, bytearray) else bytearray(plaintext)
        if len(iv_ba) == 0:
            raise ValueError("iv must be non-empty")

        out_ct = bytearray(len(pt_ba))
        out_tag = bytearray(KQ_TAG_LEN)

        rc = self.lib.encrypt_vault(
            _as_ubyte_ptr(key32),
            _as_ubyte_ptr(iv_ba),
            _as_ubyte_ptr(pt_ba),
            len(pt_ba),
            _as_ubyte_ptr(out_ct),
            _as_ubyte_ptr(out_tag),
        )
        if rc != 0:
            raise RuntimeError(f"encrypt_vault failed rc={rc}")

        return out_ct, out_tag
