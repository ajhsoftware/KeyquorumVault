import ctypes as C
import os
from typing import Optional, Tuple, Union

# ---- ctypes types ----
c_ubyte_p = C.POINTER(C.c_ubyte)
c_void_p = C.c_void_p
c_size_t = C.c_size_t
c_int = C.c_int
c_char_p = C.c_char_p

KQ_TAG_LEN = 16
KQ_KEY_LEN = 32

def _load_lib(path: str) -> C.CDLL:
    """Load the native library (cdecl exports)."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Native library not found: {path}")
    return C.CDLL(path)

def _as_ubyte_ptr(buf: Union[bytearray, memoryview]) -> c_ubyte_p:
    """POINTER(c_ubyte) view of a writable buffer (no copy)."""
    mv = memoryview(buf)
    if mv.readonly:
        raise TypeError("Buffer must be writable.")
    return C.cast(C.c_void_p(C.addressof(C.c_ubyte.from_buffer(mv))), c_ubyte_p)

def _as_ubyte_ptr_copy(b: bytes) -> c_ubyte_p:
    """Pointer to a copy of read-only bytes (for non-secret inputs)."""
    arr = (C.c_ubyte * len(b)).from_buffer_copy(b)
    return C.cast(arr, c_ubyte_p)

class KeyquorumCore:
    """Native crypto wrapper.

    Preferred (secure) mode:
      - open_session() -> opaque session handle (int pointer value)
      - session_encrypt()/session_decrypt() use keys stored inside the DLL
      - close_session() wipes keys inside the DLL

    Legacy mode (compat):
      - derive_vault_key()
      - decrypt_vault(key,...)
      - encrypt_vault(key,...)
    """

    def __init__(self, lib_path: str):
        self.lib = _load_lib(lib_path)

        # int kq_version()
        self.lib.kq_version.argtypes = []
        self.lib.kq_version.restype = c_int

        # const char* kq_crypto_backend()
        self.lib.kq_crypto_backend.argtypes = []
        self.lib.kq_crypto_backend.restype = c_char_p

        # void secure_wipe(void* ptr, size_t len)
        self.lib.secure_wipe.argtypes = [c_void_p, c_size_t]
        self.lib.secure_wipe.restype = None

        # legacy: int derive_vault_key(pw, pwlen, salt, out_key32)
        self.lib.derive_vault_key.argtypes = [c_ubyte_p, c_size_t, c_ubyte_p, c_ubyte_p]
        self.lib.derive_vault_key.restype = c_int

        # legacy: int decrypt_vault(key32, iv, ct, ctlen, tag16, out_pt)
        self.lib.decrypt_vault.argtypes = [c_ubyte_p, c_ubyte_p, c_ubyte_p, c_size_t, c_ubyte_p, c_ubyte_p]
        self.lib.decrypt_vault.restype = c_int

        # legacy: int encrypt_vault(key32, iv, pt, ptlen, out_ct, out_tag16)
        self.lib.encrypt_vault.argtypes = [c_ubyte_p, c_ubyte_p, c_ubyte_p, c_size_t, c_ubyte_p, c_ubyte_p]
        self.lib.encrypt_vault.restype = c_int

        # session: int kq_session_open(pw, pwlen, salt, saltlen, out_session)
        self.lib.kq_session_open.argtypes = [c_ubyte_p, c_size_t, c_ubyte_p, c_size_t, C.POINTER(c_void_p)]
        self.lib.kq_session_open.restype = c_int

        # int kq_session_open_from_key(key32, key_len, out_session)
        self.lib.kq_session_open_from_key.argtypes = [c_ubyte_p, c_size_t, C.POINTER(c_void_p)]
        self.lib.kq_session_open_from_key.restype = c_int

        # session: void kq_session_close(session)
        self.lib.kq_session_close.argtypes = [c_void_p]
        self.lib.kq_session_close.restype = None

        # session: int kq_session_decrypt(session, iv, ivlen, ct, ctlen, tag, taglen, out_pt)
        self.lib.kq_session_decrypt.argtypes = [
            c_void_p,
            c_ubyte_p, c_size_t,
            c_ubyte_p, c_size_t,
            c_ubyte_p, c_size_t,
            c_ubyte_p,
        ]
        self.lib.kq_session_decrypt.restype = c_int

        # session: int kq_session_encrypt(session, iv, ivlen, pt, ptlen, out_ct, out_tag, taglen)
        self.lib.kq_session_encrypt.argtypes = [
            c_void_p,
            c_ubyte_p, c_size_t,
            c_ubyte_p, c_size_t,
            c_ubyte_p,
            c_ubyte_p, c_size_t,
        ]
        self.lib.kq_session_encrypt.restype = c_int

    def version(self) -> int:
        return int(self.lib.kq_version())

    def crypto_backend(self) -> str:
        s = self.lib.kq_crypto_backend()
        return s.decode("utf-8", "replace") if s else "unknown"

    def secure_wipe(self, buf: bytearray) -> None:
        if not buf:
            return
        mv = memoryview(buf)
        ptr = C.c_void_p(C.addressof(C.c_ubyte.from_buffer(mv)))
        self.lib.secure_wipe(ptr, len(buf))

    # -----------------------------
    # Session mode (preferred)
    # -----------------------------
    def open_session(self, password_buf: bytearray, salt: Union[bytes, bytearray]) -> int:
        if not isinstance(password_buf, bytearray) or not password_buf:
            raise ValueError("password_buf must be a non-empty bytearray")

        # salt isn't secret; OK to copy if needed
        salt_ba = salt if isinstance(salt, bytearray) else bytearray(salt)
        if not salt_ba:
            raise ValueError("salt must be non-empty")

        out = c_void_p()
        rc = self.lib.kq_session_open(
            _as_ubyte_ptr(password_buf), len(password_buf),
            _as_ubyte_ptr(salt_ba), len(salt_ba),
            C.byref(out),
        )
        if rc != 0 or not out.value:
            raise RuntimeError(f"kq_session_open failed rc={rc}")
        return int(out.value)

    def open_session_from_key(self, key32: bytes | bytearray) -> int:
        if isinstance(key32, bytes):
            key_ba = bytearray(key32)
        else:
            key_ba = key32

        if len(key_ba) != 32:
            raise ValueError("key32 must be exactly 32 bytes")

        out = c_void_p()
        try:
            rc = self.lib.kq_session_open_from_key(
                _as_ubyte_ptr(key_ba), len(key_ba),
                C.byref(out)
            )
        finally:
            # Always wipe our temporary copy
            try:
                self.secure_wipe(key_ba)
            except Exception:
                pass

        if rc != 0 or not out.value:
            raise RuntimeError(f"kq_session_open_from_key failed rc={rc}")

        return int(out.value)

    def close_session(self, session_handle: Optional[int]) -> None:
        if not session_handle:
            return
        self.lib.kq_session_close(c_void_p(session_handle))

    def session_decrypt(self, session_handle: int, iv: bytes, ciphertext: bytes, tag: bytes) -> bytearray:
        if not session_handle:
            raise ValueError("session_handle missing/invalid")
        if len(tag) != KQ_TAG_LEN:
            raise ValueError("tag must be 16 bytes")
        if not iv:
            raise ValueError("iv must be non-empty")

        iv_ba = bytearray(iv)
        ct_ba = bytearray(ciphertext)
        tag_ba = bytearray(tag)

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

    def session_encrypt(self, session_handle: int, iv: bytes, plaintext: bytes) -> Tuple[bytearray, bytearray]:
        if not session_handle:
            raise ValueError("session_handle missing/invalid")
        if not iv:
            raise ValueError("iv must be non-empty")

        iv_ba = bytearray(iv)
        pt_ba = bytearray(plaintext)

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

    # -----------------------------
    # Legacy mode (compat)
    # -----------------------------
    def derive_vault_key(self, password_buf: bytearray, salt: Union[bytes, bytearray]) -> bytearray:
        if not isinstance(password_buf, bytearray) or not password_buf:
            raise ValueError("password_buf must be a non-empty bytearray")
        salt_ba = salt if isinstance(salt, bytearray) else bytearray(salt)
        out_key = bytearray(KQ_KEY_LEN)
        rc = self.lib.derive_vault_key(
            _as_ubyte_ptr(password_buf), len(password_buf),
            _as_ubyte_ptr(salt_ba),
            _as_ubyte_ptr(out_key),
        )
        if rc != 0:
            raise RuntimeError(f"derive_vault_key failed rc={rc}")
        return out_key

    def decrypt_vault(self, key32: bytearray, iv: bytes, ciphertext: bytes, tag16: bytes) -> bytearray:
        if not isinstance(key32, (bytearray, bytes)) or len(key32) != KQ_KEY_LEN:
            raise ValueError("key must be 32 bytes")
        key_ba = key32 if isinstance(key32, bytearray) else bytearray(key32)
        out_pt = bytearray(len(ciphertext))
        ct_ba = bytearray(ciphertext)
        iv_ba = bytearray(iv)
        tag_ba = bytearray(tag16)
        rc = self.lib.decrypt_vault(
            _as_ubyte_ptr(key_ba),
            _as_ubyte_ptr(iv_ba),
            _as_ubyte_ptr(ct_ba),
            len(ct_ba),
            _as_ubyte_ptr(tag_ba),
            _as_ubyte_ptr(out_pt),
        )
        if rc != 0:
            raise RuntimeError(f"decrypt_vault failed rc={rc}")
        return out_pt

    def encrypt_vault(self, key32: bytearray, iv: bytes, plaintext: bytes) -> Tuple[bytearray, bytearray]:
        if not isinstance(key32, (bytearray, bytes)) or len(key32) != KQ_KEY_LEN:
            raise ValueError("key must be 32 bytes")
        key_ba = key32 if isinstance(key32, bytearray) else bytearray(key32)
        pt_ba = bytearray(plaintext)
        iv_ba = bytearray(iv)
        out_ct = bytearray(len(pt_ba))
        out_tag = bytearray(KQ_TAG_LEN)
        rc = self.lib.encrypt_vault(
            _as_ubyte_ptr(key_ba),
            _as_ubyte_ptr(iv_ba),
            _as_ubyte_ptr(pt_ba),
            len(pt_ba),
            _as_ubyte_ptr(out_ct),
            _as_ubyte_ptr(out_tag),
        )
        if rc != 0:
            raise RuntimeError(f"encrypt_vault failed rc={rc}")
        return out_ct, out_tag
