import ctypes as C
import os
from typing import Optional, Tuple, Union

# ---- ctypes types ----
c_ubyte = C.c_ubyte
c_ubyte_p = C.POINTER(c_ubyte)
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
        raise TypeError("Buffer must be writable")
    return C.cast(C.c_void_p(C.addressof(c_ubyte.from_buffer(mv))), c_ubyte_p)


def _as_ubyte_ptr_copy(b: bytes) -> c_ubyte_p:
    """Pointer to a COPY of read-only bytes (for inputs)."""
    arr = (c_ubyte * len(b)).from_buffer_copy(b)
    return C.cast(arr, c_ubyte_p)


class KeyquorumCore:
    """Native crypto wrapper.

    Strict/secure mode:
      - open_session() returns an opaque session handle (pointer value as int)
      - session_encrypt()/session_decrypt() use keys stored inside the DLL
      - close_session() wipes keys inside the DLL

    Optional Windows DPAPI:
      - dpapi_unprotect_to_session() opens a native session without returning the key to Python
      - session_export_key_dpapi() exports the current session key as a DPAPI blob (still encrypted)
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

        # Optional (KDF-v2): int kq_session_open_ex(pw, pwlen, salt, saltlen, time_cost, memory_kib, parallelism, out_session)
        # Newer DLLs export this to support per-vault Argon2id parameters (no Python fallback required).
        self._has_session_open_ex = False
        try:
            self.lib.kq_session_open_ex.argtypes = [
                c_ubyte_p, c_size_t,        # pw, pwlen
                c_ubyte_p, c_size_t,        # salt, saltlen
                c_int, c_int, c_int,        # time_cost, memory_kib, parallelism
                C.POINTER(c_void_p),        # out_session
            ]
            self.lib.kq_session_open_ex.restype = c_int
            self._has_session_open_ex = True
        except Exception:
            self._has_session_open_ex = False

        # Optional (KDF-v2): int derive_vault_key_ex(pw, pwlen, salt, saltlen, time_cost, memory_kib, parallelism, out_key32)
        self._has_derive_vault_key_ex = False
        try:
            self.lib.derive_vault_key_ex.argtypes = [
                c_ubyte_p, c_size_t,        # pw, pwlen
                c_ubyte_p, c_size_t,        # salt, saltlen
                c_int, c_int, c_int,        # time_cost, memory_kib, parallelism
                c_ubyte_p,                  # out_key32
            ]
            self.lib.derive_vault_key_ex.restype = c_int
            self._has_derive_vault_key_ex = True
        except Exception:
            self._has_derive_vault_key_ex = False

        # session: int kq_session_open_from_key(key32, key_len, out_session)
        self.lib.kq_session_open_from_key.argtypes = [c_ubyte_p, c_size_t, C.POINTER(c_void_p)]
        self.lib.kq_session_open_from_key.restype = c_int

        # session: void kq_session_close(session)
        self.lib.kq_session_close.argtypes = [c_void_p]
        self.lib.kq_session_close.restype = None

        # session: int kq_session_decrypt(session, iv, ivlen, ct, ctlen, tag, taglen, out_pt)
        self.lib.kq_session_decrypt.argtypes = [
            c_void_p,
            c_ubyte_p,
            c_size_t,
            c_ubyte_p,
            c_size_t,
            c_ubyte_p,
            c_size_t,
            c_ubyte_p,
        ]
        self.lib.kq_session_decrypt.restype = c_int

        # session: int kq_session_encrypt(session, iv, ivlen, pt, ptlen, out_ct, out_tag, taglen)
        self.lib.kq_session_encrypt.argtypes = [
            c_void_p,
            c_ubyte_p,
            c_size_t,
            c_ubyte_p,
            c_size_t,
            c_ubyte_p,
            c_ubyte_p,
            c_size_t,
        ]
        self.lib.kq_session_encrypt.restype = c_int

        # session key wrap/unwrap
        self.lib.kq_session_wrap_session_key.argtypes = [
            c_void_p,
            c_void_p,
            c_ubyte_p,
            c_size_t,
            c_ubyte_p,
            c_size_t,
            c_ubyte_p,
            c_size_t,
        ]
        self.lib.kq_session_wrap_session_key.restype = c_int

        self.lib.kq_session_unwrap_to_session.argtypes = [
            c_void_p,
            c_ubyte_p,
            c_size_t,
            c_ubyte_p,
            c_size_t,
            c_ubyte_p,
            c_size_t,
            C.POINTER(c_void_p),
        ]
        self.lib.kq_session_unwrap_to_session.restype = c_int

        # Optional DPAPI exports (Windows)
        self._has_dpapi = False
        self._has_dpapi_to_session = False
        self._has_session_export_dpapi = False
        self._bind_optional_dpapi_exports()

    # -------------------------
    # Info / wipe
    # -------------------------
    def version(self) -> int:
        return int(self.lib.kq_version())

    def crypto_backend(self) -> str:
        s = self.lib.kq_crypto_backend()
        return s.decode("utf-8", "replace") if s else "unknown"

    def secure_wipe(self, buf: bytearray) -> None:
        if not buf:
            return
        mv = memoryview(buf)
        ptr = C.c_void_p(C.addressof(c_ubyte.from_buffer(mv)))
        self.lib.secure_wipe(ptr, len(buf))

    # -------------------------
    # Session mode (preferred)
    # -------------------------
    def open_session(self, password_buf: bytearray, salt: Union[bytes, bytearray]) -> int:
        if not isinstance(password_buf, bytearray) or not password_buf:
            raise ValueError("password_buf must be a non-empty bytearray")

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


    def has_session_open_ex(self) -> bool:
        return bool(getattr(self, "_has_session_open_ex", False))

    def open_session_ex(
        self,
        password_buf: bytearray,
        salt: Union[bytes, bytearray],
        *,
        time_cost: int,
        memory_kib: int,
        parallelism: int,
    ) -> int:
        """Open a native session using explicit Argon2id parameters (KDF-v2).

        Raises RuntimeError if the export is not available in the loaded DLL.
        """
        if not self.has_session_open_ex():
            raise RuntimeError("kq_session_open_ex export not available in this DLL")

        if not isinstance(password_buf, bytearray) or not password_buf:
            raise ValueError("password_buf must be a non-empty bytearray")

        salt_ba = salt if isinstance(salt, bytearray) else bytearray(salt)
        if not salt_ba:
            raise ValueError("salt must be non-empty")

        out = c_void_p()
        rc = self.lib.kq_session_open_ex(
            _as_ubyte_ptr(password_buf), len(password_buf),
            _as_ubyte_ptr(salt_ba), len(salt_ba),
            int(time_cost), int(memory_kib), int(parallelism),
            C.byref(out),
        )
        if rc != 0 or not out.value:
            raise RuntimeError(f"kq_session_open_ex failed rc={rc}")
        return int(out.value)

    def has_derive_vault_key_ex(self) -> bool:
        return bool(getattr(self, "_has_derive_vault_key_ex", False))

    def derive_vault_key_ex(
        self,
        password_buf: bytearray,
        salt: bytes,
        *,
        time_cost: int,
        memory_kib: int,
        parallelism: int,
    ) -> bytes:
        """Derive a 32-byte vault key using explicit Argon2id parameters (KDF-v2)."""
        if not self.has_derive_vault_key_ex():
            raise RuntimeError("derive_vault_key_ex export not available in this DLL")

        if not isinstance(password_buf, bytearray) or not password_buf:
            raise ValueError("password_buf must be non-empty bytearray")
        if not isinstance(salt, (bytes, bytearray, memoryview)) or not bytes(salt):
            raise ValueError("salt must be non-empty bytes")

        salt_ba = bytearray(bytes(salt))
        out_key = bytearray(32)
        rc = self.lib.derive_vault_key_ex(
            _as_ubyte_ptr(password_buf), len(password_buf),
            _as_ubyte_ptr(salt_ba), len(salt_ba),
            int(time_cost), int(memory_kib), int(parallelism),
            _as_ubyte_ptr(out_key),
        )
        if rc != 0:
            raise RuntimeError(f"derive_vault_key_ex failed rc={rc}")
        return bytes(out_key)

    def open_session_auto(self, password_buf: bytearray, salt: Union[bytes, bytearray], kdf: Optional[dict] = None) -> int:
        """Convenience: open v2 session if params provided + export exists, else fall back to legacy open_session()."""
        if kdf and self.has_session_open_ex():
            return self.open_session_ex(
                password_buf, salt,
                time_cost=int(kdf.get("time_cost", 3)),
                memory_kib=int(kdf.get("memory_kib", 256_000)),
                parallelism=int(kdf.get("parallelism", 2)),
            )
        return self.open_session(password_buf, salt)

    def open_session_from_key(self, key32: Union[bytes, bytearray]) -> int:
        key_ba = bytearray(key32) if isinstance(key32, (bytes, bytearray, memoryview)) else None
        if key_ba is None or len(key_ba) != 32:
            raise ValueError("key32 must be exactly 32 bytes")

        out = c_void_p()
        try:
            rc = self.lib.kq_session_open_from_key(
                _as_ubyte_ptr(key_ba), len(key_ba),
                C.byref(out),
            )
        finally:
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
        self.lib.kq_session_close(c_void_p(int(session_handle)))

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
            c_void_p(int(session_handle)),
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
            c_void_p(int(session_handle)),
            _as_ubyte_ptr(iv_ba), len(iv_ba),
            _as_ubyte_ptr(pt_ba), len(pt_ba),
            _as_ubyte_ptr(out_ct),
            _as_ubyte_ptr(out_tag), len(out_tag),
        )
        if rc != 0:
            raise RuntimeError(f"kq_session_encrypt failed rc={rc}")
        return out_ct, out_tag

    def session_wrap_session_key(self, key_session_handle: int, wrapping_session_handle: int) -> Tuple[bytearray, bytearray, bytearray]:
        if not key_session_handle or not wrapping_session_handle:
            raise ValueError("session handles missing/invalid")

        out_iv = bytearray(12)
        out_ct = bytearray(32)
        out_tag = bytearray(KQ_TAG_LEN)

        rc = self.lib.kq_session_wrap_session_key(
            c_void_p(int(key_session_handle)),
            c_void_p(int(wrapping_session_handle)),
            _as_ubyte_ptr(out_iv), len(out_iv),
            _as_ubyte_ptr(out_ct), len(out_ct),
            _as_ubyte_ptr(out_tag), len(out_tag),
        )
        if rc != 0:
            raise RuntimeError(f"kq_session_wrap_session_key failed rc={rc}")
        return out_iv, out_ct, out_tag

    def session_unwrap_to_session(self, wrapping_session_handle: int, iv: bytes, ciphertext32: bytes, tag: bytes) -> int:
        if not wrapping_session_handle:
            raise ValueError("wrapping_session_handle missing/invalid")
        if len(iv) != 12:
            raise ValueError("iv must be 12 bytes")
        if len(ciphertext32) != 32:
            raise ValueError("ciphertext must be 32 bytes")
        if len(tag) != KQ_TAG_LEN:
            raise ValueError("tag must be 16 bytes")

        iv_ba = bytearray(iv)
        ct_ba = bytearray(ciphertext32)
        tag_ba = bytearray(tag)

        out = c_void_p()
        rc = self.lib.kq_session_unwrap_to_session(
            c_void_p(int(wrapping_session_handle)),
            _as_ubyte_ptr(iv_ba), len(iv_ba),
            _as_ubyte_ptr(ct_ba), len(ct_ba),
            _as_ubyte_ptr(tag_ba), len(tag_ba),
            C.byref(out),
        )
        if rc != 0 or not out.value:
            raise RuntimeError(f"kq_session_unwrap_to_session failed rc={rc}")
        return int(out.value)

    # -------------------------
    # Legacy helpers (compat)
    # -------------------------
    def derive_vault_key(self, password_buf: bytearray, salt: bytes) -> bytes:
        if not isinstance(password_buf, bytearray) or not password_buf:
            raise ValueError("password_buf must be non-empty bytearray")
        if not isinstance(salt, (bytes, bytearray, memoryview)) or not bytes(salt):
            raise ValueError("salt must be non-empty bytes")

        salt_ba = bytearray(bytes(salt))
        out_key = bytearray(32)
        rc = self.lib.derive_vault_key(
            _as_ubyte_ptr(password_buf), len(password_buf),
            _as_ubyte_ptr(salt_ba),
            _as_ubyte_ptr(out_key),
        )
        if rc != 0:
            raise RuntimeError(f"derive_vault_key failed rc={rc}")
        return bytes(out_key)

    # -------------------------
    # Optional DPAPI helpers
    # -------------------------
    def _bind_optional_dpapi_exports(self) -> None:
        # These may not exist in older DLLs.
        try:
            self.lib.kq_dpapi_protect.argtypes = [
                c_ubyte_p, c_size_t,
                c_ubyte_p, c_size_t,
                C.POINTER(c_void_p), C.POINTER(c_size_t),
            ]
            self.lib.kq_dpapi_protect.restype = c_int

            self.lib.kq_dpapi_unprotect.argtypes = [
                c_ubyte_p, c_size_t,
                c_ubyte_p, c_size_t,
                C.POINTER(c_void_p), C.POINTER(c_size_t),
            ]
            self.lib.kq_dpapi_unprotect.restype = c_int

            self.lib.kq_dpapi_free.argtypes = [c_void_p]
            self.lib.kq_dpapi_free.restype = None

            # Optional: int kq_dpapi_unprotect_to_session(blob, blob_len, entropy, entropy_len, out_session)
            try:
                self.lib.kq_dpapi_unprotect_to_session.argtypes = [
                    c_ubyte_p, c_size_t,
                    c_ubyte_p, c_size_t,
                    C.POINTER(c_void_p),
                ]
                self.lib.kq_dpapi_unprotect_to_session.restype = c_int
                self._has_dpapi_to_session = True
            except Exception:
                self._has_dpapi_to_session = False

            # Optional: int kq_session_export_key_dpapi(session, entropy, entropy_len, out_ptr, out_len)
            try:
                self.lib.kq_session_export_key_dpapi.argtypes = [
                    c_void_p,
                    c_ubyte_p, c_size_t,
                    C.POINTER(c_void_p), C.POINTER(c_size_t),
                ]
                self.lib.kq_session_export_key_dpapi.restype = c_int
                self._has_session_export_dpapi = True
            except Exception:
                self._has_session_export_dpapi = False

            self._has_dpapi = True
        except Exception:
            self._has_dpapi = False
            self._has_dpapi_to_session = False
            self._has_session_export_dpapi = False

    def dpapi_unprotect_to_session(self, blob: bytes, entropy: bytes = b"") -> int:
        if not self._has_dpapi_to_session:
            raise RuntimeError("DPAPI-to-session export not available in this DLL")
        blob_b = bytes(blob or b"")
        ent_b = bytes(entropy or b"")
        if not blob_b:
            raise ValueError("blob must be non-empty")

        out = c_void_p()
        rc = self.lib.kq_dpapi_unprotect_to_session(
            _as_ubyte_ptr_copy(blob_b), len(blob_b),
            _as_ubyte_ptr_copy(ent_b) if ent_b else _as_ubyte_ptr_copy(b""),
            len(ent_b),
            C.byref(out),
        )
        if rc != 0 or not out.value:
            raise RuntimeError(f"kq_dpapi_unprotect_to_session failed rc={rc}")
        return int(out.value)

    def session_export_key_dpapi(self, session_handle: int, entropy: bytes) -> bytes:
        """Export the current session's 32-byte key into a DPAPI-protected blob (key never returned to Python)."""
        if not self._has_session_export_dpapi:
            raise RuntimeError("kq_session_export_key_dpapi export not available in this DLL")
        if not session_handle:
            raise ValueError("session_handle missing")
        ent_b = bytes(entropy or b"")
        if not ent_b:
            raise ValueError("entropy must be non-empty")

        out_ptr = c_void_p()
        out_len = c_size_t(0)
        rc = self.lib.kq_session_export_key_dpapi(
            c_void_p(int(session_handle)),
            _as_ubyte_ptr_copy(ent_b), len(ent_b),
            C.byref(out_ptr), C.byref(out_len),
        )
        if rc != 0 or not out_ptr.value or int(out_len.value) <= 0:
            raise RuntimeError(f"kq_session_export_key_dpapi failed rc={rc}")

        try:
            data = C.string_at(out_ptr, int(out_len.value))
            return data
        finally:
            try:
                self.lib.kq_dpapi_free(out_ptr)
            except Exception:
                pass


__all__ = ["KeyquorumCore", "KQ_TAG_LEN", "KQ_KEY_LEN"]
