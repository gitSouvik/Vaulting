"""
vaulting/native.py — Python bridge to the Vaulting C core.

Loads libvaulting_core.{dylib,so} from the package directory and exposes
three APIs:

  scanner   — Aho-Corasick multi-pattern matcher (O(n) scan)
  secure_mem — mlock'd secure buffer allocation/zeroing
  shamir     — GF(2^8) Shamir secret sharing split/combine

The library is loaded lazily on first use.  If the shared library is not
found or fails to load, all functions fall back gracefully to pure-Python
equivalents so that the rest of the package continues to work.
"""

from __future__ import annotations

import ctypes
import os
import platform
import threading
from pathlib import Path
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

_lib: Optional[ctypes.CDLL] = None
_lib_lock = threading.Lock()


def _find_lib() -> Optional[Path]:
    """Locate the compiled shared library next to this .py file."""
    here = Path(__file__).parent
    ext = "dylib" if platform.system() == "Darwin" else "so"
    candidate = here / f"libvaulting_core.{ext}"
    return candidate if candidate.exists() else None


def _load_lib() -> Optional[ctypes.CDLL]:
    global _lib
    if _lib is not None:
        return _lib
    with _lib_lock:
        if _lib is not None:
            return _lib
        path = _find_lib()
        if path is None:
            return None
        try:
            lib = ctypes.CDLL(str(path))
            _configure_lib(lib)
            _lib = lib
        except OSError:
            _lib = None
    return _lib


def _configure_lib(lib: ctypes.CDLL) -> None:
    """Set argtypes / restypes for all exported C functions."""
    # --- ACScan / scanner ---
    lib.acs_new.restype  = ctypes.c_void_p
    lib.acs_new.argtypes = []

    lib.acs_add_pattern.restype  = ctypes.c_int
    lib.acs_add_pattern.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
    ]

    lib.acs_build.restype  = ctypes.c_int
    lib.acs_build.argtypes = [ctypes.c_void_p]

    lib.acs_search.restype  = None
    lib.acs_search.argtypes = [
        ctypes.c_void_p,    # ac
        ctypes.c_char_p,    # text
        ctypes.c_size_t,    # tlen
        ctypes.c_void_p,    # callback (CFUNCTYPE)
        ctypes.c_void_p,    # userdata
    ]

    lib.acs_free.restype  = None
    lib.acs_free.argtypes = [ctypes.c_void_p]

    lib.acs_pattern_count.restype  = ctypes.c_size_t
    lib.acs_pattern_count.argtypes = [ctypes.c_void_p]

    # --- secure_mem ---
    # SecureBuffer layout: data (ptr), len (size_t), _alloc_size (size_t)
    # We only use vlt_explicit_zero from Python (alloc/free stay in C)

    lib.vlt_explicit_zero.restype  = None
    lib.vlt_explicit_zero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

    lib.vlt_consttime_memcmp.restype  = ctypes.c_int
    lib.vlt_consttime_memcmp.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
    ]

    # --- Shamir ---
    lib.shamir_split.restype  = ctypes.c_int
    lib.shamir_split.argtypes = [
        ctypes.c_char_p,   # secret
        ctypes.c_size_t,   # secret_len
        ctypes.c_uint8,    # k
        ctypes.c_uint8,    # n
        ctypes.c_char_p,   # shares_out
    ]

    lib.shamir_combine.restype  = ctypes.c_int
    lib.shamir_combine.argtypes = [
        ctypes.POINTER(ctypes.c_char_p),  # shares (array of pointers)
        ctypes.c_uint8,                   # k
        ctypes.c_size_t,                  # secret_len
        ctypes.c_char_p,                  # secret_out
    ]


# ---------------------------------------------------------------------------
# AhoCorasickScanner
# ---------------------------------------------------------------------------

# Match callback type: (pos: size_t, pattern_id: uint32, userdata: void*) -> int
_ACS_CB_TYPE = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_size_t,
    ctypes.c_uint32,
    ctypes.c_void_p,
)


class AhoCorasickScanner:
    """
    Multi-pattern O(n) scanner backed by the C Aho-Corasick DFA.

    Usage::

        s = AhoCorasickScanner()
        s.add_pattern(b"secret1", pid=0)
        s.add_pattern(b"token_abc", pid=1)
        s.build()
        matches = s.search(text_bytes)
        # matches: list of (end_pos, pattern_id)

    Falls back to a naive Python scan if the library is unavailable.
    """

    def __init__(self) -> None:
        self._lib = _load_lib()
        self._patterns: list[tuple[bytes, int]] = []  # for Python fallback
        self._built = False
        if self._lib:
            self._handle = self._lib.acs_new()
        else:
            self._handle = None

    def add_pattern(self, pattern: bytes, pid: int = 0) -> None:
        if not pattern:
            return
        self._patterns.append((pattern, pid))
        if self._lib and self._handle:
            self._lib.acs_add_pattern(
                self._handle, pattern, len(pattern), pid
            )

    def build(self) -> None:
        self._built = True
        if self._lib and self._handle:
            self._lib.acs_build(self._handle)

    def search(self, text: bytes) -> list[tuple[int, int]]:
        """Return list of (end_byte_pos, pattern_id) for every match."""
        if not self._built:
            self.build()
        if self._lib and self._handle:
            return self._search_native(text)
        return self._search_python(text)

    def _search_native(self, text: bytes) -> list[tuple[int, int]]:
        results: list[tuple[int, int]] = []

        @_ACS_CB_TYPE
        def _cb(pos: int, pid: int, _ud: object) -> int:  # type: ignore[override]
            results.append((pos, pid))
            return 0  # continue

        self._lib.acs_search(
            self._handle, text, len(text), _cb, None
        )
        return results

    def _search_python(self, text: bytes) -> list[tuple[int, int]]:
        """Naive O(n*m) Python fallback."""
        results: list[tuple[int, int]] = []
        for pattern, pid in self._patterns:
            start = 0
            while True:
                idx = text.find(pattern, start)
                if idx == -1:
                    break
                results.append((idx + len(pattern) - 1, pid))
                start = idx + 1
        return results

    def __del__(self) -> None:
        if self._lib and self._handle:
            try:
                self._lib.acs_free(self._handle)
            except Exception:
                pass
        self._handle = None


# ---------------------------------------------------------------------------
# Secure memory helpers (Python-level wrappers)
# ---------------------------------------------------------------------------

def explicit_zero(buf: bytearray) -> None:
    """
    Zero a bytearray in-place using the C explicit_zero routine
    (resistant to compiler dead-store elimination).
    Falls back to a Python loop if the library is unavailable.
    """
    lib = _load_lib()
    if lib and len(buf) > 0:
        ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
        lib.vlt_explicit_zero(ptr, len(buf))
    else:
        for i in range(len(buf)):
            buf[i] = 0


def consttime_eq(a: bytes | bytearray, b: bytes | bytearray) -> bool:
    """Constant-time byte comparison (no short-circuit)."""
    if len(a) != len(b):
        return False
    lib = _load_lib()
    if lib:
        ba = (ctypes.c_char * len(a)).from_buffer_copy(a)
        bb = (ctypes.c_char * len(b)).from_buffer_copy(b)
        return lib.vlt_consttime_memcmp(ba, bb, len(a)) == 0
    # Python fallback
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


class SecureBuffer:
    """
    Guarded memory buffer that explicitly zeroes its contents on close or garbage collection.
    """

    def __init__(self, data: bytes | bytearray | int) -> None:
        if isinstance(data, int):
            self._buf = bytearray(data)
        else:
            self._buf = bytearray(data)

    @property
    def data(self) -> bytearray:
        return self._buf

    def __len__(self) -> int:
        return len(self._buf)

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.wipe()

    def wipe(self) -> None:
        if self._buf:
            explicit_zero(self._buf)

    def __del__(self) -> None:
        self.wipe()


# ---------------------------------------------------------------------------
# Shamir's Secret Sharing
# ---------------------------------------------------------------------------

def shamir_split(secret: bytes, k: int, n: int) -> list[bytes]:
    """
    Split *secret* into *n* shares, any *k* of which reconstruct it.

    Returns a list of n share blobs.  Each blob is
    ``1 + len(secret)`` bytes: [x-coord byte] [y-coord bytes...].

    Uses the C implementation if available, otherwise raises RuntimeError.
    """
    if not 1 <= k <= n <= 255:
        raise ValueError(f"Invalid threshold: k={k}, n={n}")
    if not secret:
        raise ValueError("Secret must be non-empty")

    lib = _load_lib()
    if lib:
        return _shamir_split_native(lib, secret, k, n)
    return _shamir_split_python(secret, k, n)


def shamir_combine(shares: list[bytes], secret_len: int) -> bytes:
    """
    Reconstruct a secret from *k* or more shares.

    *shares* must be a list of share blobs as returned by :func:`shamir_split`.
    *secret_len* is the length of the original secret.
    """
    if not shares:
        raise ValueError("No shares provided")
    if secret_len <= 0:
        raise ValueError("secret_len must be positive")

    lib = _load_lib()
    if lib:
        return _shamir_combine_native(lib, shares, secret_len)
    return _shamir_combine_python(shares, secret_len)


def _shamir_split_native(
    lib: ctypes.CDLL, secret: bytes, k: int, n: int
) -> list[bytes]:
    stride = 1 + len(secret)
    out_buf = ctypes.create_string_buffer(n * stride)
    rc = lib.shamir_split(secret, len(secret), k, n, out_buf)
    if rc != 0:
        raise RuntimeError("shamir_split() C call failed")
    raw = bytes(out_buf)
    return [raw[i * stride : (i + 1) * stride] for i in range(n)]


def _shamir_combine_native(
    lib: ctypes.CDLL, shares: list[bytes], secret_len: int
) -> bytes:
    k = len(shares)
    # Build a C array of char* pointers
    ptrs = (ctypes.c_char_p * k)(*[ctypes.cast(ctypes.c_char_p(s), ctypes.c_char_p) for s in shares])
    out_buf = ctypes.create_string_buffer(secret_len)
    rc = lib.shamir_combine(ptrs, k, secret_len, out_buf)
    if rc != 0:
        raise RuntimeError("shamir_combine() C call failed")
    return bytes(out_buf)


# ---------------------------------------------------------------------------
# Pure-Python Shamir fallback (GF(2^8) with generator 3)
# ---------------------------------------------------------------------------

def _gf_tables() -> tuple[list[int], list[int]]:
    """Build GF(2^8) log/exp tables with generator 3 (matching C implementation)."""
    exp = [0] * 510
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        # multiply by 3 in GF(2^8): x * 3 = x * (2+1) = x<<1 ^ x, then reduce
        x2 = (x << 1) ^ (0x1B if x & 0x80 else 0)
        x = (x2 ^ x) & 0xFF
    exp[255] = 1
    for i in range(255):
        exp[255 + i] = exp[i]
    for i in range(255):
        log[exp[i]] = i
    return exp, log


_GF_EXP, _GF_LOG = _gf_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_div(a: int, b: int) -> int:
    if a == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] - _GF_LOG[b] + 255]


def _poly_eval(coeff: list[int], x: int) -> int:
    """Horner's method in GF(2^8)."""
    result = 0
    for c in reversed(coeff):
        result = c ^ _gf_mul(result, x)
    return result


def _shamir_split_python(secret: bytes, k: int, n: int) -> list[bytes]:
    import os as _os

    shares = [[0] * (1 + len(secret)) for _ in range(n)]
    for i in range(n):
        shares[i][0] = i + 1  # x-coordinate

    rand_bytes = _os.urandom(len(secret) * (k - 1))
    ri = 0
    for b_idx, s_byte in enumerate(secret):
        coeff = [s_byte] + [rand_bytes[ri + j] for j in range(k - 1)]
        ri += k - 1
        for i in range(n):
            shares[i][1 + b_idx] = _poly_eval(coeff, i + 1)

    return [bytes(s) for s in shares]


def _shamir_combine_python(shares: list[bytes], secret_len: int) -> bytes:
    k = len(shares)
    xs = [s[0] for s in shares]
    result = bytearray(secret_len)
    for b_idx in range(secret_len):
        val = 0
        for i in range(k):
            yi = shares[i][1 + b_idx]
            num = 1
            den = 1
            for j in range(k):
                if j == i:
                    continue
                num = _gf_mul(num, xs[j])
                den = _gf_mul(den, xs[j] ^ xs[i])
            val ^= _gf_mul(yi, _gf_div(num, den))
        result[b_idx] = val
    return bytes(result)


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

def native_available() -> bool:
    """Return True if the C shared library was loaded successfully."""
    return _load_lib() is not None


def native_info() -> dict:
    """Return version/path info about the loaded native library."""
    lib = _load_lib()
    path = _find_lib()
    return {
        "available": lib is not None,
        "path": str(path) if path else None,
    }
