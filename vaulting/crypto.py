"""Envelope encryption with AES-256-GCM (via the vetted `cryptography` package).

    secret value --AES-GCM(DEK)--> ciphertext          (stored)
    DEK          --AES-GCM(KEK)--> wrapped DEK         (stored next to it)
    KEK (master key) lives OUTSIDE the database: env var or a 0600 key file.

Why two layers?
  * Every secret version has its own random data key (DEK), so one compromised
    key never exposes everything.
  * Rotating the master key (KEK) only means re-wrapping small DEKs. The
    ciphertexts are never touched (see `rewrap`).
  * The Keyring has two methods (wrap/unwrap). A cloud KMS can implement the
    same two methods, which is how this design scales to a real deployment.

AAD (additional authenticated data) binds each ciphertext to its secret name
and version, so an attacker with DB write access cannot swap two rows' contents.
"""
import base64
import binascii
import os
import re
import stat
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12
_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class CryptoError(Exception):
    pass


def _b64decode(text: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError) as e:
        raise CryptoError("key is not valid base64") from e


class Keyring:
    """Master keys (KEKs) by id. New wraps use the active key; old ids still unwrap."""

    def __init__(self, keys: Dict[str, bytes], active_id: str):
        if not keys:
            raise CryptoError("keyring is empty")
        for kid, key in keys.items():
            if not _KEY_ID.match(kid):
                raise CryptoError(f"bad key id {kid!r} (use letters, digits, - or _)")
            if len(key) != KEY_BYTES:
                raise CryptoError(f"key {kid!r} must be exactly {KEY_BYTES} bytes")
        if active_id not in keys:
            raise CryptoError(f"active key {active_id!r} is not in the keyring")
        self._keys = dict(keys)
        self.active_id = active_id

    # ---- construction ------------------------------------------------------
    @classmethod
    def generate(cls, key_id: str = "k1") -> "Keyring":
        return cls({key_id: AESGCM.generate_key(256)}, key_id)

    @staticmethod
    def new_key_b64() -> str:
        return base64.b64encode(AESGCM.generate_key(256)).decode()

    @classmethod
    def from_spec(cls, spec: str, active_id: Optional[str] = None) -> "Keyring":
        """spec = 'k1:<base64>,k2:<base64>' (commas or newlines). Last key is active by default."""
        keys: Dict[str, bytes] = {}
        order = []
        for part in spec.replace("\n", ",").split(","):
            part = part.strip()
            if not part:
                continue
            if ":" not in part:
                raise CryptoError("key entries look like <id>:<base64>")
            kid, b64 = part.split(":", 1)
            keys[kid.strip()] = _b64decode(b64)
            order.append(kid.strip())
        if not keys:
            raise CryptoError("no keys found")
        return cls(keys, active_id or order[-1])

    @classmethod
    def from_env(cls, environ=None) -> "Keyring":
        env = os.environ if environ is None else environ
        active = env.get("VAULTING_ACTIVE_KEY")
        path = env.get("VAULTING_KEY_FILE")
        if path:
            mode = os.stat(path).st_mode
            if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise CryptoError(f"{path} must not be readable by group/others (chmod 600)")
            with open(path) as fh:
                return cls.from_spec(fh.read(), active)
        spec = env.get("VAULTING_KEYS")
        if spec:
            return cls.from_spec(spec, active)
        raise CryptoError(
            "no encryption key configured. Run `python -m vaulting keygen` and set "
            "VAULTING_KEYS or VAULTING_KEY_FILE")

    def spec(self) -> str:
        return ",".join(f"{k}:{base64.b64encode(v).decode()}" for k, v in self._keys.items())

    # ---- the two operations a KMS backend would also implement -------------
    def wrap(self, dek: bytes, aad: bytes) -> Tuple[str, bytes, bytes]:
        nonce = os.urandom(NONCE_BYTES)
        wrapped = AESGCM(self._keys[self.active_id]).encrypt(nonce, dek, self._wrap_aad(aad, self.active_id))
        return self.active_id, nonce, wrapped

    def unwrap(self, kek_id: str, nonce: bytes, wrapped: bytes, aad: bytes) -> bytes:
        if kek_id not in self._keys:
            raise CryptoError(f"master key {kek_id!r} is not available; cannot decrypt")
        try:
            return AESGCM(self._keys[kek_id]).decrypt(nonce, wrapped, self._wrap_aad(aad, kek_id))
        except InvalidTag as e:
            raise CryptoError("decryption failed: wrong key or tampered data") from e

    @staticmethod
    def _wrap_aad(aad: bytes, kek_id: str) -> bytes:
        return aad + b"|kek:" + kek_id.encode()


@dataclass
class Sealed:
    ciphertext: bytes
    nonce: bytes
    wrapped_dek: bytes
    dek_nonce: bytes
    kek_id: str


def seal(keyring: Keyring, plaintext: bytes, aad: bytes) -> Sealed:
    dek = AESGCM.generate_key(256)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    kek_id, dek_nonce, wrapped = keyring.wrap(dek, aad)
    return Sealed(ciphertext, nonce, wrapped, dek_nonce, kek_id)


def open_sealed(keyring: Keyring, s: Sealed, aad: bytes) -> bytes:
    dek = keyring.unwrap(s.kek_id, s.dek_nonce, s.wrapped_dek, aad)
    try:
        return AESGCM(dek).decrypt(s.nonce, s.ciphertext, aad)
    except InvalidTag as e:
        raise CryptoError("decryption failed: wrong key or tampered data") from e


def rewrap(keyring: Keyring, s: Sealed, aad: bytes) -> Sealed:
    """Move a sealed value to the active master key WITHOUT touching its ciphertext."""
    dek = keyring.unwrap(s.kek_id, s.dek_nonce, s.wrapped_dek, aad)
    kek_id, dek_nonce, wrapped = keyring.wrap(dek, aad)
    return Sealed(s.ciphertext, s.nonce, wrapped, dek_nonce, kek_id)
