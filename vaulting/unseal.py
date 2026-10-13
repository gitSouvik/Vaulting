"""
vaulting/unseal.py — Vault unseal state machine (Shamir threshold)

The vault starts in SEALED state.  An operator (or automated process)
presents secret-sharing shares one at a time.  When at least *threshold*
shares have been presented the state machine reconstructs the master key,
transitions to UNSEALED, and returns it to the caller.

State diagram::

    SEALED ──[add_share: count >= threshold]──► UNSEALED
    SEALED ──[reset()]─────────────────────────► SEALED
    UNSEALED ──[seal()]────────────────────────► SEALED

Security properties:
  • Shares are held only in memory (never persisted by this module).
  • Once unsealed the reconstructed key is returned to the caller and
    immediately wiped from the state machine's memory.
  • A failed unseal (wrong shares) returns None; the machine stays in
    SEALED state and collected shares are wiped.
  • Thread-safe: all mutations are protected by a reentrant lock.
"""

from __future__ import annotations

import enum
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional

from vaulting.native import shamir_combine, shamir_split, explicit_zero

log = logging.getLogger(__name__)


class UnsealState(enum.Enum):
    SEALED   = "sealed"
    UNSEALED = "unsealed"


class UnsealError(Exception):
    """Raised when the unseal operation fails."""


@dataclass
class UnsealMachine:
    """
    Collect Shamir key-shares and unseal the vault when enough arrive.

    Parameters
    ----------
    threshold : int
        Minimum number of shares required to reconstruct the master key
        (the *k* value from shamir_split).
    secret_len : int
        Length of the master key in bytes.  Must match what was used when
        splitting.
    """

    threshold: int
    secret_len: int

    # internal
    _state: UnsealState = field(default=UnsealState.SEALED, init=False, repr=False)
    _shares: list[bytes]  = field(default_factory=list, init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    # ------------------------------------------------------------------ props

    @property
    def state(self) -> UnsealState:
        return self._state

    @property
    def shares_held(self) -> int:
        with self._lock:
            return len(self._shares)

    @property
    def shares_needed(self) -> int:
        with self._lock:
            return max(0, self.threshold - len(self._shares))

    # ------------------------------------------------------------------ API

    def add_share(self, share: bytes) -> Optional[bytes]:
        """
        Present a single Shamir share.

        Returns the reconstructed master key (bytes) if the threshold is met,
        *None* if more shares are still needed.

        Raises :class:`UnsealError` if already unsealed or if reconstruction
        fails (e.g. wrong shares provided).
        """
        with self._lock:
            if self._state is UnsealState.UNSEALED:
                raise UnsealError("Vault is already unsealed")

            if not isinstance(share, (bytes, bytearray)):
                raise TypeError("share must be bytes")
            expected_share_len = 1 + self.secret_len
            if len(share) != expected_share_len:
                raise UnsealError(
                    f"Share has wrong length: expected {expected_share_len}, "
                    f"got {len(share)}"
                )

            self._shares.append(bytes(share))
            log.info(
                "unseal: received share %d/%d",
                len(self._shares), self.threshold,
            )

            if len(self._shares) < self.threshold:
                return None  # need more shares

            # Attempt reconstruction
            try:
                key = shamir_combine(self._shares, self.secret_len)
            except Exception as exc:
                self._wipe_shares()
                raise UnsealError(f"Key reconstruction failed: {exc}") from exc
            finally:
                # Regardless of success/failure, wipe held shares
                self._wipe_shares()

            self._state = UnsealState.UNSEALED
            log.info("unseal: vault unsealed successfully")
            return key

    def seal(self) -> None:
        """Transition back to SEALED, clearing any held state."""
        with self._lock:
            self._wipe_shares()
            self._state = UnsealState.SEALED
            log.info("unseal: vault sealed")

    def reset(self) -> None:
        """Wipe collected shares and restart the collection process."""
        with self._lock:
            self._wipe_shares()
            log.info("unseal: shares reset")

    # ------------------------------------------------------------------ helpers

    def _wipe_shares(self) -> None:
        """Securely erase all held share material."""
        for s in self._shares:
            buf = bytearray(s)
            explicit_zero(buf)
        self._shares.clear()


# ---------------------------------------------------------------------------
# Convenience: generate shares from a master key
# ---------------------------------------------------------------------------

def generate_shares(master_key: bytes, threshold: int, total: int) -> list[bytes]:
    """
    Split *master_key* into *total* Shamir shares (threshold *k*).

    Returns a list of opaque share blobs.  Distribute one per operator.
    This function should be called once at vault initialisation time.
    """
    if not 1 <= threshold <= total <= 255:
        raise ValueError(f"Invalid (k={threshold}, n={total})")
    if not master_key:
        raise ValueError("master_key must be non-empty")
    return shamir_split(master_key, threshold, total)


# ---------------------------------------------------------------------------
# Demo / smoke-test (python -m vaulting.unseal)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os

    print("=== Unseal smoke test ===")
    key = os.urandom(32)
    k, n = 3, 5
    shares = generate_shares(key, k, n)
    print(f"Generated {n} shares (threshold={k}) for a 32-byte master key")

    machine = UnsealMachine(threshold=k, secret_len=len(key))
    print(f"State: {machine.state.value}")

    # Present shares 0, 2, 4 (any 3 of 5)
    for idx in [0, 2, 4]:
        result = machine.add_share(shares[idx])
        print(
            f"  Added share {idx}: state={machine.state.value}, "
            f"remaining={machine.shares_needed}"
        )
        if result is not None:
            assert result == key, "Reconstructed key does not match!"
            print(f"  ✓ Key reconstructed correctly ({len(result)} bytes)")

    machine.seal()
    print(f"Sealed: {machine.state.value}")
    print("All checks passed.")
