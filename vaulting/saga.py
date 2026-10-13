"""
vaulting/saga.py — Crash-safe secret rotation via a persistent saga pattern

Problem
-------
The naive rotate-then-verify flow has a gap: if the process dies after
writing the new ciphertext but before the health-check confirms it's
readable, the vault is in an inconsistent state.  On restart the old
key may be gone but the new ciphertext is unverified.

Solution
--------
We model rotation as a SQLite-persisted state machine (a "saga"):

  IDLE → PREPARED → ROTATING → VERIFYING → DONE
                                        ↘ ROLLING_BACK → DONE

Each transition is atomic (written to the DB before any external action).
On startup the saga runner calls :func:`recover` which inspects any
in-progress saga and completes or rolls it back.

States
------
IDLE         No rotation in progress.
PREPARED     New key generated and stored (encrypted under old key).
             Old key still active.
ROTATING     New ciphertext written under new key.
             Old ciphertext preserved as backup.
VERIFYING    Health-check round-trip in progress.
DONE         Rotation complete; old key material pruned.
ROLLING_BACK Verification failed; restoring old ciphertext.

Usage::

    saga = RotationSaga(db_path="vault.db")
    saga.recover()      # call on every startup — safe to call if IDLE

    # Later, to rotate the active key:
    saga.begin(secret_name="db_password")
    # (this is handled automatically by the CLI / vault manager)
"""

from __future__ import annotations

import enum
import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

class SagaState(enum.Enum):
    IDLE          = "idle"
    PREPARED      = "prepared"
    ROTATING      = "rotating"
    VERIFYING     = "verifying"
    ROLLING_BACK  = "rolling_back"
    DONE          = "done"


_TERMINAL_STATES = {SagaState.DONE, SagaState.IDLE}

# Valid forward transitions
_TRANSITIONS: dict[SagaState, set[SagaState]] = {
    SagaState.IDLE:         {SagaState.PREPARED},
    SagaState.PREPARED:     {SagaState.ROTATING,     SagaState.IDLE},
    SagaState.ROTATING:     {SagaState.VERIFYING,    SagaState.ROLLING_BACK},
    SagaState.VERIFYING:    {SagaState.DONE,          SagaState.ROLLING_BACK},
    SagaState.ROLLING_BACK: {SagaState.IDLE},
    SagaState.DONE:         {SagaState.IDLE},
}


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rotation_saga (
    id          INTEGER PRIMARY KEY DEFAULT 1,   -- singleton row
    state       TEXT    NOT NULL DEFAULT 'idle',
    secret_name TEXT,
    old_version INTEGER,
    new_version INTEGER,
    metadata    TEXT,        -- JSON blob for extra state
    updated_at  REAL NOT NULL DEFAULT (unixepoch('now'))
);
-- Ensure exactly one row exists
INSERT OR IGNORE INTO rotation_saga (id) VALUES (1);
"""


@dataclass
class SagaRecord:
    state:       SagaState
    secret_name: Optional[str]
    old_version: Optional[int]
    new_version: Optional[int]
    metadata:    dict
    updated_at:  float


# ---------------------------------------------------------------------------
# Saga runner
# ---------------------------------------------------------------------------

class RotationSaga:
    """
    Persistent saga state machine for crash-safe key rotation.

    Parameters
    ----------
    db_path : str
        Path to the SQLite database (same as the vault DB is fine).
    rotate_fn : callable, optional
        ``rotate_fn(secret_name, old_ver, new_ver)`` — perform the actual
        ciphertext re-encryption.  Called during the ROTATING phase.
    verify_fn : callable, optional
        ``verify_fn(secret_name, new_ver) -> bool`` — verify the new
        ciphertext is readable.  Called during the VERIFYING phase.
    rollback_fn : callable, optional
        ``rollback_fn(secret_name, old_ver)`` — restore old ciphertext.
    """

    def __init__(
        self,
        db_path: str,
        rotate_fn:   Optional[Callable[[str, int, int], None]] = None,
        verify_fn:   Optional[Callable[[str, int], bool]]       = None,
        rollback_fn: Optional[Callable[[str, int], None]]       = None,
    ) -> None:
        self.db_path    = db_path
        self.rotate_fn  = rotate_fn
        self.verify_fn  = verify_fn
        self.rollback_fn = rollback_fn
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------ DB helpers

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _read(self) -> SagaRecord:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM rotation_saga WHERE id=1").fetchone()
        meta = json.loads(row["metadata"] or "{}")
        return SagaRecord(
            state       = SagaState(row["state"]),
            secret_name = row["secret_name"],
            old_version = row["old_version"],
            new_version = row["new_version"],
            metadata    = meta,
            updated_at  = row["updated_at"],
        )

    def _write(
        self,
        state:       SagaState,
        secret_name: Optional[str] = None,
        old_version: Optional[int] = None,
        new_version: Optional[int] = None,
        metadata:    Optional[dict] = None,
    ) -> None:
        """Atomically persist a state transition."""
        with self._conn() as conn:
            conn.execute(
                """UPDATE rotation_saga
                   SET state=?, secret_name=?, old_version=?, new_version=?,
                       metadata=?, updated_at=unixepoch('now')
                   WHERE id=1""",
                (
                    state.value,
                    secret_name,
                    old_version,
                    new_version,
                    json.dumps(metadata or {}),
                ),
            )
        log.info("saga: state → %s (secret=%s)", state.value, secret_name)

    def _transition(self, to: SagaState, rec: SagaRecord, **extra) -> None:
        current = rec.state
        if to not in _TRANSITIONS.get(current, set()):
            raise RuntimeError(
                f"Invalid saga transition: {current.value} → {to.value}"
            )
        self._write(
            to,
            secret_name = extra.get("secret_name", rec.secret_name),
            old_version = extra.get("old_version", rec.old_version),
            new_version = extra.get("new_version", rec.new_version),
            metadata    = extra.get("metadata",    rec.metadata),
        )

    # ------------------------------------------------------------------ public API

    @property
    def current_state(self) -> SagaState:
        return self._read().state

    def recover(self) -> None:
        """
        Inspect any in-progress saga and resume it to completion.
        Call this on every process startup before serving requests.
        """
        with self._lock:
            rec = self._read()
            if rec.state in _TERMINAL_STATES:
                log.debug("saga: nothing to recover (state=%s)", rec.state.value)
                return

            log.warning(
                "saga: recovering interrupted rotation for '%s' "
                "(state=%s, age=%.1fs)",
                rec.secret_name,
                rec.state.value,
                time.time() - rec.updated_at,
            )
            self._resume(rec)

    def begin(self, secret_name: str, old_version: int, new_version: int) -> None:
        """
        Start a new rotation saga.  Raises if one is already in progress.
        """
        with self._lock:
            rec = self._read()
            if rec.state not in _TERMINAL_STATES:
                raise RuntimeError(
                    f"Cannot begin rotation: saga is in state {rec.state.value!r}"
                )
            self._transition(
                SagaState.PREPARED, rec,
                secret_name = secret_name,
                old_version = old_version,
                new_version = new_version,
            )
            self._run_saga(self._read())

    def abort(self) -> None:
        """Abort a PREPARED saga (before rotation has started)."""
        with self._lock:
            rec = self._read()
            if rec.state != SagaState.PREPARED:
                raise RuntimeError(
                    f"Can only abort from PREPARED state, not {rec.state.value!r}"
                )
            self._transition(SagaState.IDLE, rec)

    # ------------------------------------------------------------------ private

    def _run_saga(self, rec: SagaRecord) -> None:
        """Drive the saga forward from its current state to DONE."""
        try:
            if rec.state == SagaState.PREPARED:
                self._do_rotate(rec)
                rec = self._read()

            if rec.state == SagaState.ROTATING:
                self._do_verify(rec)
                rec = self._read()

            if rec.state == SagaState.VERIFYING:
                # Recovery: crashed between writing VERIFYING and DONE
                self._complete_verify(rec)
                rec = self._read()

            if rec.state == SagaState.ROLLING_BACK:
                self._do_rollback(rec)
                rec = self._read()

            if rec.state == SagaState.DONE:
                self._do_cleanup(rec)

        except Exception as exc:
            log.error("saga: unhandled error during saga: %s", exc, exc_info=True)
            # Attempt rollback as a safety net
            try:
                rec = self._read()
                if rec.state not in (SagaState.ROLLING_BACK, SagaState.DONE, SagaState.IDLE):
                    self._transition(SagaState.ROLLING_BACK, rec)
                    self._do_rollback(self._read())
            except Exception:
                log.critical("saga: rollback also failed — manual intervention required")
            raise

    def _resume(self, rec: SagaRecord) -> None:
        """Resume from a partially-completed saga (called by recover)."""
        self._run_saga(rec)

    def _complete_verify(self, rec: SagaRecord) -> None:
        """Complete a partially-done verify step (called during recovery)."""
        ok = True
        if self.verify_fn:
            ok = self.verify_fn(rec.secret_name, rec.new_version)  # type: ignore[arg-type]
        if ok:
            self._transition(SagaState.DONE, rec)
        else:
            log.warning("saga: recovery verify failed — rolling back")
            self._transition(SagaState.ROLLING_BACK, rec)

    def _do_rotate(self, rec: SagaRecord) -> None:
        self._transition(SagaState.ROTATING, rec)
        if self.rotate_fn:
            self.rotate_fn(rec.secret_name, rec.old_version, rec.new_version)  # type: ignore[arg-type]
        else:
            log.info("saga: rotate_fn not set — skipping actual re-encryption")

    def _do_verify(self, rec: SagaRecord) -> None:
        self._transition(SagaState.VERIFYING, rec)
        rec = self._read()  # re-read: state is now VERIFYING
        ok = True
        if self.verify_fn:
            ok = self.verify_fn(rec.secret_name, rec.new_version)  # type: ignore[arg-type]
        else:
            log.info("saga: verify_fn not set — assuming OK")

        if ok:
            self._transition(SagaState.DONE, rec)
        else:
            log.warning("saga: verification failed — initiating rollback")
            self._transition(SagaState.ROLLING_BACK, rec)

    def _do_rollback(self, rec: SagaRecord) -> None:
        if self.rollback_fn:
            self.rollback_fn(rec.secret_name, rec.old_version)  # type: ignore[arg-type]
        else:
            log.warning("saga: rollback_fn not set — data may be inconsistent")
        self._transition(SagaState.IDLE, rec)

    def _do_cleanup(self, rec: SagaRecord) -> None:
        """Reset saga to IDLE after a successful rotation."""
        rec = self._read()  # ensure we see DONE state
        self._transition(SagaState.IDLE, rec)

    # ------------------------------------------------------------------ diagnostics

    def status(self) -> dict:
        rec = self._read()
        return {
            "state":       rec.state.value,
            "secret_name": rec.secret_name,
            "old_version": rec.old_version,
            "new_version": rec.new_version,
            "updated_at":  rec.updated_at,
            "age_seconds": round(time.time() - rec.updated_at, 1),
        }


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile, os

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db = tf.name

    rotated = []
    verified = []
    rolled = []

    saga = RotationSaga(
        db_path     = db,
        rotate_fn   = lambda name, old, new: rotated.append((name, old, new)),
        verify_fn   = lambda name, ver: (verified.append(ver), True)[1],
        rollback_fn = lambda name, ver: rolled.append(ver),
    )

    print("Initial status:", saga.status())
    saga.begin("db_password", old_version=1, new_version=2)
    print("After rotation:", saga.status())
    print(f"  rotated={rotated}, verified={verified}, rolled_back={rolled}")
    assert rotated == [("db_password", 1, 2)]
    assert verified == [2]
    assert rolled == []
    print("✓ Happy path passed")

    # Recovery test: simulate crash mid-rotation by injecting state directly
    saga._write(SagaState.ROTATING, "api_key", 5, 6)
    print("\nSimulated crash — saga in ROTATING state")
    print("Calling recover()...")
    saga.recover()
    print("After recover:", saga.status())
    assert saga.current_state == SagaState.IDLE
    print("✓ Recovery passed")

    os.unlink(db)
    print("\nAll checks passed.")
