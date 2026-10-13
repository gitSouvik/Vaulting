"""The vault: encrypted versioned secrets, app identities, grants, tamper-evident audit log.

Security model in one paragraph: secret values are envelope-encrypted (see crypto.py)
before they touch the database, so a stolen DB file is useless without the master key,
which never lives in the database. App tokens are stored only as SHA-256 hashes (they
are 192-bit random values, so a fast hash is correct; slow hashes like bcrypt are for
low-entropy human passwords). The access log is a hash chain, so edits and mid-log
deletions are detectable.
"""
import hashlib
import hmac
import re
import secrets
import time
from contextlib import contextmanager
from typing import Optional

from . import crypto
from .crypto import Keyring, Sealed
from .db import connect, init_db

GENESIS = "0" * 64
NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")


class VaultError(Exception):
    pass


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aad(name: str, version: int) -> bytes:
    return f"vaulting:v2|{name}|{version}".encode()


def _entry_hash(prev: str, ts: float, app_id, secret_name, version, outcome: str) -> str:
    parts = [prev, repr(ts), app_id or "", secret_name or "",
             "" if version is None else str(version), outcome]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _sealed(row) -> Sealed:
    return Sealed(row["ciphertext"], row["nonce"], row["wrapped_dek"], row["dek_nonce"], row["kek_id"])


class Vault:
    def __init__(self, db_path: str, keyring: Keyring):
        self.db_path = str(db_path)
        self.keyring = keyring
        init_db(self.db_path)

    @contextmanager
    def tx(self, immediate: bool = False):
        conn = connect(self.db_path)
        try:
            if immediate:
                conn.execute("BEGIN IMMEDIATE")  # take the write lock up front
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _decrypt(self, row) -> str:
        return crypto.open_sealed(self.keyring, _sealed(row), _aad(row["name"], row["version"])).decode()

    # ---- secrets -----------------------------------------------------------
    def put_secret(self, name: str, value: Optional[str] = None) -> dict:
        if not NAME_RE.match(name):
            raise VaultError("secret names may only use letters, digits, '_', '.', '-' (max 128)")
        value = value or secrets.token_urlsafe(24)
        now = time.time()
        s = crypto.seal(self.keyring, value.encode(), _aad(name, 1))
        with self.tx() as c:
            if c.execute("SELECT 1 FROM secrets WHERE name=?", (name,)).fetchone():
                raise VaultError(f"secret '{name}' already exists")
            c.execute("INSERT INTO secrets(name, created_at) VALUES (?, ?)", (name, now))
            c.execute(
                "INSERT INTO secret_versions(name, version, ciphertext, nonce, wrapped_dek, dek_nonce, "
                "kek_id, status, created_at, reason) VALUES (?, 1, ?, ?, ?, ?, ?, 'active', ?, 'created')",
                (name, s.ciphertext, s.nonce, s.wrapped_dek, s.dek_nonce, s.kek_id, now),
            )
        return {"name": name, "version": 1, "value": value}

    def get_active(self, name: str) -> Optional[dict]:
        with self.tx() as c:
            row = c.execute(
                "SELECT * FROM secret_versions WHERE name=? AND status='active'", (name,)
            ).fetchone()
        if not row:
            return None
        return {"name": row["name"], "version": row["version"], "status": row["status"],
                "created_at": row["created_at"], "value": self._decrypt(row)}

    def versions(self, name: str) -> list:
        """Metadata only. Never returns values or key material."""
        with self.tx() as c:
            rows = c.execute(
                "SELECT version, status, kek_id, created_at, revoked_at, reason "
                "FROM secret_versions WHERE name=? ORDER BY version", (name,)
            ).fetchall()
        return [dict(r) for r in rows]

    def rotate(self, name: str, reason: str = "scheduled", new_value: Optional[str] = None) -> dict:
        """active -> grace, new version becomes active. Old grace (if any) is revoked."""
        new_value = new_value or secrets.token_urlsafe(24)
        now = time.time()
        with self.tx() as c:
            cur = c.execute(
                "SELECT version FROM secret_versions WHERE name=? AND status='active'", (name,)
            ).fetchone()
            if not cur:
                raise VaultError(f"no active version for '{name}'")
            nxt = c.execute("SELECT MAX(version) FROM secret_versions WHERE name=?", (name,)).fetchone()[0] + 1
            s = crypto.seal(self.keyring, new_value.encode(), _aad(name, nxt))
            # Order matters: the partial unique indexes are checked per statement.
            c.execute(
                "UPDATE secret_versions SET status='revoked', revoked_at=?, reason=? "
                "WHERE name=? AND status='grace'", (now, "superseded by newer rotation", name))
            c.execute(
                "UPDATE secret_versions SET status='grace', graced_at=? WHERE name=? AND status='active'",
                (now, name))
            c.execute(
                "INSERT INTO secret_versions(name, version, ciphertext, nonce, wrapped_dek, dek_nonce, "
                "kek_id, status, created_at, reason) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
                (name, nxt, s.ciphertext, s.nonce, s.wrapped_dek, s.dek_nonce, s.kek_id, now, reason))
        return {"name": name, "old_version": cur["version"], "version": nxt, "value": new_value}

    def revoke_grace(self, name: str, reason: str = "grace period over") -> int:
        with self.tx() as c:
            return c.execute(
                "UPDATE secret_versions SET status='revoked', revoked_at=?, reason=? "
                "WHERE name=? AND status='grace'", (time.time(), reason, name)).rowcount

    def expire_grace(self, grace_seconds: float, now: Optional[float] = None) -> int:
        """Revoke every grace version that has been in grace longer than grace_seconds."""
        now = time.time() if now is None else now
        with self.tx() as c:
            return c.execute(
                "UPDATE secret_versions SET status='revoked', revoked_at=?, reason='grace period expired' "
                "WHERE status='grace' AND graced_at <= ?", (now, now - grace_seconds)).rowcount

    def rollback(self, name: str, reason: str = "rollback") -> dict:
        """Revoke the current active version and promote the grace version back."""
        now = time.time()
        with self.tx() as c:
            grace = c.execute(
                "SELECT version FROM secret_versions WHERE name=? AND status='grace'", (name,)).fetchone()
            if not grace:
                raise VaultError(f"nothing to roll back to for '{name}'")
            c.execute(
                "UPDATE secret_versions SET status='revoked', revoked_at=?, reason=? "
                "WHERE name=? AND status='active'", (now, reason, name))
            c.execute(
                "UPDATE secret_versions SET status='active', graced_at=NULL WHERE name=? AND status='grace'",
                (name,))
        return {"name": name, "version": grace["version"]}

    def validate(self, name: str, value: str) -> bool:
        """True if value matches the active or grace version (constant-time compare)."""
        with self.tx() as c:
            rows = c.execute(
                "SELECT * FROM secret_versions WHERE name=? AND status IN ('active','grace')", (name,)
            ).fetchall()
        return any(hmac.compare_digest(self._decrypt(r), value) for r in rows)

    def live_values(self) -> list:
        """Decrypted (name, version, value) of every still-usable value. Sentinel input; keep in memory only."""
        with self.tx() as c:
            rows = c.execute("SELECT * FROM secret_versions WHERE status IN ('active','grace')").fetchall()
        return [{"name": r["name"], "version": r["version"], "value": self._decrypt(r)} for r in rows]

    # ---- key management ----------------------------------------------------
    def rewrap_all(self) -> int:
        """Re-wrap every data key under the ACTIVE master key. Ciphertexts are untouched."""
        n = 0
        with self.tx() as c:
            for r in c.execute("SELECT * FROM secret_versions").fetchall():
                if r["kek_id"] == self.keyring.active_id:
                    continue
                s = crypto.rewrap(self.keyring, _sealed(r), _aad(r["name"], r["version"]))
                c.execute("UPDATE secret_versions SET wrapped_dek=?, dek_nonce=?, kek_id=? WHERE id=?",
                          (s.wrapped_dek, s.dek_nonce, s.kek_id, r["id"]))
                n += 1
        return n

    # ---- rotation policy ---------------------------------------------------
    def set_rotation_policy(self, name: str, seconds: Optional[float]) -> None:
        with self.tx() as c:
            if c.execute("UPDATE secrets SET rotation_interval=? WHERE name=?", (seconds, name)).rowcount == 0:
                raise VaultError(f"no such secret '{name}'")

    def due_for_rotation(self, now: Optional[float] = None) -> list:
        now = time.time() if now is None else now
        with self.tx() as c:
            rows = c.execute(
                "SELECT s.name FROM secrets s JOIN secret_versions v "
                "ON v.name = s.name AND v.status = 'active' "
                "WHERE s.rotation_interval IS NOT NULL AND ? - v.created_at >= s.rotation_interval", (now,)
            ).fetchall()
        return [r["name"] for r in rows]

    # ---- identities and access ---------------------------------------------
    def register_app(self, app_id: str, ttl_seconds: Optional[float] = None) -> str:
        """Returns the bearer token. Shown once; only its hash is stored."""
        token = "vl_" + secrets.token_urlsafe(24)
        now = time.time()
        with self.tx() as c:
            c.execute(
                "INSERT INTO apps(app_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (app_id, _hash_token(token), now, now + ttl_seconds if ttl_seconds else None))
        return token

    def revoke_app(self, app_id: str) -> None:
        with self.tx() as c:
            if c.execute("UPDATE apps SET revoked=1 WHERE app_id=?", (app_id,)).rowcount == 0:
                raise VaultError(f"no such app '{app_id}'")

    def grant(self, app_id: str, secret_name: str) -> None:
        with self.tx() as c:
            c.execute("INSERT OR IGNORE INTO grants(app_id, secret_name) VALUES (?, ?)", (app_id, secret_name))

    def authenticate(self, token: str) -> Optional[str]:
        with self.tx() as c:
            row = c.execute(
                "SELECT app_id, expires_at, revoked FROM apps WHERE token_hash=?", (_hash_token(token),)
            ).fetchone()
        if not row or row["revoked"]:
            return None
        if row["expires_at"] is not None and row["expires_at"] <= time.time():
            return None
        return row["app_id"]

    def authorize(self, app_id: str, secret_name: str) -> bool:
        with self.tx() as c:
            return c.execute(
                "SELECT 1 FROM grants WHERE app_id=? AND secret_name=?", (app_id, secret_name)
            ).fetchone() is not None

    # ---- tamper-evident audit log ------------------------------------------
    def log_access(self, app_id, secret_name, version, outcome: str) -> None:
        ts = time.time()
        with self.tx(immediate=True) as c:  # serialize writers so the chain never forks
            row = c.execute("SELECT entry_hash FROM access_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["entry_hash"] if row else GENESIS
            c.execute(
                "INSERT INTO access_log(ts, app_id, secret_name, version, outcome, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ts, app_id, secret_name, version, outcome, prev,
                 _entry_hash(prev, ts, app_id, secret_name, version, outcome)))

    def verify_audit_chain(self) -> dict:
        """Recompute the chain. Detects edited rows and deleted rows (except truncation of the
        tail: anchor `head` somewhere external, e.g. print it to a separate system, to cover that)."""
        prev, n = GENESIS, 0
        with self.tx() as c:
            for r in c.execute("SELECT * FROM access_log ORDER BY id"):
                good = _entry_hash(prev, r["ts"], r["app_id"], r["secret_name"], r["version"], r["outcome"])
                if r["prev_hash"] != prev or r["entry_hash"] != good:
                    return {"ok": False, "entries": n, "bad_id": r["id"], "head": prev}
                prev, n = r["entry_hash"], n + 1
        return {"ok": True, "entries": n, "bad_id": None, "head": prev}

    def recent_access(self, limit: int = 20) -> list:
        with self.tx() as c:
            rows = c.execute(
                "SELECT ts, app_id, secret_name, version, outcome FROM access_log ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ---- monitoring --------------------------------------------------------
    def metrics(self, window: float = 300.0) -> dict:
        now = time.time()
        with self.tx() as c:
            versions = {r["status"]: r["n"] for r in c.execute(
                "SELECT status, COUNT(*) AS n FROM secret_versions GROUP BY status")}
            access = {r["outcome"]: r["n"] for r in c.execute(
                "SELECT outcome, COUNT(*) AS n FROM access_log WHERE ts >= ? GROUP BY outcome", (now - window,))}
            out = {
                "secrets": c.execute("SELECT COUNT(*) FROM secrets").fetchone()[0],
                "versions": versions,
                "apps": c.execute("SELECT COUNT(*) FROM apps WHERE revoked=0").fetchone()[0],
                "open_findings": c.execute("SELECT COUNT(*) FROM findings WHERE handled=0").fetchone()[0],
                "access_last_window": access, "window_seconds": window,
                "oldest_active_secret_age_s": None,
            }
            r = c.execute("SELECT MIN(created_at) FROM secret_versions WHERE status='active'").fetchone()[0]
            if r is not None:
                out["oldest_active_secret_age_s"] = round(now - r, 1)
        out["audit_chain_ok"] = self.verify_audit_chain()["ok"]
        return out
