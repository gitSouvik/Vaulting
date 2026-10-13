"""SQLite helpers. One short-lived connection per operation keeps threads safe."""
import os
import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


class LegacyDatabaseError(Exception):
    pass


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path: str) -> None:
    existed = os.path.exists(path)
    conn = connect(path)
    try:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(secret_versions)")]
        if cols and "ciphertext" not in cols:
            raise LegacyDatabaseError(
                "this database stores secrets in plaintext (schema v1). Create a new "
                "database and re-add the secrets so they are encrypted.")
        conn.executescript(SCHEMA_PATH.read_text())
        conn.commit()
    finally:
        conn.close()
    if not existed and os.name == "posix":
        os.chmod(path, 0o600)  # owner-only; the file holds ciphertext and token hashes
