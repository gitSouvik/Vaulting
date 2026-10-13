PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS secrets (
    name               TEXT PRIMARY KEY,
    created_at         REAL NOT NULL,
    rotation_interval  REAL                -- seconds; NULL = no scheduled rotation
);

-- Values are NEVER stored in plaintext. Each version is envelope-encrypted:
-- ciphertext (AES-256-GCM under a per-version data key) + that key wrapped by a master key.
-- Status lifecycle:  active -> grace -> revoked   (rotation)
--                    grace  -> active             (rollback)
CREATE TABLE IF NOT EXISTS secret_versions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL REFERENCES secrets(name),
    version      INTEGER NOT NULL,
    ciphertext   BLOB NOT NULL,
    nonce        BLOB NOT NULL,
    wrapped_dek  BLOB NOT NULL,
    dek_nonce    BLOB NOT NULL,
    kek_id       TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('active', 'grace', 'revoked')),
    created_at   REAL NOT NULL,
    graced_at    REAL,
    revoked_at   REAL,
    reason       TEXT,
    UNIQUE (name, version)
);

-- Invariants enforced by the database, not by application code.
CREATE UNIQUE INDEX IF NOT EXISTS one_active_per_secret
    ON secret_versions(name) WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS one_grace_per_secret
    ON secret_versions(name) WHERE status = 'grace';

CREATE TABLE IF NOT EXISTS apps (
    app_id      TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,      -- sha256 of a 192-bit random token, never the token
    created_at  REAL NOT NULL,
    expires_at  REAL,                      -- NULL = never expires
    revoked     INTEGER NOT NULL DEFAULT 0
);

-- secret_name has no FK on purpose: grants can also cover external provider paths.
CREATE TABLE IF NOT EXISTS grants (
    app_id       TEXT NOT NULL REFERENCES apps(app_id),
    secret_name  TEXT NOT NULL,
    PRIMARY KEY (app_id, secret_name)
);

-- Tamper-evident: each row's entry_hash covers the previous row's hash (a hash chain).
CREATE TABLE IF NOT EXISTS access_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    app_id       TEXT,
    secret_name  TEXT,
    version      INTEGER,
    outcome      TEXT NOT NULL,            -- ok | denied | unauthenticated | not_found | provider_error
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_access_ts ON access_log(ts);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    source       TEXT NOT NULL,
    kind         TEXT NOT NULL,
    secret_name  TEXT,
    severity     TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    detail       TEXT NOT NULL,            -- always redacted, never the raw value
    fingerprint  TEXT NOT NULL UNIQUE,
    handled      INTEGER NOT NULL DEFAULT 0,
    outcome      TEXT
);

CREATE TABLE IF NOT EXISTS agent_trace (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    run_id      TEXT NOT NULL,
    finding_id  INTEGER REFERENCES findings(id),
    step        INTEGER NOT NULL,
    thought     TEXT NOT NULL,
    action      TEXT NOT NULL,
    result      TEXT NOT NULL
);

PRAGMA user_version = 2;
