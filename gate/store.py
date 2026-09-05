"""SQLite connection + schema. Everything that touches the DB goes through here.

Not in the the project spec §4 layout — added because the schema needed a home and
ledger.py should not own the nonce and approval tables it doesn't read.
"""
from __future__ import annotations

import pathlib
import sqlite3

DB_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "gate.db"

SCHEMA = """
PRAGMA journal_mode=WAL;

-- Append-only. No UPDATE, no DELETE, ever. Later stages of a decision are new
-- rows carrying the same decision_id (the project spec §5.2).
CREATE TABLE IF NOT EXISTS ledger (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  decision_id  TEXT    NOT NULL,
  kind         TEXT    NOT NULL,   -- decision|execution|reconciliation|incident|explanation
  ts           TEXT    NOT NULL,
  agent_id     TEXT,               -- denormalised so velocity is one indexed scan
  prev_hash    TEXT    NOT NULL,
  record_hash  TEXT    NOT NULL,
  record       TEXT    NOT NULL,   -- canonical JSON; hashed exactly as stored
  sig          TEXT    NOT NULL    -- Ed25519 over record_hash
);
CREATE INDEX IF NOT EXISTS idx_ledger_decision ON ledger(decision_id);
CREATE INDEX IF NOT EXISTS idx_ledger_velocity ON ledger(agent_id, kind, ts);

-- Replay defence (Phase 2).
CREATE TABLE IF NOT EXISTS nonces (
  nonce    TEXT PRIMARY KEY,
  agent_id TEXT    NOT NULL,
  seen_at  INTEGER NOT NULL
);

-- Escalation tokens (Phase 6). Mutable by design, so not in the ledger: the
-- ledger records that an approval happened, this table is the one-time latch.
CREATE TABLE IF NOT EXISTS approvals (
  token_hash    TEXT PRIMARY KEY,
  decision_id   TEXT    NOT NULL,
  envelope_hash TEXT    NOT NULL,  -- approval is scoped to this exact cart
  expires_at    INTEGER NOT NULL,
  used_at       INTEGER,
  approver      TEXT,
  outcome       TEXT              -- approved|rejected
);

-- Reconciliation idempotency (Phase 7): one row per payment we've settled.
CREATE TABLE IF NOT EXISTS settled_payments (
  payment_id  TEXT PRIMARY KEY,
  decision_id TEXT NOT NULL,
  settled_at  INTEGER NOT NULL
);
"""


def connect(path: pathlib.Path | str = DB_PATH) -> sqlite3.Connection:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # check_same_thread=False because ASGI may hand a request to a worker thread.
    # ponytail: relies on sqlite3's own serialised mode plus WAL and a single
    # writer, which is what this workload is. Needs a connection pool or a
    # write queue before it is more than one merchant.
    conn = sqlite3.connect(path, isolation_level=None,  # autocommit; ledger appends are single statements
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(path: pathlib.Path | str = DB_PATH) -> sqlite3.Connection:
    conn = connect(path)
    conn.executescript(SCHEMA)
    return conn


if __name__ == "__main__":
    c = init_db()
    tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    print("tables:", ", ".join(tables))
