"""One-time, TTL-bounded approval tokens. Fails closed on every edge.

The token is a bearer secret; only its sha256 is stored, so a dump of the DB
does not hand anyone the ability to approve. An approval is scoped to an
envelope_hash: if the cart changes by one paise, the approval does not apply
to it.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from dataclasses import dataclass

TTL_S = 300


def token_hash(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True)
class Redemption:
    ok: bool
    reason: str                      # ok | unknown_token | expired | already_used | envelope_mismatch
    decision_id: str | None = None
    envelope_hash: str | None = None
    outcome: str | None = None       # approved | rejected


def issue(conn: sqlite3.Connection, *, decision_id: str, envelope_hash: str,
          ttl_s: int = TTL_S, now: int | None = None) -> tuple[str, str]:
    now = int(time.time()) if now is None else now
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO approvals(token_hash, decision_id, envelope_hash, expires_at)"
                 " VALUES (?,?,?,?)", (token_hash(token), decision_id, envelope_hash, now + ttl_s))
    return token, token_hash(token)


def peek(conn: sqlite3.Connection, token: str, now: int | None = None) -> Redemption:
    """Read-only view for rendering the approval page. Never consumes."""
    now = int(time.time()) if now is None else now
    row = conn.execute("SELECT * FROM approvals WHERE token_hash=?", (token_hash(token),)).fetchone()
    if row is None:
        return Redemption(False, "unknown_token")
    if row["used_at"] is not None:
        return Redemption(False, "already_used", row["decision_id"], row["envelope_hash"], row["outcome"])
    if now > row["expires_at"]:
        return Redemption(False, "expired", row["decision_id"], row["envelope_hash"])
    return Redemption(True, "ok", row["decision_id"], row["envelope_hash"])


def redeem(conn: sqlite3.Connection, token: str, *, approver: str, outcome: str = "approved",
           expect_envelope_hash: str | None = None, now: int | None = None) -> Redemption:
    """Consume the token. One shot: the UPDATE is guarded on used_at IS NULL so
    two simultaneous clicks cannot both win."""
    now = int(time.time()) if now is None else now
    state = peek(conn, token, now)
    if not state.ok:
        return state
    if expect_envelope_hash is not None and expect_envelope_hash != state.envelope_hash:
        return Redemption(False, "envelope_mismatch", state.decision_id, state.envelope_hash)
    cur = conn.execute(
        "UPDATE approvals SET used_at=?, approver=?, outcome=? WHERE token_hash=? AND used_at IS NULL",
        (now, approver, outcome, token_hash(token)))
    if cur.rowcount != 1:
        return Redemption(False, "already_used", state.decision_id, state.envelope_hash)
    return Redemption(True, "ok", state.decision_id, state.envelope_hash, outcome)


def expire_due(conn: sqlite3.Connection, now: int | None = None) -> list[sqlite3.Row]:
    """Approvals past their TTL that nobody answered. The caller turns each into
    an auto-deny record — silence is a no."""
    now = int(time.time()) if now is None else now
    return conn.execute("SELECT * FROM approvals WHERE used_at IS NULL AND expires_at < ?",
                        (now,)).fetchall()
