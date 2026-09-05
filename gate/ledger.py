"""Append-only, hash-chained, Ed25519-signed decision ledger.

Three properties, none of them optional (the project spec §5.2):
  replayable      — the facts and the bundle hash are in the record
  counterfactual  — every rule carries observed and threshold
  tamper-evident  — prev_hash chain + a signature over each record hash

Nothing here ever UPDATEs or DELETEs. Later stages of a decision are appended
as new rows carrying the same decision_id.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

GENESIS = "sha256:" + "0" * 64
KEY_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "keys" / "gate-1.json"
SPENDING_EFFECTS = ("allow", "escalate")   # a denied decision never reserved money


def canonical(obj: Any) -> str:
    """The one JSON encoding the hash is taken over. Sorted, compact, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def envelope_hash(decision_id: str, cart: dict[str, Any]) -> str:
    """The binding between an approval, an order and a capture.

    Covers exactly what must not change between "a human said yes" and "money
    moved": which decision, which SKUs, which quantities, which unit prices,
    the total and the currency.
    """
    return sha256(canonical({
        "decision_id": decision_id,
        "items": sorted(({"sku": i["sku"], "qty": i["qty"],
                          "unit_price_paise": i["unit_price_paise"]} for i in cart["items"]),
                        key=lambda i: i["sku"]),
        "total_paise": cart["total_paise"],
        "currency": cart.get("currency", "INR"),
    }))


def new_decision_id() -> str:
    return "dec_" + secrets.token_hex(10)


def iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_key(path: pathlib.Path = KEY_PATH) -> tuple[SigningKey, bytes]:
    k = json.loads(path.read_text())
    sk = SigningKey(base64.b64decode(k["private_key"]))
    return sk, base64.b64decode(k["public_key"])


@dataclass
class ChainResult:
    ok: bool
    checked: int
    problems: list[dict[str, Any]] = field(default_factory=list)


class Ledger:
    def __init__(self, conn: sqlite3.Connection, key_path: pathlib.Path = KEY_PATH):
        self.conn = conn
        self.signing_key, self.public_key = _load_key(key_path)
        self.kid = "gate-1"

    def head(self) -> str:
        row = self.conn.execute("SELECT record_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return row["record_hash"] if row else GENESIS

    def append(self, *, kind: str, decision_id: str, record: dict[str, Any],
               agent_id: str | None = None, now: int | None = None) -> dict[str, Any]:
        now = int(time.time()) if now is None else now
        # These four fields are part of what gets hashed and signed, so a row's
        # identity, order and timestamp are all inside the tamper envelope.
        full = dict(record, decision_id=decision_id, kind=kind, ts=iso(now),
                    prev_hash=self.head())
        body = canonical(full)
        record_hash = sha256(body)
        sig = base64.b64encode(self.signing_key.sign(record_hash.encode()).signature).decode()
        cur = self.conn.execute(
            "INSERT INTO ledger(decision_id,kind,ts,agent_id,prev_hash,record_hash,record,sig)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (decision_id, kind, full["ts"], agent_id, full["prev_hash"], record_hash, body, sig))
        return {"seq": cur.lastrowid, "decision_id": decision_id, "kind": kind, "ts": full["ts"],
                "prev_hash": full["prev_hash"], "record_hash": record_hash, "sig": sig,
                "record": full}

    def by_decision(self, decision_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM ledger WHERE decision_id=? ORDER BY seq", (decision_id,)).fetchall()
        return [dict(r, record=json.loads(r["record"])) for r in rows]

    def window(self, agent_id: str, now: int | None = None) -> dict[str, int]:
        """Velocity facts, computed from the ledger itself.

        # ponytail: indexed scan over (agent_id, kind, ts), no counter table. A
        # counter is a second source of truth that can drift from the ledger;
        # add one only if the red-team harness shows this in p95 latency.
        """
        now = int(time.time()) if now is None else now
        rows = self.conn.execute(
            "SELECT record FROM ledger WHERE agent_id=? AND kind='decision' AND ts>=?",
            (agent_id, iso(now - 86400))).fetchall()
        count_1h, spend = 0, 0
        hour_ago = iso(now - 3600)
        for r in rows:
            doc = json.loads(r["record"])
            if doc["ts"] >= hour_ago:
                count_1h += 1
            outcome = doc.get("outcome") or {}
            if outcome.get("effect") in SPENDING_EFFECTS:
                spend += outcome.get("bound_amount_paise") or 0
        return {"txn_count_1h": count_1h, "spend_24h_paise": spend}


def verify_chain(conn: sqlite3.Connection, key_path: pathlib.Path = KEY_PATH) -> ChainResult:
    """Walk the chain and name every broken link. Read-only."""
    _, public_key = _load_key(key_path)
    verifier = VerifyKey(public_key)
    problems: list[dict[str, Any]] = []
    expected_prev, checked = GENESIS, 0

    for row in conn.execute("SELECT * FROM ledger ORDER BY seq"):
        checked += 1
        where = {"seq": row["seq"], "decision_id": row["decision_id"], "kind": row["kind"]}
        if row["prev_hash"] != expected_prev:
            problems.append({**where, "problem": "broken_link",
                             "expected_prev_hash": expected_prev, "found_prev_hash": row["prev_hash"]})
        if sha256(row["record"]) != row["record_hash"]:
            problems.append({**where, "problem": "record_hash_mismatch",
                             "expected": sha256(row["record"]), "found": row["record_hash"]})
        else:
            try:
                verifier.verify(row["record_hash"].encode(), base64.b64decode(row["sig"]))
            except (BadSignatureError, ValueError):
                problems.append({**where, "problem": "bad_signature"})
        try:
            if json.loads(row["record"])["prev_hash"] != row["prev_hash"]:
                problems.append({**where, "problem": "prev_hash_column_mismatch"})
        except (json.JSONDecodeError, KeyError):
            problems.append({**where, "problem": "unparseable_record"})
        expected_prev = row["record_hash"]

    problems.sort(key=lambda p: p["seq"])
    return ChainResult(ok=not problems, checked=checked, problems=problems)
