"""The differentiator: verify that what actually settled matches what was
authorised, and reverse it automatically when it does not.

ACP, AP2 and TAP all gate before payment. Nothing in them checks afterwards.
This module is that check. It is pure comparison plus a refund call — no LLM
touches it (the project spec §6).
"""
from __future__ import annotations

import sqlite3
import time
from typing import Any

from gate.ledger import Ledger


def _bound_envelope(ledger: Ledger, decision_id: str) -> dict[str, Any] | None:
    """The amount a human or a rule actually authorised, from the ledger."""
    rows = ledger.by_decision(decision_id)
    decision = next((r["record"] for r in rows if r["kind"] == "decision"), None)
    if decision is None:
        return None
    execution = next((r["record"] for r in rows if r["kind"] == "execution"), None)
    return {
        "outcome": decision["outcome"],
        "envelope_hash": decision["outcome"].get("envelope_hash"),
        "order_id": (execution or {}).get("execution", {}).get("razorpay_order_id"),
        "authorised": decision["escalation"]["required"] is False
                      or decision["escalation"].get("approver") is not None
                      or any(r["kind"] == "approval" for r in rows),
    }


def on_capture(conn: sqlite3.Connection, ledger: Ledger, adapter, event: dict[str, Any],
               now: int | None = None) -> dict[str, Any]:
    """Handle payment.captured. Idempotent: a webhook retry is a no-op."""
    now = int(time.time()) if now is None else now
    entity = ((event.get("payload") or {}).get("payment") or {}).get("entity") or {}
    payment_id = entity.get("id")
    notes = entity.get("notes") or {}
    decision_id = notes.get("decision_id")
    captured = entity.get("amount")
    currency = entity.get("currency")

    if not payment_id:
        return {"status": "ignored", "reason": "no_payment_id"}

    if not decision_id:
        # A capture we cannot attribute is itself an incident, not a shrug.
        ledger.append(kind="incident", decision_id=f"orphan_{payment_id}",
                      record={"incident": {"type": "capture_without_decision_id",
                                           "payment_id": payment_id, "captured_paise": captured}},
                      now=now)
        return {"status": "incident", "reason": "capture_without_decision_id", "payment_id": payment_id}

    # Idempotency latch. INSERT OR IGNORE is the whole duplicate defence: a
    # retried webhook loses the race and never triggers a second refund.
    cur = conn.execute("INSERT OR IGNORE INTO settled_payments(payment_id, decision_id, settled_at)"
                       " VALUES (?,?,?)", (payment_id, decision_id, now))
    if cur.rowcount == 0:
        return {"status": "duplicate_ignored", "decision_id": decision_id, "payment_id": payment_id}

    env = _bound_envelope(ledger, decision_id)
    if env is None:
        ledger.append(kind="incident", decision_id=decision_id,
                      record={"incident": {"type": "capture_for_unknown_decision",
                                           "payment_id": payment_id, "captured_paise": captured}},
                      now=now)
        return {"status": "incident", "reason": "unknown_decision_id", "decision_id": decision_id}

    bound = env["outcome"]["bound_amount_paise"]
    delta = captured - bound                      # integer paise, always
    problems = []
    if delta != 0:
        problems.append("amount_mismatch")
    if currency != env["outcome"]["bound_currency"]:
        problems.append("currency_mismatch")
    if env["envelope_hash"] and notes.get("envelope_hash") != env["envelope_hash"]:
        problems.append("envelope_mismatch")
    if env["order_id"] and entity.get("order_id") and entity["order_id"] != env["order_id"]:
        problems.append("order_mismatch")
    if not env["authorised"]:
        problems.append("capture_without_approval")

    if not problems:
        ledger.append(kind="reconciliation", decision_id=decision_id,
                      record={"reconciliation": {"status": "matched", "delta_paise": 0,
                                                 "remediation": None, "payment_id": payment_id,
                                                 "captured_paise": captured}}, now=now)
        return {"status": "matched", "decision_id": decision_id, "captured_paise": captured}

    # Remediate. Over-capture is refundable to the delta; anything else that is
    # not a clean over-capture gets the whole capture reversed, because we
    # cannot say which part of it was authorised.
    refund, remediation = None, "flagged_no_automatic_reversal"
    refund_paise = delta if problems == ["amount_mismatch"] and delta > 0 else (
        captured if captured and captured > 0 and problems != ["amount_mismatch"] else 0)
    if refund_paise > 0:
        refund = adapter.refund(payment_id=payment_id, amount_paise=refund_paise,
                                decision_id=decision_id, reason=",".join(problems))
        remediation = "refund_delta" if refund_paise == delta else "refund_full"

    ledger.append(kind="reconciliation", decision_id=decision_id,
                  record={"reconciliation": {"status": "mismatch", "delta_paise": delta,
                                             "problems": problems, "remediation": remediation,
                                             "payment_id": payment_id, "captured_paise": captured,
                                             "bound_paise": bound,
                                             "refund_id": (refund or {}).get("id"),
                                             "refunded_paise": refund_paise}}, now=now)
    ledger.append(kind="incident", decision_id=decision_id,
                  record={"incident": {"type": "capture_mismatch", "problems": problems,
                                       "bound_paise": bound, "captured_paise": captured,
                                       "delta_paise": delta, "remediation": remediation,
                                       "refund_id": (refund or {}).get("id"),
                                       "agent_notice": {
                                           "status": "reversed", "reason": problems[0],
                                           "bound_amount_paise": bound,
                                           "captured_amount_paise": captured,
                                           "refunded_paise": refund_paise,
                                           "decision_id": decision_id}}}, now=now)
    return {"status": "mismatch", "decision_id": decision_id, "problems": problems,
            "delta_paise": delta, "refund_id": (refund or {}).get("id"),
            "refunded_paise": refund_paise, "remediation": remediation}
