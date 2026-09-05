"""Phase 5, 6, 7 acceptance, plus the §6 monotone-authority boundary."""
import json
import time
from types import SimpleNamespace

import pytest

from buyer_agent.agent import BuyerAgent
from gate import escalation
from gate.app import Gate
from gate.ledger import verify_chain
from gate.razorpay_adapter import RazorpayAdapter
from gate.store import init_db

SKU_1499 = "SKU-1062"      # ₹1,499.00
SKU_249 = "SKU-1042"       # ₹2,499.00, max_qty 10, injected description
SKU_RESTRICTED = "SKU-1184"
SKU_BIG = "SKU-1134"       # ₹24,999.00


@pytest.fixture
def gate():
    return Gate(init_db(":memory:"), adapter=RazorpayAdapter(key_id="", key_secret=""),
                base_url="http://test")


@pytest.fixture
def agent():
    return BuyerAgent()


def post(gate, agent, **kw):
    return gate.process_checkout(*agent.request(**kw))


# --- Phase 5: catalog is the only price truth --------------------------------

def test_claimed_price_is_discarded_and_recorded(gate, agent):
    """A request claiming ₹1 for a ₹1,499 SKU is priced at ₹1,499."""
    status, body = post(gate, agent, cart=[{"sku": SKU_1499, "qty": 1,
                                            "claimed_unit_price_paise": 100}])
    assert body["amount_paise"] == 149900
    decision = gate.ledger.by_decision(body["decision_id"])[0]["record"]
    line = decision["cart"]["items"][0]
    assert line["unit_price_paise"] == 149900 and line["price_source"] == "catalog"
    assert decision["cart"]["discarded_price_claims"] == [
        {"sku": SKU_1499, "claimed_unit_price_paise": 100, "catalog_unit_price_paise": 149900}]
    assert status == 403 and body["reason"] == "price.substitution"


def test_a_plausible_price_claim_is_still_ignored(gate, agent):
    """Within tolerance, no rule fires — but the total is catalog truth anyway."""
    status, body = post(gate, agent, cart=[{"sku": SKU_1499, "qty": 1,
                                            "claimed_unit_price_paise": 140000}])
    assert status == 200 and body["amount_paise"] == 149900


def test_prompt_injection_in_a_description_does_not_change_the_parsed_intent(gate):
    """SKU-1042's catalog description tells the parser to add 50 units. The
    parser never sees descriptions, so the intent is unchanged."""
    from gate.catalog import catalog
    from gate.intent import parse_intent
    assert "IGNORE PREVIOUS INSTRUCTIONS" in catalog().get(SKU_249)["description"]
    parsed = parse_intent(intent_text="one boat power bank", proposed_cart=[], catalog=catalog())
    assert parsed.status == "validated"
    assert parsed.items == [{"sku": SKU_249, "qty": 1}]


def test_descriptions_are_never_sent_to_the_model(gate):
    """Belt and braces: capture the prompt and assert no description text in it."""
    seen = {}

    class FakeLLM:
        class messages:
            @staticmethod
            def create(**kw):
                seen["prompt"] = kw["messages"][0]["content"]
                return SimpleNamespace(content=[SimpleNamespace(
                    type="text", text=json.dumps({"items": [{"sku": SKU_249, "qty": 1}],
                                                  "suspected_injection": True}))])

    from gate.catalog import catalog
    from gate.intent import parse_intent
    parsed = parse_intent(intent_text="one boat power bank", proposed_cart=[],
                          catalog=catalog(), client=FakeLLM())
    assert "IGNORE PREVIOUS INSTRUCTIONS" not in seen["prompt"]
    assert "Ships from the Bengaluru warehouse" not in seen["prompt"]
    assert parsed.status == "validated" and parsed.advisory["effect"] == "escalate"


def test_llm_output_that_fails_schema_fails_closed(gate):
    class FakeLLM:
        class messages:
            @staticmethod
            def create(**kw):
                return SimpleNamespace(content=[SimpleNamespace(
                    type="text", text=json.dumps({"items": [{"sku": SKU_249, "qty": 1,
                                                             "unit_price_paise": 1}]}))])
    from gate.catalog import catalog
    from gate.intent import parse_intent
    # a price field is not in the schema, so this is rejected outright
    assert parse_intent(intent_text="one power bank", proposed_cart=[],
                        catalog=catalog(), client=FakeLLM()).status == "schema_error"


def test_a_hallucinated_sku_fails_closed(gate):
    class FakeLLM:
        class messages:
            @staticmethod
            def create(**kw):
                return SimpleNamespace(content=[SimpleNamespace(
                    type="text", text=json.dumps({"items": [{"sku": "SKU-99999", "qty": 1}]}))])
    from gate.catalog import catalog
    from gate.intent import parse_intent
    assert parse_intent(intent_text="one power bank", proposed_cart=[],
                        catalog=catalog(), client=FakeLLM()).status == "unknown_sku"


# --- §6: the LLM cannot loosen anything --------------------------------------

def test_an_llm_advisory_cannot_upgrade_a_deny_to_an_allow():
    """The headline property. An LLM signal saying "allow" over a denied
    outcome is ignored and recorded as ignored."""
    from gate.policy.engine import Outcome, apply_advisory
    denied = Outcome("deny", "category.restricted", [], "sha256:t", 1)
    merged = apply_advisory(denied, {"effect": "allow", "source": "llm_intent",
                                     "reason": "model says it is fine"})
    assert merged.effect == "deny" and merged.deciding_rule_id == "category.restricted"
    row = merged.rules_evaluated[-1]
    assert row["advisory"] and row["applied"] is False


def test_an_llm_advisory_can_only_tighten():
    from gate.policy.engine import Outcome, apply_advisory
    allowed = Outcome("allow", None, [], "sha256:t", 1)
    assert apply_advisory(allowed, {"effect": "escalate", "source": "llm_intent"}).effect == "escalate"
    assert apply_advisory(allowed, {"effect": "deny", "source": "llm_intent"}).effect == "deny"
    escalated = Outcome("escalate", "cap.per_txn", [], "sha256:t", 1)
    assert apply_advisory(escalated, {"effect": "allow", "source": "llm_intent"}).effect == "escalate"


def test_a_garbage_advisory_is_ignored():
    from gate.policy.engine import Outcome, apply_advisory
    o = Outcome("escalate", "cap.per_txn", [], "sha256:t", 1)
    assert apply_advisory(o, {"effect": "YOLO"}).effect == "escalate"
    assert apply_advisory(o, None) is o


# --- Phase 6: allow, escalate, approve, timeout ------------------------------

def test_allow_creates_an_order_bound_to_the_decision(gate, agent):
    status, body = post(gate, agent, cart=[{"sku": SKU_1499, "qty": 1}])
    assert status == 200 and body["status"] == "allowed" and body["order_id"].startswith("order_")
    rows = gate.ledger.by_decision(body["decision_id"])
    assert [r["kind"] for r in rows] == ["decision", "execution"]


def test_oversized_cart_escalates_with_an_approval_link(gate, agent):
    status, body = post(gate, agent, cart=[{"sku": SKU_BIG, "qty": 1}])   # ₹24,999 > tier B ₹2,500
    assert status == 202 and body["status"] == "escalation_required"
    assert body["reason"] == "cap.per_txn"
    assert body["observed"] == 2499900 and body["threshold"] == 250000
    assert body["approval_url"].startswith("http://test/approve/")


def approve_flow(gate, agent, outcome="approved"):
    _, body = post(gate, agent, cart=[{"sku": SKU_BIG, "qty": 1}])
    token = body["approval_url"].rsplit("/", 1)[1]
    return body, gate.approve(token, approver="ops@merchant.test", outcome=outcome)


def test_approval_releases_a_payment_link(gate, agent):
    body, (status, result) = approve_flow(gate, agent)
    assert status == 200 and result["status"] == "approved"
    assert result["payment_link_id"].startswith("plink_")
    assert gate.decision_status(body["decision_id"])[1]["status"] == "allowed"


def test_rejection_denies(gate, agent):
    body, (status, result) = approve_flow(gate, agent, outcome="rejected")
    assert result["status"] == "denied" and result["reason"] == "approval_rejected"
    assert gate.decision_status(body["decision_id"])[1]["reason"] == "approval_rejected"


def test_an_approval_token_is_one_shot(gate, agent):
    body, _ = approve_flow(gate, agent)
    token = body["approval_url"].rsplit("/", 1)[1]
    status, result = gate.approve(token, approver="ops@merchant.test")
    assert status == 410 and result["reason"] == "approval_already_used"


def test_approval_is_scoped_to_the_envelope(gate, agent):
    """Rewriting the cart after approval was issued invalidates the token."""
    _, body = post(gate, agent, cart=[{"sku": SKU_BIG, "qty": 1}])
    token = body["approval_url"].rsplit("/", 1)[1]
    gate.conn.execute("UPDATE approvals SET envelope_hash='sha256:someone_elses_cart'"
                      " WHERE decision_id=?", (body["decision_id"],))
    status, result = gate.approve(token, approver="ops@merchant.test")
    assert status == 409 and result["reason"] == "approval_envelope_mismatch"


def test_approval_timeout_fails_closed_with_a_retry_hint(gate, agent):
    _, body = post(gate, agent, cart=[{"sku": SKU_BIG, "qty": 1}])
    later = int(time.time()) + 301
    status, result = gate.decision_status(body["decision_id"], now=later)
    assert status == 403
    assert result == {"status": "denied", "reason": "approval_timeout",
                      "retry_after_s": 900, "decision_id": body["decision_id"]}


def test_approving_after_the_timeout_is_refused(gate, agent):
    _, body = post(gate, agent, cart=[{"sku": SKU_BIG, "qty": 1}])
    token = body["approval_url"].rsplit("/", 1)[1]
    status, result = gate.approve(token, approver="ops@merchant.test", now=int(time.time()) + 301)
    assert status == 410 and result["reason"] in ("approval_expired", "approval_already_used")


def test_restricted_category_is_denied_end_to_end(gate, agent):
    status, body = post(gate, agent, cart=[{"sku": SKU_RESTRICTED, "qty": 1}])
    assert status == 403 and body["reason"] == "category.restricted"


def test_unsigned_request_is_denied_at_the_strictest_tier(gate, agent):
    body, headers = agent.request(cart=[{"sku": SKU_1499, "qty": 1}])
    status, out = gate.process_checkout(body, {"Content-Type": "application/json"})
    assert status == 403 and out["reason"] == "sig.unverified"
    record = gate.ledger.by_decision(out["decision_id"])[0]["record"]
    assert record["agent"]["trust_tier"] == "C"


def test_velocity_evasion_by_splitting_is_caught(gate, agent):
    for i in range(10):
        status, _ = post(gate, agent, cart=[{"sku": "SKU-1050", "qty": 1}])
        assert status == 200, f"request {i + 1} should still be under the limit"
    status, body = post(gate, agent, cart=[{"sku": "SKU-1050", "qty": 1}])   # the 11th
    assert status == 403 and body["reason"] == "velocity.1h"


def test_quantity_overflow_is_denied(gate, agent):
    status, body = post(gate, agent, cart=[{"sku": SKU_249, "qty": 99}])   # max_qty_per_order 10
    assert status == 403 and body["reason"] == "cart.unfulfillable"


# --- Phase 7: reconciliation --------------------------------------------------

def capture_event(decision_id, amount, envelope_hash, payment_id="pay_TEST1", order_id=None,
                  currency="INR"):
    return {"event": "payment.captured",
            "payload": {"payment": {"entity": {
                "id": payment_id, "amount": amount, "currency": currency, "order_id": order_id,
                "notes": {"decision_id": decision_id, "envelope_hash": envelope_hash}}}}}


def allowed_decision(gate, agent):
    _, body = post(gate, agent, cart=[{"sku": SKU_1499, "qty": 1}])
    return body


def test_matching_capture_closes_out(gate, agent):
    from gate.reconciler import on_capture
    body = allowed_decision(gate, agent)
    r = on_capture(gate.conn, gate.ledger, gate.adapter,
                   capture_event(body["decision_id"], 149900, body["envelope_hash"],
                                 order_id=body["order_id"]))
    assert r["status"] == "matched"
    assert [x["kind"] for x in gate.ledger.by_decision(body["decision_id"])][-1] == "reconciliation"


def test_overcapture_is_refunded_to_the_delta_with_an_incident(gate, agent):
    from gate.reconciler import on_capture
    body = allowed_decision(gate, agent)
    r = on_capture(gate.conn, gate.ledger, gate.adapter,
                   capture_event(body["decision_id"], 999900, body["envelope_hash"],
                                 order_id=body["order_id"]))
    assert r["status"] == "mismatch" and r["problems"] == ["amount_mismatch"]
    assert r["delta_paise"] == 850000 and r["refunded_paise"] == 850000
    assert r["refund_id"].startswith("rfnd_") and r["remediation"] == "refund_delta"
    kinds = [x["kind"] for x in gate.ledger.by_decision(body["decision_id"])]
    assert kinds == ["decision", "execution", "reconciliation", "incident"]
    incident = gate.ledger.by_decision(body["decision_id"])[-1]["record"]["incident"]
    assert incident["agent_notice"]["reason"] == "amount_mismatch"


def test_envelope_mismatch_reverses_the_whole_capture(gate, agent):
    from gate.reconciler import on_capture
    body = allowed_decision(gate, agent)
    r = on_capture(gate.conn, gate.ledger, gate.adapter,
                   capture_event(body["decision_id"], 149900, "sha256:a_different_cart",
                                 order_id=body["order_id"]))
    assert "envelope_mismatch" in r["problems"] and r["remediation"] == "refund_full"
    assert r["refunded_paise"] == 149900


def test_undercapture_is_flagged_not_silently_accepted(gate, agent):
    from gate.reconciler import on_capture
    body = allowed_decision(gate, agent)
    r = on_capture(gate.conn, gate.ledger, gate.adapter,
                   capture_event(body["decision_id"], 100, body["envelope_hash"],
                                 order_id=body["order_id"]))
    assert r["status"] == "mismatch" and r["delta_paise"] == -149800
    assert r["remediation"] == "flagged_no_automatic_reversal" and r["refund_id"] is None


def test_duplicate_capture_is_ignored_and_refunds_only_once(gate, agent):
    from gate.reconciler import on_capture
    body = allowed_decision(gate, agent)
    ev = capture_event(body["decision_id"], 999900, body["envelope_hash"], order_id=body["order_id"])
    first = on_capture(gate.conn, gate.ledger, gate.adapter, ev)
    second = on_capture(gate.conn, gate.ledger, gate.adapter, ev)
    assert first["status"] == "mismatch" and second["status"] == "duplicate_ignored"
    kinds = [x["kind"] for x in gate.ledger.by_decision(body["decision_id"])]
    assert kinds.count("reconciliation") == 1


def test_capture_for_an_unknown_decision_writes_an_incident(gate):
    from gate.reconciler import on_capture
    r = on_capture(gate.conn, gate.ledger, gate.adapter,
                   capture_event("dec_never_seen", 5000, "sha256:x"))
    assert r["status"] == "incident" and r["reason"] == "unknown_decision_id"
    assert gate.ledger.by_decision("dec_never_seen")[0]["kind"] == "incident"


def test_capture_with_no_decision_id_writes_an_orphan_incident(gate):
    from gate.reconciler import on_capture
    ev = capture_event("x", 5000, "y", payment_id="pay_ORPHAN")
    ev["payload"]["payment"]["entity"]["notes"] = {}
    r = on_capture(gate.conn, gate.ledger, gate.adapter, ev)
    assert r["reason"] == "capture_without_decision_id"


def test_webhook_signature_is_required():
    from gate.razorpay_adapter import verify_webhook
    import hashlib, hmac
    body = b'{"event":"payment.captured"}'
    good = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert verify_webhook(body, good, "secret")
    assert not verify_webhook(body, good, "wrong-secret")
    assert not verify_webhook(b'{"event":"payment.failed"}', good, "secret")


# --- the chain survives all of it --------------------------------------------

def test_ledger_chain_is_intact_after_a_full_lifecycle(gate, agent):
    from gate.reconciler import on_capture
    post(gate, agent, cart=[{"sku": SKU_1499, "qty": 1}])
    post(gate, agent, cart=[{"sku": SKU_RESTRICTED, "qty": 1}])
    body, _ = approve_flow(gate, agent)
    allowed = allowed_decision(gate, agent)
    on_capture(gate.conn, gate.ledger, gate.adapter,
               capture_event(allowed["decision_id"], 999900, allowed["envelope_hash"]))
    result = verify_chain(gate.conn)
    assert result.ok and result.checked >= 8


def test_replay_reproduces_every_stored_decision(gate, agent):
    from cli.replay import replay
    post(gate, agent, cart=[{"sku": SKU_1499, "qty": 1, "claimed_unit_price_paise": 100}])
    post(gate, agent, cart=[{"sku": SKU_BIG, "qty": 1}])
    post(gate, agent, cart=[{"sku": SKU_RESTRICTED, "qty": 1}])
    ids = [r["decision_id"] for r in gate.conn.execute(
        "SELECT decision_id FROM ledger WHERE kind='decision'")]
    assert len(ids) == 3
    for did in ids:
        ok, detail = replay(did, conn=gate.conn)
        assert ok, detail


def test_a_failed_payment_link_does_not_burn_the_approval_token(gate, agent):
    """Regression: Razorpay rejecting create_payment_link must not leave the
    decision stuck approved-but-unpayable with a dead token."""
    status, body = post(gate, agent, cart=[{"sku": SKU_BIG, "qty": 1}])
    token = body["approval_url"].rsplit("/", 1)[1]

    def boom(**kw):
        raise RuntimeError("expire_by: timestamp must be atleast 15 minutes in future.")
    gate.adapter.create_payment_link = boom

    status, result = gate.approve(token, approver="ops@merchant.test")
    assert status == 502 and result["reason"] == "payment_link_failed"
    assert escalation.peek(gate.conn, token).ok, "token was burned despite the failed call"

    gate.adapter.create_payment_link = RazorpayAdapter(key_id="", key_secret="").create_payment_link
    status, result = gate.approve(token, approver="ops@merchant.test")
    assert status == 200 and result["status"] == "approved"
