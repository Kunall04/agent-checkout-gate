"""FastAPI surface plus the request pipeline itself.

`process_checkout` is a plain function, deliberately: the red-team harness and
the demo script drive it in-process, so what is measured is the gate and not
an HTTP stack. The route is a five-line wrapper around it.
"""
from __future__ import annotations

import html
import json
import os
import time
import urllib.parse
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from gate import escalation
from gate.catalog import Catalog, catalog
from gate.explain import narrate, rupees
from gate.intent import parse_intent
from gate.ledger import Ledger, envelope_hash, new_decision_id
from gate.policy.engine import Bundle, apply_advisory, evaluate, load_bundle
from gate.policy.facts import build_facts
from gate.razorpay_adapter import RazorpayAdapter, verify_webhook
from gate.reconciler import on_capture
from gate.registry import Registry, registry
from gate.signatures import verify_request
from gate.store import init_db

load_dotenv()

CHECKOUT_PATH = "/agent/checkout"
STRICTEST_TIER = "C"          # what an unidentified caller gets
RETRY_AFTER_S = 900


class Gate:
    """Everything the pipeline needs, in one place, so tests can swap any of it."""

    def __init__(self, conn=None, *, adapter=None, cat: Catalog | None = None,
                 reg: Registry | None = None, bundle: Bundle | None = None,
                 base_url: str | None = None, llm=None):
        self.conn = conn or init_db()
        self.ledger = Ledger(self.conn)
        self.adapter = adapter or RazorpayAdapter()
        self.catalog = cat or catalog()
        self.registry = reg or registry()
        self.bundle = bundle or load_bundle()
        self.base_url = base_url or os.getenv("GATE_BASE_URL", "http://127.0.0.1:8000")
        self.llm = llm

    # --- pipeline ------------------------------------------------------------

    def process_checkout(self, raw_body: bytes, headers: dict[str, str],
                         now: int | None = None) -> tuple[int, dict[str, Any]]:
        now = int(time.time()) if now is None else now
        decision_id = new_decision_id()

        try:
            body = json.loads(raw_body)
            if not isinstance(body, dict):
                raise ValueError
        except (json.JSONDecodeError, ValueError):
            body = {}
        claimed_agent_id = body.get("agent_id")

        sig = verify_request("POST", CHECKOUT_PATH, raw_body, headers,
                             registry=self.registry, conn=self.conn, now=now,
                             claimed_agent_id=claimed_agent_id)
        agent = {"agent_id": sig.agent_id or claimed_agent_id or "unknown",
                 "key_id": sig.key_id, "sig_verified": sig.ok, "sig_reason": sig.reason,
                 # tier always comes from the verified key; an unverified caller
                 # is treated as the strictest tier, never as what it claims.
                 "trust_tier": sig.trust_tier if sig.ok else STRICTEST_TIER,
                 "registry_version": self.registry.version}

        intent = parse_intent(intent_text=body.get("intent_text", "") or "",
                              proposed_cart=body.get("proposed_cart") or [],
                              catalog=self.catalog, client=self.llm)

        # Price from the catalog. The agent's claimed prices ride along only so
        # the record can show what was claimed and refused.
        claims = {str(l.get("sku")): l.get("claimed_unit_price_paise")
                  for l in (body.get("proposed_cart") or []) if isinstance(l, dict)}
        cart = self.catalog.price_cart([
            {"sku": i["sku"], "qty": i["qty"], "claimed_unit_price_paise": claims.get(i["sku"])}
            for i in intent.items])

        window = self.ledger.window(agent["agent_id"], now=now)
        # Count the attempt in front of us, so "more than 10 in an hour" denies
        # the eleventh request rather than the twelfth.
        window["txn_count_1h"] += 1
        facts = build_facts(agent=agent, cart=cart, window=window, intent=intent.to_dict())
        outcome = apply_advisory(evaluate(facts, self.bundle), intent.advisory)

        env_hash = envelope_hash(decision_id, cart)
        record: dict[str, Any] = {
            "request_hash": "sha256:" + __import__("hashlib").sha256(raw_body).hexdigest(),
            "agent": agent,
            "intent": intent.to_dict(),
            "cart": cart,
            "facts_snapshot": facts,   # not in the §5.2 sample; replay is impossible without it
            "policy": outcome.to_dict(),
            "outcome": {"effect": outcome.effect, "bound_amount_paise": cart["total_paise"],
                        "bound_currency": cart["currency"], "envelope_hash": env_hash,
                        "ttl_s": escalation.TTL_S if outcome.effect == "escalate" else None},
            "escalation": {"required": outcome.effect == "escalate", "token_hash": None,
                           "approver": None, "responded_at": None, "timed_out": False},
            "execution": {"razorpay_order_id": None, "payment_id": None, "captured_paise": None},
            "reconciliation": {"status": "pending", "delta_paise": 0, "remediation": None},
            "explanation": {"text": None, "generated_by": None, "regenerable": True},
        }

        deciding = next((r for r in outcome.rules_evaluated
                         if r["rule_id"] == outcome.deciding_rule_id), None)

        if outcome.effect == "escalate":
            token, th = escalation.issue(self.conn, decision_id=decision_id,
                                         envelope_hash=env_hash, now=now)
            record["escalation"]["token_hash"] = th

        row = self.ledger.append(kind="decision", decision_id=decision_id,
                                 agent_id=agent["agent_id"], record=record, now=now)

        if outcome.effect == "allow":
            order = self.adapter.create_order(amount_paise=cart["total_paise"],
                                              decision_id=decision_id, envelope_hash=env_hash)
            self.ledger.append(kind="execution", decision_id=decision_id, agent_id=agent["agent_id"],
                               record={"execution": {"razorpay_order_id": order["id"],
                                                     "amount_paise": cart["total_paise"],
                                                     "mock": order.get("_mock", False)}}, now=now)
            return 200, {"status": "allowed", "decision_id": decision_id,
                         "order_id": order["id"], "amount_paise": cart["total_paise"],
                         "currency": cart["currency"], "envelope_hash": env_hash,
                         "ledger_seq": row["seq"]}

        if outcome.effect == "escalate":
            return 202, {"status": "escalation_required", "decision_id": decision_id,
                         "envelope_hash": env_hash,
                         "reason": outcome.deciding_rule_id,
                         "explain": outcome.explain,
                         "observed": (deciding or {}).get("observed"),
                         "threshold": (deciding or {}).get("threshold"),
                         "amount_paise": cart["total_paise"],
                         "approval_url": f"{self.base_url}/approve/{token}",
                         "expires_in_s": escalation.TTL_S,
                         "poll_url": f"{self.base_url}/agent/decision/{decision_id}"}

        return 403, {"status": "denied", "decision_id": decision_id,
                     "envelope_hash": env_hash,
                     "reason": outcome.deciding_rule_id, "explain": outcome.explain,
                     "observed": (deciding or {}).get("observed"),
                     "threshold": (deciding or {}).get("threshold"),
                     "amount_paise": cart["total_paise"], "retry_after_s": RETRY_AFTER_S}

    # --- escalation ----------------------------------------------------------

    def sweep_timeouts(self, now: int | None = None) -> list[str]:
        """Silence is a no. Every approval past its TTL becomes a recorded deny."""
        now = int(time.time()) if now is None else now
        timed_out = []
        for row in escalation.expire_due(self.conn, now):
            self.conn.execute("UPDATE approvals SET used_at=?, outcome='timed_out'"
                              " WHERE token_hash=? AND used_at IS NULL", (now, row["token_hash"]))
            self.ledger.append(kind="escalation_timeout", decision_id=row["decision_id"],
                               record={"escalation": {"required": True, "approver": None,
                                                      "responded_at": None, "timed_out": True},
                                       "outcome": {"effect": "deny", "bound_amount_paise": 0,
                                                   "bound_currency": "INR"},
                                       "reason": "approval_timeout"}, now=now)
            timed_out.append(row["decision_id"])
        return timed_out

    def decision_status(self, decision_id: str, now: int | None = None) -> tuple[int, dict[str, Any]]:
        self.sweep_timeouts(now)
        rows = self.ledger.by_decision(decision_id)
        if not rows:
            return 404, {"status": "unknown_decision", "decision_id": decision_id}
        kinds = {r["kind"]: r["record"] for r in rows}
        if "escalation_timeout" in kinds:
            return 403, {"status": "denied", "reason": "approval_timeout",
                         "retry_after_s": RETRY_AFTER_S, "decision_id": decision_id}
        if "approval" in kinds and kinds["approval"]["escalation"].get("outcome") == "rejected":
            return 403, {"status": "denied", "reason": "approval_rejected",
                         "retry_after_s": RETRY_AFTER_S, "decision_id": decision_id}
        if "execution" in kinds:
            ex = kinds["execution"]["execution"]
            return 200, {"status": "allowed", "decision_id": decision_id,
                         "order_id": ex.get("razorpay_order_id"),
                         "payment_link": ex.get("payment_link_url"),
                         "amount_paise": ex.get("amount_paise")}
        decision = kinds.get("decision", {})
        effect = decision.get("outcome", {}).get("effect")
        if effect == "escalate":
            return 202, {"status": "pending_approval", "decision_id": decision_id,
                         "expires_in_s": decision["outcome"].get("ttl_s")}
        return 403, {"status": "denied", "decision_id": decision_id,
                     "reason": decision.get("policy", {}).get("deciding_rule_id"),
                     "retry_after_s": RETRY_AFTER_S}

    def approve(self, token: str, *, approver: str, outcome: str = "approved",
                now: int | None = None) -> tuple[int, dict[str, Any]]:
        now = int(time.time()) if now is None else now
        self.sweep_timeouts(now)
        state = escalation.peek(self.conn, token, now)
        if not state.ok:
            return 410, {"status": "denied", "reason": f"approval_{state.reason}",
                         "retry_after_s": RETRY_AFTER_S, "decision_id": state.decision_id}

        rows = self.ledger.by_decision(state.decision_id)
        decision = next((r["record"] for r in rows if r["kind"] == "decision"), None)
        if decision is None:
            return 404, {"status": "denied", "reason": "unknown_decision"}

        # Re-derive the envelope from the ledger and require it to match what
        # was approved: a cart changed by one paise invalidates the approval.
        current = envelope_hash(state.decision_id, decision["cart"])

        link = None
        if outcome == "approved":
            # Talk to Razorpay BEFORE burning the one-time token. If this call
            # fails, the token must still be redeemable on retry — otherwise a
            # transient Razorpay error leaves the decision approved-but-unpayable
            # forever, with no path to either a payment or a timeout.
            # ponytail: a second concurrent click could lose the redeem race
            # below after already creating a payment link here — an orphaned,
            # unused Razorpay object, not a double-charge. Add per-token locking
            # if that shows up in practice.
            try:
                link = self.adapter.create_payment_link(
                    amount_paise=decision["cart"]["total_paise"], decision_id=state.decision_id,
                    envelope_hash=current, description=f"Approved agent order {state.decision_id}",
                    callback_url=f"{self.base_url}/agent/decision/{state.decision_id}")
            except Exception as e:
                return 502, {"status": "error", "reason": "payment_link_failed",
                             "detail": str(e), "decision_id": state.decision_id}

        red = escalation.redeem(self.conn, token, approver=approver, outcome=outcome,
                                expect_envelope_hash=current, now=now)
        if not red.ok:
            return 409, {"status": "denied", "reason": f"approval_{red.reason}",
                         "decision_id": state.decision_id}

        self.ledger.append(kind="approval", decision_id=state.decision_id,
                           agent_id=decision["agent"]["agent_id"],
                           record={"escalation": {"required": True, "approver": approver,
                                                  "responded_at": now, "timed_out": False,
                                                  "outcome": outcome,
                                                  "envelope_hash": current}}, now=now)
        if outcome != "approved":
            return 200, {"status": "denied", "reason": "approval_rejected",
                         "decision_id": state.decision_id, "retry_after_s": RETRY_AFTER_S}

        self.ledger.append(kind="execution", decision_id=state.decision_id,
                           agent_id=decision["agent"]["agent_id"],
                           record={"execution": {"razorpay_order_id": link.get("order_id"),
                                                 "payment_link_id": link["id"],
                                                 "payment_link_url": link.get("short_url"),
                                                 "amount_paise": decision["cart"]["total_paise"],
                                                 "mock": link.get("_mock", False)}}, now=now)
        return 200, {"status": "approved", "decision_id": state.decision_id,
                     "payment_link": link.get("short_url"), "payment_link_id": link["id"],
                     "amount_paise": decision["cart"]["total_paise"]}


# --- HTTP --------------------------------------------------------------------

app = FastAPI(title="Agent Checkout Gate", docs_url=None, redoc_url=None)
_gate: Gate | None = None


def gate() -> Gate:
    global _gate
    if _gate is None:
        _gate = Gate()
    return _gate


@app.post(CHECKOUT_PATH)
async def checkout(request: Request):
    raw = await request.body()
    status, payload = gate().process_checkout(raw, dict(request.headers))
    return JSONResponse(payload, status_code=status)


@app.get("/agent/decision/{decision_id}")
async def decision_status(decision_id: str):
    status, payload = gate().decision_status(decision_id)
    return JSONResponse(payload, status_code=status)


@app.post("/webhooks/razorpay")
async def razorpay_webhook(request: Request):
    raw = await request.body()
    # Verified before the body is even parsed. Unsigned webhooks do not exist.
    if not verify_webhook(raw, request.headers.get("x-razorpay-signature", "")):
        return JSONResponse({"status": "rejected", "reason": "bad_webhook_signature"}, status_code=400)
    event = json.loads(raw)
    if event.get("event") != "payment.captured":
        return JSONResponse({"status": "ignored", "event": event.get("event")})
    g = gate()
    return JSONResponse(on_capture(g.conn, g.ledger, g.adapter, event))


def _approval_page(g: Gate, token: str, message: str = "") -> HTMLResponse:
    state = escalation.peek(g.conn, token)
    if not state.ok:
        return HTMLResponse(f"<h1>This approval link is {html.escape(state.reason)}.</h1>", status_code=410)
    decision = next((r["record"] for r in g.ledger.by_decision(state.decision_id)
                     if r["kind"] == "decision"), None)
    rule = next((r for r in decision["policy"]["rules_evaluated"]
                 if r["rule_id"] == decision["policy"]["deciding_rule_id"]), {})
    rows = "".join(
        f"<tr><td>{html.escape(i['sku'])}</td><td>{html.escape(i['category'])}</td>"
        f"<td>{i['qty']}</td><td>{rupees(i['unit_price_paise'])}</td>"
        f"<td>{rupees(i['line_total_paise'])}</td><td>{i['price_source']}</td></tr>"
        for i in decision["cart"]["items"])
    claims = "".join(
        f"<li>Agent claimed {rupees(d['claimed_unit_price_paise'])} for {html.escape(d['sku'])}; "
        f"catalog says {rupees(d['catalog_unit_price_paise'])}. Catalog wins.</li>"
        for d in decision["cart"].get("discarded_price_claims", []))
    return HTMLResponse(f"""<!doctype html><meta charset=utf-8>
<title>Approve agent order {html.escape(state.decision_id)}</title>
<body style="font-family:system-ui;max-width:52rem;margin:2rem auto;line-height:1.5">
<h1>Approval required</h1>
<p style="color:#b00">{html.escape(message)}</p>
<p><b>Agent</b> {html.escape(decision['agent']['agent_id'])} (tier {html.escape(decision['agent']['trust_tier'])},
   signature {html.escape(decision['agent']['sig_reason'])})<br>
   <b>Requested</b> {html.escape(decision['intent']['parsed'].get('items') and str(decision['intent']['parsed']['items']) or '')}<br>
   <b>Decision</b> {html.escape(state.decision_id)}</p>
<h2>Cart, priced from the merchant catalog</h2>
<table border=1 cellpadding=6 style="border-collapse:collapse">
<tr><th>SKU<th>Category<th>Qty<th>Unit<th>Line<th>Price source</tr>{rows}
<tr><td colspan=4></td><td><b>{rupees(decision['cart']['total_paise'])}</b></td><td></td></tr></table>
{f'<h3>Price claims discarded</h3><ul>{claims}</ul>' if claims else ''}
<h2>Rule that fired</h2>
<p><code>{html.escape(str(rule.get('rule_id')))}</code> — {html.escape(str(rule.get('explain')))}<br>
observed <b>{html.escape(str(rule.get('observed')))}</b>,
threshold <b>{html.escape(str(rule.get('threshold')))}</b></p>
<p>Bundle <code>{html.escape(decision['policy']['bundle_hash'][:23])}…</code></p>
<form method=post><button name=action value=approve>Approve</button>
<button name=action value=reject>Reject</button></form>
<p><small>This link is one-time and expires. No response is a denial.</small></p>
</body>""")


@app.get("/approve/{token}")
async def approval_page(token: str):
    return _approval_page(gate(), token)


@app.post("/approve/{token}")
async def approval_submit(token: str, request: Request):
    # urlencoded by hand rather than pulling in python-multipart for one field.
    form = urllib.parse.parse_qs((await request.body()).decode())
    action = "approved" if form.get("action", [""])[0] == "approve" else "rejected"
    status, payload = gate().approve(token, approver="ops@merchant.test", outcome=action)
    return HTMLResponse(
        f"<!doctype html><meta charset=utf-8><body style='font-family:system-ui;margin:2rem'>"
        f"<h1>{html.escape(payload['status'])}</h1><pre>{html.escape(json.dumps(payload, indent=2))}</pre>"
        + (f"<p><a href='{html.escape(payload['payment_link'])}'>Payment link</a></p>"
           if payload.get("payment_link") else ""),
        status_code=status)


@app.get("/healthz")
async def healthz():
    g = gate()
    return {"ok": True, "razorpay_mock": g.adapter.mock,
            "bundle_hash": g.bundle.hash, "catalog_version": g.catalog.version,
            "ledger_head": g.ledger.head()}
