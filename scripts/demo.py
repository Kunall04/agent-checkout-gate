"""The seven-step demo from the project spec §10, in order, in one take.

    ./scripts/demo.sh          (or: make demo)

Resets data/gate.db so the run is repeatable. With Razorpay test keys in .env
steps 1, 3 and 5 hit the real test-mode API and are visible in the dashboard;
without them the adapter runs in MOCK mode and says so on every line.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from buyer_agent.agent import BuyerAgent
from gate.app import Gate
from gate.catalog import catalog
from gate.explain import rupees
from gate.ledger import Ledger, canonical
from gate.razorpay_adapter import RazorpayAdapter
from gate.reconciler import on_capture
from gate.store import init_db

DB = pathlib.Path("data/gate.db")
PY = sys.executable
BOLD, DIM, RED, GREEN, YEL, OFF = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"


def step(n: int, title: str) -> None:
    print(f"\n{BOLD}{'─' * 78}\n {n}. {title}\n{'─' * 78}{OFF}")


def show(label: str, payload: dict) -> None:
    print(f"{DIM}{label}{OFF}\n{json.dumps(payload, indent=2)[:1400]}")


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    print(f"{DIM}$ {' '.join(cmd)}{OFF}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    print(proc.stdout.rstrip() or proc.stderr.rstrip())
    return proc


def main() -> int:
    for suffix in ("", "-wal", "-shm"):
        pathlib.Path(str(DB) + suffix).unlink(missing_ok=True)

    gate = Gate(init_db(DB), base_url="http://127.0.0.1:8000")
    agent = BuyerAgent()
    cat = catalog()
    mode = "MOCK (no test keys in .env)" if gate.adapter.mock else f"REAL test mode {gate.adapter.key_id}"
    print(f"{BOLD}Agent Checkout Gate — demo{OFF}\n"
          f"  catalog   {cat.version} ({len(cat.items)} SKUs)\n"
          f"  bundle    {gate.bundle.hash}\n"
          f"  razorpay  {mode}")

    sku = "SKU-1062"                      # Rs 1,499.00
    big = "SKU-1134"                      # Rs 24,999.00
    truth = cat.get(sku)["unit_price_paise"]

    # ---------------------------------------------------------------- 1
    step(1, f"Attack succeeds with the gate BYPASSED — agent claims Rs 1 for a {rupees(truth)} SKU")
    bypass = RazorpayAdapter()
    order = bypass.create_order(amount_paise=100, decision_id="dec_no_gate", envelope_hash="none")
    print(f"{RED}Order created straight from the agent's claimed price: "
          f"{order['id']} for {rupees(order['amount'])}{OFF}")
    print(f"{DIM}The merchant just sold a {rupees(truth)} item for {rupees(100)}.{OFF}")

    # ---------------------------------------------------------------- 2
    step(2, "Same attack with the gate ON")
    status, denied = gate.process_checkout(*agent.request(
        cart=[{"sku": sku, "qty": 1, "claimed_unit_price_paise": 100}]))
    show(f"HTTP {status}", denied)
    record = gate.ledger.by_decision(denied["decision_id"])[0]["record"]
    claim = record["cart"]["discarded_price_claims"][0]
    print(f"{GREEN}DENIED by {denied['reason']}: observed {denied['observed']} bps under catalog, "
          f"threshold {denied['threshold']}.{OFF}")
    print(f"  claimed {rupees(claim['claimed_unit_price_paise'])}, "
          f"catalog {rupees(claim['catalog_unit_price_paise'])}, "
          f"priced at {rupees(record['cart']['total_paise'])} from source "
          f"'{record['cart']['items'][0]['price_source']}'")

    # ---------------------------------------------------------------- 3
    step(3, f"Legitimate oversized cart ({rupees(cat.get(big)['unit_price_paise'])}, tier B ceiling "
            f"{rupees(gate.bundle.limits['per_txn_paise']['B'])}) — ESCALATE, human approves")
    status, esc = gate.process_checkout(*agent.request(cart=[{"sku": big, "qty": 1}]))
    show(f"HTTP {status}", esc)
    token = esc["approval_url"].rsplit("/", 1)[1]
    print(f"{YEL}Approver opens {esc['approval_url']} and clicks Approve.{OFF}")
    status, approved = gate.approve(token, approver="ops@merchant.test")
    show(f"HTTP {status}", approved)
    print(f"{GREEN}Payment link released only after a human said yes.{OFF}")

    # ---------------------------------------------------------------- 4
    step(4, "Approval timeout — fail closed")
    status, pending = gate.process_checkout(*agent.request(cart=[{"sku": big, "qty": 1}]))
    print(f"{DIM}escalated {pending['decision_id']}, TTL {pending['expires_in_s']}s; "
          f"nobody answers...{OFF}")
    status, timed_out = gate.decision_status(pending["decision_id"],
                                             now=int(time.time()) + pending["expires_in_s"] + 1)
    show(f"HTTP {status}", timed_out)
    print(f"{GREEN}Silence is a denial, with a retry hint the agent can act on.{OFF}")

    # ---------------------------------------------------------------- 5
    step(5, "Capture mismatch — automatic reversal + incident record")
    # A different agent: agt_shopper_01 has spent its 24h tier-B allowance in
    # steps 3 and 4, and would now escalate on cap.daily rather than allow.
    procurement = BuyerAgent(agent_id="agt_procure_ent")
    status, allowed = gate.process_checkout(*procurement.request(cart=[{"sku": sku, "qty": 1}]))
    assert status == 200, allowed
    print(f"{DIM}approved {rupees(allowed['amount_paise'])}, order {allowed['order_id']}{OFF}")
    inflated = allowed["amount_paise"] * 7
    print(f"{RED}...but the capture that arrives is {rupees(inflated)}.{OFF}")
    # The overcapture itself is fabricated — there's no way to make Razorpay
    # actually capture the wrong amount on demand. Refunding a payment id that
    # never really existed always goes through the mock adapter, real keys or
    # not: a real refund call against a fake payment_id would 500. The refund
    # LOGIC being exercised here is identical to a real one (see step 3, where
    # a real payment link was created with these same keys).
    mock_adapter = RazorpayAdapter(key_id="", key_secret="")
    result = on_capture(gate.conn, gate.ledger, mock_adapter, {
        "event": "payment.captured", "payload": {"payment": {"entity": {
            "id": "pay_DEMO_MISMATCH", "amount": inflated, "currency": "INR",
            "order_id": allowed["order_id"],
            "notes": {"decision_id": allowed["decision_id"],
                      "envelope_hash": allowed["envelope_hash"]}}}}})
    show("reconciler", result)
    incident = gate.ledger.by_decision(allowed["decision_id"])[-1]["record"]["incident"]
    show("incident record linked to the decision", incident)
    print(f"{GREEN}Refund {result['refund_id']} for {rupees(result['refunded_paise'])} issued "
          f"automatically (MOCK — this capture never really happened, so there is nothing real "
          f"to refund; the refund call itself works the same way against a real one, as step 3 proved).{OFF}")
    dup = on_capture(gate.conn, gate.ledger, mock_adapter, {
        "event": "payment.captured", "payload": {"payment": {"entity": {
            "id": "pay_DEMO_MISMATCH", "amount": inflated, "currency": "INR",
            "order_id": allowed["order_id"],
            "notes": {"decision_id": allowed["decision_id"],
                      "envelope_hash": allowed["envelope_hash"]}}}}})
    print(f"{GREEN}Webhook retry: {dup['status']} — refunded once, not twice.{OFF}")

    # ---------------------------------------------------------------- 6
    step(6, "Replay reproduces the decision; then tamper with the ledger")
    run([PY, "-m", "cli.replay", denied["decision_id"]])
    run([PY, "-m", "cli.verify_chain"])
    print(f"\n{RED}An insider edits one row: cart total 149900 -> 1 paise.{OFF}")
    row = gate.conn.execute(
        "SELECT seq, record FROM ledger WHERE decision_id=? AND kind='decision'",
        (denied["decision_id"],)).fetchone()
    doc = json.loads(row["record"])
    doc["cart"]["total_paise"] = 1
    doc["facts_snapshot"]["cart"]["total_paise"] = 1     # so replay diverges too
    gate.conn.execute("UPDATE ledger SET record=? WHERE seq=?", (canonical(doc), row["seq"]))
    proc = run([PY, "-m", "cli.verify_chain"])
    print(f"{GREEN}Tampering detected and the broken link named.{OFF}"
          if proc.returncode else f"{RED}TAMPER NOT DETECTED{OFF}")
    print(f"{DIM}...and replay no longer reproduces the recorded outcome either:{OFF}")
    run([PY, "-m", "cli.replay", denied["decision_id"]])

    # ---------------------------------------------------------------- 7
    step(7, "Red-team corpus — 40 adversarial, 60 benign")
    run([PY, "-m", "redteam.run", "--quiet"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
