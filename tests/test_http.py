"""The HTTP surface: routes, the approval page, and webhook verification."""
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

import gate.app as app_module
from buyer_agent.agent import BuyerAgent
from gate.razorpay_adapter import RazorpayAdapter
from gate.store import init_db


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", "whsec_test")
    app_module._gate = app_module.Gate(init_db(":memory:"),
                                       adapter=RazorpayAdapter(key_id="", key_secret=""),
                                       base_url="http://test")
    yield TestClient(app_module.app)
    app_module._gate = None


@pytest.fixture
def agent():
    return BuyerAgent()


def send(client, agent, **kw):
    body, headers = agent.request(**kw)
    return client.post("/agent/checkout", content=body, headers=headers)


def test_healthz_reports_the_pinned_artifacts(client):
    body = client.get("/healthz").json()
    assert body["bundle_hash"].startswith("sha256:") and body["catalog_version"].startswith("cat_")


def test_allow_over_http(client, agent):
    r = send(client, agent, cart=[{"sku": "SKU-1062", "qty": 1}])
    assert r.status_code == 200 and r.json()["order_id"].startswith("order_")


def test_deny_over_http_carries_the_evidence(client, agent):
    r = send(client, agent, cart=[{"sku": "SKU-1062", "qty": 1, "claimed_unit_price_paise": 100}])
    assert r.status_code == 403
    assert r.json()["reason"] == "price.substitution" and r.json()["observed"] == 9993


def test_approval_page_shows_the_catalog_cart_and_the_rule(client, agent):
    esc = send(client, agent, cart=[{"sku": "SKU-1134", "qty": 1}]).json()
    token = esc["approval_url"].rsplit("/", 1)[1]
    page = client.get(f"/approve/{token}")
    assert page.status_code == 200
    for expected in ("cap.per_txn", "₹24,999.00", "250000", "catalog", "agt_shopper_01"):
        assert expected in page.text

    assert client.post(f"/approve/{token}", data={"action": "approve"}).status_code == 200
    assert client.get(f"/agent/decision/{esc['decision_id']}").json()["status"] == "allowed"
    assert client.get(f"/approve/{token}").status_code == 410     # one-shot


def test_rejecting_from_the_page_denies(client, agent):
    esc = send(client, agent, cart=[{"sku": "SKU-1134", "qty": 1}]).json()
    token = esc["approval_url"].rsplit("/", 1)[1]
    client.post(f"/approve/{token}", data={"action": "reject"})
    assert client.get(f"/agent/decision/{esc['decision_id']}").json()["reason"] == "approval_rejected"


def test_unknown_decision_poll_is_404(client):
    assert client.get("/agent/decision/dec_nope").status_code == 404


def signed_capture(secret: bytes, **entity):
    body = json.dumps({"event": "payment.captured",
                       "payload": {"payment": {"entity": entity}}}).encode()
    return body, hmac.new(secret, body, hashlib.sha256).hexdigest()


def test_webhook_without_a_valid_signature_is_rejected(client):
    body, _ = signed_capture(b"whsec_test", id="pay_X", amount=1, currency="INR", notes={})
    assert client.post("/webhooks/razorpay", content=body,
                       headers={"X-Razorpay-Signature": "deadbeef"}).status_code == 400
    assert client.post("/webhooks/razorpay", content=body).status_code == 400
    forged = hmac.new(b"guessed", body, hashlib.sha256).hexdigest()
    r = client.post("/webhooks/razorpay", content=body, headers={"X-Razorpay-Signature": forged})
    assert r.status_code == 400 and r.json()["reason"] == "bad_webhook_signature"


def test_signed_capture_is_reconciled(client, agent):
    allowed = send(client, agent, cart=[{"sku": "SKU-1062", "qty": 1}]).json()
    body, sig = signed_capture(b"whsec_test", id="pay_OK", amount=allowed["amount_paise"],
                               currency="INR", order_id=allowed["order_id"],
                               notes={"decision_id": allowed["decision_id"],
                                      "envelope_hash": allowed["envelope_hash"]})
    r = client.post("/webhooks/razorpay", content=body, headers={"X-Razorpay-Signature": sig})
    assert r.status_code == 200 and r.json()["status"] == "matched"


def test_signed_overcapture_is_refunded_over_http(client, agent):
    allowed = send(client, agent, cart=[{"sku": "SKU-1062", "qty": 1}]).json()
    body, sig = signed_capture(b"whsec_test", id="pay_BIG", amount=allowed["amount_paise"] * 4,
                               currency="INR", order_id=allowed["order_id"],
                               notes={"decision_id": allowed["decision_id"],
                                      "envelope_hash": allowed["envelope_hash"]})
    r = client.post("/webhooks/razorpay", content=body, headers={"X-Razorpay-Signature": sig}).json()
    assert r["status"] == "mismatch" and r["refunded_paise"] == allowed["amount_paise"] * 3


def test_non_capture_events_are_ignored(client):
    body = json.dumps({"event": "payment.failed"}).encode()
    sig = hmac.new(b"whsec_test", body, hashlib.sha256).hexdigest()
    r = client.post("/webhooks/razorpay", content=body, headers={"X-Razorpay-Signature": sig})
    assert r.json() == {"status": "ignored", "event": "payment.failed"}
