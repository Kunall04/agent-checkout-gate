"""Phase 2 acceptance: valid passes; tampered body, unknown key, stale
timestamp and reused nonce each fail with a *distinct* reason."""
import base64
import time

import pytest
from nacl.signing import SigningKey

from buyer_agent.agent import BuyerAgent, CHECKOUT_PATH
from gate.registry import registry
from gate.signatures import verify_request
from gate.store import init_db


@pytest.fixture
def conn():
    return init_db(":memory:")


def verify(body, headers, conn, **kw):
    return verify_request("POST", CHECKOUT_PATH, body, headers,
                          registry=registry(), conn=conn, **kw)


def test_valid_signature_passes(conn):
    body, headers = BuyerAgent().request(cart=[{"sku": "SKU-1042", "qty": 1}])
    r = verify(body, headers, conn)
    assert r.ok and r.reason == "verified"
    assert r.agent_id == "agt_shopper_01" and r.trust_tier == "B"


def test_tampered_body_fails(conn):
    a = BuyerAgent()
    honest = a.build(cart=[{"sku": "SKU-1042", "qty": 1}])
    evil = dict(honest, proposed_cart=[{"sku": "SKU-1042", "qty": 99}])
    body, headers = a.sign(honest, tamper_body=evil)  # headers signed over `honest`
    assert verify(body, headers, conn).reason == "digest_mismatch"


def test_tampered_digest_header_still_fails(conn):
    """Attacker rewrites body *and* Content-Digest but cannot re-sign."""
    from gate.signatures import content_digest
    a = BuyerAgent()
    evil = a.build(cart=[{"sku": "SKU-1042", "qty": 99}])
    body, headers = a.sign(a.build(cart=[{"sku": "SKU-1042", "qty": 1}]), tamper_body=evil)
    headers["Content-Digest"] = content_digest(body)
    assert verify(body, headers, conn).reason == "signature_invalid"


def test_unknown_key_fails(conn):
    stranger = BuyerAgent(agent_id="agt_shopper_01", seed=bytes(SigningKey.generate()._seed))
    body, headers = stranger.request(cart=[{"sku": "SKU-1042", "qty": 1}])
    headers["Signature-Input"] = headers["Signature-Input"].replace(
        'keyid="agt_shopper_01.k1"', 'keyid="agt_nobody.k9"')
    assert verify(body, headers, conn).reason == "unknown_key"


def test_known_keyid_wrong_private_key_fails(conn):
    """Right keyid, attacker's key: signature check, not registry lookup, stops it."""
    forger = BuyerAgent(agent_id="agt_shopper_01", seed=bytes(SigningKey.generate()._seed))
    body, headers = forger.request(cart=[{"sku": "SKU-1042", "qty": 1}])
    assert verify(body, headers, conn).reason == "signature_invalid"


def test_stale_timestamp_fails(conn):
    body, headers = BuyerAgent().request(cart=[{"sku": "SKU-1042", "qty": 1}],
                                         created=int(time.time()) - 3600)
    assert verify(body, headers, conn).reason == "stale_timestamp"


def test_future_timestamp_fails(conn):
    body, headers = BuyerAgent().request(cart=[{"sku": "SKU-1042", "qty": 1}],
                                         created=int(time.time()) + 3600)
    assert verify(body, headers, conn).reason == "stale_timestamp"


def test_reused_nonce_fails(conn):
    body, headers = BuyerAgent().request(cart=[{"sku": "SKU-1042", "qty": 1}])
    assert verify(body, headers, conn).ok
    assert verify(body, headers, conn).reason == "nonce_replay"   # byte-identical replay


def test_revoked_key_fails(conn):
    body, headers = BuyerAgent(agent_id="agt_revoked_09").request(cart=[{"sku": "SKU-1042", "qty": 1}])
    assert verify(body, headers, conn).reason == "revoked_key"


def test_body_agent_id_must_match_keyid(conn):
    a = BuyerAgent()
    payload = a.build(cart=[{"sku": "SKU-1042", "qty": 1}])
    payload["agent_id"] = "agt_procure_ent"          # claim a higher tier in the body
    body, headers = a.sign(payload)
    r = verify(body, headers, conn, claimed_agent_id="agt_procure_ent")
    assert r.reason == "agent_id_mismatch"
    assert r.trust_tier == "B", "tier must come from the key, never the body"


def test_missing_and_malformed_headers(conn):
    body, headers = BuyerAgent().request(cart=[{"sku": "SKU-1042", "qty": 1}])
    assert verify(body, {}, conn).reason == "missing_signature"
    assert verify(body, dict(headers, **{"Signature-Input": "garbage"}), conn).reason == "malformed_signature_input"
    assert verify(body, dict(headers, **{
        "Signature-Input": headers["Signature-Input"].replace('alg="ed25519"', 'alg="rsa-pss-sha512"')
    }), conn).reason == "unsupported_alg"


def test_failed_signature_does_not_burn_the_nonce(conn):
    """A forged request must not let an attacker consume a victim's nonce."""
    a = BuyerAgent()
    good_body, good_headers = a.request(cart=[{"sku": "SKU-1042", "qty": 1}])
    forger = BuyerAgent(agent_id="agt_shopper_01", seed=bytes(SigningKey.generate()._seed))
    nonce = good_headers["Signature-Input"].split('nonce="')[1].rstrip('"')
    bad_body, bad_headers = forger.request(cart=[{"sku": "SKU-1042", "qty": 1}], nonce=nonce)
    assert verify(bad_body, bad_headers, conn).reason == "signature_invalid"
    assert verify(good_body, good_headers, conn).ok, "victim's nonce was burned by a forgery"


def test_signature_base_is_exactly_rfc_shaped():
    from gate.signatures import signature_base
    base = signature_base("post", "/agent/checkout", "sha-256=:AA=:", '("@method");created=1')
    assert base == ('"@method": POST\n'
                    '"@path": /agent/checkout\n'
                    '"content-digest": sha-256=:AA=:\n'
                    '"@signature-params": ("@method");created=1')
