"""Phase 4 acceptance: append-only hash chain, Ed25519 per record, tampering
is detected and the broken link is named."""
import json

import pytest

from gate.ledger import GENESIS, Ledger, canonical, new_decision_id, verify_chain
from gate.store import init_db


@pytest.fixture
def led():
    return Ledger(init_db(":memory:"))


def rec(total=24900, effect="allow"):
    return {"agent": {"agent_id": "agt_shopper_01", "trust_tier": "B"},
            "cart": {"total_paise": total},
            "outcome": {"effect": effect, "bound_amount_paise": total, "bound_currency": "INR"}}


def test_canonical_json_is_stable_and_compact():
    assert canonical({"b": 1, "a": [2, 3]}) == '{"a":[2,3],"b":1}'
    assert canonical({"a": 1, "b": 2}) == canonical({"b": 2, "a": 1})


def test_first_record_links_to_genesis(led):
    row = led.append(kind="decision", decision_id=new_decision_id(),
                     agent_id="agt_shopper_01", record=rec())
    assert row["prev_hash"] == GENESIS and row["seq"] == 1


def test_chain_links_each_record_to_the_previous(led):
    a = led.append(kind="decision", decision_id=new_decision_id(), agent_id="a", record=rec())
    b = led.append(kind="decision", decision_id=new_decision_id(), agent_id="a", record=rec())
    assert b["prev_hash"] == a["record_hash"]


def test_verify_chain_passes_on_an_untouched_ledger(led):
    for _ in range(5):
        led.append(kind="decision", decision_id=new_decision_id(), agent_id="a", record=rec())
    r = verify_chain(led.conn)
    assert r.ok and r.checked == 5 and r.problems == []


def test_verify_chain_passes_on_an_empty_ledger(led):
    assert verify_chain(led.conn).ok


def test_editing_a_record_breaks_the_chain_and_names_the_link(led):
    ids = [led.append(kind="decision", decision_id=new_decision_id(),
                      agent_id="a", record=rec())["seq"] for _ in range(4)]
    # hand-edit row 2: change the amount, as an insider would
    row = led.conn.execute("SELECT record FROM ledger WHERE seq=2").fetchone()["record"]
    doc = json.loads(row)
    doc["cart"]["total_paise"] = 1
    led.conn.execute("UPDATE ledger SET record=? WHERE seq=2", (canonical(doc),))

    r = verify_chain(led.conn)
    assert not r.ok
    assert r.problems[0]["seq"] == 2
    assert r.problems[0]["problem"] == "record_hash_mismatch"
    assert ids == [1, 2, 3, 4]


def test_recomputing_the_hash_after_editing_still_fails_on_the_signature(led):
    led.append(kind="decision", decision_id=new_decision_id(), agent_id="a", record=rec())
    import hashlib
    doc = json.loads(led.conn.execute("SELECT record FROM ledger WHERE seq=1").fetchone()["record"])
    doc["cart"]["total_paise"] = 1
    body = canonical(doc)
    led.conn.execute("UPDATE ledger SET record=?, record_hash=? WHERE seq=1",
                     (body, "sha256:" + hashlib.sha256(body.encode()).hexdigest()))
    r = verify_chain(led.conn)
    assert not r.ok and r.problems[0]["problem"] == "bad_signature"


def test_deleting_a_row_breaks_the_link(led):
    for _ in range(3):
        led.append(kind="decision", decision_id=new_decision_id(), agent_id="a", record=rec())
    led.conn.execute("DELETE FROM ledger WHERE seq=2")
    r = verify_chain(led.conn)
    assert not r.ok and r.problems[0]["problem"] == "broken_link" and r.problems[0]["seq"] == 3


def test_later_stages_are_new_rows_not_mutations(led):
    did = new_decision_id()
    led.append(kind="decision", decision_id=did, agent_id="a", record=rec())
    led.append(kind="execution", decision_id=did, agent_id="a",
               record={"execution": {"razorpay_order_id": "order_TEST"}})
    rows = led.by_decision(did)
    assert [r["kind"] for r in rows] == ["decision", "execution"]
    assert rows[0]["record"]["cart"]["total_paise"] == 24900, "original row untouched"
    assert verify_chain(led.conn).ok


def test_window_counts_only_this_agent(led):
    for _ in range(3):
        led.append(kind="decision", decision_id=new_decision_id(), agent_id="a", record=rec())
    led.append(kind="decision", decision_id=new_decision_id(), agent_id="b", record=rec())
    assert led.window("a")["txn_count_1h"] == 3
    assert led.window("b")["txn_count_1h"] == 1


def test_window_spend_excludes_denied_decisions(led):
    led.append(kind="decision", decision_id=new_decision_id(), agent_id="a", record=rec(50000, "allow"))
    led.append(kind="decision", decision_id=new_decision_id(), agent_id="a", record=rec(90000, "deny"))
    assert led.window("a")["spend_24h_paise"] == 50000


def test_window_ignores_records_outside_the_window(led):
    import time
    old = int(time.time()) - 7200
    led.append(kind="decision", decision_id=new_decision_id(), agent_id="a", record=rec(), now=old)
    led.append(kind="decision", decision_id=new_decision_id(), agent_id="a", record=rec())
    w = led.window("a")
    assert w["txn_count_1h"] == 1 and w["spend_24h_paise"] == 49800
