"""Phase 3 acceptance: engine is a pure function; every rule covered firing and
not firing; precedence; default-allow; determinism."""
import copy

import pytest

from gate.policy.engine import Bundle, PolicyError, evaluate, load_bundle
from gate.policy.facts import build_facts


@pytest.fixture(scope="module")
def bundle() -> Bundle:
    return load_bundle()


def facts(**over):
    """A clean, allow-by-default fact set; override one thing per test."""
    base = build_facts(
        agent={"agent_id": "agt_shopper_01", "key_id": "k1", "sig_verified": True,
               "sig_reason": "verified", "trust_tier": "B", "registry_version": "2026-09-04"},
        cart={"items": [{"sku": "SKU-1042", "qty": 1, "unit_price_paise": 24900,
                         "line_total_paise": 24900, "category": "electronics",
                         "price_source": "catalog"}],
              "total_paise": 24900, "currency": "INR", "catalog_version": "cat_test",
              "problems": [], "discarded_price_claims": []},
        window={"txn_count_1h": 1, "spend_24h_paise": 0},
        intent={"parser_status": "validated", "schema_version": "1.0"},
    )
    for dotted, value in over.items():
        ns, _, key = dotted.partition("__")
        base[ns][key] = value
    return base


def fired(outcome) -> set[str]:
    return {r["rule_id"] for r in outcome.rules_evaluated if r["fired"]}


# --- default -----------------------------------------------------------------

def test_default_allow_when_nothing_fires(bundle):
    o = evaluate(facts(), bundle)
    assert o.effect == "allow" and o.deciding_rule_id is None and fired(o) == set()


def test_every_rule_is_recorded_even_when_it_does_not_fire(bundle):
    o = evaluate(facts(), bundle)
    assert len(o.rules_evaluated) == len(bundle.rules) == 8
    assert all(r["fired"] is False for r in o.rules_evaluated)


# --- each rule fires ---------------------------------------------------------

def test_sig_unverified_denies(bundle):
    o = evaluate(facts(agent__sig_verified=False, agent__sig_reason="unknown_key"), bundle)
    assert o.effect == "deny" and o.deciding_rule_id == "sig.unverified"


def test_intent_unvalidated_denies(bundle):
    o = evaluate(facts(intent__parser_status="schema_error"), bundle)
    assert o.effect == "deny" and o.deciding_rule_id == "intent.unvalidated"


def test_cart_unfulfillable_denies(bundle):
    o = evaluate(facts(cart__problem_count=1), bundle)
    assert o.effect == "deny" and "cart.unfulfillable" in fired(o)


def test_per_txn_cap_escalates_at_tier_b(bundle):
    o = evaluate(facts(cart__total_paise=299800), bundle)
    assert o.effect == "escalate" and o.deciding_rule_id == "cap.per_txn"


def test_same_cart_allows_at_tier_a(bundle):
    """The counterfactual the record is supposed to make derivable."""
    o = evaluate(facts(cart__total_paise=299800, agent__trust_tier="A"), bundle)
    assert o.effect == "allow"


def test_price_substitution_denies(bundle):
    o = evaluate(facts(cart__max_underclaim_bps=9993), bundle)
    assert o.effect == "deny" and o.deciding_rule_id == "price.substitution"


def test_velocity_denies(bundle):
    o = evaluate(facts(window__txn_count_1h=11), bundle)
    assert o.effect == "deny" and o.deciding_rule_id == "velocity.1h"


def test_daily_cap_escalates(bundle):
    o = evaluate(facts(window__spend_24h_paise=999_000, cart__total_paise=24900), bundle)
    assert o.effect == "escalate" and o.deciding_rule_id == "cap.daily"


def test_restricted_category_denies(bundle):
    o = evaluate(facts(cart__categories=["grocery", "restricted"]), bundle)
    assert o.effect == "deny" and "category.restricted" in fired(o)


# --- boundaries: rules must not fire one paise early -------------------------

@pytest.mark.parametrize("total,expected", [(250000, "allow"), (250001, "escalate")])
def test_per_txn_boundary_is_strictly_greater_than(bundle, total, expected):
    assert evaluate(facts(cart__total_paise=total), bundle).effect == expected


@pytest.mark.parametrize("count,expected", [(10, "allow"), (11, "deny")])
def test_velocity_boundary(bundle, count, expected):
    assert evaluate(facts(window__txn_count_1h=count), bundle).effect == expected


@pytest.mark.parametrize("bps,expected", [(5000, "allow"), (5001, "deny")])
def test_underclaim_boundary(bundle, bps, expected):
    assert evaluate(facts(cart__max_underclaim_bps=bps), bundle).effect == expected


# --- precedence --------------------------------------------------------------

def test_deny_beats_escalate_regardless_of_priority(bundle):
    o = evaluate(facts(cart__total_paise=299800, window__txn_count_1h=11), bundle)
    assert o.effect == "deny" and o.deciding_rule_id == "velocity.1h"
    assert {"cap.per_txn", "velocity.1h"} <= fired(o)


def test_lowest_priority_number_wins_within_the_same_effect(bundle):
    o = evaluate(facts(agent__sig_verified=False, window__txn_count_1h=11,
                       cart__categories=["restricted"]), bundle)
    assert o.effect == "deny" and o.deciding_rule_id == "sig.unverified"   # priority 1


def test_escalate_beats_allow(bundle):
    o = evaluate(facts(cart__total_paise=299800), bundle)
    assert o.effect == "escalate"


# --- observed / threshold ----------------------------------------------------

def test_observed_and_threshold_are_recorded_for_fired_and_unfired_rules(bundle):
    o = evaluate(facts(cart__total_paise=299800), bundle)
    cap = next(r for r in o.rules_evaluated if r["rule_id"] == "cap.per_txn")
    vel = next(r for r in o.rules_evaluated if r["rule_id"] == "velocity.1h")
    assert cap["observed"] == 299800 and cap["threshold"] == 250000 and cap["fired"]
    assert vel["observed"] == 1 and vel["threshold"] == 10 and not vel["fired"]


# --- purity and determinism --------------------------------------------------

def test_same_inputs_always_give_the_same_output(bundle):
    f = facts(cart__total_paise=299800)
    first = evaluate(f, bundle)
    for _ in range(50):
        assert evaluate(f, bundle).to_dict() == first.to_dict()


def test_evaluate_does_not_mutate_its_inputs(bundle):
    f = facts(cart__total_paise=299800)
    before = copy.deepcopy(f)
    evaluate(f, bundle)
    assert f == before


def test_engine_module_performs_no_io_and_imports_no_llm():
    import ast
    import pathlib
    src = pathlib.Path("gate/policy/engine.py").read_text()
    imported = {n.names[0].name.split(".")[0] for n in ast.walk(ast.parse(src))
                if isinstance(n, (ast.Import, ast.ImportFrom)) and n.names}
    assert not (imported & {"anthropic", "requests", "httpx", "sqlite3", "socket", "urllib", "random"})
    assert "open(" not in src


# --- fail closed -------------------------------------------------------------

def test_unknown_fact_in_a_rule_fails_closed_not_open(bundle):
    broken = Bundle(version=1, hash="sha256:test", limits=bundle.limits,
                    rules=[{"id": "bad", "effect": "allow", "priority": 5,
                            "when": "cart.no_such_fact > 1", "explain": ""}])
    o = evaluate(facts(), broken)
    assert o.effect == "deny" and o.deciding_rule_id == "bad"
    assert o.rules_evaluated[0]["error"].startswith("unknown fact")


def test_dangerous_expressions_are_rejected_at_load_time(bundle):
    for expr in ["__import__('os').system('id')", "open('/etc/passwd').read()",
                 "(lambda: 1)()", "cart.__class__.__mro__"]:
        with pytest.raises(PolicyError):
            evaluate(facts(), Bundle(1, "sha256:t", bundle.limits,
                                     [{"id": "x", "effect": "deny", "priority": 1,
                                       "when": expr, "explain": ""}]))


def test_bundle_hash_is_the_sha256_of_the_file_bytes():
    import hashlib
    import pathlib
    raw = pathlib.Path("gate/policy/bundle.yaml").read_bytes()
    assert load_bundle().hash == "sha256:" + hashlib.sha256(raw).hexdigest()
