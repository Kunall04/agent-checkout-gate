"""Assemble the fact dict the rules are evaluated against.

The output is plain JSON-serialisable data and nothing else: it is stored
verbatim in the decision record so `cli/replay.py` can re-run the pinned
bundle against exactly the same inputs.

`limits.*` is deliberately NOT here — limits live in the bundle, and the
bundle is pinned by hash in every record, so replay picks them up from there.
"""
from __future__ import annotations

from typing import Any


def _max_underclaim_bps(discarded: list[dict[str, Any]]) -> int:
    """How far below catalog truth the agent's biggest lie was, in basis points.

    Integer arithmetic only — money never touches a float. 10000 bps = claimed
    zero; 0 bps = claimed at or above the real price (over-claiming is not an
    attack we price on, the customer is charged catalog truth either way).
    """
    worst = 0
    for d in discarded:
        truth = d["catalog_unit_price_paise"]
        if truth <= 0:
            continue
        gap = truth - d["claimed_unit_price_paise"]
        if gap > 0:
            worst = max(worst, gap * 10_000 // truth)
    return worst


def build_facts(*, agent: dict[str, Any], cart: dict[str, Any],
                window: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent": {
            "agent_id": agent["agent_id"],
            "key_id": agent.get("key_id"),
            "sig_verified": bool(agent["sig_verified"]),
            "sig_reason": agent.get("sig_reason", "unknown"),
            "trust_tier": agent["trust_tier"],
            "registry_version": agent.get("registry_version"),
        },
        "cart": {
            "total_paise": cart["total_paise"],
            "currency": cart.get("currency", "INR"),
            "line_count": len(cart.get("items", [])),
            "max_qty": max((i["qty"] for i in cart.get("items", [])), default=0),
            "categories": sorted({i["category"] for i in cart.get("items", [])}),
            "problem_count": len(cart.get("problems", [])),
            "problems": sorted({p["problem"] for p in cart.get("problems", [])}),
            "max_underclaim_bps": _max_underclaim_bps(cart.get("discarded_price_claims", [])),
            "catalog_version": cart.get("catalog_version"),
        },
        "window": {
            "txn_count_1h": window.get("txn_count_1h", 0),
            "spend_24h_paise": window.get("spend_24h_paise", 0),
        },
        "intent": {
            "parser_status": intent.get("parser_status", "missing"),
            "schema_version": intent.get("schema_version"),
        },
    }


if __name__ == "__main__":  # self-check: the money arithmetic
    assert _max_underclaim_bps([{"catalog_unit_price_paise": 149900,
                                 "claimed_unit_price_paise": 100}]) == 9993
    assert _max_underclaim_bps([{"catalog_unit_price_paise": 100,
                                 "claimed_unit_price_paise": 100}]) == 0
    assert _max_underclaim_bps([{"catalog_unit_price_paise": 100,
                                 "claimed_unit_price_paise": 900}]) == 0
    assert _max_underclaim_bps([]) == 0
    print("facts ok")
