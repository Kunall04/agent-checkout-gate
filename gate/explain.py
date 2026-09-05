"""Post-hoc, non-binding narration of a decision that has already been made.

Runs after the outcome is fixed and can never change it. If it is missing,
wrong or hallucinated, the decision is unaffected — which is why the record
carries regenerable: true. Without an API key it produces a deterministic
sentence assembled from the rule trace, and says so.
"""
from __future__ import annotations

import os
from typing import Any

MODEL = "claude-sonnet-5"


def rupees(paise: Any) -> str:
    return f"₹{paise / 100:,.2f}" if isinstance(paise, int) else str(paise)


def deterministic(outcome: dict[str, Any], cart: dict[str, Any]) -> str:
    rule = next((r for r in outcome["rules_evaluated"]
                 if r["rule_id"] == outcome["deciding_rule_id"]), None)
    if rule is None:
        return (f"Allowed: no rule in bundle {outcome['bundle_version']} fired for a "
                f"{rupees(cart['total_paise'])} cart.")
    bits = [f"{outcome['effect'].upper()} by rule {rule['rule_id']}.", rule["explain"]]
    if rule.get("observed") is not None:
        bits.append(f"Observed {rule['observed']}"
                    + (f" against a threshold of {rule['threshold']}." if rule.get("threshold") is not None else "."))
    return " ".join(bits)


def narrate(outcome: dict[str, Any], cart: dict[str, Any], client: Any | None = None) -> dict[str, Any]:
    text, by = deterministic(outcome, cart), "deterministic_template"
    if client is None and os.getenv("ANTHROPIC_API_KEY"):
        import anthropic
        client = anthropic.Anthropic()
    if client is not None:
        try:
            msg = client.messages.create(
                model=MODEL, max_tokens=200,
                messages=[{"role": "user", "content":
                           "Rewrite this checkout decision for a merchant ops reviewer in two "
                           "plain sentences. Do not add numbers that are not present, do not "
                           "speculate about intent, do not suggest overriding it.\n\n" + text}])
            text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
            by = MODEL
        except Exception:
            pass                     # narration is cosmetic; never fail a decision over it
    return {"text": text, "generated_by": by, "regenerable": True}
