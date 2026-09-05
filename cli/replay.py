"""Re-run a stored decision from its own record and assert the same outcome.

    python -m cli.replay dec_abc123

Replay uses the facts snapshot in the record and the bundle pinned by hash. If
the bundle on disk is not the bundle that decided, replay refuses rather than
quietly reproducing a different answer.
"""
from __future__ import annotations

import argparse
import json
import sys

from gate.ledger import Ledger
from gate.policy.engine import apply_advisory, evaluate, load_bundle
from gate.store import connect


def replay(decision_id: str, conn=None) -> tuple[bool, dict]:
    conn = conn or connect()
    rows = Ledger(conn).by_decision(decision_id)
    decision = next((r["record"] for r in rows if r["kind"] == "decision"), None)
    if decision is None:
        return False, {"error": "unknown_decision", "decision_id": decision_id}

    bundle = load_bundle()
    if bundle.hash != decision["policy"]["bundle_hash"]:
        return False, {"error": "bundle_drift",
                       "recorded": decision["policy"]["bundle_hash"], "on_disk": bundle.hash}

    advisory = next((r for r in decision["policy"]["rules_evaluated"] if r.get("advisory")), None)
    outcome = evaluate(decision["facts_snapshot"], bundle)
    if advisory:
        outcome = apply_advisory(outcome, {"effect": advisory["effect"], "source": "llm_intent",
                                           "reason": advisory["observed"],
                                           "explain": advisory["explain"]})

    recorded, replayed = decision["policy"], outcome.to_dict()
    same = (recorded["effect"] == replayed["effect"]
            and recorded["deciding_rule_id"] == replayed["deciding_rule_id"]
            and recorded["rules_evaluated"] == replayed["rules_evaluated"])
    return same, {"decision_id": decision_id, "recorded_effect": recorded["effect"],
                  "replayed_effect": replayed["effect"],
                  "recorded_rule": recorded["deciding_rule_id"],
                  "replayed_rule": replayed["deciding_rule_id"],
                  "bundle_hash": bundle.hash,
                  "diff": None if same else {"recorded": recorded, "replayed": replayed}}


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay a decision from the ledger.")
    ap.add_argument("decision_id")
    ap.add_argument("--db", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    ok, detail = replay(args.decision_id, conn=connect(args.db) if args.db else None)
    if args.json:
        print(json.dumps(detail, indent=2))
    elif "error" in detail:
        print(f"REPLAY FAILED: {detail['error']}  {detail}")
    else:
        print(f"decision  {detail['decision_id']}")
        print(f"bundle    {detail['bundle_hash']}")
        print(f"recorded  {detail['recorded_effect']:<9} by {detail['recorded_rule']}")
        print(f"replayed  {detail['replayed_effect']:<9} by {detail['replayed_rule']}")
        if ok:
            print("IDENTICAL")
        else:
            print("DIVERGED")
            rec = {r["rule_id"]: r for r in detail["diff"]["recorded"]["rules_evaluated"]}
            rep = {r["rule_id"]: r for r in detail["diff"]["replayed"]["rules_evaluated"]}
            for rid in sorted(set(rec) | set(rep)):
                if rec.get(rid) != rep.get(rid):
                    print(f"  {rid}: recorded {rec.get(rid, {}).get('observed')!r} "
                          f"fired={rec.get(rid, {}).get('fired')} "
                          f"-> replayed {rep.get(rid, {}).get('observed')!r} "
                          f"fired={rep.get(rid, {}).get('fired')}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
