"""Red-team harness. Runs every scenario, writes results.csv, prints the matrix.

    python -m redteam.run [--csv redteam/results/results.csv]

Blocked means "not silently allowed": a deny, or an escalate that puts a human
in the loop. For prompt-injection scenarios it means neutralised — see the
docstring on injected_intent in scenarios.py.
"""
from __future__ import annotations

import argparse
import csv
import pathlib
import statistics
import time
import traceback

from redteam.scenarios import ALL, Ctx, FAMILIES, Result, Scenario

DEFAULT_CSV = pathlib.Path(__file__).resolve().parent / "results" / "results.csv"


def run_one(s: Scenario) -> tuple[Result, float]:
    ctx = Ctx()
    t0 = time.perf_counter()
    try:
        result = s.run(ctx)
    except Exception:
        result = Result(False, "harness_error: " + traceback.format_exc(limit=1).strip().replace("\n", " | "))
    wall = (time.perf_counter() - t0) * 1000
    # Gate latency, not scenario latency: several scenarios make many calls.
    result.latency_ms = statistics.median(ctx.latencies) if ctx.latencies else wall
    return result, wall


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(DEFAULT_CSV))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    rows, latencies = [], []
    tp = fp = tn = fn = 0
    fp_cost = leaked = 0

    for s in ALL:
        result, wall = run_one(s)
        correct = result.blocked == s.expect_blocked
        if s.expect_blocked:
            if result.blocked:
                tp += 1
            else:
                fn += 1
                leaked += result.amount_paise
        else:
            if result.blocked:
                fp += 1
                fp_cost += result.amount_paise
            else:
                tn += 1
        latencies.append(result.latency_ms)
        rows.append({"id": s.id, "kind": s.kind, "family": s.family,
                     "description": s.description, "expected": "block" if s.expect_blocked else "pass",
                     "blocked": result.blocked, "correct": correct, "detail": result.detail,
                     "amount_paise": result.amount_paise,
                     "gate_latency_ms": round(result.latency_ms, 2),
                     "scenario_wall_ms": round(wall, 2)})
        if not args.quiet and not correct:
            print(f"  MISS {s.id:<22} {s.family:<24} {result.detail}")

    out = pathlib.Path(args.csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    adv, ben = tp + fn, tn + fp
    p95 = sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)]
    rupees = lambda p: f"Rs {p / 100:,.2f}"

    print(f"""
Agent Checkout Gate — red-team results        ({len(ALL)} scenarios, {adv} adversarial / {ben} benign)

                     gate says BLOCK   gate says ALLOW
  adversarial   {tp:>12} (TP)  {fn:>13} (FN)
  benign        {fp:>12} (FP)  {tn:>13} (TN)

  block rate (recall)      {tp / adv:>7.1%}   {tp}/{adv} attacks stopped
  false positive rate      {fp / ben:>7.1%}   {fp}/{ben} legitimate carts wrongly stopped
  precision                {tp / (tp + fp) if tp + fp else 1:>7.1%}
  accuracy                 {(tp + tn) / len(ALL):>7.1%}
  false-positive cost      {rupees(fp_cost):>12}   revenue blocked in error
  value leaked by misses   {rupees(leaked):>12}
  added latency p50/p95    {statistics.median(latencies):>6.1f} / {p95:.1f} ms per decision

  families covered: {", ".join(FAMILIES)}
  results: {out}""")
    return 0 if fn == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
