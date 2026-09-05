"""Detect ledger tampering.

    python -m cli.verify_chain

Exit 0 if every link and signature checks out, 1 otherwise, naming each broken
link by sequence number and decision id.
"""
from __future__ import annotations

import argparse
import json
import sys

from gate.ledger import verify_chain
from gate.store import connect


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify the ledger hash chain and signatures.")
    ap.add_argument("--db", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    conn = connect(args.db) if args.db else connect()
    result = verify_chain(conn)
    if args.json:
        print(json.dumps({"ok": result.ok, "checked": result.checked,
                          "problems": result.problems}, indent=2))
    elif result.ok:
        print(f"OK  {result.checked} records, chain and signatures intact.")
    else:
        print(f"TAMPERED  {result.checked} records checked, {len(result.problems)} problem(s):")
        for p in result.problems:
            print(f"  seq {p['seq']:>4}  {p['decision_id']}  [{p['kind']}]  {p['problem']}")
            for k in ("expected_prev_hash", "found_prev_hash", "expected", "found"):
                if k in p:
                    print(f"        {k}: {p[k]}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
