"""Print the reconciliation result for the most recent decision. Demo-only helper."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from gate.store import connect
from gate.ledger import Ledger

c = connect("data/gate.db")
last_id = c.execute(
    "SELECT decision_id FROM ledger WHERE kind='decision' ORDER BY seq DESC LIMIT 1"
).fetchone()["decision_id"]
rows = Ledger(c).by_decision(last_id)
print(rows[-1]["record"]["reconciliation"])
