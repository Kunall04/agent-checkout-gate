"""The policy engine. Pure, deterministic, no I/O, no network, no LLM.

evaluate(facts, bundle) -> Outcome. Same inputs, same output, always. The only
function that decides ALLOW / DENY / ESCALATE in this codebase.

Rule expressions are evaluated with `eval`, but only after the expression's
AST has been checked against a whitelist of node types and the fact namespace
is the only thing in scope. The bundle is a merchant artifact that is
content-hashed into every decision record — it is not agent input. A hand-rolled
parser would be ~200 more lines to reach the same place; the whitelist below is
the part that actually does the work, so it is here in the open.
"""
from __future__ import annotations

import ast
import hashlib
import pathlib
from dataclasses import dataclass, field
from typing import Any

import yaml

BUNDLE_PATH = pathlib.Path(__file__).resolve().parent / "bundle.yaml"

# strictest wins; ties broken by lowest `priority`
SEVERITY = {"allow": 0, "escalate": 1, "deny": 2}

_ALLOWED_NODES = (
    ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.USub,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod,
    ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    ast.Name, ast.Load, ast.Attribute, ast.Subscript, ast.Constant,
    ast.List, ast.Tuple, ast.Call,
)
_ALLOWED_CALLS = {"has_category"}   # methods on a fact namespace, nothing else


class PolicyError(Exception):
    """A malformed or unsafe *bundle*. Propagates — a broken policy is an
    operator error and must be loud, not quietly denied."""


class FactError(PolicyError):
    """A rule referenced a fact that isn't there. Fails the rule closed."""


def _check(expr: str) -> ast.Expression:
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise PolicyError(f"cannot parse expression {expr!r}: {e}") from None
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise PolicyError(f"disallowed syntax {type(node).__name__} in {expr!r}")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Attribute) or node.func.attr not in _ALLOWED_CALLS:
                raise PolicyError(f"disallowed call in {expr!r}")
        name = getattr(node, "attr", None) or getattr(node, "id", None)
        if isinstance(name, str) and name.startswith("_"):
            raise PolicyError(f"private attribute {name!r} in {expr!r}")
    return tree


class _NS:
    """Read-only dotted/indexed view over a fact dict. Unknown fact -> PolicyError,
    which the caller turns into a fail-closed deny rather than a silent pass."""

    __slots__ = ("_d",)

    def __init__(self, d: dict[str, Any]):
        object.__setattr__(self, "_d", d)

    def __getattr__(self, k: str) -> Any:
        d = object.__getattribute__(self, "_d")
        if k not in d:
            raise FactError(f"unknown fact: {k}")
        v = d[k]
        return _NS(v) if isinstance(v, dict) else v

    def __getitem__(self, k: Any) -> Any:
        d = object.__getattribute__(self, "_d")
        if k not in d:
            raise FactError(f"unknown fact key: {k!r}")
        v = d[k]
        return _NS(v) if isinstance(v, dict) else v


class _Cart(_NS):
    __slots__ = ()

    def has_category(self, name: str) -> bool:
        return name in object.__getattribute__(self, "_d").get("categories", [])


@dataclass(frozen=True)
class Bundle:
    version: int
    hash: str
    limits: dict[str, Any]
    rules: list[dict[str, Any]]


@dataclass
class Outcome:
    effect: str
    deciding_rule_id: str | None
    rules_evaluated: list[dict[str, Any]]
    bundle_hash: str
    bundle_version: int
    explain: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_hash": self.bundle_hash, "bundle_version": self.bundle_version,
            "rules_evaluated": self.rules_evaluated,
            "deciding_rule_id": self.deciding_rule_id,
            "effect": self.effect, "explain": self.explain,
        }


def load_bundle(path: pathlib.Path = BUNDLE_PATH) -> Bundle:
    raw = pathlib.Path(path).read_bytes()          # hash the file bytes, not the parse
    doc = yaml.safe_load(raw)
    rules = sorted(doc["rules"], key=lambda r: (r["priority"], r["id"]))
    for r in rules:
        if r["effect"] not in SEVERITY:
            raise PolicyError(f"rule {r['id']}: unknown effect {r['effect']!r}")
    return Bundle(version=doc["bundle_version"],
                  hash="sha256:" + hashlib.sha256(raw).hexdigest(),
                  limits=doc["limits"], rules=rules)


def _namespace(facts: dict[str, Any], bundle: Bundle) -> dict[str, Any]:
    ns = {k: _NS(v) for k, v in facts.items()}
    ns["cart"] = _Cart(facts.get("cart", {}))
    ns["limits"] = _NS(bundle.limits)              # limits come from the pinned bundle
    return ns


def _eval(tree: ast.Expression, ns: dict[str, Any]) -> Any:
    return eval(compile(tree, "<bundle>", "eval"), {"__builtins__": {}}, ns)


def evaluate(facts: dict[str, Any], bundle: Bundle) -> Outcome:
    """Evaluate every rule, record every rule, then resolve."""
    ns = _namespace(facts, bundle)
    trace: list[dict[str, Any]] = []

    for rule in bundle.rules:
        row: dict[str, Any] = {"rule_id": rule["id"], "fired": False,
                               "effect": rule["effect"], "priority": rule["priority"],
                               "observed": None, "threshold": None,
                               "explain": rule.get("explain", ""), "error": None}
        # observed/threshold are evidence, not control flow: if they blow up we
        # note it and carry on, because only `when` decides anything.
        for field_name in ("observed", "threshold"):
            if rule.get(field_name):
                try:
                    row[field_name] = _eval(_check(rule[field_name]), ns)
                except FactError as e:
                    row["error"] = f"{field_name}: {e}"
        try:
            row["fired"] = bool(_eval(_check(rule["when"]), ns))
        except FactError as e:
            # Fail closed: a rule we cannot evaluate is a deny, never a pass.
            row.update(fired=True, effect="deny", error=str(e))
        trace.append(row)

    fired = [r for r in trace if r["fired"]]
    if not fired:
        return Outcome("allow", None, trace, bundle.hash, bundle.version)
    winner = min(fired, key=lambda r: (-SEVERITY[r["effect"]], r["priority"], r["rule_id"]))
    return Outcome(winner["effect"], winner["rule_id"], trace,
                   bundle.hash, bundle.version, winner["explain"])


# --- LLM authority boundary (the project spec §6) -----------------------------------
#
# No LLM decides anything. An LLM-influenced signal may only make an outcome
# STRICTER. This is the merge step, and the assertion below is the whole rule.

def apply_advisory(outcome: Outcome, advisory: dict[str, Any] | None) -> Outcome:
    """Fold a non-binding, possibly LLM-derived signal into a decided outcome.

    A stricter advisory tightens the outcome and is recorded as its own trace
    row. A looser one is *ignored* and recorded as ignored — it can never turn
    a deny into an allow, no matter what the model returns.
    """
    if not advisory or advisory.get("effect") not in SEVERITY:
        return outcome
    proposed, current = advisory["effect"], outcome.effect
    tightens = SEVERITY[proposed] > SEVERITY[current]
    row = {"rule_id": "advisory." + advisory.get("source", "llm"),
           "fired": True, "effect": proposed if tightens else current,
           "priority": 0, "observed": advisory.get("reason"), "threshold": None,
           "explain": advisory.get("explain", "Advisory signal (non-binding)."),
           "error": None, "advisory": True, "applied": tightens}
    merged = Outcome(effect=proposed if tightens else current,
                     deciding_rule_id=row["rule_id"] if tightens else outcome.deciding_rule_id,
                     rules_evaluated=outcome.rules_evaluated + [row],
                     bundle_hash=outcome.bundle_hash, bundle_version=outcome.bundle_version,
                     explain=row["explain"] if tightens else outcome.explain)
    assert SEVERITY[merged.effect] >= SEVERITY[current], (
        "monotone authority violated: an advisory signal loosened the outcome")
    return merged
