"""Source-of-truth pricing.

The gate never trusts a price supplied by the agent. Every cart is repriced
from this catalog and every priced line carries price_source="catalog".
Money is integer paise throughout; a float anywhere here is a bug.
"""
from __future__ import annotations

import json
import pathlib
import re
from typing import Any

CATALOG_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "catalog.json"

_STOP = {"the", "a", "an", "of", "for", "and", "with", "buy", "get", "me", "my",
         "please", "some", "two", "three", "one", "x", "in", "to", "order"}


class Catalog:
    def __init__(self, path: pathlib.Path = CATALOG_PATH):
        raw = json.loads(path.read_text())
        self.version: str = raw["catalog_version"]
        self.currency: str = raw["currency"]
        self.items: dict[str, dict[str, Any]] = {i["sku"]: i for i in raw["items"]}
        for sku, item in self.items.items():
            if not isinstance(item["unit_price_paise"], int):
                raise ValueError(f"{sku}: price must be integer paise, got {item['unit_price_paise']!r}")

    def get(self, sku: str) -> dict[str, Any] | None:
        return self.items.get(sku)

    def search(self, text: str, limit: int = 5) -> list[dict[str, Any]]:
        """Token-overlap match over titles. Deterministic fallback for intent.py
        when no LLM is configured. Only ever *proposes* a SKU; pricing is
        still done by price_cart from the catalog row."""
        want = {w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in _STOP}
        scored = []
        for item in self.items.values():
            # NB: title only. Descriptions carry attacker-controlled text and
            # must not steer SKU selection (Phase 5).
            have = set(re.findall(r"[a-z0-9]+", item["title"].lower()))
            overlap = len(want & have)
            if overlap:
                scored.append((overlap / len(have | want), item))
        scored.sort(key=lambda s: (-s[0], s[1]["sku"]))
        return [i for _, i in scored[:limit]]

    def price_cart(self, proposed: list[dict[str, Any]]) -> dict[str, Any]:
        """Reprice a proposed cart from catalog truth.

        `proposed` entries may carry claimed_unit_price_paise. It is recorded as
        evidence and then discarded — it never reaches the total.
        """
        # Merge duplicate SKUs first. Split across several lines, 3 x qty 5 of a
        # max-qty-5 item would otherwise pass three per-line checks and still
        # ship 15 units — the discount/quantity stacking attack.
        merged: dict[str, dict[str, Any]] = {}
        for line in proposed:
            key = str(line.get("sku", ""))
            if key in merged and isinstance(line.get("qty"), int) and isinstance(merged[key].get("qty"), int):
                merged[key] = {**merged[key], "qty": merged[key]["qty"] + line["qty"]}
                if line.get("claimed_unit_price_paise") is not None:
                    merged[key]["claimed_unit_price_paise"] = line["claimed_unit_price_paise"]
            else:
                merged.setdefault(key, dict(line))

        items, problems, total, discarded = [], [], 0, []
        for line in merged.values():
            sku = str(line.get("sku", ""))
            qty = line.get("qty", 0)
            if not isinstance(qty, int) or qty < 1:
                problems.append({"sku": sku, "problem": "invalid_qty", "observed": qty})
                continue
            row = self.get(sku)
            if row is None:
                problems.append({"sku": sku, "problem": "unknown_sku"})
                continue
            if not row["in_stock"]:
                problems.append({"sku": sku, "problem": "out_of_stock"})
            if qty > row["max_qty_per_order"]:
                problems.append({"sku": sku, "problem": "qty_over_max",
                                 "observed": qty, "threshold": row["max_qty_per_order"]})
            unit = row["unit_price_paise"]
            claimed = line.get("claimed_unit_price_paise")
            if claimed is not None and claimed != unit:
                discarded.append({"sku": sku, "claimed_unit_price_paise": claimed,
                                  "catalog_unit_price_paise": unit})
            items.append({"sku": sku, "qty": qty, "unit_price_paise": unit,
                          "line_total_paise": unit * qty, "category": row["category"],
                          "price_source": "catalog"})
            total += unit * qty
        return {
            "items": items,
            "total_paise": total,
            "currency": self.currency,
            "catalog_version": self.version,
            "problems": problems,
            "discarded_price_claims": discarded,
        }


_catalog: Catalog | None = None


def catalog() -> Catalog:
    global _catalog
    if _catalog is None:
        _catalog = Catalog()
    return _catalog


if __name__ == "__main__":  # self-check
    c = catalog()
    assert len(c.items) == 150, len(c.items)
    assert all(isinstance(i["unit_price_paise"], int) for i in c.items.values())
    assert any(i["category"] == "restricted" for i in c.items.values())
    sku = next(iter(c.items))
    priced = c.price_cart([{"sku": sku, "qty": 2, "claimed_unit_price_paise": 100}])
    assert priced["total_paise"] == c.items[sku]["unit_price_paise"] * 2
    assert priced["discarded_price_claims"][0]["claimed_unit_price_paise"] == 100
    assert priced["items"][0]["price_source"] == "catalog"
    assert c.price_cart([{"sku": "SKU-nope", "qty": 1}])["problems"][0]["problem"] == "unknown_sku"
    assert c.search("anker charger"), "search found nothing"
    print(f"catalog ok: {len(c.items)} SKUs, version {c.version}")
