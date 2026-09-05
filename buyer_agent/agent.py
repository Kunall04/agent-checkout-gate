"""# MOCK: the buyer agent. We wrote it, so it is the adversary in this repo,
not the hero. A real third-party agent (ACP/AP2/TAP client) would sit here.
It is deliberately capable of lying: see the `tamper` options, which the
red-team harness drives.
"""
from __future__ import annotations

import base64
import json
import pathlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from gate.signatures import sign_request

KEYS = pathlib.Path(__file__).resolve().parent.parent / "data" / "keys"
CHECKOUT_PATH = "/agent/checkout"


@dataclass
class BuyerAgent:
    agent_id: str = "agt_shopper_01"
    key_id: str = "k1"
    seed: bytes = field(default=b"", repr=False)

    def __post_init__(self):
        if not self.seed:
            k = json.loads((KEYS / f"{self.agent_id}.{self.key_id}.json").read_text())
            self.seed = base64.b64decode(k["private_key"])

    def build(self, *, intent_text: str = "", cart: list[dict[str, Any]] | None = None,
              idempotency_key: str | None = None) -> dict[str, Any]:
        """The request payload. `claimed_unit_price_paise` exists on purpose:
        it is the price-substitution attack surface, and the gate discards it."""
        return {
            "agent_id": self.agent_id,
            "intent_text": intent_text,
            "proposed_cart": cart or [],
            "currency": "INR",
            "idempotency_key": idempotency_key or f"req_{secrets.token_hex(8)}",
        }

    def sign(self, payload: dict[str, Any], *, path: str = CHECKOUT_PATH,
             created: int | None = None, nonce: str | None = None,
             tamper_body: dict[str, Any] | None = None) -> tuple[bytes, dict[str, str]]:
        """Return (body_to_send, headers). If tamper_body is given, headers are
        computed over `payload` but `tamper_body` is what goes on the wire —
        that is the man-in-the-middle / body-swap attack."""
        signed_over = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        headers = sign_request("POST", path, signed_over, agent_id=self.agent_id,
                               key_id=self.key_id, private_key_seed=self.seed,
                               created=created, nonce=nonce)
        on_wire = signed_over if tamper_body is None else json.dumps(
            tamper_body, sort_keys=True, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
        return on_wire, headers

    def request(self, **kw) -> tuple[bytes, dict[str, str]]:
        """build + sign in one call."""
        build_kw = {k: kw.pop(k) for k in ("intent_text", "cart", "idempotency_key") if k in kw}
        return self.sign(self.build(**build_kw), **kw)


if __name__ == "__main__":  # self-check: emit a signed request and verify it
    from gate.registry import registry
    from gate.signatures import verify_request
    from gate.store import init_db

    a = BuyerAgent()
    body, headers = a.request(intent_text="buy two 65W anker chargers",
                              cart=[{"sku": "SKU-1042", "qty": 2, "claimed_unit_price_paise": 100}])
    print(json.dumps(json.loads(body), indent=2))
    print(json.dumps(headers, indent=2))
    r = verify_request("POST", CHECKOUT_PATH, body, headers,
                       registry=registry(), conn=init_db(":memory:"))
    assert r.ok and r.trust_tier == "B", r
    print("self-signed request verifies:", r.reason, "tier", r.trust_tier)
