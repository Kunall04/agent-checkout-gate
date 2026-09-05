# Agent Checkout Gate

Admission control between a third-party AI buying agent and a merchant's Razorpay checkout.

Every agent-initiated purchase is authenticated, **priced from the merchant's own catalog
rather than the agent's claimed price**, evaluated against deterministic merchant policy, and
resolved to **ALLOW / DENY / ESCALATE**. Every decision is written to a hash-chained,
Ed25519-signed ledger that can be replayed to reproduce the same outcome. After payment, a
reconciler compares what was actually captured against what was authorised and automatically
reverses any mismatch.

Razorpay AI Buildathon, Track 1 (AI Growth & Agentic Commerce).

---

## The thesis

ACP (OpenAI/Stripe), AP2 (Google) and Visa's Trusted Agent Protocol all gate *before* payment.
None of them verify that what actually settled matches what was authorised. **That
post-execution loop is what this repo is for.** Everything else exists to make the loop
meaningful: you cannot check a capture against an authorisation unless the authorisation was
precise, recorded, and tamper-evident in the first place.

Second: Track 1's bar is qualitative. This submission ships a confusion matrix anyway.

## Measured results

100 scenarios — 40 adversarial across 16 attack families, 60 benign — against a fresh gate each:

```
                     gate says BLOCK   gate says ALLOW
  adversarial             40 (TP)              0 (FN)
  benign                   1 (FP)             59 (TN)

  block rate (recall)       100.0%
  false positive rate         1.7%   1/60 legitimate carts wrongly stopped
  false-positive cost    Rs 2,999.00   revenue blocked in error
  value leaked by misses     Rs 0.00
  added latency p50/p95    2.0 / 3.7 ms per decision
```

Reproduce with `make redteam`; per-scenario rows land in `redteam/results/results.csv`.

The single false positive is real and worth reading: `ben_text_01`, "get me a desk lamp",
matched a Rs 2,999 lamp against a tier-B ceiling of Rs 2,500 and escalated to a human. It is a
policy false positive, not a bug — and it is the honest shape of this trade-off. Raise the
ceiling and it disappears along with some of the block rate.

Attack families covered: price substitution, quantity overflow, discount/quantity stacking,
restricted category, prompt injection, replayed signature, tampered body, unknown agent key,
revoked key, unsigned request, stale timestamp, trust-tier escalation, split-transaction
velocity evasion, expired/reused/re-scoped approval tokens, capture-amount mismatch, currency
swap, duplicate capture, orphan capture, forged webhook signature, ledger tampering,
malformed request.

## Quickstart

```sh
make setup          # venv, deps, generate catalog + Ed25519 keys and registry
make test           # 93 tests
make demo           # the seven-step demo below, one take
make redteam        # confusion matrix
make serve          # uvicorn on :8000
```

Razorpay test keys are optional. Without them the adapter runs in MOCK mode, labels every
object `_mock: true`, and the demo says so on the relevant lines. With
`RAZORPAY_KEY_ID=rzp_test_...` in `.env`, orders, payment links and refunds are real test-mode
API calls visible in the dashboard. `rzp_live_*` keys are refused by the constructor.

`ANTHROPIC_API_KEY` is also optional: without it, free-text intent parsing falls back to a
deterministic title-match and every record says `parser_model: "deterministic_fallback"`.

## What `make demo` shows

1. **The attack, with the gate bypassed.** An agent claims Rs 1 for a Rs 1,499 SKU and an order
   is created for Rs 1.
2. **The same attack, gate on.** `DENY` by `price.substitution`, observed 9993 bps below
   catalog against a 5000 bps threshold, with the discarded price claim in the record.
3. **Legitimate oversized cart.** Rs 24,999 against a tier-B ceiling of Rs 2,500 → `ESCALATE`,
   one-time approval link, human approves, payment link released.
4. **Approval timeout.** Nobody clicks → `{"status":"denied","reason":"approval_timeout",
   "retry_after_s":900,"decision_id":"..."}`. Silence is a no.
5. **Capture mismatch.** A capture arrives for 7x the authorised amount → automatic refund of
   the delta, a linked incident record, and a structured notice for the agent. Then the webhook
   is retried: `duplicate_ignored`, refunded once.
6. **Replay and tamper.** `python -m cli.replay dec_...` reproduces the decision exactly;
   `python -m cli.verify_chain` says the chain is intact. Edit one ledger row by hand and both
   commands fail, naming the broken link.
7. **The confusion matrix.**

## The three properties that make a decision explainable

Every ledger row carries all three. None of them is narration.

- **Replayable** — the facts snapshot and the policy bundle hash are in the record.
  `cli/replay.py` re-runs the pinned bundle against the recorded facts and asserts an identical
  outcome. If the bundle on disk is not the bundle that decided, replay refuses rather than
  quietly producing a different answer.
- **Counterfactual** — every rule, fired or not, records its `observed` value and its
  `threshold`. "Would have passed at tier A" is derivable from the record, not asserted by a
  model.
- **Tamper-evident** — `prev_hash` chain plus a per-record Ed25519 signature over the record
  hash. Editing a row breaks the hash; recomputing the hash breaks the signature.

## Where the LLM is, and is not

An LLM parses free-text intent into a strict schema, and drafts post-hoc explanations. That is
all. It never decides ALLOW/DENY/ESCALATE, never touches money arithmetic, never verifies a
signature, never triggers a capture or refund, never performs the reconciliation comparison.

The intent schema has **no price, currency, discount or total field**, so a model cannot express
money even if it wanted to. Product descriptions are attacker-controlled and are never sent to
the model — only SKU ids and titles from a deterministic catalog search.

**Monotone authority:** any LLM-influenced signal may only make an outcome *stricter*. This is
enforced by an assertion in `apply_advisory` and proved by
`tests/test_gate.py::test_an_llm_advisory_cannot_upgrade_a_deny_to_an_allow`. An advisory that
would loosen an outcome is ignored and recorded as ignored.

## Real vs mocked

**Real.** Razorpay test-mode Orders API, Payment Links and refunds. `X-Razorpay-Signature`
webhook verification (HMAC-SHA256 over the raw body, constant-time compare, written out rather
than delegated so it can be read). Ed25519 request signing and ledger signing. RFC 9421 HTTP
Message Signature verification, hand-rolled. Policy evaluation. The hash chain. The reconciler.

**Mocked** — every one carries a `# MOCK:` comment at the site:

| What | Where | What the real thing would be |
|---|---|---|
| The buyer agent | `buyer_agent/agent.py` | A third-party ACP/AP2/TAP client. We wrote it, so here it is the adversary, not the hero. |
| The agent trust registry | `gate/registry.py`, `scripts/gen_keys.py` | Real crypto, our own trust root. Visa TAP or a JWKS endpoint would replace `Registry.load`; nothing in `signatures.py` moves. |
| The catalog | `scripts/gen_catalog.py` | The merchant's PIM or Razorpay's item store. 150 synthetic SKUs, integer paise, 8 restricted, 4 carrying prompt-injection payloads in their descriptions. |
| Razorpay objects when no test keys are set | `gate/razorpay_adapter.py` | The API response. Mock objects share the real shape and are labelled `_mock: true`. |
| Free-text parsing with no API key | `gate/intent.py` | The Claude call. Falls back to deterministic title matching and records `parser_model: "deterministic_fallback"`. |

**Explicitly future work — not faked, not stubbed:** NPCI UAP / UPI Reserve Pay binding, real
TAP registry integration, cross-merchant agent reputation, a policy authoring UI, OPA/Rego at
production scale, multi-tenant isolation.

## Dependencies

The pinned stack is FastAPI, uvicorn, PyNaCl, PyYAML, the official `razorpay` SDK, the Anthropic
SDK, python-dotenv and pytest. One addition: **`jsonschema`**, because §6 requires JSON Schema
validation of untrusted model output and a hand-rolled validator is the wrong place to save
fifty lines. No Redis, no Postgres, no Docker. Velocity counters are an indexed scan over the
ledger — a counter table would be a second source of truth that can drift from the record.

## Layout

```
gate/
  app.py                FastAPI routes + the request pipeline (process_checkout)
  signatures.py         RFC 9421 subset, Ed25519, nonce + timestamp replay defence
  registry.py           agent_id -> pubkey, trust tier
  catalog.py            the only source of price truth
  intent.py             free text -> schema-validated intent, fails closed
  policy/engine.py      pure deterministic evaluation; no I/O, no LLM
  policy/facts.py       the fact dict; JSON-serialisable so replay works
  policy/bundle.yaml    the rules, content-hashed into every decision
  ledger.py             hash chain, Ed25519 signing, velocity windows, envelope hash
  escalation.py         one-time TTL approval tokens scoped to an envelope
  razorpay_adapter.py   orders, payment links, refunds, webhook verification
  reconciler.py         captured vs authorised -> automatic remediation
  explain.py            post-hoc narration, non-binding, regenerable
  store.py              SQLite schema and connection
cli/replay.py           re-run a decision from its record
cli/verify_chain.py     detect ledger tampering
redteam/                40 adversarial + 60 benign scenarios and the harness
tests/                  93 tests
```

`ARCHITECTURE.md` has the request lifecycle, the threat model, and the deliberate
simplifications.
