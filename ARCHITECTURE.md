# Architecture

## Request lifecycle

```
agent  --signed POST /agent/checkout-->  Gate.process_checkout
                                          |
  1. verify_request .................... RFC 9421: keyid -> registry -> digest -> skew -> Ed25519 -> nonce
  2. parse_intent ...................... free text -> JSON Schema -> SKUs that exist, or fail closed
  3. catalog.price_cart ................ agent's claimed prices DISCARDED; total recomputed
  4. ledger.window ..................... velocity facts from the ledger itself
  5. build_facts ....................... plain JSON: agent.* cart.* window.* intent.*
  6. evaluate(facts, bundle) ........... pure; every rule evaluated and recorded
  7. apply_advisory .................... an LLM signal may only tighten. assertion enforced
  8. ledger.append ..................... hash-chained, Ed25519 signed, append-only
  9. act ............................... allow -> order | escalate -> approval token | deny -> reason
                                          |
        razorpay --payment.captured-->  /webhooks/razorpay -> reconciler.on_capture
                                          |
       compare captured vs bound envelope -> matched, or refund + incident + agent notice
```

Steps 1-8 always happen, in that order, whatever the outcome. A denial is a full ledger record
with the same evidence as an approval: that is what makes the corpus in `redteam/` measurable
rather than anecdotal.

`process_checkout` is a plain function, not a route handler. The red-team harness and the demo
drive it in-process, so the measured latency is the gate and not an HTTP stack. The FastAPI
route is a five-line wrapper.

## Why the pricing step is where it is

The single most important line in the codebase is that step 3 takes only `sku` and `qty` from
step 2 and looks the price up itself. `claimed_unit_price_paise` survives into the record as
`cart.discarded_price_claims` — evidence of what was claimed and refused — and never reaches
`total_paise`.

That means the price-substitution attack is not *detected* so much as *structurally impossible*;
the `price.substitution` rule exists to deny and flag the attempt, not to protect the total. If
that rule were deleted the merchant would still charge Rs 1,499 for a Rs 1,499 item.

**Money is integer paise everywhere.** No floats in any money path, including the
underclaim ratio, which is computed in integer basis points.

## The policy engine

`evaluate(facts, bundle) -> Outcome`. Pure: no I/O, no network, no clock, no LLM — there is a
test that parses `engine.py` and asserts it imports none of them.

**Evaluation.** Every rule is evaluated and recorded, including the ones that did not fire, with
their `observed` and `threshold`. That is what makes the record counterfactual: "would this have
passed at tier A" is arithmetic over the record, not a second opinion from a model.

**Resolution.** Strictest effect wins — `deny` > `escalate` > `allow` — ties broken by lowest
`priority`, then by rule id for total determinism. Default when nothing fires is `allow`.

**Expressions.** Rules are expressions over the fact namespace, evaluated with `eval` after the
AST has been checked against a node whitelist: no lambdas, no comprehensions, no calls except a
named set of fact methods, no name or attribute beginning with `_`, and `__builtins__` emptied.
The bundle is a merchant artifact that is content-hashed into every decision, not agent input. A
hand-rolled expression parser would be ~200 more lines to arrive at the same place; the
whitelist is the part that actually does the work, so it is 25 readable lines instead.

**Two failure modes, deliberately different.** A malformed *bundle* raises `PolicyError` and is
loud — a broken policy is an operator error. A rule that references a *fact* that isn't there
raises `FactError`, and that rule fails **closed**: it is recorded with its error, forced to
`deny`, and becomes the deciding rule. A rule the engine cannot evaluate is never a pass.

**Content hashing.** `bundle_hash` is the sha256 of the raw file bytes, not of the parsed
structure, so a comment change is a different bundle. Replay refuses to run against a bundle
whose hash does not match the record.

## The ledger

One append-only table. No UPDATE, no DELETE. Later stages of a decision — execution, approval,
reconciliation, incident, escalation timeout — are new rows carrying the same `decision_id`.

Each row stores the record as canonical JSON (sorted keys, compact separators) and hashes
**exactly the bytes in the column**. `decision_id`, `kind`, `ts` and `prev_hash` are folded into
the record before hashing, so a row's identity, order and timestamp are all inside the tamper
envelope.

- Edit the record → `record_hash` no longer matches the stored bytes.
- Recompute `record_hash` too → the Ed25519 signature over it fails.
- Delete a row → the next row's `prev_hash` no longer matches its predecessor: `broken_link`.

`verify_chain` reports every problem it finds with the sequence number, decision id and kind,
rather than stopping at the first.

**One addition to the the project spec §5.2 record shape:** `facts_snapshot`. Replay is impossible
without the inputs — `rules_evaluated[].observed` is the output of evaluation, not the input to
it. Everything else in §5.2 is present as specified.

## The envelope, and what binds to it

`envelope_hash = sha256(decision_id, sorted items with sku/qty/unit_price, total, currency)`.

It is the binding between "a human said yes" and "money moved". It is written into the decision
record, into the approval row, into `notes.envelope_hash` on the Razorpay order and payment
link, and it comes back on the capture webhook. An approval is scoped to it: change the cart by
one paise and the approval no longer applies. The reconciler checks it again at settlement.

## Escalation

A one-time bearer token, `secrets.token_urlsafe(32)`, of which only the sha256 is stored — a
dump of the database does not let anyone approve anything. TTL 300s. Redemption is guarded by
`UPDATE ... WHERE used_at IS NULL`, so two simultaneous clicks cannot both win.

Timeout is not a hang: `sweep_timeouts` turns every expired unanswered approval into a recorded
deny and the agent's poll returns `{"status":"denied","reason":"approval_timeout",
"retry_after_s":900}`. Silence is a no.

The approval page is plain HTML with no JavaScript. It shows the agent and its verified tier,
the cart **priced from the catalog**, any price claims that were discarded, and the exact rule
that fired with its observed value and threshold.

## The reconciler

On `payment.captured`, after the webhook signature is verified over the raw body:

1. **Attribute.** No `decision_id` in `notes` → an orphan incident record. Not a shrug.
2. **Latch.** `INSERT OR IGNORE INTO settled_payments`. This single statement is the entire
   duplicate defence: a retried webhook loses the race and can never trigger a second refund.
3. **Compare.** Captured amount vs bound amount, currency, envelope hash, order id, and whether
   the decision was actually authorised.
4. **Remediate.** A clean over-capture is refunded to the delta. Anything else — currency swap,
   envelope mismatch, order mismatch, capture without approval — reverses the whole capture,
   because we cannot say which part of it was authorised. An under-capture cannot be reversed
   and is flagged as an incident rather than silently accepted.
5. **Record.** A reconciliation row and an incident row, both linked to the decision, the
   incident carrying a structured `agent_notice` the agent can act on.

No LLM anywhere in that path.

## Threat model

| Attack | What stops it | Where |
|---|---|---|
| Agent lies about a price | Cart is repriced from catalog; claim recorded and refused | `catalog.price_cart`, `price.substitution` |
| Body swapped after signing | `Content-Digest` covered by the signature | `signatures.verify_request` → `digest_mismatch` |
| Digest rewritten too | Ed25519 over the signature base | → `signature_invalid` |
| Request replayed | Nonce store + ±60s `created` window | → `nonce_replay`, `stale_timestamp` |
| Unknown or revoked key | Registry lookup before anything else | → `unknown_key`, `revoked_key` |
| Agent claims a higher tier in the body | Tier comes from the verified key, never the body | → `agent_id_mismatch` |
| Unsigned request | Treated as the strictest tier and denied | `sig.unverified` |
| Quantity overflow | Per-order max from the catalog | `cart.unfulfillable` |
| Same SKU split across lines to stack past the max | Lines merged by SKU **before** the check | `catalog.price_cart` |
| Restricted goods | Category rule | `category.restricted` |
| Big order split into many small ones | Velocity and 24h spend, computed from the ledger | `velocity.1h`, `cap.daily` |
| Prompt injection in a product description | Descriptions never reach the model; schema has no price field | `intent.py` |
| Model hallucinates a SKU or emits junk | Schema validation + catalog existence check, fail closed | `intent.unvalidated` |
| Model asked to loosen a decision | Monotone authority assertion | `apply_advisory` |
| Approval token reused, expired, or re-scoped | One-shot latch, TTL, envelope binding | `escalation.py` |
| Nobody approves | Timeout auto-denies with a retry hint | `Gate.sweep_timeouts` |
| Capture larger than authorised | Automatic refund of the delta + incident | `reconciler.on_capture` |
| Capture in the wrong currency / against a swapped envelope | Full reversal | `reconciler.on_capture` |
| Duplicate capture webhook | `INSERT OR IGNORE` latch | `settled_payments` |
| Capture for a decision that never existed | Incident record | `reconciler.on_capture` |
| Forged webhook | HMAC-SHA256 over the raw body, constant-time, unset secret fails closed | `verify_webhook` |
| Insider edits the ledger | Hash chain + per-record signature | `verify_chain` |

## Deliberate simplifications

Marked in the code with `ponytail:` comments where they have a known ceiling.

- **Velocity is an indexed scan over the ledger, not a counter table.** A counter is a second
  source of truth that can drift from the record. Currently 2ms p50 for a whole decision; add a
  counter only if the harness shows it in p95.
- **SQLite, single writer, WAL.** The ledger is append-only and the workload is one merchant.
  Multi-tenant isolation is explicitly future work.
- **`sweep_timeouts` runs on read**, not on a timer. There is no scheduler in the stack, and an
  expired approval that nobody ever asks about has no effect to have.
- **Approvals are a mutable table, not ledger rows.** A one-time latch needs an UPDATE; the
  ledger records *that* an approval happened, the table is the latch that makes it one-shot.
- **The deterministic intent fallback matches on token overlap over titles.** It exists so the
  demo and the harness run offline; it is honest about being a fallback in every record it
  produces.

## Test map

93 tests, `make test`.

| File | Covers |
|---|---|
| `tests/test_signatures.py` | 13 — valid, tampered body, rewritten digest, unknown key, wrong key, stale and future timestamps, nonce replay, revoked key, tier claim in body, malformed headers, nonce-burning resistance, the exact signature base |
| `tests/test_policy_engine.py` | 27 — every rule firing and not firing, off-by-one boundaries, precedence, default-allow, observed/threshold, determinism over 50 runs, input immutability, no-I/O assertion, fail-closed on unknown facts, rejection of dangerous expressions, bundle hashing |
| `tests/test_ledger.py` | 12 — canonical JSON, genesis, chain linkage, tamper detection at each layer, deletion, append-only staging, velocity windows |
| `tests/test_gate.py` | 31 — catalog price truth, injection, schema fail-closed, monotone authority, allow/escalate/approve/reject/timeout, one-shot and envelope-scoped tokens, velocity, quantity, all reconciliation paths, chain intact after a full lifecycle, replay of every stored decision |
| `tests/test_http.py` | 10 — every route, the approval page contents, one-shot links over HTTP, forged and missing webhook signatures, capture reconciled and refunded end to end |
