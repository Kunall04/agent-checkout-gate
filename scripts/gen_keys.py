"""Generate Ed25519 keys and the agent registry.

# MOCK: the trust root. Real crypto, our own CA. In production the registry
# below is replaced by a Visa Trusted Agent Protocol / JWKS lookup — the
# verification path in gate/signatures.py does not change, only where the
# public key comes from.
Run: python scripts/gen_keys.py
"""
import base64, json, pathlib
from nacl.signing import SigningKey

ROOT = pathlib.Path(__file__).resolve().parent.parent
KEYS = ROOT / "data" / "keys"
KEYS.mkdir(parents=True, exist_ok=True)

b64 = lambda b: base64.b64encode(bytes(b)).decode()

AGENTS = [  # agent_id, key_id, trust_tier, status
    ("agt_shopper_01", "k1", "B", "active"),
    ("agt_procure_ent", "k1", "A", "active"),
    ("agt_lowtrust_03", "k1", "C", "active"),
    ("agt_revoked_09", "k1", "B", "revoked"),
]

registry = {"registry_version": "2026-09-04", "trust_root": "MOCK: local dev CA", "agents": {}}
for agent_id, key_id, tier, status in AGENTS:
    sk = SigningKey.generate()
    (KEYS / f"{agent_id}.{key_id}.json").write_text(json.dumps(
        {"agent_id": agent_id, "key_id": key_id,
         "private_key": b64(sk._seed), "public_key": b64(sk.verify_key)}, indent=2) + "\n")
    registry["agents"][f"{agent_id}.{key_id}"] = {
        "agent_id": agent_id, "key_id": key_id, "alg": "ed25519",
        "public_key": b64(sk.verify_key), "trust_tier": tier, "status": status}

# the gate's own ledger-signing key
gk = SigningKey.generate()
(KEYS / "gate-1.json").write_text(json.dumps(
    {"kid": "gate-1", "private_key": b64(gk._seed), "public_key": b64(gk.verify_key)}, indent=2) + "\n")
(ROOT / "data" / "gate_pubkey.json").write_text(json.dumps(
    {"kid": "gate-1", "alg": "Ed25519", "public_key": b64(gk.verify_key)}, indent=2) + "\n")

(ROOT / "data" / "registry.json").write_text(json.dumps(registry, indent=2) + "\n")
print(f"wrote {len(AGENTS)} agent keys + gate-1 to {KEYS}, registry at data/registry.json")
