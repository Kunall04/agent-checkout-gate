"""agent_id -> public key + trust tier.

# MOCK: the trust root. See scripts/gen_keys.py. Crypto is real; the
# authority that vouches for the key is ours. Swapping this for a TAP/JWKS
# fetch changes only load() — nothing in signatures.py moves.
"""
from __future__ import annotations

import base64
import json
import pathlib
from dataclasses import dataclass

REGISTRY_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "registry.json"


@dataclass(frozen=True)
class AgentKey:
    agent_id: str
    key_id: str
    alg: str
    public_key: bytes
    trust_tier: str
    status: str


class Registry:
    def __init__(self, path: pathlib.Path = REGISTRY_PATH):
        raw = json.loads(path.read_text())
        self.version: str = raw["registry_version"]
        self.keys: dict[str, AgentKey] = {
            k: AgentKey(v["agent_id"], v["key_id"], v["alg"],
                        base64.b64decode(v["public_key"]), v["trust_tier"], v["status"])
            for k, v in raw["agents"].items()
        }

    def lookup(self, keyid: str) -> AgentKey | None:
        """keyid is "<agent_id>.<key_id>" — self-contained so verification
        never has to trust the request body to find a key."""
        return self.keys.get(keyid)


_registry: Registry | None = None


def registry() -> Registry:
    global _registry
    if _registry is None:
        _registry = Registry()
    return _registry
