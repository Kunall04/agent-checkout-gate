"""RFC 9421 HTTP Message Signatures — the subset this gate needs, by hand.

Implemented: Ed25519 ("ed25519"), one signature label (`sig1`), derived
components "@method" and "@path", the "content-digest" header (RFC 9530,
sha-256), and the `created` / `keyid` / `alg` / `nonce` signature parameters.

Not implemented (deliberately, and stated so no one mistakes this for a full
library): multiple labels, `expires`, `@authority`/`@query`/`@target-uri`,
structured-field parameters on components, JWS algorithms other than Ed25519.

Replay defence beyond the RFC: a nonce store plus a +/-60s window on `created`.
"""
from __future__ import annotations

import base64
import hashlib
import re
import sqlite3
import time
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from gate.registry import Registry

COVERED = ("@method", "@path", "content-digest")
MAX_SKEW_S = 60
NONCE_TTL_S = 300  # keep nonces well past the skew window before pruning
LABEL = "sig1"

_PARAMS_RE = re.compile(
    r'^\s*(?P<label>[A-Za-z0-9_-]+)=\((?P<covered>[^)]*)\)(?P<params>(;[^;]+)*)\s*$')
_SIG_RE = re.compile(r'^\s*(?P<label>[A-Za-z0-9_-]+)=:(?P<b64>[A-Za-z0-9+/=]+):\s*$')


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str                     # "verified" or a distinct machine-readable failure
    agent_id: str | None = None
    key_id: str | None = None
    trust_tier: str | None = None
    registry_version: str | None = None
    created: int | None = None


def content_digest(body: bytes) -> str:
    """RFC 9530 Content-Digest, sha-256 only."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def _params_string(created: int, keyid: str, nonce: str) -> str:
    covered = " ".join(f'"{c}"' for c in COVERED)
    return f'({covered});created={created};keyid="{keyid}";alg="ed25519";nonce="{nonce}"'


def signature_base(method: str, path: str, digest: str, params: str) -> str:
    """The exact bytes that get signed. One line per covered component, then
    @signature-params. No trailing newline (RFC 9421 §2.5)."""
    values = {"@method": method.upper(), "@path": path, "content-digest": digest}
    lines = [f'"{c}": {values[c]}' for c in COVERED]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines)


def sign_request(method: str, path: str, body: bytes, *, agent_id: str, key_id: str,
                 private_key_seed: bytes, created: int | None = None,
                 nonce: str | None = None) -> dict[str, str]:
    """Produce the three headers a client must send. Used by buyer_agent and tests."""
    import secrets
    created = int(time.time()) if created is None else created
    nonce = secrets.token_hex(16) if nonce is None else nonce
    keyid = f"{agent_id}.{key_id}"
    digest = content_digest(body)
    params = _params_string(created, keyid, nonce)
    sig = SigningKey(private_key_seed).sign(signature_base(method, path, digest, params).encode()).signature
    return {
        "Content-Digest": digest,
        "Signature-Input": f"{LABEL}={params}",
        "Signature": f"{LABEL}=:{base64.b64encode(sig).decode()}:",
    }


def _parse_params(value: str) -> dict[str, str] | None:
    m = _PARAMS_RE.match(value)
    if not m or m.group("label") != LABEL:
        return None
    covered = tuple(c.strip().strip('"') for c in m.group("covered").split() if c.strip())
    if covered != COVERED:
        return None
    out: dict[str, str] = {"_covered": " ".join(covered), "_raw": value.split("=", 1)[1].strip()}
    for part in m.group("params").split(";"):
        if not part:
            continue
        k, _, v = part.partition("=")
        out[k.strip()] = v.strip().strip('"')
    return out


def _check_nonce(conn: sqlite3.Connection, nonce: str, agent_id: str, now: int) -> bool:
    """True if fresh. Insert-or-fail is the whole check — PRIMARY KEY does the
    concurrency work, so there is no read-then-write race to lose."""
    conn.execute("DELETE FROM nonces WHERE seen_at < ?", (now - NONCE_TTL_S,))
    try:
        conn.execute("INSERT INTO nonces(nonce, agent_id, seen_at) VALUES (?,?,?)",
                     (nonce, agent_id, now))
        return True
    except sqlite3.IntegrityError:
        return False


def verify_request(method: str, path: str, body: bytes, headers: dict[str, str], *,
                   registry: Registry, conn: sqlite3.Connection,
                   now: int | None = None, claimed_agent_id: str | None = None) -> VerifyResult:
    """Verify in cheapest-first order, and fail closed with a distinct reason.

    Order matters: never touch the nonce store until the signature itself is
    good, or an attacker could burn a victim's nonces with forged requests.
    """
    now = int(time.time()) if now is None else now
    h = {k.lower(): v for k, v in headers.items()}

    raw_input, raw_sig = h.get("signature-input"), h.get("signature")
    if not raw_input or not raw_sig:
        return VerifyResult(False, "missing_signature")

    params = _parse_params(raw_input)
    sig_m = _SIG_RE.match(raw_sig)
    if params is None or sig_m is None or sig_m.group("label") != LABEL:
        return VerifyResult(False, "malformed_signature_input")
    if params.get("alg") != "ed25519":
        return VerifyResult(False, "unsupported_alg")
    if not params.get("nonce"):
        return VerifyResult(False, "missing_nonce")
    try:
        created = int(params["created"])
    except (KeyError, ValueError):
        return VerifyResult(False, "malformed_created")

    key = registry.lookup(params.get("keyid", ""))
    if key is None:
        return VerifyResult(False, "unknown_key")
    ident = dict(agent_id=key.agent_id, key_id=key.key_id, trust_tier=key.trust_tier,
                 registry_version=registry.version, created=created)
    if key.status != "active":
        return VerifyResult(False, "revoked_key", **ident)
    if claimed_agent_id is not None and claimed_agent_id != key.agent_id:
        return VerifyResult(False, "agent_id_mismatch", **ident)

    sent_digest = h.get("content-digest", "")
    if sent_digest != content_digest(body):
        # Covers both a lying digest header and a body edited in flight.
        return VerifyResult(False, "digest_mismatch", **ident)

    if abs(now - created) > MAX_SKEW_S:
        return VerifyResult(False, "stale_timestamp", **ident)

    base = signature_base(method, path, sent_digest, params["_raw"])
    try:
        VerifyKey(key.public_key).verify(base.encode(), base64.b64decode(sig_m.group("b64")))
    except (BadSignatureError, ValueError):
        return VerifyResult(False, "signature_invalid", **ident)

    if not _check_nonce(conn, params["nonce"], key.agent_id, now):
        return VerifyResult(False, "nonce_replay", **ident)

    return VerifyResult(True, "verified", **ident)
