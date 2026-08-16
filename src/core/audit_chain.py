"""
Audit Chain — cross-surface causal audit trail for Demo 4 (Hybrid Gateway+Sidecar).

The gateway stamps every forwarded request with an X-NomosFlow-Audit-Chain header
containing a base64-encoded JSON list of AuditChainEntry records for the tiers it
has already evaluated.  The sidecar reads the header, prepends the gateway entries
to its own audit batch, and writes the complete causal chain to S3/SQLite.

This module is pure (no I/O); it is safe to import in both the gateway process
and the sidecar process.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import asdict, dataclass
from typing import Any

HEADER_NAME = "X-NomosFlow-Audit-Chain"
TIERS_HEADER = "X-NomosFlow-Tiers-Completed"


@dataclass
class AuditChainEntry:
    """One tier's contribution to the causal audit chain."""
    surface: str          # "gateway" | "sidecar"
    tier: str             # "APL" | "rate_limit" | "OPA-coarse" | "CMF" | "OPA-fine" | "LLM"
    verdict: str          # "PASS" | "DENY" | "THROTTLE" | "ESCALATE"
    latency_ms: float
    reason: str = ""
    rules_evaluated: list[str] | None = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = _utcnow()
        if self.rules_evaluated is None:
            self.rules_evaluated = []

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def encode_chain(entries: list[AuditChainEntry]) -> str:
    """Serialise a list of AuditChainEntry objects to a single header value."""
    payload = json.dumps([e.to_dict() for e in entries], separators=(",", ":"))
    return base64.b64encode(payload.encode()).decode()


def decode_chain(header_value: str) -> list[AuditChainEntry]:
    """Deserialise a header value back to AuditChainEntry objects.

    Returns an empty list on any decode error so callers never crash on a
    malformed or absent header.
    """
    if not header_value:
        return []
    try:
        raw = json.loads(base64.b64decode(header_value.encode()).decode())
        return [AuditChainEntry(**entry) for entry in raw]
    except Exception:
        return []


def _utcnow() -> str:
    """ISO-8601 timestamp in UTC without external dependencies."""
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

# Made with Bob
