"""
verdict_api.py — The NomosFlow Stable Verdict Contract
=======================================================

THIS FILE IS THE CONTRACT. It changes only with a major version bump.
Every surface adapter (PDP, ext-authz, proxy, sidecar) speaks this shape.
Adapters must never branch on tier_traces for enforcement — only on verdict.

Input:  VerdictRequest  (principal + operation + optional enriched context)
Output: VerdictResponse (verdict + reasons + full audit record)
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any


def _is_prod() -> bool:
    """Return True when NOMOSFLOW_ENV=production.

    Force-flags are stripped in production so that no external caller can
    manipulate a compliance verdict by injecting force* keys into the request.
    Set NOMOSFLOW_ENV=production in your deployment environment.
    Unset (or any other value) → dev/test/demo mode, flags are accepted.
    """
    return os.getenv("NOMOSFLOW_ENV", "").lower() == "production"


# ─────────────────────────────────────────────────────────────────────────────
# INPUT TYPES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Principal:
    """Who is making the request."""
    id: str                         # user_id / agent_id / service account
    role: str                       # JUNIOR | SENIOR | ADMIN | ANALYST | …
    token: str | None = None        # JWT / Bearer token (optional)


@dataclass
class Operation:
    """What is being requested."""
    action: str                     # READ | WRITE | DELETE | ANALYZE | TRADE
    resource: str                   # fred/UNRATE, s3://bucket/key, /data/file.csv …
    method: str | None = None       # HTTP verb when the caller is a proxy adapter
    purpose: str | None = None      # FinancialAnalysis | Research | ExternalSharing …


@dataclass
class EnrichedContext:
    """
    Context enriched by CMF (ContextForge) during evaluation.
    Callers may pre-populate known fields; the engine fills the rest.
    """
    classification: str = "public"          # public | internal | confidential | restricted
    contains_pii: bool = False
    pii_types: list[str] = field(default_factory=list)
    risk_level: str = "LOW"                 # LOW | MEDIUM | HIGH | CRITICAL
    session_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class VerdictRequest:
    """
    The complete input to the engine.
    Construct one per inbound request; pass to NomosFlowEngine.decide().
    """
    request_id: str
    principal: Principal
    operation: Operation
    context: EnrichedContext = field(default_factory=EnrichedContext)

    # Force-flags for demo/test scenarios (ignored in production mode)
    _force: dict[str, Any] = field(default_factory=dict)

    def to_legacy_ctx(self) -> dict[str, Any]:
        """Convert to the flat ctx dict that the bridge tier functions expect."""
        d: dict[str, Any] = {
            "request_id": self.request_id,
            "user_id":    self.principal.id,
            "agent_id":   self.principal.id,
            "role":       self.principal.role,
            "action":     self.operation.action,
            "resource":   self.operation.resource,
            "risk_level": self.context.risk_level,
        }
        if self.principal.token:
            d["token"] = self.principal.token
        if self.operation.purpose:
            d["purpose"] = self.operation.purpose
        # Expose session_metadata so run_cmf() can scan the payload for PII.
        if self.context.session_metadata:
            d["session_metadata"] = self.context.session_metadata
        d.update(self._force)
        return d

    @classmethod
    def from_legacy_ctx(cls, ctx: dict[str, Any]) -> "VerdictRequest":
        """Construct from the flat ctx dict used by the bridge and adapters."""
        _FORCE_KEYS = {
            "forceBlockUser", "forceOPADeny", "forcePII", "forceRateLimit",
            "forceAnomaly", "forceDelegation", "forceLLMDeny",
            "forceOPAEscalate",
            "_forceBlockUser", "_forceOPADeny", "_forcePII", "_forceRateLimit",
            "_forceAnomaly", "_forceDelegation", "_forceLLMDeny",
        }
        # Strip force-flags entirely in production — they must never reach
        # a live compliance decision from an external caller.
        force = {} if _is_prod() else {k: v for k, v in ctx.items() if k in _FORCE_KEYS and v}
        return cls(
            request_id = ctx.get("request_id", f"req-{int(time.time()*1000)}"),
            principal  = Principal(
                id    = ctx.get("user_id") or ctx.get("agent_id", "unknown"),
                role  = ctx.get("role", "ANALYST"),
                token = ctx.get("token"),
            ),
            operation  = Operation(
                action   = ctx.get("action", "READ"),
                resource = ctx.get("resource", "/data/unknown"),
                method   = ctx.get("method"),
                purpose  = ctx.get("purpose"),
            ),
            context    = EnrichedContext(
                risk_level       = ctx.get("risk_level", "LOW"),
                session_metadata = ctx.get("session_metadata") or {},
            ),
            _force     = force,
        )


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT TYPES
# ─────────────────────────────────────────────────────────────────────────────

VERDICTS = frozenset({"ALLOW", "DENY", "THROTTLE", "DELEGATE"})


@dataclass
class TierTrace:
    """One tier's contribution to the decision — for observability only."""
    tier: str           # APL | CMF | OPA | Stateful | LLM
    verdict: str        # ALLOW | DENY | PASS | ESCALATE | THROTTLE | DELEGATE
    reason: str
    latency_ms: float
    live: bool = True   # True → real service; False → simulation fallback

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditRecord:
    """
    The immutable audit record for one request.
    The engine generates this; the AuditEmitter ships it to S3/Kafka/SQLite.
    Adapters may forward it in a response header for distributed tracing.
    Adapters must never write it themselves.
    """
    request_id:    str
    timestamp:     str
    principal_id:  str
    role:          str
    action:        str
    resource:      str
    final_verdict: str
    tier_traces:   list[TierTrace]
    engine_version: str = "1.0.0"
    policy_version: str | None = None
    # OSCAL / compliance-trestle integration.
    # Populated asynchronously by TrestleAnnotator after decide() returns.
    # Each entry is a NIST SP 800-53 rev 5 control ID (e.g. "AC-3", "AU-2").
    oscal_controls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class VerdictResponse:
    """
    The complete output from the engine.
    Adapters enforce on verdict ONLY.  All other fields are for
    observability, audit forwarding, and demo visualisation.
    """
    request_id:   str
    verdict:      str           # ALLOW | DENY | THROTTLE | DELEGATE
    reason:       str
    tier_traces:  list[TierTrace]
    audit:        AuditRecord
    latency_ms:   float

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id":  self.request_id,
            "verdict":     self.verdict,
            "reason":      self.reason,
            "latency_ms":  round(self.latency_ms, 2),
            "tier_traces": [t.to_dict() for t in self.tier_traces],
            "audit":       self.audit.to_dict(),
        }

    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    # Compatibility helper: produce the legacy bridge shape so existing
    # callers of run_pipeline() continue to work without modification.
    def to_legacy(self) -> dict[str, Any]:
        """
        Map VerdictResponse → { tiers: [...], final: str, request_id: str }
        which is the shape /decide has always returned.
        """
        final_map = {
            "ALLOW":    "APPROVED",
            "DENY":     "DENIED",
            "THROTTLE": "THROTTLED",
            "DELEGATE": "DELEGATED",
        }
        tier_decision_map = {
            "ALLOW":    "PASS_THROUGH",
            "PASS":     "PASS_THROUGH"  # vault-radar:ignore,
            "DENY":     "DENIED",
            "THROTTLE": "THROTTLED",
            "ESCALATE": "ESCALATED",
            "DELEGATE": "DELEGATED",
        }
        tiers = [
            {
                "tier":     t.tier,
                "num":      i + 1,
                "decision": tier_decision_map.get(t.verdict.upper(), t.verdict),
                "reason":   t.reason,
                "ms":       round(t.latency_ms, 2),
                "rules":    0,
                "live":     t.live,
            }
            for i, t in enumerate(self.tier_traces)
        ]
        return {
            "tiers":      tiers,
            "final":      final_map.get(self.verdict, self.verdict),
            "request_id": self.request_id,
        }
