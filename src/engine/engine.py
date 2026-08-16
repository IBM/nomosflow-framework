"""
engine.py — NomosFlowEngine: the single shared decision engine
==============================================================

All five compliance tiers run inside decide().  Adapters call decide() and
nothing else.  They enforce on VerdictResponse.verdict only.

Architecture invariants (enforced by code review):
  • No adapter file may call _run_apl / _run_cmf / … directly.
  • No adapter file may write audit records — AuditEmitter is called here.
  • VerdictResponse.tier_traces is for observability only; adapters must not
    branch on it for enforcement logic.

The engine wraps the existing bridge tier functions (run_apl, run_cmf, etc.)
so all live-service fallback logic in the bridge is reused unchanged.  This
is a thin orchestration wrapper — the tier implementations are not duplicated.
"""

from __future__ import annotations

import os
import time
import logging
from dataclasses import replace

from src.engine.verdict_api import (
    VerdictRequest, VerdictResponse,
    TierTrace, AuditRecord,
)
from src.engine.audit_emitter import AuditEmitter
from src.validators.trestle_validator import TrestleAnnotator

logger = logging.getLogger(__name__)

_ENGINE_VERSION = "1.0.0"

# ─── lazy import of bridge tier functions ─────────────────────────────────────
# These are imported lazily so the engine can be imported without Flask
# being on the import path.  The bridge tier functions are the canonical
# implementations of each tier — we do not duplicate logic here.

def _get_bridge():
    """Return the compliance_bridge module, importing it on first call."""
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    import importlib
    return importlib.import_module("demo.compliance_bridge")


def _utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


# ─── verdict mapping ──────────────────────────────────────────────────────────

_TIER_VERDICT = {
    "PASS_THROUGH": "PASS",
    "APPROVED":     "ALLOW",
    "DENIED":       "DENY",
    "THROTTLED":    "THROTTLE",
    "DELEGATED":    "DELEGATE",
    "ESCALATED":    "ESCALATE",
}

_FINAL_VERDICT = {
    "APPROVED":  "ALLOW",
    "DENIED":    "DENY",
    "THROTTLED": "THROTTLE",
    "DELEGATED": "DELEGATE",
}


class NomosFlowEngine:
    """
    The shared compliance engine.

    Instantiate once per process (or per-request for stateless use).
    Thread-safe: the tier functions are stateless.

    Example::
        engine = NomosFlowEngine()
        resp = engine.decide(VerdictRequest.from_legacy_ctx(ctx))
        if resp.allowed():
            forward(request)
        else:
            return 403, resp.reason
    """

    def __init__(self) -> None:
        self._emitter    = AuditEmitter()
        # Pass emitter so TrestleAnnotator can UPDATE the persisted row after
        # resolving controls — closing the two-phase write loop.
        self._annotator  = TrestleAnnotator(emitter=self._emitter)
        logger.info("NomosFlowEngine initialised (version %s)", _ENGINE_VERSION)

    # ─── public API ─────────────────────────────────────────────────────────

    def decide(self, req: VerdictRequest) -> VerdictResponse:
        """
        Evaluate a VerdictRequest through all five tiers and return a
        VerdictResponse.  The AuditRecord is emitted asynchronously.
        """
        t0 = time.perf_counter()
        traces: list[TierTrace] = []
        bridge = _get_bridge()
        ctx = req.to_legacy_ctx()

        # ── Tier 1: APL (blocklist, token, role check) ───────────────────
        r1 = bridge.run_apl(ctx)
        traces.append(_to_trace(r1))
        if r1["decision"] != "PASS_THROUGH":
            return self._respond(req, r1["decision"], r1["reason"], traces, t0)

        # ── Tier 2: CMF (context enrichment + PII tagging) ───────────────
        r2, cmf_ctx = bridge.run_cmf(ctx)
        traces.append(_to_trace(r2))
        # propagate enrichment into request context
        req = replace(req, context=replace(
            req.context,
            classification = cmf_ctx.get("classification", req.context.classification),
            contains_pii   = cmf_ctx.get("containsPII",    req.context.contains_pii),
            pii_types      = cmf_ctx.get("pii",            req.context.pii_types),
        ))
        ctx = req.to_legacy_ctx()           # rebuild ctx with enrichment

        # ── Tier 3: OPA (policy evaluation) ──────────────────────────────
        r3 = bridge.run_opa(ctx, cmf_ctx)
        traces.append(_to_trace(r3))
        if r3["decision"] == "ESCALATED":
            r5 = bridge.run_llm(ctx)
            traces.append(_to_trace(r5))
            return self._respond(req, r5["decision"], r5["reason"], traces, t0)
        # THROTTLE on CRITICAL risk → escalate to LLM for human-delegation check.
        # All other non-PASS_THROUGH OPA outcomes (DENIED, THROTTLED on LOW/MEDIUM/HIGH) terminate.
        if r3["decision"] == "THROTTLED" and req.context.risk_level == "CRITICAL":
            r5 = bridge.run_llm(ctx)
            traces.append(_to_trace(r5))
            return self._respond(req, r5["decision"], r5["reason"], traces, t0)
        if r3["decision"] != "PASS_THROUGH":
            return self._respond(req, r3["decision"], r3["reason"], traces, t0)

        # ── Tier 4: Stateful (rate limit + anomaly detection) ────────────
        r4 = bridge.run_stateful(ctx)
        traces.append(_to_trace(r4))
        if r4["decision"] == "ESCALATED":
            r5 = bridge.run_llm(ctx)
            traces.append(_to_trace(r5))
            return self._respond(req, r5["decision"], r5["reason"], traces, t0)
        if r4["decision"] != "PASS_THROUGH":
            return self._respond(req, r4["decision"], r4["reason"], traces, t0)

        return self._respond(req, "APPROVED", "All tiers passed", traces, t0)

    # ─── internal helpers ───────────────────────────────────────────────────

    def _respond(
        self,
        req: VerdictRequest,
        legacy_decision: str,
        reason: str,
        traces: list[TierTrace],
        t0: float,
    ) -> VerdictResponse:
        latency = (time.perf_counter() - t0) * 1000
        verdict = _FINAL_VERDICT.get(legacy_decision, "DENY")

        audit = AuditRecord(
            request_id    = req.request_id,
            timestamp     = _utcnow(),
            principal_id  = req.principal.id,
            role          = req.principal.role,
            action        = req.operation.action,
            resource      = req.operation.resource,
            final_verdict = verdict,
            tier_traces   = traces,
            engine_version= _ENGINE_VERSION,
        )
        self._emitter.emit(audit, latency)
        # Annotate with OSCAL control IDs asynchronously (never blocks decide()).
        self._annotator.annotate(VerdictResponse(
            request_id  = req.request_id,
            verdict     = verdict,
            reason      = reason,
            tier_traces = traces,
            audit       = audit,
            latency_ms  = latency,
        ))

        return VerdictResponse(
            request_id  = req.request_id,
            verdict     = verdict,
            reason      = reason,
            tier_traces = traces,
            audit       = audit,
            latency_ms  = latency,
        )


# ─── module-level convenience ─────────────────────────────────────────────────

_default_engine: NomosFlowEngine | None = None


def get_engine() -> NomosFlowEngine:
    """Return the process-level singleton engine (lazy-initialised)."""
    global _default_engine
    if _default_engine is None:
        _default_engine = NomosFlowEngine()
    return _default_engine


# ─── helper ───────────────────────────────────────────────────────────────────

def _to_trace(tier_dict: dict) -> TierTrace:
    """Convert a bridge tier result dict to a TierTrace."""
    raw  = tier_dict.get("decision", "PASS_THROUGH")
    verd = _TIER_VERDICT.get(raw, raw)
    return TierTrace(
        tier       = tier_dict.get("tier", "?"),
        verdict    = verd,
        reason     = tier_dict.get("reason", ""),
        latency_ms = float(tier_dict.get("ms", 0.0)),
        live       = bool(tier_dict.get("live", False)),
    )
