"""
experiments/exp2_resolution/run.py
EXP-2 — Resolution Distribution for the NomosFlow VLDB paper.

Pipeline tiers (deployed order):
  T1_APL    — APL checks 1-5 (token/role/action/resource/RBAC)
  T1_ATTEST — APL Check 6 (skill attestation); only fires when skill_id present
  T2_CMF    — CMF enrichment; always passes through (never denies)
  T3_OPA    — OPA policy engine (decide())
  T4_RATE   — Rate-limit counter (count > 50/s → DENY).
              NOTE: T4's anomaly-detection runs as a post-decision daemon thread
              and is advisory only — it is NOT counted as a resolving tier here.
  T5_LLM    — LLM semantic check; only for requests flagged _route_to_llm=True
  APPROVED  — cleared all tiers

Prop. 3 cost model: optimal tier order minimises sum_i c_i / (1 - p_i),
where p_i is the fraction of requests that *reach* tier i and c_i is the
mean latency of tier i (across requests that reached it).
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_REPO_ROOT_INSERT = _Path(__file__).resolve().parents[2]
if str(_REPO_ROOT_INSERT) not in _sys.path:
    _sys.path.insert(0, str(_REPO_ROOT_INSERT))

import os
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

# ── ensure repo root on sys.path ──────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from experiments.shared.common import (
    Timer,
    _stats,
    make_request,
    save_result,
)
from experiments.shared.opa_client import decide
from experiments.shared.report import fmt_ms, write_summary

# ── optional validator imports (try/except fallbacks) ─────────────────────────
try:
    from src.validators.apl_validator import APLValidator as _APLValidator
    _apl_validator = _APLValidator()
    _APL_AVAILABLE = True
except Exception:
    _APLValidator = None          # type: ignore[assignment,misc]
    _apl_validator = None
    _APL_AVAILABLE = False

try:
    from src.validators.cmf_context_enricher import CMFContextEnricher as _CMFEnricher
    _cmf_enricher = _CMFEnricher(pii_detection=False)   # lightweight for benchmarking
    _CMF_AVAILABLE = True
except Exception:
    _CMFEnricher = None           # type: ignore[assignment,misc]
    _cmf_enricher = None
    _CMF_AVAILABLE = False

# ── experiment constants ───────────────────────────────────────────────────────
_N_DEFAULT          = 2000
_SKILL_PROB         = 0.15   # fraction of requests that carry a skill_id
_LLM_ROUTE_PROB     = 0.01   # fraction routed to T5 (matches make_request default)
_RATE_LIMIT_PER_S   = 50     # requests per second before T4 triggers
_LLM_LATENCY_MU     = 95.0   # ms — LLM simulated latency mean
_LLM_LATENCY_SIG    = 20.0
_LLM_DENY_RATE      = 0.30   # 30 % of escalated requests denied by LLM

# Tier names in deployed pipeline order
_TIERS = ["T1_APL", "T1_ATTEST", "T2_CMF", "T3_OPA", "T4_RATE", "T5_LLM", "APPROVED"]


# ─────────────────────────────────────────────────────────────────────────────
# Simulated tier helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run_t1_apl(req: dict[str, Any]) -> tuple[bool, str, float]:
    """Checks 1-5 via APLValidator.validate().  Returns (allowed, reason, ms)."""
    if _APL_AVAILABLE and _apl_validator is not None:
        with Timer() as t:
            approved, reason, _us = _apl_validator.validate(req)
        return approved, reason, t.ms
    # simulation fallback: ~5 % bad-token / RBAC deny rate
    t0 = time.perf_counter()
    role   = req.get("role", "SENIOR")
    action = req.get("action", "READ")
    token  = req.get("token", "")
    bad_token  = not token or len(token) < 10
    rbac_fail  = (role == "JUNIOR" and action == "WRITE")
    purpose_ok = req.get("purpose", "OK") not in ("PersonalUse", "MarketingCampaign")
    ms = (time.perf_counter() - t0) * 1000 + max(0.1, random.gauss(0.3, 0.05))
    if bad_token:
        return False, "SIM APL: bad token", ms
    if rbac_fail:
        return False, "SIM APL: JUNIOR cannot WRITE", ms
    if not purpose_ok:
        return False, "SIM APL: invalid purpose", ms
    return True, "SIM APL: approved", ms


def _run_t1_attest(req: dict[str, Any]) -> tuple[bool, str, float] | None:
    """Check 6 (skill attestation).  Returns None if skill_id absent."""
    if not req.get("skill_id"):
        return None   # not applicable — no skill on this request
    if _APL_AVAILABLE and _apl_validator is not None:
        with Timer() as t:
            # Re-invoke validate; APLValidator internally skips checks 1-5 only
            # when the token has already been seen (lru_cache hit).  We call the
            # full validate() again — it is cheap and check 6 will fire.
            approved, reason, _us = _apl_validator.validate(req)
        # If APL already denied at check 1-5 that was caught above; here we
        # report the attestation sub-outcome.  In the pipeline the request
        # would not reach attest at all after a T1_APL deny, so we re-run
        # only to measure the check-6 specific path.
        return approved, reason, t.ms
    # simulation fallback: 20 % of skill requests fail attestation
    t0 = time.perf_counter()
    ms = (time.perf_counter() - t0) * 1000 + max(0.05, random.gauss(0.2, 0.04))
    if random.random() < 0.20:
        return False, "SIM ATTEST: skill not registered", ms
    return True, "SIM ATTEST: attested", ms


def _run_t2_cmf(req: dict[str, Any]) -> tuple[dict[str, Any], float]:
    """CMF enrichment — always passes through; returns (enriched_req, ms)."""
    if _CMF_AVAILABLE and _cmf_enricher is not None:
        with Timer() as t:
            enriched = _cmf_enricher.enrich_message(req)
        return enriched, t.ms
    # simulation fallback
    t0 = time.perf_counter()
    ms = (time.perf_counter() - t0) * 1000 + max(0.05, random.gauss(0.8, 0.15))
    return req, ms


def _run_t3_opa(req: dict[str, Any]) -> tuple[bool, str, float]:
    """OPA policy evaluation via opa_client.decide()."""
    allowed, reason, ms = decide(req)
    return allowed, reason, ms


def _run_t4_rate(req: dict[str, Any], window_counts: dict[int, int]) -> tuple[bool, str, float]:
    """
    Rate-limit check: count > _RATE_LIMIT_PER_S in the current second → DENY.
    window_counts maps second-bucket → count so far.
    NOTE: T4's anomaly detection runs post-decision in a daemon thread and is
    advisory only — it is NOT counted here as a resolving tier.
    """
    t0 = time.perf_counter()
    ts  = int(req.get("timestamp", time.time()))
    bucket = ts // 1          # 1-second buckets on the synthetic timestamp
    window_counts[bucket] += 1
    ms = (time.perf_counter() - t0) * 1000 + max(0.01, random.gauss(0.05, 0.01))
    if window_counts[bucket] > _RATE_LIMIT_PER_S:
        return False, "T4: rate limit exceeded", ms
    return True, "T4: within rate limit", ms


def _run_t5_llm(req: dict[str, Any]) -> tuple[bool, str, float]:
    """
    LLM semantic check — simulated only (no live API call in experiments).
    30 % deny rate, latency ~ N(95 ms, 20 ms).
    """
    t0 = time.perf_counter()
    ms = (time.perf_counter() - t0) * 1000 + max(5.0, random.gauss(_LLM_LATENCY_MU, _LLM_LATENCY_SIG))
    if random.random() < _LLM_DENY_RATE:
        return False, "T5_LLM: hallucination detected", ms
    return True, "T5_LLM: cleared", ms


# ─────────────────────────────────────────────────────────────────────────────
# Single-request pipeline
# ─────────────────────────────────────────────────────────────────────────────

def _run_pipeline(
    req: dict[str, Any],
    window_counts: dict[int, int],
    *,
    forced: bool = False,
) -> dict[str, Any]:
    """
    Execute the 5-tier pipeline for one request.

    Args:
        req:           synthetic compliance request
        window_counts: mutable rate-window state shared across requests
        forced:        if True, run every tier regardless of DENY (ablation)

    Returns dict with:
      resolved_tier: str  — tier that issued the final verdict
      verdict:       str  — "DENY" | "ALLOW"
      tier_latencies: {tier: ms}  — latency for each tier that was reached
      total_ms:      float
    """
    tier_latencies: dict[str, float] = {}
    resolved_tier  = "APPROVED"
    verdict        = "ALLOW"
    total_ms       = 0.0
    final_deny_tier: str | None = None  # used in forced mode

    # ── T1_APL ────────────────────────────────────────────────────────────────
    allowed_t1, reason_t1, ms_t1 = _run_t1_apl(req)
    tier_latencies["T1_APL"] = ms_t1
    total_ms += ms_t1
    if not allowed_t1:
        if not forced:
            return {
                "resolved_tier": "T1_APL", "verdict": "DENY",
                "tier_latencies": tier_latencies, "total_ms": total_ms,
            }
        final_deny_tier = final_deny_tier or "T1_APL"

    # ── T1_ATTEST ─────────────────────────────────────────────────────────────
    attest_result = _run_t1_attest(req)
    if attest_result is not None:
        allowed_ta, _reason_ta, ms_ta = attest_result
        tier_latencies["T1_ATTEST"] = ms_ta
        total_ms += ms_ta
        if not allowed_ta:
            if not forced:
                return {
                    "resolved_tier": "T1_ATTEST", "verdict": "DENY",
                    "tier_latencies": tier_latencies, "total_ms": total_ms,
                }
            final_deny_tier = final_deny_tier or "T1_ATTEST"

    # ── T2_CMF (enrichment — never denies) ───────────────────────────────────
    enriched_req, ms_t2 = _run_t2_cmf(req)
    tier_latencies["T2_CMF"] = ms_t2
    total_ms += ms_t2

    # ── T3_OPA ────────────────────────────────────────────────────────────────
    allowed_t3, _reason_t3, ms_t3 = _run_t3_opa(enriched_req)
    tier_latencies["T3_OPA"] = ms_t3
    total_ms += ms_t3
    if not allowed_t3:
        if not forced:
            return {
                "resolved_tier": "T3_OPA", "verdict": "DENY",
                "tier_latencies": tier_latencies, "total_ms": total_ms,
            }
        final_deny_tier = final_deny_tier or "T3_OPA"

    # ── T4_RATE (rate-limit only; anomaly detection is advisory/async) ────────
    allowed_t4, _reason_t4, ms_t4 = _run_t4_rate(req, window_counts)
    tier_latencies["T4_RATE"] = ms_t4
    total_ms += ms_t4
    if not allowed_t4:
        if not forced:
            return {
                "resolved_tier": "T4_RATE", "verdict": "DENY",
                "tier_latencies": tier_latencies, "total_ms": total_ms,
            }
        final_deny_tier = final_deny_tier or "T4_RATE"

    # ── T5_LLM (only for escalated requests) ─────────────────────────────────
    if req.get("_route_to_llm"):
        allowed_t5, _reason_t5, ms_t5 = _run_t5_llm(req)
        tier_latencies["T5_LLM"] = ms_t5
        total_ms += ms_t5
        if not allowed_t5:
            if not forced:
                return {
                    "resolved_tier": "T5_LLM", "verdict": "DENY",
                    "tier_latencies": tier_latencies, "total_ms": total_ms,
                }
            final_deny_tier = final_deny_tier or "T5_LLM"

    # ── verdict ───────────────────────────────────────────────────────────────
    if final_deny_tier:
        resolved_tier = final_deny_tier
        verdict = "DENY"
    return {
        "resolved_tier": resolved_tier,
        "verdict":       verdict,
        "tier_latencies": tier_latencies,
        "total_ms":      total_ms,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main experiment
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    random.seed(42)
    N = int(os.getenv("RESOLUTION_N", str(_N_DEFAULT)))
    print(f"\n=== EXP-2  Resolution Distribution  (N={N}) ===")

    # ── build request set ─────────────────────────────────────────────────────
    requests: list[dict[str, Any]] = []
    for i in range(N):
        skill = f"skill-{(i % 8):03d}" if random.random() < _SKILL_PROB else None
        req = make_request(
            idx=i,
            invalid_token_prob=0.05,
            llm_rate=_LLM_ROUTE_PROB,
            skill_id=skill,
        )
        requests.append(req)

    # ── PASS 1: ladder mode (short-circuit) ───────────────────────────────────
    print("  Running ladder (short-circuit) pass…")
    wc_ladder: dict[int, int] = defaultdict(int)
    ladder_results: list[dict[str, Any]] = []
    for req in requests:
        ladder_results.append(_run_pipeline(req, wc_ladder, forced=False))

    # ── PASS 2: forced_pipeline mode (all tiers regardless) ──────────────────
    print("  Running forced_pipeline pass…")
    wc_forced: dict[int, int] = defaultdict(int)
    forced_results: list[dict[str, Any]] = []
    for req in requests:
        forced_results.append(_run_pipeline(req, wc_forced, forced=True))

    # ─────────────────────────────────────────────────────────────────────────
    # Analysis
    # ─────────────────────────────────────────────────────────────────────────

    # Section 1 — resolved_at_tier histogram
    tier_counts: dict[str, int]            = defaultdict(int)
    tier_latencies_all: dict[str, list[float]] = defaultdict(list)   # per-tier, requests that reached it
    tier_resolving_lat: dict[str, list[float]] = defaultdict(list)   # latency of the resolving tier only

    for res in ladder_results:
        rt = res["resolved_tier"]
        tier_counts[rt] += 1
        for tier, ms in res["tier_latencies"].items():
            tier_latencies_all[tier].append(ms)
        tier_resolving_lat[rt].append(res["tier_latencies"].get(rt, 0.0))

    # Survival probability p_i = fraction of requests that *reach* tier i
    # = number that had tier i in their tier_latencies dict / N
    tier_reach_count: dict[str, int] = {
        tier: len(tier_latencies_all[tier]) for tier in _TIERS
    }

    # Section 2 — p_i and c_i
    p_i: dict[str, float] = {
        tier: tier_reach_count.get(tier, 0) / N for tier in _TIERS
    }
    c_i: dict[str, float] = {
        tier: (sum(tier_latencies_all[tier]) / len(tier_latencies_all[tier]))
        if tier_latencies_all[tier] else 0.0
        for tier in _TIERS
    }

    # Section 3 — ordering comparison (Prop. 3: sort by c_i / (1 - p_i))
    # p_i for APPROVED is 1.0 by definition; avoid divide-by-zero
    def _cost_ratio(tier: str) -> float:
        denom = 1.0 - p_i[tier]
        return c_i[tier] / denom if denom > 1e-9 else float("inf")

    deployed_order = [t for t in _TIERS if t != "APPROVED"]  # T5_LLM only fires for escalated
    optimal_order  = sorted(deployed_order, key=_cost_ratio)

    # Section 4 — short-circuit ablation
    ladder_totals  = [r["total_ms"] for r in ladder_results]
    forced_totals  = [r["total_ms"] for r in forced_results]
    mean_ladder    = sum(ladder_totals)  / len(ladder_totals)
    mean_forced    = sum(forced_totals)  / len(forced_totals)
    reduction_pct  = (mean_forced - mean_ladder) / mean_forced * 100.0 if mean_forced > 0 else 0.0

    # ─────────────────────────────────────────────────────────────────────────
    # Build raw result dict
    # ─────────────────────────────────────────────────────────────────────────
    raw: dict[str, Any] = {
        "experiment": "exp2_resolution",
        "N": N,
        "apl_available": _APL_AVAILABLE,
        "cmf_available": _CMF_AVAILABLE,
        "resolved_at_tier": {
            t: {
                "count":    tier_counts.get(t, 0),
                "fraction": tier_counts.get(t, 0) / N,
                "mean_resolving_ms": (
                    sum(tier_resolving_lat[t]) / len(tier_resolving_lat[t])
                    if tier_resolving_lat[t] else 0.0
                ),
            }
            for t in _TIERS
        },
        "p_i": p_i,
        "c_i": c_i,
        "cost_ratio": {t: _cost_ratio(t) for t in deployed_order},
        "deployed_order":  deployed_order,
        "optimal_order":   optimal_order,
        "ablation": {
            "ladder_mean_ms":     mean_ladder,
            "forced_mean_ms":     mean_forced,
            "reduction_pct":      reduction_pct,
            "ladder_stats":  _stats(ladder_totals),
            "forced_stats":  _stats(forced_totals),
        },
    }
    save_result("exp2", raw)

    # ─────────────────────────────────────────────────────────────────────────
    # Build summary tables
    # ─────────────────────────────────────────────────────────────────────────

    # Section 1 table
    sec1_rows = [["Tier", "Count", "Fraction", "Mean_latency_ms"]]
    for t in _TIERS:
        cnt  = tier_counts.get(t, 0)
        frac = cnt / N
        mean_lat = (
            sum(tier_resolving_lat[t]) / len(tier_resolving_lat[t])
            if tier_resolving_lat[t] else 0.0
        )
        sec1_rows.append([t, str(cnt), f"{frac:.3f}", fmt_ms(mean_lat)])

    # Section 2 table
    sec2_rows = [["Tier", "p_i (reach prob)", "c_i (mean ms)"]]
    for t in _TIERS:
        sec2_rows.append([t, f"{p_i[t]:.4f}", fmt_ms(c_i.get(t, 0.0))])

    # Section 3 table — ordering comparison
    deployed_rank = {t: i + 1 for i, t in enumerate(deployed_order)}
    optimal_rank  = {t: i + 1 for i, t in enumerate(optimal_order)}
    sec3_rows = [["Deployed_rank", "Optimal_rank", "Tier", "c_i/(1-p_i)"]]
    for t in deployed_order:
        cr = _cost_ratio(t)
        sec3_rows.append([
            str(deployed_rank[t]),
            str(optimal_rank[t]),
            t,
            fmt_ms(cr) if cr != float("inf") else "∞",
        ])

    # Section 4 table — ablation
    sec4_rows = [["Mode", "Mean_total_ms", "Reduction_pct"]]
    sec4_rows.append(["ladder",          fmt_ms(mean_ladder), "—"])
    sec4_rows.append(["forced_pipeline", fmt_ms(mean_forced), f"{reduction_pct:.1f}%"])

    sections = [
        {
            "heading": "Section 1 — Resolution distribution",
            "text":    f"N={N} requests across the 5-tier pipeline (ladder mode).",
            "table":   sec1_rows,
        },
        {
            "heading": "Section 2 — Survival probabilities and per-tier latency",
            "text": (
                "p_i = fraction of requests that reached tier i; "
                "c_i = mean latency of tier i across those requests."
            ),
            "table": sec2_rows,
        },
        {
            "heading": "Section 3 — Tier ordering: deployed vs optimal (Prop. 3)",
            "text": (
                "Optimal order minimises Σ c_i / (1 − p_i).  "
                "Deployed rank = position in T1→T2→T3→T4→T5 pipeline."
            ),
            "table": sec3_rows,
        },
        {
            "heading": "Section 4 — Short-circuit ablation",
            "text": (
                "ladder: stop at first DENY.  "
                "forced_pipeline: run all tiers regardless of DENY."
            ),
            "table": sec4_rows,
        },
    ]

    gaps = [
        "Anomaly detection runs post-decision async — not counted as a resolving tier",
    ]

    write_summary("exp2", "EXP-2: Resolution Distribution (NomosFlow)", sections, gaps=gaps)
    print("=== EXP-2 complete ===\n")


if __name__ == "__main__":
    main()

# Made with Bob
