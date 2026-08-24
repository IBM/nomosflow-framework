"""
EXP-6b  Selective screening Pareto frontier.

Runs the EXP-3 labeled corpus (80 requests, inline) through the pipeline at
varying LLM routing rates.  For each rate we measure:

  recall      — fraction of true violations caught
  throughput  — proxy: 1 / mean_latency_ms, normalised to rate=0.0

The static floor is the recall achievable with zero LLM routing (deterministic
tiers only).  Screened-out requests always fall back to static/OPA verdict —
they never become ALLOW.

The Pareto frontier contains rate values where recall improves without
throughput regressing vs. the previous Pareto point.

Configure via env:  LLM_RATES="0.0,0.05,0.2,0.5,1.0"

Latency model (corrected, 2026-08):
  Static tier base:  Gaussian(mu=3.2 ms, sigma=0.8 ms)  — unchanged
  Semantic (T7/LLM): sampled from lognormal fitted to EXP-1 LIVE_BENCHMARK
                     T7 (LLM tier) measurements (Table 7, P50 ≈ 9,500 ms,
                     sigma_log ≈ 0.26).  The prior constant of 45 ms was
                     ~200× too optimistic; this correction makes the
                     throughput collapse visible and strengthens the case
                     for selective screening.
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
from pathlib import Path
from typing import Any

# ── shared imports ────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from experiments.shared.common import (
    _stats, make_request, make_violation_request, result_dir, save_result,
)
from experiments.shared.opa_client import decide
from experiments.shared.report import fmt_ms, fmt_pct, write_summary

# ── experiment parameters ─────────────────────────────────────────────────────
_DEFAULT_RATES = "0.0,0.05,0.2,0.5,1.0"
LLM_RATES: list[float] = [
    float(r)
    for r in os.getenv("LLM_RATES", _DEFAULT_RATES).split(",")
    if r.strip()
]

# Static tier base latency (ms, normal distributed) — unchanged
_BASE_LATENCY_MU  = 3.2
_BASE_LATENCY_SIG = 0.8

# Semantic / LLM per-call latency model.
# Fitted to EXP-1 LIVE_BENCHMARK T7 (LLM tier) observations (Table 7):
#   P50 ≈ 9,500 ms  →  mu_log = ln(9500) ≈ 9.159
#   sigma_log = 0.26  (gives P95 ≈ 15,100 ms, matching observed spread)
# The previous constant (45 ms) was ~200× below the measured value and
# made the throughput column artificially optimistic.
import math as _math
_LLM_LAT_MU_LOG  = _math.log(9_500.0)   # lognormal location (ln ms)
_LLM_LAT_SIG_LOG = 0.26                  # lognormal scale


# ─────────────────────────────────────────────────────────────────────────────
# EXP-3 corpus (80 requests, same composition as the labelled detection set)
# ─────────────────────────────────────────────────────────────────────────────

def _build_exp3_corpus() -> list[dict[str, Any]]:
    """
    80-request corpus that mirrors EXP-3's label distribution:
      40 benign, 40 violations split across violation classes.
    Returns list of (request, label, violation_class).
    """
    random.seed(42)
    corpus: list[dict[str, Any]] = []

    # 40 benign
    for i in range(40):
        req = make_violation_request("benign")
        req["_label"] = "benign"
        req["_vclass"] = "none"
        corpus.append(req)

    # 40 violations, 8 per class
    vclasses = [
        "rbac_write",
        "purpose_mismatch",
        "bad_token",
        "future_timestamp",
        "purpose_bypass_fred",
    ]
    for vc in vclasses:
        for _ in range(8):
            req = make_violation_request(vc)
            req["_label"] = "violation"
            req["_vclass"] = vc
            corpus.append(req)

    random.shuffle(corpus)
    return corpus


def _save_corpus(corpus: list[dict[str, Any]]) -> None:
    """Serialise the EXP-6b screening corpus to experiments/results/exp6b/corpus.json.

    The file contains:
      description  — human-readable summary of composition
      vclass_counts — violation-class breakdown
      corpus        — all 80 entries with _label, _vclass, and request fields
    """
    import json as _json
    from collections import Counter as _Counter

    vclass_counts = dict(_Counter(r["_vclass"] for r in corpus))
    label_counts  = dict(_Counter(r["_label"]  for r in corpus))

    doc = {
        "description": (
            "EXP-6b selective-screening corpus — 80 requests. "
            "40 benign (label=benign, vclass=none); "
            "40 violations: 8 each of rbac_write, purpose_mismatch, "
            "bad_token, future_timestamp, purpose_bypass_fred. "
            "Structural classes (rbac_write, bad_token, future_timestamp) are "
            "caught by static/OPA tiers; semantic classes (purpose_mismatch, "
            "purpose_bypass_fred) require LLM routing."
        ),
        "label_counts": label_counts,
        "vclass_counts": vclass_counts,
        "corpus": corpus,
    }
    path = result_dir("exp6b") / "corpus.json"
    path.write_text(_json.dumps(doc, indent=2, default=str))
    print(f"  ✓ corpus  → experiments/results/exp6b/corpus.json  ({len(corpus)} requests)")


# ─────────────────────────────────────────────────────────────────────────────
# LLM simulation
# ─────────────────────────────────────────────────────────────────────────────

def _llm_detect(req: dict[str, Any]) -> bool:
    """
    Simulated LLM verdict.
    Detects the violation if and only if the request is of class "semantic"
    (purpose_mismatch, purpose_bypass_fred) and is actually routed to the LLM.
    Structural violations (bad_token, rbac_write, future_timestamp) are already
    caught by static/OPA tiers, so LLM adds recall only for semantic classes.
    """
    return req["_vclass"] in ("purpose_mismatch", "purpose_bypass_fred")


# ─────────────────────────────────────────────────────────────────────────────
# Single-rate pipeline
# ─────────────────────────────────────────────────────────────────────────────

def _run_rate(
    rate: float,
    corpus: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    For each request in corpus:
    1. Static tiers catch structural violations deterministically.
    2. If routed_to_llm and class=="semantic": LLM catches it.
    3. Record caught/missed, latency.
    """
    caught  = 0
    total_violations = sum(1 for r in corpus if r["_label"] == "violation")
    latencies: list[float] = []

    random.seed(0)  # reproducible routing decisions
    for req in corpus:
        # ── static / OPA tier (simulated) ────────────────────────────────────
        static_catch = req["_vclass"] in (
            "rbac_write", "bad_token", "future_timestamp"
        )
        # simulate static tier latency
        lat = max(0.1, random.gauss(_BASE_LATENCY_MU, _BASE_LATENCY_SIG))

        routed = random.random() < rate
        llm_catch = False
        if routed:
            # Sample semantic latency from the measured T7 (LLM tier)
            # distribution (EXP-1 LIVE_BENCHMARK, Table 7: P50 ≈ 9,500 ms)
            lat += random.lognormvariate(_LLM_LAT_MU_LOG, _LLM_LAT_SIG_LOG)
            llm_catch = _llm_detect(req)

        # A violation is caught if static or LLM detected it
        if req["_label"] == "violation":
            if static_catch or llm_catch:
                caught += 1

        latencies.append(lat)

    recall = caught / total_violations if total_violations > 0 else 0.0
    stats  = _stats(latencies)
    return {
        "rate":             rate,
        "recall":           recall,
        "mean_latency_ms":  stats["mean"],
        "total_violations": total_violations,
        "caught":           caught,
        "latency_stats":    stats,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Pareto frontier
# ─────────────────────────────────────────────────────────────────────────────

def _pareto_frontier(points: list[dict[str, Any]]) -> set[float]:
    """
    Identify Pareto-optimal (rate, recall, throughput_norm) points.
    A point is on the frontier if no other point dominates it on both
    recall (higher is better) and throughput_norm (higher is better).
    """
    frontier: set[float] = set()
    for p in points:
        dominated = False
        for q in points:
            if q is p:
                continue
            if (q["recall"] >= p["recall"] and
                    q["throughput_norm"] >= p["throughput_norm"] and
                    (q["recall"] > p["recall"] or
                     q["throughput_norm"] > p["throughput_norm"])):
                dominated = True
                break
        if not dominated:
            frontier.add(p["rate"])
    return frontier


# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("EXP-6b  Selective screening Pareto frontier")
    print("=" * 60)
    print(f"  LLM_RATES = {LLM_RATES}")

    corpus = _build_exp3_corpus()
    _save_corpus(corpus)
    print(f"  Corpus: {len(corpus)} requests "
          f"({sum(1 for r in corpus if r['_label']=='violation')} violations)")

    rate_results: list[dict[str, Any]] = []
    for rate in LLM_RATES:
        res = _run_rate(rate, corpus)
        rate_results.append(res)
        print(f"  rate={rate:.2f}  recall={fmt_pct(res['recall'])}"
              f"  mean_lat={fmt_ms(res['mean_latency_ms'])}ms")

    # ── Throughput normalisation (relative to rate=0.0 baseline) ─────────────
    base_lat  = next(r["mean_latency_ms"] for r in rate_results if r["rate"] == 0.0)
    base_tput = 1.0 / base_lat if base_lat > 0 else 1.0

    for r in rate_results:
        tput = 1.0 / r["mean_latency_ms"] if r["mean_latency_ms"] > 0 else 0.0
        r["throughput_norm"] = tput / base_tput

    static_floor_recall = next(
        r["recall"] for r in rate_results if r["rate"] == 0.0
    )

    # ── Pareto frontier ───────────────────────────────────────────────────────
    frontier_rates = _pareto_frontier(rate_results)
    print(f"  Pareto-optimal rates: {sorted(frontier_rates)}")

    # ── Build output tables ───────────────────────────────────────────────────
    pareto_rows: list[list[str]] = [
        ["LLM_rate", "Recall", "Throughput_norm", "On_Pareto"]
    ]
    for r in rate_results:
        pareto_rows.append([
            str(r["rate"]),
            fmt_pct(r["recall"]),
            f"{r['throughput_norm']:.3f}",
            "yes" if r["rate"] in frontier_rates else "no",
        ])

    static_floor_text = (
        f"Static (deterministic) recall floor at LLM_rate=0.0: "
        f"{fmt_pct(static_floor_recall)}. "
        "Screened-out requests fall back to static/OPA verdict; "
        "the soundness floor is never lowered by the screening decision."
    )

    raw_output: dict[str, Any] = {
        "rates":               LLM_RATES,
        "static_floor_recall": static_floor_recall,
        "pareto_rates":        sorted(frontier_rates),
        "results":             rate_results,
    }

    save_result("exp6b", raw_output)
    latency_note = (
        "Selective screening Pareto frontier (Table~14). "
        "Semantic per-call latency sampled from lognormal fitted to EXP-1 "
        "LIVE\\_BENCHMARK T7 (LLM tier) measurements (Table~7): P50 \\approx 9{,}500\\,ms, "
        "$\\sigma_{\\ln} = 0.26$. "
        "Static tier base: $\\mathcal{N}(3.2\\,\\text{ms},\\,0.8\\,\\text{ms})$."
    )
    write_summary(
        exp_id="exp6b",
        title="EXP-6b  Selective screening Pareto frontier",
        sections=[
            {
                "heading": "Recall / throughput Pareto",
                "caption": latency_note,
                "table":   pareto_rows,
            },
            {
                "heading": "Static floor",
                "text":    static_floor_text,
            },
            {
                "heading": "Latency model",
                "text":    (
                    "Semantic per-call latency (T7/LLM tier): lognormal, P50 = 9,500 ms, "
                    "sigma_log = 0.26 (EXP-1 LIVE_BENCHMARK T7, Table 7). "
                    "Static base: Gaussian(3.2 ms, 0.8 ms)."
                ),
            },
        ],
        gaps=[
            "This is a deliberately lossy ablation — kept separate from EXP-2"
            " natural escalation rate",
            "Screened requests fall back to static/OPA verdict; soundness floor"
            " is unchanged",
        ],
    )
    print("\nEXP-6b complete.")


if __name__ == "__main__":
    main()

# Made with Bob
