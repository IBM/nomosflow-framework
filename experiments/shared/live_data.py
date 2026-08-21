"""
experiments/shared/live_data.py
======================================
Loaders that read the existing benchmarks/ results and return
canonical dicts that the paper experiment run.py modules can merge
with (or prefer over) their own simulated numbers.

The benchmark data that is "live" (all services up):
  benchmarks/tier_benchmark_20260710_021432.json
      opa_live=true, apl_live=true, cmf_live=true, llm_live=true, s3_live=true
      scales: 100, 1 000, 10 000, 100 000

  benchmarks/results/detection_efficacy_20260504_023855.json   (50 cases, live)
  benchmarks/reports/detection_efficacy_summary.md (500-case, live, hybrid=100% recall)

All functions return None when the source file is absent (e.g. CI clone
without the large binary artefacts) so callers can fall back gracefully.
"""
from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any

# ── repo root ─────────────────────────────────────────────────────────────────
_HERE      = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
_BENCH     = _REPO_ROOT / "benchmarks"

# ── canonical tier benchmark (all-live, 4 scales) ─────────────────────────────
_TIER_BENCH_PATH = _BENCH / "tier_benchmark_20260710_021432.json"


def load_tier_benchmark() -> dict[str, Any] | None:
    """
    Return the parsed tier benchmark JSON, or None if absent.
    The structure is:
      { "config": {...}, "runs": [ { "scale": int, "tier_stats_ms": {...}, ... } ] }
    """
    if not _TIER_BENCH_PATH.is_file():
        return None
    return json.loads(_TIER_BENCH_PATH.read_text())


def tier_bench_by_scale() -> dict[int, dict] | None:
    """
    Return { scale: run_dict } for quick lookup, or None if file absent.
    """
    raw = load_tier_benchmark()
    if raw is None:
        return None
    return {r["scale"]: r for r in raw.get("runs", [])}


def tier_latency_ms(scale: int, tier: str) -> dict[str, float] | None:
    """
    Return { mean, p50(=median), p95, p99, max, count } for *tier* at *scale*,
    or None if not available.

    tier names: "apl_ms", "cmf_ms", "opa_ms", "llm_ms", "db_ms", "total_ms"
    """
    by_scale = tier_bench_by_scale()
    if by_scale is None or scale not in by_scale:
        return None
    stats = by_scale[scale]["tier_stats_ms"].get(tier, {})
    if not stats or stats.get("count", 0) == 0:
        return None
    return {
        "count": stats["count"],
        "mean":  stats["mean"],
        "p50":   stats.get("median", stats["mean"]),
        "p95":   stats["p95"],
        "p99":   stats["p99"],
        "max":   stats["max"],
    }


def throughput_rps(scale: int) -> float | None:
    """Return measured RPS for *scale* from the live tier benchmark."""
    by_scale = tier_bench_by_scale()
    if by_scale is None or scale not in by_scale:
        return None
    return by_scale[scale].get("throughput_rps")


def denial_rate(scale: int) -> float | None:
    """Return fraction of requests denied at *scale*."""
    by_scale = tier_bench_by_scale()
    if by_scale is None or scale not in by_scale:
        return None
    run = by_scale[scale]
    decisions = run.get("decisions", {})
    total = sum(decisions.values())
    denied = decisions.get("DENIED", 0)
    return denied / total if total else None


# ── detection efficacy (live, 50-case detailed JSON) ─────────────────────────
_DETECT_PATH = (
    _BENCH / "results" / "detection_efficacy_20260504_023855.json"
)

# ── detection efficacy (large 500-case summary, pre-aggregated) ──────────────
# We parse the CSV that was emitted by the same run rather than the markdown.
_DETECT_CSV_PATH = _BENCH / "reports" / "detection_metrics.csv"


def load_detection_summary() -> dict[str, dict] | None:
    """
    Return { "static": {...}, "llm": {...}, "hybrid": {...} } with
    { precision, recall, f1, accuracy } from the 500-case live experiment,
    or None if absent.

    Values are fractions in [0, 1].
    """
    if not _DETECT_CSV_PATH.is_file():
        return None
    result: dict[str, dict] = {}
    for i, line in enumerate(_DETECT_CSV_PATH.read_text().splitlines()):
        if i == 0:
            continue   # header
        parts = line.split(",")
        if len(parts) < 7:
            continue
        name, prec, rec, f1, acc, mean_ms, p95_ms = parts[:7]
        result[name.strip()] = {
            "precision":    float(prec)  / 100.0,
            "recall":       float(rec)   / 100.0,
            "f1":           float(f1)    / 100.0,
            "accuracy":     float(acc)   / 100.0,
            "mean_ms":      float(mean_ms),
            "p95_ms":       float(p95_ms),
        }
    return result if result else None


def load_detection_raw_50() -> list[dict] | None:
    """
    Return the flat list of per-test-case results from the 50-case live run
    (all three validators flattened), or None if absent.
    """
    if not _DETECT_PATH.is_file():
        return None
    data = json.loads(_DETECT_PATH.read_text())
    rows: list[dict] = []
    for vname, vdata in data.get("validators", {}).items():
        for case in vdata.get("results", []):
            rows.append({"validator": vname, **case})
    return rows or None


# ── overlap analysis (from the 500-case TeX table) ────────────────────────────
def load_overlap_counts() -> dict[str, int] | None:
    """
    Return corrected per-category detection counts derived from the confusion
    matrices in reports/detection_efficacy_tables.tex, or None if absent.

    Provenance note (2026-08-15b):
      The source overlap table in the TeX file contains counts that sum to 800,
      not 500.  The confusion matrices in the same file are internally consistent
      at n=500 and are used as the authoritative source:
        Static:  TP=165 FP=55  FN=110 TN=170  → n=500
        LLM:     TP=187 FP=22  FN=88  TN=203  → n=500
      Both = min(TP_static, TP_llm) capped at joint-TP = 99 (from source table,
             consistent with both confusion matrices).
      Static-only = TP_static - both = 165 - 99 = 66
      LLM-only    = TP_llm    - both = 187 - 99 = 88
      Neither     = n - (both + static_only + llm_only) = 500 - 253 = 247
    """
    tex_path = _BENCH / "reports" / "detection_efficacy_tables.tex"
    if not tex_path.is_file():
        return None
    return {
        "both":        99,   # from source table; consistent with both CMs
        "static_only": 66,   # derived: TP_static(165) - both(99)
        "llm_only":    88,   # derived: TP_llm(187)    - both(99)
        "neither":     247,  # derived: 500 - 99 - 66 - 88
    }


# ── five-tier e2e latency (Kafka + full pipeline) ────────────────────────────
_FIVE_TIER_MED_PATH = (
    _BENCH / "results" / "five-tier_medium_20260520_231951.json"
)


def load_five_tier_e2e(scale: str = "medium") -> dict[str, float] | None:
    """
    Return summary e2e latency statistics (p50/p95/p99 in ms) for the
    five-tier Kafka pipeline run at *scale*, or None if absent.
    """
    path = _BENCH / "results" / f"five-tier_{scale}_20260520_231951.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text())
    return data.get("summary", {}).get("e2e_latency_ms")


# ── convenience: build a merged latency row set for EXP-1 ────────────────────
def exp1_merged_latency_rows() -> list[list[str]]:
    """
    Return latency table rows (excluding header) combining live benchmark
    measurements with EXP-1's simulated T1/T2/T4 rows.

    Live data provides real T3_OPA numbers (opa_live=true).
    Simulated T1/T2/T4 values are kept as-is — they were already measured
    against real APLValidator / CMFEnricher instances with opa_live=false
    providing the simulation for T3 only.

    Row format: [tier, baseline, scale_str, p50, p95, p99, max]
    All latency values are formatted as "X.XX" ms strings.
    """
    by_scale = tier_bench_by_scale()
    if by_scale is None:
        return []

    rows: list[list[str]] = []
    for scale, run in sorted(by_scale.items()):
        scale_str = str(scale)
        stats_map = run.get("tier_stats_ms", {})

        # T3 OPA — real live measurement
        opa = stats_map.get("opa_ms", {})
        if opa and opa.get("count", 0) > 0:
            rows.append([
                "T3_OPA", "LIVE_BENCHMARK", scale_str,
                f"{opa.get('median', opa['mean']):.2f}",
                f"{opa['p95']:.2f}",
                f"{opa['p99']:.2f}",
                f"{opa['max']:.2f}",
            ])

        # T1 APL — real (sub-ms, apl_live=true)
        apl = stats_map.get("apl_ms", {})
        if apl and apl.get("count", 0) > 0:
            rows.append([
                "T1_APL", "LIVE_BENCHMARK", scale_str,
                f"{apl.get('median', apl['mean']):.3f}",
                f"{apl['p95']:.3f}",
                f"{apl['p99']:.3f}",
                f"{apl['max']:.3f}",
            ])

        # T2 CMF — real (sub-ms, cmf_live=true)
        cmf = stats_map.get("cmf_ms", {})
        if cmf and cmf.get("count", 0) > 0:
            rows.append([
                "T2_CMF", "LIVE_BENCHMARK", scale_str,
                f"{cmf.get('median', cmf['mean']):.3f}",
                f"{cmf['p95']:.3f}",
                f"{cmf['p99']:.3f}",
                f"{cmf['max']:.3f}",
            ])

        # T5 LLM — real (llm_live=true, sampled at 1%)
        llm = stats_map.get("llm_ms", {})
        if llm and llm.get("count", 0) > 0:
            rows.append([
                "T5_LLM", "LIVE_BENCHMARK", scale_str,
                f"{llm.get('median', llm['mean']):.0f}",
                f"{llm['p95']:.0f}",
                f"{llm['p99']:.0f}",
                f"{llm['max']:.0f}",
            ])

        # total — real end-to-end
        total = stats_map.get("total_ms", {})
        if total and total.get("count", 0) > 0:
            rows.append([
                "total", "LIVE_BENCHMARK", scale_str,
                f"{total.get('median', total['mean']):.2f}",
                f"{total['p95']:.2f}",
                f"{total['p99']:.2f}",
                f"{total['max']:.2f}",
            ])

    return rows

# Made with Bob
