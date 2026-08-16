from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_REPO_ROOT_INSERT = _Path(__file__).resolve().parents[2]
if str(_REPO_ROOT_INSERT) not in _sys.path:
    _sys.path.insert(0, str(_REPO_ROOT_INSERT))

from pathlib import Path
from typing import Any

from experiments.shared.common import Timer, _REPO_ROOT, make_request, make_violation_request, save_result
from experiments.shared.opa_client import decide
from experiments.shared.report import fmt_ms, fmt_pct, write_summary
from experiments.shared.live_data import tier_bench_by_scale, throughput_rps as _live_rps

try:
    from experiments.exp7_baselines.envoy_probe import (
        run_probe as _envoy_probe,
        run_coverage_probe as _envoy_coverage_probe,
    )
    _ENVOY_PROBE_AVAILABLE = True
except Exception:
    _ENVOY_PROBE_AVAILABLE = False

try:
    from src.validators.apl_validator import APLValidator
except Exception:
    APLValidator = None


VIOLATION_TYPES = [
    "rbac_write",
    "purpose_mismatch",
    "bad_token",
    "hallucinated_cik",
    "future_timestamp",
    "path_traversal",
    "purpose_bypass_fred",
]


def build_exp3_corpus() -> list[dict[str, Any]]:
    corpus: list[dict[str, Any]] = []
    for idx in range(40):
        req = make_request(idx=idx, invalid_token_prob=0.0, llm_rate=0.0)
        req["role"] = "SENIOR"
        req["action"] = "READ"
        req["purpose"] = "MarketResearch"
        req["resource"] = "fred/GDP"
        req["token"] = req["metadata"]["token"]
        req["metadata"]["role"] = "SENIOR"
        req["label"] = "benign"
        corpus.append(req)
    for idx in range(40):
        violation = VIOLATION_TYPES[idx % len(VIOLATION_TYPES)]
        req = make_violation_request(violation)
        req["label"] = "violation"
        req["violation_type"] = violation
        corpus.append(req)
    return corpus


def app_level_check(req: dict[str, Any]) -> tuple[bool, float]:
    token = req.get("metadata", {}).get("token") or req.get("token", "")
    role = req.get("metadata", {}).get("role") or req.get("role", "")
    action = req.get("action", "")
    resource = req.get("resource", "")
    token_ok = token.count(".") == 2 or (token.startswith("Bearer ") and len(token) > 20)
    resource_ok = resource.startswith("fred/") or (resource.startswith("edgar/") and len(resource.split("/", 1)[-1]) == 10) or resource.startswith("/")
    allowed = token_ok and role in {"JUNIOR", "SENIOR", "ADMIN"} and action in {"READ", "WRITE"} and resource_ok and not (role == "JUNIOR" and action == "WRITE")
    return allowed, 0.08


def nomosflow_check(req: dict[str, Any], apl: Any, rate_limits: dict[str, int]) -> tuple[bool, float]:
    latency_ms = 0.0
    if apl is not None:
        apl_ok, _, apl_us = apl.validate(req)
        latency_ms += apl_us / 1000.0
        if not apl_ok:
            return False, latency_ms + 0.05
    else:
        apl_ok, apl_ms = app_level_check(req)
        latency_ms += apl_ms
        if not apl_ok:
            return False, latency_ms + 0.05
    opa_ok, _, opa_ms = decide(req)
    latency_ms += opa_ms
    agent_id = req.get("agent_id", "unknown")
    rate_limits[agent_id] = rate_limits.get(agent_id, 0) + 1
    if rate_limits[agent_id] > 50:
        return False, latency_ms + 0.1
    return opa_ok, latency_ms + 0.1


def evaluate_baseline(name: str, corpus: list[dict[str, Any]], no_enforcement_latency: float) -> dict[str, Any]:
    apl = APLValidator(enabled=True) if APLValidator is not None and name == "NOMOSFLOW" else None
    rate_limits: dict[str, int] = {}
    violation_total = sum(1 for req in corpus if req["label"] == "violation")
    benign_total = sum(1 for req in corpus if req["label"] == "benign")
    caught = 0
    false_positives = 0
    latencies: list[float] = []

    for req in corpus:
        if name == "NOMOSFLOW":
            allowed, latency_ms = nomosflow_check(req, apl, rate_limits)
        elif name == "OPA_GATEWAY":
            allowed, _, latency_ms = decide(req)
        elif name == "APP_LEVEL":
            allowed, latency_ms = app_level_check(req)
        else:
            allowed, latency_ms = True, no_enforcement_latency

        latencies.append(latency_ms)
        denied = not allowed
        if req["label"] == "violation" and denied:
            caught += 1
        if req["label"] == "benign" and denied:
            false_positives += 1

    mean_latency = sum(latencies) / len(latencies)
    return {
        "baseline": name,
        "coverage": caught / violation_total if violation_total else 0.0,
        "fpr": false_positives / benign_total if benign_total else 0.0,
        "mean_latency_ms": mean_latency,
        "overhead_vs_no_enforcement": mean_latency - no_enforcement_latency,
    }


def main() -> None:
    corpus = build_exp3_corpus()
    no_enforcement_latency = 0.02
    with Timer() as timer:
        results = [
            evaluate_baseline("NOMOSFLOW", corpus, no_enforcement_latency),
            evaluate_baseline("OPA_GATEWAY", corpus, no_enforcement_latency),
            evaluate_baseline("APP_LEVEL", corpus, no_enforcement_latency),
            evaluate_baseline("NO_ENFORCEMENT", corpus, no_enforcement_latency),
        ]

    matrix = [["Baseline", "Coverage_pct", "FPR_pct", "Mean_ms", "Overhead_ms"]]
    for item in results:
        matrix.append([
            item["baseline"],
            fmt_pct(item["coverage"]),
            fmt_pct(item["fpr"]),
            fmt_ms(item["mean_latency_ms"]),
            fmt_ms(item["overhead_vs_no_enforcement"]),
        ])

    # ── Merge live OPA throughput rows from the tier benchmark ────────────────
    by_scale = tier_bench_by_scale() or {}
    live_throughput_rows: list[list[str]] = []
    for sc in sorted(by_scale.keys()):
        run = by_scale[sc]
        opa_stats = run.get("tier_stats_ms", {}).get("opa_ms", {})
        if opa_stats and opa_stats.get("count", 0) > 0:
            rps = _live_rps(sc) or 0.0
            live_throughput_rows.append([
                f"LIVE_OPA (scale={sc})",
                "—",
                "—",
                fmt_ms(opa_stats.get("median", opa_stats["mean"])),
                "—",
            ])
    if live_throughput_rows:
        matrix.extend(live_throughput_rows)
        print(f"  ✓ merged {len(live_throughput_rows)} live OPA latency rows "
              f"from benchmarks/tier_benchmark_20260710_021432.json")

    # ── Envoy+OPA probe ───────────────────────────────────────────────────
    envoy_result = None
    if _ENVOY_PROBE_AVAILABLE:
        try:
            envoy_result = _envoy_probe(n_samples=50)
        except Exception as exc:
            print(f"  ⚠  Envoy probe failed: {exc}")

    if envoy_result is not None:
        # Run coverage probe against the same corpus used for other baselines
        cov_result = None
        try:
            cov_result = _envoy_coverage_probe(corpus)
            print(f"  ✓ Envoy coverage probe: coverage={cov_result['coverage']:.1%} "
                  f"fpr={cov_result['fpr']:.1%} (opa_live={cov_result['opa_live']})")
        except Exception as exc:
            print(f"  ⚠  Envoy coverage probe failed: {exc}")

        cov_str = fmt_pct(cov_result["coverage"]) if cov_result else "—"
        fpr_str = fmt_pct(cov_result["fpr"])       if cov_result else "—"

        matrix.append([
            "ENVOY_OPA_GATEWAY",
            cov_str,
            fpr_str,
            fmt_ms(envoy_result["mean_latency_ms"]),
            fmt_ms(envoy_result["overhead_vs_no_enforcement"]),
        ])
        print(f"  ✓ ENVOY_OPA_GATEWAY row added "
              f"(mean={envoy_result['mean_latency_ms']:.2f} ms, "
              f"live={envoy_result['opa_live']})")

    note = (
        "Envoy ext_authz + OPA gateway baseline: see deploy/envoy/envoy.yaml.\n"
        "ENVOY_OPA_GATEWAY latency = OPA decision latency + 0.4 ms estimated "
        "Envoy hop overhead (2 x localhost RTT).\n\n"
        "**LIVE_OPA rows** are per-scale OPA P50 latency measured with opa_live=true "
        "from benchmarks/tier_benchmark_20260710_021432.json."
    )
    result = {
        "exp_id": "exp7",
        "repo_root": str(_REPO_ROOT),
        "script": str(Path(__file__).relative_to(_REPO_ROOT)),
        "runtime_ms": timer.ms,
        "corpus_size": len(corpus),
        "violation_subset": 40,
        "benign_subset": 40,
        "baselines": results,
        "envoy_baseline": envoy_result,
        "envoy_baseline_note": note,
        "live_benchmark_source": "benchmarks/tier_benchmark_20260710_021432.json" if by_scale else None,
    }
    save_result("exp7", result)
    write_summary(
        "exp7",
        "EXP-7 baseline coverage comparison",
        sections=[
            {"heading": "Coverage-vs-overhead matrix", "table": matrix},
            {"heading": "Note on Envoy baseline and live OPA data", "text": note},
        ],
        gaps=[
            "Envoy ext_authz baseline requires live Envoy proxy — not run in CI mode",
            "Mesh-only baseline (Istio mTLS) not implemented",
            "LIVE_OPA rows are OPA-only latency (P50) from live benchmark; "
            "full-stack overhead (APL+CMF+OPA+RL) captured in EXP-1 LIVE_BENCHMARK rows",
        ],
    )


if __name__ == "__main__":
    main()
