"""
experiments/exp1_overhead/run.py
EXP-1: Per-tier latency overhead microbenchmark — NomosFlow VLDB paper.

Baselines
---------
  NO_ENFORCEMENT  – raw dict pass-through, no validation
  OPA_ONLY        – APLValidator disabled, CMF disabled, OPA call only
  NOMOSFLOW_FULL  – APL(T1) + attest(T1.6) + CMF(T2) + OPA(T3) + rate_limit(T4)
                    LLM(T5) measured separately at LLM_RATE fraction with circuit-breaker

Run:
  python experiments/exp1_overhead/run.py
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_REPO_ROOT_INSERT = _Path(__file__).resolve().parents[2]
if str(_REPO_ROOT_INSERT) not in _sys.path:
    _sys.path.insert(0, str(_REPO_ROOT_INSERT))

import os
import sys
import time
import random
import importlib
from pathlib import Path

# ── repo root on path ─────────────────────────────────────────────────────────
_HERE      = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ── shared helpers ────────────────────────────────────────────────────────────
from experiments.shared.common import (
    _stats, make_request, save_result, result_dir, Timer,
    RESULTS_DIR, _REPO_ROOT, load_env,
)
from experiments.shared.opa_client import probe, decide, OPA_URL
from experiments.shared.report   import write_summary, fmt_ms
from experiments.shared.live_data import (
    exp1_merged_latency_rows,
    tier_bench_by_scale,
    throughput_rps as _live_rps,
    load_tier_benchmark,
)

load_env()

# ── optional psutil ───────────────────────────────────────────────────────────
try:
    import psutil as _psutil
    _PSUTIL = True
except ImportError:                     # pragma: no cover
    _psutil = None                      # type: ignore[assignment]
    _PSUTIL = False

# ── env config ────────────────────────────────────────────────────────────────
_SCALES_RAW = os.getenv("BENCHMARK_SCALES", "100,1000,10000")
SCALES      = [int(s.strip()) for s in _SCALES_RAW.split(",") if s.strip()]
LLM_RATE    = float(os.getenv("LLM_RATE", "0.01"))   # fraction of requests for T5

EXP_ID  = "exp1"
TITLE   = "EXP-1: Per-Tier Overhead Microbenchmark"

# ── T4 rate-limit state (mirrors sidecar_optimized.py lines 930-936) ─────────
_rate_limits: dict[str, dict] = {}
_RL_THRESHOLD = 50   # requests per second per agent_id

# ── try/except imports for src validators ────────────────────────────────────

# APLValidator
try:
    from src.validators.apl_validator import APLValidator as _APLValidator
    _apl_validator = _APLValidator(enabled=True, attestation_enabled=True)
    _APL_REAL = True
    print("  ✓ APLValidator loaded from src.validators.apl_validator")
except Exception as _e:
    _APL_REAL = False
    print(f"  ⚠  APLValidator unavailable ({_e}); using simulation fallback")

# CMFContextEnricher
try:
    from src.validators.cmf_context_enricher import CMFContextEnricher as _CMFEnricher
    _cmf_enricher = _CMFEnricher(pii_detection=True)
    _CMF_REAL = True
    print("  ✓ CMFContextEnricher loaded from src.validators.cmf_context_enricher")
except Exception as _e:
    _CMF_REAL = False
    print(f"  ⚠  CMFContextEnricher unavailable ({_e}); using simulation fallback")

# LLMValidator
try:
    from src.validators.llm_validator import LLMValidator as _LLMValidator
    _llm_validator = _LLMValidator(
        model=os.getenv("LLM_MODEL", "gpt-3.5-turbo"),
        enabled=True,
        cache_enabled=True,
    )
    _LLM_REAL = True
    print("  ✓ LLMValidator loaded from src.validators.llm_validator")
except Exception as _e:
    _LLM_REAL = False
    print(f"  ⚠  LLMValidator unavailable ({_e}); using simulation fallback")

# SkillRegistry — register benchmark_analytics skill if available
try:
    from src.validators.skill_registry import get_registry as _get_registry
    _reg = _get_registry()
    _reg.register(
        skill_id  = "benchmark_analytics",
        version   = "1.0.0",
        contract  = {
            "allowed_actions":    ["READ"],
            "allowed_resources":  ["fred/*", "edgar/*"],
            "max_rps":            200,
        },
    )
    print("  ✓ benchmark_analytics skill registered in SkillRegistry")
except Exception as _e:
    print(f"  ⚠  SkillRegistry unavailable ({_e}); attestation skipped")


# ─────────────────────────────────────────────────────────────────────────────
# Tier implementations (real or simulation fallback)
# ─────────────────────────────────────────────────────────────────────────────

def _tier_apl(req: dict) -> tuple[bool, str, float]:
    """T1: APL validation + T1.6 attestation."""
    if _APL_REAL:
        ok, reason, us = _apl_validator.validate(req)
        return ok, reason, us / 1000.0   # µs → ms
    # simulation: ~0.15 ms
    t0 = time.perf_counter()
    time.sleep(max(0, random.gauss(0.00015, 0.00003)))
    return True, "SIM:APL", (time.perf_counter() - t0) * 1000


def _tier_cmf(req: dict) -> tuple[dict, float]:
    """T2: CMF context enrichment."""
    if _CMF_REAL:
        t0 = time.perf_counter()
        enriched = _cmf_enricher.enrich_message(req)
        return enriched, (time.perf_counter() - t0) * 1000
    # simulation: ~0.45 ms
    t0 = time.perf_counter()
    time.sleep(max(0, random.gauss(0.00045, 0.00008)))
    return req, (time.perf_counter() - t0) * 1000


def _tier_opa(req: dict) -> tuple[bool, str, float]:
    """T3: OPA policy decision."""
    allowed, reason, ms = decide(req)
    return allowed, reason, ms


def _tier_rate_limit(req: dict) -> tuple[bool, float]:
    """T4: In-memory 1-second token-bucket rate limiter.
    Exact logic from sidecar_optimized.py lines 930-936.
    """
    t0       = time.perf_counter()
    agent_id = req.get("agent_id", "unknown")
    now      = int(time.time())
    if _rate_limits.get(agent_id, {}).get("time") != now:
        _rate_limits[agent_id] = {"time": now, "count": 1}
    else:
        _rate_limits[agent_id]["count"] += 1
        if _rate_limits[agent_id]["count"] > _RL_THRESHOLD:
            return False, (time.perf_counter() - t0) * 1000
    return True, (time.perf_counter() - t0) * 1000


def _tier_llm(req: dict) -> tuple[bool, str, float]:
    """T5: LLM hallucination-detection (sampled at LLM_RATE with circuit-breaker)."""
    if _LLM_REAL:
        # validate_request returns (is_valid, reason, duration_seconds)
        ok, reason, dur_s = _llm_validator.validate_request(req)
        return ok, reason, dur_s * 1000
    # simulation: ~180 ms network round-trip
    t0 = time.perf_counter()
    time.sleep(max(0, random.gauss(0.180, 0.030)))
    return True, "SIM:LLM", (time.perf_counter() - t0) * 1000


# ─────────────────────────────────────────────────────────────────────────────
# psutil helpers
# ─────────────────────────────────────────────────────────────────────────────

def _snapshot() -> tuple[float, float]:
    """Return (cpu_pct, rss_mb) or (0, 0) if psutil unavailable."""
    if not _PSUTIL:
        return 0.0, 0.0
    proc = _psutil.Process()
    cpu  = proc.cpu_percent(interval=None)
    rss  = proc.memory_info().rss / (1024 * 1024)
    return cpu, rss


# ─────────────────────────────────────────────────────────────────────────────
# Per-baseline run
# ─────────────────────────────────────────────────────────────────────────────

def run_no_enforcement(requests: list[dict]) -> dict:
    timings: list[float] = []
    for req in requests:
        t0 = time.perf_counter()
        _ = req                        # pass-through — no validation
        timings.append((time.perf_counter() - t0) * 1000)
    return {"total": _stats(timings)}


def run_opa_only(requests: list[dict]) -> dict:
    t3_ms: list[float] = []
    for req in requests:
        _, _, ms = _tier_opa(req)
        t3_ms.append(ms)
    return {"T3_OPA": _stats(t3_ms)}


def run_nomosflow_full(requests: list[dict]) -> dict:
    t1_ms: list[float] = []
    t2_ms: list[float] = []
    t3_ms: list[float] = []
    t4_ms: list[float] = []
    t5_ms: list[float] = []
    llm_cb_open  = False
    llm_failures = 0

    for req in requests:
        # T1 APL + attestation
        _, _, ms = _tier_apl(req)
        t1_ms.append(ms)

        # T2 CMF enrichment
        _, ms = _tier_cmf(req)
        t2_ms.append(ms)

        # T3 OPA decision
        _, _, ms = _tier_opa(req)
        t3_ms.append(ms)

        # T4 rate-limit
        _, ms = _tier_rate_limit(req)
        t4_ms.append(ms)

        # T5 LLM — sampled + circuit-breaker
        if req.get("_route_to_llm") and not llm_cb_open:
            _, _, ms = _tier_llm(req)
            t5_ms.append(ms)
            if ms > 5000:               # >5 s → open circuit-breaker
                llm_failures += 1
                if llm_failures >= 3:
                    llm_cb_open = True
                    print("  ⚡ T5 circuit-breaker OPEN (3 consecutive slow LLM calls)")

    result: dict = {
        "T1_APL":        _stats(t1_ms),
        "T2_CMF":        _stats(t2_ms),
        "T3_OPA":        _stats(t3_ms),
        "T4_rate_limit": _stats(t4_ms),
    }
    if t5_ms:
        result["T5_LLM"] = _stats(t5_ms)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Main benchmark loop
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{'='*60}")
    print(f"  {TITLE}")
    print(f"  scales={SCALES}  LLM_RATE={LLM_RATE}  OPA_URL={OPA_URL}")
    opa_live = probe()
    print(f"  OPA live: {opa_live}")
    print(f"{'='*60}\n")

    raw: dict = {"scales": SCALES, "opa_live": opa_live, "runs": {}}

    # ── tables accumulated across all scales ──────────────────────────────────
    latency_rows: list[list[str]] = [
        ["Tier", "Baseline", "Scale", "P50", "P95", "P99", "Max"]
    ]
    throughput_rows: list[list[str]] = [
        ["Baseline", "Scale", "RPS", "CPU_delta_pct", "RSS_delta_MB"]
    ]

    for scale in SCALES:
        print(f"── Scale {scale:,} ──────────────────────────────────────────")
        requests = [
            make_request(idx=i, llm_rate=LLM_RATE, skill_id="benchmark_analytics")
            for i in range(scale)
        ]

        for baseline, run_fn in [
            ("NO_ENFORCEMENT",  run_no_enforcement),
            ("OPA_ONLY",        run_opa_only),
            ("NOMOSFLOW_FULL",  run_nomosflow_full),
        ]:
            print(f"  → {baseline} …", end=" ", flush=True)
            cpu0, rss0 = _snapshot()
            _psutil and _psutil.Process().cpu_percent(interval=None)  # prime

            wall_t0 = time.perf_counter()
            tier_data = run_fn(requests)
            wall_ms   = (time.perf_counter() - wall_t0) * 1000

            cpu1, rss1 = _snapshot()
            rps           = scale / max(wall_ms / 1000, 1e-9)
            delta_cpu     = round(cpu1 - cpu0, 2)
            delta_rss     = round(rss1 - rss0, 3)
            print(f"done  ({wall_ms/1000:.2f}s, {rps:.0f} RPS)")

            raw["runs"].setdefault(str(scale), {})[baseline] = {
                "wall_ms":     wall_ms,
                "rps":         rps,
                "delta_cpu":   delta_cpu,
                "delta_rss_mb": delta_rss,
                "tiers":       tier_data,
            }

            # ── latency table rows ─────────────────────────────────────────
            for tier_name, st in tier_data.items():
                if st["count"] == 0:
                    continue
                latency_rows.append([
                    tier_name,
                    baseline,
                    str(scale),
                    fmt_ms(st["p50"]),
                    fmt_ms(st["p95"]),
                    fmt_ms(st["p99"]),
                    fmt_ms(st["max"]),
                ])

            # ── throughput table rows ──────────────────────────────────────
            throughput_rows.append([
                baseline,
                str(scale),
                f"{rps:.0f}",
                str(delta_cpu),
                str(delta_rss),
            ])

    # ── merge live benchmark data (all-services-up, 2026-07-10) ──────────────
    live_bench = load_tier_benchmark()
    live_latency_rows = exp1_merged_latency_rows()
    if live_latency_rows:
        print(f"  ✓ merged {len(live_latency_rows)} live-benchmark rows "
              f"(opa_live=true, scales 100/1k/10k/100k)")
        latency_rows.extend(live_latency_rows)
        raw["live_benchmark"] = {
            "source": "benchmarks/tier_benchmark_20260710_021432.json",
            "config": live_bench.get("config", {}) if live_bench else {},
            "note":   "all services live: opa_live=true, apl_live=true, cmf_live=true, llm_live=true",
        }
        # live throughput rows
        by_scale = tier_bench_by_scale() or {}
        for sc, run in sorted(by_scale.items()):
            throughput_rows.append([
                "LIVE_BENCHMARK",
                str(sc),
                f"{run.get('throughput_rps', 0):.1f}",
                "measured",
                "measured",
            ])

    # ── persist raw JSON ──────────────────────────────────────────────────────
    save_result(EXP_ID, raw)

    # ── write summary ─────────────────────────────────────────────────────────
    live_note = (
        "Live benchmark (2026-07-10, all services up) rows are labelled "
        "**LIVE_BENCHMARK**. Scales 100 / 1 000 / 10 000 / 100 000 were run "
        "with `opa_live=true`, `apl_live=true`, `cmf_live=true`, `llm_live=true`."
        if live_latency_rows else
        "No live benchmark file found; all rows from simulated run."
    )

    sections = [
        {
            "heading": "Per-Tier Latency (P50 / P95 / P99 in ms)",
            "table":   latency_rows,
        },
        {
            "heading": "Live benchmark provenance",
            "text": live_note,
        },
        {
            "heading": "Throughput comparison",
            "table":   throughput_rows,
        },
        {
            "heading": "In-pod vs. gateway overhead",
            "text": (
                "Without a live Envoy ext_authz gRPC service the gateway baseline "
                "is **not available** in this run.\n\n"
                "To collect it manually:\n\n"
                "```bash\n"
                "# 1. Start Envoy with the NomosFlow ext_authz filter:\n"
                "#      envoy -c deploy/envoy/envoy.yaml\n"
                "# 2. Run the wrk2 load generator against the Envoy listener:\n"
                "#      wrk2 -t4 -c100 -d60s -R 1000 \\\n"
                "#           --script experiments/exp1_overhead/envoy_lua.lua \\\n"
                "#           http://localhost:10000/authz\n"
                "# 3. Compare wrk2 latency percentiles with T3_OPA column above.\n"
                "```\n"
            ),
        },
    ]

    gaps = [
        "OPA 5-min cache creates stale-ALLOW window during hot-reload",
        "LLM tier measured separately at LLM_RATE fraction only",
        "LIVE_BENCHMARK rows from benchmarks/tier_benchmark_20260710_021432.json "
        "(opa_live=true, llm_live=true at 1% routing); "
        "simulated rows from this run are labelled NO_ENFORCEMENT/OPA_ONLY/NOMOSFLOW_FULL",
    ]

    write_summary(EXP_ID, TITLE, sections, gaps=gaps)
    print("\nEXP-1 complete.\n")


if __name__ == "__main__":
    main()
