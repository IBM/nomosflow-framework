from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_REPO_ROOT_INSERT = _Path(__file__).resolve().parents[2]
if str(_REPO_ROOT_INSERT) not in _sys.path:
    _sys.path.insert(0, str(_REPO_ROOT_INSERT))

import multiprocessing
import os
import statistics
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path
from typing import Any

from experiments.shared.common import _REPO_ROOT, _stats, make_request, save_result
from experiments.shared.opa_client import decide
from experiments.shared.report import fmt_ms, write_summary

try:
    import psutil
except Exception:
    psutil = None

try:
    from src.validators.apl_validator import APLValidator
except Exception:
    APLValidator = None


REQUESTS_PER_AGENT = 200


def parse_agent_counts() -> list[int]:
    raw = os.getenv("AGENT_COUNTS", "1,5,10,25,50,100")
    return [int(item.strip()) for item in raw.split(",") if item.strip()]


def run_request(req: dict[str, Any], apl: Any, rate_limits: dict[str, int]) -> float:
    start = time.perf_counter()
    if apl is not None:
        apl_ok, _, _ = apl.validate(req)
    else:
        apl_ok = True
    if apl_ok:
        decide(req)
        agent_id = req["agent_id"]
        rate_limits[agent_id] = rate_limits.get(agent_id, 0) + 1
    return (time.perf_counter() - start) * 1000


def run_agent(agent_idx: int, apl: Any) -> dict[str, Any]:
    agent_id = f"agent-{agent_idx:04d}"
    rate_limits: dict[str, int] = {}
    latencies: list[float] = []
    for req_idx in range(REQUESTS_PER_AGENT):
        req = make_request(idx=req_idx, agent_id=agent_id, invalid_token_prob=0.0, llm_rate=0.0)
        req["role"] = "SENIOR"
        req["action"] = "READ"
        req["resource"] = "fred/GDP"
        req["purpose"] = "MarketResearch"
        req["metadata"]["role"] = "SENIOR"
        latencies.append(run_request(req, apl, rate_limits))
    return {"agent_id": agent_id, "latencies": latencies, "rate_limits": len(rate_limits)}


# ── top-level worker for ProcessPoolExecutor (must be picklable) ──────────────

def _process_worker(agent_idx: int) -> dict[str, Any]:
    """
    Top-level (picklable) worker for multiprocessing.
    Re-creates APLValidator in each worker process so there are no shared
    in-memory state objects crossing process boundaries.
    """
    try:
        from src.validators.apl_validator import APLValidator as _APL
        apl = _APL(enabled=True)
    except Exception:
        apl = None
    return run_agent(agent_idx, apl)


def benchmark(agent_count: int, mode: str = "thread") -> dict[str, Any]:
    """
    Run agent_count concurrent agents.

    mode='thread'  — ThreadPoolExecutor (original; shared memory, GIL-bound)
    mode='process' — ProcessPoolExecutor (true parallelism; isolated RSS)
    """
    process = psutil.Process() if psutil is not None else None
    rss_before = process.memory_info().rss if process is not None else None
    wall_start = time.perf_counter()

    if mode == "process":
        # Each worker gets its own Python interpreter and OPA client.
        # Cap at the number of physical CPUs to avoid thrashing.
        max_w = min(agent_count, multiprocessing.cpu_count())
        with ProcessPoolExecutor(max_workers=max_w) as pool:
            results = list(pool.map(_process_worker, range(agent_count)))
    else:
        apl = APLValidator(enabled=True) if APLValidator is not None else None
        with ThreadPoolExecutor(max_workers=agent_count) as pool:
            results = list(pool.map(lambda idx: run_agent(idx, apl), range(agent_count)))

    wall_ms = (time.perf_counter() - wall_start) * 1000
    rss_after = process.memory_info().rss if process is not None else None

    all_latencies = [lat for result in results for lat in result["latencies"]]
    total_requests = agent_count * REQUESTS_PER_AGENT
    total_rps = total_requests / (wall_ms / 1000.0)
    per_agent_means = [statistics.mean(result["latencies"]) for result in results]
    p99_ms = _stats(all_latencies)["p99"]
    rss_delta = (
        (rss_after - rss_before)
        if rss_before is not None and rss_after is not None
        else None
    )
    per_agent_rss = (rss_delta / agent_count) if rss_delta is not None else None

    return {
        "agent_count": agent_count,
        "mode": mode,
        "total_requests": total_requests,
        "total_rps": total_rps,
        "per_agent_rps": total_rps / agent_count,
        "per_agent_mean_latency_ms": statistics.mean(per_agent_means),
        "p99_ms": p99_ms,
        "peak_rss_bytes": rss_delta,
        "per_agent_rss_bytes": per_agent_rss,
    }


def main() -> None:
    counts = parse_agent_counts()

    # ── threaded run (original, for backward-compatible comparison) ───────────
    print("  → threaded run …")
    scaling_thread = [benchmark(c, mode="thread") for c in counts]

    # ── multi-process run (true isolation) ────────────────────────────────────
    # Use a reduced count set to keep wall time reasonable:
    # processes start up at ~150 ms each, so large counts are expensive.
    mp_counts_env = os.getenv("MP_AGENT_COUNTS", "1,5,10,25")
    mp_counts = [int(x.strip()) for x in mp_counts_env.split(",") if x.strip()]
    # Only include counts that are also in the thread run
    mp_counts = [c for c in mp_counts if c in counts]
    print(f"  → multi-process run (counts={mp_counts}) …")
    scaling_mp: list[dict] = []
    for c in mp_counts:
        try:
            scaling_mp.append(benchmark(c, mode="process"))
        except Exception as exc:
            print(f"    ⚠  process benchmark failed at count={c}: {exc}")

    # ── tables ────────────────────────────────────────────────────────────────
    thread_rows = [["Agents", "Total_RPS", "Per_agent_RPS", "P99_ms", "Mode"]]
    for item in scaling_thread:
        thread_rows.append([
            str(item["agent_count"]),
            f"{item['total_rps']:.1f}",
            f"{item['per_agent_rps']:.1f}",
            fmt_ms(item["p99_ms"]),
            "thread",
        ])
    for item in scaling_mp:
        thread_rows.append([
            str(item["agent_count"]),
            f"{item['total_rps']:.1f}",
            f"{item['per_agent_rps']:.1f}",
            fmt_ms(item["p99_ms"]),
            "process",
        ])

    resource_rows = [["Agents", "Mode", "Peak_RSS_MB", "Per_agent_RSS_KB"]]
    for item in scaling_thread + scaling_mp:
        peak_mb = (
            "n/a" if item["peak_rss_bytes"] is None
            else f"{item['peak_rss_bytes'] / (1024 * 1024):.2f}"
        )
        per_kb = (
            "n/a" if item["per_agent_rss_bytes"] is None
            else f"{item['per_agent_rss_bytes'] / 1024:.2f}"
        )
        resource_rows.append([
            str(item["agent_count"]), item["mode"], peak_mb, per_kb,
        ])

    component_rows = [["Component", "Growth_model", "Notes"]]
    component_rows += [
        ["OPA process",            "amortised/shared",  "single shared policy engine (thread); isolated per worker (process)"],
        ["APL validator instance", "amortised/shared",  "single instance reused across agents (thread); per-worker (process)"],
        ["CMF enricher",           "amortised/shared",  "conceptually shared service, not separately exercised here"],
        ["rate_limits dict entry", "O(N_agents)",        "~200 bytes per principal"],
        ["per-principal history",  "O(N_agents * H)",    "H = rate_limits update count"],
    ]

    result = {
        "exp_id":              "exp11",
        "repo_root":           str(_REPO_ROOT),
        "script":              str(Path(__file__).relative_to(_REPO_ROOT)),
        "requests_per_agent":  REQUESTS_PER_AGENT,
        "scaling_thread":      scaling_thread,
        "scaling_process":     scaling_mp,
        # keep 'scaling' key for backward compat with exp7/run.py imports
        "scaling":             scaling_thread,
        "components":          component_rows[1:],
    }
    save_result("exp11", result)
    write_summary(
        "exp11",
        "EXP-11 multi-agent scalability",
        sections=[
            {
                "heading": "Throughput scaling (thread + process)",
                "table": thread_rows,
            },
            {
                "heading": "Per-agent resource growth",
                "table": resource_rows,
            },
            {
                "heading": "Amortised vs. per-agent components",
                "table": component_rows,
            },
        ],
        gaps=[
            "Thread mode: agents share OPA client and Python GIL — "
            "RSS isolation approximate; throughput is GIL-limited above ~10 agents.",
            "Process mode: true OS process isolation (ProcessPoolExecutor); "
            "each worker has independent OPA HTTP client and APLValidator instance. "
            f"Run with MP_AGENT_COUNTS env var to control which counts are tested "
            f"(default: {mp_counts_env}).",
            "Per-principal history H is the rate_limits dict; "
            "full sequence_state (sidecar_optimized.py) not exercised in this benchmark.",
        ],
    )
    print("  ✓ EXP-11 complete")


if __name__ == "__main__":
    main()
