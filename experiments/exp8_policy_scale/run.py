"""
EXP-8  Policy scale + hot-reload correctness.

Part A — Policy scale
  Synthetic Rego policies with increasing rule counts: [10, 100, 1000, 5000].
  Each policy is N copies of:
      allow if input.role == "SENIOR_<k>"
  appended to the base allow-all stub.
  200 requests per rule count via opa_client.decide().
  If OPA is unreachable: simulate latency = 0.5 + 0.0003 * rule_count ms.

Part B — Hot-reload correctness
  Baseline: 100 requests, record decisions.
  Push a policy that denies all JUNIOR READ requests via opa_client.hot_reload().
  Continue for 10 seconds, recording every decision.
  Detect stale-ALLOW: JUNIOR READ requests approved after the reload timestamp.
  Report propagation_latency_ms and stale_allow_count.

Known limitation: OPA 5-min decision cache (now//300) creates a stale-ALLOW
window — documented as a gap.
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

# ── real policy path for restore ──────────────────────────────────────────────
_REAL_POLICY_PATH = Path(__file__).resolve().parents[2] / "config" / "policies" / "policy.rego"

# ── shared imports ────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from experiments.shared.common import (
    Timer, _stats, make_request, make_violation_request, save_result,
)
from experiments.shared import opa_client
from experiments.shared.opa_client import decide, hot_reload, probe
from experiments.shared.report import fmt_ms, fmt_pct, write_summary

# ── experiment parameters ─────────────────────────────────────────────────────
RULE_COUNTS        = [10, 100, 1000, 5000]
REQUESTS_PER_COUNT = 200
BASELINE_REQUESTS  = 100
RELOAD_WINDOW_S    = 10   # seconds to run after hot-reload

# Linear simulation model: lat_ms = SIM_INTERCEPT + SIM_SLOPE * rule_count
SIM_INTERCEPT = 0.5
SIM_SLOPE     = 0.0003
SIM_P99_MULT  = 2.1   # p99 ≈ 2.1× mean in the linear model

# ─────────────────────────────────────────────────────────────────────────────
# Rego policy templates
# ─────────────────────────────────────────────────────────────────────────────

_BASE_POLICY = """\
package bank.authz

default allow = false

allow if {
    input.operation == "READ"
    input.context.role == "SENIOR"
}

allow if {
    input.context.role == "ADMIN"
}
"""

_DENY_JUNIOR_READ_POLICY = """\
package bank.authz

default allow = false

allow if {
    input.operation == "READ"
    input.context.role != "JUNIOR"
}

allow if {
    input.context.role == "ADMIN"
}
"""


def _make_synthetic_policy(rule_count: int) -> str:
    """
    Generate a Rego policy with `rule_count` synthetic allow rules.
    Each rule is a distinct variant: allow if input.role == "SENIOR_<k>".
    The extra rules do not change the effective policy for the test corpus
    (they only match non-existent roles) but force OPA to evaluate more rules.
    """
    lines = [_BASE_POLICY, "# --- synthetic scale rules ---"]
    for k in range(rule_count):
        lines.append(
            f'allow if {{ input.context.role == "SENIOR_{k}" }}'
        )
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Simulation fallback
# ─────────────────────────────────────────────────────────────────────────────

def _simulate_latency(rule_count: int) -> float:
    """Linear latency model + jitter."""
    base = SIM_INTERCEPT + SIM_SLOPE * rule_count
    jitter = random.gauss(0.0, base * 0.15)
    return max(SIM_INTERCEPT * 0.5, base + jitter)


# ─────────────────────────────────────────────────────────────────────────────
# Part A: policy scale
# ─────────────────────────────────────────────────────────────────────────────

def run_policy_scale(opa_live: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for rule_count in RULE_COUNTS:
        print(f"  rule_count={rule_count:>5d}  ", end="", flush=True)

        if opa_live:
            # Push the synthetic policy before measuring
            policy_text = _make_synthetic_policy(rule_count)
            ok, _reload_ms = hot_reload(policy_text)
            if not ok:
                print("(policy push failed — falling back to simulation)")
                opa_live_this = False
            else:
                opa_live_this = True
        else:
            opa_live_this = False

        latencies: list[float] = []
        for i in range(REQUESTS_PER_COUNT):
            req = make_request(idx=i)
            if opa_live_this:
                with Timer() as t:
                    decide(req)
                latencies.append(t.ms)
            else:
                latencies.append(_simulate_latency(rule_count))

        stats = _stats(latencies)
        simulated = not opa_live_this
        print(
            f"mean={fmt_ms(stats['mean'])}ms  "
            f"p99={fmt_ms(stats['p99'])}ms"
            f"  {'[SIM]' if simulated else '[LIVE]'}"
        )
        results.append({
            "rule_count": rule_count,
            "n":          REQUESTS_PER_COUNT,
            "simulated":  simulated,
            "stats":      stats,
        })

    # Restore the real policy after scale tests to leave OPA in a known-good state
    if opa_live:
        real_policy = _REAL_POLICY_PATH.read_text() if _REAL_POLICY_PATH.exists() else _BASE_POLICY
        hot_reload(real_policy)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Part B: hot-reload correctness
# ─────────────────────────────────────────────────────────────────────────────

def _is_junior_read(req: dict[str, Any]) -> bool:
    return req.get("role") == "JUNIOR" and req.get("action") == "READ"


def run_hot_reload(opa_live: bool) -> dict[str, Any]:
    """
    Establish baseline, push deny-JUNIOR-READ policy, then measure propagation.
    Returns metrics dict.
    """
    print("\n  [Part B] Hot-reload correctness")

    # ── Build a corpus that contains JUNIOR READ requests ────────────────────
    random.seed(7)
    baseline_corpus: list[dict[str, Any]] = []
    for i in range(BASELINE_REQUESTS):
        req = make_request(idx=i)
        baseline_corpus.append(req)

    # Force some JUNIOR READ into baseline so we have a before/after contrast
    for i in range(0, BASELINE_REQUESTS, 10):
        baseline_corpus[i]["role"]   = "JUNIOR"
        baseline_corpus[i]["action"] = "READ"

    # ── Baseline run ──────────────────────────────────────────────────────────
    baseline_decisions: list[dict[str, Any]] = []
    for req in baseline_corpus:
        with Timer() as t:
            if opa_live:
                allowed, reason, _ms = decide(req)
            else:
                # simulate: JUNIOR READ denied by base policy
                allowed = not _is_junior_read(req)
                reason  = "SIM_baseline"
        baseline_decisions.append({
            "allowed":        allowed,
            "is_junior_read": _is_junior_read(req),
            "latency_ms":     t.ms,
        })
    baseline_junior_denied = sum(
        1 for d in baseline_decisions
        if d["is_junior_read"] and not d["allowed"]
    )
    print(f"    Baseline JUNIOR-READ denied: {baseline_junior_denied}/{BASELINE_REQUESTS}")

    # ── Push new policy ───────────────────────────────────────────────────────
    print("    Pushing deny-JUNIOR-READ policy …", end=" ", flush=True)
    reload_ok = False
    reload_ts = time.time()
    reload_ms = 0.0

    if opa_live:
        reload_ok, reload_ms = hot_reload(_DENY_JUNIOR_READ_POLICY)
        reload_ts = time.time()
    else:
        # Simulate: pretend reload took 12 ms
        time.sleep(0.012)
        reload_ok = True
        reload_ms = 12.0
        reload_ts = time.time()

    first_new_policy_ts: float | None = None
    propagation_latency_ms: float | None = None
    stale_allow_count = 0
    post_decisions: list[dict[str, Any]] = []

    print(f"ok={reload_ok}  reload_ms={fmt_ms(reload_ms)}")

    # ── Post-reload requests (RELOAD_WINDOW_S seconds) ────────────────────────
    print(f"    Running requests for {RELOAD_WINDOW_S}s after reload …")
    deadline = time.time() + RELOAD_WINDOW_S
    req_idx  = 0
    while time.time() < deadline:
        # Alternate between JUNIOR READ (should be denied) and normal requests
        if req_idx % 3 == 0:
            req = make_request(idx=req_idx)
            req["role"]   = "JUNIOR"
            req["action"] = "READ"
        else:
            req = make_request(idx=req_idx)
        req_ts = time.time()

        with Timer() as t:
            if opa_live:
                allowed, reason, _ms = decide(req)
            else:
                # Simulate propagation: new policy effective after reload_ms
                elapsed_since_reload = (req_ts - reload_ts) * 1000
                if elapsed_since_reload >= reload_ms:
                    allowed = not _is_junior_read(req)
                    reason  = "SIM_new_policy"
                else:
                    # Stale cache window
                    allowed = True
                    reason  = "SIM_stale_cache"

        is_jr = _is_junior_read(req)
        after_reload = req_ts >= reload_ts

        if is_jr and after_reload and allowed:
            stale_allow_count += 1

        if (first_new_policy_ts is None and is_jr and not allowed and after_reload):
            first_new_policy_ts = req_ts
            propagation_latency_ms = (first_new_policy_ts - reload_ts) * 1000

        post_decisions.append({
            "allowed":        allowed,
            "is_junior_read": is_jr,
            "after_reload":   after_reload,
            "reason":         reason,
            "latency_ms":     t.ms,
        })
        req_idx += 1
        time.sleep(0.02)  # ~50 req/s — avoid spinning

    if propagation_latency_ms is None:
        propagation_latency_ms = reload_ms  # at most as fast as the reload itself

    post_jr_denied = sum(
        1 for d in post_decisions
        if d["is_junior_read"] and d["after_reload"] and not d["allowed"]
    )
    print(
        f"    Post-reload JUNIOR-READ denied: {post_jr_denied}/"
        f"{sum(1 for d in post_decisions if d['is_junior_read'])}  "
        f"stale_allows={stale_allow_count}  "
        f"propagation={fmt_ms(propagation_latency_ms)}ms"
    )

    return {
        "reload_ok":               reload_ok,
        "reload_latency_ms":       reload_ms,
        "propagation_latency_ms":  propagation_latency_ms,
        "stale_allow_count":       stale_allow_count,
        "first_new_policy_ts":     first_new_policy_ts,
        "post_requests":           len(post_decisions),
        "post_junior_read_denied": post_jr_denied,
        "opa_live":                opa_live,
    }


# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("EXP-8  Policy scale + hot-reload correctness")
    print("=" * 60)

    opa_live = probe()
    print(f"  OPA live: {opa_live}")

    # ── Part A ────────────────────────────────────────────────────────────────
    print("\n  [Part A] Policy scale")
    scale_results = run_policy_scale(opa_live)

    # ── Part B ────────────────────────────────────────────────────────────────
    reload_result = run_hot_reload(opa_live)

    # ── Restore original policy so downstream experiments see a clean OPA ─────
    if opa_live and _REAL_POLICY_PATH.exists():
        hot_reload(_REAL_POLICY_PATH.read_text())
        print("  Restored original policy.rego into OPA.")

    # ── Output tables ─────────────────────────────────────────────────────────
    scale_rows: list[list[str]] = [
        ["Rule_count", "Mean_ms", "P99_ms", "Simulated"]
    ]
    for r in scale_results:
        scale_rows.append([
            str(r["rule_count"]),
            fmt_ms(r["stats"]["mean"]),
            fmt_ms(r["stats"]["p99"]),
            "yes" if r["simulated"] else "no",
        ])

    reload_rows: list[list[str]] = [
        ["Metric", "Value"],
        ["OPA_live",                str(reload_result["opa_live"])],
        ["reload_ok",               str(reload_result["reload_ok"])],
        ["reload_latency_ms",       fmt_ms(reload_result["reload_latency_ms"])],
        ["propagation_latency_ms",  fmt_ms(reload_result["propagation_latency_ms"])],
        ["stale_allow_count",       str(reload_result["stale_allow_count"])],
        ["post_requests",           str(reload_result["post_requests"])],
        ["post_junior_read_denied", str(reload_result["post_junior_read_denied"])],
    ]

    raw_output: dict[str, Any] = {
        "opa_live":      opa_live,
        "scale_results": scale_results,
        "reload_result": reload_result,
    }

    save_result("exp8", raw_output)
    write_summary(
        exp_id="exp8",
        title="EXP-8  Policy scale + hot-reload correctness",
        sections=[
            {
                "heading": "Latency vs. rule count",
                "table":   scale_rows,
            },
            {
                "heading": "Hot-reload correctness",
                "table":   reload_rows,
            },
        ],
        gaps=[
            "OPA 5-min decision cache (now//300) creates stale-ALLOW window:"
            " sidecar_optimized.py:965",
            "Policy scale uses synthetic rules; real policy complexity may have"
            " different coefficients",
        ],
    )
    print("\nEXP-8 complete.")


if __name__ == "__main__":
    main()

# Made with Bob
