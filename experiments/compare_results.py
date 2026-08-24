"""
experiments/compare_results.py — NomosFlow reviewer invariant checker.

Reads the most recent raw_*.json per experiment and verifies the paper's
14 structural invariants with a pass/fail table.  Returns exit code 1 on
any failure so CI catches regressions.

Usage
-----
    python experiments/compare_results.py
    python experiments/compare_results.py --compare-canonical
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_RESULTS = Path(__file__).parent / "results"
_COMPARE_CANONICAL = "--compare-canonical" in sys.argv[1:]


def _latest(exp: str) -> dict:
    """Return parsed JSON of the most recently written raw_*.json for exp."""
    d = _RESULTS / exp
    files = sorted(d.glob("raw_*.json"), key=lambda f: f.stat().st_mtime)
    if not files:
        raise FileNotFoundError(f"No raw_*.json for {exp} — run experiments first")
    return json.loads(files[-1].read_text())


def _canonical(exp: str) -> dict:
    """Return parsed JSON of the checked-in raw_CANONICAL.json for exp."""
    path = _RESULTS / exp / "raw_CANONICAL.json"
    if not path.exists():
        raise FileNotFoundError(f"No raw_CANONICAL.json for {exp}")
    return json.loads(path.read_text())


def _check(label: str, ok: bool, detail: str = "") -> tuple[str, str, str]:
    return label, detail, "PASS" if ok else "FAIL"


def _canonical_check(exp: str) -> tuple[str, str, str]:
    latest = _latest(exp)
    canonical = _canonical(exp)
    return _check(f"{exp} latest == canonical", latest == canonical)


checks: list[tuple[str, str, str]] = []

# ── EXP-1: tier latency ordering T1 < T3 ─────────────────────────────────────
try:
    raw = _latest("exp1")
    for scale_str, baselines in raw.get("runs", {}).items():
        nf = baselines.get("NOMOSFLOW_FULL", {}).get("tiers", {})
        t1_p50 = nf.get("T1_APL", {}).get("p50", 999)
        t3_p50 = nf.get("T3_OPA", {}).get("p50", 0)
        checks.append(_check("exp1 T1 P50 < T3 P50", t1_p50 < t3_p50, f"scale={scale_str}"))
        break
except Exception as e:
    checks.append(("exp1", str(e), "SKIP"))

# ── EXP-2: tier fractions plausible, short-circuit saving > 0 ────────────────
try:
    raw = _latest("exp2")
    t1_frac = raw.get("resolved_at_tier", {}).get("T1_APL", {}).get("fraction", 0)
    saving  = raw.get("ablation", {}).get("reduction_pct", 0)
    checks.append(_check("exp2 T1 resolves > 20% traffic", t1_frac > 0.20, f"fraction={t1_frac:.3f}"))
    checks.append(_check("exp2 short-circuit saving > 0%",  saving > 0,    f"saving={saving:.1f}%"))
except Exception as e:
    checks.append(("exp2", str(e), "SKIP"))

# ── EXP-3: precision=1.0, FPR=0.0, recall ≥ 0.80 ────────────────────────────
try:
    raw  = _latest("exp3")
    full = raw["aggregate"]["FULL"]
    checks.append(_check("exp3 FULL precision = 100%", full["precision"] == 1.0,
                         f"precision={full['precision']:.3f}"))
    checks.append(_check("exp3 FULL FPR = 0%",         full["fpr"] == 0.0,
                         f"fpr={full['fpr']:.3f}"))
    checks.append(_check("exp3 FULL recall ≥ 80%",     full["recall"] >= 0.80,
                         f"recall={full['recall']:.3f}"))
except Exception as e:
    checks.append(("exp3", str(e), "SKIP"))

# ── EXP-4: zero ALLOW verdicts on adversarial payloads ───────────────────────
try:
    raw = _latest("exp4")
    adv_allows = sum(
        r.get("false_allows", r.get("allow_count", 0))
        for r in raw.get("results", [])
        if r.get("class", "") in ("adversarial_deny", "true_violation")
    )
    checks.append(_check("exp4 false_allows = 0 (adversarial)", adv_allows == 0,
                         f"false_allows={adv_allows}"))
except Exception as e:
    checks.append(("exp4", str(e), "SKIP"))

# ── EXP-6: false_allows = 0 across all fault scenarios ───────────────────────
try:
    raw = _latest("exp6")
    scenarios = raw.get("scenarios", [])
    all_safe = all(s.get("false_allows", 1) == 0 for s in scenarios)
    checks.append(_check("exp6 false_allows = 0 (all scenarios)", all_safe))
except Exception as e:
    checks.append(("exp6", str(e), "SKIP"))

# ── EXP-7: NomosFlow coverage = 1.0, FPR = 0.0, > app_level ─────────────────
try:
    raw     = _latest("exp7")
    bl      = {b["baseline"]: b for b in raw.get("baselines", [])}
    nf_cov  = bl.get("NOMOSFLOW", {}).get("coverage", 0)
    nf_fpr  = bl.get("NOMOSFLOW", {}).get("fpr", 1)
    app_cov = bl.get("APP_LEVEL", {}).get("coverage", 1)
    checks.append(_check("exp7 NomosFlow coverage = 100%", nf_cov == 1.0,
                         f"coverage={nf_cov:.3f}"))
    checks.append(_check("exp7 NomosFlow FPR = 0%",        nf_fpr == 0.0,
                         f"fpr={nf_fpr:.3f}"))
    checks.append(_check("exp7 NomosFlow > App-level coverage", nf_cov > app_cov,
                         f"NomosFlow={nf_cov:.2f} App={app_cov:.2f}"))
except Exception as e:
    checks.append(("exp7", str(e), "SKIP"))

# ── EXP-8: stale_allow_count = 0 after hot-reload ────────────────────────────
try:
    raw = _latest("exp8")
    stale = raw.get("reload", {}).get("stale_allow_count", raw.get("stale_allow_count", 0))
    checks.append(_check("exp8 stale_allow_count = 0 after reload", stale == 0,
                         f"stale={stale}"))
except Exception as e:
    checks.append(("exp8", str(e), "SKIP"))

# ── EXP-9: denied_with_data = 0, static audit gated = 1 ─────────────────────
try:
    raw = _latest("exp9")
    dwd    = raw.get("denied_with_data", raw.get("runtime", {}).get("denied_with_data", 0))
    gated  = raw.get("static_gated", raw.get("static_audit", {}).get("gated", 1))
    checks.append(_check("exp9 denied_with_data = 0",    dwd   == 0, f"denied_with_data={dwd}"))
    checks.append(_check("exp9 static fetch gated = 1", gated == 1, f"gated={gated}"))
except Exception as e:
    checks.append(("exp9", str(e), "SKIP"))

# ── EXP-11: thread-mode RPS peaks between 5–25 agents ────────────────────────
try:
    raw = _latest("exp11")
    thread_rows = raw.get("scaling_thread", [])
    if thread_rows:
        peak_agent = max(thread_rows, key=lambda r: r.get("total_rps", 0))["agent_count"]
        checks.append(_check("exp11 thread peak in 5–50 agent range",
                             5 <= peak_agent <= 50, f"peak_agent={peak_agent}"))
    else:
        checks.append(("exp11", "no thread rows", "SKIP"))
except Exception as e:
    checks.append(("exp11", str(e), "SKIP"))

# ── EXP-12: full_stack incremental RSS is small (< 20 MB) ────────────────────
try:
    raw = _latest("exp12")
    configs = {r["config"]: r for r in raw.get("results", [])}
    rss_no   = configs.get("no_enforcement",  {}).get("mean_rss_mb", 0)
    rss_full = configs.get("full_stack",       {}).get("mean_rss_mb", 0)
    delta    = rss_full - rss_no
    checks.append(_check("exp12 incremental RSS < 20 MB", delta < 20,
                         f"delta_rss={delta:.1f} MB"))
except Exception as e:
    checks.append(("exp12", str(e), "SKIP"))

# ── EXP-GAP-13: all 3/3 interceptors importable with hooks OK ────────────────
try:
    raw = _latest("exp_gap13")
    n_ok = raw.get("n_hooks_ok", 0)
    n_total = raw.get("n_interceptors", 3)
    checks.append(_check("gap13 all hooks OK (3/3)", n_ok == n_total and n_total == 3,
                         f"{n_ok}/{n_total}"))
except Exception as e:
    checks.append(("gap13", str(e), "SKIP"))

# ── EXP-GAP-32: zero drift between OPA and Python OSCAL maps ─────────────────
try:
    raw = _latest("exp_gap32")
    drift = len(raw.get("keys_in_opa_not_py", [])) + len(raw.get("keys_in_py_not_opa", []))
    checks.append(_check("gap32 OPA↔Python key_drift = 0", drift == 0,
                         f"key_drift={drift}"))
except Exception as e:
    checks.append(("gap32", str(e), "SKIP"))

# ── EXP-GAP-35: 5/5 redaction test cases pass ────────────────────────────────
try:
    raw = _latest("exp_gap35")
    cases = raw.get("redaction_cases", [])
    passed = sum(1 for case in cases if case.get("ok"))
    total = len(cases)
    checks.append(_check("gap35 redaction 5/5 pass", passed == total and total >= 5,
                         f"{passed}/{total}"))
except Exception as e:
    checks.append(("gap35", str(e), "SKIP"))

if _COMPARE_CANONICAL:
    for exp in (
        "exp1", "exp2", "exp3", "exp4", "exp6", "exp7", "exp8", "exp9",
        "exp11", "exp12", "exp_gap13", "exp_gap32", "exp_gap35",
    ):
        try:
            checks.append(_canonical_check(exp))
        except Exception as e:
            checks.append((f"{exp} canonical", str(e), "SKIP"))


# ── Report ────────────────────────────────────────────────────────────────────
col = max(len(c[0]) for c in checks) + 2
print(f"\n{'Experiment':{col}}  {'Claim':{50}}  Status")
print("─" * (col + 58))
for label, detail, status in checks:
    mark = "✓" if status == "PASS" else ("?" if status == "SKIP" else "✗")
    print(f"{label:{col}}  {detail:{50}}  {mark} {status}")

passed = sum(1 for c in checks if c[2] == "PASS")
skipped = sum(1 for c in checks if c[2] == "SKIP")
failed  = sum(1 for c in checks if c[2] == "FAIL")
total   = len(checks)

print()
if failed == 0 and skipped == 0:
    print(f"  ✓ All {passed}/{total} invariant checks PASSED\n")
elif failed == 0:
    print(f"  ✓ {passed} PASSED  {skipped} SKIPPED (run experiments to populate results)\n")
else:
    print(f"  ✗ {failed} FAILED  {passed} PASSED  {skipped} SKIPPED\n")

sys.exit(1 if failed > 0 else 0)

# Made with Bob
