"""
experiments/run_all.py — NomosFlow paper: master experiment runner.

Runs every EXP-* module in order, collects timing and status, then prints a
summary table.  A single experiment can be targeted with --exp <name>.

Usage
-----
    python experiments/run_all.py               # run all
    python experiments/run_all.py --exp exp12   # run one
    python experiments/run_all.py --exp exp1_overhead
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

# ── ensure repo root is on sys.path ──────────────────────────────────────────
_REPO_ROOT = _Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_REPO_ROOT))

import argparse
import importlib
import time

# ── ordered experiment registry ──────────────────────────────────────────────
_EXPERIMENTS: list[str] = [
    "exp1_overhead",
    "exp2_resolution",
    "exp3_detection",
    "exp4_semantic",
    "exp6_failure",
    "exp6b_screening",
    "exp7_baselines",
    "exp8_policy_scale",
    "exp9_rb_stream",
    "exp11_multiagent",
    "exp12_resource",
    "exp_gap13",
    "exp_gap32",
    "exp_gap35",
]

# Canonical module path pattern: experiments.<exp_dir>.run
_MODULE_PATTERN = "experiments.{exp}.run"


def _run_one(exp: str) -> tuple[str, str, float]:
    """
    Dynamically import experiments.<exp>.run and call its main().
    Returns (status, results_subdir, duration_s).
    """
    module_path = _MODULE_PATTERN.format(exp=exp)
    results_dir = f"experiments/results/{exp}"

    t0 = time.perf_counter()
    try:
        mod = importlib.import_module(module_path)
    except ModuleNotFoundError as exc:
        duration = time.perf_counter() - t0
        print(f"  [SKIP] {exp}: module not found ({exc})")
        return "SKIP", results_dir, round(duration, 2)

    try:
        mod.main()
        duration = time.perf_counter() - t0
        return "OK", results_dir, round(duration, 2)
    except Exception as exc:
        duration = time.perf_counter() - t0
        print(f"  [ERROR] {exp}: {exc.__class__.__name__}: {exc}")
        return "ERROR", results_dir, round(duration, 2)


def run_all(target: str | None = None) -> None:
    experiments = [target] if target else _EXPERIMENTS

    if target and target not in _EXPERIMENTS:
        print(f"Unknown experiment '{target}'. Choose from:\n  " + "\n  ".join(_EXPERIMENTS))
        _sys.exit(1)

    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║       NomosFlow — master experiment runner               ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    summary: list[tuple[str, str, str, float]] = []

    for exp in experiments:
        print(f"━━━ {exp} ━━━")
        status, res_dir, dur = _run_one(exp)
        summary.append((exp, status, res_dir, dur))
        print()

    # ── summary table ─────────────────────────────────────────────────────────
    col_exp    = max(len("Experiment"),  max(len(r[0]) for r in summary))
    col_status = max(len("Status"),      max(len(r[1]) for r in summary))
    col_dir    = max(len("Results_dir"), max(len(r[2]) for r in summary))
    col_dur    = max(len("Duration_s"),  len("999.99"))

    def _row(exp, status, res_dir, dur) -> str:
        return (
            f"  {exp:<{col_exp}}  {status:<{col_status}}"
            f"  {res_dir:<{col_dir}}  {str(dur):>{col_dur}}"
        )

    header = _row("Experiment", "Status", "Results_dir", "Duration_s")
    sep    = "  " + "-" * (col_exp + col_status + col_dir + col_dur + 6)

    print("\n" + header)
    print(sep)
    for row in summary:
        print(_row(*row))
    print()

    ok_count    = sum(1 for r in summary if r[1] == "OK")
    skip_count  = sum(1 for r in summary if r[1] == "SKIP")
    error_count = sum(1 for r in summary if r[1] == "ERROR")
    total_dur   = sum(r[3] for r in summary)

    print(
        f"  Completed {ok_count}/{len(summary)} experiments  "
        f"({skip_count} skipped, {error_count} errors)  "
        f"total {total_dur:.1f}s"
    )
    print()
    print("  Results written to experiments/results/")
    print("  — see summary.md in each subfolder")
    print("  — run experiments/compare_results.py to check paper invariants")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run NomosFlow paper experiments.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python experiments/run_all.py\n"
            "  python experiments/run_all.py --exp exp12\n"
            "  python experiments/run_all.py --exp exp1_overhead\n"
        ),
    )
    parser.add_argument(
        "--exp",
        metavar="NAME",
        default=None,
        help=(
            "Run a single experiment by name, e.g. exp1 or exp1_overhead. "
            "Prefix matching is supported: 'exp12' matches 'exp12_resource'."
        ),
    )
    args = parser.parse_args()

    target = args.exp
    if target:
        if target not in _EXPERIMENTS:
            matches = [e for e in _EXPERIMENTS if e.startswith(target)]
            if len(matches) == 1:
                target = matches[0]
            elif len(matches) > 1:
                print(f"Ambiguous --exp '{target}'. Matches: {matches}")
                _sys.exit(1)

    run_all(target=target)

# Made with Bob
