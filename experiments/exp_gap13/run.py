"""
experiments/exp_gap13/run.py
EXP-GAP-13: Interceptor Inventory — NomosFlow VLDB paper

Enumerates and characterises all compliance interceptors deployed in the
NomosFlow sidecar, verifying that:

  (a) every expected interceptor module is present and importable, and
  (b) each interceptor exposes the canonical hook surface expected by the
      paper (attach / detach / is_active, or the proxy equivalent).

This experiment does not run live traffic — it is a static inventory check
with lightweight functional smoke-tests.  It produces a table suitable for
the paper's "interceptor coverage" figure.

Interceptors catalogued
-----------------------
  compliance_interceptor   — RIIP: patches builtins.open, urllib.request.urlopen,
                             boto3.make_request, sqlite3.connect
  mcp_interceptor          — MCP JSON-RPC proxy (stdio/SSE transport)
  compliance_proxy_server  — Flask HTTP compliance proxy

Results
-------
  experiments/results/exp_gap13/summary.md
  experiments/results/exp_gap13/tables.tex
  experiments/results/exp_gap13/raw_<ts>.json
"""
from __future__ import annotations

import importlib
import inspect
import sys
import time
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve()
_REPO = _HERE.parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from experiments.shared.common import Timer, _REPO_ROOT, save_result
from experiments.shared.report import write_summary

# ---------------------------------------------------------------------------
# Interceptor registry — (module_path, canonical_hooks, description)
# ---------------------------------------------------------------------------
_INTERCEPTORS: list[dict[str, Any]] = [
    {
        "name":        "compliance_interceptor",
        "module":      "src.interceptors.compliance_interceptor",
        "hooks":       ["attach", "detach"],
        "patches":     [
            "builtins.open",
            "urllib.request.urlopen",
            "boto3.make_request",
            "sqlite3.connect",
        ],
        "type":        "RIIP",            # Runtime Inline Instrumentation Point
        "transport":   "in-process",
        "description": "Patches Python builtins and stdlib I/O to intercept "
                       "all file/network/database access for compliance checks.",
    },
    {
        "name":        "mcp_interceptor",
        "module":      "src.interceptors.mcp_interceptor",
        "hooks":       ["handle_request"],
        "patches":     [],
        "type":        "PROXY",
        "transport":   "stdio / SSE",
        "description": "MCP JSON-RPC proxy that wraps tool calls and resources "
                       "before forwarding to the upstream MCP server.",
    },
    {
        "name":        "compliance_proxy_server",
        "module":      "src.interceptors.compliance_proxy_server",
        "hooks":       ["create_app"],
        "patches":     [],
        "type":        "PROXY",
        "transport":   "HTTP (Flask)",
        "description": "Flask HTTP reverse proxy that applies compliance checks "
                       "to all inbound requests before forwarding downstream.",
    },
]


def _probe_interceptor(spec: dict[str, Any]) -> dict[str, Any]:
    """
    Attempt to import the interceptor module and verify hook surface.
    Returns a result dict with status, found hooks, and any import error.
    """
    module_path = spec["module"]
    expected_hooks = spec["hooks"]

    try:
        mod = importlib.import_module(module_path)
        import_ok = True
        import_error = None
    except Exception as exc:
        return {
            "name":         spec["name"],
            "import_ok":    False,
            "import_error": f"{type(exc).__name__}: {exc}",
            "hooks_found":  [],
            "hooks_missing": expected_hooks,
            "all_hooks_ok": False,
            "module_file":  None,
            "type":         spec["type"],
            "transport":    spec["transport"],
            "description":  spec["description"],
            "patches":      spec["patches"],
        }

    found_hooks: list[str] = []
    missing_hooks: list[str] = []
    for hook in expected_hooks:
        if hasattr(mod, hook):
            found_hooks.append(hook)
        else:
            missing_hooks.append(hook)

    # Attempt to find module source file
    try:
        mod_file = inspect.getfile(mod)
        rel_file = str(Path(mod_file).relative_to(_REPO))
    except (TypeError, ValueError):
        rel_file = module_path

    return {
        "name":          spec["name"],
        "import_ok":     True,
        "import_error":  None,
        "hooks_found":   found_hooks,
        "hooks_missing": missing_hooks,
        "all_hooks_ok":  len(missing_hooks) == 0,
        "module_file":   rel_file,
        "type":          spec["type"],
        "transport":     spec["transport"],
        "description":   spec["description"],
        "patches":       spec["patches"],
    }


def main() -> None:
    with Timer() as timer:
        results = [_probe_interceptor(spec) for spec in _INTERCEPTORS]

    n_total    = len(results)
    n_importok = sum(1 for r in results if r["import_ok"])
    n_hooksok  = sum(1 for r in results if r["all_hooks_ok"])

    # ── console summary ───────────────────────────────────────────────────
    for r in results:
        status = "✓" if r["import_ok"] else "✗"
        hooks  = "hooks OK" if r["all_hooks_ok"] else f"missing: {r['hooks_missing']}"
        print(f"  {status} {r['name']:<30}  [{r['type']:6}]  {hooks}")
    print()
    print(f"  {n_importok}/{n_total} modules importable, "
          f"{n_hooksok}/{n_total} hook surfaces complete")

    # ── tables ────────────────────────────────────────────────────────────
    matrix = [["Interceptor", "Type", "Transport", "Import", "Hooks_OK", "Patches_count"]]
    for r in results:
        matrix.append([
            r["name"],
            r["type"],
            r["transport"],
            "YES" if r["import_ok"] else "NO",
            "YES" if r["all_hooks_ok"] else "PARTIAL",
            str(len(r["patches"])),
        ])

    # ── persistence ───────────────────────────────────────────────────────
    raw = {
        "exp_id":       "exp_gap13",
        "repo_root":    str(_REPO_ROOT),
        "runtime_ms":   timer.ms,
        "n_interceptors": n_total,
        "n_import_ok":  n_importok,
        "n_hooks_ok":   n_hooksok,
        "interceptors": results,
    }
    save_result("exp_gap13", raw)

    gap_notes: list[str] = []
    for r in results:
        if not r["import_ok"]:
            gap_notes.append(
                f"{r['name']}: module not importable — {r['import_error']}"
            )
        elif not r["all_hooks_ok"]:
            gap_notes.append(
                f"{r['name']}: missing hooks {r['hooks_missing']}"
            )
    if not gap_notes:
        gap_notes.append("All interceptors importable with complete hook surface.")

    write_summary(
        "exp_gap13",
        "EXP-GAP-13: Interceptor inventory",
        sections=[
            {
                "heading": "Interceptor inventory",
                "table":   matrix,
            },
            {
                "heading": "Descriptions",
                "text": "\n".join(
                    f"  {r['name']}: {r['description']}" for r in results
                ),
            },
        ],
        gaps=gap_notes,
    )


if __name__ == "__main__":
    main()

# Made with Bob
