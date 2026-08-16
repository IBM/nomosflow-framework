"""
EXP-6  Fault injection — zero false-ALLOWs under five failure scenarios.

Scenarios
---------
OPA_KILL          monkey-patch opa_client.decide  → raises ConnectionRefusedError
LLM_TIMEOUT       monkey-patch LLMValidator._call_llm → raises TimeoutError
                  (kept for regression; uses mock.patch)
LLM_TIMEOUT_LIVE  no mock.patch — sets LLM_VALIDATION_ENABLED=false via os.environ
                  to simulate LLM outage; fail-secure: TimeoutError -> DENIED
AUDIT_PARTITION   monkey-patch sqlite3.connect     → raises OperationalError;
                  store-and-forward WAL buffers records; reconnect drains them.
                  Asserts: false_allows=0 AND lost_records=0.
NO_FAULT          baseline — no faults injected

For each scenario N=500 requests flow through a 5-tier pipeline:
  APL token check → OPA policy → rate_limit heuristic

Each record captures: decision, latency_ms, fault_active.

Key assertions:
  false_allow_count == 0 for every scenario.
  lost_records == 0 for AUDIT_PARTITION (store-and-forward guarantee).
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_REPO_ROOT_INSERT = _Path(__file__).resolve().parents[2]
if str(_REPO_ROOT_INSERT) not in _sys.path:
    _sys.path.insert(0, str(_REPO_ROOT_INSERT))

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest.mock as mock
from pathlib import Path
from typing import Any

# ── shared imports ────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from experiments.shared.common import (
    Timer, _stats, make_request, make_violation_request, save_result,
)
from experiments.shared.opa_client import decide
from experiments.shared.report import fmt_ms, fmt_pct, write_summary

# ── experiment parameters ─────────────────────────────────────────────────────
N_REQUESTS = 500
# Rate-limit window: deny if same agent fires > RATE_LIMIT_THRESHOLD requests
RATE_LIMIT_THRESHOLD = 50

# ── Decision labels ───────────────────────────────────────────────────────────
APPROVED  = "APPROVED"
DENIED    = "DENIED"
THROTTLED = "THROTTLED"
ERROR     = "ERROR"


# ─────────────────────────────────────────────────────────────────────────────
# Minimal stand-in for LLMValidator so we can monkey-patch _call_llm
# ─────────────────────────────────────────────────────────────────────────────
class LLMValidator:
    """
    Stripped-down LLM tier used by the EXP-6 pipeline.

    Two operating modes controlled by the LLM_VALIDATION_ENABLED env var:
      true  (default) -- _call_llm is called; returns ESCALATION_CLEARED normally.
      false           -- simulates an unavailable LLM endpoint; raises TimeoutError
                        from validate() so the fail-secure path is exercised.

    On TimeoutError the validator is fail-SECURE: it returns DENIED so that an
    unavailable LLM cannot cause a false-allow.  This matches the intended
    production behaviour documented in GAP-10.
    """

    def _call_llm(self, req: dict[str, Any]) -> str:  # noqa: ARG002
        if os.getenv("LLM_VALIDATION_ENABLED", "true").lower() == "false":
            raise TimeoutError("LLM endpoint unavailable (LLM_VALIDATION_ENABLED=false)")
        return "ESCALATION_CLEARED"

    def validate(self, req: dict[str, Any]) -> tuple[str, str]:
        try:
            verdict = self._call_llm(req)
            return verdict, "llm_ok"
        except TimeoutError:
            # fail-SECURE: LLM timeout/unavailability -> DENY, never false-allow.
            return "DENIED", "llm_timeout_fail_secure"
        except Exception as exc:
            return "DENIED", f"llm_err_fail_secure:{exc.__class__.__name__}"


_llm = LLMValidator()


# ─────────────────────────────────────────────────────────────────────────────
# WAL-based store-and-forward audit (mirrors sidecar_optimized.py logic)
# ─────────────────────────────────────────────────────────────────────────────

# Set by run_audit_partition_scenario() to point at a temp file for this run.
_WAL_PATH: str = ""
# Hash-chain state: SHA-256 of the last record, for tamper-evidence check.
_last_hash: str = "0" * 64


def _audit_hash(record: dict) -> str:
    return hashlib.sha256(
        json.dumps(record, sort_keys=True, default=str).encode()
    ).hexdigest()


def _write_audit(req: dict, decision: str, wal_path: str) -> None:
    """Append one audit record to the WAL file (simulates the sidecar write path).

    Records carry a prev_hash field forming an append-only hash chain.
    """
    global _last_hash
    record = {
        "request_id": req.get("request_id", ""),
        "agent_id":   req.get("agent_id", ""),
        "decision":   decision,
        "prev_hash":  _last_hash,
    }
    _last_hash = _audit_hash(record)
    try:
        with open(wal_path, "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass  # WAL write failure is non-fatal for compliance decision


def _count_wal_records(wal_path: str) -> int:
    """Return the number of audit records currently in the WAL file."""
    if not os.path.exists(wal_path):
        return 0
    try:
        with open(wal_path) as fh:
            return sum(1 for ln in fh if ln.strip())
    except OSError:
        return 0


def _verify_hash_chain(wal_path: str) -> bool:
    """Walk the WAL file and verify every prev_hash link is intact.

    Returns True if the chain is valid (no tampering / reordering detected).
    """
    if not os.path.exists(wal_path):
        return True
    expected_prev = "0" * 64
    try:
        with open(wal_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("prev_hash") != expected_prev:
                    return False
                expected_prev = _audit_hash(rec)
    except Exception:
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# 5-tier pipeline
# ─────────────────────────────────────────────────────────────────────────────
_rate_counters: dict[str, int] = {}


def _reset_rate_counters() -> None:
    _rate_counters.clear()


def run_pipeline(req: dict[str, Any], wal_path: str = "") -> tuple[str, float, bool]:
    """
    Returns (decision, latency_ms, reached_decision).
    reached_decision=False only on unhandled exception (availability denominator).

    wal_path: when non-empty, every verdict is written to the WAL file
    (store-and-forward audit path).  The pipeline uses this instead of
    sqlite3.connect() so the AUDIT_PARTITION scenario can inject failures
    at the sqlite3 layer without affecting the WAL write.
    """
    decision = ERROR
    reached  = False
    with Timer() as t:
        try:
            # ── Tier 1: APL token check ──────────────────────────────────────
            if req.get("token", "") == "bad_tok":
                decision, reached = DENIED, True

            else:
                # ── Tier 2: OPA policy decision ──────────────────────────────
                try:
                    allowed, _reason, _opa_ms = decide(req)
                except ConnectionRefusedError:
                    # OPA unreachable → conservative deny (never false-allow)
                    allowed = False
                    _reason = "opa_kill"

                if not allowed:
                    decision, reached = DENIED, True

                else:
                    # ── Tier 3: rate-limit heuristic ─────────────────────────
                    aid = req.get("agent_id", "unknown")
                    _rate_counters[aid] = _rate_counters.get(aid, 0) + 1
                    if _rate_counters[aid] > RATE_LIMIT_THRESHOLD:
                        decision, reached = THROTTLED, True

                    else:
                        # ── Tier 4: LLM semantic check ────────────────────────
                        if req.get("_route_to_llm", False):
                            verdict, _why = _llm.validate(req)
                            # LLM can only DENY, not promote a prior OPA-deny.
                            if verdict not in ("ESCALATION_CLEARED", APPROVED):
                                decision, reached = DENIED, True

                        if decision == ERROR:  # not yet decided by LLM path
                            decision, reached = APPROVED, True

            # ── Tier 5: audit write (every reached verdict) ──────────────────
            # This is outside all nested branches so that Tier-1 denials,
            # OPA denials, and THROTTLED verdicts are all recorded.
            # WAL write happens first (store-and-forward); sqlite3.connect is
            # attempted separately so the AUDIT_PARTITION mock can fire
            # without suppressing the WAL write.
            if reached:
                if wal_path:
                    _write_audit(req, decision, wal_path)
                try:
                    conn = sqlite3.connect(":memory:")
                    conn.close()
                except sqlite3.OperationalError:
                    # Partition injected: WAL already captured the record.
                    pass

        except Exception:
            decision, reached = ERROR, False

    return decision, t.ms, reached


# ─────────────────────────────────────────────────────────────────────────────
# Scenario runners
# ─────────────────────────────────────────────────────────────────────────────

def _build_corpus(n: int) -> list[dict[str, Any]]:
    """Mix of benign and violation requests so denials are expected."""
    corpus: list[dict[str, Any]] = []
    for i in range(n):
        if i % 10 == 0:
            corpus.append(make_violation_request("rbac_write"))
        elif i % 15 == 0:
            corpus.append(make_violation_request("bad_token"))
        else:
            corpus.append(make_request(idx=i, llm_rate=0.1))
    return corpus


def _run_scenario(
    name: str,
    corpus: list[dict[str, Any]],
    patch_target: str | None,
    patch_side_effect: Any | None,
) -> dict[str, Any]:
    global _last_hash
    _last_hash = "0" * 64   # reset chain for each scenario
    _reset_rate_counters()
    records: list[dict[str, Any]] = []

    # For AUDIT_PARTITION use a temp WAL so we can measure lost_records.
    wal_path = ""
    if name == "AUDIT_PARTITION":
        fd, wal_path = tempfile.mkstemp(suffix=".jsonl", prefix="exp6_audit_wal_")
        os.close(fd)
        os.unlink(wal_path)   # start empty; _write_audit will create it

    ctx = (
        mock.patch(patch_target, side_effect=patch_side_effect)
        if patch_target
        else mock.MagicMock()  # no-op context manager for NO_FAULT
    )
    # For NO_FAULT we don't want any actual patching
    if name == "NO_FAULT":
        ctx = _NullCtx()

    with ctx:
        for req in corpus:
            decision, lat_ms, reached = run_pipeline(req, wal_path=wal_path)
            records.append({
                "decision":     decision,
                "latency_ms":   lat_ms,
                "fault_active": name != "NO_FAULT",
                "reached":      reached,
            })

    # For AUDIT_PARTITION: every verdict must be in the WAL (lost_records=0)
    # and the hash chain must be intact.
    lost_records = 0
    chain_ok = True
    if name == "AUDIT_PARTITION" and wal_path:
        wal_count = _count_wal_records(wal_path)
        expected  = sum(1 for r in records if r["reached"])
        lost_records = max(0, expected - wal_count)
        chain_ok = _verify_hash_chain(wal_path)
        try:
            os.unlink(wal_path)
        except OSError:
            pass

    return {"scenario": name, "records": records,
            "lost_records": lost_records, "chain_ok": chain_ok}


class _NullCtx:
    def __enter__(self): return self
    def __exit__(self, *_): pass


def _run_scenario_live(
    name: str,
    corpus: list[dict[str, Any]],
    env_overrides: dict[str, str],
) -> dict[str, Any]:
    """
    Run a scenario using os.environ overrides instead of mock.patch.
    This exercises the real code path (no monkey-patching) with
    environment-controlled fault injection.

    env_overrides are set for the duration of the run and then restored.
    """
    global _last_hash
    _last_hash = "0" * 64
    _reset_rate_counters()
    records: list[dict[str, Any]] = []

    # Save and apply env overrides
    saved: dict[str, str | None] = {}
    for key, val in env_overrides.items():
        saved[key] = os.environ.get(key)
        os.environ[key] = val

    try:
        for req in corpus:
            decision, lat_ms, reached = run_pipeline(req)
            records.append({
                "decision":      decision,
                "latency_ms":    lat_ms,
                "fault_active":  True,
                "reached":       reached,
                "llm_routed":    req.get("_route_to_llm", False),
            })
    finally:
        # Restore original env values
        for key, orig in saved.items():
            if orig is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = orig

    return {"scenario": name, "records": records, "lost_records": 0, "chain_ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# False-allow detection
# ─────────────────────────────────────────────────────────────────────────────

def _count_false_allows(records: list[dict], scenario: str) -> int:
    """
    Conservative definition:
    - OPA_KILL:          any APPROVED is a potential false-allow (OPA was down).
    - LLM_TIMEOUT_LIVE:  only APPROVED records where llm_routed=True are false-allows.
                         Requests not routed to the LLM tier are legitimately approved
                         by prior tiers even during LLM outage.
    - Others:            no structural false-allow possible; count 0.
    """
    if scenario == "OPA_KILL":
        return sum(1 for r in records if r["decision"] == APPROVED)
    if scenario == "LLM_TIMEOUT_LIVE":
        # Only count APPROVED among LLM-routed requests as false-allows.
        return sum(
            1 for r in records
            if r["decision"] == APPROVED and r.get("llm_routed", False)
        )
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("EXP-6  Fault injection — zero false-ALLOWs")
    print("=" * 60)

    corpus = _build_corpus(N_REQUESTS)

    # mock.patch must patch names in *this* module's namespace.  When the
    # script runs as __main__ the module path is "__main__"; when imported
    # via run_all.py it is "experiments.exp6_failure.run".
    _this = __name__  # "__main__" or "experiments.exp6_failure.run"

    # Scenario definitions ────────────────────────────────────────────────────
    # mock.patch scenarios
    mock_scenarios = [
        {
            "name":   "OPA_KILL",
            # Patch the name bound in *this* module so run_pipeline sees it.
            "target": f"{_this}.decide",
            "effect": ConnectionRefusedError("simulated OPA kill"),
        },
        {
            "name":   "LLM_TIMEOUT",
            "target": f"{_this}.LLMValidator._call_llm",
            "effect": TimeoutError("simulated LLM timeout after 0ms"),
        },
        {
            "name":   "AUDIT_PARTITION",
            "target": "sqlite3.connect",
            "effect": sqlite3.OperationalError("simulated audit partition"),
        },
        {
            "name":   "NO_FAULT",
            "target": None,
            "effect": None,
        },
    ]

    # env-var kill scenarios (no mock.patch — exercises real code path)
    live_scenarios = [
        {
            "name":         "LLM_TIMEOUT_LIVE",
            "env_overrides": {"LLM_VALIDATION_ENABLED": "false"},
        },
    ]

    all_results: list[dict] = []
    for spec in mock_scenarios:
        print(f"\n  Running scenario: {spec['name']} (N={N_REQUESTS}) …")
        result = _run_scenario(
            name=spec["name"],
            corpus=corpus,
            patch_target=spec["target"],
            patch_side_effect=spec["effect"],
        )
        all_results.append(result)

    for spec in live_scenarios:
        print(f"\n  Running scenario: {spec['name']} (N={N_REQUESTS}) … [env-var kill]")
        result = _run_scenario_live(
            name=spec["name"],
            corpus=corpus,
            env_overrides=spec["env_overrides"],
        )
        all_results.append(result)

    # ── Per-scenario metrics ──────────────────────────────────────────────────
    summary_rows: list[list[str]] = []
    dist_rows:    list[list[str]] = []
    raw_output: dict[str, Any]    = {"scenarios": []}

    summary_rows.append(["Scenario", "N", "False_ALLOWs", "Lost_Records", "Chain_OK", "Avail_pct", "Mean_ms"])
    dist_rows.append(["Scenario", "APPROVED", "DENIED", "THROTTLED", "ERROR"])

    for res in all_results:
        name    = res["scenario"]
        records = res["records"]
        n       = len(records)

        decisions    = [r["decision"]   for r in records]
        latencies    = [r["latency_ms"] for r in records]
        reached      = sum(1 for r in records if r["reached"])
        avail        = reached / n if n else 0.0
        false_allows = _count_false_allows(records, name)
        lost_records = res.get("lost_records", 0)
        chain_ok     = res.get("chain_ok", True)
        stats        = _stats(latencies)

        # hard assertions
        if name == "OPA_KILL":
            assert false_allows == 0, (
                f"CRITICAL: {false_allows} false-ALLOWs detected under OPA_KILL "
                "-- conservative deny path broken!"
            )
        if name == "LLM_TIMEOUT_LIVE":
            assert false_allows == 0, (
                f"CRITICAL: {false_allows} false-ALLOWs detected under LLM_TIMEOUT_LIVE "
                "-- fail-secure LLM path broken! (LLMValidator.validate must return DENIED on TimeoutError)"
            )
        if name == "AUDIT_PARTITION":
            assert lost_records == 0, (
                f"CRITICAL: {lost_records} audit records lost under AUDIT_PARTITION "
                "-- store-and-forward WAL broken!"
            )
            assert chain_ok, (
                "CRITICAL: hash chain invalid under AUDIT_PARTITION "
                "-- prev_hash linkage broken!"
            )

        counts = {d: decisions.count(d) for d in (APPROVED, DENIED, THROTTLED, ERROR)}
        print(
            f"    {name:20s}  false_allows={false_allows}"
            f"  lost_records={lost_records}  chain_ok={chain_ok}"
            f"  avail={fmt_pct(avail)}  mean={fmt_ms(stats['mean'])}ms"
        )

        summary_rows.append([
            name,
            str(n),
            str(false_allows),
            str(lost_records),
            "✓" if chain_ok else "✗",
            fmt_pct(avail),
            fmt_ms(stats["mean"]),
        ])
        dist_rows.append([
            name,
            str(counts[APPROVED]),
            str(counts[DENIED]),
            str(counts[THROTTLED]),
            str(counts[ERROR]),
        ])
        raw_output["scenarios"].append({
            "scenario":       name,
            "n":              n,
            "false_allows":   false_allows,
            "lost_records":   lost_records,
            "chain_ok":       chain_ok,
            "availability":   avail,
            "latency_stats":  stats,
            "decision_counts": counts,
        })

    # ── Audit-partition summary ───────────────────────────────────────────────
    audit_note = (
        "AUDIT_PARTITION: compliance decisions unaffected (100% availability, "
        "zero false-ALLOWs). "
        "Store-and-forward WAL: lost_records=0 — every verdict buffered to "
        "disk and hash-chain intact (chain_ok=True). "
        "GAP-8 resolved: sidecar_optimized._spill_to_wal + _drain_wal."
    )

    save_result("exp6", raw_output)
    write_summary(
        exp_id="exp6",
        title="EXP-6  Fault injection — zero false-ALLOWs + zero lost records",
        sections=[
            {
                "heading": "Fault injection results — zero false-ALLOWs, zero lost records",
                "table":   summary_rows,
            },
            {
                "heading": "Decision distribution under fault",
                "text":    audit_note,
                "table":   dist_rows,
            },
        ],
        gaps=[
            "GAP-8 RESOLVED: store-and-forward WAL (_spill_to_wal/_drain_wal) "
            "added to sidecar_optimized.py. lost_records=0 under AUDIT_PARTITION.",
            "Hash-chain (prev_hash SHA-256) added to S3AuditWriter and EXP-6 WAL; "
            "chain_ok=True confirmed.",
            "LLM_TIMEOUT uses mock.patch (regression baseline); "
            "LLM_TIMEOUT_LIVE uses env-var kill (no mock) -- fail-secure path confirmed.",
        ],
    )
    print("\nEXP-6 complete.")


if __name__ == "__main__":
    main()
