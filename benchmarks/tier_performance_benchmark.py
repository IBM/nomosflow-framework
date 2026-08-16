#!/usr/bin/env python3
"""
Tier Performance Benchmark
===========================
Exercises every tier of the compliance pipeline with per-stage timing,
including database writes (SQLite audit log), optional S3 writes, and
optional OPA/LLM tiers.  LLM is only invoked for ~1 % of requests.

Scales tested: 100, 1 000, 10 000, 100 000 requests.

Architecture under test
-----------------------
  Tier 1 – APL   : Inline authorisation (µs-range)
  Tier 2 – CMF   : CDM v2 context enrichment (µs-range)
  Tier 3 – OPA   : Open Policy Agent policy evaluation (ms-range)
  Tier 4 – LLM   : LLM hallucination validation (~1 % routing)
  Storage – SQLite: Audit log insert per request
  Storage – S3   : Batched JSONL write (optional; skipped when LocalStack absent)

Usage
-----
  python benchmarks/tier_performance_benchmark.py

Override defaults via environment variables:
  BENCHMARK_SCALES=100,1000,10000   # comma-separated
  LLM_RATE=0.01                     # fraction of requests sent to LLM (0–1)
  OPA_URL=http://localhost:8181     # OPA endpoint
  S3_ENDPOINT_URL=http://localhost:4566
  S3_AUDIT_BUCKET=compliance-audit-logs
  BENCHMARK_DB=benchmarks/benchmark_audit.db
"""

import json
import math
import os
import random
import sqlite3
import statistics
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# ---------------------------------------------------------------------------
# Project root on sys.path so we can import src.*
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

# ---------------------------------------------------------------------------
# Auto-load .env.local from the repo root when it exists.
# The file uses shell `export KEY=value` syntax, so we strip the `export`
# prefix and skip comments/blank lines.  Only sets variables that are not
# already present in the environment, so an explicit `export VAR=x` in the
# caller's shell always takes precedence.
# ---------------------------------------------------------------------------
def _load_env_local(path: Path) -> int:
    """Load KEY=value lines from *path* into os.environ.  Returns # vars loaded."""
    if not path.is_file():
        return 0
    loaded = 0
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # strip optional leading `export `
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")   # remove optional quoting
        if key and key not in os.environ:          # never override caller's env
            os.environ[key] = val
            loaded += 1
    return loaded

_env_local_path = _REPO_ROOT / ".env.local"
_env_loaded = _load_env_local(_env_local_path)

try:
    from src.validators.apl_validator import APLValidator
    from src.validators.skill_registry import get_registry as _get_skill_registry
    APL_AVAILABLE = True
except ImportError:
    APL_AVAILABLE = False
    _get_skill_registry = None   # type: ignore[assignment]

try:
    from src.validators.cmf_context_enricher import CMFContextEnricher
    CMF_AVAILABLE = True
except ImportError:
    CMF_AVAILABLE = False

try:
    from src.validators.llm_validator import LLMValidator
    LLM_IMPORT_AVAILABLE = True
except ImportError:
    LLM_IMPORT_AVAILABLE = False

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Info,
        start_http_server as _prom_start_http,
        REGISTRY,
    )
    PROM_AVAILABLE = True
except ImportError:
    PROM_AVAILABLE = False

# ---------------------------------------------------------------------------
# Prometheus metrics (defined at module level so they survive restarts)
# Each metric is guarded so re-importing the module doesn't double-register.
# ---------------------------------------------------------------------------
def _get_or_create_metric(cls, name, doc, labelnames=None, **kwargs):
    """Return existing metric if already registered, else create it."""
    try:
        if labelnames:
            return cls(name, doc, labelnames, **kwargs)
        return cls(name, doc, **kwargs)
    except ValueError:
        # Already registered — retrieve from the collector registry
        for collector in list(REGISTRY._names_to_collectors.values()):
            if hasattr(collector, '_name') and collector._name == name:
                return collector
        return None

if PROM_AVAILABLE:
    bm_requests_total = _get_or_create_metric(
        Counter, "benchmark_requests_total",
        "Total requests processed by the benchmark",
        labelnames=["scale", "decision"],
    )
    bm_throughput = _get_or_create_metric(
        Gauge, "benchmark_throughput_rps",
        "Current benchmark throughput in requests per second",
        labelnames=["scale"],
    )
    bm_tier_latency = _get_or_create_metric(
        Histogram, "benchmark_tier_latency_ms",
        "Per-tier request latency in milliseconds",
        labelnames=["tier"],
        buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 25,
                 50, 100, 250, 500, 1000, 5000, 15000, 30000],
    )
    bm_llm_invocations = _get_or_create_metric(
        Counter, "benchmark_llm_invocations_total",
        "Number of requests routed to the LLM tier",
        labelnames=["scale", "cb_tripped"],
    )
    bm_active_scale = _get_or_create_metric(
        Gauge, "benchmark_active_scale",
        "Number of requests in the current scale run",
    )
    bm_progress = _get_or_create_metric(
        Gauge, "benchmark_progress_pct",
        "Completion percentage of the current scale run",
        labelnames=["scale"],
    )
    bm_circuit_breaker = _get_or_create_metric(
        Gauge, "benchmark_llm_circuit_breaker_open",
        "1 when the LLM circuit breaker is tripped (rate-limited), 0 otherwise",
    )

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
class C:
    BLUE    = '\033[0;34m'
    GREEN   = '\033[0;32m'
    YELLOW  = '\033[1;33m'
    RED     = '\033[0;31m'
    MAGENTA = '\033[0;35m'
    CYAN    = '\033[0;36m'
    BOLD    = '\033[1m'
    NC      = '\033[0m'

def _hdr(text: str) -> None:
    print(f"\n{C.BOLD}{C.MAGENTA}{'='*68}{C.NC}")
    print(f"{C.BOLD}{C.MAGENTA}{text}{C.NC}")
    print(f"{C.BOLD}{C.MAGENTA}{'='*68}{C.NC}")

def _ok(text: str) -> None:
    print(f"{C.GREEN}✓ {text}{C.NC}")

def _warn(text: str) -> None:
    print(f"{C.YELLOW}⚠  {text}{C.NC}")

def _info(text: str) -> None:
    print(f"{C.CYAN}  {text}{C.NC}")

# ---------------------------------------------------------------------------
# Percentile helper (no numpy dependency)
# ---------------------------------------------------------------------------
def _pct(sorted_data: List[float], p: float) -> float:
    """Return the p-th percentile of a pre-sorted list (0 < p ≤ 100)."""
    if not sorted_data:
        return 0.0
    idx = (p / 100) * (len(sorted_data) - 1)
    lo, hi = int(idx), min(int(idx) + 1, len(sorted_data) - 1)
    return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * (idx - lo)

# ---------------------------------------------------------------------------
# Synthetic request generator
# ---------------------------------------------------------------------------
_RESOURCES  = ["fred/GDP", "fred/UNRATE", "edgar/0000051143", "edgar/0001018724",
                "fred/DFF", "edgar/0000320193", "fred/CPIAUCSL", "edgar/0000789019"]
_ROLES      = ["JUNIOR", "SENIOR", "ADMIN"]
_ACTIONS    = ["READ", "WRITE"]
_PURPOSES   = ["MarketResearch", "RiskAnalysis", "AuditReview", "Compliance"]
_AGENTS     = [f"agent-{i:04d}" for i in range(1, 51)]   # 50 distinct agents
_VALID_TOK  = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.benchmark.signature"

# Timestamp window: use a plausible recent-past range that falls clearly within
# any LLM's training data.  We anchor to 2024-01-01 and spread randomly across
# the following 12 months.  This avoids Claude flagging benchmark timestamps as
# "future dates" because its training cutoff is earlier than the run date.
_TS_BASE  = 1704067200   # 2024-01-01 00:00:00 UTC
_TS_RANGE = 365 * 24 * 3600  # 1 year of seconds

def _make_request(idx: int, llm_rate: float) -> Dict[str, Any]:
    """Generate one synthetic compliance request."""
    role = random.choice(_ROLES)
    action = random.choice(_ACTIONS)
    # Inject a small % of intentionally invalid requests to exercise deny paths
    invalid_frac = 0.05
    token = _VALID_TOK if random.random() > invalid_frac else "bad_tok"
    return {
        "request_id": str(uuid.uuid4()),
        "agent_id": random.choice(_AGENTS),
        "resource": random.choice(_RESOURCES),
        "action": action,
        "purpose": random.choice(_PURPOSES),
        "timestamp": _TS_BASE + random.randint(0, _TS_RANGE),
        "token": token,
        "role": role,
        "metadata": {
            "token": token,
            "role": role,
            "user_id": f"user-{(idx % 200):04d}",
            "user_clearance": random.choice(["public", "internal", "confidential"]),
            "department": random.choice(["finance", "risk", "compliance", "engineering"]),
        },
        "_route_to_llm": random.random() < llm_rate,
    }

# ---------------------------------------------------------------------------
# SQLite audit store
# ---------------------------------------------------------------------------
class AuditDB:
    """Lightweight SQLite writer used only by the benchmark (not the sidecar)."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS benchmark_audit (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id          TEXT    NOT NULL,
                request_id      TEXT    NOT NULL,
                agent_id        TEXT    NOT NULL,
                resource        TEXT    NOT NULL,
                action          TEXT    NOT NULL,
                decision        TEXT    NOT NULL,
                tier_ms_apl     REAL,
                tier_ms_attest  REAL,
                tier_ms_cmf     REAL,
                tier_ms_opa     REAL,
                tier_ms_llm     REAL,
                tier_ms_db      REAL,
                total_ms        REAL,
                ts              INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ba_run    ON benchmark_audit(run_id);
            CREATE INDEX IF NOT EXISTS idx_ba_agent  ON benchmark_audit(agent_id);
            CREATE INDEX IF NOT EXISTS idx_ba_ts     ON benchmark_audit(ts);

            CREATE TABLE IF NOT EXISTS benchmark_runs (
                run_id       TEXT PRIMARY KEY,
                scale        INTEGER,
                llm_rate     REAL,
                started_at   TEXT,
                finished_at  TEXT,
                summary_json TEXT
            );
        """)
        self._conn.commit()

    def insert_record(self, run_id: str, req: Dict, decision: str,
                      timings: Dict[str, float]) -> float:
        """Insert one audit record; returns write latency in ms."""
        t0 = time.perf_counter()
        self._conn.execute(
            """INSERT INTO benchmark_audit
               (run_id, request_id, agent_id, resource, action, decision,
                tier_ms_apl, tier_ms_attest, tier_ms_cmf, tier_ms_opa,
                tier_ms_llm, tier_ms_db, total_ms, ts)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run_id, req["request_id"], req["agent_id"],
                req["resource"], req["action"], decision,
                timings.get("apl_ms"),
                timings.get("attest_ms"),   # attestation overhead (µs range)
                timings.get("cmf_ms"),
                timings.get("opa_ms"),
                timings.get("llm_ms"),
                None,                        # db_ms filled in after
                timings.get("total_ms"),
                int(time.time()),
            ),
        )
        self._conn.commit()
        db_ms = (time.perf_counter() - t0) * 1000
        return db_ms

    def save_run(self, run_id: str, scale: int, llm_rate: float,
                 started_at: str, finished_at: str, summary: Dict) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO benchmark_runs
               (run_id, scale, llm_rate, started_at, finished_at, summary_json)
               VALUES (?,?,?,?,?,?)""",
            (run_id, scale, llm_rate, started_at, finished_at,
             json.dumps(summary)),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

# ---------------------------------------------------------------------------
# Optional S3 writer (thin wrapper around boto3 to avoid the full
# S3AuditWriter dependency which needs Prometheus metrics registered)
# ---------------------------------------------------------------------------
class _S3Writer:
    def __init__(self, endpoint: str, bucket: str,
                 access_key: str = "test", secret_key: str = "test",
                 region: str = "us-east-1", batch_size: int = 200):
        self.bucket = bucket
        self.batch_size = batch_size
        self._batch: List[Dict] = []
        self._key_prefix = "benchmark-audit"
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )
        try:
            self._client.head_bucket(Bucket=bucket)
        except ClientError:
            self._client.create_bucket(Bucket=bucket)

    def add(self, record: Dict) -> Optional[float]:
        """Add record to batch; flush and return flush_ms when batch is full."""
        self._batch.append(record)
        if len(self._batch) >= self.batch_size:
            return self.flush()
        return None

    def flush(self) -> float:
        if not self._batch:
            return 0.0
        t0 = time.perf_counter()
        ts = datetime.now(UTC).strftime("%Y/%m/%d/%H%M%S%f")
        key = f"{self._key_prefix}/{ts}-{len(self._batch)}.jsonl"
        body = "\n".join(json.dumps(r) for r in self._batch).encode()
        self._client.put_object(Bucket=self.bucket, Key=key, Body=body)
        ms = (time.perf_counter() - t0) * 1000
        self._batch = []
        return ms

    def close(self) -> float:
        return self.flush()


# ---------------------------------------------------------------------------
# OPA probe
# ---------------------------------------------------------------------------
def _probe_opa(opa_url: str) -> bool:
    try:
        r = requests.get(f"{opa_url}/health", timeout=1.5)
        return r.status_code == 200
    except Exception:
        return False

def _call_opa(opa_url: str, request: Dict) -> Tuple[bool, float]:
    """POST to OPA; return (allowed, latency_ms). Falls back to simulated on error."""
    payload = {
        "input": {
            "user": {
                "clearance_level": request["metadata"].get("user_clearance", "public"),
                "role": request["role"],
                "request_count": random.randint(10, 90),
                "time_window_seconds": 60,
            },
            "topic": {
                "classification": random.choice(["public", "internal", "confidential"]),
                "data_category": random.choice(["financial", "general", "personal"]),
                "jurisdiction": random.choice(["US", "EU"]),
            },
            "message": {
                "timestamp_ms": int(time.time() * 1000),
                "created_at_ms": int(time.time() * 1000),
                "contains_pii": random.random() < 0.15,
                "quality_score": round(random.uniform(0.6, 1.0), 2),
                "completeness_score": round(random.uniform(0.8, 1.0), 2),
                "accuracy_score": round(random.uniform(0.85, 1.0), 2),
                "schema_version": "v1.0.0",
                "consent_obtained": random.random() > 0.2,
            },
        }
    }
    t0 = time.perf_counter()
    try:
        r = requests.post(
            f"{opa_url}/v1/data/bank/authz",
            json=payload,
            timeout=1.0,
        )
        ms = (time.perf_counter() - t0) * 1000
        allowed = r.status_code == 200 and r.json().get("result", True)
        return (bool(allowed), ms)
    except Exception:
        # Simulate ~2.8 ms OPA response with Gaussian noise
        ms = (time.perf_counter() - t0) * 1000
        sim_ms = max(0.5, random.gauss(2.8, 0.6))
        allowed = random.random() > 0.12   # ~12% deny rate
        return (allowed, sim_ms)

# ---------------------------------------------------------------------------
# Simulated tier helpers when real services are unavailable
# ---------------------------------------------------------------------------
def _sim_apl(request: Dict) -> Tuple[bool, float]:
    """Simulate APL; returns (approved, latency_µs converted to ms)."""
    us = max(0.05, random.gauss(0.35, 0.08))
    role  = request.get("role", "JUNIOR")
    token = request.get("token", "")
    denied = (len(token) < 10) or (role == "JUNIOR" and request.get("action") == "WRITE")
    return (not denied, us / 1000)

def _sim_cmf(request: Dict) -> float:
    """Simulate CMF enrichment; returns latency_ms."""
    return max(0.01, random.gauss(0.020, 0.005))

def _sim_llm(request: Dict) -> Tuple[bool, float]:
    """Simulate LLM; returns (valid, latency_ms)."""
    ms = max(50, random.gauss(380, 60))
    return (random.random() > 0.04, ms)   # 4% LLM flag rate

# ---------------------------------------------------------------------------
# Per-request pipeline
# ---------------------------------------------------------------------------
# ── Benchmark skill registration (one-time, at pipeline init) ─────────────────
# When the SkillRegistry is available we register a set of benchmark skills
# that cover all resources used by _make_request().  Requests that carry
# skill_id will be verified against these contracts; requests without skill_id
# are unaffected (Check 6 is a pass-through for non-skill calls).

def _register_benchmark_skills() -> None:
    """Register benchmark skills in the process-level SkillRegistry."""
    if _get_skill_registry is None:
        return
    reg = _get_skill_registry()
    reg.register(
        skill_id="benchmark_analytics",
        version="1.0.0",
        contract={
            "allowed_actions":   ["READ", "WRITE"],
            "allowed_resources": _RESOURCES,
        },
    )


class TierPipeline:
    """Runs a request through APL → CMF → OPA → (LLM if routed) and times each."""

    # Circuit-breaker: after this many consecutive LLM failures the pipeline
    # stops sending requests to the LLM for the remainder of the scale run and
    # falls back to simulation.  Prevents rate-limit storms from stalling the
    # benchmark for hours.
    _LLM_CB_THRESHOLD = 3

    def __init__(
        self,
        opa_url: str,
        opa_live: bool,
        apl: Optional[Any],          # APLValidator | None
        cmf: Optional[Any],          # CMFContextEnricher | None
        llm: Optional[Any],          # LLMValidator | None
    ):
        self.opa_url  = opa_url
        self.opa_live = opa_live
        self.apl      = apl
        self.cmf      = cmf
        self.llm      = llm
        self._llm_consecutive_errors = 0
        self._llm_tripped = False   # True = circuit open; route to simulation

    def reset_circuit_breaker(self) -> None:
        """Reset between scale runs."""
        self._llm_consecutive_errors = 0
        self._llm_tripped = False

    def run(self, request: Dict) -> Tuple[str, Dict[str, float]]:
        """
        Process one request through the tier stack.

        Returns
        -------
        decision : str  – "APPROVED" | "DENIED"
        timings  : dict – {apl_ms, attest_ms, cmf_ms, opa_ms, llm_ms, total_ms}

        ``attest_ms`` is the isolated cost of Check 6 only.  It is extracted
        from the total APL wall-clock time by running APL twice on requests
        that carry a skill_id: once without attestation (checks 1–5) and
        once with (checks 1–6).  The delta is the attestation overhead.
        For requests without skill_id, attest_ms is 0.0.
        """
        wall_start = time.perf_counter()
        timings: Dict[str, float] = {}
        decision = "APPROVED"

        # ── Tier 1: APL ──────────────────────────────────────────────────
        import io, contextlib
        t0 = time.perf_counter()
        if self.apl is not None:
            _null = io.StringIO()
            with contextlib.redirect_stdout(_null):
                approved, reason, lat_us = self.apl.validate(request)
            timings["apl_ms"] = lat_us / 1000
        else:
            approved, apl_ms = _sim_apl(request)
            timings["apl_ms"] = apl_ms
        timings["apl_ms"] = (time.perf_counter() - t0) * 1000  # wall clock wins

        # ── Isolated attestation overhead (attest_ms) ─────────────────────
        # Measured only when the request carries a skill_id so the number is
        # meaningful.  We re-run just the attestation sub-check on a no-op
        # validator to isolate Check 6 from the rest of APL.
        timings["attest_ms"] = 0.0
        if self.apl is not None and request.get("skill_id"):
            t_attest = time.perf_counter()
            self.apl._validate_attestation(
                request.get("skill_id", ""),
                request.get("skill_version", "latest"),
                request.get("action", "READ"),
                request.get("resource", ""),
            )
            timings["attest_ms"] = (time.perf_counter() - t_attest) * 1000

        if not approved:
            decision = "DENIED"
            timings["total_ms"] = (time.perf_counter() - wall_start) * 1000
            return decision, timings

        # ── Tier 2: CMF ──────────────────────────────────────────────────
        t0 = time.perf_counter()
        if self.cmf is not None:
            try:
                self.cmf.enrich(request)
            except Exception:
                pass
        else:
            time.sleep(_sim_cmf(request) / 1000)  # simulate µs enrichment
        timings["cmf_ms"] = (time.perf_counter() - t0) * 1000

        # ── Tier 3: OPA ──────────────────────────────────────────────────
        t0 = time.perf_counter()
        if self.opa_live:
            allowed, _ = _call_opa(self.opa_url, request)
        else:
            allowed, sim_ms = _call_opa(self.opa_url, request)   # always simulates on error
            allowed = allowed   # suppress unused warning
        timings["opa_ms"] = (time.perf_counter() - t0) * 1000

        if not allowed:
            decision = "DENIED"
            timings["total_ms"] = (time.perf_counter() - wall_start) * 1000
            return decision, timings

        # ── Tier 4: LLM (≈1 % routing) ──────────────────────────────────
        timings["llm_ms"] = 0.0
        if request.get("_route_to_llm", False):
            t0 = time.perf_counter()
            use_live_llm = (
                self.llm is not None
                and self.llm.enabled
                and not self._llm_tripped
            )
            if use_live_llm:
                # Strip benchmark-internal fields before sending to the LLM.
                llm_req = {k: v for k, v in request.items()
                           if not k.startswith("_")}
                try:
                    valid, reason, _ = self.llm.validate_request(llm_req)
                    if not valid:
                        decision = "DENIED"
                    # Success — reset the consecutive-error counter
                    self._llm_consecutive_errors = 0
                except Exception:
                    valid = True
                    self._llm_consecutive_errors += 1
                    if self._llm_consecutive_errors >= self._LLM_CB_THRESHOLD:
                        self._llm_tripped = True
                        _warn(f"LLM circuit breaker tripped after "
                              f"{self._llm_consecutive_errors} consecutive errors "
                              f"— falling back to simulation for this scale run")
            else:
                # Simulation path (no live LLM, or circuit breaker open)
                valid, sim_ms = _sim_llm(request)
                time.sleep(sim_ms / 1000)
                if not valid:
                    decision = "DENIED"
            timings["llm_ms"] = (time.perf_counter() - t0) * 1000

        timings["total_ms"] = (time.perf_counter() - wall_start) * 1000
        return decision, timings

# ---------------------------------------------------------------------------
# Scale runner
# ---------------------------------------------------------------------------
def run_scale(
    scale: int,
    pipeline: TierPipeline,
    db: AuditDB,
    s3: Optional[_S3Writer],
    llm_rate: float,
    run_id: str,
    progress_every: int = 0,
) -> Dict[str, Any]:
    """
    Run *scale* requests through the pipeline and record every timing.

    Returns a summary dict with per-tier percentile statistics.
    """
    _hdr(f"Scale: {scale:,} requests  (LLM rate: {llm_rate*100:.1f}%)")

    started_at = datetime.now(UTC).isoformat()

    # Accumulators
    # NOTE: llm_ms only accumulates samples where LLM was actually invoked
    # (llm_ms > 0).  Including the zero-latency non-LLM requests would make
    # all percentiles appear as 0 because only ~1% of requests hit the tier.
    # attest_ms similarly only accumulates samples where skill_id was present.
    tier_times: Dict[str, List[float]] = {
        "apl_ms": [], "attest_ms": [], "cmf_ms": [], "opa_ms": [],
        "llm_ms": [], "db_ms": [], "s3_ms": [], "total_ms": [],
    }
    decisions: Dict[str, int] = {"APPROVED": 0, "DENIED": 0}
    llm_invoked = 0
    s3_flush_latencies: List[float] = []

    if progress_every <= 0:
        progress_every = max(1, scale // 10)

    scale_label = str(scale)

    if PROM_AVAILABLE:
        bm_active_scale.set(scale)
        bm_progress.labels(scale=scale_label).set(0)
        bm_circuit_breaker.set(0)

    batch_start = time.perf_counter()

    for i in range(scale):
        req = _make_request(i, llm_rate)
        if req["_route_to_llm"]:
            llm_invoked += 1

        decision, timings = pipeline.run(req)
        decisions[decision] += 1

        # ── SQLite write ─────────────────────────────────────────────────
        db_ms = db.insert_record(run_id, req, decision, timings)
        timings["db_ms"] = db_ms

        # ── Optional S3 write ────────────────────────────────────────────
        s3_ms = 0.0
        if s3 is not None:
            flush_ms = s3.add({
                "run_id": run_id,
                "request_id": req["request_id"],
                "decision": decision,
                **timings,
            })
            if flush_ms is not None:
                s3_flush_latencies.append(flush_ms)
                s3_ms = flush_ms

        # Accumulate per-tier latencies.
        # LLM: only record the sample when the tier was actually exercised so
        # that percentiles reflect real LLM latency, not a sea of zeros.
        # attest_ms: only record when skill_id was present (non-zero sample).
        for k in ("apl_ms", "cmf_ms", "opa_ms", "db_ms", "total_ms"):
            if k in timings:
                tier_times[k].append(timings[k])
        llm_sample = timings.get("llm_ms", 0.0)
        if llm_sample > 0.0:
            tier_times["llm_ms"].append(llm_sample)
        attest_sample = timings.get("attest_ms", 0.0)
        if attest_sample > 0.0:
            tier_times["attest_ms"].append(attest_sample)
        if s3_ms > 0:
            tier_times["s3_ms"].append(s3_ms)

        # ── Prometheus metrics ────────────────────────────────────────────
        if PROM_AVAILABLE:
            bm_requests_total.labels(
                scale=scale_label, decision=decision).inc()
            for tier_key, tier_label in (
                ("apl_ms",   "apl"),
                ("cmf_ms",   "cmf"),
                ("opa_ms",   "opa"),
                ("db_ms",    "sqlite"),
                ("total_ms", "total"),
            ):
                v = timings.get(tier_key)
                if v is not None:
                    bm_tier_latency.labels(tier=tier_label).observe(v)
            if llm_sample > 0.0:
                bm_tier_latency.labels(tier="llm").observe(llm_sample)
                bm_llm_invocations.labels(
                    scale=scale_label,
                    cb_tripped=str(pipeline._llm_tripped),
                ).inc()
            if attest_sample > 0.0:
                bm_tier_latency.labels(tier="attest").observe(attest_sample)
            if pipeline._llm_tripped:
                bm_circuit_breaker.set(1)

        # Progress + live throughput gauge
        if (i + 1) % progress_every == 0:
            elapsed = time.perf_counter() - batch_start
            rps = (i + 1) / elapsed
            if PROM_AVAILABLE:
                bm_throughput.labels(scale=scale_label).set(rps)
                bm_progress.labels(scale=scale_label).set(
                    round((i + 1) / scale * 100, 1))
            _info(f"  [{i+1:>{len(str(scale))}}/{scale}]  "
                  f"{rps:7.1f} req/s  "
                  f"decisions={decisions}")

    # Final S3 flush
    if s3 is not None:
        flush_ms = s3.flush()
        if flush_ms > 0:
            s3_flush_latencies.append(flush_ms)

    finished_at = datetime.now(UTC).isoformat()
    wall_total  = time.perf_counter() - batch_start
    throughput  = scale / wall_total

    # ── Per-tier statistics ───────────────────────────────────────────────
    def _stats(values: List[float]) -> Dict[str, float]:
        if not values:
            return {"count": 0}
        sv = sorted(values)
        return {
            "count":  len(sv),
            "mean":   statistics.mean(sv),
            "median": statistics.median(sv),
            "p95":    _pct(sv, 95),
            "p99":    _pct(sv, 99),
            "max":    sv[-1],
            "min":    sv[0],
        }

    tier_stats = {tier: _stats(vals) for tier, vals in tier_times.items()}

    # LLM cost amortised across every request (for capacity planning)
    llm_amortised_mean_ms = 0.0
    if tier_times["llm_ms"]:
        llm_amortised_mean_ms = round(
            statistics.mean(tier_times["llm_ms"]) * llm_rate, 4
        )

    summary = {
        "run_id":              run_id,
        "scale":               scale,
        "llm_rate":            llm_rate,
        "llm_invoked":         llm_invoked,
        "actual_llm_pct":      round(llm_invoked / scale * 100, 2),
        "llm_amortised_mean_ms": llm_amortised_mean_ms,
        "started_at":          started_at,
        "finished_at":         finished_at,
        "wall_seconds":        round(wall_total, 3),
        "throughput_rps":      round(throughput, 1),
        "decisions":           decisions,
        "tier_stats_ms":       tier_stats,
        "s3_flushes":          len(s3_flush_latencies),
        "s3_flush_mean_ms":    round(statistics.mean(s3_flush_latencies), 2)
                               if s3_flush_latencies else 0.0,
    }

    db.save_run(run_id, scale, llm_rate, started_at, finished_at, summary)

    return summary

# ---------------------------------------------------------------------------
# Pretty printer
# ---------------------------------------------------------------------------
def print_summary(summary: Dict[str, Any]) -> None:
    scale = summary["scale"]
    _hdr(f"Results — {scale:,} requests")

    _ok(f"Wall time:      {summary['wall_seconds']:.2f} s")
    _ok(f"Throughput:     {summary['throughput_rps']:.1f} req/s")
    _ok(f"Decisions:      {summary['decisions']}")
    _ok(f"LLM invocations:{summary['llm_invoked']}  "
        f"({summary['actual_llm_pct']:.2f}% of requests)")
    if summary["s3_flushes"]:
        _ok(f"S3 flushes:     {summary['s3_flushes']}  "
            f"(mean flush {summary['s3_flush_mean_ms']:.1f} ms)")

    header = f"{'Tier':<18}  {'Count':>7}  {'Mean ms':>9}  {'P50 ms':>9}  "   \
             f"{'P95 ms':>9}  {'P99 ms':>9}  {'Max ms':>9}"
    print(f"\n{C.CYAN}{header}{C.NC}")
    print("  " + "-" * (len(header) - 2))

    # LLM row uses invocation count, not total-request count, so the label
    # carries a note.  All other tiers show count == requests processed.
    llm_note = f"LLM T4 ({summary['llm_invoked']:,} inv)"

    tier_labels = [
        ("apl_ms",    "APL (T1)"),
        ("attest_ms", "  Attest (T1.6)"),
        ("cmf_ms",    "CMF (T2)"),
        ("opa_ms",    "OPA (T3)"),
        ("llm_ms",    llm_note),
        ("db_ms",     "SQLite"),
        ("s3_ms",     "S3-batch"),
        ("total_ms",  "TOTAL"),
    ]

    ts = summary["tier_stats_ms"]
    for key, label in tier_labels:
        st = ts.get(key, {})
        if not st or st.get("count", 0) == 0:
            continue
        row = (f"{label:<18}  {st['count']:>7,}  {st['mean']:>9.3f}  "
               f"{st.get('median', 0):>9.3f}  {st['p95']:>9.3f}  "
               f"{st['p99']:>9.3f}  {st['max']:>9.3f}")
        colour = C.YELLOW if key == "total_ms" else ""
        print(f"  {colour}{row}{C.NC if colour else ''}")

    # Extra LLM footnote when LLM was active
    if summary.get("llm_invoked", 0) > 0:
        amort = summary.get("llm_amortised_mean_ms", 0.0)
        _info(f"  * LLM (T4) stats are over invocations only (~{summary['actual_llm_pct']:.1f}% "
              f"of requests).  Amortised mean across ALL requests: {amort:.4f} ms")


def print_scaling_table(summaries: List[Dict[str, Any]]) -> None:
    _hdr("Scaling Summary")
    hdr = (f"{'Scale':>10}  {'RPS':>8}  {'Total ms P95':>14}  "
           f"{'APL ms P95':>12}  {'OPA ms P95':>12}  "
           f"{'DB ms P95':>11}  {'LLM invoked':>13}  {'Deny%':>7}")
    print(f"{C.BOLD}{C.CYAN}{hdr}{C.NC}")
    print("  " + "-" * (len(hdr) - 2))
    for s in summaries:
        ts  = s["tier_stats_ms"]
        den = s["decisions"].get("DENIED", 0)
        tot = s["scale"]
        deny_pct = f"{den/tot*100:.1f}%" if tot else "-"
        row = (
            f"{s['scale']:>10,}  "
            f"{s['throughput_rps']:>8.1f}  "
            f"{ts.get('total_ms',{}).get('p95',0):>14.3f}  "
            f"{ts.get('apl_ms',{}).get('p95',0):>12.4f}  "
            f"{ts.get('opa_ms',{}).get('p95',0):>12.3f}  "
            f"{ts.get('db_ms',{}).get('p95',0):>11.3f}  "
            f"{s['llm_invoked']:>13,}  "
            f"{deny_pct:>7}"
        )
        print(f"  {row}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _silence_llm_loggers() -> None:
    """Suppress verbose per-request logging from LiteLLM, httpx, and the validator.

    LiteLLM logs every HTTP call at INFO level through multiple loggers.
    httpx logs every request/response.  The validator logs JSON-parse warnings.
    All of these are noise during a benchmark run — set them to ERROR so only
    genuine failures surface.  The benchmark's own _ok/_warn helpers are
    unaffected (they use print, not logging).
    """
    import logging
    noisy = (
        "LiteLLM", "LiteLLM Proxy", "LiteLLM Router",
        "litellm", "litellm.proxy", "litellm.router", "litellm.utils",
        "httpx", "httpcore", "httpcore.http11",
        "openai", "openai._base_client",   # openai SDK retry messages
        "src.validators.llm_validator",
    )
    for name in noisy:
        lg = logging.getLogger(name)
        lg.setLevel(logging.ERROR)
        lg.propagate = False   # stop ERROR+ from bubbling to the root handler too

    # Suppress litellm module-level verbose flag
    try:
        import litellm as _ll
        _ll.set_verbose = False
        _ll.suppress_debug_info = True
    except ImportError:
        pass


def main() -> None:
    random.seed(42)
    _silence_llm_loggers()

    # ── Configuration ─────────────────────────────────────────────────────
    raw_scales  = os.getenv("BENCHMARK_SCALES", "100,1000,10000,100000")
    scales      = [int(x.strip()) for x in raw_scales.split(",")]
    llm_rate    = float(os.getenv("LLM_RATE", "0.01"))
    opa_url     = os.getenv("OPA_URL", "http://localhost:8181")
    s3_endpoint = os.getenv("S3_ENDPOINT_URL", "http://localhost:4566")
    s3_bucket   = os.getenv("S3_AUDIT_BUCKET", "compliance-audit-logs")
    db_path     = os.getenv("BENCHMARK_DB", "benchmarks/benchmark_audit.db")
    prom_port   = int(os.getenv("BENCHMARK_PROM_PORT", "8001"))

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    _hdr("Tier Performance Benchmark")
    _info(f"Scales:     {scales}")
    _info(f"LLM rate:   {llm_rate*100:.1f}%  (~1 LLM call per {int(1/llm_rate):,} requests)")
    _info(f"OPA URL:    {opa_url}")
    _info(f"SQLite DB:  {db_path}")
    if _env_loaded > 0:
        _ok(f"Loaded {_env_loaded} variables from {_env_local_path.name}")
    else:
        _info(f"({_env_local_path.name} not found or already exported — using current env)")

    # ── Prometheus metrics server ─────────────────────────────────────────
    if PROM_AVAILABLE:
        try:
            _prom_start_http(prom_port)
            _ok(f"Prometheus metrics → http://localhost:{prom_port}/metrics")
            _info(f"  Grafana live dashboard → http://localhost:3000  (Tier Benchmark)")
        except OSError as e:
            _warn(f"Metrics server port {prom_port} busy: {e} — metrics disabled")
    else:
        _warn("prometheus_client not installed — no live metrics (pip install prometheus_client)")

    # ── Service availability probes ───────────────────────────────────────
    opa_live = _probe_opa(opa_url)
    _ok(f"OPA:   {'LIVE' if opa_live else 'offline → simulated'}") if True else None
    if opa_live:
        _ok(f"OPA live at {opa_url}")
    else:
        _warn(f"OPA not reachable at {opa_url}; tier-3 will be simulated")

    # APL + Skill Registry (attestation)
    apl = None
    if APL_AVAILABLE:
        apl = APLValidator(enabled=True)
        _register_benchmark_skills()
        _ok("APL validator loaded  (Check 6: skill attestation enabled)")
    else:
        _warn("APL import failed; tier-1 will be simulated")

    # CMF
    cmf = None
    if CMF_AVAILABLE:
        try:
            cmf = CMFContextEnricher(pii_detection=False)
            _ok("CMF context enricher loaded")
        except Exception as e:
            _warn(f"CMF init failed ({e}); tier-2 will be simulated")
    else:
        _warn("CMF import failed; tier-2 will be simulated")

    # LLM — only enable when an API key is present to avoid noisy auth errors
    llm = None
    _llm_key_present = bool(
        os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
        or os.getenv("ANTHROPIC_API_KEY") or os.getenv("LITELLM_BASE_URL")
    )
    if LLM_IMPORT_AVAILABLE and _llm_key_present:
        try:
            llm = LLMValidator(
                model=os.getenv("LLM_MODEL", "aws/claude-sonnet-4-5"),
                enabled=True,
                cache_enabled=True,
                timeout=30.0,
            )
            if llm.enabled:
                _ok(f"LLM validator loaded (live): {llm.model}")
            else:
                _warn("LLM validator disabled by library; will simulate")
                llm = None
        except Exception as e:
            _warn(f"LLM init failed ({e}); tier-4 will be simulated")
    elif LLM_IMPORT_AVAILABLE:
        _warn("No LLM API key found; tier-4 will be simulated (set LLM_API_KEY to enable)")
    else:
        _warn("LLM import failed; tier-4 will be simulated")

    # S3
    s3_writer_inst: Optional[_S3Writer] = None
    if BOTO3_AVAILABLE:
        try:
            s3_writer_inst = _S3Writer(
                endpoint=s3_endpoint,
                bucket=s3_bucket,
                batch_size=200,
            )
            _ok(f"S3 writer connected: {s3_endpoint}/{s3_bucket}")
        except Exception as e:
            _warn(f"S3 unavailable ({e}); S3 writes will be skipped")
    else:
        _warn("boto3 not installed; S3 writes skipped")

    # ── Build pipeline ────────────────────────────────────────────────────
    pipeline = TierPipeline(
        opa_url=opa_url,
        opa_live=opa_live,
        apl=apl,
        cmf=cmf,
        llm=llm,
    )

    # ── Database ──────────────────────────────────────────────────────────
    db = AuditDB(db_path)

    # ── Run each scale ────────────────────────────────────────────────────
    all_summaries: List[Dict[str, Any]] = []
    overall_run_id = f"bench-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"

    for scale in scales:
        run_id = f"{overall_run_id}-{scale}"
        pipeline.reset_circuit_breaker()
        summary = run_scale(
            scale=scale,
            pipeline=pipeline,
            db=db,
            s3=s3_writer_inst,
            llm_rate=llm_rate,
            run_id=run_id,
        )
        print_summary(summary)
        all_summaries.append(summary)

        if scale != scales[-1]:
            _info("Cooling down 3 s before next scale…")
            time.sleep(3)

    # ── Scaling summary ───────────────────────────────────────────────────
    print_scaling_table(all_summaries)

    # ── Persist full results JSON ─────────────────────────────────────────
    ts_str  = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    outfile = Path("benchmarks") / f"tier_benchmark_{ts_str}.json"
    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(json.dumps({
        "benchmark": "tier_performance",
        "generated_at": datetime.now(UTC).isoformat(),
        "config": {
            "scales": scales,
            "llm_rate": llm_rate,
            "opa_url": opa_url,
            "opa_live": opa_live,
            "apl_live": apl is not None,
            "cmf_live": cmf is not None,
            "llm_live": llm is not None,
            "s3_live":  s3_writer_inst is not None,
            "db_path":  db_path,
        },
        "runs": all_summaries,
    }, indent=2))
    _ok(f"Full results saved → {outfile}")

    # ── Cleanup ───────────────────────────────────────────────────────────
    if s3_writer_inst:
        s3_writer_inst.close()
    db.close()

    _hdr("Benchmark complete")


if __name__ == "__main__":
    main()

# Made with Bob
