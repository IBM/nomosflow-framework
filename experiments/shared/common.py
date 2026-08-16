"""
shared/common.py — shared utilities for all NomosFlow VLDB paper experiments.

Provides:
  - _pct()          percentile on pre-sorted list (no numpy)
  - _stats()        mean/p50/p95/p99/max from a list of floats
  - make_request()  synthetic compliance request generator
  - RESULTS_DIR     canonical results path
  - save_result()   write raw JSON + return path
  - load_env()      load .env.local from repo root
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Repo root on sys.path so `src.*` imports work from any CWD
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ---------------------------------------------------------------------------
# Load .env.local once
# ---------------------------------------------------------------------------
def load_env() -> int:
    env_path = _REPO_ROOT / ".env.local"
    if not env_path.is_file():
        return 0
    loaded = 0
    for raw in env_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:]
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v
            loaded += 1
    return loaded

load_env()

# ---------------------------------------------------------------------------
# Results directory
# ---------------------------------------------------------------------------
RESULTS_DIR = Path(
    os.getenv("RESULTS_DIR", str(_REPO_ROOT / "experiments" / "results"))
)

def result_dir(exp_id: str) -> Path:
    d = RESULTS_DIR / exp_id
    d.mkdir(parents=True, exist_ok=True)
    return d

def save_result(exp_id: str, data: dict[str, Any], label: str = "") -> Path:
    d = result_dir(exp_id)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = f"_{label}" if label else ""
    path = d / f"raw{suffix}_{ts}.json"
    path.write_text(json.dumps(data, indent=2, default=str))
    print(f"  ✓ saved {path.relative_to(_REPO_ROOT)}")
    return path

# ---------------------------------------------------------------------------
# Percentile helpers (no numpy)
# ---------------------------------------------------------------------------
def _pct(sorted_data: list[float], p: float) -> float:
    if not sorted_data:
        return 0.0
    idx = (p / 100.0) * (len(sorted_data) - 1)
    lo, hi = int(idx), min(int(idx) + 1, len(sorted_data) - 1)
    return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * (idx - lo)

def _stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"count": 0, "mean": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
    s = sorted(values)
    return {
        "count": len(s),
        "mean":  sum(s) / len(s),
        "p50":   _pct(s, 50),
        "p95":   _pct(s, 95),
        "p99":   _pct(s, 99),
        "max":   s[-1],
    }

# ---------------------------------------------------------------------------
# Synthetic request generator
# ---------------------------------------------------------------------------
_RESOURCES = [
    "fred/GDP", "fred/UNRATE", "edgar/0000051143", "edgar/0001018724",
    "fred/DFF", "edgar/0000320193", "fred/CPIAUCSL", "edgar/0000789019",
]
_ROLES    = ["JUNIOR", "SENIOR", "ADMIN"]
_ACTIONS  = ["READ", "WRITE"]
_PURPOSES = ["MarketResearch", "RiskAnalysis", "AuditReview", "Compliance"]
_VALID_TOKEN = (
    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.benchmark.signature"
)
_TS_BASE  = 1704067200   # 2024-01-01 UTC
_TS_RANGE = 365 * 24 * 3600


def make_request(
    idx: int = 0,
    agent_id: str | None = None,
    *,
    invalid_token_prob: float = 0.05,
    llm_rate: float = 0.01,
    skill_id: str | None = None,
) -> dict[str, Any]:
    role   = random.choice(_ROLES)
    action = random.choice(_ACTIONS)
    token  = _VALID_TOKEN if random.random() > invalid_token_prob else "bad_tok"
    aid    = agent_id or random.choice([f"agent-{i:04d}" for i in range(1, 51)])
    req: dict[str, Any] = {
        "request_id":   str(uuid.uuid4()),
        "agent_id":     aid,
        "resource":     random.choice(_RESOURCES),
        "action":       action,
        "purpose":      random.choice(_PURPOSES),
        "timestamp":    _TS_BASE + random.randint(0, _TS_RANGE),
        "token":        token,
        "role":         role,
        "metadata": {
            "token":          token,
            "role":           role,
            "user_id":        f"user-{(idx % 200):04d}",
            "user_clearance": random.choice(["public", "internal", "confidential"]),
            "department":     random.choice(["finance", "risk", "compliance", "eng"]),
        },
        "_route_to_llm": random.random() < llm_rate,
    }
    if skill_id:
        req["skill_id"]      = skill_id
        req["skill_version"] = "1.0.0"
    return req


def make_violation_request(violation_type: str) -> dict[str, Any]:
    """Return a request guaranteed to trigger a specific violation class."""
    base = make_request(invalid_token_prob=0.0, llm_rate=0.0)
    if violation_type == "rbac_write":
        base["role"] = "JUNIOR"
        base["action"] = "WRITE"
        base["metadata"]["role"] = "JUNIOR"
    elif violation_type == "purpose_mismatch":
        base["purpose"] = "MarketingCampaign"
    elif violation_type == "bad_token":
        base["token"] = "bad_tok"
        base["metadata"]["token"] = "bad_tok"
    elif violation_type == "hallucinated_cik":
        base["resource"] = "edgar/FAKE12345"
    elif violation_type == "future_timestamp":
        base["timestamp"] = int(time.time()) + 86400 * 365
    elif violation_type == "path_traversal":
        base["resource"] = "/../etc/passwd"
    elif violation_type == "purpose_bypass_fred":
        base["resource"] = "fred/GDP"
        base["purpose"]  = "PersonalUse"
    elif violation_type == "benign":
        base["role"]    = "SENIOR"
        base["action"]  = "READ"
        base["purpose"] = "MarketResearch"
        base["resource"] = "fred/GDP"
        base["token"]   = _VALID_TOKEN
        base["metadata"]["role"]  = "SENIOR"
        base["metadata"]["token"] = _VALID_TOKEN
    return base


# ---------------------------------------------------------------------------
# Timing helper
# ---------------------------------------------------------------------------
class Timer:
    def __enter__(self):
        self._t = time.perf_counter()
        return self
    def __exit__(self, *_):
        self.ms = (time.perf_counter() - self._t) * 1000

# ---------------------------------------------------------------------------
# Digest helper for deterministic request fingerprints
# ---------------------------------------------------------------------------
def req_digest(req: dict) -> str:
    clean = {k: v for k, v in req.items() if not k.startswith("_")}
    return hashlib.sha256(
        json.dumps(clean, sort_keys=True).encode()
    ).hexdigest()[:12]
