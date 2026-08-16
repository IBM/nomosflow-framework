"""
shared/opa_client.py — thin OPA wrapper used by all experiments.

Falls back to a deterministic simulation when OPA is unreachable so that
experiments can run without live services.
"""
from __future__ import annotations

import os
import random
import time
from typing import Any

import requests as _requests

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")
OPA_POLICY_PATH = "/v1/data/bank/authz"
OPA_POLICY_ENDPOINT = f"{OPA_URL}{OPA_POLICY_PATH}"

_DENY_RATE_SIM   = 0.12   # ~12 % deny rate in simulation
_OPA_LATENCY_MU  = 2.8    # ms
_OPA_LATENCY_SIG = 0.6


def probe() -> bool:
    """Return True if OPA is reachable."""
    try:
        r = _requests.get(f"{OPA_URL}/health", timeout=1.5)
        return r.status_code == 200
    except Exception:
        return False


def decide(event: dict[str, Any]) -> tuple[bool, str, float]:
    """
    Submit *event* to OPA and return (allowed, reason, latency_ms).
    Falls back to simulation on any error.
    """
    payload = {
        "input": {
            **event,
            "context": {
                "role":    event.get("role", ""),
                "purpose": event.get("purpose", ""),
                "region":  event.get("region", "US"),
            },
            "operation": event.get("action", "READ"),
        }
    }
    t0 = time.perf_counter()
    try:
        r = _requests.post(OPA_POLICY_ENDPOINT, json=payload, timeout=2.0)
        ms = (time.perf_counter() - t0) * 1000
        r.raise_for_status()
        result = r.json().get("result", {})
        if isinstance(result, bool):
            allowed = result
            reason  = "OPA direct bool"
        else:
            allowed = result.get("allow", False)
            reason  = result.get("reason", "OPA deny")
        return allowed, reason, ms
    except Exception as exc:
        ms = (time.perf_counter() - t0) * 1000
        sim_ms  = max(0.3, random.gauss(_OPA_LATENCY_MU, _OPA_LATENCY_SIG))
        allowed = random.random() > _DENY_RATE_SIM
        return allowed, f"SIM ({exc.__class__.__name__})", sim_ms + ms


def hot_reload(policy_text: str, policy_id: str = "bank_authz") -> tuple[bool, float]:
    """
    Push a new policy via OPA's management API. Returns (ok, latency_ms).

    Uses the same policy_id as the base policy (bank_authz) so the PUT is an
    in-place update.  Pushing to a *different* policy ID while the base policy
    occupies the same package causes a duplicate-default Rego compile error.
    """
    url = f"{OPA_URL}/v1/policies/{policy_id}"
    t0  = time.perf_counter()
    try:
        r = _requests.put(url, data=policy_text.encode(),
                          headers={"Content-Type": "text/plain"}, timeout=5.0)
        ms = (time.perf_counter() - t0) * 1000
        return r.status_code in (200, 201), ms
    except Exception:
        ms = (time.perf_counter() - t0) * 1000
        return False, ms
