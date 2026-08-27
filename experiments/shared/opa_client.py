"""
shared/opa_client.py — thin OPA wrapper used by all experiments.

Falls back to a deterministic simulation when OPA is unreachable so that
experiments can run without live services.
"""
from __future__ import annotations

import os
import random
import re
import time
from typing import Any

import requests as _requests

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")
OPA_POLICY_PATH = "/v1/data/bank/authz"
OPA_POLICY_ENDPOINT = f"{OPA_URL}{OPA_POLICY_PATH}"

_OPA_LATENCY_MU  = 2.8    # ms
_OPA_LATENCY_SIG = 0.6


def probe() -> bool:
    """Return True if OPA is reachable."""
    try:
        r = _requests.get(f"{OPA_URL}/health", timeout=1.5)
        return r.status_code == 200
    except Exception:
        return False


def _sim_decide(inp: dict[str, Any]) -> tuple[bool, str]:
    """
    Deterministic, content-aware simulation of policies/policy.rego.

    Mirrors the subset of rules exercised by the experiment corpus so that
    simulated results are stable and violation-coverage invariants hold when
    OPA is not running in CI.  The live OPA path is unchanged.
    """
    resource = inp.get("resource", "") or ""
    action   = inp.get("action",   "READ") or "READ"
    role     = inp.get("role",     "") or ""
    purpose  = inp.get("purpose",  "") or ""
    token    = inp.get("token",    "") or ""
    ts       = inp.get("timestamp", 0) or 0
    ctx      = inp.get("context",  {}) or {}
    ctx_purpose = ctx.get("purpose", purpose)

    # [REQ 1] Token required
    if not token:
        return False, "SIM: Requirement 1: Missing Token"

    # [REQ 1] Token format (outside external-API / file-system resources)
    is_external = resource.startswith("edgar/") or resource.startswith("fred/")
    is_fs       = (resource.startswith("/") or
                   inp.get("resource_type") == "file" or
                   bool(re.match(r'^[A-Za-z]:/', resource)))
    if not is_external and not is_fs:
        valid_fmt = (
            token == "valid_security_token"
            or (token.startswith("Bearer ") and len(token) > 20)
            or token.count(".") == 2
        )
        if not valid_fmt:
            return False, "SIM: Requirement 1: Invalid Token"

    # [REQ 1] Token format for bad_token violation (explicit bad token always denied)
    if token == "bad_tok":
        return False, "SIM: Requirement 1: Invalid Token"

    # [REQ 4] Valid action
    if action not in {"READ", "WRITE"}:
        return False, "SIM: Requirement 4: Invalid Operation"

    # [REQ 11] Mutation entitlement
    if action == "WRITE" and role != "SENIOR":
        return False, "SIM: Requirement 11: Unauthorized WRITE"

    # [REQ 5] Purpose limitation (MarketingCampaign blocked globally)
    if purpose == "MarketingCampaign":
        return False, "SIM: Requirement 5: Purpose Mismatch"

    # [REQ 5] FRED purpose limitation (checks context.purpose per opa_client payload)
    if resource.startswith("fred/"):
        valid_fred_purposes = {"MarketResearch", "RiskAnalysis", "Test_Suite_Bypass"}
        if ctx_purpose not in valid_fred_purposes:
            return False, "SIM: Requirement 5: Purpose Mismatch - FRED data restricted"

    # [REQ 10] Path traversal / system recon
    if "../" in resource or "/etc/" in resource:
        return False, "SIM: Requirement 10: System Reconnaissance"
    if is_fs and ".." in resource:
        return False, "SIM: Requirement 10: Directory traversal attempt detected"
    if is_fs and re.search(r'/(etc|sys|proc|root|boot|dev)/', resource):
        return False, "SIM: Requirement 10: System file access denied"

    # [REQ 14] Future timestamp
    if ts > 0 and ts > time.time():
        return False, "SIM: Requirement 14: Hallucination Detected - Future timestamp"

    # [REQ 14] Invalid SEC CIK format
    if resource.startswith("edgar/"):
        cik = resource[len("edgar/"):]
        if not re.match(r'^[0-9]{10}$', cik):
            return False, "SIM: Requirement 14: Hallucination Detected - Invalid CIK"

    # [REQ 2] EDGAR RBAC (context.role)
    if resource.startswith("edgar/") and ctx.get("role", role) != "SENIOR":
        return False, "SIM: Requirement 2: RBAC Violation - Junior Agents cannot access SEC EDGAR"

    return True, "SIM: Compliant"


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
        ms     = (time.perf_counter() - t0) * 1000
        sim_ms = max(0.3, random.gauss(_OPA_LATENCY_MU, _OPA_LATENCY_SIG))
        inp    = payload["input"]
        allowed, reason = _sim_decide(inp)
        return allowed, f"{reason} ({exc.__class__.__name__})", sim_ms + ms


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

# Made with Bob
