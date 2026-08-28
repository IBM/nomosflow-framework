"""
skill_registry.py — In-process Skill Registry with HMAC-based Attestation
==========================================================================

Provides a lightweight, zero-external-dependency registry that:

  1. Stores capability contracts for registered skills (what tables/actions
     a skill is allowed to use, max rows, allowed jurisdictions, etc.).
  2. Signs each contract at registration time with an HMAC-SHA256 over the
     canonical JSON representation of the contract.
  3. Verifies the stored signature at runtime so any tampering — or an
     unregistered skill_id — is detected before the request reaches OPA.

Design constraints (to keep this compatible with APL's sub-µs target):
  • No network calls, no file I/O during verify().
  • LRU cache on verify() so repeated checks for the same (skill_id, version)
    hit the cache without re-computing the HMAC.
  • The signing secret is read once from NOMOSFLOW_ATTESTATION_SECRET (env);
    it falls back to a per-process random key so the module always works in
    unit-test environments without configuration.

Usage
-----
    from src.validators.skill_registry import SkillRegistry

    registry = SkillRegistry()           # singleton – one per process
    registry.register(
        skill_id="customer_churn",
        version="1.0.0",
        contract={
            "allowed_resources": ["fred/GDP", "edgar/0000051143"],
            "allowed_actions":   ["READ"],
            "max_rows":          100_000,
            "allowed_jurisdictions": ["US"],
        },
    )

    # At request time (called by APLValidator):
    ok, reason = registry.verify(
        skill_id="customer_churn",
        version="1.0.0",
        action="READ",
        resource="fred/GDP",
    )
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any


# ── module-level secret ───────────────────────────────────────────────────────
# Read once.  In production, set NOMOSFLOW_ATTESTATION_SECRET to a stable
# base-64 or hex string so signatures survive process restarts.
# In dev/test the random fallback is fine — skills must be re-registered on
# each start, which is the expected behaviour for an in-process registry.

_SECRET: bytes = os.getenv(
    "NOMOSFLOW_ATTESTATION_SECRET", ""
).encode() or secrets.token_bytes(32)


# ── data model ────────────────────────────────────────────────────────────────

@dataclass
class SkillRecord:
    """One registered skill version with its contract and HMAC seal."""
    skill_id:  str
    version:   str
    contract:  dict[str, Any]
    signature: str              # hex HMAC-SHA256 of canonical contract JSON
    registered_at: float = field(default_factory=time.time)


# ── registry ──────────────────────────────────────────────────────────────────

class SkillRegistry:
    """
    Thread-safe in-process registry.

    Instantiate once per process (or use the module-level singleton returned
    by ``get_registry()``).
    """

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], SkillRecord] = {}
        self._lock = threading.Lock()

    # ── write path ───────────────────────────────────────────────────────────

    def register(
        self,
        skill_id: str,
        version: str,
        contract: dict[str, Any],
    ) -> str:
        """
        Register a skill and return its HMAC signature (the "seal").

        The signature is deterministic for a given (contract, secret) pair,
        so repeated registration of the same skill is idempotent.
        """
        sig = _sign(contract)
        record = SkillRecord(
            skill_id=skill_id,
            version=version,
            contract=contract,
            signature=sig,
        )
        with self._lock:
            self._store[(skill_id, version)] = record
            # Invalidate any cached verify() result for this key.
            self._verify_cached.cache_clear()
        return sig

    def revoke(self, skill_id: str, version: str) -> bool:
        """Remove a skill from the registry. Returns True if it existed."""
        with self._lock:
            existed = (skill_id, version) in self._store
            self._store.pop((skill_id, version), None)
            self._verify_cached.cache_clear()
        return existed

    # ── read path (hot) ──────────────────────────────────────────────────────

    def verify(
        self,
        skill_id: str,
        version: str,
        action: str,
        resource: str,
    ) -> tuple[bool, str]:
        """
        Verify that *skill_id@version* is registered, its contract seal is
        intact, and the requested (action, resource) pair is within its
        declared capability contract.

        Returns (True, "") on success or (False, reason) on any failure.

        Hot path: results are LRU-cached per (skill_id, version, action,
        resource) tuple so repeated identical checks are near-zero cost.
        The cache is invalidated whenever register() or revoke() is called.
        """
        return self._verify_cached(skill_id, version, action, resource)

    @lru_cache(maxsize=2048)
    def _verify_cached(
        self,
        skill_id: str,
        version: str,
        action: str,
        resource: str,
    ) -> tuple[bool, str]:
        record = self._store.get((skill_id, version))
        if record is None:
            return False, f"APL[attest]: skill '{skill_id}@{version}' not registered"

        # 1 — Re-derive the HMAC and compare with stored seal.
        expected = _sign(record.contract)
        if not hmac.compare_digest(expected, record.signature):
            return False, f"APL[attest]: contract seal broken for '{skill_id}@{version}'"

        contract = record.contract

        # 2 — Action allowed by contract?
        allowed_actions = contract.get("allowed_actions", [])
        if allowed_actions and action not in allowed_actions:
            return (
                False,
                f"APL[attest]: action '{action}' not in contract for '{skill_id}@{version}' "
                f"(allowed: {allowed_actions})",
            )

        # 3 — Resource allowed by contract?
        allowed_resources = contract.get("allowed_resources", [])
        if allowed_resources and resource not in allowed_resources:
            return (
                False,
                f"APL[attest]: resource '{resource}' not in contract for "
                f"'{skill_id}@{version}' (allowed: {allowed_resources})",
            )

        return True, ""

    def list_skills(self) -> list[dict[str, Any]]:
        """Return a summary list of all registered skills (for observability)."""
        with self._lock:
            return [
                {
                    "skill_id":       r.skill_id,
                    "version":        r.version,
                    "registered_at":  r.registered_at,
                    "allowed_actions":   r.contract.get("allowed_actions", []),
                    "allowed_resources": r.contract.get("allowed_resources", []),
                }
                for r in self._store.values()
            ]


# ── helpers ───────────────────────────────────────────────────────────────────

def _sign(contract: dict[str, Any]) -> str:
    """Return the hex HMAC-SHA256 of the canonical JSON of *contract*."""
    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(_SECRET, canonical, hashlib.sha256).hexdigest()


# ── module-level singleton ────────────────────────────────────────────────────

_default_registry: SkillRegistry | None = None
_registry_lock = threading.Lock()


def get_registry() -> SkillRegistry:
    """Return the process-level singleton registry (lazy-initialised)."""
    global _default_registry
    if _default_registry is None:
        with _registry_lock:
            if _default_registry is None:
                _default_registry = SkillRegistry()
    return _default_registry

# Made with Bob
