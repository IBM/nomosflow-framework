"""
APL (Authorization Policy Layer) - Fast-Path Authorization
Implements sub-microsecond authorization checks for common cases
"""

import time
import re
from typing import Dict, Any, Tuple, Optional
from functools import lru_cache

# ── Attestation registry (optional import; APL works without it) ──────────────
try:
    from src.validators.skill_registry import get_registry as _get_registry
    _REGISTRY_AVAILABLE = True
except ImportError:
    _get_registry = None          # type: ignore[assignment]
    _REGISTRY_AVAILABLE = False


class APLValidator:
    """
    Authorization Policy Layer - Fast-path authorization checks

    Handles common authorization patterns with minimal overhead:
    - Token validation (basic format checks)
    - Role-based access control (RBAC)
    - Resource pattern matching
    - Action validation
    - Skill attestation (Check 6): verifies that the requesting skill is
      registered, its capability contract seal is intact, and the requested
      (action, resource) pair falls within the declared contract bounds.

    Performance target: < 1 microsecond per check (cached path)

    Attestation check
    -----------------
    When a request carries ``skill_id`` and ``skill_version`` fields the
    validator looks up the skill in the process-level SkillRegistry.  If the
    skill is not registered, its contract seal is broken, or the requested
    (action, resource) pair lies outside the contract, the request is DENIED
    immediately — before OPA or LLM are ever invoked.

    The check is skipped (pass-through) when:
      • ``skill_id`` is absent from the request (non-skill requests are
        unaffected — backwards-compatible).
      • ``attestation_enabled=False`` was passed to the constructor.
      • The SkillRegistry module could not be imported.
    """

    # Valid roles
    VALID_ROLES = {'JUNIOR', 'SENIOR', 'ADMIN'}

    # Valid actions
    VALID_ACTIONS = {'READ', 'WRITE'}

    # Resource patterns (compiled regex for speed)
    RESOURCE_PATTERNS = {
        'fred':  re.compile(r'^fred/[A-Z0-9_]+$'),
        'edgar': re.compile(r'^edgar/\d{10}$'),
        'local': re.compile(r'^/[a-zA-Z0-9/_.-]+$'),
    }

    def __init__(self, enabled: bool = True, attestation_enabled: bool = True):
        """
        Initialize APL validator.

        Args:
            enabled:             Enable/disable all APL validation.
            attestation_enabled: Enable/disable Check 6 (skill attestation).
                                 Defaults to True; set False to restore
                                 pre-attestation behaviour in environments
                                 that have not yet registered skills.
        """
        self.enabled = enabled
        self.attestation_enabled = attestation_enabled and _REGISTRY_AVAILABLE
        self._stats = {
            'total_checks': 0,
            'approved': 0,
            'denied': 0,
            'bypassed': 0,
            'attest_hits': 0,        # requests carrying skill_id
            'attest_denied': 0,      # denied specifically by attestation
        }
    
    @lru_cache(maxsize=1000)
    def _validate_token_format(self, token: str) -> bool:
        """
        Fast token format validation (cached)
        
        Args:
            token: JWT or bearer token
            
        Returns:
            True if token format is valid
        """
        if not token or len(token) < 10:
            return False
        
        # Basic JWT format check (header.payload.signature)
        if token.count('.') == 2:
            return True
        
        # Bearer token format
        if token.startswith('Bearer ') and len(token) > 20:
            return True
        
        return False
    
    @lru_cache(maxsize=100)
    def _validate_role(self, role: str) -> bool:
        """
        Fast role validation (cached)
        
        Args:
            role: User role
            
        Returns:
            True if role is valid
        """
        return role in self.VALID_ROLES
    
    @lru_cache(maxsize=100)
    def _validate_action(self, action: str) -> bool:
        """
        Fast action validation (cached)
        
        Args:
            action: Requested action
            
        Returns:
            True if action is valid
        """
        return action in self.VALID_ACTIONS
    
    @lru_cache(maxsize=1000)
    def _validate_resource_pattern(self, resource: str) -> Tuple[bool, str]:
        """
        Fast resource pattern validation (cached)
        
        Args:
            resource: Resource identifier
            
        Returns:
            Tuple of (is_valid, resource_type)
        """
        # Check FRED pattern
        if self.RESOURCE_PATTERNS['fred'].match(resource):
            return (True, 'fred')
        
        # Check EDGAR pattern
        if self.RESOURCE_PATTERNS['edgar'].match(resource):
            return (True, 'edgar')
        
        # Check local file pattern
        if self.RESOURCE_PATTERNS['local'].match(resource):
            return (True, 'local')
        
        return (False, 'unknown')
    
    def _validate_attestation(
        self,
        skill_id: str,
        skill_version: str,
        action: str,
        resource: str,
    ) -> Tuple[bool, str]:
        """
        Check 6: Skill attestation — capability-contract seal verification.

        Delegates to SkillRegistry.verify() whose hot path is LRU-cached,
        so this adds ~0.1 µs on a cache hit after the first call.

        Returns (True, "") when the skill is approved or when attestation is
        not applicable (module missing, check disabled, or no skill_id).
        """
        if not self.attestation_enabled:
            return True, ""
        registry = _get_registry()
        return registry.verify(skill_id, skill_version, action, resource)

    def validate(self, event: Dict[str, Any]) -> Tuple[bool, str, float]:
        """
        Fast-path authorization validation.

        Args:
            event: Request event with agent_id, resource, action, metadata.
                   Optional fields for attestation:
                     skill_id      (str) — identifies the calling skill
                     skill_version (str) — version to look up; defaults to "latest"

        Returns:
            Tuple of (approved, reason, latency_us)
        """
        start_time = time.perf_counter()

        # If disabled, bypass all checks
        if not self.enabled:
            self._stats['bypassed'] += 1
            latency_us = (time.perf_counter() - start_time) * 1_000_000
            return (True, "APL disabled", latency_us)

        self._stats['total_checks'] += 1

        # Extract fields
        agent_id = event.get('agent_id', '')
        resource = event.get('resource', '')
        action   = event.get('action', '')
        metadata = event.get('metadata', {})

        # Check token in metadata first, then fall back to top-level
        token = metadata.get('token', '') or event.get('token', '')
        role  = metadata.get('role',  '') or event.get('role',  '')

        # Check 1: Token format validation
        if not self._validate_token_format(token):
            self._stats['denied'] += 1
            latency_us = (time.perf_counter() - start_time) * 1_000_000
            print(f"🚫 APL DENIED: Invalid token format. Token='{token[:50] if token else 'EMPTY'}'")
            return (False, "APL: Invalid token format", latency_us)

        # Check 2: Role validation
        if not self._validate_role(role):
            self._stats['denied'] += 1
            latency_us = (time.perf_counter() - start_time) * 1_000_000
            return (False, f"APL: Invalid role '{role}'", latency_us)

        # Check 3: Action validation
        if not self._validate_action(action):
            self._stats['denied'] += 1
            latency_us = (time.perf_counter() - start_time) * 1_000_000
            return (False, f"APL: Invalid action '{action}'", latency_us)

        # Check 4: Resource pattern validation
        is_valid, resource_type = self._validate_resource_pattern(resource)
        if not is_valid:
            self._stats['denied'] += 1
            latency_us = (time.perf_counter() - start_time) * 1_000_000
            return (False, f"APL: Invalid resource pattern '{resource}'", latency_us)

        # Check 5: Basic RBAC - JUNIOR cannot WRITE
        if role == 'JUNIOR' and action == 'WRITE':
            self._stats['denied'] += 1
            latency_us = (time.perf_counter() - start_time) * 1_000_000
            return (False, "APL: JUNIOR role cannot WRITE", latency_us)

        # Check 6: Skill attestation (only when skill_id is present)
        skill_id = event.get('skill_id', '') or metadata.get('skill_id', '')
        if skill_id:
            self._stats['attest_hits'] += 1
            skill_version = (
                event.get('skill_version', '')
                or metadata.get('skill_version', '')
                or 'latest'
            )
            ok, reason = self._validate_attestation(skill_id, skill_version, action, resource)
            if not ok:
                self._stats['denied'] += 1
                self._stats['attest_denied'] += 1
                latency_us = (time.perf_counter() - start_time) * 1_000_000
                return (False, reason, latency_us)

        # All fast-path checks passed
        self._stats['approved'] += 1
        latency_us = (time.perf_counter() - start_time) * 1_000_000
        return (True, "APL: Approved", latency_us)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get APL validation statistics"""
        return self._stats.copy()
    
    def reset_stats(self) -> None:
        """Reset statistics counters"""
        self._stats = {
            'total_checks': 0,
            'approved': 0,
            'denied': 0,
            'bypassed': 0
        }
    
    def benchmark(
        self,
        num_iterations: int = 10000,
        with_attestation: bool = False,
    ) -> Dict[str, Any]:
        """
        Benchmark APL performance.

        Args:
            num_iterations:   Number of iterations to run.
            with_attestation: When True, register a test skill and include
                              skill_id/skill_version in the test event so
                              Check 6 is exercised on every iteration.

        Returns:
            Benchmark results with latency statistics.
        """
        # Optionally register a test skill so Check 6 can be measured.
        if with_attestation and _REGISTRY_AVAILABLE:
            reg = _get_registry()
            reg.register(
                skill_id="_benchmark_skill",
                version="1.0.0",
                contract={
                    "allowed_actions":   ["READ", "WRITE"],
                    "allowed_resources": ["fred/GDP", "edgar/0000051143",
                                          "fred/UNRATE"],
                },
            )

        test_event: Dict[str, Any] = {
            'agent_id': 'agent-123',
            'resource': 'fred/GDP',
            'action':   'READ',
            'metadata': {
                'token': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature',
                'role':  'SENIOR',
            },
        }
        if with_attestation:
            test_event['skill_id']      = '_benchmark_skill'
            test_event['skill_version'] = '1.0.0'

        latencies = []
        for _ in range(num_iterations):
            _, _, latency_us = self.validate(test_event)
            latencies.append(latency_us)

        latencies.sort()
        mean_latency = sum(latencies) / len(latencies)
        p50 = latencies[len(latencies) // 2]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]

        return {
            'iterations':             num_iterations,
            'with_attestation':       with_attestation,
            'mean_latency_us':        mean_latency,
            'p50_latency_us':         p50,
            'p95_latency_us':         p95,
            'p99_latency_us':         p99,
            'throughput_ops_per_sec': 1_000_000 / mean_latency,
            'stats':                  self.get_stats(),
        }


# ── module-level convenience ──────────────────────────────────────────────────

def validate_request(
    event: Dict[str, Any],
    enabled: bool = True,
    attestation_enabled: bool = True,
) -> Tuple[bool, str, float]:
    """
    Quick APL validation (creates a one-shot validator; use APLValidator
    directly when you need persistent stats or caching across calls).

    Args:
        event:                Request event dict.
        enabled:              Enable/disable all APL checks.
        attestation_enabled:  Enable/disable Check 6 (skill attestation).

    Returns:
        Tuple of (approved, reason, latency_us)
    """
    validator = APLValidator(enabled=enabled, attestation_enabled=attestation_enabled)
    return validator.validate(event)

# Made with Bob
