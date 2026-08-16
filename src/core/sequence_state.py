"""
Sequence State — per-agent in-process history for Demo 4 (Hybrid Gateway+Sidecar).

The sidecar maintains a lightweight, in-process per-agent read history.  When an
agent that has previously read PII-classified content then attempts to write that
content to an unclassified destination, the sidecar detects the composition risk
and can deny the write — a structural capability the gateway cannot provide because
it never sees the prior read.

Thread-safety: all public methods acquire a per-agent lock before mutating state.
The state is in-process only; it resets when the sidecar restarts.  This is
intentional for the demo — production deployments would use Redis or a sidecar-local
SQLite table for persistence.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

# How long (seconds) a read event stays in an agent's history.
# Kept short for demo purposes so the demo scenario plays out within a single run.
_HISTORY_TTL_S = int(600)

# Destinations that are considered "unclassified public" for composition checks.
_PUBLIC_DESTINATION_PREFIXES = (
    "s3://public",
    "s3://unclassified",
    "https://",
    "http://",
)


@dataclass
class _ReadEvent:
    resource: str
    pii_flag: bool
    data_classification: str        # "PII" | "confidential" | "public" | ""
    recorded_at: float = field(default_factory=time.time)


class AgentSequenceState:
    """Tracks a single agent's read history and exposes composition-risk queries."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self._lock = threading.Lock()
        self._reads: list[_ReadEvent] = []

    def record_read(self, resource: str, pii_flag: bool, data_classification: str = "") -> None:
        """Record that this agent has read *resource*.  Call after an APPROVED read."""
        with self._lock:
            self._evict_expired()
            self._reads.append(_ReadEvent(
                resource=resource,
                pii_flag=pii_flag,
                data_classification=data_classification or ("PII" if pii_flag else "public"),
            ))

    def check_composition_risk(self, write_target: str) -> tuple[bool, str]:
        """
        Returns (risk_detected: bool, reason: str).

        Risk is detected when:
          • The agent has read any PII-classified resource in its active history, AND
          • The intended write target looks like an unclassified public destination.

        This is the core "gateway cannot see this" scenario: the gateway sees only
        the current write request and has no knowledge of the earlier PII read.
        """
        with self._lock:
            self._evict_expired()
            pii_reads = [r for r in self._reads if r.pii_flag or r.data_classification == "PII"]
            if not pii_reads:
                return False, ""

            is_public_target = any(
                write_target.startswith(prefix) for prefix in _PUBLIC_DESTINATION_PREFIXES
            )
            if not is_public_target:
                return False, ""

            resources = ", ".join(r.resource for r in pii_reads[:3])
            reason = (
                f"Composition risk: agent previously read PII-classified resource(s) "
                f"[{resources}] and is now writing to unclassified destination [{write_target}]. "
                f"Cross-classification data flow denied."
            )
            return True, reason

    def summary(self) -> dict[str, Any]:
        with self._lock:
            self._evict_expired()
            return {
                "agent_id": self.agent_id,
                "active_reads": len(self._reads),
                "pii_reads": sum(1 for r in self._reads if r.pii_flag),
                "resources": [r.resource for r in self._reads],
            }

    def _evict_expired(self) -> None:
        now = time.time()
        self._reads = [r for r in self._reads if now - r.recorded_at < _HISTORY_TTL_S]


class SequenceStateRegistry:
    """
    Process-wide singleton registry — one AgentSequenceState per agent_id.

    Usage:
        from src.core.sequence_state import get_sequence_registry
        registry = get_sequence_registry()
        registry.record_read(agent_id, resource, pii_flag)
        risk, reason = registry.check_composition_risk(agent_id, write_target)
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._agents: dict[str, AgentSequenceState] = {}

    def _get_or_create(self, agent_id: str) -> AgentSequenceState:
        with self._lock:
            if agent_id not in self._agents:
                self._agents[agent_id] = AgentSequenceState(agent_id)
            return self._agents[agent_id]

    def record_read(self, agent_id: str, resource: str, pii_flag: bool,
                    data_classification: str = "") -> None:
        self._get_or_create(agent_id).record_read(resource, pii_flag, data_classification)

    def check_composition_risk(self, agent_id: str, write_target: str) -> tuple[bool, str]:
        return self._get_or_create(agent_id).check_composition_risk(write_target)

    def get_summary(self, agent_id: str) -> dict[str, Any]:
        return self._get_or_create(agent_id).summary()


# Module-level singleton
_registry: SequenceStateRegistry | None = None
_registry_lock = threading.Lock()


def get_sequence_registry() -> SequenceStateRegistry:
    global _registry
    with _registry_lock:
        if _registry is None:
            _registry = SequenceStateRegistry()
    return _registry

# Made with Bob
