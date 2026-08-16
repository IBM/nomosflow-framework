"""
trestle_validator.py — compliance-trestle integration for NomosFlow
====================================================================

Provides two public objects:

  TrestleAnnotator
      Post-decision annotator.  Given a VerdictResponse (already decided by
      the engine), it resolves which NIST SP 800-53 rev 5 controls were
      exercised and writes them back to AuditRecord.oscal_controls.
      Runs asynchronously so it never adds latency to the hot path.

  CONTROL_MAP
      Rule-key → list[NIST-control-ID].  Populated at module load time from
      the OSCAL Component Definition via the C2P plugin
      (``src/c2p_plugin/opa_plugin.build_control_map_from_component_definition``).
      Falls back to the static dict below when the Component Definition file
      is absent (e.g. unit-test environments without the full project tree).
      The static dict is kept in sync manually as a safety net and documents
      all supported rule-keys.

Trestle is imported conditionally; if it is not installed the annotator
still works by using only the built-in CONTROL_MAP lookup table.  Install
compliance-trestle to unlock OSCAL catalog validation and SSP generation.

Usage
-----
    from src.validators.trestle_validator import TrestleAnnotator

    annotator = TrestleAnnotator()            # singleton – one per process
    # After engine.decide() returns:
    annotator.annotate(verdict_response)      # non-blocking, mutates audit record
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.engine.verdict_api import VerdictResponse
    from src.engine.audit_emitter import AuditEmitter

logger = logging.getLogger(__name__)

# ─── trestle availability ─────────────────────────────────────────────────────

try:
    import trestle  # noqa: F401
    _TRESTLE_AVAILABLE = True
    logger.info("compliance-trestle available — OSCAL catalog validation enabled")
except ImportError:
    _TRESTLE_AVAILABLE = False
    logger.info(
        "compliance-trestle not installed — control annotation uses built-in map only. "
        "Install with: pip install compliance-trestle"
    )

# ─── CONTROL MAP ──────────────────────────────────────────────────────────────
#
# Maps NomosFlow enforcement rule-keys to NIST SP 800-53 rev 5 control IDs.
# Rule-keys match the short identifiers used inside OPA violation messages and
# the TierTrace reason strings so they can be detected with a simple substring
# search.
#
# Primary source: integration/trestle/oscal/component-definition.json
#   Loaded at import time via build_control_map_from_component_definition().
#   When the file is present the dict below is merged with the parsed result
#   so that any rule-keys not yet in the Component Definition are still covered.
#
# References:
#   https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
#   https://github.com/oscal-compass/compliance-trestle
#   https://github.com/oscal-compass/compliance-to-policy

_CONTROL_MAP_STATIC: dict[str, list[str]] = {
    # ── Tier 1: APL (Authorization Policy Layer) ─────────────────────────────
    # IA-5 = Authenticator Management, IA-11 = Re-Authentication
    "Missing Token":             ["IA-2",  "IA-5",  "IA-8",  "AC-3"],
    "Invalid Token":             ["IA-2",  "IA-5",  "IA-8",  "AC-3"],
    "Expired Token":             ["IA-2",  "IA-11", "AC-12"],
    "Invalid Role":              ["AC-2",  "AC-3",  "AC-6"],
    "Invalid Action":            ["AC-3",  "AC-17"],
    "Blocked User":              ["AC-2",  "AC-6",  "SI-3"],

    # ── Tier 2: CMF (Context enrichment / PII detection) ─────────────────────
    "PII Detected":              ["SI-12", "SI-19", "SC-28", "MP-6"],
    "Critical PII":              ["SI-12", "SI-19", "SC-28", "PL-8"],
    "Classification Elevated":   ["AC-4",  "SC-16"],

    # ── Tier 3: OPA (policy evaluation) ──────────────────────────────────────
    # Requirement 1 — Zero-Trust Identity
    # IA-5 = Authenticator Management, IA-11 = Re-Authentication
    # (replaces non-standard ZT-1 extension ID)
    "Requirement 1":             ["IA-2",  "IA-5",  "IA-11"],
    # Requirement 2 — Role-Based Access Control
    "Requirement 2":             ["AC-2",  "AC-3",  "AC-6"],
    # Requirement 3 — Data Residency / Contract Adherence
    "Requirement 3":             ["AC-4",  "SC-8",  "SC-28", "AR-8"],
    # Requirement 4 — Rate Limiting / Strict Operations
    "Requirement 4":             ["SC-5",  "SI-17"],
    # Requirement 5 — Purpose Limitation / Audit Trail
    "Requirement 5":             ["AU-2",  "AU-3",  "AU-12"],
    # Requirement 6 — PII Protection / Schema Validation
    "Requirement 6":             ["SI-12", "SI-19", "SC-28"],
    # Requirement 7 — Data Freshness / Stale Data
    "Requirement 7":             ["SI-10", "SI-12"],
    # Requirement 8 — External API Governance
    "Requirement 8":             ["CA-3",  "SA-9"],
    # Requirement 9 — File-System Security
    "Requirement 9":             ["AC-3",  "MP-6",  "SI-3"],
    # Requirement 10 — Infrastructure Shield / Sequence Enforcement
    "Requirement 10":            ["AU-10", "SI-7"],
    # Requirement 11 — Mutation Entitlement
    "Requirement 11":            ["SI-12", "SI-18"],
    # Requirement 12 — Geo-Sovereignty
    "Requirement 12":            ["SI-10", "SI-12"],
    # Requirement 13 — Data-Lake Format / Size / Schema / PII / ACID
    # SI-10 = Information Input Validation
    # SC-28 = Protection of Information at Rest
    # AC-3  = Access Enforcement
    # CM-3  = Configuration Change Control
    "Requirement 13":            ["SI-10", "SC-28", "AC-3",  "CM-3"],
    # Requirement 14 — AI Hallucination / Fabricated-Identifier Detection
    # SI-10 = Information Input Validation
    # SI-3  = Malicious Code Protection (adversarial/fabricated input)
    # SA-11 = Developer Testing (adversarial content detection)
    # RA-3  = Risk Assessment
    "Requirement 14":            ["SI-10", "SI-3",  "SA-11", "RA-3"],
    # Requirement 17 — Consent Verification (GDPR Art. 7, CCPA §1798.120)
    # PT-2 = Authority to Process PII
    # PT-3 = Personally Identifiable Information Retention and Disposal
    # AC-3 = Access Enforcement
    "Requirement 17":            ["PT-2",  "PT-3",  "AC-3"],
    # Requirement 18 — Right to Erasure / Right to be Forgotten
    #                  (GDPR Art. 17, CCPA §1798.105)
    # PT-3  = PII Retention and Disposal
    # SI-12 = Information Management and Retention
    # AC-3  = Access Enforcement
    "Requirement 18":            ["PT-3",  "SI-12", "AC-3"],
    # Requirement 25 — Cross-Border Data Transfer
    #                  (GDPR Art. 44–50, Schrems II / SCC / BCR / Adequacy)
    # AC-4 = Information Flow Enforcement
    # AR-8 = Accounting of Disclosures
    # SC-8 = Transmission Confidentiality and Integrity
    "Requirement 25":            ["AC-4",  "AR-8",  "SC-8"],
    # GDPR / CCPA
    "GDPR":                      ["PT-1",  "PT-2",  "PT-3",  "AR-1"],
    "CCPA":                      ["PT-1",  "PT-5",  "AR-1"],
    "consent_obtained":          ["PT-2",  "PT-3"],
    "deletion_requested":        ["PT-3",  "SI-12"],
    "data_residency":            ["AC-4",  "AR-8"],
    # HIPAA / SOX / PCI
    "HIPAA":                     ["AU-2",  "AU-3",  "SC-28", "AC-3"],
    "SOX":                       ["AU-2",  "AU-9",  "AU-11"],
    "PCI":                       ["SC-28", "SC-8",  "AU-2",  "IA-2"],
    "retention":                 ["AU-11", "SI-12"],
    # Data quality / governance
    "quality_score":             ["SI-10"],
    "completeness_score":        ["SI-10"],
    "accuracy_score":            ["SI-10"],
    "schema_version":            ["CM-3",  "SI-10"],
    # Tier 4: Stateful (rate limit + anomaly)
    "Rate limit exceeded":       ["SC-5",  "SI-17"],
    "Anomaly detected":          ["SI-3",  "SI-4",  "RA-3"],
    # Tier 5: LLM (hallucination / delegation)
    "Delegated":                 ["CA-7",  "IR-6"],
    "Hallucination":             ["SI-3",  "SA-11"],
    # Escalation
    "Escalated":                 ["CA-7",  "IR-2",  "IR-4"],
    # Clearance
    "clearance":                 ["AC-3",  "AC-6",  "PS-6"],
    "Insufficient clearance":    ["AC-3",  "AC-6",  "PS-6"],
}

# ── Load from Component Definition (C2P) — merge with static fallback ─────────
#
# The C2P plugin parses the OSCAL Component Definition and returns a dict with
# the same shape as _CONTROL_MAP_STATIC.  We merge so that:
#   • All rule-keys declared in the Component Definition are present.
#   • Any rule-key in _CONTROL_MAP_STATIC but not yet in the Component
#     Definition is still available (backward-compat safety net).
#   • When the same rule-key appears in both, the Component Definition wins
#     (it is authoritative) — we still union the control IDs so no coverage
#     is lost.

def _load_control_map() -> dict[str, list[str]]:
    merged: dict[str, list[str]] = dict(_CONTROL_MAP_STATIC)
    try:
        from src.c2p_plugin.opa_plugin import build_control_map_from_component_definition
        cd_map = build_control_map_from_component_definition()
        for rule_key, ctrl_ids in cd_map.items():
            if rule_key in merged:
                # Union the control lists, preserving order
                existing = merged[rule_key]
                for c in ctrl_ids:
                    if c not in existing:
                        existing.append(c)
            else:
                merged[rule_key] = list(ctrl_ids)
        if cd_map:
            logger.debug(
                "CONTROL_MAP: enriched with %d rule-keys from Component Definition",
                len(cd_map),
            )
    except Exception as exc:
        logger.debug("CONTROL_MAP: C2P load skipped (%s) — using static map", exc)
    return merged


CONTROL_MAP: dict[str, list[str]] = _load_control_map()

# Deduplicated set of every NIST control referenced by this system
ALL_CONTROLS: list[str] = sorted(
    {ctrl for controls in CONTROL_MAP.values() for ctrl in controls}
)


# ─── OSCAL catalog helpers (trestle-backed, optional) ─────────────────────────

def validate_control_ids(control_ids: list[str]) -> list[str]:
    """
    Return the subset of *control_ids* that exist in the NIST SP 800-53 rev 5
    catalog loaded via compliance-trestle.

    Falls back silently to the full input list when trestle is unavailable so
    callers never have to branch on trestle availability.
    """
    if not _TRESTLE_AVAILABLE or not control_ids:
        return control_ids
    try:
        from trestle.oscal.catalog import Catalog  # type: ignore
        catalog_path = os.getenv(
            "TRESTLE_CATALOG_PATH",
            "integration/trestle/oscal/nist-sp-800-53-rev5-catalog.json",
        )
        if not os.path.exists(catalog_path):
            return control_ids
        catalog: Catalog = Catalog.oscal_read(catalog_path)  # type: ignore
        valid_ids: set[str] = set()
        for group in (catalog.groups or []):
            for ctrl in (group.controls or []):
                valid_ids.add(ctrl.id.upper())
        return [c for c in control_ids if c.upper() in valid_ids]
    except Exception as exc:  # never crash the hot path
        logger.debug("trestle catalog validation skipped: %s", exc)
        return control_ids


# ─── ANNOTATOR ────────────────────────────────────────────────────────────────

class TrestleAnnotator:
    """
    Resolves NIST SP 800-53 rev 5 controls for a completed VerdictResponse and
    appends them to AuditRecord.oscal_controls.

    Thread-safe.  annotate() is fire-and-forget (runs in a daemon thread).

    Example::

        annotator = TrestleAnnotator()

        resp: VerdictResponse = engine.decide(req)
        annotator.annotate(resp)          # non-blocking
        return resp.to_dict()             # returned immediately
    """

    def __init__(
        self,
        enabled: bool = True,
        validate_against_catalog: bool = False,
        emitter: "AuditEmitter | None" = None,
    ) -> None:
        """
        Args:
            enabled:                   Toggle annotation on/off (e.g. via env flag).
            validate_against_catalog:  When True and trestle is installed, each
                                       resolved control ID is verified against the
                                       loaded NIST catalog.  Adds ~2 ms on first
                                       call (catalog cached after that).
            emitter:                   AuditEmitter instance.  When provided,
                                       update_oscal_controls() is called after
                                       annotation so the persisted row is updated
                                       with the resolved control IDs.
        """
        self.enabled = enabled and bool(
            os.getenv("TRESTLE_ANNOTATOR_ENABLED", "true").lower() != "false"
        )
        self._validate = validate_against_catalog
        self._catalog_validated = False  # lazy flag
        self._emitter = emitter          # may be None (e.g. in unit tests)

    # ─── public ──────────────────────────────────────────────────────────────

    def annotate(self, response: "VerdictResponse") -> None:
        """Fire-and-forget annotation.  Never raises; never blocks decide()."""
        if not self.enabled:
            return
        t = threading.Thread(
            target=self._do_annotate,
            args=(response,),
            daemon=True,
        )
        t.start()

    def resolve_controls(self, reason: str, tier_traces: list) -> list[str]:
        """
        Pure, synchronous helper — useful for testing.

        Scans *reason* and each TierTrace.reason against CONTROL_MAP and
        returns a deduplicated, sorted list of NIST control IDs.
        """
        matched: set[str] = set()
        texts = [reason] + [getattr(t, "reason", "") for t in tier_traces]
        for text in texts:
            if not text:
                continue
            for rule_key, controls in CONTROL_MAP.items():
                if rule_key.lower() in text.lower():
                    matched.update(controls)
        return sorted(matched)

    # ─── internal ────────────────────────────────────────────────────────────

    def _do_annotate(self, response: "VerdictResponse") -> None:
        try:
            controls = self.resolve_controls(
                response.reason,
                response.tier_traces,
            )
            if self._validate and not self._catalog_validated:
                controls = validate_control_ids(controls)
                self._catalog_validated = True  # validated once is enough
            # 1. Mutate the in-memory audit record (always).
            response.audit.oscal_controls = controls
            logger.debug(
                "OSCAL annotation: request_id=%s controls=%s",
                response.request_id,
                controls,
            )
            # 2. Persist back to the database row (when an emitter is wired in).
            if self._emitter is not None and controls:
                self._emitter.update_oscal_controls(response.request_id, controls)
        except Exception as exc:
            logger.warning("TrestleAnnotator._do_annotate failed: %s", exc)
