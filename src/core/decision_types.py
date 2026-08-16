"""
Decision Types for Escalation & Delegation Logic

This module defines the decision types and structures used in the
progressive filtering architecture with escalation support.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


class ComplianceDecision(Enum):
    """
    Decision outcomes for compliance evaluation
    
    Used throughout the tier-by-tier compliance pipeline to indicate
    the result of policy evaluation at each tier.
    """
    APPROVED = "approved"           # Request is allowed to proceed
    DENIED = "denied"               # Request is rejected
    THROTTLED = "throttled"         # Request is rate-limited
    DELEGATED = "delegated"         # Requires human review
    ESCALATED = "escalated"         # Route to next tier (skip intermediate tiers)
    PASS_THROUGH = "pass_through"   # Continue to next tier in sequence


@dataclass
class DecisionResult:
    """
    Structured decision result from a compliance tier
    
    Attributes:
        decision: The compliance decision outcome
        reason: Human-readable explanation of the decision
        tier: Name of the tier that made the decision (APL, CMF, OPA, Stateful, LLM)
        metadata: Additional context about the decision
        confidence: Confidence score (0.0-1.0) if applicable
        escalated_from: Name of tier that escalated to this tier (if applicable)
    """
    decision: ComplianceDecision
    reason: str
    tier: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    confidence: Optional[float] = None
    escalated_from: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "tier": self.tier,
            "metadata": self.metadata,
            "confidence": self.confidence,
            "escalated_from": self.escalated_from
        }
    
    def is_terminal(self) -> bool:
        """Check if this decision is terminal (no further processing needed)"""
        return self.decision in [
            ComplianceDecision.APPROVED,
            ComplianceDecision.DENIED,
            ComplianceDecision.THROTTLED,
            ComplianceDecision.DELEGATED
        ]
    
    def requires_escalation(self) -> bool:
        """Check if this decision requires escalation to another tier"""
        return self.decision == ComplianceDecision.ESCALATED
    
    def requires_delegation(self) -> bool:
        """Check if this decision requires human review"""
        return self.decision == ComplianceDecision.DELEGATED


def create_decision(
    decision: ComplianceDecision,
    reason: str,
    tier: str,
    **kwargs
) -> DecisionResult:
    """
    Factory function to create a DecisionResult
    
    Args:
        decision: The compliance decision
        reason: Explanation of the decision
        tier: Name of the tier making the decision
        **kwargs: Additional metadata (confidence, escalated_from, etc.)
    
    Returns:
        DecisionResult instance
    """
    return DecisionResult(
        decision=decision,
        reason=reason,
        tier=tier,
        metadata=kwargs.get('metadata', {}),
        confidence=kwargs.get('confidence'),
        escalated_from=kwargs.get('escalated_from')
    )


# Backward compatibility helpers
def is_approved(decision: Any) -> bool:
    """Check if decision is approved (supports both string and enum)"""
    if isinstance(decision, ComplianceDecision):
        return decision == ComplianceDecision.APPROVED
    return decision == "APPROVED"


def is_denied(decision: Any) -> bool:
    """Check if decision is denied (supports both string and enum)"""
    if isinstance(decision, ComplianceDecision):
        return decision == ComplianceDecision.DENIED
    return decision == "DENIED"


def to_legacy_format(decision: ComplianceDecision) -> str:
    """Convert ComplianceDecision to legacy string format"""
    if decision == ComplianceDecision.APPROVED:
        return "APPROVED"
    elif decision == ComplianceDecision.DENIED:
        return "DENIED"
    elif decision == ComplianceDecision.THROTTLED:
        return "THROTTLED"
    elif decision == ComplianceDecision.DELEGATED:
        return "DELEGATED"
    elif decision == ComplianceDecision.ESCALATED:
        return "ESCALATED"
    else:
        return "PASS_THROUGH"

# Made with Bob
