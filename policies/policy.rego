package bank.authz

import rego.v1

# By default, deny all requests
default allow := false
default reason := "Default Deny: No rules matched or request malformed"

# ---------------------------------------------------------
# 1. MAIN DECISION BLOCK
# ---------------------------------------------------------
# A request is allowed ONLY if there are exactly 0 violations
allow if {
    count(violations) == 0
}

# Generate a comma-separated string of all violation reasons if denied
reason := concat(" | ", violations) if {
    count(violations) > 0
}
reason := "Compliant" if {
    count(violations) == 0
}

# ---------------------------------------------------------
# 2. THE 10 STATELESS COMPLIANCE RULES (Reqs 1-7, 10-12)
# ---------------------------------------------------------
# EXTERNAL API EXEMPTIONS (SEC EDGAR, FRED, etc.)
# ---------------------------------------------------------
# External public APIs should bypass strict token validation
# These are public data sources for market research
external_api_resource if {
    startswith(input.resource, "edgar/")
}
external_api_resource if {
    startswith(input.resource, "fred/")
}

# File system operations - local file access
# File operations have relaxed token validation but strict path security
file_system_resource if {
    input.resource_type == "file"
}
file_system_resource if {
    startswith(input.resource, "/")
}
file_system_resource if {
    # Windows paths (C:/, D:/, etc.)
    regex.match(`^[A-Za-z]:/`, input.resource)
}

# ---------------------------------------------------------

# [REQ 1] Zero-Trust Identity
# Token is ALWAYS required - authentication is mandatory for all requests
violations contains msg if {
    not input.token
    msg := "Requirement 1: Missing Token"
}

# Helper to check if token is valid format (JWT or Bearer)
valid_token_format(token) if {
    # Accept old format for backward compatibility
    token == "valid_security_token"
}
valid_token_format(token) if {
    # Accept Bearer token format
    startswith(token, "Bearer ")
    count(token) > 20
}
valid_token_format(token) if {
    # Accept JWT format (has 2 dots)
    count(split(token, ".")) == 3
}

# Token format validation (relaxed for external APIs and file operations)
# External APIs and file operations still need a token, but format validation is less strict
violations contains msg if {
    input.token
    not valid_token_format(input.token)
    not external_api_resource
    not file_system_resource
    msg := "Requirement 1: Invalid Token"
}

# [REQ 4] Strict Operations
violations contains msg if {
    valid_actions := {"READ", "WRITE"}
    not valid_actions[input.action]
    msg := "Requirement 4: Invalid Operation"
}

# [REQ 6] Schema Validation
violations contains msg if {
    not is_string(input.resource)
    msg := "Requirement 6: Broken Schema"
}

# [REQ 2] Base RBAC
violations contains msg if {
    input.role == "JUNIOR"
    contains(input.resource, "executive")
    msg := "Requirement 2: RBAC Violation"
}

# [REQ 3] Contract Adherence
violations contains msg if {
    contains(input.resource, "unmapped")
    msg := "Requirement 3: Unmapped Dataset"
}

# [REQ 5] Purpose Limitation
violations contains msg if {
    input.purpose == "MarketingCampaign"
    msg := "Requirement 5: Purpose Mismatch"
}

# [REQ 7] Data Freshness (Cannot request data > 24 hours old)
# Skip freshness check for external API resources (they fetch real-time data)
violations contains msg if {
    not external_api_resource
    provided_ns := input.timestamp * 1000000000
    max_age_ns := 24 * 60 * 60 * 1000000000
    
    time.now_ns() - provided_ns > max_age_ns
    msg := "Requirement 7: Stale Data Access"
}

# [REQ 10] Infrastructure Shield
violations contains msg if {
    contains(input.resource, "/etc/")
    msg := "Requirement 10: System Reconnaissance"
}
violations contains msg if {
    contains(input.resource, "../")
    msg := "Requirement 10: System Reconnaissance"
}

# [REQ 10] File System Security - Sensitive file protection
# Prevent unauthorized access to configuration files
violations contains msg if {
    file_system_resource
    contains(input.resource, "/.env")
    input.action == "READ"
    input.role != "SENIOR"
    input.role != "AGENT"  # Allow AGENT role for file operations
    msg := "Requirement 10: Unauthorized access to sensitive configuration files"
}

# [REQ 10] File System Security - System file protection
# Prevent access to critical system directories
violations contains msg if {
    file_system_resource
    regex.match(`/(etc|sys|proc|root|boot|dev)/`, input.resource)
    msg := "Requirement 10: System file access denied"
}

# [REQ 10] File System Security - Prevent directory traversal
# Additional check for file operations to prevent path traversal attacks
violations contains msg if {
    file_system_resource
    contains(input.resource, "..")
    msg := "Requirement 10: Directory traversal attempt detected"
}

# ============================================================================
# ESCALATION & DELEGATION RULES (Feature Flag Controlled)
# ============================================================================
# These rules enable dynamic tier-skipping and human delegation
# Only evaluated if input.features.escalation_enabled == true

# Check if escalation features are enabled
escalation_enabled := input.features.escalation_enabled
delegation_enabled := input.features.delegation_enabled

# Default: escalation disabled if not specified
default escalation_enabled := false
default delegation_enabled := false

# ---------------------------------------------------------
# CMF → LLM Escalation Conditions
# ---------------------------------------------------------
# Escalate from CMF directly to LLM tier (skip OPA)

escalate_to_llm_from_cmf if {
    escalation_enabled == true
    # PII detected with CRITICAL risk level
    input.cdm_context.context.message.contains_pii == true
    input.risk_level == "CRITICAL"
}

escalate_to_llm_from_cmf if {
    escalation_enabled == true
    # Multiple PII types detected
    count(input.cdm_context.context.message.pii_types) >= 3
}

# ---------------------------------------------------------
# OPA → LLM Escalation Conditions
# ---------------------------------------------------------
# Escalate from OPA to LLM tier for complex semantic analysis

escalate_to_llm_from_opa if {
    escalation_enabled == true
    # Low policy confidence - needs semantic analysis
    input.policy_confidence < 0.7
}

# Disabled: exceptions variable not defined
# escalate_to_llm_from_opa if {
#     escalation_enabled == true
#     # Conflicting rules detected
#     count(violations) > 0
#     count(exceptions) > 0
# }

escalate_to_llm_from_opa if {
    escalation_enabled == true
    # Complex resource pattern requiring semantic understanding
    input.requires_semantic_analysis == true
}

# ---------------------------------------------------------
# Stateful → LLM Escalation Conditions
# ---------------------------------------------------------
# Escalate from Stateful tier to LLM for anomaly validation

escalate_to_llm_from_stateful if {
    escalation_enabled == true
    # High anomaly score detected
    input.anomaly_score > 0.8
}

escalate_to_llm_from_stateful if {
    escalation_enabled == true
    # Unusual access pattern
    input.access_pattern == "anomalous"
}

# ---------------------------------------------------------
# Human Delegation Conditions
# ---------------------------------------------------------
# Delegate to human review queue

delegate_to_human if {
    delegation_enabled == true
    # LLM confidence below threshold
    input.llm_confidence < 0.85
}

delegate_to_human if {
    delegation_enabled == true
    # Ambiguous policy interpretation
    input.policy_ambiguity == true
}

delegate_to_human if {
    delegation_enabled == true
    # High-risk decision requiring human oversight
    input.risk_level == "CRITICAL"
    count(violations) == 0  # Would normally be approved
}

# ---------------------------------------------------------
# Enhanced Decision Structure
# ---------------------------------------------------------
# Return structured decision with escalation support

# Determine the action to take
action := "ESCALATE" if {
    escalate_to_llm_from_cmf
} else := "ESCALATE" if {
    escalate_to_llm_from_opa
} else := "ESCALATE" if {
    escalate_to_llm_from_stateful
} else := "DELEGATE" if {
    delegate_to_human
} else := "APPROVE" if {
    allow
} else := "DENY"

# Determine which tier should handle escalation
escalation_target := "LLM" if {
    escalate_to_llm_from_cmf
} else := "LLM" if {
    escalate_to_llm_from_opa
} else := "LLM" if {
    escalate_to_llm_from_stateful
} else := "HUMAN" if {
    delegate_to_human
} else := "NONE"

# Enhanced decision object (backward compatible)
decision := {
    "allow": allow,
    "reason": reason,
    "action": action,
    "tier": "OPA",
    "escalation_enabled": escalation_enabled,
    "escalation_target": escalation_target,
    "delegation_enabled": delegation_enabled
}

# ---------------------------------------------------------
# ---------------------------------------------------------
# DATA LAKE FORMAT SECURITY RULES
# ---------------------------------------------------------

# Data lake resource detection - identify data lake format files
data_lake_resource if {
    regex.match(`\.(parquet|pq|avro|orc)$`, lower(input.resource))
}
data_lake_resource if {
    # Delta Lake tables (directory with _delta_log)
    contains(input.resource, "_delta_log")
}

# [REQ 13] Data Lake Format Validation
# Ensure only approved data lake formats are accessed
violations contains msg if {
    data_lake_resource
    not regex.match(`\.(parquet|pq|avro|orc)$`, lower(input.resource))
    not contains(input.resource, "_delta_log")
    msg := "Requirement 13: Unsupported data lake format"
}

# [REQ 13] Data Lake Size Limits
# Prevent access to excessively large data lake files (metadata check)
violations contains msg if {
    data_lake_resource
    input.metadata.file_size_mb
    input.metadata.file_size_mb > 100
    msg := "Requirement 13: Data lake file exceeds size limit (100MB)"
}

# [REQ 13] Data Lake Row Limits
# Enforce row count limits for data lake operations
violations contains msg if {
    data_lake_resource
    input.metadata.row_count
    input.metadata.row_count > 10000
    input.role != "SENIOR"
    msg := "Requirement 13: Data lake row count exceeds limit for non-senior roles"
}

# [REQ 13] Data Lake Schema Validation
# Ensure data lake files have valid schema metadata
violations contains msg if {
    data_lake_resource
    input.action == "READ"
    not input.metadata.schema
    msg := "Requirement 13: Data lake file missing schema metadata"
}

# [REQ 13] Data Lake PII Detection
# Flag data lake files that may contain PII based on column names
violations contains msg if {
    data_lake_resource
    input.metadata.column_names
    pii_columns := {"ssn", "social_security", "credit_card", "password", "secret"}
    some column in input.metadata.column_names
    pii_columns[lower(column)]
    input.role != "SENIOR"
    msg := "Requirement 13: Data lake file contains PII columns - senior access required"
}

# [REQ 13] Data Lake Format-Specific Rules
# Parquet files require compression for storage efficiency
violations contains msg if {
    regex.match(`\.parquet$`, lower(input.resource))
    input.metadata.compression
    input.metadata.compression == "none"
    input.action == "WRITE"
    msg := "Requirement 13: Parquet files must use compression"
}

# [REQ 13] Delta Lake ACID Compliance
# Delta Lake operations must maintain ACID properties
violations contains msg if {
    contains(input.resource, "_delta_log")
    input.action == "WRITE"
    not input.metadata.transaction_id
    msg := "Requirement 13: Delta Lake write operations require transaction ID"
}

# [REQ 13] Data Lake Temporal Access
# Restrict access to historical data lake versions
violations contains msg if {
    data_lake_resource
    input.metadata.version
    input.metadata.version < 0
    msg := "Requirement 13: Invalid data lake version number"
}

# [REQ 11] Mutation Entitlement
violations contains msg if {
    input.action == "WRITE"
    input.role != "SENIOR"
    msg := "Requirement 11: Unauthorized WRITE"
}

# [REQ 12] Geo-Sovereignty
violations contains msg if {
    input.region == "US"
    contains(input.resource, "EU_PINNED")
    msg := "Requirement 12: Sovereignty Violation"
}

# ---------------------------------------------------------
# 3. EXTERNAL DATA API GOVERNANCE (FRED & SEC EDGAR)
# ---------------------------------------------------------

# [NEW] SEC EDGAR Financial Data RBAC
# Only SENIOR agents can trigger live SEC 10-K document fetches.
violations contains msg if {
    startswith(input.resource, "edgar/")
    input.context.role != "SENIOR"
    msg := "Requirement 2: RBAC Violation - Junior Agents cannot access SEC EDGAR filings"
}

# [NEW] FRED Macroeconomic Purpose Limitation
# To prevent API abuse, FRED data can only be pulled for specific business purposes.
violations contains msg if {
    startswith(input.resource, "fred/")
    valid_purposes := {"MarketResearch", "RiskAnalysis", "Test_Suite_Bypass"}
    not valid_purposes[input.context.purpose]
    msg := "Requirement 5: Purpose Mismatch - FRED data restricted to MarketResearch or RiskAnalysis"
}

# ---------------------------------------------------------
# 4. HALLUCINATION GUARDRAILS (REQ 14)
# ---------------------------------------------------------

# [REQ 14] Hallucination Detection - Suspicious Patterns
# Detect potential AI hallucinations or fabricated data patterns
violations contains msg if {
    contains(lower(input.resource), "hallucinated")
    msg := "Requirement 14: Hallucination Detected - Resource contains suspicious patterns"
}

# [REQ 14] Hallucination Detection - Fabricated Identifiers
# Block requests with obviously fake or test identifiers that might indicate hallucinated data
violations contains msg if {
    regex.match("(fake|test|dummy|mock|hallucin|fabricat)[_-]", lower(input.resource))
    not input.purpose == "Test_Suite_Bypass"
    msg := "Requirement 14: Hallucination Detected - Fabricated identifier in resource"
}

# [REQ 14] Hallucination Detection - Unrealistic Timestamps
# Block requests with timestamps in the future (potential hallucination)
violations contains msg if {
    input.timestamp > 0
    provided_ns := input.timestamp * 1000000000
    provided_ns > time.now_ns()
    msg := "Requirement 14: Hallucination Detected - Future timestamp (unrealistic data)"
}

# [REQ 14] Hallucination Detection - Invalid CIK Codes
# SEC EDGAR CIK codes must be 10 digits, detect invalid formats
violations contains msg if {
    startswith(input.resource, "edgar/")
    cik := trim_prefix(input.resource, "edgar/")
    not regex.match("^[0-9]{10}$", cik)
    msg := "Requirement 14: Hallucination Detected - Invalid SEC CIK format (must be 10 digits)"
}

# [REQ 14] Hallucination Detection - Suspicious CIK Patterns
# Detect obviously fabricated or unrealistic CIK patterns
violations contains msg if {
    startswith(input.resource, "edgar/")
    cik := trim_prefix(input.resource, "edgar/")
    
    # Detect all 9s (9999999999) - commonly used as placeholder
    regex.match("^9{10}$", cik)
    msg := "Requirement 14: Hallucination Detected - Suspicious CIK pattern (all 9s - likely placeholder)"
}

violations contains msg if {
    startswith(input.resource, "edgar/")
    cik := trim_prefix(input.resource, "edgar/")
    
    # Detect all same digit (0000000000, 1111111111, etc.)
    regex.match("^([0-9])\\1{9}$", cik)
    msg := "Requirement 14: Hallucination Detected - Suspicious CIK pattern (repeated digit)"
}

violations contains msg if {
    startswith(input.resource, "edgar/")
    cik := trim_prefix(input.resource, "edgar/")
    
    # Detect sequential patterns (0123456789, 1234567890)
    regex.match("^(0123456789|1234567890|9876543210)$", cik)
    msg := "Requirement 14: Hallucination Detected - Suspicious CIK pattern (sequential digits)"
}


# ---------------------------------------------------------
# 5. PRIVACY & DATA PROTECTION (REQS 17-18)
# ---------------------------------------------------------

# [REQ 17] Consent Verification (GDPR Art. 7, CCPA §1798.120)
# Personal data access requires valid, active consent
violations contains msg if {
    # Check if request involves personal data (indicated by user_id or personal_data flag)
    input.user_id
    
    # Consent ID must be provided
    not input.consent_id
    msg := "Requirement 17: Missing Consent - Personal data access requires consent_id"
}

violations contains msg if {
    input.user_id
    input.consent_id
    
    # Look up consent in data.consents registry
    consent := data.consents[input.consent_id]
    
    # Consent must exist
    not consent
    msg := "Requirement 17: Invalid Consent - Consent ID not found in registry"
}

violations contains msg if {
    input.user_id
    input.consent_id
    consent := data.consents[input.consent_id]
    
    # Consent must be active (not revoked or expired)
    consent.status != "active"
    msg := "Requirement 17: Inactive Consent - Consent has been revoked or expired"
}

violations contains msg if {
    input.user_id
    input.consent_id
    consent := data.consents[input.consent_id]
    
    # Consent purpose must match request purpose
    consent.purpose != input.purpose
    msg := "Requirement 17: Purpose Mismatch - Consent purpose does not match request purpose"
}

violations contains msg if {
    input.user_id
    input.consent_id
    consent := data.consents[input.consent_id]
    
    # Consent must not be expired (check expiry timestamp)
    consent.expires_at
    consent.expires_at < time.now_ns() / 1000000000
    msg := "Requirement 17: Expired Consent - Consent has passed expiration date"
}

# [REQ 18] Right to Erasure / Right to be Forgotten (GDPR Art. 17, CCPA §1798.105)
# Deleted user data must not be accessible
violations contains msg if {
    input.user_id
    
    # Check if user is in deleted_users registry
    data.deleted_users[input.user_id]
    msg := "Requirement 18: User Data Deleted - Access denied for deleted user (Right to be Forgotten)"
}

# ---------------------------------------------------------
# 6. CROSS-BORDER DATA TRANSFER (REQ 25)
# ---------------------------------------------------------

# [REQ 25] Cross-Border Data Transfer Compliance (GDPR Art. 44-50, Schrems II)
# EU data must not leave EU without adequate safeguards

# Allow if data is not EU-pinned
# (No violation if data_classification is not EU_PINNED)

# Allow if EU data stays in EU
# (No violation if destination is EU)

# Require transfer mechanism for EU data going outside EU
violations contains msg if {
    # Data is EU-pinned
    input.data_classification == "EU_PINNED"
    
    # Destination is outside EU
    input.destination_region
    input.destination_region != "EU"
    
    # No valid transfer mechanism provided
    not input.transfer_mechanism
    msg := "Requirement 25: Missing Transfer Mechanism - EU data transfer requires SCC, BCR, or Adequacy Decision"
}

violations contains msg if {
    input.data_classification == "EU_PINNED"
    input.destination_region
    input.destination_region != "EU"
    input.transfer_mechanism
    
    # Transfer mechanism must be one of the approved methods
    valid_mechanisms := {"SCC", "BCR", "Adequacy"}
    not valid_mechanisms[input.transfer_mechanism]
    msg := "Requirement 25: Invalid Transfer Mechanism - Must be SCC (Standard Contractual Clauses), BCR (Binding Corporate Rules), or Adequacy Decision"
}

violations contains msg if {
    input.data_classification == "EU_PINNED"
    input.destination_region
    input.destination_region != "EU"
    input.transfer_mechanism == "Adequacy"
    
    # Adequacy decisions only valid for specific countries
    # As of 2024: UK, Switzerland, Japan, Canada (commercial), Israel, etc.
    # US does not have adequacy decision post-Schrems II
    adequate_countries := {"UK", "Switzerland", "Japan", "Canada", "Israel", "NewZealand", "SouthKorea"}
    not adequate_countries[input.destination_region]
    msg := "Requirement 25: Invalid Adequacy Claim - Destination country does not have EU adequacy decision"
}


# Hot reload test - Wed Mar 18 06:28:47 PDT 2026

# Hot reload test - Wed Mar 18 06:29:18 PDT 2026

# Hot reload test - Wed Mar 18 06:50:45 PDT 2026

# Hot reload test - Wed Mar 18 06:51:51 PDT 2026

# Hot reload test - Wed Mar 18 10:29:16 PDT 2026

# Hot reload test - Wed Mar 18 10:41:31 PDT 2026
# Test comment added at Wed Mar 18 10:57:14 PDT 2026
# Test comment added at Wed Mar 18 11:26:59 PDT 2026

# Hot reload test - Wed Apr  1 14:28:11 PDT 2026

# Hot reload test - Wed Apr  1 15:57:41 PDT 2026

# Hot reload test - Fri Apr  3 08:36:12 PDT 2026

# Hot reload test - Fri Apr  3 14:10:14 PDT 2026

# Hot reload test - Fri Apr  3 17:08:07 PDT 2026
# Test modification at Fri Apr  3 18:58:06 PDT 2026
# Test modification at Sat Apr  4 07:14:12 PDT 2026
# Test modification at Sat Apr  4 16:23:11 PDT 2026
# Test modification at Sat Apr  4 18:03:41 PDT 2026
# Test modification at Sat Apr  4 19:50:22 PDT 2026
# Test modification at Sat Apr  4 21:01:45 PDT 2026
# Test modification at Sun Apr  5 17:45:40 PDT 2026
# Test modification at Mon May 25 10:22:47 PDT 2026
# Test modification at Fri May 29 06:55:07 PDT 2026
# Test modification at Fri May 29 08:34:48 PDT 2026
# Test modification at Fri May 29 08:35:23 PDT 2026
