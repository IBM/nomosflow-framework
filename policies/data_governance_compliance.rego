package data_governance

# Data Governance and Quality Compliance Policy
#
# This policy enforces:
# - Data freshness requirements
# - Data retention policies
# - Rate limiting
# - Data quality standards
# - Access patterns
# - Regulatory compliance (GDPR, CCPA, SOX, HIPAA)

import future.keywords.if
import future.keywords.in

# Default deny
default allow = false

# Main allow rule - all conditions must pass
allow if {
    not data_too_stale
    not retention_period_exceeded
    not rate_limit_exceeded
    not data_quality_insufficient
    not regulatory_violation
    clearance_sufficient
}

##############################################################################
# Data Freshness Rules
##############################################################################

# Check if data is too stale based on data category
data_too_stale if {
    input.message.timestamp_ms
    current_time_ms := time.now_ns() / 1000000
    age_ms := current_time_ms - input.message.timestamp_ms
    
    # Get freshness requirement for data category
    freshness_requirements := {
        "real-time": 1000,        # 1 second
        "near-real-time": 60000,  # 1 minute
        "batch": 3600000,         # 1 hour
        "historical": 86400000,   # 24 hours
        "archived": 2592000000    # 30 days
    }
    
    data_category := input.topic.data_category
    max_age_ms := freshness_requirements[data_category]
    age_ms > max_age_ms
}

# Financial data must be fresh (< 5 minutes)
data_too_stale if {
    input.topic.data_category == "financial"
    input.message.timestamp_ms
    current_time_ms := time.now_ns() / 1000000
    age_ms := current_time_ms - input.message.timestamp_ms
    age_ms > 300000  # 5 minutes
}

# Market data must be very fresh (< 1 second)
data_too_stale if {
    input.topic.data_category == "market_data"
    input.message.timestamp_ms
    current_time_ms := time.now_ns() / 1000000
    age_ms := current_time_ms - input.message.timestamp_ms
    age_ms > 1000  # 1 second
}

##############################################################################
# Data Retention Rules
##############################################################################

# Check if data has exceeded retention period
retention_period_exceeded if {
    input.message.created_at_ms
    current_time_ms := time.now_ns() / 1000000
    age_days := (current_time_ms - input.message.created_at_ms) / 86400000
    
    # Retention periods by data classification
    retention_periods := {
        "public": 365,           # 1 year
        "internal": 730,         # 2 years
        "confidential": 2555,    # 7 years (SOX compliance)
        "secret": 3650,          # 10 years
        "pii": 1095              # 3 years (GDPR)
    }
    
    classification := input.topic.classification
    max_retention_days := retention_periods[classification]
    age_days > max_retention_days
}

# GDPR: Personal data must not be retained beyond necessity
retention_period_exceeded if {
    input.message.contains_pii
    input.message.created_at_ms
    current_time_ms := time.now_ns() / 1000000
    age_days := (current_time_ms - input.message.created_at_ms) / 86400000
    
    # GDPR default retention: 3 years unless justified
    age_days > 1095
    not input.message.retention_justified
}

# HIPAA: Healthcare data retention (6 years)
retention_period_exceeded if {
    input.topic.data_category == "healthcare"
    input.message.created_at_ms
    current_time_ms := time.now_ns() / 1000000
    age_days := (current_time_ms - input.message.created_at_ms) / 86400000
    age_days > 2190  # 6 years
}

##############################################################################
# Rate Limiting Rules
##############################################################################

# Check if user has exceeded rate limits
rate_limit_exceeded if {
    input.user.request_count
    input.user.time_window_seconds
    
    # Rate limits by user role
    rate_limits := {
        "admin": 10000,
        "power_user": 1000,
        "standard_user": 100,
        "guest": 10
    }
    
    user_role := input.user.role
    max_requests := rate_limits[user_role]
    input.user.request_count > max_requests
}

# Topic-specific rate limits
rate_limit_exceeded if {
    input.topic.rate_limit_per_minute
    input.user.topic_request_count
    input.user.topic_request_count > input.topic.rate_limit_per_minute
}

# Burst protection: no more than 10 requests per second
rate_limit_exceeded if {
    input.user.requests_last_second
    input.user.requests_last_second > 10
}

##############################################################################
# Data Quality Rules
##############################################################################

# Check if data quality meets minimum standards
data_quality_insufficient if {
    input.message.quality_score
    input.message.quality_score < 0.7  # Minimum 70% quality score
}

# Required fields must be present
data_quality_insufficient if {
    required_fields := ["id", "timestamp", "source", "version"]
    some field in required_fields
    not input.message[field]
}

# Data must have valid schema version
data_quality_insufficient if {
    input.message.schema_version
    not valid_schema_version(input.message.schema_version)
}

# Check for data completeness
data_quality_insufficient if {
    input.message.completeness_score
    input.message.completeness_score < 0.9  # Minimum 90% complete
}

# Check for data accuracy
data_quality_insufficient if {
    input.message.accuracy_score
    input.message.accuracy_score < 0.95  # Minimum 95% accurate
}

##############################################################################
# Regulatory Compliance Rules
##############################################################################

# GDPR compliance checks
regulatory_violation if {
    input.topic.jurisdiction == "EU"
    input.message.contains_pii
    not input.message.consent_obtained
}

# GDPR: Right to be forgotten
regulatory_violation if {
    input.topic.jurisdiction == "EU"
    input.message.contains_pii
    input.message.deletion_requested
    not input.message.deleted
}

# CCPA compliance (California)
regulatory_violation if {
    input.topic.jurisdiction == "California"
    input.message.contains_pii
    not input.message.privacy_notice_provided
}

# SOX compliance (financial data)
regulatory_violation if {
    input.topic.data_category == "financial"
    input.topic.sox_applicable
    not input.message.audit_trail_complete
}

# HIPAA compliance (healthcare)
regulatory_violation if {
    input.topic.data_category == "healthcare"
    input.message.contains_phi  # Protected Health Information
    not input.message.hipaa_compliant
}

# PCI-DSS compliance (payment card data)
regulatory_violation if {
    input.message.contains_payment_card_data
    not input.message.pci_compliant
}

##############################################################################
# Clearance and Authorization
##############################################################################

# Check if user has sufficient clearance
clearance_sufficient if {
    clearance_levels := {
        "public": 0,
        "internal": 1,
        "confidential": 2,
        "secret": 3,
        "top-secret": 4
    }
    
    user_level := clearance_levels[input.user.clearance_level]
    required_level := clearance_levels[input.topic.classification]
    user_level >= required_level
}

##############################################################################
# Helper Functions
##############################################################################

# Validate schema version format
valid_schema_version(version) if {
    # Schema version must be in format: v1.2.3
    regex.match(`^v\d+\.\d+\.\d+$`, version)
}

# Calculate data age in days
data_age_days(timestamp_ms) := age_days if {
    current_time_ms := time.now_ns() / 1000000
    age_days := (current_time_ms - timestamp_ms) / 86400000
}

##############################################################################
# Violations and Reporting
##############################################################################

# Collect all violations
violations contains msg if {
    data_too_stale
    data_category := input.topic.data_category
    age_ms := (time.now_ns() / 1000000) - input.message.timestamp_ms
    msg := sprintf("Data too stale: %v data is %v ms old", [data_category, age_ms])
}

violations contains msg if {
    retention_period_exceeded
    classification := input.topic.classification
    age_days := data_age_days(input.message.created_at_ms)
    msg := sprintf("Retention period exceeded: %v data is %v days old", [classification, age_days])
}

violations contains msg if {
    rate_limit_exceeded
    user_role := input.user.role
    request_count := input.user.request_count
    msg := sprintf("Rate limit exceeded: %v user made %v requests", [user_role, request_count])
}

violations contains msg if {
    data_quality_insufficient
    quality_score := input.message.quality_score
    msg := sprintf("Data quality insufficient: score is %v (minimum 0.7)", [quality_score])
}

violations contains msg if {
    regulatory_violation
    jurisdiction := input.topic.jurisdiction
    msg := sprintf("Regulatory violation: %v compliance not met", [jurisdiction])
}

violations contains msg if {
    not clearance_sufficient
    user_clearance := input.user.clearance_level
    required_clearance := input.topic.classification
    msg := sprintf("Insufficient clearance: user has '%v' but '%v' required", [user_clearance, required_clearance])
}

##############################################################################
# Decision and Response
##############################################################################

# Final decision
decision := "APPROVED" if {
    allow
    count(violations) == 0
} else := "DENIED"

# Reason for decision
reason := "All compliance checks passed" if {
    allow
    count(violations) == 0
} else := concat("; ", [v | violations[v]])

# Risk score calculation
risk_score := score if {
    base_score := 0
    
    # Add risk for stale data
    stale_risk := 20 if data_too_stale else 0
    
    # Add risk for retention violations
    retention_risk := 30 if retention_period_exceeded else 0
    
    # Add risk for rate limit violations
    rate_risk := 10 if rate_limit_exceeded else 0
    
    # Add risk for quality issues
    quality_risk := 25 if data_quality_insufficient else 0
    
    # Add risk for regulatory violations
    regulatory_risk := 50 if regulatory_violation else 0
    
    # Add risk for clearance issues
    clearance_risk := 40 if not clearance_sufficient else 0
    
    score := base_score + stale_risk + retention_risk + rate_risk + quality_risk + regulatory_risk + clearance_risk
}

# Compliance metadata
compliance_metadata := {
    "data_freshness_check": not data_too_stale,
    "retention_check": not retention_period_exceeded,
    "rate_limit_check": not rate_limit_exceeded,
    "data_quality_check": not data_quality_insufficient,
    "regulatory_check": not regulatory_violation,
    "clearance_check": clearance_sufficient,
    "risk_score": risk_score,
    "timestamp": time.now_ns()
}

# Full response
response := {
    "allowed": allow,
    "decision": decision,
    "reason": reason,
    "violations": violations,
    "risk_score": risk_score,
    "compliance_metadata": compliance_metadata,
    "policy_version": "1.0.0",
    "timestamp": time.now_ns()
}