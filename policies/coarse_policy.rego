package bank.coarse

# Coarse Gateway Policy — Demo 4 (Hybrid Gateway+Sidecar)
#
# This package contains ONLY the cheap, stateless, org-wide rules that the gateway
# can evaluate without payload inspection (Reqs 1-9).  The richer, context-heavy
# rules (Reqs 14, 17, 18, 25 and the LLM/sequence tiers) stay in the sidecar's
# bank.authz package where they belong.
#
# The gateway calls:  POST /v1/data/bank/coarse
# The sidecar calls:  POST /v1/data/bank/authz  (unchanged)
#
# Both packages are loaded into the SAME OPA server instance — one engine, two rule
# sets, as described in the hybrid architecture.

import rego.v1

default allow := false
default reason := "Default Deny: No coarse rule matched"

# ---- helpers ---------------------------------------------------------------

valid_token_format(token) if { token == "valid_security_token" }
valid_token_format(token) if { startswith(token, "Bearer "); count(token) > 20 }
valid_token_format(token) if { count(split(token, ".")) == 3 }

external_api_resource if { startswith(input.resource, "edgar/") }
external_api_resource if { startswith(input.resource, "fred/") }
file_system_resource  if { input.resource_type == "file" }
file_system_resource  if { startswith(input.resource, "/") }

# ---- allow / reason --------------------------------------------------------

allow if { count(violations) == 0 }

reason := concat(" | ", violations) if { count(violations) > 0 }
reason := "Coarse policy compliant" if { count(violations) == 0 }

# ---- violations (Reqs 1-9 stateless subset) --------------------------------

# [REQ 1] Token required
violations contains "REQ1: Missing token" if { not input.token }

# [REQ 1] Token format (relaxed for external APIs and file ops)
violations contains "REQ1: Invalid token format" if {
    input.token
    not valid_token_format(input.token)
    not external_api_resource
    not file_system_resource
}

# [REQ 2] RBAC — JUNIOR cannot access executive resources
violations contains "REQ2: RBAC violation - JUNIOR cannot access executive resources" if {
    input.role == "JUNIOR"
    contains(input.resource, "executive")
}

# [REQ 3] Contract adherence — unmapped datasets blocked
violations contains "REQ3: Unmapped dataset" if {
    contains(input.resource, "unmapped")
}

# [REQ 4] Valid action required
violations contains "REQ4: Invalid action" if {
    valid_actions := {"READ", "WRITE"}
    not valid_actions[input.action]
}

# [REQ 5] Purpose limitation — marketing campaigns blocked
violations contains "REQ5: Purpose mismatch - marketing campaigns not permitted" if {
    input.purpose == "MarketingCampaign"
}

# [REQ 6] Schema — resource must be a string
violations contains "REQ6: Broken schema - resource must be a string" if {
    not is_string(input.resource)
}

# [REQ 7] Data freshness — requests >24 h old blocked (not for real-time external APIs)
violations contains "REQ7: Stale data access" if {
    not external_api_resource
    provided_ns := input.timestamp * 1000000000
    max_age_ns := 24 * 60 * 60 * 1000000000
    time.now_ns() - provided_ns > max_age_ns
}

# [REQ 9] Rate limit exceeded — gateway tracks this in Python; OPA provides the rule text
# The gateway Python layer enforces the actual counter; this rule fires only when the
# gateway explicitly sets input.rate_limit_exceeded to signal the policy engine.
violations contains "REQ9: Rate limit exceeded" if {
    input.rate_limit_exceeded == true
}

# [REQ 10] Infrastructure shield
violations contains "REQ10: System reconnaissance - /etc/ path detected" if {
    contains(input.resource, "/etc/")
}
violations contains "REQ10: Directory traversal attempt" if {
    contains(input.resource, "../")
}

# ---- metadata for audit chain ----------------------------------------------

rules_evaluated := [
    "REQ1_token_required",
    "REQ1_token_format",
    "REQ2_rbac",
    "REQ3_unmapped",
    "REQ4_valid_action",
    "REQ5_purpose",
    "REQ6_schema",
    "REQ7_freshness",
    "REQ9_rate_limit",
    "REQ10_infra_shield",
]

# Made with Bob
