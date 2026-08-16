package mcp.compliance

# ==============================================================================
# MCP (Model Context Protocol) Compliance Policies
# ==============================================================================
# 
# These policies govern AI agent access to MCP tools including:
# - File system operations
# - Database queries
# - API calls
# - Custom tool invocations
#
# Policy Structure:
# - Tool authorization (which agents can use which tools)
# - Parameter validation (allowed paths, domains, queries)
# - Rate limiting (tool usage frequency)
# - Context-aware decisions (based on user, session, data classification)
# ==============================================================================

import future.keywords.if
import future.keywords.in

# Default deny - all MCP operations must be explicitly allowed
default allow = false

# ==============================================================================
# TOOL AUTHORIZATION
# ==============================================================================

# Allow filesystem read operations for authorized agents
allow if {
    input.event_type == "mcp_request"
    input.mcp_tool.name == "filesystem.read"
    authorized_for_filesystem_read
    allowed_file_path(input.mcp_tool.arguments.path)
}

# Allow filesystem write operations for authorized agents
allow if {
    input.event_type == "mcp_request"
    input.mcp_tool.name == "filesystem.write"
    authorized_for_filesystem_write
    allowed_file_path(input.mcp_tool.arguments.path)
    not sensitive_file_path(input.mcp_tool.arguments.path)
}

# Allow database query operations
allow if {
    input.event_type == "mcp_request"
    input.mcp_tool.name == "database.query"
    authorized_for_database_access
    safe_database_query(input.mcp_tool.arguments.query)
}

# Allow API call operations
allow if {
    input.event_type == "mcp_request"
    input.mcp_tool.name == "api.call"
    authorized_for_api_calls
    whitelisted_domain(input.mcp_tool.arguments.url)
}

# Allow search operations
allow if {
    input.event_type == "mcp_request"
    input.mcp_tool.name == "search.query"
    authorized_for_search
    not contains_pii(input.mcp_tool.arguments.query)
}

# ==============================================================================
# AUTHORIZATION CHECKS
# ==============================================================================

# Check if agent is authorized for filesystem read
authorized_for_filesystem_read if {
    input.agent_id
    # Add agent whitelist or role-based check here
    # For now, allow all authenticated agents
    true
}

# Check if agent is authorized for filesystem write
authorized_for_filesystem_write if {
    input.agent_id
    # Require explicit write permission
    agent_has_permission("filesystem:write")
}

# Check if agent is authorized for database access
authorized_for_database_access if {
    input.agent_id
    agent_has_permission("database:read")
}

# Check if agent is authorized for API calls
authorized_for_api_calls if {
    input.agent_id
    agent_has_permission("api:call")
}

# Check if agent is authorized for search
authorized_for_search if {
    input.agent_id
    true  # Allow all agents to search
}

# Helper: Check if agent has specific permission
agent_has_permission(permission) if {
    # This would integrate with your permission system
    # For now, check against a simple list
    agent_permissions := {
        "agent-123": ["filesystem:read", "filesystem:write", "database:read", "api:call"],
        "agent-456": ["filesystem:read", "database:read"],
    }
    
    permissions := agent_permissions[input.agent_id]
    permission in permissions
}

# ==============================================================================
# FILE PATH VALIDATION
# ==============================================================================

# Allowed file paths (whitelist approach)
allowed_file_path(path) if {
    # Allow reads from /data directory
    startswith(path, "/data/")
}

allowed_file_path(path) if {
    # Allow reads from /tmp directory
    startswith(path, "/tmp/")
}

allowed_file_path(path) if {
    # Allow reads from user workspace
    startswith(path, "/workspace/")
}

# Sensitive file paths (blacklist)
sensitive_file_path(path) if {
    # Block access to system files
    startswith(path, "/etc/")
}

sensitive_file_path(path) if {
    # Block access to credentials
    contains(path, "credentials")
}

sensitive_file_path(path) if {
    # Block access to private keys
    contains(path, ".ssh/")
}

sensitive_file_path(path) if {
    # Block access to environment files
    endswith(path, ".env")
}

# ==============================================================================
# DATABASE QUERY VALIDATION
# ==============================================================================

# Safe database queries
safe_database_query(query) if {
    # Block DROP statements
    not contains(lower(query), "drop ")
}

safe_database_query(query) if {
    # Block DELETE without WHERE clause
    not regex.match(`delete\s+from\s+\w+\s*;`, lower(query))
}

safe_database_query(query) if {
    # Block access to sensitive tables
    not accesses_sensitive_table(query)
}

# Check if query accesses sensitive tables
accesses_sensitive_table(query) if {
    sensitive_tables := ["users", "passwords", "credentials", "api_keys"]
    some table in sensitive_tables
    contains(lower(query), table)
}

# ==============================================================================
# API DOMAIN WHITELISTING
# ==============================================================================

# Whitelisted domains for API calls
whitelisted_domain(url) if {
    allowed_domains := [
        "api.example.com",
        "fred.stlouisfed.org",
        "api.github.com",
        "api.openai.com",
        "api.anthropic.com"
    ]
    
    some domain in allowed_domains
    contains(url, domain)
}

# ==============================================================================
# RATE LIMITING
# ==============================================================================

# Deny if rate limit exceeded
deny[msg] if {
    input.event_type == "mcp_request"
    tool_usage_exceeded
    msg := sprintf("Rate limit exceeded for tool: %v", [input.mcp_tool.name])
}

# Check if tool usage rate limit is exceeded
tool_usage_exceeded if {
    # This would integrate with your rate limiting system
    # For now, use a simple counter check
    tool_name := input.mcp_tool.name
    agent_id := input.agent_id
    
    # Define rate limits per tool
    rate_limits := {
        "filesystem.read": 100,
        "filesystem.write": 50,
        "database.query": 50,
        "api.call": 100,
    }
    
    limit := rate_limits[tool_name]
    # In production, check actual usage count from state store
    # count := get_tool_usage_count(agent_id, tool_name)
    # count > limit
    false  # Placeholder - implement actual rate limiting
}

# ==============================================================================
# PII DETECTION
# ==============================================================================

# Check if text contains PII
contains_pii(text) if {
    # Email pattern
    regex.match(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, text)
}

contains_pii(text) if {
    # SSN pattern
    regex.match(`\d{3}-\d{2}-\d{4}`, text)
}

contains_pii(text) if {
    # Credit card pattern
    regex.match(`\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`, text)
}

# ==============================================================================
# CONTEXT-AWARE POLICIES
# ==============================================================================

# Deny if data classification requires higher authorization
deny[msg] if {
    input.event_type == "mcp_request"
    input.data_classification == "confidential"
    not agent_has_permission("data:confidential")
    msg := "Agent not authorized for confidential data access"
}

# Deny if user consent is required but not provided
deny[msg] if {
    input.event_type == "mcp_request"
    requires_user_consent(input.mcp_tool.name)
    not input.consent_id
    msg := sprintf("User consent required for tool: %v", [input.mcp_tool.name])
}

# Check if tool requires user consent
requires_user_consent(tool_name) if {
    consent_required_tools := [
        "database.query",
        "api.call"
    ]
    tool_name in consent_required_tools
}

# ==============================================================================
# VIOLATION MESSAGES
# ==============================================================================

# Collect all denial reasons
violations[msg] if {
    deny[msg]
}

# Decision output
decision := "APPROVED" if {
    allow
    count(violations) == 0
} else := "DENIED"

# Reason for denial
reason := concat(", ", [v | violations[v]]) if {
    count(violations) > 0
} else := "Approved"

# ==============================================================================
# RESPONSE STRUCTURE
# ==============================================================================

# Final response
response := {
    "allowed": allow,
    "decision": decision,
    "reason": reason,
    "violations": violations,
    "timestamp": time.now_ns(),
    "policy_version": "1.0.0"
}