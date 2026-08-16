# NomosFlow Architecture

## System overview

NomosFlow is a compliance sidecar that runs as a co-process alongside each AI
agent pod. Every data-access request emitted by an agent is intercepted and
evaluated through a five-tier validation pipeline before any external data is
fetched or any response is written back to the agent.

## Five-tier pipeline

```
Agent request
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│  T1 — APL (Authorization Policy Layer)          µs range   │
│       • Token format validation                             │
│       • RBAC check (role × action matrix)                   │
│       • Resource pattern match (FRED / EDGAR / local)       │
│       • Purpose validation                                  │
│       • Skill attestation (contract seal check)             │
│                                                             │
│  T2 — CMF (Context Metadata Forge)              µs range   │
│       • CDM v2 context enrichment                           │
│       • PII tagging                                         │
│       (never denies; enriches and passes through)           │
│                                                             │
│  T3 — OPA (Open Policy Agent)                   ms range   │
│       • Full Rego policy evaluation                         │
│       • 15+ regulatory rules (GDPR, SOX, HIPAA …)          │
│       • Hot-reload supported (in-place policy update)       │
│                                                             │
│  T4 — Rate-limit                                µs range   │
│       • Per-agent token-bucket (50 req/s default)           │
│       • Configurable via RATE_LIMIT_THRESHOLD env var       │
│                                                             │
│  T5 — LLM validator                            ms–s range  │
│       • Semantic / hallucination check                      │
│       • Sampled at ~1 % of traffic                          │
│       • Fails SECURE: outage → DENY (not ALLOW)            │
│       • PII redacted from payload before model call         │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
   APPROVED → fetch data → return to agent
   DENIED   → 403 + audit record
```

## Short-circuit behaviour

The pipeline is a **ladder**: as soon as any tier issues DENY, processing stops
and the request is rejected without invoking downstream tiers. This means:
- ~31% of traffic is resolved at T1 (cheap APL checks)
- ~41% is resolved at T3 (OPA policy)
- Only ~0.1% reaches T5 (LLM)

Short-circuiting reduces mean end-to-end latency by ~36–55% versus running all
tiers for every request (see EXP-2).

## Fail-secure design

Every tier defaults to DENY on error:
- **T3 OPA unreachable**: APL provides a safe fallback — T1 denies invalid tokens / RBAC violations; legitimate traffic is passed.
- **T5 LLM unavailable**: `LLMValidator` raises `TimeoutError` → sidecar maps to DENIED (set `FAIL_OPEN_LLM=true` only for testing).
- **Audit DB failure**: records are spilled to a local WAL (`/tmp/compliance_audit_wal.jsonl`) and drained on the next successful flush; the hash-chain remains intact.

## Interceptors

Three intercept points are provided:

| Interceptor | Type | Transport | Purpose |
|-------------|------|-----------|---------|
| `compliance_interceptor` | RIIP | in-process | Patches Python builtins (`open`, `urllib`, `boto3`, `sqlite3`) |
| `mcp_interceptor` | PROXY | stdio / SSE | MCP JSON-RPC tool-call wrapper |
| `compliance_proxy_server` | PROXY | HTTP (Flask) | Reverse proxy for HTTP-based agents |

## Deployment topologies

**In-pod sidecar** (recommended)
```
[Agent container] ←→ [NomosFlow sidecar container]
                         (same pod, localhost comms)
```

**Gateway mode** (Envoy ext_authz)
```
[Client] → [Envoy] --ext_authz--> [NomosFlow] → [Backend]
```

**Standalone proxy**
```
[Agent] → [compliance_proxy_server :8080] → [Target service]
```

## Policy structure

Policies are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
and loaded into OPA at startup. The canonical policy (`policies/policy.rego`) encodes
17 governance requirements, each mapped to one or more NIST SP 800-53 Rev 5 controls
(46 distinct control IDs across 15 families — see `policies/oscal_compliance.rego`).
