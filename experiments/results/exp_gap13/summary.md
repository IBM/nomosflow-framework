# EXP-GAP-13: Interceptor inventory

*Generated: 2026-08-14T05:25:07.499334+00:00*

## Interceptor inventory
| Interceptor | Type | Transport | Import | Hooks_OK | Patches_count |
| ----------- | ---- | --------- | ------ | -------- | ------------- |
| compliance_interceptor | RIIP | in-process | YES | YES | 4 |
| mcp_interceptor | PROXY | stdio / SSE | YES | YES | 0 |
| compliance_proxy_server | PROXY | HTTP (Flask) | YES | YES | 0 |

## Descriptions
  compliance_interceptor: Patches Python builtins and stdlib I/O to intercept all file/network/database access for compliance checks.
  mcp_interceptor: MCP JSON-RPC proxy that wraps tool calls and resources before forwarding to the upstream MCP server.
  compliance_proxy_server: Flask HTTP reverse proxy that applies compliance checks to all inbound requests before forwarding downstream.

## Paper §5 gap disclosures
- All interceptors importable with complete hook surface.
