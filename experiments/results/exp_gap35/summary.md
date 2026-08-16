# EXP-GAP-35  Redaction-before-inference + local-model default

*Generated: 2026-08-14T05:25:07.512222+00:00*

## Verification summary (GAP-35 resolved)
| Check | Result | Detail |
| ----- | ------ | ------ |
| Redaction test cases | 5/5 pass | SSN, email, phone, CC, nested, structural |
| PII patterns covered | 4 | ssn, email, phone, credit_card |
| call sites instrumented | 4 | all process_llm_tier calls wrapped |
| Base compose: local model | ✓ | ollama/granite3.2:2b default |
| Base compose: no cloud key | ✓ | no sk- credentials in tracked file |
| Base compose: ollama svc | ✓ | ollama/ollama:latest + ollama-models vol |
| Base compose: REDACT=true | ✓ | REDACT_FOR_LLM=true set explicitly |
| LLM override: REDACT=true | ✓ | docker-compose.llm.yml preserves flag |
| LLM override: no cloud key | ✓ | credentials via env/secrets only |

## Paper §5 gap disclosures
- GAP-35 RESOLVED: redact_for_llm() added to sidecar_optimized.py; all 4 process_llm_tier call sites now pass redact_for_llm(event). PII patterns: ssn, email, phone, credit_card. Structural fields (resource, action, token, …) preserved. docker-compose.yml default changed from cloud to ollama/granite3.2:2b; REDACT_FOR_LLM=true set in both base and cloud-override compose files. No cloud API keys in any tracked compose file.
