# EXP-6  Fault injection — zero false-ALLOWs + zero lost records

*Generated: 2026-08-14T05:23:30.786535+00:00*

## Fault injection results — zero false-ALLOWs, zero lost records
| Scenario | N | False_ALLOWs | Lost_Records | Chain_OK | Avail_pct | Mean_ms |
| -------- | ---- | ------------ | ------------ | -------- | --------- | ------- |
| OPA_KILL | 500 | 0 | 0 | ✓ | 100.0% | 0.02 |
| LLM_TIMEOUT | 500 | 0 | 0 | ✓ | 100.0% | 2.51 |
| AUDIT_PARTITION | 500 | 0 | 0 | ✓ | 100.0% | 2.46 |
| NO_FAULT | 500 | 0 | 0 | ✓ | 100.0% | 2.72 |
| LLM_TIMEOUT_LIVE | 500 | 0 | 0 | ✓ | 100.0% | 2.46 |

## Decision distribution under fault
AUDIT_PARTITION: compliance decisions unaffected (100% availability, zero false-ALLOWs). Store-and-forward WAL: lost_records=0 — every verdict buffered to disk and hash-chain intact (chain_ok=True). GAP-8 resolved: sidecar_optimized._spill_to_wal + _drain_wal.

| Scenario | APPROVED | DENIED | THROTTLED | ERROR |
| -------- | -------- | ------ | --------- | ----- |
| OPA_KILL | 0 | 500 | 0 | 0 |
| LLM_TIMEOUT | 123 | 377 | 0 | 0 |
| AUDIT_PARTITION | 137 | 363 | 0 | 0 |
| NO_FAULT | 137 | 363 | 0 | 0 |
| LLM_TIMEOUT_LIVE | 123 | 377 | 0 | 0 |

## Paper §5 gap disclosures
- GAP-8 RESOLVED: store-and-forward WAL (_spill_to_wal/_drain_wal) added to sidecar_optimized.py. lost_records=0 under AUDIT_PARTITION.
- Hash-chain (prev_hash SHA-256) added to S3AuditWriter and EXP-6 WAL; chain_ok=True confirmed.
- LLM_TIMEOUT uses mock.patch (regression baseline); LLM_TIMEOUT_LIVE uses env-var kill (no mock) -- fail-secure path confirmed.
