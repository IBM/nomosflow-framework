# EXP-6  Fault injection — zero false-ALLOWs + zero lost records

*Generated: 2026-08-28T21:40:28.681364+00:00*

## EXP-6: Fault injection results
| Scenario | False-ALLOWs | Lost-Records | Chain-OK | Avail. | Mean\,(ms) |
| -------- | ------------ | ------------ | -------- | ------ | ---------- |
| OPA\_KILL | 0 | 0 | \checkmark | 100.0\% | 0.03 |
| LLM\_TIMEOUT | 0 | 0 | \checkmark | 100.0\% | 2.64 |
| AUDIT\_PARTITION | 0 | 0 | \checkmark | 100.0\% | 1.91 |
| NO\_FAULT | 0 | 0 | \checkmark | 100.0\% | 1.87 |
| LLM\_TIMEOUT\_LIVE | 0 | 0 | \checkmark | 100.0\% | 2.60 |
