# EXP-11 multi-agent scalability

*Generated: 2026-08-28T21:40:28.683488+00:00*

## EXP-11: Multi-agent scalability (live OPA).
| Agents | Total RPS | Per-agent RPS | P99\,(ms) | Mode |
| ------ | --------- | ------------- | --------- | ---- |
| 1 | 511 | 511 | 4.3 | thread |
| 5 | 1{,}592 | 318 | 5.0 | thread |
| 10 | 1{,}657 | 166 | 9.2 | thread |
| 25 | 1{,}653 | 66 | 24.7 | thread |
| 50 | 1{,}472 | 29 | 59.7 | thread |
| 100 | 891 | 9 | 170.3 | thread |
| 1 | 339 | 339 | 4.0 | process |
| 5 | 1{,}421 | 284 | 6.6 | process |
| 10 | 1{,}939 | 194 | 12.1 | process |
| 25 | 2{,}244 | 90 | 13.7 | process |
