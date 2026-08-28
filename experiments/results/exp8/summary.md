# EXP-8  Policy scale + hot-reload correctness

*Generated: 2026-08-28T21:40:28.682511+00:00*

## EXP-8: Policy scale latency vs.\ rule count (live OPA, $N$=200 requests each).
| Rule count | Mean\,(ms) | P99\,(ms) | Live? |
| ---------- | ---------- | --------- | ----- |
| 10 | 1.47 | 2.40 | \checkmark |
| 100 | 1.30 | 2.14 | \checkmark |
| 1{,}000 | 1.61 | 2.18 | \checkmark |
| 5{,}000 | 1.63 | 3.17 | \checkmark |

## EXP-8: Hot-reload correctness (live OPA, in-place update).
| Metric | Value |
| ------ | ----- |
| OPA live | True |
| Reload OK | True |
| Reload latency (ms) | 5.82 |
| Propagation (ms) | 0.06 |
| Stale-ALLOW count | 0 |
| Post-reload requests | 334 |
| JUNIOR READ denied | 147 |
