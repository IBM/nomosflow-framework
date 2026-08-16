# EXP-8  Policy scale + hot-reload correctness

*Generated: 2026-08-14T05:23:43.860019+00:00*

## Latency vs. rule count
| Rule_count | Mean_ms | P99_ms | Simulated |
| ---------- | ------- | ------ | --------- |
| 10 | 2.19 | 3.50 | no |
| 100 | 2.75 | 5.40 | no |
| 1000 | 2.74 | 7.89 | no |
| 5000 | 1.96 | 3.60 | no |

## Hot-reload correctness
| Metric | Value |
| ------ | ----- |
| OPA_live | True |
| reload_ok | True |
| reload_latency_ms | 4.11 |
| propagation_latency_ms | 0.05 |
| stale_allow_count | 0 |
| post_requests | 317 |
| post_junior_read_denied | 141 |

## Paper §5 gap disclosures
- OPA 5-min decision cache (now//300) creates stale-ALLOW window: sidecar_optimized.py:965
- Policy scale uses synthetic rules; real policy complexity may have different coefficients
