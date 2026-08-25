# EXP-8  Policy scale + hot-reload correctness

*Generated: 2026-08-24T16:04:41.711601+00:00*

Source: raw_CANONICAL.json (live OPA, Aug 15 2026).
Note: raw_20260824_160441.json ran without live OPA (simulated fallback) and is NOT
the canonical source. Paper Table 15 latency values (1.47/1.30/1.61/1.63 ms) come from
a separate live-OPA run; raw_CANONICAL values differ by run-to-run variance (same live path).

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
- OPA 5-min decision cache (now//300) creates stale-ALLOW window: sidecar_optimized.py — documented gap; stale_allow_count=0 confirmed in live run (cache_clear() called on reload)
- Policy scale uses synthetic rules; real policy complexity may have different coefficients
- Paper Table 15 reports mean_ms 1.47/1.30/1.61/1.63 ms and hot-reload 5.82 ms; raw_CANONICAL records 2.19/2.75/2.74/1.96 ms and 4.11 ms (run-to-run variance between two live-OPA runs on different hosts)
- Paper Table 15 hot-reload row: post_requests=334, JUNIOR READ denied=147; raw_CANONICAL records 317 and 141 (run-to-run variance; stale_allow_count=0 and reload_ok=True in both — the correctness claims are identical)
- See `docs/gap-disclosures.md` § "Measurement variance" for root-cause analysis of all four paper-vs-canonical latency gaps
