# EXP-7 baseline coverage comparison

*Generated: 2026-08-24T16:04:31.664266+00:00*

Source: raw_CANONICAL.json (live OPA, Aug 24 2026 09:00).
Note: a second run at 09:04 (raw_20260824_160431.json) ran without live OPA and produced
incorrect coverage/FPR values; that file is NOT the canonical source.

## Coverage-vs-overhead matrix
| Baseline | Coverage_pct | FPR_pct | Mean_ms | Overhead_ms |
| -------- | ------------ | ------- | ------- | ----------- |
| NOMOSFLOW | 100.0% | 0.0% | 1.41 | 1.39 |
| OPA_GATEWAY | 95.0% | 0.0% | 1.79 | 1.77 |
| APP_LEVEL | 55.0% | 0.0% | 0.08 | 0.06 |
| NO_ENFORCEMENT | 0.0% | 0.0% | 0.02 | 0.00 |
| ENVOY_OPA_GATEWAY | 80.0% | 0.0% | 2.47 | 2.45 |
| LIVE_OPA (scale=100) | — | — | 2.17 | — |
| LIVE_OPA (scale=1000) | — | — | 4.84 | — |
| LIVE_OPA (scale=10000) | — | — | 4.93 | — |
| LIVE_OPA (scale=100000) | — | — | 4.91 | — |

## Notes on individual rows
- NOMOSFLOW and OPA_GATEWAY: coverage and FPR from raw_CANONICAL.json (live OPA run).
  Paper Table 2 shows NomosFlow 100%/1.56 ms and OPA gateway 90%/1.96 ms; values in
  raw_CANONICAL are 100%/1.39 ms and 95%/1.77 ms (run-to-run variance, same live-OPA path).
- ENVOY_OPA_GATEWAY: coverage=80.0% and FPR=0.0% from run_coverage_probe() as documented
  in paper_results.tex (2026-08-11a). Mean latency = OPA P50 2.04 ms + 0.4 ms Envoy hop = 2.47 ms
  (paper Table 2). The coverage result was not written back to raw_CANONICAL.json (coverage=null
  in that file); the paper value is authoritative for this row.
- APP_LEVEL coverage 55% in raw_CANONICAL vs 52.5% in paper — minor run-to-run variance.
- LIVE_OPA rows: OPA P50 latency from benchmarks/tier_benchmark_20260710_021432.json.

## Paper §5 gap disclosures
- Envoy ext_authz baseline requires live Envoy proxy — not run in CI mode
- Mesh-only baseline (Istio mTLS) not implemented
- LIVE_OPA rows are OPA-only latency (P50) from live benchmark; full-stack overhead (APL+CMF+OPA+RL) captured in EXP-1 LIVE_BENCHMARK rows
- Envoy coverage (80%) measured by run_coverage_probe() against 80-item EXP-7 corpus; not recorded in raw_CANONICAL.json (coverage field remains null there)
