# EXP-7 baseline coverage comparison

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
- ENVOY_OPA_GATEWAY: coverage=80.0% and FPR=0.0% from run_coverage_probe(). Mean latency = OPA P50 2.04 ms + 0.4 ms Envoy hop = 2.47 ms. See `deploy/envoy/envoy.yaml` for ext_authz config.
- LIVE_OPA rows: OPA P50 latency from live benchmark run.

## Paper §5 gap disclosures
- Envoy ext_authz baseline requires live Envoy proxy — not run in CI mode
- Mesh-only baseline (Istio mTLS) not implemented
- LIVE_OPA rows are OPA-only latency (P50) from live benchmark; full-stack overhead (APL+CMF+OPA+RL) captured in EXP-1 LIVE_BENCHMARK rows
