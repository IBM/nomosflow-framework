# EXP-7 baseline coverage comparison

*Generated: 2026-08-14T05:23:31.265054+00:00*

## Coverage-vs-overhead matrix
| Baseline | Coverage_pct | FPR_pct | Mean_ms | Overhead_ms |
| -------- | ------------ | ------- | ------- | ----------- |
| NOMOSFLOW | 100.0% | 0.0% | 1.41 | 1.39 |
| OPA_GATEWAY | 95.0% | 0.0% | 1.79 | 1.77 |
| APP_LEVEL | 55.0% | 0.0% | 0.08 | 0.06 |
| NO_ENFORCEMENT | 0.0% | 0.0% | 0.02 | 0.00 |
| LIVE_OPA (scale=100) | — | — | 2.17 | — |
| LIVE_OPA (scale=1000) | — | — | 4.84 | — |
| LIVE_OPA (scale=10000) | — | — | 4.93 | — |
| LIVE_OPA (scale=100000) | — | — | 4.91 | — |
| ENVOY_OPA_GATEWAY | 85.0% | 0.0% | 1.96 | 1.94 |

## Note on Envoy baseline and live OPA data
Envoy ext_authz + OPA gateway baseline: see deploy/envoy/envoy.yaml.
ENVOY_OPA_GATEWAY latency = OPA decision latency + 0.4 ms estimated Envoy hop overhead (2 x localhost RTT).

**LIVE_OPA rows** are per-scale OPA P50 latency measured with opa_live=true from benchmarks/tier_benchmark_20260710_021432.json.

## Paper §5 gap disclosures
- Envoy ext_authz baseline requires live Envoy proxy — not run in CI mode
- Mesh-only baseline (Istio mTLS) not implemented
- LIVE_OPA rows are OPA-only latency (P50) from live benchmark; full-stack overhead (APL+CMF+OPA+RL) captured in EXP-1 LIVE_BENCHMARK rows
