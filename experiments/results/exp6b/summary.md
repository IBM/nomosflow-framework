# EXP-6b  Selective screening Pareto frontier

## Recall / throughput Pareto
| LLM_rate | Recall | Throughput_norm | On_Pareto |
| -------- | ------ | --------------- | --------- |
| 0.0 | 60.0% | 1.000 | yes |
| 0.05 | 62.5% | 0.013 | yes |
| 0.2 | 70.0% | 0.002 | yes |
| 0.5 | 80.0% | 0.001 | yes |
| 1.0 | 100.0% | 3.2×10⁻⁴ | yes |

## Static floor
Static (deterministic) recall floor at LLM_rate=0.0: 60.0%. Screened-out requests fall back to static/OPA verdict; the soundness floor is never lowered by the screening decision.

## Latency model
Semantic per-call latency (T7/LLM tier): lognormal, P50 = 9,500 ms, sigma_log = 0.26 (EXP-1 LIVE_BENCHMARK T7, Table 7). Static base: Gaussian(3.2 ms, 0.8 ms).

## Paper §5 gap disclosures
- This is a deliberately lossy ablation — kept separate from EXP-2 natural escalation rate
- Screened requests fall back to static/OPA verdict; soundness floor is unchanged
