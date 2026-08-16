# EXP-6b  Selective screening Pareto frontier

*Generated: 2026-08-14T05:23:30.789880+00:00*

## Recall / throughput Pareto
| LLM_rate | Recall | Throughput_norm | On_Pareto |
| -------- | ------ | --------------- | --------- |
| 0.0 | 60.0% | 1.000 | yes |
| 0.05 | 62.5% | 0.853 | yes |
| 0.1 | 62.5% | 0.744 | no |
| 0.2 | 70.0% | 0.346 | yes |
| 0.5 | 72.5% | 0.162 | yes |
| 1.0 | 100.0% | 0.068 | yes |

## Static floor
Static (deterministic) recall floor at LLM_rate=0.0: 60.0%. Screened-out requests fall back to static/OPA verdict; the soundness floor is never lowered by the screening decision.

## Paper §5 gap disclosures
- This is a deliberately lossy ablation — kept separate from EXP-2 natural escalation rate
- Screened requests fall back to static/OPA verdict; soundness floor is unchanged
