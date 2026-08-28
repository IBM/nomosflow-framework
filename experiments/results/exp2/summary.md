# EXP-2: Resolution Distribution (NomosFlow)

*Generated: 2026-08-28T21:40:28.680134+00:00*

## EXP-2: Resolution distribution across tiers ($N$=2{,}000, live OPA).
| Tier | Count | Fraction | $p_i$ | $c_i$\,(ms) |
| ---- | ----- | -------- | ----- | ----------- |
| T4\,(APL) | 629 | 0.315 | 1.000 | 0.00 |
| T3\,(CMF) | 0 | 0.000 | 0.685 | 0.02 |
| T5\,(OPA) | 813 | 0.406 | 0.685 | 1.96 |
| T6\,(rate-limit) | 0 | 0.000 | 0.279 | 0.05 |
| T7\,(LLM) | 1 | 0.001 | 0.003 | 92.82 |
| APPROVED | 557 | 0.279 | --- | --- |

## EXP-2: Short-circuit ablation (live OPA).
| Mode | Mean total (ms) | Saving |
| ---- | --------------- | ------ |
| Ladder (deployed) | 1.60 | --- |
| Forced pipeline | 3.56 | 55.0\% |
