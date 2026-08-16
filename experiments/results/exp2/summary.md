# EXP-2: Resolution Distribution (NomosFlow)

*Generated: 2026-08-14T05:23:22.448955+00:00*

## Section 1 — Resolution distribution
N=2000 requests across the 5-tier pipeline (ladder mode).

| Tier | Count | Fraction | Mean_latency_ms |
| ---- | ----- | -------- | --------------- |
| T1_APL | 629 | 0.315 | 0.01 |
| T1_ATTEST | 0 | 0.000 | 0.00 |
| T2_CMF | 0 | 0.000 | 0.00 |
| T3_OPA | 813 | 0.406 | 2.92 |
| T4_RATE | 0 | 0.000 | 0.00 |
| T5_LLM | 1 | 0.001 | 98.62 |
| APPROVED | 557 | 0.279 | 0.00 |

## Section 2 — Survival probabilities and per-tier latency
p_i = fraction of requests that reached tier i; c_i = mean latency of tier i across those requests.

| Tier | p_i (reach prob) | c_i (mean ms) |
| ---- | ---------------- | ------------- |
| T1_APL | 1.0000 | 0.00 |
| T1_ATTEST | 0.0000 | 0.00 |
| T2_CMF | 0.6855 | 0.02 |
| T3_OPA | 0.6855 | 2.90 |
| T4_RATE | 0.2790 | 0.05 |
| T5_LLM | 0.0025 | 92.82 |
| APPROVED | 0.0000 | 0.00 |

## Section 3 — Tier ordering: deployed vs optimal (Prop. 3)
Optimal order minimises Σ c_i / (1 − p_i).  Deployed rank = position in T1→T2→T3→T4→T5 pipeline.

| Deployed_rank | Optimal_rank | Tier | c_i/(1-p_i) |
| ------------- | ------------ | ---- | ----------- |
| 1 | 6 | T1_APL | ∞ |
| 2 | 1 | T1_ATTEST | 0.00 |
| 3 | 3 | T2_CMF | 0.08 |
| 4 | 4 | T3_OPA | 9.23 |
| 5 | 2 | T4_RATE | 0.07 |
| 6 | 5 | T5_LLM | 93.05 |

## Section 4 — Short-circuit ablation
ladder: stop at first DENY.  forced_pipeline: run all tiers regardless of DENY.

| Mode | Mean_total_ms | Reduction_pct |
| ---- | ------------- | ------------- |
| ladder | 2.26 | — |
| forced_pipeline | 3.53 | 36.0% |

## Paper §5 gap disclosures
- Anomaly detection runs post-decision async — not counted as a resolving tier
