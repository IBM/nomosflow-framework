# EXP-2: Resolution Distribution (NomosFlow)

Tier labels use paper notation (T3=CMF, T4=APL, T5=OPA, T6=rate-limit, T7=LLM).

## Section 1 — Resolution distribution
N=2000 requests across the 5-tier pipeline (ladder mode).

| Tier | Count | Fraction | p_i | c_i (mean ms) |
| ---- | ----- | -------- | --- | ------------- |
| T3 (CMF) | 0 | 0.000 | 0.686 | 0.02 |
| T4 (APL) | 629 | 0.315 | 1.000 | 0.00 |
| T5 (OPA) | 813 | 0.406 | 0.686 | 2.90 |
| T6 (rate-limit) | 0 | 0.000 | 0.279 | 0.05 |
| T7 (LLM) | 1 | 0.001 | 0.003 | 92.82 |
| APPROVED | 557 | 0.279 | — | — |

## Section 2 — Survival probabilities and per-tier latency
p_i = fraction of requests that reached tier i; c_i = mean latency of tier i across those requests.

| Tier | p_i (reach prob) | c_i (mean ms) |
| ---- | ---------------- | ------------- |
| T3 (CMF) | 0.686 | 0.02 |
| T4 (APL) | 1.000 | 0.00 |
| T5 (OPA) | 0.686 | 2.90 |
| T6 (rate-limit) | 0.279 | 0.05 |
| T7 (LLM) | 0.003 | 92.82 |
| APPROVED | 0.279 | — |

## Section 3 — Tier ordering: deployed vs optimal (Prop. 3)
Optimal order minimises Σ c_i / (1 − p_i). Deployed rank = position in the cascade (T4 APL runs
first as fast-path checks, T3 CMF enriches the event for OPA/LLM, then T5 OPA → T6 rate-limit →
T7 LLM). See Figure 1 in the paper: T2/T4 (APL filters/attr) precede T3 (CMF enrichment) in
execution order; the latency table lists by ascending tier number, not execution order.
T4 (APL) has p_i=1.0 (mandatory, always reached) and is excluded from the Prop. 3 optimisation
domain (you cannot reorder a tier with p_i=1.0 — it is always first).

| Deployed_rank | Optimal_rank | Tier | c_i/(1-p_i) |
| ------------- | ------------ | ---- | ----------- |
| 1 | 6 | T4 (APL) | ∞ |
| 2 | 1 | T4 (APL-attest) | 0.00 |
| 3 | 2 | T3 (CMF) | 0.08 |
| 4 | 4 | T5 (OPA) | 9.23 |
| 5 | 3 | T6 (rate-limit) | 0.07 |
| 6 | 5 | T7 (LLM) | 93.05 |

## Section 4 — Short-circuit ablation
ladder: stop at first DENY. forced_pipeline: run all tiers regardless of DENY.
T7 (LLM) is excluded from both arms — this is a deterministic-tier ablation.

| Mode | Mean_total_ms | Saving |
| ---- | ------------- | ------ |
| ladder (deployed) | 2.26 | — |
| forced_pipeline | 3.53 | 36.0% |

## Paper §5 gap disclosures
- Anomaly detection runs post-decision async — not counted as a resolving tier
- T4 (APL) p_i=1.0: mandatory first tier, excluded from Prop. 3 cost-optimal ordering
