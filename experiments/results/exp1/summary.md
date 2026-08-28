# EXP-1: Per-Tier Overhead Microbenchmark

*Generated: 2026-08-24T16:04:26.687493+00:00*

## Per-Tier Latency (P50 / P95 / P99 in ms)

**Tier naming:** Internal code uses T1_APL, T2_CMF, T3_OPA, T4_rate_limit, T5_LLM. Paper Table 7 uses T3=CMF, T4=APL, T5=OPA, T6=rate-lim, T7=LLM (different numbering). NOMOSFLOW_FULL / OPA_ONLY rows below are from the live-OPA run in `raw_CANONICAL.json` (2026-08-15). The paper's values for those rows are from an earlier live run; run-to-run variance explains small differences (e.g. paper OPA_ONLY n=100 P50=1.91 ms vs canonical 2.27 ms). The LIVE_BENCHMARK rows (2026-07-10) are the primary calibration source for paper Table 7 tier claims.

| Tier | Baseline | Scale | P50 | P95 | P99 | Max |
| ---- | -------- | ----- | ---- | ---- | ---- | ---- |
| total | NO_ENFORCEMENT | 100 | 0.00 | 0.00 | 0.00 | 0.00 |
| T3_OPA | OPA_ONLY | 100 | 2.27 | 3.79 | 7.00 | 7.55 |
| T1_APL | NOMOSFLOW_FULL | 100 | 0.004 | 0.038 | 0.050 | 0.11 |
| T2_CMF | NOMOSFLOW_FULL | 100 | 0.024 | 0.044 | 0.093 | 0.23 |
| T3_OPA | NOMOSFLOW_FULL | 100 | 2.32 | 4.00 | 8.02 | 17.89 |
| T4_rate_limit | NOMOSFLOW_FULL | 100 | 0.002 | 0.002 | 0.004 | 0.005 |
| total | NO_ENFORCEMENT | 1000 | 0.00 | 0.00 | 0.00 | 0.00 |
| T3_OPA | OPA_ONLY | 1000 | 2.02 | 3.44 | 6.09 | 27.09 |
| T1_APL | NOMOSFLOW_FULL | 1000 | 0.004 | 0.009 | 0.013 | 0.07 |
| T2_CMF | NOMOSFLOW_FULL | 1000 | 0.020 | 0.043 | 0.068 | 0.13 |
| T3_OPA | NOMOSFLOW_FULL | 1000 | 2.09 | 3.32 | 4.38 | 12.85 |
| T4_rate_limit | NOMOSFLOW_FULL | 1000 | 0.002 | 0.003 | 0.005 | 0.023 |
| T5_LLM | NOMOSFLOW_FULL | 1000 | 36113 | 36148 | 36151 | 36152 |
| total | NO_ENFORCEMENT | 10000 | 0.00 | 0.00 | 0.00 | 0.00 |
| T3_OPA | OPA_ONLY | 10000 | 2.27 | 3.86 | 5.85 | 62.37 |
| T1_APL | NOMOSFLOW_FULL | 10000 | 0.004 | 0.010 | 0.019 | 0.35 |
| T2_CMF | NOMOSFLOW_FULL | 10000 | 0.025 | 0.046 | 0.079 | 2.18 |
| T3_OPA | NOMOSFLOW_FULL | 10000 | 2.44 | 3.84 | 5.21 | 14.17 |
| T4_rate_limit | NOMOSFLOW_FULL | 10000 | 0.002 | 0.004 | 0.007 | 0.07 |
| T5_LLM | NOMOSFLOW_FULL | 10000 | 15235 | 22103 | 22714 | 22866 |
| T3_OPA | LIVE_BENCHMARK | 100 | 2.17 | 4.92 | 6.65 | 10.11 |
| T1_APL | LIVE_BENCHMARK | 100 | 0.005 | 0.009 | 0.011 | 0.011 |
| T2_CMF | LIVE_BENCHMARK | 100 | 0.002 | 0.002 | 0.003 | 0.005 |
| total | LIVE_BENCHMARK | 100 | 2.12 | 4.85 | 6.10 | 10.12 |
| T3_OPA | LIVE_BENCHMARK | 1000 | 4.84 | 8.29 | 10.51 | 16.02 |
| T1_APL | LIVE_BENCHMARK | 1000 | 0.017 | 0.034 | 0.062 | 0.422 |
| T2_CMF | LIVE_BENCHMARK | 1000 | 0.005 | 0.010 | 0.014 | 0.136 |
| T5_LLM | LIVE_BENCHMARK | 1000 | 4584 | 9432 | 10225 | 10423 |
| total | LIVE_BENCHMARK | 1000 | 4.33 | 8.15 | 15.10 | 10425.10 |
| T3_OPA | LIVE_BENCHMARK | 10000 | 4.93 | 9.14 | 12.74 | 43.96 |
| T1_APL | LIVE_BENCHMARK | 10000 | 0.019 | 0.039 | 0.060 | 3.059 |
| T2_CMF | LIVE_BENCHMARK | 10000 | 0.006 | 0.011 | 0.017 | 0.650 |
| T5_LLM | LIVE_BENCHMARK | 10000 | 6923 | 14924 | 16740 | 17475 |
| total | LIVE_BENCHMARK | 10000 | 4.47 | 9.10 | 21.15 | 17479.94 |
| T3_OPA | LIVE_BENCHMARK | 100000 | 4.91 | 8.90 | 11.81 | 117.91 |
| T1_APL | LIVE_BENCHMARK | 100000 | 0.019 | 0.038 | 0.060 | 6.672 |
| T2_CMF | LIVE_BENCHMARK | 100000 | 0.006 | 0.010 | 0.017 | 14.776 |
| T5_LLM | LIVE_BENCHMARK | 100000 | 6440 | 13429 | 16330 | 31338 |
| total | LIVE_BENCHMARK | 100000 | 4.49 | 8.84 | 15.82 | 31343.27 |

## Live benchmark provenance
Live benchmark (2026-07-10, all services up) rows are labelled **LIVE_BENCHMARK**. Scales 100 / 1 000 / 10 000 / 100 000 were run with `opa_live=true`, `apl_live=true`, `cmf_live=true`, `llm_live=true`.

## Throughput comparison

**Gap note:** The paper's throughput table (Table 7, body) shows NO_ENFORCEMENT/OPA_ONLY/NOMOSFLOW_FULL rows from a live run whose JSON is not preserved separately. The values below for those baselines are from `raw_CANONICAL.json` (2026-08-15 live run) and differ slightly from the paper due to run-to-run variance. LIVE_BENCHMARK rows are from `benchmarks/tier_benchmark_20260710_021432.json` and match the paper exactly.

| Baseline | Scale | RPS | CPU_delta_pct | RSS_delta_MB |
| -------- | ----- | ---- | ------------- | ------------ |
| NO_ENFORCEMENT | 100 | 3761658 | 0.0 | 0.0 |
| OPA_ONLY | 100 | 395 | 0.0 | 0.016 |
| NOMOSFLOW_FULL | 100 | 362 | 0.0 | 0.062 |
| NO_ENFORCEMENT | 1000 | 4672001 | 0.0 | 0.0 |
| OPA_ONLY | 1000 | 436 | 0.0 | 0.031 |
| NOMOSFLOW_FULL | 1000 | 12 | 0.0 | -45.953 |
| NO_ENFORCEMENT | 10000 | 6262721 | 0.0 | 0.406 |
| OPA_ONLY | 10000 | 397 | 0.0 | -31.578 |
| NOMOSFLOW_FULL | 10000 | 127 | 0.0 | 5.688 |
| LIVE_BENCHMARK | 100 | 392 | measured | measured |
| LIVE_BENCHMARK | 1000 | 18.3 | measured | measured |
| LIVE_BENCHMARK | 10000 | 14.8 | measured | measured |
| LIVE_BENCHMARK | 100000 | 17.1 | measured | measured |

## In-pod vs. gateway overhead
Without a live Envoy ext_authz gRPC service the gateway baseline is **not available** in this run.

To collect it manually:

```bash
# 1. Start Envoy with the NomosFlow ext_authz filter:
#      envoy -c deploy/envoy/envoy.yaml
# 2. Run the wrk2 load generator against the Envoy listener:
#      wrk2 -t4 -c100 -d60s -R 1000 \
#           --script experiments/exp1_overhead/envoy_lua.lua \
#           http://localhost:10000/authz
# 3. Compare wrk2 latency percentiles with T3_OPA column above.
```


## Paper §5 gap disclosures
- OPA 5-min cache creates stale-ALLOW window during hot-reload
- LLM tier measured separately at LLM_RATE fraction only
- LIVE_BENCHMARK rows from `benchmarks/tier_benchmark_20260710_021432.json` (opa_live=true, llm_live=true at 1% routing); these are the primary source for paper Table 7 claims
- NOMOSFLOW_FULL / OPA_ONLY rows use tier names T1_APL/T2_CMF/T3_OPA/T4_rate_limit/T5_LLM (internal code convention); paper Table 7 uses T3=CMF, T4=APL, T5=OPA, T6=rate-lim, T7=LLM
- NOMOSFLOW_FULL / OPA_ONLY values updated from `raw_CANONICAL.json` (2026-08-15 live run); paper values from an earlier run — run-to-run variance only, no methodology difference
