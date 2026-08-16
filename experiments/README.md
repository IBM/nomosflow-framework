# NomosFlow — Experiments

Self-contained experiment suite for the NomosFlow paper.
Every experiment writes raw results to `results/<EXP_ID>/` as JSON
and a paper-ready summary to `results/<EXP_ID>/summary.md`.

```
experiments/
├── README.md                  ← this file
├── run_all.py                 ← master runner
├── compare_results.py         ← reviewer invariant checker
├── shared/
│   ├── common.py              ← percentile helpers, request generator, AuditDB
│   ├── opa_client.py          ← OPA probe + call wrapper
│   ├── report.py              ← summary → markdown + LaTeX table emitter
│   └── live_data.py           ← loaders for canonical benchmark files
├── exp1_overhead/run.py       ← EXP-1: per-tier latency + baselines
├── exp2_resolution/run.py     ← EXP-2: resolved_at_tier histogram + p_i/c_i
├── exp3_detection/run.py      ← EXP-3: detection efficacy + FPR headline
├── exp4_semantic/run.py       ← EXP-4: semantic tier robustness / prompt injection
├── exp6_failure/run.py        ← EXP-6: fault injection (OPA kill, LLM timeout)
├── exp6b_screening/run.py     ← EXP-6b: selective screening Pareto frontier
├── exp7_baselines/run.py      ← EXP-7: NomosFlow vs. OPA-gateway vs. app-level
├── exp8_policy_scale/run.py   ← EXP-8: policy scale + hot-reload correctness
├── exp9_rb_stream/run.py      ← EXP-9: buffer-then-release invariant verification
├── exp11_multiagent/run.py    ← EXP-11: 1–100 agents, per-agent resource curve
├── exp12_resource/run.py      ← EXP-12: sidecar CPU/RSS overhead
├── exp_gap13/run.py           ← EXP-GAP-13: interceptor inventory
├── exp_gap32/run.py           ← EXP-GAP-32: OSCAL control-mapping verification
├── exp_gap35/run.py           ← EXP-GAP-35: redaction-before-inference
└── results/                   ← canonical + fresh run outputs
    └── <EXP_ID>/
        ├── raw_CANONICAL.json ← checked-in reference numbers
        ├── raw_<timestamp>.json ← fresh runs (gitignored)
        └── summary.md
```

## Quick start — run all experiments

```bash
cd <repo-root>
# Run without live services (all tiers simulated):
python experiments/run_all.py

# Run with live OPA (start OPA first):
OPA_URL=http://localhost:8181 python experiments/run_all.py

# Run single experiment:
python experiments/exp1_overhead/run.py

# Check paper invariants against your run:
python experiments/compare_results.py
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `OPA_URL` | `http://localhost:8181` | OPA endpoint |
| `LLM_VALIDATION_ENABLED` | `false` | Enable live LLM tier |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | LLM endpoint |
| `LLM_MODEL` | `gpt-4o-mini` | LLM model name |
| `BENCHMARK_SCALES` | `100,1000,10000` | Request scales for EXP-1/EXP-11 |
| `AGENT_COUNTS` | `1,5,10,25,50,100` | Agent counts for EXP-11 |
| `LLM_RATES` | `0.0,0.05,0.1,0.2,0.5,1.0` | Routing fractions for EXP-6b |
| `RESULTS_DIR` | `experiments/results` | Output directory |

## Paper section mapping

| Experiment | Paper section | Key claim |
|---|---|---|
| EXP-1 | §6.1 | Per-tier P50/P95/P99; in-pod vs. gateway overhead |
| EXP-2 | §6.1 | resolved_at_tier histogram; empirical p_i, c_i |
| EXP-3 | §6.2 | Detection F1; FPR on benign traffic (headline) |
| EXP-4 | §6.2 | Semantic tier deny/escalate-only under prompt injection |
| EXP-6 | §6.3 | Zero false-ALLOWs under fault injection |
| EXP-6b | §6.3 | Recall/throughput Pareto (lossy trade-off) |
| EXP-7 | §6.4 | Coverage-vs-overhead vs. Envoy+OPA, app-level |
| EXP-8 | §6.5 | Policy scale latency; hot-reload correctness |
| EXP-9 | §6.6 | Buffer-then-release invariant (atomic RB) |
| EXP-11 | §6.7 | Per-agent resource curve (1–100 agents) |
| EXP-12 | §6.7 | Sidecar CPU/RSS overhead decomposition |
| EXP-GAP-13 | §5 | Interceptor inventory |
| EXP-GAP-32 | §5 | OSCAL control-mapping drift = 0 |
| EXP-GAP-35 | §5 | Redaction-before-inference |

## Gap disclosures (§5)

- **OPA cache staleness**: 5-min TTL creates a stale-ALLOW window during hot-reload (EXP-8).
- **Anomaly detection is advisory**: runs post-decision on daemon thread; not a pre-emission gate.
- **Audit durability**: store-and-forward WAL in `/tmp/compliance_audit_wal.jsonl` on SQLite failure.
- **T5 fail-open**: LLM API outage degrades coverage; GAP-10 fix enforces deny/escalate-only by default.
- **EXP-3 POLICY TP ±3**: OPA's `time.now_ns()` causes clock-boundary flips in 4 edge-case requests.
- **EXP-6b fully simulated**: Pareto table uses seeded RNG + deterministic oracle; no live LLM calls.
- **EXP-9 runtime check**: `denied_with_data=0` is invariant-by-construction; static code audit is the evidence.
