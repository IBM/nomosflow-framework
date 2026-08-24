# NomosFlow

[![CI](https://github.com/IBM/nomosflow/actions/workflows/experiments.yml/badge.svg)](https://github.com/IBM/nomosflow/actions/workflows/experiments.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**NomosFlow** is an event-driven compliance sidecar for AI agents. It intercepts
every data-access event at the pod boundary and passes it through a five-tier
validation pipeline before allowing it to proceed:

| Tier | Component | Latency | Purpose |
|------|-----------|---------|---------|
| T1 | APL (Authorization Policy Layer) | µs | Token / RBAC / attestation |
| T2 | CMF (Context Metadata Forge) | µs | CDM v2 context enrichment |
| T3 | OPA (Open Policy Agent) | ms | Rego policy evaluation |
| T4 | Rate-limit | µs | Per-agent token-bucket |
| T5 | LLM validator | ~ms–s | Semantic / hallucination check (sampled) |

Short-circuiting means most requests resolve at T1 or T3; T5 is invoked for
only ~1% of traffic. The sidecar fails **secure**: any tier failure defaults to
DENY rather than ALLOW.

## Quick start

```bash
git clone https://github.com/IBM/nomosflow
cd nomosflow
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run all paper experiments (no API keys, no containers needed — ~90 s):
python experiments/run_all.py

# Check paper invariants against your fresh run:
python experiments/compare_results.py

# Optionally compare your fresh run against the checked-in canonical outputs:
python experiments/compare_results.py --compare-canonical
```

Reviewer note:
- [`python experiments/run_all.py`](experiments/run_all.py) generates fresh result files under [`experiments/results/`](experiments/results/).
- [`python experiments/compare_results.py`](experiments/compare_results.py:10) is the primary reproducibility check and validates the paper's invariants/claims.
- [`python experiments/compare_results.py --compare-canonical`](experiments/compare_results.py:11) is stricter and checks whether the latest generated `raw_*.json` files exactly match the checked-in [`raw_CANONICAL.json`](experiments/results/exp2/raw_CANONICAL.json) outputs.
- Performance- and resource-oriented experiments such as [`exp1_overhead`](experiments/exp1_overhead/run.py), [`exp11_multiagent`](experiments/exp11_multiagent/run.py), and [`exp12_resource`](experiments/exp12_resource/run.py) can be sensitive to hardware, OS, Python/runtime version, and background system load. Treat the invariant check as the primary portability check; use canonical comparison as an exact-match check for like-for-like environments.

## With live OPA (reproduces measured latency values)

```bash
# Start OPA in Podman or Docker:
podman-compose up -d opa        # or: docker compose up -d opa

# Run experiments against live OPA:
OPA_URL=http://localhost:8181 python experiments/run_all.py
```

## Repository layout

```
nomosflow/
├── src/                   NomosFlow sidecar source (validators, core, interceptors)
├── policies/              OPA Rego policies
├── deploy/envoy/          Envoy ext_authz config (EXP-7 gateway baseline)
├── benchmarks/            Canonical live-service measurement files
├── experiments/           Self-contained experiment suite
│   ├── run_all.py         Master runner
│   ├── compare_results.py Reviewer invariant checker
│   ├── shared/            Shared utilities and OPA client
│   ├── exp1_overhead/     §6.1 per-tier latency
│   ├── exp2_resolution/   §6.1 resolution histogram
│   ├── exp3_detection/    §6.2 detection F1 / FPR / IAA
│   ├── exp4_semantic/     §6.2 prompt-injection robustness
│   ├── exp6_failure/      §6.3 fault injection
│   ├── exp6b_screening/   §6.3 selective-screening Pareto
│   ├── exp7_baselines/    §6.4 NomosFlow vs OPA-gateway vs app-level
│   ├── exp8_policy_scale/ §6.5 policy scale + hot-reload
│   ├── exp9_rb_stream/    §6.6 buffer-then-release invariant
│   ├── exp11_multiagent/  §6.7 multi-agent scalability
│   ├── exp12_resource/    §6.7 CPU/RSS overhead
│   ├── exp_gap13/         §5 interceptor inventory
│   ├── exp_gap32/         §5 OSCAL control-mapping
│   ├── exp_gap35/         §5 redaction-before-inference
│   └── results/           Pre-computed canonical outputs (checked in)
├── docs/                  Architecture and methodology docs
└── docker-compose.yml     Minimal stack: OPA + Redpanda + Prometheus
```

See [`experiments/README.md`](experiments/README.md) for detailed per-experiment
documentation, environment variables, and the paper section mapping.

## Citing this work

If you use NomosFlow or these experimental results, please cite using
[`CITATION.cff`](CITATION.cff) or the paper DOI (to be added on publication).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). All contributors must sign the IBM CLA.
